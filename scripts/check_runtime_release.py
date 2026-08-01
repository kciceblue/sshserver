#!/usr/bin/env python3
"""Verify cgo-free runtime release binaries and exercise the native target."""

from __future__ import annotations

import argparse
from pathlib import Path
import platform
import signal
import socket
import subprocess
import sys
import tempfile
import time


ALL_TARGETS = ("linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64")
REQUIRED_SQLITE = "github.com/ncruces/go-sqlite3\tv0.32.0"
FORBIDDEN_METADATA = (
    "github.com/dchest/siphash",
    "github.com/hashicorp/golang-lru",
    "github.com/ncruces/sort",
    "modernc.org/",
    "libssh",
    "wolfssh",
)


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def native_target() -> str | None:
    operating_system = platform.system().lower()
    architecture = platform.machine().lower()
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(
        architecture, architecture
    )
    target = f"{operating_system}/{architecture}"
    return target if target in ALL_TARGETS else None


def binary_path(directory: Path, target: str) -> Path:
    operating_system, architecture = target.split("/", 1)
    return directory / f"sshserver-{operating_system}-{architecture}"


def verify_binary(path: Path, target: str, errors: list[str]) -> None:
    if not path.is_file():
        errors.append(f"missing release binary: {path}")
        return
    if path.stat().st_size == 0:
        errors.append(f"empty release binary: {path}")
        return

    metadata = run("go", "version", "-m", str(path), check=False)
    if metadata.returncode != 0:
        errors.append(f"cannot read Go metadata for {path.name}: {metadata.stderr.strip()}")
        return
    operating_system, architecture = target.split("/", 1)
    required = (
        f"build\tCGO_ENABLED=0",
        f"build\tGOOS={operating_system}",
        f"build\tGOARCH={architecture}",
        f"dep\t{REQUIRED_SQLITE}",
    )
    normalized = metadata.stdout.replace("\tbuild\t", "build\t").replace(
        "\tdep\t", "dep\t"
    )
    for marker in required:
        if marker not in normalized:
            errors.append(f"{path.name} lacks metadata marker {marker!r}")
    lowered = normalized.lower()
    for forbidden in FORBIDDEN_METADATA:
        if forbidden in lowered:
            errors.append(f"{path.name} contains forbidden module marker {forbidden}")

    file_result = run("file", str(path), check=False)
    if file_result.returncode != 0:
        errors.append(f"file inspection failed for {path.name}")
    else:
        description = file_result.stdout.lower()
        expected_format = "elf" if operating_system == "linux" else "mach-o"
        architecture_markers = (
            ("x86-64", "x86_64")
            if architecture == "amd64"
            else ("arm64", "aarch64")
        )
        if expected_format not in description or not any(
            marker in description for marker in architecture_markers
        ):
            errors.append(
                f"{path.name} has unexpected file description: {file_result.stdout.strip()}"
            )
        if operating_system == "linux" and "statically linked" not in description:
            errors.append(f"{path.name} is not reported as statically linked")

    if operating_system == "darwin" and platform.system() == "Darwin":
        libraries = run("otool", "-L", str(path), check=False)
        if libraries.returncode != 0:
            errors.append(f"otool inspection failed for {path.name}")
        else:
            lowered_libraries = libraries.stdout.lower()
            for forbidden in ("sqlite", "libssl", "libcrypto"):
                if forbidden in lowered_libraries:
                    errors.append(
                        f"{path.name} dynamically links forbidden library {forbidden}"
                    )


def reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def exercise_native(path: Path, version: str, errors: list[str]) -> None:
    version_result = run(str(path), "version", check=False)
    if version_result.returncode != 0 or version_result.stdout != f"sshserver {version}\n":
        errors.append(
            f"native version command failed: {version_result.stdout!r} {version_result.stderr!r}"
        )
        return

    with tempfile.TemporaryDirectory(prefix="jat-runtime-smoke-") as temporary:
        state_directory = Path(temporary) / "state"
        address = f"127.0.0.1:{reserve_loopback_port()}"
        initialized = run(
            str(path),
            "init",
            "--state-dir",
            str(state_directory),
            "--listen",
            address,
            check=False,
        )
        if initialized.returncode != 0:
            errors.append(f"native init failed: {initialized.stderr.strip()}")
            return
        server = subprocess.Popen(
            [str(path), "serve", "--state-dir", str(state_directory)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 10
            health = None
            while time.monotonic() < deadline:
                health = run(
                    str(path), "health", "--address", address, check=False
                )
                if health.returncode == 0:
                    break
                if server.poll() is not None:
                    break
                time.sleep(0.05)
            if health is None or health.returncode != 0 or health.stdout != "ok\n":
                errors.append(
                    "native foreground health check failed: "
                    + (health.stderr.strip() if health is not None else "not attempted")
                )
        finally:
            if server.poll() is None:
                server.send_signal(signal.SIGTERM)
            try:
                stdout, stderr = server.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                stdout, stderr = server.communicate()
                errors.append("native foreground server did not stop after SIGTERM")
            if server.returncode != 0:
                errors.append(
                    f"native foreground server exit {server.returncode}: {stdout!r} {stderr!r}"
                )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    parser.add_argument("--version", default="dev")
    parser.add_argument(
        "--target", action="append", dest="targets", choices=ALL_TARGETS
    )
    parser.add_argument("--execute-native", action="store_true")
    args = parser.parse_args(argv)

    targets = tuple(args.targets or ALL_TARGETS)
    errors: list[str] = []
    for target in targets:
        verify_binary(binary_path(args.dist, target), target, errors)

    if args.execute_native:
        native = native_target()
        if native is None:
            errors.append("host is not one of the supported release targets")
        elif native not in targets:
            errors.append(f"native target {native} was not selected")
        else:
            exercise_native(binary_path(args.dist, native), args.version, errors)

    if errors:
        for error in errors:
            print(f"runtime release: {error}", file=sys.stderr)
        return 1
    print(f"runtime release: valid ({len(targets)} targets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
