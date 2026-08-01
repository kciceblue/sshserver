#!/usr/bin/env python3
"""Verify the trimmed runtime SQLite fork against its exact upstream module."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MODULE = "github.com/ncruces/go-sqlite3"
VERSION = "v0.32.0"
SELECTOR = f"{MODULE}@{VERSION}"
EXPECTED_SUM = "h1:hNBUXp88LrfQCsuyXLqWTbTUG35sUuktDsqhhgHvU20="
EXPECTED_GO_MOD_SUM = "h1:MIWTK60ONDl0oVY073zYvJP21C3Dly6P9bxVpgkLwdQ="
EXPECTED_COMMIT = "5842ec9343b4a71dae70976d66fd8c9a3d49b868"
VENDOR_RELATIVE = Path("runtime/third_party/go-sqlite3")
MANIFEST_NAME = "UPSTREAM_FILES.sha256"
LOCAL_METADATA = frozenset({"go.mod", "go.sum", "UPSTREAM.md", MANIFEST_NAME})
MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  ([^\r\n]+)$")


def _hash_file(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_manifest(manifest_path: Path, errors: list[str]) -> dict[str, str]:
    try:
        lines = manifest_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        errors.append(f"cannot read {MANIFEST_NAME}: {error}")
        return {}
    if not lines:
        errors.append(f"{MANIFEST_NAME} must not be empty")
        return {}

    entries: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        match = MANIFEST_LINE.fullmatch(line)
        if match is None:
            errors.append(f"{MANIFEST_NAME}:{line_number}: invalid manifest line")
            continue
        expected_hash, relative_text = match.groups()
        relative = PurePosixPath(relative_text)
        if (
            relative.is_absolute()
            or relative_text != relative.as_posix()
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            errors.append(
                f"{MANIFEST_NAME}:{line_number}: unsafe path {relative_text!r}"
            )
            continue
        if relative_text in LOCAL_METADATA:
            errors.append(
                f"{MANIFEST_NAME}:{line_number}: local metadata cannot be upstream content"
            )
            continue
        if relative_text in entries:
            errors.append(
                f"{MANIFEST_NAME}:{line_number}: duplicate path {relative_text}"
            )
            continue
        entries[relative_text] = expected_hash
    return entries


def _collect_files(directory: Path, errors: list[str]) -> set[str]:
    files: set[str] = set()

    def record_walk_error(error: OSError) -> None:
        errors.append(f"cannot walk {directory}: {error}")

    for current_text, directory_names, file_names in os.walk(
        directory, topdown=True, onerror=record_walk_error, followlinks=False
    ):
        current = Path(current_text)
        for name in list(directory_names):
            candidate = current / name
            try:
                mode = candidate.lstat().st_mode
            except OSError as error:
                errors.append(f"cannot inspect {candidate}: {error}")
                directory_names.remove(name)
                continue
            if stat.S_ISLNK(mode):
                errors.append(
                    f"vendored source contains symlink: {candidate.relative_to(directory)}"
                )
                directory_names.remove(name)
            elif not stat.S_ISDIR(mode):
                errors.append(
                    f"vendored source contains non-directory entry: {candidate.relative_to(directory)}"
                )
                directory_names.remove(name)
        for name in file_names:
            candidate = current / name
            relative = candidate.relative_to(directory).as_posix()
            try:
                mode = candidate.lstat().st_mode
            except OSError as error:
                errors.append(f"cannot inspect {candidate}: {error}")
                continue
            if stat.S_ISLNK(mode):
                errors.append(f"vendored source contains symlink: {relative}")
            elif stat.S_ISREG(mode):
                files.add(relative)
            else:
                errors.append(f"vendored source contains non-regular file: {relative}")
    return files


def _download_module(root: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        result = subprocess.run(
            ["go", "mod", "download", "-json", SELECTOR],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as error:
        errors.append(f"cannot execute `go mod download` for {SELECTOR}: {error}")
        return None
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
        errors.append(f"cannot download exact upstream {SELECTOR}: {detail}")
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        errors.append(f"invalid `go mod download` output for {SELECTOR}: {error}")
        return None
    if not isinstance(payload, dict):
        errors.append(f"invalid `go mod download` object for {SELECTOR}")
        return None
    return payload


def validate_vendor(
    root: Path, *, download_payload: dict[str, Any] | None = None
) -> list[str]:
    """Return provenance violations for the trimmed SQLite replacement."""

    root = root.resolve()
    errors: list[str] = []
    vendor_directory = root / VENDOR_RELATIVE
    if not vendor_directory.is_dir() or vendor_directory.is_symlink():
        return [f"{VENDOR_RELATIVE} must be a real directory"]

    manifest = _load_manifest(vendor_directory / MANIFEST_NAME, errors)
    local_files = _collect_files(vendor_directory, errors)
    expected_local_files = set(manifest) | set(LOCAL_METADATA)
    for relative in sorted(expected_local_files - local_files):
        errors.append(f"vendored source is missing required file: {relative}")
    for relative in sorted(local_files - expected_local_files):
        errors.append(f"vendored source has untracked file: {relative}")

    payload = download_payload or _download_module(root, errors)
    if payload is None:
        return errors
    expected_fields = {
        "Path": MODULE,
        "Version": VERSION,
        "Sum": EXPECTED_SUM,
        "GoModSum": EXPECTED_GO_MOD_SUM,
    }
    for field, expected in expected_fields.items():
        if payload.get(field) != expected:
            errors.append(
                f"upstream {field} must be {expected!r}, got {payload.get(field)!r}"
            )
    origin = payload.get("Origin")
    if not isinstance(origin, dict) or origin.get("Hash") != EXPECTED_COMMIT:
        actual_commit = origin.get("Hash") if isinstance(origin, dict) else None
        errors.append(
            f"upstream commit must be {EXPECTED_COMMIT}, got {actual_commit!r}"
        )
    upstream_text = payload.get("Dir")
    if not isinstance(upstream_text, str) or not upstream_text:
        errors.append("upstream module directory is missing")
        return errors
    upstream_directory = Path(upstream_text)
    if not upstream_directory.is_dir() or upstream_directory.is_symlink():
        errors.append("upstream module directory must be a real directory")
        return errors

    for relative, expected_hash in sorted(manifest.items()):
        local_file = vendor_directory / relative
        upstream_file = upstream_directory / relative
        if not local_file.is_file() or local_file.is_symlink():
            continue
        if not upstream_file.is_file() or upstream_file.is_symlink():
            errors.append(f"upstream module is missing regular file: {relative}")
            continue
        try:
            local_hash = _hash_file(local_file)
            upstream_hash = _hash_file(upstream_file)
            local_executable = stat.S_IMODE(local_file.stat().st_mode) & 0o111
            upstream_executable = stat.S_IMODE(upstream_file.stat().st_mode) & 0o111
        except OSError as error:
            errors.append(f"cannot verify vendored file {relative}: {error}")
            continue
        if local_hash != expected_hash:
            errors.append(
                f"vendored file does not match manifest: {relative} ({local_hash})"
            )
        if upstream_hash != expected_hash:
            errors.append(
                f"manifest does not match exact upstream: {relative} ({upstream_hash})"
            )
        if local_executable != upstream_executable:
            errors.append(f"vendored executable mode differs from upstream: {relative}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    arguments = parser.parse_args()
    errors = validate_vendor(arguments.root)
    if errors:
        for error in errors:
            print(f"runtime vendor policy: {error}", file=sys.stderr)
        return 1
    print(f"runtime vendor policy valid: {SELECTOR}, {len(_load_manifest(arguments.root / VENDOR_RELATIVE / MANIFEST_NAME, []))} retained files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
