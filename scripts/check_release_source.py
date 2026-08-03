#!/usr/bin/env python3
"""Require an exact clean Git revision before producing release artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys


REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def is_generated_release_output(path: bytes) -> bool:
    """Allow only the release output tree, which is never a Go build input."""
    return path == b"dist" or path.startswith(b"dist/")


def git(root: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(f"Git command failed: {detail or arguments[0]}")
    return completed.stdout


def validate_release_source(root: Path, revision: str) -> list[str]:
    errors: list[str] = []
    if not REVISION_PATTERN.fullmatch(revision):
        return ["source revision must be an exact lowercase 40-character Git commit ID"]
    try:
        canonical_root = root.resolve(strict=True)
    except OSError as error:
        return [f"release source root is unavailable: {error}"]

    try:
        top_level = Path(
            git(canonical_root, "rev-parse", "--show-toplevel")
            .decode("utf-8", errors="strict")
            .strip()
        ).resolve(strict=True)
        head = (
            git(canonical_root, "rev-parse", "--verify", "HEAD")
            .decode("ascii", errors="strict")
            .strip()
        )
        status = git(
            canonical_root,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        )
        ignored = git(
            canonical_root,
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "-z",
        )
    except (OSError, UnicodeError, ValueError) as error:
        return [str(error)]

    if top_level != canonical_root:
        errors.append("release source root must be the exact Git worktree root")
    if head != revision:
        errors.append(f"release source HEAD {head!r} does not match {revision!r}")
    if status:
        entries = [item for item in status.split(b"\0") if item]
        errors.append(f"release source worktree is not clean ({len(entries)} status entries)")
    ignored_inputs = [
        item
        for item in ignored.split(b"\0")
        if item and not is_generated_release_output(item)
    ]
    if ignored_inputs:
        errors.append(
            "release source worktree contains ignored inputs "
            f"({len(ignored_inputs)} ignored entries outside dist/)"
        )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--revision", required=True)
    args = parser.parse_args(argv)

    errors = validate_release_source(args.root, args.revision)
    if errors:
        for error in errors:
            print(f"release source: {error}", file=sys.stderr)
        return 1
    print(f"release source: exact clean revision {args.revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
