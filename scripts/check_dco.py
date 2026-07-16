#!/usr/bin/env python3
"""Verify that every commit in a Git range has a matching DCO sign-off."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SIGNOFF_RE = re.compile(
    r"^Signed-off-by:\s*(?P<name>.+?)\s*<(?P<email>[^<>\s]+)>\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def _git(repo: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _signoff_trailers(
    repo: Path, message: str
) -> tuple[list[dict[str, str]], str | None]:
    parsed = subprocess.run(
        ["git", "interpret-trailers", "--parse"],
        cwd=repo,
        check=False,
        input=message,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if parsed.returncode != 0:
        detail = parsed.stderr.strip() or f"exit status {parsed.returncode}"
        return [], detail
    return [match.groupdict() for match in SIGNOFF_RE.finditer(parsed.stdout)], None


def _identity_matches(
    signoff_name: str,
    signoff_email: str,
    identities: tuple[tuple[str, str], ...],
) -> bool:
    normalized_name = " ".join(signoff_name.split()).casefold()
    normalized_email = signoff_email.strip().casefold()
    return any(
        normalized_name == " ".join(name.split()).casefold()
        and normalized_email == email.strip().casefold()
        for name, email in identities
    )


def check_range(repo: Path, base: str, head: str) -> list[str]:
    """Return DCO violations for commits reachable from head but not base."""

    repo = repo.resolve()
    errors: list[str] = []
    revision_range = f"{base}..{head}"
    revisions = _git(repo, "rev-list", "--reverse", revision_range)
    if revisions.returncode != 0:
        detail = revisions.stderr.strip() or f"exit status {revisions.returncode}"
        return [f"cannot enumerate {revision_range}: {detail}"]

    commits = [line for line in revisions.stdout.splitlines() if line]
    if not commits:
        return [f"range {revision_range} contains no commits"]

    for commit in commits:
        details = _git(
            repo,
            "show",
            "-s",
            "--format=%an%x00%ae%x00%cn%x00%ce%x00%B",
            commit,
        )
        if details.returncode != 0:
            detail = details.stderr.strip() or f"exit status {details.returncode}"
            errors.append(f"{commit}: cannot read commit: {detail}")
            continue
        fields = details.stdout.split("\0", 4)
        if len(fields) != 5:
            errors.append(f"{commit}: malformed Git metadata")
            continue
        author_name, author_email, committer_name, committer_email, message = fields
        identities = (
            (author_name, author_email),
            (committer_name, committer_email),
        )
        signoffs, trailer_error = _signoff_trailers(repo, message)
        if trailer_error is not None:
            errors.append(f"{commit}: cannot parse commit trailers: {trailer_error}")
            continue
        if not signoffs:
            errors.append(
                f"{commit}: missing Signed-off-by trailer for "
                f"{author_name} <{author_email}>"
            )
            continue
        if not any(
            _identity_matches(item["name"], item["email"], identities)
            for item in signoffs
        ):
            errors.append(
                f"{commit}: no Signed-off-by trailer matches the author or "
                "committer identity"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="base commit SHA or ref")
    parser.add_argument("--head", required=True, help="head commit SHA or ref")
    parser.add_argument(
        "--repo",
        type=Path,
        default=ROOT,
        help="Git repository to inspect (defaults to this repository)",
    )
    args = parser.parse_args(argv)

    errors = check_range(args.repo, args.base, args.head)
    if errors:
        for error in errors:
            print(f"DCO check: {error}", file=sys.stderr)
        return 1
    print(f"DCO check: all commits in {args.base}..{args.head} are signed off")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
