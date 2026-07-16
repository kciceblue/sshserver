#!/usr/bin/env python3
"""Fail closed when dependencies escape the repository license inventory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_NAME = "DEPENDENCIES.json"
ALLOWED_LICENSES = frozenset(
    {"Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MIT"}
)
ALLOWED_MANIFESTS = frozenset({"go.mod", "go.sum"})
KNOWN_MANIFESTS = frozenset(
    {
        "Cargo.lock",
        "Cargo.toml",
        "Cartfile",
        "Cartfile.resolved",
        "Gemfile",
        "Gemfile.lock",
        "Package.resolved",
        "Package.swift",
        "Podfile",
        "Podfile.lock",
        "go.mod",
        "go.sum",
        "package-lock.json",
        "package.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pyproject.toml",
        "requirements.txt",
        "uv.lock",
        "yarn.lock",
    }
)
USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^\s'\"#]+)", re.MULTILINE)


def _load_json(path: Path, errors: list[str]) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        errors.append(f"{path.name}: cannot load JSON: {error}")
        return None


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
    except ValueError:
        return False
    return True


def _parse_json_stream(payload: str, errors: list[str]) -> list[dict[str, Any]]:
    """Parse the concatenated JSON objects emitted by `go list -json`."""

    decoder = json.JSONDecoder()
    position = 0
    values: list[dict[str, Any]] = []
    while position < len(payload):
        while position < len(payload) and payload[position].isspace():
            position += 1
        if position == len(payload):
            break
        try:
            value, position = decoder.raw_decode(payload, position)
        except json.JSONDecodeError as error:
            errors.append(f"go module graph is not valid JSON: {error}")
            return []
        if not isinstance(value, dict):
            errors.append("go module graph contains a non-object value")
            continue
        values.append(value)
    return values


def _go_module_graph(root: Path, errors: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["go", "list", "-mod=readonly", "-m", "-json", "all"],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as error:
        errors.append(f"cannot execute `go list` for dependency discovery: {error}")
        return None
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit status {result.returncode}"
        errors.append(f"`go list -mod=readonly -m -json all` failed: {detail}")
        return None
    return result.stdout


def validate_repository(
    root: Path, *, go_modules_json: str | None = None
) -> list[str]:
    """Return policy violations for *root*; an empty result means success."""

    root = root.resolve()
    errors: list[str] = []
    inventory = _load_json(root / INVENTORY_NAME, errors)
    if not isinstance(inventory, dict):
        if inventory is not None:
            errors.append(f"{INVENTORY_NAME}: root value must be an object")
        return errors

    if inventory.get("schema_version") != 1:
        errors.append(f"{INVENTORY_NAME}: schema_version must be 1")
    if inventory.get("policy") != "go-modules-and-ci-actions":
        errors.append(
            f"{INVENTORY_NAME}: policy must be go-modules-and-ci-actions"
        )

    configured_allowlist = inventory.get("allowed_licenses")
    if (
        not isinstance(configured_allowlist, list)
        or set(configured_allowlist) != ALLOWED_LICENSES
        or len(configured_allowlist) != len(ALLOWED_LICENSES)
    ):
        errors.append(
            "allowed_licenses must be exactly Apache-2.0, BSD-2-Clause, "
            "BSD-3-Clause, ISC, and MIT"
        )

    raw_dependencies = inventory.get("dependencies")
    if not isinstance(raw_dependencies, list):
        errors.append(f"{INVENTORY_NAME}: dependencies must be an array")
        raw_dependencies = []

    dependencies: dict[str, dict[str, Any]] = {}
    third_party_directory = root / "ThirdPartyLicenses"
    for index, dependency in enumerate(raw_dependencies):
        label = f"dependency entry {index}"
        if not isinstance(dependency, dict):
            errors.append(f"{label} must be an object")
            continue

        selector = dependency.get("selector")
        name = dependency.get("name")
        usage = dependency.get("usage")
        license_id = dependency.get("license")
        if not isinstance(selector, str) or not selector.strip():
            errors.append(f"{label} has no non-empty selector")
            continue
        label = selector
        if selector in dependencies:
            errors.append(f"duplicate dependency selector: {selector}")
        else:
            dependencies[selector] = dependency
        if not isinstance(name, str) or not name.strip():
            errors.append(f"{label} has no non-empty name")
        if license_id not in ALLOWED_LICENSES:
            errors.append(
                f"{label} uses non-allowlisted license "
                f"{license_id if license_id else '<missing>'}"
            )
        if usage not in {"ci-action", "go-module"}:
            errors.append(f"{label} has unsupported usage {usage!r}")
            continue

        if usage == "go-module":
            module = dependency.get("module")
            version = dependency.get("version")
            license_file = dependency.get("license_file")
            if not isinstance(module, str) or not module.strip():
                errors.append(f"{label} has no non-empty module")
            if not isinstance(version, str) or not version.strip():
                errors.append(f"{label} has no non-empty version")
            if isinstance(module, str) and isinstance(version, str):
                expected_selector = f"{module}@{version}"
                if selector != expected_selector:
                    errors.append(
                        f"{label} selector must equal module@version "
                        f"({expected_selector})"
                    )
            if not isinstance(license_file, str) or not license_file.strip():
                errors.append(f"{label} has no license_file")
            else:
                path = root / license_file
                if not _inside(path, third_party_directory):
                    errors.append(
                        f"{label} license_file must be inside ThirdPartyLicenses"
                    )
                elif not path.is_file():
                    errors.append(f"{label} license_file does not exist: {license_file}")
                else:
                    try:
                        license_text = path.read_text(encoding="utf-8").strip()
                    except (OSError, UnicodeError) as error:
                        errors.append(f"{label} license_file is unreadable: {error}")
                    else:
                        if len(license_text) < 40:
                            errors.append(
                                f"{label} license_file is too short to be a full license"
                            )

    discovered_actions: set[str] = set()
    workflow_directory = root / ".github" / "workflows"
    workflows = sorted(
        path
        for path in workflow_directory.glob("*")
        if path.suffix in {".yml", ".yaml"}
    )
    for workflow in workflows:
        try:
            workflow_text = workflow.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            errors.append(f"{workflow.relative_to(root)} is unreadable: {error}")
            continue
        for selector in USES_RE.findall(workflow_text):
            if selector.startswith("./"):
                continue
            discovered_actions.add(selector)
            dependency = dependencies.get(selector)
            if dependency is None:
                errors.append(
                    f"{workflow.relative_to(root)} uses unlisted GitHub Action "
                    f"{selector}"
                )
            elif dependency.get("usage") != "ci-action":
                errors.append(f"{selector} is used as a CI action but inventoried otherwise")

    listed_actions = {
        selector
        for selector, dependency in dependencies.items()
        if dependency.get("usage") == "ci-action"
    }
    for selector in sorted(listed_actions - discovered_actions):
        errors.append(f"stale CI action inventory entry: {selector}")

    manifests = sorted(
        path.relative_to(root)
        for path in root.rglob("*")
        if path.is_file()
        and (
            path.name in KNOWN_MANIFESTS
            or path.name.startswith("requirements-")
            and path.suffix in {".in", ".txt"}
        )
        and ".git" not in path.parts
    )
    unsupported_manifests = [
        path for path in manifests if path.name not in ALLOWED_MANIFESTS
    ]
    if unsupported_manifests:
        errors.append(
            "unsupported dependency manifest(s) require a fail-closed parser "
            "before merge: " + ", ".join(map(str, unsupported_manifests))
        )
    if (root / "go.sum").exists() and not (root / "go.mod").is_file():
        errors.append("go.sum exists without go.mod")

    discovered_modules: set[str] = set()
    if (root / "go.mod").is_file():
        module_payload = (
            go_modules_json
            if go_modules_json is not None
            else _go_module_graph(root, errors)
        )
        if module_payload is not None:
            for module in _parse_json_stream(module_payload, errors):
                if module.get("Main") is True:
                    continue
                module_path = module.get("Path")
                version = module.get("Version") or "local"
                if not isinstance(module_path, str) or not module_path:
                    errors.append("go module graph contains a dependency without Path")
                    continue
                selector = f"{module_path}@{version}"
                if selector in discovered_modules:
                    errors.append(f"go module graph contains duplicate {selector}")
                    continue
                discovered_modules.add(selector)
                dependency = dependencies.get(selector)
                if dependency is None:
                    errors.append(f"unlisted Go module: {selector}")
                    continue
                if dependency.get("usage") != "go-module":
                    errors.append(
                        f"{selector} is used as a Go module but inventoried otherwise"
                    )
                replacement = module.get("Replace")
                if isinstance(replacement, dict):
                    replacement_path = replacement.get("Path")
                    replacement_version = replacement.get("Version") or "local"
                    expected_replacement = (
                        f"{replacement_path}@{replacement_version}"
                        if isinstance(replacement_path, str) and replacement_path
                        else None
                    )
                    if dependency.get("replacement") != expected_replacement:
                        errors.append(
                            f"{selector} replacement must be inventoried as "
                            f"{expected_replacement}"
                        )

    listed_modules = {
        selector
        for selector, dependency in dependencies.items()
        if dependency.get("usage") == "go-module"
    }
    for selector in sorted(listed_modules - discovered_modules):
        errors.append(f"stale Go module inventory entry: {selector}")

    try:
        notice_text = (root / "NOTICE").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        errors.append(f"NOTICE is missing or unreadable: {error}")
    else:
        for selector in sorted(listed_modules):
            module = dependencies[selector].get("module")
            if isinstance(module, str) and module not in notice_text:
                errors.append(f"NOTICE does not list Go module {module}")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="repository root (defaults to the script's parent repository)",
    )
    args = parser.parse_args(argv)

    errors = validate_repository(args.root)
    if errors:
        for error in errors:
            print(f"license policy: {error}", file=sys.stderr)
        return 1

    inventory = json.loads(
        (args.root / INVENTORY_NAME).read_text(encoding="utf-8")
    )
    dependencies = inventory["dependencies"]
    action_count = sum(item["usage"] == "ci-action" for item in dependencies)
    module_count = sum(item["usage"] == "go-module" for item in dependencies)
    print(
        "dependency license policy: valid "
        f"({module_count} Go modules, {action_count} CI actions)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
