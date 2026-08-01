#!/usr/bin/env python3
"""Verify the frozen Task 2.0 profile and its independent crypto KATs."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "protocol/v1/fixtures/crypto-review-vectors.json"
ENVELOPE_PATH = ROOT / "protocol/v1/fixtures/vault-envelope.json"
PROFILE_PATH = ROOT / "protocol/v1/conformance/approved-profile.json"
EVIDENCE_PATH = ROOT / "protocol/v1/conformance/kat-evidence.json"
APPROVED_COMMIT = "1a4951947efbef1827b1fcba4be89a7781405c5d"
APPROVED_BASE_COMMIT = "5cbd584d4ef32c3c213a95944db132eec8e8257f"
APPROVED_ON = "2026-08-01"
APPROVAL_EVIDENCE = (
    "https://github.com/kciceblue/sshserver/pull/6#issuecomment-5150051992"
)
APPROVAL_SCOPE = (
    "P1-P6 protocol, Crypto, Keychain, Network Extension, and canonical "
    "software-identity fingerprint profile"
)
PROFILE_RULE = (
    "The approval commit hashes remain historical anchors. The post-approval "
    "transition changes only approval/evidence status and the reviewed crypto "
    "outputs; proposed_suite, inputs, proposed_argon2id, and every behavioral "
    "machine-readable value remain unchanged. Post-approval artifacts are then "
    "frozen by exact hash."
)
FIXTURE_RELATIVE_PATH = "protocol/v1/fixtures/crypto-review-vectors.json"
ENVELOPE_RELATIVE_PATH = "protocol/v1/fixtures/vault-envelope.json"
GO_IMPLEMENTATION_PATH = "conformance/go/main.go"
SWIFT_IMPLEMENTATION_PATH = "conformance/swift/CryptoKAT.swift"
CHECKER_PATH = "scripts/check_crypto_kats.py"
GO_PROVIDER = "golang.org/x/crypto@v0.54.0"
SWIFT_PROVIDER = "CryptoKit + independent HChaCha20 + OpenSSL 3.6.3 Argon2id"
OPENSSL_VERSION = (
    "OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)"
)
APPROVED_CRYPTO_INPUT_SHA256 = (
    "ca6ae94cb8fc8ca110f650fecddcb5764ba5636de61cd1a791499060a774c1f0"
)
REVIEWED_OUTPUT_SHA256 = (
    "da0c40c70d2527025e804cd7d819135929a71eacbcfe50368d2f2d7fafb1d4d7"
)
APPROVED_TEXT_TRANSITION_SHA256 = (
    "596299081247a245797dc3b49def42a2b37662b5de01ca06ec503665d5644b77"
)
TEXT_PROFILE_PATHS = frozenset(
    {"DECISIONS.md", "SYNC-PROTOCOL.md", "docs/THREAT-MODEL.md"}
)
APPROVED_FILE_PATHS = TEXT_PROFILE_PATHS | {FIXTURE_RELATIVE_PATH}
MACHINE_TRANSITIONS: dict[str, tuple[tuple[str, ...], ...]] = {
    "protocol/v1/fixtures/api-and-recovery.json": (("status",),),
    "protocol/v1/fixtures/device-lifecycle.json": (("status",),),
    "protocol/v1/fixtures/enrollment.json": (("status",),),
    "protocol/v1/fixtures/forward-profile-validation.json": (("status",),),
    "protocol/v1/fixtures/full-snapshot-recovery.json": (("status",),),
    "protocol/v1/fixtures/host-loss-recovery.json": (("status",),),
    "protocol/v1/fixtures/known-host-public-key.json": (("status",),),
    "protocol/v1/fixtures/secure-enclave-identity.json": (("status",),),
    "protocol/v1/fixtures/server-persistence-boundary.json": (("status",),),
    "protocol/v1/fixtures/software-identity-keys.json": (("status",),),
    "protocol/v1/fixtures/sync-conflict.json": (("status",),),
    "protocol/v1/fixtures/tombstone-retirement.json": (("status",),),
    ENVELOPE_RELATIVE_PATH: (("status",), ("description",)),
    "protocol/v1/openapi.json": (("info", "version"), ("info", "description")),
    "protocol/v1/schemas/backup-manifest.schema.json": (),
    "protocol/v1/schemas/encrypted-payload.schema.json": (),
    "protocol/v1/schemas/wire.schema.json": (("description",),),
}
MACHINE_PROFILE_PATHS = frozenset(MACHINE_TRANSITIONS)
POST_APPROVAL_PATHS = MACHINE_PROFILE_PATHS | TEXT_PROFILE_PATHS | {"README.md"}
MACHINE_CURRENT_VALUES: dict[str, dict[tuple[str, ...], Any]] = {
    "protocol/v1/fixtures/api-and-recovery.json": {
        ("status",): "owner-approved-semantics"
    },
    "protocol/v1/fixtures/device-lifecycle.json": {
        ("status",): "owner-approved-semantics"
    },
    "protocol/v1/fixtures/enrollment.json": {
        ("status",): "owner-approved-shape-only"
    },
    "protocol/v1/fixtures/forward-profile-validation.json": {
        ("status",): "owner-approved-schema-semantics"
    },
    "protocol/v1/fixtures/full-snapshot-recovery.json": {
        ("status",): "owner-approved-semantics"
    },
    "protocol/v1/fixtures/host-loss-recovery.json": {
        ("status",): "owner-approved-semantics"
    },
    "protocol/v1/fixtures/known-host-public-key.json": {
        ("status",): "owner-approved-client-known-host-validation"
    },
    "protocol/v1/fixtures/secure-enclave-identity.json": {
        ("status",): "owner-approved-executable-public-only-secure-enclave-fixture"
    },
    "protocol/v1/fixtures/server-persistence-boundary.json": {
        ("status",): "owner-approved-semantics"
    },
    "protocol/v1/fixtures/software-identity-keys.json": {
        ("status",): "owner-approved-executable-software-identity-key-fixture"
    },
    "protocol/v1/fixtures/sync-conflict.json": {
        ("status",): "owner-approved-shape-only"
    },
    "protocol/v1/fixtures/tombstone-retirement.json": {
        ("status",): "owner-approved-semantics"
    },
    ENVELOPE_RELATIVE_PATH: {
        ("status",): "owner-approved-shape-only",
        (
            "description",
        ): "Approved envelope shape and generation/CAS cases. wrapped_vmk values "
        "remain shape placeholders; reviewed XChaCha20-Poly1305 outputs live in "
        "crypto-review-vectors.json.",
    },
    "protocol/v1/openapi.json": {
        ("info", "version"): "1.0.0",
        (
            "info",
            "description",
        ): "Owner-approved Task 2.0 API contract. It is reachable only through an "
        "SSH-forwarded loopback listener; runtime implementation and release "
        "evidence remain downstream tasks.",
    },
    "protocol/v1/schemas/backup-manifest.schema.json": {},
    "protocol/v1/schemas/encrypted-payload.schema.json": {},
    "protocol/v1/schemas/wire.schema.json": {
        (
            "description",
        ): "Owner-approved Task 2.0 wire schema; runtime implementation and release "
        "evidence remain downstream tasks."
    },
}
CRYPTO_ALLOWED_TRANSITIONS = (
    ("status",),
    ("description",),
    ("expected",),
    ("exit_condition",),
)
EXPECTED_FIELDS = frozenset(
    {
        "base_wrap_key_hex",
        "base_envelope_ad_hex",
        "base_wrapped_vmk_hex",
        "passphrase_material_hex",
        "passphrase_wrap_key_hex",
        "passphrase_wrapped_vmk_hex",
        "record_key_hex",
        "collection_witness_key_hex",
        "authorized_collection_witness_authenticator_base64url",
        "initial_live_record_ad_hex",
        "initial_live_record_ciphertext_hex",
        "authorized_superseding_record_ad_hex",
        "authorized_superseding_record_ciphertext_hex",
        "tampered_ad_result",
        "wrong_passphrase_result",
        "rewrap_preserves_vmk",
    }
)
PROFILE_INPUT_FIELDS = (
    "proposed_suite",
    "inputs",
    "proposed_argon2id",
)


class ConformanceError(RuntimeError):
    """A fail-closed conformance or evidence violation."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConformanceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_nonfinite(value: str) -> None:
    raise ConformanceError(f"non-finite JSON number: {value}")


def load_json_bytes(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ConformanceError(f"cannot load {label}: {error}") from error
    if not isinstance(value, dict):
        raise ConformanceError(f"{label} must contain a JSON object")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ConformanceError(
            f"cannot load {path.relative_to(ROOT)}: {error}"
        ) from error
    return load_json_bytes(payload, label=str(path.relative_to(ROOT)))


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as error:
        raise ConformanceError(f"cannot hash {path.relative_to(ROOT)}: {error}") from error


def relative_path(value: Any, *, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ConformanceError(f"{label} must be a non-empty repository-relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ConformanceError(f"{label} escapes the repository: {value}")
    resolved = (ROOT / path).resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError as error:
        raise ConformanceError(f"{label} escapes the repository: {value}") from error
    return resolved


def require_sha256(value: Any, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ConformanceError(f"{label} must be a lowercase SHA-256 digest")
    return value


def run_git(arguments: list[str], *, label: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise ConformanceError(f"cannot execute git for {label}: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ConformanceError(
            f"git failed for {label} with exit status {result.returncode}: {detail}"
        )
    return result.stdout


def git_show(commit: str, path: str) -> bytes:
    return run_git(["show", f"{commit}:{path}"], label=f"{commit}:{path}")


def require_exact_hash_map(
    raw_files: Any, *, label: str, expected_paths: frozenset[str]
) -> dict[str, str]:
    if not isinstance(raw_files, dict):
        raise ConformanceError(f"{label} must be an object")
    if frozenset(raw_files) != expected_paths:
        missing = sorted(expected_paths - frozenset(raw_files))
        extra = sorted(frozenset(raw_files) - expected_paths)
        raise ConformanceError(f"{label} path set changed; missing={missing}, extra={extra}")
    result: dict[str, str] = {}
    for raw_path, raw_digest in sorted(raw_files.items()):
        relative_path(raw_path, label=f"{label} path")
        result[raw_path] = require_sha256(
            raw_digest, label=f"{label}[{raw_path}]"
        )
    return result


def verify_hashed_files(raw_files: Any, *, label: str) -> None:
    if not isinstance(raw_files, dict) or not raw_files:
        raise ConformanceError(f"{label} must be a non-empty object")
    for raw_path, raw_digest in sorted(raw_files.items()):
        path = relative_path(raw_path, label=f"{label} path")
        expected = require_sha256(raw_digest, label=f"{label}[{raw_path}]")
        actual = sha256_path(path)
        if actual != expected:
            raise ConformanceError(
                f"{raw_path} changed after profile approval: expected {expected}, got {actual}"
            )


def replace_json_path(
    target: dict[str, Any], source: dict[str, Any], path: tuple[str, ...], *, label: str
) -> None:
    target_parent: Any = target
    source_parent: Any = source
    for component in path[:-1]:
        if not isinstance(target_parent, dict) or component not in target_parent:
            raise ConformanceError(f"{label} is missing current path {'/'.join(path)}")
        if not isinstance(source_parent, dict) or component not in source_parent:
            raise ConformanceError(f"{label} is missing approved path {'/'.join(path)}")
        target_parent = target_parent[component]
        source_parent = source_parent[component]
    final = path[-1]
    if not isinstance(target_parent, dict) or final not in target_parent:
        raise ConformanceError(f"{label} is missing current path {'/'.join(path)}")
    if not isinstance(source_parent, dict) or final not in source_parent:
        raise ConformanceError(f"{label} is missing approved path {'/'.join(path)}")
    target_parent[final] = copy.deepcopy(source_parent[final])


def json_path_value(target: dict[str, Any], path: tuple[str, ...], *, label: str) -> Any:
    value: Any = target
    for component in path:
        if not isinstance(value, dict) or component not in value:
            raise ConformanceError(f"{label} is missing path {'/'.join(path)}")
        value = value[component]
    return value


def verify_json_transition(
    *, path: str, approved_payload: bytes, allowed_paths: tuple[tuple[str, ...], ...]
) -> None:
    approved = load_json_bytes(approved_payload, label=f"approved {path}")
    current = load_json(ROOT / path)
    normalized_current = copy.deepcopy(current)
    for allowed_path in allowed_paths:
        replace_json_path(
            normalized_current,
            approved,
            allowed_path,
            label=path,
        )
    if normalized_current != approved:
        raise ConformanceError(
            f"{path} changed outside its explicit post-approval metadata transition"
        )


def immutable_profile(fixture: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in PROFILE_INPUT_FIELDS if field not in fixture]
    if missing:
        raise ConformanceError(f"crypto fixture is missing profile fields: {', '.join(missing)}")
    return {field: fixture[field] for field in PROFILE_INPUT_FIELDS}


def expected_outputs(fixture: dict[str, Any]) -> dict[str, Any]:
    expected = fixture.get("expected")
    if not isinstance(expected, dict):
        raise ConformanceError("crypto fixture expected value must be an object")
    actual_fields = frozenset(expected)
    if actual_fields != EXPECTED_FIELDS:
        missing = sorted(EXPECTED_FIELDS - actual_fields)
        extra = sorted(actual_fields - EXPECTED_FIELDS)
        raise ConformanceError(
            f"crypto fixture output fields changed; missing={missing}, extra={extra}"
        )
    if any(value is None for value in expected.values()):
        raise ConformanceError("crypto fixture still contains null expected outputs")
    if expected.get("tampered_ad_result") != "authentication_failed":
        raise ConformanceError("tampered associated data must fail authentication")
    if expected.get("wrong_passphrase_result") != "authentication_failed":
        raise ConformanceError("wrong passphrase must fail authentication")
    if expected.get("rewrap_preserves_vmk") is not True:
        raise ConformanceError("base/passphrase rewrap must preserve the exact VMK")
    return expected


def verify_evidence() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    fixture = load_json(FIXTURE_PATH)
    profile = load_json(PROFILE_PATH)
    evidence = load_json(EVIDENCE_PATH)

    profile_fields = {
        "schema_version",
        "status",
        "approved_on",
        "approved_commit",
        "approved_base_commit",
        "approval_evidence",
        "approval_scope",
        "approved_file_sha256",
        "approved_machine_artifact_sha256",
        "post_approval_protocol_artifact_sha256",
        "approved_text_transition_diff_sha256",
        "immutable_crypto_input_sha256",
        "profile_rule",
    }
    if set(profile) != profile_fields:
        raise ConformanceError("approved profile manifest field set changed")
    expected_profile_values = {
        "schema_version": 1,
        "status": "owner-approved",
        "approved_on": APPROVED_ON,
        "approved_commit": APPROVED_COMMIT,
        "approved_base_commit": APPROVED_BASE_COMMIT,
        "approval_evidence": APPROVAL_EVIDENCE,
        "approval_scope": APPROVAL_SCOPE,
        "profile_rule": PROFILE_RULE,
    }
    for field, expected_value in expected_profile_values.items():
        if profile.get(field) != expected_value:
            raise ConformanceError(f"approved profile {field} changed")

    run_git(
        ["cat-file", "-e", f"{APPROVED_COMMIT}^{{commit}}"],
        label="approved commit availability",
    )
    run_git(
        ["cat-file", "-e", f"{APPROVED_BASE_COMMIT}^{{commit}}"],
        label="approved base commit availability",
    )
    run_git(
        ["merge-base", "--is-ancestor", APPROVED_BASE_COMMIT, APPROVED_COMMIT],
        label="approved base ancestry",
    )
    run_git(
        ["merge-base", "--is-ancestor", APPROVED_COMMIT, "HEAD"],
        label="approved commit ancestry",
    )

    approved_file_hashes = require_exact_hash_map(
        profile.get("approved_file_sha256"),
        label="approved_file_sha256",
        expected_paths=APPROVED_FILE_PATHS,
    )
    approved_machine_hashes = require_exact_hash_map(
        profile.get("approved_machine_artifact_sha256"),
        label="approved_machine_artifact_sha256",
        expected_paths=MACHINE_PROFILE_PATHS,
    )
    for path, digest in sorted(
        {**approved_file_hashes, **approved_machine_hashes}.items()
    ):
        approved_payload = git_show(APPROVED_COMMIT, path)
        if sha256_bytes(approved_payload) != digest:
            raise ConformanceError(
                f"historical hash for {path} does not match approved commit"
            )

    post_approval_hashes = require_exact_hash_map(
        profile.get("post_approval_protocol_artifact_sha256"),
        label="post_approval_protocol_artifact_sha256",
        expected_paths=POST_APPROVAL_PATHS,
    )
    verify_hashed_files(
        post_approval_hashes,
        label="post_approval_protocol_artifact_sha256",
    )

    for path, allowed_paths in sorted(MACHINE_TRANSITIONS.items()):
        verify_json_transition(
            path=path,
            approved_payload=git_show(APPROVED_COMMIT, path),
            allowed_paths=allowed_paths,
        )
        current_artifact = load_json(ROOT / path)
        for metadata_path, expected_value in MACHINE_CURRENT_VALUES[path].items():
            if (
                json_path_value(current_artifact, metadata_path, label=path)
                != expected_value
            ):
                raise ConformanceError(
                    f"{path} approval metadata {'/'.join(metadata_path)} changed"
                )
    verify_json_transition(
        path=FIXTURE_RELATIVE_PATH,
        approved_payload=git_show(APPROVED_COMMIT, FIXTURE_RELATIVE_PATH),
        allowed_paths=CRYPTO_ALLOWED_TRANSITIONS,
    )
    expected_crypto_metadata = {
        "status": "owner-approved-independent-swift-go-verified",
        "description": (
            "Tom approved the immutable construction inputs at commit "
            f"{APPROVED_COMMIT}. The expected values below were retained only "
            "after independent Swift and Go implementations agreed byte-for-byte."
        ),
        "exit_condition": (
            "Satisfied on 2026-08-01: every expected value is owner-reviewed and "
            "independently verified by Swift and Go; the initial-live input "
            "authorization remains intentionally null."
        ),
    }
    for field, expected_value in expected_crypto_metadata.items():
        if fixture.get(field) != expected_value:
            raise ConformanceError(f"crypto fixture approval metadata {field} changed")

    text_transition = run_git(
        [
            "diff",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--unified=3",
            APPROVED_COMMIT,
            "--",
            *sorted(TEXT_PROFILE_PATHS),
        ],
        label="approved text transition",
    )
    expected_text_transition_hash = require_sha256(
        profile.get("approved_text_transition_diff_sha256"),
        label="approved_text_transition_diff_sha256",
    )
    if sha256_bytes(text_transition) != expected_text_transition_hash:
        raise ConformanceError(
            "normative approval prose changed outside the reviewed transition"
        )
    if expected_text_transition_hash != APPROVED_TEXT_TRANSITION_SHA256:
        raise ConformanceError("reviewed normative prose transition digest changed")

    actual_profile_hash = sha256_bytes(canonical_bytes(immutable_profile(fixture)))
    recorded_profile_hash = require_sha256(
        profile.get("immutable_crypto_input_sha256"),
        label="immutable_crypto_input_sha256",
    )
    if recorded_profile_hash != APPROVED_CRYPTO_INPUT_SHA256:
        raise ConformanceError("reviewed immutable crypto-input digest changed")
    if actual_profile_hash != recorded_profile_hash:
        raise ConformanceError(
            "approved crypto inputs changed: "
            f"expected {recorded_profile_hash}, got {actual_profile_hash}"
        )
    evidence_fields = {
        "schema_version",
        "status",
        "approved_profile_commit",
        "approved_profile_manifest_sha256",
        "fixture",
        "fixture_sha256",
        "immutable_crypto_input_sha256",
        "expected_output_sha256",
        "implementations",
        "evidence_checker",
        "go_dependency_file_sha256",
        "openssl_provider",
        "negative_cases",
        "rewrap_preserves_vmk",
        "result",
    }
    if set(evidence) != evidence_fields:
        raise ConformanceError("KAT evidence field set changed")
    if evidence.get("schema_version") != 1 or evidence.get("status") != "verified":
        raise ConformanceError("KAT evidence is not verified schema version 1")
    if evidence.get("approved_profile_commit") != APPROVED_COMMIT:
        raise ConformanceError("KAT evidence does not reference the approved profile commit")
    if evidence.get("fixture") != FIXTURE_RELATIVE_PATH:
        raise ConformanceError("KAT evidence fixture path changed")
    if evidence.get("immutable_crypto_input_sha256") != recorded_profile_hash:
        raise ConformanceError("KAT evidence does not bind the approved crypto inputs")

    expected = expected_outputs(fixture)
    expected_hash = sha256_bytes(canonical_bytes(expected))
    if expected_hash != REVIEWED_OUTPUT_SHA256:
        raise ConformanceError("reviewed known-answer output digest changed")
    if evidence.get("expected_output_sha256") != expected_hash:
        raise ConformanceError("KAT evidence output digest does not match the fixture")
    if evidence.get("fixture_sha256") != sha256_path(FIXTURE_PATH):
        raise ConformanceError("KAT evidence does not match the committed crypto fixture")
    if evidence.get("approved_profile_manifest_sha256") != sha256_path(PROFILE_PATH):
        raise ConformanceError("KAT evidence does not match the approved profile manifest")

    implementations = evidence.get("implementations")
    if not isinstance(implementations, dict) or set(implementations) != {"go", "swift"}:
        raise ConformanceError("KAT evidence must contain exactly Go and Swift implementations")
    expected_implementations = {
        "go": (GO_IMPLEMENTATION_PATH, GO_PROVIDER),
        "swift": (SWIFT_IMPLEMENTATION_PATH, SWIFT_PROVIDER),
    }
    for name, implementation in implementations.items():
        if not isinstance(implementation, dict):
            raise ConformanceError(f"{name} implementation evidence must be an object")
        if set(implementation) != {"path", "source_sha256", "provider", "output_sha256"}:
            raise ConformanceError(f"{name} implementation evidence field set changed")
        expected_path, expected_provider = expected_implementations[name]
        if implementation.get("path") != expected_path:
            raise ConformanceError(f"{name} implementation path changed")
        if implementation.get("provider") != expected_provider:
            raise ConformanceError(f"{name} provider evidence changed")
        path = relative_path(implementation.get("path"), label=f"{name} implementation path")
        source_hash = require_sha256(
            implementation.get("source_sha256"),
            label=f"{name} source_sha256",
        )
        if sha256_path(path) != source_hash:
            raise ConformanceError(f"{name} implementation changed after evidence capture")
        if implementation.get("output_sha256") != expected_hash:
            raise ConformanceError(f"{name} output digest does not match the reviewed fixture")

    go_files = require_exact_hash_map(
        evidence.get("go_dependency_file_sha256"),
        label="go_dependency_file_sha256",
        expected_paths=frozenset({"go.mod", "go.sum"}),
    )
    verify_hashed_files(go_files, label="go_dependency_file_sha256")
    checker = evidence.get("evidence_checker")
    if not isinstance(checker, dict) or set(checker) != {"path", "source_sha256"}:
        raise ConformanceError("KAT evidence must bind its evidence checker")
    if checker.get("path") != CHECKER_PATH:
        raise ConformanceError("KAT evidence checker path changed")
    checker_path = relative_path(
        checker.get("path"), label="evidence checker path"
    )
    checker_hash = require_sha256(
        checker.get("source_sha256"), label="evidence checker source_sha256"
    )
    if sha256_path(checker_path) != checker_hash:
        raise ConformanceError("evidence checker changed after evidence capture")

    openssl = evidence.get("openssl_provider")
    expected_openssl = {
        "license": "Apache-2.0",
        "selection": "explicit JAT_OPENSSL_BIN or Homebrew openssl@3",
        "usage": "Swift Argon2id conformance only; not linked or redistributed",
        "version": OPENSSL_VERSION,
    }
    if openssl != expected_openssl:
        raise ConformanceError("OpenSSL provider evidence changed")
    expected_negative_cases = {
        "tampered_associated_data": expected["tampered_ad_result"],
        "wrong_passphrase": expected["wrong_passphrase_result"],
    }
    if evidence.get("negative_cases") != expected_negative_cases:
        raise ConformanceError("negative-case evidence differs from reviewed outputs")
    if evidence.get("rewrap_preserves_vmk") is not expected["rewrap_preserves_vmk"]:
        raise ConformanceError("rewrap evidence differs from reviewed output")
    if evidence.get("result") != "byte-for-byte-match":
        raise ConformanceError("KAT evidence does not record a byte-for-byte match")
    return fixture, profile, evidence


def run_json_command(
    command: list[str],
    *,
    label: str,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
    except OSError as error:
        raise ConformanceError(f"cannot execute {label}: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ConformanceError(
            f"{label} failed with exit status {result.returncode}: {detail}"
        )
    try:
        value = json.loads(
            result.stdout,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite,
        )
    except json.JSONDecodeError as error:
        raise ConformanceError(f"{label} emitted invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise ConformanceError(f"{label} must emit one JSON object")
    return value


def go_kat_output() -> dict[str, Any]:
    fixture_argument = str(FIXTURE_PATH.relative_to(ROOT))
    envelope_argument = str(ENVELOPE_PATH.relative_to(ROOT))
    return run_json_command(
        [
            "go",
            "run",
            "-mod=readonly",
            "./conformance/go",
            fixture_argument,
            envelope_argument,
        ],
        label="independent Go KAT",
    )


def resolve_openssl() -> str:
    candidate = os.environ.get("JAT_OPENSSL_BIN")
    if candidate is None:
        try:
            prefix = subprocess.run(
                ["brew", "--prefix", "openssl@3"],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as error:
            raise ConformanceError(
                "JAT_OPENSSL_BIN is unset and Homebrew is unavailable: "
                f"{error}"
            ) from error
        if prefix.returncode != 0:
            detail = prefix.stderr.strip() or f"exit status {prefix.returncode}"
            raise ConformanceError(
                "JAT_OPENSSL_BIN is unset and `brew --prefix openssl@3` failed: "
                f"{detail}"
            )
        candidate = str(Path(prefix.stdout.strip()) / "bin/openssl")
    path = Path(candidate)
    if not path.is_absolute() or not path.is_file():
        raise ConformanceError(
            "JAT_OPENSSL_BIN must name an existing absolute OpenSSL executable"
        )
    try:
        version = subprocess.run(
            [str(path), "version"],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as error:
        raise ConformanceError(f"cannot execute reviewed OpenSSL: {error}") from error
    if version.returncode != 0:
        detail = version.stderr.strip() or f"exit status {version.returncode}"
        raise ConformanceError(f"reviewed OpenSSL version check failed: {detail}")
    if version.stdout.strip() != OPENSSL_VERSION:
        raise ConformanceError(
            "OpenSSL provider version changed: "
            f"expected {OPENSSL_VERSION!r}, got {version.stdout.strip()!r}"
        )
    return str(path)


def swift_kat_output() -> dict[str, Any]:
    fixture_argument = str(FIXTURE_PATH.relative_to(ROOT))
    envelope_argument = str(ENVELOPE_PATH.relative_to(ROOT))
    environment = os.environ.copy()
    environment["JAT_OPENSSL_BIN"] = resolve_openssl()
    return run_json_command(
        [
            "swift",
            "conformance/swift/CryptoKAT.swift",
            fixture_argument,
            envelope_argument,
        ],
        label="independent Swift KAT",
        environment=environment,
    )


def verify_runner_output(
    output: dict[str, Any], expected: dict[str, Any], *, label: str
) -> bytes:
    if frozenset(output) != EXPECTED_FIELDS:
        raise ConformanceError(f"{label} output field set changed")
    if output != expected:
        raise ConformanceError(f"{label} output differs from committed reviewed values")
    return canonical_bytes(output)


def run_go_kat() -> None:
    fixture, _, _ = verify_evidence()
    expected = expected_outputs(fixture)
    output = go_kat_output()
    output_bytes = verify_runner_output(output, expected, label="Go KAT")
    print(
        "crypto Go KAT: valid "
        f"(16 outputs, sha256 {sha256_bytes(output_bytes)}, Go == fixture)"
    )


def run_kats() -> None:
    fixture, _, _ = verify_evidence()
    expected = expected_outputs(fixture)
    go_output = go_kat_output()
    swift_output = swift_kat_output()
    go_bytes = verify_runner_output(go_output, expected, label="Go KAT")
    swift_bytes = verify_runner_output(swift_output, expected, label="Swift KAT")
    if go_bytes != swift_bytes:
        raise ConformanceError("independent Swift and Go outputs differ byte-for-byte")
    print(
        "crypto KATs: valid "
        f"(16 outputs, sha256 {sha256_bytes(go_bytes)}, Swift == Go == fixture)"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--run",
        action="store_true",
        help="execute both independent implementations and compare their output",
    )
    mode.add_argument(
        "--run-go",
        action="store_true",
        help="execute the Go implementation and compare it with reviewed outputs",
    )
    mode.add_argument(
        "--verify-evidence",
        action="store_true",
        help="verify committed hashes and evidence without requiring Swift",
    )
    args = parser.parse_args(argv)
    try:
        if args.run:
            run_kats()
        elif args.run_go:
            run_go_kat()
        else:
            verify_evidence()
            print("crypto KAT evidence: valid (approved profile and frozen artifacts match)")
    except ConformanceError as error:
        print(f"crypto KAT evidence: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
