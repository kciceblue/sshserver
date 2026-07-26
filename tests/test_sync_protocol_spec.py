from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import hmac
import json
from pathlib import Path
import re
import struct
import subprocess
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_ROOT = ROOT / "protocol" / "v1"
SCHEMA_ROOT = PROTOCOL_ROOT / "schemas"
FIXTURE_ROOT = PROTOCOL_ROOT / "fixtures"

EXPECTED_ROUTES = {
    "/v1/healthz",
    "/v1/capabilities",
    "/v1/enrollments",
    "/v1/vault-envelope",
    "/v1/sync",
    "/v1/snapshot-reads",
    "/v1/snapshot-reads/{snapshot_id}/pages",
    "/v1/devices",
    "/v1/devices/{device_id}/revoke",
    "/v1/device-token-rotations",
}
EXPECTED_SCOPES = [
    "devices:manage",
    "devices:read",
    "envelope:read",
    "envelope:write",
    "sync:read",
    "sync:write",
]
PAYLOAD_TYPES = {
    "host",
    "snippet",
    "forward_profile",
    "software_identity",
    "secure_enclave_identity",
    "known_host",
    "tombstone",
}
DEVICE_LOCAL_FIELDS = {
    "custody_generation",
    "custody_recovery",
    "identity_files",
    "session_logging_enabled",
    "store_epoch",
    "keychain_persistent_reference",
}
BACKUP_MANIFEST_PATHS = frozenset({"config.json", "instance-secret", "sync.db"})
ED25519_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
P256_SPKI_PREFIX = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d030107034200"
)
SNAPSHOT_REQUIRED_CAPABILITIES = [
    "authenticated-collection-frontiers-v2",
    "snapshot-collection-markers-v1",
    "snapshot-device-registry-v1",
    "snapshot-read-v1",
]


def read_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=reject_duplicate_keys)


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def assert_uuid_v4(test: unittest.TestCase, value: str) -> None:
    parsed = uuid.UUID(value)
    test.assertEqual(str(parsed), value)
    test.assertEqual(parsed.version, 4)
    test.assertIn(parsed.variant, (uuid.RFC_4122, "specified in RFC 4122"))


def decode_base64url(value: str) -> bytes:
    if "=" in value or re.search(r"[^A-Za-z0-9_-]", value):
        raise ValueError("not canonical unpadded base64url")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as error:
        raise ValueError("not canonical unpadded base64url") from error
    reencoded = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if reencoded != value:
        raise ValueError("not canonical unpadded base64url")
    return decoded


def lp(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def hkdf_sha256_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_sha256_expand_32(prk: bytes, info: bytes) -> bytes:
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def collection_witness_key(
    vmk: bytes,
    instance_id: str,
    vault_id: str,
    record_id: str,
    crypto_suite_id: int = 2,
) -> bytes:
    prk = hkdf_sha256_extract(uuid.UUID(record_id).bytes, vmk)
    info = (
        lp(b"JAT collection witness key v1")
        + struct.pack(">HH", 1, crypto_suite_id)
        + uuid.UUID(instance_id).bytes
        + uuid.UUID(vault_id).bytes
        + uuid.UUID(record_id).bytes
    )
    return hkdf_sha256_expand_32(prk, info)


def compute_collection_witness_authenticator(
    vmk: bytes,
    instance_id: str,
    vault_id: str,
    record_id: str,
    witness_revision_id: str,
    frontier: list[dict],
    crypto_suite_id: int = 2,
) -> bytes:
    vector = canonical_vector_map(frontier)
    vector_bytes = b"".join(
        uuid.UUID(device_id).bytes + struct.pack(">Q", counter)
        for device_id, counter in vector.items()
    )
    message = (
        lp(b"JAT collection witness authenticator v1")
        + struct.pack(">HH", 1, crypto_suite_id)
        + uuid.UUID(instance_id).bytes
        + uuid.UUID(vault_id).bytes
        + uuid.UUID(record_id).bytes
        + uuid.UUID(witness_revision_id).bytes
        + struct.pack(">H", len(vector))
        + vector_bytes
    )
    return hmac.new(
        collection_witness_key(
            vmk,
            instance_id,
            vault_id,
            record_id,
            crypto_suite_id,
        ),
        message,
        hashlib.sha256,
    ).digest()


def verify_marker_collection_witness_authenticator(
    marker: dict,
    vmk: bytes,
    instance_id: str,
    vault_id: str,
    crypto_suite_id: int = 2,
) -> None:
    supplied = decode_base64url(marker["collection_witness_authenticator"])
    if len(supplied) != 32:
        raise ValueError("collection witness authenticator must be exactly 32 bytes")
    expected = compute_collection_witness_authenticator(
        vmk,
        instance_id,
        vault_id,
        marker["record_id"],
        marker["witness_revision_id"],
        marker["frontier"],
        crypto_suite_id,
    )
    if not hmac.compare_digest(supplied, expected):
        raise ValueError("collection_witness_authenticator_mismatch")


def collection_witness_ad_component(authenticator: str | None) -> bytes:
    if authenticator is None:
        return b"\x00"
    decoded = decode_base64url(authenticator)
    if len(decoded) != 32:
        raise ValueError("collection witness authenticator must be exactly 32 bytes")
    return b"\x01" + decoded


def openssl_transform(arguments: list[str], input_bytes: bytes) -> bytes:
    """Run the Apache-2.0 OpenSSL CLI as an executable conformance parser."""
    try:
        result = subprocess.run(
            ["openssl", *arguments],
            check=False,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as error:
        raise RuntimeError("openssl is required for key fixture validation") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(detail or f"openssl exited with {result.returncode}")
    return result.stdout


def validate_software_identity_keypair(body: dict) -> None:
    """Enforce V1 kind/encoding, canonical parse, and key correspondence."""
    private_key = decode_base64url(body["private_key"])
    public_key = decode_base64url(body["public_key"])
    key_kind = body["key_kind"]

    if key_kind == "ed25519":
        if body["private_key_encoding"] != "ed25519-seed-v1":
            raise ValueError("wrong Ed25519 private-key encoding")
        if body["public_key_encoding"] != "ed25519-raw-v1":
            raise ValueError("wrong Ed25519 public-key encoding")
        if len(private_key) != 32 or len(public_key) != 32:
            raise ValueError("Ed25519 keys must each be exactly 32 bytes")
        public_spki = openssl_transform(
            ["pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
            ED25519_PKCS8_PREFIX + private_key,
        )
        if not public_spki.startswith(ED25519_SPKI_PREFIX):
            raise ValueError("unexpected Ed25519 SubjectPublicKeyInfo encoding")
        derived_public_key = public_spki[len(ED25519_SPKI_PREFIX) :]
        if len(derived_public_key) != 32 or derived_public_key != public_key:
            raise ValueError("Ed25519 public key does not match private seed")
        return

    if key_kind == "rsa":
        if body["private_key_encoding"] != "rsa-pkcs8-der-v1":
            raise ValueError("wrong RSA private-key encoding")
        if body["public_key_encoding"] != "rsa-pkcs1-der-v1":
            raise ValueError("wrong RSA public-key encoding")
        if not private_key or not public_key:
            raise ValueError("RSA keys must be non-empty")

        openssl_transform(
            ["rsa", "-inform", "DER", "-check", "-noout"],
            private_key,
        )
        canonical_private = openssl_transform(
            [
                "pkcs8",
                "-topk8",
                "-nocrypt",
                "-inform",
                "DER",
                "-outform",
                "DER",
            ],
            private_key,
        )
        if canonical_private != private_key:
            raise ValueError("RSA private key is not canonical PKCS#8 DER")

        canonical_public = openssl_transform(
            [
                "rsa",
                "-RSAPublicKey_in",
                "-inform",
                "DER",
                "-RSAPublicKey_out",
                "-outform",
                "DER",
            ],
            public_key,
        )
        if canonical_public != public_key:
            raise ValueError("RSA public key is not canonical PKCS#1 DER")

        derived_public_key = openssl_transform(
            ["rsa", "-inform", "DER", "-RSAPublicKey_out", "-outform", "DER"],
            private_key,
        )
        if derived_public_key != public_key:
            raise ValueError("RSA public key does not match private key")
        return

    raise ValueError(f"unsupported software identity key kind: {key_kind}")


def ssh_fingerprint_p256(public_key: bytes) -> str:
    def ssh_string(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    public_blob = (
        ssh_string(b"ecdsa-sha2-nistp256")
        + ssh_string(b"nistp256")
        + ssh_string(public_key)
    )
    digest = hashlib.sha256(public_blob).digest()
    return "SHA256:" + base64.b64encode(digest).rstrip(b"=").decode("ascii")


def validate_secure_enclave_public_key(body: dict) -> None:
    """Enforce the V1 canonical public-only Secure Enclave identity shape."""
    if body["key_kind"] != "secure_enclave_p256":
        raise ValueError("wrong Secure Enclave key kind")
    if body["public_key_encoding"] != "p256-x963-uncompressed-v1":
        raise ValueError("wrong Secure Enclave public-key encoding")
    public_key = decode_base64url(body["public_key"])
    if len(public_key) != 65 or public_key[0] != 0x04:
        raise ValueError("P-256 public key must be 65-byte uncompressed X9.63")
    spki = P256_SPKI_PREFIX + public_key
    canonical_spki = openssl_transform(
        ["pkey", "-pubin", "-inform", "DER", "-pubout", "-outform", "DER"],
        spki,
    )
    if canonical_spki != spki:
        raise ValueError("P-256 point is invalid or not canonically encoded")
    if ssh_fingerprint_p256(public_key) != body["fingerprint"]:
        raise ValueError("Secure Enclave public-key fingerprint mismatch")


def self_revocation_body_fingerprint(
    instance_id: str,
    vault_id: str,
    target_device_id: str,
    raw_body: bytes,
) -> bytes:
    return hashlib.sha256(
        lp(b"JAT self revocation body fingerprint v1")
        + uuid.UUID(instance_id).bytes
        + uuid.UUID(vault_id).bytes
        + uuid.UUID(target_device_id).bytes
        + lp(raw_body)
    ).digest()


def self_revocation_replay_outcome(case: dict) -> tuple[str, int]:
    exact = all(
        case[field]
        for field in (
            "same_endpoint",
            "same_token",
            "same_target_device",
            "same_header_request_id",
            "same_body_request_id",
            "same_exact_raw_body",
        )
    )
    if exact:
        return ("recorded_self_revocation_response", 200)
    return ("token_revoked", 401)


def parse_uint64(value: str) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise ValueError("not a canonical unsigned decimal string")
    parsed = int(value)
    if not 0 <= parsed <= (1 << 64) - 1:
        raise ValueError("outside uint64")
    return parsed


def canonical_vector_map(entries: list[dict]) -> dict[str, int]:
    if not entries:
        raise ValueError("empty vector or frontier")
    ids = [entry["device_id"] for entry in entries]
    uuid_keys = [uuid.UUID(device_id).bytes for device_id in ids]
    if uuid_keys != sorted(uuid_keys):
        raise ValueError("vector or frontier entries are not sorted")
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate device vector or frontier entry")
    counters = {
        entry["device_id"]: parse_uint64(entry["counter"])
        for entry in entries
    }
    if any(counter == 0 for counter in counters.values()):
        raise ValueError("zero vector or frontier component")
    return counters


def vector_map(revision: dict) -> dict[str, int]:
    return canonical_vector_map(revision["version_vector"])


def validate_revision_vector(revision: dict) -> dict[str, int]:
    author_counter = parse_uint64(revision["author_counter"])
    if author_counter == 0:
        raise ValueError("zero author counter")
    vector = vector_map(revision)
    if vector.get(revision["author_device_id"]) != author_counter:
        raise ValueError("author vector entry mismatch")
    return vector


def validate_snapshot_capability_declaration(request: dict) -> None:
    if request.get("required_capabilities") != SNAPSHOT_REQUIRED_CAPABILITIES:
        raise ValueError("unsupported_capability")


def snapshot_create_outcome(case: dict, limits: dict) -> tuple[str, int]:
    if case.get("same_device_and_request_id"):
        return ("existing_snapshot", 200)
    if (
        case["prior_unique_attempts_in_rolling_minute"]
        >= limits["max_snapshot_creates_per_minute_per_device"]
    ):
        return ("rate_limited", 429)
    if (
        case["active_snapshots_for_device"]
        >= limits["max_active_snapshots_per_device"]
        or case["active_snapshots_for_instance"]
        >= limits["max_active_snapshots_per_instance"]
        or case.get("active_metadata_bytes", 0)
        + case.get("candidate_metadata_bytes", 0)
        > limits["max_active_snapshot_metadata_bytes_per_instance"]
    ):
        return ("limit_exceeded", 413)
    return ("snapshot_created", 201)


def recorded_fixture_raw_page_bodies(pages: list[dict]) -> list[bytes]:
    """Return the raw request bodies recorded by the deterministic fixture."""
    return [
        json.dumps(
            page,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        for page in pages
    ]


def recovery_raw_bodies_sha256(raw_bodies: list[bytes]) -> str:
    digest = hashlib.sha256()
    for body in raw_bodies:
        body.decode("utf-8")
        digest.update(struct.pack(">Q", len(body)))
        digest.update(body)
    return digest.hexdigest()


def validate_recovery_manifest_pages(
    manifest: dict,
    pages: list[dict],
    raw_bodies: list[bytes],
) -> None:
    if len(raw_bodies) != len(pages):
        raise ValueError("raw request-body count mismatch")
    for page, raw_body in zip(pages, raw_bodies):
        parsed_body = json.loads(
            raw_body.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
        if parsed_body != page:
            raise ValueError("raw request-body semantic mismatch")
    expected_counts = {
        "page_count": len(pages),
        "revision_count": sum(len(page["revisions"]) for page in pages),
        "collection_marker_count": sum(
            len(page["collection_markers"]) for page in pages
        ),
        "source_device_count": sum(
            len(page["source_devices"]) for page in pages
        ),
    }
    for field, expected in expected_counts.items():
        if parse_uint64(manifest[field]) != expected:
            raise ValueError(f"{field} mismatch")
    if manifest["pages_sha256"] != recovery_raw_bodies_sha256(raw_bodies):
        raise ValueError("pages_sha256 mismatch")


def source_device_counter_map(entries: list[dict]) -> dict[str, int]:
    ids = [entry["device_id"] for entry in entries]
    uuid_keys = [uuid.UUID(device_id).bytes for device_id in ids]
    if uuid_keys != sorted(uuid_keys):
        raise ValueError("source device entries are not sorted")
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate source device entry")
    return {
        entry["device_id"]: parse_uint64(entry["max_author_counter"])
        for entry in entries
    }


def dominates(left: dict[str, int], right: dict[str, int]) -> bool:
    keys = set(left) | set(right)
    return all(left.get(key, 0) >= right.get(key, 0) for key in keys) and any(
        left.get(key, 0) > right.get(key, 0) for key in keys
    )


def should_emit_collection_witness_authenticator(
    tombstone: bool,
    revision_vector: list[dict],
    complete_durable_frontier: list[dict] | None,
) -> bool:
    if tombstone:
        return True
    if complete_durable_frontier is None:
        return False
    return dominates(
        canonical_vector_map(revision_vector),
        canonical_vector_map(complete_durable_frontier),
    )


def record_revision_ad(
    revision: dict,
    instance_id: str,
    vault_id: str,
    crypto_suite_id: int = 2,
) -> bytes:
    vector = canonical_vector_map(revision["version_vector"])
    vector_bytes = b"".join(
        uuid.UUID(device_id).bytes + struct.pack(">Q", counter)
        for device_id, counter in vector.items()
    )
    return (
        lp(b"JAT record revision AD v1")
        + struct.pack(">HH", 1, crypto_suite_id)
        + uuid.UUID(instance_id).bytes
        + uuid.UUID(vault_id).bytes
        + uuid.UUID(revision["record_id"]).bytes
        + uuid.UUID(revision["revision_id"]).bytes
        + uuid.UUID(revision["author_device_id"]).bytes
        + struct.pack(">Q", parse_uint64(revision["author_counter"]))
        + struct.pack(">H", parse_uint64(revision["payload_schema"]))
        + bytes([1 if revision["tombstone"] else 0])
        + struct.pack(">H", len(vector))
        + vector_bytes
        + collection_witness_ad_component(
            revision["collection_witness_authenticator"]
        )
    )


def marker_transition_outcome(
    current_marker: dict | None,
    proposed_marker: dict,
) -> str:
    if current_marker is None:
        return "create"
    if proposed_marker == current_marker:
        return "idempotent_no_cursor"
    current = canonical_vector_map(current_marker["frontier"])
    proposed = canonical_vector_map(proposed_marker["frontier"])
    if proposed == current:
        return "revision_equivocation"
    if dominates(proposed, current):
        return "replace_same_record_row"
    return "collection_ineligible"


def marker_covers_durable_frontier(
    marker: dict | None,
    durable_frontier: list[dict],
) -> bool:
    if marker is None:
        return False
    marker_vector = canonical_vector_map(marker["frontier"])
    checkpoint = canonical_vector_map(durable_frontier)
    return marker_vector == checkpoint or dominates(marker_vector, checkpoint)


def validate_backup_manifest_paths(
    manifest: dict,
    archive_members: list[str] | None = None,
) -> None:
    """Enforce the exact canonical V1 manifest and archive allowlist."""
    seen: set[str] = set()
    for item in manifest["files"]:
        path = item["path"]
        if path not in BACKUP_MANIFEST_PATHS:
            raise ValueError(f"noncanonical backup manifest path: {path}")
        if path in seen:
            raise ValueError(f"duplicate backup manifest path: {path}")
        seen.add(path)
    if seen != BACKUP_MANIFEST_PATHS:
        missing = ", ".join(sorted(BACKUP_MANIFEST_PATHS - seen))
        raise ValueError(f"missing backup manifest path: {missing}")
    if archive_members is None:
        return
    seen_archive_members: set[str] = set()
    for path in archive_members:
        if path not in BACKUP_MANIFEST_PATHS:
            raise ValueError(f"noncanonical backup archive member: {path}")
        if path in seen_archive_members:
            raise ValueError(f"duplicate backup archive member: {path}")
        seen_archive_members.add(path)
    if seen_archive_members != BACKUP_MANIFEST_PATHS:
        missing = ", ".join(sorted(BACKUP_MANIFEST_PATHS - seen_archive_members))
        raise ValueError(f"missing backup archive member: {missing}")


def schema_matches(
    value: object,
    schema: dict,
    root: dict,
    external_roots: dict[str, dict] | None = None,
) -> bool:
    reference = schema.get("$ref")
    if reference is not None:
        reference_root = root
        reference_fragment = reference
        if not reference.startswith("#/"):
            document, separator, fragment = reference.partition("#")
            if (
                not separator
                or external_roots is None
                or document not in external_roots
                or not fragment.startswith("/")
            ):
                raise ValueError(
                    f"external schema reference is unsupported: {reference}"
                )
            reference_root = external_roots[document]
            reference_fragment = f"#{fragment}"
        target: object = reference_root
        for component in reference_fragment.removeprefix("#/").split("/"):
            if not isinstance(target, dict):
                raise ValueError(f"invalid schema reference: {reference}")
            target = target[component.replace("~1", "/").replace("~0", "~")]
        if not isinstance(target, dict):
            raise ValueError(f"schema reference is not an object: {reference}")
        if not schema_matches(
            value,
            target,
            reference_root,
            external_roots,
        ):
            return False

    value_type = schema.get("type")
    type_matches = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "null": value is None,
    }
    if value_type is not None and not type_matches[value_type]:
        return False
    if "const" in schema and value != schema["const"]:
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    if "oneOf" in schema:
        if (
            sum(
                schema_matches(value, child, root, external_roots)
                for child in schema["oneOf"]
            )
            != 1
        ):
            return False
    if "allOf" in schema:
        if not all(
            schema_matches(value, child, root, external_roots)
            for child in schema["allOf"]
        ):
            return False
    if "if" in schema and schema_matches(
        value,
        schema["if"],
        root,
        external_roots,
    ):
        if "then" in schema and not schema_matches(
            value,
            schema["then"],
            root,
            external_roots,
        ):
            return False

    if isinstance(value, dict):
        required = set(schema.get("required", []))
        if not required.issubset(value):
            return False
        properties = schema.get("properties", {})
        for key, child in properties.items():
            if key in value and not schema_matches(
                value[key],
                child,
                root,
                external_roots,
            ):
                return False
        if schema.get("additionalProperties") is False:
            if not set(value).issubset(properties):
                return False
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            return False
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            return False
        if schema.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            return False
        if "items" in schema:
            if not all(
                schema_matches(item, schema["items"], root, external_roots)
                for item in value
            ):
                return False
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            return False
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            return False
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            return False
    return True


class SyncProtocolSpecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.protocol_text = (ROOT / "SYNC-PROTOCOL.md").read_text(encoding="utf-8")
        cls.threat_text = (ROOT / "docs" / "THREAT-MODEL.md").read_text(
            encoding="utf-8"
        )
        cls.openapi = read_json(PROTOCOL_ROOT / "openapi.json")
        cls.wire = read_json(SCHEMA_ROOT / "wire.schema.json")
        cls.payload = read_json(SCHEMA_ROOT / "encrypted-payload.schema.json")
        cls.backup_schema = read_json(SCHEMA_ROOT / "backup-manifest.schema.json")
        cls.fixtures = {
            path.name: read_json(path)
            for path in sorted(FIXTURE_ROOT.glob("*.json"))
        }

    def test_every_protocol_artifact_is_valid_duplicate_free_json(self) -> None:
        json_paths = sorted(PROTOCOL_ROOT.rglob("*.json"))
        self.assertGreaterEqual(len(json_paths), 10)
        for path in json_paths:
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertIsInstance(read_json(path), dict)

    def test_every_fixture_revision_and_marker_has_draft2_collection_witness_authenticator(self) -> None:
        revision_count = 0
        null_revision_authenticator_count = 0
        non_null_revision_authenticator_count = 0
        marker_count = 0

        def visit(value: object) -> None:
            nonlocal revision_count
            nonlocal null_revision_authenticator_count
            nonlocal non_null_revision_authenticator_count
            nonlocal marker_count
            if isinstance(value, dict):
                if {
                    "record_id",
                    "revision_id",
                    "version_vector",
                    "crypto_suite",
                }.issubset(value):
                    revision_count += 1
                    self.assertEqual(
                        value["crypto_suite"],
                        "jat-xchacha-hkdf-argon2id-draft2",
                    )
                    self.assertIn("collection_witness_authenticator", value)
                    authenticator = value["collection_witness_authenticator"]
                    if authenticator is None:
                        null_revision_authenticator_count += 1
                        self.assertFalse(value["tombstone"])
                    else:
                        non_null_revision_authenticator_count += 1
                        self.assertEqual(len(decode_base64url(authenticator)), 32)
                if {
                    "record_id",
                    "witness_revision_id",
                    "frontier",
                    "barrier_cursor",
                }.issubset(value):
                    marker_count += 1
                    self.assertEqual(
                        len(
                            decode_base64url(
                                value["collection_witness_authenticator"]
                            )
                        ),
                        32,
                    )
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        for fixture in self.fixtures.values():
            visit(fixture)
        self.assertGreaterEqual(revision_count, 8)
        self.assertGreaterEqual(null_revision_authenticator_count, 3)
        self.assertGreaterEqual(non_null_revision_authenticator_count, 5)
        self.assertGreaterEqual(marker_count, 4)

    def test_review_status_is_unambiguous_and_does_not_claim_approval(self) -> None:
        self.assertIn("not approved for implementation or release", self.protocol_text)
        self.assertIn("REVIEW-PENDING", self.protocol_text)
        self.assertIn("Tom review required", self.threat_text)
        self.assertNotIn("Tom approved", self.protocol_text)
        self.assertNotIn("Tom approved", self.threat_text)
        crypto = self.fixtures["crypto-review-vectors.json"]
        self.assertEqual(crypto["status"], "tom-review-required-no-expected-outputs")
        self.assertTrue(all(value is None for value in crypto["expected"].values()))
        self.assertIn("before removing review-pending status", crypto["exit_condition"])

    def test_locked_boundaries_and_key_quarantine_invariant_are_present(self) -> None:
        normalized_protocol = re.sub(r"\s+", " ", self.protocol_text)
        normalized_threat = re.sub(r"\s+", " ", self.threat_text)
        required_protocol_claims = (
            "Secure Enclave private key never leaves its device",
            "server performs no vault cryptography",
            "Ordinary SSH destinations remain agentless",
            "MUST NOT directly delete Keychain or Secure Enclave material",
            "preserves any local protected material as an orphan",
            "Corrupt, replayed, or conflicting sync data can never invoke a Keychain cleanup",
        )
        for claim in required_protocol_claims:
            with self.subTest(claim=claim):
                self.assertIn(claim, normalized_protocol)
        self.assertIn(
            "no server record, device token, remote tombstone, version vector, or encrypted payload can directly authorize Keychain cleanup",
            normalized_threat,
        )

    def test_public_draft_contains_no_private_product_or_infrastructure_details(self) -> None:
        public_text = self.protocol_text + self.threat_text
        for forbidden in (
            "YLJU8C8DN6",
            "Hengyu Xu",
            "Small Business Program",
            "/Users/",
            "bastion",
            "App Store Connect",
            "$1",
            "seven-day preview",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, public_text)

    def test_openapi_is_loopback_only_and_has_the_complete_v1_surface(self) -> None:
        self.assertEqual(self.openapi["openapi"], "3.1.0")
        self.assertEqual(set(self.openapi["paths"]), EXPECTED_ROUTES)
        server_urls = [server["url"] for server in self.openapi["servers"]]
        self.assertEqual(server_urls, ["http://127.0.0.1:37421"])
        rendered = json.dumps(self.openapi, sort_keys=True)
        self.assertNotIn("0.0.0.0", rendered)
        self.assertNotIn("https://", rendered)
        self.assertIn("SSH local forward", rendered)

        self.assertEqual(
            set(self.openapi["components"]["securitySchemes"]),
            {"deviceBearer", "enrollmentGrant"},
        )
        for route, operations in self.openapi["paths"].items():
            for method, operation in operations.items():
                with self.subTest(route=route, method=method):
                    self.assertIn("operationId", operation)
                    self.assertIn("responses", operation)
                    parameter_refs = {
                        item.get("$ref")
                        for item in operation.get("parameters", [])
                        if isinstance(item, dict)
                    }
                    self.assertIn("#/components/parameters/ProtocolVersion", parameter_refs)
                    self.assertIn("#/components/parameters/RequestID", parameter_refs)

        for route, operations in self.openapi["paths"].items():
            for method, operation in operations.items():
                statuses = set(operation["responses"])
                with self.subTest(route=route, method=method, contract="common-errors"):
                    self.assertTrue({"400", "426", "500"}.issubset(statuses))
                if operation.get("security") == [{"deviceBearer": []}]:
                    with self.subTest(route=route, method=method, contract="bearer-errors"):
                        self.assertTrue({"401", "403"}.issubset(statuses))

        revoke_statuses = set(
            self.openapi["paths"]["/v1/devices/{device_id}/revoke"]["post"]["responses"]
        )
        self.assertTrue({"404", "507"}.issubset(revoke_statuses))
        envelope_put_statuses = set(
            self.openapi["paths"]["/v1/vault-envelope"]["put"]["responses"]
        )
        self.assertIn("507", envelope_put_statuses)
        rotation_statuses = set(
            self.openapi["paths"]["/v1/device-token-rotations"]["post"]["responses"]
        )
        self.assertIn("403", rotation_statuses)
        enrollment_statuses = set(
            self.openapi["paths"]["/v1/enrollments"]["post"]["responses"]
        )
        self.assertIn("507", enrollment_statuses)
        snapshot_statuses = set(
            self.openapi["paths"]["/v1/snapshot-reads/{snapshot_id}/pages"]["post"]["responses"]
        )
        self.assertTrue({"404", "410"}.issubset(snapshot_statuses))
        snapshot_create_statuses = set(
            self.openapi["paths"]["/v1/snapshot-reads"]["post"]["responses"]
        )
        self.assertTrue({"413", "429"}.issubset(snapshot_create_statuses))

    def test_all_openapi_external_schema_references_resolve(self) -> None:
        references: list[str] = []

        def visit(value: object) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if key == "$ref" and isinstance(child, str) and not child.startswith("#"):
                        references.append(child)
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(self.openapi)
        self.assertTrue(references)
        for reference in references:
            with self.subTest(reference=reference):
                path_text, _, fragment = reference.partition("#")
                target = read_json(PROTOCOL_ROOT / path_text)
                if fragment:
                    current: object = target
                    for component in fragment.removeprefix("/").split("/"):
                        self.assertIsInstance(current, dict)
                        current = current[component.replace("~1", "/").replace("~0", "~")]

    def test_all_json_schema_external_references_resolve(self) -> None:
        for schema_path in sorted(SCHEMA_ROOT.glob("*.json")):
            schema = read_json(schema_path)
            references: list[str] = []

            def visit(value: object) -> None:
                if isinstance(value, dict):
                    for key, child in value.items():
                        if key == "$ref" and isinstance(child, str) and not child.startswith("#"):
                            references.append(child)
                        visit(child)
                elif isinstance(value, list):
                    for child in value:
                        visit(child)

            visit(schema)
            for reference in references:
                with self.subTest(schema=schema_path.name, reference=reference):
                    path_text, _, fragment = reference.partition("#")
                    target = read_json(schema_path.parent / path_text)
                    if fragment:
                        current: object = target
                        for component in fragment.removeprefix("/").split("/"):
                            self.assertIsInstance(current, dict)
                            current = current[component.replace("~1", "/").replace("~0", "~")]

    def test_wire_schema_has_strict_core_objects_and_stable_errors(self) -> None:
        defs = self.wire["$defs"]
        for name in (
            "record_revision",
            "vault_envelope",
            "device",
            "source_device_registry_entry",
            "enrollment_request",
            "sync_request",
            "sync_response",
            "snapshot_create_request",
            "snapshot_create_response",
            "snapshot_page_request",
            "snapshot_page_response",
            "host_recovery_manifest",
            "recovery_import_page",
            "error_response",
        ):
            with self.subTest(name=name):
                self.assertFalse(defs[name]["additionalProperties"])

        error_codes = set(
            defs["error_response"]["properties"]["error"]["properties"]["code"]["enum"]
        )
        for required in (
            "token_revoked",
            "generation_conflict",
            "generation_exhausted",
            "revision_equivocation",
            "cursor_expired",
            "unsupported_protocol",
            "zero_active_confirmation_required",
            "authenticated_device_mismatch",
            "device_not_found",
            "snapshot_expired",
            "snapshot_not_found",
            "stale_after_collection",
        ):
            self.assertIn(required, error_codes)
        self.assertEqual(error_codes, set(self.openapi["x-jat-error-status-map"]))
        advertised_statuses = {
            int(status)
            for operations in self.openapi["paths"].values()
            for operation in operations.values()
            for status in operation["responses"]
        }
        self.assertTrue(
            set(self.openapi["x-jat-error-status-map"].values()).issubset(
                advertised_statuses
            )
        )
        self.assertNotIn("restore_incompatible", error_codes)
        self.assertNotIn("unsupported_response_field", error_codes)
        self.assertEqual(self.openapi["x-jat-error-status-map"]["unsupported_protocol"], 426)
        self.assertEqual(self.openapi["x-jat-error-status-map"]["generation_exhausted"], 409)
        self.assertEqual(self.openapi["x-jat-error-status-map"]["server_cursor_exhausted"], 507)
        self.assertEqual(self.openapi["x-jat-error-status-map"]["device_not_found"], 404)
        self.assertEqual(
            self.openapi["x-jat-error-status-map"]["authenticated_device_mismatch"],
            403,
        )
        envelope_schema = defs["vault_envelope"]
        self.assertEqual(len(envelope_schema["allOf"]), 2)
        self.assertEqual(
            defs["record_revision"]["properties"]["author_counter"]["$ref"],
            "#/$defs/positive_uint64",
        )
        self.assertEqual(
            defs["vector_entry"]["properties"]["counter"]["$ref"],
            "#/$defs/positive_uint64",
        )
        for field_schema in (
            defs["record_revision"]["properties"]["version_vector"],
            defs["collection_marker"]["properties"]["frontier"],
        ):
            self.assertEqual(field_schema["minItems"], 1)
            self.assertTrue(field_schema["uniqueItems"])
        revision_authenticator_schema = defs["record_revision"]["properties"][
            "collection_witness_authenticator"
        ]
        self.assertEqual(
            revision_authenticator_schema["oneOf"][0],
            {"type": "null"},
        )
        revision_exact_shape = revision_authenticator_schema["oneOf"][1][
            "allOf"
        ][1]
        self.assertEqual(revision_exact_shape["minLength"], 43)
        self.assertEqual(revision_exact_shape["maxLength"], 43)
        marker_exact_shape = defs["collection_marker"]["properties"][
            "collection_witness_authenticator"
        ]["allOf"][1]
        self.assertEqual(marker_exact_shape["minLength"], 43)
        self.assertEqual(marker_exact_shape["maxLength"], 43)
        self.assertIn(
            "collection_witness_authenticator",
            defs["record_revision"]["required"],
        )
        self.assertEqual(
            set(defs["collection_marker"]["required"]),
            {
                "record_id",
                "witness_revision_id",
                "frontier",
                "collection_witness_authenticator",
                "barrier_cursor",
            },
        )

    def test_uint64_schema_and_semantic_parser_enforce_the_exact_maximum(self) -> None:
        pattern = re.compile(self.wire["$defs"]["uint64"]["pattern"])
        positive_pattern = re.compile(
            self.wire["$defs"]["positive_uint64"]["pattern"]
        )
        accepted = ("0", "1", "9999999999999999999", "18446744073709551615")
        rejected = (
            "",
            "00",
            "01",
            "-1",
            "18446744073709551616",
            "99999999999999999999",
            "184467440737095516150",
        )
        for value in accepted:
            with self.subTest(value=value, result="accepted"):
                self.assertIsNotNone(pattern.fullmatch(value))
                self.assertEqual(parse_uint64(value), int(value))
                if value == "0":
                    self.assertIsNone(positive_pattern.fullmatch(value))
                else:
                    self.assertIsNotNone(positive_pattern.fullmatch(value))
        for value in rejected:
            with self.subTest(value=value, result="rejected"):
                self.assertIsNone(pattern.fullmatch(value))
                with self.assertRaises(ValueError):
                    parse_uint64(value)
                self.assertIsNone(positive_pattern.fullmatch(value))

    def test_base64url_schema_and_semantic_parser_require_canonical_bits(
        self,
    ) -> None:
        pattern = re.compile(self.wire["$defs"]["base64url"]["pattern"])
        structurally_valid = (
            "",
            "AA",
            "AQ",
            "_w",
            "AAA",
            "AAE",
            "__8",
            "AAAA",
            "AAAAAA",
            "AAAAAAA",
            "AAAAAAAA",
        )
        structurally_invalid = ("A", "AAAAA", "AAAAAAAAA", "AA=", "AA+")
        noncanonical_trailing_bits = (
            "AB",
            "A_",
            "AAB",
            "AA_",
            "AAAAAB",
            "AAAAAAB",
        )
        for value in structurally_valid:
            with self.subTest(value=value, result="accepted"):
                self.assertIsNotNone(pattern.fullmatch(value))
                decoded = decode_base64url(value)
                self.assertEqual(
                    base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii"),
                    value,
                )
        for value in structurally_invalid:
            with self.subTest(value=value, result="rejected"):
                self.assertIsNone(pattern.fullmatch(value))
                with self.assertRaises(ValueError):
                    decode_base64url(value)
        for value in noncanonical_trailing_bits:
            with self.subTest(value=value, result="noncanonical-trailing-bits"):
                self.assertIsNotNone(pattern.fullmatch(value))
                with self.assertRaises(ValueError):
                    decode_base64url(value)
        self.assertIn(
            "strictly decode, re-encode without padding, and require byte-for-byte equality",
            self.wire["$defs"]["base64url"]["description"],
        )

    def test_enrollment_grant_is_consumed_once_but_exact_retry_returns_result(
        self,
    ) -> None:
        normalized_protocol = re.sub(r"\s+", " ", self.protocol_text)
        required_contract = (
            "The grant authorizes exactly one state-changing enrollment transaction.",
            "That first successful transaction consumes it.",
            "The server returns the recorded success without authorizing a second state change.",
        )
        for claim in required_contract:
            with self.subTest(claim=claim):
                self.assertIn(claim, normalized_protocol)
        self.assertNotIn(
            "is never accepted after its first successful transaction",
            normalized_protocol,
        )

        idempotency = self.fixtures["enrollment.json"]["idempotency"]
        self.assertTrue(idempotency["grant_consumed_after_success"])
        self.assertEqual(idempotency["byte_equivalent_retry_status"], 200)
        recovery = idempotency["lost_response_recovery"]
        self.assertEqual(recovery["lookup_before_insert"], "enrollment_id")
        self.assertTrue(recovery["retains_original_tuple"])
        self.assertTrue(recovery["requires_valid_replacement_grant_after_expiry"])
        self.assertEqual(recovery["original_did_not_commit_status"], 201)
        self.assertEqual(recovery["original_committed_status"], 200)
        self.assertEqual(recovery["original_committed_device_rows_created"], 0)
        self.assertEqual(recovery["original_committed_device_rows_updated"], 0)
        self.assertTrue(recovery["replacement_grant_consumed_on_success"])
        self.assertEqual(recovery["retained_id_mismatch_status"], 409)
        self.assertEqual(
            recovery["retained_id_mismatch_error"],
            "enrollment_replay_mismatch",
        )
        self.assertFalse(
            recovery["retained_id_mismatch_consumes_replacement_grant"]
        )
        enrollment_api = self.openapi["paths"]["/v1/enrollments"]["post"]
        self.assertIn("valid replacement grant", enrollment_api["description"])
        self.assertIn(
            "no device state change",
            enrollment_api["responses"]["200"]["description"],
        )
        for claim in (
            "The server consumes the replacement grant, associates its hash with that record, and returns the recorded original result with `200`",
            "it does not insert or update a device, change the active-device count, or reapply any enrollment side effect",
            "returns `enrollment_replay_mismatch` without consuming the replacement grant or changing state",
        ):
            with self.subTest(claim=claim):
                self.assertIn(claim, normalized_protocol)

    def test_enrollment_fixture_is_retry_safe_and_has_exact_sizes(self) -> None:
        fixture = self.fixtures["enrollment.json"]
        bootstrap = fixture["ssh_bootstrap"]
        request = fixture["request"]
        response = fixture["created_response"]
        for field in ("instance_id", "vault_id"):
            assert_uuid_v4(self, bootstrap[field])
        for field in ("enrollment_id", "device_id"):
            assert_uuid_v4(self, request[field])
        self.assertEqual(len(decode_base64url(bootstrap["instance_secret"])), 32)
        self.assertEqual(len(decode_base64url(bootstrap["enrollment_grant"])), 32)
        self.assertEqual(len(decode_base64url(request["device_token"])), 32)
        self.assertEqual(request["scopes"], EXPECTED_SCOPES)
        self.assertEqual(response["device"]["scopes"], EXPECTED_SCOPES)
        self.assertTrue(response["became_first_active_device"])
        self.assertEqual(fixture["idempotency"]["byte_equivalent_retry_status"], 200)
        self.assertEqual(
            fixture["idempotency"]["mismatched_tuple_error"],
            "enrollment_replay_mismatch",
        )
        self.assertTrue(fixture["idempotency"]["grant_consumed_after_success"])

    def test_envelope_fixture_enforces_modes_sizes_and_generation_cas(self) -> None:
        fixture = self.fixtures["vault-envelope.json"]
        base = fixture["base_mode"]["envelope"]
        protected = fixture["passphrase_rewrap"]["envelope"]
        for envelope in (base, protected):
            assert_uuid_v4(self, envelope["instance_id"])
            assert_uuid_v4(self, envelope["vault_id"])
            self.assertEqual(len(decode_base64url(envelope["hkdf_salt"])), 32)
            self.assertEqual(len(decode_base64url(envelope["nonce"])), 24)
            self.assertEqual(len(decode_base64url(envelope["wrapped_vmk"])), 48)
            parse_uint64(envelope["envelope_generation"])
            parse_uint64(envelope["instance_secret_generation"])
        self.assertEqual(base["mode"], "base")
        self.assertIsNone(base["argon2"])
        self.assertEqual(protected["mode"], "passphrase")
        self.assertEqual(len(decode_base64url(protected["argon2"]["salt"])), 16)
        self.assertEqual(protected["argon2"]["version"], 19)
        self.assertIn("version", self.wire["$defs"]["argon2_parameters"]["required"])
        self.assertEqual(
            {
                key: protected["argon2"][key]
                for key in ("memory_kib", "iterations", "parallelism", "output_length")
            },
            {"memory_kib": 65536, "iterations": 3, "parallelism": 1, "output_length": 32},
        )
        cases = {case["name"]: case for case in fixture["cases"]}
        self.assertEqual(cases["stale_writer"]["result"], "generation_conflict")
        self.assertEqual(cases["skip_generation"]["result"], "invalid_request")
        exhausted = cases["generation_exhausted"]
        self.assertEqual(
            parse_uint64(exhausted["stored_generation"]),
            (1 << 64) - 1,
        )
        self.assertEqual(
            exhausted["expected_generation"],
            exhausted["stored_generation"],
        )
        self.assertEqual(
            exhausted["new_generation"],
            exhausted["stored_generation"],
        )
        self.assertEqual(exhausted["result"], "generation_exhausted")
        self.assertEqual(exhausted["http_status"], 409)
        self.assertFalse(exhausted["retryable"])
        self.assertTrue(exhausted["checked_before_successor_and_cursor_capacity"])
        self.assertFalse(exhausted["state_mutated"])
        self.assertFalse(exhausted["cursor_consumed"])

        crypto = self.fixtures["crypto-review-vectors.json"]
        self.assertEqual(crypto["proposed_argon2id"]["version"], 19)
        self.assertEqual(crypto["inputs"]["protocol_major"], 1)
        self.assertEqual(crypto["inputs"]["crypto_suite_id"], 2)
        self.assertEqual(
            crypto["proposed_suite"],
            "jat-xchacha-hkdf-argon2id-draft2",
        )
        self.assertIn(
            "collection_witness_key_hex",
            crypto["expected"],
        )
        self.assertIn(
            "authorized_collection_witness_authenticator_base64url",
            crypto["expected"],
        )
        self.assertIn(
            "initial_live_record_ad_hex",
            crypto["expected"],
        )
        self.assertIn("authorized_superseding_record_ad_hex", crypto["expected"])
        self.assertTrue(all(value is None for value in crypto["expected"].values()))
        record_cases = crypto["inputs"]["record_cases"]
        initial_live = record_cases["initial_live_null_authorization"]
        self.assertEqual(initial_live["collection_witness_authenticator_kind"], 0)
        self.assertIsNone(initial_live["collection_witness_authenticator"])
        self.assertIsNone(initial_live["complete_durable_frontier_before_revision"])
        self.assertFalse(
            should_emit_collection_witness_authenticator(
                initial_live["tombstone"],
                initial_live["version_vector"],
                initial_live["complete_durable_frontier_before_revision"],
            )
        )
        authorized = record_cases["authorized_superseding_live"]
        self.assertEqual(authorized["collection_witness_authenticator_kind"], 1)
        self.assertTrue(
            should_emit_collection_witness_authenticator(
                authorized["tombstone"],
                authorized["version_vector"],
                authorized["complete_durable_frontier_before_revision"],
            )
        )
        for case in record_cases.values():
            self.assertEqual(len(bytes.fromhex(case["record_nonce_hex"])), 24)
        self.assertIn("version = 0x13 (decimal 19)", self.protocol_text)
        self.assertIn("u32be(argon2_version_or_zero)", self.protocol_text)
        plaintext = json.loads(bytes.fromhex(crypto["inputs"]["record_plaintext_utf8_hex"]))
        snippet = self.payload["$defs"]["snippet_payload"]
        required_body = set(self.payload["$defs"]["snippet_body"]["required"])
        self.assertEqual(plaintext["payload_version"], 1)
        self.assertEqual(plaintext["record_type"], snippet["properties"]["record_type"]["const"])
        self.assertEqual(set(plaintext["body"]), required_body)
        body = plaintext["body"]
        self.assertIsInstance(body["name"], str)
        self.assertGreaterEqual(len(body["name"]), 1)
        self.assertIsInstance(body["command"], str)
        self.assertGreaterEqual(len(body["command"]), 1)
        self.assertIsInstance(body["notes"], str)
        for field in ("created_at", "updated_at"):
            self.assertRegex(
                body[field],
                r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$",
            )

    def test_conflict_fixture_retains_concurrent_edit_delete_and_resolution_dominates(self) -> None:
        fixture = self.fixtures["sync-conflict.json"]
        first, second = fixture["concurrent_siblings"]
        resolution = fixture["resolution"]
        for revision in (first, second, resolution):
            self._assert_record_revision_shape(revision)

        first_vector = validate_revision_vector(first)
        second_vector = validate_revision_vector(second)
        resolution_vector = validate_revision_vector(resolution)
        self.assertFalse(dominates(first_vector, second_vector))
        self.assertFalse(dominates(second_vector, first_vector))
        self.assertTrue(dominates(resolution_vector, first_vector))
        self.assertTrue(dominates(resolution_vector, second_vector))
        self.assertFalse(first["tombstone"])
        self.assertTrue(second["tombstone"])
        self.assertTrue(fixture["projection_does_not_delete_sibling"])
        self.assertFalse(
            fixture["expected"]["remote_identity_tombstone_may_delete_keychain_material"]
        )
        self.assertEqual(
            fixture["expected"]["remote_identity_tombstone_local_key_action"],
            "unlink_shared_record_and_quarantine_local_key_as_orphan",
        )
        vector_validation = fixture["vector_validation"]
        self.assertEqual(
            vector_validation["canonical_order"],
            "strict_raw_uuid_bytes",
        )
        self.assertEqual(vector_validation["normal_upload_result"], "accepted")
        self.assertTrue(validate_revision_vector(first))
        structurally_rejected = {"empty_vector", "zero_component"}
        record_schema = self.wire["$defs"]["record_revision"]
        self.assertIsNone(first["collection_witness_authenticator"])
        self.assertTrue(schema_matches(first, record_schema, self.wire))
        missing_required_authenticator = copy.deepcopy(first)
        del missing_required_authenticator["collection_witness_authenticator"]
        self.assertFalse(
            schema_matches(missing_required_authenticator, record_schema, self.wire)
        )
        authorization = vector_validation["collection_witness_authorization"]
        self.assertTrue(
            authorization[
                "complete_durable_frontier_includes_all_verified_revisions_and_prior_marker"
            ]
        )
        self.assertFalse(
            authorization["acknowledgement_alone_discards_frontier_input"]
        )
        authorization_cases = {
            case["name"]: case for case in authorization["cases"]
        }
        self.assertEqual(
            set(authorization_cases),
            {
                "initial_live_revision",
                "incomparable_live_sibling",
                "stale_live_revision",
                "strictly_dominating_resolution",
                "tombstone_authorization_before_collection_eligibility",
            },
        )
        for name, case in authorization_cases.items():
            with self.subTest(collection_witness_authorization=name):
                should_emit = should_emit_collection_witness_authenticator(
                    case["tombstone"],
                    case["revision_vector"],
                    case["complete_durable_frontier"],
                )
                self.assertEqual(
                    should_emit,
                    case["collection_witness_authenticator"] is not None,
                )
        initial_ad = record_revision_ad(
            first,
            "00000000-0000-4000-8000-000000000001",
            "00000000-0000-4000-8000-000000000002",
        )
        self.assertEqual(initial_ad[-1:], b"\x00")
        illegally_tagged_initial = copy.deepcopy(first)
        illegally_tagged_initial["collection_witness_authenticator"] = (
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        tagged_initial_ad = record_revision_ad(
            illegally_tagged_initial,
            "00000000-0000-4000-8000-000000000001",
            "00000000-0000-4000-8000-000000000002",
        )
        self.assertEqual(tagged_initial_ad[-33:-32], b"\x01")
        self.assertNotEqual(initial_ad, tagged_initial_ad)
        self.assertEqual(
            authorization[
                "initial_live_null_replaced_with_resolution_tag_result"
            ],
            "aead_or_collection_witness_authenticator_mismatch",
        )
        self.assertEqual(
            {case["name"] for case in vector_validation["malformed_cases"]},
            {
                "empty_vector",
                "duplicate_device_different_counter",
                "out_of_order",
                "zero_component",
                "author_counter_mismatch",
            },
        )
        for case in vector_validation["malformed_cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(case["result"], "invalid_request")
                candidate = copy.deepcopy(first)
                candidate["version_vector"] = case["version_vector"]
                with self.assertRaises(ValueError):
                    validate_revision_vector(candidate)
                recovery_page = copy.deepcopy(
                    self.fixtures["host-loss-recovery.json"]["import_pages"][0]
                )
                recovery_revision = recovery_page["revisions"][0]
                recovery_revision["version_vector"] = case["version_vector"]
                with self.assertRaises(ValueError):
                    validate_revision_vector(recovery_revision)
                self.assertEqual(
                    schema_matches(candidate, record_schema, self.wire),
                    case["name"] not in structurally_rejected,
                )
        self.assertEqual(
            vector_validation["malformed_recovery_import_result"],
            "refuse_recovery_import",
        )
        canonical_marker = next(
            marker
            for page in self.fixtures["full-snapshot-recovery.json"]["pages"]
            for marker in page["response"]["collection_markers"]
        )
        self.assertEqual(
            vector_validation["normal_collection_marker_result"],
            "accepted",
        )
        self.assertTrue(canonical_vector_map(canonical_marker["frontier"]))
        marker_schema = self.wire["$defs"]["collection_marker"]
        null_marker_authenticator = copy.deepcopy(canonical_marker)
        null_marker_authenticator["collection_witness_authenticator"] = None
        self.assertFalse(
            schema_matches(null_marker_authenticator, marker_schema, self.wire)
        )
        self.assertEqual(
            authorization["marker_null_authenticator_result"],
            "invalid_request",
        )
        structurally_rejected_frontiers = {
            "empty_frontier",
            "zero_component_frontier",
        }
        recovery_marker_page = next(
            page
            for page in self.fixtures["host-loss-recovery.json"]["import_pages"]
            if page["collection_markers"]
        )
        self.assertEqual(
            {
                case["name"]
                for case in vector_validation["malformed_frontier_cases"]
            },
            {
                "empty_frontier",
                "duplicate_device_different_counter_frontier",
                "out_of_order_frontier",
                "zero_component_frontier",
            },
        )
        for case in vector_validation["malformed_frontier_cases"]:
            with self.subTest(frontier_case=case["name"]):
                self.assertEqual(case["result"], "invalid_request")
                marker = copy.deepcopy(canonical_marker)
                marker["frontier"] = case["frontier"]
                with self.assertRaises(ValueError):
                    canonical_vector_map(marker["frontier"])
                self.assertEqual(
                    schema_matches(marker, marker_schema, self.wire),
                    case["name"] not in structurally_rejected_frontiers,
                )
                recovery_page = copy.deepcopy(recovery_marker_page)
                recovery_marker = recovery_page["collection_markers"][0]
                recovery_marker["frontier"] = case["frontier"]
                with self.assertRaises(ValueError):
                    canonical_vector_map(recovery_marker["frontier"])

        runtime_vmk = bytes(range(32))
        runtime_instance = "00000000-0000-4000-8000-000000000001"
        runtime_vault = "00000000-0000-4000-8000-000000000002"
        authenticated_marker = copy.deepcopy(canonical_marker)
        authenticated_marker["collection_witness_authenticator"] = (
            base64.urlsafe_b64encode(
                compute_collection_witness_authenticator(
                    runtime_vmk,
                    runtime_instance,
                    runtime_vault,
                    authenticated_marker["record_id"],
                    authenticated_marker["witness_revision_id"],
                    authenticated_marker["frontier"],
                )
            )
            .rstrip(b"=")
            .decode("ascii")
        )
        verify_marker_collection_witness_authenticator(
            authenticated_marker,
            runtime_vmk,
            runtime_instance,
            runtime_vault,
        )
        self.assertEqual(
            len(
                decode_base64url(
                    authenticated_marker["collection_witness_authenticator"]
                )
            ),
            32,
        )

        smaller_frontier = copy.deepcopy(authenticated_marker)
        smaller_frontier["frontier"][0]["counter"] = "2"
        self.assertTrue(
            schema_matches(smaller_frontier, marker_schema, self.wire)
        )
        self.assertTrue(canonical_vector_map(smaller_frontier["frontier"]))
        with self.assertRaisesRegex(
            ValueError,
            "^collection_witness_authenticator_mismatch$",
        ):
            verify_marker_collection_witness_authenticator(
                smaller_frontier,
                runtime_vmk,
                runtime_instance,
                runtime_vault,
            )
        self.assertEqual(
            vector_validation[
                "smaller_structurally_valid_frontier_with_unchanged_authenticator_result"
            ],
            "collection_witness_authenticator_mismatch",
        )
        self.assertTrue(
            vector_validation[
                "non_null_collection_witness_authenticator_placeholder_is_not_reviewed_crypto_output"
            ]
        )

        resolution = fixture["resolution"]
        resolution_authenticator = base64.urlsafe_b64encode(
            compute_collection_witness_authenticator(
                runtime_vmk,
                runtime_instance,
                runtime_vault,
                resolution["record_id"],
                resolution["revision_id"],
                resolution["version_vector"],
            )
        ).rstrip(b"=").decode("ascii")
        initial_with_resolution_tag = {
            "record_id": first["record_id"],
            "witness_revision_id": first["revision_id"],
            "frontier": first["version_vector"],
            "collection_witness_authenticator": resolution_authenticator,
            "barrier_cursor": "1",
        }
        self.assertTrue(
            schema_matches(initial_with_resolution_tag, marker_schema, self.wire)
        )
        with self.assertRaisesRegex(
            ValueError,
            "^collection_witness_authenticator_mismatch$",
        ):
            verify_marker_collection_witness_authenticator(
                initial_with_resolution_tag,
                runtime_vmk,
                runtime_instance,
                runtime_vault,
            )

        mismatch_cases: list[tuple[str, dict, str, str, int]] = []
        wrong_record = copy.deepcopy(authenticated_marker)
        wrong_record["record_id"] = "00000000-0000-4000-8000-000000000032"
        mismatch_cases.append(
            (
                "record",
                wrong_record,
                runtime_instance,
                runtime_vault,
                2,
            )
        )
        wrong_witness = copy.deepcopy(authenticated_marker)
        wrong_witness["witness_revision_id"] = (
            "00000000-0000-4000-8000-000000000033"
        )
        mismatch_cases.append(
            (
                "witness",
                wrong_witness,
                runtime_instance,
                runtime_vault,
                2,
            )
        )
        shorter_vector = copy.deepcopy(authenticated_marker)
        shorter_vector["frontier"] = shorter_vector["frontier"][:1]
        mismatch_cases.append(
            (
                "vector_count",
                shorter_vector,
                runtime_instance,
                runtime_vault,
                2,
            )
        )
        wrong_tag = copy.deepcopy(authenticated_marker)
        wrong_tag["collection_witness_authenticator"] = (
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        mismatch_cases.extend(
            [
                (
                    "instance",
                    authenticated_marker,
                    "00000000-0000-4000-8000-000000000004",
                    runtime_vault,
                    2,
                ),
                (
                    "vault",
                    authenticated_marker,
                    runtime_instance,
                    "00000000-0000-4000-8000-000000000005",
                    2,
                ),
                (
                    "suite",
                    authenticated_marker,
                    runtime_instance,
                    runtime_vault,
                    1,
                ),
                (
                    "tag",
                    wrong_tag,
                    runtime_instance,
                    runtime_vault,
                    2,
                ),
            ]
        )
        for name, candidate, instance_id, vault_id, suite_id in mismatch_cases:
            with self.subTest(collection_witness_hmac_domain=name):
                with self.assertRaisesRegex(
                    ValueError,
                    "^collection_witness_authenticator_mismatch$",
                ):
                    verify_marker_collection_witness_authenticator(
                        candidate,
                        runtime_vmk,
                        instance_id,
                        vault_id,
                        suite_id,
                    )

        changed_barrier = copy.deepcopy(authenticated_marker)
        changed_barrier["barrier_cursor"] = "1"
        verify_marker_collection_witness_authenticator(
            changed_barrier,
            runtime_vmk,
            runtime_instance,
            runtime_vault,
        )
        durable_revision_frontier = copy.deepcopy(
            authenticated_marker["frontier"]
        )
        self.assertTrue(
            marker_covers_durable_frontier(
                authenticated_marker,
                durable_revision_frontier,
            )
        )
        older_valid_marker = copy.deepcopy(authenticated_marker)
        older_valid_marker["witness_revision_id"] = (
            "00000000-0000-4000-8000-000000000030"
        )
        older_valid_marker["frontier"][0]["counter"] = "2"
        older_valid_marker["collection_witness_authenticator"] = (
            base64.urlsafe_b64encode(
                compute_collection_witness_authenticator(
                    runtime_vmk,
                    runtime_instance,
                    runtime_vault,
                    older_valid_marker["record_id"],
                    older_valid_marker["witness_revision_id"],
                    older_valid_marker["frontier"],
                )
            )
            .rstrip(b"=")
            .decode("ascii")
        )
        verify_marker_collection_witness_authenticator(
            older_valid_marker,
            runtime_vmk,
            runtime_instance,
            runtime_vault,
        )
        self.assertFalse(
            marker_covers_durable_frontier(
                older_valid_marker,
                durable_revision_frontier,
            )
        )
        self.assertFalse(
            marker_covers_durable_frontier(None, durable_revision_frontier)
        )
        normalized_protocol = re.sub(r"\s+", " ", self.protocol_text)
        self.assertIn(
            "u8(collection_witness_authenticator_kind)",
            normalized_protocol,
        )
        self.assertIn(
            "The witness HMAC proves only that a VMK holder explicitly authorized that exact revision ID and vector",
            normalized_protocol,
        )

    def test_tombstone_fixture_requires_ack_retention_and_zero_device_freeze(self) -> None:
        fixture = self.fixtures["tombstone-retirement.json"]
        self.assertEqual(parse_uint64(fixture["tombstone"]["minimum_retention_seconds"]), 90 * 24 * 60 * 60)
        self.assertEqual(
            fixture["tombstone"]["retention_clock"],
            "durable_accumulated_daemon_monotonic_uptime",
        )
        states = {state["name"]: state for state in fixture["states"]}
        for state in states.values():
            parse_uint64(state["retention_age_seconds"])
        self.assertFalse(states["active_device_has_not_acknowledged"]["collection_eligible"])
        self.assertTrue(states["all_active_acknowledged_after_retirement"]["collection_eligible"])
        self.assertFalse(states["all_active_acknowledged_after_retirement"]["retired_device_id_reusable"])
        self.assertFalse(states["zero_active_devices_freezes_collection"]["collection_eligible"])
        barrier = fixture["acknowledgement_barrier"]
        later_states = {state["name"]: state for state in barrier["later_sibling_states"]}
        raised = later_states["later_concurrent_sibling_raises_barrier"]
        unresolved = later_states["sibling_acknowledged_but_conflict_unresolved"]
        waiting = later_states["resolution_not_fully_acknowledged"]
        resolved = later_states["resolution_fully_acknowledged"]
        self.assertEqual(parse_uint64(raised["barrier_cursor"]), 41)
        self.assertFalse(raised["collection_eligible"])
        self.assertFalse(unresolved["collection_eligible"])
        self.assertEqual(parse_uint64(waiting["barrier_cursor"]), 42)
        self.assertFalse(waiting["collection_eligible"])
        self.assertTrue(resolved["collection_eligible"])
        self.assertTrue(
            barrier["collection_requires_single_authenticated_witness"]
        )
        self.assertTrue(barrier["server_componentwise_join_for_marker_forbidden"])
        self.assertEqual(barrier["collection_marker_key"], ["record_id"])
        self.assertEqual(barrier["maximum_collection_markers_per_record"], 1)
        self.assertTrue(
            barrier["collection_marker_is_monotonic_exact_witness_certificate"]
        )
        self.assertIsNone(
            barrier["later_concurrent_sibling"][
                "collection_witness_authenticator"
            ]
        )
        self.assertEqual(
            len(
                decode_base64url(
                    barrier["dominating_resolution"][
                        "collection_witness_authenticator"
                    ]
                )
            ),
            32,
        )
        self_witness_collection = barrier[
            "sole_tombstone_self_witness_collection"
        ]
        self_witness_marker = self_witness_collection["marker"]
        self.assertEqual(
            self_witness_marker["witness_revision_id"],
            fixture["tombstone"]["revision_id"],
        )
        self.assertEqual(
            canonical_vector_map(self_witness_marker["frontier"]),
            canonical_vector_map(fixture["tombstone"]["vector"]),
        )
        self.assertEqual(
            self_witness_marker["collection_witness_authenticator"],
            fixture["tombstone"]["collection_witness_authenticator"],
        )
        self.assertTrue(self_witness_collection["candidate_bytes_removed"])
        self.assertTrue(
            self_witness_collection["marker_persists_after_candidate_removal"]
        )
        self.assertTrue(
            self_witness_collection[
                "later_strictly_dominating_witness_replaces_marker"
            ]
        )
        marker = barrier["collection_marker"]
        self.assertEqual(
            marker_transition_outcome(self_witness_marker, marker),
            "replace_same_record_row",
        )
        self.assertEqual(marker["barrier_cursor"], resolved["barrier_cursor"])
        self.assertEqual(
            marker["witness_revision_id"],
            barrier["dominating_resolution"]["revision_id"],
        )
        self.assertEqual(
            vector_map({"version_vector": marker["frontier"]}),
            vector_map({"version_vector": barrier["dominating_resolution"]["vector"]}),
        )
        self.assertEqual(
            marker["collection_witness_authenticator"],
            barrier["dominating_resolution"]["collection_witness_authenticator"],
        )
        unchanged_prune = barrier[
            "later_aged_candidate_prune_under_unchanged_marker"
        ]
        persisted_marker = unchanged_prune["persisted_marker"]
        now_eligible = unchanged_prune["now_eligible_candidate"]
        self.assertTrue(
            schema_matches(
                persisted_marker,
                self.wire["$defs"]["collection_marker"],
                self.wire,
            )
        )
        self.assertFalse(unchanged_prune["original_witness_revision_bytes_present"])
        self.assertTrue(
            dominates(
                canonical_vector_map(persisted_marker["frontier"]),
                canonical_vector_map(now_eligible["vector"]),
            )
        )
        self.assertTrue(
            unchanged_prune[
                "candidate_strictly_dominated_by_persisted_marker"
            ]
        )
        self.assertFalse(unchanged_prune["retained_witness_selected"])
        self.assertEqual(
            parse_uint64(
                unchanged_prune[
                    "barrier_recomputed_across_current_retained_revisions"
                ]
            ),
            61,
        )
        self.assertTrue(
            all(
                parse_uint64(cursor) >= 61
                for cursor in unchanged_prune["active_device_ack_cursors"]
            )
        )
        self.assertTrue(unchanged_prune["candidate_bytes_removed"])
        self.assertTrue(
            unchanged_prune["marker_tuple_byte_identical_after_prune"]
        )
        self.assertFalse(unchanged_prune["marker_change_cursor_consumed"])
        transitions = barrier["marker_transition_rules"]
        self.assertEqual(
            transitions,
            {
                "no_existing_marker": "create",
                "exact_tuple_retry": "idempotent_no_cursor",
                "strictly_dominating_witness": "replace_same_record_row",
                "equal_vector_different_witness": "revision_equivocation",
                "weaker_or_incomparable_witness": "collection_ineligible",
                "physical_prune_covered_by_unchanged_marker": (
                    "no_marker_change_no_cursor"
                ),
            },
        )
        self.assertEqual(marker_transition_outcome(None, marker), "create")
        self.assertEqual(
            marker_transition_outcome(marker, copy.deepcopy(marker)),
            "idempotent_no_cursor",
        )
        stronger_marker = copy.deepcopy(marker)
        stronger_marker["witness_revision_id"] = (
            "00000000-0000-4000-8000-000000000024"
        )
        stronger_marker["frontier"][0]["counter"] = "3"
        self.assertEqual(
            marker_transition_outcome(marker, stronger_marker),
            "replace_same_record_row",
        )
        equal_different_witness = copy.deepcopy(marker)
        equal_different_witness["witness_revision_id"] = (
            "00000000-0000-4000-8000-000000000024"
        )
        self.assertEqual(
            marker_transition_outcome(marker, equal_different_witness),
            "revision_equivocation",
        )
        weaker_marker = copy.deepcopy(marker)
        weaker_marker["frontier"][0]["counter"] = "1"
        self.assertEqual(
            marker_transition_outcome(marker, weaker_marker),
            "collection_ineligible",
        )
        incomparable_marker = copy.deepcopy(marker)
        incomparable_marker["frontier"] = [
            {
                "device_id": "00000000-0000-4000-8000-000000000010",
                "counter": "3",
            }
        ]
        self.assertEqual(
            marker_transition_outcome(marker, incomparable_marker),
            "collection_ineligible",
        )
        cycle = barrier["delete_recreate_delete_cycle"]
        self.assertEqual(cycle["marker_rows_before"], 1)
        self.assertTrue(
            cycle["recreation_vector_includes_verified_marker_frontier"]
        )
        self.assertTrue(cycle["recreation_must_strictly_dominate_marker"])
        self.assertTrue(
            cycle[
                "second_tombstone_witness_strictly_dominates_recreation_and_old_marker"
            ]
        )
        self.assertEqual(cycle["marker_rows_after"], 1)
        self.assertTrue(cycle["same_record_marker_replaced"])
        selective_replay = barrier["selective_valid_certificate_replay"]
        self.assertTrue(selective_replay["older_certificate_hmac_valid"])
        self.assertTrue(
            selective_replay[
                "durable_frontier_includes_newer_authenticated_revision"
            ]
        )
        self.assertEqual(
            selective_replay["result"],
            "rollback_or_fork_rejected",
        )
        self.assertTrue(
            selective_replay[
                "revision_causal_bytes_retained_until_covering_marker"
            ]
        )
        self.assertFalse(
            selective_replay["acknowledgement_alone_allows_discard"]
        )
        initial_state = later_states[
            "tombstone_acknowledged_but_not_collected"
        ]
        self.assertTrue(initial_state["candidate_witnesses_itself"])
        self.assertEqual(
            initial_state["witness_revision_id"],
            fixture["tombstone"]["revision_id"],
        )
        self.assertTrue(barrier["later_mutation_must_dominate_persisted_frontier"])
        self.assertEqual(barrier["stale_later_mutation_error"], "stale_after_collection")
        returning = fixture["returning_retired_device"]
        self.assertTrue(returning["must_enroll_with_new_device_id"])
        self.assertFalse(returning["implicit_resurrection_allowed"])

    def test_device_lifecycle_fixture_covers_retry_revocation_rotation_and_downgrade(self) -> None:
        fixture = self.fixtures["device-lifecycle.json"]
        assert_uuid_v4(self, fixture["device_id"])
        rotation = fixture["token_rotation"]
        assert_uuid_v4(self, rotation["rotation_id"])
        self.assertEqual(len(decode_base64url(rotation["old_device_token"])), 32)
        self.assertEqual(len(decode_base64url(rotation["request"]["new_device_token"])), 32)
        states = {state["name"]: state for state in rotation["states"]}
        self.assertTrue(states["pending_local_keychain"]["old_auth"])
        self.assertFalse(states["server_committed_response_lost"]["old_auth"])
        self.assertTrue(states["server_committed_response_lost"]["new_auth"])
        self.assertTrue(rotation["self_only"])
        self.assertTrue(rotation["body_device_id_must_equal_bearer_device_id"])
        self.assertEqual(
            rotation["different_body_device_id_error"],
            "authenticated_device_mismatch",
        )
        self.assertEqual(rotation["different_body_device_id_http_status"], 403)
        revocation = fixture["revocation"]
        self.assertEqual(
            revocation["last_device_without_confirmation"],
            "zero_active_confirmation_required",
        )
        self.assertFalse(revocation["revocation_erases_cached_plaintext_or_vmk"])
        self.assertFalse(revocation["snapshot_lease_may_delay_or_block_revocation"])
        self.assertEqual(
            revocation["revoked_snapshot_owner_page_result"],
            "token_revoked",
        )
        self.assertEqual(
            revocation["revoked_snapshot_owner_page_http_status"],
            401,
        )
        replay = revocation["self_revocation_receipt_replay"]
        self.assertEqual(
            replay["header_request_id"],
            replay["body"]["request_id"],
        )
        raw_body = replay["exact_raw_body_utf8"].encode("utf-8")
        self.assertEqual(
            json.loads(raw_body, object_pairs_hook=reject_duplicate_keys),
            replay["body"],
        )
        fingerprint = self_revocation_body_fingerprint(
            replay["instance_id"],
            replay["vault_id"],
            replay["target_device_id"],
            raw_body,
        )
        reordered_body = (
            '{"allow_zero_active":false,"request_id":'
            '"00000000-0000-4000-8000-000000000032"}'
        ).encode("utf-8")
        self.assertEqual(json.loads(reordered_body), replay["body"])
        self.assertNotEqual(
            fingerprint,
            self_revocation_body_fingerprint(
                replay["instance_id"],
                replay["vault_id"],
                replay["target_device_id"],
                reordered_body,
            ),
        )
        self.assertEqual(
            set(replay["retained_for_life_of_retired_row"]),
            {
                "self_revocation_request_id",
                "exact_authenticated_body_fingerprint",
                "pre_revocation_token_hash",
                "byte_equivalent_200_response",
            },
        )
        recorded_body_bytes = replay["recorded_response_body_utf8"].encode(
            "utf-8"
        )
        self.assertIn(
            f"Content-Length: {len(recorded_body_bytes)}",
            replay["recorded_response_headers_in_order"],
        )
        self.assertTrue(
            schema_matches(
                json.loads(
                    recorded_body_bytes,
                    object_pairs_hook=reject_duplicate_keys,
                ),
                self.wire["$defs"]["device"],
                self.wire,
            )
        )
        self.assertIn(
            f"JAT-Request-ID: {replay['header_request_id']}",
            replay["recorded_response_headers_in_order"],
        )
        self.assertTrue(
            replay[
                "lookup_before_ordinary_revoked_token_rejection_on_this_endpoint_only"
            ]
        )
        self.assertFalse(replay["mismatch_reveals_receipt_details"])
        self.assertEqual(
            {case["name"] for case in replay["cases"]},
            {
                "exact_lost_response_retry",
                "different_token",
                "different_target_device",
                "different_header_request_id",
                "different_body_request_id",
                "semantically_equal_reordered_body",
                "same_tuple_on_other_endpoint",
            },
        )
        for case in replay["cases"]:
            with self.subTest(self_revocation_case=case["name"]):
                self.assertEqual(
                    self_revocation_replay_outcome(case),
                    (case["result"], case["http_status"]),
                )
                if case["http_status"] == 200:
                    self.assertTrue(case["response_byte_equivalent"])
        side_effects = replay["receipt_lookup_side_effects"]
        self.assertTrue(side_effects["retired_receipt_row_lookup"])
        self.assertTrue(
            all(
                value is False
                for key, value in side_effects.items()
                if key != "retired_receipt_row_lookup"
            )
        )
        normalized_protocol = re.sub(r"\s+", " ", self.protocol_text)
        self.assertIn(
            "On this endpoint only, receipt lookup for a retired row occurs before the ordinary revoked-token rejection",
            normalized_protocol,
        )
        self.assertIn(
            "Any token, target, header, or body mismatch returns the same HTTP 401 `token_revoked` response",
            normalized_protocol,
        )
        secret_rotation = fixture["instance_secret_rotation"]
        self.assertEqual(secret_rotation["rotation_without_device_held_vmk"], "forbidden")
        self.assertGreaterEqual(len(secret_rotation["states"]), 5)
        self.assertEqual(
            secret_rotation["backup_while_pending_or_recovery_slot_exists"],
            "refused_rotation_in_progress",
        )
        generation_exhaustion = secret_rotation["generation_exhaustion"]
        self.assertEqual(
            parse_uint64(generation_exhaustion["active_generation"]),
            (1 << 64) - 1,
        )
        self.assertEqual(
            generation_exhaustion["result"],
            "generation_exhausted",
        )
        self.assertEqual(generation_exhaustion["http_status"], 409)
        self.assertFalse(generation_exhaustion["retryable"])
        self.assertFalse(generation_exhaustion["pending_secret_created"])
        self.assertFalse(
            generation_exhaustion["active_or_recovery_state_mutated"]
        )
        self.assertFalse(generation_exhaustion["cursor_consumed"])

        snapshot_negotiation = fixture[
            "snapshot_create_capability_negotiation"
        ]
        self.assertEqual(
            snapshot_negotiation["required_exact"],
            SNAPSHOT_REQUIRED_CAPABILITIES,
        )
        self.assertTrue(snapshot_negotiation["checked_before_snapshot_creation"])
        self.assertEqual(
            {case["name"] for case in snapshot_negotiation["cases"]},
            {
                "exact_canonical_declaration",
                "missing_declaration",
                "incomplete_declaration",
                "noncanonical_order",
                "duplicate_declaration",
                "additional_unknown_capability",
            },
        )
        create_schema = self.wire["$defs"]["snapshot_create_request"]
        base_request = self.fixtures["full-snapshot-recovery.json"][
            "create_request"
        ]
        for case in snapshot_negotiation["cases"]:
            with self.subTest(snapshot_capability_case=case["name"]):
                request = copy.deepcopy(base_request)
                if case.get("omit_required_capabilities"):
                    request.pop("required_capabilities")
                else:
                    request["required_capabilities"] = case[
                        "request_required_capabilities"
                    ]
                if case["result"] == "snapshot_created":
                    validate_snapshot_capability_declaration(request)
                    self.assertTrue(
                        schema_matches(request, create_schema, self.wire)
                    )
                    self.assertTrue(case["snapshot_created"])
                else:
                    with self.assertRaisesRegex(
                        ValueError,
                        r"^unsupported_capability$",
                    ):
                        validate_snapshot_capability_declaration(request)
                    self.assertFalse(
                        schema_matches(request, create_schema, self.wire)
                    )
                    self.assertEqual(case["http_status"], 426)
                    self.assertFalse(case["snapshot_created"])

        cursor_contract = fixture["cursor_contract"]
        self.assertEqual(
            set(cursor_contract["cursor_bearing_transitions"]),
            {
                "device_enrollment",
                "vault_envelope_change",
                "record_revision",
                "device_revocation_or_retirement",
                "collection_marker",
            },
        )
        self.assertFalse(
            cursor_contract["exact_idempotent_retry_consumes_second_cursor"]
        )
        self.assertEqual(
            set(cursor_contract["non_cursor_transitions"]),
            {
                "device_token_hash_rotation",
                "ack_cursor_update",
                "last_successful_sync_update",
                "snapshot_creation_or_page",
                "snapshot_lease_expiry",
                "backup_read",
            },
        )
        exhausted_cursor = cursor_contract["at_uint64_max"]
        for operation in ("new_envelope_put", "new_device_revocation"):
            self.assertEqual(
                exhausted_cursor[operation]["result"],
                "server_cursor_exhausted",
            )
            self.assertEqual(exhausted_cursor[operation]["http_status"], 507)
            self.assertFalse(exhausted_cursor[operation]["state_mutated"])
        self.assertFalse(
            exhausted_cursor["exact_committed_retry"][
                "additional_cursor_consumed"
            ]
        )
        for operation in (
            "token_rotation",
            "acknowledgement_only_sync",
            "snapshot_read",
            "authenticated_reads_and_backups",
        ):
            self.assertEqual(exhausted_cursor[operation], "allowed")

        version_results = {case["result"]: case for case in fixture["version_negotiation"]}
        self.assertEqual(version_results["unsupported_protocol"]["http_status"], 426)
        unsupported_capabilities = [
            case
            for case in fixture["version_negotiation"]
            if case["result"] == "unsupported_capability"
        ]
        self.assertEqual(
            {case["missing_required_capability"] for case in unsupported_capabilities},
            {
                "envelope-cas-v1",
                "authenticated-collection-frontiers-v2",
                "snapshot-collection-markers-v1",
                "snapshot-device-registry-v1",
            },
        )
        self.assertTrue(
            all(case["http_status"] == 426 for case in unsupported_capabilities)
        )
        self.assertIn("preserve_opaque_and_block_write", version_results)

    def test_payload_schema_is_allowlisted_and_excludes_device_local_authority(self) -> None:
        defs = self.payload["$defs"]
        payload_types = {
            definition["properties"]["record_type"]["const"]
            for name, definition in defs.items()
            if name.endswith("_payload") and "properties" in definition
        }
        self.assertEqual(payload_types, PAYLOAD_TYPES)
        for name, definition in defs.items():
            if name.endswith("_body"):
                with self.subTest(name=name):
                    self.assertFalse(definition["additionalProperties"])
                    fields = set(definition["properties"])
                    self.assertTrue(fields.isdisjoint(DEVICE_LOCAL_FIELDS))

        secure_fields = set(defs["secure_enclave_identity_body"]["properties"])
        self.assertNotIn("private_key", secure_fields)
        self.assertNotIn("custody_generation", secure_fields)
        self.assertEqual(
            defs["secure_enclave_identity_body"]["properties"]["availability"]["const"],
            "device_bound",
        )
        host_fields = set(defs["host_body"]["properties"])
        self.assertNotIn("identity_files", host_fields)
        self.assertNotIn("session_logging_enabled", host_fields)

    def test_secure_enclave_identity_uses_canonical_public_only_p256_fixture(self) -> None:
        body_schema = self.payload["$defs"]["secure_enclave_identity_body"]
        self.assertIn("public_key_encoding", body_schema["required"])
        self.assertEqual(
            body_schema["properties"]["public_key_encoding"]["const"],
            "p256-x963-uncompressed-v1",
        )
        public_shape = body_schema["properties"]["public_key"]["allOf"][1]
        self.assertEqual(public_shape["minLength"], 87)
        self.assertEqual(public_shape["maxLength"], 87)

        fixture = self.fixtures["secure-enclave-identity.json"]
        self.assertEqual(
            fixture["status"],
            "review-pending-executable-public-only-secure-enclave-fixture",
        )
        canonical = fixture["canonical_identity"]
        external_roots = {"wire.schema.json": self.wire}
        self.assertTrue(
            schema_matches(
                canonical,
                self.payload,
                self.payload,
                external_roots,
            )
        )
        public_key = decode_base64url(canonical["body"]["public_key"])
        self.assertEqual(
            len(public_key),
            fixture["expected"]["decoded_public_key_bytes"],
        )
        self.assertEqual(public_key[0], 0x04)
        validate_secure_enclave_public_key(canonical["body"])
        self.assertFalse(fixture["expected"]["private_key_committed"])
        self.assertNotIn("private_key", canonical["body"])

        expected_negative_cases = {
            "missing-public-key-encoding",
            "wrong-public-key-encoding",
            "empty-public-key",
            "compressed-sec1-public-key",
            "spki-der-public-key",
            "wrong-uncompressed-prefix",
            "off-curve-point",
            "noncanonical-base64url",
            "fingerprint-mismatch",
        }
        self.assertEqual(
            {case["name"] for case in fixture["negative_cases"]},
            expected_negative_cases,
        )
        for case in fixture["negative_cases"]:
            with self.subTest(case=case["name"]):
                candidate = copy.deepcopy(canonical)
                mutation = case["mutation"]
                if mutation["operation"] == "remove":
                    del candidate["body"][mutation["field"]]
                else:
                    self.assertEqual(mutation["operation"], "replace")
                    candidate["body"][mutation["field"]] = mutation["value"]
                matches_schema = schema_matches(
                    candidate,
                    self.payload,
                    self.payload,
                    external_roots,
                )
                if case["rejected_by"] == "schema":
                    self.assertFalse(matches_schema)
                else:
                    self.assertEqual(case["rejected_by"], "key_validation")
                    self.assertTrue(matches_schema)
                    with self.assertRaises(ValueError):
                        validate_secure_enclave_public_key(candidate["body"])

        normalized_protocol = re.sub(r"\s+", " ", self.protocol_text)
        normalized_threat = re.sub(r"\s+", " ", self.threat_text)
        for claim in (
            "public_key_encoding = p256-x963-uncompressed-v1",
            "0x04 || X32 || Y32",
            "exactly 65 decoded bytes and 87 unpadded base64url characters",
            "recompute the OpenSSH `ecdsa-sha2-nistp256` SHA-256 fingerprint",
            "Before any persistent local import or custody mutation",
        ):
            with self.subTest(claim=claim):
                self.assertIn(claim, normalized_protocol)
        self.assertIn(
            "compressed, DER/SPKI, wrong-length, wrong-prefix, off-curve, non-canonical",
            normalized_threat,
        )

    def test_software_identity_schema_and_fixture_enforce_canonical_keypairs(self) -> None:
        body_schema = self.payload["$defs"]["software_identity_body"]
        branches = {
            branch["if"]["properties"]["key_kind"]["const"]: branch["then"][
                "properties"
            ]
            for branch in body_schema["allOf"]
        }
        self.assertEqual(set(branches), {"ed25519", "rsa"})
        self.assertEqual(
            branches["ed25519"]["private_key_encoding"]["const"],
            "ed25519-seed-v1",
        )
        self.assertEqual(
            branches["rsa"]["private_key_encoding"]["const"],
            "rsa-pkcs8-der-v1",
        )
        self.assertEqual(
            branches["ed25519"]["public_key_encoding"]["const"],
            "ed25519-raw-v1",
        )
        self.assertEqual(
            branches["rsa"]["public_key_encoding"]["const"],
            "rsa-pkcs1-der-v1",
        )
        for field in ("private_key", "public_key"):
            with self.subTest(field=field):
                ed25519_key_shape = branches["ed25519"][field]["allOf"][1]
                self.assertEqual(ed25519_key_shape["minLength"], 43)
                self.assertEqual(ed25519_key_shape["maxLength"], 43)
        self.assertEqual(
            body_schema["properties"]["private_key"]["allOf"][1]["minLength"],
            1,
        )
        self.assertEqual(
            body_schema["properties"]["public_key"]["allOf"][1]["minLength"],
            1,
        )
        self.assertIn("public_key_encoding", body_schema["required"])

        normalized_protocol = re.sub(r"\s+", " ", self.protocol_text)
        for claim in (
            "public_key_encoding = ed25519-raw-v1",
            "public_key_encoding = rsa-pkcs1-der-v1",
            "require byte-for-byte equality with the received bytes",
            "derive the canonical public-key bytes from the validated private key and require exact equality",
            "before persistent Keychain import or any local custody mutation",
        ):
            with self.subTest(claim=claim):
                self.assertIn(claim, normalized_protocol)

        fixture = self.fixtures["software-identity-keys.json"]
        self.assertEqual(
            fixture["status"],
            "review-pending-executable-software-identity-key-fixture",
        )
        self.assertRegex(
            openssl_transform(["version"], b"").decode("ascii"),
            r"^OpenSSL 3\.",
        )
        external_roots = {"wire.schema.json": self.wire}
        for name, payload in fixture["canonical_identities"].items():
            with self.subTest(valid_identity=name):
                self.assertTrue(
                    schema_matches(
                        payload,
                        self.payload,
                        self.payload,
                        external_roots,
                    )
                )
                validate_software_identity_keypair(payload["body"])

        negative_cases = fixture["negative_cases"]
        self.assertEqual(
            {case["name"] for case in negative_cases},
            {
                "missing-public-key-encoding",
                "empty-public-key",
                "empty-private-key",
                "wrong-ed25519-public-encoding",
                "wrong-ed25519-private-encoding",
                "short-ed25519-public-key",
                "long-ed25519-private-key",
                "mismatched-ed25519-keypair",
                "wrong-rsa-public-encoding",
                "wrong-rsa-private-encoding",
                "malformed-rsa-pkcs8-private-key",
                "wrong-rsa-private-algorithm",
                "noncanonical-rsa-private-trailing-bytes",
                "malformed-rsa-pkcs1-public-key",
                "rsa-spki-public-instead-of-pkcs1",
                "noncanonical-rsa-public-trailing-byte",
                "mismatched-rsa-keypair",
            },
        )
        for case in negative_cases:
            with self.subTest(invalid_identity=case["name"]):
                invalid_payload = copy.deepcopy(
                    fixture["canonical_identities"][case["base"]]
                )
                mutation = case["mutation"]
                if mutation["operation"] == "remove":
                    del invalid_payload["body"][mutation["field"]]
                elif mutation["operation"] == "append":
                    invalid_payload["body"][mutation["field"]] += mutation["value"]
                else:
                    self.assertEqual(mutation["operation"], "replace")
                    invalid_payload["body"][mutation["field"]] = mutation["value"]

                matches_schema = schema_matches(
                    invalid_payload,
                    self.payload,
                    self.payload,
                    external_roots,
                )
                if case["rejected_by"] == "schema":
                    self.assertFalse(matches_schema)
                else:
                    self.assertEqual(case["rejected_by"], "key_validation")
                    self.assertTrue(matches_schema)
                    with self.assertRaises(ValueError):
                        validate_software_identity_keypair(invalid_payload["body"])

    def test_backup_fixture_is_complete_sensitive_and_fail_closed(self) -> None:
        fixture = self.fixtures["api-and-recovery.json"]
        manifest = fixture["backup_manifest"]
        assert_uuid_v4(self, manifest["instance_id"])
        assert_uuid_v4(self, manifest["vault_id"])
        self.assertEqual(
            {item["path"] for item in manifest["files"]},
            BACKUP_MANIFEST_PATHS,
        )
        self.assertEqual(manifest["secret_rotation_state"], "stable")
        self.assertIn("collection_marker_count", self.backup_schema["required"])
        self.assertEqual(parse_uint64(manifest["collection_marker_count"]), 1)
        self.assertEqual(
            self.backup_schema["properties"]["secret_rotation_state"]["const"],
            "stable",
        )
        archive_members = [item["path"] for item in manifest["files"]]
        validate_backup_manifest_paths(manifest, archive_members)
        for item in manifest["files"]:
            self.assertEqual(item["mode"], "0600")
            parse_uint64(item["size"])
            self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")
        cases = {case["name"]: case["result"] for case in fixture["restore_cases"]}
        self.assertEqual(cases["database_secret_instance_mismatch"], "instance_mismatch")
        self.assertEqual(cases["missing_secret"], "restore_incompatible")
        self.assertEqual(
            cases["duplicate_manifest_path_with_different_checksum"],
            "restore_incompatible",
        )
        self.assertEqual(cases["case_alias_manifest_path"], "restore_incompatible")
        self.assertEqual(
            cases["missing_canonical_manifest_path"],
            "restore_incompatible",
        )
        self.assertEqual(
            cases["missing_canonical_archive_member"],
            "restore_incompatible",
        )
        self.assertEqual(cases["unlisted_archive_member"], "restore_incompatible")
        duplicate_manifest = copy.deepcopy(manifest)
        duplicate_path = copy.deepcopy(duplicate_manifest["files"][0])
        duplicate_path["sha256"] = "f" * 64
        duplicate_manifest["files"].append(duplicate_path)
        paths = [item["path"] for item in duplicate_manifest["files"]]
        self.assertNotEqual(len(paths), len(set(paths)))
        with self.assertRaisesRegex(
            ValueError,
            r"^duplicate backup manifest path: sync\.db$",
        ):
            validate_backup_manifest_paths(duplicate_manifest)
        case_alias_manifest = copy.deepcopy(manifest)
        case_alias_manifest["files"][0]["path"] = "SYNC.db"
        with self.assertRaisesRegex(
            ValueError,
            r"^noncanonical backup manifest path: SYNC\.db$",
        ):
            validate_backup_manifest_paths(case_alias_manifest)
        missing_manifest_path = copy.deepcopy(manifest)
        missing_manifest_path["files"] = [
            item
            for item in missing_manifest_path["files"]
            if item["path"] != "config.json"
        ]
        with self.assertRaisesRegex(
            ValueError,
            r"^missing backup manifest path: config\.json$",
        ):
            validate_backup_manifest_paths(missing_manifest_path)
        with self.assertRaisesRegex(
            ValueError,
            r"^missing backup archive member: config\.json$",
        ):
            validate_backup_manifest_paths(
                manifest,
                [
                    path
                    for path in archive_members
                    if path != "config.json"
                ],
            )
        with self.assertRaisesRegex(
            ValueError,
            r"^noncanonical backup archive member: metadata\.json$",
        ):
            validate_backup_manifest_paths(
                manifest,
                [*archive_members, "metadata.json"],
            )
        file_schema = self.backup_schema["properties"]["files"]
        self.assertEqual(file_schema["minItems"], len(BACKUP_MANIFEST_PATHS))
        self.assertEqual(file_schema["maxItems"], len(BACKUP_MANIFEST_PATHS))
        self.assertEqual(
            set(file_schema["items"]["properties"]["path"]["enum"]),
            BACKUP_MANIFEST_PATHS,
        )
        self.assertIn(
            "each exactly once with exact ASCII spelling and case",
            file_schema["description"],
        )
        backup_cases = {case["name"]: case["result"] for case in fixture["backup_cases"]}
        self.assertEqual(
            backup_cases["pending_secret_exists"],
            "backup_refused_rotation_in_progress",
        )
        self.assertEqual(
            backup_cases["old_recovery_slot_exists"],
            "backup_refused_rotation_in_progress",
        )
        self.assertIn("complete backup includes token hashes and the instance secret", self.threat_text)

    def test_api_fixture_matches_negotiation_and_empty_sync_contract(self) -> None:
        fixture = self.fixtures["api-and-recovery.json"]
        capabilities = fixture["capabilities"]
        self.assertEqual(capabilities["protocol_min"], "1")
        self.assertEqual(capabilities["protocol_max"], "1")
        self.assertEqual(capabilities["crypto_suites"], ["jat-xchacha-hkdf-argon2id-draft2"])
        self.assertEqual(
            capabilities["capabilities"],
            sorted(capabilities["capabilities"]),
        )
        self.assertTrue(
            {
                "authenticated-collection-frontiers-v2",
                "snapshot-read-v1",
                "snapshot-collection-markers-v1",
                "snapshot-device-registry-v1",
            }.issubset(
                capabilities["capabilities"]
            )
        )
        self.assertTrue(
            schema_matches(
                capabilities,
                self.wire["$defs"]["capabilities_response"],
                self.wire,
            )
        )
        self.assertEqual(capabilities["limits"]["max_snapshot_page_revisions"], 128)
        self.assertEqual(
            capabilities["limits"]["max_snapshot_page_collection_markers"],
            128,
        )
        self.assertEqual(
            capabilities["limits"]["max_snapshot_page_source_devices"],
            64,
        )
        self.assertEqual(
            {
                key: capabilities["limits"][key]
                for key in (
                    "max_active_snapshots_per_device",
                    "max_active_snapshots_per_instance",
                    "max_snapshot_creates_per_minute_per_device",
                    "max_active_snapshot_metadata_bytes_per_instance",
                )
            },
            {
                "max_active_snapshots_per_device": 1,
                "max_active_snapshots_per_instance": 8,
                "max_snapshot_creates_per_minute_per_device": 5,
                "max_active_snapshot_metadata_bytes_per_instance": 67108864,
            },
        )
        self.assertEqual(
            set(capabilities["limits"]),
            set(
                self.wire["$defs"]["capabilities_response"]["properties"][
                    "limits"
                ]["required"]
            ),
        )
        request = fixture["empty_sync_request"]
        response = fixture["empty_sync_response"]
        assert_uuid_v4(self, request["device_id"])
        assert_uuid_v4(self, request["request_id"])
        self.assertEqual(request["mutations"], [])
        self.assertEqual(response["changes"], [])
        self.assertFalse(response["has_more"])
        for value in (request["after_cursor"], request["ack_cursor"], response["server_cursor"], response["next_cursor"]):
            parse_uint64(value)

        ordering = fixture["mutation_ordering"]
        self.assertEqual(
            ordering["key"],
            ["author_counter_uint64", "record_id_uuid_bytes", "revision_id_uuid_bytes"],
        )
        keys = [
            (
                parse_uint64(item["author_counter"]),
                uuid.UUID(item["record_id"]).bytes,
                uuid.UUID(item["revision_id"]).bytes,
            )
            for item in ordering["ordered_examples"]
        ]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(keys), len(set(keys)))
        self.assertFalse(ordering["duplicates_allowed"])
        self.assertEqual(ordering["unsorted_error"], "invalid_request")
        errors = {case["code"]: case for case in fixture["errors"]}
        self.assertEqual(errors["generation_exhausted"]["http_status"], 409)
        self.assertFalse(errors["generation_exhausted"]["retryable"])

    def test_full_snapshot_is_stable_sibling_complete_and_transitions_to_delta(self) -> None:
        fixture = self.fixtures["full-snapshot-recovery.json"]
        create_request = fixture["create_request"]
        create_response = fixture["create_response"]
        assert_uuid_v4(self, create_request["device_id"])
        assert_uuid_v4(self, create_request["request_id"])
        assert_uuid_v4(self, create_response["snapshot_id"])
        validate_snapshot_capability_declaration(create_request)
        self.assertTrue(
            schema_matches(
                create_request,
                self.wire["$defs"]["snapshot_create_request"],
                self.wire,
            )
        )
        cut = parse_uint64(create_response["cut_cursor"])
        self.assertEqual(len(decode_base64url(create_response["first_page_token"])), 32)
        self.assertEqual(
            create_response["envelope_generation"],
            create_response["envelope"]["envelope_generation"],
        )
        self.assertNotEqual(
            create_response["envelope"]["envelope_generation"],
            create_response["envelope"]["instance_secret_generation"],
        )

        revisions: list[dict] = []
        collection_markers: list[dict] = []
        source_devices: list[dict] = []
        phases: list[str] = []
        expected_token = create_response["first_page_token"]
        for index, page in enumerate(fixture["pages"]):
            request_page = page["request"]
            response_page = page["response"]
            self.assertTrue(
                schema_matches(
                    response_page,
                    self.wire["$defs"]["snapshot_page_response"],
                    self.wire,
                )
            )
            self.assertEqual(request_page["device_id"], create_request["device_id"])
            self.assertEqual(request_page["page_token"], expected_token)
            self.assertEqual(response_page["snapshot_id"], create_response["snapshot_id"])
            self.assertEqual(parse_uint64(response_page["cut_cursor"]), cut)
            self.assertEqual(
                response_page["envelope_generation"],
                create_response["envelope_generation"],
            )
            populated_phase_count = sum(
                bool(response_page[field])
                for field in ("revisions", "collection_markers", "source_devices")
            )
            self.assertEqual(populated_phase_count, 1)
            revisions.extend(response_page["revisions"])
            collection_markers.extend(response_page["collection_markers"])
            source_devices.extend(response_page["source_devices"])
            if response_page["revisions"]:
                phases.append("record_revisions")
            elif response_page["collection_markers"]:
                phases.append("collection_markers")
            elif response_page["source_devices"]:
                phases.append("source_devices")
            expected_token = response_page["next_page_token"]
            self.assertEqual(response_page["has_more"], index < len(fixture["pages"]) - 1)
        self.assertIsNone(expected_token)
        self.assertEqual(phases, fixture["expected"]["page_phases"])
        self.assertEqual(
            list(dict.fromkeys(phases)),
            fixture["expected"]["snapshot_phases"],
        )

        revision_keys = [
            (uuid.UUID(item["record_id"]).bytes, uuid.UUID(item["revision_id"]).bytes)
            for item in revisions
        ]
        self.assertEqual(revision_keys, sorted(revision_keys))
        self.assertEqual(len(revisions), 2)
        self.assertEqual({item["record_id"] for item in revisions}, {revisions[0]["record_id"]})
        self.assertEqual(sum(not item["tombstone"] for item in revisions), 1)
        self.assertEqual(sum(item["tombstone"] for item in revisions), 1)
        self.assertFalse(
            dominates(
                validate_revision_vector(revisions[0]),
                validate_revision_vector(revisions[1]),
            )
        )
        self.assertFalse(
            dominates(
                validate_revision_vector(revisions[1]),
                validate_revision_vector(revisions[0]),
            )
        )
        marker_keys = [
            uuid.UUID(item["record_id"]).bytes
            for item in collection_markers
        ]
        self.assertEqual(marker_keys, sorted(marker_keys))
        self.assertEqual(len(marker_keys), len(set(marker_keys)))
        self.assertEqual(
            len(collection_markers),
            fixture["expected"]["collection_marker_count"],
        )
        self.assertTrue(fixture["expected"]["all_persistent_collection_markers_included"])
        self.assertTrue(fixture["expected"]["collection_marker_frontiers_preserved"])
        self.assertTrue(
            fixture["expected"][
                "collection_marker_witness_certificates_preserved"
            ]
        )
        checkpoint_coverage = fixture["expected"]["checkpoint_coverage"]
        ordinary = checkpoint_coverage[
            "ordinary_revision_checkpoint_without_prior_marker"
        ]
        self.assertFalse(ordinary["prior_marker_checkpoint_present"])
        self.assertFalse(ordinary["incoming_marker_present"])
        self.assertNotIn(
            ordinary["record_id"],
            {marker["record_id"] for marker in collection_markers},
        )
        ordinary_revisions = [
            revision
            for revision in revisions
            if revision["record_id"] == ordinary["record_id"]
        ]
        aggregate: dict[str, int] = {}
        for revision in ordinary_revisions:
            for device_id, counter in validate_revision_vector(revision).items():
                aggregate[device_id] = max(aggregate.get(device_id, 0), counter)
        prior_ordinary = canonical_vector_map(ordinary["prior_durable_frontier"])
        self.assertTrue(
            aggregate == prior_ordinary or dominates(aggregate, prior_ordinary)
        )
        self.assertTrue(
            ordinary["incoming_revision_aggregate_covers_prior_frontier"]
        )
        self.assertEqual(ordinary["result"], "accepted")
        prior_marker_case = checkpoint_coverage["prior_marker_checkpoint"]
        incoming_prior_marker = next(
            marker
            for marker in collection_markers
            if marker["record_id"] == prior_marker_case["record_id"]
        )
        self.assertEqual(
            canonical_vector_map(incoming_prior_marker["frontier"]),
            canonical_vector_map(prior_marker_case["prior_marker_frontier"]),
        )
        self.assertEqual(prior_marker_case["incoming_marker_relation"], "exact")
        self.assertEqual(prior_marker_case["result"], "accepted")
        self.assertEqual(
            prior_marker_case["missing_incoming_marker_result"],
            "rollback_or_fork_rejected",
        )
        for marker in collection_markers:
            self.assertLessEqual(parse_uint64(marker["barrier_cursor"]), cut)
            self.assertTrue(vector_map({"version_vector": marker["frontier"]}))
            assert_uuid_v4(self, marker["witness_revision_id"])
            self.assertEqual(
                len(decode_base64url(marker["collection_witness_authenticator"])),
                32,
            )
        source_counters = source_device_counter_map(source_devices)
        self.assertEqual(
            len(source_devices),
            fixture["expected"]["source_device_count"],
        )
        self.assertTrue(fixture["expected"]["all_source_devices_included"])
        self.assertEqual(
            fixture["expected"]["never_authored_source_device_id"],
            create_request["device_id"],
        )
        referenced_counters: dict[str, int] = {}
        for revision in revisions:
            self.assertIn(revision["author_device_id"], source_counters)
            for device_id, counter in validate_revision_vector(revision).items():
                referenced_counters[device_id] = max(
                    referenced_counters.get(device_id, 0),
                    counter,
                )
        for marker in collection_markers:
            for device_id, counter in vector_map(
                {"version_vector": marker["frontier"]}
            ).items():
                referenced_counters[device_id] = max(
                    referenced_counters.get(device_id, 0),
                    counter,
                )
        self.assertTrue(set(referenced_counters).issubset(source_counters))
        for device_id, counter in referenced_counters.items():
            self.assertLessEqual(counter, source_counters[device_id])
        never_authored = fixture["expected"]["never_authored_source_device_id"]
        self.assertIn(never_authored, source_counters)
        self.assertEqual(source_counters[never_authored], 0)
        self.assertNotIn(never_authored, referenced_counters)

        lease = fixture["lease_and_revocation"]
        self.assertEqual(
            lease["snapshot_storage"],
            "copied_metadata_with_content_addressed_revision_references",
        )
        self.assertEqual(
            set(lease["copied_snapshot_members"]),
            {
                "envelope",
                "collection_markers",
                "source_device_projection",
                "ordered_membership_and_paging_metadata",
            },
        )
        self.assertEqual(
            lease["revision_payload_storage"],
            "retained_reference_to_existing_immutable_content_addressed_object",
        )
        self.assertFalse(lease["revision_payload_bytes_duplicated_per_snapshot"])
        self.assertFalse(lease["live_revision_rows_pinned"])
        self.assertFalse(lease["live_device_rows_pinned"])
        self.assertFalse(lease["live_mutations_blocked"])
        self.assertTrue(lease["page_requests_authenticate_current_live_device_state"])
        revoked_owner = lease["owner_revoked_during_lease"]
        self.assertTrue(revoked_owner["revocation_committed_immediately"])
        self.assertFalse(revoked_owner["snapshot_lease_deferred_revocation"])
        self.assertEqual(revoked_owner["subsequent_page_result"], "token_revoked")
        self.assertEqual(revoked_owner["subsequent_page_http_status"], 401)
        self.assertFalse(revoked_owner["page_bytes_returned"])
        self.assertTrue(
            fixture["expected"]["immutable_projection_materialized_at_creation"]
        )

        resource_limits = fixture["resource_limits"]
        self.assertEqual(
            {
                key: resource_limits[key]
                for key in (
                    "max_active_snapshots_per_device",
                    "max_active_snapshots_per_instance",
                    "max_snapshot_creates_per_minute_per_device",
                    "max_active_snapshot_metadata_bytes_per_instance",
                )
            },
            {
                "max_active_snapshots_per_device": 1,
                "max_active_snapshots_per_instance": 8,
                "max_snapshot_creates_per_minute_per_device": 5,
                "max_active_snapshot_metadata_bytes_per_instance": 67108864,
            },
        )
        self.assertEqual(
            resource_limits["evaluation_order"],
            [
                "exact_idempotency_lookup",
                "unique_request_rate_limit",
                "expire_old_snapshots_and_recompute_usage",
                "active_snapshot_count_limits",
                "metadata_byte_limit",
                "allocate_metadata_and_retain_payload_references",
            ],
        )
        self.assertIn(
            "shared_immutable_revision_payload_objects",
            resource_limits["metadata_accounting_excludes"],
        )
        cases = {case["name"]: case for case in resource_limits["cases"]}
        self.assertEqual(
            set(cases),
            {
                "exact_retry_at_allocation_limits",
                "second_active_snapshot_for_device",
                "ninth_active_snapshot_for_instance",
                "metadata_exact_fit",
                "metadata_one_byte_over",
                "sixth_unique_create_in_rolling_minute",
            },
        )
        for name, case in cases.items():
            with self.subTest(snapshot_resource_case=name):
                self.assertEqual(
                    snapshot_create_outcome(case, resource_limits),
                    (case["result"], case["http_status"]),
                )
                if case["result"] in {"limit_exceeded", "rate_limited"}:
                    self.assertFalse(case["metadata_allocated"])
                    self.assertFalse(case["payload_reference_retained"])
        exact_retry = cases["exact_retry_at_allocation_limits"]
        self.assertFalse(exact_retry["unique_rate_attempt_consumed"])
        self.assertFalse(exact_retry["additional_capacity_consumed"])
        self.assertFalse(exact_retry["lease_refreshed"])
        exact_fit = cases["metadata_exact_fit"]
        self.assertEqual(
            exact_fit["active_metadata_bytes"]
            + exact_fit["candidate_metadata_bytes"],
            resource_limits["max_active_snapshot_metadata_bytes_per_instance"],
        )
        one_byte_over = cases["metadata_one_byte_over"]
        self.assertEqual(
            one_byte_over["active_metadata_bytes"]
            + one_byte_over["candidate_metadata_bytes"],
            resource_limits["max_active_snapshot_metadata_bytes_per_instance"]
            + 1,
        )
        self.assertTrue(
            resource_limits[
                "all_rejections_before_snapshot_persist_or_allocation"
            ]
        )

        delta_request = fixture["delta_transition_request"]
        delta_response = fixture["delta_transition_response"]
        self.assertEqual(parse_uint64(delta_request["after_cursor"]), cut)
        self.assertEqual(parse_uint64(delta_request["ack_cursor"]), cut)
        self.assertGreater(parse_uint64(delta_response["changes"][0]["cursor"]), cut)
        self.assertTrue(fixture["expected"]["all_undominated_siblings_included"])
        self.assertTrue(fixture["expected"]["partial_snapshot_must_be_discarded_on_expiry"])

    def test_snapshot_and_recovery_page_schemas_reject_mixed_or_incomplete_phases(
        self,
    ) -> None:
        fixture = self.fixtures["full-snapshot-recovery.json"]
        schema = self.wire["$defs"]["snapshot_page_response"]
        revision_page = fixture["pages"][0]["response"]
        marker_page = next(
            page["response"]
            for page in fixture["pages"]
            if page["response"]["collection_markers"]
        )
        source_device_page = next(
            page["response"]
            for page in fixture["pages"]
            if page["response"]["source_devices"]
        )

        mixed_page = copy.deepcopy(revision_page)
        mixed_page["collection_markers"] = copy.deepcopy(
            marker_page["collection_markers"]
        )
        self.assertFalse(schema_matches(mixed_page, schema, self.wire))

        mixed_source_device_page = copy.deepcopy(revision_page)
        mixed_source_device_page["source_devices"] = copy.deepcopy(
            source_device_page["source_devices"]
        )
        self.assertFalse(schema_matches(mixed_source_device_page, schema, self.wire))

        empty_nonterminal_page = copy.deepcopy(revision_page)
        empty_nonterminal_page["revisions"] = []
        self.assertFalse(schema_matches(empty_nonterminal_page, schema, self.wire))

        null_nonterminal_token = copy.deepcopy(revision_page)
        null_nonterminal_token["next_page_token"] = None
        self.assertFalse(schema_matches(null_nonterminal_token, schema, self.wire))

        token_on_final_page = copy.deepcopy(source_device_page)
        token_on_final_page["next_page_token"] = revision_page["next_page_token"]
        self.assertFalse(schema_matches(token_on_final_page, schema, self.wire))

        recovery_schema = self.wire["$defs"]["recovery_import_page"]
        recovery_page = self.fixtures["host-loss-recovery.json"]["import_pages"][0]
        self.assertTrue(schema_matches(recovery_page, recovery_schema, self.wire))
        phase_payload_mismatch = copy.deepcopy(recovery_page)
        phase_payload_mismatch["phase"] = "collection_markers"
        self.assertFalse(
            schema_matches(phase_payload_mismatch, recovery_schema, self.wire)
        )
        recovery_source_page = self.fixtures["host-loss-recovery.json"][
            "import_pages"
        ][-1]
        self.assertTrue(
            schema_matches(recovery_source_page, recovery_schema, self.wire)
        )
        source_phase_payload_mismatch = copy.deepcopy(recovery_source_page)
        source_phase_payload_mismatch["phase"] = "record_revisions"
        self.assertFalse(
            schema_matches(
                source_phase_payload_mismatch,
                recovery_schema,
                self.wire,
            )
        )

    def test_identity_preserving_host_recovery_preserves_records_and_rebuilds_cursors(self) -> None:
        fixture = self.fixtures["host-loss-recovery.json"]
        source = fixture["source_completed_snapshot"]
        manifest = fixture["recovery_manifest"]
        pages = fixture["import_pages"]
        recovered = fixture["recovered_instance"]
        imported = fixture["atomic_import"]
        cursors = fixture["cursor_transition"]
        self.assertEqual(fixture["strategy"], "identity_preserving_recovery")
        self.assertTrue(source["all_undominated_siblings_present"])
        self.assertEqual(source["live_siblings"], 1)
        self.assertEqual(source["tombstone_siblings"], 1)
        self.assertTrue(source["all_persistent_collection_markers_present"])
        self.assertEqual(
            parse_uint64(source["collection_marker_count"]),
            len(source["collection_markers"]),
        )
        self.assertTrue(source["all_source_devices_present"])
        self.assertEqual(
            parse_uint64(source["source_device_count"]),
            len(source["source_devices"]),
        )
        snapshot_fixture = self.fixtures["full-snapshot-recovery.json"]
        snapshot_revisions = [
            revision
            for page in snapshot_fixture["pages"]
            for revision in page["response"]["revisions"]
        ]
        snapshot_markers = [
            marker
            for page in snapshot_fixture["pages"]
            for marker in page["response"]["collection_markers"]
        ]
        snapshot_source_devices = [
            source_device
            for page in snapshot_fixture["pages"]
            for source_device in page["response"]["source_devices"]
        ]
        self.assertEqual(source["collection_markers"], snapshot_markers)
        self.assertEqual(source["source_devices"], snapshot_source_devices)
        source_registry = source_device_counter_map(source["source_devices"])
        for device_id in source_registry:
            assert_uuid_v4(self, device_id)
        snapshot_envelope = snapshot_fixture["create_response"]["envelope"]
        passphrase_rewrap_envelope = self.fixtures["vault-envelope.json"][
            "passphrase_rewrap"
        ]["envelope"]
        self.assertEqual(snapshot_envelope, passphrase_rewrap_envelope)
        self.assertEqual(
            source["envelope_generation"],
            snapshot_envelope["envelope_generation"],
        )
        self.assertEqual(
            source["instance_secret_generation"],
            snapshot_envelope["instance_secret_generation"],
        )
        self.assertEqual(
            source["envelope_generation"],
            passphrase_rewrap_envelope["envelope_generation"],
        )
        self.assertEqual(
            source["instance_secret_generation"],
            passphrase_rewrap_envelope["instance_secret_generation"],
        )
        self.assertTrue(
            source[
                "envelope_and_instance_secret_generations_diverged_after_passphrase_rewrap"
            ]
        )
        self.assertNotEqual(
            source["envelope_generation"],
            source["instance_secret_generation"],
        )
        self.assertTrue(
            source[
                "surviving_client_verified_revision_aead_and_every_non_null_collection_witness_authenticator"
            ]
        )
        self.assertTrue(
            source["surviving_client_verified_marker_authenticators"]
        )
        self.assertEqual(recovered["instance_id"], source["instance_id"])
        self.assertEqual(recovered["vault_id"], source["vault_id"])
        self.assertTrue(recovered["record_ciphertexts_byte_identical"])
        self.assertTrue(
            recovered["record_ids_revision_ids_vectors_and_tombstone_flags_byte_identical"]
        )
        self.assertTrue(
            recovered[
                "collection_marker_witness_certificates_and_frontiers_byte_identical"
            ]
        )
        self.assertTrue(
            recovered[
                "recovering_client_readback_reverified_before_completion"
            ]
        )
        self.assertTrue(
            recovered["source_abandoned_only_after_destination_reverification"]
        )
        self.assertTrue(
            recovered["source_device_ids_and_max_author_counters_preserved"]
        )
        self.assertEqual(manifest["instance_id"], source["instance_id"])
        self.assertEqual(manifest["vault_id"], source["vault_id"])
        self.assertEqual(manifest["source_cut_cursor"], source["cut_cursor"])
        self.assertEqual(
            manifest["source_envelope_generation"],
            source["envelope_generation"],
        )
        self.assertEqual(
            manifest["source_instance_secret_generation"],
            source["instance_secret_generation"],
        )
        self.assertEqual(
            parse_uint64(recovered["new_envelope_generation"]),
            parse_uint64(manifest["source_envelope_generation"]) + 1,
        )
        self.assertEqual(
            parse_uint64(recovered["new_instance_secret_generation"]),
            parse_uint64(manifest["source_instance_secret_generation"]) + 1,
        )
        self.assertEqual(
            set(manifest),
            set(self.wire["$defs"]["host_recovery_manifest"]["required"]),
        )
        self.assertTrue(
            schema_matches(
                manifest,
                self.wire["$defs"]["host_recovery_manifest"],
                self.wire,
            )
        )
        self.assertEqual(manifest["revision_count"], source["revision_count"])
        self.assertEqual(
            manifest["collection_marker_count"],
            source["collection_marker_count"],
        )
        self.assertEqual(
            manifest["source_device_count"],
            source["source_device_count"],
        )
        self.assertEqual(parse_uint64(manifest["page_count"]), len(pages))
        for page in pages:
            self.assertEqual(
                set(page),
                set(self.wire["$defs"]["recovery_import_page"]["required"]),
            )
            self.assertTrue(
                schema_matches(
                    page,
                    self.wire["$defs"]["recovery_import_page"],
                    self.wire,
                )
            )
        recorded_raw_bodies = recorded_fixture_raw_page_bodies(pages)
        self.assertEqual(
            fixture["digest_fixture_encoding"],
            "recorded_raw_request_body_bytes_are_compact_sorted_json_utf8_pages_each_prefixed_u64be_length",
        )
        validate_recovery_manifest_pages(
            manifest,
            pages,
            recorded_raw_bodies,
        )
        self.assertEqual(
            recovery_raw_bodies_sha256(recorded_raw_bodies),
            manifest["pages_sha256"],
        )
        for field in (
            "page_count",
            "revision_count",
            "collection_marker_count",
            "source_device_count",
        ):
            with self.subTest(recovery_manifest_mismatch=field):
                mismatched_manifest = copy.deepcopy(manifest)
                mismatched_manifest[field] = str(
                    parse_uint64(mismatched_manifest[field]) + 1
                )
                with self.assertRaisesRegex(
                    ValueError,
                    rf"^{field} mismatch$",
                ):
                    validate_recovery_manifest_pages(
                        mismatched_manifest,
                        pages,
                        recorded_raw_bodies,
                    )
        digest_mismatch = copy.deepcopy(manifest)
        digest_mismatch["pages_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, r"^pages_sha256 mismatch$"):
            validate_recovery_manifest_pages(
                digest_mismatch,
                pages,
                recorded_raw_bodies,
            )
        mutated_pages = copy.deepcopy(pages)
        mutated_pages[-1]["source_devices"][0]["max_author_counter"] = "1"
        mutated_raw_bodies = recorded_fixture_raw_page_bodies(mutated_pages)
        with self.assertRaisesRegex(ValueError, r"^pages_sha256 mismatch$"):
            validate_recovery_manifest_pages(
                manifest,
                mutated_pages,
                mutated_raw_bodies,
            )

        raw_digest_cases = {
            case["name"]: case
            for case in fixture["raw_body_digest_cases"]
        }
        self.assertEqual(
            set(raw_digest_cases),
            {
                "recorded_fixture_bodies",
                "leading_whitespace_added",
                "top_level_keys_reordered",
            },
        )
        self.assertEqual(
            raw_digest_cases["recorded_fixture_bodies"]["result"],
            "matches_manifest",
        )

        whitespace_bodies = list(recorded_raw_bodies)
        whitespace_bodies[0] = b" " + whitespace_bodies[0]
        self.assertEqual(
            json.loads(whitespace_bodies[0]),
            pages[0],
        )
        self.assertNotEqual(whitespace_bodies[0], recorded_raw_bodies[0])
        self.assertNotEqual(
            recovery_raw_bodies_sha256(whitespace_bodies),
            manifest["pages_sha256"],
        )
        with self.assertRaisesRegex(ValueError, r"^pages_sha256 mismatch$"):
            validate_recovery_manifest_pages(
                manifest,
                pages,
                whitespace_bodies,
            )
        whitespace_case = raw_digest_cases["leading_whitespace_added"]
        self.assertTrue(whitespace_case["semantic_pages_equal"])
        self.assertFalse(whitespace_case["raw_bytes_equal"])
        self.assertEqual(
            whitespace_case["result"],
            "manifest_digest_mismatch",
        )
        self.assertFalse(whitespace_case["destination_activated"])

        reordered_bodies = list(recorded_raw_bodies)
        reordered_bodies[0] = json.dumps(
            pages[0],
            sort_keys=False,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        self.assertEqual(json.loads(reordered_bodies[0]), pages[0])
        self.assertNotEqual(reordered_bodies[0], recorded_raw_bodies[0])
        self.assertNotEqual(
            recovery_raw_bodies_sha256(reordered_bodies),
            manifest["pages_sha256"],
        )
        with self.assertRaisesRegex(ValueError, r"^pages_sha256 mismatch$"):
            validate_recovery_manifest_pages(
                manifest,
                pages,
                reordered_bodies,
            )
        reordered_case = raw_digest_cases["top_level_keys_reordered"]
        self.assertTrue(reordered_case["semantic_pages_equal"])
        self.assertFalse(reordered_case["raw_bytes_equal"])
        self.assertEqual(
            reordered_case["result"],
            "manifest_digest_mismatch",
        )
        self.assertFalse(reordered_case["destination_activated"])
        self.assertEqual(
            [page["phase"] for page in pages],
            imported["page_phases"],
        )
        self.assertEqual(
            [parse_uint64(page["page_index"]) for page in pages],
            list(range(len(pages))),
        )
        imported_revisions = [
            revision for page in pages for revision in page["revisions"]
        ]
        imported_markers = [
            marker for page in pages for marker in page["collection_markers"]
        ]
        imported_source_devices = [
            source_device
            for page in pages
            for source_device in page["source_devices"]
        ]
        self.assertEqual(
            len(imported_revisions),
            parse_uint64(manifest["revision_count"]),
        )
        self.assertEqual(imported_revisions, snapshot_revisions)
        self.assertEqual(
            len(imported_markers),
            parse_uint64(manifest["collection_marker_count"]),
        )
        self.assertEqual(imported_markers, source["collection_markers"])
        imported_marker_keys = [
            uuid.UUID(marker["record_id"]).bytes
            for marker in imported_markers
        ]
        self.assertEqual(imported_marker_keys, sorted(imported_marker_keys))
        self.assertEqual(
            len(imported_marker_keys),
            len(set(imported_marker_keys)),
        )
        self.assertEqual(
            imported["collection_marker_pages_sorted_by"],
            ["record_id_uuid_bytes"],
        )
        self.assertTrue(
            imported[
                "server_has_no_vmk_and_does_not_verify_aead_or_collection_witness_hmac"
            ]
        )
        self.assertTrue(
            imported[
                "server_enforces_canonical_shape_order_uniqueness_and_counter_bounds"
            ]
        )
        self.assertEqual(
            len(imported_source_devices),
            parse_uint64(manifest["source_device_count"]),
        )
        self.assertEqual(imported_source_devices, source["source_devices"])
        self.assertEqual(imported_source_devices, snapshot_source_devices)
        self.assertTrue(imported["collection_markers_imported_before_activation"])
        self.assertTrue(
            imported["complete_source_device_registry_imported_before_activation"]
        )
        self.assertEqual(
            imported["conflicting_duplicate_marker"],
            "refuse_recovery_import",
        )
        self.assertEqual(
            imported["conflicting_duplicate_source_device"],
            "refuse_recovery_import",
        )
        duplicate_source_devices = copy.deepcopy(imported_source_devices)
        duplicate_source_device = copy.deepcopy(duplicate_source_devices[0])
        duplicate_source_device["max_author_counter"] = "1"
        duplicate_source_devices.append(duplicate_source_device)
        with self.assertRaisesRegex(
            ValueError,
            r"^duplicate source device entry$",
        ):
            source_device_counter_map(
                sorted(
                    duplicate_source_devices,
                    key=lambda item: uuid.UUID(item["device_id"]).bytes,
                )
            )
        with self.assertRaisesRegex(
            ValueError,
            r"^source device entries are not sorted$",
        ):
            source_device_counter_map(list(reversed(imported_source_devices)))
        self.assertTrue(
            imported[
                "staged_envelope_and_reconstructed_retired_devices_are_activation_baseline"
            ]
        )
        self.assertFalse(imported["activation_baseline_rows_receive_change_cursors"])
        self.assertTrue(imported["mandatory_post_recovery_enrollment_cursor_reserved"])
        self.assertTrue(
            imported["mandatory_post_recovery_enrollment_device_slot_reserved"]
        )
        self.assertTrue(imported["all_source_device_ids_marked_retired"])
        self.assertTrue(
            imported[
                "source_max_author_counters_reconstructed_from_authoritative_device_registry"
            ]
        )
        self.assertTrue(
            imported["all_authors_vectors_and_frontiers_reference_registered_devices"]
        )
        self.assertTrue(imported["all_referenced_counters_at_or_below_registry_max"])
        referenced_counters: dict[str, int] = {}
        for revision in imported_revisions:
            self.assertIn(revision["author_device_id"], source_registry)
            for device_id, counter in validate_revision_vector(revision).items():
                referenced_counters[device_id] = max(
                    referenced_counters.get(device_id, 0),
                    counter,
                )
        for marker in imported_markers:
            for device_id, counter in vector_map(
                {"version_vector": marker["frontier"]}
            ).items():
                referenced_counters[device_id] = max(
                    referenced_counters.get(device_id, 0),
                    counter,
                )
        expected_counters = {
            item["device_id"]: parse_uint64(item["max_author_counter"])
            for item in imported["reconstructed_source_max_author_counters"]
        }
        self.assertEqual(expected_counters, source_registry)
        self.assertTrue(set(referenced_counters).issubset(source_registry))
        for device_id, counter in referenced_counters.items():
            self.assertLessEqual(counter, source_registry[device_id])
        never_authored = imported[
            "never_authored_source_device_reconstructed_retired"
        ]
        self.assertEqual(
            never_authored,
            snapshot_fixture["expected"]["never_authored_source_device_id"],
        )
        self.assertIn(never_authored, source_registry)
        self.assertEqual(source_registry[never_authored], 0)
        self.assertNotIn(never_authored, referenced_counters)
        self.assertFalse(
            imported["source_token_hashes_scopes_status_timestamps_copied"]
        )
        self.assertFalse(imported["source_acknowledgements_copied"])
        self.assertFalse(imported["source_tombstone_retention_age_copied"])
        self.assertEqual(parse_uint64(imported["destination_tombstone_retention_age_seconds"]), 0)
        source_cut = parse_uint64(cursors["source_cut_cursor"])
        self.assertEqual(parse_uint64(cursors["destination_cursor_floor"]), source_cut)
        imported_cursors = [parse_uint64(value) for value in cursors["imported_item_cursors"]]
        self.assertEqual(imported_cursors, list(range(source_cut + 1, source_cut + 1 + len(imported_cursors))))
        self.assertEqual(
            len(imported_cursors),
            len(imported_revisions) + len(imported_markers),
        )
        self.assertGreater(len(imported_source_devices), 0)
        self.assertFalse(imported["activation_baseline_rows_receive_change_cursors"])
        self.assertEqual(parse_uint64(cursors["destination_import_end_cursor"]), imported_cursors[-1])
        self.assertEqual(
            cursors["recovering_device_resumes_delta_after_cursor"],
            cursors["destination_import_end_cursor"],
        )
        enrollment_cursor = parse_uint64(
            cursors["mandatory_post_recovery_enrollment_cursor"]
        )
        self.assertEqual(
            enrollment_cursor,
            parse_uint64(cursors["destination_import_end_cursor"]) + 1,
        )
        self.assertEqual(
            fixture["post_import_enrollment"]["device_state_change_cursor"],
            cursors["mandatory_post_recovery_enrollment_cursor"],
        )
        capacity = fixture["cursor_capacity"]
        item_count = parse_uint64(capacity["imported_item_count"])
        reserved_enrollment_count = parse_uint64(
            capacity["reserved_enrollment_cursor_count"]
        )
        self.assertEqual(reserved_enrollment_count, 1)
        exact_fit = capacity["exact_fit"]
        self.assertEqual(
            parse_uint64(exact_fit["source_cut_cursor"]) + item_count,
            parse_uint64(exact_fit["destination_import_end_cursor"]),
        )
        self.assertEqual(
            parse_uint64(exact_fit["destination_import_end_cursor"])
            + reserved_enrollment_count,
            parse_uint64(exact_fit["mandatory_post_recovery_enrollment_cursor"]),
        )
        self.assertEqual(
            parse_uint64(exact_fit["mandatory_post_recovery_enrollment_cursor"]),
            (1 << 64) - 1,
        )
        self.assertEqual(exact_fit["result"], "accepted")
        overflow = capacity["overflow"]
        self.assertEqual(
            parse_uint64(overflow["source_cut_cursor"]) + item_count,
            (1 << 64) - 1,
        )
        self.assertGreater(
            parse_uint64(overflow["source_cut_cursor"])
            + item_count
            + reserved_enrollment_count,
            (1 << 64) - 1,
        )
        self.assertEqual(overflow["result"], "server_cursor_exhausted")
        self.assertFalse(overflow["staging_state_created"])
        self.assertTrue(capacity["checked_at_recovery_begin_and_finalize"])
        device_capacity = fixture["device_registry_capacity"]
        max_devices = parse_uint64(
            device_capacity["max_active_plus_retired_devices"]
        )
        source_device_count = parse_uint64(
            device_capacity["fixture_source_device_count"]
        )
        reserved_device_slots = parse_uint64(
            device_capacity["reserved_fresh_enrollment_slots"]
        )
        self.assertEqual(source_device_count, len(imported_source_devices))
        self.assertEqual(source_device_count, parse_uint64(manifest["source_device_count"]))
        self.assertEqual(max_devices, 64)
        self.assertEqual(reserved_device_slots, 1)
        self.assertLessEqual(
            source_device_count + reserved_device_slots,
            max_devices,
        )
        self.assertEqual(device_capacity["fixture_result"], "accepted")
        device_exact_fit = device_capacity["exact_fit"]
        self.assertEqual(
            parse_uint64(device_exact_fit["source_device_count"])
            + reserved_device_slots,
            parse_uint64(device_exact_fit["post_enrollment_device_count"]),
        )
        self.assertEqual(
            parse_uint64(device_exact_fit["post_enrollment_device_count"]),
            max_devices,
        )
        self.assertEqual(device_exact_fit["result"], "accepted")
        device_overflow = device_capacity["capacity_exhausted_source"]
        self.assertGreater(
            parse_uint64(device_overflow["source_device_count"])
            + parse_uint64(
                device_overflow["required_fresh_enrollment_slots"]
            ),
            max_devices,
        )
        self.assertEqual(
            device_overflow["result"],
            "recovery_device_capacity_exhausted",
        )
        self.assertFalse(device_overflow["staging_state_created"])
        finalize_capacity = device_capacity["finalize_defense_in_depth"]
        self.assertEqual(
            parse_uint64(
                finalize_capacity["verified_manifest_source_device_count"]
            ),
            parse_uint64(finalize_capacity["imported_unique_source_device_count"]),
        )
        self.assertGreater(
            parse_uint64(finalize_capacity["imported_unique_source_device_count"])
            + parse_uint64(
                finalize_capacity["required_fresh_enrollment_slots"]
            ),
            max_devices,
        )
        self.assertEqual(
            finalize_capacity["result"],
            "recovery_device_capacity_exhausted",
        )
        self.assertFalse(finalize_capacity["destination_activated"])
        self.assertTrue(
            device_capacity["checked_at_recovery_begin_and_finalize"]
        )
        self.assertEqual(
            fixture["failure_rules"][
                "source_registry_leaves_no_fresh_enrollment_slot"
            ],
            "recovery_device_capacity_exhausted",
        )
        generation_capacity = fixture["generation_capacity"]
        self.assertTrue(generation_capacity["source_generations_diverge"])
        self.assertTrue(
            generation_capacity["checked_successors_at_recovery_begin_and_finalize"]
        )
        for fixture_name, source_field, destination_field in (
            (
                "envelope_generation",
                "source_envelope_generation",
                "new_envelope_generation",
            ),
            (
                "instance_secret_generation",
                "source_instance_secret_generation",
                "new_instance_secret_generation",
            ),
        ):
            transition = generation_capacity[fixture_name]
            source_generation = parse_uint64(transition["source"])
            destination_generation = parse_uint64(transition["destination"])
            self.assertEqual(
                transition["source"],
                manifest[source_field],
            )
            self.assertEqual(
                transition["destination"],
                recovered[destination_field],
            )
            self.assertEqual(destination_generation, source_generation + 1)
        self.assertEqual(
            {
                overflow_case["source_field"]
                for overflow_case in generation_capacity["overflow_cases"]
            },
            {
                "source_envelope_generation",
                "source_instance_secret_generation",
            },
        )
        for overflow_case in generation_capacity["overflow_cases"]:
            self.assertEqual(
                parse_uint64(overflow_case["source_value"]),
                (1 << 64) - 1,
            )
            self.assertEqual(
                overflow_case["result"],
                "recovery_generation_exhausted",
            )
            self.assertFalse(overflow_case["staging_state_created"])
        self.assertEqual(
            fixture["failure_rules"]["source_generation_has_no_uint64_successor"],
            "recovery_generation_exhausted",
        )
        self.assertEqual(
            fixture["failure_rules"]["missing_or_incomplete_source_device_registry"],
            "refuse_recovery_import",
        )
        post_enrollment = fixture["post_import_enrollment"]
        self.assertNotIn(post_enrollment["new_device_id"], source_registry)
        self.assertFalse(post_enrollment["old_device_ids_reusable"])
        barrier = fixture["post_import_collection_barrier"]
        persisted = vector_map({"version_vector": barrier["persisted_frontier"]})
        self.assertEqual(
            persisted,
            vector_map({"version_vector": imported_markers[0]["frontier"]}),
        )
        equal_upload = vector_map(barrier["equal_frontier_upload"])
        older_upload = vector_map(barrier["older_upload"])
        dominating_upload = vector_map(barrier["dominating_upload"])
        self.assertTrue(
            barrier[
                "new_mutation_causal_context_includes_verified_marker_frontiers"
            ]
        )
        self.assertFalse(dominates(equal_upload, persisted))
        self.assertFalse(dominates(older_upload, persisted))
        self.assertTrue(dominates(dominating_upload, persisted))
        self.assertEqual(
            barrier["dominating_upload"]["author_device_id"],
            fixture["post_import_enrollment"]["new_device_id"],
        )
        self.assertEqual(
            dominating_upload[
                barrier["dominating_upload"]["author_device_id"]
            ],
            parse_uint64(barrier["dominating_upload"]["author_counter"]),
        )
        self.assertTrue(
            barrier["dominating_upload"][
                "causal_context_from_verified_marker_frontiers"
            ]
        )
        self.assertTrue(
            set(persisted.items()).issubset(dominating_upload.items())
        )
        self.assertEqual(
            barrier["equal_frontier_upload"]["result"],
            "stale_after_collection",
        )
        self.assertEqual(
            barrier["older_upload"]["result"],
            "stale_after_collection",
        )
        self.assertEqual(barrier["dominating_upload"]["result"], "accepted")
        self.assertTrue(barrier["marker_active_at_destination_activation"])
        self.assertFalse(barrier["stale_revision_resurrection_allowed"])
        normalized_protocol = re.sub(r"\s+", " ", self.protocol_text)
        normalized_threat = re.sub(r"\s+", " ", self.threat_text)
        self.assertIn(
            "every later mutation for that record must dominate its imported marker frontier",
            normalized_protocol,
        )
        self.assertIn(
            "component-wise maximum of every durable revision vector and every retained, cryptographically verified collection-marker frontier",
            normalized_protocol,
        )
        self.assertIn(
            "recovery never resets the barrier",
            normalized_threat,
        )
        self.assertIn("recovery_generation_exhausted", normalized_protocol)
        self.assertIn("recovery_device_capacity_exhausted", normalized_protocol)

    def _assert_record_revision_shape(self, revision: dict) -> None:
        for field in ("record_id", "revision_id", "author_device_id"):
            assert_uuid_v4(self, revision[field])
        authenticator = revision["collection_witness_authenticator"]
        if authenticator is not None:
            self.assertEqual(len(decode_base64url(authenticator)), 32)
        self.assertEqual(len(decode_base64url(revision["nonce"])), 24)
        self.assertGreaterEqual(len(decode_base64url(revision["ciphertext"])), 16)
        self.assertTrue(validate_revision_vector(revision))


if __name__ == "__main__":
    unittest.main()
