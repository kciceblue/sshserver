from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
from pathlib import Path
import re
import struct
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


def parse_uint64(value: str) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise ValueError("not a canonical unsigned decimal string")
    parsed = int(value)
    if not 0 <= parsed <= (1 << 64) - 1:
        raise ValueError("outside uint64")
    return parsed


def vector_map(revision: dict) -> dict[str, int]:
    entries = revision["version_vector"]
    ids = [entry["device_id"] for entry in entries]
    if ids != sorted(ids):
        raise ValueError("vector entries are not sorted")
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate device vector entry")
    return {entry["device_id"]: parse_uint64(entry["counter"]) for entry in entries}


def dominates(left: dict[str, int], right: dict[str, int]) -> bool:
    keys = set(left) | set(right)
    return all(left.get(key, 0) >= right.get(key, 0) for key in keys) and any(
        left.get(key, 0) > right.get(key, 0) for key in keys
    )


def validate_backup_manifest_paths(manifest: dict) -> None:
    """Enforce path-key uniqueness after structural JSON Schema validation."""
    seen: set[str] = set()
    for item in manifest["files"]:
        path = item["path"]
        if path in seen:
            raise ValueError(f"duplicate backup manifest path: {path}")
        seen.add(path)


def schema_matches(value: object, schema: dict, root: dict) -> bool:
    reference = schema.get("$ref")
    if reference is not None:
        if not reference.startswith("#/"):
            raise ValueError(f"external schema reference is unsupported: {reference}")
        target: object = root
        for component in reference.removeprefix("#/").split("/"):
            if not isinstance(target, dict):
                raise ValueError(f"invalid schema reference: {reference}")
            target = target[component.replace("~1", "/").replace("~0", "~")]
        if not isinstance(target, dict):
            raise ValueError(f"schema reference is not an object: {reference}")
        if not schema_matches(value, target, root):
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
        if sum(schema_matches(value, child, root) for child in schema["oneOf"]) != 1:
            return False
    if "allOf" in schema:
        if not all(schema_matches(value, child, root) for child in schema["allOf"]):
            return False
    if "if" in schema and schema_matches(value, schema["if"], root):
        if "then" in schema and not schema_matches(value, schema["then"], root):
            return False

    if isinstance(value, dict):
        required = set(schema.get("required", []))
        if not required.issubset(value):
            return False
        properties = schema.get("properties", {})
        for key, child in properties.items():
            if key in value and not schema_matches(value[key], child, root):
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
            if not all(schema_matches(item, schema["items"], root) for item in value):
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
        self.assertIn("404", revoke_statuses)
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
        self.assertEqual(self.openapi["x-jat-error-status-map"]["server_cursor_exhausted"], 507)
        self.assertEqual(self.openapi["x-jat-error-status-map"]["device_not_found"], 404)
        self.assertEqual(
            self.openapi["x-jat-error-status-map"]["authenticated_device_mismatch"],
            403,
        )
        envelope_schema = defs["vault_envelope"]
        self.assertEqual(len(envelope_schema["allOf"]), 2)

    def test_uint64_schema_and_semantic_parser_enforce_the_exact_maximum(self) -> None:
        pattern = re.compile(self.wire["$defs"]["uint64"]["pattern"])
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
        for value in rejected:
            with self.subTest(value=value, result="rejected"):
                self.assertIsNone(pattern.fullmatch(value))
                with self.assertRaises(ValueError):
                    parse_uint64(value)

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
        cases = {case["name"]: case["result"] for case in fixture["cases"]}
        self.assertEqual(cases["stale_writer"], "generation_conflict")
        self.assertEqual(cases["skip_generation"], "invalid_request")

        crypto = self.fixtures["crypto-review-vectors.json"]
        self.assertEqual(crypto["proposed_argon2id"]["version"], 19)
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

        first_vector = vector_map(first)
        second_vector = vector_map(second)
        resolution_vector = vector_map(resolution)
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
        self.assertTrue(barrier["collection_marker_persists_joined_frontier"])
        marker = barrier["collection_marker"]
        self.assertEqual(marker["barrier_cursor"], resolved["barrier_cursor"])
        self.assertEqual(
            vector_map({"version_vector": marker["frontier"]}),
            vector_map({"version_vector": barrier["dominating_resolution"]["vector"]}),
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
        secret_rotation = fixture["instance_secret_rotation"]
        self.assertEqual(secret_rotation["rotation_without_device_held_vmk"], "forbidden")
        self.assertGreaterEqual(len(secret_rotation["states"]), 5)
        self.assertEqual(
            secret_rotation["backup_while_pending_or_recovery_slot_exists"],
            "refused_rotation_in_progress",
        )
        version_results = {case["result"]: case for case in fixture["version_negotiation"]}
        self.assertEqual(version_results["unsupported_protocol"]["http_status"], 426)
        unsupported_capabilities = [
            case
            for case in fixture["version_negotiation"]
            if case["result"] == "unsupported_capability"
        ]
        self.assertEqual(
            {case["missing_required_capability"] for case in unsupported_capabilities},
            {"envelope-cas-v1", "snapshot-collection-markers-v1"},
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

    def test_backup_fixture_is_complete_sensitive_and_fail_closed(self) -> None:
        fixture = self.fixtures["api-and-recovery.json"]
        manifest = fixture["backup_manifest"]
        assert_uuid_v4(self, manifest["instance_id"])
        assert_uuid_v4(self, manifest["vault_id"])
        self.assertEqual({item["path"] for item in manifest["files"]}, {"sync.db", "instance-secret", "config.json"})
        self.assertEqual(manifest["secret_rotation_state"], "stable")
        self.assertIn("collection_marker_count", self.backup_schema["required"])
        self.assertEqual(parse_uint64(manifest["collection_marker_count"]), 1)
        self.assertEqual(
            self.backup_schema["properties"]["secret_rotation_state"]["const"],
            "stable",
        )
        validate_backup_manifest_paths(manifest)
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
        self.assertIn(
            "Every path value MUST be unique",
            self.backup_schema["properties"]["files"]["description"],
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
        self.assertEqual(capabilities["crypto_suites"], ["jat-xchacha-hkdf-argon2id-draft1"])
        self.assertEqual(
            capabilities["capabilities"],
            sorted(capabilities["capabilities"]),
        )
        self.assertTrue(
            {"snapshot-read-v1", "snapshot-collection-markers-v1"}.issubset(
                capabilities["capabilities"]
            )
        )
        self.assertEqual(capabilities["limits"]["max_snapshot_page_revisions"], 128)
        self.assertEqual(
            capabilities["limits"]["max_snapshot_page_collection_markers"],
            128,
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

    def test_full_snapshot_is_stable_sibling_complete_and_transitions_to_delta(self) -> None:
        fixture = self.fixtures["full-snapshot-recovery.json"]
        create_request = fixture["create_request"]
        create_response = fixture["create_response"]
        assert_uuid_v4(self, create_request["device_id"])
        assert_uuid_v4(self, create_request["request_id"])
        assert_uuid_v4(self, create_response["snapshot_id"])
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
            self.assertFalse(
                response_page["revisions"] and response_page["collection_markers"]
            )
            revisions.extend(response_page["revisions"])
            collection_markers.extend(response_page["collection_markers"])
            if response_page["revisions"]:
                phases.append("record_revisions")
            elif response_page["collection_markers"]:
                phases.append("collection_markers")
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
        self.assertFalse(dominates(vector_map(revisions[0]), vector_map(revisions[1])))
        self.assertFalse(dominates(vector_map(revisions[1]), vector_map(revisions[0])))
        marker_keys = [
            (
                uuid.UUID(item["record_id"]).bytes,
                uuid.UUID(item["collected_revision_id"]).bytes,
            )
            for item in collection_markers
        ]
        self.assertEqual(marker_keys, sorted(marker_keys))
        self.assertEqual(
            len(collection_markers),
            fixture["expected"]["collection_marker_count"],
        )
        self.assertTrue(fixture["expected"]["all_persistent_collection_markers_included"])
        self.assertTrue(fixture["expected"]["collection_marker_frontiers_preserved"])
        for marker in collection_markers:
            self.assertLessEqual(parse_uint64(marker["barrier_cursor"]), cut)
            self.assertTrue(vector_map({"version_vector": marker["frontier"]}))

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
        marker_page = fixture["pages"][-1]["response"]

        mixed_page = copy.deepcopy(revision_page)
        mixed_page["collection_markers"] = copy.deepcopy(
            marker_page["collection_markers"]
        )
        self.assertFalse(schema_matches(mixed_page, schema, self.wire))

        empty_nonterminal_page = copy.deepcopy(revision_page)
        empty_nonterminal_page["revisions"] = []
        self.assertFalse(schema_matches(empty_nonterminal_page, schema, self.wire))

        null_nonterminal_token = copy.deepcopy(revision_page)
        null_nonterminal_token["next_page_token"] = None
        self.assertFalse(schema_matches(null_nonterminal_token, schema, self.wire))

        token_on_final_page = copy.deepcopy(marker_page)
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
        self.assertEqual(source["collection_markers"], snapshot_markers)
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
        self.assertEqual(recovered["instance_id"], source["instance_id"])
        self.assertEqual(recovered["vault_id"], source["vault_id"])
        self.assertTrue(recovered["record_ciphertexts_byte_identical"])
        self.assertTrue(
            recovered["record_ids_revision_ids_vectors_and_tombstone_flags_byte_identical"]
        )
        self.assertTrue(recovered["collection_markers_and_frontiers_byte_identical"])
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
        self.assertEqual(parse_uint64(manifest["page_count"]), len(pages))
        digest = hashlib.sha256()
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
            body = json.dumps(
                page,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
            digest.update(struct.pack(">Q", len(body)))
            digest.update(body)
        self.assertEqual(digest.hexdigest(), manifest["pages_sha256"])
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
        self.assertTrue(imported["collection_markers_imported_before_activation"])
        self.assertEqual(
            imported["conflicting_duplicate_marker"],
            "refuse_recovery_import",
        )
        self.assertTrue(
            imported[
                "staged_envelope_and_reconstructed_retired_devices_are_activation_baseline"
            ]
        )
        self.assertFalse(imported["activation_baseline_rows_receive_change_cursors"])
        self.assertTrue(imported["mandatory_post_recovery_enrollment_cursor_reserved"])
        self.assertTrue(imported["all_source_device_ids_marked_retired"])
        self.assertTrue(
            imported[
                "source_max_author_counters_reconstructed_from_revision_vectors_and_marker_frontiers"
            ]
        )
        reconstructed_counters: dict[str, int] = {}
        for revision in imported_revisions:
            for device_id, counter in vector_map(revision).items():
                reconstructed_counters[device_id] = max(
                    reconstructed_counters.get(device_id, 0),
                    counter,
                )
        for marker in imported_markers:
            for device_id, counter in vector_map(
                {"version_vector": marker["frontier"]}
            ).items():
                reconstructed_counters[device_id] = max(
                    reconstructed_counters.get(device_id, 0),
                    counter,
                )
        expected_counters = {
            item["device_id"]: parse_uint64(item["counter"])
            for item in imported["reconstructed_source_max_author_counters"]
        }
        self.assertEqual(reconstructed_counters, expected_counters)
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
        barrier = fixture["post_import_collection_barrier"]
        persisted = vector_map({"version_vector": barrier["persisted_frontier"]})
        self.assertEqual(
            persisted,
            vector_map({"version_vector": imported_markers[0]["frontier"]}),
        )
        equal_upload = vector_map(barrier["equal_frontier_upload"])
        older_upload = vector_map(barrier["older_upload"])
        dominating_upload = vector_map(barrier["dominating_upload"])
        self.assertFalse(dominates(equal_upload, persisted))
        self.assertFalse(dominates(older_upload, persisted))
        self.assertTrue(dominates(dominating_upload, persisted))
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
            "every later mutation for that record must dominate every imported marker frontier",
            normalized_protocol,
        )
        self.assertIn(
            "recovery never resets the barrier",
            normalized_threat,
        )
        self.assertIn("recovery_generation_exhausted", normalized_protocol)

    def _assert_record_revision_shape(self, revision: dict) -> None:
        for field in ("record_id", "revision_id", "author_device_id"):
            assert_uuid_v4(self, revision[field])
        self.assertEqual(len(decode_base64url(revision["nonce"])), 24)
        self.assertGreaterEqual(len(decode_base64url(revision["ciphertext"])), 16)
        author_counter = parse_uint64(revision["author_counter"])
        vector = vector_map(revision)
        self.assertEqual(vector[revision["author_device_id"]], author_counter)


if __name__ == "__main__":
    unittest.main()
