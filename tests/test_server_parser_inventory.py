import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "docs" / "SERVER_PARSER_INVENTORY.json"

EXPECTED_SIGNALS = {
    "build_metadata_parser": r"\bfunc\s+validLocalMainVersion\s*\(",
    "header_token_parser": r"\bfunc\s+headerContainsToken\s*\(",
    "install_command_parser": r"\bfunc\s+InstallCommand\s*\(",
    "json_decoder_constructor": r"\bjson\.NewDecoder\s*\(",
    "json_unmarshal_call": r"\bjson\.Unmarshal\s*\(",
    "listener_validator": r"\bfunc\s+ValidateListener\s*\(",
    "parser_function_declaration": (
        r"\bfunc\s+(?:(?:P|p)arse|decode)[A-Za-z0-9_]*\s*\("
    ),
    "release_identifier_validator": r"\bfunc\s+Valid\s*\(",
    "url_parser_call": r"\burl\.(?:Parse|ParseQuery)\s*\(",
}


def strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


class ServerParserInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = json.loads(
            INVENTORY_PATH.read_text(encoding="utf-8"),
            object_pairs_hook=strict_json_object,
        )

    def test_inventory_rejects_duplicate_json_keys(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate JSON key: id"):
            json.loads(
                '{"id":"first","id":"second"}',
                object_pairs_hook=strict_json_object,
            )

    @staticmethod
    def signal_counts(source: str) -> dict[str, int]:
        counts = {
            name: len(re.findall(pattern, source))
            for name, pattern in EXPECTED_SIGNALS.items()
        }
        return {name: count for name, count in counts.items() if count}

    def derived_source_signal_counts(self) -> dict[str, dict[str, int]]:
        result = {}
        for path in sorted((ROOT / "runtime").rglob("*.go")):
            relative = str(path.relative_to(ROOT))
            if "/third_party/" in relative or relative.endswith("_test.go"):
                continue
            if relative.startswith("runtime/conformance/"):
                continue
            counts = self.signal_counts(path.read_text(encoding="utf-8"))
            if counts:
                result[relative] = counts
        return result

    def test_inventory_is_exactly_source_derived_and_fails_closed(self) -> None:
        derivation = self.inventory["sourceDerivation"]
        self.assertEqual(derivation["signals"], EXPECTED_SIGNALS)
        derived = self.derived_source_signal_counts()
        self.assertEqual(derivation["sourceSignalCounts"], derived)
        self.assertEqual(derivation["sourceFileCount"], len(derived))
        self.assertEqual(
            derivation["sourceSignalCount"],
            sum(sum(counts.values()) for counts in derived.values()),
        )

    def test_every_signal_bearing_file_has_a_fuzz_owner(self) -> None:
        derived_files = set(self.derived_source_signal_counts())
        boundaries = self.inventory["boundaries"]
        self.assertEqual(
            len({boundary["id"] for boundary in boundaries}), len(boundaries)
        )
        inventoried_files = {
            source
            for boundary in boundaries
            for source in boundary["sourceFiles"]
        }
        self.assertEqual(inventoried_files, derived_files)
        owners = set(self.inventory["coverageOwners"])
        used_owners = set()
        for boundary in boundaries:
            with self.subTest(boundary=boundary["id"]):
                self.assertTrue(boundary["sourceFiles"])
                self.assertTrue(boundary["coverageOwners"])
                self.assertTrue(set(boundary["coverageOwners"]) <= owners)
                used_owners.update(boundary["coverageOwners"])
        self.assertEqual(used_owners, owners)

    def test_every_fuzz_owner_is_executable_and_has_checked_in_corpus(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        for owner_id, owner in self.inventory["coverageOwners"].items():
            with self.subTest(owner=owner_id):
                self.assertEqual(
                    set(owner), {"corpus", "package", "testFile", "testMethod"}
                )
                test_file = ROOT / owner["testFile"]
                self.assertTrue(test_file.is_file())
                self.assertRegex(
                    test_file.read_text(encoding="utf-8"),
                    rf"\bfunc\s+{re.escape(owner['testMethod'])}\s*\(",
                )
                corpus = ROOT / owner["corpus"]
                seeds = sorted(path for path in corpus.iterdir() if path.is_file())
                self.assertTrue(seeds)
                for seed in seeds:
                    self.assertLessEqual(len(seed.read_bytes()), 256)
                    self.assertTrue(seed.read_bytes().startswith(b"go test fuzz v1\n"))
                self.assertEqual(
                    makefile.count(f"-fuzz '^{owner['testMethod']}$$'"), 1
                )
                self.assertIn(owner["package"], makefile)

    def test_a_new_parser_signal_cannot_hide_behind_an_existing_file(self) -> None:
        derived = self.derived_source_signal_counts()
        path = "runtime/internal/store/models.go"
        simulated = {key: dict(value) for key, value in derived.items()}
        simulated[path]["json_decoder_constructor"] += 1
        self.assertNotEqual(
            simulated, self.inventory["sourceDerivation"]["sourceSignalCounts"]
        )

    def test_persisted_canonical_destination_inventory_is_exact(self) -> None:
        source = (
            ROOT / "runtime/internal/store/scalar_fuzz_test.go"
        ).read_text(encoding="utf-8")
        table = source[
            source.index("var storedJSONShapeFuzzTargets") :
            source.index("func FuzzStoredJSONShapes")
        ]
        destinations = set(
            re.findall(
                r"newDestination:\s*func\(\) any \{ return &([^{}]+)\{\} \}",
                table,
            )
        )
        self.assertEqual(
            destinations,
            {
                "[]string",
                "[]api.Header",
                "vaultEnvelope",
                "recordRevision",
                "[]vectorEntry",
                "collectionMarker",
                "snapshotPageDescriptor",
                "syncResponse",
                "device",
                "enrollmentResponse",
                "snapshotCreateResponse",
            },
        )
        devices = (ROOT / "runtime/internal/store/devices.go").read_text(
            encoding="utf-8"
        )
        validation = (ROOT / "runtime/internal/store/validation.go").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "decodeStoredCanonical(headersBody, &receipt.headers)", devices
        )
        self.assertIn("decodeStoredCanonical(headersBody, &headers)", validation)
        self.assertIn(
            "TestFuzzStoredJSONShapesHasAcceptedSeedsForEveryDestination",
            source,
        )

    def test_config_and_deployment_fuzzers_apply_production_semantics(self) -> None:
        config_fuzzer = (
            ROOT / "runtime/internal/config/config_fuzz_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn("value.(*Settings).Validate()", config_fuzzer)
        self.assertIn("value.(*InstallMarker).Validate()", config_fuzzer)

        deployment_fuzzer = (
            ROOT / "runtime/internal/deployment/metadata_fuzz_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn("value.(*DeploymentState).Validate(layout)", deployment_fuzzer)
        self.assertIn(
            "value.(*DeploymentJournal).Validate(layout)", deployment_fuzzer
        )

    def test_exclusions_remain_narrow_and_explicit(self) -> None:
        exclusions = {entry["id"]: entry["reason"] for entry in self.inventory["exclusions"]}
        self.assertEqual(
            set(exclusions),
            {
                "conformance-tool",
                "stdlib-cli-flags-and-static-templates",
                "tests-and-vendored-runtime",
            },
        )
        for identifier, reason in exclusions.items():
            with self.subTest(exclusion=identifier):
                self.assertGreater(len(reason), 80)


if __name__ == "__main__":
    unittest.main()
