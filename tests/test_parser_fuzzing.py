import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ParserFuzzingPolicyTests(unittest.TestCase):
    def test_every_server_parser_target_has_a_checked_in_minimized_seed(self) -> None:
        targets = {
            "runtime/internal/store/models_fuzz_test.go": "FuzzDecodeStrictJSON",
            "runtime/internal/store/scalar_fuzz_test.go#shapes": "FuzzStoredJSONShapes",
            "runtime/internal/store/scalar_fuzz_test.go#scalars": "FuzzStoreScalarAndStoredParsers",
            "runtime/internal/store/dataplane_fuzz_test.go": "FuzzPathIdentifier",
            "runtime/internal/store/dataplane_fuzz_test.go#receipts": "FuzzOperationReceiptKey",
            "runtime/internal/store/schema_fuzz_test.go": "FuzzSQLiteSchemaState",
            "runtime/internal/deployment/parser_fuzz_test.go": "FuzzParsePinnedManifest",
            "runtime/internal/deployment/parser_fuzz_test.go#preview": "FuzzParseDeploymentPreview",
            "runtime/internal/deployment/metadata_fuzz_test.go#metadata": "FuzzDecodeDeploymentMetadata",
            "runtime/internal/deployment/metadata_fuzz_test.go#identity": "FuzzParseBuildIdentityJSON",
            "runtime/internal/deployment/metadata_fuzz_test.go#scalars": "FuzzDeploymentScalarParsers",
            "runtime/internal/deployment/path_fuzz_test.go": "FuzzDeploymentPathGrammar",
            "runtime/internal/deployment/metadata_fuzz_test.go#go-buildinfo": "FuzzParseArtifactGoBuildInfo",
            "runtime/internal/deployment/remove_artifacts_fuzz_test.go": "FuzzValidateRemovableArtifactName",
            "runtime/internal/deployment/manager_fuzz_test.go": "FuzzServiceManagerOutput",
            "runtime/internal/service/service_fuzz_test.go": "FuzzServiceDefinitionPaths",
            "runtime/internal/server/server_fuzz_test.go": "FuzzDecodeAdminRequest",
            "runtime/internal/server/server_fuzz_test.go#request-head": "FuzzHTTP1RequestHead",
            "runtime/internal/config/config_fuzz_test.go": "FuzzDecodeConfigJSON",
            "runtime/internal/cli/response_fuzz_test.go": "FuzzDecodeCLIResponses",
            "runtime/internal/buildinfo/buildinfo_fuzz_test.go": "FuzzParseAttestation",
            "runtime/internal/uuidv4/uuid_fuzz_test.go": "FuzzParseUUIDv4",
            "runtime/internal/releaseid/releaseid_fuzz_test.go": "FuzzReleaseIdentifier",
            "runtime/internal/releasebundle/installer_fuzz_test.go": "FuzzInstallCommandInput",
            "runtime/internal/releasebundle/bundle_fuzz_test.go": "FuzzValidLocalMainVersion",
            "runtime/internal/releasebundle/buildinfo_fuzz_test.go": "FuzzParseReleaseBundleGoBuildInfo",
            "runtime/internal/httpapi/handler_fuzz_test.go": "FuzzHeaderContainsToken",
            "runtime/internal/httpapi/handler_fuzz_test.go#transport": "FuzzValidateTransportRequest",
            "runtime/internal/httpapi/handler_fuzz_test.go#body": "FuzzHTTPBodyFraming",
        }
        for source_key, target in targets.items():
            source = ROOT / source_key.split("#", 1)[0]
            self.assertIn(f"func {target}(f *testing.F)", source.read_text(encoding="utf-8"))
            corpus = source.parent / "testdata" / "fuzz" / target
            seeds = sorted(path for path in corpus.iterdir() if path.is_file())
            self.assertGreaterEqual(len(seeds), 1, target)
            for seed in seeds:
                payload = seed.read_bytes()
                self.assertLessEqual(len(payload), 256, seed)
                self.assertTrue(payload.startswith(b"go test fuzz v1\n"), seed)

    def test_complete_gate_runs_each_fuzz_target_with_a_bounded_budget(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        check_line = next(line for line in makefile.splitlines() if line.startswith("check:"))
        self.assertIn("runtime-fuzz-smoke", check_line)
        deterministic_budget = (
            "-fuzztime=64x -fuzzminimizetime=64x -parallel=1"
        )
        self.assertEqual(makefile.count(deterministic_budget), 29)
        for target in (
            "FuzzDecodeStrictJSON",
            "FuzzStoredJSONShapes",
            "FuzzStoreScalarAndStoredParsers",
            "FuzzPathIdentifier",
            "FuzzOperationReceiptKey",
            "FuzzSQLiteSchemaState",
            "FuzzParsePinnedManifest",
            "FuzzParseDeploymentPreview",
            "FuzzDecodeDeploymentMetadata",
            "FuzzParseBuildIdentityJSON",
            "FuzzDeploymentScalarParsers",
            "FuzzDeploymentPathGrammar",
            "FuzzParseArtifactGoBuildInfo",
            "FuzzValidateRemovableArtifactName",
            "FuzzServiceManagerOutput",
            "FuzzServiceDefinitionPaths",
            "FuzzDecodeAdminRequest",
            "FuzzHTTP1RequestHead",
            "FuzzDecodeConfigJSON",
            "FuzzDecodeCLIResponses",
            "FuzzParseAttestation",
            "FuzzParseUUIDv4",
            "FuzzReleaseIdentifier",
            "FuzzInstallCommandInput",
            "FuzzValidLocalMainVersion",
            "FuzzParseReleaseBundleGoBuildInfo",
            "FuzzHeaderContainsToken",
            "FuzzValidateTransportRequest",
            "FuzzHTTPBodyFraming",
        ):
            self.assertEqual(makefile.count(f"-fuzz '^{target}$$'"), 1, target)

    def test_documentation_keeps_the_cross_repository_claim_open(self) -> None:
        documentation = (ROOT / "docs" / "PARSER_FUZZING.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("make runtime-fuzz-smoke", documentation)
        self.assertIn("does not claim", documentation)
        self.assertIn("client parsers", documentation)
        self.assertIn("24-hour soak", documentation)


if __name__ == "__main__":
    unittest.main()
