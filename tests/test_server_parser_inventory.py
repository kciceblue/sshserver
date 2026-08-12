import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "docs" / "SERVER_PARSER_INVENTORY.json"

EXPECTED_SIGNALS = {
    "artifact_expectation_parser": r"\bfunc\s+parseArtifactExpectation\s*\(",
    "artifact_name_validator": r"\bfunc\s+validateArtifactName\s*\(",
    "base64_decoder_call": (
        r"\bbase64\.(?:RawURL|URL|RawStd|Std)Encoding"
        r"(?:\.Strict\(\))?\.Decode(?:String)?\s*\("
    ),
    "binary_integer_decoder_call": (
        r"\bbinary\.(?:BigEndian|LittleEndian)\.Uint(?:16|32|64)\s*\("
    ),
    "build_metadata_parser": r"\bfunc\s+validLocalMainVersion\s*\(",
    "bundle_output_grammar": r"\bfunc\s+validateBundleOutput\s*\(",
    "filesystem_path_grammar_call": (
        r"\bfilepath\."
        r"(?:Base|Clean|Dir|EvalSymlinks|IsAbs|Rel|ToSlash)\s*\("
    ),
    "fixed_scope_set_validator": r"\bfunc\s+ValidateScopes\s*\(",
    "go_buildinfo_decoder_call": r"\bdebugbuildinfo\.Read\s*\(",
    "header_token_parser": r"\bfunc\s+headerContainsToken\s*\(",
    "hex_decoder_call": r"\bhex\.(?:Decode|DecodeString)\s*\(",
    "http_request_head_limit_parser": (
        r"\bfunc\s+\(connection\s+\*headerLimitConn\)\s+Read\s*\("
    ),
    "http_request_id_header_parser": r"\bfunc\s+requestIDValues\s*\(",
    "http_transport_validator": r"\bfunc\s+validateTransport\s*\(",
    "install_command_parser": r"\bfunc\s+InstallCommand\s*\(",
    "installed_artifact_filename_validator": (
        r"\bfunc\s+validateRemovableArtifact\s*\("
    ),
    "json_decoder_constructor": r"\bjson\.NewDecoder\s*\(",
    "json_unmarshal_call": r"\bjson\.Unmarshal\s*\(",
    "listener_validator": r"\bfunc\s+ValidateListener\s*\(",
    "network_address_parser_call": (
        r"\bnet\.(?:SplitHostPort|ParseIP|ParseCIDR)\s*\("
    ),
    "operation_receipt_key_parser": r"\bfunc\s+validOperationReceiptKey\s*\(",
    "parser_function_declaration": (
        r"\bfunc\s+(?:[Pp]arse|[Dd]ecode)[A-Za-z0-9_]*\s*\("
    ),
    "regexp_grammar_constructor": r"\bregexp\.(?:MustCompile|Compile)\s*\(",
    "regexp_match_call": (
        r"\b[A-Za-z_][A-Za-z0-9_]*\."
        r"(?:MatchString|FindStringSubmatch)\s*\("
    ),
    "release_identifier_validator": r"\bfunc\s+Valid\s*\(",
    "route_identifier_parser": r"\bfunc\s+pathIdentifier\s*\(",
    "scanner_constructor": r"\bbufio\.NewScanner\s*\(",
    "service_definition_grammar": (
        r"\bfunc\s+(?:Render|validPathText|validateServicePath|"
        r"quoteSystemd(?:ExecArgument|Path)?)\s*\("
    ),
    "service_manager_output_parser": (
        r"(?:\bfunc\s+(?:(?:\(adapter\s+ServiceManagerAdapter\)\s+IsActive)|"
        r"(?:managerUnavailable|managerNotLoaded|systemdInactiveState))\s*\(|"
        r"\bresult\.(?:Stdout|Stderr)\b)"
    ),
    "sqlite_schema_state_parser": (
        r"\bfunc\s+(?:inspectSchemaState|validateSchemaState|readSchemaTables|"
        r"schemaTablesEqual)\s*\("
    ),
    "strconv_parser_call": (
        r"\bstrconv\.(?:Atoi|ParseBool|ParseFloat|ParseInt|ParseUint)\s*\("
    ),
    "slash_path_grammar_call": r"\b(?:path|pathpkg)\.(?:Base|Clean)\s*\(",
    "string_split_parser_call": (
        r"\b(?:bytes|strings)\."
        r"(?:Split|SplitN|Fields|FieldsFunc|Cut|CutPrefix|"
        r"Trim|TrimSpace|TrimPrefix|TrimSuffix)\s*\("
    ),
    "time_parser_call": r"\btime\.Parse\s*\(",
    "url_parser_call": r"\burl\.(?:Parse|ParseQuery)\s*\(",
    "utf8_text_validator_call": r"\butf8\.ValidString\s*\(",
    "xml_text_escape_call": r"\bxml\.EscapeText\s*\(",
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

    def test_service_manager_output_grammar_is_fail_closed_and_executed(self) -> None:
        production = (
            ROOT / "runtime/internal/deployment/manager.go"
        ).read_text(encoding="utf-8")
        counts = self.signal_counts(production)
        self.assertEqual(counts["service_manager_output_parser"], 13)
        self.assertNotEqual(
            self.signal_counts(production + "\nvar extra = result.Stdout\n"),
            counts,
        )

        fuzzer = (
            ROOT / "runtime/internal/deployment/manager_fuzz_test.go"
        ).read_text(encoding="utf-8")
        for production_entrypoint in {
            "managerUnavailable(platform, result)",
            "managerNotLoaded(platform, result)",
            "adapter.IsActive(context.Background())",
            "systemdInactiveState(strings.TrimSpace(stdout))",
            "commandError(ManagerSystemd, \"fuzz status\", result, runErr)",
        }:
            with self.subTest(production_entrypoint=production_entrypoint):
                self.assertIn(production_entrypoint, fuzzer)
        for oracle in {
            "exactManagerUnavailable",
            "exactManagerNotLoaded",
            "exactManagerIsActive",
            "exactSystemdInactiveState",
        }:
            with self.subTest(oracle=oracle):
                self.assertIn(oracle, fuzzer)

    def test_sqlite_schema_grammar_is_fail_closed_and_executed(self) -> None:
        production = (
            ROOT / "runtime/internal/store/schema.go"
        ).read_text(encoding="utf-8")
        counts = self.signal_counts(production)
        self.assertEqual(counts["sqlite_schema_state_parser"], 4)
        self.assertNotEqual(
            self.signal_counts(production + "\nfunc inspectSchemaState() {}\n"),
            counts,
        )

        fuzzer = (
            ROOT / "runtime/internal/store/schema_fuzz_test.go"
        ).read_text(encoding="utf-8")
        for production_entrypoint in {
            "inspectSchemaState(ctx, database)",
            "validateSchemaState(ctx, database)",
            "readSchemaTables(ctx, database)",
            "schemaTablesEqual(fixture.tables, expected)",
        }:
            with self.subTest(production_entrypoint=production_entrypoint):
                self.assertIn(production_entrypoint, fuzzer)
        self.assertIn("exactSchemaFuzzInspection", fuzzer)
        self.assertIn("maps.Equal(fixture.tables, candidate.tables)", fuzzer)
        self.assertIn('"unexpected", "CREATE TABLE unexpected (value TEXT)"', fuzzer)

    def test_generic_grammar_entrypoints_are_fail_closed(self) -> None:
        derived = self.derived_source_signal_counts()
        totals = {
            signal: sum(counts.get(signal, 0) for counts in derived.values())
            for signal in EXPECTED_SIGNALS
        }
        self.assertEqual(totals["scanner_constructor"], 0)
        self.assertEqual(totals["regexp_grammar_constructor"], 14)
        self.assertEqual(totals["regexp_match_call"], 45)
        self.assertEqual(totals["string_split_parser_call"], 29)
        self.assertEqual(totals["strconv_parser_call"], 4)
        self.assertEqual(totals["filesystem_path_grammar_call"], 60)
        self.assertEqual(totals["fixed_scope_set_validator"], 1)
        self.assertEqual(totals["slash_path_grammar_call"], 6)
        self.assertEqual(totals["network_address_parser_call"], 7)
        self.assertEqual(totals["time_parser_call"], 5)
        self.assertEqual(totals["hex_decoder_call"], 3)
        self.assertEqual(totals["base64_decoder_call"], 3)
        self.assertEqual(totals["binary_integer_decoder_call"], 1)
        self.assertEqual(totals["parser_function_declaration"], 25)
        self.assertEqual(totals["utf8_text_validator_call"], 1)
        self.assertEqual(totals["xml_text_escape_call"], 1)
        self.assertEqual(totals["artifact_name_validator"], 1)
        self.assertEqual(totals["artifact_expectation_parser"], 1)
        self.assertEqual(totals["bundle_output_grammar"], 1)

    def test_service_and_deployment_path_grammars_have_exact_owners(self) -> None:
        service = (ROOT / "runtime/internal/service/service.go").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            self.signal_counts(service)["service_definition_grammar"], 6
        )
        service_fuzzer = (
            ROOT / "runtime/internal/service/service_fuzz_test.go"
        ).read_text(encoding="utf-8")
        for entrypoint in {
            "validPathText(binary)",
            "quoteSystemdExecArgument",
            "quoteSystemdPath",
            "quoteSystemd(value",
            'validateServicePath("service output path", outputPath, false)',
            "Render(platform, binary, stateDir)",
        }:
            with self.subTest(service_entrypoint=entrypoint):
                self.assertIn(entrypoint, service_fuzzer)
        for oracle in {
            "exactServicePathText",
            "exactServicePath",
            "exactSystemdQuote",
            "exactServiceDefinition",
            "exactXMLEscape",
        }:
            with self.subTest(service_oracle=oracle):
                self.assertIn(oracle, service_fuzzer)
        oracle_source = service_fuzzer[
            service_fuzzer.index("func exactServicePathText") :
        ]
        for production_helper in {
            "validPathText(",
            "validateServicePath(",
            "quoteSystemd(",
            "Render(",
        }:
            self.assertNotIn(production_helper, oracle_source)

        deployment_fuzzer = (
            ROOT / "runtime/internal/deployment/path_fuzz_test.go"
        ).read_text(encoding="utf-8")
        for entrypoint in {
            "validateArtifactName(candidate)",
            "validateAbsoluteCanonicalPath(candidate)",
            "canonicalAbsolutePath(candidate)",
            "requireStrictDescendant(homeDir, installRoot",
            "NewLayout(homeDir, installRoot, stateDir)",
        }:
            with self.subTest(deployment_entrypoint=entrypoint):
                self.assertIn(entrypoint, deployment_fuzzer)
        self.assertIn("exactDeploymentCanonicalPath", deployment_fuzzer)
        self.assertIn("exactStrictDescendant", deployment_fuzzer)
        self.assertIn("exactArtifactName", deployment_fuzzer)
        artifact_name_oracle = deployment_fuzzer[
            deployment_fuzzer.index("func exactArtifactName") :
            deployment_fuzzer.index("func exactDeploymentCanonicalPath")
        ]
        self.assertNotIn("validateArtifactName", artifact_name_oracle)
        self.assertNotIn("filepath.", artifact_name_oracle)

        scalar_fuzzer = (
            ROOT / "runtime/internal/deployment/metadata_fuzz_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn("parseArtifactExpectation(expectedBytes, digest)", scalar_fuzzer)
        self.assertIn("exactArtifactExpectation(expectedBytes, digest)", scalar_fuzzer)
        artifact_expectation_oracle = scalar_fuzzer[
            scalar_fuzzer.index("func exactArtifactExpectation") :
        ]
        self.assertNotIn("parseArtifactExpectation", artifact_expectation_oracle)
        self.assertNotIn("hex.Decode", artifact_expectation_oracle)
        self.assertNotIn("strings.ToLower", artifact_expectation_oracle)

        installer_fuzzer = (
            ROOT / "runtime/internal/releasebundle/installer_fuzz_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn("validateInstallerRenderOptions(options)", installer_fuzzer)
        self.assertIn("exactInstallerRenderOptions(options)", installer_fuzzer)

        bundle_fuzzer = (
            ROOT / "runtime/internal/releasebundle/bundle_fuzz_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn("validateBundleInputPaths(options)", bundle_fuzzer)
        self.assertIn("exactBundleInputPaths(options)", bundle_fuzzer)
        self.assertIn("validateBundleOutput(output)", bundle_fuzzer)
        self.assertIn("exactBundleOutput(output)", bundle_fuzzer)
        bundle_output_oracle = bundle_fuzzer[
            bundle_fuzzer.index("func exactBundleOutput") :
            bundle_fuzzer.index("func exactBundleInputPaths")
        ]
        self.assertNotIn("validateBundleOutput", bundle_output_oracle)
        self.assertNotIn("filepath.", bundle_output_oracle)

        cli_fuzzer = (
            ROOT / "runtime/internal/cli/response_fuzz_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn("discoverableIPv4LoopbackPort(listeners)", cli_fuzzer)
        self.assertIn("exactEndpointPort(portText)", cli_fuzzer)
        self.assertIn("filepathAbs(string(payload))", cli_fuzzer)

        config_fuzzer = (
            ROOT / "runtime/internal/config/config_fuzz_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn("validAbsolutePath(path)", config_fuzzer)
        self.assertIn("containsZeroByte(payload)", config_fuzzer)

        stored_fuzzer = (
            ROOT / "runtime/internal/store/scalar_fuzz_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn("decodeUint64Error([]byte(numberText))", stored_fuzzer)

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

    def test_json_fuzzers_apply_production_semantics(self) -> None:
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

        request_fuzzer = (
            ROOT / "runtime/internal/store/models_fuzz_test.go"
        ).read_text(encoding="utf-8")
        for validator in {
            "validateEnrollmentRequest",
            "validatePutEnvelopeRequestGenerations",
            "validatePutEnvelopeRequestEnvelope",
            "validateSyncRequest",
            "validateSnapshotCreateRequest",
            "validateSnapshotPageRequest",
            "validateRevision",
            "validateEnvelope",
            "validateRevokeDeviceRequest",
            "validateTokenRotationRequest",
        }:
            with self.subTest(request_validator=validator):
                self.assertIn(validator, request_fuzzer)

        stored_fuzzer = (
            ROOT / "runtime/internal/store/scalar_fuzz_test.go"
        ).read_text(encoding="utf-8")
        for validator in {
            "auth.ValidateScopes",
            "api.V1ResponseHeaders",
            "validateEnvelope",
            "validateRevision",
            "validateVector",
            "validateCollectionMarker",
            "decodeStoredSnapshotPageDescriptor",
            "validateSyncResponse",
            "validateDevice",
            "validateStoredEnrollmentResponse",
            "validateStoredSnapshotCreateResponse",
        }:
            with self.subTest(stored_validator=validator):
                self.assertIn(validator, stored_fuzzer)

        receipt_fuzzer = (
            ROOT / "runtime/internal/store/dataplane_fuzz_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn("validOperationReceiptKey", receipt_fuzzer)
        self.assertIn("validateStoredOperationResponse", receipt_fuzzer)
        self.assertIn("exactOperationReceiptKey(operation)", receipt_fuzzer)
        operation_oracle = receipt_fuzzer[
            receipt_fuzzer.index("func exactOperationReceiptKey") :
            receipt_fuzzer.index("func FuzzPathIdentifier")
        ]
        self.assertNotIn("validOperationReceiptKey", operation_oracle)
        self.assertNotIn("validateUUID", operation_oracle)
        self.assertNotIn("uuidv4", operation_oracle)

        request_fuzzer = (
            ROOT / "runtime/internal/store/models_fuzz_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn("parserFuzzStoredEnvelopeGeneration uint64 = 0", request_fuzzer)
        self.assertIn(
            "validatePutEnvelopeRequestGenerations(request, parserFuzzStoredEnvelopeGeneration)",
            request_fuzzer,
        )
        self.assertIn("f.Add(mismatchedPutEnvelopeGenerationFuzzSeed)", request_fuzzer)

        server_fuzzer = (
            ROOT / "runtime/internal/server/server_fuzz_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn("requestIDValues(payload)", server_fuzzer)
        self.assertIn("&headerLimitConn{", server_fuzzer)
        self.assertIn("splitRequestID", server_fuzzer)
        self.assertIn("unterminated buffered header line", server_fuzzer)

        http_fuzzer = (
            ROOT / "runtime/internal/httpapi/handler_fuzz_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn("func FuzzValidateTransportRequest(", http_fuzzer)
        self.assertIn("validateTransport(first)", http_fuzzer)
        self.assertIn("transportRequestMutation(mutation)", http_fuzzer)

        deployment_fuzzer = (
            ROOT / "runtime/internal/deployment/metadata_fuzz_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "mutateAcceptedArtifactExecutable(executable, mutation)",
            deployment_fuzzer,
        )
        self.assertIn("parseArtifactGoBuildInfo(executable)", deployment_fuzzer)
        self.assertIn("ValidateReleaseIdentity(first, expected)", deployment_fuzzer)

        removal_fuzzer = (
            ROOT / "runtime/internal/deployment/remove_artifacts_fuzz_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn("validateRemovableArtifact(name, stat)", removal_fuzzer)
        self.assertIn("exactRemovableArtifactOracle(name, stat)", removal_fuzzer)
        oracle = removal_fuzzer[
            removal_fuzzer.index("func exactRemovableArtifactOracle") :
            removal_fuzzer.index("func removableArtifactFuzzStat")
        ]
        self.assertNotIn("installedArtifactNamePattern", oracle)
        self.assertNotIn("stagedArtifactTemporaryPattern", oracle)
        for adversarial_seed in {
            "sshserver-linux-amd64.backup",
            "0123456789abcdef0123456789abcdeF",
            "0o400 | 2<<9",
            "0o400 | 1<<11",
            "0o400 | 1<<12",
            "0o400 | 1<<13",
        }:
            with self.subTest(adversarial_seed=adversarial_seed):
                self.assertIn(adversarial_seed, removal_fuzzer)

        release_fuzzer = (
            ROOT / "runtime/internal/releasebundle/buildinfo_fuzz_test.go"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "mutateAcceptedReleaseBundleExecutable(executable, mutation)",
            release_fuzzer,
        )
        self.assertIn("parseReleaseBundleGoBuildInfo(executable)", release_fuzzer)

    def test_authorization_parser_has_an_exact_independent_oracle(self) -> None:
        fuzzer = (
            ROOT / "runtime/internal/store/scalar_fuzz_test.go"
        ).read_text(encoding="utf-8")
        for entrypoint in {
            'parseAuthorization(authorization, scheme)',
            'exactAuthorization(authorization, scheme)',
            'exactRawURLToken32(value[len(prefix):])',
        }:
            with self.subTest(entrypoint=entrypoint):
                self.assertIn(entrypoint, fuzzer)
        oracle = fuzzer[fuzzer.index("func exactAuthorization") :]
        self.assertNotIn("parseAuthorization(", oracle)
        self.assertNotIn("decodeBase64(", oracle)
        self.assertNotIn("base64.", oracle)
        for adversarial_seed in {
            '"bearer " + base64Token',
            '"Bearer  " + base64Token',
            '"Bearer\\t" + base64Token',
            '"Bearer " + base64Token + "="',
            '"Bearer +" + base64Token[1:]',
            'base64Token[:len(base64Token)-1] + "B"',
        }:
            with self.subTest(adversarial_seed=adversarial_seed):
                self.assertIn(adversarial_seed, fuzzer)

    def test_fixed_scope_validator_has_an_exact_independent_owner(self) -> None:
        production = (
            ROOT / "runtime/internal/auth/token.go"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            self.signal_counts(production)["fixed_scope_set_validator"], 1
        )
        fuzzer = (
            ROOT / "runtime/internal/store/scalar_fuzz_test.go"
        ).read_text(encoding="utf-8")
        for entrypoint in {
            "auth.ValidateScopes(*destination.(*[]string))",
            "exactFixedScopeSet(*destination.(*[]string))",
            "(firstValidationErr == nil) != firstWant",
        }:
            with self.subTest(entrypoint=entrypoint):
                self.assertIn(entrypoint, fuzzer)
        oracle = fuzzer[
            fuzzer.index("func exactFixedScopeSet") :
            fuzzer.index("func FuzzStoreScalarAndStoredParsers")
        ]
        self.assertNotIn("auth.ValidateScopes", oracle)
        self.assertNotIn("auth.FixedScopes", oracle)
        self.assertNotIn("slices.Equal", oracle)
        for adversarial_seed in {
            '"devices:read","devices:manage"',
            '"sync:write","sync:admin"',
            '"sync:write","sync:write"',
            '"envelope:write","sync:read"]`)',
            '"Devices:manage"',
        }:
            with self.subTest(adversarial_seed=adversarial_seed):
                self.assertIn(adversarial_seed, fuzzer)

    def test_exclusions_remain_narrow_and_explicit(self) -> None:
        exclusions = {entry["id"]: entry["reason"] for entry in self.inventory["exclusions"]}
        self.assertEqual(
            set(exclusions),
            {
                "conformance-tool",
                "scanner-entrypoints",
                "stdlib-cli-flags-and-static-templates",
                "tests-and-vendored-runtime",
                "validated-derived-path-and-listener-consumers",
            },
        )
        for identifier, reason in exclusions.items():
            with self.subTest(exclusion=identifier):
                self.assertGreater(len(reason), 80)


if __name__ == "__main__":
    unittest.main()
