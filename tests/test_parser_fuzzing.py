import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ParserFuzzingPolicyTests(unittest.TestCase):
    def test_every_server_parser_target_has_a_checked_in_minimized_seed(self) -> None:
        targets = {
            "runtime/internal/store/models_fuzz_test.go": "FuzzDecodeStrictJSON",
            "runtime/internal/deployment/parser_fuzz_test.go": "FuzzParsePinnedManifest",
            "runtime/internal/deployment/parser_fuzz_test.go#preview": "FuzzParseDeploymentPreview",
            "runtime/internal/server/server_fuzz_test.go": "FuzzDecodeAdminRequest",
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
        self.assertEqual(makefile.count(deterministic_budget), 4)
        for target in (
            "FuzzDecodeStrictJSON",
            "FuzzParsePinnedManifest",
            "FuzzParseDeploymentPreview",
            "FuzzDecodeAdminRequest",
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
