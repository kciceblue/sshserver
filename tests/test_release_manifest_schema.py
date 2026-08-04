import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "packaging" / "release-manifest.schema.json"
RELEASE_ID_PATH = ROOT / "runtime" / "internal" / "releaseid" / "releaseid.go"


class ReleaseManifestSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_schema_is_strict_v1_and_has_exact_top_level_fields(self) -> None:
        self.assertEqual(
            self.schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
        )
        self.assertFalse(self.schema["additionalProperties"])
        properties = self.schema["properties"]
        self.assertEqual(set(self.schema["required"]), set(properties))
        self.assertEqual(properties["manifest_version"], {"const": 1})
        self.assertEqual(properties["protocol_version"], {"const": "1"})
        self.assertEqual(properties["storage_schema"], {"const": "1"})
        release = properties["release"]
        self.assertEqual((release["minLength"], release["maxLength"]), (1, 64))
        self.assertEqual(
            release["pattern"],
            r"^v?[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9]+([.-][a-z0-9]+)*)?$",
        )

    def test_release_grammar_accepts_only_exact_immutable_versions(self) -> None:
        release = self.schema["properties"]["release"]
        pattern = re.compile(release["pattern"])

        for value in (
            "1.2.3",
            "v1.2.3",
            "2026.08.03",
            "v1.2.3-rc.1",
            "v0.0.0-metadata-test",
            "1.2.3-" + ("a" * 58),
        ):
            self.assertLessEqual(len(value), release["maxLength"])
            self.assertIsNotNone(pattern.fullmatch(value), value)

        for value in (
            "",
            "latest",
            "stable",
            "current",
            "main",
            "nightly",
            "v1",
            "v1.2",
            "v1..2",
            "V1.2.3",
            "v1.2.3-RC1",
            "v1.2.3-rc..1",
            "v1.2.3-rc_1",
            "v1.2.3+build",
            "../v1.2.3",
            "v1.2.3/sshserver",
            "1.2.3-" + ("a" * 59),
        ):
            accepted = (
                release["minLength"] <= len(value) <= release["maxLength"]
                and pattern.fullmatch(value) is not None
            )
            self.assertFalse(accepted, value)

    def test_public_schema_and_runtime_share_one_release_pattern(self) -> None:
        source = RELEASE_ID_PATH.read_text(encoding="utf-8")
        match = re.search(r"\bPattern\s+=\s+`([^`]+)`", source)
        self.assertIsNotNone(match)
        self.assertEqual(
            match.group(1), self.schema["properties"]["release"]["pattern"]
        )

    def test_schema_freezes_four_targets_in_canonical_order(self) -> None:
        artifacts = self.schema["properties"]["artifacts"]
        self.assertEqual((artifacts["minItems"], artifacts["maxItems"]), (4, 4))
        self.assertFalse(artifacts["items"])
        references = [item["$ref"] for item in artifacts["prefixItems"]]
        self.assertEqual(
            references,
            [
                "#/$defs/linux_amd64",
                "#/$defs/linux_arm64",
                "#/$defs/darwin_amd64",
                "#/$defs/darwin_arm64",
            ],
        )
        for name, operating_system, architecture in (
            ("linux_amd64", "linux", "amd64"),
            ("linux_arm64", "linux", "arm64"),
            ("darwin_amd64", "darwin", "amd64"),
            ("darwin_arm64", "darwin", "arm64"),
        ):
            target = self.schema["$defs"][name]["allOf"][1]["properties"]
            self.assertEqual(target["os"], {"const": operating_system})
            self.assertEqual(target["architecture"], {"const": architecture})

    def test_schema_freezes_license_and_notice_and_bounded_hashes(self) -> None:
        release_files = self.schema["properties"]["release_files"]
        self.assertEqual(
            (release_files["minItems"], release_files["maxItems"]), (2, 2)
        )
        self.assertFalse(release_files["items"])
        names = [
            item["allOf"][1]["properties"]["name"]["const"]
            for item in release_files["prefixItems"]
        ]
        self.assertEqual(names, ["LICENSE", "NOTICE"])
        self.assertEqual(
            self.schema["$defs"]["sha256"]["pattern"], "^[0-9a-f]{64}$"
        )
        self.assertEqual(
            self.schema["$defs"]["artifact"]["properties"]["bytes"]["maximum"],
            256 * 1024 * 1024,
        )
        self.assertEqual(
            self.schema["$defs"]["release_file"]["properties"]["bytes"][
                "maximum"
            ],
            4 * 1024 * 1024,
        )


if __name__ == "__main__":
    unittest.main()
