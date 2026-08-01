from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts import check_dependency_licenses as checker


CHECKOUT = {
    "license": "MIT",
    "name": "actions/checkout",
    "selector": "actions/checkout@v4",
    "usage": "ci-action",
}
SYSTEM_OPENSSL = {
    "command": "openssl",
    "license": "Apache-2.0",
    "name": "System OpenSSL 3 command-line tool",
    "redistributed": False,
    "selector": "system:openssl@3",
    "usage": "test-tool",
    "version_pattern": r"^OpenSSL 3\.[0-9]",
}


class DependencyLicensePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        (self.root / ".github" / "workflows").mkdir(parents=True)
        (self.root / "ThirdPartyLicenses").mkdir()
        (self.root / ".github" / "workflows" / "ci.yml").write_text(
            "steps:\n  - uses: actions/checkout@v4\n", encoding="utf-8"
        )
        (self.root / "NOTICE").write_text(
            "Example server\nNo distributed dependencies.\n", encoding="utf-8"
        )
        self.write_inventory([CHECKOUT])

    def write_inventory(self, dependencies: list[dict[str, str]]) -> None:
        payload = {
            "allowed_licenses": [
                "Apache-2.0",
                "BSD-2-Clause",
                "BSD-3-Clause",
                "ISC",
                "MIT",
            ],
            "dependencies": dependencies,
            "policy": "go-modules-ci-actions-and-test-tools",
            "schema_version": 2,
        }
        (self.root / "DEPENDENCIES.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )

    def add_go_fixture(
        self, *, license_id: str = "MIT", inventoried: bool = True
    ) -> str:
        module = "example.com/permitted/module"
        version = "v1.2.3"
        (self.root / "go.mod").write_text(
            "module example.com/server\n\ngo 1.24\n", encoding="utf-8"
        )
        (self.root / "ThirdPartyLicenses" / "module-LICENSE").write_text(
            "Permission is hereby granted to use this test fixture license text "
            "for policy validation.\n",
            encoding="utf-8",
        )
        dependencies = [CHECKOUT]
        if inventoried:
            dependencies.append(
                {
                    "license": license_id,
                    "license_file": "ThirdPartyLicenses/module-LICENSE",
                    "module": module,
                    "name": "permitted module",
                    "selector": f"{module}@{version}",
                    "usage": "go-module",
                    "version": version,
                }
            )
        self.write_inventory(dependencies)
        (self.root / "NOTICE").write_text(
            f"Example server\nThird-party module: {module}\n", encoding="utf-8"
        )
        return "\n".join(
            (
                json.dumps({"Path": "example.com/server", "Main": True}),
                json.dumps({"Path": module, "Version": version}),
            )
        )

    def test_clean_scaffold_passes(self) -> None:
        self.assertEqual(checker.validate_repository(self.root), [])

    def test_non_allowlisted_action_license_fails(self) -> None:
        forbidden = dict(CHECKOUT)
        forbidden["license"] = "GPL-3.0-only"
        self.write_inventory([forbidden])

        errors = checker.validate_repository(self.root)

        self.assertTrue(
            any("non-allowlisted license GPL-3.0-only" in item for item in errors),
            errors,
        )

    def test_test_peer_usage_does_not_broaden_dependency_allowlist(self) -> None:
        forbidden = dict(CHECKOUT)
        forbidden["usage"] = "test-peer"
        forbidden["license"] = "GPL-3.0-only"
        self.write_inventory([forbidden])

        errors = checker.validate_repository(self.root)

        self.assertTrue(
            any("non-allowlisted license GPL-3.0-only" in item for item in errors),
            errors,
        )

    def test_unlisted_action_fails(self) -> None:
        (self.root / ".github" / "workflows" / "ci.yml").write_text(
            "steps:\n  - uses: example/unreviewed@v1\n", encoding="utf-8"
        )

        errors = checker.validate_repository(self.root)

        self.assertTrue(any("unlisted GitHub Action" in item for item in errors), errors)

    def test_valid_inventoried_go_module_passes(self) -> None:
        module_graph = self.add_go_fixture()

        self.assertEqual(
            checker.validate_repository(self.root, go_modules_json=module_graph), []
        )

    def test_nested_go_module_graph_is_inventoried_and_deduplicated(self) -> None:
        module_graph = self.add_go_fixture()
        runtime = self.root / "runtime"
        runtime.mkdir()
        (runtime / "go.mod").write_text(
            "module example.com/server/runtime\n\ngo 1.24\n", encoding="utf-8"
        )
        nested_graph = "\n".join(
            (
                json.dumps(
                    {"Path": "example.com/server/runtime", "Main": True}
                ),
                json.dumps(
                    {
                        "Path": "example.com/permitted/module",
                        "Version": "v1.2.3",
                    }
                ),
            )
        )

        self.assertEqual(
            checker.validate_repository(
                self.root,
                go_modules_json={".": module_graph, "runtime": nested_graph},
            ),
            [],
        )

    def test_local_go_replacement_must_remain_inside_repository(self) -> None:
        self.add_go_fixture()
        inventory = json.loads(
            (self.root / "DEPENDENCIES.json").read_text(encoding="utf-8")
        )
        inventory["dependencies"][-1]["replacement"] = "../outside@local"
        self.write_inventory(inventory["dependencies"])
        graph = "\n".join(
            (
                json.dumps({"Path": "example.com/server", "Main": True}),
                json.dumps(
                    {
                        "Path": "example.com/permitted/module",
                        "Version": "v1.2.3",
                        "Replace": {"Path": "../outside"},
                    }
                ),
            )
        )

        errors = checker.validate_repository(self.root, go_modules_json=graph)

        self.assertTrue(any("escapes repository" in item for item in errors), errors)

    def test_each_nested_graph_occurrence_validates_replacement(self) -> None:
        module_graph = self.add_go_fixture()
        runtime = self.root / "runtime"
        runtime.mkdir()
        (runtime / "go.mod").write_text(
            "module example.com/server/runtime\n\ngo 1.24\n", encoding="utf-8"
        )
        (runtime / "inside").mkdir()
        (runtime / "inside" / "go.mod").write_text(
            "module example.com/permitted/module\n\ngo 1.24\n", encoding="utf-8"
        )
        inventory = json.loads(
            (self.root / "DEPENDENCIES.json").read_text(encoding="utf-8")
        )
        inventory["dependencies"][-1]["replacement"] = "./inside@local"
        self.write_inventory(inventory["dependencies"])
        nested_graph = "\n".join(
            (
                json.dumps({"Path": "example.com/server/runtime", "Main": True}),
                json.dumps(
                    {
                        "Path": "example.com/permitted/module",
                        "Version": "v1.2.3",
                        "Replace": {"Path": "./inside"},
                    }
                ),
            )
        )

        errors = checker.validate_repository(
            self.root,
            go_modules_json={
                ".": module_graph,
                "runtime": nested_graph,
                "runtime/inside": json.dumps(
                    {"Path": "example.com/permitted/module", "Main": True}
                ),
            },
        )

        self.assertTrue(any("stale replacement" in item for item in errors), errors)

    def test_valid_nonredistributed_test_tool_passes(self) -> None:
        self.write_inventory([CHECKOUT, SYSTEM_OPENSSL])
        (self.root / "NOTICE").write_text(
            "Example server\nTest tool: system:openssl@3\n", encoding="utf-8"
        )

        self.assertEqual(checker.validate_repository(self.root), [])

    def test_test_tool_requires_command_version_pattern_and_nonredistribution(self) -> None:
        invalid = dict(SYSTEM_OPENSSL)
        invalid["command"] = ""
        invalid["version_pattern"] = "OpenSSL 3["
        invalid["redistributed"] = True
        self.write_inventory([CHECKOUT, invalid])
        (self.root / "NOTICE").write_text(
            "Example server\nTest tool: system:openssl@3\n", encoding="utf-8"
        )

        errors = checker.validate_repository(self.root)

        self.assertTrue(any("non-empty command" in item for item in errors), errors)
        self.assertTrue(any("start-anchored" in item for item in errors), errors)
        self.assertTrue(any("version_pattern is invalid" in item for item in errors), errors)
        self.assertTrue(any("redistributed=false" in item for item in errors), errors)

    def test_test_tool_rejects_semantic_command_and_pattern_drift(self) -> None:
        drifted = dict(SYSTEM_OPENSSL)
        drifted["command"] = "printf"
        drifted["version_pattern"] = "^"
        self.write_inventory([CHECKOUT, drifted])
        (self.root / "NOTICE").write_text(
            "Example server\nTest tool: system:openssl@3\n", encoding="utf-8"
        )

        errors = checker.validate_repository(self.root)

        self.assertTrue(any("command must be 'openssl'" in item for item in errors), errors)
        self.assertTrue(
            any("version_pattern must be" in item for item in errors), errors
        )

    def test_test_tool_must_be_named_in_notice(self) -> None:
        self.write_inventory([CHECKOUT, SYSTEM_OPENSSL])

        errors = checker.validate_repository(self.root)

        self.assertTrue(any("NOTICE does not list test tool" in item for item in errors), errors)

    def test_non_allowlisted_go_module_license_fails(self) -> None:
        module_graph = self.add_go_fixture(license_id="GPL-2.0-only")

        errors = checker.validate_repository(
            self.root, go_modules_json=module_graph
        )

        self.assertTrue(
            any("non-allowlisted license GPL-2.0-only" in item for item in errors),
            errors,
        )

    def test_unlisted_go_module_fails(self) -> None:
        module_graph = self.add_go_fixture(inventoried=False)

        errors = checker.validate_repository(
            self.root, go_modules_json=module_graph
        )

        self.assertTrue(any("unlisted Go module" in item for item in errors), errors)

    def test_go_module_requires_full_license_text(self) -> None:
        module_graph = self.add_go_fixture()
        (self.root / "ThirdPartyLicenses" / "module-LICENSE").write_text(
            "MIT", encoding="utf-8"
        )

        errors = checker.validate_repository(
            self.root, go_modules_json=module_graph
        )

        self.assertTrue(any("too short" in item for item in errors), errors)

    def test_shared_license_bundle_requires_selector_labels(self) -> None:
        self.add_go_fixture()
        inventory = json.loads(
            (self.root / "DEPENDENCIES.json").read_text(encoding="utf-8")
        )
        second = dict(inventory["dependencies"][-1])
        second.update(
            {
                "module": "example.com/permitted/second",
                "name": "second permitted module",
                "selector": "example.com/permitted/second@v2.0.0",
                "version": "v2.0.0",
            }
        )
        inventory["dependencies"].append(second)
        self.write_inventory(inventory["dependencies"])
        (self.root / "NOTICE").write_text(
            "example.com/permitted/module\nexample.com/permitted/second\n",
            encoding="utf-8",
        )
        graph = "\n".join(
            (
                json.dumps({"Path": "example.com/server", "Main": True}),
                json.dumps(
                    {
                        "Path": "example.com/permitted/module",
                        "Version": "v1.2.3",
                    }
                ),
                json.dumps(
                    {
                        "Path": "example.com/permitted/second",
                        "Version": "v2.0.0",
                    }
                ),
            )
        )

        errors = checker.validate_repository(self.root, go_modules_json=graph)

        self.assertTrue(any("shared license bundle" in item for item in errors), errors)

    def test_unhandled_package_manifest_fails_closed(self) -> None:
        (self.root / "package.json").write_text("{}\n", encoding="utf-8")

        errors = checker.validate_repository(self.root)

        self.assertTrue(
            any("unsupported dependency manifest" in item for item in errors), errors
        )


if __name__ == "__main__":
    unittest.main()
