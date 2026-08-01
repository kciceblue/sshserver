from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from scripts import check_runtime_vendor as checker


class RuntimeVendorPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.vendor = self.root / checker.VENDOR_RELATIVE
        self.vendor.mkdir(parents=True)
        self.upstream = self.root / "upstream"
        self.upstream.mkdir()
        for metadata in checker.LOCAL_METADATA - {checker.MANIFEST_NAME}:
            (self.vendor / metadata).write_text(f"local {metadata}\n", encoding="utf-8")
        self.source = b"exact permitted upstream source\n"
        (self.vendor / "source.go").write_bytes(self.source)
        (self.upstream / "source.go").write_bytes(self.source)
        digest = hashlib.sha256(self.source).hexdigest()
        (self.vendor / checker.MANIFEST_NAME).write_text(
            f"{digest}  source.go\n", encoding="utf-8"
        )
        self.payload = {
            "Path": checker.MODULE,
            "Version": checker.VERSION,
            "Sum": checker.EXPECTED_SUM,
            "GoModSum": checker.EXPECTED_GO_MOD_SUM,
            "Dir": str(self.upstream),
            "Origin": {"Hash": checker.EXPECTED_COMMIT},
        }

    def test_exact_trimmed_source_passes(self) -> None:
        self.assertEqual(
            checker.validate_vendor(self.root, download_payload=self.payload), []
        )

    def test_local_tamper_fails(self) -> None:
        (self.vendor / "source.go").write_text("modified\n", encoding="utf-8")

        errors = checker.validate_vendor(
            self.root, download_payload=self.payload
        )

        self.assertTrue(any("does not match manifest" in error for error in errors), errors)

    def test_extra_file_and_symlink_fail(self) -> None:
        (self.vendor / "extra.go").write_text("extra\n", encoding="utf-8")
        os.symlink(self.vendor / "source.go", self.vendor / "linked.go")

        errors = checker.validate_vendor(
            self.root, download_payload=self.payload
        )

        self.assertTrue(any("untracked file: extra.go" in error for error in errors), errors)
        self.assertTrue(any("contains symlink: linked.go" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
