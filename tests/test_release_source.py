from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import check_release_source as checker


class ReleaseSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.run_git("init", "--quiet")
        self.run_git("config", "user.name", "Release Test")
        self.run_git("config", "user.email", "release@example.invalid")
        (self.root / "tracked.txt").write_text("frozen\n", encoding="utf-8")
        self.run_git("add", "tracked.txt")
        self.run_git("commit", "--quiet", "-m", "frozen source")
        self.revision = self.run_git("rev-parse", "HEAD").strip()

    def run_git(self, *arguments: str) -> str:
        return subprocess.run(
            ("git", "-C", str(self.root), *arguments),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout

    def test_exact_clean_revision_passes(self) -> None:
        self.assertEqual(
            checker.validate_release_source(self.root, self.revision), []
        )

    def test_mismatched_revision_fails(self) -> None:
        errors = checker.validate_release_source(self.root, "0" * 40)
        self.assertTrue(any("does not match" in error for error in errors), errors)

    def test_tracked_or_untracked_changes_fail(self) -> None:
        (self.root / "tracked.txt").write_text("changed\n", encoding="utf-8")
        errors = checker.validate_release_source(self.root, self.revision)
        self.assertTrue(any("not clean" in error for error in errors), errors)

        self.run_git("restore", "tracked.txt")
        (self.root / "untracked.txt").write_text("new\n", encoding="utf-8")
        errors = checker.validate_release_source(self.root, self.revision)
        self.assertTrue(any("not clean" in error for error in errors), errors)

    def test_invalid_or_nested_root_fails(self) -> None:
        self.assertTrue(checker.validate_release_source(self.root, "dev"))
        nested = self.root / "nested"
        nested.mkdir()
        errors = checker.validate_release_source(nested, self.revision)
        self.assertTrue(any("exact Git worktree root" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
