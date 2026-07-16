from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import check_dco


class DCOCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.repo = Path(self.temporary_directory.name)
        self.git("init", "--quiet")
        self.git("config", "user.name", "Alice Example")
        self.git("config", "user.email", "alice@example.com")
        (self.repo / "fixture.txt").write_text("base\n", encoding="utf-8")
        self.git("add", "fixture.txt")
        self.git("commit", "--quiet", "-m", "base")
        self.base = self.git("rev-parse", "HEAD").stdout.strip()

    def git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def change_and_commit(self, message: str, *, signoff: bool = False) -> str:
        fixture = self.repo / "fixture.txt"
        fixture.write_text(
            fixture.read_text(encoding="utf-8") + f"{message}\n", encoding="utf-8"
        )
        self.git("add", "fixture.txt")
        arguments = ["commit", "--quiet", "-m", message]
        if signoff:
            arguments.append("--signoff")
        self.git(*arguments)
        return self.git("rev-parse", "HEAD").stdout.strip()

    def test_matching_signoff_passes(self) -> None:
        head = self.change_and_commit("signed change", signoff=True)

        self.assertEqual(check_dco.check_range(self.repo, self.base, head), [])

    def test_unsigned_commit_fails(self) -> None:
        head = self.change_and_commit("unsigned change")

        errors = check_dco.check_range(self.repo, self.base, head)

        self.assertEqual(len(errors), 1, errors)
        self.assertIn("missing Signed-off-by", errors[0])

    def test_mismatched_signoff_fails(self) -> None:
        fixture = self.repo / "fixture.txt"
        fixture.write_text("base\nmismatched\n", encoding="utf-8")
        self.git("add", "fixture.txt")
        self.git(
            "commit",
            "--quiet",
            "-m",
            "mismatched signoff",
            "-m",
            "Signed-off-by: Mallory Example <mallory@example.com>",
        )
        head = self.git("rev-parse", "HEAD").stdout.strip()

        errors = check_dco.check_range(self.repo, self.base, head)

        self.assertEqual(len(errors), 1, errors)
        self.assertIn("matches the author or committer", errors[0])

    def test_signoff_text_in_message_body_is_not_a_trailer(self) -> None:
        fixture = self.repo / "fixture.txt"
        fixture.write_text("base\nquoted signoff\n", encoding="utf-8")
        self.git("add", "fixture.txt")
        self.git(
            "commit",
            "--quiet",
            "-m",
            "document a signoff example",
            "-m",
            "Signed-off-by: Alice Example <alice@example.com>\n\n"
            "This line makes the example part of the message body.",
        )
        head = self.git("rev-parse", "HEAD").stdout.strip()

        errors = check_dco.check_range(self.repo, self.base, head)

        self.assertEqual(len(errors), 1, errors)
        self.assertIn("missing Signed-off-by", errors[0])

    def test_every_commit_in_pull_request_range_is_checked(self) -> None:
        self.change_and_commit("first signed change", signoff=True)
        head = self.change_and_commit("second unsigned change")

        errors = check_dco.check_range(self.repo, self.base, head)

        self.assertEqual(len(errors), 1, errors)
        self.assertIn("missing Signed-off-by", errors[0])

    def test_empty_range_fails(self) -> None:
        errors = check_dco.check_range(self.repo, self.base, self.base)

        self.assertEqual(len(errors), 1, errors)
        self.assertIn("contains no commits", errors[0])


if __name__ == "__main__":
    unittest.main()
