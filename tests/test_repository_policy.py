from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
GUARDRAILS = """## Guardrails — non-negotiable, apply to every task

1. Dependencies must be MIT/BSD/Apache/ISC licensed; update NOTICE. Never fetch, read, or paste GPL sources (mosh, Blink, libssh, wolfSSH). Unmodified stock mosh binaries/packages may be executed only as black-box interoperability targets; their source is never an input.
2. SSP work may only use: the USENIX 2012 mosh paper, RFC 7253, and our own black-box captures. Log derivations with dates in the derivation log.
3. Crypto, Keychain, and Network Extension changes require Tom's review before merge.
4. Close any decision or gate you resolve in the coordinator `DECISIONS.md` within the same work item.
5. Ordinary SSH targets are agentless: never install or require a proprietary daemon on them. The only product server is the optional sync server on a user-selected host; SSP is offered only when a stock mosh-server is already present by the user's choice."""


class RepositoryPolicyTests(unittest.TestCase):
    def test_agent_files_end_with_exact_guardrails(self) -> None:
        for filename in ("AGENTS.md", "CLAUDE.md"):
            with self.subTest(filename=filename):
                text = (ROOT / filename).read_text(encoding="utf-8")
                start = text.index("## Guardrails")
                self.assertEqual(text[start:].strip(), GUARDRAILS)

    def test_agent_files_have_identical_policy(self) -> None:
        self.assertEqual(
            (ROOT / "AGENTS.md").read_text(encoding="utf-8"),
            (ROOT / "CLAUDE.md").read_text(encoding="utf-8"),
        )

    def test_dco_workflow_uses_trusted_base_and_full_history(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "dco.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("on:\n  pull_request:", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertIn("fetch-depth: 0", workflow)
        self.assertIn("ref: ${{ github.event.pull_request.base.sha }}", workflow)
        self.assertIn("python3 scripts/check_dco.py", workflow)

    def test_repository_uses_full_apache_2_license(self) -> None:
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("Apache License\n                           Version 2.0", license_text)
        self.assertIn("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION", license_text)
        self.assertIn("END OF TERMS AND CONDITIONS", license_text)


if __name__ == "__main__":
    unittest.main()
