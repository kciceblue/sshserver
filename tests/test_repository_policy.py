from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
COORDINATOR_WORKFLOW_URL = (
    "https://github.com/kciceblue/just-another-terminal/blob/main/"
    "PLAN.md#how-agents-should-use-this-file"
)
PUBLIC_ISSUE_URL = "https://github.com/kciceblue/sshserver/issues/new"
PUBLIC_DECISION_IDS = {
    "D2",
    "D3",
    "D4",
    "D6",
    "D7",
    "D10",
    "D12",
    "D14",
    "D16",
    "G2",
}
DECISION_FIELDS = ("Status", "Rationale", "Evidence", "Closing task")
GUARDRAILS = """## Guardrails — non-negotiable, apply to every task

1. Product/runtime dependencies and implementation inputs must be MIT/BSD/Apache/ISC licensed; update NOTICE. Never fetch, read, or paste GPL sources (mosh, Blink, libssh, wolfSSH). Unmodified stock mosh, Dropbear, and tmux binaries/packages may be executed only as non-shipped black-box interoperability targets in tests, including future test harnesses; their source is never an input and they are never linked into or redistributed with the products.
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

    def test_public_decision_projection_has_only_server_records(self) -> None:
        text = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")
        records: dict[str, str] = {}
        matches = list(re.finditer(r"(?m)^## ((?:D|G)\d+) — .+$", text))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            records[match.group(1)] = text[match.end() : end]

        self.assertEqual(len(matches), len(PUBLIC_DECISION_IDS))
        self.assertEqual(set(records), PUBLIC_DECISION_IDS)
        for record_id, body in records.items():
            with self.subTest(record_id=record_id):
                for field in DECISION_FIELDS:
                    self.assertRegex(body, rf"(?m)^- \*\*{re.escape(field)}:\*\* \S.+$")
                    self.assertEqual(body.count(f"- **{field}:**"), 1)

    def test_public_decision_projection_excludes_private_product_details(self) -> None:
        text = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")
        for private_detail in (
            "YLJU8C8DN6",
            "Hengyu Xu",
            "Small Business Program",
            "bundle identifier",
            "seven-day preview",
            "$1",
        ):
            with self.subTest(private_detail=private_detail):
                self.assertNotIn(private_detail, text)

    def test_d16_keeps_black_box_peers_outside_products(self) -> None:
        text = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")
        d16 = text.split("## D16 —", 1)[1].split("\n## ", 1)[0]
        self.assertIn("mosh, Dropbear, and tmux", d16)
        self.assertIn("non-shipped black-box interoperability targets", d16)
        self.assertIn("future test harnesses", d16)
        self.assertIn("never an implementation input", d16)
        self.assertIn("never linked into or redistributed", d16)
        self.assertIn("remain restricted to\nthe D6 allowlist", d16)

    def test_public_decision_update_workflow_supports_external_contributors(self) -> None:
        decisions = (ROOT / "DECISIONS.md").read_text(encoding="utf-8")
        pull_request_template = (
            ROOT / ".github" / "pull_request_template.md"
        ).read_text(encoding="utf-8")

        for document in (decisions, pull_request_template):
            with self.subTest(document=document[:40]):
                self.assertIn(COORDINATOR_WORKFLOW_URL, document)
                self.assertIn(PUBLIC_ISSUE_URL, document)
        self.assertIn("Coordinator task ID:", pull_request_template)
        self.assertIn("Public issue:", pull_request_template)


if __name__ == "__main__":
    unittest.main()
