# Agent instructions

The private coordinator repository owns the canonical `PLAN.md`, decision
ledger, and generated tracker. Follow its dependency and evidence workflow.

## Guardrails — non-negotiable, apply to every task

1. Dependencies must be MIT/BSD/Apache/ISC licensed; update NOTICE. Never fetch, read, or paste GPL sources (mosh, Blink, libssh, wolfSSH). Unmodified stock mosh binaries/packages may be executed only as black-box interoperability targets; their source is never an input.
2. SSP work may only use: the USENIX 2012 mosh paper, RFC 7253, and our own black-box captures. Log derivations with dates in the derivation log.
3. Crypto, Keychain, and Network Extension changes require Tom's review before merge.
4. Close any decision or gate you resolve in the coordinator `DECISIONS.md` within the same work item.
5. Ordinary SSH targets are agentless: never install or require a proprietary daemon on them. The only product server is the optional sync server on a user-selected host; SSP is offered only when a stock mosh-server is already present by the user's choice.
