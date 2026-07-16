# Public decisions

This ledger publishes the subset of the private coordinator's canonical
decisions that constrains this repository. Canonical IDs are retained so a
public change can be reconciled with the private plan without copying private
product or infrastructure details here.

## Update workflow

Maintainers follow the
[private coordinator task workflow](https://github.com/kciceblue/just-another-terminal/blob/main/PLAN.md#how-agents-should-use-this-file):
start an eligible task, link the product pull request to that task, and record
the merge evidence in the coordinator before acknowledging the task. A change
that resolves or revises a decision or gate must update the canonical
coordinator ledger and this public projection in the same work item.

External contributors are not expected to have access to the private
coordinator. Open or link a
[public sshserver issue](https://github.com/kciceblue/sshserver/issues/new)
instead; a maintainer will map it to the private work item. Pull requests must
reference either a coordinator task ID or that public issue. Public evidence
belongs in this repository, while private planning and infrastructure details
remain in the coordinator.

## D2 — Server distribution and contribution model

- **Status:** Locked.
- **Rationale:** A public, auditable server lowers the trust burden for a self-hosted service; Go supports the intended single-binary distribution model, and a DCO records contributor certification without a separate contributor agreement.
- **Evidence:** [Apache-2.0 license](LICENSE), [DCO](DCO.md), and the pull-request DCO workflow and policy tests.
- **Closing task:** 0.2 publishes the decision; server implementation begins at 2.1.

The server is open source under Apache-2.0, implemented in Go, distributed as
a single binary per supported platform, and requires DCO sign-off on every
public contribution.

## D3 — Key-custody boundary

- **Status:** Locked.
- **Rationale:** Sync must not turn device-bound or exportable user credentials into plaintext server data.
- **Evidence:** Canonical decision D3, projected publicly by task 0.2; implementation evidence is required by tasks 2.1 through 2.3.
- **Closing task:** 0.2 publishes the decision; cryptographic enforcement closes in client task 2.2.

Exportable private keys may reach the server only inside authenticated
ciphertext. Device-bound private keys never reach the server; only their public
keys and non-secret metadata may be represented in synchronized records.

## D4 — Client-side encrypted sync

- **Status:** Locked.
- **Rationale:** The optional sync host should store opaque data and the minimum metadata needed for synchronization, while an optional user passphrase provides a stronger mode against host-only compromise.
- **Evidence:** Canonical decision D4, projected publicly by task 0.2; the threat model and wire-level evidence close at 2.0 and 2.2.
- **Closing task:** 0.2 publishes the decision; protocol details close at 2.0.

Clients encrypt records and create the wrapped vault-key envelope. The server
stores ciphertext, the wrapped envelope, and minimum synchronization metadata.
It does not implement vault cryptography or parse private-key material. Base
mode explicitly trusts the selected sync host; optional passphrase mode is
specified to prevent that host alone from unwrapping the vault key.

## D6 — Dependency and implementation-input policy

- **Status:** Locked.
- **Rationale:** A narrow permissive-license allowlist keeps the public server redistributable and preserves the clean-room boundary for optional interoperability work elsewhere in the product.
- **Evidence:** [Repository guardrails](AGENTS.md), [dependency inventory](DEPENDENCIES.json), [NOTICE](NOTICE), and the fail-closed license check.
- **Closing task:** 0.1 established enforcement; 0.2 publishes the decision.

Dependencies must use MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, or ISC.
libssh, wolfSSH, mosh or Blink source, and an Eternal Terminal port must never
be used as dependencies or implementation inputs. Unmodified stock mosh
binaries or packages may be executed only as black-box interoperability peers;
their source is never an input.

## D7 — Agentless ordinary SSH targets

- **Status:** Locked.
- **Rationale:** Terminal access should continue to work against ordinary SSH hosts without installing project-specific software or altering the host.
- **Evidence:** Canonical decision D7, the scope statement in [README.md](README.md), and repository guardrail 5.
- **Closing task:** 0.2 publishes the decision; client-side resilience is implemented separately.

This repository contains the optional sync server only. It is installed solely
on a host the user explicitly selects for sync. It is not an SSH session daemon
and must never be installed or required on ordinary SSH targets.

## D10 — SSH-anchored bootstrap and local transport

- **Status:** Locked.
- **Rationale:** Reusing a verified SSH connection avoids requiring a publicly exposed sync endpoint and anchors installation and enrollment to a host the user has selected.
- **Evidence:** Canonical decision D10, projected publicly by task 0.2; protocol evidence closes at 2.0 and deployment evidence at 2.5.
- **Closing task:** 0.2 publishes the decision; protocol details close at 2.0.

Installation and enrollment occur through a verified SSH session. The service
binds locally on the selected host, and normal sync reaches it through an SSH
forward by default. A public sync port is not required.

## D12 — Synchronized identity records

- **Status:** Locked.
- **Rationale:** Sync may carry restorable software-backed identities without implying that device-bound private keys are exportable.
- **Evidence:** Canonical decision D12, projected publicly by task 0.2; record-shape and cryptographic evidence close at 2.2 and 2.3.
- **Closing task:** 0.2 publishes the decision; client enforcement closes at 2.2.

Software-backed private keys may be synchronized only as authenticated
ciphertext. Device-bound identities synchronize only their public key and
non-secret metadata.

## D14 — Tenancy, platforms, and installation

- **Status:** Locked.
- **Rationale:** A one-person, user-scoped service keeps authorization, operations, and self-hosting understandable while covering common personal server platforms.
- **Evidence:** Canonical decision D14, projected publicly by task 0.2; release and installation evidence closes at 2.1 and 2.5.
- **Closing task:** 0.2 publishes the decision; platform artifacts close at 2.1 and installation closes at 2.5.

One server instance serves one individual Unix account. Version 1 supports
Linux and macOS on amd64 and arm64. Installation is available through the app
over SSH and as an equivalent copyable one-line command. Ordinary SSH targets
need nothing beyond SSH.

## G2 — Proprietary session daemon

- **Status:** Closed and superseded by D7.
- **Rationale:** A project-specific daemon on ordinary SSH targets conflicts with the agentless product boundary.
- **Evidence:** Canonical gate G2 and public decision D7.
- **Closing task:** 0.2 records the already-closed gate.

No proprietary session daemon is part of the server or required on ordinary
SSH targets. The optional service in this repository is limited to sync on the
single host a user explicitly chooses for that purpose.
