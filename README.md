# Just Another Terminal Sync Server

`sshserver` is the optional, single-user sync service for Just Another
Terminal. A user may install it on a Linux or macOS host that they explicitly
trust. Normal SSH destinations remain agentless and do not require this
service.

This repository is the public, Apache-2.0-licensed Go server. The private iOS
client and the canonical product plan live in separate repositories. The
server implementation has not started yet; this scaffold establishes the
licensing and contribution controls required before feature work begins.

## Protocol review draft

Task 2.0's public [sync protocol](SYNC-PROTOCOL.md) and
[threat model](docs/THREAT-MODEL.md) are review drafts. Their exact HTTP,
credential, cryptographic, retention, and recovery profiles are deliberately
marked **REVIEW-PENDING** and are not approved for implementation or release.
Machine-readable schemas, OpenAPI, and non-cryptographic shape fixtures live in
[`protocol/v1/`](protocol/v1/). The crypto fixture intentionally has no expected
outputs until the owner review and independent Swift/Go verification required
by the protocol are complete.

The draft does not start the server implementation. It preserves the locked
boundaries that the server remains loopback-only, stores opaque client-encrypted
records, performs no vault cryptography, parses no private keys, and is never
installed on ordinary SSH targets.

## Development policy

Run the complete local policy suite before proposing a change:

```sh
make check
```

Only MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, and ISC product/runtime
dependencies and implementation inputs are permitted. Every Go module must be
recorded in `DEPENDENCIES.json`; its full license text must be placed in
`ThirdPartyLicenses/`; and its required notice must be added to `NOTICE`. The
fail-closed policy checker compares the inventory with both the Go module graph
and GitHub Actions used by CI.

Test harnesses may execute unmodified stock mosh, Dropbear, and tmux
binaries/packages only as external, non-shipped black-box interoperability
targets. Their source is never an implementation input, and the targets are
never linked into or redistributed with the products. Code and dependencies
used to implement those harnesses remain subject to the allowlist and
inventory requirements above.

Never use GPL source as an implementation input. The complete clean-room and
product guardrails are repeated in `AGENTS.md` and `CLAUDE.md`.

The public, server-relevant subset of the canonical product decisions is in
`DECISIONS.md`. External contributors may use a public repository issue in
place of the private coordinator task reference described there.

## Contributing and DCO

Every commit in a pull request must certify the Developer Certificate of
Origin in `DCO.md`. Add the certification with Git's sign-off option:

```sh
git commit -s
```

The pull-request DCO workflow checks each commit and rejects missing or
mismatched `Signed-off-by` trailers.
