# Just Another Terminal Sync Server

`sshserver` is the optional, single-user sync service for Just Another
Terminal. A user may install it on a Linux or macOS host that they explicitly
trust. Normal SSH destinations remain agentless and do not require this
service.

This repository is the public, Apache-2.0-licensed Go server. The private iOS
client and the canonical product plan live in separate repositories. The
server implementation has not started yet; this scaffold establishes the
licensing and contribution controls required before feature work begins.

## Development policy

Run the complete local policy suite before proposing a change:

```sh
make check
```

Only MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, and ISC dependencies are
permitted. Every Go module must be recorded in `DEPENDENCIES.json`; its full
license text must be placed in `ThirdPartyLicenses/`; and its required notice
must be added to `NOTICE`. The fail-closed policy checker compares the
inventory with both the Go module graph and GitHub Actions used by CI.

Never use GPL source as an implementation input. The complete clean-room and
product guardrails are repeated in `AGENTS.md` and `CLAUDE.md`.

## Contributing and DCO

Every commit in a pull request must certify the Developer Certificate of
Origin in `DCO.md`. Add the certification with Git's sign-off option:

```sh
git commit -s
```

The pull-request DCO workflow checks each commit and rejects missing or
mismatched `Signed-off-by` trailers.
