# V1 server runtime

This module implements the frozen V1 loopback data plane: protected on-host
initialization, an SSH-only enrollment bootstrap, hash-only grant and device
authorization, opaque envelope and record persistence, retry-safe sync and
snapshot reads, and device listing, revocation, and token rotation. It also
provides transactional user-scoped deployment, native service activation, and
supervised foreground fallback.

The runtime is loopback-only, stores only opaque client-encrypted records and
minimal protocol metadata, performs no vault cryptography, parses no private
keys, and is never installed on ordinary SSH targets. Host-loss import,
instance-secret rotation, and backup/restore commands remain separate roadmap
work; no unsupported route is advertised.

From the repository root, build and verify cgo-free Linux and macOS binaries
for amd64 and arm64:

```sh
make runtime-release-check
```

Initialize and run a foreground instance using the binary matching the host:

```sh
./dist/sshserver-darwin-arm64 init --state-dir /absolute/private/state
./dist/sshserver-darwin-arm64 serve --state-dir /absolute/private/state
./dist/sshserver-darwin-arm64 health --address 127.0.0.1:37421
```

While `serve` is running, a verified SSH session can obtain one bounded
bootstrap object with:

```sh
./dist/sshserver-darwin-arm64 enrollment create \
  --format=json \
  --state-dir /absolute/private/state
```

The command talks to an owner-only Unix socket in the protected state
directory. It writes exactly one JSON object to standard output; the instance
secret and five-minute, single-use enrollment grant are never accepted in
arguments, environment variables, the HTTP API, or service-manager files.
For an active managed binary, the explicit state directory must exactly match
its deployment record and the request remains bound to that deployment. A
directly initialized binary keeps the same explicit form without a deployment
binding.

Normal sync discovers a configurable loopback port without minting a grant by
invoking the exact active deployed binary with `endpoint show --format=json`.
That read-only command resolves the recorded deployment state independently of
ambient XDG variables and emits only the protocol version, public instance and
vault UUIDs, and validated IPv4 loopback port. The normative command and client
boundary are specified in
[`../protocol/v1/endpoint-discovery.md`](../protocol/v1/endpoint-discovery.md).

`init` is idempotent and refuses unsafe ownership, permissions, symlinks, hard
links, mixed partial installations, and listener changes. Only literal IPv4 or
IPv6 loopback listeners are accepted. The 32-byte instance secret lives in a
separate owner-only regular file and is never written to SQLite; plaintext
device credentials are hashed before persistence.

The `service render` and `service install` commands generate a systemd user
unit or per-user LaunchAgent that executes the same foreground path without a
credential in arguments, environment, or service files. Before confirmation,
`deploy preview` accepts the same pinned manifest, artifact, LICENSE, NOTICE,
and layout arguments as `deploy apply`. It emits deterministic canonical JSON
covering the exact identities, paths, native-manager or supervised-foreground
outcome, existing transaction classification, remaining actions, preserved
data, and loopback-only listeners. Preview verifies its inputs and probes the
current-user service-manager domain without creating the install root, state
directory, lifecycle or initialization lock, journal, service definition,
instance, or release artifact. Its exact action sequence records whether each
lock must be created and records bootstrap admission, lifecycle locking, and
the initialization lease in Apply order before the remaining layout repair,
journal, or idempotent release work. Rollback and uninstall recovery plans
likewise record bootstrap and lifecycle admission before full layout repair.
A journal already checkpointed at `state_saved` is resumable only when the
saved deployment state exactly matches that transaction and its prior rollback
release remains verified. Discarding the result is therefore a complete
cancellation.

The transactional `deploy apply` and `deploy recover` require the SHA-256 of
the exact canonical preview bytes, including their terminal newline. They
rebuild that plan while holding the lifecycle and initialization locks and
refuse before product mutation if any field or action changed. The leased
initialization-lock path is re-attested against its flocked descriptor before
each journal mutation, release staging, and initialization, so unlink or
replacement fails closed. `deploy status`, `deploy rollback`, and `deploy
uninstall` commands validate an exact pinned release, publish its binary and
LICENSE/NOTICE without replacement, preserve protected instance state, and
drive only the current user's native service manager.
Apply detects the manager before its first mutation and revalidates the exact
outcome before deployment work. Recognized manager absence returns an explicit
supervised-foreground command; a manager failure or changed preflight outcome
is never silently treated as success.

Release builds contain one encoded identity covering release, source revision,
exact Go patch toolchain, target-derived build identity, protocol version, and
storage schema. Malformed production identities fail closed. See
[`../packaging/README.md`](../packaging/README.md) for the immutable bundle and
the client-upload boundary.

The SQLite driver is an exact, mechanically trimmed source fork of the
MIT-licensed `github.com/ncruces/go-sqlite3` v0.32.0 package closure. Its
upstream commit, checksums, and retained source boundary are documented in
[`third_party/go-sqlite3/UPSTREAM.md`](third_party/go-sqlite3/UPSTREAM.md).
