# Task 2.1 server runtime

This module is the first executable sync-server substrate. It implements
protected on-host initialization, SQLite metadata and hash-only device
credential storage, exact health and capability responses, foreground service
lifecycle, and user-scoped service-definition rendering.

Enrollment, encrypted-record synchronization, recovery, and deployment-time
service activation remain unavailable until their roadmap tasks land. The
runtime is loopback-only, stores only opaque client-encrypted records, performs
no vault cryptography, parses no private keys, and is never installed on
ordinary SSH targets.

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

`init` is idempotent and refuses unsafe ownership, permissions, symlinks, hard
links, mixed partial installations, and listener changes. Only literal IPv4 or
IPv6 loopback listeners are accepted. The 32-byte instance secret lives in a
separate owner-only regular file and is never written to SQLite; plaintext
device credentials are hashed before persistence.

The `service render` and `service install` commands generate a systemd user
unit or per-user LaunchAgent that executes the same foreground path without a
credential in arguments, environment, or service files. They do not enable or
start the service manager. See [`../packaging/README.md`](../packaging/README.md)
for the packaging boundary.

The SQLite driver is an exact, mechanically trimmed source fork of the
MIT-licensed `github.com/ncruces/go-sqlite3` v0.32.0 package closure. Its
upstream commit, checksums, and retained source boundary are documented in
[`third_party/go-sqlite3/UPSTREAM.md`](third_party/go-sqlite3/UPSTREAM.md).
