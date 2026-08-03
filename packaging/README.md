# Immutable release and user-scoped deployment

Task 2.5's server-side release foundation produces one immutable directory for
Linux and macOS on amd64 and arm64. Run it only from the exact clean source
revision being released:

```sh
make runtime-release-bundle-check \
  VERSION=v1.2.3 \
  SOURCE_REVISION="$(git rev-parse HEAD)" \
  DOWNLOAD_ORIGIN=https://downloads.example.test
```

The clean-source gate rejects a non-root checkout path, a mismatched 40-byte
commit ID, tracked changes, and untracked changes. Builds use the local exact Go
patch release, cgo disabled, baseline amd64/arm64 settings, no workspace,
overlay, tags, GOFLAGS, or GOEXPERIMENT, and one encoded release attestation.
The generator reads metadata from the same bytes it hashes and publishes the
entire bundle with no-replace directory semantics. Repeating identical inputs
is allowed; changing any byte under the same release ID is refused.

The resulting public layout is:

```text
dist/releases/<release>/
  LICENSE
  NOTICE
  release-manifest.json
  sshserver-{linux,darwin}-{amd64,arm64}
  activation-{linux,darwin}-{amd64,arm64}.txt
```

The canonical manifest is frozen by
[`release-manifest.schema.json`](release-manifest.schema.json). It binds the
exact origin, release, source revision, Go toolchain, four target identities,
byte counts, SHA-256 digests, LICENSE, and NOTICE.

## Client upload and activation boundary

The bundle generator reports an `upload_files` contract for each target. The
authenticated SSH client must verify the selected manifest and release files
locally, create the target-specific directory in the selected sync host's
physical home, and atomically publish exactly these owner-only paths:

```text
upload directory       0700
release-manifest.json  0400
sshserver              0500
LICENSE                0400
NOTICE                 0400
```

It then invokes the matching `activation-*.txt` line as one SSH exec command.
That command uses no shell pipeline, downloader, checksum utility, `sudo`, or
host package prerequisite. The uploaded binary reopens and re-verifies the
pinned manifest, artifact, LICENSE, and NOTICE before publishing anything.
`--consume-inputs` removes the four verified upload files only after a
successful transaction.

This is deliberately the server activation foundation, not yet a standalone
copy-and-paste installer: target detection, downloads, local verification,
atomic SSH upload, supervision of a foreground fallback, and enrollment
handoff belong to the following private-client adapter and UI work. A clean
sync host needs only its existing SSH service; ordinary SSH targets never
receive this server.

## Service-manager behavior

The release binary renders the platform definition from the same foreground
serve path used during local operation:

```text
sshserver service render --platform linux --binary /absolute/sshserver --state-dir /absolute/state
sshserver service render --platform darwin --binary /absolute/sshserver --state-dir /absolute/state
```

`sshserver service install` writes the definition with mode `0600` to the
current user's systemd-user or LaunchAgents directory. The low-level command
does not start it. The higher-level transactional deployment lifecycle installs
the exact definition, activates it through `systemctl --user` or the current
user's `launchctl` domain, verifies health and the running release identity,
then commits deployment state. Neither definition contains an instance secret,
token, grant, VMK, passphrase, private key, or usable SSH credential.

The Linux unit is a `systemd --user` service with a restrictive umask,
loopback-capable address-family allowlist, read-only home/system views except
for the chosen state directory, and no-new-privileges hardening. The macOS
definition is a per-user LaunchAgent. Both execute only:

```text
sshserver serve --state-dir <absolute path>
```

Foreground operation remains the documented fallback when the target host has
no supported user service manager. The caller must supervise the returned argv
for its full lifetime. `deploy status` distinguishes active, inactive,
foreground-running, foreground-stopped, damaged, identity-mismatch, and
recovery-required states; rollback and uninstall reuse the same durable
transaction journal.

## Stable deployment locator and upgrade refresh

The app retains one previously verified immutable lifecycle binary together
with the canonical home, install-root, and state-directory paths from the
lifecycle request/result context. Before each new sync channel it runs:

```text
<absolute-verified-lifecycle-binary> deploy status \
  --home-dir <canonical-home> \
  --install-root <canonical-install-root> \
  --state-dir <canonical-state-directory>
```

All three layout flags must be supplied together. Exact-layout status parses
them before consulting defaults and does not use ambient `HOME`,
`XDG_DATA_HOME`, `XDG_STATE_HOME`, or `XDG_CONFIG_HOME` to select or validate
another deployment layout. The client accepts only a healthy running result
with no recovery journal and issues the active-binary capability only from the
fully validated active release.

Apply, recover, upgrade, and rollback never remove an installed immutable
release directory. This lets a locator retained before an equivalent one-line
or other supported out-of-app upgrade report the newest active binary. Only
explicit uninstall removes the immutable version tree. A missing or damaged
locator, partial layout tuple, unhealthy status, or recovery-required result
fails closed into deployment recovery; it never triggers PATH lookup, port
scanning, or a direct/public fallback.
