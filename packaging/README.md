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
  preview-{linux,darwin}-{amd64,arm64}.txt
```

The canonical manifest is frozen by
[`release-manifest.schema.json`](release-manifest.schema.json). It binds the
exact origin, release, source revision, Go toolchain, four target identities,
byte counts, SHA-256 digests, LICENSE, and NOTICE.

## Client upload, preview, and activation boundary

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

It first invokes the matching `preview-*.txt` line as one SSH exec command and
strictly parses the returned canonical JSON. Preview creates no install root,
state directory, lock, journal, service definition, instance, or release file,
so discarding it is complete cancellation. After showing and confirming those
exact bytes, the client computes their SHA-256 including the terminal newline
and constructs the target-specific `deploy apply` line with
`--confirmed-preview-sha256`. The server rebuilds and compares that exact plan
while holding its lifecycle and initialization locks before journal, artifact,
instance, or service mutation.

Neither command uses a shell pipeline, downloader, checksum utility, `sudo`,
host package prerequisite, or stdout/stderr redirection. The uploaded binary
reopens and re-verifies the pinned manifest, artifact, LICENSE, and NOTICE
before publishing anything. `--consume-inputs` removes the four verified upload
files only after a successful transaction. On success, the confirmed activation
line passes through the one-line `deploy apply` JSON result, including its
`deployment_locator`, unchanged.

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

A successful fresh, idempotent, or recovered apply and a successful rollback
emit exactly one nested `deployment_locator` with these keys:

```text
version                     string "1"
lifecycle_binary_path       canonical absolute immutable installed binary
home_dir                    canonical absolute selected-user home
install_root                canonical absolute deployment root beneath home
state_dir                   canonical absolute protected state root beneath home
release                     exact immutable release identifier
os                          linux or darwin
architecture                amd64 or arm64
manifest_sha256             64 lowercase hexadecimal characters
binary_sha256               64 lowercase hexadecimal characters
binary_bytes                positive bounded integer
```

The lifecycle builds the object only from its already validated layout and
committed active release. It never uses the consumed upload path, `PATH`,
ambient defaults, or the current executable path. Errors, uninstall, and a
recovery-required status emit no locator rather than a partial one. The locator
contains no password, SSH key, token, grant, instance secret, device/instance/
vault/host identifier, service definition, endpoint port, or transaction data.
The host-local absolute paths can disclose an account name and should be
handled as operational metadata.

This object is a credential-free routing receipt, not an attestation or a claim
of provenance. Copied or pasted output is untrusted. The app binds it to the
user-selected host profile only after host-key verification and SSH
authentication, strict V1 decoding, comparison with the locally pinned release
manifest, canonical validation of the complete path tuple, and no-follow SFTP
verification of the remote binary's exact byte count and SHA-256. It stores the
host binding separately and never places an SSH credential in the receipt.

The app retains one accepted immutable lifecycle binary and layout tuple.
Before each new sync channel it runs:

```text
<absolute-verified-lifecycle-binary> deploy status \
  --home-dir <canonical-home> \
  --install-root <canonical-install-root> \
  --state-dir <canonical-state-directory>
```

All three layout flags must be supplied together for this read-only status
locator. Mutating apply, recover, rollback, and uninstall commands retain their
independent per-flag override behavior and merge omitted fields from platform
defaults. Exact-layout status parses its tuple before consulting defaults and
does not use ambient `HOME`,
`XDG_DATA_HOME`, `XDG_STATE_HOME`, or `XDG_CONFIG_HOME` to select or validate
another deployment layout. The client accepts only a healthy running result
with no recovery journal and issues the active-binary capability only from the
fully validated active release.

The client uses that same refreshed active binary for
`enrollment create --format=json`. A managed binary resolves the protected
state directory from the active deployment record; an explicit `--state-dir`
is accepted only when it exactly matches that directory. Both forms bind the
private admin request to its generation, exact binary path, and artifact digest.
The serving binary takes a shared lifecycle lock, rejects
any present, malformed, or insecure recovery journal, and reloads that record
while retaining the lock through grant creation. A concurrent or crashed apply,
recover, rollback, or uninstall therefore cannot let a stale or
recovery-required binary mint a grant. The explicit `--state-dir` form also
remains available for directly initialized, non-managed binaries and is parsed
without first consulting ambient defaults.

Apply, recover, upgrade, and rollback never remove an installed immutable
release directory. This lets a locator retained before an equivalent one-line
or other supported out-of-app upgrade report the newest active binary. Only
explicit uninstall removes the immutable version tree. A missing or damaged
locator, partial layout tuple, unhealthy status, or recovery-required result
fails closed into deployment recovery; it never triggers PATH lookup, port
scanning, or a direct/public fallback.
