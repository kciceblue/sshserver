# Immutable release and user-scoped deployment

Task 2.5's server-side release foundation produces one immutable directory for
Linux and macOS on amd64 and arm64. Run it only from the exact clean source
revision being released:

```sh
make runtime-release-bundle-check \
  VERSION=v1.2.3 \
  SOURCE_REVISION="$(git rev-parse HEAD)" \
  DOWNLOAD_ORIGIN=https://kciceblue.github.io/sshserver
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
  install.sh
  install-command.txt
  sshserver-{linux,darwin}-{amd64,arm64}
  preview-{linux,darwin}-{amd64,arm64}.txt
```

The canonical manifest is frozen by
[`release-manifest.schema.json`](release-manifest.schema.json). It binds the
exact origin, release, source revision, Go toolchain, four target identities,
byte counts, SHA-256 digests, LICENSE, and NOTICE.

The download base is an exact lowercase HTTPS host with an optional canonical,
unescaped path prefix. The prefix is at most 256 ASCII bytes including its
leading slash, and the existing 512-character bound still applies to the
complete origin. Every file URL must append exactly
`/releases/<release>/<file>` to that base. This permits a repository-scoped
GitHub Pages site while still rejecting redirects, queries, fragments, encoded
segments, dot segments, empty segments, and moving release labels.

Release identifiers are 1–64 ASCII bytes and match
`^v?[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9]+([.-][a-z0-9]+)*)?$`. Examples include
`1.2.3`, `v1.2.3`, and `v1.2.3-rc.1`. Moving channels such as `latest`,
`stable`, `current`, `main`, and `nightly` are never release identifiers.

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

## Copyable one-line installer

`install-command.txt` contains exactly one shell command. Obtain that command
from the trusted app release catalog or another authenticated release channel;
the command itself is the trust root and carries the literal `install.sh` URL,
exact byte count, and lowercase SHA-256. It starts a clean `/bin/sh`, disables
curl configuration, permits HTTPS only, refuses redirect following, applies
finite connect and transfer timeouts plus both curl's expected-size check and an
independent process file-size limit for unknown-length responses, downloads to
a new owner-only temporary directory, opens and retains the downloaded file,
unlinks its pathname, and captures its bytes through that descriptor. It
checks the exact captured byte count and digest before passing that same
NUL-free, at-most-64-KiB string to `/bin/sh -c`; neither a later pathname
replacement nor a separately downloaded checksum file can select the executed
installer bytes. Unverified response bytes are never piped into a shell.

The verified `install.sh` starts again with a sanitized environment. It retains
only a validated absolute `HOME` and optional absolute XDG data, state,
configuration, and runtime directories; fixes `PATH` and `LC_ALL`; uses a new
owner-only executable workspace beneath the physical home rather than `/tmp`;
enters and reprotects that directory before writing it; and keeps every
download, digest check, preview, and artifact execution relative to that pinned
working-directory inode. Renaming or replacing the workspace's parent pathname
therefore does not redirect those relative lookups. Immediately before both
native launches it repeats the artifact's exact byte-count and SHA-256 checks.
A symlink or automounted `HOME` remains supported because the deployment
process receives the original `HOME` while the staging directory uses its
physical location. The installer
requires system curl 7.58.0 or newer plus either `sha256sum` or `shasum`. Both
the bootstrap and verified installer preflight that curl floor before their
first download, so an older or unparseable system curl fails with an explicit
diagnostic. It maps the
execution architecture as follows:

```text
Linux  x86_64 or amd64   -> linux/amd64
Linux  aarch64 or arm64  -> linux/arm64
Darwin x86_64 or amd64   -> darwin/amd64
Darwin arm64 or aarch64  -> darwin/arm64
```

This intentionally follows the architecture reported to the executing shell;
an x86_64 shell under Rosetta installs the amd64 binary. Unknown and 32-bit
targets fail before downloading or executing an artifact.

The native launch rechecks are defense in depth, not an atomic inode-execution
claim. Portable POSIX shell has no cross-platform retained-descriptor execution
primitive for native Linux and macOS binaries; in particular, Darwin has no
`fexecve`/`execveat` equivalent available to this bootstrap. A hostile
concurrent process running as the selected Unix account is therefore outside
the installer integrity boundary. Such a process can also replace the
user-owned installed runtime or its state after installation, so it is treated
as compromise of that account and requires restoration from a known-good host.
The parent-namespace swap tests exercise accidental or externally induced path
instability; they do not claim protection from an already-compromised account.

The installer embeds the exact manifest, LICENSE, NOTICE, and all four artifact
URLs, byte counts, and SHA-256 digests. It downloads and verifies the manifest,
support files, and selected artifact before any artifact execution. The
installer repeats the artifact pin immediately before preview and apply; the
artifact then reopens and revalidates those same pinned inputs and its frozen
Go attestation. A controlling `/dev/tty` is mandatory: the installer writes the
exact canonical read-only deployment preview there and proceeds only after the
user types the literal word `yes`. The installer closes both terminal
descriptors before apply, so neither the apply child nor a long-lived foreground
server inherits them. Decline, missing tools or terminal, redirect, timeout,
truncation, oversize response, checksum mismatch, unsupported target, or preview
failure leaves the artifact unapplied.

After confirmation the installer invokes `deploy apply --consume-inputs
--supervise-foreground`. A native current-user systemd or LaunchAgent result
prints one credential-free locator receipt and returns. If no supported user
service manager is available, the apply command first emits that same receipt,
validates the committed foreground state and exact installed locator argv, then
replaces itself with `<installed-binary> serve --state-dir <installed-state>`;
the SSH or terminal session must supervise it for its full lifetime. Neither
path invokes `sudo`, requests a public listener, changes another user, or
installs anything on ordinary SSH target hosts.

The authenticated app flow remains package-manager and downloader independent:
it verifies catalog bytes locally, transfers them over the existing
host-key-verified SFTP generation, and uses the target-specific preview/apply
contract above. First-device enrollment and locator binding remain app-owned;
the one-line installer emits no credential or enrollment material.

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
