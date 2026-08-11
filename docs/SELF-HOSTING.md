# Self-host Just Another Terminal sync

This guide is for one person who already has an SSH account on a Linux or
macOS host. The sync server is optional. It belongs only on the host you select
for sync; Just Another Terminal never installs a daemon on ordinary SSH
destinations.

The service listens only on literal loopback addresses. The app reaches it by
opening a local forward inside an already host-key-verified, authenticated SSH
connection. Do not open port 37421 in a firewall, publish it through a reverse
proxy, or add a public listener.

## Before you begin

You need:

- a non-root SSH account whose home directory is writable by that account;
- Linux or macOS on `amd64`/`x86_64` or `arm64`/`aarch64`;
- no `sudo`, container runtime, package manager, or public DNS name;
- an active seven-day product preview or lifetime unlock in the app; setup
  routes to the access screen when neither is available;
- a client whose **Sync Server** release panel displays `v0.1.1`; an older
  release-pinned client cannot verify or import a `v0.1.1` locator receipt;
- system `curl` 7.58.0 or newer for the copyable installer, plus either
  `sha256sum` or `shasum` for the installer and cold backup/restore; and
- an interactive terminal when using the one-line installer, because the
  verified preview requires a literal `yes` on `/dev/tty`.

An x86_64 shell running under Rosetta installs the macOS amd64 build. Unknown
and 32-bit targets stop before an artifact is executed.

This is an availability-gated operator contract, not a claim that every
currently published client exposes every section. Do not present it as a
completed Task 2.6 walkthrough until a released client both pins `v0.1.1` and
ships the protection-choice, device-management, and token-rotation controls
described below.

## Fast path: install and enroll from the app

1. Add the intended sync host to Just Another Terminal. Connect once and
   verify its host key before continuing.
2. Open **Hosts**, select that host, then open **Sync Server**.
3. Choose **Preview**. Review the exact release, OS/architecture, service mode,
   install root, state directory, binary, and service-definition path.
4. Confirm only if those exact changes are expected. The app transfers the
   pinned manifest, binary, LICENSE, and NOTICE over the verified SSH/SFTP
   generation, rechecks every byte remotely, installs as the selected Unix
   user, and starts a current-user service when one is available.
5. Keep the screen open while it enrolls the device and completes the first
   authenticated sync round trip. **Ready** means that bounded operation
   succeeded; it does not expose the server publicly.

To add a second device in base mode, add and verify the same SSH host on that
device and repeat these steps. The install is idempotent. The new device gets a
fresh enrollment grant through its own verified SSH connection, joins the
existing vault, and downloads the encrypted state. Do not copy a bearer token,
enrollment grant, VMK, or instance secret between devices.

If the app reports **Sync pending**, keep local edits and retry from that
screen. If it reports an unknown install outcome, reconnect to the same host
and let the app re-read the exact deployment status; do not start a second
installation under a different account or path.

## Equivalent pinned one-line install

The **Sync Server** screen also displays the exact one-line command pinned by
the client release. Copying that line from the app is the preferred independent
path. Run it in an interactive SSH session as the same non-root user, inspect
the canonical preview, and type `yes` only if it matches the intended layout.

For release `v0.1.1`, the public release record is
<https://github.com/kciceblue/sshserver/releases/tag/v0.1.1>. Its immutable
bundle is <https://kciceblue.github.io/sshserver/releases/v0.1.1/>. If the app
is unavailable, download the command as data, verify these exact published
bytes, inspect it, and then run that verified file:

```sh
(
set -eu
PATH=/usr/bin:/bin
LC_ALL=C
export PATH LC_ALL
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy \
  NO_PROXY no_proxy CURL_HOME CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR \
  PERL5OPT ENV BASH_ENV
umask 077
JAT_INSTALL_COMMAND_DIR="$(mktemp -d "/tmp/jat-install.XXXXXXXX")"
case "$JAT_INSTALL_COMMAND_DIR" in
  /tmp/jat-install.*) ;;
  *) exit 1 ;;
esac
test -d "$JAT_INSTALL_COMMAND_DIR"
test ! -L "$JAT_INSTALL_COMMAND_DIR"
chmod 700 "$JAT_INSTALL_COMMAND_DIR"
cd "$JAT_INSTALL_COMMAND_DIR"
test "$(pwd -P)" = "$JAT_INSTALL_COMMAND_DIR"
JAT_INSTALL_COMMAND=./install-command.txt
trap 'rm -f "$JAT_INSTALL_COMMAND"; cd /; rmdir "$JAT_INSTALL_COMMAND_DIR"' \
  EXIT HUP INT TERM
/usr/bin/curl --disable --fail --silent --show-error --proto '=https' \
  --tlsv1.2 --connect-timeout 10 --max-time 30 --max-filesize 5779 \
  --output "$JAT_INSTALL_COMMAND" \
  https://kciceblue.github.io/sshserver/releases/v0.1.1/install-command.txt
test -f "$JAT_INSTALL_COMMAND"
test ! -L "$JAT_INSTALL_COMMAND"
chmod 400 "$JAT_INSTALL_COMMAND"
exec 5< "$JAT_INSTALL_COMMAND"
rm -f "$JAT_INSTALL_COMMAND"
JAT_INSTALL_SENTINEL=__JAT_INSTALL_COMMAND_EOF_9f3c6a7b__
JAT_INSTALL_WITH_SENTINEL="$(/bin/cat <&5; printf '%s' "$JAT_INSTALL_SENTINEL")"
exec 5<&-
case "$JAT_INSTALL_WITH_SENTINEL" in
  *"$JAT_INSTALL_SENTINEL") ;;
  *) exit 1 ;;
esac
JAT_INSTALL_PROGRAM=${JAT_INSTALL_WITH_SENTINEL%"$JAT_INSTALL_SENTINEL"}
unset JAT_INSTALL_WITH_SENTINEL
set -- $(printf '%s' "$JAT_INSTALL_PROGRAM" | wc -c)
test "$#" = 1
test "$1" = 5779
if command -v sha256sum >/dev/null 2>&1; then
  JAT_INSTALL_DIGEST="$(printf '%s' "$JAT_INSTALL_PROGRAM" | sha256sum)"
else
  JAT_INSTALL_DIGEST="$(printf '%s' "$JAT_INSTALL_PROGRAM" | shasum -a 256)"
fi
set -- $JAT_INSTALL_DIGEST
test "$#" -ge 1
test "$1" = 485f80db51a14b1001ee58f5ed3174090d22fa6bf00d8e3324b8e94e87210be6
unset JAT_INSTALL_DIGEST
printf '%s' "$JAT_INSTALL_PROGRAM"
/bin/sh -c "$JAT_INSTALL_PROGRAM" install-command.txt
unset JAT_INSTALL_PROGRAM
)
```

Never shorten this to `curl ... | sh`: that would execute network bytes before
the pinned length and SHA-256 have been checked. Do not substitute a moving
`latest`, `main`, or `stable` URL.

The one-line installer performs installation only. Copy its single JSON
locator receipt back to **Sync Server** -> **Verify receipt** in a client whose
release panel shows the same `v0.1.1` release. The app binds that untrusted
receipt to the selected host, re-verifies the installed binary over SSH/SFTP,
then performs enrollment and the first sync. The receipt contains paths and
release metadata, not credentials.

## Service and foreground modes

On Linux the normal result is a `systemd --user` unit named
`com.kciceblue.sshserver.service`. On macOS it is the current user's
`com.kciceblue.sshserver` LaunchAgent. Both execute only the immutable active
binary with `serve --state-dir <absolute-state-directory>`.

If the current-user manager is absent or its user domain is unavailable, the
installer returns a supervised foreground command. The app keeps its verified
SSH process lease alive. From a standalone one-line install, the interactive
SSH/terminal session is the supervisor: closing it stops sync. Use a real
user-service manager or another user-owned supervisor if the service must
survive logout; do not use `sudo` to turn the V1 install into a system service.

## Protection modes

The server stores opaque authenticated ciphertext in both modes; it never sees
record plaintext, private-key plaintext, or the vault master key.

- **Base mode** derives envelope protection from the instance secret stored
  separately from the database. Someone who obtains only `server.db` still
  lacks that secret. A full host compromise or a complete backup containing
  both files can unwrap the vault envelope, so the selected host is trusted for
  confidentiality.
- **Passphrase mode** also requires the user's passphrase through the reviewed
  Argon2id profile. A full host or complete-backup disclosure does not directly
  reveal the VMK, but it enables offline passphrase guessing. Use a strong,
  unique passphrase and keep it outside the host backup.

Use a client release whose **Sync Server** flow presents a protection choice
before first-vault creation and a passphrase prompt when joining that vault.
If those controls are absent, that client supports the base-mode flow only;
never place a passphrase in a shell command, environment variable, server
configuration file, or support log. Losing the passphrase when no enrolled
device retains the VMK is intentionally unrecoverable.

## Devices, revocation, and token rotation

Each device has its own random ID and token. In a client release that exposes
**Sync Server** -> **Devices**:

1. Refresh the list through the verified SSH-forwarded connection.
2. Match the device ID before acting; names are display metadata.
3. Revoke a lost or retired device. Revocation blocks its future server access
   but cannot erase plaintext or keys already present on that device.
4. Revoking the last active device requires a separate explicit confirmation.
   Do that only when intentionally abandoning the vault.
5. Use **Rotate this device token** after suspected token disclosure. Rotation
   is self-only and exact-retry safe; it does not rotate another device's
   credential or the VMK.

If the client does not expose these controls, update the client. Do not use raw
HTTP requests or copy tokens into `curl`; the product path owns request IDs,
Keychain promotion, exact-retry receipts, and revocation admission barriers.

## Upgrade, recovery, rollback, and uninstall

The app previews a newer pinned release through the same **Sync Server** flow.
Confirming an upgrade preserves the protected instance and keeps the prior
immutable release for rollback. Re-running the exact same app or one-line
request is idempotent.

Keep the `lifecycle_binary_path`, `home_dir`, `install_root`, and `state_dir`
from the verified locator receipt. Read status with all three layout paths so
ambient XDG or home changes cannot select another deployment:

```sh
"$JAT_LIFECYCLE_BINARY" deploy status \
  --home-dir "$JAT_PHYSICAL_HOME" \
  --install-root "$JAT_INSTALL_ROOT" \
  --state-dir "$JAT_STATE_DIR"
```

- For `recovery_required`, reconnect through the same app flow or re-run the
  exact pinned installer that created the interrupted transaction. Never delete
  `deployment-journal.json` by hand.
- To roll back to the retained prior release:

  ```sh
  "$JAT_LIFECYCLE_BINARY" deploy rollback \
    --home-dir "$JAT_PHYSICAL_HOME" \
    --install-root "$JAT_INSTALL_ROOT" \
    --state-dir "$JAT_STATE_DIR"
  ```

- To stop the service and remove installed immutable releases while preserving
  the instance state directory:

  ```sh
  "$JAT_LIFECYCLE_BINARY" deploy uninstall \
    --home-dir "$JAT_PHYSICAL_HOME" \
    --install-root "$JAT_INSTALL_ROOT" \
    --state-dir "$JAT_STATE_DIR"
  ```

Uninstall emits no usable locator. Back up the instance first if it is not
intentionally being abandoned.

## Cold backup and restore

Release `v0.1.1` does not implement the approved manifest-driven admin backup
and atomic-restore CLI described in the protocol, nor does it provide a general
hot-backup shortcut. The following is a manual cold-copy workaround. Make one
fail-fast copy while the server is stopped and create its checksum manifest in
the same operation. A complete V1 instance copy contains
exactly these protected state files plus the generated `SHA256SUMS` file:

```text
config.json
instance-secret
server.db
install-state.json
```

Treat the backup as sensitive. In base mode it contains everything the host
uses to open the vault envelope; in passphrase mode it is still an offline
guessing target and contains device token hashes and metadata.

1. Record the exact state directory and active layout from the app preview or
   verified locator. Stop the current-user service:

   Linux:

   ```sh
   systemctl --user disable --now com.kciceblue.sshserver.service
   ```

   macOS:

   ```sh
   launchctl bootout "gui/$(id -u)/com.kciceblue.sshserver"
   ```

   For foreground mode, terminate and wait for the supervising process. Do not
   continue until `.enrollment.sock` is gone and no `server.db-wal`,
   `server.db-shm`, or `server.db-journal` file remains.

2. Set `JAT_BACKUP_DIR` to a path that does not exist. Copy the exact
   closed-state set into that fresh owner-only directory on encrypted storage:

   ```sh
   (
     set -eu
     umask 077
     test ! -e "$JAT_BACKUP_DIR"
     mkdir -m 700 "$JAT_BACKUP_DIR"
     for name in config.json instance-secret server.db install-state.json; do
       test -f "$JAT_STATE_DIR/$name"
       test ! -L "$JAT_STATE_DIR/$name"
     done
     for name in .enrollment.sock server.db-wal server.db-shm server.db-journal; do
       test ! -e "$JAT_STATE_DIR/$name"
       test ! -L "$JAT_STATE_DIR/$name"
     done
     cp -p \
       "$JAT_STATE_DIR/config.json" \
       "$JAT_STATE_DIR/instance-secret" \
       "$JAT_STATE_DIR/server.db" \
       "$JAT_STATE_DIR/install-state.json" \
       "$JAT_BACKUP_DIR/"
     chmod 600 "$JAT_BACKUP_DIR"/*
     cd "$JAT_BACKUP_DIR"
     if command -v sha256sum >/dev/null 2>&1; then
       sha256sum config.json instance-secret server.db install-state.json \
         > SHA256SUMS
     else
       shasum -a 256 config.json instance-secret server.db install-state.json \
         > SHA256SUMS
     fi
     chmod 600 SHA256SUMS
   )
   ```

   The new-directory check prevents overwriting or mixing a prior backup. Keep
   the five files together. If this block exits nonzero, any newly created
   directory is a partial, invalid attempt; never reuse it as a backup. The
   checksum manifest detects later omission,
   substitution, or accidental mixing relative to this stopped snapshot; it is
   not a signature and cannot prove that unrelated source files already came
   from one instance before capture.

3. Restart the same user service. On Linux use:

   ```sh
   systemctl --user enable --now com.kciceblue.sshserver.service
   ```

   On macOS use the exact service-definition path shown by the confirmed
   preview, or re-read `state.service_definition` from `deploy status`. The
   credential-free deployment locator deliberately does not contain this path:

   ```sh
   launchctl bootstrap "gui/$(id -u)" "$JAT_SERVICE_DEFINITION"
   launchctl kickstart -k "gui/$(id -u)/com.kciceblue.sshserver"
   ```

   In foreground mode, restart the exact supervised argv from the verified
   deployment result (the immutable active binary plus `serve --state-dir`
   pointing to `JAT_STATE_DIR`) and keep that supervisor alive.

To restore, install an equal or newer V1-compatible release, stop it, and keep
its current state directory as a recoverable sibling rather than overwriting
it. Before copying anything, verify that the backup contains only the four
named state files and `SHA256SUMS`, all as regular non-symlink files, then run
`sha256sum -c SHA256SUMS` or `shasum -a 256 -c SHA256SUMS` from inside that
directory. Create a fresh mode-0700 state directory at the exact recorded path,
copy the four verified files into it with mode 0600, and verify the destination
against the same manifest before starting the service.

```sh
(
  set -eu
  for entry in \
    "$JAT_BACKUP_DIR"/* \
    "$JAT_BACKUP_DIR"/.[!.]* \
    "$JAT_BACKUP_DIR"/..?*; do
    test -e "$entry" || test -L "$entry" || continue
    case "$entry" in
      "$JAT_BACKUP_DIR/config.json"|\
      "$JAT_BACKUP_DIR/instance-secret"|\
      "$JAT_BACKUP_DIR/server.db"|\
      "$JAT_BACKUP_DIR/install-state.json"|\
      "$JAT_BACKUP_DIR/SHA256SUMS") ;;
      *) exit 1 ;;
    esac
  done
  for name in config.json instance-secret server.db install-state.json; do
    test -f "$JAT_BACKUP_DIR/$name"
    test ! -L "$JAT_BACKUP_DIR/$name"
  done
  test -f "$JAT_BACKUP_DIR/SHA256SUMS"
  test ! -L "$JAT_BACKUP_DIR/SHA256SUMS"
  cd "$JAT_BACKUP_DIR"
  awk '
    NF != 2 { bad = 1 }
    $2 == "config.json" { config++ ; next }
    $2 == "instance-secret" { secret++ ; next }
    $2 == "server.db" { database++ ; next }
    $2 == "install-state.json" { state++ ; next }
    { bad = 1 }
    END {
      if (bad || config != 1 || secret != 1 || database != 1 || state != 1) {
        exit 1
      }
    }
  ' SHA256SUMS
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS
  else
    shasum -a 256 -c SHA256SUMS
  fi
  test ! -e "$JAT_STATE_DIR"
  mkdir -m 700 "$JAT_STATE_DIR"
  cp -p config.json instance-secret server.db install-state.json \
    "$JAT_STATE_DIR/"
  chmod 600 "$JAT_STATE_DIR"/*
  cd "$JAT_STATE_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$JAT_BACKUP_DIR/SHA256SUMS"
  else
    shasum -a 256 -c "$JAT_BACKUP_DIR/SHA256SUMS"
  fi
)
```

Do not rely on `v0.1.1` startup to detect an incoherent manual restore. It
validates individual formats but does not bind the four files to one captured
instance: a missing database can be initialized, and a well-formed secret from
another instance is not rejected by provenance. If the exact five-file set or
its checksum verification fails, keep the server stopped and restore the
recoverable sibling; do not repair the copy by deleting a file or initializing
a new instance over the old database.

After start, reconnect from an enrolled device and complete a full refresh.
Keep the prior state directory and backup until that device verifies the
expected instance/vault IDs and encrypted records.

## Troubleshooting without weakening the boundary

- A host-key warning is blocking. Resolve the SSH identity; do not bypass it.
- `foreground_required` means the user service manager is unavailable, not
  that installation failed. Keep the supervised process alive.
- `recovery_required` means resume the exact transaction; do not delete the
  journal or select a different install root.
- A passphrase error must not fall back to base mode.
- Server-unreachable sync leaves local work intact. Retry after SSH and the
  loopback service are healthy.
- Support bundles must not contain tokens, grants, VMKs, passphrases, instance
  secrets, private keys, raw receipts, hostnames, or absolute home paths.

The [threat model](THREAT-MODEL.md), [protocol](../SYNC-PROTOCOL.md), and
[immutable deployment contract](../packaging/README.md) are authoritative for
the deeper security and failure semantics. Their manifest-driven atomic
backup/restore design remains roadmap work and is not a claim about the manual
`v0.1.1` workaround above. The human under-15-minute
walkthrough and the full native OS/architecture acceptance matrix remain
separate evidence; this document does not claim either run has occurred.
