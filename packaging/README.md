# User-scoped service packaging

The release binary renders the platform definition from the same foreground
serve path used during local operation:

```text
sshserver service render --platform linux --binary /absolute/sshserver --state-dir /absolute/state
sshserver service render --platform darwin --binary /absolute/sshserver --state-dir /absolute/state
```

`sshserver service install` writes the definition with mode `0600` to the
current user's systemd-user or LaunchAgents directory. It deliberately does
not enable, start, or modify the user's service manager; Task 2.5 owns the
reviewed installation and activation workflow. Neither definition contains an
instance secret, token, grant, VMK, passphrase, private key, or usable SSH
credential.

The Linux unit is a `systemd --user` service with a restrictive umask,
loopback-capable address-family allowlist, read-only home/system views except
for the chosen state directory, and no-new-privileges hardening. The macOS
definition is a per-user LaunchAgent. Both execute only:

```text
sshserver serve --state-dir <absolute path>
```

Foreground operation remains the documented fallback when the target host has
no supported user service manager.
