# Verified-SSH endpoint discovery extension

Status: **D21 normative V1 routing extension**

This document adds one read-only routing command to the frozen,
owner-approved public V1 product profile in [`../../SYNC-PROTOCOL.md`](../../SYNC-PROTOCOL.md).
It does not change that profile's HTTP routes or headers, identifiers,
cryptography, Keychain behavior, credential custody, or storage semantics.

## Invocation and deployment binding

For a lifecycle-managed installation, the client retains the absolute active
binary path returned by the verified deployment result. On the same
host-key-verified SSH generation used for forwarding, it invokes that exact
binary with this argument vector and no stdin:

```text
<absolute-active-sshserver-binary> endpoint show --format=json
```

The server derives the immutable installation root from its resolved current
executable, reads the canonical owner-only `deployment.json`, requires that
the record is active or supervised-foreground and names that exact executable
as its active release, and takes the protected state directory from that
record. It does not recompute the deployed state directory from `XDG_STATE_HOME`
or `XDG_DATA_HOME`. Missing, malformed, insecure, inactive, or mismatched
deployment metadata fails closed rather than falling back to an ambient
default.

A directly initialized, non-lifecycle-managed binary may instead use the
explicit form:

```text
sshserver endpoint show --format=json --state-dir <absolute-protected-state-directory>
```

The explicit path remains subject to the same ownership, mode, symlink,
completion-marker, configuration, and listener validation. It is not the
normal product deployment path.

## Success and failure contract

Success exits zero, writes nothing to stderr, and writes exactly one bounded
JSON object followed by one newline:

```json
{"protocol_version":"1","instance_id":"00000000-0000-4000-8000-000000000001","vault_id":"00000000-0000-4000-8000-000000000002","loopback_port":37421}
```

`protocol_version` is the string `"1"`. Both identifiers are the lowercase
canonical UUIDv4 values created during initialization; the public V1 product
profile creates both the instance and vault identifiers before enrollment, so
`vault_id` is never null. `loopback_port` is the configured integer port from
a literal `127.0.0.1` listener in the inclusive range 1 through 65535. A
dual-stack configuration is allowed only when all listeners share that port.

The command reads only the protected completion marker, validated runtime
configuration, and, for managed deployment, the protected deployment record.
It does not open or migrate SQLite, read the instance secret, create an
enrollment grant or token, bind a listener, or mutate product state. Any
invalid state exits nonzero with bounded stderr and no stdout; errors expose
no filesystem path, host identifier, secret, grant, or token.

## Client requirements

The client strictly decodes the response, validates the protocol plus expected
instance and vault UUIDs, and opens a generation-bound forward only to the
reported `127.0.0.1:<loopback_port>`. It then calls V1 capabilities through
that forward and revalidates both identities before exposing an enrollment
grant or bearer token. It never scans ports, resolves a hostname, follows a
redirect, honors a proxy, or tries a direct or public endpoint. Discovery
failure leaves the offline-first engine local and consumes no credential.
