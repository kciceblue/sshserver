# Verified-SSH endpoint discovery extension

Status: **D21 normative V1 routing extension**

This document adds one read-only routing command to the frozen,
owner-approved public V1 product profile in [`../../SYNC-PROTOCOL.md`](../../SYNC-PROTOCOL.md).
It does not change that profile's HTTP routes or headers, identifiers,
cryptography, Keychain behavior, credential custody, or storage semantics.

## Invocation and deployment binding

For a lifecycle-managed installation, the client retains a deployment locator
from the verified lifecycle request/result context: one exact immutable binary
path plus the canonical home, install-root, and state-directory paths. Before
each new channel, on the same host-key-verified SSH generation used for
forwarding, it invokes that exact locator with this argument vector and no
stdin:

```text
<absolute-verified-lifecycle-binary> deploy status \
  --home-dir <canonical-home> \
  --install-root <canonical-install-root> \
  --state-dir <canonical-state-directory>
```

All three layout arguments are mandatory together. Their explicit form is
parsed before deployment defaults and the read-only status path does not
consult `HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, or `XDG_CONFIG_HOME` to
select or validate another layout. The client strictly accepts only status
`active` or `foreground_running`, `running: true`,
`recovery_required: false`, no journal, and a complete validated active-release
record. It issues a fresh active-binary capability only from that result, then
invokes the returned exact path with:

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

Supported apply, recover, upgrade, and rollback operations retain immutable
release binaries; explicit uninstall removes them. A locator captured before
an equivalent one-line or other supported out-of-app upgrade can therefore
refresh the replacement active path. A missing or damaged locator, partial
layout tuple, recovery journal, unhealthy status, identity mismatch, or
uninstalled state fails closed and requires explicit deployment recovery.

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

The client performs the exact-layout status refresh above before every new
channel, strictly decodes the endpoint response, validates the protocol plus
expected instance and vault UUIDs, and opens a generation-bound forward only
to the reported `127.0.0.1:<loopback_port>`. It then calls V1 capabilities
through that forward and revalidates both identities before exposing an
enrollment grant or bearer token. It never infers an executable from an upload
destination, trusts PATH or a cached port, scans ports, resolves a hostname,
follows a redirect, honors a proxy, or tries a direct or public endpoint.
Discovery failure leaves the offline-first engine local and consumes no
credential.
