# Just Another Terminal sync protocol

Status: **task 2.0 review draft — not approved for implementation or release**

This document is the proposed public contract between the Just Another
Terminal client and its optional single-user sync server. It is deliberately
precise so the Swift client and Go server can be implemented independently,
but the items labelled **REVIEW-PENDING** remain subject to Tom's protocol and
cryptography review. Until that review is recorded, this document is not a
shipping cryptographic profile and task 2.0 is not complete.

The words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY describe the behavior of
this draft. They become normative only when the review-pending status is
removed.

## 1. Status and decision boundary

### 1.1 Locked product constraints

The following constraints are already locked by the canonical coordinator
decisions and are not reopened by this draft:

- **LOCKED — client-side encryption:** the client creates the random vault
  master key (VMK), encrypts records with XChaCha20-Poly1305, and creates the
  wrapped VMK envelope. The server performs no vault cryptography and parses no
  private key.
- **LOCKED — two threat modes:** base mode trusts the selected sync host because
  that host retains the instance secret. Optional passphrase mode combines
  Argon2id-derived passphrase material with the instance secret so host-only
  compromise cannot unwrap the VMK without an offline passphrase guess.
- **LOCKED — key custody:** software-backed private keys may sync only inside
  authenticated ciphertext. A Secure Enclave private key never leaves its
  device; only its public key and non-secret descriptive metadata may sync.
- **LOCKED — SSH anchor:** installation and enrollment use an already verified
  SSH session. The service binds to loopback, and normal sync uses an SSH local
  forward by default. A public service port is not required.
- **LOCKED — deployment:** one instance serves one individual Unix account.
  Linux and macOS on amd64 and arm64 are the V1 server targets. Ordinary SSH
  destinations remain agentless.
- **LOCKED — conflict retention:** version vectors detect concurrency,
  concurrent values remain explicit conflicts, and tombstones are collected
  only after active-device acknowledgement or a documented retirement rule.

### 1.2 Review-pending profile

The following exact choices are a coherent proposal, not an approval:

| ID | Proposed V1 choice | Status |
| --- | --- | --- |
| P1 | HTTP/1.1 JSON over SSH-forwarded loopback TCP | **REVIEW-PENDING** |
| P2 | 256-bit instance secret, VMK, enrollment grant, and device token | **REVIEW-PENDING** |
| P3 | HKDF-SHA-256 domain separation plus XChaCha20-Poly1305 for VMK wrapping | **REVIEW-PENDING** |
| P4 | Argon2id version `0x13` (decimal 19): 64 MiB, 3 iterations, parallelism 1, 32-byte output | **REVIEW-PENDING; device calibration required** |
| P5 | Client-generated device tokens for retry-safe enrollment and rotation | **REVIEW-PENDING** |
| P6 | The metadata, limits, retention, recovery, and last-device rules below | **REVIEW-PENDING** |

Implementations MUST NOT ship P1–P6 until Tom approves the exact profile and
the fixtures in `protocol/v1/fixtures/crypto-review-vectors.json` contain
independently verified cryptographic outputs.

The proposed wire suite is
`jat-xchacha-hkdf-argon2id-draft2`, with numeric suite ID 2 in canonical
associated data. It supersedes the never-shipped draft1 proposal because
draft2 adds explicit nullable collection-witness authorization to record
revisions and binds its kind and bytes into record associated data. Draft1 and
draft2 are not interchangeable or negotiable as the same suite. Servers advertise
`authenticated-collection-frontiers-v2`; a client that does not understand it
preserves the opaque data and blocks writes.

## 2. Scope and non-goals

One server instance owns one `instance_id` and one `vault_id`. It serves one
person through multiple enrolled devices. A device can continue to use its
local library while the server is absent or unreachable; sync is never a
startup or terminal-session dependency.

V1 does not provide:

- multi-user or organization tenancy;
- a public Internet API, TLS termination, or anonymous access;
- a terminal/session daemon, PTY, SSH proxy, or software for ordinary targets;
- confidentiality against a compromised enrolled device that already holds
  the VMK;
- availability against a malicious sync host;
- perfect hiding of record count, ciphertext length, timing, device count, or
  version-vector activity;
- automatic deletion of device-local Keychain or Secure Enclave material from
  a remotely received tombstone; or
- recovery of a Secure Enclave private key or recovery without the material
  explicitly listed in section 14.

## 3. Terminology and identifiers

- **Instance secret:** random host-resident secret delivered to a client only
  through the verified SSH bootstrap command. It is not returned by the normal
  HTTP API.
- **VMK:** the random client-generated key that protects vault records.
- **Envelope:** the authenticated ciphertext containing the VMK.
- **Enrollment grant:** short-lived, single-use credential created through SSH
  and accepted only by the enrollment endpoint.
- **Device token:** independent bearer credential bound to one device ID,
  instance, vault, and fixed V1 scopes.
- **Record:** one logical synchronized object with a stable random `record_id`.
- **Revision:** one encrypted value or tombstone for a record, identified by a
  random `revision_id` and a version vector.
- **Sibling:** a revision not dominated by another known revision of the same
  record.
- **Change cursor:** server-assigned pagination position. It is transport state,
  not a cryptographic clock and not a conflict-resolution input.

`instance_id`, `vault_id`, `device_id`, `record_id`, `revision_id`, and request
IDs are independently generated UUID version 4 values. They are serialized as
lowercase canonical UUID strings. Reuse of a retired `device_id` is forbidden.

## 4. Wire encoding and limits — REVIEW-PENDING P1/P6

### 4.1 HTTP and JSON

The proposed V1 endpoint is HTTP/1.1 on `127.0.0.1:37421` and `[::1]:37421`.
The port MAY be configured, but every resolved listener address MUST be
loopback. Startup MUST fail rather than bind a wildcard or non-loopback
address. The client reaches the endpoint through an SSH local forward.

Requests and responses use `application/json; charset=utf-8`. JSON field names
use `snake_case`. Writers MUST NOT emit duplicate keys, non-finite numbers, or
invalid UTF-8. Readers MUST reject duplicate keys and unknown fields in V1
write requests. Additive response fields require an advertised capability;
otherwise clients stop locally with `unsupported_response_field` rather than
guessing. That is a client diagnostic, not an HTTP server error.

Unsigned 64-bit values are canonical JSON decimal strings in the inclusive
range `0` through `18446744073709551615`. The wire schema rejects larger
strings, and every implementation MUST additionally use checked unsigned
64-bit parsing before arithmetic or comparison. Binary values use unpadded RFC
4648 base64url. A schema match is not sufficient to establish canonicality:
readers MUST decode with a strict base64url decoder, re-encode the decoded
bytes as unpadded base64url, and reject the value with `invalid_request` unless
the re-encoding is byte-for-byte equal to the input. This rejects non-zero
unused bits in a final two- or three-character quantum. Times are UTC RFC 3339
strings with exactly millisecond precision; server times are informational and
MUST NOT resolve conflicts or authorize an operation.

Every request sends:

```text
JAT-Protocol-Version: 1
JAT-Request-ID: <uuid-v4>
```

Authenticated requests additionally send:

```text
Authorization: Bearer <unpadded-base64url-device-token>
```

Enrollment instead uses `Authorization: JAT-Enrollment <grant>`. Authorization
headers, grants, tokens, instance secrets, envelopes, and record ciphertext
MUST be redacted from logs.

The service emits no CORS permission headers and rejects requests carrying an
`Origin` header with `invalid_request`. Browser access is not a V1 client
surface. HTTP proxy mode, absolute-form request targets, protocol upgrade, and
`CONNECT` are rejected.

### 4.2 Proposed limits

| Resource | V1 limit |
| --- | ---: |
| Request headers | 16 KiB |
| Request or response body | 4 MiB |
| JSON nesting | 32 levels |
| Devices, active plus retired | 64 |
| Vector entries | 64 |
| Mutations per sync request | 256 |
| Returned changes per page | 128 |
| Returned snapshot revisions per page | 128 |
| Returned snapshot collection markers per page | 128 |
| Returned snapshot source devices per page | 64 |
| Active snapshots per authenticated device | 1 |
| Active snapshots per instance | 8 |
| Unique snapshot-create requests per device | 5 per rolling minute |
| Active snapshot metadata per instance | 64 MiB |
| Ciphertext per record revision | 512 KiB |
| Undominated siblings per record | 32 |
| Enrollment attempts per instance | 5 per minute |

Exceeding a limit produces the stable error described in section 12 without
partially applying the request.

## 5. Installation, instance state, and SSH bootstrap

### 5.1 Host files

On first installation the server command creates, from the operating-system
CSPRNG:

- a UUIDv4 `instance_id`;
- a UUIDv4 `vault_id`; and
- a 32-byte `instance_secret` (**REVIEW-PENDING P2**).

The instance secret is stored separately from the ciphertext database in a
regular file owned by the selected Unix account, mode `0600`. Its parent
directory MUST NOT be group- or world-writable. The daemon does not expose the
secret through `/v1`; the administration CLI reads it only for bootstrap,
backup, restore, and rotation operations. Database-only disclosure therefore
does not include the instance secret, while a full host compromise does.

Re-running installation is idempotent and MUST NOT replace an existing
instance secret, instance ID, vault ID, database, or device registry. A partial
installation is resumed or rolled back using a durable install-state marker;
it is never treated as a fresh empty vault without explicit confirmation.

### 5.2 Bootstrap command

After normal SSH host verification succeeds, the app executes the equivalent
of:

```text
sshserver enrollment create --format=json
```

The command creates a 32-byte grant, stores only its domain-separated hash,
and writes exactly one JSON object to the protected SSH channel:

```json
{
  "protocol_version": "1",
  "instance_id": "00000000-0000-4000-8000-000000000001",
  "vault_id": "00000000-0000-4000-8000-000000000002",
  "instance_secret": "<32 bytes, base64url>",
  "enrollment_grant": "<32 bytes, base64url>",
  "expires_at": "2026-07-19T12:05:00.000Z",
  "loopback_port": 37421
}
```

The grant expires five minutes after creation. The grant authorizes exactly one
state-changing enrollment transaction. That first successful transaction
consumes it. A later byte-equivalent retry may retrieve the recorded result as
described in section 6, but the consumed grant cannot authorize another state
change. Exact recovery with a replacement grant also consumes that grant, but
does not exercise or preserve its authority to create enrollment state. The
command MUST suppress shell tracing and MUST NOT put secrets in command-line
arguments, environment variables, persistent logs, or service-manager
configuration.

Grant lifetime is measured with the daemon's monotonic clock and is bound to a
random daemon boot ID. An unconsumed grant becomes invalid when that daemon
process restarts, regardless of the displayed `expires_at`. Wall-clock rollback
therefore cannot extend a grant. `expires_at` is informational UI metadata.

The app treats host-key verification failure, malformed output, a changed
`instance_id`, or a changed `vault_id` as blocking. It does not retry against a
different host automatically.

## 6. Enrollment and device tokens — REVIEW-PENDING P2/P5

The proposed retry-safe enrollment is client-token-generated:

1. The client generates a new `device_id`, `enrollment_id`, and 32-byte device
   token with its CSPRNG.
2. Before sending, it stores the token as pending device-only Keychain material
   under a Tom-reviewed access policy. The token is never written to the local
   JSON library.
3. Through the SSH forward, it calls `POST /v1/enrollments` with the grant,
   IDs, token, and the fixed V1 scope set.
4. In one database transaction the server validates the grant, looks up the
   enrollment ID before attempting any insert, and either performs the new
   enrollment or recovers an exact prior enrollment as described below. A new
   enrollment consumes the grant, stores the token hash, creates the device,
   and records the enrollment ID, request fingerprint, and result against the
   consumed grant hash. Enrollment IDs and device IDs are independently unique
   within the instance and vault.
5. When that consumed grant is presented again, a byte-equivalent retry with
   the same enrollment ID, device ID, token hash, and fixed scope set returns
   the original success. The server returns the recorded success without
   authorizing a second state change. Any mismatch against that recorded
   enrollment returns `enrollment_replay_mismatch`; a consumed grant without a
   matching recorded enrollment returns `grant_consumed`.
6. After success the client promotes the pending token to active Keychain
   state. If it never receives success, it may repeat the same request until
   grant expiry. It MUST retain the pending tuple until the outcome is known.
7. After expiry or a daemon restart, the client creates a replacement grant
   through verified SSH and submits the exact same enrollment ID, device ID,
   token, and scopes. In one transaction the server looks up the enrollment ID
   before inserting a device:
   - If no enrollment or device uses either retained ID, the original request
     did not commit. The server consumes the replacement grant, creates exactly
     one device and enrollment record, and returns `201`.
   - If the enrollment ID, device ID, token hash, and scopes exactly match the
     durable enrollment record, the original request committed. The server
     consumes the replacement grant, associates its hash with that record, and
     returns the recorded original result with `200`; it does not insert or
     update a device, change the active-device count, or reapply any enrollment
     side effect.
   - If either retained ID exists but the full tuple does not match, the server
     returns `enrollment_replay_mismatch` without consuming the replacement
     grant or changing state.

This lookup-before-insert rule makes the two possible lost-response outcomes
converge without allowing a fresh grant to duplicate an already committed
device. Subsequent exact retries with the replacement grant retrieve the same
recorded result under the consumed-grant rule in step 5.

### 6.1 First vault and later-device state machine

The enrollment transaction reports the current envelope generation and whether
the device changed the active-device count from zero to one:

- If it is the first active device and generation is zero, the client creates a
  new random VMK and conditionally writes envelope generation one. A lost PUT
  response is retried with the same generation and bytes. The device MUST NOT
  upload application records until it has read back and authenticated that
  envelope.
- If an envelope already exists, the client retrieves it and unwraps the VMK
  with the SSH-delivered instance secret plus the passphrase when required.
  Wrong passphrase or envelope authentication failure leaves the new device
  enrolled but locked. A conforming client cannot write records or replace the
  envelope merely because it has a device token. The opaque server cannot prove
  VMK possession, so a token-only attacker can still upload invalid opaque data
  and cause denial of service as stated in the threat model.
- If active devices or records exist but the envelope is missing, the server
  and client enter `envelope_missing` recovery. They never create a new VMK over
  existing ciphertext. A surviving device holding the old VMK may explicitly
  repair the envelope after local authorization; otherwise recovery is
  intentionally unavailable.

An interrupted first enrollment may leave one active device and no envelope.
The exact enrollment tuple remains retryable, and the administration CLI can
revoke that device. Re-running installation never resets this state.

The proposed hash is:

```text
SHA-256(
  lp("JAT device token hash v1") ||
  uuid_bytes(instance_id) ||
  uuid_bytes(vault_id) ||
  uuid_bytes(device_id) ||
  token
)
```

`lp(x)` is a four-byte unsigned big-endian length followed by `x`. Grant hashes
use the same construction with label `JAT enrollment grant hash v1`, no device
ID, and the grant in place of the token. Comparisons are constant-time.

Each V1 device token has only these instance- and vault-bound scopes:

- `sync:read`, `sync:write`;
- `envelope:read`, `envelope:write`; and
- `devices:read`, `devices:manage`.

The server stores the random device ID, token hash, fixed scopes, created time,
revoked time, last successful sync time, last acknowledged cursor, and maximum
accepted author counter. It stores no plaintext device label.

### 6.2 Rotation and revocation

Token rotation is self-only. The bearer token first resolves an authenticated
device ID; the request body's `device_id` MUST equal that ID. A mismatch returns
HTTP 403 `authenticated_device_mismatch` before any lookup or write. The
`devices:manage` scope does not authorize rotating another device's token.

Rotation uses a client-generated pending token and rotation ID. The server
atomically replaces only the authenticated device's hash. A retry authenticated
by either the old token before replacement or the new token after replacement
is idempotent when the rotation tuple matches. The client deletes the old
Keychain token only after authenticating successfully with the new token.

Revocation takes effect before the response is committed. A revoked token can
no longer read or write ciphertext, rotate itself, or manage devices. Revocation
does not erase ciphertext already downloaded, a VMK already held by that
device, or local plaintext. A potentially compromised device therefore also
requires a separately reviewed VMK-rotation/re-encryption operation if future
confidentiality from that device is required; that operation is outside V1.

Self-revocation remains permitted and has one deliberately narrow exception to
ordinary revoked-token rejection. In the same transaction that retires its own
row, the server retains for the life of that row:

- the self-revocation request ID;
- the exact authenticated request-body fingerprint;
- the pre-revocation device-token hash; and
- the byte-equivalent HTTP 200 response, including its original headers and
  body.

The body fingerprint is computed only after the bearer is matched to the
retired row and the path target plus equal header and body request IDs are
validated:

```text
SHA-256(
  lp("JAT self revocation body fingerprint v1") ||
  uuid_bytes(instance_id) ||
  uuid_bytes(vault_id) ||
  uuid_bytes(target_device_id) ||
  lp(exact_raw_request_body_bytes)
)
```

On this endpoint only, receipt lookup for a retired row occurs before the
ordinary revoked-token rejection. The same pre-revocation bearer may retrieve
only the recorded response when the target device, `JAT-Request-ID`, body
request ID, and exact raw authenticated body bytes all match the retained
receipt. This is a receipt lookup, not authorization: it performs no general
device, vault, envelope, ciphertext, sync, snapshot, cursor, acknowledgement,
scope, lease, last-sync, or rate-window read beyond the constant-time
retired-receipt row lookup; performs no state mutation; and does not refresh
any timestamp, receipt lifetime, or other lifetime. Any token, target, header,
or body mismatch returns the same HTTP 401 `token_revoked` response without
revealing whether a receipt exists or which field differed. No other endpoint
or request gains this exception. Token-hash and body-fingerprint comparisons
are constant-time.

Revoking the last active device requires `allow_zero_active: true`. With zero
active devices, record and tombstone garbage collection freezes. A new device
can enroll only with a fresh SSH-created grant. Vault deletion is a separate
explicit administration operation and is never implied by last-device
revocation.

## 7. Vault cryptography — REVIEW-PENDING P2/P3/P4

### 7.1 Inputs

| Value | Proposed size/source |
| --- | --- |
| VMK | 32 random bytes from the client CSPRNG |
| Instance secret | 32 random bytes from the host CSPRNG |
| Envelope HKDF salt | 32 random bytes per envelope generation |
| Argon2id salt | 16 random bytes when passphrase mode is enabled |
| XChaCha20 nonce | 24 random bytes per envelope or record revision |

Random values MUST be generated independently. Nonce reuse with the same key
is a fatal local error; the client does not send the affected write.

### 7.2 Passphrase bytes

The proposed client normalizes the user-entered passphrase to Unicode NFC,
does not trim or case-fold it, and encodes it as UTF-8. The confirmation UI
must compare normalized byte strings. Empty passphrases are rejected.

Passphrase mode derives:

```text
passphrase_material = Argon2id(
  version = 0x13 (decimal 19),
  password = normalized_utf8,
  salt = argon2_salt,
  memory = 65536 KiB,
  iterations = 3,
  parallelism = 1,
  output_length = 32
)
```

The Argon2 version and parameters are a review baseline, not an approved
shipping minimum. They must be calibrated on the supported device floor without
silently changing the version or lowering a stored envelope's parameters.

### 7.3 Wrapping-key derivation

Base mode uses an empty `passphrase_material`. Passphrase mode uses the 32-byte
Argon2id output. Both modes derive:

```text
ikm = lp(instance_secret) || lp(passphrase_material)
prk = HKDF-SHA-256-Extract(salt = hkdf_salt, ikm = ikm)
wrap_key = HKDF-SHA-256-Expand(
  prk,
  info = lp("JAT vault wrapping key v1") ||
         uuid_bytes(instance_id) ||
         uuid_bytes(vault_id) ||
         u8(mode),
  length = 32
)
```

`mode` is `0` for base and `1` for passphrase. UUID bytes are the 16 bytes in
network order from their canonical textual representation.

### 7.4 Canonical envelope associated data

The envelope uses XChaCha20-Poly1305 with `wrap_key`. Its plaintext is exactly
the 32-byte VMK. Associated data is this byte concatenation:

```text
lp("JAT vault envelope AD v1") ||
u16be(protocol_major = 1) ||
u16be(crypto_suite = 2) ||
uuid_bytes(instance_id) ||
uuid_bytes(vault_id) ||
u64be(envelope_generation) ||
u64be(instance_secret_generation) ||
u8(mode) ||
lp(hkdf_salt) ||
lp(argon2_salt_or_empty) ||
u32be(argon2_version_or_zero) ||
u32be(argon2_memory_kib_or_zero) ||
u32be(argon2_iterations_or_zero) ||
u32be(argon2_parallelism_or_zero)
```

The resulting ciphertext is 48 bytes: 32 encrypted VMK bytes and a 16-byte
authentication tag. Every KDF and mode field is therefore authenticated.

The client stores the VMK as device-only Keychain material under a policy Tom
must approve. The VMK is never stored in the local JSON library, logs, crash
reports, device token, or server database.

### 7.5 Envelope changes

The server stores one envelope with a monotonically increasing generation.
Creation uses `expected_generation = "0"` and `new_generation = "1"`.
Replacement requires `new_generation = expected_generation + 1`. The client
constructs ciphertext for the new generation before the conditional PUT. A
generation conflict never overwrites the winner. Successor arithmetic is
checked before ciphertext construction. After authenticating and structurally
validating the request, the server first compares `expected_generation`; a
stale value returns `generation_conflict`. When the matching stored and
expected generation is `UInt64.max`, replacement returns non-retryable HTTP 409
`generation_exhausted` before validating a successor value or envelope and
before checking cursor capacity. It does not change the envelope, consume a
cursor, or record a partial request result. Otherwise the server requires the
exact successor and then checks cursor capacity.

Enabling, changing, disabling, or recovering a passphrase rewraps the same VMK
and leaves record ciphertext unchanged. A surviving device that already holds
the VMK can replace a lost passphrase after local user authorization; the old
passphrase is not cryptographically required. This recovery behavior and the
warning for disabling passphrase mode require explicit Tom approval.

## 8. Encrypted record revisions — REVIEW-PENDING P3/P6

For each `record_id`, derive a record key:

```text
record_prk = HKDF-SHA-256-Extract(
  salt = uuid_bytes(record_id),
  ikm = VMK
)
record_key = HKDF-SHA-256-Expand(
  record_prk,
  info = lp("JAT record key v1") ||
         u16be(protocol_major = 1) ||
         u16be(crypto_suite = 2) ||
         uuid_bytes(instance_id) ||
         uuid_bytes(vault_id) ||
         uuid_bytes(record_id),
  length = 32
)
```

The separately domain-separated per-record collection-witness key is:

```text
collection_witness_prk = HKDF-SHA-256-Extract(
  salt = uuid_bytes(record_id),
  ikm = VMK
)
collection_witness_key = HKDF-SHA-256-Expand(
  collection_witness_prk,
  info = lp("JAT collection witness key v1") ||
         u16be(protocol_major = 1) ||
         u16be(crypto_suite = 2) ||
         uuid_bytes(instance_id) ||
         uuid_bytes(vault_id) ||
         uuid_bytes(record_id),
  length = 32
)
```

`collection_witness_authenticator` is a required nullable wire field. `null`
explicitly means that the revision is not authorized for use as a collection
witness. An honest client:

- MUST emit `null` for an initial live revision and for any live revision that
  does not strictly dominate its complete durable same-record causal frontier;
- MUST emit a non-null authenticator for a tombstone; and
- MUST emit a non-null authenticator for a live revision that strictly
  dominates that complete frontier, including a conflict resolution.

The complete durable frontier incorporates every authenticated revision and
every previously verified marker for the record; acknowledgement alone does
not remove an input. A tombstone may carry explicit authorization before it is
eligible for collection, but the server-side dominance, age, and
acknowledgement checks below still apply. Initial live revisions never carry
authorization. For an authorized revision, the client computes:

```text
collection_witness_authenticator = HMAC-SHA-256(
  collection_witness_key,
  lp("JAT collection witness authenticator v1") ||
  u16be(protocol_major = 1) ||
  u16be(crypto_suite = 2) ||
  uuid_bytes(instance_id) ||
  uuid_bytes(vault_id) ||
  uuid_bytes(record_id) ||
  uuid_bytes(revision_id) ||
  u16be(vector_entry_count) ||
  concat(for each vector entry sorted by device UUID bytes:
      uuid_bytes(device_id) || u64be(counter))
)
```

The wire encodes a present authenticator's exact 32 bytes as 43-character
unpadded base64url. The server stores the nullable field but cannot derive the
key or authenticate a non-null value. Every revision uses a new 24-byte random
nonce. Its associated data is:

```text
lp("JAT record revision AD v1") ||
u16be(protocol_major = 1) ||
u16be(crypto_suite = 2) ||
uuid_bytes(instance_id) ||
uuid_bytes(vault_id) ||
uuid_bytes(record_id) ||
uuid_bytes(revision_id) ||
uuid_bytes(author_device_id) ||
u64be(author_counter) ||
u16be(payload_schema = 1) ||
u8(tombstone ? 1 : 0) ||
u16be(vector_entry_count) ||
concat(for each vector entry sorted by device UUID bytes:
    uuid_bytes(device_id) || u64be(counter)) ||
u8(collection_witness_authenticator_kind) ||
if collection_witness_authenticator_kind == 1:
    collection_witness_authenticator_bytes
```

Authenticator kind 0 means `null` and contributes no following bytes. Kind 1
means the HMAC construction above and contributes exactly 32 decoded bytes.
Every other kind is invalid. Consequently altering an existing ciphertext's
field from null to non-null or vice versa, or substituting another revision's
tag, changes associated data and fails AEAD validation; a tag copied across
revision IDs or vectors also fails HMAC verification.

Every version vector and collection-marker frontier is nonempty and canonical.
Entries are strictly increasing by the raw 16 UUID bytes, so each device ID
appears exactly once. Every encoded counter is in `1...UInt64.max`; a zero
component is omitted and is invalid if transmitted. A revision's
`author_counter` is also positive, and its vector contains exactly one
`author_device_id` entry whose counter equals `author_counter`. Servers and
clients reject an empty, duplicate, out-of-order, zero-valued, or
author-mismatched vector or frontier with `invalid_request` before using it for
comparison, associated-data construction, snapshot staging, or recovery
import.

All client-supplied server-visible synchronization metadata is authenticated:
record AEAD binds the author, counter, payload, tombstone, vector, and nullable
authorization kind and bytes. When authorization is non-null, its
domain-separated HMAC additionally binds the canonical witness revision and
vector. The server-assigned change cursor and receipt time are not part of the
record and are never used to select data.

For a live revision, plaintext is UTF-8 JSON matching section 9. For a
tombstone, plaintext is exactly the UTF-8 bytes
`{"payload_version":1,"record_type":"tombstone","body":{}}`.
The visible tombstone flag and encrypted marker must agree; disagreement is a
corrupt record.

The client validates identifiers, vector ordering, associated data, AEAD tag,
every non-null collection-witness authenticator, payload schema, record type,
and application fields before mutating local state. One corrupt revision is
quarantined with its opaque bytes and does not cause good records to be
discarded.

## 9. Encrypted application payload registry

Payloads have this outer shape:

```json
{
  "payload_version": 1,
  "record_type": "host",
  "body": {}
}
```

`record_type` and all body fields are encrypted. V1 defines:

### 9.1 `host`

The body contains stable record ID references plus `name`, `hostname`, `port`,
`username`, optional `proxy_jump`, optional `identity_id`,
`forward_profile_ids`, `notes`, `created_at`, and `updated_at`.

It MUST NOT contain filesystem `identity_files`, `session_logging_enabled`, a
password, passphrase, token, Keychain reference, or runtime session state.
Filesystem paths are device-local, and enabling unredacted session logging is
device-local consent rather than synchronized configuration.

### 9.2 `snippet`

The body contains `name`, `command`, `notes`, `created_at`, and `updated_at`.

### 9.3 `forward_profile`

The body contains `name`, `kind` (`local`, `remote`, or `dynamic`), `bind_host`,
`listen_port`, optional destination host/port, `notes`, `created_at`, and
`updated_at`.

### 9.4 `software_identity`

The body contains `name`, `notes`, `key_kind` (`ed25519` or `rsa`), exact
private- and public-key encoding identifiers, private-key bytes, public-key
bytes, fingerprint, requested local biometric policy, and timestamps. The
entire body is inside record AEAD. V1 defines these canonical pairs:

- `ed25519` uses `private_key_encoding = ed25519-seed-v1` for exactly 32 raw
  seed bytes and `public_key_encoding = ed25519-raw-v1` for exactly 32 raw
  public-key bytes.
- `rsa` uses `private_key_encoding = rsa-pkcs8-der-v1` for a non-empty
  canonical PKCS#8 `PrivateKeyInfo` DER value containing an RSA private key and
  `public_key_encoding = rsa-pkcs1-der-v1` for a non-empty canonical PKCS#1
  `RSAPublicKey` DER value.

After canonical base64url decode, the client MUST bind `key_kind` to exactly
that encoding pair. It MUST enforce both Ed25519 lengths. It MUST strictly parse
each RSA value as the declared ASN.1 type and algorithm, re-encode it to DER,
and require byte-for-byte equality with the received bytes; accepting a BER
variant, trailing bytes, a different algorithm, or an empty value is forbidden.
For either key kind, the client MUST derive the canonical public-key bytes from
the validated private key and require exact equality with `public_key`. Any
encoding, parse, canonicality, or correspondence failure rejects the decrypted
record before persistent Keychain import or any local custody mutation. The
fingerprint is recomputed from the validated public key rather than trusted as
proof of correspondence. This export/import path and its local user
authorization are **REVIEW-PENDING**.

Restoration writes no plaintext key file. The client authorizes access,
decrypts in memory, imports directly into device-only Keychain storage, and
best-effort clears app-owned buffers under the separately reviewed custody
boundary.

### 9.5 `secure_enclave_identity`

The body contains `name`, `notes`, `key_kind = secure_enclave_p256`, public-key
bytes with `public_key_encoding = p256-x963-uncompressed-v1`, fingerprint,
`origin_device_id`, `availability = device_bound`, and timestamps. The public
key is the canonical uncompressed ANSI X9.63/SEC1 P-256 point
`0x04 || X32 || Y32`: exactly 65 decoded bytes and 87 unpadded base64url
characters. Before any persistent local import or custody mutation, the client
MUST strictly base64url-decode it, parse it as a point on P-256, canonically
re-encode it in the same uncompressed form, and require byte-for-byte equality.
It rejects an empty, compressed, DER/SPKI, wrong-length, wrong-prefix,
off-curve, or non-canonical value. The client then MUST recompute the OpenSSH
`ecdsa-sha2-nistp256` SHA-256 fingerprint from the canonical public point and
require exact equality with `fingerprint`; the supplied fingerprint is not
trusted.

The body MUST NOT contain a private key, wrapped private key, Keychain
persistent reference, custody generation, or cleanup authority. The public-key
encoding, parsing, fingerprint verification, and local custody behavior remain
**REVIEW-PENDING** and require Tom's review before implementation or merge.

On any device without the matching local key, this record is an unavailable
device-bound placeholder. The UI must say that the private key was not backed
up. Replacing it creates a newly authorized local key/identity transition; it
never claims to reconstruct the original private key.

### 9.6 `known_host`

The body contains an ordered array of host patterns, marker (`none`,
`cert_authority`, or `revoked`), public-key algorithm, public-key blob,
optional comment, and timestamps. Plain and hashed patterns remain encrypted
from the sync server. Task 1.6 must implement this shape as its sync-ready
known-host model.

### 9.7 Explicitly device-local state

The sync serializer is an allowlist; it never encrypts an entire local
application snapshot. These values MUST NOT sync:

- local snapshot revision or store epoch;
- Keychain `custody_generation` or `custody_recovery` state;
- Keychain persistent references and deletion/recovery handles;
- app appearance, terminal preferences, and new-host defaults;
- session logs, active sessions, automation runtime, diagnostics, and recovery
  archives;
- local filesystem identity paths; and
- per-device logging consent.

Local wall-clock timestamps are display metadata only. They never replace a
version vector or decide a conflict.

## 10. Version vectors, conflicts, and tombstones

### 10.1 Counters

Each device maintains one durable unsigned 64-bit author counter across all
records. Creating a mutation increments it exactly once. The version vector is
the component-wise maximum of every durable revision vector and every retained,
cryptographically verified collection-marker frontier observed by the client,
with the new author counter substituted for its own entry. Marker frontiers
remain part of this durable causal context even when no revision bytes for the
record remain. A client MUST verify a marker before joining its frontier, and
MUST NOT create a mutation for that record while an unverified or quarantined
marker is present. This component-wise maximum is permitted for constructing a
new client-authenticated revision; it is not permission for a server to
synthesize a collection-marker frontier.

The client also persists that component-wise maximum as the complete durable
per-record causal frontier across every authenticated revision and verified
marker it has ever accepted. Acknowledging a server cursor does not erase this
causal evidence. While revision bytes remain locally retained, the checkpoint
also retains the exact authenticated wire object for every undominated sibling;
the component-wise aggregate is not a substitute for any one sibling. The
client retains those authenticated revision bytes and frontiers at least until
it has verified and durably checkpointed one marker whose frontier equals or
strictly dominates the complete durable frontier and which, for every retained
sibling, either names that exact revision ID/vector/authenticator as its
witness or strictly dominates that sibling's vector. Only then may it prune
local revision bytes under its local policy; the causal frontier and latest
marker tuple remain durable rollback evidence. Reusing a retained sibling's
revision ID with a changed marker vector or authenticator is equivocation, not
strict domination.

Counters never wrap. A device at `UInt64.max` receives `counter_exhausted`, is
made read-only, and must enroll with a new device ID before creating further
mutations. The old device ID and vector component remain historical evidence.

The server verifies that an uploaded revision:

- is authored by the token's device ID;
- contains exactly one matching author entry;
- advances that device's maximum accepted author counter by exactly one, unless
  the revision ID and bytes are an idempotent replay; and
- does not claim another device counter above the server's maximum accepted
  value for that device.

These checks limit accidents and simple inflation. They do not make an enrolled
malicious device trustworthy.

### 10.2 Comparison and active projection

Vector `A` dominates `B` when every component of A is at least B and one is
greater. Equal vectors with byte-identical revision data are duplicates. Equal
vectors with different revision IDs or bytes are equivocation/corruption and
are quarantined; neither silently wins. Incomparable vectors are concurrent
siblings.

Clients retain every undominated concurrent sibling. For an immediately usable
local projection they choose the lexicographically greatest `revision_id`
among valid undominated siblings, comparing UUID raw bytes. This deterministic
choice is presentation only; losing siblings remain visible conflicts.

Resolving a conflict creates a new revision whose vector dominates every
resolved sibling. The user may choose one value or create a merged value.
Concurrent edit/delete is a conflict under the same rule; a tombstone never
silently destroys an incomparable live edit.

Cross-record references are projected only after merge. Unresolved or dangling
references stay in the sync conflict store; they are not inserted into an
application model that requires referential integrity.

### 10.3 Remote identity deletion and local key custody

**LOCKED SAFETY INVARIANT:** a remotely received identity tombstone, including
one with a valid record AEAD tag, MUST NOT directly delete Keychain or Secure
Enclave material. Sync records do not carry device-local custody generation or
cleanup authority. The client removes or unlinks the shared active identity
record, preserves any local protected material as an orphan, and requires an
explicit local cleanup action through the reviewed exact-generation custody
transaction. Corrupt, replayed, or conflicting sync data can never invoke a
Keychain cleanup path.

### 10.4 Acknowledgement and collection

The server assigns a monotonically increasing change cursor exactly once to
each committed record revision, envelope creation or replacement, device
enrollment, device revocation or retirement, and collection marker. An exact
idempotent retry returns the recorded operation result; its original change
retains the original cursor and the retry consumes no second cursor. A request
that commits several new cursor-bearing items reserves and
assigns one cursor per item atomically or commits none. The client acknowledges
a cursor only in a later request, after every preceding change is durably
stored or quarantined locally.

Token-hash rotation, acknowledgement and last-successful-sync metadata,
snapshot creation and paging, snapshot lease expiry, backup reads, and the
pending/recovery-slot bookkeeping of instance-secret rotation do not receive a
change cursor. The envelope replacement that names a pending instance-secret
generation remains cursor-bearing.

The change cursor never wraps. At `UInt64.max` the server rejects only a request
that would commit one or more new cursor-bearing items with HTTP 507
`server_cursor_exhausted`, before any part of that request mutates state. Exact
retries of already committed items return their recorded operation results
without allocating another cursor. Authenticated reads, backups,
acknowledgement and last-sync updates, token rotation, snapshot operations, and
other safe non-cursor operations remain available. Beginning an instance-secret
rotation also preflights capacity for its required envelope replacement;
exhaustion returns `server_cursor_exhausted` without creating a pending secret.

The proposed minimum tombstone retention is 90 days of accumulated daemon
uptime. The server increments a durable per-candidate retention-age counter
only from positive monotonic elapsed time while the daemon runs, checkpointing
before collection. Restart downtime earns no age. Wall-clock jumps can alter
displayed receipt times but cannot accelerate collection.

Collection uses one bounded monotonic marker per record, keyed and ordered only
by `record_id`. A witness covers a candidate only when the candidate is the
witness itself, with the exact same revision ID and vector, or when the witness
vector strictly dominates the candidate vector. Equal-vector revisions with
different IDs do not cover one another and prevent collection.

A marker-advance transaction locks the record, its current marker, and new
revisions, then:

1. selects exactly one retained witness revision for the record and requires
   its `collection_witness_authenticator` to be non-null. A tombstone that is
   the sole undominated revision may witness itself; otherwise the witness is a
   retained resolution that the creating client explicitly authorized. The
   marker frontier equals the witness's own vector. That vector MUST strictly
   dominate every other candidate and retained revision for the record and,
   when replacing a marker, strictly dominate its existing frontier;
2. copies the witness revision ID, exact vector, and exact 32-byte non-null
   authenticator. It MUST NOT synthesize a component-wise join, change a
   counter, treat `null` as authorization, or substitute another revision's
   authenticator;
3. computes `barrier_cursor` as the greatest change cursor of every retained
   revision for that record, including a sibling or resolution accepted after
   the candidate;
4. requires every candidate selected for removal to have at least 90 days of
   durable retention age and every currently active device's durable
   `ack_cursor` to be at least `barrier_cursor`;
5. creates the marker when none exists, or replaces it only when the new exact
   witness vector strictly dominates the old marker frontier. An exact replay
   of the whole marker tuple is idempotent and consumes no new cursor;
   the old `witness_revision_id` with any changed vector, authenticator, or
   other tuple field and equal-vector/different-witness input are
   `revision_equivocation`, while a weaker or incomparable witness cannot
   authorize collection; and only then
6. removes every selected retention-eligible candidate covered by that
   witness—the self-witnessing sole tombstone itself or another revision the
   witness strictly dominates—in the same transaction.

A marker-unchanged physical-prune transaction does not select a retained
witness and remains possible after the original witness revision bytes were
deleted. It locks the same state, reuses the persisted exact non-null marker,
recomputes the barrier across every currently retained revision, applies the
same per-candidate age and active-device acknowledgement requirements, and
removes only now-eligible candidates that the marker already covers. The
marker tuple remains byte-identical and no marker change cursor is consumed.
An equal-vector revision with a different revision ID is not covered by this
path.

A later concurrent sibling therefore raises the barrier and also makes an
undominated tombstone ineligible until a retained resolution dominates both.
The barrier is recomputed rather than cached outside the collection
transaction. One transaction may remove multiple retention-eligible candidates
dominated by the same witness and changes the one marker at most once. A later
physical prune under the unchanged exact marker is not a new logical marker
transition. Delete/recreate/delete cycles therefore replace the same bounded
row with strictly advancing witness certificates rather than growing marker
storage. The server never combines witnesses, joins frontiers, treats a null
revision field as authorization, or treats `barrier_cursor` as authenticated
metadata.

The witness HMAC proves only that a VMK holder explicitly authorized that exact
revision ID and vector for possible collection use. It does not prove that the
server reported all revisions, selected the maximal witness, completed a
collection, or reported an honest `barrier_cursor`. A client recomputes and
constant-time verifies every non-null revision authenticator and every marker
HMAC before a marker can affect snapshot activation, durable causal context, a
`stale_after_collection` decision, or recovery. A null marker authenticator or
a missing, malformed, or mismatched non-null authenticator quarantines the
record and fails snapshot/recovery closed; it can never replace or weaken the
client's durable authenticated frontier checkpoint.

A later mutation must strictly dominate the persisted marker frontier or the
server rejects it with `stale_after_collection`; acknowledgement
followed by delayed stale upload cannot resurrect collected state. A surviving
client durably checkpoints the latest verified marker tuple and the complete
causal frontier from all authenticated revisions and markers per record.
Before accepting any marker, its verified frontier MUST equal or strictly
dominate that complete durable frontier and the one marker MUST individually
cover every still-retained sibling: it either names that sibling's exact
revision ID/vector/authenticator as its witness or strictly dominates that
sibling's vector. A marker that reuses a retained sibling's revision ID with a
changed vector or authenticator is equivocation and is rejected before
dominance comparison. Delta processing compares each incoming marker to the
latest persisted marker checkpoint before any dominance decision: the exact
whole tuple is a replay, the same prior `witness_revision_id` with any changed
frontier, authenticator, or other tuple field is equivocation, and only a
different witness ID with a strictly dominating frontier may replace it. A
missing, weaker, incomparable, aggregate-only, or equal-vector/different-witness
marker is rejected. For every prior marker checkpoint, a full snapshot applies
the same ordering and MUST contain that exact marker or a valid strictly
dominating replacement with a different `witness_revision_id`, even when its
cut cursor is newer. This comparison remains mandatory when the original
witness revision bytes have been pruned.
For every exact authenticated revision object still retained in the local
checkpoint, one same-record incoming item MUST independently prove continuity:
either the same `revision_id` reappears with every authenticated field, nonce,
and ciphertext byte unchanged, one authenticated incoming revision strictly
dominates its vector, or one verified incoming marker names it as the exact
witness with the same vector and authenticator or strictly dominates its
vector. Reuse of the same `revision_id` with any changed authenticated field,
nonce, or ciphertext is revision equivocation and fails activation even if its
changed vector would dominate. Likewise, a marker that names the same witness
revision ID with a changed vector or authenticator is equivocation and cannot
use the strict-domination branch. Equal-vector/different-ID revisions do not
cover one another, and vectors from multiple incoming items MUST NOT be joined
to cover one prior sibling. Independently, the aggregate
causal frontier formed from every authenticated snapshot revision and verified
snapshot marker for each record MUST equal or strictly dominate that record's
complete durable causal frontier, including causal evidence whose revision
bytes were already pruned. No marker is required for an ordinary record that
had no prior marker checkpoint when the snapshot revisions alone provide both
per-sibling continuity and aggregate coverage. A valid older revision
certificate or marker can therefore be replayed only as selective omission or
coherent full-state rollback, which a surviving checkpoint detects. A newly
enrolled device with no independent checkpoint cannot prove that a coherent
older complete view was not replayed; V1 does not claim otherwise. The exact
sequence is executable in
`protocol/v1/fixtures/tombstone-retirement.json`.

Retirement removes a device from future acknowledgement quorum but never
reuses its ID or erases its historical vector component. A returning retired
device must enroll with a fresh device ID. Its stale library is treated as an
explicit import and cannot resurrect deleted data automatically. With no
active devices, collection is frozen.

## 11. API operations — REVIEW-PENDING P1/P5/P6

`protocol/v1/openapi.json` is the machine-readable route and object contract.
The required operations are:

| Method and path | Authentication | Semantics |
| --- | --- | --- |
| `GET /v1/healthz` | none | Bounded liveness and protocol major only |
| `GET /v1/capabilities` | none | Instance/vault IDs, version range, capabilities and limits |
| `POST /v1/enrollments` | enrollment grant | Transactional, retry-safe device enrollment |
| `GET /v1/vault-envelope` | bearer, envelope read | Current envelope or `envelope_missing` |
| `PUT /v1/vault-envelope` | bearer, envelope write | Conditional generation replacement |
| `POST /v1/sync` | bearer, sync read/write | Atomic mutations/ack followed by one change page |
| `POST /v1/snapshot-reads` | bearer, sync read | Create an idempotent stable full-state cut |
| `POST /v1/snapshot-reads/{snapshot_id}/pages` | bearer, sync read | Read one stable sibling-complete snapshot page |
| `GET /v1/devices` | bearer, devices read | Active and retired device metadata budget |
| `POST /v1/devices/{device_id}/revoke` | bearer, devices manage | Durable revocation, optional zero-active confirmation, exact self-revocation receipt replay |
| `POST /v1/device-token-rotations` | bearer | Retry-safe token-hash replacement |

### 11.1 Delta requests and deterministic mutation order

The server applies all mutations and the prior durable acknowledgement in one
transaction, then reads the response page from the committed state. A request
either applies completely or not at all. Reusing a request ID with identical
authenticated device and body is idempotent; reuse with different bytes is
`request_id_reused`.

When an operation carries a request ID in both the required header and body,
the values MUST match. Enrollment IDs and token-rotation IDs are retained for
the life of their device so those state transitions remain retry-safe. Sync
request receipts are retained for at least 30 days and 10,000 requests per
device, whichever retains more. After a receipt ages out, record revision IDs,
author counters, envelope generations, and acknowledgements still make an exact
retry idempotent, but reuse of an expired request ID with unrelated bytes is no
longer a security claim. The retired-row self-revocation receipt in section 6.2
is a permanent endpoint-only exception to this generic aging policy.

The sync request carries `after_cursor`, `ack_cursor`, and sorted mutations.
The mutation array is strictly increasing by this exact key:
`(author_counter as uint64, record_id UUID bytes, revision_id UUID bytes)`.
Every normal sync mutation is authored by the authenticated device, so no
author-device tie breaker is needed. Duplicate keys or an out-of-order array
return `invalid_request` before the transaction; the server never sorts a
client write silently.

`ack_cursor` cannot exceed a cursor previously returned to that device.
Responses return changes in cursor order, `next_cursor`, `has_more`, and the
current server cursor. A client applies a page durably before requesting the
next page. A cursor older than retained history returns `cursor_expired` and a
full-snapshot requirement; it is never silently interpreted as an empty delta.

### 11.2 Stable full-snapshot recovery

After `cursor_expired`, or when no trusted local checkpoint exists, the client
uses the snapshot-read endpoints rather than guessing a new delta cursor.
Recovery-complete V1 snapshots require `snapshot-read-v1`,
`snapshot-collection-markers-v1`, `snapshot-device-registry-v1`, and
`authenticated-collection-frontiers-v2`. A server
emitting the required `collection_markers` or `source_devices` response member
and its corresponding advertised page limit MUST advertise the corresponding
capability; a client MUST require all four before creating a snapshot and
fails closed with `unsupported_capability` when any is absent. The snapshot
create body MUST declare `required_capabilities` as exactly this canonical,
UTF-8-byte-sorted array:

```json
[
  "authenticated-collection-frontiers-v2",
  "snapshot-collection-markers-v1",
  "snapshot-device-registry-v1",
  "snapshot-read-v1"
]
```

Before allocating a snapshot or retaining its idempotency result, the server
checks this declaration. A missing, incomplete, duplicate, additional, or
noncanonically ordered declaration returns HTTP 426 `unsupported_capability`;
it is not silently sorted or interpreted as the legacy `snapshot-read-v1`
shape.

`POST /v1/snapshot-reads` atomically chooses `cut_cursor = C`, captures the
exact envelope at C, and materializes the membership of every retained
undominated revision, every persistent collection marker, and the complete
device registry at C. Each source-device entry contains exactly `device_id` and
the registry's `max_author_counter`; credentials, scopes, status,
acknowledgements, and timestamps are excluded. Revisions include every live
and tombstone conflict sibling, never only the deterministic projection. A
marker remains in the cut even when no revision for its record remains,
because its frontier is the durable barrier against resurrection. A device
entry remains even when that device never authored a retained revision or
marker frontier, because its ID must never be reused after host recovery.
Creation is idempotent by authenticated device and request ID.

Snapshot allocation is bounded before any durable metadata is allocated or any
revision payload reference is retained. After authentication, request-shape and
capability validation, the server first looks up the device/request-ID
idempotency tuple. An exact retry returns the existing snapshot and unchanged
expiry without consuming rate or capacity. A mismatched retained request ID
returns `request_id_reused`. For a new unique request, the server then enforces
at most five unique create attempts per authenticated device in any rolling
60 seconds of daemon monotonic uptime. The sixth returns HTTP 429
`rate_limited`. Rate-admitted requests then enforce at most one active snapshot
per device, eight active snapshots per instance, and
`64 * 1024 * 1024 = 67108864` total bytes of active snapshot metadata per
instance. A count or metadata excess returns HTTP 413 `limit_exceeded`.
Unique attempts count toward the rate limit even when a later count or metadata
check rejects them; exact idempotent retries do not. Expired snapshots are
removed from active counts and metadata totals before these checks. Failure
does not persist a snapshot or cut, allocate snapshot metadata, retain a
revision payload reference, or change an existing lease.

Snapshot membership and page bytes remain fixed despite concurrent writes.
The stream has three phases: pages of at most 128 revisions strictly ordered
by `(record_id UUID bytes, revision_id UUID bytes)`, followed by pages of at
most 128 collection markers strictly ordered by `record_id UUID bytes`,
followed by pages of at most 64 source-device entries strictly ordered by
`device_id UUID bytes`. Because there is exactly one marker per record,
duplicate marker record IDs are invalid. Empty phases are skipped, and a page
never mixes phases; siblings, markers, or device entries may cross a page
boundary. Each opaque 32-byte page token is bound to snapshot ID, authenticated
device ID, cut cursor, phase, and the next ordering key. Replaying a page token
returns byte-equivalent JSON.
At creation the server copies the envelope, collection markers, projected
source-device entries, ordered membership keys, content addresses, and paging
metadata into immutable snapshot metadata for the lease, proposed as 15
minutes of daemon monotonic uptime. It does not duplicate the full revision
payload bytes per snapshot. Each revision membership entry retains a reference
to the server's existing immutable, content-addressed revision object; the
object is released only after its last live reference is removed and its last
snapshot reference expires.
The 64 MiB metadata cap counts every copied byte and reference/index/lease/token
record owned by active snapshots, but not the shared immutable revision payload
objects themselves. Before allocation, the server uses checked arithmetic over
the exact encoded lengths of the metadata representation it would persist; an
overflow is a metadata-limit excess. A reference may delay garbage collection
of an immutable object for the bounded lease, but the lease never pins or
blocks changes to live revision, marker, envelope, or device-registry rows.
Enrollment, revocation, token rotation, acknowledgement, collection, and sync
continue normally. Every page request authenticates the bearer against the
current live device registry before consulting the immutable snapshot. If the
snapshot owner has been revoked, paging returns HTTP 401 `token_revoked`
immediately; the lease neither delays revocation nor grants another device
access to the device-bound snapshot. `expires_at` is display metadata only.

The client stages pages under one snapshot ID and atomically replaces its sync
store only after all pages, the envelope, every AEAD value, every collection
marker witness HMAC, every unique source-device entry, and the final null page
token validate. It recomputes every non-null revision
`collection_witness_authenticator` and every marker authenticator with the
VMK-derived per-record key and compares in constant time; a null revision field
is valid but cannot authorize a marker, while a null marker field is invalid.
A marker's operational `barrier_cursor` MUST be at most C, but that cursor is
not authenticated and never changes causal acceptance. Every
`author_device_id`, revision-vector device ID, and marker-frontier device ID
MUST appear in `source_devices`, and each referenced counter MUST be at most
that entry's `max_author_counter`. Before activation, every prior marker
checkpoint MUST have an exact incoming marker or a valid strictly dominating
replacement with a different `witness_revision_id`. An incoming marker that
reuses the checkpoint's witness revision ID with any changed frontier,
authenticator, or other tuple field is equivocation and fails before dominance
comparison; missing, weaker, incomparable, or equal-vector/different-witness
input is rollback/fork evidence. Each exact authenticated prior sibling still
retained in the local checkpoint MUST also have one same-record continuity
witness: the same-ID revision with every authenticated field, nonce, and
ciphertext byte unchanged, one authenticated revision that strictly dominates
it, or one verified marker that exactly witnesses it or strictly dominates it.
A same-ID revision with any changed authenticated field, nonce, or ciphertext
is revision equivocation and fails activation before other witnesses are
considered. A marker that reuses that revision ID with a changed vector or
authenticator is the same kind of equivocation and cannot count as a strictly
dominating marker. Combining several incoming vectors to cover one prior
sibling is forbidden. Separately, for every locally checkpointed record, the
aggregate frontier from all authenticated incoming revisions and verified
incoming markers MUST equal or strictly dominate the complete durable causal
frontier. An ordinary record with no prior marker needs no marker when its
incoming revisions satisfy both individual sibling continuity and aggregate
coverage. The client retains every marker and source device separately; it
never drops or weakens a frontier because the corresponding revision bytes are
absent, and never infers that an absent device ID is reusable. It then calls
`/v1/sync` with `after_cursor = C` and may set
`ack_cursor = C` only after the complete snapshot is durable. The first delta
therefore returns every change at C+1 or later, including envelope changes.
`snapshot_expired` or `snapshot_not_found` requires discarding the entire
partial snapshot and starting a new cut; pages from different snapshot IDs are
never combined. The complete conflict, collection-marker, device-registry, and
delta transition are in
`protocol/v1/fixtures/full-snapshot-recovery.json`.

## 12. Error contract

Errors have one shape and contain no secret or raw parser detail:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "The request did not match protocol version 1.",
    "retryable": false,
    "request_id": "00000000-0000-4000-8000-000000000003"
  }
}
```

V1 stable codes include:

- `invalid_request`, `unsupported_protocol`, `unsupported_capability`;
- `unauthorized`, `token_revoked`, `scope_denied`,
  `authenticated_device_mismatch`, `rate_limited`;
- `grant_expired`, `grant_consumed`, `enrollment_replay_mismatch`;
- `request_id_reused`, `generation_conflict`, `generation_exhausted`,
  `counter_conflict`, `counter_exhausted`;
- `revision_equivocation`, `too_many_siblings`, `limit_exceeded`;
- `cursor_expired`, `snapshot_expired`, `snapshot_not_found`,
  `envelope_missing`, `device_not_found`, `zero_active_confirmation_required`;
- `instance_mismatch`;
- `stale_after_collection`, `server_cursor_exhausted`; and
- `internal_error`, which is retryable only when the server knows no partial
  transaction committed.

HTTP status mapping is fixed below and repeated as
`x-jat-error-status-map` in the OpenAPI document. Clients branch on `code`, not
localized `message`.

| HTTP | Codes |
| ---: | --- |
| 400 | `invalid_request` |
| 401 | `unauthorized`, `token_revoked` |
| 403 | `scope_denied`, `authenticated_device_mismatch` |
| 404 | `envelope_missing`, `device_not_found`, `snapshot_not_found` |
| 409 | `enrollment_replay_mismatch`, `request_id_reused`, `generation_conflict`, `generation_exhausted`, `counter_conflict`, `counter_exhausted`, `revision_equivocation`, `too_many_siblings`, `zero_active_confirmation_required`, `instance_mismatch`, `stale_after_collection` |
| 410 | `grant_expired`, `grant_consumed`, `cursor_expired`, `snapshot_expired` |
| 413 | `limit_exceeded` |
| 426 | `unsupported_protocol`, `unsupported_capability` |
| 429 | `rate_limited` |
| 500 | `internal_error` |
| 507 | `server_cursor_exhausted` |

The administration CLI uses `restore_incompatible`,
`backup_refused_rotation_in_progress`, and
`recovery_generation_exhausted`, and
`recovery_device_capacity_exhausted` as non-HTTP diagnostics. They are not
members of the OpenAPI error schema or `x-jat-error-status-map`.

## 13. Version negotiation and downgrade behavior

V1 advertises `protocol_min = "1"`, `protocol_max = "1"`, an exact storage
schema, exact crypto-suite identifiers, and a sorted capability set. The client
must find a common protocol major and every capability needed to interpret the
envelope and records before writing.

Unknown protocol majors return HTTP 426 and `unsupported_protocol`. Unknown
crypto suites, payload schemas, or required capabilities are preserved as
opaque data and block affected writes; they are never downgraded, deleted, or
guessed. A server upgrade must read the immediately previous storage schema and
perform a transactional migration. Rolling upgrade compatibility changes only
through an explicit advertised capability and fixture update.
`snapshot-collection-markers-v1` and `snapshot-device-registry-v1` are required
in addition to `snapshot-read-v1` for the recovery-complete snapshot shape;
reusing `snapshot-read-v1` alone for either required response member is
forbidden.

Protocol negotiation cannot prevent a malicious host from replaying an old but
previously valid complete view. A surviving client compares the server view to
its durable envelope generation, author counter, vector components, per-record
authenticated marker checkpoints, and change checkpoint and blocks rollback.
The HMAC proves marker tuple integrity, not completeness or maximality. A newly
recovered device with no external checkpoint cannot distinguish a coherent old
backup or valid older marker from the latest state.

## 14. Backup, restore, and lifecycle recovery — REVIEW-PENDING P6

### 14.1 Backup set

The administration CLI creates a consistent user-owned backup containing:

- ciphertext database and database schema version;
- instance ID, vault ID, and instance-secret generation;
- instance secret;
- loopback-only configuration;
- device token hashes/scopes/status and acknowledgement metadata; and
- a manifest with file sizes, SHA-256 checksums, and
  `secret_rotation_state = stable`, including the persistent collection-marker
  row count protected by the ciphertext-database checksum.

V1 does not serialize a partially completed instance-secret rotation. Backup
holds the rotation lock and refuses with `backup_refused_rotation_in_progress`
if a pending secret or an old recovery slot exists, checking both before and
after its database checkpoint. This fail-closed choice prevents an archive from
containing an envelope without the corresponding usable secret. Restore rejects
a manifest whose rotation state is absent or not `stable`.

The archive and manifest are mode `0600`. A backup is sensitive even though the
database is ciphertext-only: in base mode, database plus instance secret is
sufficient to unwrap the VMK. In passphrase mode it also enables offline
passphrase guessing.

Restore occurs into an isolated stopped instance. The CLI validates manifest,
checksums, regular-file ownership/modes, schema compatibility, and matching
instance/vault IDs before atomically replacing live state. V1 has one fixed
canonical manifest-path allowlist: exact ASCII `config.json`,
`instance-secret`, and `sync.db`, each exactly once. Before extracting any
archive member, restore rejects every other spelling or path, including case
aliases, duplicate allowlisted paths with different metadata, missing paths,
and unlisted archive members as `restore_incompatible`. It never delegates
path identity to destination-filesystem case or Unicode semantics. The CLI
also compares the manifest collection-marker count with the marker rows loaded
from the checked database and refuses any mismatch; restore never rebuilds or
discards marker frontiers. A partial or mixed backup fails closed. The old
instance remains recoverable until the restored service passes a loopback
health check.

### 14.2 Recovery matrix

| Loss or compromise | Base mode | Passphrase mode |
| --- | --- | --- |
| Database only disclosed | No plaintext without instance secret | No plaintext without instance secret and passphrase guess |
| Full host compromised | Host can unwrap VMK by design | Host must guess passphrase offline; weak passphrases remain weak |
| One device lost | Revoke token; other device/SSH recovery continues | Same; revocation does not erase the lost device |
| Host lost, device survives | Identity-preserving recovery from a completed sibling-full snapshot; same IDs/VMK, new instance secret and envelope | Same; the surviving VMK permits rewrap under the selected passphrase |
| Instance secret lost, device survives | Rotate to a new instance secret and rewrap VMK | Same with passphrase material |
| Passphrase lost, device survives | Not applicable | Locally authorize and rewrap under a new passphrase |
| All devices lost, host survives | Enroll through verified SSH; host secret plus envelope recovers VMK | Also requires the passphrase |
| All devices and passphrase lost | Host secret suffices in base mode | Intentionally unrecoverable |
| Host, all devices, and complete backup lost | Intentionally unrecoverable | Intentionally unrecoverable |
| Secure Enclave device lost | Private key is lost; replace/reauthorize identity | Same |

The intentional unrecoverability statements require Tom's explicit approval.
No support flow, server administrator, or backup can reconstruct a Secure
Enclave private key.

### 14.3 Host-loss recovery with a surviving device

V1 uses identity-preserving recovery because record keys and associated data
authenticate `instance_id` and `vault_id`. The precondition is a surviving
client that holds the VMK and a durably completed snapshot at source cut C,
including every undominated live/tombstone sibling and its exact revision ID,
vector, collection witness authenticator, nonce, and ciphertext, plus the single
persistent collection marker for each applicable record and its exact witness
revision ID, frontier, collection witness authenticator, and barrier cursor, plus every
source device ID and its exact maximum author counter. Before producing an
import, the surviving client verifies every revision AEAD, every non-null
revision collection-witness authenticator, and every marker witness
authenticator with the VMK. A local
store containing only the deterministic projection, omitting a marker, or
inferring its device registry only from retained vectors/frontiers is
insufficient and the recovery command MUST refuse it.

Through a newly verified SSH connection, the user runs an administrative
`recovery begin` command naming the old instance ID, old vault ID, source cut C,
and a strict recovery manifest with the source envelope generation, source
instance-secret generation, separate revision, collection-marker,
source-device, and page counts, plus a SHA-256 digest. The two source
generations are independent: passphrase rewrap can advance the envelope
generation without rotating the instance secret. The digest covers each exact
raw UTF-8 `recovery import-page` request-body byte sequence, in page order,
preceded by its unsigned 64-bit big-endian byte length. The server hashes the
received bytes before JSON parsing and never parses then reserializes,
reorders keys, normalizes whitespace, or otherwise canonicalizes them for the
digest. Semantically equivalent JSON with different bytes therefore has a
different digest and is not an idempotent page replay.

Before creating staging, the server uses checked unsigned arithmetic to
require both source generations to be less than `UInt64.max`. It computes the
destination envelope and instance-secret generations as their respective
checked successors. If either successor is unavailable, recovery fails with
`recovery_generation_exhausted` and creates no recovery state. The server also
requires the manifest's `source_device_count <= 63`, reserving one of the fixed
64 active-plus-retired registry slots for the mandatory fresh device without
performing an overflow-prone addition. A complete source registry of 64 fails
with
`recovery_device_capacity_exhausted` before any staging state is created. The
server separately reserves one change cursor for that enrollment and requires
`C + revision_count + collection_marker_count + 1 <= UInt64.max`; overflow
fails with `server_cursor_exhausted` and creates no recovery state.
Finalization repeats the generation, device-capacity, and cursor-capacity
checks against the verified manifest and exact imported unique counts.

The new server creates an inert staging instance with those same IDs, a fresh
instance secret at `source_instance_secret_generation + 1`, and a random
recovery ID. The client rewraps the same VMK in a new envelope at
`source_envelope_generation + 1`, naming that new instance-secret generation.
It streams JSON pages through verified SSH standard input to
`recovery import-page`. Revision pages come first and are strictly ordered by
`(record_id UUID bytes, revision_id UUID bytes)`; collection-marker pages
follow and are strictly ordered by unique `record_id UUID bytes`; source-device
pages come last and are strictly ordered by `device_id UUID bytes`. Pages are
idempotent only when the page index and exact raw request-body bytes match.
`recovery finalize`
checks the manifest, exact checked envelope and instance-secret successors,
phase and page order, all three counts, digest, vector and frontier
canonicality, one-marker-per-record and revision/device uniqueness, every marker
`barrier_cursor <= C`, every referenced author/vector/frontier device's
presence in the source registry, every referenced counter against that
registry entry's exact `max_author_counter`, the reserved fresh-device slot,
and an otherwise empty staging instance, then activates all state in one
transaction. Conflicting duplicate markers or source-device entries fail
closed rather than joining, replacing, or weakening state. Interrupted or
invalid staging is inert and can only be resumed with the same recovery ID or
discarded. The server cannot derive the VMK and therefore enforces only
canonical shape, ordering, uniqueness, counter bounds, and opaque-byte
preservation; it does not claim to cryptographically verify a revision or
marker authenticator.

Because the instance/vault IDs and VMK are preserved, every imported record
ciphertext, record/revision ID, version vector, author counter, and tombstone
flag is byte-identical. Every collection marker, including its witness
revision ID, frontier, collection witness authenticator, and source barrier
cursor, is also preserved exactly.
Every imported source device ID is created as retired with the exact maximum
counter from the authoritative source-device registry entry, including a
never-authored ID absent from all imported vectors and frontiers, and it is
never reused. Source token hashes, scopes, status, acknowledgements, and
timestamps are not copied. The recovering client enrolls afterward with a
fresh device ID and token. Retained-tombstone retention ages restart at zero;
collection markers are not retention candidates and remain persistent.

The destination change cursor is initialized to floor C. Imported retained
revisions and collection markers receive new cursors C+1 onward in the same
deterministic phase and item order; source change cursors are not copied because
cursors are server transport state. The preserved marker `barrier_cursor` is
historical source metadata, while its frontier is the active mutation barrier.
The staged envelope and reconstructed retired-device rows are activation
baseline, not post-activation changes, and receive no change cursors. This is a
narrow recovery-only exception; the mandatory fresh enrollment remains a
normal cursor-bearing device-state change. Let R be C when the import has no
items and otherwise the final imported-item cursor; enrollment receives the
reserved cursor R+1.
Before the staging transaction becomes visible, every later mutation for that
record must dominate its imported marker frontier or fail with
`stale_after_collection`. Collection stays frozen until the new device has
read back and re-verified every imported revision AEAD and frontier
authenticator and every marker authenticator, then acknowledged R; only then is
recovery complete and the source may be abandoned. Delta sync starts with
`after_cursor = R`. This preserves the surviving
rollback checkpoint and tombstone barriers without pretending that old
cursor-to-item assignments survived. The executable state description is
`protocol/v1/fixtures/host-loss-recovery.json`.

Creating different instance or vault IDs is not this recovery operation: every
live sibling and tombstone would have to be decrypted, validated, and
re-encrypted with new record keys and associated data while explicitly mapping
vectors and rebuilding cursors. V1 defines no lossy shortcut and refuses such a
request. If the abandoned host returns, it is a separate fork; clients MUST NOT
sync both histories, and old host tokens are not accepted by the recovered
instance.

### 14.4 Instance-secret rotation

The proposed crash-safe rotation is two phase:

1. Through verified SSH, the CLI checks that both
   `instance_secret_generation` has a successor and the required envelope
   replacement has cursor capacity. It then creates a pending random secret at
   exactly `active_generation + 1`, preserving the active secret.
2. The client receives the pending secret through that SSH channel, derives a
   new wrapping key, and conditionally stores a new VMK envelope naming the
   pending generation.
3. The client asks the CLI/API to commit the pending generation. The host
   atomically promotes the pending secret only after observing the matching
   envelope; it retains the old secret in a recovery slot until health and
   envelope retrieval succeed.
4. Interruption before envelope replacement discards only the pending secret.
   Interruption after replacement resumes promotion; it never loses both
   secrets. Final cleanup securely removes the recovery slot to the extent the
   filesystem supports deletion.

If no enrolled device holds the VMK, instance-secret rotation is impossible;
replacing the secret alone would destroy recovery.

Ordinary envelope replacement and instance-secret rotation use checked
successor arithmetic. If the current envelope generation or active
instance-secret generation is `UInt64.max`, the server returns non-retryable
HTTP 409 `generation_exhausted` (and the verified-SSH CLI prints the same stable
code) before generating ciphertext, creating a pending secret, advancing a
generation, consuming a cursor, or changing any active/recovery state. This is
distinct from the offline host-recovery diagnostic
`recovery_generation_exhausted`. Generation exhaustion takes precedence over
cursor exhaustion; when a successor exists but its required envelope commit
does not have cursor capacity, the operation instead fails with
`server_cursor_exhausted`.

## 15. Server-visible metadata budget

The honest server may persist only:

- instance/vault IDs and protocol, storage, and capability versions;
- random device IDs, token/grant hashes and scopes, status, created/revoked/
  last-sync times, acknowledgements, and maximum counters;
- random record/revision IDs, author device/counter, version vectors,
  tombstone state, nonce, exact opaque authenticated ciphertext bytes,
  nullable collection-witness authenticator bytes, ciphertext length, receipt
  time, change cursor, retention age, and immutable content addresses;
- persistent collection-marker tuples (record and witness revision IDs, exact
  frontier, exact non-null witness authenticator, and barrier cursor), plus
  snapshot IDs, cuts, leases, page tokens/order keys, and immutable revision
  content-address references required to serve a stable snapshot;
- idempotency receipt device/request IDs, raw authenticated-body fingerprints,
  recorded response bytes, and retention-expiry state;
- envelope version, mode, KDF parameters/salts, nonce, wrapped bytes, and
  generation numbers; and
- bounded operational health, error, and rate-limit counters.

Record ciphertext and collection-witness bytes are opaque stored values. The
server neither decrypts nor parses them, and a client verifies their AEAD/HMAC
authentication before using them. The allowlist permits retaining the exact
bytes and the server state necessary to return immutable revisions and stable
snapshots; it does not permit retaining plaintext or private-key material.

It MUST NOT persist plaintext host aliases, usernames, addresses, ports,
snippets, commands, known-host keys/patterns, identity labels, private keys,
passphrases, VMKs, device labels, local file paths, or application settings.

SSH and operating-system logs remain outside the service and can reveal the
selected Unix account, connection source, and timing. The threat model states
that limitation rather than claiming traffic anonymity.

## 16. Conformance evidence and review exit

Before this draft becomes approved:

1. Tom must approve P1–P6 and the threat guarantees in
   `docs/THREAT-MODEL.md`.
2. `crypto-review-vectors.json` must replace its shape-only outputs with
   reviewed known-answer values for both modes, record encryption, wrong
   passphrase, tampered associated data, and passphrase rewrap.
3. Independent Swift and Go implementations must consume the same immutable
   fixtures and agree byte-for-byte.
4. Wire fixtures must demonstrate enrollment retry, self-only token rotation,
   deterministic mutation order, sibling-complete snapshot pagination and delta
   transition, per-prior-sibling snapshot continuity without aggregate-vector
   substitution, marker- and device-registry-capability negotiation, bounded
   snapshot allocation with fail-before-retain behavior, conflict retention,
   later-sibling tombstone barriers, identity-preserving host recovery with
   independent generation successors, raw-body digest sensitivity, complete
   source-device reconstruction, and reserved enrollment device/cursor
   capacity, last-device retirement, rotation-safe backup refusal, fixed
   canonical-path restore rejection, restore mismatch, and version downgrade
   rejection.
5. Policy checks must confirm that the server has no vault-crypto or private-key
   parser and that all implementation inputs satisfy the permissive-license
   allowlist.
6. Boundary tests must accept `18446744073709551615`, reject
   `18446744073709551616` before any cursor/counter arithmetic, reject ordinary
   envelope and instance-secret successor attempts at `UInt64.max` with
   `generation_exhausted` and no mutation, and reject a recovery source
   generation at `UInt64.max` before attempting its successor.
7. The coordinator records the reviewed exact commits and evidence before task
   2.0 is acknowledged. Until then task 2.1 and cryptographic implementation
   remain downstream work.
