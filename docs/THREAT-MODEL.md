# Sync threat model

Status: **task 2.0 review draft — Tom review required**

This document analyzes the proposed V1 contract in
[`SYNC-PROTOCOL.md`](../SYNC-PROTOCOL.md). Locked product boundaries are
distinguished from review-pending protocol and cryptographic choices. It does
not claim that the proposed crypto profile has been approved or implemented.

## 1. Assets

The protected assets are:

- software-backed SSH private keys;
- host addresses, usernames, jump topology, notes, and forward profiles;
- snippets and commands;
- known-host keys and host patterns;
- the vault master key (VMK), recovery passphrase, instance secret, enrollment
  grants, and device tokens;
- device-local Secure Enclave private keys and Keychain cleanup authority; and
- integrity and availability of synchronized records, conflicts, and deletions.

Ciphertext length, record/device counts, random identifiers, version-vector
activity, tombstone state, receipt time, SSH source/account metadata, and
service availability are not hidden completely.

## 2. Trust boundaries

### 2.1 Trusted components

- The user and a non-compromised enrolled iOS/iPadOS client are trusted with
  vault plaintext and the VMK.
- The local operating system, Secure Enclave, Keychain access group, app binary,
  and random-number generators are trusted within their documented boundaries.
- The SSH client must authenticate the selected sync host before bootstrap or
  forwarding. Accepting an unverified or changed host key crosses the trust
  boundary and is never automatic.
- In base mode, the selected host and its administrators are trusted for vault
  confidentiality because the host stores the instance secret.

### 2.2 Conditionally trusted component

In optional passphrase mode, the selected host remains trusted for availability
and freshness but is not trusted with the passphrase or VMK. A host compromise
can copy the instance secret, envelope, salts, Argon2id parameters, and all
ciphertext and can perform offline guesses. The guarantee therefore depends on
passphrase strength and the reviewed KDF parameters; it is not an absolute
claim against guessing.

### 2.3 Untrusted components and actors

- network observers or active attackers outside the verified SSH connection;
- ordinary SSH target hosts, which run no JAT service;
- a database-only thief;
- a stolen device token without the device's VMK;
- malformed, stale, replayed, or swapped server data; and
- retired devices attempting to reconnect with revoked credentials.

A compromised enrolled device that holds the VMK is outside the
confidentiality boundary. It can read vault data and create cryptographically
valid writes until its token is revoked. Revocation prevents future server use
but cannot erase data or keys already present on that device.

## 3. Security goals

### Locked goals

1. Server database records contain no plaintext application records or usable
   private keys.
2. Software private keys reach the server only as authenticated ciphertext.
3. A Secure Enclave private key never syncs or exports.
4. The service never parses a private key and performs no vault cryptography.
5. Bootstrap and enrollment require a verified SSH relationship; normal V1
   transport remains loopback-only through an SSH forward.
6. Ordinary SSH destinations remain agentless.
7. Concurrent edits and deletes are retained rather than silently lost.
8. Remote sync data cannot directly authorize deletion of local Keychain or
   Secure Enclave material.

### Review-pending goals

1. XChaCha20-Poly1305 detects record modification, swapping between IDs,
   visible-metadata modification, and wrong-key/wrong-passphrase use; the
   independently domain-separated per-record HMAC authenticates exact
   revision/witness frontiers after revision ciphertext is collected.
2. Passphrase mode prevents host-only VMK unwrapping except through offline
   guessing.
3. Per-device bearer credentials provide independently revocable server
   access without storing token plaintext server-side.
4. Durable client checkpoints, including the complete per-record causal
   frontier from every authenticated revision and marker plus the latest
   authenticated monotonic marker tuple, detect rollback relative to state
   that device has previously observed.
5. Retention and acknowledgement rules prevent an honest server from collecting
   a deletion before every active device has durably observed it.
6. Stable full snapshots return every undominated sibling, the single
   persistent authenticated witness marker per applicable record, and every
   source device ID with its exact maximum author counter at one cut, then move
   to deltas without a pagination gap, resurrection window, or reusable
   retired identity.

These goals become claims only after Tom approves the exact construction and
the Swift and Go conformance suites pass reviewed vectors.

## 4. Explicit non-goals

V1 does not protect against:

- plaintext extraction from a fully compromised enrolled client;
- cryptographically valid malicious writes from a device that holds the VMK;
- denial of service, selective omission, or permanent data destruction by a
  malicious host without an independent backup;
- offline passphrase guessing after full host or complete-backup disclosure;
- disclosure of the metadata budget listed in the protocol;
- a user explicitly trusting an attacker's SSH host key;
- coherent rollback, including a valid older marker certificate, presented to a
  newly recovered device that has no surviving checkpoint;
- secure remote erasure of a lost device;
- filesystem guarantees stronger than the host operating system provides; or
- reconstruction of any Secure Enclave private key.

## 5. Threat and recovery matrix

| Threat/event | Detection or guarantee | Required response / residual risk |
| --- | --- | --- |
| Database-only disclosure | Database lacks instance secret and plaintext; record and VMK envelope remain ciphertext | Rotate device tokens if token hashes or metadata are exposed. Base-mode plaintext still requires the separately stored instance secret. |
| Full host compromise, base mode | No confidentiality guarantee: attacker has instance secret and envelope | Restore a known-good host, rotate instance secret and tokens, and treat vault plaintext as compromised. |
| Full host compromise, passphrase mode | Instance secret and envelope do not directly reveal VMK | Attacker can guess passphrase offline. Restore, rotate host secret/tokens, and rewrap under a strong passphrase. |
| Network attacker | SSH authenticates/encrypts bootstrap and forwarded API | A host-key warning is blocking. If the user accepted a wrong key, treat grants, instance secret, tokens, and records as exposed/tampered. |
| Compromised ordinary SSH target | It has no sync service or instance secret | It cannot impersonate the selected sync host unless host verification is bypassed or its key is wrongly trusted. |
| Stolen device token only | Token can read/write opaque server data but cannot unwrap VMK | Revoke promptly. Ciphertext/metadata disclosure and denial of service remain possible until revocation. |
| Stolen enrolled device | Device may hold token, VMK, plaintext, and software keys | Revoke token. Revocation is not remote erasure; rotate/re-encrypt the vault in a future reviewed flow if continuing secrecy is needed. |
| Revoked device reconnects | Server rejects token before read/write transaction | Returning local edits require explicit import under a fresh device ID; no implicit resurrection. |
| Modified ciphertext/tag | AEAD validation fails | Quarantine exact opaque revision; keep good siblings and do not apply local or Keychain mutations. |
| Record swapping | Record/revision/vault IDs are authenticated as associated data | Reject and quarantine. |
| Visible vector/frontier/tombstone/authorization alteration | Revision vectors, tombstone fields, and the null/non-null collection-witness authorization kind and bytes are bound by AEAD associated data; a non-null authorization is additionally a VMK-derived per-record witness HMAC that can survive as the marker certificate | Reject empty, duplicate, out-of-order, zero-valued, author-mismatched, noncanonical, or HMAC/AEAD-invalid input before comparison or local activation. Initial and non-dominating live revisions carry null and cannot authorize collection. The HMAC proves explicit authorization and tuple integrity, not server completeness or maximality; server-owned cursor/time remain non-authoritative. |
| Replay of an older individual revision | Durable vectors/counters retain newer siblings | Ignore dominated replay and record diagnostic evidence. |
| Selective or coherent valid-certificate rollback | Surviving device retains the complete durable causal frontier from all authenticated revisions and markers, plus the latest marker tuple and change checkpoint | Before accepting a marker, require its verified frontier to cover the full causal checkpoint; reject a valid but older revision/marker certificate, missing marker, weaker/incomparable frontier, or equal-vector/different-witness tuple. Acknowledgement alone never discards the evidence. A fresh device with no checkpoint cannot prove freshness. |
| Server equivocation/fork | Different clients can receive different valid histories | V1 has no transparency log. It can detect contradictions when histories meet but cannot guarantee timely fork detection. |
| Version-vector inflation by host | Host cannot forge valid record AD | Reject altered records. It can omit data or deny service. |
| Version-vector inflation by enrolled malicious device | Device with VMK can create valid data; server enforces sequential author counters | Limit prevents large jumps but not deliberate valid churn. Revoke device; availability impact remains. |
| Concurrent edit/edit | Vectors incomparable | Retain both; deterministic projection is not deletion. User resolution dominates both. |
| Concurrent edit/delete | Vectors incomparable | Retain live and tombstone siblings; never silently delete the edit or local key. |
| Later sibling after tombstone acknowledgement | Per-record collection barrier is recomputed while the record and its one monotonic marker are locked; a marker-advance witness must carry explicit non-null authorization and strictly dominate every other current revision and the old marker | Raise the barrier; unresolved siblings and null-authorized live revisions remain ineligible. Copy the witness ID/vector/HMAC exactly, never synthesize a join, and reject later writes that do not dominate the persisted marker frontier. A later-aged candidate already covered by an unchanged marker may be physically pruned after the original witness bytes are gone, but only under the same recomputed barrier, age, and acknowledgement checks. |
| Host loss after collection | The surviving completed snapshot contains the single authenticated witness marker for every applicable record, even when no revision for that record remains | Surviving client verifies AEAD/HMAC before import; server preserves opaque bytes and structural invariants; recovering client re-verifies after activation. A stale write that does not dominate the imported marker fails with `stale_after_collection`; recovery never resets the barrier. |
| Remote identity tombstone | Has no device-local custody generation or cleanup authority | Unlink shared record, preserve local key as orphan, require explicit local exact-generation cleanup. |
| Lost one device | Other device or verified SSH path survives | Revoke token. Secure Enclave key on lost device is unrecoverable and must be replaced. |
| Lost host, surviving device | Surviving client has VMK and a completed snapshot containing every sibling/tombstone/vector/nullable authorization, both source generations, each non-null monotonic marker witness tuple, and the complete source device registry at cut C | Verify AEAD, every non-null revision authorization, and every marker HMAC client-side; preserve instance/vault IDs, take checked independent successors, rewrap the same VMK, atomically import exact opaque revisions/markers/device IDs, rebuild cursor floor C while reserving enrollment, re-verify from the activated destination, and never sync the abandoned fork. Projection-only, marker-incomplete, inferred-registry, capacity-exhausted, or cryptographically invalid recovery fails closed. |
| Lost instance secret, surviving device | Client still holds VMK | Create a new secret and conditionally rewrap. Never replace secret without a device-held VMK. |
| Lost passphrase, surviving device | Device already holds VMK | After local authorization, set a new passphrase envelope. This proposed recovery requires Tom approval. |
| Lost all devices, base mode | Host secret plus envelope can unwrap VMK | Enroll through verified SSH. Software identities recover; Secure Enclave private keys do not. |
| Lost all devices, passphrase mode | Host alone cannot unwrap VMK | Enroll through SSH and supply passphrase. Losing passphrase too is intentionally unrecoverable. |
| Partial or path-aliased backup/restore | Manifest, checksum, schema, IDs, file-mode, fixed canonical path allowlist, and persistent collection-marker count validation fail before extraction | Keep old instance untouched; restore only into isolation. Require exact ASCII `config.json`, `instance-secret`, and `sync.db` once each, reject case aliases and unlisted archive members, and never reconstruct or omit marker frontiers. |
| Backup during instance-secret rotation | Pending or recovery secret slot makes the transition unstable | V1 refuses backup until rotation returns to `stable`; it never emits a partial transition archive. |
| Database and secret from different instances | Instance/vault/generation mismatch | Fail closed with `instance_mismatch`; never try alternate derivations. |
| Clock skew | Grants use a boot-bound monotonic deadline; collection age accrues only from durably checkpointed positive daemon monotonic uptime | Wall clocks are display metadata. Restart downtime and clock jumps can delay collection but cannot accelerate it or select a value. |
| Interrupted enrollment | Grant consumption and device creation are one transaction; enrollment and device IDs are unique; replacement-grant recovery performs an exact-tuple lookup before insert | Retry the retained tuple with the original grant, or obtain a replacement through verified SSH after expiry. The server either creates the one missing device or returns the recorded result without repeating enrollment state; any retained-ID mismatch fails without consuming the replacement grant. |
| Interrupted passphrase rewrap | Envelope generation CAS leaves one committed envelope | Reload winner; records are unchanged. |
| Interrupted secret rotation | Active and pending generations remain recoverable until envelope and secret agree | Resume or discard pending state according to two-phase state machine. |
| Snapshot expires mid-page | Snapshot ID/token is missing or lease expires | Discard all staged pages and begin a fresh cut; never combine snapshots or fall back to an empty delta. |
| Snapshot-create storage exhaustion | A unique request is rate-limited to five attempts per rolling minute per device, with one active snapshot per device, eight per instance, and 64 MiB total active snapshot metadata | Return `rate_limited` or `limit_exceeded` before persisting a snapshot/cut, allocating metadata, or retaining a revision reference. Exact retries return the existing lease without consuming capacity. Snapshot membership uses content-addressed references to existing immutable revision payloads rather than full-vault copies. |
| Snapshot holder attempts to delay revocation | Copied snapshot metadata and retained content-addressed revision references never lock live registry rows; each page reauthenticates current device state | Commit revocation immediately and return `token_revoked` on every later page request by that owner. |
| Lost self-revocation response | Retired row retains the exact request ID, authenticated raw-body fingerprint, pre-revocation token hash, and byte-equivalent 200 response | On the revoke endpoint only, the same revoked bearer may retrieve that exact receipt when target, header ID, body ID, and raw body all match. Any mismatch returns indistinguishable `token_revoked`; beyond the constant-time retired-receipt row lookup, replay grants no general device/vault/ciphertext read, mutation, scope, cursor, lease, timing refresh, or authority elsewhere. |
| Incompatible protocol/crypto version | Negotiation lacks draft2 or the snapshot caller does not declare the exact canonical quartet `authenticated-collection-frontiers-v2`, `snapshot-collection-markers-v1`, `snapshot-device-registry-v1`, and `snapshot-read-v1` | Preserve opaque data and block affected writes; reject snapshot creation with `unsupported_capability` before allocation; never treat draft1 and draft2 as the same suite or downgrade/reset. |

## 6. Mode guarantees

### 6.1 Base trusted-host mode

Database-only disclosure does not disclose plaintext because the instance
secret is a separate file. A complete host backup or full host compromise does
include that secret and can unwrap the VMK. “Client-side encrypted” therefore
describes the honest server implementation and database representation; it
does not mean the selected host is outside the base-mode trust boundary.

### 6.2 Optional passphrase-protected mode

The passphrase is entered and processed only by the client. It is never sent to
the server or stored in the envelope. Full host compromise obtains everything
needed for an offline Argon2id attack except the passphrase itself. Security is
bounded by the user's passphrase entropy and the reviewed parameters. Server
rate limits do not mitigate an offline attacker.

Changing the passphrase rewraps the VMK and cannot revoke a compromised device
that already has the VMK. Likewise, switching from passphrase mode to base mode
is an explicit confidentiality downgrade and must receive an owner-approved UI
warning before implementation.

## 7. Key-custody boundary

### 7.1 Software-backed identities

The client may read exportable private material only through a separately
reviewed local authorization path, encrypt it directly into a vault record, and
restore it directly into device-only Keychain storage. No plaintext temporary
file, sync log, JSON library field, or crash report is allowed. Before any
persistent import, the client strictly validates the protocol's kind-bound
canonical Ed25519/RSA private and public encodings, derives the public key from
the private key, and requires an exact match. An empty, malformed,
non-canonical, wrong-kind, or mismatched pair is rejected as an invalid
decrypted record without a Keychain or local-custody mutation. The encoding
contract, export/import implementation, local authorization, and Keychain
access policy remain review-pending.

### 7.2 Secure Enclave identities

Only public key, fingerprint, origin device, and non-secret descriptive data
sync. Before persistence, clients require the canonical 65-byte uncompressed
P-256 X9.63 point, strict curve parse and byte-identical re-encoding, and an
exact recomputed OpenSSH fingerprint. Empty, compressed, DER/SPKI,
wrong-length, wrong-prefix, off-curve, non-canonical, and fingerprint-mismatched
values are rejected before local state or custody changes. Other devices
display an unavailable placeholder and must not imply the private key was
backed up. Device loss means replacement and remote reauthorization, not key
recovery. This validation and the local custody boundary remain Tom-review
gates.

### 7.3 Deletion authority

The existing local custody design binds destructive cleanup to an exact local
identity generation and durable recovery transaction. That generation is
intentionally excluded from sync. Consequently no server record, device token,
remote tombstone, version vector, or encrypted payload can directly authorize
Keychain cleanup. This separation also limits damage from a compromised
enrolled device that creates a valid identity tombstone.

## 8. Backup implications

A ciphertext database alone is weaker recovery material than a complete
backup. A complete backup includes token hashes and the instance secret and is
therefore highly sensitive:

- in base mode it can unlock the VMK envelope;
- in passphrase mode it permits unlimited offline guesses; and
- in both modes it can reveal the complete server-visible metadata history.

Backups need host filesystem protection and user-controlled off-host handling.
The V1 server does not add a second server-side encryption password because
that would create another unreviewed recovery system. Users wanting an
additional backup envelope need a future explicit design.

V1 also refuses to create a backup while a pending instance secret or old
recovery slot exists. The stable manifest records that fact. Serializing only
one side of the transition could pair an envelope with an unusable secret and
turn an apparently complete archive into destructive recovery material.
The manifest also records the persistent collection-marker row count covered
by the database checksum. Restore compares the checked database with that
count before activation and never treats missing marker rows as collectable
history; otherwise a stale client could resurrect a record after host restore.
Before extraction, restore also requires exactly the fixed V1 canonical path
allowlist (`config.json`, `instance-secret`, and `sync.db`) and rejects case
aliases, duplicates, missing paths, or extra archive members. This avoids
depending on whether the destination filesystem is case-sensitive or how it
canonicalizes names.

## 9. Operational controls

The implementation must eventually demonstrate:

- loopback-only IPv4/IPv6 listeners and startup rejection of wildcard binds;
- mode `0600` instance secret, config, database, and backup artifacts;
- bounded HTTP parsing, request bodies, pages, sibling counts, and rate limits;
- stable snapshot cuts, replayable phase-bound page tokens, sibling- and
  collection-marker-complete pagination, complete source-device registry
  projection copied independently of live rows, content-addressed immutable
  revision references, bounded active metadata/allocation rate, live-state
  authentication on every page, expiry discard, and exact cut-to-delta
  transition;
- constant-time grant/token-hash comparison;
- structured log redaction tests covering every credential and ciphertext
  field;
- transactional enrollment, token rotation/revocation, sync, envelope CAS,
  backup checkpoint, and restore replacement;
- atomic identity-preserving host-recovery import with independent checked
  generation successors, cursor-floor and reserved-enrollment cursor/device
  capacity, authoritative complete source-device reconstruction, revision
  vector/AEAD and nullable witness-authorization verification, monotonic
  one-marker-per-record non-null witness HMAC,
  pre-import and post-activation client verification, and
  stale-after-collection tests;
- crash/restart tests at each durable state-machine boundary; and
- no server vault-crypto dependency or private-key parser.

## 10. Tom review checklist

Tom's recorded review must explicitly accept or revise:

1. HTTP/1.1 JSON over SSH-forwarded loopback and the listener/limit profile.
2. Random sizes, token/grant hashing, client-generated token model, scopes,
   rotation, and last-device rules.
3. HKDF construction, domain labels, envelope and draft2 record associated
   data, independent collection-witness key/HMAC, XChaCha20-Poly1305 usage,
   nonce requirements, marker-checkpoint rollback behavior, and known-answer
   vectors.
4. Argon2id version `0x13` (19), parameters, device calibration floor, NFC handling, passphrase
   reset with a surviving device, and the warning for disabling passphrase
   mode.
5. VMK/token Keychain policy and software-private-key export/import encoding.
6. Metadata budget, logging, rate limits, conflict projection, 90-day
   tombstone retention, retirement quorum, and zero-device freeze.
7. Remote identity tombstone quarantine and the rule that only explicit local
   exact-generation actions may delete protected keys.
8. Base/passphrase compromise wording, rollback limitation, recovery matrix,
   and intentional unrecoverability cases.
9. Stable full-snapshot pagination, the bounded monotonic authenticated witness
   marker per record, draft2 marker/device-registry capability negotiation, and
   identity-preserving host-loss recovery including independent generation
   successors, complete source-device reconstruction, reserved enrollment
   cursor/device capacity, and stale-after-collection reconstruction.

Until those answers and exact conformance results are recorded, this threat
model is a review artifact rather than a completed security claim.
