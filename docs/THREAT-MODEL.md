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
   visible-metadata modification, and wrong-key/wrong-passphrase use.
2. Passphrase mode prevents host-only VMK unwrapping except through offline
   guessing.
3. Per-device bearer credentials provide independently revocable server
   access without storing token plaintext server-side.
4. Durable client checkpoints detect rollback relative to state that device has
   previously observed.
5. Retention and acknowledgement rules prevent an honest server from collecting
   a deletion before every active device has durably observed it.
6. Stable full snapshots return every undominated sibling at one cut and move
   to deltas without a pagination gap.

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
- coherent rollback presented to a newly recovered device that has no surviving
  checkpoint;
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
| Visible vector/tombstone alteration | Vector and tombstone fields are authenticated as associated data | Reject and quarantine; server-owned cursor/time remain non-authoritative. |
| Replay of an older individual revision | Durable vectors/counters retain newer siblings | Ignore dominated replay and record diagnostic evidence. |
| Coherent full-state rollback | Surviving device compares durable envelope generation, author counter, vectors, and checkpoint | Block sync and require recovery. A new device with no checkpoint cannot prove freshness. |
| Server equivocation/fork | Different clients can receive different valid histories | V1 has no transparency log. It can detect contradictions when histories meet but cannot guarantee timely fork detection. |
| Version-vector inflation by host | Host cannot forge valid record AD | Reject altered records. It can omit data or deny service. |
| Version-vector inflation by enrolled malicious device | Device with VMK can create valid data; server enforces sequential author counters | Limit prevents large jumps but not deliberate valid churn. Revoke device; availability impact remains. |
| Concurrent edit/edit | Vectors incomparable | Retain both; deterministic projection is not deletion. User resolution dominates both. |
| Concurrent edit/delete | Vectors incomparable | Retain live and tombstone siblings; never silently delete the edit or local key. |
| Later sibling after tombstone acknowledgement | Per-record collection barrier is recomputed from every retained revision cursor while the record is locked | Raise the barrier; an unresolved concurrent tombstone remains ineligible. After collection, reject writes that do not dominate the persisted frontier. |
| Remote identity tombstone | Has no device-local custody generation or cleanup authority | Unlink shared record, preserve local key as orphan, require explicit local exact-generation cleanup. |
| Lost one device | Other device or verified SSH path survives | Revoke token. Secure Enclave key on lost device is unrecoverable and must be replaced. |
| Lost host, surviving device | Surviving client has VMK and a completed snapshot containing every sibling/tombstone/vector at cut C | Preserve instance/vault IDs, rewrap the same VMK under a new host secret, atomically import exact revisions, rebuild cursor floor C, retire old device IDs, and never sync the abandoned fork. A projection-only local store is insufficient. |
| Lost instance secret, surviving device | Client still holds VMK | Create a new secret and conditionally rewrap. Never replace secret without a device-held VMK. |
| Lost passphrase, surviving device | Device already holds VMK | After local authorization, set a new passphrase envelope. This proposed recovery requires Tom approval. |
| Lost all devices, base mode | Host secret plus envelope can unwrap VMK | Enroll through verified SSH. Software identities recover; Secure Enclave private keys do not. |
| Lost all devices, passphrase mode | Host alone cannot unwrap VMK | Enroll through SSH and supply passphrase. Losing passphrase too is intentionally unrecoverable. |
| Partial backup/restore | Manifest, checksum, schema, IDs, and file-mode validation fail | Keep old instance untouched; restore only into isolation. |
| Backup during instance-secret rotation | Pending or recovery secret slot makes the transition unstable | V1 refuses backup until rotation returns to `stable`; it never emits a partial transition archive. |
| Database and secret from different instances | Instance/vault/generation mismatch | Fail closed with `instance_mismatch`; never try alternate derivations. |
| Clock skew | Grants use a boot-bound monotonic deadline; collection age accrues only from durably checkpointed positive daemon monotonic uptime | Wall clocks are display metadata. Restart downtime and clock jumps can delay collection but cannot accelerate it or select a value. |
| Interrupted enrollment | Grant consumption and device creation are one transaction; tuple is idempotent | Retry exact tuple. Mismatch or expired grant requires a new SSH grant. |
| Interrupted passphrase rewrap | Envelope generation CAS leaves one committed envelope | Reload winner; records are unchanged. |
| Interrupted secret rotation | Active and pending generations remain recoverable until envelope and secret agree | Resume or discard pending state according to two-phase state machine. |
| Snapshot expires mid-page | Snapshot ID/token is missing or lease expires | Discard all staged pages and begin a fresh cut; never combine snapshots or fall back to an empty delta. |
| Incompatible protocol/crypto version | Negotiation has no compatible required capability | Preserve opaque data and block affected writes; never downgrade or reset. |

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
file, sync log, JSON library field, or crash report is allowed. The exact
Ed25519/RSA encoding and Keychain access policy remain review-pending.

### 7.2 Secure Enclave identities

Only public key, fingerprint, origin device, and non-secret descriptive data
sync. Other devices display an unavailable placeholder and must not imply the
private key was backed up. Device loss means replacement and remote
reauthorization, not key recovery.

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

## 9. Operational controls

The implementation must eventually demonstrate:

- loopback-only IPv4/IPv6 listeners and startup rejection of wildcard binds;
- mode `0600` instance secret, config, database, and backup artifacts;
- bounded HTTP parsing, request bodies, pages, sibling counts, and rate limits;
- stable snapshot cuts, replayable page tokens, sibling-complete pagination,
  expiry discard, and exact cut-to-delta transition;
- constant-time grant/token-hash comparison;
- structured log redaction tests covering every credential and ciphertext
  field;
- transactional enrollment, token rotation/revocation, sync, envelope CAS,
  backup checkpoint, and restore replacement;
- atomic identity-preserving host-recovery import with cursor-floor and vector
  reconstruction tests;
- crash/restart tests at each durable state-machine boundary; and
- no server vault-crypto dependency or private-key parser.

## 10. Tom review checklist

Tom's recorded review must explicitly accept or revise:

1. HTTP/1.1 JSON over SSH-forwarded loopback and the listener/limit profile.
2. Random sizes, token/grant hashing, client-generated token model, scopes,
   rotation, and last-device rules.
3. HKDF construction, domain labels, envelope and record associated data,
   XChaCha20-Poly1305 usage, nonce requirements, and known-answer vectors.
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
9. Stable full-snapshot pagination, tombstone sibling barriers, and
   identity-preserving host-loss recovery including cursor reconstruction.

Until those answers and exact conformance results are recorded, this threat
model is a review artifact rather than a completed security claim.
