# Task 2.0 cryptographic conformance

Tom approved the exact Task 2.0 P1-P6 profile at commit
`1a4951947efbef1827b1fcba4be89a7781405c5d`. The durable approval link,
historical source hashes, immutable crypto-input hash, and byte-identical
machine-readable artifact hashes are recorded in `approved-profile.json`.

Two independent implementations consume the same frozen fixture:

- `conformance/go/main.go` uses the BSD-3-Clause Go `x/crypto` implementation
  for Argon2id and XChaCha20-Poly1305.
- `conformance/swift/CryptoKAT.swift` uses system CryptoKit, a separately
  implemented HChaCha20 transform, and the explicitly selected Apache-2.0
  OpenSSL 3.6.3 CLI for Argon2id. OpenSSL is an executable test tool and is not
  linked into or redistributed with the server.

Run both implementations and require canonical byte-for-byte agreement with
the reviewed fixture:

```sh
make kat
```

`make kat` uses `JAT_OPENSSL_BIN` when set; otherwise it resolves Homebrew's
`openssl@3` formula and rejects any version other than the reviewed 3.6.3
provider. Stock macOS LibreSSL is never selected implicitly.

`make check` verifies the exact approved Git commit and allowed status-only
artifact transition, hashes, dependency files, negative authentication
results, populated fixture, and a freshly executed Go derivation. Manual CI
also runs `make kat` on macOS so both independent providers are reproduced.
The checks do not regenerate or silently bless new expected values. Any
intended profile or vector change requires a new owner review and evidence.
