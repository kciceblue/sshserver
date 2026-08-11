# Server parser fuzzing

This repository keeps coverage-guided Go fuzz targets at every source-derived
project-owned runtime parsing boundary. The fail-closed inventory in
`SERVER_PARSER_INVENTORY.json` scans non-vendored production Go source and maps
all 70 current parser signals in 24 files to one or more executable owners.
The targets cover:

- strict sync requests plus every V1 request DTO (`FuzzDecodeStrictJSON`);
- device-revocation and snapshot-page route identifiers
  (`FuzzPathIdentifier`);
- persisted operation-receipt keys and their destination-specific response
  validators (`FuzzOperationReceiptKey`);
- every persisted canonical response destination (response headers, envelope,
  sync, device, enrollment, snapshot-create, revision, and snapshot-page
  shapes), scalar/base64 fields, and authorization (`FuzzStoredJSONShapes`,
  `FuzzStoreScalarAndStoredParsers`);
- immutable release manifests and deployment previews
  (`FuzzParsePinnedManifest`, `FuzzParseDeploymentPreview`);
- canonical deployment state/journals, production-validated build-identity
  JSON, URLs, digests, and sizes (`FuzzDecodeDeploymentMetadata`,
  `FuzzParseBuildIdentityJSON`,
  `FuzzDeploymentScalarParsers`), plus Go executable build metadata through
  the production artifact decoder (`FuzzParseArtifactGoBuildInfo`) and the
  installed-artifact filename grammar (`FuzzValidateRemovableArtifactName`);
- protected instance configuration and listener grammar
  (`FuzzDecodeConfigJSON`);
- owner-only admin-socket requests, raw HTTP/1 request-head limits and request
  IDs, and the CLI's strict loopback responses (`FuzzDecodeAdminRequest`,
  `FuzzHTTP1RequestHead`, `FuzzDecodeCLIResponses`);
- the complete HTTP transport request grammar plus comma-delimited
  `Connection` header tokens (`FuzzValidateTransportRequest`,
  `FuzzHeaderContainsToken`);
- build attestations, UUIDv4, and release identifiers
  (`FuzzParseAttestation`, `FuzzParseUUIDv4`,
  `FuzzReleaseIdentifier`);
- local nested-module pseudo-version, source-revision, and VCS-time binding
  (`FuzzValidLocalMainVersion`) plus release-bundle executable metadata through
  its production decoder (`FuzzParseReleaseBundleGoBuildInfo`); and
- one-line installer URL/payload inputs (`FuzzInstallCommandInput`).

All 24 targets have a checked-in minimized invalid seed under their package's
`testdata/fuzz` directory. Structured owners construct canonical accepted
seeds; each executable-metadata owner mutates a bounded copy of the current Go
test executable through the exact production decoder, so successful metadata
paths remain in the coverage-guided corpus.
Accepted structured inputs with a canonical encoding must
re-encode and reparse without changing bytes or typed values. Go's ordinary
package test runs replay every seed. The
repository gate also runs 64 coverage-guided mutations per target with one
worker. If a mutation fails, Go's crasher minimization is separately capped at
64 executions rather than its time-based default:

```sh
make runtime-fuzz-smoke
```

For a longer local campaign, run one target at a time from `runtime/`, for
example:

```sh
go test -mod=readonly -run '^$' -fuzz '^FuzzDecodeStrictJSON$' -fuzztime=30m -parallel=1 ./internal/store
```

Any new crasher must first become a minimized checked-in corpus entry, then be
fixed and replayed by `make check`. Do not commit machine-local fuzz cache
contents.

This closes only the source-derived server-runtime parser software inventory.
It does not claim that client parsers, the named 24-hour soak, or the full
cross-repository recovery campaign are complete.
