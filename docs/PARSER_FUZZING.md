# Server parser fuzzing

This repository keeps coverage-guided Go fuzz targets at every source-derived
project-owned runtime parsing boundary. The fail-closed inventory in
`SERVER_PARSER_INVENTORY.json` scans non-vendored production Go source and maps
all 60 current parser signals in 21 files to one or more executable owners.
The targets cover:

- strict sync requests plus every V1 request DTO (`FuzzDecodeStrictJSON`);
- stored sync JSON shapes, canonical records, scalar/base64 fields, and
  authorization (`FuzzStoredJSONShapes`,
  `FuzzStoreScalarAndStoredParsers`);
- immutable release manifests and deployment previews
  (`FuzzParsePinnedManifest`, `FuzzParseDeploymentPreview`);
- canonical deployment state/journals, build-identity JSON, URLs, digests, and
  sizes (`FuzzDecodeDeploymentMetadata`, `FuzzParseBuildIdentityJSON`,
  `FuzzDeploymentScalarParsers`);
- protected instance configuration and listener grammar
  (`FuzzDecodeConfigJSON`);
- owner-only admin-socket requests and the CLI's strict loopback responses
  (`FuzzDecodeAdminRequest`, `FuzzDecodeCLIResponses`);
- build attestations, UUIDv4, and release identifiers
  (`FuzzParseAttestation`, `FuzzParseUUIDv4`,
  `FuzzReleaseIdentifier`); and
- one-line installer URL/payload inputs (`FuzzInstallCommandInput`).

All 15 targets have a checked-in minimized invalid seed under their package's
`testdata/fuzz` directory and one or more canonical accepted seeds constructed
by the test. Accepted inputs must re-encode and reparse without changing bytes
or typed values. Go's ordinary package test runs replay every seed. The
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
