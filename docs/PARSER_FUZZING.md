# Server parser fuzzing

This repository keeps coverage-guided Go fuzz targets at the strict parsing
boundaries that accept project-owned wire or deployment bytes:

- sync wire JSON (`FuzzDecodeStrictJSON`);
- immutable release manifests (`FuzzParsePinnedManifest`);
- canonical deployment previews (`FuzzParseDeploymentPreview`); and
- owner-only admin-socket requests (`FuzzDecodeAdminRequest`).

Each target has a checked-in minimized invalid seed under its package's
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

This is the server-parser slice of coordinator Task 3.6. It does not claim that
client parsers, the named 24-hour soak, or the full cross-repository recovery
campaign are complete.
