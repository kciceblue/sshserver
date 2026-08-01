# Upstream provenance

This directory is a mechanically trimmed, otherwise unmodified source fork of
the MIT-licensed `github.com/ncruces/go-sqlite3` module at tag `v0.32.0`:

- upstream commit: `5842ec9343b4a71dae70976d66fd8c9a3d49b868`
- Go module sum: `h1:hNBUXp88LrfQCsuyXLqWTbTUG35sUuktDsqhhgHvU20=`
- upstream module-file sum: `h1:MIWTK60ONDl0oVY073zYvJP21C3Dly6P9bxVpgkLwdQ=`

The package closure was produced with `go mod vendor` from a module importing
only `github.com/ncruces/go-sqlite3/driver` and
`github.com/ncruces/go-sqlite3/embed`. Tests, examples, optional extensions,
and packages outside that shipping closure are intentionally absent. The local
`go.mod` records only the dependencies imported by this retained source.

The retained upstream `LICENSE` applies to the vendored source. The server's
fail-closed dependency checker examines this replacement module and its full
selected graph as independent Go modules. `UPSTREAM_FILES.sha256` binds every
retained upstream byte, including the embedded SQLite WebAssembly engine, and
`make runtime-vendor-check` compares those bytes and executable mode bits with
the exact checksummed upstream module before release.
