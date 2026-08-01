module github.com/kciceblue/sshserver/runtime

go 1.25.0

require github.com/ncruces/go-sqlite3 v0.32.0

require (
	github.com/ncruces/julianday v1.0.0 // indirect
	github.com/tetratelabs/wazero v1.11.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

replace github.com/ncruces/go-sqlite3 => ./third_party/go-sqlite3
