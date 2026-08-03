package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func mutateStartupFixedBlobOversized(t *testing.T, database *sql.DB, statement string, arguments ...any) {
	t.Helper()
	if _, err := database.Exec("PRAGMA foreign_keys = OFF"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(statement, arguments...); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("PRAGMA ignore_check_constraints = OFF"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatal(err)
	}
}

func mutateStartupFixedBlobWrongType(t *testing.T, database *sql.DB, table, statement string, arguments ...any) {
	t.Helper()
	if _, err := database.Exec("PRAGMA foreign_keys = OFF"); err != nil {
		t.Fatal(err)
	}
	var originalSchema string
	if err := database.QueryRow("SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?", table).Scan(&originalSchema); err != nil {
		t.Fatal(err)
	}
	nonstrictSchema := strings.TrimSuffix(originalSchema, " STRICT")
	if nonstrictSchema == originalSchema {
		t.Fatalf("%s schema is not STRICT", table)
	}
	var schemaVersion int
	if err := database.QueryRow("PRAGMA schema_version").Scan(&schemaVersion); err != nil {
		t.Fatal(err)
	}
	rewrite := func(schema string, version int) {
		t.Helper()
		if _, err := database.Exec("PRAGMA writable_schema = ON"); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec("UPDATE sqlite_schema SET sql = ? WHERE type = 'table' AND name = ?", schema, table); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(fmt.Sprintf("PRAGMA schema_version = %d", version)); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec("PRAGMA writable_schema = OFF"); err != nil {
			t.Fatal(err)
		}
	}
	rewrite(nonstrictSchema, schemaVersion+1)
	if _, err := database.Exec(statement, arguments...); err != nil {
		t.Fatal(err)
	}
	rewrite(originalSchema, schemaVersion+2)
	if _, err := database.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatal(err)
	}
}

func requireFixedBlobStartupRejection(t *testing.T, seed boundedPersistenceSeed, wantDetail string) {
	t.Helper()
	if err := seed.opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), seed.path, testIdentity)
	if reopened != nil {
		reopened.Close()
	}
	if !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), wantDetail) {
		t.Fatalf("startup error=%v, want ErrUnexpectedSchema containing %q", err, wantDetail)
	}
}

func TestStartupFixedBlobGuardsAcceptCanonicalState(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{marker: true})
	if err := seed.opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), seed.path, testIdentity)
	if err != nil {
		t.Fatalf("canonical startup state rejected after fixed-BLOB projection changes: %v", err)
	}
	defer reopened.Close()
}

func TestStartupFixedBlobGuardsRejectOversizedValues(t *testing.T) {
	const oversizedBytes = maxBodyBytes + 1
	tests := []struct {
		name       string
		options    boundedSeedOptions
		mutate     func(*testing.T, *sql.DB)
		wantDetail string
	}{
		{
			name: "runtime cursor", mutate: func(t *testing.T, database *sql.DB) {
				mutateStartupFixedBlobOversized(t, database, "UPDATE runtime_state SET server_cursor = zeroblob(?) WHERE singleton = 1", oversizedBytes)
			}, wantDetail: "invalid runtime state",
		},
		{
			name: "envelope generation", mutate: func(t *testing.T, database *sql.DB) {
				mutateStartupFixedBlobOversized(t, database, "UPDATE vault_envelope SET generation = zeroblob(?) WHERE singleton = 1", oversizedBytes)
			}, wantDetail: "invalid envelope row",
		},
		{
			name: "revision object hash", mutate: func(t *testing.T, database *sql.DB) {
				mutateStartupFixedBlobOversized(t, database, "UPDATE revision_objects SET content_hash = zeroblob(?)", oversizedBytes)
			}, wantDetail: "revision object exceeds body limit",
		},
		{
			name: "vector index hash", mutate: func(t *testing.T, database *sql.DB) {
				mutateStartupFixedBlobOversized(t, database, "UPDATE record_vector_index SET vector_hash = zeroblob(?)", oversizedBytes)
			}, wantDetail: "invalid record vector index",
		},
		{
			name: "collection barrier", mutate: func(t *testing.T, database *sql.DB) {
				mutateStartupFixedBlobOversized(t, database, "UPDATE collection_records SET barrier_cursor = zeroblob(?)", oversizedBytes)
			}, wantDetail: "invalid collection record queue",
		},
		{
			name: "marker witness authenticator", options: boundedSeedOptions{marker: true}, mutate: func(t *testing.T, database *sql.DB) {
				mutateStartupFixedBlobOversized(t, database, "UPDATE collection_markers SET collection_witness_authenticator = zeroblob(?)", oversizedBytes)
			}, wantDetail: "invalid marker row",
		},
		{
			name: "enrollment grant boot id", mutate: func(t *testing.T, database *sql.DB) {
				mutateStartupFixedBlobOversized(t, database, "UPDATE enrollment_grants SET boot_id = zeroblob(?)", oversizedBytes)
			}, wantDetail: "invalid enrollment grant",
		},
		{
			name: "receipt uptime", mutate: func(t *testing.T, database *sql.DB) {
				mutateStartupFixedBlobOversized(t, database, "UPDATE operation_receipts SET created_uptime_ms = zeroblob(?) WHERE receipt_sequence = (SELECT min(receipt_sequence) FROM operation_receipts)", oversizedBytes)
			}, wantDetail: "invalid operation receipt",
		},
		{
			name: "receipt retention uptime", mutate: func(t *testing.T, database *sql.DB) {
				mutateStartupFixedBlobOversized(t, database, "UPDATE operation_receipt_retention SET created_uptime_ms = zeroblob(?) WHERE receipt_sequence = (SELECT min(receipt_sequence) FROM operation_receipt_retention)", oversizedBytes)
			}, wantDetail: "invalid operation receipt retention",
		},
		{
			name: "snapshot cut", mutate: func(t *testing.T, database *sql.DB) {
				mutateStartupFixedBlobOversized(t, database, "UPDATE snapshots SET cut_cursor = zeroblob(?)", oversizedBytes)
			}, wantDetail: "invalid snapshot row",
		},
		{
			name: "snapshot reference hash", mutate: func(t *testing.T, database *sql.DB) {
				mutateStartupFixedBlobOversized(t, database, "UPDATE snapshot_revision_refs SET content_hash = zeroblob(?)", oversizedBytes)
			}, wantDetail: "invalid snapshot reference",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, test.options)
			test.mutate(t, seed.opened.db)
			requireFixedBlobStartupRejection(t, seed, test.wantDetail)
		})
	}
}

func TestStartupFixedBlobGuardsRejectExactWidthText(t *testing.T) {
	tests := []struct {
		name       string
		table      string
		statement  string
		value      string
		wantDetail string
	}{
		{
			name: "runtime cursor", table: "runtime_state",
			statement:  "UPDATE runtime_state SET server_cursor = ? WHERE singleton = 1",
			value:      "12345678",
			wantDetail: "invalid runtime state",
		},
		{
			name: "envelope generation", table: "vault_envelope",
			statement:  "UPDATE vault_envelope SET generation = ? WHERE singleton = 1",
			value:      "12345678",
			wantDetail: "invalid envelope row",
		},
		{
			name: "vector index hash", table: "record_vector_index",
			statement:  "UPDATE record_vector_index SET vector_hash = ?",
			value:      strings.Repeat("v", 32),
			wantDetail: "invalid record vector index",
		},
		{
			name: "enrollment grant hash", table: "enrollment_grants",
			statement:  "UPDATE enrollment_grants SET grant_hash = ?",
			value:      strings.Repeat("g", 32),
			wantDetail: "invalid enrollment grant",
		},
		{
			name: "receipt fingerprint", table: "operation_receipts",
			statement:  "UPDATE operation_receipts SET request_fingerprint = ? WHERE receipt_sequence = (SELECT min(receipt_sequence) FROM operation_receipts)",
			value:      strings.Repeat("r", 32),
			wantDetail: "invalid operation receipt",
		},
		{
			name: "snapshot fingerprint", table: "snapshots",
			statement:  "UPDATE snapshots SET request_fingerprint = ?",
			value:      strings.Repeat("s", 32),
			wantDetail: "invalid snapshot row",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{})
			mutateStartupFixedBlobWrongType(t, seed.opened.db, test.table, test.statement, test.value)
			requireFixedBlobStartupRejection(t, seed, test.wantDetail)
		})
	}
}
