package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

func downgradeRecordRevisionsToPriorFullV1(t *testing.T, database *sql.DB) {
	t.Helper()
	transaction, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	if _, err := transaction.Exec(
		"ALTER TABLE record_revisions RENAME TO record_revisions_current_v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(createRecordRevisionsPriorFullV1); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(`
		INSERT INTO record_revisions (
			revision_id, record_id, author_device_id, author_counter,
			vector_json, collection_witness_authenticator, tombstone,
			content_hash, received_at_ms, accepted_uptime_ms,
			change_cursor, collected_generation, retained, undominated
		)
		SELECT revision_id, record_id, author_device_id, author_counter,
		       vector_json, collection_witness_authenticator, tombstone,
		       content_hash, received_at_ms, accepted_uptime_ms,
		       change_cursor, collected_generation, retained, undominated
		FROM record_revisions_current_v1`); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec("DROP TABLE record_revisions_current_v1"); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := database.QueryRow(`
		SELECT sql FROM sqlite_schema
		WHERE type = 'table' AND name = 'record_revisions'`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if schema != createRecordRevisionsPriorFullV1 {
		t.Fatalf("prior full record-revision schema mismatch:\n%s", schema)
	}
	kind, version, err := inspectSchemaState(context.Background(), database)
	if err != nil || kind != schemaPriorFull || version != SchemaVersion {
		t.Fatalf("prior full schema inspection: kind=%d version=%d error=%v", kind, version, err)
	}
}

func assertMigratedRecordAliasPlan(t *testing.T, database *sql.DB) {
	t.Helper()
	recordID := "f7580000-0000-4000-8000-000000000001"
	lowerBytes := []byte(recordID)
	upperBytes := append([]byte(nil), lowerBytes...)
	upperBytes[len(upperBytes)-1]++
	rows, err := database.Query("EXPLAIN QUERY PLAN "+recordKeyAliasProbeSQL,
		recordID, string(upperBytes), lowerBytes, upperBytes,
		recordID, string(upperBytes), lowerBytes, upperBytes,
		recordID, string(upperBytes), lowerBytes, upperBytes,
		recordID, string(upperBytes), lowerBytes, upperBytes,
		recordID, string(upperBytes), lowerBytes, upperBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	revisionSearches := 0
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if strings.Contains(detail, "SCAN record_revisions") {
			rows.Close()
			t.Fatalf("migrated record-key probe scans record_revisions: %s", detail)
		}
		if strings.Contains(detail, "SEARCH record_revisions") &&
			strings.Contains(detail, "record_id>?") && strings.Contains(detail, "record_id<?") {
			revisionSearches++
		}
	}
	iterationErr := rows.Err()
	closeErr := rows.Close()
	if iterationErr != nil || closeErr != nil {
		t.Fatalf("explain migrated record-key probe: iteration=%v close=%v", iterationErr, closeErr)
	}
	if revisionSearches != 2 {
		t.Fatalf("migrated record-revision range searches=%d, want=2", revisionSearches)
	}
}

func TestOpenMigratesExactPriorFullV1RecordRevisionSchema(t *testing.T) {
	for _, history := range []string{"retained head", "dominated retained", "collected permanent"} {
		t.Run(history, func(t *testing.T) {
			fixture := seedRevisionKeyFixture(t, history)
			before := markerKeyDurableDigest(t, fixture.seed.opened.db)
			downgradeRecordRevisionsToPriorFullV1(t, fixture.seed.opened.db)
			if afterDowngrade := markerKeyDurableDigest(t, fixture.seed.opened.db); afterDowngrade != before {
				fixture.seed.opened.Close()
				t.Fatalf("test downgrade changed durable rows: before=%x after=%x", before, afterDowngrade)
			}
			if err := fixture.seed.opened.Close(); err != nil {
				t.Fatal(err)
			}

			opened, err := Open(context.Background(), fixture.seed.path, testIdentity)
			if err != nil {
				t.Fatal(err)
			}
			if after := markerKeyDurableDigest(t, opened.db); after != before {
				opened.Close()
				t.Fatalf("migration changed durable rows: before=%x after=%x", before, after)
			}
			kind, version, err := inspectSchemaState(context.Background(), opened.db)
			if err != nil || kind != schemaFull || version != SchemaVersion {
				opened.Close()
				t.Fatalf("migrated schema inspection: kind=%d version=%d error=%v", kind, version, err)
			}
			verified, err := opened.VerifyDeviceToken(context.Background(), fixture.seed.deviceID, fixture.seed.token)
			if err != nil || !verified {
				opened.Close()
				t.Fatalf("migrated credential verified=%v error=%v", verified, err)
			}
			assertMigratedRecordAliasPlan(t, opened.db)
			if err := opened.Close(); err != nil {
				t.Fatal(err)
			}

			reopened, err := Open(context.Background(), fixture.seed.path, testIdentity)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if after := markerKeyDurableDigest(t, reopened.db); after != before {
				t.Fatalf("reopen changed migrated rows: before=%x after=%x", before, after)
			}
		})
	}
}

func TestPriorFullV1MigrationRollsBackOnInvalidDurableState(t *testing.T) {
	fixture := seedRevisionKeyFixture(t, "retained head")
	downgradeRecordRevisionsToPriorFullV1(t, fixture.seed.opened.db)
	corruptRecordID := fixture.seed.recordID + "\x00suffix"
	if _, err := fixture.seed.opened.db.Exec(
		"UPDATE record_revisions SET record_id = ? WHERE revision_id = ?",
		corruptRecordID, fixture.seed.revisionID,
	); err != nil {
		fixture.seed.opened.Close()
		t.Fatal(err)
	}
	before := markerKeyDurableDigest(t, fixture.seed.opened.db)
	if err := fixture.seed.opened.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(context.Background(), fixture.seed.path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) {
		t.Fatalf("invalid prior full migration error=%v", err)
	}
	raw, err := sql.Open("sqlite3", "file:"+fixture.seed.path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if after := markerKeyDurableDigest(t, raw); after != before {
		t.Fatalf("failed migration changed durable rows: before=%x after=%x", before, after)
	}
	var schema string
	if err := raw.QueryRow(`
		SELECT sql FROM sqlite_schema
		WHERE type = 'table' AND name = 'record_revisions'`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	if schema != createRecordRevisionsPriorFullV1 {
		t.Fatalf("failed migration changed prior schema:\n%s", schema)
	}
	var temporaryTables int
	if err := raw.QueryRow(`
		SELECT count(*) FROM sqlite_schema
		WHERE type = 'table' AND name = 'record_revisions_prior_full_v1'`).Scan(&temporaryTables); err != nil {
		t.Fatal(err)
	}
	if temporaryTables != 0 {
		t.Fatalf("failed migration left temporary tables=%d", temporaryTables)
	}
	kind, version, err := inspectSchemaState(context.Background(), raw)
	if err != nil || kind != schemaPriorFull || version != SchemaVersion {
		t.Fatalf("rolled-back schema inspection: kind=%d version=%d error=%v", kind, version, err)
	}
}
