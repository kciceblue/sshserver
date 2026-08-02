package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/auth"
)

const identifierScanOversizedSuffixBytes = 64 * 1024

func TestOwnedStoreTextScansRejectMalformedStorage(t *testing.T) {
	t.Run("identity fields", func(t *testing.T) {
		oversizedSuffix := strings.Repeat("x", identifierScanOversizedSuffixBytes)
		tests := []struct {
			name          string
			instanceID    any
			vaultID       any
			protocolMajor any
			storageSchema any
		}{
			{
				name:          "NUL-suffixed instance ID",
				instanceID:    testIdentity.InstanceID + "\x00" + oversizedSuffix,
				vaultID:       testIdentity.VaultID,
				protocolMajor: "1", storageSchema: "1",
			},
			{
				name:          "BLOB instance ID",
				instanceID:    []byte(testIdentity.InstanceID),
				vaultID:       testIdentity.VaultID,
				protocolMajor: "1", storageSchema: "1",
			},
			{
				name:          "NUL-suffixed vault ID",
				instanceID:    testIdentity.InstanceID,
				vaultID:       testIdentity.VaultID + "\x00" + oversizedSuffix,
				protocolMajor: "1", storageSchema: "1",
			},
			{
				name:          "NUL-suffixed protocol major",
				instanceID:    testIdentity.InstanceID,
				vaultID:       testIdentity.VaultID,
				protocolMajor: "1\x00" + oversizedSuffix, storageSchema: "1",
			},
			{
				name:          "BLOB storage schema",
				instanceID:    testIdentity.InstanceID,
				vaultID:       testIdentity.VaultID,
				protocolMajor: "1", storageSchema: []byte("1"),
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				database := openIdentifierScanFixture(t)
				mustIdentifierScanExec(t, database, `
					CREATE TABLE instance_metadata (
						singleton INTEGER PRIMARY KEY,
						instance_id, vault_id, protocol_major, storage_schema
					)`)
				mustIdentifierScanExec(t, database, `
					INSERT INTO instance_metadata (
						singleton, instance_id, vault_id, protocol_major, storage_schema
					) VALUES (1, ?, ?, ?, ?)`, test.instanceID, test.vaultID, test.protocolMajor, test.storageSchema)
				if err := validateIdentity(context.Background(), database, testIdentity); !errors.Is(err, ErrIdentityMismatch) {
					t.Fatalf("validateIdentity error = %v, want ErrIdentityMismatch", err)
				}
			})
		}
	})

	t.Run("device scopes", func(t *testing.T) {
		wantScopes, err := json.Marshal(auth.FixedScopes())
		if err != nil {
			t.Fatal(err)
		}
		oversizedSuffix := strings.Repeat("x", identifierScanOversizedSuffixBytes)
		for _, test := range []struct {
			name   string
			scopes any
		}{
			{name: "NUL-suffixed TEXT", scopes: string(wantScopes) + "\x00" + oversizedSuffix},
			{name: "BLOB", scopes: append([]byte(nil), wantScopes...)},
		} {
			t.Run(test.name, func(t *testing.T) {
				database := openIdentifierScanFixture(t)
				mustIdentifierScanExec(t, database, "CREATE TABLE devices (device_id, token_hash, scopes_json)")
				deviceID := "a1000000-0000-4000-8000-000000000001"
				mustIdentifierScanExec(t, database,
					"INSERT INTO devices (device_id, token_hash, scopes_json) VALUES (?, ?, ?)",
					deviceID, make([]byte, 32), test.scopes,
				)
				fixture := &Store{db: database}
				if _, _, err := fixture.DeviceCredential(context.Background(), deviceID); err == nil || err.Error() != "stored device credential is invalid" {
					t.Fatalf("DeviceCredential error = %v, want bounded stored-credential error", err)
				}
			})
		}
	})
}

func TestOwnedSyncTextScansRejectMalformedStorage(t *testing.T) {
	validRevisionID := "a2000000-0000-4000-8000-000000000001"
	validMarkerID := "a2000000-0000-4000-8000-000000000002"
	oversizedSuffix := strings.Repeat("x", identifierScanOversizedSuffixBytes)
	tests := []struct {
		name       string
		kind       any
		revisionID any
		markerID   any
		markerBody any
	}{
		{name: "NUL-suffixed kind", kind: "record_revision\x00" + oversizedSuffix, revisionID: validRevisionID},
		{name: "BLOB kind", kind: []byte("record_revision"), revisionID: validRevisionID},
		{name: "NUL-suffixed revision ID", kind: "record_revision", revisionID: validRevisionID + "\x00" + oversizedSuffix},
		{name: "BLOB revision ID", kind: "record_revision", revisionID: []byte(validRevisionID)},
		{name: "NUL-suffixed marker ID", kind: "collection_marker", markerID: validMarkerID + "\x00" + oversizedSuffix, markerBody: []byte("{}")},
		{name: "BLOB marker ID", kind: "collection_marker", markerID: []byte(validMarkerID), markerBody: []byte("{}")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database := openIdentifierScanFixture(t)
			mustIdentifierScanExec(t, database, `
				CREATE TABLE changes (
					cursor, kind, received_at_ms,
					record_revision_id, collection_marker_record_id, collection_marker_json
				)`)
			cursor := EncodeUint64(1)
			mustIdentifierScanExec(t, database, `
				INSERT INTO changes (
					cursor, kind, received_at_ms,
					record_revision_id, collection_marker_record_id, collection_marker_json
				) VALUES (?, ?, ?, ?, ?, ?)`, cursor[:], test.kind, protocolFixtureTime.UnixMilli(), test.revisionID, test.markerID, test.markerBody)
			transaction := beginIdentifierScanFixture(t, database)
			defer transaction.Rollback()
			if _, _, _, protocolErr := loadChanges(context.Background(), transaction, 0); protocolErr == nil || protocolErr.Code != "internal_error" {
				t.Fatalf("loadChanges error = %v, want internal_error", protocolErr)
			}
		})
	}

	t.Run("frontier revision ID", func(t *testing.T) {
		for _, test := range []struct {
			name       string
			revisionID any
		}{
			{name: "NUL-suffixed TEXT", revisionID: validRevisionID + "\x00" + oversizedSuffix},
			{name: "BLOB", revisionID: []byte(validRevisionID)},
		} {
			t.Run(test.name, func(t *testing.T) {
				database := openIdentifierScanFixture(t)
				mustIdentifierScanExec(t, database, "CREATE TABLE record_heads (record_id, revision_id)")
				mustIdentifierScanExec(t, database, "CREATE TABLE record_revisions (revision_id, vector_json)")
				recordID := "a2000000-0000-4000-8000-000000000003"
				mustIdentifierScanExec(t, database, "INSERT INTO record_heads (record_id, revision_id) VALUES (?, ?)", recordID, test.revisionID)
				mustIdentifierScanExec(t, database, "INSERT INTO record_revisions (revision_id, vector_json) VALUES (?, ?)", test.revisionID, []byte("[]"))
				transaction := beginIdentifierScanFixture(t, database)
				defer transaction.Rollback()
				if _, _, protocolErr := classifyRevisionFrontier(context.Background(), transaction, recordID, map[string]uint64{}); protocolErr == nil || protocolErr.Code != "internal_error" {
					t.Fatalf("classifyRevisionFrontier error = %v, want internal_error", protocolErr)
				}
			})
		}
	})
}

func TestOwnedCollectionTextScansRejectMalformedStorage(t *testing.T) {
	validRecordID := "a3000000-0000-4000-8000-000000000001"
	validRevisionID := "a3000000-0000-4000-8000-000000000002"
	oversizedSuffix := strings.Repeat("x", identifierScanOversizedSuffixBytes)

	t.Run("scan cursor and record ID", func(t *testing.T) {
		tests := []struct {
			name      string
			scanAfter any
			recordID  any
			insertRow bool
			wantError bool
		}{
			{name: "valid empty cursor", scanAfter: ""},
			{name: "NUL-suffixed cursor", scanAfter: validRecordID + "\x00" + oversizedSuffix, wantError: true},
			{name: "BLOB cursor", scanAfter: []byte(validRecordID), wantError: true},
			{name: "NUL-suffixed record ID", scanAfter: "", recordID: validRecordID + "\x00" + oversizedSuffix, insertRow: true, wantError: true},
			{name: "BLOB record ID", scanAfter: "", recordID: []byte(validRecordID), insertRow: true, wantError: true},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				database := openIdentifierScanFixture(t)
				mustIdentifierScanExec(t, database, "CREATE TABLE runtime_state (singleton INTEGER PRIMARY KEY, collection_scan_after_record_id)")
				mustIdentifierScanExec(t, database, "CREATE TABLE collection_records (record_id)")
				mustIdentifierScanExec(t, database, "INSERT INTO runtime_state (singleton, collection_scan_after_record_id) VALUES (1, ?)", test.scanAfter)
				if test.insertRow {
					mustIdentifierScanExec(t, database, "INSERT INTO collection_records (record_id) VALUES (?)", test.recordID)
				}
				transaction := beginIdentifierScanFixture(t, database)
				defer transaction.Rollback()
				recordIDs, scanAfter, protocolErr := loadCollectionRecordBatch(context.Background(), transaction)
				if test.wantError {
					if protocolErr == nil || protocolErr.Code != "internal_error" {
						t.Fatalf("loadCollectionRecordBatch error = %v, want internal_error", protocolErr)
					}
					return
				}
				if protocolErr != nil || len(recordIDs) != 0 || scanAfter != "" {
					t.Fatalf("valid empty cursor result = records %v cursor %q error %v", recordIDs, scanAfter, protocolErr)
				}
			})
		}
	})

	t.Run("collection revision IDs", func(t *testing.T) {
		for _, test := range []struct {
			name       string
			revisionID any
			recordID   any
		}{
			{name: "NUL-suffixed revision ID", revisionID: validRevisionID + "\x00" + oversizedSuffix, recordID: validRecordID},
			{name: "BLOB revision ID", revisionID: []byte(validRevisionID), recordID: validRecordID},
			{name: "NUL-suffixed record ID", revisionID: validRevisionID, recordID: validRecordID + "\x00" + oversizedSuffix},
			{name: "BLOB record ID", revisionID: validRevisionID, recordID: []byte(validRecordID)},
		} {
			t.Run(test.name, func(t *testing.T) {
				database := openIdentifierScanFixture(t)
				mustIdentifierScanExec(t, database, "CREATE TABLE collection_records (record_id, barrier_cursor)")
				mustIdentifierScanExec(t, database, "CREATE TABLE record_heads (record_id, revision_id)")
				mustIdentifierScanExec(t, database, `
					CREATE TABLE record_revisions (
						revision_id, record_id, vector_json, content_hash,
						collection_witness_authenticator, tombstone,
						accepted_uptime_ms, change_cursor
					)`)
				one := EncodeUint64(1)
				mustIdentifierScanExec(t, database, "INSERT INTO collection_records (record_id, barrier_cursor) VALUES (?, ?)", validRecordID, one[:])
				mustIdentifierScanExec(t, database, "INSERT INTO record_heads (record_id, revision_id) VALUES (?, ?)", validRecordID, test.revisionID)
				mustIdentifierScanExec(t, database, `
					INSERT INTO record_revisions (
						revision_id, record_id, vector_json, content_hash,
						collection_witness_authenticator, tombstone,
						accepted_uptime_ms, change_cursor
					) VALUES (?, ?, ?, ?, NULL, 0, ?, ?)`, test.revisionID, test.recordID, []byte("[]"), make([]byte, 32), one[:], one[:])
				transaction := beginIdentifierScanFixture(t, database)
				defer transaction.Rollback()
				if _, _, _, protocolErr := loadCollectionRecordWork(context.Background(), transaction, validRecordID, 0); protocolErr == nil || protocolErr.Code != "internal_error" {
					t.Fatalf("loadCollectionRecordWork error = %v, want internal_error", protocolErr)
				}
			})
		}
	})

	t.Run("witness revision ID", func(t *testing.T) {
		for _, test := range []struct {
			name      string
			witnessID any
		}{
			{name: "NUL-suffixed TEXT", witnessID: validRevisionID + "\x00" + oversizedSuffix},
			{name: "BLOB", witnessID: []byte(validRevisionID)},
		} {
			t.Run(test.name, func(t *testing.T) {
				database := openIdentifierScanFixture(t)
				mustIdentifierScanExec(t, database, `
					CREATE TABLE collection_markers (
						record_id, witness_revision_id, frontier_json,
						collection_witness_authenticator, barrier_cursor, marker_json
					)`)
				one := EncodeUint64(1)
				mustIdentifierScanExec(t, database, `
					INSERT INTO collection_markers (
						record_id, witness_revision_id, frontier_json,
						collection_witness_authenticator, barrier_cursor, marker_json
					) VALUES (?, ?, ?, ?, ?, ?)`, validRecordID, test.witnessID, []byte("[]"), make([]byte, 32), one[:], []byte("{}"))
				transaction := beginIdentifierScanFixture(t, database)
				defer transaction.Rollback()
				if _, protocolErr := loadCollectionMarker(context.Background(), transaction, validRecordID); protocolErr == nil || protocolErr.Code != "internal_error" {
					t.Fatalf("loadCollectionMarker error = %v, want internal_error", protocolErr)
				}
			})
		}
	})

	t.Run("snapshot ID before deletion", func(t *testing.T) {
		for _, test := range []struct {
			name       string
			snapshotID any
		}{
			{name: "NUL-suffixed TEXT", snapshotID: "a3000000-0000-4000-8000-000000000003\x00" + oversizedSuffix},
			{name: "BLOB", snapshotID: []byte("a3000000-0000-4000-8000-000000000003")},
		} {
			t.Run(test.name, func(t *testing.T) {
				database := openIdentifierScanFixture(t)
				mustIdentifierScanExec(t, database, "CREATE TABLE record_revisions (revision_id, retained, content_hash)")
				mustIdentifierScanExec(t, database, "CREATE TABLE snapshots (snapshot_id)")
				mustIdentifierScanExec(t, database, "CREATE TABLE snapshot_revision_refs (snapshot_id, revision_id)")
				mustIdentifierScanExec(t, database, "CREATE TABLE revision_objects (content_hash)")
				var hash [32]byte
				mustIdentifierScanExec(t, database, "INSERT INTO record_revisions (revision_id, retained, content_hash) VALUES (?, 0, ?)", validRevisionID, hash[:])
				mustIdentifierScanExec(t, database, "INSERT INTO snapshots (snapshot_id) VALUES (?)", test.snapshotID)
				mustIdentifierScanExec(t, database, "INSERT INTO revision_objects (content_hash) VALUES (?)", hash[:])
				transaction := beginIdentifierScanFixture(t, database)
				defer transaction.Rollback()
				if protocolErr := deleteUnreferencedRevisionObject(context.Background(), transaction, hash, validRevisionID); protocolErr == nil || protocolErr.Code != "internal_error" {
					t.Fatalf("deleteUnreferencedRevisionObject error = %v, want internal_error", protocolErr)
				}
				var objectCount int
				if err := transaction.QueryRow("SELECT count(*) FROM revision_objects").Scan(&objectCount); err != nil || objectCount != 1 {
					t.Fatalf("revision object count after rejected scan = %d, error %v", objectCount, err)
				}
			})
		}
	})
}

func openIdentifierScanFixture(t *testing.T) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "identifier-scan.db"))
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close identifier scan fixture: %v", err)
		}
	})
	return database
}

func mustIdentifierScanExec(t *testing.T, database *sql.DB, statement string, arguments ...any) {
	t.Helper()
	if _, err := database.Exec(statement, arguments...); err != nil {
		t.Fatal(err)
	}
}

func beginIdentifierScanFixture(t *testing.T, database *sql.DB) *sql.Tx {
	t.Helper()
	transaction, err := database.BeginTx(context.Background(), &sql.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return transaction
}
