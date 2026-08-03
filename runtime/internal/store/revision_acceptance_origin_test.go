package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
)

func setRevisionAcceptanceAge(t *testing.T, database *sql.DB, revisionID string, age uint64) {
	t.Helper()
	encoded := EncodeUint64(age)
	transaction, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	for _, statement := range []string{
		"UPDATE record_revisions SET accepted_uptime_ms = ? WHERE revision_id = ?",
		"UPDATE collection_candidates SET accepted_uptime_ms = ? WHERE revision_id = ?",
		"UPDATE revision_acceptance_origins SET accepted_uptime_ms = ? WHERE revision_id = ?",
	} {
		result, err := transaction.Exec(statement, encoded[:], revisionID)
		if err != nil {
			t.Fatal(err)
		}
		if affected, err := result.RowsAffected(); err != nil || affected != 1 {
			t.Fatalf("set revision acceptance age affected=%d error=%v", affected, err)
		}
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
}

func setAccumulatedUptimeMilliseconds(t *testing.T, database *sql.DB, uptime uint64) {
	t.Helper()
	encoded := EncodeUint64(uptime)
	result, err := database.Exec("UPDATE runtime_state SET accumulated_uptime_ms = ? WHERE singleton = 1", encoded[:])
	if err != nil {
		t.Fatal(err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		t.Fatalf("set accumulated uptime affected=%d error=%v", affected, err)
	}
}

func acceptanceOriginSyncRequest(t *testing.T, seed boundedPersistenceSeed, requestID, cursor string, mutations []recordRevision) api.Request {
	t.Helper()
	if mutations == nil {
		mutations = []recordRevision{}
	}
	body, err := marshalJSON(syncRequest{
		ProtocolVersion: "1",
		DeviceID:        seed.deviceID,
		RequestID:       requestID,
		AfterCursor:     cursor,
		AckCursor:       cursor,
		Mutations:       mutations,
	})
	if err != nil {
		t.Fatal(err)
	}
	return api.Request{
		Method:        "POST",
		Path:          "/v1/sync",
		RequestID:     requestID,
		Authorization: authorization(seed.token),
		Body:          body,
		Now:           protocolFixtureTime,
	}
}

// prepareAcceptanceCollectionPair leaves the original revision retained but
// dominated by a second authorized head. The original is therefore a real
// collection target once its own 90-day age is reached.
func prepareAcceptanceCollectionPair(t *testing.T, seed boundedPersistenceSeed, acceptedAt uint64) string {
	t.Helper()
	setRevisionAcceptanceAge(t, seed.opened.db, seed.revisionID, acceptedAt)
	setAccumulatedUptimeMilliseconds(t, seed.opened.db, acceptedAt)
	witnessBody := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	witnessRevisionID := "e1000000-0000-4000-8000-000000000010"
	witness := recordRevision{
		RecordID: seed.recordID, RevisionID: witnessRevisionID, AuthorDeviceID: seed.deviceID,
		AuthorCounter: "2", VersionVector: []vectorEntry{{DeviceID: seed.deviceID, Counter: "2"}},
		CollectionWitnessAuthenticator: &witnessBody, PayloadSchema: "1", CryptoSuite: cryptoSuite,
		Nonce:      base64.RawURLEncoding.EncodeToString(make([]byte, 24)),
		Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	request := acceptanceOriginSyncRequest(t, seed, "e1000000-0000-4000-8000-000000000011", "3", []recordRevision{witness})
	response, protocolErr := seed.opened.HandleAPI(context.Background(), request)
	if protocolErr != nil || response.Status != 200 {
		t.Fatalf("prepare collection pair response=%+v error=%v", response, protocolErr)
	}
	var serverBytes, ackBytes, returnedBytes []byte
	if err := seed.opened.db.QueryRow(`
		SELECT s.server_cursor, d.last_ack_cursor, x.max_returned_cursor
		FROM runtime_state s CROSS JOIN devices d
		JOIN device_sync_state x USING (device_id)
		WHERE s.singleton = 1 AND d.device_id = ?`, seed.deviceID,
	).Scan(&serverBytes, &ackBytes, &returnedBytes); err != nil {
		t.Fatal(err)
	}
	server, serverErr := DecodeUint64(serverBytes)
	ack, ackErr := DecodeUint64(ackBytes)
	returned, returnedErr := DecodeUint64(returnedBytes)
	if serverErr != nil || ackErr != nil || returnedErr != nil || server != 4 || ack != 3 || returned != 4 {
		t.Fatalf("prepared sync state server=%d/%v ack=%d/%v returned=%d/%v", server, serverErr, ack, ackErr, returned, returnedErr)
	}
	return witnessRevisionID
}

func TestCollectionRejectsCoherentlyLoweredMutableAcceptanceAges(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	dayMilliseconds := uint64((24 * time.Hour) / time.Millisecond)
	acceptedAt := 60 * dayMilliseconds
	currentUptime := 100 * dayMilliseconds
	prepareAcceptanceCollectionPair(t, seed, acceptedAt)
	setAccumulatedUptimeMilliseconds(t, seed.opened.db, currentUptime)

	zero := EncodeUint64(0)
	transaction, err := seed.opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec("UPDATE record_revisions SET accepted_uptime_ms = ? WHERE revision_id = ?", zero[:], seed.revisionID); err != nil {
		transaction.Rollback()
		t.Fatal(err)
	}
	if _, err := transaction.Exec("UPDATE collection_candidates SET accepted_uptime_ms = ? WHERE revision_id = ?", zero[:], seed.revisionID); err != nil {
		transaction.Rollback()
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}

	stable := markerKeyDurableDigest(t, seed.opened.db)
	request := acceptanceOriginSyncRequest(t, seed, "e1000000-0000-4000-8000-000000000012", "4", nil)
	if response, protocolErr := seed.opened.HandleAPI(context.Background(), request); protocolErr == nil || protocolErr.Code != "internal_error" || !protocolErr.Retryable {
		t.Fatalf("premature collection response=%+v error=%v", response, protocolErr)
	}
	if after := markerKeyDurableDigest(t, seed.opened.db); after != stable {
		t.Fatalf("failed-closed collection changed durable state: before=%x after=%x", stable, after)
	}
	var retained int
	var generationBytes, originBytes []byte
	if err := seed.opened.db.QueryRow(`
		SELECT r.retained, s.collection_generation, a.accepted_uptime_ms
		FROM record_revisions r
		JOIN revision_acceptance_origins a USING (revision_id)
		CROSS JOIN runtime_state s
		WHERE r.revision_id = ? AND s.singleton = 1`, seed.revisionID,
	).Scan(&retained, &generationBytes, &originBytes); err != nil {
		t.Fatal(err)
	}
	generation, generationErr := DecodeUint64(generationBytes)
	origin, originErr := DecodeUint64(originBytes)
	if retained != 1 || generationErr != nil || generation != 0 || originErr != nil || origin != acceptedAt {
		t.Fatalf("rollback state retained=%d generation=%d generationErr=%v origin=%d originErr=%v", retained, generation, generationErr, origin, originErr)
	}
}

func TestCollectionUsesDurableAcceptanceAgeAtFullRetention(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	dayMilliseconds := uint64((24 * time.Hour) / time.Millisecond)
	acceptedAt := 60 * dayMilliseconds
	prepareAcceptanceCollectionPair(t, seed, acceptedAt)
	setAccumulatedUptimeMilliseconds(t, seed.opened.db, acceptedAt+uint64(minimumRetentionUptime/time.Millisecond))

	request := acceptanceOriginSyncRequest(t, seed, "e1000000-0000-4000-8000-000000000013", "4", nil)
	response, protocolErr := seed.opened.HandleAPI(context.Background(), request)
	if protocolErr != nil || response.Status != 200 {
		seed.opened.Close()
		t.Fatalf("valid collection response=%+v error=%v", response, protocolErr)
	}
	var retained, candidates int
	var generationBytes, originBytes []byte
	if err := seed.opened.db.QueryRow(`
		SELECT r.retained, s.collection_generation, a.accepted_uptime_ms,
		       (SELECT count(*) FROM collection_candidates q WHERE q.revision_id = r.revision_id)
		FROM record_revisions r
		JOIN revision_acceptance_origins a USING (revision_id)
		CROSS JOIN runtime_state s
		WHERE r.revision_id = ? AND s.singleton = 1`, seed.revisionID,
	).Scan(&retained, &generationBytes, &originBytes, &candidates); err != nil {
		seed.opened.Close()
		t.Fatal(err)
	}
	generation, generationErr := DecodeUint64(generationBytes)
	origin, originErr := DecodeUint64(originBytes)
	if retained != 0 || candidates != 0 || generationErr != nil || generation != 1 || originErr != nil || origin != acceptedAt {
		seed.opened.Close()
		t.Fatalf("valid collection retained=%d candidates=%d generation=%d generationErr=%v origin=%d originErr=%v", retained, candidates, generation, generationErr, origin, originErr)
	}
	if err := seed.opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), seed.path, testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.db.QueryRow(`
		SELECT a.accepted_uptime_ms FROM revision_acceptance_origins a
		JOIN record_revisions r USING (revision_id)
		WHERE a.revision_id = ? AND r.retained = 0`, seed.revisionID,
	).Scan(&originBytes); err != nil {
		t.Fatal(err)
	}
	if origin, err := DecodeUint64(originBytes); err != nil || origin != acceptedAt {
		t.Fatalf("reopened collected origin=%d error=%v", origin, err)
	}
}

func TestStartupRejectsRevisionAcceptanceOriginCorruption(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, boundedPersistenceSeed)
	}{
		{
			name: "mismatched age",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				one := EncodeUint64(1)
				if _, err := seed.opened.db.Exec("UPDATE revision_acceptance_origins SET accepted_uptime_ms = ? WHERE revision_id = ?", one[:], seed.revisionID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing origin",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				if _, err := seed.opened.db.Exec("DELETE FROM revision_acceptance_origins WHERE revision_id = ?", seed.revisionID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "orphan origin",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				zero := EncodeUint64(0)
				if _, err := seed.opened.db.Exec(`
					INSERT INTO revision_acceptance_origins (revision_id, accepted_uptime_ms)
					VALUES ('e1000000-0000-4000-8000-0000000000ff', ?)`, zero[:]); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{})
			test.mutate(t, seed)
			if err := seed.opened.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(context.Background(), seed.path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) {
				t.Fatalf("corrupt acceptance-origin startup error=%v", err)
			}
		})
	}
}

func dropRevisionAcceptanceOriginsForMigration(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec("DROP TABLE revision_acceptance_origins"); err != nil {
		t.Fatal(err)
	}
	kind, version, err := inspectSchemaState(context.Background(), database)
	if err != nil || kind != schemaPriorAcceptanceOrigin || version != SchemaVersion {
		t.Fatalf("prior acceptance-origin schema inspection: kind=%d version=%d error=%v", kind, version, err)
	}
}

func TestAcceptanceOriginMigrationRebasesBothExactPriorSchemas(t *testing.T) {
	tests := []struct {
		name           string
		oldRevisionDDL bool
	}{
		{name: "80760f exact schema"},
		{name: "704f exact schema", oldRevisionDDL: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{})
			current := uint64((100 * 24 * time.Hour) / time.Millisecond)
			setAccumulatedUptimeMilliseconds(t, seed.opened.db, current)
			if test.oldRevisionDDL {
				downgradeRecordRevisionsToPriorFullV1(t, seed.opened.db)
			} else {
				dropRevisionAcceptanceOriginsForMigration(t, seed.opened.db)
			}
			if err := seed.opened.Close(); err != nil {
				t.Fatal(err)
			}

			opened, err := Open(context.Background(), seed.path, testIdentity)
			if err != nil {
				t.Fatal(err)
			}
			var revisionBytes, candidateBytes, originBytes []byte
			if err := opened.db.QueryRow(`
				SELECT r.accepted_uptime_ms, q.accepted_uptime_ms, a.accepted_uptime_ms
				FROM record_revisions r
				JOIN collection_candidates q USING (revision_id)
				JOIN revision_acceptance_origins a USING (revision_id)
				WHERE r.revision_id = ?`, seed.revisionID,
			).Scan(&revisionBytes, &candidateBytes, &originBytes); err != nil {
				opened.Close()
				t.Fatal(err)
			}
			for name, encoded := range map[string][]byte{"revision": revisionBytes, "candidate": candidateBytes, "origin": originBytes} {
				value, err := DecodeUint64(encoded)
				if err != nil || value != current {
					opened.Close()
					t.Fatalf("migrated %s age=%d error=%v, want=%d", name, value, err, current)
				}
			}
			kind, version, err := inspectSchemaState(context.Background(), opened.db)
			if err != nil || kind != schemaFull || version != SchemaVersion {
				opened.Close()
				t.Fatalf("migrated schema inspection: kind=%d version=%d error=%v", kind, version, err)
			}
			if err := opened.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(context.Background(), seed.path, testIdentity)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if err := reopened.db.QueryRow("SELECT accepted_uptime_ms FROM revision_acceptance_origins WHERE revision_id = ?", seed.revisionID).Scan(&originBytes); err != nil {
				t.Fatal(err)
			}
			if value, err := DecodeUint64(originBytes); err != nil || value != current {
				t.Fatalf("reopened migrated origin=%d error=%v, want=%d", value, err, current)
			}
		})
	}
}

func TestAcceptanceOriginMigrationRollsBackAfterValidationFailure(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	dropRevisionAcceptanceOriginsForMigration(t, seed.opened.db)
	corruptRecordID := seed.recordID + "\x00suffix"
	if _, err := seed.opened.db.Exec("UPDATE record_revisions SET record_id = ? WHERE revision_id = ?", corruptRecordID, seed.revisionID); err != nil {
		seed.opened.Close()
		t.Fatal(err)
	}
	stable := markerKeyDurableDigest(t, seed.opened.db)
	if err := seed.opened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), seed.path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) {
		t.Fatalf("failed migration error=%v", err)
	}
	raw, err := sql.Open("sqlite3", "file:"+seed.path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if after := markerKeyDurableDigest(t, raw); after != stable {
		t.Fatalf("failed migration changed durable state: before=%x after=%x", stable, after)
	}
	kind, version, err := inspectSchemaState(context.Background(), raw)
	if err != nil || kind != schemaPriorAcceptanceOrigin || version != SchemaVersion {
		t.Fatalf("rolled-back schema inspection: kind=%d version=%d error=%v", kind, version, err)
	}
}

func TestAcceptanceOriginMigrationRejectsNoncanonicalCurrentUptime(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	dropRevisionAcceptanceOriginsForMigration(t, seed.opened.db)
	mutateValidationOwnerWrongType(t, seed.opened.db, "runtime_state",
		"UPDATE runtime_state SET accumulated_uptime_ms = CAST(? AS TEXT) WHERE singleton = 1", "12345678")
	stable := markerKeyDurableDigest(t, seed.opened.db)
	if err := seed.opened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), seed.path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) {
		t.Fatalf("noncanonical migration uptime error=%v", err)
	}
	raw, err := sql.Open("sqlite3", "file:"+seed.path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if after := markerKeyDurableDigest(t, raw); after != stable {
		t.Fatalf("rejected noncanonical migration changed durable state: before=%x after=%x", stable, after)
	}
	var storageClass string
	if err := raw.QueryRow("SELECT typeof(accumulated_uptime_ms) FROM runtime_state WHERE singleton = 1").Scan(&storageClass); err != nil {
		t.Fatal(err)
	}
	if storageClass != "text" {
		t.Fatalf("rejected migration healed uptime storage class=%q", storageClass)
	}
}

func TestCollectionAcceptanceOriginLookupPlanIsBounded(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	cutoff := EncodeUint64(0)
	rows, err := opened.db.Query("EXPLAIN QUERY PLAN "+collectionCandidatesSQL,
		maxUUIDBytes, maxUUIDBytes, maxVectorBytes,
		"e1000000-0000-4000-8000-000000000006", cutoff[:], collectionCandidateBatch,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var candidateRange, revisionLookup, originLookup bool
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(detail, "SCAN q") || strings.Contains(detail, "SCAN collection_candidates") || strings.Contains(detail, "USE TEMP B-TREE") || strings.Contains(detail, "AUTOMATIC") {
			t.Fatalf("unbounded collection candidate plan: %s", detail)
		}
		candidateRange = candidateRange || strings.Contains(detail, "SEARCH q ") && strings.Contains(detail, "record_id=?") && strings.Contains(detail, "accepted_uptime_ms<?")
		revisionLookup = revisionLookup || strings.Contains(detail, "SEARCH r ") && strings.Contains(detail, "revision_id=?")
		originLookup = originLookup || strings.Contains(detail, "SEARCH a ") && strings.Contains(detail, "revision_id=?")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !candidateRange || !revisionLookup || !originLookup {
		t.Fatalf("bounded lookups: candidates=%v revisions=%v origins=%v", candidateRange, revisionLookup, originLookup)
	}
}
