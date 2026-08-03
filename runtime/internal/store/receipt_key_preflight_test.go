package store

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
)

type receiptKeyPreflightDeviceState struct {
	tokenHash        []byte
	createdAt        int64
	revokedAt        sql.NullInt64
	lastSyncAt       sql.NullInt64
	ackCursor        []byte
	maxAuthorCounter []byte
	createdCursor    []byte
	revokedCursor    []byte
}

type receiptKeyPreflightState struct {
	serverCursor, cursorFloor, envelopeGeneration []byte
	secretGeneration, collectionGeneration        []byte
	accumulatedUptime                             []byte
	counts                                        [14]int
	devices                                       []receiptKeyPreflightDeviceState
}

func readReceiptKeyPreflightState(t *testing.T, database *sql.DB, deviceIDs ...string) receiptKeyPreflightState {
	t.Helper()
	var state receiptKeyPreflightState
	arguments := []any{
		&state.serverCursor, &state.cursorFloor, &state.envelopeGeneration,
		&state.secretGeneration, &state.collectionGeneration, &state.accumulatedUptime,
	}
	for index := range state.counts {
		arguments = append(arguments, &state.counts[index])
	}
	if err := database.QueryRow(`
		SELECT server_cursor, cursor_floor, envelope_generation,
		       instance_secret_generation, collection_generation, accumulated_uptime_ms,
		       (SELECT count(*) FROM devices),
		       (SELECT count(*) FROM device_origins),
		       (SELECT count(*) FROM device_sync_state),
		       (SELECT count(*) FROM enrollments),
		       (SELECT count(*) FROM enrollment_grants),
		       (SELECT count(*) FROM record_revisions),
		       (SELECT count(*) FROM changes),
		       (SELECT count(*) FROM change_origins),
		       (SELECT count(*) FROM operation_receipts),
		       (SELECT count(*) FROM operation_receipt_retention),
		       (SELECT count(*) FROM self_revocation_receipts),
		       (SELECT count(*) FROM snapshots),
		       (SELECT count(*) FROM snapshot_pages),
		       (SELECT count(*) FROM snapshot_revision_refs)
		FROM runtime_state WHERE singleton = 1`,
	).Scan(arguments...); err != nil {
		t.Fatal(err)
	}
	for _, deviceID := range deviceIDs {
		var device receiptKeyPreflightDeviceState
		if err := database.QueryRow(`
			SELECT d.token_hash, d.created_at_ms, d.revoked_at_ms, d.last_sync_at_ms,
			       d.last_ack_cursor, d.max_author_counter,
			       o.created_cursor, o.revoked_cursor
			FROM devices d JOIN device_origins o USING (device_id)
			WHERE d.device_id = ?`, deviceID,
		).Scan(
			&device.tokenHash, &device.createdAt, &device.revokedAt, &device.lastSyncAt,
			&device.ackCursor, &device.maxAuthorCounter, &device.createdCursor, &device.revokedCursor,
		); err != nil {
			t.Fatal(err)
		}
		state.devices = append(state.devices, device)
	}
	return state
}

func assertReceiptKeyPreflightStateUnchanged(t *testing.T, before, after receiptKeyPreflightState) {
	t.Helper()
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("durable state changed: before=%+v after=%+v", before, after)
	}
}

func writeReceiptKeyWrongType(t *testing.T, database *sql.DB, update string, arguments ...any) {
	t.Helper()
	const table = "operation_receipts"
	var originalSchema string
	if err := database.QueryRow("SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?", table).Scan(&originalSchema); err != nil {
		t.Fatal(err)
	}
	nonstrictSchema := strings.TrimSuffix(originalSchema, " STRICT")
	if nonstrictSchema == originalSchema {
		t.Fatal("operation_receipts schema is not STRICT")
	}
	var schemaVersion int
	if err := database.QueryRow("PRAGMA schema_version").Scan(&schemaVersion); err != nil {
		t.Fatal(err)
	}
	rewrite := func(schema string, version int) {
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
	if _, err := database.Exec(update, arguments...); err != nil {
		t.Fatal(err)
	}
	rewrite(originalSchema, schemaVersion+2)
}

func removeReceiptRetentionSequenceUniqueness(t *testing.T, database *sql.DB) {
	t.Helper()
	withoutSequenceUnique := strings.Replace(createOperationReceiptRetentionV1, ",\n\t\t\tUNIQUE (receipt_sequence)", "", 1)
	if withoutSequenceUnique == createOperationReceiptRetentionV1 {
		t.Fatal("receipt retention schema does not contain sequence uniqueness")
	}
	transaction, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	if _, err := transaction.Exec("ALTER TABLE operation_receipt_retention RENAME TO operation_receipt_retention_original"); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(withoutSequenceUnique); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(`
		INSERT INTO operation_receipt_retention (
			device_id, receipt_class, receipt_sequence, created_uptime_ms
		)
		SELECT device_id, receipt_class, receipt_sequence, created_uptime_ms
		FROM operation_receipt_retention_original`); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec("DROP TABLE operation_receipt_retention_original"); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
}

func expectReceiptKeyPreflightError(t *testing.T, opened *Store, call api.Request, code string) {
	t.Helper()
	if _, protocolErr := opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != code {
		t.Fatalf("receipt-key preflight error=%v, want=%s", protocolErr, code)
	}
}

func receiptKeyQueryPlan(t *testing.T, database *sql.DB, query string, arguments ...any) string {
	t.Helper()
	rows, err := database.Query("EXPLAIN QUERY PLAN "+query, arguments...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(details, "\n")
}

func TestOperationReceiptKeyPreflightUsesBoundedIndexes(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	deviceID := "f7300000-0000-4000-8000-000000000001"
	requestID := "f7300000-0000-4000-8000-000000000002"
	deviceTextLower, deviceTextUpper, deviceBlobLower, deviceBlobUpper := receiptKeyPrefixBounds(deviceID)
	requestTextLower, requestTextUpper, requestBlobLower, requestBlobUpper := receiptKeyPrefixBounds(requestID)
	for _, test := range []struct {
		name             string
		query            string
		arguments        []any
		want             []string
		coveringSearches int
	}{
		{
			name:  "independent device aliases",
			query: receiptDeviceAliasProbeQuery,
			arguments: []any{
				deviceTextLower, deviceTextUpper, deviceBlobLower, deviceBlobUpper,
			},
			want:             []string{"USING COVERING INDEX", "(device_id>? AND device_id<?)"},
			coveringSearches: 2,
		},
		{
			name:  "independent request aliases",
			query: receiptRequestAliasProbeQuery,
			arguments: []any{
				requestTextLower, requestTextUpper, requestBlobLower, requestBlobUpper,
			},
			want:             []string{"USING COVERING INDEX", "(request_id>? AND request_id<?)"},
			coveringSearches: 2,
		},
		{
			name:  "device then request prefix",
			query: receiptDeviceRequestCandidateQuery,
			arguments: []any{
				deviceID, requestTextLower, requestTextUpper,
				deviceID, requestBlobLower, requestBlobUpper,
			},
			want:             []string{"USING COVERING INDEX", "(device_id=? AND request_id>? AND request_id<?)"},
			coveringSearches: 2,
		},
		{
			name:  "request then device prefix",
			query: receiptRequestDeviceCandidateQuery,
			arguments: []any{
				requestID, deviceTextLower, deviceTextUpper,
				requestID, deviceBlobLower, deviceBlobUpper,
			},
			want:             []string{"USING COVERING INDEX", "(request_id=? AND device_id>? AND device_id<?)"},
			coveringSearches: 2,
		},
		{
			name:             "fingerprint",
			query:            receiptFingerprintCandidateQuery,
			arguments:        []any{make([]byte, 32)},
			want:             []string{"USING COVERING INDEX", "(request_fingerprint=?)"},
			coveringSearches: 1,
		},
		{
			name:  "candidate retention mapping",
			query: receiptCandidateValidationQuery,
			arguments: []any{
				maxUUIDBytes, maxOperationBytes, maxUUIDBytes, maxUUIDBytes, 1,
			},
			want: []string{"USING INTEGER PRIMARY KEY (rowid=?)", "(receipt_sequence=?) LEFT-JOIN"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := receiptKeyQueryPlan(t, opened.db, test.query, test.arguments...)
			if strings.Contains(plan, "SCAN operation_receipts") || strings.Contains(plan, "SCAN operation_receipt_retention") || strings.Contains(plan, "AUTOMATIC") {
				t.Fatalf("unbounded receipt-key plan:\n%s", plan)
			}
			if searches := strings.Count(plan, "USING COVERING INDEX"); searches != test.coveringSearches {
				t.Fatalf("receipt-key covering searches=%d, want=%d:\n%s", searches, test.coveringSearches, plan)
			}
			for _, want := range test.want {
				if !strings.Contains(plan, want) {
					t.Fatalf("receipt-key plan missing %q:\n%s", want, plan)
				}
			}
		})
	}
}

func corruptReceiptDeviceAndRequestAliases(t *testing.T, database *sql.DB, operation, deviceID, requestID string, blob bool) {
	t.Helper()
	if blob {
		writeReceiptKeyWrongType(t, database, `
			UPDATE operation_receipts
			SET device_id = CAST(? AS BLOB), request_id = CAST(? AS BLOB)
			WHERE operation = ? AND device_id = ? AND request_id = ?`,
			deviceID, requestID, operation, deviceID, requestID)
		return
	}
	if _, err := database.Exec(`
		UPDATE operation_receipts SET device_id = ?, request_id = ?
		WHERE operation = ? AND device_id = ? AND request_id = ?`,
		deviceID+"\x00alias", requestID+"\x00alias", operation, deviceID, requestID,
	); err != nil {
		t.Fatal(err)
	}
}

func TestOperationReceiptKeyPreflightRejectsPairedDeviceAndRequestAliases(t *testing.T) {
	for _, blob := range []bool{false, true} {
		form := "NUL-suffixed TEXT"
		if blob {
			form = "BLOB-equivalent"
		}
		t.Run("sync/"+form, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{})
			defer seed.opened.Close()
			corruptReceiptDeviceAndRequestAliases(t, seed.opened.db, "sync", seed.deviceID, seed.sync.RequestID, blob)
			before := readReceiptKeyPreflightState(t, seed.opened.db, seed.deviceID)
			changed := boundedSyncCall(seed, seed.sync.RequestID, "0", nil)
			expectReceiptKeyPreflightError(t, seed.opened, changed, "internal_error")
			after := readReceiptKeyPreflightState(t, seed.opened.db, seed.deviceID)
			assertReceiptKeyPreflightStateUnchanged(t, before, after)
		})

		t.Run("vault envelope/"+form, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{})
			defer seed.opened.Close()
			requestID := "e1000000-0000-4000-8000-000000000004"
			corruptReceiptDeviceAndRequestAliases(t, seed.opened.db, "vault-envelope", seed.deviceID, requestID, blob)
			before := readReceiptKeyPreflightState(t, seed.opened.db, seed.deviceID)
			changed := validationOwnerEnvelopeCall(t, seed.token, requestID)
			expectReceiptKeyPreflightError(t, seed.opened, changed, "internal_error")
			after := readReceiptKeyPreflightState(t, seed.opened.db, seed.deviceID)
			assertReceiptKeyPreflightStateUnchanged(t, before, after)
		})

		t.Run("device revocation/"+form, func(t *testing.T) {
			opened, _ := openDataPlane(t)
			defer opened.Close()
			managerID := "f7330000-0000-4000-8000-000000000001"
			firstTargetID := "f7330000-0000-4000-8000-000000000002"
			secondTargetID := "f7330000-0000-4000-8000-000000000003"
			managerToken := tokenWithByte(0x76)
			enrollDevice(t, opened, protocolFixtureTime, "f7330000-0000-4000-8000-000000000004", managerID, "f7330000-0000-4000-8000-000000000005", managerToken)
			enrollDevice(t, opened, protocolFixtureTime, "f7330000-0000-4000-8000-000000000006", firstTargetID, "f7330000-0000-4000-8000-000000000007", tokenWithByte(0x77))
			enrollDevice(t, opened, protocolFixtureTime, "f7330000-0000-4000-8000-000000000008", secondTargetID, "f7330000-0000-4000-8000-000000000009", tokenWithByte(0x78))
			requestID := "f7330000-0000-4000-8000-00000000000a"
			first := revocationCall(t, firstTargetID, requestID, managerToken, false, protocolFixtureTime.Add(time.Second))
			if response, protocolErr := opened.HandleAPI(context.Background(), first); protocolErr != nil || response.Status != http.StatusOK {
				t.Fatalf("seed revocation: response=%+v error=%v", response, protocolErr)
			}
			operation := "device-revocation/" + firstTargetID
			corruptReceiptDeviceAndRequestAliases(t, opened.db, operation, managerID, requestID, blob)
			before := readReceiptKeyPreflightState(t, opened.db, managerID, firstTargetID, secondTargetID)
			changed := revocationCall(t, secondTargetID, requestID, managerToken, false, protocolFixtureTime.Add(2*time.Second))
			changed.Body = append(changed.Body, '\n')
			expectReceiptKeyPreflightError(t, opened, changed, "internal_error")
			after := readReceiptKeyPreflightState(t, opened.db, managerID, firstTargetID, secondTargetID)
			assertReceiptKeyPreflightStateUnchanged(t, before, after)
		})
	}
}

func TestOperationReceiptKeyPreflightRejectsInvalidProbeIdentifiers(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	transaction, err := opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	validDeviceID := "f7310000-0000-4000-8000-000000000001"
	validRequestID := "f7310000-0000-4000-8000-000000000002"
	for _, test := range []struct {
		name, deviceID, operation, requestID string
	}{
		{name: "empty device", operation: "sync", requestID: validRequestID},
		{name: "empty operation", deviceID: validDeviceID, requestID: validRequestID},
		{name: "empty request", deviceID: validDeviceID, operation: "sync"},
		{name: "invalid device", deviceID: "invalid", operation: "sync", requestID: validRequestID},
		{name: "invalid operation", deviceID: validDeviceID, operation: "invalid", requestID: validRequestID},
		{name: "invalid request", deviceID: validDeviceID, operation: "sync", requestID: "invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			protocolErr := preflightOperationReceiptKeys(context.Background(), transaction, test.deviceID, test.operation, test.requestID, [32]byte{})
			if protocolErr == nil || protocolErr.Code != "internal_error" {
				t.Fatalf("invalid receipt probe error=%v", protocolErr)
			}
		})
	}
}

func TestEnvelopeFingerprintCandidateAllowsFreshRequestToReachGenerationConflict(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	first := validationOwnerEnvelopeCall(t, seed.token, "f7320000-0000-4000-8000-000000000001")
	response, protocolErr := seed.opened.HandleAPI(context.Background(), first)
	if protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("commit stale-writer envelope body: response=%+v error=%v", response, protocolErr)
	}
	beforeOwner := readValidationOwnerEnvelopeState(t, seed.opened.db)
	beforeReceipt := readReceiptKeyPreflightState(t, seed.opened.db, seed.deviceID)
	stale := first
	stale.RequestID = "f7320000-0000-4000-8000-000000000002"
	if _, protocolErr := seed.opened.HandleAPI(context.Background(), stale); protocolErr == nil || protocolErr.Code != "generation_conflict" {
		t.Fatalf("fresh request ID stale-writer error=%v, want=generation_conflict", protocolErr)
	}
	afterOwner := readValidationOwnerEnvelopeState(t, seed.opened.db)
	afterReceipt := readReceiptKeyPreflightState(t, seed.opened.db, seed.deviceID)
	if beforeOwner != afterOwner {
		t.Fatalf("generation conflict changed envelope state: before=%+v after=%+v", beforeOwner, afterOwner)
	}
	assertReceiptKeyPreflightStateUnchanged(t, beforeReceipt, afterReceipt)
}

func TestOperationReceiptKeyPreflightRejectsMalformedCurrentDeviceKeys(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, boundedPersistenceSeed)
	}{
		{
			name: "NUL-suffixed request ID",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				corrupt := seed.sync.RequestID + "\x00" + strings.Repeat("x", maxBodyBytes+1)
				if _, err := seed.opened.db.Exec("UPDATE operation_receipts SET request_id = ? WHERE operation = 'sync'", corrupt); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "exact-length invalid request UUID",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				if _, err := seed.opened.db.Exec("UPDATE operation_receipts SET request_id = ? WHERE operation = 'sync'", "z7000000-0000-4000-8000-000000000001"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong-type request ID",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeReceiptKeyWrongType(t, seed.opened.db, "UPDATE operation_receipts SET request_id = zeroblob(?) WHERE operation = 'sync'", maxUUIDBytes)
			},
		},
		{
			name: "NUL-suffixed device ID",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				corrupt := seed.deviceID + "\x00" + strings.Repeat("x", maxBodyBytes+1)
				if _, err := seed.opened.db.Exec("UPDATE operation_receipts SET device_id = ? WHERE operation = 'sync'", corrupt); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "NUL-suffixed operation",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				corrupt := "sync\x00" + strings.Repeat("x", maxBodyBytes+1)
				if _, err := seed.opened.db.Exec("UPDATE operation_receipts SET operation = ? WHERE operation = 'sync'", corrupt); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{})
			defer seed.opened.Close()
			test.mutate(t, seed)
			before := readReceiptKeyPreflightState(t, seed.opened.db, seed.deviceID)
			expectReceiptKeyPreflightError(t, seed.opened, seed.sync, "internal_error")
			after := readReceiptKeyPreflightState(t, seed.opened.db, seed.deviceID)
			assertReceiptKeyPreflightStateUnchanged(t, before, after)
		})
	}
}

func TestOperationReceiptKeyPreflightPreservesCanonicalAbsenceReplayAndReuse(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	call := boundedSyncCall(seed, "f7100000-0000-4000-8000-000000000001", "0", nil)
	created, protocolErr := seed.opened.HandleAPI(context.Background(), call)
	if protocolErr != nil || created.Status != http.StatusOK {
		t.Fatalf("canonical receipt absence: response=%+v error=%v", created, protocolErr)
	}
	afterCreate := readReceiptKeyPreflightState(t, seed.opened.db, seed.deviceID)
	replayed, protocolErr := seed.opened.HandleAPI(context.Background(), call)
	if protocolErr != nil || replayed.Status != http.StatusOK || !bytes.Equal(replayed.Body, created.Body) {
		t.Fatalf("canonical receipt replay: response=%+v error=%v", replayed, protocolErr)
	}
	afterReplay := readReceiptKeyPreflightState(t, seed.opened.db, seed.deviceID)
	assertReceiptKeyPreflightStateUnchanged(t, afterCreate, afterReplay)

	mismatch := call
	mismatch.Body = append(append([]byte(nil), call.Body...), '\n')
	expectReceiptKeyPreflightError(t, seed.opened, mismatch, "request_id_reused")
	afterReuse := readReceiptKeyPreflightState(t, seed.opened.db, seed.deviceID)
	assertReceiptKeyPreflightStateUnchanged(t, afterCreate, afterReuse)
}

func TestOperationReceiptKeyPreflightBlocksCorruptCrossTargetRevocationReuse(t *testing.T) {
	for _, test := range []struct {
		name      string
		corrupt   func(*testing.T, *sql.DB, string)
		wantError string
	}{
		{
			name:      "canonical control",
			corrupt:   func(*testing.T, *sql.DB, string) {},
			wantError: "request_id_reused",
		},
		{
			name: "NUL-suffixed request ID",
			corrupt: func(t *testing.T, database *sql.DB, requestID string) {
				value := requestID + "\x00" + strings.Repeat("x", maxBodyBytes+1)
				if _, err := database.Exec("UPDATE operation_receipts SET request_id = ? WHERE request_id = ?", value, requestID); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "internal_error",
		},
		{
			name: "different valid request UUID",
			corrupt: func(t *testing.T, database *sql.DB, requestID string) {
				if _, err := database.Exec("UPDATE operation_receipts SET request_id = ? WHERE request_id = ?",
					"f7200000-0000-4000-8000-00000000000c", requestID); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "internal_error",
		},
		{
			name: "different valid request with masquerading envelope operation",
			corrupt: func(t *testing.T, database *sql.DB, requestID string) {
				if _, err := database.Exec(`
					UPDATE operation_receipts SET request_id = ?, operation = 'vault-envelope'
					WHERE request_id = ?`, "f7200000-0000-4000-8000-00000000000c", requestID); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "internal_error",
		},
		{
			name: "exact-length invalid request UUID",
			corrupt: func(t *testing.T, database *sql.DB, requestID string) {
				if _, err := database.Exec("UPDATE operation_receipts SET request_id = ? WHERE request_id = ?", "z7200000-0000-4000-8000-000000000001", requestID); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "internal_error",
		},
		{
			name: "NUL-suffixed retention device ID",
			corrupt: func(t *testing.T, database *sql.DB, requestID string) {
				var deviceID string
				if err := database.QueryRow(`
					SELECT q.device_id FROM operation_receipt_retention q
					JOIN operation_receipts r USING (receipt_sequence)
					WHERE r.request_id = ?`, requestID).Scan(&deviceID); err != nil {
					t.Fatal(err)
				}
				if _, err := database.Exec(`
					UPDATE operation_receipt_retention SET device_id = ?
					WHERE receipt_sequence = (SELECT receipt_sequence FROM operation_receipts WHERE request_id = ?)`,
					deviceID+"\x00"+strings.Repeat("x", maxBodyBytes+1), requestID); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "internal_error",
		},
		{
			name: "different retention device ID",
			corrupt: func(t *testing.T, database *sql.DB, requestID string) {
				if _, err := database.Exec(`
					UPDATE operation_receipt_retention SET device_id = ?
					WHERE receipt_sequence = (SELECT receipt_sequence FROM operation_receipts WHERE request_id = ?)`,
					"f7200000-0000-4000-8000-00000000000b", requestID); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "internal_error",
		},
		{
			name: "missing retention mapping",
			corrupt: func(t *testing.T, database *sql.DB, requestID string) {
				if _, err := database.Exec(`
					DELETE FROM operation_receipt_retention
					WHERE receipt_sequence = (SELECT receipt_sequence FROM operation_receipts WHERE request_id = ?)`, requestID); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "internal_error",
		},
		{
			name: "unjoined retention mapping",
			corrupt: func(t *testing.T, database *sql.DB, requestID string) {
				if _, err := database.Exec(`
					UPDATE operation_receipt_retention SET receipt_sequence = receipt_sequence + 1000000
					WHERE receipt_sequence = (SELECT receipt_sequence FROM operation_receipts WHERE request_id = ?)`, requestID); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "internal_error",
		},
		{
			name: "duplicate retention mapping",
			corrupt: func(t *testing.T, database *sql.DB, requestID string) {
				removeReceiptRetentionSequenceUniqueness(t, database)
				if _, err := database.Exec(`
					INSERT INTO operation_receipt_retention (
						device_id, receipt_class, receipt_sequence, created_uptime_ms
					)
					SELECT device_id,
					       CASE receipt_class WHEN 'sync' THEN 'other' ELSE 'sync' END,
					       receipt_sequence, created_uptime_ms
					FROM operation_receipt_retention
					WHERE receipt_sequence = (SELECT receipt_sequence FROM operation_receipts WHERE request_id = ?)`, requestID); err != nil {
					t.Fatal(err)
				}
			},
			wantError: "internal_error",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			opened, _ := openDataPlane(t)
			defer opened.Close()
			managerID := "f7200000-0000-4000-8000-000000000001"
			firstTargetID := "f7200000-0000-4000-8000-000000000002"
			secondTargetID := "f7200000-0000-4000-8000-000000000003"
			managerToken := tokenWithByte(0x72)
			enrollDevice(t, opened, protocolFixtureTime, "f7200000-0000-4000-8000-000000000004", managerID, "f7200000-0000-4000-8000-000000000005", managerToken)
			enrollDevice(t, opened, protocolFixtureTime, "f7200000-0000-4000-8000-000000000006", firstTargetID, "f7200000-0000-4000-8000-000000000007", tokenWithByte(0x73))
			enrollDevice(t, opened, protocolFixtureTime, "f7200000-0000-4000-8000-000000000008", secondTargetID, "f7200000-0000-4000-8000-000000000009", tokenWithByte(0x74))

			requestID := "f7200000-0000-4000-8000-00000000000a"
			body, _ := marshalJSON(revokeDeviceRequest{RequestID: requestID})
			first := api.Request{
				Method: "POST", Path: "/v1/devices/" + firstTargetID + "/revoke", RequestID: requestID,
				Authorization: authorization(managerToken), Body: body, Now: protocolFixtureTime.Add(time.Second),
			}
			if response, protocolErr := opened.HandleAPI(context.Background(), first); protocolErr != nil || response.Status != http.StatusOK {
				t.Fatalf("seed first revocation: response=%+v error=%v", response, protocolErr)
			}
			test.corrupt(t, opened.db, requestID)
			before := readReceiptKeyPreflightState(t, opened.db, managerID, firstTargetID, secondTargetID)
			second := first
			second.Path = "/v1/devices/" + secondTargetID + "/revoke"
			expectReceiptKeyPreflightError(t, opened, second, test.wantError)
			after := readReceiptKeyPreflightState(t, opened.db, managerID, firstTargetID, secondTargetID)
			assertReceiptKeyPreflightStateUnchanged(t, before, after)
			if after.devices[2].revokedAt.Valid {
				t.Fatal("cross-target reuse revoked the second target")
			}
		})
	}
}
