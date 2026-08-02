package store

import (
	"context"
	"database/sql"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
)

type snapshotKeyStoredRow struct {
	snapshotID, ownerHex, ownerType, requestHex, requestType string
	ownerLength, requestLength                               int64
	expiresAt, metadataBytes                                 int64
	responseHex                                              string
}

type snapshotKeyPreflightState struct {
	serverCursor, maxReturned []byte
	pageCount, referenceCount int
	rows                      []snapshotKeyStoredRow
	deadlines                 map[string]time.Time
	attempts                  []time.Time
}

func readSnapshotKeyPreflightState(t *testing.T, seed boundedPersistenceSeed) snapshotKeyPreflightState {
	t.Helper()
	var state snapshotKeyPreflightState
	if err := seed.opened.db.QueryRow(`
		SELECT r.server_cursor, d.max_returned_cursor,
		       (SELECT count(*) FROM snapshot_pages),
		       (SELECT count(*) FROM snapshot_revision_refs)
		FROM runtime_state r JOIN device_sync_state d
		WHERE r.singleton = 1 AND d.device_id = ?`, seed.deviceID,
	).Scan(&state.serverCursor, &state.maxReturned, &state.pageCount, &state.referenceCount); err != nil {
		t.Fatal(err)
	}
	rows, err := seed.opened.db.Query(`
		SELECT snapshot_id,
		       hex(CAST(owner_device_id AS BLOB)), typeof(owner_device_id), octet_length(owner_device_id),
		       hex(CAST(request_id AS BLOB)), typeof(request_id), octet_length(request_id),
		       expires_at_ms, metadata_bytes, hex(create_response_json)
		FROM snapshots ORDER BY snapshot_id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var row snapshotKeyStoredRow
		if err := rows.Scan(
			&row.snapshotID,
			&row.ownerHex, &row.ownerType, &row.ownerLength,
			&row.requestHex, &row.requestType, &row.requestLength,
			&row.expiresAt, &row.metadataBytes, &row.responseHex,
		); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		state.rows = append(state.rows, row)
	}
	iterationErr := rows.Err()
	closeErr := rows.Close()
	if iterationErr != nil || closeErr != nil {
		t.Fatalf("read snapshot-key state: iteration=%v close=%v", iterationErr, closeErr)
	}
	seed.opened.ephemeral.mu.Lock()
	state.deadlines = make(map[string]time.Time, len(seed.opened.ephemeral.snapshotDeadlines))
	for snapshotID, deadline := range seed.opened.ephemeral.snapshotDeadlines {
		state.deadlines[snapshotID] = deadline
	}
	state.attempts = append([]time.Time(nil), seed.opened.ephemeral.snapshotAttempts[seed.deviceID]...)
	seed.opened.ephemeral.mu.Unlock()
	return state
}

type snapshotKeyStorage int

const (
	snapshotKeyCanonicalText snapshotKeyStorage = iota
	snapshotKeyNULText
	snapshotKeyCanonicalBlob
	snapshotKeyNULBlob
)

func snapshotKeyMutationValue(value string, storage snapshotKeyStorage) (expression string, argument any, wrongType, ignoresChecks bool) {
	switch storage {
	case snapshotKeyCanonicalText:
		return "?", value, false, false
	case snapshotKeyNULText:
		return "?", oversizedNULSuffixedText(value), false, false
	case snapshotKeyCanonicalBlob:
		return "CAST(? AS BLOB)", value, true, false
	case snapshotKeyNULBlob:
		return "CAST(? AS BLOB)", oversizedNULSuffixedText(value), true, true
	default:
		panic("unsupported snapshot key storage")
	}
}

func corruptSnapshotOwnerRequestKeys(t *testing.T, seed boundedPersistenceSeed, ownerStorage, requestStorage snapshotKeyStorage) {
	t.Helper()
	ownerExpression, ownerArgument, ownerWrongType, ownerIgnoresChecks := snapshotKeyMutationValue(seed.deviceID, ownerStorage)
	requestExpression, requestArgument, requestWrongType, requestIgnoresChecks := snapshotKeyMutationValue(seed.snapshotCreate.RequestID, requestStorage)
	statement := "UPDATE snapshots SET owner_device_id = " + ownerExpression + ", request_id = " + requestExpression + " WHERE snapshot_id = ?"
	arguments := []any{ownerArgument, requestArgument, seed.snapshot.SnapshotID}
	if ownerIgnoresChecks || requestIgnoresChecks {
		if _, err := seed.opened.db.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := seed.opened.db.Exec("PRAGMA ignore_check_constraints = OFF"); err != nil {
				t.Fatal(err)
			}
		}()
	}
	if ownerWrongType || requestWrongType {
		writeLiveWrongTypeText(t, seed.opened.db, "snapshots", statement, arguments...)
		return
	}
	if _, err := seed.opened.db.Exec(statement, arguments...); err != nil {
		t.Fatal(err)
	}
}

func expectSnapshotKeyPreflightFailureWithoutMutation(t *testing.T, seed boundedPersistenceSeed, callNow time.Time) {
	t.Helper()
	call := seed.snapshotCreate
	call.Now = callNow
	before := readSnapshotKeyPreflightState(t, seed)
	if _, protocolErr := seed.opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "internal_error" {
		t.Fatalf("snapshot-key preflight error=%v", protocolErr)
	}
	after := readSnapshotKeyPreflightState(t, seed)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("snapshot key failure changed durable or lease state: before=%+v after=%+v", before, after)
	}
}

func TestSnapshotOwnerRequestKeyPreflightRejectsAliasesWithoutMutation(t *testing.T) {
	tests := []struct {
		name                         string
		ownerStorage, requestStorage snapshotKeyStorage
	}{
		{name: "NUL TEXT owner exact TEXT request", ownerStorage: snapshotKeyNULText, requestStorage: snapshotKeyCanonicalText},
		{name: "BLOB owner exact TEXT request", ownerStorage: snapshotKeyCanonicalBlob, requestStorage: snapshotKeyCanonicalText},
		{name: "NUL BLOB owner exact TEXT request", ownerStorage: snapshotKeyNULBlob, requestStorage: snapshotKeyCanonicalText},
		{name: "exact TEXT owner NUL TEXT request", ownerStorage: snapshotKeyCanonicalText, requestStorage: snapshotKeyNULText},
		{name: "exact TEXT owner BLOB request", ownerStorage: snapshotKeyCanonicalText, requestStorage: snapshotKeyCanonicalBlob},
		{name: "exact TEXT owner NUL BLOB request", ownerStorage: snapshotKeyCanonicalText, requestStorage: snapshotKeyNULBlob},
		{name: "NUL TEXT owner NUL TEXT request", ownerStorage: snapshotKeyNULText, requestStorage: snapshotKeyNULText},
		{name: "BLOB owner BLOB request", ownerStorage: snapshotKeyCanonicalBlob, requestStorage: snapshotKeyCanonicalBlob},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{})
			defer seed.opened.Close()
			corruptSnapshotOwnerRequestKeys(t, seed, test.ownerStorage, test.requestStorage)
			expectSnapshotKeyPreflightFailureWithoutMutation(t, seed, protocolFixtureTime.Add(time.Second))
		})
	}
}

func TestSnapshotOwnerRequestKeyPreflightPrecedesRateLimitAndPrune(t *testing.T) {
	t.Run("rate limit", func(t *testing.T) {
		seed := seedBoundedPersistence(t, boundedSeedOptions{})
		defer seed.opened.Close()
		corruptSnapshotOwnerRequestKeys(t, seed, snapshotKeyNULText, snapshotKeyCanonicalText)
		seed.opened.ephemeral.mu.Lock()
		seed.opened.ephemeral.snapshotAttempts[seed.deviceID] = []time.Time{
			protocolFixtureTime, protocolFixtureTime, protocolFixtureTime,
			protocolFixtureTime, protocolFixtureTime,
		}
		seed.opened.ephemeral.mu.Unlock()
		expectSnapshotKeyPreflightFailureWithoutMutation(t, seed, protocolFixtureTime.Add(time.Second))
	})

	t.Run("expired lease prune", func(t *testing.T) {
		seed := seedBoundedPersistence(t, boundedSeedOptions{})
		defer seed.opened.Close()
		corruptSnapshotOwnerRequestKeys(t, seed, snapshotKeyCanonicalBlob, snapshotKeyCanonicalText)
		expectSnapshotKeyPreflightFailureWithoutMutation(t, seed, protocolFixtureTime.Add(snapshotLifetime+time.Second))
	})
}

func TestSnapshotOwnerRequestKeyPreflightPreservesAuthenticationOrdering(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	corruptSnapshotOwnerRequestKeys(t, seed, snapshotKeyNULText, snapshotKeyCanonicalText)

	for _, test := range []struct {
		name string
		call api.Request
		code string
	}{
		{
			name: "unauthorized",
			call: func() api.Request {
				call := seed.snapshotCreate
				call.Authorization = "JAT-Device invalid"
				return call
			}(),
			code: "unauthorized",
		},
		{
			name: "authenticated device mismatch",
			call: func() api.Request {
				call := seed.snapshotCreate
				body, err := marshalJSON(snapshotCreateRequest{
					ProtocolVersion: "1",
					DeviceID:        "f7540000-0000-4000-8000-000000000001",
					RequestID:       call.RequestID,
					RequiredCapabilities: append([]string(nil),
						requiredSnapshotCapabilities...),
				})
				if err != nil {
					t.Fatal(err)
				}
				call.Body = body
				return call
			}(),
			code: "authenticated_device_mismatch",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := readSnapshotKeyPreflightState(t, seed)
			if _, protocolErr := seed.opened.HandleAPI(context.Background(), test.call); protocolErr == nil || protocolErr.Code != test.code {
				t.Fatalf("snapshot authentication ordering error=%v, want=%s", protocolErr, test.code)
			}
			after := readSnapshotKeyPreflightState(t, seed)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("snapshot authentication failure changed state: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestSnapshotOwnerRequestKeyPreflightKeepsCompositeScope(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	transaction, err := seed.opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	otherRequestID := "f7500000-0000-4000-8000-000000000001"
	if protocolErr := preflightSnapshotOwnerKeys(context.Background(), transaction, seed.deviceID, otherRequestID); protocolErr != nil {
		t.Fatalf("different request for the same canonical owner: %v", protocolErr)
	}
	otherOwnerID := "f7500000-0000-4000-8000-000000000002"
	if protocolErr := preflightSnapshotOwnerKeys(context.Background(), transaction, otherOwnerID, seed.snapshotCreate.RequestID); protocolErr != nil {
		t.Fatalf("same request under an unrelated owner: %v", protocolErr)
	}
	if protocolErr := preflightSnapshotOwnerKeys(context.Background(), transaction, seed.deviceID, seed.snapshotCreate.RequestID); protocolErr == nil || protocolErr.Code != "internal_error" {
		t.Fatalf("exact pair after an authoritative miss error=%v", protocolErr)
	}
}

func TestSnapshotOwnerKeyProbeUsesBoundedCompositeIndex(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	ownerID := "f7510000-0000-4000-8000-000000000001"
	lowerBytes := []byte(ownerID)
	upperBytes := append([]byte(nil), lowerBytes...)
	upperBytes[len(upperBytes)-1]++
	rows, err := opened.db.Query("EXPLAIN QUERY PLAN "+snapshotOwnerKeyProbeSQL,
		maxUUIDBytes, maxUUIDBytes, ownerID, string(upperBytes),
		maxUUIDBytes, maxUUIDBytes, lowerBytes, upperBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	searches := 0
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if strings.Contains(detail, "SCAN snapshots") || strings.Contains(detail, "USE TEMP B-TREE") {
			rows.Close()
			t.Fatalf("unbounded snapshot owner-key probe: %s", detail)
		}
		if strings.Contains(detail, "SEARCH snapshots USING COVERING INDEX") &&
			strings.Contains(detail, "owner_device_id>?") && strings.Contains(detail, "owner_device_id<?") {
			searches++
		}
	}
	iterationErr := rows.Err()
	closeErr := rows.Close()
	if iterationErr != nil || closeErr != nil {
		t.Fatalf("explain snapshot owner-key probe: iteration=%v close=%v", iterationErr, closeErr)
	}
	if searches != 2 {
		t.Fatalf("snapshot owner-key indexed range searches=%d, want=2", searches)
	}
}

func TestSnapshotOwnerKeyProbeRejectsSecondCandidate(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	secondSnapshotID := "f7520000-0000-4000-8000-000000000001"
	secondRequestID := "f7520000-0000-4000-8000-000000000002"
	if _, err := seed.opened.db.Exec(`
		INSERT INTO snapshots (
			snapshot_id, owner_device_id, request_id, request_fingerprint,
			cut_cursor, envelope_generation, collection_generation,
			expires_at_ms, metadata_bytes, create_response_json
		)
		SELECT ?, owner_device_id, ?, request_fingerprint,
		       cut_cursor, envelope_generation, collection_generation,
		       expires_at_ms, metadata_bytes, create_response_json
		FROM snapshots WHERE snapshot_id = ?`, secondSnapshotID, secondRequestID, seed.snapshot.SnapshotID,
	); err != nil {
		t.Fatal(err)
	}
	transaction, err := seed.opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	if protocolErr := preflightSnapshotOwnerKeys(context.Background(), transaction, seed.deviceID,
		"f7520000-0000-4000-8000-000000000003"); protocolErr == nil || protocolErr.Code != "internal_error" {
		t.Fatalf("second owner candidate error=%v", protocolErr)
	}
}

func TestSnapshotOwnerKeyPreflightRejectsInvalidProbeIdentifiers(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	transaction, err := opened.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	valid := "f7530000-0000-4000-8000-000000000001"
	for _, test := range []struct {
		owner, request string
	}{
		{owner: "invalid", request: valid},
		{owner: valid, request: "invalid"},
	} {
		if protocolErr := preflightSnapshotOwnerKeys(context.Background(), transaction, test.owner, test.request); protocolErr == nil || protocolErr.Code != "internal_error" {
			t.Fatalf("invalid snapshot preflight identifiers owner=%q request=%q error=%v", test.owner, test.request, protocolErr)
		}
	}
}
