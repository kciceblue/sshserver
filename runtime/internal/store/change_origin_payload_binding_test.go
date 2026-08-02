package store

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
	"github.com/kciceblue/sshserver/runtime/internal/auth"
)

func expectOriginBindingRejectedWithoutEnvelopeMutation(t *testing.T, seed boundedPersistenceSeed, requestID string) {
	t.Helper()
	serverCursor, envelopeGeneration, _, _, err := validatePersistentRuntime(context.Background(), seed.opened.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validatePersistentChangeOrigins(context.Background(), seed.opened.db, serverCursor, envelopeGeneration, nil); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "origin") {
		t.Fatalf("permanent owner binding error=%v", err)
	}
	before := readValidationOwnerEnvelopeState(t, seed.opened.db)
	expectInternalError(t, seed.opened, validationOwnerEnvelopeCall(t, seed.token, requestID))
	after := readValidationOwnerEnvelopeState(t, seed.opened.db)
	if before != after {
		t.Fatalf("owner-binding envelope PUT mutated state: before=%+v after=%+v", before, after)
	}
}

func TestEnvelopePutRejectsPermanentOwnerPayloadMismatchWithoutMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, boundedPersistenceSeed)
	}{
		{
			name: "revision change valid ID mismatch",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerText(t, seed.opened.db,
					"UPDATE changes SET record_revision_id = ? WHERE kind = 'record_revision'",
					"e8380000-0000-4000-8000-000000000001")
			},
		},
		{
			name: "marker change valid ID mismatch",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerText(t, seed.opened.db,
					"UPDATE changes SET collection_marker_record_id = ? WHERE kind = 'collection_marker'",
					"e8380000-0000-4000-8000-000000000002")
			},
		},
		{
			name: "marker change body mismatch",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerText(t, seed.opened.db, `
					UPDATE changes
					SET collection_marker_json = CAST(collection_marker_json || x'00' AS BLOB)
					WHERE kind = 'collection_marker'`)
			},
		},
		{
			name: "current marker row missing",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerText(t, seed.opened.db, "DELETE FROM collection_markers WHERE record_id = ?", seed.recordID)
			},
		},
		{
			name: "current marker row canonical body mismatch",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				var body []byte
				if err := seed.opened.db.QueryRow("SELECT marker_json FROM collection_markers WHERE record_id = ?", seed.recordID).Scan(&body); err != nil {
					t.Fatal(err)
				}
				marker, err := decodeStoredCollectionMarker(body)
				if err != nil {
					t.Fatal(err)
				}
				marker.BarrierCursor = "0"
				mismatched, err := marshalJSON(marker)
				if err != nil {
					t.Fatal(err)
				}
				mutateValidationOwnerText(t, seed.opened.db,
					"UPDATE collection_markers SET marker_json = ? WHERE record_id = ?", mismatched, seed.recordID)
			},
		},
		{
			name: "revision owner missing",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerText(t, seed.opened.db, "DELETE FROM record_revisions WHERE revision_id = ?", seed.revisionID)
			},
		},
		{
			name: "revision owner swapped onto marker cursor",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerText(t, seed.opened.db, `
					UPDATE record_revisions
					SET change_cursor = (SELECT change_cursor FROM collection_markers)
					WHERE revision_id = ?`, seed.revisionID)
			},
		},
		{
			name: "enrollment change valid device mismatch",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerText(t, seed.opened.db,
					"UPDATE changes SET device_changed_id = ? WHERE device_change_kind = 'enrolled'",
					"e8380000-0000-4000-8000-000000000003")
			},
		},
		{
			name: "enrollment event kind flipped",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerText(t, seed.opened.db,
					"UPDATE changes SET device_change_kind = 'revoked' WHERE device_change_kind = 'enrolled'")
			},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{marker: true})
			defer seed.opened.Close()
			test.mutate(t, seed)
			requestID := "e8390000-0000-4000-8000-" + strings.Repeat("0", 11) + string(rune('1'+index))
			expectOriginBindingRejectedWithoutEnvelopeMutation(t, seed, requestID)
		})
	}
}

type twoMarkerAdvanceFixture struct {
	opened                    *Store
	deviceID, recordID        string
	token                     []byte
	firstCursor, latestCursor uint64
}

func handleMarkerLifecycleSync(t *testing.T, opened *Store, stage string, call api.Request) syncResponse {
	t.Helper()
	response, protocolErr := opened.HandleAPI(context.Background(), call)
	if protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("marker lifecycle %s sync: response=%+v error=%v", stage, response, protocolErr)
	}
	var decoded syncResponse
	if err := decodeStrict(response.Body, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func seedTwoMarkerAdvanceLifecycle(t *testing.T) twoMarkerAdvanceFixture {
	t.Helper()
	opened, _ := openDataPlane(t)
	fixture := twoMarkerAdvanceFixture{
		opened:   opened,
		deviceID: "e83f0000-0000-4000-8000-000000000001",
		recordID: "e83f0000-0000-4000-8000-000000000002",
		token:    tokenWithByte(0x91),
	}
	enrollDevice(t, opened, protocolFixtureTime,
		"e83f0000-0000-4000-8000-000000000003", fixture.deviceID,
		"e83f0000-0000-4000-8000-000000000004", fixture.token)
	var envelopeFixture struct {
		BaseMode putEnvelopeRequest `json:"base_mode"`
	}
	loadFixture(t, "vault-envelope.json", &envelopeFixture)
	envelopeBody, err := marshalJSON(envelopeFixture.BaseMode)
	if err != nil {
		t.Fatal(err)
	}
	if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "PUT", Path: "/v1/vault-envelope", RequestID: "e83f0000-0000-4000-8000-000000000005",
		Authorization: authorization(fixture.token), Body: envelopeBody, Now: protocolFixtureTime,
	}); protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("seed marker lifecycle envelope: response=%+v error=%v", response, protocolErr)
	}

	firstRevision := markerKeyRevision(fixture.deviceID, fixture.recordID,
		"e83f0000-0000-4000-8000-000000000006", 1, true, true)
	firstWrite := handleMarkerLifecycleSync(t, opened, "first write", markerKeySyncCall(t,
		fixture.deviceID, fixture.token, "e83f0000-0000-4000-8000-000000000007",
		"0", "0", []recordRevision{firstRevision}, protocolFixtureTime.Add(time.Second)))
	oneRetention := EncodeUint64(uint64(minimumRetentionUptime / time.Millisecond))
	if _, err := opened.db.Exec("UPDATE runtime_state SET accumulated_uptime_ms = ? WHERE singleton = 1", oneRetention[:]); err != nil {
		t.Fatal(err)
	}
	firstCollect := handleMarkerLifecycleSync(t, opened, "first collection", markerKeySyncCall(t,
		fixture.deviceID, fixture.token, "e83f0000-0000-4000-8000-000000000008",
		firstWrite.ServerCursor, firstWrite.ServerCursor, []recordRevision{}, protocolFixtureTime.Add(2*time.Second)))

	secondRevision := markerKeyRevision(fixture.deviceID, fixture.recordID,
		"e83f0000-0000-4000-8000-000000000009", 2, true, true)
	secondWrite := handleMarkerLifecycleSync(t, opened, "second write", markerKeySyncCall(t,
		fixture.deviceID, fixture.token, "e83f0000-0000-4000-8000-00000000000a",
		firstCollect.ServerCursor, firstCollect.ServerCursor, []recordRevision{secondRevision}, protocolFixtureTime.Add(3*time.Second)))
	twoRetentions := EncodeUint64(2 * uint64(minimumRetentionUptime/time.Millisecond))
	if _, err := opened.db.Exec("UPDATE runtime_state SET accumulated_uptime_ms = ? WHERE singleton = 1", twoRetentions[:]); err != nil {
		t.Fatal(err)
	}
	handleMarkerLifecycleSync(t, opened, "second collection", markerKeySyncCall(t,
		fixture.deviceID, fixture.token, "e83f0000-0000-4000-8000-00000000000b",
		secondWrite.ServerCursor, secondWrite.ServerCursor, []recordRevision{}, protocolFixtureTime.Add(4*time.Second)))

	var markerCount int
	var firstCursorBytes, latestCursorBytes []byte
	if err := opened.db.QueryRow(`
		SELECT count(*), min(c.cursor), max(c.cursor)
		FROM changes c
		WHERE c.kind = 'collection_marker' AND c.collection_marker_record_id = ?`, fixture.recordID,
	).Scan(&markerCount, &firstCursorBytes, &latestCursorBytes); err != nil {
		t.Fatal(err)
	}
	var decodeErr error
	fixture.firstCursor, decodeErr = DecodeUint64(firstCursorBytes)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	fixture.latestCursor, decodeErr = DecodeUint64(latestCursorBytes)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	var currentCursorBytes []byte
	if err := opened.db.QueryRow("SELECT change_cursor FROM collection_markers WHERE record_id = ?", fixture.recordID).Scan(&currentCursorBytes); err != nil {
		t.Fatal(err)
	}
	currentCursor, err := DecodeUint64(currentCursorBytes)
	if err != nil || markerCount != 2 || fixture.firstCursor >= fixture.latestCursor || currentCursor != fixture.latestCursor {
		t.Fatalf("two-marker lifecycle: count=%d first=%d latest=%d current=%d error=%v", markerCount, fixture.firstCursor, fixture.latestCursor, currentCursor, err)
	}
	return fixture
}

func TestPermanentMarkerOriginsAcceptTwoRealAdvances(t *testing.T) {
	fixture := seedTwoMarkerAdvanceLifecycle(t)
	defer fixture.opened.Close()
	if err := validatePersistentState(context.Background(), fixture.opened.db, testIdentity); err != nil {
		t.Fatalf("two-marker startup validation: %v", err)
	}
	serverCursor, envelopeGeneration, _, _, err := validatePersistentRuntime(context.Background(), fixture.opened.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validatePersistentChangeOrigins(context.Background(), fixture.opened.db, serverCursor, envelopeGeneration, nil); err != nil {
		t.Fatalf("two-marker origin validation: %v", err)
	}
	response, protocolErr := fixture.opened.HandleAPI(context.Background(), validationOwnerEnvelopeCall(
		t, fixture.token, "e83f0000-0000-4000-8000-00000000000c"))
	if protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("two-marker envelope PUT: response=%+v error=%v", response, protocolErr)
	}
}

func TestHistoricalMarkerOriginRejectsMalformedPayloadWithoutMutation(t *testing.T) {
	fixture := seedTwoMarkerAdvanceLifecycle(t)
	defer fixture.opened.Close()
	firstCursor := EncodeUint64(fixture.firstCursor)
	if _, err := fixture.opened.db.Exec(`
		UPDATE changes SET collection_marker_json = x'00'
		WHERE cursor = ? AND kind = 'collection_marker'`, firstCursor[:]); err != nil {
		t.Fatal(err)
	}
	seed := boundedPersistenceSeed{opened: fixture.opened, token: fixture.token}
	expectOriginBindingRejectedWithoutEnvelopeMutation(t, seed, "e83f0000-0000-4000-8000-00000000000d")
}

func markerLifecycleReturnedCursor(t *testing.T, fixture twoMarkerAdvanceFixture) string {
	t.Helper()
	var encoded []byte
	if err := fixture.opened.db.QueryRow(`
		SELECT s.max_returned_cursor
		FROM device_sync_state s WHERE s.device_id = ?`, fixture.deviceID).Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	cursor, err := DecodeUint64(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return encodeUint64Text(cursor)
}

func TestMarkerOwnerAtCursorRejectsCrossRecordRelocationWithoutMutation(t *testing.T) {
	fixture := seedTwoMarkerAdvanceLifecycle(t)
	defer fixture.opened.Close()
	secondRecordID := "e8400000-0000-4000-8000-000000000001"
	cursor := markerLifecycleReturnedCursor(t, fixture)
	thirdRevision := markerKeyRevision(fixture.deviceID, secondRecordID,
		"e8400000-0000-4000-8000-000000000002", 3, true, true)
	thirdWrite := handleMarkerLifecycleSync(t, fixture.opened, "second record first write", markerKeySyncCall(t,
		fixture.deviceID, fixture.token, "e8400000-0000-4000-8000-000000000003",
		cursor, cursor, []recordRevision{thirdRevision}, protocolFixtureTime.Add(5*time.Second)))
	threeRetentions := EncodeUint64(3 * uint64(minimumRetentionUptime/time.Millisecond))
	if _, err := fixture.opened.db.Exec("UPDATE runtime_state SET accumulated_uptime_ms = ? WHERE singleton = 1", threeRetentions[:]); err != nil {
		t.Fatal(err)
	}
	thirdCollect := handleMarkerLifecycleSync(t, fixture.opened, "second record first collection", markerKeySyncCall(t,
		fixture.deviceID, fixture.token, "e8400000-0000-4000-8000-000000000004",
		thirdWrite.ServerCursor, thirdWrite.ServerCursor, []recordRevision{}, protocolFixtureTime.Add(6*time.Second)))
	fourthRevision := markerKeyRevision(fixture.deviceID, secondRecordID,
		"e8400000-0000-4000-8000-000000000005", 4, true, true)
	fourthWrite := handleMarkerLifecycleSync(t, fixture.opened, "second record second write", markerKeySyncCall(t,
		fixture.deviceID, fixture.token, "e8400000-0000-4000-8000-000000000006",
		thirdCollect.ServerCursor, thirdCollect.ServerCursor, []recordRevision{fourthRevision}, protocolFixtureTime.Add(7*time.Second)))
	fourRetentions := EncodeUint64(4 * uint64(minimumRetentionUptime/time.Millisecond))
	if _, err := fixture.opened.db.Exec("UPDATE runtime_state SET accumulated_uptime_ms = ? WHERE singleton = 1", fourRetentions[:]); err != nil {
		t.Fatal(err)
	}
	handleMarkerLifecycleSync(t, fixture.opened, "second record second collection", markerKeySyncCall(t,
		fixture.deviceID, fixture.token, "e8400000-0000-4000-8000-000000000007",
		fourthWrite.ServerCursor, fourthWrite.ServerCursor, []recordRevision{}, protocolFixtureTime.Add(8*time.Second)))
	if err := validatePersistentState(context.Background(), fixture.opened.db, testIdentity); err != nil {
		t.Fatalf("two-record marker control: %v", err)
	}
	var historicalCursorBytes []byte
	var markerCount int
	if err := fixture.opened.db.QueryRow(`
		SELECT count(*), min(cursor) FROM changes
		WHERE kind = 'collection_marker' AND collection_marker_record_id = ?`, secondRecordID,
	).Scan(&markerCount, &historicalCursorBytes); err != nil {
		t.Fatal(err)
	}
	if markerCount != 2 {
		t.Fatalf("second record marker history count=%d, want=2", markerCount)
	}
	if _, err := fixture.opened.db.Exec(`
		UPDATE collection_markers SET change_cursor = ? WHERE record_id = ?`, historicalCursorBytes, fixture.recordID); err != nil {
		t.Fatal(err)
	}
	seed := boundedPersistenceSeed{opened: fixture.opened, token: fixture.token}
	expectOriginBindingRejectedWithoutEnvelopeMutation(t, seed, "e8400000-0000-4000-8000-000000000008")
}

func TestCollectedRevisionOriginRequiresChangeAbsence(t *testing.T) {
	t.Run("canonical collected control", func(t *testing.T) {
		seed := seedBoundedPersistence(t, boundedSeedOptions{})
		defer seed.opened.Close()
		collectBoundedSeedRevision(t, seed)
		serverCursor, envelopeGeneration, _, _, err := validatePersistentRuntime(context.Background(), seed.opened.db)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validatePersistentChangeOrigins(context.Background(), seed.opened.db, serverCursor, envelopeGeneration, nil); err != nil {
			t.Fatalf("canonical collected origin rejected: %v", err)
		}
	})

	t.Run("same-kind resurrection", func(t *testing.T) {
		seed := seedBoundedPersistence(t, boundedSeedOptions{})
		defer seed.opened.Close()
		collectBoundedSeedRevision(t, seed)
		if _, err := seed.opened.db.Exec(`
			INSERT INTO changes (cursor, kind, received_at_ms, record_revision_id)
			SELECT change_cursor, 'record_revision', received_at_ms, revision_id
			FROM record_revisions WHERE revision_id = ?`, seed.revisionID); err != nil {
			t.Fatal(err)
		}
		expectOriginBindingRejectedWithoutEnvelopeMutation(t, seed, "e8390000-0000-4000-8000-000000000008")
	})
}

func seedRevokedOriginBinding(t *testing.T) (boundedPersistenceSeed, string) {
	t.Helper()
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	targetID := "e83a0000-0000-4000-8000-000000000001"
	enrollDevice(t, seed.opened, protocolFixtureTime.Add(4*time.Second),
		"e83a0000-0000-4000-8000-000000000002", targetID,
		"e83a0000-0000-4000-8000-000000000003", tokenWithByte(0x8a))
	revokeDevice(t, seed.opened, targetID, seed.token, false,
		"e83a0000-0000-4000-8000-000000000004", protocolFixtureTime.Add(5*time.Second))
	return seed, targetID
}

func TestEnvelopePutRejectsRevocationOwnerMismatchWithoutMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, boundedPersistenceSeed, string)
	}{
		{
			name: "revocation change valid device mismatch",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, targetID string) {
				mutateValidationOwnerText(t, seed.opened.db,
					"UPDATE changes SET device_changed_id = ? WHERE device_changed_id = ? AND device_change_kind = 'revoked'",
					seed.deviceID, targetID)
			},
		},
		{
			name: "revocation event kind flipped",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, targetID string) {
				mutateValidationOwnerText(t, seed.opened.db,
					"UPDATE changes SET device_change_kind = 'enrolled' WHERE device_changed_id = ? AND device_change_kind = 'revoked'", targetID)
			},
		},
		{
			name: "revocation owner missing",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, targetID string) {
				mutateValidationOwnerText(t, seed.opened.db,
					"UPDATE device_origins SET revoked_cursor = NULL WHERE device_id = ?", targetID)
			},
		},
		{
			name: "revocation owner relocated to envelope cursor",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, targetID string) {
				two := EncodeUint64(2)
				mutateValidationOwnerText(t, seed.opened.db,
					"UPDATE device_origins SET revoked_cursor = ? WHERE device_id = ?", two[:], targetID)
			},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed, targetID := seedRevokedOriginBinding(t)
			defer seed.opened.Close()
			test.mutate(t, seed, targetID)
			requestID := "e83b0000-0000-4000-8000-00000000000" + string(rune('1'+index))
			expectOriginBindingRejectedWithoutEnvelopeMutation(t, seed, requestID)
		})
	}
}

func TestRevocationCursorBindsPostActivationOwners(t *testing.T) {
	t.Run("enrolled device", func(t *testing.T) {
		seed, targetID := seedRevokedOriginBinding(t)
		defer seed.opened.Close()
		var createdCursor, revokedCursor, changeCursor []byte
		if err := seed.opened.db.QueryRow(`
			SELECT o.created_cursor, o.revoked_cursor, c.cursor
			FROM device_origins o JOIN changes c
			  ON c.device_changed_id = o.device_id AND c.device_change_kind = 'revoked'
			WHERE o.device_id = ?`, targetID).Scan(&createdCursor, &revokedCursor, &changeCursor); err != nil {
			t.Fatal(err)
		}
		created, createdErr := DecodeUint64(createdCursor)
		revoked, revokedErr := DecodeUint64(revokedCursor)
		change, changeErr := DecodeUint64(changeCursor)
		if createdErr != nil || revokedErr != nil || changeErr != nil || revoked != change || revoked <= created {
			t.Fatalf("enrolled revocation binding: created=%d revoked=%d change=%d errors=%v/%v/%v", created, revoked, change, createdErr, revokedErr, changeErr)
		}
		if err := validatePersistentState(context.Background(), seed.opened.db, testIdentity); err != nil {
			t.Fatalf("canonical enrolled revocation rejected: %v", err)
		}
	})

	t.Run("active baseline device", func(t *testing.T) {
		ctx := context.Background()
		opened, err := Open(ctx, t.TempDir()+"/server.db", testIdentity)
		if err != nil {
			t.Fatal(err)
		}
		defer opened.Close()
		managerID := "e83c0000-0000-4000-8000-000000000001"
		targetID := "e83c0000-0000-4000-8000-000000000002"
		managerToken := tokenWithByte(0x8c)
		if err := opened.CreateDevice(ctx, managerID, managerToken, auth.FixedScopes(), protocolFixtureTime); err != nil {
			t.Fatal(err)
		}
		if err := opened.CreateDevice(ctx, targetID, tokenWithByte(0x8d), auth.FixedScopes(), protocolFixtureTime); err != nil {
			t.Fatal(err)
		}
		if err := opened.StartBoot(ctx); err != nil {
			t.Fatal(err)
		}
		revokeDevice(t, opened, targetID, managerToken, false,
			"e83c0000-0000-4000-8000-000000000003", protocolFixtureTime.Add(time.Second))
		var originKind string
		var createdCursor, revokedCursor, changeCursor []byte
		var baselineRevoked int
		if err := opened.db.QueryRow(`
			SELECT o.origin_kind, o.created_cursor, o.revoked_cursor, o.baseline_revoked, c.cursor
			FROM device_origins o JOIN changes c
			  ON c.device_changed_id = o.device_id AND c.device_change_kind = 'revoked'
			WHERE o.device_id = ?`, targetID).Scan(
			&originKind, &createdCursor, &revokedCursor, &baselineRevoked, &changeCursor,
		); err != nil {
			t.Fatal(err)
		}
		if originKind != "baseline" || createdCursor != nil || revokedCursor == nil || baselineRevoked != 0 || string(revokedCursor) != string(changeCursor) {
			t.Fatalf("baseline revocation binding: kind=%q created=%x revoked=%x baseline=%d change=%x", originKind, createdCursor, revokedCursor, baselineRevoked, changeCursor)
		}
		if err := validatePersistentState(ctx, opened.db, testIdentity); err != nil {
			t.Fatalf("canonical baseline revocation rejected: %v", err)
		}
	})
}

func TestRevocationCursorRollsBackWithFailedReceiptCheckpoint(t *testing.T) {
	ctx := context.Background()
	opened, err := Open(ctx, t.TempDir()+"/server.db", testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	managerID := "e83d0000-0000-4000-8000-000000000001"
	targetID := "e83d0000-0000-4000-8000-000000000002"
	managerToken := tokenWithByte(0x8e)
	if err := opened.CreateDevice(ctx, managerID, managerToken, auth.FixedScopes(), protocolFixtureTime); err != nil {
		t.Fatal(err)
	}
	if err := opened.CreateDevice(ctx, targetID, tokenWithByte(0x8f), auth.FixedScopes(), protocolFixtureTime); err != nil {
		t.Fatal(err)
	}
	if err := opened.StartBoot(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.db.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.db.Exec("UPDATE runtime_state SET accumulated_uptime_ms = zeroblob(7) WHERE singleton = 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.db.Exec("PRAGMA ignore_check_constraints = OFF"); err != nil {
		t.Fatal(err)
	}
	before := readReceiptKeyPreflightState(t, opened.db, managerID, targetID)
	requestID := "e83d0000-0000-4000-8000-000000000003"
	body, err := marshalJSON(revokeDeviceRequest{RequestID: requestID})
	if err != nil {
		t.Fatal(err)
	}
	expectInternalError(t, opened, api.Request{
		Method: "POST", Path: "/v1/devices/" + targetID + "/revoke", RequestID: requestID,
		Authorization: authorization(managerToken), Body: body, Now: protocolFixtureTime.Add(time.Second),
	})
	after := readReceiptKeyPreflightState(t, opened.db, managerID, targetID)
	assertReceiptKeyPreflightStateUnchanged(t, before, after)
	if after.devices[1].revokedAt.Valid || after.devices[1].revokedCursor != nil {
		t.Fatalf("failed revocation retained state: revoked_at=%v revoked_cursor=%x", after.devices[1].revokedAt, after.devices[1].revokedCursor)
	}
}

func TestRevocationCursorSchemaRejectsDuplicateOwnership(t *testing.T) {
	seed, targetID := seedRevokedOriginBinding(t)
	defer seed.opened.Close()
	otherID := "e83e0000-0000-4000-8000-000000000001"
	enrollDevice(t, seed.opened, protocolFixtureTime.Add(6*time.Second),
		"e83e0000-0000-4000-8000-000000000002", otherID,
		"e83e0000-0000-4000-8000-000000000003", tokenWithByte(0x90))
	var revokedCursor []byte
	if err := seed.opened.db.QueryRow("SELECT revoked_cursor FROM device_origins WHERE device_id = ?", targetID).Scan(&revokedCursor); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.opened.db.Exec("UPDATE device_origins SET revoked_cursor = ? WHERE device_id = ?", revokedCursor, otherID); err == nil {
		t.Fatal("duplicate revocation cursor unexpectedly accepted")
	}
}

func TestRevocationCursorPreScanGuardsPersistentAndReadinessValidation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, boundedPersistenceSeed, string)
	}{
		{
			name: "oversized BLOB",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, targetID string) {
				if _, err := seed.opened.db.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
					t.Fatal(err)
				}
				if _, err := seed.opened.db.Exec("UPDATE device_origins SET revoked_cursor = zeroblob(9) WHERE device_id = ?", targetID); err != nil {
					t.Fatal(err)
				}
				if _, err := seed.opened.db.Exec("PRAGMA ignore_check_constraints = OFF"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "TEXT",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, targetID string) {
				mutateValidationOwnerWrongType(t, seed.opened.db, "device_origins",
					"UPDATE device_origins SET revoked_cursor = ? WHERE device_id = ?", "12345678", targetID)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			seed, targetID := seedRevokedOriginBinding(t)
			defer seed.opened.Close()
			test.mutate(t, seed, targetID)
			serverCursor, _, _, _, err := validatePersistentRuntime(context.Background(), seed.opened.db)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validatePersistentDevices(context.Background(), seed.opened.db, serverCursor); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "invalid device row") {
				t.Fatalf("persistent revoked_cursor guard error=%v", err)
			}
			if err := validateReadinessDevices(context.Background(), seed.opened.db, serverCursor); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "invalid readiness device sentinel") {
				t.Fatalf("readiness revoked_cursor guard error=%v", err)
			}
		})
	}
}
