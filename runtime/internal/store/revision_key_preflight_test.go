package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
)

type revisionKeyFixture struct {
	seed        boundedPersistenceSeed
	nextCounter uint64
	afterCursor string
}

func revisionKeyMutation(deviceID, recordID, revisionID string, counter uint64) recordRevision {
	encodedCounter := encodeUint64Text(counter)
	return recordRevision{
		RecordID:       recordID,
		RevisionID:     revisionID,
		AuthorDeviceID: deviceID,
		AuthorCounter:  encodedCounter,
		VersionVector:  []vectorEntry{{DeviceID: deviceID, Counter: encodedCounter}},
		PayloadSchema:  "1",
		CryptoSuite:    cryptoSuite,
		Nonce:          base64.RawURLEncoding.EncodeToString(make([]byte, 24)),
		Ciphertext:     base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
}

func seedRevisionKeyFixture(t *testing.T, history string) revisionKeyFixture {
	t.Helper()
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	fixture := revisionKeyFixture{seed: seed, nextCounter: 2, afterCursor: "0"}
	switch history {
	case "retained head":
	case "dominated retained":
		successor := revisionKeyMutation(seed.deviceID, seed.recordID,
			"f7500000-0000-4000-8000-000000000001", fixture.nextCounter)
		syncMutation(t, seed.opened, seed.deviceID, seed.token,
			"f7500000-0000-4000-8000-000000000002", successor, protocolFixtureTime.Add(time.Second))
		fixture.nextCounter++
	case "collected permanent":
		collectBoundedSeedRevision(t, seed)
		fixture.afterCursor = "3"
	default:
		seed.opened.Close()
		t.Fatalf("unknown revision history %q", history)
	}
	var retained, undominated int
	if err := seed.opened.db.QueryRow(`
		SELECT retained, undominated FROM record_revisions WHERE revision_id = ?`, seed.revisionID,
	).Scan(&retained, &undominated); err != nil {
		seed.opened.Close()
		t.Fatal(err)
	}
	wantRetained, wantUndominated := 1, 1
	if history == "dominated retained" {
		wantUndominated = 0
	}
	if history == "collected permanent" {
		wantRetained, wantUndominated = 0, 0
	}
	if retained != wantRetained || undominated != wantUndominated {
		seed.opened.Close()
		t.Fatalf("%s target state retained=%d undominated=%d", history, retained, undominated)
	}
	return fixture
}

func corruptRevisionKey(t *testing.T, fixture revisionKeyFixture, form string) {
	t.Helper()
	switch form {
	case "NUL-suffixed TEXT":
		if _, err := fixture.seed.opened.db.Exec(
			"UPDATE record_revisions SET revision_id = ? WHERE revision_id = ?",
			fixture.seed.revisionID+"\x00suffix", fixture.seed.revisionID,
		); err != nil {
			t.Fatal(err)
		}
		assertNULSuffixPassedSQLiteLengthCheck(t, fixture.seed.opened.db, `
			SELECT length(revision_id), octet_length(revision_id), typeof(revision_id)
			FROM record_revisions`)
	case "BLOB-equivalent":
		writeLiveWrongTypeText(t, fixture.seed.opened.db, "record_revisions",
			"UPDATE record_revisions SET revision_id = CAST(? AS BLOB) WHERE revision_id = ?",
			fixture.seed.revisionID, fixture.seed.revisionID)
	case "NUL-suffixed BLOB":
		if _, err := fixture.seed.opened.db.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
			t.Fatal(err)
		}
		writeLiveWrongTypeText(t, fixture.seed.opened.db, "record_revisions",
			"UPDATE record_revisions SET revision_id = CAST(? AS BLOB) WHERE revision_id = ?",
			fixture.seed.revisionID+"\x00suffix", fixture.seed.revisionID)
		if _, err := fixture.seed.opened.db.Exec("PRAGMA ignore_check_constraints = OFF"); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown revision key form %q", form)
	}
}

func revisionKeySyncCall(t *testing.T, fixture revisionKeyFixture, requestID string, counter uint64) api.Request {
	t.Helper()
	mutation := revisionKeyMutation(fixture.seed.deviceID, fixture.seed.recordID, fixture.seed.revisionID, counter)
	body, err := marshalJSON(syncRequest{
		ProtocolVersion: "1",
		DeviceID:        fixture.seed.deviceID,
		RequestID:       requestID,
		AfterCursor:     fixture.afterCursor,
		AckCursor:       "0",
		Mutations:       []recordRevision{mutation},
	})
	if err != nil {
		t.Fatal(err)
	}
	return api.Request{
		Method:        "POST",
		Path:          "/v1/sync",
		RequestID:     requestID,
		Authorization: authorization(fixture.seed.token),
		Body:          body,
		Now:           protocolFixtureTime.Add(2 * time.Second),
	}
}

func TestRevisionKeyPreflightRejectsAliasesAcrossPermanentHistoryWithoutMutation(t *testing.T) {
	for _, history := range []string{"retained head", "dominated retained", "collected permanent"} {
		for _, form := range []string{"NUL-suffixed TEXT", "BLOB-equivalent", "NUL-suffixed BLOB"} {
			t.Run(history+"/"+form, func(t *testing.T) {
				fixture := seedRevisionKeyFixture(t, history)
				defer fixture.seed.opened.Close()
				corruptRevisionKey(t, fixture, form)
				before := markerKeyDurableDigest(t, fixture.seed.opened.db)
				call := revisionKeySyncCall(t, fixture,
					"f7500000-0000-4000-8000-000000000003", fixture.nextCounter)
				if _, protocolErr := fixture.seed.opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "internal_error" {
					t.Fatalf("revision alias error=%v", protocolErr)
				}
				after := markerKeyDurableDigest(t, fixture.seed.opened.db)
				if before != after {
					t.Fatalf("revision alias changed durable state: before=%x after=%x", before, after)
				}
				var canonicalRows int
				if err := fixture.seed.opened.db.QueryRow(
					"SELECT count(*) FROM record_revisions WHERE revision_id = ?", fixture.seed.revisionID,
				).Scan(&canonicalRows); err != nil {
					t.Fatal(err)
				}
				if canonicalRows != 0 {
					t.Fatalf("canonical revision alias inserted: count=%d", canonicalRows)
				}
			})
		}
	}
}

func seededRevisionMutation(t *testing.T, seed boundedPersistenceSeed) recordRevision {
	t.Helper()
	var request syncRequest
	if err := json.Unmarshal(seed.sync.Body, &request); err != nil || len(request.Mutations) != 1 {
		t.Fatalf("decode seeded revision: mutations=%d error=%v", len(request.Mutations), err)
	}
	return request.Mutations[0]
}

func revisionOrderingCall(t *testing.T, seed boundedPersistenceSeed, requestID string, mutation recordRevision) api.Request {
	t.Helper()
	body, err := marshalJSON(syncRequest{
		ProtocolVersion: "1", DeviceID: seed.deviceID, RequestID: requestID,
		AfterCursor: "0", AckCursor: "0", Mutations: []recordRevision{mutation},
	})
	if err != nil {
		t.Fatal(err)
	}
	return api.Request{
		Method: "POST", Path: "/v1/sync", RequestID: requestID,
		Authorization: authorization(seed.token), Body: body, Now: protocolFixtureTime.Add(time.Second),
	}
}

func TestRevisionKeyPreflightPreservesReplayEquivocationAndCounterOrdering(t *testing.T) {
	t.Run("exact replay", func(t *testing.T) {
		seed := seedBoundedPersistence(t, boundedSeedOptions{})
		defer seed.opened.Close()
		call := revisionOrderingCall(t, seed, "f7510000-0000-4000-8000-000000000001", seededRevisionMutation(t, seed))
		response, protocolErr := seed.opened.HandleAPI(context.Background(), call)
		if protocolErr != nil || response.Status != http.StatusOK {
			t.Fatalf("exact revision replay: response=%+v error=%v", response, protocolErr)
		}
	})

	t.Run("exact equivocation precedes counter conflict", func(t *testing.T) {
		seed := seedBoundedPersistence(t, boundedSeedOptions{})
		defer seed.opened.Close()
		mutation := seededRevisionMutation(t, seed)
		mutation.AuthorCounter = "3"
		mutation.VersionVector = []vectorEntry{{DeviceID: seed.deviceID, Counter: "3"}}
		call := revisionOrderingCall(t, seed, "f7510000-0000-4000-8000-000000000002", mutation)
		before := markerKeyDurableDigest(t, seed.opened.db)
		if _, protocolErr := seed.opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "revision_equivocation" {
			t.Fatalf("exact equivocation ordering error=%v", protocolErr)
		}
		if after := markerKeyDurableDigest(t, seed.opened.db); before != after {
			t.Fatalf("exact equivocation changed durable state: before=%x after=%x", before, after)
		}
	})

	t.Run("true absence reaches counter conflict", func(t *testing.T) {
		seed := seedBoundedPersistence(t, boundedSeedOptions{})
		defer seed.opened.Close()
		mutation := revisionKeyMutation(seed.deviceID, seed.recordID,
			"f7510000-0000-4000-8000-000000000003", 3)
		call := revisionOrderingCall(t, seed, "f7510000-0000-4000-8000-000000000004", mutation)
		before := markerKeyDurableDigest(t, seed.opened.db)
		if _, protocolErr := seed.opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "counter_conflict" {
			t.Fatalf("absent revision counter ordering error=%v", protocolErr)
		}
		if after := markerKeyDurableDigest(t, seed.opened.db); before != after {
			t.Fatalf("counter conflict changed durable state: before=%x after=%x", before, after)
		}
	})

	t.Run("alias corruption precedes counter conflict", func(t *testing.T) {
		fixture := seedRevisionKeyFixture(t, "retained head")
		defer fixture.seed.opened.Close()
		corruptRevisionKey(t, fixture, "NUL-suffixed TEXT")
		call := revisionKeySyncCall(t, fixture,
			"f7510000-0000-4000-8000-000000000005", fixture.nextCounter+1)
		before := markerKeyDurableDigest(t, fixture.seed.opened.db)
		if _, protocolErr := fixture.seed.opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "internal_error" {
			t.Fatalf("alias/counter ordering error=%v", protocolErr)
		}
		if after := markerKeyDurableDigest(t, fixture.seed.opened.db); before != after {
			t.Fatalf("alias/counter error changed durable state: before=%x after=%x", before, after)
		}
	})
}

func TestRevisionKeyPreflightIsBoundedAtMaximumMutationBatch(t *testing.T) {
	fixture := seedRevisionKeyFixture(t, "retained head")
	defer fixture.seed.opened.Close()
	corruptRevisionKey(t, fixture, "NUL-suffixed TEXT")
	mutations := make([]recordRevision, 0, maxMutations)
	for index := 0; index < maxMutations-1; index++ {
		counter := uint64(index) + fixture.nextCounter
		mutations = append(mutations, revisionKeyMutation(
			fixture.seed.deviceID,
			fmt.Sprintf("f7520000-0000-4000-8000-%012x", index+1),
			fmt.Sprintf("f7530000-0000-4000-8000-%012x", index+1),
			counter,
		))
	}
	mutations = append(mutations, revisionKeyMutation(
		fixture.seed.deviceID, fixture.seed.recordID, fixture.seed.revisionID,
		fixture.nextCounter+uint64(maxMutations)-1,
	))
	requestID := "f7520000-0000-4000-8000-000000000fff"
	body, err := marshalJSON(syncRequest{
		ProtocolVersion: "1", DeviceID: fixture.seed.deviceID, RequestID: requestID,
		AfterCursor: "0", AckCursor: "0", Mutations: mutations,
	})
	if err != nil {
		t.Fatal(err)
	}
	call := api.Request{
		Method: "POST", Path: "/v1/sync", RequestID: requestID,
		Authorization: authorization(fixture.seed.token), Body: body, Now: protocolFixtureTime.Add(time.Second),
	}
	before := markerKeyDurableDigest(t, fixture.seed.opened.db)
	if _, protocolErr := fixture.seed.opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "internal_error" {
		t.Fatalf("maximum-batch alias error=%v", protocolErr)
	}
	if after := markerKeyDurableDigest(t, fixture.seed.opened.db); before != after {
		t.Fatalf("maximum-batch alias changed durable state: before=%x after=%x", before, after)
	}
}

func TestRevisionKeyAliasProbeUsesPrimaryKeyRanges(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	revisionID := "f7540000-0000-4000-8000-000000000001"
	lowerBytes := []byte(revisionID)
	upperBytes := append([]byte(nil), lowerBytes...)
	upperBytes[len(upperBytes)-1]++
	rows, err := opened.db.Query("EXPLAIN QUERY PLAN "+revisionKeyAliasProbeSQL,
		revisionID, string(upperBytes), lowerBytes, upperBytes,
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
		if strings.Contains(detail, "SCAN record_revisions") {
			rows.Close()
			t.Fatalf("revision-key alias probe scans full table: %s", detail)
		}
		if strings.Contains(detail, "SEARCH record_revisions") &&
			strings.Contains(detail, "revision_id>?") && strings.Contains(detail, "revision_id<?") {
			searches++
		}
	}
	iterationErr := rows.Err()
	closeErr := rows.Close()
	if iterationErr != nil || closeErr != nil {
		t.Fatalf("explain revision-key alias probe: iteration=%v close=%v", iterationErr, closeErr)
	}
	if searches != 2 {
		t.Fatalf("revision-key indexed range searches=%d, want=2", searches)
	}
}
