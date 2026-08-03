package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
)

type tokenRotationKeyFixture struct {
	seed       boundedPersistenceSeed
	rotationID string
	reuseCall  api.Request
}

type tokenRotationMutationState struct {
	deviceTokenHash [32]byte
	rotationCount   int
}

func seedTokenRotationKeyFixture(t *testing.T) tokenRotationKeyFixture {
	t.Helper()
	seed := seedBoundedPersistence(t, boundedSeedOptions{rotation: true})
	var original tokenRotationRequest
	if err := decodeStrict(seed.rotation.Body, &original); err != nil {
		seed.opened.Close()
		t.Fatal(err)
	}
	reuse := tokenRotationRequest{
		RotationID:     original.RotationID,
		DeviceID:       seed.deviceID,
		NewDeviceToken: base64.RawURLEncoding.EncodeToString(tokenWithByte(0xe3)),
	}
	body, err := marshalJSON(reuse)
	if err != nil {
		seed.opened.Close()
		t.Fatal(err)
	}
	return tokenRotationKeyFixture{
		seed:       seed,
		rotationID: original.RotationID,
		reuseCall: api.Request{
			Method: "POST", Path: "/v1/device-token-rotations",
			RequestID:     "f7500000-0000-4000-8000-000000000001",
			Authorization: authorization(seed.token), Body: body,
			Now: protocolFixtureTime.Add(2 * time.Second),
		},
	}
}

func readTokenRotationMutationState(t *testing.T, fixture tokenRotationKeyFixture) tokenRotationMutationState {
	t.Helper()
	var state tokenRotationMutationState
	var tokenHash []byte
	if err := fixture.seed.opened.db.QueryRow(`
		SELECT token_hash, (SELECT count(*) FROM token_rotations)
		FROM devices WHERE device_id = ?`, fixture.seed.deviceID,
	).Scan(&tokenHash, &state.rotationCount); err != nil {
		t.Fatal(err)
	}
	if len(tokenHash) != len(state.deviceTokenHash) {
		t.Fatalf("device token hash length=%d", len(tokenHash))
	}
	copy(state.deviceTokenHash[:], tokenHash)
	return state
}

func expectTokenRotationError(t *testing.T, opened *Store, call api.Request, code string) {
	t.Helper()
	if _, protocolErr := opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != code {
		t.Fatalf("token rotation error=%v, want=%s", protocolErr, code)
	}
}

func assertTokenRotationStateUnchanged(t *testing.T, before, after tokenRotationMutationState) {
	t.Helper()
	if before != after {
		t.Fatalf("token rotation mutated state: before=%+v after=%+v", before, after)
	}
}

func TestTokenRotationKeyPreflightRejectsMalformedAliasesWithoutMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, tokenRotationKeyFixture)
	}{
		{
			name: "NUL-suffixed TEXT key",
			mutate: func(t *testing.T, fixture tokenRotationKeyFixture) {
				if _, err := fixture.seed.opened.db.Exec(
					"UPDATE token_rotations SET rotation_id = ? WHERE rotation_id = ?",
					oversizedNULSuffixedText(fixture.rotationID), fixture.rotationID,
				); err != nil {
					t.Fatal(err)
				}
				assertNULSuffixPassedSQLiteLengthCheck(t, fixture.seed.opened.db, `
					SELECT length(rotation_id), octet_length(rotation_id), typeof(rotation_id)
					FROM token_rotations`)
			},
		},
		{
			name: "BLOB-equivalent key",
			mutate: func(t *testing.T, fixture tokenRotationKeyFixture) {
				writeLiveWrongTypeText(t, fixture.seed.opened.db, "token_rotations",
					"UPDATE token_rotations SET rotation_id = CAST(? AS BLOB) WHERE rotation_id = ?",
					fixture.rotationID, fixture.rotationID)
			},
		},
		{
			name: "NUL-suffixed BLOB key",
			mutate: func(t *testing.T, fixture tokenRotationKeyFixture) {
				if _, err := fixture.seed.opened.db.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
					t.Fatal(err)
				}
				writeLiveWrongTypeText(t, fixture.seed.opened.db, "token_rotations",
					"UPDATE token_rotations SET rotation_id = CAST(? AS BLOB) WHERE rotation_id = ?",
					fixture.rotationID+"\x00suffix", fixture.rotationID)
				if _, err := fixture.seed.opened.db.Exec("PRAGMA ignore_check_constraints = OFF"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "canonical TEXT plus BLOB alias",
			mutate: func(t *testing.T, fixture tokenRotationKeyFixture) {
				writeLiveWrongTypeText(t, fixture.seed.opened.db, "token_rotations", `
					INSERT INTO token_rotations (
						rotation_id, device_id, old_token_hash, new_token_hash,
						request_fingerprint, response_json, created_at_ms
					)
					SELECT CAST(rotation_id AS BLOB), device_id, old_token_hash, new_token_hash,
					       request_fingerprint, response_json, created_at_ms
					FROM token_rotations WHERE rotation_id = ?`, fixture.rotationID)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedTokenRotationKeyFixture(t)
			defer fixture.seed.opened.Close()
			test.mutate(t, fixture)

			before := readTokenRotationMutationState(t, fixture)
			expectTokenRotationError(t, fixture.seed.opened, fixture.reuseCall, "internal_error")
			after := readTokenRotationMutationState(t, fixture)
			assertTokenRotationStateUnchanged(t, before, after)
		})
	}
}

func TestTokenRotationKeyPreflightPreservesCanonicalReplayReuseAndAbsence(t *testing.T) {
	fixture := seedTokenRotationKeyFixture(t)
	defer fixture.seed.opened.Close()

	replayed, protocolErr := fixture.seed.opened.HandleAPI(context.Background(), fixture.seed.rotation)
	if protocolErr != nil || replayed.Status != http.StatusOK {
		t.Fatalf("canonical old-token replay: response=%+v error=%v", replayed, protocolErr)
	}
	beforeReuse := readTokenRotationMutationState(t, fixture)
	expectTokenRotationError(t, fixture.seed.opened, fixture.reuseCall, "request_id_reused")
	afterReuse := readTokenRotationMutationState(t, fixture)
	assertTokenRotationStateUnchanged(t, beforeReuse, afterReuse)

	var fresh tokenRotationRequest
	if err := decodeStrict(fixture.reuseCall.Body, &fresh); err != nil {
		t.Fatal(err)
	}
	fresh.RotationID = "f7500000-0000-4000-8000-000000000002"
	fresh.NewDeviceToken = base64.RawURLEncoding.EncodeToString(tokenWithByte(0xe4))
	freshBody, err := marshalJSON(fresh)
	if err != nil {
		t.Fatal(err)
	}
	freshCall := fixture.reuseCall
	freshCall.RequestID = "f7500000-0000-4000-8000-000000000003"
	freshCall.Body = freshBody
	response, protocolErr := fixture.seed.opened.HandleAPI(context.Background(), freshCall)
	if protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("canonical rotation absence: response=%+v error=%v", response, protocolErr)
	}
	afterFresh := readTokenRotationMutationState(t, fixture)
	if afterFresh.rotationCount != afterReuse.rotationCount+1 || bytes.Equal(afterFresh.deviceTokenHash[:], afterReuse.deviceTokenHash[:]) {
		t.Fatalf("fresh rotation state: before=%+v after=%+v", afterReuse, afterFresh)
	}
}

func TestTokenRotationKeyPreflightPreservesEarlierErrorOrdering(t *testing.T) {
	fixture := seedTokenRotationKeyFixture(t)
	defer fixture.seed.opened.Close()
	if _, err := fixture.seed.opened.db.Exec(
		"UPDATE token_rotations SET rotation_id = ? WHERE rotation_id = ?",
		oversizedNULSuffixedText(fixture.rotationID), fixture.rotationID,
	); err != nil {
		t.Fatal(err)
	}
	before := readTokenRotationMutationState(t, fixture)

	invalidBody := fixture.reuseCall
	invalidBody.Body = []byte("{")
	expectTokenRotationError(t, fixture.seed.opened, invalidBody, "invalid_request")

	invalidAuthorization := fixture.reuseCall
	invalidAuthorization.Authorization = "Bearer invalid"
	expectTokenRotationError(t, fixture.seed.opened, invalidAuthorization, "unauthorized")

	var mismatch tokenRotationRequest
	if err := decodeStrict(fixture.reuseCall.Body, &mismatch); err != nil {
		t.Fatal(err)
	}
	mismatch.DeviceID = "f7500000-0000-4000-8000-000000000004"
	mismatchBody, err := marshalJSON(mismatch)
	if err != nil {
		t.Fatal(err)
	}
	authenticatedMismatch := fixture.reuseCall
	authenticatedMismatch.Body = mismatchBody
	expectTokenRotationError(t, fixture.seed.opened, authenticatedMismatch, "authenticated_device_mismatch")

	after := readTokenRotationMutationState(t, fixture)
	assertTokenRotationStateUnchanged(t, before, after)

	if _, err := fixture.seed.opened.db.Exec(`
		UPDATE devices SET revoked_at_ms = created_at_ms WHERE device_id = ?`, fixture.seed.deviceID); err != nil {
		t.Fatal(err)
	}
	revokedBefore := readTokenRotationMutationState(t, fixture)
	expectTokenRotationError(t, fixture.seed.opened, fixture.reuseCall, "token_revoked")
	revokedAfter := readTokenRotationMutationState(t, fixture)
	assertTokenRotationStateUnchanged(t, revokedBefore, revokedAfter)
}

func TestTokenRotationKeyProbeUsesPrimaryKeyRanges(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	rotationID := "f7510000-0000-4000-8000-000000000001"
	lowerBytes := []byte(rotationID)
	upperBytes := append([]byte(nil), lowerBytes...)
	upperBytes[len(upperBytes)-1]++
	rows, err := opened.db.Query("EXPLAIN QUERY PLAN "+tokenRotationKeyProbeSQL,
		maxUUIDBytes, rotationID, string(upperBytes),
		maxUUIDBytes, lowerBytes, upperBytes,
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
		if strings.Contains(detail, "SCAN token_rotations") {
			rows.Close()
			t.Fatalf("token-rotation key probe scans full table: %s", detail)
		}
		if strings.Contains(detail, "SEARCH token_rotations") &&
			strings.Contains(detail, "rotation_id>?") && strings.Contains(detail, "rotation_id<?") {
			searches++
		}
	}
	iterationErr := rows.Err()
	closeErr := rows.Close()
	if iterationErr != nil || closeErr != nil {
		t.Fatalf("explain token-rotation key probe: iteration=%v close=%v", iterationErr, closeErr)
	}
	if searches != 2 {
		t.Fatalf("token-rotation key indexed range searches=%d, want=2", searches)
	}
}

func TestTokenRotationKeyPreflightRejectsInvalidProbeIdentifier(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	transaction, err := opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	if present, protocolErr := preflightTokenRotationKey(context.Background(), transaction, "invalid"); present || protocolErr == nil || protocolErr.Code != "internal_error" {
		t.Fatalf("invalid rotation-key probe: present=%t error=%v", present, protocolErr)
	}
}
