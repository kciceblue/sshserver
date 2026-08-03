package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
	"github.com/kciceblue/sshserver/runtime/internal/auth"
)

func (store *Store) handleEnrollment(ctx context.Context, call api.Request) (api.Response, *api.Error) {
	var request enrollmentRequest
	if err := decodeStrict(call.Body, &request); err != nil {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	token, err := validateEnrollmentRequest(request)
	if err != nil {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	defer clear(token)
	grant, err := parseAuthorization(call.Authorization, "JAT-Enrollment")
	if err != nil {
		return api.Response{}, api.NewError("unauthorized", false)
	}
	defer clear(grant)
	grantHash, err := auth.EnrollmentGrantHash(store.identity.InstanceID, store.identity.VaultID, grant)
	if err != nil {
		return api.Response{}, api.NewError("unauthorized", false)
	}
	tokenHash, err := auth.DeviceTokenHash(store.identity.InstanceID, store.identity.VaultID, request.DeviceID, token)
	if err != nil {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	fingerprint, protocolErr := requestFingerprint(store, "JAT enrollment request fingerprint v1", request.DeviceID, call.Body)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}

	transaction, protocolErr := beginTransaction(ctx, store.db)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	defer transaction.Rollback()
	consumedEnrollmentID, grantErr := store.lookupGrant(ctx, transaction, grantHash, call.Now)
	if grantErr != nil {
		return api.Response{}, grantErr
	}

	if consumedEnrollmentID != nil {
		response, exact, lookupErr := store.lookupEnrollment(ctx, transaction, *consumedEnrollmentID, request, tokenHash, fingerprint)
		if lookupErr != nil {
			return api.Response{}, lookupErr
		}
		if !exact {
			return api.Response{}, api.NewError("grant_consumed", false)
		}
		return api.Response{Status: http.StatusOK, Body: response}, nil
	}

	response, exists, lookupErr := store.lookupEnrollment(ctx, transaction, request.EnrollmentID, request, tokenHash, fingerprint)
	if lookupErr != nil {
		return api.Response{}, lookupErr
	}
	if exists {
		if _, err := transaction.ExecContext(ctx, "UPDATE enrollment_grants SET consumed_enrollment_id = ? WHERE grant_hash = ?", request.EnrollmentID, grantHash[:]); err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		if protocolErr := commitTransaction(transaction); protocolErr != nil {
			return api.Response{}, protocolErr
		}
		return api.Response{Status: http.StatusOK, Body: response}, nil
	}

	deviceCollision, protocolErr := preflightEnrollmentDeviceCollision(ctx, transaction, request.DeviceID)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if deviceCollision {
		return api.Response{}, api.NewError("enrollment_replay_mismatch", false)
	}
	var conflictWitness int
	err = transaction.QueryRowContext(ctx, "SELECT 1 FROM devices WHERE token_hash = ?", tokenHash[:]).Scan(&conflictWitness)
	if err == nil {
		return api.Response{}, api.NewError("enrollment_replay_mismatch", false)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if protocolErr := store.admitEnrollmentAttempt(call.Now); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	var deviceCount, activeCount int
	if err := transaction.QueryRowContext(ctx, `
		SELECT count(*), coalesce(sum(revoked_at_ms IS NULL), 0)
		FROM (SELECT revoked_at_ms FROM devices LIMIT 65)`,
	).Scan(&deviceCount, &activeCount); err != nil || deviceCount > 64 {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if deviceCount >= 64 {
		return api.Response{}, api.NewError("limit_exceeded", false)
	}
	newCursor, protocolErr := reserveCursors(ctx, transaction, 1)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	_, envelopeGeneration, _, _, protocolErr := readRuntimeState(ctx, transaction)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	createdAt := call.Now.UTC().Truncate(time.Millisecond)
	zero := EncodeUint64(0)
	createdCursor := EncodeUint64(newCursor)
	scopesJSON, _ := json.Marshal(auth.FixedScopes())
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO devices (
			device_id, token_hash, scopes_json, created_at_ms,
			last_ack_cursor, max_author_counter
		) VALUES (?, ?, ?, ?, ?, ?)`,
		request.DeviceID, tokenHash[:], string(scopesJSON), createdAt.UnixMilli(), zero[:], zero[:],
	); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO device_origins (
			device_id, origin_kind, created_cursor, baseline_revoked
		) VALUES (?, 'enrolled', ?, 0)`, request.DeviceID, createdCursor[:]); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if _, err := transaction.ExecContext(ctx, "INSERT INTO device_sync_state (device_id, max_returned_cursor) VALUES (?, ?)", request.DeviceID, zero[:]); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	responseValue := enrollmentResponse{
		ProtocolVersion:         "1",
		InstanceID:              store.identity.InstanceID,
		VaultID:                 store.identity.VaultID,
		Device:                  deviceFromValues(request.DeviceID, createdAt.UnixMilli(), nil, nil, 0, 0),
		EnvelopeGeneration:      encodeUint64Text(envelopeGeneration),
		BecameFirstActiveDevice: activeCount == 0,
	}
	responseBody, err := marshalJSON(responseValue)
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO enrollments (
			enrollment_id, device_id, created_cursor, token_hash, scopes_json,
			request_fingerprint, response_json, created_status
		) VALUES (?, ?, ?, ?, ?, ?, ?, 201)`,
		request.EnrollmentID, request.DeviceID, createdCursor[:], tokenHash[:], string(scopesJSON), fingerprint[:], responseBody,
	); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE enrollment_grants SET consumed_enrollment_id = ? WHERE grant_hash = ?", request.EnrollmentID, grantHash[:]); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if protocolErr := insertChange(ctx, transaction, newCursor, "device_changed", "", "", request.DeviceID, "enrolled", 0, call.Now); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if protocolErr := setServerCursor(ctx, transaction, newCursor); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if protocolErr := commitTransaction(transaction); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	return api.Response{Status: http.StatusCreated, Body: responseBody}, nil
}

func (store *Store) admitEnrollmentAttempt(now time.Time) *api.Error {
	store.ephemeral.mu.Lock()
	defer store.ephemeral.mu.Unlock()
	if !store.ephemeral.booted {
		return api.NewError("grant_expired", false)
	}
	cutoff := now.Add(-time.Minute)
	retained := store.ephemeral.enrollmentAttempts[:0]
	for _, attempt := range store.ephemeral.enrollmentAttempts {
		if attempt.After(cutoff) {
			retained = append(retained, attempt)
		}
	}
	store.ephemeral.enrollmentAttempts = retained
	if len(retained) >= 5 {
		return api.NewError("rate_limited", false)
	}
	store.ephemeral.enrollmentAttempts = append(store.ephemeral.enrollmentAttempts, now)
	return nil
}

const enrollmentDeviceCollisionProbeSQL = `
	SELECT 1, octet_length(device_id),
	       CASE WHEN typeof(device_id) = 'text'
	                  AND octet_length(device_id) = ? THEN device_id END
	FROM enrollments
	WHERE device_id >= ? AND device_id < ?
	UNION ALL
	SELECT 1, octet_length(device_id),
	       CASE WHEN typeof(device_id) = 'text'
	                  AND octet_length(device_id) = ? THEN device_id END
	FROM enrollments
	WHERE device_id >= ? AND device_id < ?
	UNION ALL
	SELECT 2, octet_length(device_id),
	       CASE WHEN typeof(device_id) = 'text'
	                  AND octet_length(device_id) = ? THEN device_id END
	FROM devices
	WHERE device_id >= ? AND device_id < ?
	UNION ALL
	SELECT 2, octet_length(device_id),
	       CASE WHEN typeof(device_id) = 'text'
	                  AND octet_length(device_id) = ? THEN device_id END
	FROM devices
	WHERE device_id >= ? AND device_id < ?
	LIMIT 4`

// preflightEnrollmentDeviceCollision makes the device-key absence checks for
// both the permanent registry and the one-enrollment-per-device witness
// authoritative. Each pair of indexed ranges covers canonical TEXT and BLOB
// prefixes without scanning unrelated devices or enrollment history.
func preflightEnrollmentDeviceCollision(ctx context.Context, transaction *sql.Tx, deviceID string) (bool, *api.Error) {
	if validateUUID(deviceID) != nil {
		return false, api.NewError("internal_error", true)
	}
	lowerBytes := []byte(deviceID)
	upperBytes := append([]byte(nil), lowerBytes...)
	upperBytes[len(upperBytes)-1]++
	rows, err := transaction.QueryContext(ctx, enrollmentDeviceCollisionProbeSQL,
		maxUUIDBytes, deviceID, string(upperBytes),
		maxUUIDBytes, lowerBytes, upperBytes,
		maxUUIDBytes, deviceID, string(upperBytes),
		maxUUIDBytes, lowerBytes, upperBytes,
	)
	if err != nil {
		return false, api.NewError("internal_error", true)
	}
	defer rows.Close()
	var seen [3]int
	for rows.Next() {
		var source int
		var storedDeviceID sql.NullString
		var deviceIDLength int64
		if rows.Scan(&source, &deviceIDLength, &storedDeviceID) != nil || source < 1 || source > 2 ||
			deviceIDLength != maxUUIDBytes || !boundedRequiredText(deviceIDLength, storedDeviceID, maxUUIDBytes) ||
			validateUUID(storedDeviceID.String) != nil || storedDeviceID.String != deviceID {
			rows.Close()
			return false, api.NewError("internal_error", true)
		}
		seen[source]++
		if seen[source] > 1 {
			rows.Close()
			return false, api.NewError("internal_error", true)
		}
	}
	iterationErr := rows.Err()
	closeErr := rows.Close()
	if iterationErr != nil || closeErr != nil {
		return false, api.NewError("internal_error", true)
	}
	return seen[1] == 1 || seen[2] == 1, nil
}

func (store *Store) lookupGrant(ctx context.Context, transaction *sql.Tx, presented [32]byte, now time.Time) (*string, *api.Error) {
	store.ephemeral.mu.Lock()
	booted := store.ephemeral.booted
	bootID := store.ephemeral.bootID
	deadlines := append([]grantDeadline(nil), store.ephemeral.grantDeadlines...)
	store.ephemeral.mu.Unlock()
	if !booted {
		return nil, api.NewError("grant_expired", false)
	}
	rows, err := transaction.QueryContext(ctx, `
		SELECT octet_length(grant_hash),
		       CASE WHEN typeof(grant_hash) = 'blob' AND octet_length(grant_hash) = 32 THEN grant_hash END,
		       expires_at_ms, octet_length(consumed_enrollment_id),
		       CASE WHEN typeof(consumed_enrollment_id) = 'text' AND octet_length(consumed_enrollment_id) = ?
		            THEN consumed_enrollment_id END
		FROM enrollment_grants WHERE boot_id = ? ORDER BY grant_hash`, maxUUIDBytes, bootID[:])
	if err != nil {
		return nil, api.NewError("internal_error", true)
	}
	defer rows.Close()
	matched := false
	var consumed sql.NullString
	for rows.Next() {
		var hashBytes []byte
		var hashLength, expiresAt int64
		var consumedLength sql.NullInt64
		var candidateConsumed sql.NullString
		if err := rows.Scan(&hashLength, &hashBytes, &expiresAt, &consumedLength, &candidateConsumed); err != nil ||
			!boundedRequiredBytes(hashLength, hashBytes, 32) || hashLength != 32 ||
			!boundedOptionalText(consumedLength, candidateConsumed, maxUUIDBytes) || consumedLength.Valid &&
			(consumedLength.Int64 != maxUUIDBytes || validateUUID(candidateConsumed.String) != nil) {
			return nil, api.NewError("internal_error", true)
		}
		var candidate [32]byte
		copy(candidate[:], hashBytes)
		if auth.VerifyHash(candidate, presented) {
			matched = true
			consumed = candidateConsumed
		}
	}
	if err := rows.Err(); err != nil {
		return nil, api.NewError("internal_error", true)
	}
	var deadline time.Time
	hasDeadline := false
	for _, candidate := range deadlines {
		candidateMatches := auth.VerifyHash(candidate.hash, presented)
		if candidateMatches {
			deadline = candidate.deadline
			hasDeadline = true
		}
	}
	if !matched {
		return nil, api.NewError("unauthorized", false)
	}
	if !hasDeadline || !now.Before(deadline) {
		return nil, api.NewError("grant_expired", false)
	}
	if consumed.Valid {
		return &consumed.String, nil
	}
	return nil, nil
}

const enrollmentKeyProbeSQL = `
	SELECT octet_length(enrollment_id),
	       CASE WHEN typeof(enrollment_id) = 'text'
	                  AND octet_length(enrollment_id) = ? THEN enrollment_id END
	FROM enrollments
	WHERE enrollment_id >= ? AND enrollment_id < ?
	UNION ALL
	SELECT octet_length(enrollment_id),
	       CASE WHEN typeof(enrollment_id) = 'text'
	                  AND octet_length(enrollment_id) = ? THEN enrollment_id END
	FROM enrollments
	WHERE enrollment_id >= ? AND enrollment_id < ?
	LIMIT 2`

// preflightEnrollmentKey makes exact enrollment-key absence authoritative
// without scanning unrelated enrollment history. SQLite orders storage classes
// before values, so separate primary-key ranges cover TEXT and BLOB forms of
// the canonical UUID plus every byte-suffixed variant.
func preflightEnrollmentKey(ctx context.Context, transaction *sql.Tx, enrollmentID string) (bool, *api.Error) {
	if validateUUID(enrollmentID) != nil {
		return false, api.NewError("internal_error", true)
	}
	lowerBytes := []byte(enrollmentID)
	upperBytes := append([]byte(nil), lowerBytes...)
	upperBytes[len(upperBytes)-1]++
	rows, err := transaction.QueryContext(ctx, enrollmentKeyProbeSQL,
		maxUUIDBytes, enrollmentID, string(upperBytes),
		maxUUIDBytes, lowerBytes, upperBytes,
	)
	if err != nil {
		return false, api.NewError("internal_error", true)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		var storedEnrollmentID sql.NullString
		var enrollmentIDLength int64
		if rows.Scan(&enrollmentIDLength, &storedEnrollmentID) != nil || enrollmentIDLength != maxUUIDBytes ||
			!boundedRequiredText(enrollmentIDLength, storedEnrollmentID, maxUUIDBytes) ||
			validateUUID(storedEnrollmentID.String) != nil || storedEnrollmentID.String != enrollmentID {
			rows.Close()
			return false, api.NewError("internal_error", true)
		}
	}
	iterationErr := rows.Err()
	closeErr := rows.Close()
	if iterationErr != nil || closeErr != nil || count > 1 {
		return false, api.NewError("internal_error", true)
	}
	return count == 1, nil
}

func (store *Store) lookupEnrollment(ctx context.Context, transaction *sql.Tx, enrollmentID string, request enrollmentRequest, tokenHash, fingerprint [32]byte) ([]byte, bool, *api.Error) {
	present, protocolErr := preflightEnrollmentKey(ctx, transaction, enrollmentID)
	if protocolErr != nil {
		return nil, false, protocolErr
	}
	if !present {
		return nil, false, nil
	}
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	var deviceID sql.NullString
	var scopesJSON sql.NullString
	var storedToken, storedFingerprint, response []byte
	var deviceIDLength, tokenLength, scopesLength, fingerprintLength, responseLength int64
	var createdStatus int
	err := transaction.QueryRowContext(ctx, `
		SELECT octet_length(device_id),
		       CASE WHEN typeof(device_id) = 'text' AND octet_length(device_id) = ? THEN device_id END,
		       octet_length(token_hash),
		       CASE WHEN typeof(token_hash) = 'blob' AND octet_length(token_hash) = 32 THEN token_hash END,
		       octet_length(scopes_json),
		       CASE WHEN typeof(scopes_json) = 'text' AND octet_length(scopes_json) = ? THEN scopes_json END,
		       octet_length(request_fingerprint),
		       CASE WHEN typeof(request_fingerprint) = 'blob' AND octet_length(request_fingerprint) = 32 THEN request_fingerprint END,
		       length(response_json),
		       CASE WHEN length(response_json) BETWEEN 1 AND ? THEN response_json END,
		       created_status
		FROM enrollments WHERE enrollment_id = ?`, maxUUIDBytes, len(wantScopes), maxBodyBytes, enrollmentID,
	).Scan(&deviceIDLength, &deviceID, &tokenLength, &storedToken, &scopesLength, &scopesJSON, &fingerprintLength, &storedFingerprint, &responseLength, &response, &createdStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, api.NewError("internal_error", true)
	}
	if err != nil || deviceIDLength != maxUUIDBytes || !boundedRequiredText(deviceIDLength, deviceID, maxUUIDBytes) || validateUUID(deviceID.String) != nil ||
		!boundedRequiredBytes(tokenLength, storedToken, 32) || tokenLength != 32 ||
		!boundedRequiredBytes(fingerprintLength, storedFingerprint, 32) || fingerprintLength != 32 ||
		scopesLength != int64(len(wantScopes)) ||
		!boundedRequiredText(scopesLength, scopesJSON, len(wantScopes)) || scopesJSON.String != string(wantScopes) ||
		!boundedRequiredBytes(responseLength, response, maxBodyBytes) || createdStatus != http.StatusCreated ||
		validateStoredEnrollmentResponse(response, store.identity, deviceID.String) != nil {
		return nil, false, api.NewError("internal_error", true)
	}
	var recordedToken, recordedFingerprint [32]byte
	copy(recordedToken[:], storedToken)
	copy(recordedFingerprint[:], storedFingerprint)
	exact := enrollmentID == request.EnrollmentID &&
		deviceID.String == request.DeviceID && scopesJSON.String == string(wantScopes) &&
		auth.VerifyHash(recordedToken, tokenHash) && auth.VerifyHash(recordedFingerprint, fingerprint)
	if !exact {
		return nil, false, api.NewError("enrollment_replay_mismatch", false)
	}
	return append([]byte(nil), response...), true, nil
}

func encodeUint64Text(value uint64) string {
	return strconv.FormatUint(value, 10)
}
