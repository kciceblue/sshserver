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

	var enrollmentForDeviceWitness int
	err = transaction.QueryRowContext(ctx, "SELECT 1 FROM enrollments WHERE device_id = ?", request.DeviceID).Scan(&enrollmentForDeviceWitness)
	if err == nil {
		return api.Response{}, api.NewError("enrollment_replay_mismatch", false)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return api.Response{}, api.NewError("internal_error", true)
	}
	var conflictWitness int
	err = transaction.QueryRowContext(ctx, "SELECT 1 FROM devices WHERE device_id = ? OR token_hash = ? LIMIT 1", request.DeviceID, tokenHash[:]).Scan(&conflictWitness)
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
		SELECT grant_hash, expires_at_ms, octet_length(consumed_enrollment_id),
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
		var expiresAt int64
		var consumedLength sql.NullInt64
		var candidateConsumed sql.NullString
		if err := rows.Scan(&hashBytes, &expiresAt, &consumedLength, &candidateConsumed); err != nil || len(hashBytes) != 32 ||
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

func (store *Store) lookupEnrollment(ctx context.Context, transaction *sql.Tx, enrollmentID string, request enrollmentRequest, tokenHash, fingerprint [32]byte) ([]byte, bool, *api.Error) {
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	var deviceID sql.NullString
	var scopesJSON sql.NullString
	var storedToken, storedFingerprint, response []byte
	var deviceIDLength, scopesLength, responseLength int64
	var createdStatus int
	err := transaction.QueryRowContext(ctx, `
		SELECT octet_length(device_id),
		       CASE WHEN typeof(device_id) = 'text' AND octet_length(device_id) = ? THEN device_id END,
		       token_hash, octet_length(scopes_json),
		       CASE WHEN typeof(scopes_json) = 'text' AND octet_length(scopes_json) = ? THEN scopes_json END,
		       request_fingerprint, length(response_json),
		       CASE WHEN length(response_json) BETWEEN 1 AND ? THEN response_json END,
		       created_status
		FROM enrollments WHERE enrollment_id = ?`, maxUUIDBytes, len(wantScopes), maxBodyBytes, enrollmentID,
	).Scan(&deviceIDLength, &deviceID, &storedToken, &scopesLength, &scopesJSON, &storedFingerprint, &responseLength, &response, &createdStatus)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil || deviceIDLength != maxUUIDBytes || !boundedRequiredText(deviceIDLength, deviceID, maxUUIDBytes) || validateUUID(deviceID.String) != nil ||
		len(storedToken) != 32 || len(storedFingerprint) != 32 ||
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
