package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
	"github.com/kciceblue/sshserver/runtime/internal/auth"
)

func deviceFromValues(deviceID string, createdAt int64, revokedAt, lastSyncAt *int64, ackCursor, maxAuthorCounter uint64) device {
	var revokedText, syncText *string
	status := "active"
	if revokedAt != nil {
		value := formatTimestamp(*revokedAt)
		revokedText = &value
		status = "revoked"
	}
	if lastSyncAt != nil {
		value := formatTimestamp(*lastSyncAt)
		syncText = &value
	}
	return device{
		DeviceID:         deviceID,
		Scopes:           auth.FixedScopes(),
		Status:           status,
		CreatedAt:        formatTimestamp(createdAt),
		RevokedAt:        revokedText,
		LastSyncAt:       syncText,
		AckCursor:        encodeUint64Text(ackCursor),
		MaxAuthorCounter: encodeUint64Text(maxAuthorCounter),
	}
}

func readDevice(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, deviceID string) (device, [32]byte, *api.Error) {
	var tokenBytes, ackBytes, counterBytes []byte
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	var scopesJSON sql.NullString
	var scopesLength int64
	var createdAt int64
	var revokedAt, lastSyncAt sql.NullInt64
	err := query.QueryRowContext(ctx, `
		SELECT token_hash, octet_length(scopes_json),
		       CASE WHEN typeof(scopes_json) = 'text' AND octet_length(scopes_json) = ? THEN scopes_json END,
		       created_at_ms, revoked_at_ms,
		       last_sync_at_ms, last_ack_cursor, max_author_counter
		FROM devices WHERE device_id = ?`, len(wantScopes), deviceID,
	).Scan(&tokenBytes, &scopesLength, &scopesJSON, &createdAt, &revokedAt, &lastSyncAt, &ackBytes, &counterBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return device{}, [32]byte{}, api.NewError("device_not_found", false)
	}
	if err != nil || len(tokenBytes) != 32 || scopesLength != int64(len(wantScopes)) ||
		!boundedRequiredText(scopesLength, scopesJSON, len(wantScopes)) || scopesJSON.String != string(wantScopes) {
		return device{}, [32]byte{}, api.NewError("internal_error", true)
	}
	var scopes []string
	if json.Unmarshal([]byte(scopesJSON.String), &scopes) != nil || auth.ValidateScopes(scopes) != nil {
		return device{}, [32]byte{}, api.NewError("internal_error", true)
	}
	ackCursor, err := DecodeUint64(ackBytes)
	if err != nil {
		return device{}, [32]byte{}, api.NewError("internal_error", true)
	}
	maxCounter, err := DecodeUint64(counterBytes)
	if err != nil {
		return device{}, [32]byte{}, api.NewError("internal_error", true)
	}
	var revokedPointer, syncPointer *int64
	if revokedAt.Valid {
		value := revokedAt.Int64
		revokedPointer = &value
	}
	if lastSyncAt.Valid {
		value := lastSyncAt.Int64
		syncPointer = &value
	}
	var tokenHash [32]byte
	copy(tokenHash[:], tokenBytes)
	return deviceFromValues(deviceID, createdAt, revokedPointer, syncPointer, ackCursor, maxCounter), tokenHash, nil
}

func (store *Store) handleListDevices(ctx context.Context, call api.Request) (api.Response, *api.Error) {
	if len(call.Body) != 0 {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	transaction, protocolErr := beginTransaction(ctx, store.db)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	defer transaction.Rollback()
	if _, protocolErr := store.authenticate(ctx, transaction, call.Authorization, "devices:read"); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	rows, err := transaction.QueryContext(ctx, `
		SELECT octet_length(device_id),
		       CASE WHEN typeof(device_id) = 'text' AND octet_length(device_id) = ? THEN device_id END
		FROM devices ORDER BY device_id LIMIT 65`, maxUUIDBytes)
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	var identifiers []string
	for rows.Next() {
		var identifier sql.NullString
		var identifierLength int64
		if err := rows.Scan(&identifierLength, &identifier); err != nil || identifierLength != maxUUIDBytes ||
			!boundedRequiredText(identifierLength, identifier, maxUUIDBytes) || validateUUID(identifier.String) != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		identifiers = append(identifiers, identifier.String)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return api.Response{}, api.NewError("internal_error", true)
	}
	if err := rows.Close(); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if len(identifiers) > 64 {
		return api.Response{}, api.NewError("internal_error", true)
	}
	devices := make([]device, 0, len(identifiers))
	for _, identifier := range identifiers {
		value, _, protocolErr := readDevice(ctx, transaction, identifier)
		if protocolErr != nil {
			return api.Response{}, protocolErr
		}
		devices = append(devices, value)
	}
	body, err := marshalJSON(struct {
		Devices []device `json:"devices"`
	}{Devices: devices})
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	return api.Response{Status: http.StatusOK, Body: body}, nil
}

func (store *Store) handleRevokeDevice(ctx context.Context, call api.Request, targetDeviceID string) (api.Response, *api.Error) {
	presentedToken, tokenErr := parseAuthorization(call.Authorization, "Bearer")
	defer clear(presentedToken)
	transaction, protocolErr := beginTransaction(ctx, store.db)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	defer transaction.Rollback()
	retiredMatch, protocolErr := store.lookupRetiredSelfRevocationReceipt(ctx, transaction, presentedToken, tokenErr)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if retiredMatch != nil {
		// A retired bearer never falls through to the general device registry.
		// Resolve every exact or mismatched retry solely from the endpoint-local
		// receipt table so it cannot recover any ordinary authority.
		if retiredMatch.deviceID != targetDeviceID {
			return api.Response{}, api.NewError("token_revoked", false)
		}
		var replayRequest revokeDeviceRequest
		if err := decodeStrict(call.Body, &replayRequest); err != nil || replayRequest.RequestID != call.RequestID || validateUUID(replayRequest.RequestID) != nil {
			return api.Response{}, api.NewError("token_revoked", false)
		}
		selfFingerprint, protocolErr := requestFingerprint(store, "JAT self revocation body fingerprint v1", targetDeviceID, call.Body)
		if protocolErr != nil {
			return api.Response{}, protocolErr
		}
		if retiredMatch.requestID == call.RequestID && auth.VerifyHash(retiredMatch.fingerprint, selfFingerprint) {
			return api.Response{Status: retiredMatch.status, Body: retiredMatch.body, Headers: retiredMatch.headers}, nil
		}
		return api.Response{}, api.NewError("token_revoked", false)
	}
	var request revokeDeviceRequest
	if err := decodeStrict(call.Body, &request); err != nil || request.RequestID != call.RequestID || validateUUID(request.RequestID) != nil {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	if tokenErr != nil {
		return api.Response{}, api.NewError("unauthorized", false)
	}
	authenticated, authErr := store.authenticate(ctx, transaction, call.Authorization, "devices:manage")
	if authErr != nil {
		return api.Response{}, authErr
	}
	fingerprint, protocolErr := requestFingerprint(store, "JAT device revocation request fingerprint v1", authenticated.DeviceID, call.Body)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	operation := "device-revocation/" + targetDeviceID
	if response, found, protocolErr := store.lookupReceipt(ctx, transaction, authenticated.DeviceID, operation, call.RequestID, fingerprint); protocolErr != nil || found {
		return response, protocolErr
	}
	var crossTargetReuse int
	if err := transaction.QueryRowContext(ctx, `
		SELECT count(*) FROM operation_receipts
		WHERE device_id = ? AND request_id = ?
		  AND operation LIKE 'device-revocation/%' AND operation <> ?`,
		authenticated.DeviceID, call.RequestID, operation,
	).Scan(&crossTargetReuse); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if crossTargetReuse != 0 {
		return api.Response{}, api.NewError("request_id_reused", false)
	}
	target, _, protocolErr := readDevice(ctx, transaction, targetDeviceID)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if target.Status == "revoked" {
		body, _ := marshalJSON(target)
		response := api.Response{Status: http.StatusOK, Body: body}
		checkpoint, protocolErr := store.storeReceipt(ctx, transaction, authenticated.DeviceID, operation, call.RequestID, fingerprint, response, call.Now)
		if protocolErr != nil {
			return api.Response{}, protocolErr
		}
		if protocolErr := store.commitUptimeTransaction(transaction, checkpoint); protocolErr != nil {
			return api.Response{}, protocolErr
		}
		return response, nil
	}
	var activeCount int
	if err := transaction.QueryRowContext(ctx, `
		SELECT count(*) FROM (
			SELECT 1 FROM devices WHERE revoked_at_ms IS NULL LIMIT 65
		)`).Scan(&activeCount); err != nil || activeCount > 64 {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if activeCount == 1 && !request.AllowZeroActive {
		return api.Response{}, api.NewError("zero_active_confirmation_required", false)
	}
	newCursor, protocolErr := reserveCursors(ctx, transaction, 1)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	revokedAt := call.Now.UTC().Truncate(time.Millisecond).UnixMilli()
	if _, err := transaction.ExecContext(ctx, `
		UPDATE devices SET revoked_at_ms = max(?, created_at_ms)
		WHERE device_id = ? AND revoked_at_ms IS NULL`, revokedAt, targetDeviceID); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	revokedCursor := EncodeUint64(newCursor)
	result, err := transaction.ExecContext(ctx, `
		UPDATE device_origins SET revoked_cursor = ?
		WHERE device_id = ? AND baseline_revoked = 0 AND revoked_cursor IS NULL`,
		revokedCursor[:], targetDeviceID)
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	updatedOrigins, err := result.RowsAffected()
	if err != nil || updatedOrigins != 1 {
		return api.Response{}, api.NewError("internal_error", true)
	}
	target, targetHash, protocolErr := readDevice(ctx, transaction, targetDeviceID)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	changeTime, err := time.Parse("2006-01-02T15:04:05.000Z", *target.RevokedAt)
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	body, err := marshalJSON(target)
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	response := api.Response{Status: http.StatusOK, Body: body}
	if authenticated.DeviceID == targetDeviceID {
		selfFingerprint, protocolErr := requestFingerprint(store, "JAT self revocation body fingerprint v1", targetDeviceID, call.Body)
		if protocolErr != nil {
			return api.Response{}, protocolErr
		}
		response.Headers = api.V1ResponseHeaders(call.RequestID, len(body))
		headersJSON, err := json.Marshal(response.Headers)
		if err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO self_revocation_receipts (
				device_id, request_id, body_fingerprint, pre_revocation_token_hash,
				response_status, response_headers_json, response_json
			) VALUES (?, ?, ?, ?, ?, ?, ?)`, targetDeviceID, call.RequestID, selfFingerprint[:], targetHash[:], response.Status, headersJSON, body); err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
	}
	if protocolErr := insertChange(ctx, transaction, newCursor, "device_changed", "", "", targetDeviceID, "revoked", 0, changeTime); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	checkpoint, protocolErr := store.storeReceipt(ctx, transaction, authenticated.DeviceID, operation, call.RequestID, fingerprint, response, call.Now)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if protocolErr := setServerCursor(ctx, transaction, newCursor); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if protocolErr := store.commitUptimeTransaction(transaction, checkpoint); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	return response, nil
}

type retiredSelfRevocationReceipt struct {
	deviceID    string
	requestID   string
	fingerprint [32]byte
	status      int
	headers     []api.Header
	body        []byte
}

// lookupRetiredSelfRevocationReceipt performs a bounded full scan of retired
// receipt token hashes before any ordinary device authentication. Hashes are
// derived and compared for every retained row, even after a match, so neither
// the requested target nor a match position selects the comparison work.
func (store *Store) lookupRetiredSelfRevocationReceipt(ctx context.Context, transaction *sql.Tx, presentedToken []byte, tokenErr error) (*retiredSelfRevocationReceipt, *api.Error) {
	rows, err := transaction.QueryContext(ctx, `
		SELECT octet_length(device_id),
		       CASE WHEN typeof(device_id) = 'text' AND octet_length(device_id) = ? THEN device_id END,
		       pre_revocation_token_hash
		FROM self_revocation_receipts ORDER BY device_id LIMIT 65`, maxUUIDBytes)
	if err != nil {
		return nil, api.NewError("internal_error", true)
	}
	defer rows.Close()
	tokenForHash := presentedToken
	if tokenErr != nil {
		tokenForHash = make([]byte, 32)
		defer clear(tokenForHash)
	}
	var matchedDeviceID string
	rowCount := 0
	matchCount := 0
	for rows.Next() {
		rowCount++
		var deviceID sql.NullString
		var deviceIDLength int64
		var storedBytes []byte
		if rows.Scan(&deviceIDLength, &deviceID, &storedBytes) != nil || deviceIDLength != maxUUIDBytes ||
			!boundedRequiredText(deviceIDLength, deviceID, maxUUIDBytes) || validateUUID(deviceID.String) != nil || len(storedBytes) != 32 {
			return nil, api.NewError("internal_error", true)
		}
		computed, err := auth.DeviceTokenHash(store.identity.InstanceID, store.identity.VaultID, deviceID.String, tokenForHash)
		if err != nil {
			return nil, api.NewError("internal_error", true)
		}
		var stored [32]byte
		copy(stored[:], storedBytes)
		matches := auth.VerifyHash(stored, computed)
		if tokenErr == nil && matches {
			matchedDeviceID = deviceID.String
			matchCount++
		}
	}
	if rows.Err() != nil || rows.Close() != nil || rowCount > 64 || matchCount > 1 {
		return nil, api.NewError("internal_error", true)
	}
	if matchCount == 0 {
		return nil, nil
	}
	var receipt retiredSelfRevocationReceipt
	receipt.deviceID = matchedDeviceID
	var fingerprint, headersBody, body []byte
	var requestID sql.NullString
	var requestIDLength, headersLength, bodyLength int64
	if err := transaction.QueryRowContext(ctx, `
		SELECT octet_length(request_id),
		       CASE WHEN typeof(request_id) = 'text' AND octet_length(request_id) = ? THEN request_id END,
		       body_fingerprint, response_status,
		       length(response_headers_json),
		       CASE WHEN length(response_headers_json) BETWEEN 1 AND ? THEN response_headers_json END,
		       length(response_json),
		       CASE WHEN length(response_json) BETWEEN 1 AND ? THEN response_json END
		FROM self_revocation_receipts WHERE device_id = ?`, maxUUIDBytes, maxBodyBytes, maxBodyBytes, matchedDeviceID,
	).Scan(&requestIDLength, &requestID, &fingerprint, &receipt.status, &headersLength, &headersBody, &bodyLength, &body); err != nil ||
		requestIDLength != maxUUIDBytes || !boundedRequiredText(requestIDLength, requestID, maxUUIDBytes) || validateUUID(requestID.String) != nil || len(fingerprint) != 32 ||
		!boundedRequiredBytes(headersLength, headersBody, maxBodyBytes) || !boundedRequiredBytes(bodyLength, body, maxBodyBytes) {
		return nil, api.NewError("internal_error", true)
	}
	receipt.requestID = requestID.String
	copy(receipt.fingerprint[:], fingerprint)
	var responseDevice device
	if json.Unmarshal(headersBody, &receipt.headers) != nil {
		return nil, api.NewError("internal_error", true)
	}
	canonicalHeaders, headersErr := json.Marshal(receipt.headers)
	if headersErr != nil || !bytes.Equal(canonicalHeaders, headersBody) || receipt.status != http.StatusOK ||
		!slices.Equal(receipt.headers, api.V1ResponseHeaders(receipt.requestID, len(body))) ||
		decodeStoredCanonical(body, &responseDevice) != nil || validateDevice(responseDevice) != nil ||
		responseDevice.DeviceID != matchedDeviceID || responseDevice.Status != "revoked" {
		return nil, api.NewError("internal_error", true)
	}
	receipt.body = append([]byte(nil), body...)
	return &receipt, nil
}

const tokenRotationKeyProbeSQL = `
	SELECT octet_length(rotation_id),
	       CASE WHEN typeof(rotation_id) = 'text'
	                  AND octet_length(rotation_id) = ? THEN rotation_id END
	FROM token_rotations
	WHERE rotation_id >= ? AND rotation_id < ?
	UNION ALL
	SELECT octet_length(rotation_id),
	       CASE WHEN typeof(rotation_id) = 'text'
	                  AND octet_length(rotation_id) = ? THEN rotation_id END
	FROM token_rotations
	WHERE rotation_id >= ? AND rotation_id < ?
	LIMIT 2`

// preflightTokenRotationKey makes exact rotation-key absence authoritative
// without scanning unrelated rotation history. Separate primary-key ranges
// cover TEXT and BLOB forms of the canonical UUID and every byte-suffixed
// variant because SQLite orders values within each storage class.
func preflightTokenRotationKey(ctx context.Context, transaction *sql.Tx, rotationID string) (bool, *api.Error) {
	if validateUUID(rotationID) != nil {
		return false, api.NewError("internal_error", true)
	}
	lowerBytes := []byte(rotationID)
	upperBytes := append([]byte(nil), lowerBytes...)
	upperBytes[len(upperBytes)-1]++
	rows, err := transaction.QueryContext(ctx, tokenRotationKeyProbeSQL,
		maxUUIDBytes, rotationID, string(upperBytes),
		maxUUIDBytes, lowerBytes, upperBytes,
	)
	if err != nil {
		return false, api.NewError("internal_error", true)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		var storedRotationID sql.NullString
		var rotationIDLength int64
		if rows.Scan(&rotationIDLength, &storedRotationID) != nil || rotationIDLength != maxUUIDBytes ||
			!boundedRequiredText(rotationIDLength, storedRotationID, maxUUIDBytes) ||
			validateUUID(storedRotationID.String) != nil || storedRotationID.String != rotationID {
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

func (store *Store) handleTokenRotation(ctx context.Context, call api.Request) (api.Response, *api.Error) {
	var request tokenRotationRequest
	if err := decodeStrict(call.Body, &request); err != nil || validateUUID(request.RotationID) != nil || validateUUID(request.DeviceID) != nil {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	newToken, err := decodeBase64(request.NewDeviceToken, 32, 0, 0)
	if err != nil {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	defer clear(newToken)
	presentedToken, err := parseAuthorization(call.Authorization, "Bearer")
	if err != nil {
		return api.Response{}, api.NewError("unauthorized", false)
	}
	defer clear(presentedToken)
	presentedHash, err := auth.DeviceTokenHash(store.identity.InstanceID, store.identity.VaultID, request.DeviceID, presentedToken)
	if err != nil {
		return api.Response{}, api.NewError("unauthorized", false)
	}
	newHash, err := auth.DeviceTokenHash(store.identity.InstanceID, store.identity.VaultID, request.DeviceID, newToken)
	if err != nil {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	fingerprint, protocolErr := requestFingerprint(store, "JAT token rotation request fingerprint v1", request.DeviceID, call.Body)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	transaction, protocolErr := beginTransaction(ctx, store.db)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	defer transaction.Rollback()
	authenticated, authErr := store.authenticate(ctx, transaction, call.Authorization, "")
	if authErr == nil {
		if authenticated.DeviceID != request.DeviceID {
			return api.Response{}, api.NewError("authenticated_device_mismatch", false)
		}
	} else if authErr.Code == "token_revoked" {
		return api.Response{}, authErr
	}
	rotationPresent, protocolErr := preflightTokenRotationKey(ctx, transaction, request.RotationID)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	var responseBody []byte
	if rotationPresent {
		var storedDeviceID sql.NullString
		var oldHashBytes, newHashBytes, storedFingerprint []byte
		var storedDeviceIDLength, responseLength int64
		err = transaction.QueryRowContext(ctx, `
			SELECT octet_length(device_id),
			       CASE WHEN typeof(device_id) = 'text' AND octet_length(device_id) = ? THEN device_id END,
			       old_token_hash, new_token_hash, request_fingerprint,
			       length(response_json),
			       CASE WHEN length(response_json) BETWEEN 1 AND ? THEN response_json END
			FROM token_rotations WHERE rotation_id = ?`, maxUUIDBytes, maxBodyBytes, request.RotationID,
		).Scan(&storedDeviceIDLength, &storedDeviceID, &oldHashBytes, &newHashBytes, &storedFingerprint, &responseLength, &responseBody)
		if err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		var storedResponse device
		if storedDeviceIDLength != maxUUIDBytes || !boundedRequiredText(storedDeviceIDLength, storedDeviceID, maxUUIDBytes) || validateUUID(storedDeviceID.String) != nil ||
			len(oldHashBytes) != 32 || len(newHashBytes) != 32 || len(storedFingerprint) != 32 ||
			!boundedRequiredBytes(responseLength, responseBody, maxBodyBytes) ||
			decodeStoredCanonical(responseBody, &storedResponse) != nil || validateDevice(storedResponse) != nil || storedResponse.DeviceID != storedDeviceID.String {
			return api.Response{}, api.NewError("internal_error", true)
		}
		var oldHash, recordedNewHash, recordedFingerprint [32]byte
		copy(oldHash[:], oldHashBytes)
		copy(recordedNewHash[:], newHashBytes)
		copy(recordedFingerprint[:], storedFingerprint)
		presentedStoredHash, hashErr := auth.DeviceTokenHash(store.identity.InstanceID, store.identity.VaultID, storedDeviceID.String, presentedToken)
		if hashErr != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		oldMatches := auth.VerifyHash(oldHash, presentedStoredHash)
		newMatches := auth.VerifyHash(recordedNewHash, presentedStoredHash)
		authMatches := oldMatches || newMatches
		if !authMatches {
			return api.Response{}, api.NewError("unauthorized", false)
		}
		var revoked bool
		if err := transaction.QueryRowContext(ctx, "SELECT revoked_at_ms IS NOT NULL FROM devices WHERE device_id = ?", storedDeviceID.String).Scan(&revoked); err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		if revoked {
			return api.Response{}, api.NewError("token_revoked", false)
		}
		if storedDeviceID.String != request.DeviceID {
			return api.Response{}, api.NewError("authenticated_device_mismatch", false)
		}
		if !auth.VerifyHash(recordedNewHash, newHash) || !auth.VerifyHash(recordedFingerprint, fingerprint) {
			return api.Response{}, api.NewError("request_id_reused", false)
		}
		return api.Response{Status: http.StatusOK, Body: responseBody}, nil
	}
	if authErr != nil {
		return api.Response{}, authErr
	}
	current, currentHash, protocolErr := readDevice(ctx, transaction, request.DeviceID)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if current.Status == "revoked" {
		return api.Response{}, api.NewError("token_revoked", false)
	}
	if !auth.VerifyHash(currentHash, presentedHash) {
		return api.Response{}, api.NewError("unauthorized", false)
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE devices SET token_hash = ? WHERE device_id = ?", newHash[:], request.DeviceID); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	current, _, protocolErr = readDevice(ctx, transaction, request.DeviceID)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	responseBody, err = marshalJSON(current)
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO token_rotations (
			rotation_id, device_id, old_token_hash, new_token_hash,
			request_fingerprint, response_json, created_at_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		request.RotationID, request.DeviceID, currentHash[:], newHash[:], fingerprint[:], responseBody, call.Now.UTC().UnixMilli(),
	); err != nil {
		return api.Response{}, api.NewError("request_id_reused", false)
	}
	if protocolErr := commitTransaction(transaction); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	return api.Response{Status: http.StatusOK, Body: responseBody}, nil
}
