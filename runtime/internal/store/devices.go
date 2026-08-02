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
	var scopesJSON string
	var createdAt int64
	var revokedAt, lastSyncAt sql.NullInt64
	err := query.QueryRowContext(ctx, `
		SELECT token_hash, scopes_json, created_at_ms, revoked_at_ms,
		       last_sync_at_ms, last_ack_cursor, max_author_counter
		FROM devices WHERE device_id = ?`, deviceID,
	).Scan(&tokenBytes, &scopesJSON, &createdAt, &revokedAt, &lastSyncAt, &ackBytes, &counterBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return device{}, [32]byte{}, api.NewError("device_not_found", false)
	}
	if err != nil || len(tokenBytes) != 32 || scopesJSON == "" {
		return device{}, [32]byte{}, api.NewError("internal_error", true)
	}
	var scopes []string
	if json.Unmarshal([]byte(scopesJSON), &scopes) != nil || auth.ValidateScopes(scopes) != nil {
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
	rows, err := transaction.QueryContext(ctx, "SELECT device_id FROM devices ORDER BY device_id LIMIT 65")
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	var identifiers []string
	for rows.Next() {
		var identifier string
		if err := rows.Scan(&identifier); err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		identifiers = append(identifiers, identifier)
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
	retiredMatch, targetHasRetiredReceipt, protocolErr := store.lookupRetiredSelfRevocationReceipt(ctx, transaction, presentedToken, tokenErr, targetDeviceID)
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
	if targetHasRetiredReceipt {
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
		if protocolErr := store.storeReceipt(ctx, transaction, authenticated.DeviceID, operation, call.RequestID, fingerprint, response, call.Now); protocolErr != nil {
			return api.Response{}, protocolErr
		}
		if protocolErr := commitTransaction(transaction); protocolErr != nil {
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
	target, targetHash, protocolErr := readDevice(ctx, transaction, targetDeviceID)
	if protocolErr != nil {
		return api.Response{}, protocolErr
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
	if protocolErr := insertChange(ctx, transaction, newCursor, "device_changed", "", "", call.Now); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if protocolErr := store.storeReceipt(ctx, transaction, authenticated.DeviceID, operation, call.RequestID, fingerprint, response, call.Now); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if protocolErr := setServerCursor(ctx, transaction, newCursor); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if protocolErr := commitTransaction(transaction); protocolErr != nil {
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
func (store *Store) lookupRetiredSelfRevocationReceipt(ctx context.Context, transaction *sql.Tx, presentedToken []byte, tokenErr error, targetDeviceID string) (*retiredSelfRevocationReceipt, bool, *api.Error) {
	rows, err := transaction.QueryContext(ctx, `
		SELECT device_id, pre_revocation_token_hash
		FROM self_revocation_receipts ORDER BY device_id LIMIT 65`)
	if err != nil {
		return nil, false, api.NewError("internal_error", true)
	}
	defer rows.Close()
	tokenForHash := presentedToken
	if tokenErr != nil {
		tokenForHash = make([]byte, 32)
		defer clear(tokenForHash)
	}
	var matchedDeviceID string
	targetHasReceipt := false
	rowCount := 0
	matchCount := 0
	for rows.Next() {
		rowCount++
		var deviceID string
		var storedBytes []byte
		if rows.Scan(&deviceID, &storedBytes) != nil || validateUUID(deviceID) != nil || len(storedBytes) != 32 {
			return nil, false, api.NewError("internal_error", true)
		}
		computed, err := auth.DeviceTokenHash(store.identity.InstanceID, store.identity.VaultID, deviceID, tokenForHash)
		if err != nil {
			return nil, false, api.NewError("internal_error", true)
		}
		var stored [32]byte
		copy(stored[:], storedBytes)
		matches := auth.VerifyHash(stored, computed)
		if tokenErr == nil && matches {
			matchedDeviceID = deviceID
			matchCount++
		}
		if deviceID == targetDeviceID {
			targetHasReceipt = true
		}
	}
	if rows.Err() != nil || rows.Close() != nil || rowCount > 64 || matchCount > 1 {
		return nil, false, api.NewError("internal_error", true)
	}
	if matchCount == 0 {
		return nil, targetHasReceipt, nil
	}
	var receipt retiredSelfRevocationReceipt
	receipt.deviceID = matchedDeviceID
	var fingerprint, headersBody, body []byte
	if err := transaction.QueryRowContext(ctx, `
		SELECT request_id, body_fingerprint, response_status,
		       response_headers_json, response_json
		FROM self_revocation_receipts WHERE device_id = ?`, matchedDeviceID,
	).Scan(&receipt.requestID, &fingerprint, &receipt.status, &headersBody, &body); err != nil || len(fingerprint) != 32 {
		return nil, false, api.NewError("internal_error", true)
	}
	copy(receipt.fingerprint[:], fingerprint)
	var responseDevice device
	if json.Unmarshal(headersBody, &receipt.headers) != nil {
		return nil, false, api.NewError("internal_error", true)
	}
	canonicalHeaders, headersErr := json.Marshal(receipt.headers)
	if headersErr != nil || !bytes.Equal(canonicalHeaders, headersBody) || receipt.status != http.StatusOK ||
		!slices.Equal(receipt.headers, api.V1ResponseHeaders(receipt.requestID, len(body))) ||
		decodeStoredCanonical(body, &responseDevice) != nil || validateDevice(responseDevice) != nil ||
		responseDevice.DeviceID != matchedDeviceID || responseDevice.Status != "revoked" {
		return nil, false, api.NewError("internal_error", true)
	}
	receipt.body = append([]byte(nil), body...)
	return &receipt, targetHasReceipt, nil
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
	var storedDeviceID string
	var oldHashBytes, newHashBytes, storedFingerprint, responseBody []byte
	err = transaction.QueryRowContext(ctx, `
		SELECT device_id, old_token_hash, new_token_hash, request_fingerprint, response_json
		FROM token_rotations WHERE rotation_id = ?`, request.RotationID,
	).Scan(&storedDeviceID, &oldHashBytes, &newHashBytes, &storedFingerprint, &responseBody)
	if err == nil {
		var storedResponse device
		if len(oldHashBytes) != 32 || len(newHashBytes) != 32 || len(storedFingerprint) != 32 ||
			decodeStoredCanonical(responseBody, &storedResponse) != nil || validateDevice(storedResponse) != nil || storedResponse.DeviceID != storedDeviceID {
			return api.Response{}, api.NewError("internal_error", true)
		}
		var oldHash, recordedNewHash, recordedFingerprint [32]byte
		copy(oldHash[:], oldHashBytes)
		copy(recordedNewHash[:], newHashBytes)
		copy(recordedFingerprint[:], storedFingerprint)
		presentedStoredHash, hashErr := auth.DeviceTokenHash(store.identity.InstanceID, store.identity.VaultID, storedDeviceID, presentedToken)
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
		if err := transaction.QueryRowContext(ctx, "SELECT revoked_at_ms IS NOT NULL FROM devices WHERE device_id = ?", storedDeviceID).Scan(&revoked); err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		if revoked {
			return api.Response{}, api.NewError("token_revoked", false)
		}
		if storedDeviceID != request.DeviceID {
			return api.Response{}, api.NewError("authenticated_device_mismatch", false)
		}
		if !auth.VerifyHash(recordedNewHash, newHash) || !auth.VerifyHash(recordedFingerprint, fingerprint) {
			return api.Response{}, api.NewError("request_id_reused", false)
		}
		return api.Response{Status: http.StatusOK, Body: responseBody}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return api.Response{}, api.NewError("internal_error", true)
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
