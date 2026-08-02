package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"net/http"

	"github.com/kciceblue/sshserver/runtime/internal/api"
)

func (store *Store) handleGetEnvelope(ctx context.Context, call api.Request) (api.Response, *api.Error) {
	if len(call.Body) != 0 {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	transaction, protocolErr := beginTransaction(ctx, store.db)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	defer transaction.Rollback()
	if _, protocolErr := store.authenticate(ctx, transaction, call.Authorization, "envelope:read"); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	_, runtimeGeneration, secretGeneration, _, protocolErr := readRuntimeState(ctx, transaction)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	var generationBytes, body []byte
	var bodyLength int64
	if err := transaction.QueryRowContext(ctx, `
		SELECT generation, length(envelope_json),
		       CASE WHEN length(envelope_json) BETWEEN 1 AND ? THEN envelope_json END
		FROM vault_envelope WHERE singleton = 1`, maxBodyBytes,
	).Scan(&generationBytes, &bodyLength, &body); errors.Is(err, sql.ErrNoRows) {
		if runtimeGeneration != 0 {
			return api.Response{}, api.NewError("internal_error", true)
		}
		return api.Response{}, api.NewError("envelope_missing", false)
	} else if err != nil || !boundedRequiredBytes(bodyLength, body, maxBodyBytes) {
		return api.Response{}, api.NewError("internal_error", true)
	}
	storedGeneration, err := DecodeUint64(generationBytes)
	if err != nil || storedGeneration != runtimeGeneration {
		return api.Response{}, api.NewError("internal_error", true)
	}
	var envelope vaultEnvelope
	if json.Unmarshal(body, &envelope) != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	envelopeGeneration, envelopeSecretGeneration, err := validateEnvelope(envelope, store.identity)
	canonical, marshalErr := marshalJSON(envelope)
	if err != nil || marshalErr != nil || envelopeGeneration != runtimeGeneration || envelopeSecretGeneration != secretGeneration || !bytes.Equal(canonical, body) {
		return api.Response{}, api.NewError("internal_error", true)
	}
	return api.Response{Status: http.StatusOK, Body: body}, nil
}

func (store *Store) handlePutEnvelope(ctx context.Context, call api.Request) (api.Response, *api.Error) {
	var request putEnvelopeRequest
	if err := decodeStrict(call.Body, &request); err != nil {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	expected, err := parseUint64(request.ExpectedGeneration)
	if err != nil {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	transaction, protocolErr := beginTransaction(ctx, store.db)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	defer transaction.Rollback()
	authenticated, protocolErr := store.authenticate(ctx, transaction, call.Authorization, "envelope:write")
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	fingerprint, protocolErr := requestFingerprint(store, "JAT vault envelope request fingerprint v1", authenticated.DeviceID, call.Body)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if response, found, protocolErr := store.lookupReceipt(ctx, transaction, authenticated.DeviceID, "vault-envelope", call.RequestID, fingerprint); protocolErr != nil || found {
		return response, protocolErr
	}
	cursor, storedGeneration, secretGeneration, _, protocolErr := readRuntimeState(ctx, transaction)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if err := validatePersistentEnvelope(ctx, transaction, store.identity, storedGeneration, secretGeneration); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if expected != storedGeneration {
		return api.Response{}, api.NewError("generation_conflict", true)
	}
	if storedGeneration == math.MaxUint64 {
		return api.Response{}, api.NewError("generation_exhausted", false)
	}
	newGeneration, err := parseUint64(request.NewGeneration)
	if err != nil {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	if newGeneration != storedGeneration+1 {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	if cursor == math.MaxUint64 {
		return api.Response{}, api.NewError("server_cursor_exhausted", false)
	}
	envelopeGeneration, envelopeSecretGeneration, err := validateEnvelope(request.Envelope, store.identity)
	if err != nil || envelopeGeneration != newGeneration || envelopeSecretGeneration != secretGeneration {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	responseBody, err := marshalJSON(request.Envelope)
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	encodedGeneration := EncodeUint64(newGeneration)
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO vault_envelope (singleton, generation, envelope_json)
		VALUES (1, ?, ?)
		ON CONFLICT(singleton) DO UPDATE SET generation = excluded.generation, envelope_json = excluded.envelope_json`,
		encodedGeneration[:], responseBody,
	); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE runtime_state SET envelope_generation = ? WHERE singleton = 1", encodedGeneration[:]); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	newCursor := cursor + 1
	if protocolErr := insertChange(ctx, transaction, newCursor, "envelope_changed", "", "", "", "", call.Now); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	response := api.Response{Status: http.StatusOK, Body: responseBody}
	checkpoint, protocolErr := store.storeReceipt(ctx, transaction, authenticated.DeviceID, "vault-envelope", call.RequestID, fingerprint, response, call.Now)
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
