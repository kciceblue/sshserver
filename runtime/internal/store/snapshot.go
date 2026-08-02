package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"slices"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
	"github.com/kciceblue/sshserver/runtime/internal/auth"
)

type snapshotPageDescriptor struct {
	RevisionIDs       []string           `json:"revision_ids"`
	CollectionMarkers []collectionMarker `json:"collection_markers"`
	SourceDevices     []sourceDevice     `json:"source_devices"`
	NextPageToken     *string            `json:"next_page_token"`
	HasMore           bool               `json:"has_more"`
}

type storedSnapshotPage struct {
	token      string
	descriptor snapshotPageDescriptor
	body       []byte
}

type snapshotRevisionReference struct {
	revisionID  string
	contentHash [32]byte
}

const snapshotMetadataLimit int64 = 64 * 1024 * 1024

func (store *Store) handleCreateSnapshot(ctx context.Context, call api.Request) (api.Response, *api.Error) {
	var request snapshotCreateRequest
	if err := decodeStrict(call.Body, &request); err != nil || request.ProtocolVersion != "1" ||
		validateUUID(request.DeviceID) != nil || validateUUID(request.RequestID) != nil || request.RequestID != call.RequestID {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	if !slices.Equal(request.RequiredCapabilities, requiredSnapshotCapabilities) {
		return api.Response{}, api.NewError("unsupported_capability", false)
	}
	transaction, protocolErr := beginTransaction(ctx, store.db)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	defer transaction.Rollback()
	authenticated, protocolErr := store.authenticate(ctx, transaction, call.Authorization, "sync:read")
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if authenticated.DeviceID != request.DeviceID {
		return api.Response{}, api.NewError("authenticated_device_mismatch", false)
	}
	fingerprint, protocolErr := requestFingerprint(store, "JAT snapshot create request fingerprint v1", authenticated.DeviceID, call.Body)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	var storedFingerprint, storedResponse []byte
	var storedSnapshotID, storedOwner string
	var storedCutBytes, storedGenerationBytes []byte
	var storedExpiresAt int64
	err := transaction.QueryRowContext(ctx, `
		SELECT snapshot_id, owner_device_id, request_fingerprint, cut_cursor,
		       envelope_generation, expires_at_ms, create_response_json FROM snapshots
		WHERE owner_device_id = ? AND request_id = ?`, authenticated.DeviceID, call.RequestID,
	).Scan(&storedSnapshotID, &storedOwner, &storedFingerprint, &storedCutBytes, &storedGenerationBytes, &storedExpiresAt, &storedResponse)
	if err == nil {
		storedCut, cutErr := DecodeUint64(storedCutBytes)
		storedGeneration, generationErr := DecodeUint64(storedGenerationBytes)
		if len(storedFingerprint) != 32 || cutErr != nil || generationErr != nil ||
			validateStoredSnapshotCreateResponse(storedResponse, store.identity, storedSnapshotID, storedOwner, storedCut, storedGeneration, storedExpiresAt) != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		var recorded [32]byte
		copy(recorded[:], storedFingerprint)
		if !auth.VerifyHash(recorded, fingerprint) {
			return api.Response{}, api.NewError("request_id_reused", false)
		}
		return api.Response{Status: http.StatusOK, Body: storedResponse}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if protocolErr := store.admitSnapshotAttempt(authenticated.DeviceID, call.Now); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if protocolErr := store.pruneExpiredSnapshots(ctx, transaction, call.Now); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	var activeForDevice, activeForInstance int
	var activeMetadata int64
	if err := transaction.QueryRowContext(ctx, `
		SELECT coalesce(sum(owner_device_id = ?), 0), count(*), coalesce(sum(metadata_bytes), 0)
		FROM (SELECT owner_device_id, metadata_bytes FROM snapshots LIMIT 9)`, authenticated.DeviceID,
	).Scan(&activeForDevice, &activeForInstance, &activeMetadata); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if activeForInstance > 8 {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if activeForDevice >= 1 || activeForInstance >= 8 {
		return api.Response{}, api.NewError("limit_exceeded", false)
	}
	if activeMetadata < 0 || activeMetadata > snapshotMetadataLimit {
		return api.Response{}, api.NewError("internal_error", true)
	}
	serverCursor, envelopeGeneration, secretGeneration, protocolErr := readRuntimeState(ctx, transaction)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	var envelopeBody []byte
	if err := transaction.QueryRowContext(ctx, "SELECT envelope_json FROM vault_envelope WHERE singleton = 1").Scan(&envelopeBody); errors.Is(err, sql.ErrNoRows) {
		return api.Response{}, api.NewError("envelope_missing", false)
	} else if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	var envelope vaultEnvelope
	if json.Unmarshal(envelopeBody, &envelope) != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	validatedGeneration, validatedSecretGeneration, err := validateEnvelope(envelope, store.identity)
	canonicalEnvelope, marshalErr := marshalJSON(envelope)
	if err != nil || marshalErr != nil || validatedGeneration != envelopeGeneration || validatedSecretGeneration != secretGeneration || !bytes.Equal(canonicalEnvelope, envelopeBody) {
		return api.Response{}, api.NewError("internal_error", true)
	}
	snapshotID, protocolErr := generateUUID()
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	pages, revisionReferences, protocolErr := buildSnapshotPlan(ctx, transaction, snapshotID, authenticated.DeviceID, call.RequestID, serverCursor, envelopeGeneration, snapshotMetadataLimit-activeMetadata)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	expiresAt := call.Now.UTC().Add(snapshotLifetime).Truncate(time.Millisecond)
	createBody, err := marshalJSON(snapshotCreateResponse{
		ProtocolVersion:    "1",
		SnapshotID:         snapshotID,
		CutCursor:          encodeUint64Text(serverCursor),
		EnvelopeGeneration: encodeUint64Text(envelopeGeneration),
		Envelope:           envelope,
		ExpiresAt:          formatTimestamp(expiresAt.UnixMilli()),
		FirstPageToken:     pages[0].token,
	})
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	metadataBytes, ok := snapshotMetadataBytes(snapshotID, authenticated.DeviceID, call.RequestID, createBody, pages, revisionReferences)
	if !ok || metadataBytes > snapshotMetadataLimit-activeMetadata {
		return api.Response{}, api.NewError("limit_exceeded", false)
	}
	cutCursor := EncodeUint64(serverCursor)
	encodedGeneration := EncodeUint64(envelopeGeneration)
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO snapshots (
			snapshot_id, owner_device_id, request_id, request_fingerprint,
			cut_cursor, envelope_generation, expires_at_ms, metadata_bytes,
			create_response_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		snapshotID, authenticated.DeviceID, call.RequestID, fingerprint[:], cutCursor[:], encodedGeneration[:],
		expiresAt.UnixMilli(), metadataBytes, createBody,
	); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	for index, page := range pages {
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO snapshot_pages (snapshot_id, page_index, page_token, response_json)
			VALUES (?, ?, ?, ?)`, snapshotID, index, page.token, page.body); err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
	}
	for _, reference := range revisionReferences {
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO snapshot_revision_refs (snapshot_id, revision_id, content_hash)
			VALUES (?, ?, ?)`, snapshotID, reference.revisionID, reference.contentHash[:]); err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
	}
	var maxReturnedBytes []byte
	if err := transaction.QueryRowContext(ctx, "SELECT max_returned_cursor FROM device_sync_state WHERE device_id = ?", authenticated.DeviceID).Scan(&maxReturnedBytes); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	maxReturned, err := DecodeUint64(maxReturnedBytes)
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if serverCursor > maxReturned {
		encodedReturned := EncodeUint64(serverCursor)
		if _, err := transaction.ExecContext(ctx, "UPDATE device_sync_state SET max_returned_cursor = ? WHERE device_id = ?", encodedReturned[:], authenticated.DeviceID); err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
	}
	store.ephemeral.mu.Lock()
	store.ephemeral.snapshotDeadlines[snapshotID] = call.Now.Add(snapshotLifetime)
	store.ephemeral.mu.Unlock()
	protocolErr = commitTransaction(transaction)
	if protocolErr != nil {
		store.ephemeral.mu.Lock()
		delete(store.ephemeral.snapshotDeadlines, snapshotID)
		store.ephemeral.mu.Unlock()
	}
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	return api.Response{Status: http.StatusCreated, Body: createBody}, nil
}

func (store *Store) handleSnapshotPage(ctx context.Context, call api.Request, snapshotID string) (api.Response, *api.Error) {
	var request snapshotPageRequest
	if err := decodeStrict(call.Body, &request); err != nil || request.ProtocolVersion != "1" || validateUUID(request.DeviceID) != nil {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	if _, err := decodeBase64(request.PageToken, 32, 0, 0); err != nil {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	transaction, protocolErr := beginTransaction(ctx, store.db)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	defer transaction.Rollback()
	authenticated, protocolErr := store.authenticate(ctx, transaction, call.Authorization, "sync:read")
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if authenticated.DeviceID != request.DeviceID {
		return api.Response{}, api.NewError("authenticated_device_mismatch", false)
	}
	var ownerDeviceID string
	var cutBytes, generationBytes []byte
	var expiresAt int64
	if err := transaction.QueryRowContext(ctx, `
		SELECT owner_device_id, cut_cursor, envelope_generation, expires_at_ms
		FROM snapshots WHERE snapshot_id = ?`, snapshotID,
	).Scan(&ownerDeviceID, &cutBytes, &generationBytes, &expiresAt); errors.Is(err, sql.ErrNoRows) {
		return api.Response{}, api.NewError("snapshot_not_found", false)
	} else if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if ownerDeviceID != authenticated.DeviceID {
		return api.Response{}, api.NewError("snapshot_not_found", false)
	}
	store.ephemeral.mu.Lock()
	deadline, hasDeadline := store.ephemeral.snapshotDeadlines[snapshotID]
	store.ephemeral.mu.Unlock()
	if !hasDeadline || !call.Now.Before(deadline) {
		return api.Response{}, api.NewError("snapshot_expired", false)
	}
	cutCursor, err := DecodeUint64(cutBytes)
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	envelopeGeneration, err := DecodeUint64(generationBytes)
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	var descriptorBody []byte
	if err := transaction.QueryRowContext(ctx, `
		SELECT response_json FROM snapshot_pages
		WHERE snapshot_id = ? AND page_token = ?`, snapshotID, request.PageToken,
	).Scan(&descriptorBody); errors.Is(err, sql.ErrNoRows) {
		return api.Response{}, api.NewError("invalid_request", false)
	} else if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	var descriptor snapshotPageDescriptor
	if decodeStoredSnapshotPageDescriptor(descriptorBody, &descriptor) != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	revisions := make([]recordRevision, 0, len(descriptor.RevisionIDs))
	for _, revisionID := range descriptor.RevisionIDs {
		var revisionBody, storedHashBytes, referencedHashBytes []byte
		if err := transaction.QueryRowContext(ctx, `
			SELECT o.revision_json, o.content_hash, s.content_hash
			FROM snapshot_revision_refs s
			JOIN revision_objects o USING (content_hash)
			WHERE s.snapshot_id = ? AND s.revision_id = ?`, snapshotID, revisionID,
		).Scan(&revisionBody, &storedHashBytes, &referencedHashBytes); err != nil || len(storedHashBytes) != 32 || len(referencedHashBytes) != 32 {
			return api.Response{}, api.NewError("internal_error", true)
		}
		var storedHash, referencedHash [32]byte
		copy(storedHash[:], storedHashBytes)
		copy(referencedHash[:], referencedHashBytes)
		if !auth.VerifyHash(storedHash, referencedHash) {
			return api.Response{}, api.NewError("internal_error", true)
		}
		var revision recordRevision
		if json.Unmarshal(revisionBody, &revision) != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		canonical, err := marshalJSON(revision)
		computedHash := sha256.Sum256(canonical)
		if err != nil || !bytes.Equal(canonical, revisionBody) || !auth.VerifyHash(storedHash, computedHash) {
			return api.Response{}, api.NewError("internal_error", true)
		}
		if _, _, err := validateRevision(revision); err != nil || revision.RevisionID != revisionID {
			return api.Response{}, api.NewError("internal_error", true)
		}
		revisions = append(revisions, revision)
	}
	body, err := marshalJSON(snapshotPageResponse{
		ProtocolVersion:    "1",
		SnapshotID:         snapshotID,
		CutCursor:          encodeUint64Text(cutCursor),
		EnvelopeGeneration: encodeUint64Text(envelopeGeneration),
		Revisions:          revisions,
		CollectionMarkers:  descriptor.CollectionMarkers,
		SourceDevices:      descriptor.SourceDevices,
		NextPageToken:      descriptor.NextPageToken,
		HasMore:            descriptor.HasMore,
	})
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if len(body) > maxBodyBytes {
		return api.Response{}, api.NewError("internal_error", true)
	}
	return api.Response{Status: http.StatusOK, Body: body}, nil
}

func decodeStoredSnapshotPageDescriptor(body []byte, descriptor *snapshotPageDescriptor) error {
	if err := decodeStoredCanonical(body, descriptor); err != nil {
		return err
	}
	if len(descriptor.RevisionIDs) > 128 || len(descriptor.CollectionMarkers) > 128 || len(descriptor.SourceDevices) > 64 {
		return errors.New("stored snapshot page exceeds item limits")
	}
	nonemptyPhases := 0
	if len(descriptor.RevisionIDs) != 0 {
		nonemptyPhases++
	}
	if len(descriptor.CollectionMarkers) != 0 {
		nonemptyPhases++
	}
	if len(descriptor.SourceDevices) != 0 {
		nonemptyPhases++
	}
	if nonemptyPhases > 1 || nonemptyPhases == 0 && descriptor.HasMore {
		return errors.New("stored snapshot page mixes phases")
	}
	if descriptor.HasMore {
		if descriptor.NextPageToken == nil {
			return errors.New("stored snapshot page omits next token")
		}
		if _, err := decodeBase64(*descriptor.NextPageToken, 32, 0, 0); err != nil {
			return err
		}
	} else if descriptor.NextPageToken != nil {
		return errors.New("stored final snapshot page has a next token")
	}
	seenRevisionIDs := make(map[string]struct{}, len(descriptor.RevisionIDs))
	for _, revisionID := range descriptor.RevisionIDs {
		if validateUUID(revisionID) != nil {
			return errors.New("stored snapshot revision IDs are invalid")
		}
		if _, exists := seenRevisionIDs[revisionID]; exists {
			return errors.New("stored snapshot revision IDs are duplicated")
		}
		seenRevisionIDs[revisionID] = struct{}{}
	}
	for index, marker := range descriptor.CollectionMarkers {
		if _, _, _, err := validateCollectionMarker(marker); err != nil || index != 0 && descriptor.CollectionMarkers[index-1].RecordID >= marker.RecordID {
			return errors.New("stored snapshot markers are invalid")
		}
	}
	for index, source := range descriptor.SourceDevices {
		if validateUUID(source.DeviceID) != nil || index != 0 && descriptor.SourceDevices[index-1].DeviceID >= source.DeviceID {
			return errors.New("stored snapshot devices are invalid")
		}
		if _, err := parseUint64(source.MaxAuthorCounter); err != nil {
			return err
		}
	}
	return nil
}

func (store *Store) admitSnapshotAttempt(deviceID string, now time.Time) *api.Error {
	store.ephemeral.mu.Lock()
	defer store.ephemeral.mu.Unlock()
	if !store.ephemeral.booted {
		return api.NewError("internal_error", true)
	}
	cutoff := now.Add(-time.Minute)
	retained := store.ephemeral.snapshotAttempts[deviceID][:0]
	for _, attempt := range store.ephemeral.snapshotAttempts[deviceID] {
		if attempt.After(cutoff) {
			retained = append(retained, attempt)
		}
	}
	if len(retained) >= 5 {
		store.ephemeral.snapshotAttempts[deviceID] = retained
		return api.NewError("rate_limited", false)
	}
	store.ephemeral.snapshotAttempts[deviceID] = append(retained, now)
	return nil
}

func (store *Store) pruneExpiredSnapshots(ctx context.Context, transaction *sql.Tx, now time.Time) *api.Error {
	rows, err := transaction.QueryContext(ctx, "SELECT snapshot_id FROM snapshots ORDER BY snapshot_id LIMIT 9")
	if err != nil {
		return api.NewError("internal_error", true)
	}
	var identifiers []string
	for rows.Next() {
		var identifier string
		if err := rows.Scan(&identifier); err != nil {
			rows.Close()
			return api.NewError("internal_error", true)
		}
		identifiers = append(identifiers, identifier)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return api.NewError("internal_error", true)
	}
	if err := rows.Close(); err != nil {
		return api.NewError("internal_error", true)
	}
	if len(identifiers) > 8 {
		return api.NewError("internal_error", true)
	}
	store.ephemeral.mu.Lock()
	var expired []string
	for _, identifier := range identifiers {
		deadline, exists := store.ephemeral.snapshotDeadlines[identifier]
		if !exists || !now.Before(deadline) {
			expired = append(expired, identifier)
			delete(store.ephemeral.snapshotDeadlines, identifier)
		}
	}
	store.ephemeral.mu.Unlock()
	for _, identifier := range expired {
		if protocolErr := deleteSnapshotAndReleaseObjects(ctx, transaction, identifier); protocolErr != nil {
			return protocolErr
		}
	}
	return nil
}

func deleteSnapshotAndReleaseObjects(ctx context.Context, transaction *sql.Tx, snapshotID string) *api.Error {
	rows, err := transaction.QueryContext(ctx, `
		SELECT revision_id, content_hash FROM snapshot_revision_refs
		WHERE snapshot_id = ? ORDER BY revision_id`, snapshotID)
	if err != nil {
		return api.NewError("internal_error", true)
	}
	var references []snapshotRevisionReference
	for rows.Next() {
		var reference snapshotRevisionReference
		var hashBytes []byte
		if rows.Scan(&reference.revisionID, &hashBytes) != nil || len(hashBytes) != 32 {
			rows.Close()
			return api.NewError("internal_error", true)
		}
		copy(reference.contentHash[:], hashBytes)
		references = append(references, reference)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return api.NewError("internal_error", true)
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM snapshots WHERE snapshot_id = ?", snapshotID); err != nil {
		return api.NewError("internal_error", true)
	}
	for _, reference := range references {
		if protocolErr := deleteUnreferencedRevisionObject(ctx, transaction, reference.contentHash, reference.revisionID); protocolErr != nil {
			return protocolErr
		}
	}
	return nil
}

func buildSnapshotPlan(ctx context.Context, transaction *sql.Tx, snapshotID, ownerDeviceID, requestID string, cutCursor, envelopeGeneration uint64, availableMetadata int64) ([]storedSnapshotPage, []snapshotRevisionReference, *api.Error) {
	if availableMetadata < 0 {
		return nil, nil, api.NewError("limit_exceeded", false)
	}
	lower := snapshotMetadataAccounting{}
	accountSnapshotBase(&lower, snapshotID, ownerDeviceID, requestID, nil)
	if !lower.ok() || lower.total > availableMetadata {
		return nil, nil, api.NewError("limit_exceeded", false)
	}
	var descriptors []snapshotPageDescriptor
	appendDescriptor := func(descriptor snapshotPageDescriptor) *api.Error {
		body, err := marshalJSON(descriptor)
		if err != nil {
			return api.NewError("internal_error", true)
		}
		accountSnapshotPage(&lower, snapshotID, len(descriptors), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", body)
		if !lower.ok() || lower.total > availableMetadata {
			return api.NewError("limit_exceeded", false)
		}
		descriptors = append(descriptors, descriptor)
		return nil
	}

	rows, err := transaction.QueryContext(ctx, `
		SELECT r.record_id, r.revision_id, r.content_hash, o.revision_json
		FROM record_heads h
		JOIN record_revisions r ON r.revision_id = h.revision_id
		JOIN revision_objects o USING (content_hash)
		ORDER BY h.record_id, h.revision_id`)
	if err != nil {
		return nil, nil, api.NewError("internal_error", true)
	}
	var references []snapshotRevisionReference
	var pageRevisions []recordRevision
	var pageRevisionIDs []string
	var previousRecordID, previousRevisionID string
	finishRevisionPage := func() *api.Error {
		if len(pageRevisionIDs) == 0 {
			return nil
		}
		descriptor := snapshotPageDescriptor{RevisionIDs: append([]string(nil), pageRevisionIDs...), CollectionMarkers: []collectionMarker{}, SourceDevices: []sourceDevice{}}
		if protocolErr := appendDescriptor(descriptor); protocolErr != nil {
			return protocolErr
		}
		pageRevisions = nil
		pageRevisionIDs = nil
		return nil
	}
	for rows.Next() {
		var recordID, revisionID string
		var hashBytes, body []byte
		var revision recordRevision
		if rows.Scan(&recordID, &revisionID, &hashBytes, &body) != nil || validateUUID(recordID) != nil || validateUUID(revisionID) != nil || len(hashBytes) != 32 ||
			previousRecordID != "" && (recordID < previousRecordID || recordID == previousRecordID && revisionID <= previousRevisionID) ||
			decodeStoredCanonical(body, &revision) != nil || revision.RecordID != recordID || revision.RevisionID != revisionID {
			rows.Close()
			return nil, nil, api.NewError("internal_error", true)
		}
		computed := sha256.Sum256(body)
		if !bytes.Equal(computed[:], hashBytes) {
			rows.Close()
			return nil, nil, api.NewError("internal_error", true)
		}
		candidateRevisions := append(pageRevisions, revision)
		candidateIDs := append(pageRevisionIDs, revisionID)
		if len(candidateRevisions) > 128 || !snapshotPageFits(snapshotID, cutCursor, envelopeGeneration, candidateRevisions, snapshotPageDescriptor{RevisionIDs: candidateIDs, CollectionMarkers: []collectionMarker{}, SourceDevices: []sourceDevice{}}) {
			if len(pageRevisions) == 0 {
				rows.Close()
				return nil, nil, api.NewError("internal_error", true)
			}
			if protocolErr := finishRevisionPage(); protocolErr != nil {
				rows.Close()
				return nil, nil, protocolErr
			}
			pageRevisions = []recordRevision{revision}
			pageRevisionIDs = []string{revisionID}
			if !snapshotPageFits(snapshotID, cutCursor, envelopeGeneration, pageRevisions, snapshotPageDescriptor{RevisionIDs: pageRevisionIDs, CollectionMarkers: []collectionMarker{}, SourceDevices: []sourceDevice{}}) {
				rows.Close()
				return nil, nil, api.NewError("internal_error", true)
			}
		} else {
			pageRevisions = candidateRevisions
			pageRevisionIDs = candidateIDs
		}
		var contentHash [32]byte
		copy(contentHash[:], hashBytes)
		reference := snapshotRevisionReference{revisionID: revisionID, contentHash: contentHash}
		accountSnapshotReference(&lower, snapshotID, reference)
		if !lower.ok() || lower.total > availableMetadata {
			rows.Close()
			return nil, nil, api.NewError("limit_exceeded", false)
		}
		references = append(references, reference)
		previousRecordID, previousRevisionID = recordID, revisionID
	}
	if rows.Err() != nil || rows.Close() != nil {
		return nil, nil, api.NewError("internal_error", true)
	}
	if protocolErr := finishRevisionPage(); protocolErr != nil {
		return nil, nil, protocolErr
	}

	markerRows, err := transaction.QueryContext(ctx, "SELECT marker_json FROM collection_markers ORDER BY record_id")
	if err != nil {
		return nil, nil, api.NewError("internal_error", true)
	}
	var pageMarkers []collectionMarker
	previousRecordID = ""
	finishMarkerPage := func() *api.Error {
		if len(pageMarkers) == 0 {
			return nil
		}
		descriptor := snapshotPageDescriptor{RevisionIDs: []string{}, CollectionMarkers: append([]collectionMarker(nil), pageMarkers...), SourceDevices: []sourceDevice{}}
		if protocolErr := appendDescriptor(descriptor); protocolErr != nil {
			return protocolErr
		}
		pageMarkers = nil
		return nil
	}
	for markerRows.Next() {
		var body []byte
		if markerRows.Scan(&body) != nil {
			markerRows.Close()
			return nil, nil, api.NewError("internal_error", true)
		}
		marker, err := decodeStoredCollectionMarker(body)
		if err != nil || previousRecordID != "" && previousRecordID >= marker.RecordID {
			markerRows.Close()
			return nil, nil, api.NewError("internal_error", true)
		}
		candidate := append(pageMarkers, marker)
		descriptor := snapshotPageDescriptor{RevisionIDs: []string{}, CollectionMarkers: candidate, SourceDevices: []sourceDevice{}}
		if len(candidate) > 128 || !snapshotPageFits(snapshotID, cutCursor, envelopeGeneration, nil, descriptor) {
			if len(pageMarkers) == 0 {
				markerRows.Close()
				return nil, nil, api.NewError("internal_error", true)
			}
			if protocolErr := finishMarkerPage(); protocolErr != nil {
				markerRows.Close()
				return nil, nil, protocolErr
			}
			pageMarkers = []collectionMarker{marker}
		} else {
			pageMarkers = candidate
		}
		previousRecordID = marker.RecordID
	}
	if markerRows.Err() != nil || markerRows.Close() != nil {
		return nil, nil, api.NewError("internal_error", true)
	}
	if protocolErr := finishMarkerPage(); protocolErr != nil {
		return nil, nil, protocolErr
	}

	deviceRows, err := transaction.QueryContext(ctx, "SELECT device_id, max_author_counter FROM devices ORDER BY device_id LIMIT 65")
	if err != nil {
		return nil, nil, api.NewError("internal_error", true)
	}
	var pageDevices []sourceDevice
	var previousDeviceID string
	for deviceRows.Next() {
		var deviceID string
		var counterBytes []byte
		if deviceRows.Scan(&deviceID, &counterBytes) != nil || validateUUID(deviceID) != nil || previousDeviceID != "" && previousDeviceID >= deviceID {
			deviceRows.Close()
			return nil, nil, api.NewError("internal_error", true)
		}
		counter, err := DecodeUint64(counterBytes)
		if err != nil {
			deviceRows.Close()
			return nil, nil, api.NewError("internal_error", true)
		}
		pageDevices = append(pageDevices, sourceDevice{DeviceID: deviceID, MaxAuthorCounter: encodeUint64Text(counter)})
		previousDeviceID = deviceID
	}
	if deviceRows.Err() != nil || deviceRows.Close() != nil || len(pageDevices) > 64 {
		return nil, nil, api.NewError("internal_error", true)
	}
	if len(pageDevices) != 0 {
		descriptor := snapshotPageDescriptor{RevisionIDs: []string{}, CollectionMarkers: []collectionMarker{}, SourceDevices: pageDevices}
		if !snapshotPageFits(snapshotID, cutCursor, envelopeGeneration, nil, descriptor) {
			return nil, nil, api.NewError("internal_error", true)
		}
		if protocolErr := appendDescriptor(descriptor); protocolErr != nil {
			return nil, nil, protocolErr
		}
	}
	if len(descriptors) == 0 {
		if protocolErr := appendDescriptor(snapshotPageDescriptor{RevisionIDs: []string{}, CollectionMarkers: []collectionMarker{}, SourceDevices: []sourceDevice{}}); protocolErr != nil {
			return nil, nil, protocolErr
		}
	}
	tokens := make([]string, len(descriptors))
	for index := range tokens {
		token, err := encodeRandomBase64(32)
		if err != nil {
			return nil, nil, api.NewError("internal_error", true)
		}
		tokens[index] = token
	}
	pages := make([]storedSnapshotPage, len(descriptors))
	for index := range descriptors {
		descriptors[index].HasMore = index+1 < len(descriptors)
		if descriptors[index].HasMore {
			next := tokens[index+1]
			descriptors[index].NextPageToken = &next
		}
		body, err := marshalJSON(descriptors[index])
		if err != nil {
			return nil, nil, api.NewError("internal_error", true)
		}
		pages[index] = storedSnapshotPage{token: tokens[index], descriptor: descriptors[index], body: body}
	}
	return pages, references, nil
}

func snapshotPageFits(snapshotID string, cutCursor, envelopeGeneration uint64, revisions []recordRevision, descriptor snapshotPageDescriptor) bool {
	placeholder := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	body, err := marshalJSON(snapshotPageResponse{
		ProtocolVersion:    "1",
		SnapshotID:         snapshotID,
		CutCursor:          encodeUint64Text(cutCursor),
		EnvelopeGeneration: encodeUint64Text(envelopeGeneration),
		Revisions:          revisions,
		CollectionMarkers:  descriptor.CollectionMarkers,
		SourceDevices:      descriptor.SourceDevices,
		NextPageToken:      &placeholder,
		HasMore:            true,
	})
	return err == nil && len(body) <= maxBodyBytes
}

// snapshotMetadataAccounting is the reviewed serialized accounting
// representation for the 64 MiB cap. Every record is encoded as lp(tag), an
// eight-byte field count, then lp(field) values; lp is an eight-byte big-endian
// length followed by the exact bytes. It counts owned table rows, implicit
// primary/unique index entries, the daemon-monotonic lease, page tokens and
// content-address references. Shared immutable revision payloads are excluded.
type snapshotMetadataAccounting struct {
	total    int64
	overflow bool
}

func (account *snapshotMetadataAccounting) addLength(length int) {
	if account.overflow || length < 0 || int64(length) > math.MaxInt64-account.total {
		account.overflow = true
		return
	}
	account.total += int64(length)
}

func (account *snapshotMetadataAccounting) addLP(value []byte) {
	account.addLength(8)
	account.addLength(len(value))
}

func (account *snapshotMetadataAccounting) addRecord(tag string, fields ...[]byte) {
	account.addLP([]byte(tag))
	account.addLength(8)
	for _, field := range fields {
		account.addLP(field)
	}
}

func (account snapshotMetadataAccounting) ok() bool { return !account.overflow }

func accountingUint64(value uint64) []byte {
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, value)
	return encoded
}

func accountSnapshotBase(account *snapshotMetadataAccounting, snapshotID, ownerDeviceID, requestID string, createBody []byte) {
	zero32 := make([]byte, 32)
	zero8 := make([]byte, 8)
	account.addRecord("snapshots.row", []byte(snapshotID), []byte(ownerDeviceID), []byte(requestID), zero32, zero8, zero8, zero8, zero8, createBody)
	account.addRecord("snapshots.pk", []byte(snapshotID))
	account.addRecord("snapshots.owner_request.unique", []byte(ownerDeviceID), []byte(requestID), []byte(snapshotID))
	account.addRecord("snapshots.monotonic_lease", []byte(snapshotID), zero8)
}

func accountSnapshotPage(account *snapshotMetadataAccounting, snapshotID string, pageIndex int, token string, body []byte) {
	index := accountingUint64(uint64(pageIndex))
	account.addRecord("snapshot_pages.row", []byte(snapshotID), index, []byte(token), body)
	account.addRecord("snapshot_pages.pk", []byte(snapshotID), index)
	account.addRecord("snapshot_pages.token.unique", []byte(token), []byte(snapshotID), index)
}

func accountSnapshotReference(account *snapshotMetadataAccounting, snapshotID string, reference snapshotRevisionReference) {
	account.addRecord("snapshot_revision_refs.row", []byte(snapshotID), []byte(reference.revisionID), reference.contentHash[:])
	account.addRecord("snapshot_revision_refs.pk", []byte(snapshotID), []byte(reference.revisionID))
}

func snapshotMetadataBytes(snapshotID, ownerDeviceID, requestID string, createBody []byte, pages []storedSnapshotPage, references []snapshotRevisionReference) (int64, bool) {
	account := snapshotMetadataAccounting{}
	accountSnapshotBase(&account, snapshotID, ownerDeviceID, requestID, createBody)
	for index, page := range pages {
		accountSnapshotPage(&account, snapshotID, index, page.token, page.body)
	}
	for _, reference := range references {
		accountSnapshotReference(&account, snapshotID, reference)
	}
	return account.total, account.ok()
}
