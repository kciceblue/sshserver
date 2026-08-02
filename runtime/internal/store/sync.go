package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"sort"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
)

type pendingRevision struct {
	revision      recordRevision
	canonical     []byte
	contentHash   [32]byte
	authorCounter uint64
	vector        map[string]uint64
	isNew         bool
}

func (store *Store) handleSync(ctx context.Context, call api.Request) (api.Response, *api.Error) {
	var request syncRequest
	if err := decodeStrict(call.Body, &request); err != nil || request.ProtocolVersion != "1" ||
		validateUUID(request.DeviceID) != nil || validateUUID(request.RequestID) != nil || request.RequestID != call.RequestID ||
		len(request.Mutations) > maxMutations {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	if protocolErr := validateMutationShapes(request.DeviceID, request.Mutations); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	afterCursor, err := parseUint64(request.AfterCursor)
	if err != nil {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	ackCursor, err := parseUint64(request.AckCursor)
	if err != nil {
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
	if len(request.Mutations) != 0 && !hasScope(authenticated.Scopes, "sync:write") {
		return api.Response{}, api.NewError("scope_denied", false)
	}
	fingerprint, protocolErr := requestFingerprint(store, "JAT sync request fingerprint v1", authenticated.DeviceID, call.Body)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if response, found, protocolErr := store.lookupReceipt(ctx, transaction, authenticated.DeviceID, "sync", call.RequestID, fingerprint); protocolErr != nil || found {
		return response, protocolErr
	}
	serverCursor, envelopeGeneration, _, protocolErr := readRuntimeState(ctx, transaction)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	cursorFloor, protocolErr := readCursorFloor(ctx, transaction)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if afterCursor < cursorFloor {
		return api.Response{}, api.NewError("cursor_expired", false)
	}
	if afterCursor > serverCursor {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	accumulatedUptimeMS, checkpoint, protocolErr := store.checkpointUptimeTx(ctx, transaction, call.Now)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	var storedAckBytes, maxCounterBytes, maxReturnedBytes []byte
	var createdAtMS int64
	if err := transaction.QueryRowContext(ctx, `
		SELECT d.created_at_ms, d.last_ack_cursor, d.max_author_counter, s.max_returned_cursor
		FROM devices d JOIN device_sync_state s USING (device_id)
		WHERE d.device_id = ?`, authenticated.DeviceID,
	).Scan(&createdAtMS, &storedAckBytes, &maxCounterBytes, &maxReturnedBytes); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	storedAck, err := DecodeUint64(storedAckBytes)
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	maxAuthorCounter, err := DecodeUint64(maxCounterBytes)
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	maxReturned, err := DecodeUint64(maxReturnedBytes)
	if err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if afterCursor > maxReturned {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	if ackCursor < storedAck || ackCursor > maxReturned {
		return api.Response{}, api.NewError("invalid_request", false)
	}
	pending, newCount, finalAuthorCounter, protocolErr := store.validateMutations(ctx, transaction, authenticated.DeviceID, maxAuthorCounter, request.Mutations)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if uint64(newCount) > math.MaxUint64-serverCursor {
		return api.Response{}, api.NewError("server_cursor_exhausted", false)
	}
	nextAssignedCursor := serverCursor
	for _, item := range pending {
		if !item.isNew {
			continue
		}
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO revision_objects (content_hash, revision_json)
			VALUES (?, ?) ON CONFLICT(content_hash) DO NOTHING`, item.contentHash[:], item.canonical); err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		var storedObject []byte
		var storedObjectLength int64
		if err := transaction.QueryRowContext(ctx, `
			SELECT length(revision_json),
			       CASE WHEN length(revision_json) BETWEEN 1 AND ? THEN revision_json END
			FROM revision_objects WHERE content_hash = ?`, maxBodyBytes, item.contentHash[:],
		).Scan(&storedObjectLength, &storedObject); err != nil || !boundedRequiredBytes(storedObjectLength, storedObject, maxBodyBytes) || !bytes.Equal(storedObject, item.canonical) {
			return api.Response{}, api.NewError("internal_error", true)
		}
		nextAssignedCursor++
		undominated, dominatedRevisionIDs, protocolErr := classifyRevisionFrontier(ctx, transaction, item.revision.RecordID, item.vector)
		if protocolErr != nil {
			return api.Response{}, protocolErr
		}
		for _, dominatedRevisionID := range dominatedRevisionIDs {
			if _, err := transaction.ExecContext(ctx, `
				UPDATE record_revisions SET undominated = 0
				WHERE revision_id = ? AND retained = 1 AND undominated = 1`, dominatedRevisionID); err != nil {
				return api.Response{}, api.NewError("internal_error", true)
			}
			if _, err := transaction.ExecContext(ctx, "DELETE FROM record_heads WHERE record_id = ? AND revision_id = ?", item.revision.RecordID, dominatedRevisionID); err != nil {
				return api.Response{}, api.NewError("internal_error", true)
			}
		}
		encodedCounter := EncodeUint64(item.authorCounter)
		encodedCursor := EncodeUint64(nextAssignedCursor)
		vectorJSON, _ := json.Marshal(item.revision.VersionVector)
		var witness any
		if item.revision.CollectionWitnessAuthenticator != nil {
			decoded, _ := decodeBase64(*item.revision.CollectionWitnessAuthenticator, 32, 0, 0)
			witness = decoded
		}
		encodedUptime := EncodeUint64(accumulatedUptimeMS)
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO record_revisions (
				revision_id, record_id, author_device_id, author_counter,
				vector_json, collection_witness_authenticator, tombstone,
				content_hash, received_at_ms, accepted_uptime_ms,
				change_cursor, retained, undominated
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
			item.revision.RevisionID, item.revision.RecordID, item.revision.AuthorDeviceID,
			encodedCounter[:], vectorJSON, witness, boolToInt(item.revision.Tombstone),
			item.contentHash[:], call.Now.UTC().UnixMilli(), encodedUptime[:], encodedCursor[:], boolToInt(undominated),
		); err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO collection_candidates (record_id, accepted_uptime_ms, revision_id)
			VALUES (?, ?, ?)`, item.revision.RecordID, encodedUptime[:], item.revision.RevisionID); err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		vectorHash := sha256.Sum256(vectorJSON)
		// Revision metadata is permanent in V1, so this index is permanent too:
		// equal-vector equivocation must retain its error precedence even after
		// the corresponding ciphertext object and change row are collected.
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO record_vector_index (record_id, vector_hash, revision_id)
			VALUES (?, ?, ?)`, item.revision.RecordID, vectorHash[:], item.revision.RevisionID); err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		if undominated {
			if _, err := transaction.ExecContext(ctx, "INSERT INTO record_heads (record_id, revision_id) VALUES (?, ?)", item.revision.RecordID, item.revision.RevisionID); err != nil {
				return api.Response{}, api.NewError("internal_error", true)
			}
		}
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO collection_records (record_id, barrier_cursor)
			VALUES (?, ?)
			ON CONFLICT(record_id) DO UPDATE SET barrier_cursor = excluded.barrier_cursor`, item.revision.RecordID, encodedCursor[:]); err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		if protocolErr := insertChange(ctx, transaction, nextAssignedCursor, "record_revision", item.revision.RevisionID, "", call.Now); protocolErr != nil {
			return api.Response{}, protocolErr
		}
	}
	if newCount != 0 {
		encodedCounter := EncodeUint64(finalAuthorCounter)
		if _, err := transaction.ExecContext(ctx, "UPDATE devices SET max_author_counter = ? WHERE device_id = ?", encodedCounter[:], authenticated.DeviceID); err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		if protocolErr := setServerCursor(ctx, transaction, nextAssignedCursor); protocolErr != nil {
			return api.Response{}, protocolErr
		}
		serverCursor = nextAssignedCursor
	}
	encodedAck := EncodeUint64(ackCursor)
	lastSyncAt := call.Now.UTC().Truncate(time.Millisecond).UnixMilli()
	if lastSyncAt < createdAtMS {
		lastSyncAt = createdAtMS
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE devices SET last_ack_cursor = ?, last_sync_at_ms = ? WHERE device_id = ?", encodedAck[:], lastSyncAt, authenticated.DeviceID); err != nil {
		return api.Response{}, api.NewError("internal_error", true)
	}
	if protocolErr := store.pruneExpiredSnapshots(ctx, transaction, call.Now); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	serverCursor, protocolErr = store.collectEligible(ctx, transaction, call.Now, accumulatedUptimeMS, serverCursor)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	// This request's acknowledgement can make collection eligible and advance
	// the retained-history floor. Never answer a now-expired after_cursor with a
	// silently incomplete delta; returning here rolls the whole transaction
	// back, including the acknowledgement and collection.
	cursorFloor, protocolErr = readCursorFloor(ctx, transaction)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if afterCursor < cursorFloor {
		return api.Response{}, api.NewError("cursor_expired", false)
	}
	changes, nextCursor, hasMore, protocolErr := loadChanges(ctx, transaction, afterCursor)
	if protocolErr != nil {
		return api.Response{}, protocolErr
	}
	var responseBody []byte
	for {
		responseBody, err = marshalJSON(syncResponse{
			ProtocolVersion:    "1",
			ServerCursor:       encodeUint64Text(serverCursor),
			NextCursor:         encodeUint64Text(nextCursor),
			HasMore:            hasMore,
			EnvelopeGeneration: encodeUint64Text(envelopeGeneration),
			Changes:            changes,
		})
		if err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		if len(responseBody) <= maxBodyBytes {
			break
		}
		if len(changes) <= 1 {
			return api.Response{}, api.NewError("internal_error", true)
		}
		changes = changes[:len(changes)-1]
		nextCursor, err = parseUint64(changes[len(changes)-1].Cursor)
		if err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
		hasMore = true
	}
	if nextCursor > maxReturned {
		encodedReturned := EncodeUint64(nextCursor)
		if _, err := transaction.ExecContext(ctx, "UPDATE device_sync_state SET max_returned_cursor = ? WHERE device_id = ?", encodedReturned[:], authenticated.DeviceID); err != nil {
			return api.Response{}, api.NewError("internal_error", true)
		}
	}
	response := api.Response{Status: http.StatusOK, Body: responseBody}
	if protocolErr := store.storeReceiptAtUptime(ctx, transaction, authenticated.DeviceID, "sync", call.RequestID, fingerprint, response, call.Now, accumulatedUptimeMS); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	if protocolErr := store.commitUptimeTransaction(transaction, checkpoint); protocolErr != nil {
		return api.Response{}, protocolErr
	}
	return response, nil
}

func classifyRevisionFrontier(ctx context.Context, transaction *sql.Tx, recordID string, candidate map[string]uint64) (bool, []string, *api.Error) {
	rows, err := transaction.QueryContext(ctx, `
		SELECT r.revision_id, length(r.vector_json),
		       CASE WHEN length(r.vector_json) BETWEEN 1 AND ? THEN r.vector_json END
		FROM record_heads h JOIN record_revisions r ON r.revision_id = h.revision_id
		WHERE h.record_id = ?
		ORDER BY h.revision_id LIMIT 33`, maxVectorBytes, recordID)
	if err != nil {
		return false, nil, api.NewError("internal_error", true)
	}
	defer rows.Close()
	undominated := true
	var dominated []string
	count := 0
	for rows.Next() {
		count++
		var revisionID string
		var vectorBody []byte
		var vectorLength int64
		var entries []vectorEntry
		if rows.Scan(&revisionID, &vectorLength, &vectorBody) != nil || !boundedRequiredBytes(vectorLength, vectorBody, maxVectorBytes) || json.Unmarshal(vectorBody, &entries) != nil {
			return false, nil, api.NewError("internal_error", true)
		}
		vector, err := validateVector(entries)
		if err != nil {
			return false, nil, api.NewError("internal_error", true)
		}
		if vectorDominates(vector, candidate) {
			undominated = false
		}
		if vectorDominates(candidate, vector) {
			dominated = append(dominated, revisionID)
		}
	}
	if rows.Err() != nil || count > 32 {
		return false, nil, api.NewError("internal_error", true)
	}
	return undominated, dominated, nil
}

func validateMutationShapes(deviceID string, revisions []recordRevision) *api.Error {
	for index, revision := range revisions {
		if _, _, err := validateRevision(revision); err != nil || revision.AuthorDeviceID != deviceID {
			return api.NewError("invalid_request", false)
		}
		if index > 0 && !mutationKeyLess(revisions[index-1], revision) {
			return api.NewError("invalid_request", false)
		}
	}
	return nil
}

func (store *Store) validateMutations(ctx context.Context, transaction *sql.Tx, deviceID string, initialCounter uint64, revisions []recordRevision) ([]pendingRevision, int, uint64, *api.Error) {
	pending := make([]pendingRevision, 0, len(revisions))
	pendingByRecord := make(map[string][]pendingRevision)
	pendingByRevisionID := make(map[string]pendingRevision)
	lastCounter := initialCounter
	newCount := 0
	for index, revision := range revisions {
		authorCounter, vector, err := validateRevision(revision)
		if err != nil || revision.AuthorDeviceID != deviceID {
			return nil, 0, 0, api.NewError("invalid_request", false)
		}
		if index > 0 && !mutationKeyLess(revisions[index-1], revision) {
			return nil, 0, 0, api.NewError("invalid_request", false)
		}
		canonical, err := marshalJSON(revision)
		if err != nil {
			return nil, 0, 0, api.NewError("internal_error", true)
		}
		contentHash := sha256.Sum256(canonical)
		vectorJSON, _ := json.Marshal(revision.VersionVector)
		vectorHash := sha256.Sum256(vectorJSON)
		var storedHash []byte
		err = transaction.QueryRowContext(ctx, "SELECT content_hash FROM record_revisions WHERE revision_id = ?", revision.RevisionID).Scan(&storedHash)
		if err == nil {
			if len(storedHash) != 32 {
				return nil, 0, 0, api.NewError("internal_error", true)
			}
			var recorded [32]byte
			copy(recorded[:], storedHash)
			if recorded != contentHash {
				return nil, 0, 0, api.NewError("revision_equivocation", false)
			}
			pending = append(pending, pendingRevision{revision: revision, canonical: canonical, contentHash: contentHash, authorCounter: authorCounter, vector: vector})
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, 0, 0, api.NewError("internal_error", true)
		}
		if prior, exists := pendingByRevisionID[revision.RevisionID]; exists {
			if prior.contentHash != contentHash {
				return nil, 0, 0, api.NewError("revision_equivocation", false)
			}
			continue
		}
		if protocolErr := validateEqualVectorEquivocation(ctx, transaction, revision.RecordID, revision.RevisionID, vectorHash, vector, pendingByRecord[revision.RecordID]); protocolErr != nil {
			return nil, 0, 0, protocolErr
		}
		if lastCounter == math.MaxUint64 {
			return nil, 0, 0, api.NewError("counter_exhausted", false)
		}
		if authorCounter != lastCounter+1 {
			return nil, 0, 0, api.NewError("counter_conflict", false)
		}
		if protocolErr := validateVectorRegistry(ctx, transaction, deviceID, authorCounter, vector); protocolErr != nil {
			return nil, 0, 0, protocolErr
		}
		if protocolErr := validateRecordCausality(ctx, transaction, revision.RecordID, revision.RevisionID, vector, pendingByRecord[revision.RecordID]); protocolErr != nil {
			return nil, 0, 0, protocolErr
		}
		item := pendingRevision{revision: revision, canonical: canonical, contentHash: contentHash, authorCounter: authorCounter, vector: vector, isNew: true}
		pending = append(pending, item)
		pendingByRecord[revision.RecordID] = append(pendingByRecord[revision.RecordID], item)
		pendingByRevisionID[revision.RevisionID] = item
		lastCounter = authorCounter
		newCount++
	}
	return pending, newCount, lastCounter, nil
}

func validateEqualVectorEquivocation(ctx context.Context, transaction *sql.Tx, recordID, revisionID string, vectorHash [32]byte, candidate map[string]uint64, pending []pendingRevision) *api.Error {
	for _, item := range pending {
		if item.revision.RevisionID != revisionID && vectorsEqual(candidate, item.vector) {
			return api.NewError("revision_equivocation", false)
		}
	}
	rows, err := transaction.QueryContext(ctx, `
		SELECT r.revision_id, length(r.vector_json),
		       CASE WHEN length(r.vector_json) BETWEEN 1 AND ? THEN r.vector_json END
		FROM record_vector_index i
		JOIN record_revisions r ON r.revision_id = i.revision_id
		WHERE i.record_id = ? AND i.vector_hash = ?
		ORDER BY i.revision_id`, maxVectorBytes, recordID, vectorHash[:])
	if err != nil {
		return api.NewError("internal_error", true)
	}
	defer rows.Close()
	for rows.Next() {
		var existingID string
		var vectorJSON []byte
		var vectorLength int64
		if err := rows.Scan(&existingID, &vectorLength, &vectorJSON); err != nil || !boundedRequiredBytes(vectorLength, vectorJSON, maxVectorBytes) {
			return api.NewError("internal_error", true)
		}
		var entries []vectorEntry
		if json.Unmarshal(vectorJSON, &entries) != nil {
			return api.NewError("internal_error", true)
		}
		vector, err := validateVector(entries)
		if err != nil {
			return api.NewError("internal_error", true)
		}
		if existingID != revisionID && vectorsEqual(candidate, vector) {
			return api.NewError("revision_equivocation", false)
		}
	}
	if err := rows.Err(); err != nil {
		return api.NewError("internal_error", true)
	}
	return nil
}

func mutationKeyLess(left, right recordRevision) bool {
	leftCounter, leftErr := parseUint64(left.AuthorCounter)
	rightCounter, rightErr := parseUint64(right.AuthorCounter)
	if leftErr != nil || rightErr != nil {
		return false
	}
	if leftCounter != rightCounter {
		return leftCounter < rightCounter
	}
	if left.RecordID != right.RecordID {
		return left.RecordID < right.RecordID
	}
	return left.RevisionID < right.RevisionID
}

func validateVectorRegistry(ctx context.Context, transaction *sql.Tx, authorDeviceID string, authorCounter uint64, vector map[string]uint64) *api.Error {
	for vectorDeviceID, counter := range vector {
		if vectorDeviceID == authorDeviceID {
			if counter != authorCounter {
				return api.NewError("invalid_request", false)
			}
			continue
		}
		var storedCounter []byte
		if err := transaction.QueryRowContext(ctx, "SELECT max_author_counter FROM devices WHERE device_id = ?", vectorDeviceID).Scan(&storedCounter); errors.Is(err, sql.ErrNoRows) {
			return api.NewError("invalid_request", false)
		} else if err != nil {
			return api.NewError("internal_error", true)
		}
		maximum, err := DecodeUint64(storedCounter)
		if err != nil {
			return api.NewError("internal_error", true)
		}
		if counter > maximum {
			return api.NewError("counter_conflict", false)
		}
	}
	return nil
}

func validateRecordCausality(ctx context.Context, transaction *sql.Tx, recordID, revisionID string, candidate map[string]uint64, pending []pendingRevision) *api.Error {
	var markerVectorJSON []byte
	var markerVectorLength int64
	err := transaction.QueryRowContext(ctx, `
		SELECT length(frontier_json),
		       CASE WHEN length(frontier_json) BETWEEN 1 AND ? THEN frontier_json END
		FROM collection_markers WHERE record_id = ?`, maxVectorBytes, recordID,
	).Scan(&markerVectorLength, &markerVectorJSON)
	if err == nil {
		var entries []vectorEntry
		if !boundedRequiredBytes(markerVectorLength, markerVectorJSON, maxVectorBytes) || json.Unmarshal(markerVectorJSON, &entries) != nil {
			return api.NewError("internal_error", true)
		}
		frontier, validateErr := validateVector(entries)
		if validateErr != nil {
			return api.NewError("internal_error", true)
		}
		if !vectorDominates(candidate, frontier) {
			return api.NewError("stale_after_collection", false)
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return api.NewError("internal_error", true)
	}
	rows, err := transaction.QueryContext(ctx, `
		SELECT r.revision_id, length(r.vector_json),
		       CASE WHEN length(r.vector_json) BETWEEN 1 AND ? THEN r.vector_json END
		FROM record_heads h JOIN record_revisions r ON r.revision_id = h.revision_id
		WHERE h.record_id = ? ORDER BY h.revision_id`, maxVectorBytes, recordID)
	if err != nil {
		return api.NewError("internal_error", true)
	}
	defer rows.Close()
	type existingVector struct {
		id     string
		vector map[string]uint64
	}
	vectors := []existingVector{{id: revisionID, vector: candidate}}
	for _, item := range pending {
		if vectorsEqual(candidate, item.vector) && revisionID != item.revision.RevisionID {
			return api.NewError("revision_equivocation", false)
		}
		vectors = append(vectors, existingVector{id: item.revision.RevisionID, vector: item.vector})
	}
	for rows.Next() {
		var existingID string
		var vectorJSON []byte
		var vectorLength int64
		if err := rows.Scan(&existingID, &vectorLength, &vectorJSON); err != nil || !boundedRequiredBytes(vectorLength, vectorJSON, maxVectorBytes) {
			return api.NewError("internal_error", true)
		}
		var entries []vectorEntry
		if json.Unmarshal(vectorJSON, &entries) != nil {
			return api.NewError("internal_error", true)
		}
		vector, validateErr := validateVector(entries)
		if validateErr != nil {
			return api.NewError("internal_error", true)
		}
		if vectorsEqual(candidate, vector) && existingID != revisionID {
			return api.NewError("revision_equivocation", false)
		}
		vectors = append(vectors, existingVector{id: existingID, vector: vector})
	}
	if err := rows.Err(); err != nil {
		return api.NewError("internal_error", true)
	}
	undominated := 0
	for leftIndex, left := range vectors {
		dominated := false
		for rightIndex, right := range vectors {
			if leftIndex != rightIndex && vectorDominates(right.vector, left.vector) {
				dominated = true
				break
			}
		}
		if !dominated {
			undominated++
		}
	}
	if undominated > 32 {
		return api.NewError("too_many_siblings", false)
	}
	return nil
}

func vectorsEqual(left, right map[string]uint64) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func loadChanges(ctx context.Context, transaction *sql.Tx, afterCursor uint64) ([]change, uint64, bool, *api.Error) {
	after := EncodeUint64(afterCursor)
	rows, err := transaction.QueryContext(ctx, `
		SELECT cursor, kind, received_at_ms,
		       length(record_revision_id),
		       CASE WHEN length(record_revision_id) = 36 THEN record_revision_id END,
		       length(collection_marker_record_id),
		       CASE WHEN length(collection_marker_record_id) = 36 THEN collection_marker_record_id END,
		       length(collection_marker_json),
		       CASE WHEN length(collection_marker_json) BETWEEN 1 AND ? THEN collection_marker_json END
		FROM changes WHERE cursor > ? ORDER BY cursor LIMIT ?`, maxBodyBytes, after[:], maxChanges+1)
	if err != nil {
		return nil, 0, false, api.NewError("internal_error", true)
	}
	type storedChange struct {
		cursorBytes    []byte
		kind           string
		receivedAt     int64
		revisionID     sql.NullString
		markerRecordID sql.NullString
		markerBody     []byte
	}
	stored := make([]storedChange, 0, maxChanges+1)
	for rows.Next() {
		var item storedChange
		var revisionIDLength, markerIDLength, markerBodyLength sql.NullInt64
		if err := rows.Scan(&item.cursorBytes, &item.kind, &item.receivedAt,
			&revisionIDLength, &item.revisionID, &markerIDLength, &item.markerRecordID, &markerBodyLength, &item.markerBody); err != nil ||
			!boundedOptionalText(revisionIDLength, item.revisionID, maxUUIDBytes) || revisionIDLength.Valid && revisionIDLength.Int64 != maxUUIDBytes ||
			!boundedOptionalText(markerIDLength, item.markerRecordID, maxUUIDBytes) || markerIDLength.Valid && markerIDLength.Int64 != maxUUIDBytes ||
			!boundedOptionalBytes(markerBodyLength, item.markerBody, maxBodyBytes) {
			return nil, 0, false, api.NewError("internal_error", true)
		}
		stored = append(stored, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, 0, false, api.NewError("internal_error", true)
	}
	if err := rows.Close(); err != nil {
		return nil, 0, false, api.NewError("internal_error", true)
	}
	hasMore := len(stored) > maxChanges
	if hasMore {
		stored = stored[:maxChanges]
	}
	changes := make([]change, 0, len(stored))
	nextCursor := afterCursor
	for _, storedItem := range stored {
		cursor, err := DecodeUint64(storedItem.cursorBytes)
		if err != nil {
			return nil, 0, false, api.NewError("internal_error", true)
		}
		item := change{Cursor: encodeUint64Text(cursor), Kind: storedItem.kind, ReceivedAt: formatTimestamp(storedItem.receivedAt)}
		switch storedItem.kind {
		case "record_revision":
			var body, hashBytes []byte
			var bodyLength int64
			if !storedItem.revisionID.Valid || transaction.QueryRowContext(ctx, `
				SELECT length(o.revision_json),
				       CASE WHEN length(o.revision_json) BETWEEN 1 AND ? THEN o.revision_json END,
				       r.content_hash
				FROM record_revisions r JOIN revision_objects o USING (content_hash)
				WHERE r.revision_id = ? AND r.retained = 1`, maxBodyBytes, storedItem.revisionID.String,
			).Scan(&bodyLength, &body, &hashBytes) != nil || !boundedRequiredBytes(bodyLength, body, maxBodyBytes) || len(hashBytes) != 32 {
				return nil, 0, false, api.NewError("internal_error", true)
			}
			var revision recordRevision
			if json.Unmarshal(body, &revision) != nil {
				return nil, 0, false, api.NewError("internal_error", true)
			}
			canonical, err := marshalJSON(revision)
			if err != nil || !bytes.Equal(canonical, body) {
				return nil, 0, false, api.NewError("internal_error", true)
			}
			hash := sha256.Sum256(canonical)
			if !bytes.Equal(hash[:], hashBytes) {
				return nil, 0, false, api.NewError("internal_error", true)
			}
			if _, _, err := validateRevision(revision); err != nil || revision.RevisionID != storedItem.revisionID.String {
				return nil, 0, false, api.NewError("internal_error", true)
			}
			item.RecordRevision = &revision
		case "collection_marker":
			if !storedItem.markerRecordID.Valid || len(storedItem.markerBody) == 0 {
				return nil, 0, false, api.NewError("internal_error", true)
			}
			marker, err := decodeStoredCollectionMarker(storedItem.markerBody)
			if err != nil || marker.RecordID != storedItem.markerRecordID.String {
				return nil, 0, false, api.NewError("internal_error", true)
			}
			item.CollectionMarker = &marker
		case "envelope_changed", "device_changed":
		default:
			return nil, 0, false, api.NewError("internal_error", true)
		}
		changes = append(changes, item)
		nextCursor = cursor
	}
	return changes, nextCursor, hasMore, nil
}

func hasScope(scopes []string, required string) bool {
	index := sort.SearchStrings(scopes, required)
	return index < len(scopes) && scopes[index] == required
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
