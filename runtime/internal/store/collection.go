package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
	"github.com/kciceblue/sshserver/runtime/internal/auth"
)

const (
	minimumRetentionUptime   = 90 * 24 * time.Hour
	collectionRecordBatch    = 32
	collectionCandidateBatch = 256
)

type collectionRevision struct {
	revisionID       string
	recordID         string
	vectorEntries    []vectorEntry
	vector           map[string]uint64
	authenticator    []byte
	contentHash      [32]byte
	tombstone        bool
	acceptedUptimeMS uint64
	changeCursor     uint64
}

type storedCollectionMarker struct {
	present           bool
	witnessRevisionID string
	frontierEntries   []vectorEntry
	frontier          map[string]uint64
	authenticator     []byte
	body              []byte
}

type pendingUptimeCheckpoint struct {
	next time.Time
}

// CheckpointUptime durably accounts only positive elapsed daemon-monotonic
// time. Lost time after an abrupt crash can delay collection but can never
// accelerate the 90-day retention floor.
func (store *Store) CheckpointUptime(ctx context.Context, now time.Time) error {
	transaction, err := store.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	_, checkpoint, protocolErr := store.checkpointUptimeTx(ctx, transaction, now)
	if protocolErr != nil {
		return protocolErr
	}
	if protocolErr := store.commitUptimeTransaction(transaction, checkpoint); protocolErr != nil {
		return protocolErr
	}
	return nil
}

func (store *Store) checkpointUptimeTx(ctx context.Context, transaction *sql.Tx, now time.Time) (uint64, pendingUptimeCheckpoint, *api.Error) {
	store.ephemeral.mu.Lock()
	if !store.ephemeral.booted {
		store.ephemeral.mu.Unlock()
		return 0, pendingUptimeCheckpoint{}, api.NewError("internal_error", true)
	}
	currentCheckpoint := store.ephemeral.uptimeCheckpoint
	elapsed := now.Sub(currentCheckpoint)
	elapsedMilliseconds := elapsed.Milliseconds()
	nextCheckpoint := currentCheckpoint
	if elapsedMilliseconds > 0 {
		nextCheckpoint = currentCheckpoint.Add(time.Duration(elapsedMilliseconds) * time.Millisecond)
	}
	store.ephemeral.mu.Unlock()

	var encoded []byte
	if err := transaction.QueryRowContext(ctx, "SELECT accumulated_uptime_ms FROM runtime_state WHERE singleton = 1").Scan(&encoded); err != nil {
		return 0, pendingUptimeCheckpoint{}, api.NewError("internal_error", true)
	}
	accumulated, err := DecodeUint64(encoded)
	if err != nil {
		return 0, pendingUptimeCheckpoint{}, api.NewError("internal_error", true)
	}
	if elapsedMilliseconds <= 0 {
		return accumulated, pendingUptimeCheckpoint{next: nextCheckpoint}, nil
	}
	delta := uint64(elapsedMilliseconds)
	if delta > math.MaxUint64-accumulated {
		accumulated = math.MaxUint64
	} else {
		accumulated += delta
	}
	updated := EncodeUint64(accumulated)
	if _, err := transaction.ExecContext(ctx, "UPDATE runtime_state SET accumulated_uptime_ms = ? WHERE singleton = 1", updated[:]); err != nil {
		return 0, pendingUptimeCheckpoint{}, api.NewError("internal_error", true)
	}
	return accumulated, pendingUptimeCheckpoint{next: nextCheckpoint}, nil
}

func (store *Store) commitUptimeTransaction(transaction *sql.Tx, checkpoint pendingUptimeCheckpoint) *api.Error {
	// Hold the ephemeral lock across commit so a transaction that begins as the
	// connection is released cannot read the old checkpoint and double-account
	// the same elapsed interval.
	store.ephemeral.mu.Lock()
	defer store.ephemeral.mu.Unlock()
	if err := transaction.Commit(); err != nil {
		return api.NewError("internal_error", true)
	}
	if checkpoint.next.After(store.ephemeral.uptimeCheckpoint) {
		store.ephemeral.uptimeCheckpoint = checkpoint.next
	}
	return nil
}

func (store *Store) collectEligible(ctx context.Context, transaction *sql.Tx, now time.Time, accumulatedUptimeMS, serverCursor uint64) (uint64, *api.Error) {
	var collectionGenerationBytes []byte
	if err := transaction.QueryRowContext(ctx, `
		SELECT collection_generation FROM runtime_state WHERE singleton = 1`,
	).Scan(&collectionGenerationBytes); err != nil {
		return 0, api.NewError("internal_error", true)
	}
	collectionGeneration, err := DecodeUint64(collectionGenerationBytes)
	if err != nil {
		return 0, api.NewError("internal_error", true)
	}
	if collectionGeneration == math.MaxUint64 {
		return serverCursor, nil
	}
	collectionAdvanced := false
	activeAcks, protocolErr := loadActiveAcknowledgements(ctx, transaction)
	if protocolErr != nil {
		return 0, protocolErr
	}
	if len(activeAcks) == 0 {
		return serverCursor, nil
	}
	recordIDs, scanAfter, protocolErr := loadCollectionRecordBatch(ctx, transaction)
	if protocolErr != nil {
		return 0, protocolErr
	}
	if len(recordIDs) == 0 {
		if scanAfter != "" {
			if _, err := transaction.ExecContext(ctx, "UPDATE runtime_state SET collection_scan_after_record_id = '' WHERE singleton = 1"); err != nil {
				return 0, api.NewError("internal_error", true)
			}
			recordIDs, _, protocolErr = loadCollectionRecordBatch(ctx, transaction)
			if protocolErr != nil {
				return 0, protocolErr
			}
		}
		if len(recordIDs) == 0 {
			return serverCursor, nil
		}
	}
	cursorFloor, protocolErr := readCursorFloor(ctx, transaction)
	if protocolErr != nil {
		return 0, protocolErr
	}
	for _, recordID := range recordIDs {
		barrier, heads, candidates, protocolErr := loadCollectionRecordWork(ctx, transaction, recordID, accumulatedUptimeMS)
		if protocolErr != nil {
			return 0, protocolErr
		}
		if !allAcknowledged(activeAcks, barrier) {
			continue
		}
		marker, protocolErr := loadCollectionMarker(ctx, transaction, recordID)
		if protocolErr != nil {
			return 0, protocolErr
		}

		witness := selectAdvancingWitness(heads, marker)
		selected := selectWitnessCoveredCandidates(candidates, witness)
		markerAdvanced := witness != nil && len(selected) != 0 && serverCursor != math.MaxUint64
		if !markerAdvanced {
			selected = selectMarkerCoveredCandidates(candidates, marker)
			if len(selected) == 0 {
				continue
			}
		}

		if markerAdvanced {
			serverCursor++
			markerBody, protocolErr := writeCollectionMarker(ctx, transaction, *witness, barrier, serverCursor, now)
			if protocolErr != nil {
				return 0, protocolErr
			}
			if protocolErr := insertMarkerChange(ctx, transaction, serverCursor, recordID, markerBody, now); protocolErr != nil {
				return 0, protocolErr
			}
		}
		if !collectionAdvanced {
			collectionGeneration++
			collectionAdvanced = true
		}
		encodedCollectionGeneration := EncodeUint64(collectionGeneration)

		for _, candidate := range selected {
			if _, err := transaction.ExecContext(ctx, `
				UPDATE record_revisions
				SET retained = 0, undominated = 0, collected_generation = ?
				WHERE revision_id = ? AND retained = 1`, encodedCollectionGeneration[:], candidate.revisionID); err != nil {
				return 0, api.NewError("internal_error", true)
			}
			if _, err := transaction.ExecContext(ctx, "DELETE FROM record_heads WHERE record_id = ? AND revision_id = ?", candidate.recordID, candidate.revisionID); err != nil {
				return 0, api.NewError("internal_error", true)
			}
			encodedChangeCursor := EncodeUint64(candidate.changeCursor)
			if _, err := transaction.ExecContext(ctx, "DELETE FROM changes WHERE cursor = ? AND record_revision_id = ?", encodedChangeCursor[:], candidate.revisionID); err != nil {
				return 0, api.NewError("internal_error", true)
			}
			encodedAcceptedUptime := EncodeUint64(candidate.acceptedUptimeMS)
			if _, err := transaction.ExecContext(ctx, `
				DELETE FROM collection_candidates
				WHERE record_id = ? AND accepted_uptime_ms = ? AND revision_id = ?`, candidate.recordID, encodedAcceptedUptime[:], candidate.revisionID); err != nil {
				return 0, api.NewError("internal_error", true)
			}
			if candidate.changeCursor > cursorFloor {
				cursorFloor = candidate.changeCursor
			}
			if protocolErr := deleteUnreferencedRevisionObject(ctx, transaction, candidate.contentHash, candidate.revisionID); protocolErr != nil {
				return 0, protocolErr
			}
		}
		if _, err := transaction.ExecContext(ctx, `
			DELETE FROM collection_records WHERE record_id = ?
			  AND NOT EXISTS (SELECT 1 FROM collection_candidates WHERE record_id = ?)`, recordID, recordID); err != nil {
			return 0, api.NewError("internal_error", true)
		}
	}
	encodedFloor := EncodeUint64(cursorFloor)
	encodedCursor := EncodeUint64(serverCursor)
	encodedCollectionGeneration := EncodeUint64(collectionGeneration)
	if _, err := transaction.ExecContext(ctx, `
		UPDATE runtime_state
		SET cursor_floor = ?, server_cursor = ?, collection_generation = ?,
		    collection_scan_after_record_id = ?
		WHERE singleton = 1`, encodedFloor[:], encodedCursor[:], encodedCollectionGeneration[:], recordIDs[len(recordIDs)-1]); err != nil {
		return 0, api.NewError("internal_error", true)
	}
	return serverCursor, nil
}

func loadActiveAcknowledgements(ctx context.Context, transaction *sql.Tx) ([]uint64, *api.Error) {
	rows, err := transaction.QueryContext(ctx, "SELECT last_ack_cursor FROM devices WHERE revoked_at_ms IS NULL ORDER BY device_id LIMIT 65")
	if err != nil {
		return nil, api.NewError("internal_error", true)
	}
	defer rows.Close()
	var result []uint64
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return nil, api.NewError("internal_error", true)
		}
		value, err := DecodeUint64(encoded)
		if err != nil {
			return nil, api.NewError("internal_error", true)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, api.NewError("internal_error", true)
	}
	if len(result) > 64 {
		return nil, api.NewError("internal_error", true)
	}
	return result, nil
}

func loadCollectionRecordBatch(ctx context.Context, transaction *sql.Tx) ([]string, string, *api.Error) {
	var scanAfter sql.NullString
	var scanAfterLength int64
	if err := transaction.QueryRowContext(ctx, `
		SELECT octet_length(collection_scan_after_record_id),
		       CASE WHEN typeof(collection_scan_after_record_id) = 'text'
		                  AND octet_length(collection_scan_after_record_id) IN (0, ?) THEN collection_scan_after_record_id END
		FROM runtime_state WHERE singleton = 1`, maxUUIDBytes,
	).Scan(&scanAfterLength, &scanAfter); err != nil || !boundedEmptyOrUUIDText(scanAfterLength, scanAfter) {
		return nil, "", api.NewError("internal_error", true)
	}
	rows, err := transaction.QueryContext(ctx, `
		SELECT octet_length(record_id),
		       CASE WHEN typeof(record_id) = 'text'
		                  AND octet_length(record_id) = ? THEN record_id END
		FROM collection_records
		WHERE record_id > ? ORDER BY record_id LIMIT ?`, maxUUIDBytes, scanAfter.String, collectionRecordBatch)
	if err != nil {
		return nil, "", api.NewError("internal_error", true)
	}
	defer rows.Close()
	result := make([]string, 0, collectionRecordBatch)
	for rows.Next() {
		var recordID sql.NullString
		var recordIDLength int64
		if rows.Scan(&recordIDLength, &recordID) != nil || recordIDLength != maxUUIDBytes ||
			!boundedRequiredText(recordIDLength, recordID, maxUUIDBytes) || validateUUID(recordID.String) != nil {
			return nil, "", api.NewError("internal_error", true)
		}
		result = append(result, recordID.String)
	}
	if err := rows.Err(); err != nil {
		return nil, "", api.NewError("internal_error", true)
	}
	return result, scanAfter.String, nil
}

func boundedEmptyOrUUIDText(length int64, value sql.NullString) bool {
	if !value.Valid || int64(len(value.String)) != length {
		return false
	}
	if length == 0 {
		return value.String == ""
	}
	return length == maxUUIDBytes && validateUUID(value.String) == nil
}

func loadCollectionRecordWork(ctx context.Context, transaction *sql.Tx, recordID string, accumulatedUptimeMS uint64) (uint64, []collectionRevision, []collectionRevision, *api.Error) {
	var barrierBytes []byte
	if err := transaction.QueryRowContext(ctx, "SELECT barrier_cursor FROM collection_records WHERE record_id = ?", recordID).Scan(&barrierBytes); err != nil {
		return 0, nil, nil, api.NewError("internal_error", true)
	}
	barrier, err := DecodeUint64(barrierBytes)
	if err != nil || barrier == 0 {
		return 0, nil, nil, api.NewError("internal_error", true)
	}
	heads, protocolErr := loadCollectionRevisionRows(ctx, transaction, `
		SELECT octet_length(r.revision_id),
		       CASE WHEN typeof(r.revision_id) = 'text'
		                  AND octet_length(r.revision_id) = ? THEN r.revision_id END,
		       octet_length(r.record_id),
		       CASE WHEN typeof(r.record_id) = 'text'
		                  AND octet_length(r.record_id) = ? THEN r.record_id END,
		       length(r.vector_json),
		       CASE WHEN length(r.vector_json) BETWEEN 1 AND ? THEN r.vector_json END,
		       r.content_hash, length(r.collection_witness_authenticator),
		       CASE WHEN length(r.collection_witness_authenticator) = 32 THEN r.collection_witness_authenticator END,
		       r.tombstone,
		       r.accepted_uptime_ms, r.change_cursor
		FROM record_heads h JOIN record_revisions r ON r.revision_id = h.revision_id
		WHERE h.record_id = ?
		ORDER BY h.revision_id LIMIT 33`, maxUUIDBytes, maxUUIDBytes, maxVectorBytes, recordID)
	if protocolErr != nil || len(heads) > 32 {
		if protocolErr != nil {
			return 0, nil, nil, protocolErr
		}
		return 0, nil, nil, api.NewError("internal_error", true)
	}
	minimumMS := uint64(minimumRetentionUptime / time.Millisecond)
	if accumulatedUptimeMS < minimumMS {
		return barrier, heads, nil, nil
	}
	cutoff := EncodeUint64(accumulatedUptimeMS - minimumMS)
	candidates, protocolErr := loadCollectionRevisionRows(ctx, transaction, `
		SELECT octet_length(r.revision_id),
		       CASE WHEN typeof(r.revision_id) = 'text'
		                  AND octet_length(r.revision_id) = ? THEN r.revision_id END,
		       octet_length(r.record_id),
		       CASE WHEN typeof(r.record_id) = 'text'
		                  AND octet_length(r.record_id) = ? THEN r.record_id END,
		       length(r.vector_json),
		       CASE WHEN length(r.vector_json) BETWEEN 1 AND ? THEN r.vector_json END,
		       r.content_hash, length(r.collection_witness_authenticator),
		       CASE WHEN length(r.collection_witness_authenticator) = 32 THEN r.collection_witness_authenticator END,
		       r.tombstone,
		       r.accepted_uptime_ms, r.change_cursor
		FROM collection_candidates q
		JOIN record_revisions r
		  ON r.revision_id = q.revision_id AND r.record_id = q.record_id
		 AND r.accepted_uptime_ms = q.accepted_uptime_ms
		WHERE q.record_id = ? AND q.accepted_uptime_ms <= ? AND r.retained = 1
		ORDER BY q.accepted_uptime_ms, q.revision_id LIMIT ?`, maxUUIDBytes, maxUUIDBytes, maxVectorBytes, recordID, cutoff[:], collectionCandidateBatch)
	if protocolErr != nil {
		return 0, nil, nil, protocolErr
	}
	return barrier, heads, candidates, nil
}

func loadCollectionRevisionRows(ctx context.Context, transaction *sql.Tx, statement string, arguments ...any) ([]collectionRevision, *api.Error) {
	rows, err := transaction.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, api.NewError("internal_error", true)
	}
	defer rows.Close()
	var result []collectionRevision
	for rows.Next() {
		var revision collectionRevision
		var revisionID, recordID sql.NullString
		var vectorBody, acceptedBytes, cursorBytes, contentHash, authenticator []byte
		var revisionIDLength, recordIDLength, vectorLength int64
		var authenticatorLength sql.NullInt64
		if rows.Scan(&revisionIDLength, &revisionID, &recordIDLength, &recordID, &vectorLength, &vectorBody, &contentHash, &authenticatorLength, &authenticator, &revision.tombstone, &acceptedBytes, &cursorBytes) != nil ||
			revisionIDLength != maxUUIDBytes || !boundedRequiredText(revisionIDLength, revisionID, maxUUIDBytes) || validateUUID(revisionID.String) != nil ||
			recordIDLength != maxUUIDBytes || !boundedRequiredText(recordIDLength, recordID, maxUUIDBytes) || validateUUID(recordID.String) != nil || len(contentHash) != 32 ||
			!boundedRequiredBytes(vectorLength, vectorBody, maxVectorBytes) || !boundedOptionalBytes(authenticatorLength, authenticator, 32) ||
			authenticatorLength.Valid && authenticatorLength.Int64 != 32 {
			return nil, api.NewError("internal_error", true)
		}
		revision.revisionID = revisionID.String
		revision.recordID = recordID.String
		copy(revision.contentHash[:], contentHash)
		if json.Unmarshal(vectorBody, &revision.vectorEntries) != nil {
			return nil, api.NewError("internal_error", true)
		}
		vector, err := validateVector(revision.vectorEntries)
		if err != nil {
			return nil, api.NewError("internal_error", true)
		}
		accepted, acceptedErr := DecodeUint64(acceptedBytes)
		cursor, cursorErr := DecodeUint64(cursorBytes)
		if acceptedErr != nil || cursorErr != nil {
			return nil, api.NewError("internal_error", true)
		}
		revision.vector = vector
		revision.authenticator = append([]byte(nil), authenticator...)
		revision.acceptedUptimeMS = accepted
		revision.changeCursor = cursor
		result = append(result, revision)
	}
	if rows.Err() != nil {
		return nil, api.NewError("internal_error", true)
	}
	return result, nil
}

func deleteUnreferencedRevisionObject(ctx context.Context, transaction *sql.Tx, hash [32]byte, revisionID string) *api.Error {
	var retained int
	var revisionHash []byte
	if err := transaction.QueryRowContext(ctx, "SELECT retained, content_hash FROM record_revisions WHERE revision_id = ?", revisionID).Scan(&retained, &revisionHash); err != nil || len(revisionHash) != 32 || !bytes.Equal(revisionHash, hash[:]) {
		return api.NewError("internal_error", true)
	}
	if retained == 1 {
		return nil
	}
	rows, err := transaction.QueryContext(ctx, `
		SELECT octet_length(snapshot_id),
		       CASE WHEN typeof(snapshot_id) = 'text'
		                  AND octet_length(snapshot_id) = ? THEN snapshot_id END
		FROM snapshots ORDER BY snapshot_id LIMIT 9`, maxUUIDBytes)
	if err != nil {
		return api.NewError("internal_error", true)
	}
	var snapshotIDs []string
	for rows.Next() {
		var snapshotID sql.NullString
		var snapshotIDLength int64
		if rows.Scan(&snapshotIDLength, &snapshotID) != nil || snapshotIDLength != maxUUIDBytes ||
			!boundedRequiredText(snapshotIDLength, snapshotID, maxUUIDBytes) || validateUUID(snapshotID.String) != nil {
			rows.Close()
			return api.NewError("internal_error", true)
		}
		snapshotIDs = append(snapshotIDs, snapshotID.String)
	}
	if rows.Err() != nil || rows.Close() != nil || len(snapshotIDs) > 8 {
		return api.NewError("internal_error", true)
	}
	for _, snapshotID := range snapshotIDs {
		var present int
		err := transaction.QueryRowContext(ctx, `
			SELECT 1 FROM snapshot_revision_refs
			WHERE snapshot_id = ? AND revision_id = ?`, snapshotID, revisionID).Scan(&present)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return api.NewError("internal_error", true)
		}
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM revision_objects WHERE content_hash = ?", hash[:]); err != nil {
		return api.NewError("internal_error", true)
	}
	return nil
}

const collectionMarkerKeyProbeSQL = `
	SELECT octet_length(record_id),
	       CASE WHEN typeof(record_id) = 'text'
	                  AND octet_length(record_id) = ? THEN record_id END
	FROM collection_markers
	WHERE record_id >= ? AND record_id < ?
	UNION ALL
	SELECT octet_length(record_id),
	       CASE WHEN typeof(record_id) = 'text'
	                  AND octet_length(record_id) = ? THEN record_id END
	FROM collection_markers
	WHERE record_id >= ? AND record_id < ?
	LIMIT 2`

// preflightCollectionMarkerKey makes an exact-key miss authoritative without
// scanning unrelated marker history. The two primary-key ranges use TEXT and
// BLOB parameters separately because SQLite orders storage classes before
// values. Each range spans the canonical key and every byte-suffixed variant.
func preflightCollectionMarkerKey(ctx context.Context, transaction *sql.Tx, recordID string) (bool, *api.Error) {
	if validateUUID(recordID) != nil {
		return false, api.NewError("internal_error", true)
	}
	lowerBytes := []byte(recordID)
	upperBytes := append([]byte(nil), lowerBytes...)
	upperBytes[len(upperBytes)-1]++
	rows, err := transaction.QueryContext(ctx, collectionMarkerKeyProbeSQL,
		maxUUIDBytes, recordID, string(upperBytes),
		maxUUIDBytes, lowerBytes, upperBytes,
	)
	if err != nil {
		return false, api.NewError("internal_error", true)
	}
	count := 0
	for rows.Next() {
		count++
		var storedRecordID sql.NullString
		var recordIDLength int64
		if rows.Scan(&recordIDLength, &storedRecordID) != nil || recordIDLength != maxUUIDBytes ||
			!boundedRequiredText(recordIDLength, storedRecordID, maxUUIDBytes) ||
			validateUUID(storedRecordID.String) != nil || storedRecordID.String != recordID {
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

func loadCollectionMarker(ctx context.Context, transaction *sql.Tx, recordID string) (storedCollectionMarker, *api.Error) {
	var marker storedCollectionMarker
	present, protocolErr := preflightCollectionMarkerKey(ctx, transaction, recordID)
	if protocolErr != nil || !present {
		return marker, protocolErr
	}
	var witnessRevisionID sql.NullString
	var frontierBody, authenticator, barrierBytes []byte
	var witnessRevisionIDLength, frontierLength, bodyLength int64
	err := transaction.QueryRowContext(ctx, `
		SELECT octet_length(witness_revision_id),
		       CASE WHEN typeof(witness_revision_id) = 'text'
		                  AND octet_length(witness_revision_id) = ? THEN witness_revision_id END,
		       length(frontier_json),
		       CASE WHEN length(frontier_json) BETWEEN 1 AND ? THEN frontier_json END,
		       collection_witness_authenticator, barrier_cursor, length(marker_json),
		       CASE WHEN length(marker_json) BETWEEN 1 AND ? THEN marker_json END
		FROM collection_markers WHERE record_id = ?`, maxUUIDBytes, maxVectorBytes, maxBodyBytes, recordID,
	).Scan(&witnessRevisionIDLength, &witnessRevisionID, &frontierLength, &frontierBody, &authenticator, &barrierBytes, &bodyLength, &marker.body)
	if err != nil || witnessRevisionIDLength != maxUUIDBytes || !boundedRequiredText(witnessRevisionIDLength, witnessRevisionID, maxUUIDBytes) || validateUUID(witnessRevisionID.String) != nil ||
		!boundedRequiredBytes(frontierLength, frontierBody, maxVectorBytes) || len(authenticator) != 32 ||
		!boundedRequiredBytes(bodyLength, marker.body, maxBodyBytes) {
		return marker, api.NewError("internal_error", true)
	}
	marker.witnessRevisionID = witnessRevisionID.String
	if json.Unmarshal(frontierBody, &marker.frontierEntries) != nil {
		return marker, api.NewError("internal_error", true)
	}
	frontier, err := validateVector(marker.frontierEntries)
	if err != nil {
		return marker, api.NewError("internal_error", true)
	}
	barrier, err := DecodeUint64(barrierBytes)
	if err != nil {
		return marker, api.NewError("internal_error", true)
	}
	bodyMarker, err := decodeStoredCollectionMarker(marker.body)
	if err != nil {
		return marker, api.NewError("internal_error", true)
	}
	bodyFrontier, bodyBarrier, bodyAuthenticator, err := validateCollectionMarker(bodyMarker)
	if err != nil || bodyMarker.RecordID != recordID || bodyMarker.WitnessRevisionID != marker.witnessRevisionID ||
		!vectorsEqual(bodyFrontier, frontier) || bodyBarrier != barrier {
		return marker, api.NewError("internal_error", true)
	}
	var storedAuthenticator [32]byte
	var decodedBodyAuthenticator [32]byte
	copy(storedAuthenticator[:], authenticator)
	copy(decodedBodyAuthenticator[:], bodyAuthenticator)
	if !auth.VerifyHash(storedAuthenticator, decodedBodyAuthenticator) {
		return marker, api.NewError("internal_error", true)
	}
	marker.present = true
	marker.frontier = frontier
	marker.authenticator = append([]byte(nil), authenticator...)
	return marker, nil
}

func selectAdvancingWitness(heads []collectionRevision, marker storedCollectionMarker) *collectionRevision {
	for index := range heads {
		witness := &heads[index]
		if len(witness.authenticator) != 32 {
			continue
		}
		if marker.present && !vectorDominates(witness.vector, marker.frontier) {
			continue
		}
		dominatesAll := true
		for otherIndex := range heads {
			if index == otherIndex {
				continue
			}
			if !vectorDominates(witness.vector, heads[otherIndex].vector) {
				dominatesAll = false
				break
			}
		}
		if !dominatesAll {
			continue
		}
		copy := *witness
		return &copy
	}
	return nil
}

func selectWitnessCoveredCandidates(revisions []collectionRevision, witness *collectionRevision) []collectionRevision {
	if witness == nil {
		return nil
	}
	var candidates []collectionRevision
	for _, candidate := range revisions {
		if candidate.revisionID == witness.revisionID && vectorsEqual(candidate.vector, witness.vector) {
			if witness.tombstone {
				candidates = append(candidates, candidate)
			}
			continue
		}
		if vectorDominates(witness.vector, candidate.vector) {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func selectMarkerCoveredCandidates(revisions []collectionRevision, marker storedCollectionMarker) []collectionRevision {
	if !marker.present || len(marker.authenticator) != 32 {
		return nil
	}
	var candidates []collectionRevision
	for _, candidate := range revisions {
		if candidate.revisionID == marker.witnessRevisionID && vectorsEqual(candidate.vector, marker.frontier) {
			if candidate.tombstone {
				candidates = append(candidates, candidate)
			}
			continue
		}
		if vectorDominates(marker.frontier, candidate.vector) {
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

func allAcknowledged(acknowledgements []uint64, barrier uint64) bool {
	for _, acknowledgement := range acknowledgements {
		if acknowledgement < barrier {
			return false
		}
	}
	return true
}

func writeCollectionMarker(ctx context.Context, transaction *sql.Tx, witness collectionRevision, barrier, cursor uint64, now time.Time) ([]byte, *api.Error) {
	authenticator := base64.RawURLEncoding.EncodeToString(witness.authenticator)
	marker := collectionMarker{
		RecordID:                       witness.recordID,
		WitnessRevisionID:              witness.revisionID,
		Frontier:                       witness.vectorEntries,
		CollectionWitnessAuthenticator: authenticator,
		BarrierCursor:                  encodeUint64Text(barrier),
	}
	body, err := marshalJSON(marker)
	if err != nil {
		return nil, api.NewError("internal_error", true)
	}
	frontierBody, _ := json.Marshal(witness.vectorEntries)
	encodedBarrier := EncodeUint64(barrier)
	encodedCursor := EncodeUint64(cursor)
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO collection_markers (
			record_id, witness_revision_id, frontier_json,
			collection_witness_authenticator, barrier_cursor,
			marker_json, change_cursor, received_at_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(record_id) DO UPDATE SET
			witness_revision_id = excluded.witness_revision_id,
			frontier_json = excluded.frontier_json,
			collection_witness_authenticator = excluded.collection_witness_authenticator,
			barrier_cursor = excluded.barrier_cursor,
			marker_json = excluded.marker_json,
			change_cursor = excluded.change_cursor,
			received_at_ms = excluded.received_at_ms`,
		witness.recordID, witness.revisionID, frontierBody,
		witness.authenticator, encodedBarrier[:], body, encodedCursor[:], now.UTC().UnixMilli(),
	); err != nil {
		return nil, api.NewError("internal_error", true)
	}
	return body, nil
}

func insertMarkerChange(ctx context.Context, transaction *sql.Tx, cursor uint64, recordID string, markerBody []byte, now time.Time) *api.Error {
	if protocolErr := insertChangeOrigin(ctx, transaction, cursor, "collection_marker", 0); protocolErr != nil {
		return protocolErr
	}
	encoded := EncodeUint64(cursor)
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO changes (
			cursor, kind, received_at_ms, record_revision_id,
			collection_marker_record_id, collection_marker_json
		) VALUES (?, 'collection_marker', ?, NULL, ?, ?)`,
		encoded[:], now.UTC().UnixMilli(), recordID, markerBody,
	); err != nil {
		return api.NewError("internal_error", true)
	}
	return nil
}
