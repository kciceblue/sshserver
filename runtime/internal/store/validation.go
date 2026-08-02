package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"

	"github.com/kciceblue/sshserver/runtime/internal/api"
	"github.com/kciceblue/sshserver/runtime/internal/auth"
)

type validatedDeviceRow struct {
	revoked     bool
	maxCounter  uint64
	ackCursor   uint64
	maxReturned uint64
}

type validatedMarkerChange struct {
	cursor uint64
	body   []byte
}

func invalidPersistentState(detail string) error {
	return fmt.Errorf("%w: %s", ErrUnexpectedSchema, detail)
}

// validatePersistentState rejects canonical-shape and cross-row corruption at
// startup/readiness instead of allowing a later authenticated request to turn
// it into a malformed replay or a partially usable instance.
func validatePersistentState(ctx context.Context, query schemaQueryer, identity Identity) error {
	serverCursor, envelopeGeneration, secretGeneration, err := validatePersistentRuntime(ctx, query)
	if err != nil {
		return err
	}
	devices, err := validatePersistentDevices(ctx, query, serverCursor)
	if err != nil {
		return err
	}
	if err := validatePersistentEnvelope(ctx, query, identity, envelopeGeneration, secretGeneration); err != nil {
		return err
	}
	if err := validatePersistentRevisionObjects(ctx, query); err != nil {
		return err
	}
	historicalCounters, err := validatePersistentRevisions(ctx, query, devices, serverCursor)
	if err != nil {
		return err
	}
	if err := validatePersistentHistorySequence(ctx, query, devices); err != nil {
		return err
	}
	for deviceID, row := range devices {
		if row.maxCounter != historicalCounters[deviceID] {
			return invalidPersistentState("device counter does not match accepted history")
		}
	}
	if err := validatePersistentRecordHeads(ctx, query); err != nil {
		return err
	}
	if err := validatePersistentRecordVectorIndex(ctx, query); err != nil {
		return err
	}
	if err := validatePersistentCollectionQueues(ctx, query, serverCursor); err != nil {
		return err
	}
	latestMarkerChanges, err := validatePersistentChanges(ctx, query, serverCursor)
	if err != nil {
		return err
	}
	if err := validatePersistentMarkers(ctx, query, devices, serverCursor, latestMarkerChanges); err != nil {
		return err
	}
	if err := validatePersistentReceipts(ctx, query, identity, devices); err != nil {
		return err
	}
	if err := validatePersistentReceiptRetention(ctx, query); err != nil {
		return err
	}
	if err := validatePersistentEnrollmentsAndRotations(ctx, query, identity, devices); err != nil {
		return err
	}
	if err := validatePersistentEnrollmentGrants(ctx, query); err != nil {
		return err
	}
	if err := validatePersistentSnapshots(ctx, query, identity, devices, serverCursor); err != nil {
		return err
	}
	if err := validatePersistentObjectReferences(ctx, query); err != nil {
		return err
	}
	return nil
}

func validatePersistentDevices(ctx context.Context, query schemaQueryer, serverCursor uint64) (map[string]validatedDeviceRow, error) {
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	rows, err := query.QueryContext(ctx, `
		SELECT d.device_id, d.token_hash, d.scopes_json, d.created_at_ms,
		       d.revoked_at_ms, d.last_sync_at_ms, d.last_ack_cursor,
		       d.max_author_counter, s.max_returned_cursor
		FROM devices d LEFT JOIN device_sync_state s USING (device_id)
		ORDER BY d.device_id`)
	if err != nil {
		return nil, invalidPersistentState("read device rows")
	}
	defer rows.Close()
	result := make(map[string]validatedDeviceRow)
	var previous string
	for rows.Next() {
		var deviceID, scopesJSON string
		var tokenHash, ackBytes, counterBytes, returnedBytes []byte
		var createdAt int64
		var revokedAt, lastSyncAt sql.NullInt64
		if rows.Scan(&deviceID, &tokenHash, &scopesJSON, &createdAt, &revokedAt, &lastSyncAt, &ackBytes, &counterBytes, &returnedBytes) != nil ||
			validateUUID(deviceID) != nil || len(tokenHash) != 32 || scopesJSON != string(wantScopes) ||
			previous != "" && previous >= deviceID || validateTimestamp(formatTimestamp(createdAt)) != nil {
			return nil, invalidPersistentState("invalid device row")
		}
		if revokedAt.Valid && (revokedAt.Int64 < createdAt || validateTimestamp(formatTimestamp(revokedAt.Int64)) != nil) {
			return nil, invalidPersistentState("invalid device revocation timestamp")
		}
		if lastSyncAt.Valid && (lastSyncAt.Int64 < createdAt || validateTimestamp(formatTimestamp(lastSyncAt.Int64)) != nil) {
			return nil, invalidPersistentState("invalid device sync timestamp")
		}
		ack, ackErr := DecodeUint64(ackBytes)
		counter, counterErr := DecodeUint64(counterBytes)
		returned, returnedErr := DecodeUint64(returnedBytes)
		if ackErr != nil || counterErr != nil || returnedErr != nil || ack > returned || returned > serverCursor {
			return nil, invalidPersistentState("invalid device cursor state")
		}
		result[deviceID] = validatedDeviceRow{revoked: revokedAt.Valid, maxCounter: counter, ackCursor: ack, maxReturned: returned}
		previous = deviceID
	}
	if rows.Err() != nil || len(result) > 64 {
		rows.Close()
		return nil, invalidPersistentState("invalid device registry")
	}
	if rows.Close() != nil {
		return nil, invalidPersistentState("read device registry")
	}
	var orphanSyncRows int
	if query.QueryRowContext(ctx, `
		SELECT count(*) FROM device_sync_state s
		LEFT JOIN devices d USING (device_id) WHERE d.device_id IS NULL`,
	).Scan(&orphanSyncRows) != nil || orphanSyncRows != 0 {
		return nil, invalidPersistentState("orphan device sync state")
	}
	return result, nil
}

// validateReadinessDevices inspects at most the protocol maximum plus one
// sentinel row. Full registry and orphan validation is startup-only.
func validateReadinessDevices(ctx context.Context, query schemaQueryer, serverCursor uint64) error {
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	rows, err := query.QueryContext(ctx, `
		SELECT d.device_id, d.token_hash, d.scopes_json, d.created_at_ms,
		       d.revoked_at_ms, d.last_sync_at_ms, d.last_ack_cursor,
		       d.max_author_counter, s.max_returned_cursor
		FROM devices d LEFT JOIN device_sync_state s USING (device_id)
		ORDER BY d.device_id LIMIT 65`)
	if err != nil {
		return invalidPersistentState("read readiness device sentinel")
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		var deviceID, scopesJSON string
		var tokenHash, ackBytes, counterBytes, returnedBytes []byte
		var createdAt int64
		var revokedAt, lastSyncAt sql.NullInt64
		if rows.Scan(&deviceID, &tokenHash, &scopesJSON, &createdAt, &revokedAt, &lastSyncAt, &ackBytes, &counterBytes, &returnedBytes) != nil ||
			validateUUID(deviceID) != nil || len(tokenHash) != 32 || scopesJSON != string(wantScopes) || validateTimestamp(formatTimestamp(createdAt)) != nil ||
			revokedAt.Valid && (revokedAt.Int64 < createdAt || validateTimestamp(formatTimestamp(revokedAt.Int64)) != nil) ||
			lastSyncAt.Valid && (lastSyncAt.Int64 < createdAt || validateTimestamp(formatTimestamp(lastSyncAt.Int64)) != nil) {
			return invalidPersistentState("invalid readiness device sentinel")
		}
		ack, ackErr := DecodeUint64(ackBytes)
		_, counterErr := DecodeUint64(counterBytes)
		returned, returnedErr := DecodeUint64(returnedBytes)
		if ackErr != nil || counterErr != nil || returnedErr != nil || ack > returned || returned > serverCursor {
			return invalidPersistentState("invalid readiness device cursor")
		}
	}
	if rows.Err() != nil || count > 64 {
		return invalidPersistentState("invalid readiness device registry")
	}
	return nil
}

func validatePersistentRuntime(ctx context.Context, query schemaQueryer) (uint64, uint64, uint64, error) {
	var cursorBytes, floorBytes, envelopeBytes, secretBytes, uptimeBytes, bootID []byte
	var collectionScanAfter string
	if query.QueryRowContext(ctx, `
		SELECT server_cursor, cursor_floor, envelope_generation,
		       instance_secret_generation, accumulated_uptime_ms, active_boot_id,
		       collection_scan_after_record_id
		FROM runtime_state WHERE singleton = 1`,
	).Scan(&cursorBytes, &floorBytes, &envelopeBytes, &secretBytes, &uptimeBytes, &bootID, &collectionScanAfter) != nil {
		return 0, 0, 0, invalidPersistentState("missing runtime state")
	}
	cursor, cursorErr := DecodeUint64(cursorBytes)
	floor, floorErr := DecodeUint64(floorBytes)
	envelope, envelopeErr := DecodeUint64(envelopeBytes)
	secret, secretErr := DecodeUint64(secretBytes)
	_, uptimeErr := DecodeUint64(uptimeBytes)
	if cursorErr != nil || floorErr != nil || envelopeErr != nil || secretErr != nil || uptimeErr != nil || floor > cursor || secret == 0 ||
		bootID != nil && len(bootID) != 16 || collectionScanAfter != "" && validateUUID(collectionScanAfter) != nil {
		return 0, 0, 0, invalidPersistentState("invalid runtime state")
	}
	return cursor, envelope, secret, nil
}

func validatePersistentEnvelope(ctx context.Context, query schemaQueryer, identity Identity, runtimeGeneration, secretGeneration uint64) error {
	var generationBytes, body []byte
	err := query.QueryRowContext(ctx, "SELECT generation, envelope_json FROM vault_envelope WHERE singleton = 1").Scan(&generationBytes, &body)
	if errors.Is(err, sql.ErrNoRows) {
		if runtimeGeneration != 0 {
			return invalidPersistentState("runtime envelope generation has no envelope")
		}
		return nil
	}
	if err != nil {
		return invalidPersistentState("read envelope row")
	}
	generation, err := DecodeUint64(generationBytes)
	var envelope vaultEnvelope
	if err != nil || decodeStoredCanonical(body, &envelope) != nil {
		return invalidPersistentState("invalid envelope row")
	}
	bodyGeneration, bodySecret, err := validateEnvelope(envelope, identity)
	if err != nil || generation != runtimeGeneration || bodyGeneration != generation || bodySecret != secretGeneration {
		return invalidPersistentState("inconsistent envelope row")
	}
	return nil
}

func validatePersistentRevisionObjects(ctx context.Context, query schemaQueryer) error {
	rows, err := query.QueryContext(ctx, "SELECT content_hash, revision_json FROM revision_objects ORDER BY content_hash")
	if err != nil {
		return invalidPersistentState("read revision objects")
	}
	defer rows.Close()
	for rows.Next() {
		var hashBytes, body []byte
		var revision recordRevision
		if rows.Scan(&hashBytes, &body) != nil || len(hashBytes) != 32 || decodeStoredCanonical(body, &revision) != nil {
			return invalidPersistentState("invalid revision object")
		}
		computed := sha256.Sum256(body)
		if !bytes.Equal(computed[:], hashBytes) {
			return invalidPersistentState("revision object hash mismatch")
		}
		if _, _, err := validateRevision(revision); err != nil {
			return invalidPersistentState("invalid revision object profile")
		}
	}
	if rows.Err() != nil {
		return invalidPersistentState("read revision objects")
	}
	return nil
}

// validatePersistentHistorySequence proves that the durable author history is
// complete, not merely that its maximum agrees with the device registry. V1
// never deletes revision metadata, so every device must retain exactly the
// contiguous counter sequence 1...max_author_counter. The same pass derives
// the exact cursor floor from collected revision changes; no other change kind
// is deleted by V1.
func validatePersistentHistorySequence(ctx context.Context, query schemaQueryer, devices map[string]validatedDeviceRow) error {
	rows, err := query.QueryContext(ctx, `
		SELECT author_device_id, author_counter, retained, change_cursor
		FROM record_revisions ORDER BY author_device_id, author_counter`)
	if err != nil {
		return invalidPersistentState("read revision history sequence")
	}
	seenAuthors := make(map[string]struct{}, len(devices))
	currentAuthor := ""
	lastCounter := uint64(0)
	maxCollectedCursor := uint64(0)
	finishAuthor := func() error {
		if currentAuthor != "" && devices[currentAuthor].maxCounter != lastCounter {
			return invalidPersistentState("device counter history is incomplete")
		}
		return nil
	}
	for rows.Next() {
		var authorID string
		var counterBytes, cursorBytes []byte
		var retained int
		if rows.Scan(&authorID, &counterBytes, &retained, &cursorBytes) != nil || validateUUID(authorID) != nil || retained < 0 || retained > 1 {
			rows.Close()
			return invalidPersistentState("invalid revision history sequence")
		}
		if _, exists := devices[authorID]; !exists {
			rows.Close()
			return invalidPersistentState("revision history has unknown author")
		}
		if authorID != currentAuthor {
			if err := finishAuthor(); err != nil {
				rows.Close()
				return err
			}
			currentAuthor = authorID
			lastCounter = 0
			seenAuthors[authorID] = struct{}{}
		}
		counter, counterErr := DecodeUint64(counterBytes)
		cursor, cursorErr := DecodeUint64(cursorBytes)
		if counterErr != nil || cursorErr != nil || counter == 0 || cursor == 0 || lastCounter == math.MaxUint64 || counter != lastCounter+1 {
			rows.Close()
			return invalidPersistentState("revision author counters are not contiguous")
		}
		lastCounter = counter
		if retained == 0 && cursor > maxCollectedCursor {
			maxCollectedCursor = cursor
		}
	}
	if rows.Err() != nil || rows.Close() != nil {
		return invalidPersistentState("read revision history sequence")
	}
	if err := finishAuthor(); err != nil {
		return err
	}
	for deviceID, row := range devices {
		if _, exists := seenAuthors[deviceID]; !exists && row.maxCounter != 0 {
			return invalidPersistentState("device counter history is missing")
		}
	}
	var floorBytes []byte
	if query.QueryRowContext(ctx, "SELECT cursor_floor FROM runtime_state WHERE singleton = 1").Scan(&floorBytes) != nil {
		return invalidPersistentState("read cursor floor")
	}
	floor, err := DecodeUint64(floorBytes)
	if err != nil || floor != maxCollectedCursor {
		return invalidPersistentState("cursor floor does not match collected history")
	}
	return nil
}

func validatePersistentObjectReferences(ctx context.Context, query schemaQueryer) error {
	var orphanObjects int
	if query.QueryRowContext(ctx, `
		SELECT count(*) FROM revision_objects o
		LEFT JOIN (
			SELECT content_hash FROM record_revisions WHERE retained = 1
			UNION
			SELECT content_hash FROM snapshot_revision_refs
		) refs USING (content_hash)
		WHERE refs.content_hash IS NULL`,
	).Scan(&orphanObjects) != nil || orphanObjects != 0 {
		return invalidPersistentState("orphan revision object")
	}
	return nil
}

func validatePersistentRevisions(ctx context.Context, query schemaQueryer, devices map[string]validatedDeviceRow, serverCursor uint64) (map[string]uint64, error) {
	rows, err := query.QueryContext(ctx, `
		SELECT r.revision_id, r.record_id, r.author_device_id, r.author_counter,
		       r.vector_json, r.collection_witness_authenticator, r.tombstone,
		       r.content_hash, r.received_at_ms, r.accepted_uptime_ms,
		       r.change_cursor, r.retained, r.undominated,
		       o.revision_json, c.cursor
		FROM record_revisions r
		LEFT JOIN revision_objects o USING (content_hash)
		LEFT JOIN changes c
		  ON c.cursor = r.change_cursor AND c.kind = 'record_revision'
		 AND c.record_revision_id = r.revision_id
		ORDER BY r.record_id, r.revision_id`)
	if err != nil {
		return nil, invalidPersistentState("read revision rows")
	}
	defer rows.Close()
	historicalCounters := make(map[string]uint64, len(devices))
	type frontierItem struct {
		id     string
		vector map[string]uint64
	}
	var currentRecord string
	var frontier []frontierItem
	storedHeads := make(map[string]struct{})
	flushFrontier := func() error {
		if len(frontier) != len(storedHeads) || len(frontier) > 32 {
			return invalidPersistentState("invalid stored undominated frontier")
		}
		for _, item := range frontier {
			if _, exists := storedHeads[item.id]; !exists {
				return invalidPersistentState("incorrect stored undominated flag")
			}
		}
		return nil
	}
	for rows.Next() {
		var revisionID, recordID, authorID string
		var counterBytes, vectorBody, witness, hashBytes, uptimeBytes, cursorBytes, objectBody, matchingChange []byte
		var receivedAt int64
		var tombstone, retained, undominated int
		if rows.Scan(&revisionID, &recordID, &authorID, &counterBytes, &vectorBody, &witness, &tombstone, &hashBytes, &receivedAt, &uptimeBytes, &cursorBytes, &retained, &undominated, &objectBody, &matchingChange) != nil ||
			validateUUID(revisionID) != nil || validateUUID(recordID) != nil || validateUUID(authorID) != nil || len(hashBytes) != 32 ||
			witness != nil && len(witness) != 32 || tombstone < 0 || tombstone > 1 || retained < 0 || retained > 1 || undominated < 0 || undominated > 1 ||
			retained == 0 && undominated != 0 ||
			validateTimestamp(formatTimestamp(receivedAt)) != nil {
			return nil, invalidPersistentState("invalid revision row")
		}
		counter, counterErr := DecodeUint64(counterBytes)
		uptime, uptimeErr := DecodeUint64(uptimeBytes)
		cursor, cursorErr := DecodeUint64(cursorBytes)
		_ = uptime
		var entries []vectorEntry
		if json.Unmarshal(vectorBody, &entries) != nil {
			return nil, invalidPersistentState("invalid stored revision vector")
		}
		vector, vectorErr := validateVector(entries)
		canonicalVector, _ := json.Marshal(entries)
		deviceRow, authorExists := devices[authorID]
		if counterErr != nil || uptimeErr != nil || cursorErr != nil || cursor == 0 || cursor > serverCursor || vectorErr != nil ||
			!bytes.Equal(canonicalVector, vectorBody) || vector[authorID] != counter || !authorExists || counter > deviceRow.maxCounter {
			return nil, invalidPersistentState("inconsistent revision row")
		}
		if currentRecord != recordID {
			if currentRecord != "" {
				if err := flushFrontier(); err != nil {
					return nil, err
				}
			}
			currentRecord = recordID
			frontier = nil
			clear(storedHeads)
		}
		if retained == 1 {
			dominated := false
			retainedFrontier := frontier[:0]
			for _, existing := range frontier {
				if vectorsEqual(existing.vector, vector) {
					return nil, invalidPersistentState("equal-vector revision equivocation")
				}
				if vectorDominates(existing.vector, vector) {
					dominated = true
				}
				if !vectorDominates(vector, existing.vector) {
					retainedFrontier = append(retainedFrontier, existing)
				}
			}
			frontier = retainedFrontier
			if !dominated {
				frontier = append(frontier, frontierItem{id: revisionID, vector: vector})
			}
			if undominated == 1 {
				storedHeads[revisionID] = struct{}{}
				if len(storedHeads) > 32 {
					return nil, invalidPersistentState("too many stored undominated revisions")
				}
			}
		}
		if counter > historicalCounters[authorID] {
			historicalCounters[authorID] = counter
		}
		for vectorDeviceID, vectorCounter := range vector {
			registry, exists := devices[vectorDeviceID]
			if !exists || vectorCounter > registry.maxCounter {
				return nil, invalidPersistentState("revision vector exceeds device registry")
			}
		}
		var bodyRevision recordRevision
		objectExists := objectBody != nil
		if objectExists && decodeStoredCanonical(objectBody, &bodyRevision) != nil {
			return nil, invalidPersistentState("invalid referenced revision object")
		}
		if retained == 1 && (!objectExists || len(matchingChange) != 8) {
			return nil, invalidPersistentState("retained revision object or change mismatch")
		}
		if objectExists && (bodyRevision.RevisionID != revisionID || bodyRevision.RecordID != recordID || bodyRevision.AuthorDeviceID != authorID ||
			bodyRevision.AuthorCounter != encodeUint64Text(counter) || !slices.Equal(bodyRevision.VersionVector, entries) || bodyRevision.Tombstone != (tombstone == 1)) {
			return nil, invalidPersistentState("revision object identity mismatch")
		}
		if retained == 0 && matchingChange != nil {
			return nil, invalidPersistentState("collected revision retains a change")
		}
		if objectExists {
			computed := sha256.Sum256(objectBody)
			if !bytes.Equal(computed[:], hashBytes) {
				return nil, invalidPersistentState("revision content address mismatch")
			}
			var bodyWitness []byte
			if bodyRevision.CollectionWitnessAuthenticator != nil {
				bodyWitness, _ = decodeBase64(*bodyRevision.CollectionWitnessAuthenticator, 32, 0, 0)
			}
			if !bytes.Equal(bodyWitness, witness) {
				return nil, invalidPersistentState("revision witness mismatch")
			}
		}
	}
	if rows.Err() != nil {
		return nil, invalidPersistentState("read revision rows")
	}
	if currentRecord != "" {
		if err := flushFrontier(); err != nil {
			return nil, err
		}
	}
	return historicalCounters, nil
}

func validatePersistentRecordHeads(ctx context.Context, query schemaQueryer) error {
	rows, err := query.QueryContext(ctx, `
		SELECT h.record_id, h.revision_id, r.record_id, r.retained, r.undominated
		FROM record_heads h
		LEFT JOIN record_revisions r ON r.revision_id = h.revision_id
		ORDER BY h.record_id, h.revision_id`)
	if err != nil {
		return invalidPersistentState("read record heads")
	}
	var previousRecord string
	countForRecord := 0
	for rows.Next() {
		var recordID, revisionID string
		var revisionRecord sql.NullString
		var retained, undominated sql.NullInt64
		if rows.Scan(&recordID, &revisionID, &revisionRecord, &retained, &undominated) != nil || validateUUID(recordID) != nil || validateUUID(revisionID) != nil ||
			!revisionRecord.Valid || revisionRecord.String != recordID || !retained.Valid || retained.Int64 != 1 || !undominated.Valid || undominated.Int64 != 1 {
			rows.Close()
			return invalidPersistentState("invalid record head")
		}
		if recordID != previousRecord {
			previousRecord = recordID
			countForRecord = 0
		}
		countForRecord++
		if countForRecord > 32 {
			rows.Close()
			return invalidPersistentState("too many record heads")
		}
	}
	if rows.Err() != nil || rows.Close() != nil {
		return invalidPersistentState("read record heads")
	}
	var missing int
	if query.QueryRowContext(ctx, `
		SELECT count(*) FROM record_revisions r
		WHERE r.retained = 1 AND r.undominated = 1 AND NOT EXISTS (
			SELECT 1 FROM record_heads h
			WHERE h.record_id = r.record_id AND h.revision_id = r.revision_id
		)`).Scan(&missing) != nil || missing != 0 {
		return invalidPersistentState("record head index is incomplete")
	}
	return nil
}

func validatePersistentRecordVectorIndex(ctx context.Context, query schemaQueryer) error {
	rows, err := query.QueryContext(ctx, `
		SELECT i.record_id, i.vector_hash, i.revision_id,
		       r.record_id, r.vector_json
		FROM record_vector_index i
		LEFT JOIN record_revisions r ON r.revision_id = i.revision_id
		ORDER BY i.record_id, i.vector_hash, i.revision_id`)
	if err != nil {
		return invalidPersistentState("read record vector index")
	}
	for rows.Next() {
		var recordID, revisionID string
		var vectorHash, vectorBody []byte
		var revisionRecord sql.NullString
		if rows.Scan(&recordID, &vectorHash, &revisionID, &revisionRecord, &vectorBody) != nil ||
			validateUUID(recordID) != nil || validateUUID(revisionID) != nil || len(vectorHash) != 32 || !revisionRecord.Valid || revisionRecord.String != recordID ||
			vectorBody == nil {
			rows.Close()
			return invalidPersistentState("invalid record vector index")
		}
		computed := sha256.Sum256(vectorBody)
		if !bytes.Equal(computed[:], vectorHash) {
			rows.Close()
			return invalidPersistentState("record vector index hash mismatch")
		}
	}
	if rows.Err() != nil || rows.Close() != nil {
		return invalidPersistentState("read record vector index")
	}
	var missing int
	if query.QueryRowContext(ctx, `
		SELECT count(*) FROM (
			SELECT record_id, revision_id FROM record_revisions
			EXCEPT
			SELECT record_id, revision_id FROM record_vector_index
		)`).Scan(&missing) != nil || missing != 0 {
		return invalidPersistentState("record vector index is incomplete")
	}
	return nil
}

func validatePersistentCollectionQueues(ctx context.Context, query schemaQueryer, serverCursor uint64) error {
	rows, err := query.QueryContext(ctx, `
		SELECT q.record_id, q.barrier_cursor, h.record_id, h.max_cursor
		FROM collection_records q
		LEFT JOIN (
			SELECT record_id, max(change_cursor) AS max_cursor
			FROM record_revisions GROUP BY record_id
		) h USING (record_id)
		ORDER BY q.record_id`)
	if err != nil {
		return invalidPersistentState("read collection record queue")
	}
	for rows.Next() {
		var recordID string
		var barrierBytes, maxBytes []byte
		var historicalRecord sql.NullString
		if rows.Scan(&recordID, &barrierBytes, &historicalRecord, &maxBytes) != nil || validateUUID(recordID) != nil || !historicalRecord.Valid || historicalRecord.String != recordID {
			rows.Close()
			return invalidPersistentState("invalid collection record queue")
		}
		barrier, barrierErr := DecodeUint64(barrierBytes)
		historicalMaximum, maxErr := DecodeUint64(maxBytes)
		if barrierErr != nil || maxErr != nil || barrier != historicalMaximum || barrier == 0 || barrier > serverCursor {
			rows.Close()
			return invalidPersistentState("invalid collection record barrier")
		}
	}
	if rows.Err() != nil || rows.Close() != nil {
		return invalidPersistentState("read collection record queue")
	}
	var missingRecords int
	if query.QueryRowContext(ctx, `
		SELECT count(*) FROM (
			SELECT DISTINCT r.record_id FROM record_revisions r
			WHERE r.retained = 1
			EXCEPT SELECT q.record_id FROM collection_records q
		)`).Scan(&missingRecords) != nil || missingRecords != 0 {
		return invalidPersistentState("collection record queue is incomplete")
	}
	var emptyRecords int
	if query.QueryRowContext(ctx, `
		SELECT count(*) FROM collection_records q
		WHERE NOT EXISTS (
			SELECT 1 FROM record_revisions r
			WHERE r.record_id = q.record_id AND r.retained = 1
		)`).Scan(&emptyRecords) != nil || emptyRecords != 0 {
		return invalidPersistentState("collection record queue has empty records")
	}
	candidateRows, err := query.QueryContext(ctx, `
		SELECT q.record_id, q.accepted_uptime_ms, q.revision_id,
		       r.record_id, r.accepted_uptime_ms, r.retained
		FROM collection_candidates q
		LEFT JOIN record_revisions r ON r.revision_id = q.revision_id
		ORDER BY q.record_id, q.accepted_uptime_ms, q.revision_id`)
	if err != nil {
		return invalidPersistentState("read collection candidate queue")
	}
	for candidateRows.Next() {
		var recordID, revisionID string
		var uptimeBytes, revisionUptime []byte
		var revisionRecord sql.NullString
		var retained sql.NullInt64
		if candidateRows.Scan(&recordID, &uptimeBytes, &revisionID, &revisionRecord, &revisionUptime, &retained) != nil ||
			validateUUID(recordID) != nil || validateUUID(revisionID) != nil || decodeUint64Error(uptimeBytes) != nil ||
			!revisionRecord.Valid || revisionRecord.String != recordID || !bytes.Equal(uptimeBytes, revisionUptime) || !retained.Valid || retained.Int64 != 1 {
			candidateRows.Close()
			return invalidPersistentState("invalid collection candidate queue")
		}
	}
	if candidateRows.Err() != nil || candidateRows.Close() != nil {
		return invalidPersistentState("read collection candidate queue")
	}
	var missingCandidates int
	if query.QueryRowContext(ctx, `
		SELECT count(*) FROM record_revisions r
		WHERE r.retained = 1 AND NOT EXISTS (
			SELECT 1 FROM collection_candidates q
			WHERE q.revision_id = r.revision_id AND q.record_id = r.record_id
			  AND q.accepted_uptime_ms = r.accepted_uptime_ms
		)`).Scan(&missingCandidates) != nil || missingCandidates != 0 {
		return invalidPersistentState("collection candidate queue is incomplete")
	}
	return nil
}

func decodeUint64Error(value []byte) error {
	_, err := DecodeUint64(value)
	return err
}

func validatePersistentMarkers(ctx context.Context, query schemaQueryer, devices map[string]validatedDeviceRow, serverCursor uint64, latestChanges map[string]validatedMarkerChange) error {
	rows, err := query.QueryContext(ctx, `
		SELECT m.record_id, m.witness_revision_id, m.frontier_json,
		       m.collection_witness_authenticator, m.barrier_cursor,
		       m.marker_json, m.change_cursor, m.received_at_ms,
		       r.record_id, r.vector_json, r.collection_witness_authenticator
		FROM collection_markers m
		LEFT JOIN record_revisions r ON r.revision_id = m.witness_revision_id
		ORDER BY m.record_id`)
	if err != nil {
		return invalidPersistentState("read marker rows")
	}
	defer rows.Close()
	seen := make(map[string]struct{}, len(latestChanges))
	for rows.Next() {
		var recordID, witnessID string
		var frontierBody, authenticator, barrierBytes, body, changeBytes []byte
		var witnessRecordID sql.NullString
		var witnessVector, witnessAuthenticator []byte
		var receivedAt int64
		if rows.Scan(&recordID, &witnessID, &frontierBody, &authenticator, &barrierBytes, &body, &changeBytes, &receivedAt,
			&witnessRecordID, &witnessVector, &witnessAuthenticator) != nil || len(authenticator) != 32 {
			return invalidPersistentState("invalid marker row")
		}
		latestChange, hasLatestChange := latestChanges[recordID]
		marker, err := decodeStoredCollectionMarker(body)
		barrier, barrierErr := DecodeUint64(barrierBytes)
		changeCursor, changeErr := DecodeUint64(changeBytes)
		canonicalFrontier, _ := json.Marshal(marker.Frontier)
		decodedAuthenticator, authErr := decodeBase64(marker.CollectionWitnessAuthenticator, 32, 0, 0)
		if err != nil || barrierErr != nil || changeErr != nil || authErr != nil || marker.RecordID != recordID || marker.WitnessRevisionID != witnessID ||
			!bytes.Equal(canonicalFrontier, frontierBody) || !bytes.Equal(decodedAuthenticator, authenticator) || marker.BarrierCursor != encodeUint64Text(barrier) ||
			barrier >= changeCursor || changeCursor > serverCursor || validateTimestamp(formatTimestamp(receivedAt)) != nil ||
			!witnessRecordID.Valid || witnessRecordID.String != recordID || !bytes.Equal(witnessVector, frontierBody) || !bytes.Equal(witnessAuthenticator, authenticator) ||
			!hasLatestChange || latestChange.cursor != changeCursor || !bytes.Equal(latestChange.body, body) {
			return invalidPersistentState("inconsistent marker row")
		}
		seen[recordID] = struct{}{}
		frontier, _, _, _ := validateCollectionMarker(marker)
		for deviceID, counter := range frontier {
			deviceRow, exists := devices[deviceID]
			if !exists || counter > deviceRow.maxCounter {
				return invalidPersistentState("marker frontier exceeds device registry")
			}
		}
	}
	if rows.Err() != nil {
		return invalidPersistentState("read marker rows")
	}
	if len(seen) != len(latestChanges) {
		return invalidPersistentState("marker change has no current marker")
	}
	return nil
}

func validatePersistentEnrollmentGrants(ctx context.Context, query schemaQueryer) error {
	rows, err := query.QueryContext(ctx, `
		SELECT g.grant_hash, g.boot_id, g.expires_at_ms,
		       g.consumed_enrollment_id, e.enrollment_id
		FROM enrollment_grants g
		LEFT JOIN enrollments e ON e.enrollment_id = g.consumed_enrollment_id
		ORDER BY g.grant_hash`)
	if err != nil {
		return invalidPersistentState("read enrollment grants")
	}
	defer rows.Close()
	for rows.Next() {
		var grantHash, bootID []byte
		var expiresAt int64
		var consumedID, matchedID sql.NullString
		if rows.Scan(&grantHash, &bootID, &expiresAt, &consumedID, &matchedID) != nil || len(grantHash) != 32 || len(bootID) != 16 ||
			validateTimestamp(formatTimestamp(expiresAt)) != nil || consumedID.Valid != matchedID.Valid || consumedID.Valid && consumedID.String != matchedID.String {
			return invalidPersistentState("invalid enrollment grant")
		}
	}
	if rows.Err() != nil {
		return invalidPersistentState("read enrollment grants")
	}
	return nil
}

func validatePersistentChanges(ctx context.Context, query schemaQueryer, serverCursor uint64) (map[string]validatedMarkerChange, error) {
	rows, err := query.QueryContext(ctx, `
		SELECT c.cursor, c.kind, c.received_at_ms, c.record_revision_id,
		       c.collection_marker_record_id, c.collection_marker_json,
		       r.retained
		FROM changes c LEFT JOIN record_revisions r
		  ON r.revision_id = c.record_revision_id
		ORDER BY c.cursor`)
	if err != nil {
		return nil, invalidPersistentState("read change rows")
	}
	defer rows.Close()
	previous := uint64(0)
	latestMarkerChanges := make(map[string]validatedMarkerChange)
	for rows.Next() {
		var cursorBytes, markerBody []byte
		var kind string
		var receivedAt int64
		var revisionID, markerID sql.NullString
		var revisionRetained sql.NullInt64
		if rows.Scan(&cursorBytes, &kind, &receivedAt, &revisionID, &markerID, &markerBody, &revisionRetained) != nil {
			return nil, invalidPersistentState("invalid change row")
		}
		cursor, err := DecodeUint64(cursorBytes)
		if err != nil || cursor == 0 || cursor <= previous || cursor > serverCursor || validateTimestamp(formatTimestamp(receivedAt)) != nil {
			return nil, invalidPersistentState("invalid change cursor")
		}
		switch kind {
		case "record_revision":
			if !revisionID.Valid || markerID.Valid || markerBody != nil || validateUUID(revisionID.String) != nil {
				return nil, invalidPersistentState("invalid revision change")
			}
			if !revisionRetained.Valid || revisionRetained.Int64 != 1 {
				return nil, invalidPersistentState("orphan revision change")
			}
		case "collection_marker":
			marker, markerErr := decodeStoredCollectionMarker(markerBody)
			if revisionID.Valid || !markerID.Valid || markerErr != nil || marker.RecordID != markerID.String {
				return nil, invalidPersistentState("invalid marker change")
			}
			latestMarkerChanges[markerID.String] = validatedMarkerChange{cursor: cursor, body: append([]byte(nil), markerBody...)}
		case "envelope_changed", "device_changed":
			if revisionID.Valid || markerID.Valid || markerBody != nil {
				return nil, invalidPersistentState("invalid metadata change")
			}
		default:
			return nil, invalidPersistentState("invalid change kind")
		}
		previous = cursor
	}
	if rows.Err() != nil {
		return nil, invalidPersistentState("read change rows")
	}
	if previous != serverCursor {
		return nil, invalidPersistentState("server cursor has no retained terminal change")
	}
	return latestMarkerChanges, nil
}

func validatePersistentReceipts(ctx context.Context, query schemaQueryer, identity Identity, devices map[string]validatedDeviceRow) error {
	rows, err := query.QueryContext(ctx, `
		SELECT device_id, operation, request_id, request_fingerprint,
		       response_status, response_json, created_at_ms, created_uptime_ms
		FROM operation_receipts ORDER BY receipt_sequence`)
	if err != nil {
		return invalidPersistentState("read operation receipts")
	}
	defer rows.Close()
	for rows.Next() {
		var deviceID, operation, requestID string
		var fingerprint, body, uptimeBytes []byte
		var status int
		var createdAt int64
		if rows.Scan(&deviceID, &operation, &requestID, &fingerprint, &status, &body, &createdAt, &uptimeBytes) != nil ||
			validateUUID(deviceID) != nil || validateUUID(requestID) != nil || len(fingerprint) != 32 || !deviceExists(devices, deviceID) ||
			validateTimestamp(formatTimestamp(createdAt)) != nil || validateStoredOperationResponse(operation, status, body, identity) != nil {
			return invalidPersistentState("invalid operation receipt")
		}
		if _, err := DecodeUint64(uptimeBytes); err != nil {
			return invalidPersistentState("invalid operation receipt uptime")
		}
	}
	if rows.Err() != nil {
		return invalidPersistentState("read operation receipts")
	}
	return nil
}

func validatePersistentReceiptRetention(ctx context.Context, query schemaQueryer) error {
	rows, err := query.QueryContext(ctx, `
		SELECT q.device_id, q.receipt_class, q.receipt_sequence,
		       q.created_uptime_ms, r.device_id, r.operation,
		       r.created_uptime_ms
		FROM operation_receipt_retention q
		LEFT JOIN operation_receipts r ON r.receipt_sequence = q.receipt_sequence
		ORDER BY q.device_id, q.receipt_class, q.receipt_sequence`)
	if err != nil {
		return invalidPersistentState("read operation receipt retention")
	}
	for rows.Next() {
		var deviceID, receiptClass string
		var sequence int64
		var uptimeBytes, receiptUptime []byte
		var receiptDevice, operation sql.NullString
		if rows.Scan(&deviceID, &receiptClass, &sequence, &uptimeBytes, &receiptDevice, &operation, &receiptUptime) != nil ||
			validateUUID(deviceID) != nil || sequence <= 0 || decodeUint64Error(uptimeBytes) != nil || !receiptDevice.Valid || receiptDevice.String != deviceID ||
			!operation.Valid || !bytes.Equal(uptimeBytes, receiptUptime) || receiptClass != "sync" && receiptClass != "other" ||
			receiptClass == "sync" != (operation.String == "sync") {
			rows.Close()
			return invalidPersistentState("invalid operation receipt retention")
		}
	}
	if rows.Err() != nil || rows.Close() != nil {
		return invalidPersistentState("read operation receipt retention")
	}
	var missing int
	if query.QueryRowContext(ctx, `
		SELECT count(*) FROM operation_receipts r
		WHERE NOT EXISTS (
			SELECT 1 FROM operation_receipt_retention q
			WHERE q.receipt_sequence = r.receipt_sequence
		)`).Scan(&missing) != nil || missing != 0 {
		return invalidPersistentState("operation receipt retention is incomplete")
	}
	return nil
}

func deviceExists(devices map[string]validatedDeviceRow, deviceID string) bool {
	_, exists := devices[deviceID]
	return exists
}

func validatePersistentEnrollmentsAndRotations(ctx context.Context, query schemaQueryer, identity Identity, devices map[string]validatedDeviceRow) error {
	enrollmentRows, err := query.QueryContext(ctx, `
		SELECT enrollment_id, device_id, token_hash, scopes_json,
		       request_fingerprint, response_json, created_status
		FROM enrollments ORDER BY enrollment_id`)
	if err != nil {
		return invalidPersistentState("read enrollment rows")
	}
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	for enrollmentRows.Next() {
		var enrollmentID, deviceID, scopesJSON string
		var tokenHash, fingerprint, body []byte
		var status int
		if enrollmentRows.Scan(&enrollmentID, &deviceID, &tokenHash, &scopesJSON, &fingerprint, &body, &status) != nil ||
			validateUUID(enrollmentID) != nil || !deviceExists(devices, deviceID) || len(tokenHash) != 32 || len(fingerprint) != 32 || scopesJSON != string(wantScopes) ||
			status != http.StatusCreated || validateStoredEnrollmentResponse(body, identity, deviceID) != nil {
			enrollmentRows.Close()
			return invalidPersistentState("invalid enrollment row")
		}
	}
	if enrollmentRows.Err() != nil || enrollmentRows.Close() != nil {
		return invalidPersistentState("read enrollment rows")
	}

	rotationRows, err := query.QueryContext(ctx, `
		SELECT rotation_id, device_id, old_token_hash, new_token_hash,
		       request_fingerprint, response_json, created_at_ms
		FROM token_rotations ORDER BY rotation_id`)
	if err != nil {
		return invalidPersistentState("read rotation rows")
	}
	for rotationRows.Next() {
		var rotationID, deviceID string
		var oldHash, newHash, fingerprint, body []byte
		var createdAt int64
		var response device
		if rotationRows.Scan(&rotationID, &deviceID, &oldHash, &newHash, &fingerprint, &body, &createdAt) != nil ||
			validateUUID(rotationID) != nil || !deviceExists(devices, deviceID) || len(oldHash) != 32 || len(newHash) != 32 || len(fingerprint) != 32 ||
			validateTimestamp(formatTimestamp(createdAt)) != nil || decodeStoredCanonical(body, &response) != nil || validateDevice(response) != nil || response.DeviceID != deviceID {
			rotationRows.Close()
			return invalidPersistentState("invalid token rotation row")
		}
	}
	if rotationRows.Err() != nil || rotationRows.Close() != nil {
		return invalidPersistentState("read rotation rows")
	}

	selfRows, err := query.QueryContext(ctx, `
		SELECT device_id, request_id, body_fingerprint, pre_revocation_token_hash,
		       response_status, response_headers_json, response_json
		FROM self_revocation_receipts ORDER BY device_id`)
	if err != nil {
		return invalidPersistentState("read self-revocation receipts")
	}
	for selfRows.Next() {
		var deviceID, requestID string
		var fingerprint, tokenHash, headersBody, body []byte
		var status int
		var headers []api.Header
		var response device
		if selfRows.Scan(&deviceID, &requestID, &fingerprint, &tokenHash, &status, &headersBody, &body) != nil ||
			validateUUID(requestID) != nil || len(fingerprint) != 32 || len(tokenHash) != 32 || !devices[deviceID].revoked || status != http.StatusOK ||
			json.Unmarshal(headersBody, &headers) != nil || !slices.Equal(headers, api.V1ResponseHeaders(requestID, len(body))) ||
			decodeStoredCanonical(body, &response) != nil || validateDevice(response) != nil || response.DeviceID != deviceID || response.Status != "revoked" {
			selfRows.Close()
			return invalidPersistentState("invalid self-revocation receipt")
		}
		canonicalHeaders, _ := json.Marshal(headers)
		if !bytes.Equal(canonicalHeaders, headersBody) {
			selfRows.Close()
			return invalidPersistentState("noncanonical self-revocation headers")
		}
	}
	if selfRows.Err() != nil || selfRows.Close() != nil {
		return invalidPersistentState("read self-revocation receipts")
	}
	return nil
}

func validatePersistentSnapshots(ctx context.Context, query schemaQueryer, identity Identity, devices map[string]validatedDeviceRow, serverCursor uint64) error {
	type validatedSnapshot struct {
		ownerID            string
		requestID          string
		metadataBytes      int64
		createBody         []byte
		create             snapshotCreateResponse
		pages              []storedSnapshotPage
		references         []snapshotRevisionReference
		referenceRecordIDs map[string]string
		sourceCounters     map[string]uint64
		orderedRevisionIDs []string
		validationAccount  snapshotMetadataAccounting
	}
	snapshots := make(map[string]*validatedSnapshot)
	ownerCounts := make(map[string]int)
	declaredMetadata := int64(0)
	rows, err := query.QueryContext(ctx, `
		SELECT snapshot_id, owner_device_id, request_id, request_fingerprint,
		       cut_cursor, envelope_generation, expires_at_ms, metadata_bytes,
		       create_response_json
		FROM snapshots ORDER BY snapshot_id`)
	if err != nil {
		return invalidPersistentState("read snapshots")
	}
	for rows.Next() {
		var snapshotID, ownerID, requestID string
		var fingerprint, cutBytes, generationBytes, body []byte
		var expiresAt, metadataBytes int64
		if rows.Scan(&snapshotID, &ownerID, &requestID, &fingerprint, &cutBytes, &generationBytes, &expiresAt, &metadataBytes, &body) != nil ||
			validateUUID(snapshotID) != nil || validateUUID(requestID) != nil || !deviceExists(devices, ownerID) || len(fingerprint) != 32 ||
			metadataBytes < 0 || metadataBytes > snapshotMetadataLimit || len(snapshots) >= 8 {
			rows.Close()
			return invalidPersistentState("invalid snapshot row")
		}
		cut, cutErr := DecodeUint64(cutBytes)
		generation, generationErr := DecodeUint64(generationBytes)
		var create snapshotCreateResponse
		if cutErr != nil || generationErr != nil || cut > serverCursor || validateStoredSnapshotCreateResponse(body, identity, snapshotID, ownerID, cut, generation, expiresAt) != nil ||
			decodeStoredCanonical(body, &create) != nil {
			rows.Close()
			return invalidPersistentState("inconsistent snapshot row")
		}
		if metadataBytes > snapshotMetadataLimit-declaredMetadata {
			rows.Close()
			return invalidPersistentState("active snapshot metadata exceeds limit")
		}
		validationAccount := snapshotMetadataAccounting{}
		accountSnapshotBase(&validationAccount, snapshotID, ownerID, requestID, body)
		if !validationAccount.ok() || validationAccount.total > metadataBytes {
			rows.Close()
			return invalidPersistentState("snapshot metadata undercounts base row")
		}
		declaredMetadata += metadataBytes
		ownerCounts[ownerID]++
		if ownerCounts[ownerID] > 1 {
			rows.Close()
			return invalidPersistentState("multiple active snapshots for one owner")
		}
		snapshots[snapshotID] = &validatedSnapshot{
			ownerID: ownerID, requestID: requestID, metadataBytes: metadataBytes,
			createBody: body, create: create, referenceRecordIDs: make(map[string]string),
			sourceCounters: make(map[string]uint64), validationAccount: validationAccount,
		}
	}
	if rows.Err() != nil || rows.Close() != nil {
		return invalidPersistentState("read snapshots")
	}

	pageRows, err := query.QueryContext(ctx, "SELECT snapshot_id, page_index, page_token, response_json FROM snapshot_pages ORDER BY snapshot_id, page_index")
	if err != nil {
		return invalidPersistentState("read snapshot pages")
	}
	for pageRows.Next() {
		var snapshotID, token string
		var index int64
		var body []byte
		var descriptor snapshotPageDescriptor
		snapshot := snapshots[snapshotID]
		if pageRows.Scan(&snapshotID, &index, &token, &body) != nil {
			pageRows.Close()
			return invalidPersistentState("invalid snapshot page")
		}
		snapshot = snapshots[snapshotID]
		if snapshot == nil || index < 0 || index != int64(len(snapshot.pages)) || decodeBase64Token(token) != nil || decodeStoredSnapshotPageDescriptor(body, &descriptor) != nil {
			pageRows.Close()
			return invalidPersistentState("invalid snapshot page")
		}
		accountSnapshotPage(&snapshot.validationAccount, snapshotID, len(snapshot.pages), token, body)
		if !snapshot.validationAccount.ok() || snapshot.validationAccount.total > snapshot.metadataBytes {
			pageRows.Close()
			return invalidPersistentState("snapshot pages exceed declared metadata")
		}
		snapshot.pages = append(snapshot.pages, storedSnapshotPage{token: token, descriptor: descriptor, body: body})
	}
	if pageRows.Err() != nil || pageRows.Close() != nil {
		return invalidPersistentState("read snapshot pages")
	}
	for _, snapshot := range snapshots {
		if len(snapshot.pages) == 0 || snapshot.create.FirstPageToken != snapshot.pages[0].token {
			return invalidPersistentState("snapshot has no valid first page")
		}
		for index, page := range snapshot.pages {
			last := index+1 == len(snapshot.pages)
			if last {
				if page.descriptor.HasMore || page.descriptor.NextPageToken != nil {
					return invalidPersistentState("snapshot final page is not terminal")
				}
			} else if !page.descriptor.HasMore || page.descriptor.NextPageToken == nil || *page.descriptor.NextPageToken != snapshot.pages[index+1].token {
				return invalidPersistentState("snapshot page token chain is broken")
			}
			for _, source := range page.descriptor.SourceDevices {
				counter, err := parseUint64(source.MaxAuthorCounter)
				if err != nil {
					return invalidPersistentState("invalid snapshot source counter")
				}
				if _, exists := snapshot.sourceCounters[source.DeviceID]; exists {
					return invalidPersistentState("duplicate snapshot source device")
				}
				snapshot.sourceCounters[source.DeviceID] = counter
			}
		}
		phase := -1
		var previousMarkerID, previousSourceID string
		for _, page := range snapshot.pages {
			pagePhase := 3
			switch {
			case len(page.descriptor.RevisionIDs) != 0:
				pagePhase = 0
			case len(page.descriptor.CollectionMarkers) != 0:
				pagePhase = 1
			case len(page.descriptor.SourceDevices) != 0:
				pagePhase = 2
			}
			if pagePhase == 3 && len(snapshot.pages) != 1 || pagePhase < phase {
				return invalidPersistentState("invalid snapshot phase order")
			}
			phase = pagePhase
			for _, revisionID := range page.descriptor.RevisionIDs {
				snapshot.orderedRevisionIDs = append(snapshot.orderedRevisionIDs, revisionID)
			}
			for _, marker := range page.descriptor.CollectionMarkers {
				if previousMarkerID != "" && previousMarkerID >= marker.RecordID {
					return invalidPersistentState("snapshot markers are not globally ordered")
				}
				frontier, _, _, _ := validateCollectionMarker(marker)
				for deviceID, counter := range frontier {
					maximum, exists := snapshot.sourceCounters[deviceID]
					if !exists || counter > maximum {
						return invalidPersistentState("snapshot marker exceeds source registry")
					}
				}
				previousMarkerID = marker.RecordID
			}
			for _, source := range page.descriptor.SourceDevices {
				if previousSourceID != "" && previousSourceID >= source.DeviceID {
					return invalidPersistentState("snapshot sources are not globally ordered")
				}
				previousSourceID = source.DeviceID
			}
		}
	}

	refRows, err := query.QueryContext(ctx, `
		SELECT s.snapshot_id, s.revision_id, s.content_hash,
		       r.revision_id, r.record_id, r.author_device_id,
		       r.author_counter, r.vector_json, o.content_hash
		FROM snapshot_revision_refs s
		LEFT JOIN record_revisions r
		  ON r.revision_id = s.revision_id AND r.content_hash = s.content_hash
		LEFT JOIN revision_objects o ON o.content_hash = s.content_hash
		ORDER BY s.snapshot_id, s.revision_id`)
	if err != nil {
		return invalidPersistentState("read snapshot refs")
	}
	for refRows.Next() {
		var snapshotID, revisionID string
		var hashBytes, counterBytes, vectorBody, objectHash []byte
		var matchingRevision, recordID, authorID sql.NullString
		if refRows.Scan(&snapshotID, &revisionID, &hashBytes, &matchingRevision, &recordID, &authorID, &counterBytes, &vectorBody, &objectHash) != nil {
			refRows.Close()
			return invalidPersistentState("invalid snapshot reference")
		}
		snapshot := snapshots[snapshotID]
		counter, counterErr := DecodeUint64(counterBytes)
		var entries []vectorEntry
		if snapshot == nil || validateUUID(revisionID) != nil || len(hashBytes) != 32 || !matchingRevision.Valid || matchingRevision.String != revisionID ||
			!recordID.Valid || validateUUID(recordID.String) != nil || !authorID.Valid || validateUUID(authorID.String) != nil || counterErr != nil ||
			json.Unmarshal(vectorBody, &entries) != nil || !bytes.Equal(objectHash, hashBytes) {
			refRows.Close()
			return invalidPersistentState("invalid snapshot reference")
		}
		vector, vectorErr := validateVector(entries)
		if vectorErr != nil || vector[authorID.String] != counter {
			refRows.Close()
			return invalidPersistentState("invalid snapshot reference vector")
		}
		for deviceID, vectorCounter := range vector {
			maximum, exists := snapshot.sourceCounters[deviceID]
			if !exists || vectorCounter > maximum {
				refRows.Close()
				return invalidPersistentState("snapshot revision exceeds source registry")
			}
		}
		var contentHash [32]byte
		copy(contentHash[:], hashBytes)
		reference := snapshotRevisionReference{revisionID: revisionID, contentHash: contentHash}
		accountSnapshotReference(&snapshot.validationAccount, snapshotID, reference)
		if !snapshot.validationAccount.ok() || snapshot.validationAccount.total > snapshot.metadataBytes {
			refRows.Close()
			return invalidPersistentState("snapshot references exceed declared metadata")
		}
		snapshot.references = append(snapshot.references, reference)
		snapshot.referenceRecordIDs[revisionID] = recordID.String
	}
	if refRows.Err() != nil || refRows.Close() != nil {
		return invalidPersistentState("read snapshot refs")
	}
	var totalMetadata int64
	for snapshotID, snapshot := range snapshots {
		seen := make(map[string]struct{}, len(snapshot.orderedRevisionIDs))
		var previousRecordID, previousRevisionID string
		for _, revisionID := range snapshot.orderedRevisionIDs {
			recordID, exists := snapshot.referenceRecordIDs[revisionID]
			if !exists {
				return invalidPersistentState("snapshot descriptor has no reference")
			}
			if _, duplicate := seen[revisionID]; duplicate || previousRecordID != "" && (recordID < previousRecordID || recordID == previousRecordID && revisionID <= previousRevisionID) {
				return invalidPersistentState("snapshot revisions are not globally ordered")
			}
			seen[revisionID] = struct{}{}
			previousRecordID, previousRevisionID = recordID, revisionID
		}
		if len(seen) != len(snapshot.references) {
			return invalidPersistentState("snapshot references do not match descriptors")
		}
		metadataBytes, ok := snapshotMetadataBytes(snapshotID, snapshot.ownerID, snapshot.requestID, snapshot.createBody, snapshot.pages, snapshot.references)
		if !ok || metadataBytes != snapshot.metadataBytes || metadataBytes > snapshotMetadataLimit || metadataBytes > math.MaxInt64-totalMetadata {
			return invalidPersistentState("snapshot metadata accounting mismatch")
		}
		totalMetadata += metadataBytes
	}
	if totalMetadata > snapshotMetadataLimit {
		return invalidPersistentState("active snapshot metadata exceeds limit")
	}
	return nil
}

func decodeBase64Token(value string) error {
	_, err := decodeBase64(value, 32, 0, 0)
	return err
}
