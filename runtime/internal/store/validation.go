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
	createdAt int64
	// Zero denotes a pre-activation or recovery baseline device. Normal
	// enrollments carry their permanent change cursor in the enrollment row.
	createdCursor   uint64
	revoked         bool
	revokedAt       int64
	baselineRevoked bool
	maxCounter      uint64
	ackCursor       uint64
	maxReturned     uint64
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
	serverCursor, envelopeGeneration, secretGeneration, collectionGeneration, err := validatePersistentRuntime(ctx, query)
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
	historicalCounters, err := validatePersistentRevisions(ctx, query, devices, serverCursor, collectionGeneration)
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
	latestMarkerChanges, err := validatePersistentChanges(ctx, query, devices, serverCursor)
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
	if err := validatePersistentSnapshots(ctx, query, identity, devices, serverCursor, envelopeGeneration, collectionGeneration); err != nil {
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
		SELECT d.device_id, d.token_hash, length(d.scopes_json),
		       CASE WHEN length(d.scopes_json) = ? THEN d.scopes_json END,
		       d.created_at_ms, length(o.origin_kind),
		       CASE WHEN length(o.origin_kind) = 8 THEN o.origin_kind END,
		       o.created_cursor, o.baseline_revoked,
		       d.revoked_at_ms, d.last_sync_at_ms, d.last_ack_cursor,
		       d.max_author_counter, s.max_returned_cursor
		FROM devices d LEFT JOIN device_sync_state s USING (device_id)
		LEFT JOIN device_origins o USING (device_id)
		ORDER BY d.device_id LIMIT 65`, len(wantScopes))
	if err != nil {
		return nil, invalidPersistentState("read device rows")
	}
	defer rows.Close()
	result := make(map[string]validatedDeviceRow)
	var previous string
	for rows.Next() {
		var deviceID string
		var scopesJSON, originKind sql.NullString
		var scopesLength int64
		var originLength, baselineRevoked sql.NullInt64
		var tokenHash, createdCursorBytes, ackBytes, counterBytes, returnedBytes []byte
		var createdAt int64
		var revokedAt, lastSyncAt sql.NullInt64
		if rows.Scan(
			&deviceID, &tokenHash, &scopesLength, &scopesJSON, &createdAt,
			&originLength, &originKind, &createdCursorBytes, &baselineRevoked,
			&revokedAt, &lastSyncAt, &ackBytes, &counterBytes, &returnedBytes,
		) != nil ||
			validateUUID(deviceID) != nil || len(tokenHash) != 32 || !boundedRequiredText(scopesLength, scopesJSON, len(wantScopes)) || scopesJSON.String != string(wantScopes) ||
			!boundedOptionalText(originLength, originKind, 8) || !originLength.Valid || originLength.Int64 != 8 ||
			(originKind.String != "baseline" && originKind.String != "enrolled") || !baselineRevoked.Valid || baselineRevoked.Int64 < 0 || baselineRevoked.Int64 > 1 ||
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
		createdCursor := uint64(0)
		var createdCursorErr error
		if createdCursorBytes != nil {
			createdCursor, createdCursorErr = DecodeUint64(createdCursorBytes)
		}
		if ackErr != nil || counterErr != nil || returnedErr != nil || createdCursorErr != nil ||
			(originKind.String == "enrolled") != (createdCursorBytes != nil) ||
			createdCursorBytes != nil && (createdCursor == 0 || createdCursor > serverCursor) ||
			originKind.String == "enrolled" && baselineRevoked.Int64 != 0 || baselineRevoked.Int64 == 1 && !revokedAt.Valid ||
			ack > returned || returned > serverCursor {
			return nil, invalidPersistentState("invalid device cursor state")
		}
		result[deviceID] = validatedDeviceRow{
			createdAt: createdAt, createdCursor: createdCursor,
			revoked: revokedAt.Valid, baselineRevoked: baselineRevoked.Int64 == 1, maxCounter: counter,
			ackCursor: ack, maxReturned: returned,
		}
		if revokedAt.Valid {
			row := result[deviceID]
			row.revokedAt = revokedAt.Int64
			result[deviceID] = row
		}
		if len(result) > 64 {
			return nil, invalidPersistentState("invalid device registry")
		}
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
	var orphanOriginRows int
	if query.QueryRowContext(ctx, `
		SELECT count(*) FROM device_origins o
		LEFT JOIN devices d USING (device_id) WHERE d.device_id IS NULL`,
	).Scan(&orphanOriginRows) != nil || orphanOriginRows != 0 {
		return nil, invalidPersistentState("orphan device origin")
	}
	return result, nil
}

// validateReadinessDevices inspects at most the protocol maximum plus one
// sentinel row. Full registry and orphan validation is startup-only.
func validateReadinessDevices(ctx context.Context, query schemaQueryer, serverCursor uint64) error {
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	rows, err := query.QueryContext(ctx, `
		SELECT d.device_id, d.token_hash, length(d.scopes_json),
		       CASE WHEN length(d.scopes_json) = ? THEN d.scopes_json END,
		       d.created_at_ms, length(o.origin_kind),
		       CASE WHEN length(o.origin_kind) = 8 THEN o.origin_kind END,
		       o.created_cursor, o.baseline_revoked,
		       d.revoked_at_ms, d.last_sync_at_ms, d.last_ack_cursor,
		       d.max_author_counter, s.max_returned_cursor
		FROM devices d LEFT JOIN device_sync_state s USING (device_id)
		LEFT JOIN device_origins o USING (device_id)
		ORDER BY d.device_id LIMIT 65`, len(wantScopes))
	if err != nil {
		return invalidPersistentState("read readiness device sentinel")
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
		var deviceID string
		var scopesJSON, originKind sql.NullString
		var scopesLength int64
		var originLength, baselineRevoked sql.NullInt64
		var tokenHash, createdCursorBytes, ackBytes, counterBytes, returnedBytes []byte
		var createdAt int64
		var revokedAt, lastSyncAt sql.NullInt64
		if rows.Scan(
			&deviceID, &tokenHash, &scopesLength, &scopesJSON, &createdAt,
			&originLength, &originKind, &createdCursorBytes, &baselineRevoked,
			&revokedAt, &lastSyncAt, &ackBytes, &counterBytes, &returnedBytes,
		) != nil ||
			validateUUID(deviceID) != nil || len(tokenHash) != 32 || !boundedRequiredText(scopesLength, scopesJSON, len(wantScopes)) || scopesJSON.String != string(wantScopes) || validateTimestamp(formatTimestamp(createdAt)) != nil ||
			!boundedOptionalText(originLength, originKind, 8) || !originLength.Valid || originLength.Int64 != 8 ||
			(originKind.String != "baseline" && originKind.String != "enrolled") || !baselineRevoked.Valid || baselineRevoked.Int64 < 0 || baselineRevoked.Int64 > 1 ||
			revokedAt.Valid && (revokedAt.Int64 < createdAt || validateTimestamp(formatTimestamp(revokedAt.Int64)) != nil) ||
			lastSyncAt.Valid && (lastSyncAt.Int64 < createdAt || validateTimestamp(formatTimestamp(lastSyncAt.Int64)) != nil) {
			return invalidPersistentState("invalid readiness device sentinel")
		}
		ack, ackErr := DecodeUint64(ackBytes)
		_, counterErr := DecodeUint64(counterBytes)
		returned, returnedErr := DecodeUint64(returnedBytes)
		createdCursor := uint64(0)
		var createdCursorErr error
		if createdCursorBytes != nil {
			createdCursor, createdCursorErr = DecodeUint64(createdCursorBytes)
		}
		if ackErr != nil || counterErr != nil || returnedErr != nil || createdCursorErr != nil ||
			(originKind.String == "enrolled") != (createdCursorBytes != nil) ||
			createdCursorBytes != nil && (createdCursor == 0 || createdCursor > serverCursor) ||
			originKind.String == "enrolled" && baselineRevoked.Int64 != 0 || baselineRevoked.Int64 == 1 && !revokedAt.Valid ||
			ack > returned || returned > serverCursor {
			return invalidPersistentState("invalid readiness device cursor")
		}
	}
	if rows.Err() != nil || count > 64 {
		return invalidPersistentState("invalid readiness device registry")
	}
	return nil
}

func validatePersistentRuntime(ctx context.Context, query schemaQueryer) (uint64, uint64, uint64, uint64, error) {
	var cursorBytes, floorBytes, envelopeBytes, secretBytes, collectionBytes, uptimeBytes, bootID []byte
	var collectionScanAfter string
	if query.QueryRowContext(ctx, `
		SELECT server_cursor, cursor_floor, envelope_generation,
		       instance_secret_generation, collection_generation,
		       accumulated_uptime_ms, active_boot_id,
		       collection_scan_after_record_id
		FROM runtime_state WHERE singleton = 1`,
	).Scan(&cursorBytes, &floorBytes, &envelopeBytes, &secretBytes, &collectionBytes, &uptimeBytes, &bootID, &collectionScanAfter) != nil {
		return 0, 0, 0, 0, invalidPersistentState("missing runtime state")
	}
	cursor, cursorErr := DecodeUint64(cursorBytes)
	floor, floorErr := DecodeUint64(floorBytes)
	envelope, envelopeErr := DecodeUint64(envelopeBytes)
	secret, secretErr := DecodeUint64(secretBytes)
	collection, collectionErr := DecodeUint64(collectionBytes)
	_, uptimeErr := DecodeUint64(uptimeBytes)
	if cursorErr != nil || floorErr != nil || envelopeErr != nil || secretErr != nil || collectionErr != nil || uptimeErr != nil || floor > cursor || secret == 0 ||
		bootID != nil && len(bootID) != 16 || collectionScanAfter != "" && validateUUID(collectionScanAfter) != nil {
		return 0, 0, 0, 0, invalidPersistentState("invalid runtime state")
	}
	return cursor, envelope, secret, collection, nil
}

func validatePersistentEnvelope(ctx context.Context, query schemaQueryer, identity Identity, runtimeGeneration, secretGeneration uint64) error {
	var generationBytes, body []byte
	var bodyLength int64
	err := query.QueryRowContext(ctx, `
		SELECT generation, length(envelope_json),
		       CASE WHEN length(envelope_json) BETWEEN 1 AND ? THEN envelope_json END
		FROM vault_envelope WHERE singleton = 1`, maxBodyBytes,
	).Scan(&generationBytes, &bodyLength, &body)
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
	if err != nil || !boundedRequiredBytes(bodyLength, body, maxBodyBytes) || decodeStoredCanonical(body, &envelope) != nil {
		return invalidPersistentState("invalid envelope row")
	}
	bodyGeneration, bodySecret, err := validateEnvelope(envelope, identity)
	if err != nil || generation != runtimeGeneration || bodyGeneration != generation || bodySecret != secretGeneration {
		return invalidPersistentState("inconsistent envelope row")
	}
	return nil
}

func validatePersistentChangeOrigins(ctx context.Context, query schemaQueryer, serverCursor, runtimeEnvelopeGeneration uint64, snapshotCuts []uint64) (map[uint64]uint64, error) {
	// Every assigned cursor has one permanent kind origin. Collection removes
	// only the replayable record_revision change row, never its origin, so a
	// later metadata event cannot be relocated onto that freed cursor. This
	// runtime activates from the no-envelope generation-zero state; future
	// recovery activation must persist explicit baseline envelope provenance.
	if len(snapshotCuts) > 8 {
		return nil, invalidPersistentState("too many snapshot cuts")
	}
	generationsAtCut := make(map[uint64]uint64, len(snapshotCuts))
	for _, cut := range snapshotCuts {
		if cut > serverCursor {
			return nil, invalidPersistentState("snapshot cut exceeds server cursor")
		}
		generationsAtCut[cut] = 0
	}
	// Check the reverse ownership direction before streaming origins. In
	// particular, a corrupt durable owner at server_cursor+1 must not survive
	// preflight and then collide with the cursor assigned by an envelope PUT.
	// Ack, floor, barrier, and snapshot-cut cursors are references rather than
	// owners and intentionally do not participate in this projection.
	var orphanChange, orphanDurableOwner int
	if err := query.QueryRowContext(ctx, `
		WITH durable_owners(cursor, kind) AS (
			SELECT change_cursor, 'record_revision' FROM record_revisions
			UNION ALL
			SELECT created_cursor, 'device_changed' FROM device_origins
			WHERE created_cursor IS NOT NULL
			UNION ALL
			SELECT created_cursor, 'device_changed' FROM enrollments
			UNION ALL
			SELECT change_cursor, 'collection_marker' FROM collection_markers
		)
		SELECT
			EXISTS (
				SELECT 1 FROM changes c
				LEFT JOIN change_origins o
				  ON o.cursor = c.cursor AND o.kind = c.kind
				WHERE o.cursor IS NULL
			),
			EXISTS (
				SELECT 1 FROM durable_owners d
				LEFT JOIN change_origins o
				  ON o.cursor = d.cursor AND o.kind = d.kind
				WHERE o.cursor IS NULL
			)`,
	).Scan(&orphanChange, &orphanDurableOwner); err != nil || orphanChange != 0 || orphanDurableOwner != 0 {
		return nil, invalidPersistentState("durable change owner does not match origin")
	}
	rows, err := query.QueryContext(ctx, `
		SELECT o.cursor, o.kind, o.envelope_generation,
		       c.kind, r.revision_id
		FROM change_origins o
		LEFT JOIN changes c ON c.cursor = o.cursor
		LEFT JOIN record_revisions r ON r.change_cursor = o.cursor
		ORDER BY o.cursor`)
	if err != nil {
		return nil, invalidPersistentState("read change origins")
	}
	defer rows.Close()
	previous := uint64(0)
	envelopeGeneration := uint64(0)
	for rows.Next() {
		var cursorBytes, generationBytes []byte
		var kind string
		var changeKind, revisionID sql.NullString
		if rows.Scan(&cursorBytes, &kind, &generationBytes, &changeKind, &revisionID) != nil {
			return nil, invalidPersistentState("invalid change origin")
		}
		cursor, cursorErr := DecodeUint64(cursorBytes)
		if cursorErr != nil || cursor == 0 || previous == math.MaxUint64 || cursor != previous+1 || cursor > serverCursor {
			return nil, invalidPersistentState("change origins are not contiguous")
		}
		switch kind {
		case "record_revision":
			if generationBytes != nil || !revisionID.Valid || changeKind.Valid && changeKind.String != kind {
				return nil, invalidPersistentState("change origin does not match durable owner")
			}
		case "collection_marker", "device_changed":
			if generationBytes != nil || revisionID.Valid || !changeKind.Valid || changeKind.String != kind {
				return nil, invalidPersistentState("change origin does not match durable owner")
			}
		case "envelope_changed":
			generation, generationErr := DecodeUint64(generationBytes)
			if generationErr != nil || envelopeGeneration == math.MaxUint64 || generation != envelopeGeneration+1 || revisionID.Valid ||
				!changeKind.Valid || changeKind.String != kind {
				return nil, invalidPersistentState("invalid envelope change origin")
			}
			envelopeGeneration = generation
			for cut := range generationsAtCut {
				if cursor <= cut {
					generationsAtCut[cut] = generation
				}
			}
		default:
			return nil, invalidPersistentState("invalid change origin kind")
		}
		previous = cursor
	}
	if rows.Err() != nil || rows.Close() != nil {
		return nil, invalidPersistentState("read change origins")
	}
	if previous != serverCursor {
		return nil, invalidPersistentState("change origins do not reach server cursor")
	}
	if envelopeGeneration != runtimeEnvelopeGeneration {
		return nil, invalidPersistentState("envelope generation does not match accepted history")
	}
	return generationsAtCut, nil
}

func validatePersistentRevisionObjects(ctx context.Context, query schemaQueryer) error {
	rows, err := query.QueryContext(ctx, `
		SELECT content_hash, length(revision_json),
		       CASE WHEN length(revision_json) BETWEEN 1 AND ? THEN revision_json END
		FROM revision_objects ORDER BY content_hash`, maxBodyBytes)
	if err != nil {
		return invalidPersistentState("read revision objects")
	}
	defer rows.Close()
	for rows.Next() {
		var hashBytes, body []byte
		var bodyLength int64
		var revision recordRevision
		if rows.Scan(&hashBytes, &bodyLength, &body) != nil || len(hashBytes) != 32 || bodyLength <= 0 || bodyLength > maxBodyBytes || int64(len(body)) != bodyLength {
			return invalidPersistentState("revision object exceeds body limit")
		}
		if decodeStoredCanonical(body, &revision) != nil {
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

func validatePersistentRevisions(ctx context.Context, query schemaQueryer, devices map[string]validatedDeviceRow, serverCursor, collectionGeneration uint64) (map[string]uint64, error) {
	// change_cursor is a unique fixed-width big-endian value. Replaying each
	// record in cursor order reproduces its admission-time frontier, so the
	// 32-sibling cap is sound even when a later resolution sorts after older
	// revision UUIDs.
	rows, err := query.QueryContext(ctx, `
		SELECT r.revision_id, r.record_id, r.author_device_id, r.author_counter,
		       length(r.vector_json),
		       CASE WHEN length(r.vector_json) BETWEEN 1 AND ? THEN r.vector_json END,
		       length(r.collection_witness_authenticator),
		       CASE WHEN length(r.collection_witness_authenticator) = 32 THEN r.collection_witness_authenticator END,
		       r.tombstone,
		       r.content_hash, r.received_at_ms, r.accepted_uptime_ms,
		       r.change_cursor, r.collected_generation, r.retained, r.undominated,
		       length(o.revision_json),
		       CASE WHEN length(o.revision_json) BETWEEN 1 AND ? THEN o.revision_json END,
		       c.cursor, p.kind
		FROM record_revisions r
		LEFT JOIN revision_objects o USING (content_hash)
		LEFT JOIN changes c
		  ON c.cursor = r.change_cursor AND c.kind = 'record_revision'
		 AND c.record_revision_id = r.revision_id
		LEFT JOIN change_origins p ON p.cursor = r.change_cursor
		ORDER BY r.record_id, r.change_cursor`, maxVectorBytes, maxBodyBytes)
	if err != nil {
		return nil, invalidPersistentState("read revision rows")
	}
	defer rows.Close()
	historicalCounters := make(map[string]uint64, len(devices))
	collectionGenerations := make(map[uint64]struct{})
	type frontierItem struct {
		id     string
		vector map[string]uint64
	}
	var currentRecord string
	var historicalFrontier []frontierItem
	var retainedFrontier []frontierItem
	storedHeads := make(map[string]struct{})
	flushFrontier := func() error {
		if len(retainedFrontier) != len(storedHeads) || len(retainedFrontier) > 32 {
			return invalidPersistentState("invalid stored undominated frontier")
		}
		for _, item := range retainedFrontier {
			if _, exists := storedHeads[item.id]; !exists {
				return invalidPersistentState("incorrect stored undominated flag")
			}
		}
		return nil
	}
	advanceFrontier := func(frontier []frontierItem, revisionID string, vector map[string]uint64) ([]frontierItem, error) {
		dominated := false
		next := frontier[:0]
		for _, existing := range frontier {
			if vectorsEqual(existing.vector, vector) {
				return nil, invalidPersistentState("equal-vector revision equivocation")
			}
			if vectorDominates(existing.vector, vector) {
				dominated = true
			}
			if !vectorDominates(vector, existing.vector) {
				next = append(next, existing)
			}
		}
		if !dominated {
			next = append(next, frontierItem{id: revisionID, vector: vector})
			if len(next) > 32 {
				return nil, invalidPersistentState("too many reconstructed undominated revisions")
			}
		}
		return next, nil
	}
	for rows.Next() {
		var revisionID, recordID, authorID string
		var counterBytes, vectorBody, witness, hashBytes, uptimeBytes, cursorBytes, collectedBytes, objectBody, matchingChange []byte
		var vectorLength int64
		var witnessLength sql.NullInt64
		var objectLength sql.NullInt64
		var originKind sql.NullString
		var receivedAt int64
		var tombstone, retained, undominated int
		if rows.Scan(&revisionID, &recordID, &authorID, &counterBytes, &vectorLength, &vectorBody, &witnessLength, &witness, &tombstone, &hashBytes, &receivedAt, &uptimeBytes, &cursorBytes, &collectedBytes, &retained, &undominated, &objectLength, &objectBody, &matchingChange, &originKind) != nil ||
			validateUUID(revisionID) != nil || validateUUID(recordID) != nil || validateUUID(authorID) != nil || len(hashBytes) != 32 ||
			!boundedRequiredBytes(vectorLength, vectorBody, maxVectorBytes) || !boundedOptionalBytes(witnessLength, witness, 32) || witnessLength.Valid && witnessLength.Int64 != 32 ||
			tombstone < 0 || tombstone > 1 || retained < 0 || retained > 1 || undominated < 0 || undominated > 1 ||
			retained == 0 && undominated != 0 ||
			validateTimestamp(formatTimestamp(receivedAt)) != nil {
			return nil, invalidPersistentState("invalid revision row")
		}
		if !originKind.Valid || originKind.String != "record_revision" {
			return nil, invalidPersistentState("revision does not match durable change origin")
		}
		counter, counterErr := DecodeUint64(counterBytes)
		uptime, uptimeErr := DecodeUint64(uptimeBytes)
		cursor, cursorErr := DecodeUint64(cursorBytes)
		collectedGeneration := uint64(0)
		var collectedErr error
		if collectedBytes != nil {
			collectedGeneration, collectedErr = DecodeUint64(collectedBytes)
		}
		_ = uptime
		var entries []vectorEntry
		if json.Unmarshal(vectorBody, &entries) != nil {
			return nil, invalidPersistentState("invalid stored revision vector")
		}
		vector, vectorErr := validateVector(entries)
		canonicalVector, _ := json.Marshal(entries)
		deviceRow, authorExists := devices[authorID]
		if counterErr != nil || uptimeErr != nil || cursorErr != nil || collectedErr != nil || cursor == 0 || cursor > serverCursor ||
			(retained == 0) != (collectedBytes != nil) || collectedBytes != nil && (collectedGeneration == 0 || collectedGeneration > collectionGeneration) || vectorErr != nil ||
			!bytes.Equal(canonicalVector, vectorBody) || vector[authorID] != counter || !authorExists ||
			deviceRow.createdCursor != 0 && deviceRow.createdCursor >= cursor || counter > deviceRow.maxCounter {
			return nil, invalidPersistentState("inconsistent revision row")
		}
		if collectedGeneration != 0 {
			collectionGenerations[collectedGeneration] = struct{}{}
		}
		if currentRecord != recordID {
			if currentRecord != "" {
				if err := flushFrontier(); err != nil {
					return nil, err
				}
			}
			currentRecord = recordID
			historicalFrontier = nil
			retainedFrontier = nil
			clear(storedHeads)
		}
		historicalFrontier, err = advanceFrontier(historicalFrontier, revisionID, vector)
		if err != nil {
			return nil, err
		}
		if retained == 1 {
			retainedFrontier, err = advanceFrontier(retainedFrontier, revisionID, vector)
			if err != nil {
				return nil, err
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
			if !exists || registry.createdCursor != 0 && registry.createdCursor >= cursor || vectorCounter > registry.maxCounter {
				return nil, invalidPersistentState("revision vector exceeds device registry")
			}
		}
		var bodyRevision recordRevision
		objectExists := objectLength.Valid
		if objectExists && (objectLength.Int64 <= 0 || objectLength.Int64 > maxBodyBytes || int64(len(objectBody)) != objectLength.Int64) {
			return nil, invalidPersistentState("revision object exceeds body limit")
		}
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
	if uint64(len(collectionGenerations)) != collectionGeneration {
		return nil, invalidPersistentState("collection generation does not match accepted history")
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
		       r.record_id, length(r.vector_json),
		       CASE WHEN length(r.vector_json) BETWEEN 1 AND ? THEN r.vector_json END
		FROM record_vector_index i
		LEFT JOIN record_revisions r ON r.revision_id = i.revision_id
		ORDER BY i.record_id, i.vector_hash, i.revision_id`, maxVectorBytes)
	if err != nil {
		return invalidPersistentState("read record vector index")
	}
	var previousRecordID string
	var previousVectorHash [32]byte
	havePrevious := false
	for rows.Next() {
		var recordID, revisionID string
		var vectorHash, vectorBody []byte
		var revisionRecord sql.NullString
		var vectorLength sql.NullInt64
		if rows.Scan(&recordID, &vectorHash, &revisionID, &revisionRecord, &vectorLength, &vectorBody) != nil ||
			validateUUID(recordID) != nil || validateUUID(revisionID) != nil || len(vectorHash) != 32 || !revisionRecord.Valid || revisionRecord.String != recordID ||
			!boundedOptionalBytes(vectorLength, vectorBody, maxVectorBytes) || !vectorLength.Valid {
			rows.Close()
			return invalidPersistentState("invalid record vector index")
		}
		computed := sha256.Sum256(vectorBody)
		if !bytes.Equal(computed[:], vectorHash) {
			rows.Close()
			return invalidPersistentState("record vector index hash mismatch")
		}
		if havePrevious && recordID == previousRecordID && bytes.Equal(vectorHash, previousVectorHash[:]) {
			rows.Close()
			return invalidPersistentState("duplicate record vector index")
		}
		previousRecordID = recordID
		copy(previousVectorHash[:], vectorHash)
		havePrevious = true
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
		SELECT m.record_id, m.witness_revision_id,
		       length(m.frontier_json),
		       CASE WHEN length(m.frontier_json) BETWEEN 1 AND ? THEN m.frontier_json END,
		       m.collection_witness_authenticator, m.barrier_cursor,
		       length(m.marker_json),
		       CASE WHEN length(m.marker_json) BETWEEN 1 AND ? THEN m.marker_json END,
		       m.change_cursor, m.received_at_ms,
		       r.record_id, length(r.vector_json),
		       CASE WHEN length(r.vector_json) BETWEEN 1 AND ? THEN r.vector_json END,
		       length(r.collection_witness_authenticator),
		       CASE WHEN length(r.collection_witness_authenticator) = 32 THEN r.collection_witness_authenticator END
		FROM collection_markers m
		LEFT JOIN record_revisions r ON r.revision_id = m.witness_revision_id
		ORDER BY m.record_id`, maxVectorBytes, maxBodyBytes, maxVectorBytes)
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
		var frontierLength, bodyLength int64
		var witnessVectorLength, witnessAuthenticatorLength sql.NullInt64
		var receivedAt int64
		if rows.Scan(&recordID, &witnessID, &frontierLength, &frontierBody, &authenticator, &barrierBytes, &bodyLength, &body, &changeBytes, &receivedAt,
			&witnessRecordID, &witnessVectorLength, &witnessVector, &witnessAuthenticatorLength, &witnessAuthenticator) != nil ||
			!boundedRequiredBytes(frontierLength, frontierBody, maxVectorBytes) || len(authenticator) != 32 ||
			!boundedRequiredBytes(bodyLength, body, maxBodyBytes) || !boundedOptionalBytes(witnessVectorLength, witnessVector, maxVectorBytes) ||
			!boundedOptionalBytes(witnessAuthenticatorLength, witnessAuthenticator, 32) || witnessAuthenticatorLength.Valid && witnessAuthenticatorLength.Int64 != 32 {
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
		       length(g.consumed_enrollment_id),
		       CASE WHEN length(g.consumed_enrollment_id) = 36 THEN g.consumed_enrollment_id END,
		       e.enrollment_id
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
		var consumedLength sql.NullInt64
		if rows.Scan(&grantHash, &bootID, &expiresAt, &consumedLength, &consumedID, &matchedID) != nil || len(grantHash) != 32 || len(bootID) != 16 ||
			!boundedOptionalText(consumedLength, consumedID, maxUUIDBytes) || consumedLength.Valid && consumedLength.Int64 != maxUUIDBytes ||
			validateTimestamp(formatTimestamp(expiresAt)) != nil || consumedID.Valid != matchedID.Valid || consumedID.Valid && consumedID.String != matchedID.String {
			return invalidPersistentState("invalid enrollment grant")
		}
	}
	if rows.Err() != nil {
		return invalidPersistentState("read enrollment grants")
	}
	return nil
}

func validatePersistentChanges(ctx context.Context, query schemaQueryer, devices map[string]validatedDeviceRow, serverCursor uint64) (map[string]validatedMarkerChange, error) {
	var floorBytes []byte
	if query.QueryRowContext(ctx, "SELECT cursor_floor FROM runtime_state WHERE singleton = 1").Scan(&floorBytes) != nil {
		return nil, invalidPersistentState("read cursor floor")
	}
	floor, err := DecodeUint64(floorBytes)
	if err != nil || floor > serverCursor {
		return nil, invalidPersistentState("invalid cursor floor")
	}
	rows, err := query.QueryContext(ctx, `
		SELECT c.cursor, c.kind, c.received_at_ms,
		       length(c.record_revision_id),
		       CASE WHEN length(c.record_revision_id) = 36 THEN c.record_revision_id END,
		       length(c.collection_marker_record_id),
		       CASE WHEN length(c.collection_marker_record_id) = 36 THEN c.collection_marker_record_id END,
		       length(c.collection_marker_json),
		       CASE WHEN length(c.collection_marker_json) BETWEEN 1 AND ? THEN c.collection_marker_json END,
		       length(c.device_changed_id),
		       CASE WHEN length(c.device_changed_id) = 36 THEN c.device_changed_id END,
		       length(c.device_change_kind),
		       CASE WHEN length(c.device_change_kind) BETWEEN 1 AND 8 THEN c.device_change_kind END,
		       r.retained, p.kind
		FROM changes c LEFT JOIN record_revisions r
		  ON r.revision_id = c.record_revision_id
		LEFT JOIN change_origins p ON p.cursor = c.cursor
		ORDER BY c.cursor`, maxBodyBytes)
	if err != nil {
		return nil, invalidPersistentState("read change rows")
	}
	defer rows.Close()
	previous := uint64(0)
	retainedCursor := floor
	latestMarkerChanges := make(map[string]validatedMarkerChange)
	enrollmentChanges := make(map[string]struct{}, len(devices))
	revocationChanges := make(map[string]uint64, len(devices))
	for rows.Next() {
		var cursorBytes, markerBody []byte
		var kind string
		var receivedAt int64
		var revisionID, markerID, changedDeviceID, deviceChangeKind sql.NullString
		var revisionIDLength, markerIDLength, markerBodyLength, changedDeviceIDLength, deviceChangeKindLength sql.NullInt64
		var revisionRetained sql.NullInt64
		var originKind sql.NullString
		if rows.Scan(
			&cursorBytes, &kind, &receivedAt,
			&revisionIDLength, &revisionID, &markerIDLength, &markerID,
			&markerBodyLength, &markerBody,
			&changedDeviceIDLength, &changedDeviceID,
			&deviceChangeKindLength, &deviceChangeKind,
			&revisionRetained, &originKind,
		) != nil ||
			!boundedOptionalText(revisionIDLength, revisionID, maxUUIDBytes) || revisionIDLength.Valid && revisionIDLength.Int64 != maxUUIDBytes ||
			!boundedOptionalText(markerIDLength, markerID, maxUUIDBytes) || markerIDLength.Valid && markerIDLength.Int64 != maxUUIDBytes ||
			!boundedOptionalBytes(markerBodyLength, markerBody, maxBodyBytes) ||
			!boundedOptionalText(changedDeviceIDLength, changedDeviceID, maxUUIDBytes) || changedDeviceIDLength.Valid && changedDeviceIDLength.Int64 != maxUUIDBytes ||
			!boundedOptionalText(deviceChangeKindLength, deviceChangeKind, 8) {
			return nil, invalidPersistentState("invalid change row")
		}
		if !originKind.Valid || originKind.String != kind {
			return nil, invalidPersistentState("change row does not match durable origin")
		}
		cursor, err := DecodeUint64(cursorBytes)
		if err != nil || cursor == 0 || cursor <= previous || cursor > serverCursor || validateTimestamp(formatTimestamp(receivedAt)) != nil {
			return nil, invalidPersistentState("invalid change cursor")
		}
		if cursor > floor {
			if retainedCursor == math.MaxUint64 || cursor != retainedCursor+1 {
				return nil, invalidPersistentState("retained change cursor gap")
			}
			retainedCursor = cursor
		}
		switch kind {
		case "record_revision":
			if !revisionID.Valid || markerID.Valid || markerBody != nil || changedDeviceID.Valid || deviceChangeKind.Valid || validateUUID(revisionID.String) != nil {
				return nil, invalidPersistentState("invalid revision change")
			}
			if !revisionRetained.Valid || revisionRetained.Int64 != 1 {
				return nil, invalidPersistentState("orphan revision change")
			}
		case "collection_marker":
			marker, markerErr := decodeStoredCollectionMarker(markerBody)
			if revisionID.Valid || !markerID.Valid || changedDeviceID.Valid || deviceChangeKind.Valid || markerErr != nil || marker.RecordID != markerID.String {
				return nil, invalidPersistentState("invalid marker change")
			}
			latestMarkerChanges[markerID.String] = validatedMarkerChange{cursor: cursor, body: append([]byte(nil), markerBody...)}
		case "envelope_changed":
			if revisionID.Valid || markerID.Valid || markerBody != nil || changedDeviceID.Valid || deviceChangeKind.Valid {
				return nil, invalidPersistentState("invalid metadata change")
			}
		case "device_changed":
			device, exists := devices[changedDeviceID.String]
			if revisionID.Valid || markerID.Valid || markerBody != nil || !changedDeviceID.Valid || !deviceChangeKind.Valid ||
				validateUUID(changedDeviceID.String) != nil || !exists {
				return nil, invalidPersistentState("invalid device change")
			}
			switch deviceChangeKind.String {
			case "enrolled":
				if cursor != device.createdCursor || receivedAt != device.createdAt {
					return nil, invalidPersistentState("device enrollment history mismatch")
				}
				if _, duplicate := enrollmentChanges[changedDeviceID.String]; duplicate {
					return nil, invalidPersistentState("duplicate device enrollment change")
				}
				enrollmentChanges[changedDeviceID.String] = struct{}{}
			case "revoked":
				if !device.revoked || receivedAt != device.revokedAt || cursor <= device.createdCursor {
					return nil, invalidPersistentState("device revocation history mismatch")
				}
				if _, duplicate := revocationChanges[changedDeviceID.String]; duplicate {
					return nil, invalidPersistentState("duplicate device revocation change")
				}
				revocationChanges[changedDeviceID.String] = cursor
			default:
				return nil, invalidPersistentState("invalid device change kind")
			}
		default:
			return nil, invalidPersistentState("invalid change kind")
		}
		previous = cursor
	}
	if rows.Err() != nil {
		return nil, invalidPersistentState("read change rows")
	}
	if retainedCursor != serverCursor {
		return nil, invalidPersistentState("retained change cursor gap")
	}
	for deviceID, device := range devices {
		_, enrolled := enrollmentChanges[deviceID]
		if enrolled != (device.createdCursor != 0) {
			return nil, invalidPersistentState("device enrollment change mismatch")
		}
		_, revoked := revocationChanges[deviceID]
		expectedRevocation := device.revoked && !device.baselineRevoked
		if revoked != expectedRevocation {
			return nil, invalidPersistentState("device revocation change mismatch")
		}
	}
	return latestMarkerChanges, nil
}

func validatePersistentReceipts(ctx context.Context, query schemaQueryer, identity Identity, devices map[string]validatedDeviceRow) error {
	rows, err := query.QueryContext(ctx, `
		SELECT device_id, length(operation),
		       CASE WHEN length(operation) BETWEEN 1 AND ? THEN operation END,
		       request_id, request_fingerprint, response_status,
		       length(response_json),
		       CASE WHEN length(response_json) BETWEEN 1 AND ? THEN response_json END,
		       created_at_ms, created_uptime_ms
		FROM operation_receipts ORDER BY receipt_sequence`, maxOperationBytes, maxBodyBytes)
	if err != nil {
		return invalidPersistentState("read operation receipts")
	}
	defer rows.Close()
	for rows.Next() {
		var deviceID, requestID string
		var operation sql.NullString
		var fingerprint, body, uptimeBytes []byte
		var operationLength, bodyLength int64
		var status int
		var createdAt int64
		if rows.Scan(&deviceID, &operationLength, &operation, &requestID, &fingerprint, &status, &bodyLength, &body, &createdAt, &uptimeBytes) != nil ||
			validateUUID(deviceID) != nil || validateUUID(requestID) != nil || len(fingerprint) != 32 || !deviceExists(devices, deviceID) ||
			!boundedRequiredText(operationLength, operation, maxOperationBytes) || !boundedRequiredBytes(bodyLength, body, maxBodyBytes) ||
			validateTimestamp(formatTimestamp(createdAt)) != nil || validateStoredOperationResponse(operation.String, status, body, identity) != nil {
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
		       q.created_uptime_ms, r.device_id, length(r.operation),
		       CASE WHEN length(r.operation) BETWEEN 1 AND ? THEN r.operation END,
		       r.created_uptime_ms
		FROM operation_receipt_retention q
		LEFT JOIN operation_receipts r ON r.receipt_sequence = q.receipt_sequence
		ORDER BY q.device_id, q.receipt_class, q.receipt_sequence`, maxOperationBytes)
	if err != nil {
		return invalidPersistentState("read operation receipt retention")
	}
	for rows.Next() {
		var deviceID, receiptClass string
		var sequence int64
		var uptimeBytes, receiptUptime []byte
		var receiptDevice, operation sql.NullString
		var operationLength sql.NullInt64
		if rows.Scan(&deviceID, &receiptClass, &sequence, &uptimeBytes, &receiptDevice, &operationLength, &operation, &receiptUptime) != nil ||
			validateUUID(deviceID) != nil || sequence <= 0 || decodeUint64Error(uptimeBytes) != nil || !receiptDevice.Valid || receiptDevice.String != deviceID ||
			!boundedOptionalText(operationLength, operation, maxOperationBytes) || !operationLength.Valid || !bytes.Equal(uptimeBytes, receiptUptime) || receiptClass != "sync" && receiptClass != "other" ||
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
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	enrollmentRows, err := query.QueryContext(ctx, `
		SELECT enrollment_id, device_id, created_cursor, token_hash, length(scopes_json),
		       CASE WHEN length(scopes_json) = ? THEN scopes_json END,
		       request_fingerprint, length(response_json),
		       CASE WHEN length(response_json) BETWEEN 1 AND ? THEN response_json END,
		       created_status
		FROM enrollments ORDER BY enrollment_id`, len(wantScopes), maxBodyBytes)
	if err != nil {
		return invalidPersistentState("read enrollment rows")
	}
	enrolledDevices := make(map[string]struct{}, len(devices))
	for enrollmentRows.Next() {
		var enrollmentID, deviceID string
		var scopesJSON sql.NullString
		var createdCursorBytes, tokenHash, fingerprint, body []byte
		var scopesLength, bodyLength int64
		var status int
		if enrollmentRows.Scan(&enrollmentID, &deviceID, &createdCursorBytes, &tokenHash, &scopesLength, &scopesJSON, &fingerprint, &bodyLength, &body, &status) != nil ||
			validateUUID(enrollmentID) != nil || !deviceExists(devices, deviceID) || len(tokenHash) != 32 || len(fingerprint) != 32 ||
			!boundedRequiredText(scopesLength, scopesJSON, len(wantScopes)) || scopesJSON.String != string(wantScopes) || !boundedRequiredBytes(bodyLength, body, maxBodyBytes) ||
			status != http.StatusCreated || validateStoredEnrollmentResponse(body, identity, deviceID) != nil {
			enrollmentRows.Close()
			return invalidPersistentState("invalid enrollment row")
		}
		createdCursor, cursorErr := DecodeUint64(createdCursorBytes)
		if cursorErr != nil || createdCursor == 0 || devices[deviceID].createdCursor != createdCursor {
			enrollmentRows.Close()
			return invalidPersistentState("invalid enrollment cursor")
		}
		enrolledDevices[deviceID] = struct{}{}
	}
	if enrollmentRows.Err() != nil || enrollmentRows.Close() != nil {
		return invalidPersistentState("read enrollment rows")
	}
	for deviceID, device := range devices {
		_, enrolled := enrolledDevices[deviceID]
		if enrolled != (device.createdCursor != 0) {
			return invalidPersistentState("device enrollment provenance mismatch")
		}
	}

	rotationRows, err := query.QueryContext(ctx, `
		SELECT rotation_id, device_id, old_token_hash, new_token_hash,
		       request_fingerprint, length(response_json),
		       CASE WHEN length(response_json) BETWEEN 1 AND ? THEN response_json END,
		       created_at_ms
		FROM token_rotations ORDER BY rotation_id`, maxBodyBytes)
	if err != nil {
		return invalidPersistentState("read rotation rows")
	}
	for rotationRows.Next() {
		var rotationID, deviceID string
		var oldHash, newHash, fingerprint, body []byte
		var bodyLength int64
		var createdAt int64
		var response device
		if rotationRows.Scan(&rotationID, &deviceID, &oldHash, &newHash, &fingerprint, &bodyLength, &body, &createdAt) != nil ||
			validateUUID(rotationID) != nil || !deviceExists(devices, deviceID) || len(oldHash) != 32 || len(newHash) != 32 || len(fingerprint) != 32 ||
			!boundedRequiredBytes(bodyLength, body, maxBodyBytes) || validateTimestamp(formatTimestamp(createdAt)) != nil ||
			decodeStoredCanonical(body, &response) != nil || validateDevice(response) != nil || response.DeviceID != deviceID {
			rotationRows.Close()
			return invalidPersistentState("invalid token rotation row")
		}
	}
	if rotationRows.Err() != nil || rotationRows.Close() != nil {
		return invalidPersistentState("read rotation rows")
	}

	selfRows, err := query.QueryContext(ctx, `
		SELECT device_id, request_id, body_fingerprint, pre_revocation_token_hash,
		       response_status, length(response_headers_json),
		       CASE WHEN length(response_headers_json) BETWEEN 1 AND ? THEN response_headers_json END,
		       length(response_json),
		       CASE WHEN length(response_json) BETWEEN 1 AND ? THEN response_json END
		FROM self_revocation_receipts ORDER BY device_id`, maxBodyBytes, maxBodyBytes)
	if err != nil {
		return invalidPersistentState("read self-revocation receipts")
	}
	for selfRows.Next() {
		var deviceID, requestID string
		var fingerprint, tokenHash, headersBody, body []byte
		var headersLength, bodyLength int64
		var status int
		var headers []api.Header
		var response device
		if selfRows.Scan(&deviceID, &requestID, &fingerprint, &tokenHash, &status, &headersLength, &headersBody, &bodyLength, &body) != nil ||
			validateUUID(requestID) != nil || len(fingerprint) != 32 || len(tokenHash) != 32 || !devices[deviceID].revoked || status != http.StatusOK ||
			!boundedRequiredBytes(headersLength, headersBody, maxBodyBytes) || !boundedRequiredBytes(bodyLength, body, maxBodyBytes) ||
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

func validatePersistentSnapshots(ctx context.Context, query schemaQueryer, identity Identity, devices map[string]validatedDeviceRow, serverCursor, envelopeGeneration, collectionGeneration uint64) error {
	type validatedSnapshot struct {
		ownerID              string
		requestID            string
		cutCursor            uint64
		envelopeGeneration   uint64
		collectionGeneration uint64
		expiresAt            int64
		metadataBytes        int64
		createBodyLength     int64
		createBody           []byte
		create               snapshotCreateResponse
		pages                []storedSnapshotPage
		pageBodyLengths      []int64
		references           []snapshotRevisionReference
		referenceRecordIDs   map[string]string
		sourceCounters       map[string]uint64
		markerBodies         map[string][]byte
		orderedRevisionIDs   []string
		validationAccount    snapshotMetadataAccounting
	}
	snapshots := make(map[string]*validatedSnapshot)
	snapshotCuts := make([]uint64, 0, 8)
	ownerCounts := make(map[string]int)
	declaredMetadata := int64(0)
	rows, err := query.QueryContext(ctx, `
		SELECT snapshot_id, owner_device_id, request_id, request_fingerprint,
		       cut_cursor, envelope_generation, collection_generation,
		       expires_at_ms, metadata_bytes, length(create_response_json)
		FROM snapshots ORDER BY snapshot_id`)
	if err != nil {
		return invalidPersistentState("read snapshots")
	}
	for rows.Next() {
		var snapshotID, ownerID, requestID string
		var fingerprint, cutBytes, generationBytes, snapshotCollectionBytes []byte
		var expiresAt, metadataBytes, createBodyLength int64
		if rows.Scan(&snapshotID, &ownerID, &requestID, &fingerprint, &cutBytes, &generationBytes, &snapshotCollectionBytes, &expiresAt, &metadataBytes, &createBodyLength) != nil ||
			validateUUID(snapshotID) != nil || validateUUID(requestID) != nil || !deviceExists(devices, ownerID) || len(fingerprint) != 32 ||
			metadataBytes < 0 || metadataBytes > snapshotMetadataLimit || len(snapshots) >= 8 {
			rows.Close()
			return invalidPersistentState("invalid snapshot row")
		}
		cut, cutErr := DecodeUint64(cutBytes)
		generation, generationErr := DecodeUint64(generationBytes)
		snapshotCollectionGeneration, snapshotCollectionErr := DecodeUint64(snapshotCollectionBytes)
		owner := devices[ownerID]
		if cutErr != nil || generationErr != nil || snapshotCollectionErr != nil ||
			cut > serverCursor || snapshotCollectionGeneration > collectionGeneration || owner.createdCursor != 0 && owner.createdCursor > cut {
			rows.Close()
			return invalidPersistentState("inconsistent snapshot row")
		}
		if createBodyLength <= 0 || createBodyLength > metadataBytes || createBodyLength > maxBodyBytes {
			rows.Close()
			return invalidPersistentState("snapshot create response exceeds declared metadata")
		}
		if metadataBytes > snapshotMetadataLimit-declaredMetadata {
			rows.Close()
			return invalidPersistentState("active snapshot metadata exceeds limit")
		}
		validationAccount := snapshotMetadataAccounting{}
		accountSnapshotBase(&validationAccount, snapshotID, ownerID, requestID, nil)
		validationAccount.addLength64(createBodyLength)
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
			ownerID: ownerID, requestID: requestID, cutCursor: cut, envelopeGeneration: generation,
			collectionGeneration: snapshotCollectionGeneration,
			expiresAt:            expiresAt, metadataBytes: metadataBytes, createBodyLength: createBodyLength,
			referenceRecordIDs: make(map[string]string),
			sourceCounters:     make(map[string]uint64),
			markerBodies:       make(map[string][]byte), validationAccount: validationAccount,
		}
		snapshotCuts = append(snapshotCuts, cut)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return invalidPersistentState("read snapshots")
	}
	generationsAtCut, err := validatePersistentChangeOrigins(ctx, query, serverCursor, envelopeGeneration, snapshotCuts)
	if err != nil {
		return err
	}
	for _, snapshot := range snapshots {
		if snapshot.envelopeGeneration != generationsAtCut[snapshot.cutCursor] {
			return invalidPersistentState("snapshot envelope generation does not match cut")
		}
	}

	createRows, err := query.QueryContext(ctx, `
		SELECT snapshot_id, length(create_response_json),
		       CASE WHEN length(create_response_json) BETWEEN 1 AND ? THEN create_response_json END
		FROM snapshots ORDER BY snapshot_id`, maxBodyBytes)
	if err != nil {
		return invalidPersistentState("read snapshot create responses")
	}
	createCount := 0
	for createRows.Next() {
		var snapshotID string
		var bodyLength int64
		var body []byte
		if createRows.Scan(&snapshotID, &bodyLength, &body) != nil {
			createRows.Close()
			return invalidPersistentState("invalid snapshot create response")
		}
		snapshot := snapshots[snapshotID]
		if snapshot == nil || bodyLength != snapshot.createBodyLength || !boundedRequiredBytes(bodyLength, body, maxBodyBytes) {
			createRows.Close()
			return invalidPersistentState("snapshot create response exceeds declared metadata")
		}
		var create snapshotCreateResponse
		if validateStoredSnapshotCreateResponse(body, identity, snapshotID, snapshot.ownerID, snapshot.cutCursor, snapshot.envelopeGeneration, snapshot.expiresAt) != nil ||
			decodeStoredCanonical(body, &create) != nil {
			createRows.Close()
			return invalidPersistentState("inconsistent snapshot row")
		}
		snapshot.createBody = body
		snapshot.create = create
		createCount++
	}
	if createRows.Err() != nil || createRows.Close() != nil || createCount != len(snapshots) {
		return invalidPersistentState("read snapshot create responses")
	}

	pageRows, err := query.QueryContext(ctx, `
		SELECT snapshot_id, page_index, page_token, length(response_json)
		FROM snapshot_pages ORDER BY snapshot_id, page_index`)
	if err != nil {
		return invalidPersistentState("read snapshot pages")
	}
	for pageRows.Next() {
		var snapshotID, token string
		var index int64
		var bodyLength int64
		if pageRows.Scan(&snapshotID, &index, &token, &bodyLength) != nil {
			pageRows.Close()
			return invalidPersistentState("invalid snapshot page")
		}
		snapshot := snapshots[snapshotID]
		if snapshot == nil || index < 0 || index != int64(len(snapshot.pages)) || decodeBase64Token(token) != nil {
			pageRows.Close()
			return invalidPersistentState("invalid snapshot page")
		}
		if bodyLength <= 0 || bodyLength > snapshot.metadataBytes || bodyLength > maxBodyBytes {
			pageRows.Close()
			return invalidPersistentState("snapshot page response exceeds declared metadata")
		}
		accountSnapshotPage(&snapshot.validationAccount, snapshotID, len(snapshot.pages), token, nil)
		snapshot.validationAccount.addLength64(bodyLength)
		if !snapshot.validationAccount.ok() || snapshot.validationAccount.total > snapshot.metadataBytes {
			pageRows.Close()
			return invalidPersistentState("snapshot pages exceed declared metadata")
		}
		snapshot.pages = append(snapshot.pages, storedSnapshotPage{token: token})
		snapshot.pageBodyLengths = append(snapshot.pageBodyLengths, bodyLength)
	}
	if pageRows.Err() != nil || pageRows.Close() != nil {
		return invalidPersistentState("read snapshot pages")
	}

	pageBodyRows, err := query.QueryContext(ctx, `
		SELECT snapshot_id, page_index, length(response_json),
		       CASE WHEN length(response_json) BETWEEN 1 AND ? THEN response_json END
		FROM snapshot_pages ORDER BY snapshot_id, page_index`, maxBodyBytes)
	if err != nil {
		return invalidPersistentState("read snapshot page responses")
	}
	pageBodyCount := 0
	for pageBodyRows.Next() {
		var snapshotID string
		var index, bodyLength int64
		var body []byte
		if pageBodyRows.Scan(&snapshotID, &index, &bodyLength, &body) != nil {
			pageBodyRows.Close()
			return invalidPersistentState("invalid snapshot page response")
		}
		snapshot := snapshots[snapshotID]
		if snapshot == nil || index < 0 || index >= int64(len(snapshot.pages)) || snapshot.pageBodyLengths[index] != bodyLength ||
			!boundedRequiredBytes(bodyLength, body, maxBodyBytes) {
			pageBodyRows.Close()
			return invalidPersistentState("snapshot page response exceeds declared metadata")
		}
		var descriptor snapshotPageDescriptor
		if decodeStoredSnapshotPageDescriptor(body, &descriptor) != nil {
			pageBodyRows.Close()
			return invalidPersistentState("invalid snapshot page")
		}
		snapshot.pages[index].body = body
		snapshot.pages[index].descriptor = descriptor
		pageBodyCount++
	}
	if pageBodyRows.Err() != nil || pageBodyRows.Close() != nil {
		return invalidPersistentState("read snapshot page responses")
	}
	pageCount := 0
	for _, snapshot := range snapshots {
		pageCount += len(snapshot.pages)
	}
	if pageBodyCount != pageCount {
		return invalidPersistentState("snapshot page response count mismatch")
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
				frontier, barrier, _, _ := validateCollectionMarker(marker)
				if barrier > snapshot.cutCursor {
					return invalidPersistentState("snapshot marker barrier exceeds cut")
				}
				markerBody, err := marshalJSON(marker)
				if err != nil {
					return invalidPersistentState("invalid snapshot marker")
				}
				snapshot.markerBodies[marker.RecordID] = markerBody
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
		       r.author_counter, length(r.vector_json),
		       CASE WHEN length(r.vector_json) BETWEEN 1 AND ? THEN r.vector_json END,
		       r.collected_generation, r.retained, r.change_cursor,
		       o.content_hash
		FROM snapshot_revision_refs s
		LEFT JOIN record_revisions r
		  ON r.revision_id = s.revision_id AND r.content_hash = s.content_hash
		LEFT JOIN revision_objects o ON o.content_hash = s.content_hash
		ORDER BY s.snapshot_id, s.revision_id`, maxVectorBytes)
	if err != nil {
		return invalidPersistentState("read snapshot refs")
	}
	for refRows.Next() {
		var snapshotID, revisionID string
		var hashBytes, counterBytes, vectorBody, collectedBytes, changeCursorBytes, objectHash []byte
		var matchingRevision, recordID, authorID sql.NullString
		var vectorLength sql.NullInt64
		var retained int
		if refRows.Scan(
			&snapshotID, &revisionID, &hashBytes, &matchingRevision, &recordID, &authorID,
			&counterBytes, &vectorLength, &vectorBody, &collectedBytes, &retained,
			&changeCursorBytes, &objectHash,
		) != nil {
			refRows.Close()
			return invalidPersistentState("invalid snapshot reference")
		}
		snapshot := snapshots[snapshotID]
		counter, counterErr := DecodeUint64(counterBytes)
		collectedGeneration := uint64(0)
		var collectedErr error
		if collectedBytes != nil {
			collectedGeneration, collectedErr = DecodeUint64(collectedBytes)
		}
		var entries []vectorEntry
		if snapshot == nil || validateUUID(revisionID) != nil || len(hashBytes) != 32 || !matchingRevision.Valid || matchingRevision.String != revisionID ||
			!recordID.Valid || validateUUID(recordID.String) != nil || !authorID.Valid || validateUUID(authorID.String) != nil || counterErr != nil ||
			collectedErr != nil || retained < 0 || retained > 1 || (retained == 0) != (collectedBytes != nil) ||
			collectedBytes != nil && (collectedGeneration == 0 || collectedGeneration > collectionGeneration) ||
			!boundedOptionalBytes(vectorLength, vectorBody, maxVectorBytes) || !vectorLength.Valid || json.Unmarshal(vectorBody, &entries) != nil || !bytes.Equal(objectHash, hashBytes) {
			refRows.Close()
			return invalidPersistentState("invalid snapshot reference")
		}
		if collectedGeneration != 0 && collectedGeneration <= snapshot.collectionGeneration {
			refRows.Close()
			return invalidPersistentState("snapshot reference was collected before snapshot")
		}
		changeCursor, changeCursorErr := DecodeUint64(changeCursorBytes)
		if changeCursorErr != nil || changeCursor > snapshot.cutCursor {
			refRows.Close()
			return invalidPersistentState("snapshot reference accepted after cut")
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
	type snapshotCutFrontierItem struct {
		id                  string
		vector              map[string]uint64
		tombstone           bool
		collectedGeneration uint64
	}
	for _, snapshot := range snapshots {
		encodedCut := EncodeUint64(snapshot.cutCursor)
		referencesByRecord := make(map[string]map[string]struct{})
		for revisionID, recordID := range snapshot.referenceRecordIDs {
			if referencesByRecord[recordID] == nil {
				referencesByRecord[recordID] = make(map[string]struct{})
			}
			referencesByRecord[recordID][revisionID] = struct{}{}
		}
		cutRows, err := query.QueryContext(ctx, `
			SELECT revision_id, record_id, author_device_id, author_counter,
			       length(vector_json),
			       CASE WHEN length(vector_json) BETWEEN 1 AND ? THEN vector_json END,
			       tombstone, collected_generation, retained, change_cursor
			FROM record_revisions
			WHERE change_cursor <= ?
			ORDER BY record_id, change_cursor`, maxVectorBytes, encodedCut[:])
		if err != nil {
			return invalidPersistentState("read snapshot cut revisions")
		}
		authorMaxima := make(map[string]uint64, len(devices))
		currentRecord := ""
		var frontier []snapshotCutFrontierItem
		flushFrontier := func() error {
			if currentRecord == "" {
				return nil
			}
			references := referencesByRecord[currentRecord]
			heads := make(map[string]struct{}, len(frontier))
			for _, item := range frontier {
				heads[item.id] = struct{}{}
			}
			for revisionID := range references {
				if _, exists := heads[revisionID]; !exists {
					return invalidPersistentState("snapshot reference was dominated at cut")
				}
			}
			for _, item := range frontier {
				if _, exists := references[item.id]; exists {
					continue
				}
				markerBody, hasMarker := snapshot.markerBodies[currentRecord]
				// Collection does not allocate a second cursor when it later
				// removes an exact tombstone witness. Its durable collection
				// generation proves whether that removal preceded this snapshot.
				if item.tombstone && item.collectedGeneration != 0 &&
					item.collectedGeneration <= snapshot.collectionGeneration && hasMarker {
					marker, markerErr := decodeStoredCollectionMarker(markerBody)
					markerFrontier, _, _, frontierErr := validateCollectionMarker(marker)
					if markerErr == nil && frontierErr == nil && marker.WitnessRevisionID == item.id && vectorsEqual(markerFrontier, item.vector) {
						continue
					}
				}
				return invalidPersistentState("snapshot frontier head is missing at cut")
			}
			delete(referencesByRecord, currentRecord)
			return nil
		}
		for cutRows.Next() {
			var revisionID, recordID, authorID string
			var counterBytes, vectorBody, collectedBytes, cursorBytes []byte
			var vectorLength int64
			var tombstone, retained int
			if cutRows.Scan(&revisionID, &recordID, &authorID, &counterBytes, &vectorLength, &vectorBody, &tombstone, &collectedBytes, &retained, &cursorBytes) != nil ||
				validateUUID(revisionID) != nil || validateUUID(recordID) != nil || validateUUID(authorID) != nil ||
				!boundedRequiredBytes(vectorLength, vectorBody, maxVectorBytes) || tombstone < 0 || tombstone > 1 || retained < 0 || retained > 1 {
				cutRows.Close()
				return invalidPersistentState("invalid snapshot cut revision")
			}
			counter, counterErr := DecodeUint64(counterBytes)
			cursor, cursorErr := DecodeUint64(cursorBytes)
			collectedGeneration := uint64(0)
			var collectedErr error
			if collectedBytes != nil {
				collectedGeneration, collectedErr = DecodeUint64(collectedBytes)
			}
			var entries []vectorEntry
			if counterErr != nil || cursorErr != nil || collectedErr != nil || cursor == 0 || cursor > snapshot.cutCursor ||
				(retained == 0) != (collectedBytes != nil) || json.Unmarshal(vectorBody, &entries) != nil {
				cutRows.Close()
				return invalidPersistentState("invalid snapshot cut revision")
			}
			vector, vectorErr := validateVector(entries)
			if _, exists := devices[authorID]; !exists || vectorErr != nil || vector[authorID] != counter {
				cutRows.Close()
				return invalidPersistentState("invalid snapshot cut revision vector")
			}
			if currentRecord != recordID {
				if err := flushFrontier(); err != nil {
					cutRows.Close()
					return err
				}
				currentRecord = recordID
				frontier = nil
			}
			dominated := false
			next := frontier[:0]
			for _, existing := range frontier {
				if vectorsEqual(existing.vector, vector) {
					cutRows.Close()
					return invalidPersistentState("equal-vector revision equivocation at snapshot cut")
				}
				if vectorDominates(existing.vector, vector) {
					dominated = true
				}
				if !vectorDominates(vector, existing.vector) {
					next = append(next, existing)
				}
			}
			if !dominated {
				next = append(next, snapshotCutFrontierItem{
					id: revisionID, vector: vector, tombstone: tombstone == 1, collectedGeneration: collectedGeneration,
				})
				if len(next) > 32 {
					cutRows.Close()
					return invalidPersistentState("snapshot cut has too many undominated revisions")
				}
			}
			frontier = next
			if counter > authorMaxima[authorID] {
				authorMaxima[authorID] = counter
			}
		}
		if cutRows.Err() != nil {
			cutRows.Close()
			return invalidPersistentState("read snapshot cut revisions")
		}
		if err := flushFrontier(); err != nil {
			cutRows.Close()
			return err
		}
		if cutRows.Close() != nil {
			return invalidPersistentState("read snapshot cut revisions")
		}
		if len(referencesByRecord) != 0 {
			return invalidPersistentState("snapshot reference was not accepted at cut")
		}
		expectedSources := 0
		for deviceID, device := range devices {
			if device.createdCursor != 0 && device.createdCursor > snapshot.cutCursor {
				continue
			}
			expectedSources++
			counter, exists := snapshot.sourceCounters[deviceID]
			if !exists || counter != authorMaxima[deviceID] {
				return invalidPersistentState("snapshot source registry does not match cut")
			}
		}
		if len(snapshot.sourceCounters) != expectedSources {
			return invalidPersistentState("snapshot source registry does not match cut")
		}

		remainingMarkers := make(map[string][]byte, len(snapshot.markerBodies))
		for recordID, body := range snapshot.markerBodies {
			remainingMarkers[recordID] = body
		}
		markerRows, err := query.QueryContext(ctx, `
			SELECT collection_marker_record_id, cursor, length(collection_marker_json),
			       CASE WHEN length(collection_marker_json) BETWEEN 1 AND ? THEN collection_marker_json END
			FROM changes
			WHERE kind = 'collection_marker' AND cursor <= ?
			ORDER BY collection_marker_record_id, cursor`, maxBodyBytes, encodedCut[:])
		if err != nil {
			return invalidPersistentState("read snapshot cut markers")
		}
		currentMarkerRecord := ""
		var latestMarkerBody []byte
		flushMarker := func() error {
			if currentMarkerRecord == "" {
				return nil
			}
			descriptorBody, exists := remainingMarkers[currentMarkerRecord]
			if !exists || !bytes.Equal(descriptorBody, latestMarkerBody) {
				return invalidPersistentState("snapshot marker does not match cut")
			}
			delete(remainingMarkers, currentMarkerRecord)
			return nil
		}
		for markerRows.Next() {
			var recordID string
			var cursorBytes, body []byte
			var bodyLength int64
			if markerRows.Scan(&recordID, &cursorBytes, &bodyLength, &body) != nil || validateUUID(recordID) != nil ||
				!boundedRequiredBytes(bodyLength, body, maxBodyBytes) {
				markerRows.Close()
				return invalidPersistentState("invalid snapshot cut marker")
			}
			cursor, cursorErr := DecodeUint64(cursorBytes)
			marker, markerErr := decodeStoredCollectionMarker(body)
			if cursorErr != nil || cursor == 0 || cursor > snapshot.cutCursor || markerErr != nil || marker.RecordID != recordID {
				markerRows.Close()
				return invalidPersistentState("invalid snapshot cut marker")
			}
			if currentMarkerRecord != recordID {
				if err := flushMarker(); err != nil {
					markerRows.Close()
					return err
				}
				currentMarkerRecord = recordID
			}
			latestMarkerBody = append(latestMarkerBody[:0], body...)
		}
		if markerRows.Err() != nil {
			markerRows.Close()
			return invalidPersistentState("read snapshot cut markers")
		}
		if err := flushMarker(); err != nil {
			markerRows.Close()
			return err
		}
		if markerRows.Close() != nil {
			return invalidPersistentState("read snapshot cut markers")
		}
		if len(remainingMarkers) != 0 {
			return invalidPersistentState("snapshot marker does not match cut")
		}
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
