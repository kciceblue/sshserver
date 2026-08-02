package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const createInstanceMetadataV1 = `CREATE TABLE instance_metadata (
			singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
			instance_id TEXT NOT NULL CHECK (length(instance_id) = 36),
			vault_id TEXT NOT NULL CHECK (length(vault_id) = 36),
			protocol_major TEXT NOT NULL CHECK (protocol_major = '1'),
			storage_schema TEXT NOT NULL CHECK (storage_schema = '1'),
			CHECK (instance_id <> vault_id)
		) STRICT`

const createDevicesV1 = `CREATE TABLE devices (
			device_id TEXT PRIMARY KEY CHECK (length(device_id) = 36),
			token_hash BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
			scopes_json TEXT NOT NULL,
			created_at_ms INTEGER NOT NULL,
			revoked_at_ms INTEGER,
			last_sync_at_ms INTEGER,
			last_ack_cursor BLOB NOT NULL CHECK (length(last_ack_cursor) = 8),
			max_author_counter BLOB NOT NULL CHECK (length(max_author_counter) = 8),
			CHECK (revoked_at_ms IS NULL OR revoked_at_ms >= created_at_ms),
			CHECK (last_sync_at_ms IS NULL OR last_sync_at_ms >= created_at_ms)
		) STRICT`

const createRuntimeStateV1 = `CREATE TABLE runtime_state (
			singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
			server_cursor BLOB NOT NULL CHECK (length(server_cursor) = 8),
			cursor_floor BLOB NOT NULL CHECK (length(cursor_floor) = 8),
			envelope_generation BLOB NOT NULL CHECK (length(envelope_generation) = 8),
			instance_secret_generation BLOB NOT NULL CHECK (length(instance_secret_generation) = 8),
			accumulated_uptime_ms BLOB NOT NULL CHECK (length(accumulated_uptime_ms) = 8),
			active_boot_id BLOB CHECK (active_boot_id IS NULL OR length(active_boot_id) = 16),
			collection_scan_after_record_id TEXT NOT NULL
				CHECK (collection_scan_after_record_id = '' OR length(collection_scan_after_record_id) = 36)
		) STRICT`

const createDeviceSyncStateV1 = `CREATE TABLE device_sync_state (
			device_id TEXT PRIMARY KEY REFERENCES devices(device_id),
			max_returned_cursor BLOB NOT NULL CHECK (length(max_returned_cursor) = 8)
		) STRICT`

const createEnrollmentGrantsV1 = `CREATE TABLE enrollment_grants (
			grant_hash BLOB PRIMARY KEY CHECK (length(grant_hash) = 32),
			boot_id BLOB NOT NULL CHECK (length(boot_id) = 16),
			expires_at_ms INTEGER NOT NULL,
			consumed_enrollment_id TEXT
		) STRICT`

const createEnrollmentsV1 = `CREATE TABLE enrollments (
			enrollment_id TEXT PRIMARY KEY CHECK (length(enrollment_id) = 36),
			device_id TEXT NOT NULL UNIQUE REFERENCES devices(device_id),
			created_cursor BLOB NOT NULL UNIQUE CHECK (length(created_cursor) = 8),
			token_hash BLOB NOT NULL CHECK (length(token_hash) = 32),
			scopes_json TEXT NOT NULL,
			request_fingerprint BLOB NOT NULL CHECK (length(request_fingerprint) = 32),
			response_json BLOB NOT NULL,
			created_status INTEGER NOT NULL CHECK (created_status = 201)
		) STRICT`

const createVaultEnvelopeV1 = `CREATE TABLE vault_envelope (
			singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
			generation BLOB NOT NULL CHECK (length(generation) = 8),
			envelope_json BLOB NOT NULL
		) STRICT`

const createRevisionObjectsV1 = `CREATE TABLE revision_objects (
			content_hash BLOB PRIMARY KEY CHECK (length(content_hash) = 32),
			revision_json BLOB NOT NULL CHECK (length(revision_json) > 0)
		) STRICT`

const createRecordRevisionsV1 = `CREATE TABLE record_revisions (
			revision_id TEXT PRIMARY KEY CHECK (length(revision_id) = 36),
			record_id TEXT NOT NULL CHECK (length(record_id) = 36),
			author_device_id TEXT NOT NULL CHECK (length(author_device_id) = 36),
			author_counter BLOB NOT NULL CHECK (length(author_counter) = 8),
			vector_json BLOB NOT NULL,
			collection_witness_authenticator BLOB,
			tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
			content_hash BLOB NOT NULL CHECK (length(content_hash) = 32),
			received_at_ms INTEGER NOT NULL,
			accepted_uptime_ms BLOB NOT NULL CHECK (length(accepted_uptime_ms) = 8),
			change_cursor BLOB NOT NULL UNIQUE CHECK (length(change_cursor) = 8),
			retained INTEGER NOT NULL CHECK (retained IN (0, 1)),
			undominated INTEGER NOT NULL CHECK (undominated IN (0, 1)),
			UNIQUE (author_device_id, author_counter),
			CHECK (retained = 1 OR undominated = 0)
		) STRICT`

const createCollectionRecordsV1 = `CREATE TABLE collection_records (
			record_id TEXT PRIMARY KEY CHECK (length(record_id) = 36),
			barrier_cursor BLOB NOT NULL CHECK (length(barrier_cursor) = 8)
		) STRICT`

const createRecordHeadsV1 = `CREATE TABLE record_heads (
			record_id TEXT NOT NULL CHECK (length(record_id) = 36),
			revision_id TEXT NOT NULL CHECK (length(revision_id) = 36),
			PRIMARY KEY (record_id, revision_id)
		) STRICT`

const createRecordVectorIndexV1 = `CREATE TABLE record_vector_index (
			record_id TEXT NOT NULL CHECK (length(record_id) = 36),
			vector_hash BLOB NOT NULL CHECK (length(vector_hash) = 32),
			revision_id TEXT NOT NULL CHECK (length(revision_id) = 36),
			PRIMARY KEY (record_id, vector_hash, revision_id)
		) STRICT`

const createCollectionCandidatesV1 = `CREATE TABLE collection_candidates (
			record_id TEXT NOT NULL CHECK (length(record_id) = 36),
			accepted_uptime_ms BLOB NOT NULL CHECK (length(accepted_uptime_ms) = 8),
			revision_id TEXT NOT NULL CHECK (length(revision_id) = 36),
			PRIMARY KEY (record_id, accepted_uptime_ms, revision_id)
		) STRICT`

const createCollectionMarkersV1 = `CREATE TABLE collection_markers (
			record_id TEXT PRIMARY KEY CHECK (length(record_id) = 36),
			witness_revision_id TEXT NOT NULL CHECK (length(witness_revision_id) = 36),
			frontier_json BLOB NOT NULL,
			collection_witness_authenticator BLOB NOT NULL CHECK (length(collection_witness_authenticator) = 32),
			barrier_cursor BLOB NOT NULL CHECK (length(barrier_cursor) = 8),
			marker_json BLOB NOT NULL,
			change_cursor BLOB NOT NULL UNIQUE CHECK (length(change_cursor) = 8),
			received_at_ms INTEGER NOT NULL
		) STRICT`

const createChangesV1 = `CREATE TABLE changes (
			cursor BLOB PRIMARY KEY CHECK (length(cursor) = 8),
			kind TEXT NOT NULL CHECK (kind IN ('record_revision', 'collection_marker', 'envelope_changed', 'device_changed')),
			received_at_ms INTEGER NOT NULL,
			record_revision_id TEXT,
			collection_marker_record_id TEXT,
			collection_marker_json BLOB,
			device_changed_id TEXT,
			device_change_kind TEXT CHECK (device_change_kind IN ('enrolled', 'revoked')),
			CHECK ((kind = 'record_revision') = (record_revision_id IS NOT NULL)),
			CHECK ((kind = 'collection_marker') = (collection_marker_record_id IS NOT NULL)),
			CHECK ((kind = 'collection_marker') = (collection_marker_json IS NOT NULL)),
			CHECK ((kind = 'device_changed') = (device_changed_id IS NOT NULL)),
			CHECK ((kind = 'device_changed') = (device_change_kind IS NOT NULL)),
			CHECK (device_changed_id IS NULL OR length(device_changed_id) = 36)
		) STRICT`

const createOperationReceiptsV1 = `CREATE TABLE operation_receipts (
			receipt_sequence INTEGER PRIMARY KEY,
			device_id TEXT NOT NULL CHECK (length(device_id) = 36),
			operation TEXT NOT NULL,
			request_id TEXT NOT NULL CHECK (length(request_id) = 36),
			request_fingerprint BLOB NOT NULL CHECK (length(request_fingerprint) = 32),
			response_status INTEGER NOT NULL CHECK (response_status = 200),
			response_json BLOB NOT NULL,
			created_at_ms INTEGER NOT NULL,
			created_uptime_ms BLOB NOT NULL CHECK (length(created_uptime_ms) = 8),
			UNIQUE (device_id, operation, request_id)
		) STRICT`

const createOperationReceiptRetentionV1 = `CREATE TABLE operation_receipt_retention (
			device_id TEXT NOT NULL CHECK (length(device_id) = 36),
			receipt_class TEXT NOT NULL CHECK (receipt_class IN ('sync', 'other')),
			receipt_sequence INTEGER NOT NULL,
			created_uptime_ms BLOB NOT NULL CHECK (length(created_uptime_ms) = 8),
			PRIMARY KEY (device_id, receipt_class, receipt_sequence)
		) STRICT`

const createTokenRotationsV1 = `CREATE TABLE token_rotations (
			rotation_id TEXT PRIMARY KEY CHECK (length(rotation_id) = 36),
			device_id TEXT NOT NULL CHECK (length(device_id) = 36),
			old_token_hash BLOB NOT NULL CHECK (length(old_token_hash) = 32),
			new_token_hash BLOB NOT NULL CHECK (length(new_token_hash) = 32),
			request_fingerprint BLOB NOT NULL CHECK (length(request_fingerprint) = 32),
			response_json BLOB NOT NULL,
			created_at_ms INTEGER NOT NULL
		) STRICT`

const createSelfRevocationReceiptsV1 = `CREATE TABLE self_revocation_receipts (
			device_id TEXT PRIMARY KEY CHECK (length(device_id) = 36),
			request_id TEXT NOT NULL CHECK (length(request_id) = 36),
			body_fingerprint BLOB NOT NULL CHECK (length(body_fingerprint) = 32),
			pre_revocation_token_hash BLOB NOT NULL CHECK (length(pre_revocation_token_hash) = 32),
			response_status INTEGER NOT NULL CHECK (response_status = 200),
			response_headers_json BLOB NOT NULL,
			response_json BLOB NOT NULL
		) STRICT`

const createSnapshotsV1 = `CREATE TABLE snapshots (
			snapshot_id TEXT PRIMARY KEY CHECK (length(snapshot_id) = 36),
			owner_device_id TEXT NOT NULL CHECK (length(owner_device_id) = 36),
			request_id TEXT NOT NULL CHECK (length(request_id) = 36),
			request_fingerprint BLOB NOT NULL CHECK (length(request_fingerprint) = 32),
			cut_cursor BLOB NOT NULL CHECK (length(cut_cursor) = 8),
			envelope_generation BLOB NOT NULL CHECK (length(envelope_generation) = 8),
			expires_at_ms INTEGER NOT NULL,
			metadata_bytes INTEGER NOT NULL CHECK (metadata_bytes >= 0),
			create_response_json BLOB NOT NULL,
			UNIQUE (owner_device_id, request_id)
		) STRICT`

const createSnapshotPagesV1 = `CREATE TABLE snapshot_pages (
			snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
			page_index INTEGER NOT NULL CHECK (page_index >= 0),
			page_token TEXT NOT NULL UNIQUE CHECK (length(page_token) = 43),
			response_json BLOB NOT NULL,
			PRIMARY KEY (snapshot_id, page_index)
		) STRICT`

const createSnapshotRevisionRefsV1 = `CREATE TABLE snapshot_revision_refs (
			snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
			revision_id TEXT NOT NULL CHECK (length(revision_id) = 36),
			content_hash BLOB NOT NULL REFERENCES revision_objects(content_hash) CHECK (length(content_hash) = 32),
			PRIMARY KEY (snapshot_id, revision_id)
		) STRICT`

var fullSchemaTables = map[string]string{
	"changes":                     createChangesV1,
	"collection_candidates":       createCollectionCandidatesV1,
	"collection_markers":          createCollectionMarkersV1,
	"collection_records":          createCollectionRecordsV1,
	"device_sync_state":           createDeviceSyncStateV1,
	"devices":                     createDevicesV1,
	"enrollment_grants":           createEnrollmentGrantsV1,
	"enrollments":                 createEnrollmentsV1,
	"instance_metadata":           createInstanceMetadataV1,
	"operation_receipts":          createOperationReceiptsV1,
	"operation_receipt_retention": createOperationReceiptRetentionV1,
	"record_revisions":            createRecordRevisionsV1,
	"record_heads":                createRecordHeadsV1,
	"record_vector_index":         createRecordVectorIndexV1,
	"revision_objects":            createRevisionObjectsV1,
	"runtime_state":               createRuntimeStateV1,
	"self_revocation_receipts":    createSelfRevocationReceiptsV1,
	"snapshot_pages":              createSnapshotPagesV1,
	"snapshot_revision_refs":      createSnapshotRevisionRefsV1,
	"snapshots":                   createSnapshotsV1,
	"token_rotations":             createTokenRotationsV1,
	"vault_envelope":              createVaultEnvelopeV1,
}

var legacySchemaTables = map[string]string{
	"devices":           createDevicesV1,
	"instance_metadata": createInstanceMetadataV1,
}

type schemaKind int

const (
	schemaEmpty schemaKind = iota
	schemaLegacy
	schemaFull
)

type schemaQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func inspectSchemaState(ctx context.Context, database schemaQueryer) (schemaKind, int, error) {
	var userVersion int
	if err := database.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion); err != nil {
		return schemaEmpty, 0, fmt.Errorf("read storage schema: %w", err)
	}
	if userVersion > SchemaVersion {
		return schemaEmpty, userVersion, ErrFutureSchema
	}
	if userVersion < 0 {
		return schemaEmpty, userVersion, errors.New("invalid negative storage schema")
	}
	tables, err := readSchemaTables(ctx, database)
	if err != nil {
		return schemaEmpty, userVersion, err
	}
	if userVersion == 0 {
		if len(tables) != 0 {
			return schemaEmpty, userVersion, ErrUnexpectedSchema
		}
		return schemaEmpty, userVersion, nil
	}
	if schemaTablesEqual(tables, fullSchemaTables) {
		return schemaFull, userVersion, nil
	}
	if schemaTablesEqual(tables, legacySchemaTables) {
		return schemaLegacy, userVersion, nil
	}
	return schemaEmpty, userVersion, ErrUnexpectedSchema
}

func validateSchemaState(ctx context.Context, database schemaQueryer) (int, error) {
	kind, version, err := inspectSchemaState(ctx, database)
	if err != nil {
		return version, err
	}
	if version != 0 && kind != schemaFull {
		return version, ErrUnexpectedSchema
	}
	return version, nil
}

func readSchemaTables(ctx context.Context, database schemaQueryer) (map[string]string, error) {
	var forbidden int
	if err := database.QueryRowContext(ctx, `
		SELECT count(*) FROM sqlite_schema
		WHERE type IN ('trigger', 'view') OR (type = 'index' AND sql IS NOT NULL)`,
	).Scan(&forbidden); err != nil {
		return nil, fmt.Errorf("inspect V1 auxiliary schema: %w", err)
	}
	if forbidden != 0 {
		return nil, ErrUnexpectedSchema
	}
	rows, err := database.QueryContext(ctx, `
		SELECT name, sql FROM sqlite_schema
		WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("inspect V1 storage schema: %w", err)
	}
	defer rows.Close()
	tables := make(map[string]string)
	for rows.Next() {
		var name, statement string
		if err := rows.Scan(&name, &statement); err != nil {
			return nil, fmt.Errorf("read V1 storage schema: %w", err)
		}
		tables[name] = statement
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read V1 storage schema: %w", err)
	}
	return tables, nil
}

func schemaTablesEqual(actual, expected map[string]string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for name, statement := range expected {
		if actual[name] != statement {
			return false
		}
	}
	return true
}

func createSchemaV1(ctx context.Context, transaction *sql.Tx) error {
	for _, statement := range []string{
		createInstanceMetadataV1,
		createDevicesV1,
		createRuntimeStateV1,
		createDeviceSyncStateV1,
		createEnrollmentGrantsV1,
		createEnrollmentsV1,
		createVaultEnvelopeV1,
		createRevisionObjectsV1,
		createRecordRevisionsV1,
		createRecordHeadsV1,
		createRecordVectorIndexV1,
		createCollectionRecordsV1,
		createCollectionCandidatesV1,
		createCollectionMarkersV1,
		createChangesV1,
		createOperationReceiptsV1,
		createOperationReceiptRetentionV1,
		createTokenRotationsV1,
		createSelfRevocationReceiptsV1,
		createSnapshotsV1,
		createSnapshotPagesV1,
		createSnapshotRevisionRefsV1,
		fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion),
	} {
		if _, err := transaction.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create storage schema: %w", err)
		}
	}
	return nil
}

func migrateLegacySchemaV1(ctx context.Context, transaction *sql.Tx) error {
	for _, statement := range []string{
		createRuntimeStateV1,
		createDeviceSyncStateV1,
		createEnrollmentGrantsV1,
		createEnrollmentsV1,
		createVaultEnvelopeV1,
		createRevisionObjectsV1,
		createRecordRevisionsV1,
		createRecordHeadsV1,
		createRecordVectorIndexV1,
		createCollectionRecordsV1,
		createCollectionCandidatesV1,
		createCollectionMarkersV1,
		createChangesV1,
		createOperationReceiptsV1,
		createOperationReceiptRetentionV1,
		createTokenRotationsV1,
		createSelfRevocationReceiptsV1,
		createSnapshotsV1,
		createSnapshotPagesV1,
		createSnapshotRevisionRefsV1,
	} {
		if _, err := transaction.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate storage schema: %w", err)
		}
	}
	return nil
}
