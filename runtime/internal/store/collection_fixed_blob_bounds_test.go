package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"math"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/api"
)

type collectionBlobReader func(context.Context, *sql.Tx, boundedPersistenceSeed) *api.Error

func expectCollectionBlobReaderInternalError(t *testing.T, seed boundedPersistenceSeed, reader collectionBlobReader) {
	t.Helper()
	transaction, err := seed.opened.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	if protocolErr := reader(context.Background(), transaction, seed); protocolErr == nil || protocolErr.Code != "internal_error" || !protocolErr.Retryable {
		t.Fatalf("fixed BLOB reader error=%v", protocolErr)
	}
}

func writeOversizedCollectionBlob(t *testing.T, database *sql.DB, statement string, arguments ...any) {
	t.Helper()
	if _, err := database.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(statement, arguments...); err != nil {
		database.Exec("PRAGMA ignore_check_constraints = OFF")
		t.Fatal(err)
	}
	if _, err := database.Exec("PRAGMA ignore_check_constraints = OFF"); err != nil {
		t.Fatal(err)
	}
}

func collectionWorkReader(accumulatedUptimeMS uint64) collectionBlobReader {
	return func(ctx context.Context, transaction *sql.Tx, seed boundedPersistenceSeed) *api.Error {
		_, _, _, protocolErr := loadCollectionRecordWork(ctx, transaction, seed.recordID, accumulatedUptimeMS)
		return protocolErr
	}
}

func collectionMarkerReader(ctx context.Context, transaction *sql.Tx, seed boundedPersistenceSeed) *api.Error {
	_, protocolErr := loadCollectionMarker(ctx, transaction, seed.recordID)
	return protocolErr
}

func collectionDeleteHashReader(ctx context.Context, transaction *sql.Tx, seed boundedPersistenceSeed) *api.Error {
	var objectHashBytes []byte
	if err := transaction.QueryRowContext(ctx, "SELECT content_hash FROM revision_objects ORDER BY content_hash LIMIT 1").Scan(&objectHashBytes); err != nil || len(objectHashBytes) != sha256.Size {
		return api.NewError("test_setup_error", false)
	}
	var objectHash [sha256.Size]byte
	copy(objectHash[:], objectHashBytes)
	return deleteUnreferencedRevisionObject(ctx, transaction, objectHash, seed.revisionID)
}

func TestCollectionFixedBlobReadersRejectOversizedValuesBeforeScan(t *testing.T) {
	const oversizedBytes = 4096
	tests := []struct {
		name    string
		options boundedSeedOptions
		mutate  func(*testing.T, boundedPersistenceSeed)
		read    collectionBlobReader
	}{
		{
			name: "accumulated uptime checkpoint",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeOversizedCollectionBlob(t, seed.opened.db,
					"UPDATE runtime_state SET accumulated_uptime_ms = zeroblob(?) WHERE singleton = 1", oversizedBytes)
			},
			read: func(ctx context.Context, transaction *sql.Tx, seed boundedPersistenceSeed) *api.Error {
				_, _, protocolErr := seed.opened.checkpointUptimeTx(ctx, transaction, protocolFixtureTime)
				return protocolErr
			},
		},
		{
			name: "collection generation",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeOversizedCollectionBlob(t, seed.opened.db,
					"UPDATE runtime_state SET collection_generation = zeroblob(?) WHERE singleton = 1", oversizedBytes)
			},
			read: func(ctx context.Context, transaction *sql.Tx, seed boundedPersistenceSeed) *api.Error {
				_, protocolErr := seed.opened.collectEligible(ctx, transaction, protocolFixtureTime, 0, 3)
				return protocolErr
			},
		},
		{
			name: "active acknowledgement",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeOversizedCollectionBlob(t, seed.opened.db,
					"UPDATE devices SET last_ack_cursor = zeroblob(?) WHERE device_id = ?", oversizedBytes, seed.deviceID)
			},
			read: func(ctx context.Context, transaction *sql.Tx, _ boundedPersistenceSeed) *api.Error {
				_, protocolErr := loadActiveAcknowledgements(ctx, transaction)
				return protocolErr
			},
		},
		{
			name: "record barrier",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeOversizedCollectionBlob(t, seed.opened.db,
					"UPDATE collection_records SET barrier_cursor = zeroblob(?) WHERE record_id = ?", oversizedBytes, seed.recordID)
			},
			read: collectionWorkReader(0),
		},
		{
			name: "head content hash",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeOversizedCollectionBlob(t, seed.opened.db,
					"UPDATE record_revisions SET content_hash = zeroblob(?) WHERE revision_id = ?", oversizedBytes, seed.revisionID)
			},
			read: collectionWorkReader(0),
		},
		{
			name: "head witness authenticator",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeOversizedCollectionBlob(t, seed.opened.db,
					"UPDATE record_revisions SET collection_witness_authenticator = zeroblob(?) WHERE revision_id = ?", oversizedBytes, seed.revisionID)
			},
			read: collectionWorkReader(0),
		},
		{
			name: "revision acceptance age",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeOversizedCollectionBlob(t, seed.opened.db,
					"UPDATE record_revisions SET accepted_uptime_ms = zeroblob(?) WHERE revision_id = ?", oversizedBytes, seed.revisionID)
			},
			read: collectionWorkReader(0),
		},
		{
			name: "acceptance origin",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeOversizedCollectionBlob(t, seed.opened.db,
					"UPDATE revision_acceptance_origins SET accepted_uptime_ms = zeroblob(?) WHERE revision_id = ?", oversizedBytes, seed.revisionID)
			},
			read: collectionWorkReader(0),
		},
		{
			name: "revision change cursor",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeOversizedCollectionBlob(t, seed.opened.db,
					"UPDATE record_revisions SET change_cursor = zeroblob(?) WHERE revision_id = ?", oversizedBytes, seed.revisionID)
			},
			read: collectionWorkReader(0),
		},
		{
			name: "candidate acceptance age",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeOversizedCollectionBlob(t, seed.opened.db,
					"UPDATE collection_candidates SET accepted_uptime_ms = zeroblob(?) WHERE revision_id = ?", oversizedBytes, seed.revisionID)
			},
			read: collectionWorkReader(math.MaxUint64),
		},
		{
			name:    "marker authenticator",
			options: boundedSeedOptions{marker: true},
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeOversizedCollectionBlob(t, seed.opened.db,
					"UPDATE collection_markers SET collection_witness_authenticator = zeroblob(?) WHERE record_id = ?", oversizedBytes, seed.recordID)
			},
			read: collectionMarkerReader,
		},
		{
			name:    "marker barrier",
			options: boundedSeedOptions{marker: true},
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeOversizedCollectionBlob(t, seed.opened.db,
					"UPDATE collection_markers SET barrier_cursor = zeroblob(?) WHERE record_id = ?", oversizedBytes, seed.recordID)
			},
			read: collectionMarkerReader,
		},
		{
			name: "revision object deletion hash",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeOversizedCollectionBlob(t, seed.opened.db,
					"UPDATE record_revisions SET content_hash = zeroblob(?) WHERE revision_id = ?", oversizedBytes, seed.revisionID)
			},
			read: collectionDeleteHashReader,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, test.options)
			defer seed.opened.Close()
			test.mutate(t, seed)
			expectCollectionBlobReaderInternalError(t, seed, test.read)
		})
	}
}

func TestCollectionFixedBlobReadersRejectWrongStorageClasses(t *testing.T) {
	tests := []struct {
		name      string
		options   boundedSeedOptions
		table     string
		statement string
		value     string
		arguments func(boundedPersistenceSeed) []any
		read      collectionBlobReader
	}{
		{
			name: "runtime generation text", table: "runtime_state",
			statement: "UPDATE runtime_state SET collection_generation = CAST(? AS TEXT) WHERE singleton = 1",
			value:     "12345678",
			arguments: func(boundedPersistenceSeed) []any { return nil },
			read: func(ctx context.Context, transaction *sql.Tx, seed boundedPersistenceSeed) *api.Error {
				_, protocolErr := seed.opened.collectEligible(ctx, transaction, protocolFixtureTime, 0, 3)
				return protocolErr
			},
		},
		{
			name: "optional witness text", table: "record_revisions",
			statement: "UPDATE record_revisions SET collection_witness_authenticator = CAST(? AS TEXT) WHERE revision_id = ?",
			value:     strings.Repeat("w", sha256.Size),
			arguments: func(seed boundedPersistenceSeed) []any { return []any{seed.revisionID} },
			read:      collectionWorkReader(0),
		},
		{
			name: "candidate age text", table: "collection_candidates",
			statement: "UPDATE collection_candidates SET accepted_uptime_ms = CAST(? AS TEXT) WHERE revision_id = ?",
			value:     "12345678",
			arguments: func(seed boundedPersistenceSeed) []any { return []any{seed.revisionID} },
			read:      collectionWorkReader(math.MaxUint64),
		},
		{
			name: "revision deletion hash text", table: "record_revisions",
			statement: "UPDATE record_revisions SET content_hash = CAST(? AS TEXT) WHERE revision_id = ?",
			value:     strings.Repeat("h", sha256.Size),
			arguments: func(seed boundedPersistenceSeed) []any { return []any{seed.revisionID} },
			read:      collectionDeleteHashReader,
		},
		{
			name: "marker barrier text", options: boundedSeedOptions{marker: true}, table: "collection_markers",
			statement: "UPDATE collection_markers SET barrier_cursor = CAST(? AS TEXT) WHERE record_id = ?",
			value:     "12345678",
			arguments: func(seed boundedPersistenceSeed) []any { return []any{seed.recordID} },
			read:      collectionMarkerReader,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, test.options)
			defer seed.opened.Close()
			arguments := append([]any{test.value}, test.arguments(seed)...)
			writeLiveWrongTypeText(t, seed.opened.db, test.table, test.statement, arguments...)
			expectCollectionBlobReaderInternalError(t, seed, test.read)
		})
	}
}

func TestCollectionFixedBlobReadersAcceptCanonicalRows(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{marker: true})
	defer seed.opened.Close()
	transaction, err := seed.opened.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	ctx := context.Background()

	if _, _, protocolErr := seed.opened.checkpointUptimeTx(ctx, transaction, protocolFixtureTime); protocolErr != nil {
		t.Fatalf("canonical uptime checkpoint: %v", protocolErr)
	}
	acknowledgements, protocolErr := loadActiveAcknowledgements(ctx, transaction)
	if protocolErr != nil || len(acknowledgements) != 1 {
		t.Fatalf("canonical acknowledgements=%v error=%v", acknowledgements, protocolErr)
	}
	barrier, heads, candidates, protocolErr := loadCollectionRecordWork(ctx, transaction, seed.recordID, math.MaxUint64)
	if protocolErr != nil || barrier == 0 || len(heads) != 1 || len(candidates) != 1 {
		t.Fatalf("canonical collection work barrier=%d heads=%d candidates=%d error=%v", barrier, len(heads), len(candidates), protocolErr)
	}
	marker, protocolErr := loadCollectionMarker(ctx, transaction, seed.recordID)
	if protocolErr != nil || !marker.present || len(marker.authenticator) != sha256.Size {
		t.Fatalf("canonical marker=%+v error=%v", marker, protocolErr)
	}
	if protocolErr := collectionDeleteHashReader(ctx, transaction, seed); protocolErr != nil {
		t.Fatalf("canonical revision deletion lookup: %v", protocolErr)
	}
	if _, err := transaction.ExecContext(ctx,
		"UPDATE record_revisions SET collection_witness_authenticator = NULL WHERE revision_id = ?", seed.revisionID); err != nil {
		t.Fatal(err)
	}
	_, nullableHeads, nullableCandidates, protocolErr := loadCollectionRecordWork(ctx, transaction, seed.recordID, math.MaxUint64)
	if protocolErr != nil || len(nullableHeads) != 1 || len(nullableHeads[0].authenticator) != 0 ||
		len(nullableCandidates) != 1 || len(nullableCandidates[0].authenticator) != 0 {
		t.Fatalf("canonical nullable witness heads=%+v candidates=%+v error=%v", nullableHeads, nullableCandidates, protocolErr)
	}
	if _, protocolErr := seed.opened.collectEligible(ctx, transaction, protocolFixtureTime, 0, 4); protocolErr != nil {
		t.Fatalf("canonical collection generation: %v", protocolErr)
	}
}
