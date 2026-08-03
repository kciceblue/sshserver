package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
)

func writeHotScanOversizedBlob(t *testing.T, database *sql.DB, statement string, arguments ...any) {
	t.Helper()
	if _, err := database.Exec("PRAGMA foreign_keys = OFF"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(statement, arguments...); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("PRAGMA ignore_check_constraints = OFF"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatal(err)
	}
}

func fixedBlobSeedRevision(t *testing.T, seed boundedPersistenceSeed) recordRevision {
	t.Helper()
	var request syncRequest
	if err := json.Unmarshal(seed.sync.Body, &request); err != nil || len(request.Mutations) != 1 {
		t.Fatalf("decode seeded sync request: mutations=%d error=%v", len(request.Mutations), err)
	}
	return request.Mutations[0]
}

func expectFixedBlobInternal(t *testing.T, opened *Store, call api.Request) {
	t.Helper()
	if _, protocolErr := opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "internal_error" {
		t.Fatalf("fixed-width BLOB corruption error=%v", protocolErr)
	}
}

func fixedBlobNewSnapshotCall(seed boundedPersistenceSeed, requestID string) api.Request {
	body, _ := marshalJSON(snapshotCreateRequest{
		ProtocolVersion: "1", DeviceID: seed.deviceID, RequestID: requestID,
		RequiredCapabilities: append([]string(nil), requiredSnapshotCapabilities...),
	})
	return api.Request{
		Method: "POST", Path: "/v1/snapshot-reads", RequestID: requestID,
		Authorization: authorization(seed.token), Body: body, Now: protocolFixtureTime.Add(10 * time.Second),
	}
}

func fixedBlobValidateReplay(t *testing.T, seed boundedPersistenceSeed) *api.Error {
	t.Helper()
	transaction, err := seed.opened.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	_, _, _, protocolErr := seed.opened.validateMutations(
		context.Background(), transaction, seed.deviceID, 1, []recordRevision{fixedBlobSeedRevision(t, seed)},
	)
	return protocolErr
}

func fixedBlobLoadChanges(t *testing.T, seed boundedPersistenceSeed) *api.Error {
	t.Helper()
	transaction, err := seed.opened.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	_, _, _, protocolErr := loadChanges(context.Background(), transaction, 0)
	return protocolErr
}

func fixedBlobValidateVectorRegistry(t *testing.T, seed boundedPersistenceSeed) *api.Error {
	t.Helper()
	transaction, err := seed.opened.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	return validateVectorRegistry(context.Background(), transaction,
		"fa000000-0000-4000-8000-000000000001", 1, map[string]uint64{seed.deviceID: 1})
}

func fixedBlobBuildSnapshot(t *testing.T, seed boundedPersistenceSeed) *api.Error {
	t.Helper()
	transaction, err := seed.opened.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	_, _, protocolErr := buildSnapshotPlan(context.Background(), transaction,
		"fa000000-0000-4000-8000-000000000002", seed.deviceID,
		"fa000000-0000-4000-8000-000000000003", 3, 1, snapshotMetadataLimit)
	return protocolErr
}

func fixedBlobDeleteSnapshot(t *testing.T, seed boundedPersistenceSeed) *api.Error {
	t.Helper()
	transaction, err := seed.opened.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	return deleteSnapshotAndReleaseObjects(context.Background(), transaction, seed.snapshot.SnapshotID)
}

func mutateHotScanHashPairOversized(t *testing.T, seed boundedPersistenceSeed) {
	t.Helper()
	writeHotScanOversizedBlob(t, seed.opened.db,
		"UPDATE revision_objects SET content_hash = zeroblob(33)")
	writeHotScanOversizedBlob(t, seed.opened.db,
		"UPDATE record_revisions SET content_hash = zeroblob(33) WHERE revision_id = ?", seed.revisionID)
}

func mutateHotScanHashPairWrongType(t *testing.T, seed boundedPersistenceSeed) {
	t.Helper()
	value := strings.Repeat("h", 32)
	mutateValidationOwnerWrongType(t, seed.opened.db, "revision_objects",
		"UPDATE revision_objects SET content_hash = CAST(? AS TEXT)", value)
	mutateValidationOwnerWrongType(t, seed.opened.db, "record_revisions",
		"UPDATE record_revisions SET content_hash = CAST(? AS TEXT) WHERE revision_id = ?", value, seed.revisionID)
}

func mutateHotScanSnapshotHashPairOversized(t *testing.T, seed boundedPersistenceSeed) {
	t.Helper()
	writeHotScanOversizedBlob(t, seed.opened.db,
		"UPDATE revision_objects SET content_hash = zeroblob(33)")
	writeHotScanOversizedBlob(t, seed.opened.db,
		"UPDATE snapshot_revision_refs SET content_hash = zeroblob(33) WHERE snapshot_id = ?", seed.snapshot.SnapshotID)
}

func mutateHotScanSnapshotHashPairWrongType(t *testing.T, seed boundedPersistenceSeed) {
	t.Helper()
	value := strings.Repeat("s", 32)
	mutateValidationOwnerWrongType(t, seed.opened.db, "revision_objects",
		"UPDATE revision_objects SET content_hash = CAST(? AS TEXT)", value)
	mutateValidationOwnerWrongType(t, seed.opened.db, "snapshot_revision_refs",
		"UPDATE snapshot_revision_refs SET content_hash = CAST(? AS TEXT) WHERE snapshot_id = ?", value, seed.snapshot.SnapshotID)
}

func TestSyncAndSnapshotFixedBlobHotScansAcceptCanonicalRows(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()

	if response, protocolErr := seed.opened.HandleAPI(context.Background(), seed.snapshotCreate); protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("canonical snapshot replay: response=%+v error=%v", response, protocolErr)
	}
	if response, protocolErr := seed.opened.HandleAPI(context.Background(), seed.snapshotPage); protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("canonical snapshot page: response=%+v error=%v", response, protocolErr)
	}
	if protocolErr := fixedBlobValidateReplay(t, seed); protocolErr != nil {
		t.Fatalf("canonical revision replay error=%v", protocolErr)
	}
	if protocolErr := fixedBlobLoadChanges(t, seed); protocolErr != nil {
		t.Fatalf("canonical change load error=%v", protocolErr)
	}
	if protocolErr := fixedBlobValidateVectorRegistry(t, seed); protocolErr != nil {
		t.Fatalf("canonical vector registry error=%v", protocolErr)
	}
	if protocolErr := fixedBlobBuildSnapshot(t, seed); protocolErr != nil {
		t.Fatalf("canonical snapshot build error=%v", protocolErr)
	}
	if protocolErr := fixedBlobDeleteSnapshot(t, seed); protocolErr != nil {
		t.Fatalf("canonical snapshot deletion error=%v", protocolErr)
	}
}

func TestSyncFixedBlobHotScansRejectOversizedAndWrongTypeValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, boundedPersistenceSeed)
		check  func(*testing.T, boundedPersistenceSeed) *api.Error
	}{
		{
			name: "oversized revision replay hash",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeHotScanOversizedBlob(t, seed.opened.db,
					"UPDATE record_revisions SET content_hash = zeroblob(33) WHERE revision_id = ?", seed.revisionID)
			},
			check: fixedBlobValidateReplay,
		},
		{
			name: "wrong-type revision replay hash",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerWrongType(t, seed.opened.db, "record_revisions",
					"UPDATE record_revisions SET content_hash = CAST(? AS TEXT) WHERE revision_id = ?", strings.Repeat("r", 32), seed.revisionID)
			},
			check: fixedBlobValidateReplay,
		},
		{
			name: "oversized vector registry counter",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeHotScanOversizedBlob(t, seed.opened.db,
					"UPDATE devices SET max_author_counter = zeroblob(9) WHERE device_id = ?", seed.deviceID)
			},
			check: fixedBlobValidateVectorRegistry,
		},
		{
			name: "wrong-type vector registry counter",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerWrongType(t, seed.opened.db, "devices",
					"UPDATE devices SET max_author_counter = CAST(? AS TEXT) WHERE device_id = ?", "12345678", seed.deviceID)
			},
			check: fixedBlobValidateVectorRegistry,
		},
		{
			name: "oversized change cursor",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeHotScanOversizedBlob(t, seed.opened.db,
					"UPDATE changes SET cursor = zeroblob(9) WHERE kind = 'record_revision'")
			},
			check: fixedBlobLoadChanges,
		},
		{
			name:   "oversized retained revision hash",
			mutate: mutateHotScanHashPairOversized,
			check:  fixedBlobLoadChanges,
		},
		{
			name:   "wrong-type retained revision hash",
			mutate: mutateHotScanHashPairWrongType,
			check:  fixedBlobLoadChanges,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{})
			defer seed.opened.Close()
			test.mutate(t, seed)
			if protocolErr := test.check(t, seed); protocolErr == nil || protocolErr.Code != "internal_error" {
				t.Fatalf("noncanonical sync BLOB error=%v", protocolErr)
			}
		})
	}
}

func TestSnapshotFixedBlobHotScansRejectOversizedAndWrongTypeValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, boundedPersistenceSeed)
		check  func(*testing.T, boundedPersistenceSeed)
	}{
		{
			name: "oversized replay fingerprint",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeHotScanOversizedBlob(t, seed.opened.db,
					"UPDATE snapshots SET request_fingerprint = zeroblob(33) WHERE snapshot_id = ?", seed.snapshot.SnapshotID)
			},
			check: func(t *testing.T, seed boundedPersistenceSeed) {
				expectFixedBlobInternal(t, seed.opened, seed.snapshotCreate)
			},
		},
		{
			name: "wrong-type replay cut cursor",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerWrongType(t, seed.opened.db, "snapshots",
					"UPDATE snapshots SET cut_cursor = CAST(? AS TEXT) WHERE snapshot_id = ?", "12345678", seed.snapshot.SnapshotID)
			},
			check: func(t *testing.T, seed boundedPersistenceSeed) {
				expectFixedBlobInternal(t, seed.opened, seed.snapshotCreate)
			},
		},
		{
			name: "oversized replay envelope generation",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeHotScanOversizedBlob(t, seed.opened.db,
					"UPDATE snapshots SET envelope_generation = zeroblob(9) WHERE snapshot_id = ?", seed.snapshot.SnapshotID)
			},
			check: func(t *testing.T, seed boundedPersistenceSeed) {
				expectFixedBlobInternal(t, seed.opened, seed.snapshotCreate)
			},
		},
		{
			name: "wrong-type page envelope generation",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerWrongType(t, seed.opened.db, "snapshots",
					"UPDATE snapshots SET envelope_generation = CAST(? AS TEXT) WHERE snapshot_id = ?", "12345678", seed.snapshot.SnapshotID)
			},
			check: func(t *testing.T, seed boundedPersistenceSeed) {
				expectFixedBlobInternal(t, seed.opened, seed.snapshotPage)
			},
		},
		{
			name: "oversized maximum returned cursor",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				if _, err := seed.opened.db.Exec("DELETE FROM snapshots"); err != nil {
					t.Fatal(err)
				}
				seed.opened.ephemeral.mu.Lock()
				clear(seed.opened.ephemeral.snapshotDeadlines)
				seed.opened.ephemeral.mu.Unlock()
				writeHotScanOversizedBlob(t, seed.opened.db,
					"UPDATE device_sync_state SET max_returned_cursor = zeroblob(9) WHERE device_id = ?", seed.deviceID)
			},
			check: func(t *testing.T, seed boundedPersistenceSeed) {
				expectFixedBlobInternal(t, seed.opened, fixedBlobNewSnapshotCall(seed, "fa000000-0000-4000-8000-000000000004"))
			},
		},
		{
			name: "wrong-type maximum returned cursor",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				if _, err := seed.opened.db.Exec("DELETE FROM snapshots"); err != nil {
					t.Fatal(err)
				}
				seed.opened.ephemeral.mu.Lock()
				clear(seed.opened.ephemeral.snapshotDeadlines)
				seed.opened.ephemeral.mu.Unlock()
				mutateValidationOwnerWrongType(t, seed.opened.db, "device_sync_state",
					"UPDATE device_sync_state SET max_returned_cursor = CAST(? AS TEXT) WHERE device_id = ?", "12345678", seed.deviceID)
			},
			check: func(t *testing.T, seed boundedPersistenceSeed) {
				expectFixedBlobInternal(t, seed.opened, fixedBlobNewSnapshotCall(seed, "fa000000-0000-4000-8000-000000000005"))
			},
		},
		{
			name:   "oversized page object and reference hashes",
			mutate: mutateHotScanSnapshotHashPairOversized,
			check: func(t *testing.T, seed boundedPersistenceSeed) {
				expectFixedBlobInternal(t, seed.opened, seed.snapshotPage)
			},
		},
		{
			name:   "wrong-type page object and reference hashes",
			mutate: mutateHotScanSnapshotHashPairWrongType,
			check: func(t *testing.T, seed boundedPersistenceSeed) {
				expectFixedBlobInternal(t, seed.opened, seed.snapshotPage)
			},
		},
		{
			name: "oversized snapshot build hash",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateHotScanHashPairOversized(t, seed)
			},
			check: func(t *testing.T, seed boundedPersistenceSeed) {
				if protocolErr := fixedBlobBuildSnapshot(t, seed); protocolErr == nil || protocolErr.Code != "internal_error" {
					t.Fatalf("oversized snapshot build hash error=%v", protocolErr)
				}
			},
		},
		{
			name: "wrong-type snapshot source counter",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutateValidationOwnerWrongType(t, seed.opened.db, "devices",
					"UPDATE devices SET max_author_counter = CAST(? AS TEXT) WHERE device_id = ?", "12345678", seed.deviceID)
			},
			check: func(t *testing.T, seed boundedPersistenceSeed) {
				if protocolErr := fixedBlobBuildSnapshot(t, seed); protocolErr == nil || protocolErr.Code != "internal_error" {
					t.Fatalf("wrong-type snapshot source counter error=%v", protocolErr)
				}
			},
		},
		{
			name: "oversized snapshot deletion reference hash",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				writeHotScanOversizedBlob(t, seed.opened.db,
					"UPDATE snapshot_revision_refs SET content_hash = zeroblob(33) WHERE snapshot_id = ?", seed.snapshot.SnapshotID)
			},
			check: func(t *testing.T, seed boundedPersistenceSeed) {
				if protocolErr := fixedBlobDeleteSnapshot(t, seed); protocolErr == nil || protocolErr.Code != "internal_error" {
					t.Fatalf("oversized snapshot deletion hash error=%v", protocolErr)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{})
			defer seed.opened.Close()
			test.mutate(t, seed)
			test.check(t, seed)
		})
	}
}
