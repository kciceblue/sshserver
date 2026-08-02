package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/auth"
)

func persistentOversizedText(prefix string) string {
	return prefix + "\x00" + strings.Repeat("x", maxBodyBytes+1)
}

func TestPersistentIdentifierScansBoundBeforeLoading(t *testing.T) {
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	tests := []struct {
		name    string
		options boundedSeedOptions
		detail  string
		mutate  func(*testing.T, boundedPersistenceSeed)
	}{
		{
			name: "runtime collection cursor", detail: "invalid runtime state",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE runtime_state SET collection_scan_after_record_id = ? WHERE singleton = 1", persistentOversizedText(seed.recordID))
			},
		},
		{
			name: "revision ID", detail: "invalid revision row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE record_revisions SET revision_id = ? WHERE revision_id = ?", persistentOversizedText(seed.revisionID), seed.revisionID)
			},
		},
		{
			name: "record ID", detail: "invalid revision row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE record_revisions SET record_id = ? WHERE revision_id = ?", persistentOversizedText(seed.recordID), seed.revisionID)
			},
		},
		{
			name: "record head", detail: "invalid record head",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE record_heads SET record_id = ? WHERE revision_id = ?", persistentOversizedText(seed.recordID), seed.revisionID)
			},
		},
		{
			name: "record vector index", detail: "invalid record vector index",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE record_vector_index SET revision_id = ? WHERE revision_id = ?", persistentOversizedText(seed.revisionID), seed.revisionID)
			},
		},
		{
			name: "collection record", detail: "invalid collection record queue",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE collection_records SET record_id = ? WHERE record_id = ?", persistentOversizedText(seed.recordID), seed.recordID)
			},
		},
		{
			name: "collection candidate", detail: "invalid collection candidate queue",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE collection_candidates SET revision_id = ? WHERE revision_id = ?", persistentOversizedText(seed.revisionID), seed.revisionID)
			},
		},
		{
			name: "collection marker", options: boundedSeedOptions{marker: true}, detail: "invalid marker row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE collection_markers SET witness_revision_id = ?", persistentOversizedText(seed.revisionID))
			},
		},
		{
			name: "operation request ID", detail: "invalid operation receipt",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE operation_receipts SET request_id = ? WHERE receipt_sequence = (SELECT min(receipt_sequence) FROM operation_receipts)", persistentOversizedText(seed.sync.RequestID))
			},
		},
		{
			name: "operation text", detail: "invalid operation receipt",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE operation_receipts SET operation = ? WHERE receipt_sequence = (SELECT min(receipt_sequence) FROM operation_receipts)", persistentOversizedText("sync"))
			},
		},
		{
			name: "consumed enrollment ID", detail: "invalid enrollment grant",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE enrollment_grants SET consumed_enrollment_id = ? WHERE consumed_enrollment_id IS NOT NULL", persistentOversizedText("e1000000-0000-4000-8000-000000000002"))
			},
		},
		{
			name: "enrollment ID", detail: "invalid enrollment row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE enrollments SET enrollment_id = ?", persistentOversizedText("e1000000-0000-4000-8000-000000000002"))
			},
		},
		{
			name: "enrollment scopes", detail: "invalid enrollment row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE enrollments SET scopes_json = ?", persistentOversizedText(string(wantScopes)))
			},
		},
		{
			name: "rotation ID", options: boundedSeedOptions{rotation: true}, detail: "invalid token rotation row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE token_rotations SET rotation_id = ?", persistentOversizedText("e1000000-0000-4000-8000-00000000000a"))
			},
		},
		{
			name: "self revocation request ID", options: boundedSeedOptions{self: true}, detail: "invalid self-revocation receipt",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE self_revocation_receipts SET request_id = ?", persistentOversizedText("e1000000-0000-4000-8000-00000000000c"))
			},
		},
		{
			name: "snapshot ID", detail: "invalid snapshot row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE snapshots SET snapshot_id = ?", persistentOversizedText(seed.snapshot.SnapshotID))
			},
		},
		{
			name: "snapshot request ID", detail: "invalid snapshot row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE snapshots SET request_id = ?", persistentOversizedText(seed.snapshotCreate.RequestID))
			},
		},
		{
			name: "snapshot page token", detail: "invalid snapshot page",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE snapshot_pages SET page_token = ? WHERE page_index = 0", persistentOversizedText(seed.snapshot.FirstPageToken))
			},
		},
		{
			name: "snapshot reference ID", detail: "invalid snapshot reference",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE snapshot_revision_refs SET revision_id = ?", persistentOversizedText(seed.revisionID))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, test.options)
			defer seed.opened.Close()
			test.mutate(t, seed)
			err := validatePersistentState(context.Background(), seed.opened.db, testIdentity)
			if !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), test.detail) {
				t.Fatalf("oversized identifier error=%v", err)
			}
		})
	}
}

func TestNullableChangeIdentifierScansBoundBeforeLoading(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	mutatePersistentDeviceID(t, seed.opened.db, "UPDATE changes SET record_revision_id = ? WHERE kind = 'record_revision'", persistentOversizedText(seed.revisionID))
	devices, err := validatePersistentDevices(context.Background(), seed.opened.db, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validatePersistentChanges(context.Background(), seed.opened.db, devices, 3); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "invalid change row") {
		t.Fatalf("oversized nullable change identifier error=%v", err)
	}
}
