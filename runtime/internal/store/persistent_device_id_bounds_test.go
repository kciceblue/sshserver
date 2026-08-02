package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
)

func persistentOversizedDeviceID(deviceID string) string {
	return deviceID + "\x00" + strings.Repeat("x", maxBodyBytes+1)
}

func mutatePersistentDeviceID(t *testing.T, database *sql.DB, statement string, arguments ...any) {
	t.Helper()
	if _, err := database.Exec("PRAGMA foreign_keys = OFF"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(statement, arguments...); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatal(err)
	}
}

func TestPersistentDeviceIDScansBoundBeforeLoading(t *testing.T) {
	tests := []struct {
		name    string
		options boundedSeedOptions
		detail  string
		mutate  func(*testing.T, boundedPersistenceSeed, string)
	}{
		{
			name: "primary device registry", detail: "invalid device row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, oversized string) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE devices SET device_id = ? WHERE device_id = ?", oversized, seed.deviceID)
			},
		},
		{
			name: "revision author", detail: "invalid revision row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, oversized string) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE record_revisions SET author_device_id = ? WHERE revision_id = ?", oversized, seed.revisionID)
			},
		},
		{
			name: "device change", detail: "invalid change row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, oversized string) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE changes SET device_changed_id = ? WHERE device_change_kind = 'enrolled'", oversized)
			},
		},
		{
			name: "operation receipt", detail: "invalid operation receipt",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, oversized string) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE operation_receipts SET device_id = ? WHERE receipt_sequence = (SELECT min(receipt_sequence) FROM operation_receipts)", oversized)
			},
		},
		{
			name: "receipt retention", detail: "invalid operation receipt retention",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, oversized string) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE operation_receipt_retention SET device_id = ? WHERE receipt_sequence = (SELECT min(receipt_sequence) FROM operation_receipt_retention)", oversized)
			},
		},
		{
			name: "enrollment", detail: "invalid enrollment row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, oversized string) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE enrollments SET device_id = ? WHERE device_id = ?", oversized, seed.deviceID)
			},
		},
		{
			name: "token rotation", options: boundedSeedOptions{rotation: true}, detail: "invalid token rotation row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, oversized string) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE token_rotations SET device_id = ?", oversized)
			},
		},
		{
			name: "self revocation", options: boundedSeedOptions{self: true}, detail: "invalid self-revocation receipt",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, oversized string) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE self_revocation_receipts SET device_id = ?", oversized)
			},
		},
		{
			name: "snapshot owner", detail: "invalid snapshot row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, oversized string) {
				mutatePersistentDeviceID(t, seed.opened.db, "UPDATE snapshots SET owner_device_id = ?", oversized)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, test.options)
			defer seed.opened.Close()
			oversized := persistentOversizedDeviceID(seed.deviceID)
			test.mutate(t, seed, oversized)
			err := validatePersistentState(context.Background(), seed.opened.db, testIdentity)
			if !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), test.detail) {
				t.Fatalf("oversized device ID error=%v", err)
			}
		})
	}
}

func TestPrimaryDeviceIDScanIsBoundInReadiness(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	mutatePersistentDeviceID(t, seed.opened.db, "UPDATE devices SET device_id = ? WHERE device_id = ?", persistentOversizedDeviceID(seed.deviceID), seed.deviceID)
	if err := validateReadinessDevices(context.Background(), seed.opened.db, 3); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "invalid readiness device sentinel") {
		t.Fatalf("oversized readiness device ID error=%v", err)
	}
}

func TestJoinedReceiptDeviceIDScanIsBoundBeforeLoading(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	mutatePersistentDeviceID(t, seed.opened.db, "UPDATE operation_receipts SET device_id = ? WHERE receipt_sequence = (SELECT min(receipt_sequence) FROM operation_receipts)", persistentOversizedDeviceID(seed.deviceID))
	if err := validatePersistentReceiptRetention(context.Background(), seed.opened.db); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "invalid operation receipt retention") {
		t.Fatalf("oversized joined receipt device ID error=%v", err)
	}
}

func TestRevisionAuthorDeviceIDHelperScansAreBoundBeforeLoading(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	mutatePersistentDeviceID(t, seed.opened.db, "UPDATE record_revisions SET author_device_id = ? WHERE revision_id = ?", persistentOversizedDeviceID(seed.deviceID), seed.revisionID)
	devices, err := validatePersistentDevices(context.Background(), seed.opened.db, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePersistentHistorySequence(context.Background(), seed.opened.db, devices); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "invalid revision history sequence") {
		t.Fatalf("oversized history author device ID error=%v", err)
	}
	if err := validatePersistentSnapshots(context.Background(), seed.opened.db, testIdentity, devices, 3, 1, 0); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "invalid snapshot reference") {
		t.Fatalf("oversized snapshot author device ID error=%v", err)
	}
}
