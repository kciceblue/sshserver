package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
	"github.com/kciceblue/sshserver/runtime/internal/auth"
)

type liveDeviceIDDurableState struct {
	cursor                                        []byte
	devices, enrollments, grants, rotations, self int
	snapshots, snapshotPages, snapshotRefs        int
	receipts, changes                             int
}

func oversizedNULSuffixedText(prefix string) string {
	return prefix + "\x00" + strings.Repeat("x", maxBodyBytes+1)
}

func oversizedNULSuffixedDeviceID(prefix string) string {
	return oversizedNULSuffixedText(prefix)
}

func readLiveDeviceIDDurableState(t *testing.T, database *sql.DB) liveDeviceIDDurableState {
	t.Helper()
	var state liveDeviceIDDurableState
	if err := database.QueryRow(`
		SELECT server_cursor,
		       (SELECT count(*) FROM devices),
		       (SELECT count(*) FROM enrollments),
		       (SELECT count(*) FROM enrollment_grants),
		       (SELECT count(*) FROM token_rotations),
		       (SELECT count(*) FROM self_revocation_receipts),
		       (SELECT count(*) FROM snapshots),
		       (SELECT count(*) FROM snapshot_pages),
		       (SELECT count(*) FROM snapshot_revision_refs),
		       (SELECT count(*) FROM operation_receipts),
		       (SELECT count(*) FROM changes)
		FROM runtime_state WHERE singleton = 1`,
	).Scan(&state.cursor, &state.devices, &state.enrollments, &state.grants, &state.rotations, &state.self,
		&state.snapshots, &state.snapshotPages, &state.snapshotRefs, &state.receipts, &state.changes); err != nil {
		t.Fatal(err)
	}
	return state
}

func assertLiveDeviceIDStateUnchanged(t *testing.T, before, after liveDeviceIDDurableState) {
	t.Helper()
	if !bytes.Equal(before.cursor, after.cursor) || before.devices != after.devices || before.enrollments != after.enrollments ||
		before.grants != after.grants || before.rotations != after.rotations || before.self != after.self || before.snapshots != after.snapshots ||
		before.snapshotPages != after.snapshotPages || before.snapshotRefs != after.snapshotRefs ||
		before.receipts != after.receipts || before.changes != after.changes {
		t.Fatalf("durable state changed: before=%+v after=%+v", before, after)
	}
}

func assertNULSuffixPassedSQLiteLengthCheck(t *testing.T, database *sql.DB, query string, arguments ...any) {
	t.Helper()
	assertNULSuffixPassedSQLiteTextLengthCheck(t, database, maxUUIDBytes, query, arguments...)
}

func assertNULSuffixPassedSQLiteTextLengthCheck(t *testing.T, database *sql.DB, wantLogicalLength int, query string, arguments ...any) {
	t.Helper()
	var logicalLength, octetLength int64
	var storageClass string
	if err := database.QueryRow(query, arguments...).Scan(&logicalLength, &octetLength, &storageClass); err != nil {
		t.Fatal(err)
	}
	if logicalLength != int64(wantLogicalLength) || octetLength <= int64(wantLogicalLength) || storageClass != "text" {
		t.Fatalf("corrupt ID shape: length=%d octets=%d typeof=%q", logicalLength, octetLength, storageClass)
	}
}

func setLiveDeviceIDForeignKeys(t *testing.T, database *sql.DB, enabled bool) {
	t.Helper()
	value := "OFF"
	if enabled {
		value = "ON"
	}
	if _, err := database.Exec("PRAGMA foreign_keys = " + value); err != nil {
		t.Fatal(err)
	}
}

func writeLiveWrongTypeText(t *testing.T, database *sql.DB, table, update string, arguments ...any) {
	t.Helper()
	var originalSchema string
	if err := database.QueryRow("SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?", table).Scan(&originalSchema); err != nil {
		t.Fatal(err)
	}
	nonstrictSchema := strings.TrimSuffix(originalSchema, " STRICT")
	if nonstrictSchema == originalSchema {
		t.Fatalf("%s schema is not STRICT", table)
	}
	var schemaVersion int
	if err := database.QueryRow("PRAGMA schema_version").Scan(&schemaVersion); err != nil {
		t.Fatal(err)
	}
	rewriteSchema := func(statement string, version int) {
		if _, err := database.Exec("PRAGMA writable_schema = ON"); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec("UPDATE sqlite_schema SET sql = ? WHERE type = 'table' AND name = ?", statement, table); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(fmt.Sprintf("PRAGMA schema_version = %d", version)); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec("PRAGMA writable_schema = OFF"); err != nil {
			t.Fatal(err)
		}
	}
	rewriteSchema(nonstrictSchema, schemaVersion+1)
	if _, err := database.Exec(update, arguments...); err != nil {
		t.Fatal(err)
	}
	rewriteSchema(originalSchema, schemaVersion+2)
}

func expectLiveDeviceIDError(t *testing.T, opened *Store, call api.Request, code string) {
	t.Helper()
	if _, protocolErr := opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != code {
		t.Fatalf("corrupt live device ID error=%v, want=%s", protocolErr, code)
	}
}

func TestLiveDeviceIDBoundPreservesAuthenticationScanAndErrorOrdering(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()

	corruptID := oversizedNULSuffixedDeviceID("f1000000-0000-4000-8000-000000000001")
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	zero := EncodeUint64(0)
	if _, err := seed.opened.db.Exec(`
		INSERT INTO devices (
			device_id, token_hash, scopes_json, created_at_ms,
			last_ack_cursor, max_author_counter
		) VALUES (?, ?, ?, ?, ?, ?)`,
		corruptID, tokenWithByte(0xf1), string(wantScopes), protocolFixtureTime.UnixMilli(), zero[:], zero[:],
	); err != nil {
		t.Fatal(err)
	}
	assertNULSuffixPassedSQLiteLengthCheck(t, seed.opened.db, `
		SELECT length(device_id), octet_length(device_id), typeof(device_id)
		FROM devices WHERE token_hash = ?`, tokenWithByte(0xf1))

	before := readLiveDeviceIDDurableState(t, seed.opened.db)
	invalidAuthorization := api.Request{
		Method: "GET", Path: "/v1/devices", RequestID: "f1000000-0000-4000-8000-000000000002",
		Authorization: "Bearer invalid", Now: protocolFixtureTime,
	}
	expectLiveDeviceIDError(t, seed.opened, invalidAuthorization, "unauthorized")

	validAuthorization := invalidAuthorization
	validAuthorization.RequestID = "f1000000-0000-4000-8000-000000000003"
	validAuthorization.Authorization = authorization(seed.token)
	expectLiveDeviceIDError(t, seed.opened, validAuthorization, "internal_error")
	after := readLiveDeviceIDDurableState(t, seed.opened.db)
	assertLiveDeviceIDStateUnchanged(t, before, after)
}

func TestLiveDeviceIDBoundsRejectOversizedReplayAndReadRows(t *testing.T) {
	tests := []struct {
		name    string
		options boundedSeedOptions
		mutate  func(*testing.T, boundedPersistenceSeed, string)
		call    func(boundedPersistenceSeed) api.Request
	}{
		{
			name: "enrollment replay",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, corruptID string) {
				setLiveDeviceIDForeignKeys(t, seed.opened.db, false)
				if _, err := seed.opened.db.Exec("UPDATE enrollments SET device_id = ?", corruptID); err != nil {
					t.Fatal(err)
				}
				setLiveDeviceIDForeignKeys(t, seed.opened.db, true)
				assertNULSuffixPassedSQLiteLengthCheck(t, seed.opened.db, `
					SELECT length(device_id), octet_length(device_id), typeof(device_id) FROM enrollments`)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.enrollment },
		},
		{
			name:    "token rotation replay",
			options: boundedSeedOptions{rotation: true},
			mutate: func(t *testing.T, seed boundedPersistenceSeed, corruptID string) {
				if _, err := seed.opened.db.Exec("UPDATE token_rotations SET device_id = ?", corruptID); err != nil {
					t.Fatal(err)
				}
				assertNULSuffixPassedSQLiteLengthCheck(t, seed.opened.db, `
					SELECT length(device_id), octet_length(device_id), typeof(device_id) FROM token_rotations`)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.rotation },
		},
		{
			name:    "retired self revocation lookup",
			options: boundedSeedOptions{self: true},
			mutate: func(t *testing.T, seed boundedPersistenceSeed, corruptID string) {
				if _, err := seed.opened.db.Exec("UPDATE self_revocation_receipts SET device_id = ?", corruptID); err != nil {
					t.Fatal(err)
				}
				assertNULSuffixPassedSQLiteLengthCheck(t, seed.opened.db, `
					SELECT length(device_id), octet_length(device_id), typeof(device_id) FROM self_revocation_receipts`)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.selfRevocation },
		},
		{
			name: "snapshot page owner",
			mutate: func(t *testing.T, seed boundedPersistenceSeed, corruptID string) {
				if _, err := seed.opened.db.Exec("UPDATE snapshots SET owner_device_id = ? WHERE snapshot_id = ?", corruptID, seed.snapshot.SnapshotID); err != nil {
					t.Fatal(err)
				}
				assertNULSuffixPassedSQLiteLengthCheck(t, seed.opened.db, `
					SELECT length(owner_device_id), octet_length(owner_device_id), typeof(owner_device_id)
					FROM snapshots WHERE snapshot_id = ?`, seed.snapshot.SnapshotID)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.snapshotPage },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, test.options)
			defer seed.opened.Close()
			corruptID := oversizedNULSuffixedDeviceID(seed.deviceID)
			test.mutate(t, seed, corruptID)
			before := readLiveDeviceIDDurableState(t, seed.opened.db)
			expectLiveDeviceIDError(t, seed.opened, test.call(seed), "internal_error")
			after := readLiveDeviceIDDurableState(t, seed.opened.db)
			assertLiveDeviceIDStateUnchanged(t, before, after)
		})
	}
}

func TestSnapshotPlanBoundsOversizedSourceDeviceID(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	corruptID := oversizedNULSuffixedDeviceID(seed.deviceID)
	setLiveDeviceIDForeignKeys(t, seed.opened.db, false)
	if _, err := seed.opened.db.Exec("UPDATE devices SET device_id = ? WHERE device_id = ?", corruptID, seed.deviceID); err != nil {
		t.Fatal(err)
	}
	setLiveDeviceIDForeignKeys(t, seed.opened.db, true)
	assertNULSuffixPassedSQLiteLengthCheck(t, seed.opened.db, `
		SELECT length(device_id), octet_length(device_id), typeof(device_id) FROM devices`)

	before := readLiveDeviceIDDurableState(t, seed.opened.db)
	transaction, err := seed.opened.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	_, _, protocolErr := buildSnapshotPlan(
		context.Background(), transaction,
		"f2000000-0000-4000-8000-000000000001", seed.deviceID,
		"f2000000-0000-4000-8000-000000000002", 3, 1, 1<<62,
	)
	if protocolErr == nil || protocolErr.Code != "internal_error" {
		t.Fatalf("corrupt snapshot source error=%v", protocolErr)
	}
	if err := transaction.Rollback(); err != nil && err != sql.ErrTxDone {
		t.Fatal(err)
	}
	after := readLiveDeviceIDDurableState(t, seed.opened.db)
	assertLiveDeviceIDStateUnchanged(t, before, after)
}

func TestLiveDeviceIDBoundRejectsExactLengthNonCanonicalOwner(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	invalidOwner := "z2000000-0000-4000-8000-000000000001"
	if len(invalidOwner) != maxUUIDBytes {
		t.Fatalf("invalid owner length=%d", len(invalidOwner))
	}
	if _, err := seed.opened.db.Exec(
		"UPDATE snapshots SET owner_device_id = ? WHERE snapshot_id = ?", invalidOwner, seed.snapshot.SnapshotID,
	); err != nil {
		t.Fatal(err)
	}
	before := readLiveDeviceIDDurableState(t, seed.opened.db)
	expectLiveDeviceIDError(t, seed.opened, seed.snapshotPage, "internal_error")
	after := readLiveDeviceIDDurableState(t, seed.opened.db)
	assertLiveDeviceIDStateUnchanged(t, before, after)
}

func TestLiveTextBoundsRejectNULSuffixedScopes(t *testing.T) {
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	corruptScopes := oversizedNULSuffixedText(string(wantScopes))
	t.Run("device authentication and direct read", func(t *testing.T) {
		seed := seedBoundedPersistence(t, boundedSeedOptions{})
		defer seed.opened.Close()
		if _, err := seed.opened.db.Exec("UPDATE devices SET scopes_json = ? WHERE device_id = ?", corruptScopes, seed.deviceID); err != nil {
			t.Fatal(err)
		}
		assertNULSuffixPassedSQLiteTextLengthCheck(t, seed.opened.db, len(wantScopes), `
			SELECT length(scopes_json), octet_length(scopes_json), typeof(scopes_json)
			FROM devices WHERE device_id = ?`, seed.deviceID)
		before := readLiveDeviceIDDurableState(t, seed.opened.db)
		expectLiveDeviceIDError(t, seed.opened, api.Request{
			Method: "GET", Path: "/v1/devices", RequestID: "f2100000-0000-4000-8000-000000000001",
			Authorization: authorization(seed.token), Now: protocolFixtureTime,
		}, "internal_error")
		if _, _, protocolErr := readDevice(context.Background(), seed.opened.db, seed.deviceID); protocolErr == nil || protocolErr.Code != "internal_error" {
			t.Fatalf("corrupt direct device read error=%v", protocolErr)
		}
		after := readLiveDeviceIDDurableState(t, seed.opened.db)
		assertLiveDeviceIDStateUnchanged(t, before, after)
	})

	t.Run("enrollment replay", func(t *testing.T) {
		seed := seedBoundedPersistence(t, boundedSeedOptions{})
		defer seed.opened.Close()
		if _, err := seed.opened.db.Exec("UPDATE enrollments SET scopes_json = ?", corruptScopes); err != nil {
			t.Fatal(err)
		}
		assertNULSuffixPassedSQLiteTextLengthCheck(t, seed.opened.db, len(wantScopes), `
			SELECT length(scopes_json), octet_length(scopes_json), typeof(scopes_json) FROM enrollments`)
		before := readLiveDeviceIDDurableState(t, seed.opened.db)
		expectLiveDeviceIDError(t, seed.opened, seed.enrollment, "internal_error")
		after := readLiveDeviceIDDurableState(t, seed.opened.db)
		assertLiveDeviceIDStateUnchanged(t, before, after)
	})
}

func TestLiveIdentifierBoundsRejectNULSuffixedReplayRows(t *testing.T) {
	tests := []struct {
		name    string
		options boundedSeedOptions
		mutate  func(*testing.T, boundedPersistenceSeed)
		call    func(boundedPersistenceSeed) api.Request
	}{
		{
			name:    "self revocation request ID",
			options: boundedSeedOptions{self: true},
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				corrupt := oversizedNULSuffixedText("e1000000-0000-4000-8000-00000000000c")
				if _, err := seed.opened.db.Exec("UPDATE self_revocation_receipts SET request_id = ?", corrupt); err != nil {
					t.Fatal(err)
				}
				assertNULSuffixPassedSQLiteLengthCheck(t, seed.opened.db, `
					SELECT length(request_id), octet_length(request_id), typeof(request_id) FROM self_revocation_receipts`)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.selfRevocation },
		},
		{
			name: "consumed enrollment ID",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				corrupt := oversizedNULSuffixedText("e1000000-0000-4000-8000-000000000002")
				if _, err := seed.opened.db.Exec("UPDATE enrollment_grants SET consumed_enrollment_id = ? WHERE consumed_enrollment_id IS NOT NULL", corrupt); err != nil {
					t.Fatal(err)
				}
				assertNULSuffixPassedSQLiteLengthCheck(t, seed.opened.db, `
					SELECT length(consumed_enrollment_id), octet_length(consumed_enrollment_id), typeof(consumed_enrollment_id)
					FROM enrollment_grants WHERE consumed_enrollment_id IS NOT NULL`)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.enrollment },
		},
		{
			name: "snapshot create replay ID",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				corrupt := oversizedNULSuffixedText(seed.snapshot.SnapshotID)
				setLiveDeviceIDForeignKeys(t, seed.opened.db, false)
				if _, err := seed.opened.db.Exec("UPDATE snapshots SET snapshot_id = ? WHERE snapshot_id = ?", corrupt, seed.snapshot.SnapshotID); err != nil {
					t.Fatal(err)
				}
				setLiveDeviceIDForeignKeys(t, seed.opened.db, true)
				assertNULSuffixPassedSQLiteLengthCheck(t, seed.opened.db, `
					SELECT length(snapshot_id), octet_length(snapshot_id), typeof(snapshot_id) FROM snapshots`)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.snapshotCreate },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, test.options)
			defer seed.opened.Close()
			test.mutate(t, seed)
			before := readLiveDeviceIDDurableState(t, seed.opened.db)
			expectLiveDeviceIDError(t, seed.opened, test.call(seed), "internal_error")
			after := readLiveDeviceIDDurableState(t, seed.opened.db)
			assertLiveDeviceIDStateUnchanged(t, before, after)
		})
	}
}

func TestStartBootAndPruneBoundSnapshotIDsBeforeScan(t *testing.T) {
	corruptSnapshotID := func(t *testing.T, seed boundedPersistenceSeed) {
		t.Helper()
		corrupt := oversizedNULSuffixedText(seed.snapshot.SnapshotID)
		setLiveDeviceIDForeignKeys(t, seed.opened.db, false)
		if _, err := seed.opened.db.Exec("UPDATE snapshots SET snapshot_id = ? WHERE snapshot_id = ?", corrupt, seed.snapshot.SnapshotID); err != nil {
			t.Fatal(err)
		}
		setLiveDeviceIDForeignKeys(t, seed.opened.db, true)
		assertNULSuffixPassedSQLiteLengthCheck(t, seed.opened.db, `
			SELECT length(snapshot_id), octet_length(snapshot_id), typeof(snapshot_id) FROM snapshots`)
	}

	t.Run("start boot", func(t *testing.T) {
		seed := seedBoundedPersistence(t, boundedSeedOptions{})
		defer seed.opened.Close()
		corruptSnapshotID(t, seed)
		before := readLiveDeviceIDDurableState(t, seed.opened.db)
		if err := seed.opened.StartBoot(context.Background()); err == nil {
			t.Fatal("StartBoot accepted corrupt snapshot ID")
		}
		after := readLiveDeviceIDDurableState(t, seed.opened.db)
		assertLiveDeviceIDStateUnchanged(t, before, after)
	})

	t.Run("prune", func(t *testing.T) {
		seed := seedBoundedPersistence(t, boundedSeedOptions{})
		defer seed.opened.Close()
		corruptSnapshotID(t, seed)
		before := readLiveDeviceIDDurableState(t, seed.opened.db)
		transaction, err := seed.opened.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if protocolErr := seed.opened.pruneExpiredSnapshots(context.Background(), transaction, protocolFixtureTime); protocolErr == nil || protocolErr.Code != "internal_error" {
			transaction.Rollback()
			t.Fatalf("corrupt snapshot prune error=%v", protocolErr)
		}
		if err := transaction.Rollback(); err != nil {
			t.Fatal(err)
		}
		after := readLiveDeviceIDDurableState(t, seed.opened.db)
		assertLiveDeviceIDStateUnchanged(t, before, after)
	})
}

func TestSnapshotReferenceAndHeadIdentifiersAreBoundBeforeScan(t *testing.T) {
	t.Run("snapshot revision reference", func(t *testing.T) {
		seed := seedBoundedPersistence(t, boundedSeedOptions{})
		defer seed.opened.Close()
		corrupt := oversizedNULSuffixedText(seed.revisionID)
		if _, err := seed.opened.db.Exec("UPDATE snapshot_revision_refs SET revision_id = ?", corrupt); err != nil {
			t.Fatal(err)
		}
		assertNULSuffixPassedSQLiteLengthCheck(t, seed.opened.db, `
			SELECT length(revision_id), octet_length(revision_id), typeof(revision_id) FROM snapshot_revision_refs`)
		before := readLiveDeviceIDDurableState(t, seed.opened.db)
		transaction, err := seed.opened.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if protocolErr := deleteSnapshotAndReleaseObjects(context.Background(), transaction, seed.snapshot.SnapshotID); protocolErr == nil || protocolErr.Code != "internal_error" {
			transaction.Rollback()
			t.Fatalf("corrupt snapshot reference error=%v", protocolErr)
		}
		if err := transaction.Rollback(); err != nil {
			t.Fatal(err)
		}
		after := readLiveDeviceIDDurableState(t, seed.opened.db)
		assertLiveDeviceIDStateUnchanged(t, before, after)
	})

	for _, column := range []string{"record_id", "revision_id"} {
		t.Run(column, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{})
			defer seed.opened.Close()
			corrupt := oversizedNULSuffixedText(seed.recordID)
			if column == "record_id" {
				if _, err := seed.opened.db.Exec("UPDATE record_revisions SET record_id = ? WHERE revision_id = ?", corrupt, seed.revisionID); err != nil {
					t.Fatal(err)
				}
			} else {
				corrupt = oversizedNULSuffixedText(seed.revisionID)
				if _, err := seed.opened.db.Exec("UPDATE record_heads SET revision_id = ? WHERE revision_id = ?", corrupt, seed.revisionID); err != nil {
					t.Fatal(err)
				}
				if _, err := seed.opened.db.Exec("UPDATE record_revisions SET revision_id = ? WHERE revision_id = ?", corrupt, seed.revisionID); err != nil {
					t.Fatal(err)
				}
			}
			assertNULSuffixPassedSQLiteLengthCheck(t, seed.opened.db, fmt.Sprintf(`
				SELECT length(%[1]s), octet_length(%[1]s), typeof(%[1]s) FROM record_revisions`, column))
			before := readLiveDeviceIDDurableState(t, seed.opened.db)
			transaction, err := seed.opened.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			_, _, protocolErr := buildSnapshotPlan(context.Background(), transaction,
				"f2200000-0000-4000-8000-000000000001", seed.deviceID,
				"f2200000-0000-4000-8000-000000000002", 3, 1, 1<<62)
			if protocolErr == nil || protocolErr.Code != "internal_error" {
				transaction.Rollback()
				t.Fatalf("corrupt snapshot head %s error=%v", column, protocolErr)
			}
			if err := transaction.Rollback(); err != nil {
				t.Fatal(err)
			}
			after := readLiveDeviceIDDurableState(t, seed.opened.db)
			assertLiveDeviceIDStateUnchanged(t, before, after)
		})
	}
}

func TestEnrollmentConflictUsesScalarForOversizedRegistryID(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	requestDeviceID := "f3000000-0000-4000-8000-000000000001"
	requestToken := tokenWithByte(0xf3)
	tokenHash, err := auth.DeviceTokenHash(testIdentity.InstanceID, testIdentity.VaultID, requestDeviceID, requestToken)
	if err != nil {
		t.Fatal(err)
	}
	corruptID := oversizedNULSuffixedDeviceID("f3000000-0000-4000-8000-000000000002")
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	zero := EncodeUint64(0)
	if _, err := opened.db.Exec(`
		INSERT INTO devices (
			device_id, token_hash, scopes_json, created_at_ms,
			last_ack_cursor, max_author_counter
		) VALUES (?, ?, ?, ?, ?, ?)`,
		corruptID, tokenHash[:], string(wantScopes), protocolFixtureTime.UnixMilli(), zero[:], zero[:],
	); err != nil {
		t.Fatal(err)
	}
	assertNULSuffixPassedSQLiteLengthCheck(t, opened.db, `
		SELECT length(device_id), octet_length(device_id), typeof(device_id) FROM devices`)

	grant := createGrant(t, opened, protocolFixtureTime)
	defer clear(grant.Grant)
	enrollmentID := "f3000000-0000-4000-8000-000000000003"
	body, err := marshalJSON(enrollmentRequest{
		ProtocolVersion: "1", EnrollmentID: enrollmentID, DeviceID: requestDeviceID,
		DeviceToken: base64.RawURLEncoding.EncodeToString(requestToken), Scopes: auth.FixedScopes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	call := api.Request{
		Method: "POST", Path: "/v1/enrollments", RequestID: "f3000000-0000-4000-8000-000000000004",
		Authorization: "JAT-Enrollment " + base64.RawURLEncoding.EncodeToString(grant.Grant),
		Body:          body, Now: protocolFixtureTime,
	}
	before := readLiveDeviceIDDurableState(t, opened.db)
	expectLiveDeviceIDError(t, opened, call, "enrollment_replay_mismatch")
	after := readLiveDeviceIDDurableState(t, opened.db)
	assertLiveDeviceIDStateUnchanged(t, before, after)
	if after.enrollments != 0 || after.devices != 1 {
		t.Fatalf("conflict changed registry: devices=%d enrollments=%d", after.devices, after.enrollments)
	}
}

func TestEnrollmentDeviceExistenceUsesScalarForOversizedEnrollmentID(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	corruptEnrollmentID := oversizedNULSuffixedText("e1000000-0000-4000-8000-000000000002")
	if _, err := seed.opened.db.Exec("UPDATE enrollments SET enrollment_id = ?", corruptEnrollmentID); err != nil {
		t.Fatal(err)
	}
	assertNULSuffixPassedSQLiteLengthCheck(t, seed.opened.db, `
		SELECT length(enrollment_id), octet_length(enrollment_id), typeof(enrollment_id) FROM enrollments`)

	grant := createGrant(t, seed.opened, protocolFixtureTime.Add(time.Second))
	defer clear(grant.Grant)
	requestID := "f3100000-0000-4000-8000-000000000001"
	body, err := marshalJSON(enrollmentRequest{
		ProtocolVersion: "1", EnrollmentID: "f3100000-0000-4000-8000-000000000002", DeviceID: seed.deviceID,
		DeviceToken: base64.RawURLEncoding.EncodeToString(seed.token), Scopes: auth.FixedScopes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	call := api.Request{
		Method: "POST", Path: "/v1/enrollments", RequestID: requestID,
		Authorization: "JAT-Enrollment " + base64.RawURLEncoding.EncodeToString(grant.Grant), Body: body,
		Now: protocolFixtureTime.Add(time.Second),
	}
	before := readLiveDeviceIDDurableState(t, seed.opened.db)
	expectLiveDeviceIDError(t, seed.opened, call, "enrollment_replay_mismatch")
	after := readLiveDeviceIDDurableState(t, seed.opened.db)
	assertLiveDeviceIDStateUnchanged(t, before, after)
}

func TestNullableConsumedEnrollmentIDRejectsWrongStorageClass(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	writeLiveWrongTypeText(t, seed.opened.db, "enrollment_grants", `
		UPDATE enrollment_grants SET consumed_enrollment_id = zeroblob(?)
		WHERE consumed_enrollment_id IS NOT NULL`, maxUUIDBytes)
	var octets int64
	var storageClass string
	if err := seed.opened.db.QueryRow(`
		SELECT octet_length(consumed_enrollment_id), typeof(consumed_enrollment_id)
		FROM enrollment_grants WHERE consumed_enrollment_id IS NOT NULL`,
	).Scan(&octets, &storageClass); err != nil {
		t.Fatal(err)
	}
	if octets != maxUUIDBytes || storageClass != "blob" {
		t.Fatalf("wrong-type consumed ID shape: octets=%d typeof=%q", octets, storageClass)
	}
	before := readLiveDeviceIDDurableState(t, seed.opened.db)
	expectLiveDeviceIDError(t, seed.opened, seed.enrollment, "internal_error")
	after := readLiveDeviceIDDurableState(t, seed.opened.db)
	assertLiveDeviceIDStateUnchanged(t, before, after)
}

func TestLiveDeviceIDBoundsAcceptCanonicalRows(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{rotation: true})
	defer seed.opened.Close()

	if response, protocolErr := seed.opened.HandleAPI(context.Background(), seed.rotation); protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("canonical rotation replay: response=%+v error=%v", response, protocolErr)
	}
	seed.snapshotPage.Authorization = authorization(seed.token)
	if response, protocolErr := seed.opened.HandleAPI(context.Background(), seed.snapshotPage); protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("canonical snapshot page: response=%+v error=%v", response, protocolErr)
	}
}
