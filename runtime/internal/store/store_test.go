package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/auth"
)

var testIdentity = Identity{
	InstanceID: "00000000-0000-4000-8000-000000000001",
	VaultID:    "00000000-0000-4000-8000-000000000002",
}

func TestSQLiteEngineVersionIsFrozen(t *testing.T) {
	ctx := context.Background()
	opened, err := Open(ctx, filepath.Join(t.TempDir(), "server.db"), testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	var version string
	if err := opened.db.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != "3.51.3" {
		t.Fatalf("SQLite engine version = %q, want reviewed 3.51.3", version)
	}
}

func TestStorePersistsOnlyCredentialHash(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "server.db")
	store, err := Open(ctx, path, testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	token := []byte("0123456789abcdef0123456789abcdef")
	if len(token) != 32 {
		t.Fatalf("test token length = %d", len(token))
	}
	deviceID := "00000000-0000-4000-8000-000000000003"
	if err := store.CreateDevice(ctx, deviceID, token, auth.FixedScopes(), time.Unix(1_700_000_000, 123_000_000)); err != nil {
		t.Fatal(err)
	}
	hash, scopes, err := store.DeviceCredential(ctx, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	wantHash, err := auth.DeviceTokenHash(testIdentity.InstanceID, testIdentity.VaultID, deviceID, token)
	if err != nil {
		t.Fatal(err)
	}
	if hash != wantHash {
		t.Fatal("stored token hash does not match protocol hash")
	}
	if err := auth.ValidateScopes(scopes); err != nil {
		t.Fatal(err)
	}
	verified, err := store.VerifyDeviceToken(ctx, deviceID, token)
	if err != nil || !verified {
		t.Fatalf("stored device token did not verify: verified=%v err=%v", verified, err)
	}
	wrong := append([]byte(nil), token...)
	wrong[len(wrong)-1] ^= 1
	verified, err = store.VerifyDeviceToken(ctx, deviceID, wrong)
	if err != nil || verified {
		t.Fatalf("wrong device token result: verified=%v err=%v", verified, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	databaseBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(databaseBytes, token) {
		t.Fatal("SQLite file contains plaintext device token")
	}
}

func TestCreateDeviceIsLimitedToThePreActivationBaseline(t *testing.T) {
	ctx := context.Background()
	opened, err := Open(ctx, filepath.Join(t.TempDir(), "server.db"), testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := opened.CreateDevice(ctx, "00000000-0000-4000-8000-000000000003", tokenWithByte(0x31), auth.FixedScopes(), protocolFixtureTime); err != nil {
		t.Fatal(err)
	}
	if err := opened.StartBoot(ctx); err != nil {
		t.Fatal(err)
	}
	if err := opened.CreateDevice(ctx, "00000000-0000-4000-8000-000000000004", tokenWithByte(0x32), auth.FixedScopes(), protocolFixtureTime); err == nil {
		t.Fatal("post-activation baseline device creation succeeded")
	}
}

func TestStoreIdentityAndFutureSchemaFailClosed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "server.db")
	store, err := Open(ctx, path, testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	mismatch := testIdentity
	mismatch.VaultID = "00000000-0000-4000-8000-000000000004"
	if _, err := Open(ctx, path, mismatch); err != ErrIdentityMismatch {
		t.Fatalf("identity mismatch error = %v", err)
	}

	raw, err := sql.Open("sqlite3", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, "PRAGMA user_version = 2"); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, path, testIdentity); !errors.Is(err, ErrFutureSchema) {
		t.Fatalf("future schema error = %v", err)
	}
}

func TestValidateExistingIsReadOnlyAndRejectsForeignOrMalformedState(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "server.db")
	opened, err := Open(ctx, path, testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	beforeEntries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateExisting(ctx, path, testIdentity); err != nil {
		t.Fatalf("read-only validation: %v", err)
	}
	afterEntries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterEntries) != len(beforeEntries) || !bytes.Equal(after, before) {
		t.Fatalf("read-only validation mutated database tree: entries %d -> %d bytes_equal=%t", len(beforeEntries), len(afterEntries), bytes.Equal(after, before))
	}
	for index := range beforeEntries {
		if beforeEntries[index].Name() != afterEntries[index].Name() {
			t.Fatalf("read-only validation changed database entries: %q -> %q", beforeEntries[index].Name(), afterEntries[index].Name())
		}
	}

	mismatch := testIdentity
	mismatch.VaultID = "00000000-0000-4000-8000-000000000004"
	if err := ValidateExisting(ctx, path, mismatch); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("read-only identity mismatch error=%v", err)
	}

	raw, err := sql.Open("sqlite3", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, "PRAGMA ignore_check_constraints = ON; UPDATE runtime_state SET server_cursor = X'00' WHERE singleton = 1"); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ValidateExisting(ctx, path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) {
		t.Fatalf("read-only malformed-state error=%v", err)
	}

	missing := filepath.Join(root, "missing.db")
	if err := ValidateExisting(ctx, missing, testIdentity); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing read-only validation error=%v", err)
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only validation created missing database: %v", err)
	}
}

func TestValidateExistingRejectsClosedDatabaseSameMetadataContentRewrite(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "server.db")
	opened, err := Open(ctx, path, testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	originalInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	originalPayload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	foreignIdentity := testIdentity
	foreignIdentity.InstanceID = "00000000-0000-4000-8000-000000000005"
	foreignPath := filepath.Join(t.TempDir(), "server.db")
	foreign, err := Open(ctx, foreignPath, foreignIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if err := foreign.Close(); err != nil {
		t.Fatal(err)
	}
	foreignPayload, err := os.ReadFile(foreignPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(foreignPayload) != len(originalPayload) || bytes.Equal(foreignPayload, originalPayload) {
		t.Fatalf("foreign fixture bytes=%d original=%d equal=%t", len(foreignPayload), len(originalPayload), bytes.Equal(foreignPayload, originalPayload))
	}

	rewritten := false
	err = validateExisting(ctx, path, testIdentity, func() {
		file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
		if openErr != nil {
			t.Fatalf("open closed database rewrite: %v", openErr)
		}
		if _, writeErr := file.Write(foreignPayload); writeErr != nil {
			file.Close()
			t.Fatalf("rewrite closed database: %v", writeErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			t.Fatalf("close rewritten closed database: %v", closeErr)
		}
		if chtimesErr := os.Chtimes(path, originalInfo.ModTime(), originalInfo.ModTime()); chtimesErr != nil {
			t.Fatalf("restore closed database timestamp: %v", chtimesErr)
		}
		currentInfo, statErr := os.Lstat(path)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if !os.SameFile(originalInfo, currentInfo) || currentInfo.Size() != originalInfo.Size() ||
			!currentInfo.ModTime().Equal(originalInfo.ModTime()) {
			t.Fatalf("rewrite did not preserve inode/size/mtime: before=%+v after=%+v", originalInfo, currentInfo)
		}
		rewritten = true
	})
	if !rewritten {
		t.Fatal("closed-database rewrite hook did not run")
	}
	if err == nil || !strings.Contains(err.Error(), "contents changed during read-only validation") {
		t.Fatalf("closed-database same-metadata rewrite error=%v", err)
	}
	currentPayload, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(currentPayload, foreignPayload) {
		t.Fatal("closed-database rewrite fixture did not remain at the source path")
	}
}

func TestValidateExistingReadsProtectedActiveWALWithoutCreatingFiles(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "server.db")
	opened, err := Open(ctx, path, testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := opened.CreateDevice(ctx, "00000000-0000-4000-8000-000000000003", tokenWithByte(0x31), auth.FixedScopes(), protocolFixtureTime); err != nil {
		t.Fatal(err)
	}
	beforeEntries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(beforeEntries) != 3 {
		t.Fatalf("active WAL entries=%d want database/WAL/SHM", len(beforeEntries))
	}
	beforePayloads := make(map[string][]byte, len(beforeEntries))
	for _, entry := range beforeEntries {
		payload, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		beforePayloads[entry.Name()] = payload
	}
	if err := ValidateExisting(ctx, path, testIdentity); err != nil {
		t.Fatalf("validate active WAL read-only: %v", err)
	}
	afterEntries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterEntries) != len(beforeEntries) {
		t.Fatalf("active WAL validation changed entry count %d -> %d", len(beforeEntries), len(afterEntries))
	}
	for index := range beforeEntries {
		if beforeEntries[index].Name() != afterEntries[index].Name() {
			t.Fatalf("active WAL validation changed entry %q -> %q", beforeEntries[index].Name(), afterEntries[index].Name())
		}
		info, err := afterEntries[index].Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&^0o600 != 0 {
			t.Fatalf("active WAL validation broadened %s to %04o", afterEntries[index].Name(), info.Mode().Perm())
		}
		payload, err := os.ReadFile(filepath.Join(root, afterEntries[index].Name()))
		if err != nil {
			t.Fatal(err)
		}
		// SQLite read locking may update the ephemeral SHM wal-index while an
		// active writer exists. The database and committed WAL stay byte-exact.
		if afterEntries[index].Name() != "server.db-shm" && !bytes.Equal(payload, beforePayloads[afterEntries[index].Name()]) {
			t.Fatalf("active WAL validation changed %s contents", afterEntries[index].Name())
		}
	}
}

func TestValidateExistingRejectsActiveWALSidecarReplacementRace(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "server.db")
	opened, err := Open(ctx, path, testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := opened.CreateDevice(ctx, "00000000-0000-4000-8000-000000000004", tokenWithByte(0x41), auth.FixedScopes(), protocolFixtureTime); err != nil {
		t.Fatal(err)
	}
	databaseBefore, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	err = validateExisting(ctx, path, testIdentity, func() {
		for _, suffix := range []string{"-wal", "-shm"} {
			if removeErr := os.Remove(path + suffix); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				t.Fatalf("remove raced SQLite sidecar: %v", removeErr)
			}
		}
	})
	if err == nil {
		t.Fatal("active WAL sidecar replacement race was accepted")
	}
	databaseAfter, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(databaseAfter, databaseBefore) {
		t.Fatal("active WAL sidecar race changed the durable database file")
	}
}

func TestValidateExistingAcceptsExactResumableSchemaStatesWithoutMigratingSource(t *testing.T) {
	ctx := context.Background()
	for _, testCase := range []struct {
		name    string
		prepare func(*testing.T, string)
	}{
		{
			name: "empty database after protected-file creation",
			prepare: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "reviewed legacy schema",
			prepare: func(t *testing.T, path string) {
				t.Helper()
				raw, err := sql.Open("sqlite3", "file:"+path)
				if err != nil {
					t.Fatal(err)
				}
				for _, statement := range []string{createInstanceMetadataV1, createDevicesV1, "PRAGMA user_version = 1"} {
					if _, err := raw.ExecContext(ctx, statement); err != nil {
						raw.Close()
						t.Fatal(err)
					}
				}
				if _, err := raw.ExecContext(ctx, `
					INSERT INTO instance_metadata (
						singleton, instance_id, vault_id, protocol_major, storage_schema
					) VALUES (1, ?, ?, '1', '1')`, testIdentity.InstanceID, testIdentity.VaultID); err != nil {
					raw.Close()
					t.Fatal(err)
				}
				if err := raw.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "reviewed prior acceptance-origin schema",
			prepare: func(t *testing.T, path string) {
				t.Helper()
				opened, err := Open(ctx, path, testIdentity)
				if err != nil {
					t.Fatal(err)
				}
				dropRevisionAcceptanceOriginsForMigration(t, opened.db)
				if err := opened.Close(); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "reviewed prior full schema",
			prepare: func(t *testing.T, path string) {
				t.Helper()
				opened, err := Open(ctx, path, testIdentity)
				if err != nil {
					t.Fatal(err)
				}
				downgradeRecordRevisionsToPriorFullV1(t, opened.db)
				if err := opened.Close(); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "server.db")
			testCase.prepare(t, path)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			beforeEntries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateExisting(ctx, path, testIdentity); err != nil {
				t.Fatalf("validate resumable schema: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			afterEntries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) || len(afterEntries) != len(beforeEntries) {
				t.Fatalf("resumable validation migrated source: bytes_equal=%t entries=%d->%d", bytes.Equal(after, before), len(beforeEntries), len(afterEntries))
			}
		})
	}
}

func TestStoreRejectsUnexpectedOrIncompleteSchemas(t *testing.T) {
	ctx := context.Background()
	unrelatedPath := filepath.Join(t.TempDir(), "unrelated.db")
	unrelated, err := sql.Open("sqlite3", "file:"+unrelatedPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unrelated.ExecContext(ctx, "CREATE TABLE unrelated (value TEXT)"); err != nil {
		unrelated.Close()
		t.Fatal(err)
	}
	if err := unrelated.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unrelatedPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, unrelatedPath, testIdentity); !errors.Is(err, ErrUnexpectedSchema) {
		t.Fatalf("unrelated schema error = %v", err)
	}

	incompletePath := filepath.Join(t.TempDir(), "incomplete.db")
	opened, err := Open(ctx, incompletePath, testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := opened.db.ExecContext(ctx, "DROP TABLE devices"); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, incompletePath, testIdentity); !errors.Is(err, ErrUnexpectedSchema) {
		t.Fatalf("incomplete V1 schema error = %v", err)
	}
}

func TestFutureSchemaRejectedBeforeJournalModeMutation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "future.db")
	raw, err := sql.Open("sqlite3", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, "PRAGMA user_version = 2"); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	var journalMode string
	if err := raw.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if journalMode != "delete" {
		raw.Close()
		t.Fatalf("initial journal mode = %q", journalMode)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, path, testIdentity); !errors.Is(err, ErrFutureSchema) {
		t.Fatalf("future schema error = %v", err)
	}
	raw, err = sql.Open("sqlite3", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "delete" {
		t.Fatalf("rejected future database was mutated to journal mode %q", journalMode)
	}
}

func TestReadyRevalidatesCompleteSchema(t *testing.T) {
	ctx := context.Background()
	opened, err := Open(ctx, filepath.Join(t.TempDir(), "server.db"), testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if _, err := opened.db.ExecContext(ctx, "DROP TABLE devices"); err != nil {
		t.Fatal(err)
	}
	if err := opened.Ready(ctx); !errors.Is(err, ErrUnexpectedSchema) {
		t.Fatalf("readiness after schema truncation = %v", err)
	}
}

func TestOpenMigratesReviewedTask21SchemaWithoutChangingIdentityOrCredentials(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite3", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{createInstanceMetadataV1, createDevicesV1, "PRAGMA user_version = 1"} {
		if _, err := raw.ExecContext(ctx, statement); err != nil {
			raw.Close()
			t.Fatal(err)
		}
	}
	if _, err := raw.ExecContext(ctx, `
		INSERT INTO instance_metadata (
			singleton, instance_id, vault_id, protocol_major, storage_schema
		) VALUES (1, ?, ?, '1', '1')`, testIdentity.InstanceID, testIdentity.VaultID); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	deviceID := "00000000-0000-4000-8000-000000000003"
	preRevokedDeviceID := "00000000-0000-4000-8000-000000000004"
	token := tokenWithByte(0x42)
	hash, err := auth.DeviceTokenHash(testIdentity.InstanceID, testIdentity.VaultID, deviceID, token)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	scopes, _ := json.Marshal(auth.FixedScopes())
	zero := EncodeUint64(0)
	if _, err := raw.ExecContext(ctx, `
		INSERT INTO devices (
			device_id, token_hash, scopes_json, created_at_ms,
			last_ack_cursor, max_author_counter
		) VALUES (?, ?, ?, ?, ?, ?)`, deviceID, hash[:], string(scopes), time.Now().UTC().UnixMilli(), zero[:], zero[:]); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	preRevokedToken := tokenWithByte(0x43)
	preRevokedHash, err := auth.DeviceTokenHash(testIdentity.InstanceID, testIdentity.VaultID, preRevokedDeviceID, preRevokedToken)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	createdAt := time.Now().UTC().Add(-time.Second).UnixMilli()
	revokedAt := createdAt + 1
	if _, err := raw.ExecContext(ctx, `
		INSERT INTO devices (
			device_id, token_hash, scopes_json, created_at_ms, revoked_at_ms,
			last_ack_cursor, max_author_counter
		) VALUES (?, ?, ?, ?, ?, ?, ?)`, preRevokedDeviceID, preRevokedHash[:], string(scopes), createdAt, revokedAt, zero[:], zero[:]); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}

	opened, err := Open(ctx, path, testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := opened.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	verified, err := opened.VerifyDeviceToken(ctx, deviceID, token)
	if err != nil || !verified {
		t.Fatalf("migrated credential verified=%v error=%v", verified, err)
	}
	var runtimeRows, syncRows, enrollmentRows, changeRows int
	if err := opened.db.QueryRowContext(ctx, "SELECT count(*) FROM runtime_state").Scan(&runtimeRows); err != nil || runtimeRows != 1 {
		t.Fatalf("runtime rows=%d error=%v", runtimeRows, err)
	}
	if err := opened.db.QueryRowContext(ctx, "SELECT count(*) FROM device_sync_state").Scan(&syncRows); err != nil || syncRows != 2 {
		t.Fatalf("sync rows=%d error=%v", syncRows, err)
	}
	for _, expected := range []struct {
		deviceID        string
		baselineRevoked int
	}{{deviceID: deviceID}, {deviceID: preRevokedDeviceID, baselineRevoked: 1}} {
		var originKind string
		var originCursor, revokedCursor []byte
		var baselineRevoked int
		if err := opened.db.QueryRowContext(ctx, `
			SELECT origin_kind, created_cursor, revoked_cursor, baseline_revoked
			FROM device_origins WHERE device_id = ?`, expected.deviceID,
		).Scan(&originKind, &originCursor, &revokedCursor, &baselineRevoked); err != nil || originKind != "baseline" || originCursor != nil || revokedCursor != nil || baselineRevoked != expected.baselineRevoked {
			t.Fatalf("migrated origin %s: kind=%q cursor=%x revoked_cursor=%x baseline_revoked=%d error=%v", expected.deviceID, originKind, originCursor, revokedCursor, baselineRevoked, err)
		}
	}
	if err := opened.db.QueryRowContext(ctx, "SELECT count(*) FROM enrollments").Scan(&enrollmentRows); err != nil || enrollmentRows != 0 {
		t.Fatalf("migrated baseline enrollment rows=%d error=%v", enrollmentRows, err)
	}
	if err := opened.db.QueryRowContext(ctx, "SELECT count(*) FROM changes").Scan(&changeRows); err != nil || changeRows != 0 {
		t.Fatalf("migrated baseline change rows=%d error=%v", changeRows, err)
	}
	var cursorBytes, collectionGenerationBytes []byte
	if err := opened.db.QueryRowContext(ctx, "SELECT server_cursor, collection_generation FROM runtime_state WHERE singleton = 1").Scan(&cursorBytes, &collectionGenerationBytes); err != nil {
		t.Fatal(err)
	}
	if cursor, err := DecodeUint64(cursorBytes); err != nil || cursor != 0 {
		t.Fatalf("migrated baseline cursor=%d error=%v", cursor, err)
	}
	if generation, err := DecodeUint64(collectionGenerationBytes); err != nil || generation != 0 {
		t.Fatalf("migrated collection generation=%d error=%v", generation, err)
	}
	one := EncodeUint64(1)
	transaction, err := opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO change_origins (cursor, kind)
		VALUES (?, 'device_changed')`, one[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO changes (
			cursor, kind, received_at_ms, device_changed_id, device_change_kind
		) VALUES (?, 'device_changed', ?, ?, 'revoked')`, one[:], revokedAt, preRevokedDeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE runtime_state SET server_cursor = ? WHERE singleton = 1", one[:]); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := validatePersistentState(ctx, opened.db, testIdentity); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "device revocation change mismatch") {
		t.Fatalf("spurious migrated-baseline revocation error=%v", err)
	}
}

func TestLegacyMigrationRejectsMalformedDurableDeviceRows(t *testing.T) {
	for _, test := range []struct {
		name       string
		deviceID   string
		scopesJSON string
	}{
		{name: "non-UUID identifier", deviceID: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", scopesJSON: string(mustJSON(t, auth.FixedScopes()))},
		{name: "arbitrary scopes", deviceID: "00000000-0000-4000-8000-000000000003", scopesJSON: `["sync:read"]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "legacy.db")
			raw, err := sql.Open("sqlite3", "file:"+path)
			if err != nil {
				t.Fatal(err)
			}
			for _, statement := range []string{createInstanceMetadataV1, createDevicesV1, "PRAGMA user_version = 1"} {
				if _, err := raw.ExecContext(ctx, statement); err != nil {
					raw.Close()
					t.Fatal(err)
				}
			}
			if _, err := raw.ExecContext(ctx, `
				INSERT INTO instance_metadata (
					singleton, instance_id, vault_id, protocol_major, storage_schema
				) VALUES (1, ?, ?, '1', '1')`, testIdentity.InstanceID, testIdentity.VaultID); err != nil {
				raw.Close()
				t.Fatal(err)
			}
			zero := EncodeUint64(0)
			if _, err := raw.ExecContext(ctx, `
				INSERT INTO devices (
					device_id, token_hash, scopes_json, created_at_ms,
					last_ack_cursor, max_author_counter
				) VALUES (?, zeroblob(32), ?, ?, ?, ?)`, test.deviceID, test.scopesJSON, protocolFixtureTime.UnixMilli(), zero[:], zero[:]); err != nil {
				raw.Close()
				t.Fatal(err)
			}
			if err := raw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ValidateExisting(ctx, path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) {
				t.Fatalf("malformed legacy read-only validation error = %v", err)
			}
			if _, err := Open(ctx, path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) {
				t.Fatalf("malformed legacy row error = %v", err)
			}
		})
	}
}

func TestOpenAndReadyRejectFutureDeviceCursorState(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "server.db")
	opened, err := Open(ctx, path, testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "00000000-0000-4000-8000-000000000003"
	if err := opened.CreateDevice(ctx, deviceID, tokenWithByte(0x33), auth.FixedScopes(), protocolFixtureTime); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	future := EncodeUint64(1)
	if _, err := opened.db.ExecContext(ctx, "UPDATE device_sync_state SET max_returned_cursor = ? WHERE device_id = ?", future[:], deviceID); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	if err := opened.Ready(ctx); !errors.Is(err, ErrUnexpectedSchema) {
		opened.Close()
		t.Fatalf("readiness future cursor error = %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) {
		t.Fatalf("startup future cursor error = %v", err)
	}
}

func TestOpenRejectsDeviceCounterAheadOfAcceptedHistory(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "server.db")
	opened, err := Open(ctx, path, testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "00000000-0000-4000-8000-000000000003"
	if err := opened.CreateDevice(ctx, deviceID, tokenWithByte(0x34), auth.FixedScopes(), protocolFixtureTime); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	one := EncodeUint64(1)
	if _, err := opened.db.ExecContext(ctx, "UPDATE devices SET max_author_counter = ? WHERE device_id = ?", one[:], deviceID); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) {
		t.Fatalf("future author counter error = %v", err)
	}
}

func TestReadyCostDoesNotScaleWithReceiptHistory(t *testing.T) {
	ctx := context.Background()
	opened, err := Open(ctx, filepath.Join(t.TempDir(), "server.db"), testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	transaction, err := opened.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	zero := EncodeUint64(0)
	for index := 0; index < 20_000; index++ {
		requestID := fmt.Sprintf("%08x-0000-4000-8000-%012x", index+1, index+1)
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO operation_receipts (
				device_id, operation, request_id, request_fingerprint,
				response_status, response_json, created_at_ms, created_uptime_ms
			) VALUES (?, 'sync', ?, zeroblob(32), 200, ?, ?, ?)`,
			"00000000-0000-4000-8000-000000000003", requestID, []byte("{}"), protocolFixtureTime.UnixMilli(), zero[:]); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	readyContext, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	if err := opened.Ready(readyContext); err != nil {
		t.Fatalf("bounded readiness with large receipt history: %v", err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestStoreRejectsSymlinkHardLinkAndCorruption(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	target := filepath.Join(root, "target.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked.db")
	if err := os.Link(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, link, testIdentity); err == nil {
		t.Fatal("hard-linked database unexpectedly accepted")
	}
	symlink := filepath.Join(root, "symlink.db")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, symlink, testIdentity); err == nil {
		t.Fatal("symlinked database unexpectedly accepted")
	}
	corrupt := filepath.Join(root, "corrupt.db")
	if err := os.WriteFile(corrupt, []byte("not sqlite"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, corrupt, testIdentity); err == nil {
		t.Fatal("corrupt database unexpectedly accepted")
	}
}

func TestCanonicalUint64StoragePreservesUnsignedOrderAndBounds(t *testing.T) {
	values := []uint64{0, 1, math.MaxInt64, 1 << 63, math.MaxUint64}
	var previous [8]byte
	for index, value := range values {
		encoded := EncodeUint64(value)
		decoded, err := DecodeUint64(encoded[:])
		if err != nil {
			t.Fatal(err)
		}
		if decoded != value {
			t.Fatalf("round trip %d -> %d", value, decoded)
		}
		if index > 0 && bytes.Compare(previous[:], encoded[:]) >= 0 {
			t.Fatalf("encoding does not preserve unsigned order at %d", value)
		}
		previous = encoded
	}
	if _, err := DecodeUint64(make([]byte, 7)); err == nil {
		t.Fatal("short uint64 encoding unexpectedly accepted")
	}
}
