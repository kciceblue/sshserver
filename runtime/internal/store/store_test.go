package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"math"
	"os"
	"path/filepath"
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
