// Package store implements the server's opaque SQLite persistence boundary.
// It stores credential hashes and synchronization metadata, never plaintext
// credentials, vault keys, private keys, or decrypted application payloads.
package store

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/auth"
	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/uuidv4"
	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

const SchemaVersion = 1

var (
	ErrIdentityMismatch = errors.New("database instance identity does not match config")
	ErrFutureSchema     = errors.New("database storage schema is newer than this binary")
	ErrUnexpectedSchema = errors.New("database storage schema does not match reviewed V1 schema")
)

type Identity struct {
	InstanceID string
	VaultID    string
}

type Store struct {
	db        *sql.DB
	identity  Identity
	ephemeral *ephemeralState
}

func Open(ctx context.Context, path string, identity Identity) (*Store, error) {
	if _, err := uuidv4.Parse(identity.InstanceID); err != nil {
		return nil, fmt.Errorf("instance ID: %w", err)
	}
	if _, err := uuidv4.Parse(identity.VaultID); err != nil {
		return nil, fmt.Errorf("vault ID: %w", err)
	}
	if identity.InstanceID == identity.VaultID {
		return nil, errors.New("instance and vault IDs must differ")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("database path must be absolute")
	}
	if err := config.PrepareProtectedFile(path, 0o600); err != nil {
		return nil, fmt.Errorf("prepare database file: %w", err)
	}
	if err := validateSQLiteFiles(path); err != nil {
		return nil, err
	}

	dsnURL := &url.URL{Scheme: "file", Path: path}
	query := dsnURL.Query()
	for _, pragma := range []string{
		"busy_timeout(5000)",
		"foreign_keys(1)",
		"trusted_schema(0)",
	} {
		query.Add("_pragma", pragma)
	}
	dsnURL.RawQuery = query.Encode()
	database, err := sql.Open("sqlite3", dsnURL.String())
	if err != nil {
		return nil, fmt.Errorf("open SQLite: %w", err)
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	store := &Store{db: database, identity: identity, ephemeral: newEphemeralState()}
	if err := store.initialize(ctx); err != nil {
		if closeErr := database.Close(); closeErr != nil {
			return nil, errors.Join(err, fmt.Errorf("close SQLite after initialization failure: %w", closeErr))
		}
		return nil, err
	}
	if err := restrictSQLiteFiles(path); err != nil {
		if closeErr := database.Close(); closeErr != nil {
			return nil, errors.Join(err, fmt.Errorf("close SQLite after protection failure: %w", closeErr))
		}
		return nil, err
	}
	return store, nil
}

func (store *Store) Close() error {
	return store.db.Close()
}

func (store *Store) Ready(ctx context.Context) error {
	version, err := validateSchemaState(ctx, store.db)
	if err != nil {
		return fmt.Errorf("database readiness: %w", err)
	}
	if version != SchemaVersion {
		return fmt.Errorf("database readiness: %w", ErrUnexpectedSchema)
	}
	if err := validateIdentity(ctx, store.db, store.identity); err != nil {
		return fmt.Errorf("database readiness: %w", err)
	}
	serverCursor, envelopeGeneration, secretGeneration, err := validatePersistentRuntime(ctx, store.db)
	if err != nil {
		return fmt.Errorf("database readiness: %w", err)
	}
	// The device registry is capped at 64 rows by the V1 protocol, so this is a
	// bounded health sentinel. Full revision, receipt, and snapshot graph
	// validation runs once during Open; repeating those unbounded scans on the
	// unauthenticated health endpoint would make vault size a health-check DoS.
	if err := validateReadinessDevices(ctx, store.db, serverCursor); err != nil {
		return fmt.Errorf("database readiness: %w", err)
	}
	if err := validatePersistentEnvelope(ctx, store.db, store.identity, envelopeGeneration, secretGeneration); err != nil {
		return fmt.Errorf("database readiness: %w", err)
	}
	return nil
}

// CreateDevice persists only the domain-separated token hash and the exact
// fixed scope set. The caller's plaintext token is never written to SQLite.
func (store *Store) CreateDevice(ctx context.Context, deviceID string, token []byte, scopes []string, createdAt time.Time) error {
	if _, err := uuidv4.Parse(deviceID); err != nil {
		return fmt.Errorf("device ID: %w", err)
	}
	if err := auth.ValidateScopes(scopes); err != nil {
		return err
	}
	hash, err := auth.DeviceTokenHash(store.identity.InstanceID, store.identity.VaultID, deviceID, token)
	if err != nil {
		return err
	}
	canonicalScopes, err := json.Marshal(auth.FixedScopes())
	if err != nil {
		return fmt.Errorf("encode scopes: %w", err)
	}
	createdAt = createdAt.UTC().Truncate(time.Millisecond)
	zero := EncodeUint64(0)
	transaction, err := store.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin create device: %w", err)
	}
	defer transaction.Rollback()
	_, err = transaction.ExecContext(
		ctx,
		`INSERT INTO devices (
			device_id, token_hash, scopes_json, created_at_ms,
			last_ack_cursor, max_author_counter
		) VALUES (?, ?, ?, ?, ?, ?)`,
		deviceID,
		hash[:],
		string(canonicalScopes),
		createdAt.UnixMilli(),
		zero[:],
		zero[:],
	)
	if err != nil {
		return fmt.Errorf("create device: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, "INSERT INTO device_sync_state (device_id, max_returned_cursor) VALUES (?, ?)", deviceID, zero[:]); err != nil {
		return fmt.Errorf("create device sync state: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit create device: %w", err)
	}
	return nil
}

func (store *Store) DeviceCredential(ctx context.Context, deviceID string) (hash [32]byte, scopes []string, err error) {
	if _, err := uuidv4.Parse(deviceID); err != nil {
		return hash, nil, fmt.Errorf("device ID: %w", err)
	}
	var hashBytes []byte
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	var scopesJSON sql.NullString
	var scopesLength int64
	if err := store.db.QueryRowContext(
		ctx,
		`SELECT token_hash, length(scopes_json),
		        CASE WHEN length(scopes_json) = ? THEN scopes_json END
		 FROM devices WHERE device_id = ?`,
		len(wantScopes), deviceID,
	).Scan(&hashBytes, &scopesLength, &scopesJSON); err != nil {
		return hash, nil, err
	}
	if len(hashBytes) != len(hash) || !boundedRequiredText(scopesLength, scopesJSON, len(wantScopes)) || scopesJSON.String != string(wantScopes) {
		return hash, nil, errors.New("stored device credential is invalid")
	}
	copy(hash[:], hashBytes)
	if err := json.Unmarshal([]byte(scopesJSON.String), &scopes); err != nil {
		return hash, nil, fmt.Errorf("decode stored scopes: %w", err)
	}
	if err := auth.ValidateScopes(scopes); err != nil {
		return hash, nil, fmt.Errorf("validate stored scopes: %w", err)
	}
	return hash, scopes, nil
}

// VerifyDeviceToken hashes a presented token under the device identity and
// compares it with the stored hash in constant time.
func (store *Store) VerifyDeviceToken(ctx context.Context, deviceID string, token []byte) (bool, error) {
	stored, _, err := store.DeviceCredential(ctx, deviceID)
	if err != nil {
		return false, err
	}
	computed, err := auth.DeviceTokenHash(store.identity.InstanceID, store.identity.VaultID, deviceID, token)
	if err != nil {
		return false, err
	}
	return auth.VerifyHash(stored, computed), nil
}

func EncodeUint64(value uint64) [8]byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return encoded
}

func DecodeUint64(value []byte) (uint64, error) {
	if len(value) != 8 {
		return 0, errors.New("canonical uint64 storage value must be 8 bytes")
	}
	return binary.BigEndian.Uint64(value), nil
}

func (store *Store) initialize(ctx context.Context) error {
	if err := store.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping SQLite: %w", err)
	}
	// Compatibility and the complete schema fingerprint are inspected before
	// WAL mode, because changing journal_mode would persistently mutate a
	// database that belongs to a newer or unexpected schema.
	initialKind, _, err := inspectSchemaState(ctx, store.db)
	if err != nil {
		return err
	}
	var journalMode string
	if err := store.db.QueryRowContext(ctx, "PRAGMA journal_mode = WAL").Scan(&journalMode); err != nil {
		return fmt.Errorf("enable SQLite WAL: %w", err)
	}
	if journalMode != "wal" {
		return fmt.Errorf("enable SQLite WAL: SQLite selected %q", journalMode)
	}
	if _, err := store.db.ExecContext(ctx, "PRAGMA synchronous = FULL"); err != nil {
		return fmt.Errorf("set SQLite durability: %w", err)
	}

	transaction, err := store.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin schema transaction: %w", err)
	}
	defer transaction.Rollback()
	kind, userVersion, err := inspectSchemaState(ctx, transaction)
	if err != nil {
		return err
	}
	if kind != initialKind {
		return ErrUnexpectedSchema
	}
	createdSchema := userVersion == 0
	if userVersion == 0 {
		if err := createSchemaV1(ctx, transaction); err != nil {
			return err
		}
	} else if kind == schemaLegacy {
		if err := migrateLegacySchemaV1(ctx, transaction); err != nil {
			return err
		}
	}

	if createdSchema {
		_, err = transaction.ExecContext(ctx, `
			INSERT INTO instance_metadata (
				singleton, instance_id, vault_id, protocol_major, storage_schema
			) VALUES (1, ?, ?, '1', '1')`,
			store.identity.InstanceID,
			store.identity.VaultID,
		)
		if err != nil {
			return fmt.Errorf("initialize instance metadata: %w", err)
		}
	}
	if createdSchema || kind == schemaLegacy {
		zero := EncodeUint64(0)
		one := EncodeUint64(1)
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO runtime_state (
				singleton, server_cursor, cursor_floor, envelope_generation,
				instance_secret_generation, accumulated_uptime_ms, active_boot_id,
				collection_scan_after_record_id
			) VALUES (1, ?, ?, ?, ?, ?, NULL, '')`, zero[:], zero[:], zero[:], one[:], zero[:]); err != nil {
			return fmt.Errorf("initialize runtime state: %w", err)
		}
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO device_sync_state (device_id, max_returned_cursor)
			SELECT device_id, ? FROM devices`, zero[:]); err != nil {
			return fmt.Errorf("initialize device sync state: %w", err)
		}
	}
	if _, version, err := inspectSchemaState(ctx, transaction); err != nil {
		return err
	} else if version != SchemaVersion {
		return ErrUnexpectedSchema
	}
	if err := validateIdentity(ctx, transaction, store.identity); err != nil {
		return err
	}
	if err := validatePersistentState(ctx, transaction, store.identity); err != nil {
		return fmt.Errorf("validate persistent state: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit schema transaction: %w", err)
	}
	return nil
}

func validateIdentity(ctx context.Context, database schemaQueryer, expected Identity) error {
	var stored Identity
	var protocolMajor, storageSchema string
	if err := database.QueryRowContext(ctx, `
		SELECT instance_id, vault_id, protocol_major, storage_schema
		FROM instance_metadata WHERE singleton = 1`,
	).Scan(&stored.InstanceID, &stored.VaultID, &protocolMajor, &storageSchema); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrIdentityMismatch
		}
		return fmt.Errorf("read instance metadata: %w", err)
	}
	if stored != expected || protocolMajor != "1" || storageSchema != "1" {
		return ErrIdentityMismatch
	}
	return nil
}

func validateSQLiteFiles(path string) error {
	for _, candidate := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if err := config.ValidateProtectedFile(candidate, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("validate SQLite file %s: %w", filepath.Base(candidate), err)
		}
	}
	return nil
}

func restrictSQLiteFiles(path string) error {
	for _, candidate := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		if err := config.RestrictProtectedFile(candidate, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("protect SQLite file %s: %w", filepath.Base(candidate), err)
		}
	}
	return nil
}
