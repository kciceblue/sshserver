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

type Identity struct {
	InstanceID string
	VaultID    string
}

type Store struct {
	db       *sql.DB
	identity Identity
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
	store := &Store{db: database, identity: identity}
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
	_, err = store.db.ExecContext(
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
	return nil
}

func (store *Store) DeviceCredential(ctx context.Context, deviceID string) (hash [32]byte, scopes []string, err error) {
	if _, err := uuidv4.Parse(deviceID); err != nil {
		return hash, nil, fmt.Errorf("device ID: %w", err)
	}
	var hashBytes []byte
	var scopesJSON string
	if err := store.db.QueryRowContext(
		ctx,
		"SELECT token_hash, scopes_json FROM devices WHERE device_id = ?",
		deviceID,
	).Scan(&hashBytes, &scopesJSON); err != nil {
		return hash, nil, err
	}
	if len(hashBytes) != len(hash) {
		return hash, nil, errors.New("stored token hash has invalid length")
	}
	copy(hash[:], hashBytes)
	if err := json.Unmarshal([]byte(scopesJSON), &scopes); err != nil {
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
	if _, err := validateSchemaState(ctx, store.db); err != nil {
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
	userVersion, err := validateSchemaState(ctx, transaction)
	if err != nil {
		return err
	}
	createdSchema := userVersion == 0
	if userVersion == 0 {
		if err := createSchemaV1(ctx, transaction); err != nil {
			return err
		}
		if version, err := validateSchemaState(ctx, transaction); err != nil {
			return err
		} else if version != SchemaVersion {
			return ErrUnexpectedSchema
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
	if err := validateIdentity(ctx, transaction, store.identity); err != nil {
		return err
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit schema transaction: %w", err)
	}
	return nil
}

type schemaQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type schemaObject struct {
	typeName  string
	name      string
	tableName string
	sql       string
}

var schemaV1Objects = [...]schemaObject{
	{typeName: "index", name: "sqlite_autoindex_devices_1", tableName: "devices"},
	{typeName: "index", name: "sqlite_autoindex_devices_2", tableName: "devices"},
	{typeName: "table", name: "devices", tableName: "devices", sql: createDevicesV1},
	{typeName: "table", name: "instance_metadata", tableName: "instance_metadata", sql: createInstanceMetadataV1},
}

func validateSchemaState(ctx context.Context, database schemaQueryer) (int, error) {
	var userVersion int
	if err := database.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion); err != nil {
		return 0, fmt.Errorf("read storage schema: %w", err)
	}
	if userVersion > SchemaVersion {
		return userVersion, ErrFutureSchema
	}
	if userVersion < 0 {
		return userVersion, errors.New("invalid negative storage schema")
	}
	if userVersion == 0 {
		var objectCount int
		if err := database.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema").Scan(&objectCount); err != nil {
			return userVersion, fmt.Errorf("inspect empty storage schema: %w", err)
		}
		if objectCount != 0 {
			return userVersion, ErrUnexpectedSchema
		}
		return userVersion, nil
	}
	if err := validateSchemaV1(ctx, database); err != nil {
		return userVersion, err
	}
	return userVersion, nil
}

func validateSchemaV1(ctx context.Context, database schemaQueryer) error {
	rows, err := database.QueryContext(ctx, `
		SELECT type, name, tbl_name, coalesce(sql, '')
		FROM sqlite_schema ORDER BY type, name, tbl_name`)
	if err != nil {
		return fmt.Errorf("inspect V1 storage schema: %w", err)
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		if index >= len(schemaV1Objects) {
			return ErrUnexpectedSchema
		}
		var actual schemaObject
		if err := rows.Scan(&actual.typeName, &actual.name, &actual.tableName, &actual.sql); err != nil {
			return fmt.Errorf("read V1 storage schema: %w", err)
		}
		if actual != schemaV1Objects[index] {
			return ErrUnexpectedSchema
		}
		index++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read V1 storage schema: %w", err)
	}
	if index != len(schemaV1Objects) {
		return ErrUnexpectedSchema
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

func createSchemaV1(ctx context.Context, transaction *sql.Tx) error {
	statements := []string{
		createInstanceMetadataV1,
		createDevicesV1,
		fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion),
	}
	for _, statement := range statements {
		if _, err := transaction.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create storage schema: %w", err)
		}
	}
	return nil
}
