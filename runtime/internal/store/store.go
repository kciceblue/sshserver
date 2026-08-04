// Package store implements the server's opaque SQLite persistence boundary.
// It stores credential hashes and synchronization metadata, never plaintext
// credentials, vault keys, private keys, or decrypted application payloads.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/auth"
	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/uuidv4"
	sqliteDriver "github.com/ncruces/go-sqlite3/driver"
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

type closedDatabaseValidationSnapshot struct {
	source     *os.File
	sourceInfo os.FileInfo
	root       string
	path       string
	bytes      int64
	digest     [sha256.Size]byte
}

func captureClosedDatabaseValidationSnapshot(path string) (_ *closedDatabaseValidationSnapshot, returnErr error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open closed SQLite database for validation snapshot: %w", err)
	}
	source := os.NewFile(uintptr(fd), path)
	if source == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("wrap closed SQLite validation source descriptor")
	}
	keepSource := false
	defer func() {
		if !keepSource {
			if closeErr := source.Close(); closeErr != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("close closed SQLite validation source: %w", closeErr))
			}
		}
	}()
	sourceInfo, err := source.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat closed SQLite validation source: %w", err)
	}
	if err := validateClosedDatabaseDescriptor(sourceInfo); err != nil {
		return nil, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("recheck closed SQLite validation source path: %w", err)
	}
	if !os.SameFile(sourceInfo, pathInfo) {
		return nil, errors.New("closed SQLite validation source was replaced while opening it")
	}

	root, err := os.MkdirTemp("", "jat-store-closed-validation-")
	if err != nil {
		return nil, fmt.Errorf("create private closed-database validation directory: %w", err)
	}
	keepRoot := false
	defer func() {
		if !keepRoot {
			if removeErr := os.RemoveAll(root); removeErr != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("remove private closed-database validation directory: %w", removeErr))
			}
		}
	}()
	snapshotPath := filepath.Join(root, "server.db")
	destination, err := os.OpenFile(snapshotPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create closed SQLite validation snapshot: %w", err)
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(destination, hasher), source)
	closeErr := destination.Close()
	if copyErr != nil {
		copyErr = fmt.Errorf("copy closed SQLite validation snapshot: %w", copyErr)
	}
	if closeErr != nil {
		closeErr = fmt.Errorf("close closed SQLite validation snapshot: %w", closeErr)
	}
	if err := errors.Join(copyErr, closeErr); err != nil {
		return nil, err
	}
	afterCopy, err := source.Stat()
	if err != nil {
		return nil, fmt.Errorf("recheck closed SQLite source after snapshot: %w", err)
	}
	if !os.SameFile(sourceInfo, afterCopy) || written != sourceInfo.Size() || afterCopy.Size() != sourceInfo.Size() ||
		!afterCopy.ModTime().Equal(sourceInfo.ModTime()) {
		return nil, errors.New("closed SQLite database changed while capturing validation snapshot")
	}
	pathInfo, err = os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("recheck closed SQLite source path after snapshot: %w", err)
	}
	if !os.SameFile(afterCopy, pathInfo) {
		return nil, errors.New("closed SQLite database was replaced while capturing validation snapshot")
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	keepSource = true
	keepRoot = true
	return &closedDatabaseValidationSnapshot{
		source: source, sourceInfo: sourceInfo, root: root, path: snapshotPath,
		bytes: written, digest: digest,
	}, nil
}

func validateClosedDatabaseDescriptor(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return errors.New("closed SQLite database must be a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot validate closed SQLite database metadata")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("closed SQLite database must be owned by the current user")
	}
	if uint64(stat.Nlink) != 1 {
		return errors.New("closed SQLite database must have exactly one hard link")
	}
	if info.Mode().Perm()&^0o600 != 0 {
		return fmt.Errorf("closed SQLite database permissions %04o are broader than 0600", info.Mode().Perm())
	}
	return nil
}

func (snapshot *closedDatabaseValidationSnapshot) attestSource(path string) error {
	if _, err := snapshot.source.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rewind closed SQLite validation source: %w", err)
	}
	hasher := sha256.New()
	read, err := io.Copy(hasher, snapshot.source)
	if err != nil {
		return fmt.Errorf("hash closed SQLite validation source: %w", err)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	if read != snapshot.bytes || digest != snapshot.digest {
		return errors.New("closed SQLite database contents changed during read-only validation")
	}
	if err := config.ValidateProtectedFile(path, 0o600); err != nil {
		return fmt.Errorf("recheck closed SQLite database protection: %w", err)
	}
	sourceInfo, err := snapshot.source.Stat()
	if err != nil {
		return fmt.Errorf("recheck closed SQLite database descriptor: %w", err)
	}
	if err := validateClosedDatabaseDescriptor(sourceInfo); err != nil {
		return err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("recheck closed SQLite database path: %w", err)
	}
	if !os.SameFile(snapshot.sourceInfo, sourceInfo) || !os.SameFile(sourceInfo, pathInfo) {
		return errors.New("closed SQLite database was replaced during read-only validation")
	}
	return nil
}

func (snapshot *closedDatabaseValidationSnapshot) Close() error {
	if snapshot == nil {
		return nil
	}
	return errors.Join(snapshot.source.Close(), os.RemoveAll(snapshot.root))
}

func Open(ctx context.Context, path string, identity Identity) (*Store, error) {
	if err := validateIdentityInput(identity); err != nil {
		return nil, err
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

// ValidateExisting performs the same exact-schema, instance-identity, and
// persistent-content validation as startup without issuing SQL writes or
// intentionally creating or migrating source state. A closed database is
// validated only through a private byte-exact snapshot, then the protected
// source descriptor is SHA-256-attested against those validated bytes. An
// active WAL reader may transiently update SQLite's shared-memory lock state;
// raced replacement of any database/WAL/SHM path is detected and rejected.
// Deployment preview/apply use this before journaling a resumable instance so
// malformed or foreign state cannot become a partially applied transaction.
func ValidateExisting(ctx context.Context, path string, identity Identity) error {
	return validateExisting(ctx, path, identity, nil)
}

func validateExisting(ctx context.Context, path string, identity Identity, beforeOpen func()) (returnErr error) {
	if err := validateIdentityInput(identity); err != nil {
		return err
	}
	if !filepath.IsAbs(path) {
		return errors.New("database path must be absolute")
	}
	if err := config.ValidateProtectedFile(path, 0o600); err != nil {
		return fmt.Errorf("validate database file: %w", err)
	}
	if err := validateSQLiteFiles(path); err != nil {
		return err
	}
	walPresent, err := existingPath(path + "-wal")
	if err != nil {
		return fmt.Errorf("inspect SQLite WAL: %w", err)
	}
	shmPresent, err := existingPath(path + "-shm")
	if err != nil {
		return fmt.Errorf("inspect SQLite shared memory: %w", err)
	}
	journalPresent, err := existingPath(path + "-journal")
	if err != nil {
		return fmt.Errorf("inspect SQLite rollback journal: %w", err)
	}
	if walPresent != shmPresent {
		return errors.New("read-only SQLite validation requires a complete WAL/shared-memory pair")
	}
	if journalPresent {
		return errors.New("read-only SQLite validation refuses a pending rollback journal")
	}
	var closedSnapshot *closedDatabaseValidationSnapshot
	activeSnapshots := make(map[string]os.FileInfo)
	validationPath := path
	if !walPresent {
		closedSnapshot, err = captureClosedDatabaseValidationSnapshot(path)
		if err != nil {
			return err
		}
		defer func() {
			if closeErr := closedSnapshot.Close(); closeErr != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("release closed SQLite validation snapshot: %w", closeErr))
			}
		}()
		validationPath = closedSnapshot.path
	} else {
		for _, activePath := range []string{path, path + "-wal", path + "-shm"} {
			activeSnapshots[activePath], err = os.Lstat(activePath)
			if err != nil {
				return fmt.Errorf("snapshot active SQLite file %s: %w", filepath.Base(activePath), err)
			}
		}
	}
	if beforeOpen != nil {
		beforeOpen()
	}

	dsnURL := &url.URL{Scheme: "file", Path: validationPath}
	query := dsnURL.Query()
	query.Set("mode", "ro")
	if !walPresent {
		// With no journal sidecars, the closed database is a complete immutable
		// snapshot. This suppresses SQLite's otherwise surprising creation of
		// empty WAL/SHM files while opening a WAL-mode database read-only. The
		// exact file and absence of sidecars are rechecked below so a racing
		// writer cannot make the immutable assumption stale and be accepted.
		query.Set("immutable", "1")
	}
	for _, pragma := range []string{
		"busy_timeout(5000)",
		"foreign_keys(1)",
		"query_only(1)",
		"trusted_schema(0)",
	} {
		query.Add("_pragma", pragma)
	}
	dsnURL.RawQuery = query.Encode()
	database, err := sql.Open("sqlite3", dsnURL.String())
	if err != nil {
		return fmt.Errorf("open SQLite read-only: %w", err)
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	defer func() {
		if closeErr := database.Close(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close read-only SQLite validation: %w", closeErr))
		}
	}()
	if err := database.PingContext(ctx); err != nil {
		return fmt.Errorf("ping SQLite read-only: %w", err)
	}
	connection, err := database.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve read-only SQLite connection: %w", err)
	}
	defer func() {
		if closeErr := connection.Close(); closeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("release read-only SQLite connection: %w", closeErr))
		}
	}()
	transaction, err := connection.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("begin read-only SQLite validation: %w", err)
	}
	defer transaction.Rollback()
	var integrity string
	if err := transaction.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&integrity); err != nil {
		return fmt.Errorf("check SQLite integrity: %w", err)
	}
	if integrity != "ok" {
		return fmt.Errorf("check SQLite integrity: %s", integrity)
	}
	kind, version, err := inspectSchemaState(ctx, transaction)
	if err != nil {
		return err
	}
	migratable := false
	switch kind {
	case schemaEmpty:
		if version != 0 {
			return ErrUnexpectedSchema
		}
	case schemaFull:
		if version != SchemaVersion {
			return ErrUnexpectedSchema
		}
		if err := validateIdentity(ctx, transaction, identity); err != nil {
			return err
		}
		if err := validatePersistentState(ctx, transaction, identity); err != nil {
			return fmt.Errorf("validate persistent state read-only: %w", err)
		}
	case schemaLegacy, schemaPriorFull, schemaPriorAcceptanceOrigin:
		if version != SchemaVersion {
			return ErrUnexpectedSchema
		}
		migratable = true
	default:
		return ErrUnexpectedSchema
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit read-only SQLite validation: %w", err)
	}
	if migratable {
		if err := validateMigratableCopy(ctx, connection, identity); err != nil {
			return err
		}
	}
	if closedSnapshot != nil {
		if err := closedSnapshot.attestSource(path); err != nil {
			return err
		}
		for _, sidecar := range []string{path + "-wal", path + "-shm", path + "-journal"} {
			present, err := existingPath(sidecar)
			if err != nil {
				return fmt.Errorf("recheck SQLite sidecar: %w", err)
			}
			if present {
				return errors.New("SQLite sidecar appeared during read-only validation")
			}
		}
	} else {
		for _, activePath := range []string{path, path + "-wal", path + "-shm"} {
			if err := config.ValidateProtectedFile(activePath, 0o600); err != nil {
				return fmt.Errorf("recheck active SQLite file %s: %w", filepath.Base(activePath), err)
			}
			current, err := os.Lstat(activePath)
			if err != nil {
				return fmt.Errorf("recheck active SQLite file %s: %w", filepath.Base(activePath), err)
			}
			if !os.SameFile(activeSnapshots[activePath], current) {
				return fmt.Errorf("active SQLite file %s was replaced during read-only validation", filepath.Base(activePath))
			}
		}
		journalPresent, err := existingPath(path + "-journal")
		if err != nil {
			return fmt.Errorf("recheck SQLite rollback journal: %w", err)
		}
		if journalPresent {
			return errors.New("SQLite rollback journal appeared during read-only validation")
		}
	}
	return nil
}

func validateMigratableCopy(ctx context.Context, source *sql.Conn, identity Identity) (returnErr error) {
	temporaryRoot, err := os.MkdirTemp("", "jat-store-validation-")
	if err != nil {
		return fmt.Errorf("create private migration-validation directory: %w", err)
	}
	defer func() {
		if removeErr := os.RemoveAll(temporaryRoot); removeErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("remove migration-validation directory: %w", removeErr))
		}
	}()
	destination := filepath.Join(temporaryRoot, "server.db")
	destinationURL := (&url.URL{Scheme: "file", Path: destination}).String()
	if err := source.Raw(func(raw any) error {
		connection, ok := raw.(sqliteDriver.Conn)
		if !ok {
			return errors.New("SQLite driver does not expose the reviewed backup interface")
		}
		return connection.Raw().Backup("main", destinationURL)
	}); err != nil {
		return fmt.Errorf("copy migratable SQLite snapshot: %w", err)
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		return fmt.Errorf("protect migratable SQLite snapshot: %w", err)
	}
	opened, err := Open(ctx, destination, identity)
	if err != nil {
		return fmt.Errorf("validate migratable SQLite snapshot: %w", err)
	}
	if err := opened.Close(); err != nil {
		return fmt.Errorf("close migrated SQLite validation snapshot: %w", err)
	}
	return nil
}

func validateIdentityInput(identity Identity) error {
	if _, err := uuidv4.Parse(identity.InstanceID); err != nil {
		return fmt.Errorf("instance ID: %w", err)
	}
	if _, err := uuidv4.Parse(identity.VaultID); err != nil {
		return fmt.Errorf("vault ID: %w", err)
	}
	if identity.InstanceID == identity.VaultID {
		return errors.New("instance and vault IDs must differ")
	}
	return nil
}

func existingPath(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func (store *Store) Close() error {
	return store.db.Close()
}

func (store *Store) Ready(ctx context.Context) error {
	transaction, err := store.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("database readiness: begin consistent read: %w", err)
	}
	defer transaction.Rollback()
	if err := validateReadinessSnapshot(ctx, transaction, store.identity); err != nil {
		return fmt.Errorf("database readiness: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("database readiness: commit consistent read: %w", err)
	}
	return nil
}

func validateReadinessSnapshot(ctx context.Context, query schemaQueryer, identity Identity) error {
	version, err := validateSchemaState(ctx, query)
	if err != nil {
		return err
	}
	if version != SchemaVersion {
		return ErrUnexpectedSchema
	}
	if err := validateIdentity(ctx, query, identity); err != nil {
		return err
	}
	serverCursor, envelopeGeneration, secretGeneration, _, err := validatePersistentRuntime(ctx, query)
	if err != nil {
		return err
	}
	// The device registry is capped at 64 rows by the V1 protocol, so this is a
	// bounded health sentinel. Full revision, receipt, and snapshot graph
	// validation runs once during Open; repeating those unbounded scans on the
	// unauthenticated health endpoint would make vault size a health-check DoS.
	if err := validateReadinessDevices(ctx, query, serverCursor); err != nil {
		return err
	}
	if err := validatePersistentEnvelope(ctx, query, identity, envelopeGeneration, secretGeneration); err != nil {
		return err
	}
	return nil
}

// CreateDevice adds a pre-activation baseline device and persists only the
// domain-separated token hash and exact fixed scope set. The caller's plaintext
// token is never written to SQLite.
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
	var cursorBytes, activeBootID []byte
	var cursorLength int64
	var activeBootLength sql.NullInt64
	var snapshotCount int
	if err := transaction.QueryRowContext(ctx, `
		SELECT octet_length(server_cursor),
		       CASE WHEN typeof(server_cursor) = 'blob' AND octet_length(server_cursor) = 8 THEN server_cursor END,
		       octet_length(active_boot_id),
		       CASE WHEN typeof(active_boot_id) = 'blob' AND octet_length(active_boot_id) = 16 THEN active_boot_id END,
		       (SELECT count(*) FROM (SELECT 1 FROM snapshots LIMIT 1))
		FROM runtime_state WHERE singleton = 1`).Scan(&cursorLength, &cursorBytes, &activeBootLength, &activeBootID, &snapshotCount); err != nil {
		return fmt.Errorf("read baseline activation state: %w", err)
	}
	if !boundedRequiredBytes(cursorLength, cursorBytes, 8) || cursorLength != 8 ||
		!boundedOptionalBytes(activeBootLength, activeBootID, 16) || activeBootLength.Valid && activeBootLength.Int64 != 16 {
		return errors.New("stored baseline activation state is invalid")
	}
	cursor, err := DecodeUint64(cursorBytes)
	if err != nil || cursor != 0 || activeBootID != nil || snapshotCount != 0 {
		return errors.New("create device: baseline device creation is closed after activation")
	}
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
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO device_origins (
			device_id, origin_kind, created_cursor, baseline_revoked
		) VALUES (?, 'baseline', NULL, 0)`, deviceID); err != nil {
		return fmt.Errorf("create device origin: %w", err)
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
	var hashLength, scopesLength int64
	if err := store.db.QueryRowContext(
		ctx,
		`SELECT octet_length(token_hash),
		        CASE WHEN typeof(token_hash) = 'blob' AND octet_length(token_hash) = 32 THEN token_hash END,
		        octet_length(scopes_json),
		        CASE WHEN typeof(scopes_json) = 'text'
		                   AND octet_length(scopes_json) = ? THEN scopes_json END
		 FROM devices WHERE device_id = ?`,
		len(wantScopes), deviceID,
	).Scan(&hashLength, &hashBytes, &scopesLength, &scopesJSON); err != nil {
		return hash, nil, err
	}
	if !boundedRequiredBytes(hashLength, hashBytes, len(hash)) || hashLength != int64(len(hash)) ||
		!boundedRequiredText(scopesLength, scopesJSON, len(wantScopes)) || scopesJSON.String != string(wantScopes) {
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
	} else if kind == schemaPriorFull {
		if err := migratePriorFullSchemaV1(ctx, transaction); err != nil {
			return err
		}
		if err := migrateRevisionAcceptanceOriginsV1(ctx, transaction); err != nil {
			return err
		}
	} else if kind == schemaPriorAcceptanceOrigin {
		if err := migrateRevisionAcceptanceOriginsV1(ctx, transaction); err != nil {
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
				instance_secret_generation, collection_generation,
				accumulated_uptime_ms, active_boot_id,
				collection_scan_after_record_id
			) VALUES (1, ?, ?, ?, ?, ?, ?, NULL, '')`, zero[:], zero[:], zero[:], one[:], zero[:], zero[:]); err != nil {
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
	var instanceID, vaultID, protocolMajor, storageSchema sql.NullString
	var instanceIDLength, vaultIDLength, protocolMajorLength, storageSchemaLength int64
	if err := database.QueryRowContext(ctx, `
		SELECT octet_length(instance_id),
		       CASE WHEN typeof(instance_id) = 'text'
		                  AND octet_length(instance_id) = ? THEN instance_id END,
		       octet_length(vault_id),
		       CASE WHEN typeof(vault_id) = 'text'
		                  AND octet_length(vault_id) = ? THEN vault_id END,
		       octet_length(protocol_major),
		       CASE WHEN typeof(protocol_major) = 'text'
		                  AND octet_length(protocol_major) = ? THEN protocol_major END,
		       octet_length(storage_schema),
		       CASE WHEN typeof(storage_schema) = 'text'
		                  AND octet_length(storage_schema) = ? THEN storage_schema END
		FROM instance_metadata WHERE singleton = 1`,
		maxUUIDBytes, maxUUIDBytes, len("1"), len("1"),
	).Scan(
		&instanceIDLength, &instanceID, &vaultIDLength, &vaultID,
		&protocolMajorLength, &protocolMajor, &storageSchemaLength, &storageSchema,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrIdentityMismatch
		}
		return fmt.Errorf("read instance metadata: %w", err)
	}
	if instanceIDLength != maxUUIDBytes || !boundedRequiredText(instanceIDLength, instanceID, maxUUIDBytes) ||
		vaultIDLength != maxUUIDBytes || !boundedRequiredText(vaultIDLength, vaultID, maxUUIDBytes) ||
		protocolMajorLength != int64(len("1")) || !boundedRequiredText(protocolMajorLength, protocolMajor, len("1")) ||
		storageSchemaLength != int64(len("1")) || !boundedRequiredText(storageSchemaLength, storageSchema, len("1")) ||
		(Identity{InstanceID: instanceID.String, VaultID: vaultID.String}) != expected ||
		protocolMajor.String != "1" || storageSchema.String != "1" {
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
