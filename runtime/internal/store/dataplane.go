package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
	"github.com/kciceblue/sshserver/runtime/internal/auth"
	"github.com/kciceblue/sshserver/runtime/internal/uuidv4"
)

const (
	enrollmentGrantLifetime = 5 * time.Minute
	snapshotLifetime        = 15 * time.Minute
	receiptMinimumUptime    = 30 * 24 * time.Hour
	receiptMinimumCount     = 10_000
)

type ephemeralState struct {
	mu                 sync.Mutex
	bootID             [16]byte
	booted             bool
	uptimeCheckpoint   time.Time
	grantDeadlines     []grantDeadline
	enrollmentAttempts []time.Time
	snapshotAttempts   map[string][]time.Time
	snapshotDeadlines  map[string]time.Time
}

type grantDeadline struct {
	hash     [32]byte
	deadline time.Time
}

func newEphemeralState() *ephemeralState {
	return &ephemeralState{
		snapshotAttempts:  make(map[string][]time.Time),
		snapshotDeadlines: make(map[string]time.Time),
	}
}

type EnrollmentGrant struct {
	Grant     []byte
	ExpiresAt time.Time
}

// StartBoot binds all newly issued grants to this daemon generation. Clearing
// the prior hash rows makes every unconsumed grant fail closed after restart.
func (store *Store) StartBoot(ctx context.Context) error {
	var bootID [16]byte
	if _, err := rand.Read(bootID[:]); err != nil {
		return fmt.Errorf("generate daemon boot ID: %w", err)
	}
	transaction, err := store.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, "UPDATE runtime_state SET active_boot_id = ? WHERE singleton = 1", bootID[:]); err != nil {
		return fmt.Errorf("record daemon boot ID: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM enrollment_grants"); err != nil {
		return fmt.Errorf("invalidate prior enrollment grants: %w", err)
	}
	// Snapshot leases are defined in daemon-monotonic time. A restart cannot
	// safely reconstruct that clock, so prior leases fail closed and release
	// their immutable metadata references.
	rows, err := transaction.QueryContext(ctx, "SELECT snapshot_id FROM snapshots ORDER BY snapshot_id LIMIT 9")
	if err != nil {
		return fmt.Errorf("read prior snapshot leases: %w", err)
	}
	var snapshotIDs []string
	for rows.Next() {
		var snapshotID string
		if rows.Scan(&snapshotID) != nil {
			rows.Close()
			return errors.New("read prior snapshot lease")
		}
		snapshotIDs = append(snapshotIDs, snapshotID)
	}
	if rows.Err() != nil || rows.Close() != nil || len(snapshotIDs) > 8 {
		return errors.New("invalid prior snapshot leases")
	}
	for _, snapshotID := range snapshotIDs {
		if protocolErr := deleteSnapshotAndReleaseObjects(ctx, transaction, snapshotID); protocolErr != nil {
			return fmt.Errorf("release prior snapshot revision objects: %s", protocolErr.Code)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit daemon boot: %w", err)
	}
	store.ephemeral.mu.Lock()
	store.ephemeral.bootID = bootID
	store.ephemeral.booted = true
	store.ephemeral.uptimeCheckpoint = time.Now()
	store.ephemeral.grantDeadlines = nil
	store.ephemeral.enrollmentAttempts = nil
	clear(store.ephemeral.snapshotAttempts)
	clear(store.ephemeral.snapshotDeadlines)
	store.ephemeral.mu.Unlock()
	return nil
}

// CreateEnrollmentGrant creates one daemon-generation-bound five-minute
// credential and persists only its domain-separated hash.
func (store *Store) CreateEnrollmentGrant(ctx context.Context, now time.Time) (EnrollmentGrant, error) {
	store.ephemeral.mu.Lock()
	if !store.ephemeral.booted {
		store.ephemeral.mu.Unlock()
		return EnrollmentGrant{}, errors.New("server daemon is not running")
	}
	bootID := store.ephemeral.bootID
	expiredHashes := make([][32]byte, 0)
	for _, candidate := range store.ephemeral.grantDeadlines {
		if !now.Before(candidate.deadline) {
			expiredHashes = append(expiredHashes, candidate.hash)
		}
	}
	store.ephemeral.mu.Unlock()
	grant := make([]byte, 32)
	if _, err := rand.Read(grant); err != nil {
		return EnrollmentGrant{}, fmt.Errorf("generate enrollment grant: %w", err)
	}
	hash, err := auth.EnrollmentGrantHash(store.identity.InstanceID, store.identity.VaultID, grant)
	if err != nil {
		clear(grant)
		return EnrollmentGrant{}, err
	}
	deadline := now.Add(enrollmentGrantLifetime)
	expiresAt := deadline.UTC()
	transaction, err := store.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		clear(grant)
		return EnrollmentGrant{}, fmt.Errorf("begin enrollment grant persistence: %w", err)
	}
	defer transaction.Rollback()
	for _, expiredHash := range expiredHashes {
		if _, err := transaction.ExecContext(ctx, "DELETE FROM enrollment_grants WHERE grant_hash = ? AND boot_id = ?", expiredHash[:], bootID[:]); err != nil {
			clear(grant)
			return EnrollmentGrant{}, fmt.Errorf("prune expired enrollment grant hashes: %w", err)
		}
	}
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO enrollment_grants (grant_hash, boot_id, expires_at_ms, consumed_enrollment_id)
		VALUES (?, ?, ?, NULL)`, hash[:], bootID[:], expiresAt.UnixMilli()); err != nil {
		clear(grant)
		return EnrollmentGrant{}, fmt.Errorf("persist enrollment grant hash: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		clear(grant)
		return EnrollmentGrant{}, fmt.Errorf("commit enrollment grant persistence: %w", err)
	}
	expired := make(map[[32]byte]struct{}, len(expiredHashes))
	for _, expiredHash := range expiredHashes {
		expired[expiredHash] = struct{}{}
	}
	store.ephemeral.mu.Lock()
	retained := store.ephemeral.grantDeadlines[:0]
	for _, candidate := range store.ephemeral.grantDeadlines {
		if _, remove := expired[candidate.hash]; !remove {
			retained = append(retained, candidate)
		}
	}
	store.ephemeral.grantDeadlines = retained
	store.ephemeral.grantDeadlines = append(store.ephemeral.grantDeadlines, grantDeadline{
		hash: hash, deadline: deadline,
	})
	store.ephemeral.mu.Unlock()
	return EnrollmentGrant{Grant: grant, ExpiresAt: expiresAt}, nil
}

func (store *Store) HandleAPI(ctx context.Context, request api.Request) (api.Response, *api.Error) {
	if request.Now.IsZero() {
		request.Now = time.Now()
	}
	switch {
	case request.Method == http.MethodPost && request.Path == "/v1/enrollments":
		return store.handleEnrollment(ctx, request)
	case request.Method == http.MethodGet && request.Path == "/v1/vault-envelope":
		return store.handleGetEnvelope(ctx, request)
	case request.Method == http.MethodPut && request.Path == "/v1/vault-envelope":
		return store.handlePutEnvelope(ctx, request)
	case request.Method == http.MethodPost && request.Path == "/v1/sync":
		return store.handleSync(ctx, request)
	case request.Method == http.MethodPost && request.Path == "/v1/snapshot-reads":
		return store.handleCreateSnapshot(ctx, request)
	case request.Method == http.MethodGet && request.Path == "/v1/devices":
		return store.handleListDevices(ctx, request)
	case request.Method == http.MethodPost && request.Path == "/v1/device-token-rotations":
		return store.handleTokenRotation(ctx, request)
	case request.Method == http.MethodPost && strings.HasPrefix(request.Path, "/v1/devices/") && strings.HasSuffix(request.Path, "/revoke"):
		deviceID, ok := pathIdentifier(request.Path, "/v1/devices/", "/revoke")
		if !ok {
			return api.Response{}, api.NewError("invalid_request", false)
		}
		return store.handleRevokeDevice(ctx, request, deviceID)
	case request.Method == http.MethodPost && strings.HasPrefix(request.Path, "/v1/snapshot-reads/") && strings.HasSuffix(request.Path, "/pages"):
		snapshotID, ok := pathIdentifier(request.Path, "/v1/snapshot-reads/", "/pages")
		if !ok {
			return api.Response{}, api.NewError("invalid_request", false)
		}
		return store.handleSnapshotPage(ctx, request, snapshotID)
	default:
		return api.Response{}, api.NewError("invalid_request", false)
	}
}

func pathIdentifier(path, prefix, suffix string) (string, bool) {
	value := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	if value == "" || strings.Contains(value, "/") || validateUUID(value) != nil {
		return "", false
	}
	return value, true
}

type deviceAuth struct {
	DeviceID string
	Hash     [32]byte
	Scopes   []string
	Revoked  bool
}

func parseAuthorization(value, scheme string) ([]byte, error) {
	prefix := scheme + " "
	if !strings.HasPrefix(value, prefix) || strings.TrimSpace(value) != value || strings.Contains(value[len(prefix):], " ") {
		return nil, errors.New("authorization scheme is invalid")
	}
	return decodeBase64(value[len(prefix):], 32, 0, 0)
}

func (store *Store) authenticate(ctx context.Context, transaction *sql.Tx, authorization, requiredScope string) (deviceAuth, *api.Error) {
	token, err := parseAuthorization(authorization, "Bearer")
	if err != nil {
		return deviceAuth{}, api.NewError("unauthorized", false)
	}
	defer clear(token)
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	rows, err := transaction.QueryContext(ctx, `
		SELECT device_id, token_hash, length(scopes_json),
		       CASE WHEN length(scopes_json) = ? THEN scopes_json END,
		       revoked_at_ms IS NOT NULL
		FROM devices ORDER BY device_id LIMIT 65`, len(wantScopes))
	if err != nil {
		return deviceAuth{}, api.NewError("internal_error", true)
	}
	defer rows.Close()
	var match *deviceAuth
	rowCount := 0
	for rows.Next() {
		rowCount++
		var deviceID string
		var scopesJSON sql.NullString
		var scopesLength int64
		var storedBytes []byte
		var revoked bool
		if err := rows.Scan(&deviceID, &storedBytes, &scopesLength, &scopesJSON, &revoked); err != nil || len(storedBytes) != 32 ||
			!boundedRequiredText(scopesLength, scopesJSON, len(wantScopes)) || scopesJSON.String != string(wantScopes) {
			return deviceAuth{}, api.NewError("internal_error", true)
		}
		computed, err := auth.DeviceTokenHash(store.identity.InstanceID, store.identity.VaultID, deviceID, token)
		if err != nil {
			return deviceAuth{}, api.NewError("internal_error", true)
		}
		var stored [32]byte
		copy(stored[:], storedBytes)
		if auth.VerifyHash(stored, computed) {
			var scopes []string
			if json.Unmarshal([]byte(scopesJSON.String), &scopes) != nil || auth.ValidateScopes(scopes) != nil {
				return deviceAuth{}, api.NewError("internal_error", true)
			}
			candidate := deviceAuth{DeviceID: deviceID, Hash: stored, Scopes: scopes, Revoked: revoked}
			match = &candidate
		}
	}
	if err := rows.Err(); err != nil {
		return deviceAuth{}, api.NewError("internal_error", true)
	}
	if rowCount > 64 {
		return deviceAuth{}, api.NewError("internal_error", true)
	}
	if match == nil {
		return deviceAuth{}, api.NewError("unauthorized", false)
	}
	if match.Revoked {
		return deviceAuth{}, api.NewError("token_revoked", false)
	}
	if requiredScope != "" && !slices.Contains(match.Scopes, requiredScope) {
		return deviceAuth{}, api.NewError("scope_denied", false)
	}
	return *match, nil
}

func beginTransaction(ctx context.Context, database *sql.DB) (*sql.Tx, *api.Error) {
	transaction, err := database.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, api.NewError("internal_error", true)
	}
	return transaction, nil
}

func commitTransaction(transaction *sql.Tx) *api.Error {
	if err := transaction.Commit(); err != nil {
		return api.NewError("internal_error", true)
	}
	return nil
}

func requestFingerprint(store *Store, label, deviceID string, body []byte) ([32]byte, *api.Error) {
	fingerprint, err := auth.RequestBodyFingerprint(label, store.identity.InstanceID, store.identity.VaultID, deviceID, body)
	if err != nil {
		return [32]byte{}, api.NewError("internal_error", true)
	}
	return fingerprint, nil
}

func (store *Store) lookupReceipt(ctx context.Context, transaction *sql.Tx, deviceID, operation, requestID string, fingerprint [32]byte) (api.Response, bool, *api.Error) {
	var storedFingerprint, body []byte
	var bodyLength int64
	var status int
	err := transaction.QueryRowContext(ctx, `
		SELECT request_fingerprint, response_status, length(response_json),
		       CASE WHEN length(response_json) BETWEEN 1 AND ? THEN response_json END
		FROM operation_receipts WHERE device_id = ? AND operation = ? AND request_id = ?`,
		maxBodyBytes, deviceID, operation, requestID,
	).Scan(&storedFingerprint, &status, &bodyLength, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return api.Response{}, false, nil
	}
	if err != nil || len(storedFingerprint) != 32 || !boundedRequiredBytes(bodyLength, body, maxBodyBytes) ||
		validateStoredOperationResponse(operation, status, body, store.identity) != nil {
		return api.Response{}, false, api.NewError("internal_error", true)
	}
	var stored [32]byte
	copy(stored[:], storedFingerprint)
	if !auth.VerifyHash(stored, fingerprint) {
		return api.Response{}, false, api.NewError("request_id_reused", false)
	}
	return api.Response{Status: status, Body: append([]byte(nil), body...)}, true, nil
}

func (store *Store) storeReceipt(ctx context.Context, transaction *sql.Tx, deviceID, operation, requestID string, fingerprint [32]byte, response api.Response, now time.Time) (pendingUptimeCheckpoint, *api.Error) {
	accumulatedUptimeMS, checkpoint, protocolErr := store.checkpointUptimeTx(ctx, transaction, now)
	if protocolErr != nil {
		return pendingUptimeCheckpoint{}, protocolErr
	}
	if protocolErr := store.storeReceiptAtUptime(ctx, transaction, deviceID, operation, requestID, fingerprint, response, now, accumulatedUptimeMS); protocolErr != nil {
		return pendingUptimeCheckpoint{}, protocolErr
	}
	return checkpoint, nil
}

func (store *Store) storeReceiptAtUptime(ctx context.Context, transaction *sql.Tx, deviceID, operation, requestID string, fingerprint [32]byte, response api.Response, now time.Time, accumulatedUptimeMS uint64) *api.Error {
	encodedUptime := EncodeUint64(accumulatedUptimeMS)
	result, err := transaction.ExecContext(ctx, `
		INSERT INTO operation_receipts (
			device_id, operation, request_id, request_fingerprint,
			response_status, response_json, created_at_ms, created_uptime_ms
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		deviceID, operation, requestID, fingerprint[:], response.Status, response.Body,
		now.UTC().UnixMilli(), encodedUptime[:],
	)
	if err != nil {
		return api.NewError("internal_error", true)
	}
	receiptSequence, err := result.LastInsertId()
	if err != nil || receiptSequence <= 0 {
		return api.NewError("internal_error", true)
	}
	receiptClass := "other"
	if operation == "sync" {
		receiptClass = "sync"
	}
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO operation_receipt_retention (
			device_id, receipt_class, receipt_sequence, created_uptime_ms
		) VALUES (?, ?, ?, ?)`, deviceID, receiptClass, receiptSequence, encodedUptime[:]); err != nil {
		return api.NewError("internal_error", true)
	}
	return pruneOperationReceipts(ctx, transaction, deviceID, operation, accumulatedUptimeMS, receiptMinimumCount, receiptMinimumUptime)
}

func pruneOperationReceipts(ctx context.Context, transaction *sql.Tx, deviceID, operation string, accumulatedUptimeMS uint64, retainCount int, minimumAge time.Duration) *api.Error {
	if retainCount < 1 || minimumAge < 0 {
		return api.NewError("internal_error", true)
	}
	minimumAgeMS := uint64(minimumAge / time.Millisecond)
	if accumulatedUptimeMS < minimumAgeMS {
		return nil
	}
	cutoff := EncodeUint64(accumulatedUptimeMS - minimumAgeMS)
	receiptClass := "other"
	if operation == "sync" {
		receiptClass = "sync"
	}
	var protectedBoundary int64
	err := transaction.QueryRowContext(ctx, `
		SELECT receipt_sequence FROM operation_receipt_retention
		WHERE device_id = ? AND receipt_class = ?
		ORDER BY receipt_sequence DESC LIMIT 1 OFFSET ?`, deviceID, receiptClass, retainCount-1,
	).Scan(&protectedBoundary)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil || protectedBoundary <= 0 {
		return api.NewError("internal_error", true)
	}
	rows, err := transaction.QueryContext(ctx, `
		SELECT receipt_sequence FROM operation_receipt_retention
		WHERE device_id = ? AND receipt_class = ?
		  AND receipt_sequence < ? AND created_uptime_ms <= ?
		ORDER BY receipt_sequence LIMIT 256`, deviceID, receiptClass, protectedBoundary, cutoff[:])
	if err != nil {
		return api.NewError("internal_error", true)
	}
	var expired []int64
	for rows.Next() {
		var sequence int64
		if rows.Scan(&sequence) != nil || sequence <= 0 {
			rows.Close()
			return api.NewError("internal_error", true)
		}
		expired = append(expired, sequence)
	}
	if rows.Err() != nil || rows.Close() != nil {
		return api.NewError("internal_error", true)
	}
	for _, sequence := range expired {
		if _, err := transaction.ExecContext(ctx, "DELETE FROM operation_receipts WHERE receipt_sequence = ?", sequence); err != nil {
			return api.NewError("internal_error", true)
		}
		if _, err := transaction.ExecContext(ctx, `
			DELETE FROM operation_receipt_retention
			WHERE device_id = ? AND receipt_class = ? AND receipt_sequence = ?`, deviceID, receiptClass, sequence); err != nil {
			return api.NewError("internal_error", true)
		}
	}
	return nil
}

func readRuntimeState(ctx context.Context, transaction *sql.Tx) (cursor, envelopeGeneration, secretGeneration, collectionGeneration uint64, err *api.Error) {
	var cursorBytes, envelopeBytes, secretBytes, collectionBytes []byte
	if scanErr := transaction.QueryRowContext(ctx, `
		SELECT server_cursor, envelope_generation, instance_secret_generation,
		       collection_generation
		FROM runtime_state WHERE singleton = 1`,
	).Scan(&cursorBytes, &envelopeBytes, &secretBytes, &collectionBytes); scanErr != nil {
		return 0, 0, 0, 0, api.NewError("internal_error", true)
	}
	var decodeErr error
	if cursor, decodeErr = DecodeUint64(cursorBytes); decodeErr != nil {
		return 0, 0, 0, 0, api.NewError("internal_error", true)
	}
	if envelopeGeneration, decodeErr = DecodeUint64(envelopeBytes); decodeErr != nil {
		return 0, 0, 0, 0, api.NewError("internal_error", true)
	}
	if secretGeneration, decodeErr = DecodeUint64(secretBytes); decodeErr != nil {
		return 0, 0, 0, 0, api.NewError("internal_error", true)
	}
	if collectionGeneration, decodeErr = DecodeUint64(collectionBytes); decodeErr != nil {
		return 0, 0, 0, 0, api.NewError("internal_error", true)
	}
	return cursor, envelopeGeneration, secretGeneration, collectionGeneration, nil
}

func readCursorFloor(ctx context.Context, transaction *sql.Tx) (uint64, *api.Error) {
	var encoded []byte
	if err := transaction.QueryRowContext(ctx, "SELECT cursor_floor FROM runtime_state WHERE singleton = 1").Scan(&encoded); err != nil {
		return 0, api.NewError("internal_error", true)
	}
	value, err := DecodeUint64(encoded)
	if err != nil {
		return 0, api.NewError("internal_error", true)
	}
	return value, nil
}

func reserveCursors(ctx context.Context, transaction *sql.Tx, count uint64) (uint64, *api.Error) {
	cursor, _, _, _, protocolErr := readRuntimeState(ctx, transaction)
	if protocolErr != nil {
		return 0, protocolErr
	}
	if count > math.MaxUint64-cursor {
		return 0, api.NewError("server_cursor_exhausted", false)
	}
	return cursor + count, nil
}

func setServerCursor(ctx context.Context, transaction *sql.Tx, value uint64) *api.Error {
	encoded := EncodeUint64(value)
	if _, err := transaction.ExecContext(ctx, "UPDATE runtime_state SET server_cursor = ? WHERE singleton = 1", encoded[:]); err != nil {
		return api.NewError("internal_error", true)
	}
	return nil
}

func insertChange(ctx context.Context, transaction *sql.Tx, cursor uint64, kind, revisionID, markerRecordID, deviceID, deviceChangeKind string, now time.Time) *api.Error {
	encoded := EncodeUint64(cursor)
	var revision, marker, changedDevice, deviceEvent any
	if revisionID != "" {
		revision = revisionID
	}
	if markerRecordID != "" {
		marker = markerRecordID
	}
	if deviceID != "" {
		changedDevice = deviceID
	}
	if deviceChangeKind != "" {
		deviceEvent = deviceChangeKind
	}
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO changes (
			cursor, kind, received_at_ms, record_revision_id,
			collection_marker_record_id, device_changed_id, device_change_kind
		) VALUES (?, ?, ?, ?, ?, ?, ?)`, encoded[:], kind, now.UTC().UnixMilli(), revision, marker, changedDevice, deviceEvent); err != nil {
		return api.NewError("internal_error", true)
	}
	return nil
}

func encodeRandomBase64(size int) (string, error) {
	value := make([]byte, size)
	defer clear(value)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func generateUUID() (string, *api.Error) {
	identifier, err := uuidv4.New()
	if err != nil {
		return "", api.NewError("internal_error", true)
	}
	return identifier, nil
}
