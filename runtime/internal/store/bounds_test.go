package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
	"github.com/kciceblue/sshserver/runtime/internal/auth"
)

type boundedSeedOptions struct {
	marker   bool
	rotation bool
	self     bool
}

type boundedPersistenceSeed struct {
	opened         *Store
	path           string
	deviceID       string
	recordID       string
	revisionID     string
	token          []byte
	enrollment     api.Request
	sync           api.Request
	snapshot       snapshotCreateResponse
	snapshotCreate api.Request
	snapshotPage   api.Request
	rotation       api.Request
	selfRevocation api.Request
}

type readinessInterleaveQueryer struct {
	schemaQueryer
	beforeDeviceQuery func()
	fired             bool
}

func (query *readinessInterleaveQueryer) QueryContext(ctx context.Context, statement string, arguments ...any) (*sql.Rows, error) {
	if !query.fired && strings.Contains(statement, "FROM devices d LEFT JOIN device_sync_state") {
		query.fired = true
		query.beforeDeviceQuery()
	}
	return query.schemaQueryer.QueryContext(ctx, statement, arguments...)
}

func seedBoundedPersistence(t *testing.T, options boundedSeedOptions) boundedPersistenceSeed {
	t.Helper()
	opened, path := openDataPlane(t)
	seed := boundedPersistenceSeed{
		opened:     opened,
		path:       path,
		deviceID:   "e1000000-0000-4000-8000-000000000001",
		recordID:   "e1000000-0000-4000-8000-000000000006",
		revisionID: "e1000000-0000-4000-8000-000000000007",
		token:      tokenWithByte(0xe1),
	}

	grant := createGrant(t, opened, protocolFixtureTime)
	enrollmentBody, _ := marshalJSON(enrollmentRequest{
		ProtocolVersion: "1",
		EnrollmentID:    "e1000000-0000-4000-8000-000000000002",
		DeviceID:        seed.deviceID,
		DeviceToken:     base64.RawURLEncoding.EncodeToString(seed.token),
		Scopes:          auth.FixedScopes(),
	})
	seed.enrollment = api.Request{
		Method: "POST", Path: "/v1/enrollments", RequestID: "e1000000-0000-4000-8000-000000000003",
		Authorization: "JAT-Enrollment " + base64.RawURLEncoding.EncodeToString(grant.Grant), Body: enrollmentBody, Now: protocolFixtureTime,
	}
	if response, protocolErr := opened.HandleAPI(context.Background(), seed.enrollment); protocolErr != nil || response.Status != http.StatusCreated {
		opened.Close()
		t.Fatalf("seed enrollment: response=%+v error=%v", response, protocolErr)
	}

	var envelopeFixture struct {
		BaseMode putEnvelopeRequest `json:"base_mode"`
	}
	loadFixture(t, "vault-envelope.json", &envelopeFixture)
	envelopeBody, _ := marshalJSON(envelopeFixture.BaseMode)
	if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "PUT", Path: "/v1/vault-envelope", RequestID: "e1000000-0000-4000-8000-000000000004",
		Authorization: authorization(seed.token), Body: envelopeBody, Now: protocolFixtureTime,
	}); protocolErr != nil || response.Status != http.StatusOK {
		opened.Close()
		t.Fatalf("seed envelope: response=%+v error=%v", response, protocolErr)
	}

	witness := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	revision := recordRevision{
		RecordID: seed.recordID, RevisionID: seed.revisionID, AuthorDeviceID: seed.deviceID,
		AuthorCounter: "1", VersionVector: []vectorEntry{{DeviceID: seed.deviceID, Counter: "1"}},
		CollectionWitnessAuthenticator: &witness, PayloadSchema: "1", CryptoSuite: cryptoSuite,
		Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	syncBody, _ := marshalJSON(syncRequest{
		ProtocolVersion: "1", DeviceID: seed.deviceID, RequestID: "e1000000-0000-4000-8000-000000000005",
		AfterCursor: "0", AckCursor: "0", Mutations: []recordRevision{revision},
	})
	seed.sync = api.Request{
		Method: "POST", Path: "/v1/sync", RequestID: "e1000000-0000-4000-8000-000000000005",
		Authorization: authorization(seed.token), Body: syncBody, Now: protocolFixtureTime,
	}
	if response, protocolErr := opened.HandleAPI(context.Background(), seed.sync); protocolErr != nil || response.Status != http.StatusOK {
		opened.Close()
		t.Fatalf("seed sync: response=%+v error=%v", response, protocolErr)
	}

	snapshotRequestID := "e1000000-0000-4000-8000-000000000008"
	snapshotBody, _ := marshalJSON(snapshotCreateRequest{
		ProtocolVersion: "1", DeviceID: seed.deviceID, RequestID: snapshotRequestID,
		RequiredCapabilities: append([]string(nil), requiredSnapshotCapabilities...),
	})
	seed.snapshotCreate = api.Request{
		Method: "POST", Path: "/v1/snapshot-reads", RequestID: snapshotRequestID,
		Authorization: authorization(seed.token), Body: snapshotBody, Now: protocolFixtureTime,
	}
	created, protocolErr := opened.HandleAPI(context.Background(), seed.snapshotCreate)
	if protocolErr != nil || created.Status != http.StatusCreated || json.Unmarshal(created.Body, &seed.snapshot) != nil {
		opened.Close()
		t.Fatalf("seed snapshot: response=%+v error=%v", created, protocolErr)
	}
	pageBody, _ := marshalJSON(snapshotPageRequest{ProtocolVersion: "1", DeviceID: seed.deviceID, PageToken: seed.snapshot.FirstPageToken})
	seed.snapshotPage = api.Request{
		Method: "POST", Path: "/v1/snapshot-reads/" + seed.snapshot.SnapshotID + "/pages",
		RequestID: "e1000000-0000-4000-8000-000000000009", Authorization: authorization(seed.token), Body: pageBody, Now: protocolFixtureTime,
	}

	if options.marker {
		frontier := []vectorEntry{{DeviceID: seed.deviceID, Counter: "1"}}
		frontierBody, _ := json.Marshal(frontier)
		marker := collectionMarker{
			RecordID: seed.recordID, WitnessRevisionID: seed.revisionID, Frontier: frontier,
			CollectionWitnessAuthenticator: witness, BarrierCursor: "3",
		}
		markerBody, _ := marshalJSON(marker)
		barrier := EncodeUint64(3)
		changeCursor := EncodeUint64(4)
		if _, err := opened.db.Exec(`
			INSERT INTO collection_markers (
				record_id, witness_revision_id, frontier_json,
				collection_witness_authenticator, barrier_cursor, marker_json,
				change_cursor, received_at_ms
			) VALUES (?, ?, ?, zeroblob(32), ?, ?, ?, ?)`,
			seed.recordID, seed.revisionID, frontierBody, barrier[:], markerBody, changeCursor[:], protocolFixtureTime.UnixMilli(),
		); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		if _, err := opened.db.Exec(`
			INSERT INTO change_origins (cursor, kind)
			VALUES (?, 'collection_marker')`, changeCursor[:]); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		if _, err := opened.db.Exec(`
			INSERT INTO changes (cursor, kind, received_at_ms, collection_marker_record_id, collection_marker_json)
			VALUES (?, 'collection_marker', ?, ?, ?)`, changeCursor[:], protocolFixtureTime.UnixMilli(), seed.recordID, markerBody,
		); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		if _, err := opened.db.Exec("UPDATE runtime_state SET server_cursor = ? WHERE singleton = 1", changeCursor[:]); err != nil {
			opened.Close()
			t.Fatal(err)
		}
	}

	if options.rotation {
		newToken := tokenWithByte(0xe2)
		rotationBody, _ := marshalJSON(tokenRotationRequest{
			RotationID: "e1000000-0000-4000-8000-00000000000a", DeviceID: seed.deviceID,
			NewDeviceToken: base64.RawURLEncoding.EncodeToString(newToken),
		})
		seed.rotation = api.Request{
			Method: "POST", Path: "/v1/device-token-rotations", RequestID: "e1000000-0000-4000-8000-00000000000b",
			Authorization: authorization(seed.token), Body: rotationBody, Now: protocolFixtureTime.Add(time.Second),
		}
		if response, protocolErr := opened.HandleAPI(context.Background(), seed.rotation); protocolErr != nil || response.Status != http.StatusOK {
			opened.Close()
			t.Fatalf("seed rotation: response=%+v error=%v", response, protocolErr)
		}
		seed.token = newToken
	}

	if options.self {
		selfBody, _ := marshalJSON(revokeDeviceRequest{RequestID: "e1000000-0000-4000-8000-00000000000c", AllowZeroActive: true})
		seed.selfRevocation = api.Request{
			Method: "POST", Path: "/v1/devices/" + seed.deviceID + "/revoke", RequestID: "e1000000-0000-4000-8000-00000000000c",
			Authorization: authorization(seed.token), Body: selfBody, Now: protocolFixtureTime.Add(2 * time.Second),
		}
		if response, protocolErr := opened.HandleAPI(context.Background(), seed.selfRevocation); protocolErr != nil || response.Status != http.StatusOK {
			opened.Close()
			t.Fatalf("seed self-revocation: response=%+v error=%v", response, protocolErr)
		}
	}

	if err := validatePersistentState(context.Background(), opened.db, testIdentity); err != nil {
		opened.Close()
		t.Fatalf("seed persistent state: %v", err)
	}
	return seed
}

func collectBoundedSeedRevision(t *testing.T, seed boundedPersistenceSeed) {
	t.Helper()
	one := EncodeUint64(1)
	floor := EncodeUint64(3)
	transaction, err := seed.opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`UPDATE record_revisions
		  SET retained = 0, undominated = 0, collected_generation = ?
		  WHERE revision_id = ?`, []any{one[:], seed.revisionID}},
		{"DELETE FROM record_heads WHERE revision_id = ?", []any{seed.revisionID}},
		{"DELETE FROM changes WHERE record_revision_id = ?", []any{seed.revisionID}},
		{"DELETE FROM collection_candidates WHERE revision_id = ?", []any{seed.revisionID}},
		{"DELETE FROM collection_records WHERE record_id = ?", []any{seed.recordID}},
		{"UPDATE runtime_state SET cursor_floor = ?, collection_generation = ? WHERE singleton = 1", []any{floor[:], one[:]}},
	} {
		if _, err := transaction.Exec(statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := validatePersistentState(context.Background(), seed.opened.db, testIdentity); err != nil {
		t.Fatalf("coherent collected seed: %v", err)
	}
}

func TestCollectionGenerationCorruptionFailsClosed(t *testing.T) {
	one := EncodeUint64(1)
	two := EncodeUint64(2)
	zero := EncodeUint64(0)
	tests := []struct {
		name   string
		detail string
		mutate func(*testing.T, boundedPersistenceSeed)
	}{
		{
			name: "zero collected generation", detail: "inconsistent revision row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				if _, err := seed.opened.db.Exec("UPDATE record_revisions SET collected_generation = ? WHERE revision_id = ?", zero[:], seed.revisionID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "future collected generation", detail: "inconsistent revision row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				if _, err := seed.opened.db.Exec("UPDATE record_revisions SET collected_generation = ? WHERE revision_id = ?", two[:], seed.revisionID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "gapped collected generation", detail: "collection generation does not match accepted history",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				transaction, err := seed.opened.db.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer transaction.Rollback()
				if _, err := transaction.Exec("UPDATE record_revisions SET collected_generation = ? WHERE revision_id = ?", two[:], seed.revisionID); err != nil {
					t.Fatal(err)
				}
				if _, err := transaction.Exec("UPDATE runtime_state SET collection_generation = ? WHERE singleton = 1", two[:]); err != nil {
					t.Fatal(err)
				}
				if err := transaction.Commit(); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "inflated runtime generation", detail: "collection generation does not match accepted history",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				if _, err := seed.opened.db.Exec("UPDATE runtime_state SET collection_generation = ? WHERE singleton = 1", two[:]); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "future snapshot generation", detail: "inconsistent snapshot row",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				if _, err := seed.opened.db.Exec("UPDATE snapshots SET collection_generation = ? WHERE snapshot_id = ?", two[:], seed.snapshot.SnapshotID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "post-collection snapshot reference", detail: "snapshot reference was collected before snapshot",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				if _, err := seed.opened.db.Exec("UPDATE snapshots SET collection_generation = ? WHERE snapshot_id = ?", one[:], seed.snapshot.SnapshotID); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{marker: true})
			defer seed.opened.Close()
			collectBoundedSeedRevision(t, seed)
			test.mutate(t, seed)
			err := validatePersistentState(context.Background(), seed.opened.db, testIdentity)
			if !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), test.detail) {
				t.Fatalf("collection generation corruption error=%v", err)
			}
		})
	}
}

func TestDeviceOriginProvenanceFailsClosed(t *testing.T) {
	t.Run("missing origin", func(t *testing.T) {
		opened, _ := openDataPlane(t)
		defer opened.Close()
		deviceID := "f7000000-0000-4000-8000-000000000001"
		enrollDevice(t, opened, protocolFixtureTime,
			"f7000000-0000-4000-8000-000000000002", deviceID,
			"f7000000-0000-4000-8000-000000000003", tokenWithByte(0xf7))
		if _, err := opened.db.Exec("DELETE FROM device_origins WHERE device_id = ?", deviceID); err != nil {
			t.Fatal(err)
		}
		if err := validatePersistentState(context.Background(), opened.db, testIdentity); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "invalid device row") {
			t.Fatalf("missing device origin error=%v", err)
		}
	})

	t.Run("deleted enrollment row and event", func(t *testing.T) {
		opened, _ := openDataPlane(t)
		defer opened.Close()
		deviceID := "f8000000-0000-4000-8000-000000000001"
		enrollDevice(t, opened, protocolFixtureTime,
			"f8000000-0000-4000-8000-000000000002", deviceID,
			"f8000000-0000-4000-8000-000000000003", tokenWithByte(0xf8))
		one := EncodeUint64(1)
		transaction, err := opened.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer transaction.Rollback()
		for _, statement := range []string{
			"DELETE FROM enrollment_grants",
			"DELETE FROM enrollments WHERE device_id = 'f8000000-0000-4000-8000-000000000001'",
			"DELETE FROM changes WHERE device_changed_id = 'f8000000-0000-4000-8000-000000000001' AND device_change_kind = 'enrolled'",
		} {
			if _, err := transaction.Exec(statement); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := transaction.Exec("UPDATE runtime_state SET cursor_floor = ? WHERE singleton = 1", one[:]); err != nil {
			t.Fatal(err)
		}
		if err := transaction.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := validatePersistentState(context.Background(), opened.db, testIdentity); !errors.Is(err, ErrUnexpectedSchema) {
			t.Fatalf("deleted enrollment provenance startup error=%v", err)
		}
		devices, err := validatePersistentDevices(context.Background(), opened.db, 1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validatePersistentChanges(context.Background(), opened.db, devices, 1); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "device enrollment change mismatch") {
			t.Fatalf("deleted enrollment provenance error=%v", err)
		}
	})

	t.Run("origin and enrollment cursor mismatch", func(t *testing.T) {
		opened, _ := openDataPlane(t)
		defer opened.Close()
		deviceID := "f9000000-0000-4000-8000-000000000001"
		token := tokenWithByte(0xf9)
		enrollDevice(t, opened, protocolFixtureTime,
			"f9000000-0000-4000-8000-000000000002", deviceID,
			"f9000000-0000-4000-8000-000000000003", token)
		var envelopeFixture struct {
			BaseMode putEnvelopeRequest `json:"base_mode"`
		}
		loadFixture(t, "vault-envelope.json", &envelopeFixture)
		envelopeBody, _ := marshalJSON(envelopeFixture.BaseMode)
		if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{
			Method: "PUT", Path: "/v1/vault-envelope", RequestID: "f9000000-0000-4000-8000-000000000004",
			Authorization: authorization(token), Body: envelopeBody, Now: protocolFixtureTime,
		}); protocolErr != nil || response.Status != http.StatusOK {
			t.Fatalf("put envelope: response=%+v error=%v", response, protocolErr)
		}
		two := EncodeUint64(2)
		if _, err := opened.db.Exec("UPDATE enrollments SET created_cursor = ? WHERE device_id = ?", two[:], deviceID); err != nil {
			t.Fatal(err)
		}
		if err := validatePersistentState(context.Background(), opened.db, testIdentity); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "invalid enrollment cursor") {
			t.Fatalf("origin/enrollment cursor mismatch error=%v", err)
		}
	})
}

func TestDeviceRevocationProvenanceFailsClosed(t *testing.T) {
	t.Run("active baseline needs revocation event", func(t *testing.T) {
		ctx := context.Background()
		opened, err := Open(ctx, filepath.Join(t.TempDir(), "server.db"), testIdentity)
		if err != nil {
			t.Fatal(err)
		}
		defer opened.Close()
		managerID := "fa000000-0000-4000-8000-000000000001"
		targetID := "fa000000-0000-4000-8000-000000000002"
		managerToken := tokenWithByte(0xfa)
		if err := opened.CreateDevice(ctx, managerID, managerToken, auth.FixedScopes(), protocolFixtureTime); err != nil {
			t.Fatal(err)
		}
		if err := opened.CreateDevice(ctx, targetID, tokenWithByte(0xfb), auth.FixedScopes(), protocolFixtureTime); err != nil {
			t.Fatal(err)
		}
		if err := opened.StartBoot(ctx); err != nil {
			t.Fatal(err)
		}
		revokeDevice(t, opened, targetID, managerToken, false, "fa000000-0000-4000-8000-000000000003", protocolFixtureTime.Add(time.Second))
		one := EncodeUint64(1)
		if _, err := opened.db.Exec("DELETE FROM changes WHERE device_changed_id = ? AND device_change_kind = 'revoked'", targetID); err != nil {
			t.Fatal(err)
		}
		if _, err := opened.db.Exec("UPDATE runtime_state SET cursor_floor = ? WHERE singleton = 1", one[:]); err != nil {
			t.Fatal(err)
		}
		if err := validatePersistentState(ctx, opened.db, testIdentity); !errors.Is(err, ErrUnexpectedSchema) {
			t.Fatalf("missing baseline revocation startup error=%v", err)
		}
		devices, err := validatePersistentDevices(ctx, opened.db, 1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validatePersistentChanges(ctx, opened.db, devices, 1); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "device revocation change mismatch") {
			t.Fatalf("missing baseline revocation event error=%v", err)
		}
	})

	t.Run("revocation cannot predate enrollment", func(t *testing.T) {
		opened, _ := openDataPlane(t)
		defer opened.Close()
		deviceID := "fb000000-0000-4000-8000-000000000001"
		token := tokenWithByte(0xfc)
		enrollDevice(t, opened, protocolFixtureTime,
			"fb000000-0000-4000-8000-000000000002", deviceID,
			"fb000000-0000-4000-8000-000000000003", token)
		revokeDevice(t, opened, deviceID, token, true, "fb000000-0000-4000-8000-000000000004", protocolFixtureTime.Add(time.Second))
		one := EncodeUint64(1)
		two := EncodeUint64(2)
		three := EncodeUint64(3)
		transaction, err := opened.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer transaction.Rollback()
		if _, err := transaction.Exec("INSERT INTO change_origins (cursor, kind) VALUES (?, 'device_changed')", three[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.Exec("UPDATE changes SET cursor = ? WHERE device_changed_id = ? AND device_change_kind = 'revoked'", three[:], deviceID); err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.Exec("UPDATE changes SET cursor = ? WHERE device_changed_id = ? AND device_change_kind = 'enrolled'", two[:], deviceID); err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.Exec("UPDATE changes SET cursor = ? WHERE device_changed_id = ? AND device_change_kind = 'revoked'", one[:], deviceID); err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.Exec("DELETE FROM change_origins WHERE cursor = ?", three[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.Exec("UPDATE device_origins SET created_cursor = ? WHERE device_id = ?", two[:], deviceID); err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.Exec("UPDATE enrollments SET created_cursor = ? WHERE device_id = ?", two[:], deviceID); err != nil {
			t.Fatal(err)
		}
		if err := transaction.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := validatePersistentState(context.Background(), opened.db, testIdentity); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "device revocation history mismatch") {
			t.Fatalf("revocation-before-enrollment error=%v", err)
		}
	})
}

func TestMaximumStoredVectorBoundMatchesCanonicalProfile(t *testing.T) {
	entries := make([]vectorEntry, maxVectorEntries)
	for index := range entries {
		entries[index] = vectorEntry{
			DeviceID: fmt.Sprintf("f0000000-0000-4000-8000-%012x", index+1),
			Counter:  "18446744073709551615",
		}
	}
	body, err := json.Marshal(entries)
	if err != nil || len(body) != maxVectorBytes {
		t.Fatalf("canonical maximum vector length=%d want=%d error=%v", len(body), maxVectorBytes, err)
	}
}

func TestOversizedDurableValuesFailClosedAtStartup(t *testing.T) {
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	tests := []struct {
		name    string
		options boundedSeedOptions
		mutate  func(*testing.T, boundedPersistenceSeed)
	}{
		{name: "device scopes text", mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE devices SET scopes_json = ?", strings.Repeat("x", len(wantScopes)+1))
			checkMutation(t, err)
		}},
		{name: "envelope body", mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE vault_envelope SET envelope_json = zeroblob(?)", maxBodyBytes+1)
			checkMutation(t, err)
		}},
		{name: "revision vector", mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE record_revisions SET vector_json = zeroblob(?)", maxVectorBytes+1)
			checkMutation(t, err)
		}},
		{name: "revision witness", mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE record_revisions SET collection_witness_authenticator = zeroblob(33)")
			checkMutation(t, err)
		}},
		{name: "revision payload", mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE revision_objects SET revision_json = zeroblob(?)", maxBodyBytes+1)
			checkMutation(t, err)
		}},
		{name: "operation text", mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE operation_receipts SET operation = ?", strings.Repeat("x", maxOperationBytes+1))
			checkMutation(t, err)
		}},
		{name: "operation response", mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE operation_receipts SET response_json = zeroblob(?)", maxBodyBytes+1)
			checkMutation(t, err)
		}},
		{name: "enrollment scopes text", mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE enrollments SET scopes_json = ?", strings.Repeat("x", len(wantScopes)+1))
			checkMutation(t, err)
		}},
		{name: "enrollment response", mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE enrollments SET response_json = zeroblob(?)", maxBodyBytes+1)
			checkMutation(t, err)
		}},
		{name: "consumed enrollment id", mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE enrollment_grants SET consumed_enrollment_id = ? WHERE consumed_enrollment_id IS NOT NULL", strings.Repeat("x", maxUUIDBytes+1))
			checkMutation(t, err)
		}},
		{name: "snapshot create response", mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE snapshots SET create_response_json = zeroblob(?)", maxBodyBytes+1)
			checkMutation(t, err)
		}},
		{name: "snapshot page response", mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE snapshot_pages SET response_json = zeroblob(?)", maxBodyBytes+1)
			checkMutation(t, err)
		}},
		{name: "marker frontier", options: boundedSeedOptions{marker: true}, mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE collection_markers SET frontier_json = zeroblob(?)", maxVectorBytes+1)
			checkMutation(t, err)
		}},
		{name: "marker body", options: boundedSeedOptions{marker: true}, mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE collection_markers SET marker_json = zeroblob(?)", maxBodyBytes+1)
			checkMutation(t, err)
		}},
		{name: "change marker body", options: boundedSeedOptions{marker: true}, mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE changes SET collection_marker_json = zeroblob(?) WHERE kind = 'collection_marker'", maxBodyBytes+1)
			checkMutation(t, err)
		}},
		{name: "rotation response", options: boundedSeedOptions{rotation: true}, mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE token_rotations SET response_json = zeroblob(?)", maxBodyBytes+1)
			checkMutation(t, err)
		}},
		{name: "self-revocation headers", options: boundedSeedOptions{self: true}, mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE self_revocation_receipts SET response_headers_json = zeroblob(?)", maxBodyBytes+1)
			checkMutation(t, err)
		}},
		{name: "self-revocation response", options: boundedSeedOptions{self: true}, mutate: func(t *testing.T, seed boundedPersistenceSeed) {
			_, err := seed.opened.db.Exec("UPDATE self_revocation_receipts SET response_json = zeroblob(?)", maxBodyBytes+1)
			checkMutation(t, err)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, test.options)
			test.mutate(t, seed)
			if err := seed.opened.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(context.Background(), seed.path, testIdentity)
			if reopened != nil {
				reopened.Close()
			}
			if !errors.Is(err, ErrUnexpectedSchema) {
				t.Fatalf("oversized durable value startup error=%v", err)
			}
		})
	}
}

func checkMutation(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func expectInternalError(t *testing.T, opened *Store, call api.Request) {
	t.Helper()
	if _, protocolErr := opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "internal_error" {
		t.Fatalf("live corrupt durable value error=%v", protocolErr)
	}
}

func TestOversizedDurableValuesFailClosedOnLiveReplayAndRead(t *testing.T) {
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	tests := []struct {
		name    string
		options boundedSeedOptions
		mutate  func(*testing.T, boundedPersistenceSeed)
		call    func(boundedPersistenceSeed) api.Request
	}{
		{
			name: "device scopes during authentication",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE devices SET scopes_json = ?", strings.Repeat("x", len(wantScopes)+1))
				checkMutation(t, err)
			},
			call: func(seed boundedPersistenceSeed) api.Request {
				return api.Request{Method: "GET", Path: "/v1/devices", RequestID: "e2000000-0000-4000-8000-000000000001", Authorization: authorization(seed.token), Now: protocolFixtureTime}
			},
		},
		{
			name: "envelope body",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE vault_envelope SET envelope_json = zeroblob(?)", maxBodyBytes+1)
				checkMutation(t, err)
			},
			call: func(seed boundedPersistenceSeed) api.Request {
				return api.Request{Method: "GET", Path: "/v1/vault-envelope", RequestID: "e2000000-0000-4000-8000-000000000002", Authorization: authorization(seed.token), Now: protocolFixtureTime}
			},
		},
		{
			name: "operation response replay",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE operation_receipts SET response_json = zeroblob(?) WHERE operation = 'sync'", maxBodyBytes+1)
				checkMutation(t, err)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.sync },
		},
		{
			name: "enrollment scopes replay",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE enrollments SET scopes_json = ?", strings.Repeat("x", len(wantScopes)+1))
				checkMutation(t, err)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.enrollment },
		},
		{
			name: "enrollment response replay",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE enrollments SET response_json = zeroblob(?)", maxBodyBytes+1)
				checkMutation(t, err)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.enrollment },
		},
		{
			name: "consumed enrollment ID replay",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE enrollment_grants SET consumed_enrollment_id = ?", strings.Repeat("x", maxUUIDBytes+1))
				checkMutation(t, err)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.enrollment },
		},
		{
			name: "snapshot create response replay",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE snapshots SET create_response_json = zeroblob(?)", maxBodyBytes+1)
				checkMutation(t, err)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.snapshotCreate },
		},
		{
			name: "snapshot page descriptor",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE snapshot_pages SET response_json = zeroblob(?)", maxBodyBytes+1)
				checkMutation(t, err)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.snapshotPage },
		},
		{
			name: "snapshot revision object",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE revision_objects SET revision_json = zeroblob(?)", maxBodyBytes+1)
				checkMutation(t, err)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.snapshotPage },
		},
		{
			name:    "token rotation response replay",
			options: boundedSeedOptions{rotation: true},
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE token_rotations SET response_json = zeroblob(?)", maxBodyBytes+1)
				checkMutation(t, err)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.rotation },
		},
		{
			name:    "self-revocation headers replay",
			options: boundedSeedOptions{self: true},
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE self_revocation_receipts SET response_headers_json = zeroblob(?)", maxBodyBytes+1)
				checkMutation(t, err)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.selfRevocation },
		},
		{
			name:    "self-revocation response replay",
			options: boundedSeedOptions{self: true},
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE self_revocation_receipts SET response_json = zeroblob(?)", maxBodyBytes+1)
				checkMutation(t, err)
			},
			call: func(seed boundedPersistenceSeed) api.Request { return seed.selfRevocation },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, test.options)
			defer seed.opened.Close()
			test.mutate(t, seed)
			expectInternalError(t, seed.opened, test.call(seed))
		})
	}
}

func TestOversizedDeviceScopesFailClosedOnDirectReads(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	if _, err := seed.opened.db.Exec("UPDATE devices SET scopes_json = ?", strings.Repeat("x", len(wantScopes)+1)); err != nil {
		t.Fatal(err)
	}
	if _, _, protocolErr := readDevice(context.Background(), seed.opened.db, seed.deviceID); protocolErr == nil || protocolErr.Code != "internal_error" {
		t.Fatalf("direct device read error=%v", protocolErr)
	}
	if _, _, err := seed.opened.DeviceCredential(context.Background(), seed.deviceID); err == nil {
		t.Fatal("direct device credential accepted oversized scopes")
	}
}

func TestReadinessUsesOneSnapshotAcrossConcurrentEnvelopeCommit(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	var fixture struct {
		BaseMode         putEnvelopeRequest `json:"base_mode"`
		PassphraseRewrap putEnvelopeRequest `json:"passphrase_rewrap"`
	}
	loadFixture(t, "vault-envelope.json", &fixture)

	writer, err := sql.Open("sqlite3", "file:"+seed.path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	writer.SetMaxOpenConns(1)
	if _, err := writer.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		t.Fatal(err)
	}
	setEnvelope := func(request putEnvelopeRequest) {
		t.Helper()
		generation, err := parseUint64(request.NewGeneration)
		if err != nil {
			t.Fatal(err)
		}
		encoded := EncodeUint64(generation)
		body, err := marshalJSON(request.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		transaction, err := writer.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.Exec("UPDATE vault_envelope SET generation = ?, envelope_json = ? WHERE singleton = 1", encoded[:], body); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
		if _, err := transaction.Exec("UPDATE runtime_state SET envelope_generation = ? WHERE singleton = 1", encoded[:]); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
		changeCursor := EncodeUint64(4)
		switch generation {
		case 1:
			if _, err := transaction.Exec("DELETE FROM changes WHERE cursor = ? AND kind = 'envelope_changed'", changeCursor[:]); err != nil {
				transaction.Rollback()
				t.Fatal(err)
			}
			if _, err := transaction.Exec("DELETE FROM change_origins WHERE cursor = ? AND kind = 'envelope_changed'", changeCursor[:]); err != nil {
				transaction.Rollback()
				t.Fatal(err)
			}
			serverCursor := EncodeUint64(3)
			if _, err := transaction.Exec("UPDATE runtime_state SET server_cursor = ? WHERE singleton = 1", serverCursor[:]); err != nil {
				transaction.Rollback()
				t.Fatal(err)
			}
		case 2:
			encodedGeneration := EncodeUint64(2)
			if _, err := transaction.Exec(`
				INSERT INTO change_origins (cursor, kind, envelope_generation)
				VALUES (?, 'envelope_changed', ?)`, changeCursor[:], encodedGeneration[:]); err != nil {
				transaction.Rollback()
				t.Fatal(err)
			}
			if _, err := transaction.Exec(`
				INSERT INTO changes (cursor, kind, received_at_ms)
				VALUES (?, 'envelope_changed', ?)`, changeCursor[:], protocolFixtureTime.Add(time.Second).UnixMilli()); err != nil {
				transaction.Rollback()
				t.Fatal(err)
			}
			if _, err := transaction.Exec("UPDATE runtime_state SET server_cursor = ? WHERE singleton = 1", changeCursor[:]); err != nil {
				transaction.Rollback()
				t.Fatal(err)
			}
		default:
			transaction.Rollback()
			t.Fatalf("unsupported test envelope generation %d", generation)
		}
		if err := transaction.Commit(); err != nil {
			t.Fatal(err)
		}
	}

	ctx := context.Background()
	autocommit := &readinessInterleaveQueryer{
		schemaQueryer: seed.opened.db,
		beforeDeviceQuery: func() {
			setEnvelope(fixture.PassphraseRewrap)
		},
	}
	if err := validateReadinessSnapshot(ctx, autocommit, testIdentity); !errors.Is(err, ErrUnexpectedSchema) || !autocommit.fired {
		t.Fatalf("autocommit readiness did not reproduce a stale snapshot: fired=%v error=%v", autocommit.fired, err)
	}

	setEnvelope(fixture.BaseMode)
	readTransaction, err := seed.opened.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &readinessInterleaveQueryer{
		schemaQueryer: readTransaction,
		beforeDeviceQuery: func() {
			setEnvelope(fixture.PassphraseRewrap)
		},
	}
	if err := validateReadinessSnapshot(ctx, snapshot, testIdentity); err != nil || !snapshot.fired {
		readTransaction.Rollback()
		t.Fatalf("transactional readiness left one snapshot: fired=%v error=%v", snapshot.fired, err)
	}
	if err := readTransaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := seed.opened.Ready(ctx); err != nil {
		t.Fatalf("readiness rejected the valid post-commit state: %v", err)
	}
}

func TestPresentEnvelopeGenerationZeroFailsClosed(t *testing.T) {
	opened, path := openDataPlane(t)
	var fixture struct {
		BaseMode putEnvelopeRequest `json:"base_mode"`
	}
	loadFixture(t, "vault-envelope.json", &fixture)
	fixture.BaseMode.Envelope.EnvelopeGeneration = "0"
	body, err := marshalJSON(fixture.BaseMode.Envelope)
	if err != nil {
		opened.Close()
		t.Fatal(err)
	}
	zero := EncodeUint64(0)
	if _, err := opened.db.Exec(`
		INSERT INTO vault_envelope (singleton, generation, envelope_json)
		VALUES (1, ?, ?)`, zero[:], body); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), path, testIdentity)
	if reopened != nil {
		reopened.Close()
	}
	if !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "inconsistent envelope row") {
		t.Fatalf("generation-zero envelope startup error=%v", err)
	}
}

func TestEnvelopePutRejectsPresentGenerationZeroWithoutMutation(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	deviceID := "e8400000-0000-4000-8000-000000000001"
	token := tokenWithByte(0xe4)
	enrollDevice(t, opened, protocolFixtureTime,
		"e8400000-0000-4000-8000-000000000002", deviceID,
		"e8400000-0000-4000-8000-000000000003", token)
	var fixture struct {
		BaseMode putEnvelopeRequest `json:"base_mode"`
	}
	loadFixture(t, "vault-envelope.json", &fixture)
	forbidden := fixture.BaseMode.Envelope
	forbidden.EnvelopeGeneration = "0"
	forbiddenBody, err := marshalJSON(forbidden)
	if err != nil {
		t.Fatal(err)
	}
	zero := EncodeUint64(0)
	if _, err := opened.db.Exec(`
		INSERT INTO vault_envelope (singleton, generation, envelope_json)
		VALUES (1, ?, ?)`, zero[:], forbiddenBody); err != nil {
		t.Fatal(err)
	}
	requestBody, err := marshalJSON(fixture.BaseMode)
	if err != nil {
		t.Fatal(err)
	}
	expectInternalError(t, opened, api.Request{
		Method: "PUT", Path: "/v1/vault-envelope", RequestID: "e8400000-0000-4000-8000-000000000004",
		Authorization: authorization(token), Body: requestBody, Now: protocolFixtureTime.Add(time.Second),
	})
	var runtimeGenerationBytes, serverCursorBytes, rowGenerationBytes, retainedBody []byte
	var envelopeChanges, receipts int
	if err := opened.db.QueryRow(`
		SELECT r.envelope_generation, r.server_cursor, v.generation, v.envelope_json,
		       (SELECT count(*) FROM changes WHERE kind = 'envelope_changed'),
		       (SELECT count(*) FROM operation_receipts WHERE operation = 'vault-envelope')
		FROM runtime_state r JOIN vault_envelope v ON v.singleton = r.singleton
		WHERE r.singleton = 1`).Scan(
		&runtimeGenerationBytes, &serverCursorBytes, &rowGenerationBytes, &retainedBody,
		&envelopeChanges, &receipts,
	); err != nil {
		t.Fatal(err)
	}
	runtimeGeneration, runtimeErr := DecodeUint64(runtimeGenerationBytes)
	serverCursor, cursorErr := DecodeUint64(serverCursorBytes)
	rowGeneration, rowErr := DecodeUint64(rowGenerationBytes)
	if runtimeErr != nil || cursorErr != nil || rowErr != nil || runtimeGeneration != 0 || rowGeneration != 0 || serverCursor != 1 ||
		envelopeChanges != 0 || receipts != 0 || !slices.Equal(retainedBody, forbiddenBody) {
		t.Fatalf("generation-zero PUT mutated state: runtime=%d row=%d cursor=%d changes=%d receipts=%d", runtimeGeneration, rowGeneration, serverCursor, envelopeChanges, receipts)
	}
}

func TestEnvelopePutValidatesPermanentHistoryBeforeMutation(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	collectBoundedSeedRevision(t, seed)
	two := EncodeUint64(2)
	four := EncodeUint64(4)
	if _, err := seed.opened.db.Exec("DELETE FROM changes WHERE cursor = ? AND kind = 'envelope_changed'", two[:]); err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		BaseMode         putEnvelopeRequest `json:"base_mode"`
		PassphraseRewrap putEnvelopeRequest `json:"passphrase_rewrap"`
	}
	loadFixture(t, "vault-envelope.json", &fixture)
	expectedBody, err := marshalJSON(fixture.BaseMode.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	requestBody, err := marshalJSON(fixture.PassphraseRewrap)
	if err != nil {
		t.Fatal(err)
	}
	requestID := "e8300000-0000-4000-8000-000000000001"
	expectInternalError(t, seed.opened, api.Request{
		Method: "PUT", Path: "/v1/vault-envelope", RequestID: requestID,
		Authorization: authorization(seed.token), Body: requestBody, Now: protocolFixtureTime.Add(4 * time.Second),
	})
	var runtimeGenerationBytes, serverCursorBytes, rowGenerationBytes, retainedBody []byte
	var newOriginCount, newChangeCount, newReceiptCount int
	if err := seed.opened.db.QueryRow(`
		SELECT r.envelope_generation, r.server_cursor, v.generation, v.envelope_json,
		       (SELECT count(*) FROM change_origins WHERE kind = 'envelope_changed' AND envelope_generation = ?),
		       (SELECT count(*) FROM changes WHERE cursor = ?),
		       (SELECT count(*) FROM operation_receipts WHERE operation = 'vault-envelope' AND request_id = ?)
		FROM runtime_state r JOIN vault_envelope v ON v.singleton = r.singleton
		WHERE r.singleton = 1`, two[:], four[:], requestID).Scan(
		&runtimeGenerationBytes, &serverCursorBytes, &rowGenerationBytes, &retainedBody,
		&newOriginCount, &newChangeCount, &newReceiptCount,
	); err != nil {
		t.Fatal(err)
	}
	runtimeGeneration, runtimeErr := DecodeUint64(runtimeGenerationBytes)
	serverCursor, cursorErr := DecodeUint64(serverCursorBytes)
	rowGeneration, rowErr := DecodeUint64(rowGenerationBytes)
	var retained vaultEnvelope
	bodyErr := decodeStoredCanonical(retainedBody, &retained)
	if runtimeErr != nil || cursorErr != nil || rowErr != nil || bodyErr != nil || runtimeGeneration != 1 || rowGeneration != 1 || serverCursor != 3 ||
		retained.EnvelopeGeneration != "1" || !slices.Equal(retainedBody, expectedBody) || newOriginCount != 0 || newChangeCount != 0 || newReceiptCount != 0 {
		t.Fatalf("history-corrupt PUT mutated state: runtime=%d row=%d cursor=%d body_generation=%q origins=%d changes=%d receipts=%d",
			runtimeGeneration, rowGeneration, serverCursor, retained.EnvelopeGeneration, newOriginCount, newChangeCount, newReceiptCount)
	}
}

func TestEnvelopePutRejectsFutureOrphanCursorWithoutMutation(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	collectBoundedSeedRevision(t, seed)
	one := EncodeUint64(1)
	two := EncodeUint64(2)
	four := EncodeUint64(4)
	zero := EncodeUint64(0)
	futureRevision := boundedNextRevision(seed, "e8310000-0000-4000-8000-000000000001")
	vectorBody, err := json.Marshal(futureRevision.VersionVector)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := marshalJSON(futureRevision)
	if err != nil {
		t.Fatal(err)
	}
	contentHash := sha256.Sum256(canonical)
	witness, err := decodeBase64(*futureRevision.CollectionWitnessAuthenticator, 32, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := seed.opened.db.Exec(`
		INSERT INTO record_revisions (
			revision_id, record_id, author_device_id, author_counter,
			vector_json, collection_witness_authenticator, tombstone,
			content_hash, received_at_ms, accepted_uptime_ms,
			change_cursor, collected_generation, retained, undominated
		) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, 0, 0)`,
		futureRevision.RevisionID, futureRevision.RecordID, futureRevision.AuthorDeviceID,
		two[:], vectorBody, witness, contentHash[:], protocolFixtureTime.Add(3*time.Second).UnixMilli(),
		zero[:], four[:], one[:],
	); err != nil {
		t.Fatal(err)
	}
	type putState struct {
		runtime, envelope                                                       string
		origins, envelopeOrigins, changes, envelopeChanges, receipts, retention int
	}
	capture := func() putState {
		t.Helper()
		var serverCursor, floor, envelopeGeneration, secretGeneration, collectionGeneration, uptime, bootID, rowGeneration, body []byte
		var scanAfter string
		var state putState
		if err := seed.opened.db.QueryRow(`
			SELECT r.server_cursor, r.cursor_floor, r.envelope_generation,
			       r.instance_secret_generation, r.collection_generation,
			       r.accumulated_uptime_ms, r.active_boot_id,
			       r.collection_scan_after_record_id, v.generation, v.envelope_json,
			       (SELECT count(*) FROM change_origins),
			       (SELECT count(*) FROM change_origins WHERE kind = 'envelope_changed'),
			       (SELECT count(*) FROM changes),
			       (SELECT count(*) FROM changes WHERE kind = 'envelope_changed'),
			       (SELECT count(*) FROM operation_receipts),
			       (SELECT count(*) FROM operation_receipt_retention)
			FROM runtime_state r JOIN vault_envelope v ON v.singleton = r.singleton
			WHERE r.singleton = 1`).Scan(
			&serverCursor, &floor, &envelopeGeneration, &secretGeneration, &collectionGeneration,
			&uptime, &bootID, &scanAfter, &rowGeneration, &body,
			&state.origins, &state.envelopeOrigins, &state.changes, &state.envelopeChanges,
			&state.receipts, &state.retention,
		); err != nil {
			t.Fatal(err)
		}
		state.runtime = fmt.Sprintf("%x|%x|%x|%x|%x|%x|%x|%s", serverCursor, floor, envelopeGeneration, secretGeneration, collectionGeneration, uptime, bootID, scanAfter)
		state.envelope = fmt.Sprintf("%x|%x", rowGeneration, body)
		return state
	}
	before := capture()
	var fixture struct {
		PassphraseRewrap putEnvelopeRequest `json:"passphrase_rewrap"`
	}
	loadFixture(t, "vault-envelope.json", &fixture)
	requestBody, err := marshalJSON(fixture.PassphraseRewrap)
	if err != nil {
		t.Fatal(err)
	}
	requestID := "e8310000-0000-4000-8000-000000000002"
	expectInternalError(t, seed.opened, api.Request{
		Method: "PUT", Path: "/v1/vault-envelope", RequestID: requestID,
		Authorization: authorization(seed.token), Body: requestBody, Now: protocolFixtureTime.Add(4 * time.Second),
	})
	after := capture()
	if before != after {
		t.Fatalf("future-owner PUT mutated state: before=%+v after=%+v", before, after)
	}
	var cursorBytes, collectedBytes []byte
	var retained, originCount, changeCount, receiptCount int
	if err := seed.opened.db.QueryRow(`
		SELECT r.change_cursor, r.collected_generation, r.retained,
		       (SELECT count(*) FROM change_origins WHERE cursor = ?),
		       (SELECT count(*) FROM changes WHERE cursor = ?),
		       (SELECT count(*) FROM operation_receipts WHERE operation = 'vault-envelope' AND request_id = ?)
		FROM record_revisions r WHERE r.revision_id = ?`,
		four[:], four[:], requestID, futureRevision.RevisionID,
	).Scan(&cursorBytes, &collectedBytes, &retained, &originCount, &changeCount, &receiptCount); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cursorBytes, four[:]) || !slices.Equal(collectedBytes, one[:]) || retained != 0 || originCount != 0 || changeCount != 0 || receiptCount != 0 {
		t.Fatalf("future owner changed: cursor=%x generation=%x retained=%d origins=%d changes=%d receipts=%d",
			cursorBytes, collectedBytes, retained, originCount, changeCount, receiptCount)
	}
}

func TestEnvelopeChangeCannotReuseCollectedRevisionCursor(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	collectBoundedSeedRevision(t, seed)
	if _, err := seed.opened.db.Exec("PRAGMA foreign_keys = OFF"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = seed.opened.db.Exec("PRAGMA foreign_keys = ON") })
	two := EncodeUint64(2)
	three := EncodeUint64(3)
	if _, err := seed.opened.db.Exec("DELETE FROM changes WHERE cursor = ? AND kind = 'envelope_changed'", two[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.opened.db.Exec(`
		INSERT INTO changes (cursor, kind, received_at_ms)
		VALUES (?, 'envelope_changed', ?)`, three[:], protocolFixtureTime.Add(time.Second).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.opened.db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		t.Fatal(err)
	}
	if err := validatePersistentState(context.Background(), seed.opened.db, testIdentity); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "change row does not match durable origin") {
		t.Fatalf("collected-cursor envelope substitution error=%v", err)
	}
}

func TestEnvelopeHistoryStreamsAcrossBoundedSnapshotCuts(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	const historyCount = 2048
	transaction, err := opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	for generation := uint64(1); generation <= historyCount; generation++ {
		encoded := EncodeUint64(generation)
		if _, err := transaction.Exec(`
			INSERT INTO change_origins (cursor, kind, envelope_generation)
			VALUES (?, 'envelope_changed', ?)`, encoded[:], encoded[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := transaction.Exec(`
			INSERT INTO changes (cursor, kind, received_at_ms)
			VALUES (?, 'envelope_changed', ?)`, encoded[:], protocolFixtureTime.UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	cuts := []uint64{0, 1, 17, 511, 1024, 1537, historyCount}
	generations, err := validatePersistentChangeOrigins(context.Background(), opened.db, historyCount, historyCount, cuts)
	if err != nil {
		t.Fatal(err)
	}
	for _, cut := range cuts {
		if generations[cut] != cut {
			t.Fatalf("generation at cut %d = %d", cut, generations[cut])
		}
	}
}

func TestChangeOriginScanBoundsFieldsBeforeLoading(t *testing.T) {
	const oversizedBytes = maxBodyBytes + 1
	oversizedSuffix := strings.Repeat("x", oversizedBytes)
	oversizedKind := "envelope_changed\x00" + oversizedSuffix
	oversizedRevisionID := "e8330000-0000-4000-8000-000000000001\x00" + oversizedSuffix
	tests := []struct {
		name   string
		mutate func(*testing.T, *sql.DB)
	}{
		{
			name: "origin and change cursor",
			mutate: func(t *testing.T, database *sql.DB) {
				two := EncodeUint64(2)
				if _, err := database.Exec("UPDATE changes SET cursor = zeroblob(?) WHERE cursor = ?", oversizedBytes, two[:]); err != nil {
					t.Fatal(err)
				}
				if _, err := database.Exec("UPDATE change_origins SET cursor = zeroblob(?) WHERE cursor = ?", oversizedBytes, two[:]); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "NUL-suffixed origin and change kind",
			mutate: func(t *testing.T, database *sql.DB) {
				two := EncodeUint64(2)
				if _, err := database.Exec("UPDATE changes SET kind = ? WHERE cursor = ?", oversizedKind, two[:]); err != nil {
					t.Fatal(err)
				}
				if _, err := database.Exec("UPDATE change_origins SET kind = ? WHERE cursor = ?", oversizedKind, two[:]); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "envelope generation",
			mutate: func(t *testing.T, database *sql.DB) {
				if _, err := database.Exec("UPDATE change_origins SET envelope_generation = zeroblob(?) WHERE kind = 'envelope_changed'", oversizedBytes); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "NUL-suffixed joined revision ID",
			mutate: func(t *testing.T, database *sql.DB) {
				three := EncodeUint64(3)
				if _, err := database.Exec("UPDATE record_revisions SET revision_id = ? WHERE change_cursor = ?", oversizedRevisionID, three[:]); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{})
			defer seed.opened.Close()
			if _, err := seed.opened.db.Exec("PRAGMA foreign_keys = OFF"); err != nil {
				t.Fatal(err)
			}
			if _, err := seed.opened.db.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, seed.opened.db)
			if _, err := seed.opened.db.Exec("PRAGMA ignore_check_constraints = OFF"); err != nil {
				t.Fatal(err)
			}
			if _, err := seed.opened.db.Exec("PRAGMA foreign_keys = ON"); err != nil {
				t.Fatal(err)
			}
			if _, err := validatePersistentChangeOrigins(context.Background(), seed.opened.db, 3, 1, []uint64{3}); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "invalid change origin") {
				t.Fatalf("oversized %s error=%v", test.name, err)
			}
		})
	}
}

func TestOversizedEnvelopeOriginGenerationFailsClosedAtStartup(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	if _, err := seed.opened.db.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
		seed.opened.Close()
		t.Fatal(err)
	}
	if _, err := seed.opened.db.Exec("UPDATE change_origins SET envelope_generation = zeroblob(?) WHERE kind = 'envelope_changed'", maxBodyBytes+1); err != nil {
		seed.opened.Close()
		t.Fatal(err)
	}
	if err := seed.opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), seed.path, testIdentity)
	if reopened != nil {
		reopened.Close()
	}
	if !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "invalid change origin") {
		t.Fatalf("oversized envelope origin startup error=%v", err)
	}
}

func TestEnvelopePutBoundsPermanentOriginBeforeMutation(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	if _, err := seed.opened.db.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.opened.db.Exec("UPDATE change_origins SET envelope_generation = zeroblob(?) WHERE kind = 'envelope_changed'", maxBodyBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.opened.db.Exec("PRAGMA ignore_check_constraints = OFF"); err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		BaseMode         putEnvelopeRequest `json:"base_mode"`
		PassphraseRewrap putEnvelopeRequest `json:"passphrase_rewrap"`
	}
	loadFixture(t, "vault-envelope.json", &fixture)
	expectedBody, err := marshalJSON(fixture.BaseMode.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	requestBody, err := marshalJSON(fixture.PassphraseRewrap)
	if err != nil {
		t.Fatal(err)
	}
	requestID := "e8320000-0000-4000-8000-000000000001"
	expectInternalError(t, seed.opened, api.Request{
		Method: "PUT", Path: "/v1/vault-envelope", RequestID: requestID,
		Authorization: authorization(seed.token), Body: requestBody, Now: protocolFixtureTime.Add(4 * time.Second),
	})
	two := EncodeUint64(2)
	four := EncodeUint64(4)
	var runtimeGenerationBytes, serverCursorBytes, rowGenerationBytes, retainedBody []byte
	var originLength int64
	var newOriginCount, newChangeCount, newReceiptCount int
	if err := seed.opened.db.QueryRow(`
		SELECT r.envelope_generation, r.server_cursor, v.generation, v.envelope_json,
		       (SELECT length(envelope_generation) FROM change_origins WHERE kind = 'envelope_changed'),
		       (SELECT count(*) FROM change_origins WHERE kind = 'envelope_changed' AND envelope_generation = ?),
		       (SELECT count(*) FROM changes WHERE cursor = ?),
		       (SELECT count(*) FROM operation_receipts WHERE operation = 'vault-envelope' AND request_id = ?)
		FROM runtime_state r JOIN vault_envelope v ON v.singleton = r.singleton
		WHERE r.singleton = 1`, two[:], four[:], requestID).Scan(
		&runtimeGenerationBytes, &serverCursorBytes, &rowGenerationBytes, &retainedBody,
		&originLength, &newOriginCount, &newChangeCount, &newReceiptCount,
	); err != nil {
		t.Fatal(err)
	}
	runtimeGeneration, runtimeErr := DecodeUint64(runtimeGenerationBytes)
	serverCursor, cursorErr := DecodeUint64(serverCursorBytes)
	rowGeneration, rowErr := DecodeUint64(rowGenerationBytes)
	if runtimeErr != nil || cursorErr != nil || rowErr != nil || runtimeGeneration != 1 || rowGeneration != 1 || serverCursor != 3 ||
		originLength != maxBodyBytes+1 || !slices.Equal(retainedBody, expectedBody) || newOriginCount != 0 || newChangeCount != 0 || newReceiptCount != 0 {
		t.Fatalf("oversized-origin PUT mutated state: runtime=%d row=%d cursor=%d origin_length=%d origins=%d changes=%d receipts=%d",
			runtimeGeneration, rowGeneration, serverCursor, originLength, newOriginCount, newChangeCount, newReceiptCount)
	}
}

func TestExactEnrollmentReplayBypassesNewAttemptRateLimit(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	for retry := 0; retry < 5; retry++ {
		response, protocolErr := seed.opened.HandleAPI(context.Background(), seed.enrollment)
		if protocolErr != nil || response.Status != http.StatusOK {
			t.Fatalf("exact enrollment retry %d: response=%+v error=%v", retry+1, response, protocolErr)
		}
	}
}

func TestRetainedEnrollmentDeviceConflictBypassesNewAttemptRateLimit(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	now := protocolFixtureTime.Add(time.Minute)
	grant := createGrant(t, seed.opened, now)
	defer clear(grant.Grant)
	body, _ := marshalJSON(enrollmentRequest{
		ProtocolVersion: "1",
		EnrollmentID:    "e8000000-0000-4000-8000-000000000001",
		DeviceID:        seed.deviceID,
		DeviceToken:     base64.RawURLEncoding.EncodeToString(tokenWithByte(0xe8)),
		Scopes:          auth.FixedScopes(),
	})
	call := api.Request{
		Method: "POST", Path: "/v1/enrollments", RequestID: "e8000000-0000-4000-8000-000000000002",
		Authorization: "JAT-Enrollment " + base64.RawURLEncoding.EncodeToString(grant.Grant), Body: body, Now: now,
	}
	for attempt := 1; attempt <= 6; attempt++ {
		if _, protocolErr := seed.opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "enrollment_replay_mismatch" {
			t.Fatalf("retained device conflict attempt %d error=%v", attempt, protocolErr)
		}
	}
}

func TestStartupRejectsRetainedChangeGap(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	two := EncodeUint64(2)
	if _, err := seed.opened.db.Exec("DELETE FROM changes WHERE cursor = ?", two[:]); err != nil {
		seed.opened.Close()
		t.Fatal(err)
	}
	if err := seed.opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), seed.path, testIdentity)
	if reopened != nil {
		reopened.Close()
	}
	if !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "retained change cursor gap") {
		t.Fatalf("retained change gap startup error=%v", err)
	}
}

func TestSnapshotReferenceAcceptedAfterCutFailsClosed(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	rewriteSnapshotCutCursor(t, seed.opened, seed.snapshot.SnapshotID, 2)
	ctx := context.Background()
	serverCursor, envelopeGeneration, _, collectionGeneration, err := validatePersistentRuntime(ctx, seed.opened.db)
	if err != nil {
		t.Fatal(err)
	}
	devices, err := validatePersistentDevices(ctx, seed.opened.db, serverCursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePersistentSnapshots(ctx, seed.opened.db, testIdentity, devices, serverCursor, envelopeGeneration, collectionGeneration); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "snapshot reference accepted after cut") {
		t.Fatalf("post-cut snapshot reference error=%v", err)
	}
}

func TestHistoricalSnapshotEnvelopeGenerationMustMatchCut(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	var fixture struct {
		PassphraseRewrap putEnvelopeRequest `json:"passphrase_rewrap"`
	}
	loadFixture(t, "vault-envelope.json", &fixture)
	body, err := marshalJSON(fixture.PassphraseRewrap)
	if err != nil {
		t.Fatal(err)
	}
	response, protocolErr := seed.opened.HandleAPI(context.Background(), api.Request{
		Method: "PUT", Path: "/v1/vault-envelope", RequestID: "e8500000-0000-4000-8000-000000000001",
		Authorization: authorization(seed.token), Body: body, Now: protocolFixtureTime.Add(3 * time.Second),
	})
	if protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("advance envelope: response=%+v error=%v", response, protocolErr)
	}
	var retainedCreate []byte
	if err := seed.opened.db.QueryRow("SELECT create_response_json FROM snapshots WHERE snapshot_id = ?", seed.snapshot.SnapshotID).Scan(&retainedCreate); err != nil {
		t.Fatal(err)
	}
	var create snapshotCreateResponse
	if err := json.Unmarshal(retainedCreate, &create); err != nil {
		t.Fatal(err)
	}
	create.EnvelopeGeneration = fixture.PassphraseRewrap.NewGeneration
	create.Envelope = fixture.PassphraseRewrap.Envelope
	rewrittenCreate, err := marshalJSON(create)
	if err != nil {
		t.Fatal(err)
	}
	two := EncodeUint64(2)
	if _, err := seed.opened.db.Exec(`
		UPDATE snapshots
		SET envelope_generation = ?, create_response_json = ?,
		    metadata_bytes = metadata_bytes - ? + ?
		WHERE snapshot_id = ?`, two[:], rewrittenCreate, len(retainedCreate), len(rewrittenCreate), seed.snapshot.SnapshotID); err != nil {
		t.Fatal(err)
	}
	if err := validateSnapshotsAtCurrentState(t, seed.opened); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "snapshot envelope generation does not match cut") {
		t.Fatalf("historical snapshot envelope error=%v", err)
	}
}

func TestEnvelopeHistoryBelowCollectionFloorRemainsRequired(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	collectBoundedSeedRevision(t, seed)
	two := EncodeUint64(2)
	if _, err := seed.opened.db.Exec("DELETE FROM changes WHERE cursor = ? AND kind = 'envelope_changed'", two[:]); err != nil {
		t.Fatal(err)
	}
	if err := validatePersistentState(context.Background(), seed.opened.db, testIdentity); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "invalid envelope change origin") {
		t.Fatalf("collected-floor envelope history error=%v", err)
	}
}

func TestSnapshotMarkerBarrierBeyondCutFailsClosed(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{marker: true})
	defer seed.opened.Close()
	deviceID := "e9000000-0000-4000-8000-000000000002"
	token := tokenWithByte(0xe9)
	enrollDevice(t, seed.opened, protocolFixtureTime.Add(3*time.Second),
		"e9000000-0000-4000-8000-000000000001", deviceID,
		"e9000000-0000-4000-8000-000000000003", token)
	snapshot := createBoundedSnapshot(t, seed.opened, deviceID, token,
		"e9000000-0000-4000-8000-000000000004", protocolFixtureTime.Add(4*time.Second))
	cut, _ := parseUint64(snapshot.CutCursor)
	rewriteSnapshotPageDescriptor(t, seed.opened, snapshot.SnapshotID,
		func(descriptor snapshotPageDescriptor) bool { return len(descriptor.CollectionMarkers) != 0 },
		func(descriptor *snapshotPageDescriptor) {
			descriptor.CollectionMarkers[0].BarrierCursor = encodeUint64Text(cut + 1)
		})
	if err := validateSnapshotsAtCurrentState(t, seed.opened); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "snapshot marker barrier exceeds cut") {
		t.Fatalf("post-cut snapshot marker error=%v", err)
	}
}

func TestCurrentCutSnapshotRequiresCompleteSourceRegistry(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	deviceID := "ea000000-0000-4000-8000-000000000002"
	token := tokenWithByte(0xea)
	enrollDevice(t, seed.opened, protocolFixtureTime.Add(3*time.Second),
		"ea000000-0000-4000-8000-000000000001", deviceID,
		"ea000000-0000-4000-8000-000000000003", token)
	snapshot := createBoundedSnapshot(t, seed.opened, deviceID, token,
		"ea000000-0000-4000-8000-000000000004", protocolFixtureTime.Add(4*time.Second))
	rewriteSnapshotPageDescriptor(t, seed.opened, snapshot.SnapshotID,
		func(descriptor snapshotPageDescriptor) bool { return len(descriptor.SourceDevices) != 0 },
		func(descriptor *snapshotPageDescriptor) {
			retained := descriptor.SourceDevices[:0]
			for _, source := range descriptor.SourceDevices {
				if source.DeviceID != deviceID {
					retained = append(retained, source)
				}
			}
			descriptor.SourceDevices = retained
		})
	if err := validateSnapshotsAtCurrentState(t, seed.opened); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "snapshot source registry does not match cut") {
		t.Fatalf("incomplete current-cut source registry error=%v", err)
	}
}

func TestHistoricalSnapshotRequiresCompleteZeroAuthorSourceRegistry(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	zeroAuthorID := "ea100000-0000-4000-8000-000000000002"
	zeroAuthorToken := tokenWithByte(0xa1)
	enrollDevice(t, seed.opened, protocolFixtureTime.Add(3*time.Second),
		"ea100000-0000-4000-8000-000000000001", zeroAuthorID,
		"ea100000-0000-4000-8000-000000000003", zeroAuthorToken)
	snapshot := createBoundedSnapshot(t, seed.opened, zeroAuthorID, zeroAuthorToken,
		"ea100000-0000-4000-8000-000000000004", protocolFixtureTime.Add(4*time.Second))
	enrollDevice(t, seed.opened, protocolFixtureTime.Add(5*time.Second),
		"ea100000-0000-4000-8000-000000000005", "ea100000-0000-4000-8000-000000000006",
		"ea100000-0000-4000-8000-000000000007", tokenWithByte(0xa2))
	rewriteSnapshotPageDescriptor(t, seed.opened, snapshot.SnapshotID,
		func(descriptor snapshotPageDescriptor) bool { return len(descriptor.SourceDevices) != 0 },
		func(descriptor *snapshotPageDescriptor) {
			retained := descriptor.SourceDevices[:0]
			for _, source := range descriptor.SourceDevices {
				if source.DeviceID != zeroAuthorID {
					retained = append(retained, source)
				}
			}
			descriptor.SourceDevices = retained
		})
	if err := validateSnapshotsAtCurrentState(t, seed.opened); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "snapshot source registry does not match cut") {
		t.Fatalf("historical zero-author source omission error=%v", err)
	}
}

func TestOlderSnapshotAllowsLaterDeviceEnrollment(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	enrollDevice(t, seed.opened, protocolFixtureTime.Add(3*time.Second),
		"eb000000-0000-4000-8000-000000000001", "eb000000-0000-4000-8000-000000000002",
		"eb000000-0000-4000-8000-000000000003", tokenWithByte(0xeb))
	if err := validateSnapshotsAtCurrentState(t, seed.opened); err != nil {
		t.Fatalf("older snapshot rejected after later enrollment: %v", err)
	}
}

func TestHistoricalSnapshotSourceCounterMustMatchCut(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	revision := boundedNextRevision(seed, "ec000000-0000-4000-8000-000000000001")
	response, protocolErr := seed.opened.HandleAPI(context.Background(), boundedSyncCall(
		seed, "ec000000-0000-4000-8000-000000000002", "0", []recordRevision{revision},
	))
	if protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("advance author counter: response=%+v error=%v", response, protocolErr)
	}
	rewriteSnapshotPageDescriptor(t, seed.opened, seed.snapshot.SnapshotID,
		func(descriptor snapshotPageDescriptor) bool { return len(descriptor.SourceDevices) != 0 },
		func(descriptor *snapshotPageDescriptor) {
			for index := range descriptor.SourceDevices {
				if descriptor.SourceDevices[index].DeviceID == seed.deviceID {
					descriptor.SourceDevices[index].MaxAuthorCounter = "2"
					return
				}
			}
			t.Fatal("snapshot source device not found")
		})
	if err := validateSnapshotsAtCurrentState(t, seed.opened); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "snapshot source registry does not match cut") {
		t.Fatalf("historical snapshot source counter error=%v", err)
	}
}

func TestSnapshotMarkerMustMatchLatestAtCut(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{marker: true})
	defer seed.opened.Close()
	deviceID := "ed000000-0000-4000-8000-000000000002"
	token := tokenWithByte(0xed)
	enrollDevice(t, seed.opened, protocolFixtureTime.Add(3*time.Second),
		"ed000000-0000-4000-8000-000000000001", deviceID,
		"ed000000-0000-4000-8000-000000000003", token)
	snapshot := createBoundedSnapshot(t, seed.opened, deviceID, token,
		"ed000000-0000-4000-8000-000000000004", protocolFixtureTime.Add(4*time.Second))
	rewriteSnapshotPageDescriptor(t, seed.opened, snapshot.SnapshotID,
		func(descriptor snapshotPageDescriptor) bool { return len(descriptor.CollectionMarkers) != 0 },
		func(descriptor *snapshotPageDescriptor) {
			barrier, err := parseUint64(descriptor.CollectionMarkers[0].BarrierCursor)
			if err != nil || barrier == 0 {
				t.Fatalf("snapshot marker barrier=%q error=%v", descriptor.CollectionMarkers[0].BarrierCursor, err)
			}
			descriptor.CollectionMarkers[0].BarrierCursor = encodeUint64Text(barrier - 1)
		})
	if err := validateSnapshotsAtCurrentState(t, seed.opened); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "snapshot marker does not match cut") {
		t.Fatalf("post-cut snapshot marker error=%v", err)
	}
}

func TestSnapshotReferenceMustBeUndominatedAtCut(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	revision := boundedNextRevision(seed, "ee000000-0000-4000-8000-000000000001")
	response, protocolErr := seed.opened.HandleAPI(context.Background(), boundedSyncCall(
		seed, "ee000000-0000-4000-8000-000000000002", "0", []recordRevision{revision},
	))
	var sync syncResponse
	if protocolErr != nil || response.Status != http.StatusOK || json.Unmarshal(response.Body, &sync) != nil {
		t.Fatalf("advance snapshot frontier: response=%+v error=%v", response, protocolErr)
	}
	cut, err := parseUint64(sync.ServerCursor)
	if err != nil {
		t.Fatal(err)
	}
	rewriteSnapshotPageDescriptor(t, seed.opened, seed.snapshot.SnapshotID,
		func(descriptor snapshotPageDescriptor) bool { return len(descriptor.SourceDevices) != 0 },
		func(descriptor *snapshotPageDescriptor) {
			for index := range descriptor.SourceDevices {
				if descriptor.SourceDevices[index].DeviceID == seed.deviceID {
					descriptor.SourceDevices[index].MaxAuthorCounter = "2"
					return
				}
			}
			t.Fatal("snapshot source device not found")
		})
	rewriteSnapshotCutCursor(t, seed.opened, seed.snapshot.SnapshotID, cut)
	if err := validateSnapshotsAtCurrentState(t, seed.opened); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "snapshot reference was dominated at cut") {
		t.Fatalf("dominated snapshot reference error=%v", err)
	}
}

func TestSnapshotRequiresEveryConcurrentFrontierHeadAtCut(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{})
	defer seed.opened.Close()
	deviceID := "ee100000-0000-4000-8000-000000000002"
	token := tokenWithByte(0xe3)
	enrollDevice(t, seed.opened, protocolFixtureTime.Add(3*time.Second),
		"ee100000-0000-4000-8000-000000000001", deviceID,
		"ee100000-0000-4000-8000-000000000003", token)
	witness := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	revisionID := "ee100000-0000-4000-8000-000000000004"
	revision := recordRevision{
		RecordID: seed.recordID, RevisionID: revisionID, AuthorDeviceID: deviceID,
		AuthorCounter: "1", VersionVector: []vectorEntry{{DeviceID: deviceID, Counter: "1"}},
		CollectionWitnessAuthenticator: &witness, PayloadSchema: "1", CryptoSuite: cryptoSuite,
		Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	syncBody, err := marshalJSON(syncRequest{
		ProtocolVersion: "1", DeviceID: deviceID, RequestID: "ee100000-0000-4000-8000-000000000005",
		AfterCursor: "0", AckCursor: "0", Mutations: []recordRevision{revision},
	})
	if err != nil {
		t.Fatal(err)
	}
	response, protocolErr := seed.opened.HandleAPI(context.Background(), api.Request{
		Method: "POST", Path: "/v1/sync", RequestID: "ee100000-0000-4000-8000-000000000005",
		Authorization: authorization(token), Body: syncBody, Now: protocolFixtureTime.Add(4 * time.Second),
	})
	if protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("accept concurrent head: response=%+v error=%v", response, protocolErr)
	}
	snapshot := createBoundedSnapshot(t, seed.opened, deviceID, token,
		"ee100000-0000-4000-8000-000000000006", protocolFixtureTime.Add(5*time.Second))
	rewriteSnapshotPageDescriptor(t, seed.opened, snapshot.SnapshotID,
		func(descriptor snapshotPageDescriptor) bool {
			return slices.Contains(descriptor.RevisionIDs, revisionID)
		},
		func(descriptor *snapshotPageDescriptor) {
			retained := descriptor.RevisionIDs[:0]
			for _, storedID := range descriptor.RevisionIDs {
				if storedID != revisionID {
					retained = append(retained, storedID)
				}
			}
			descriptor.RevisionIDs = retained
		})
	deleteSnapshotRevisionReference(t, seed.opened, snapshot.SnapshotID, revisionID)
	if err := validateSnapshotsAtCurrentState(t, seed.opened); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "snapshot frontier head is missing at cut") {
		t.Fatalf("missing concurrent snapshot head error=%v", err)
	}
}

func createBoundedSnapshot(t *testing.T, opened *Store, deviceID string, token []byte, requestID string, now time.Time) snapshotCreateResponse {
	t.Helper()
	body, _ := marshalJSON(snapshotCreateRequest{
		ProtocolVersion: "1", DeviceID: deviceID, RequestID: requestID,
		RequiredCapabilities: append([]string(nil), requiredSnapshotCapabilities...),
	})
	response, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "POST", Path: "/v1/snapshot-reads", RequestID: requestID,
		Authorization: authorization(token), Body: body, Now: now,
	})
	var snapshot snapshotCreateResponse
	if protocolErr != nil || response.Status != http.StatusCreated || json.Unmarshal(response.Body, &snapshot) != nil {
		t.Fatalf("create bounded snapshot: response=%+v error=%v", response, protocolErr)
	}
	return snapshot
}

func rewriteSnapshotPageDescriptor(t *testing.T, opened *Store, snapshotID string, matches func(snapshotPageDescriptor) bool, rewrite func(*snapshotPageDescriptor)) {
	t.Helper()
	rows, err := opened.db.Query("SELECT page_index, response_json FROM snapshot_pages WHERE snapshot_id = ? ORDER BY page_index", snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	matchedIndex := int64(-1)
	var matchedBody []byte
	var descriptor snapshotPageDescriptor
	for rows.Next() {
		var index int64
		var body []byte
		var candidate snapshotPageDescriptor
		if rows.Scan(&index, &body) != nil || decodeStoredSnapshotPageDescriptor(body, &candidate) != nil {
			rows.Close()
			t.Fatal("read stored snapshot page descriptor")
		}
		if matches(candidate) {
			if matchedIndex >= 0 {
				rows.Close()
				t.Fatal("multiple snapshot pages matched rewrite")
			}
			matchedIndex, matchedBody, descriptor = index, body, candidate
		}
	}
	if rows.Err() != nil || rows.Close() != nil {
		t.Fatal("read stored snapshot page descriptors")
	}
	if matchedIndex < 0 {
		t.Fatal("snapshot page rewrite target not found")
	}
	rewrite(&descriptor)
	rewrittenBody, err := marshalJSON(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	if _, err := transaction.Exec("UPDATE snapshot_pages SET response_json = ? WHERE snapshot_id = ? AND page_index = ?", rewrittenBody, snapshotID, matchedIndex); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec("UPDATE snapshots SET metadata_bytes = metadata_bytes - ? + ? WHERE snapshot_id = ?", len(matchedBody), len(rewrittenBody), snapshotID); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
}

func deleteSnapshotRevisionReference(t *testing.T, opened *Store, snapshotID, revisionID string) {
	t.Helper()
	var hashBytes []byte
	if err := opened.db.QueryRow(`
		SELECT content_hash FROM snapshot_revision_refs
		WHERE snapshot_id = ? AND revision_id = ?`, snapshotID, revisionID).Scan(&hashBytes); err != nil || len(hashBytes) != 32 {
		t.Fatalf("read snapshot reference hash length=%d error=%v", len(hashBytes), err)
	}
	var contentHash [32]byte
	copy(contentHash[:], hashBytes)
	account := snapshotMetadataAccounting{}
	accountSnapshotReference(&account, snapshotID, snapshotRevisionReference{revisionID: revisionID, contentHash: contentHash})
	if !account.ok() {
		t.Fatal("snapshot reference accounting overflow")
	}
	transaction, err := opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	result, err := transaction.Exec("DELETE FROM snapshot_revision_refs WHERE snapshot_id = ? AND revision_id = ?", snapshotID, revisionID)
	if err != nil {
		t.Fatal(err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		t.Fatalf("deleted snapshot references=%d error=%v", affected, err)
	}
	if _, err := transaction.Exec("UPDATE snapshots SET metadata_bytes = metadata_bytes - ? WHERE snapshot_id = ?", account.total, snapshotID); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
}

func rewriteSnapshotCutCursor(t *testing.T, opened *Store, snapshotID string, cut uint64) {
	t.Helper()
	var retainedCreate []byte
	if err := opened.db.QueryRow("SELECT create_response_json FROM snapshots WHERE snapshot_id = ?", snapshotID).Scan(&retainedCreate); err != nil {
		t.Fatal(err)
	}
	var create snapshotCreateResponse
	if err := json.Unmarshal(retainedCreate, &create); err != nil {
		t.Fatal(err)
	}
	create.CutCursor = encodeUint64Text(cut)
	rewrittenCreate, err := marshalJSON(create)
	if err != nil {
		t.Fatal(err)
	}
	encodedCut := EncodeUint64(cut)
	transaction, err := opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer transaction.Rollback()
	if _, err := transaction.Exec(`
		UPDATE snapshots
		SET cut_cursor = ?, create_response_json = ?, metadata_bytes = metadata_bytes - ? + ?
		WHERE snapshot_id = ?`, encodedCut[:], rewrittenCreate, len(retainedCreate), len(rewrittenCreate), snapshotID); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
}

func validateSnapshotsAtCurrentState(t *testing.T, opened *Store) error {
	t.Helper()
	ctx := context.Background()
	serverCursor, envelopeGeneration, _, collectionGeneration, err := validatePersistentRuntime(ctx, opened.db)
	if err != nil {
		t.Fatal(err)
	}
	devices, err := validatePersistentDevices(ctx, opened.db, serverCursor)
	if err != nil {
		t.Fatal(err)
	}
	return validatePersistentSnapshots(ctx, opened.db, testIdentity, devices, serverCursor, envelopeGeneration, collectionGeneration)
}

func boundedSyncCall(seed boundedPersistenceSeed, requestID, afterCursor string, mutations []recordRevision) api.Request {
	if mutations == nil {
		mutations = []recordRevision{}
	}
	body, _ := marshalJSON(syncRequest{
		ProtocolVersion: "1", DeviceID: seed.deviceID, RequestID: requestID,
		AfterCursor: afterCursor, AckCursor: "0", Mutations: mutations,
	})
	return api.Request{
		Method: "POST", Path: "/v1/sync", RequestID: requestID,
		Authorization: authorization(seed.token), Body: body, Now: protocolFixtureTime.Add(3 * time.Second),
	}
}

func boundedNextRevision(seed boundedPersistenceSeed, revisionID string) recordRevision {
	witness := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	return recordRevision{
		RecordID: seed.recordID, RevisionID: revisionID, AuthorDeviceID: seed.deviceID,
		AuthorCounter: "2", VersionVector: []vectorEntry{{DeviceID: seed.deviceID, Counter: "2"}},
		CollectionWitnessAuthenticator: &witness, PayloadSchema: "1", CryptoSuite: cryptoSuite,
		Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
}

func TestOversizedChangeFieldsFailClosedDuringLiveSync(t *testing.T) {
	tests := []struct {
		name    string
		options boundedSeedOptions
		mutate  func(*testing.T, boundedPersistenceSeed)
	}{
		{
			name: "record revision ID",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE changes SET record_revision_id = ? WHERE kind = 'record_revision'", strings.Repeat("x", maxUUIDBytes+1))
				checkMutation(t, err)
			},
		},
		{
			name:    "collection marker record ID",
			options: boundedSeedOptions{marker: true},
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE changes SET collection_marker_record_id = ? WHERE kind = 'collection_marker'", strings.Repeat("x", maxUUIDBytes+1))
				checkMutation(t, err)
			},
		},
		{
			name:    "collection marker body",
			options: boundedSeedOptions{marker: true},
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE changes SET collection_marker_json = zeroblob(?) WHERE kind = 'collection_marker'", maxBodyBytes+1)
				checkMutation(t, err)
			},
		},
		{
			name: "returned revision object",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE revision_objects SET revision_json = zeroblob(?)", maxBodyBytes+1)
				checkMutation(t, err)
			},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, test.options)
			defer seed.opened.Close()
			test.mutate(t, seed)
			requestID := fmt.Sprintf("e3000000-0000-4000-8000-%012x", index+1)
			expectInternalError(t, seed.opened, boundedSyncCall(seed, requestID, "0", nil))
		})
	}
}

func TestOversizedVectorsFailClosedDuringLiveMutation(t *testing.T) {
	for _, test := range []struct {
		name    string
		options boundedSeedOptions
		mutate  func(*testing.T, boundedPersistenceSeed)
	}{
		{
			name: "record head vector",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE record_revisions SET vector_json = zeroblob(?)", maxVectorBytes+1)
				checkMutation(t, err)
			},
		},
		{
			name:    "collection marker frontier",
			options: boundedSeedOptions{marker: true},
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE collection_markers SET frontier_json = zeroblob(?)", maxVectorBytes+1)
				checkMutation(t, err)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, test.options)
			defer seed.opened.Close()
			test.mutate(t, seed)
			revision := boundedNextRevision(seed, "e4000000-0000-4000-8000-000000000001")
			expectInternalError(t, seed.opened, boundedSyncCall(seed, "e4000000-0000-4000-8000-000000000002", "0", []recordRevision{revision}))
		})
	}
}

func TestOversizedVectorAndWitnessFailClosedInLiveCollectionConsumers(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, boundedPersistenceSeed)
		check  func(context.Context, *sql.Tx, boundedPersistenceSeed) *api.Error
	}{
		{
			name: "frontier classification vector",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE record_revisions SET vector_json = zeroblob(?)", maxVectorBytes+1)
				checkMutation(t, err)
			},
			check: func(ctx context.Context, transaction *sql.Tx, seed boundedPersistenceSeed) *api.Error {
				_, _, protocolErr := classifyRevisionFrontier(ctx, transaction, seed.recordID, map[string]uint64{seed.deviceID: 2})
				return protocolErr
			},
		},
		{
			name: "equal-vector index vector",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE record_revisions SET vector_json = zeroblob(?)", maxVectorBytes+1)
				checkMutation(t, err)
			},
			check: func(ctx context.Context, transaction *sql.Tx, seed boundedPersistenceSeed) *api.Error {
				body, _ := json.Marshal([]vectorEntry{{DeviceID: seed.deviceID, Counter: "1"}})
				hash := sha256.Sum256(body)
				return validateEqualVectorEquivocation(ctx, transaction, seed.recordID, "e5000000-0000-4000-8000-000000000001", hash, map[string]uint64{seed.deviceID: 1}, nil)
			},
		},
		{
			name: "collection work vector",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE record_revisions SET vector_json = zeroblob(?)", maxVectorBytes+1)
				checkMutation(t, err)
			},
			check: func(ctx context.Context, transaction *sql.Tx, seed boundedPersistenceSeed) *api.Error {
				_, _, _, protocolErr := loadCollectionRecordWork(ctx, transaction, seed.recordID, 0)
				return protocolErr
			},
		},
		{
			name: "collection work witness",
			mutate: func(t *testing.T, seed boundedPersistenceSeed) {
				_, err := seed.opened.db.Exec("UPDATE record_revisions SET collection_witness_authenticator = zeroblob(33)")
				checkMutation(t, err)
			},
			check: func(ctx context.Context, transaction *sql.Tx, seed boundedPersistenceSeed) *api.Error {
				_, _, _, protocolErr := loadCollectionRecordWork(ctx, transaction, seed.recordID, 0)
				return protocolErr
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{})
			defer seed.opened.Close()
			test.mutate(t, seed)
			transaction, err := seed.opened.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer transaction.Rollback()
			if protocolErr := test.check(context.Background(), transaction, seed); protocolErr == nil || protocolErr.Code != "internal_error" {
				t.Fatalf("live collection consumer error=%v", protocolErr)
			}
		})
	}
}

func TestOversizedMarkerFieldsFailClosedInLiveConsumers(t *testing.T) {
	for _, test := range []struct {
		name   string
		column string
		limit  int
	}{
		{name: "marker frontier", column: "frontier_json", limit: maxVectorBytes},
		{name: "marker body", column: "marker_json", limit: maxBodyBytes},
	} {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{marker: true})
			defer seed.opened.Close()
			if _, err := seed.opened.db.Exec("UPDATE collection_markers SET "+test.column+" = zeroblob(?)", test.limit+1); err != nil {
				t.Fatal(err)
			}
			transaction, err := seed.opened.db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer transaction.Rollback()
			if _, protocolErr := loadCollectionMarker(context.Background(), transaction, seed.recordID); protocolErr == nil || protocolErr.Code != "internal_error" {
				t.Fatalf("live marker consumer error=%v", protocolErr)
			}
		})
	}
}

func TestOversizedMarkerBodyFailsClosedDuringSnapshotBuild(t *testing.T) {
	seed := seedBoundedPersistence(t, boundedSeedOptions{marker: true})
	defer seed.opened.Close()
	if _, err := seed.opened.db.Exec("DELETE FROM snapshots"); err != nil {
		t.Fatal(err)
	}
	seed.opened.ephemeral.mu.Lock()
	clear(seed.opened.ephemeral.snapshotDeadlines)
	seed.opened.ephemeral.mu.Unlock()
	if _, err := seed.opened.db.Exec("UPDATE collection_markers SET marker_json = zeroblob(?)", maxBodyBytes+1); err != nil {
		t.Fatal(err)
	}
	requestID := "e6000000-0000-4000-8000-000000000001"
	body, _ := marshalJSON(snapshotCreateRequest{
		ProtocolVersion: "1", DeviceID: seed.deviceID, RequestID: requestID,
		RequiredCapabilities: append([]string(nil), requiredSnapshotCapabilities...),
	})
	expectInternalError(t, seed.opened, api.Request{
		Method: "POST", Path: "/v1/snapshot-reads", RequestID: requestID,
		Authorization: authorization(seed.token), Body: body, Now: protocolFixtureTime.Add(3 * time.Second),
	})
}

func TestOversizedRevisionVectorIsGuardedAtEveryStartupJoin(t *testing.T) {
	tests := []struct {
		name   string
		detail string
		check  func(context.Context, boundedPersistenceSeed, uint64, uint64, uint64, map[string]validatedDeviceRow, map[string]validatedMarkerChange) error
	}{
		{name: "revision replay", detail: "invalid revision row", check: func(ctx context.Context, seed boundedPersistenceSeed, cursor, _, collectionGeneration uint64, devices map[string]validatedDeviceRow, _ map[string]validatedMarkerChange) error {
			_, err := validatePersistentRevisions(ctx, seed.opened.db, devices, cursor, collectionGeneration)
			return err
		}},
		{name: "permanent vector index", detail: "invalid record vector index", check: func(ctx context.Context, seed boundedPersistenceSeed, _, _, _ uint64, _ map[string]validatedDeviceRow, _ map[string]validatedMarkerChange) error {
			return validatePersistentRecordVectorIndex(ctx, seed.opened.db)
		}},
		{name: "marker witness join", detail: "invalid marker row", check: func(ctx context.Context, seed boundedPersistenceSeed, cursor, _, _ uint64, devices map[string]validatedDeviceRow, changes map[string]validatedMarkerChange) error {
			return validatePersistentMarkers(ctx, seed.opened.db, devices, cursor, changes)
		}},
		{name: "snapshot reference join", detail: "invalid snapshot reference", check: func(ctx context.Context, seed boundedPersistenceSeed, cursor, envelopeGeneration, collectionGeneration uint64, devices map[string]validatedDeviceRow, _ map[string]validatedMarkerChange) error {
			return validatePersistentSnapshots(ctx, seed.opened.db, testIdentity, devices, cursor, envelopeGeneration, collectionGeneration)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seed := seedBoundedPersistence(t, boundedSeedOptions{marker: true})
			defer seed.opened.Close()
			if _, err := seed.opened.db.Exec("UPDATE record_revisions SET vector_json = zeroblob(?)", maxVectorBytes+1); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			cursor, envelopeGeneration, _, collectionGeneration, err := validatePersistentRuntime(ctx, seed.opened.db)
			if err != nil {
				t.Fatal(err)
			}
			devices, err := validatePersistentDevices(ctx, seed.opened.db, cursor)
			if err != nil {
				t.Fatal(err)
			}
			changes, err := validatePersistentChanges(ctx, seed.opened.db, devices, cursor)
			if err != nil {
				t.Fatal(err)
			}
			err = test.check(ctx, seed, cursor, envelopeGeneration, collectionGeneration, devices, changes)
			if !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), test.detail) {
				t.Fatalf("guarded vector join error=%v", err)
			}
		})
	}
}

func TestStartupRejectsSixtyFifthDeviceAtSentinel(t *testing.T) {
	opened, path := openDataPlane(t)
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	zero := EncodeUint64(0)
	transaction, err := opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 65; index++ {
		deviceID := fmt.Sprintf("f1000000-0000-4000-8000-%012x", index+1)
		hash := make([]byte, 32)
		hash[31] = byte(index + 1)
		if _, err := transaction.Exec(`
			INSERT INTO devices (device_id, token_hash, scopes_json, created_at_ms, last_ack_cursor, max_author_counter)
			VALUES (?, ?, ?, ?, ?, ?)`, deviceID, hash, string(wantScopes), protocolFixtureTime.UnixMilli(), zero[:], zero[:]); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
		if _, err := transaction.Exec("INSERT INTO device_origins (device_id, origin_kind, baseline_revoked) VALUES (?, 'baseline', 0)", deviceID); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
		if _, err := transaction.Exec("INSERT INTO device_sync_state (device_id, max_returned_cursor) VALUES (?, ?)", deviceID, zero[:]); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "invalid device registry") {
		t.Fatalf("65-device startup error=%v", err)
	}
}

func TestStartupRejectsPermanentVectorIndexEqualVectorDuplicate(t *testing.T) {
	opened, path := openDataPlane(t)
	deviceA := "e7000000-0000-4000-8000-000000000001"
	deviceB := "e7000000-0000-4000-8000-000000000004"
	enrollDevice(t, opened, protocolFixtureTime,
		"e7000000-0000-4000-8000-000000000002", deviceA,
		"e7000000-0000-4000-8000-000000000003", tokenWithByte(0xe7))
	enrollDevice(t, opened, protocolFixtureTime,
		"e7000000-0000-4000-8000-000000000005", deviceB,
		"e7000000-0000-4000-8000-000000000006", tokenWithByte(0xe8))

	recordID := "e7000000-0000-4000-8000-000000000007"
	revisions := []recordRevision{
		{
			RecordID: recordID, RevisionID: "e7000000-0000-4000-8000-000000000008", AuthorDeviceID: deviceA,
			AuthorCounter: "1", VersionVector: []vectorEntry{{DeviceID: deviceA, Counter: "1"}, {DeviceID: deviceB, Counter: "1"}},
			PayloadSchema: "1", CryptoSuite: cryptoSuite, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		},
		{
			RecordID: recordID, RevisionID: "e7000000-0000-4000-8000-000000000009", AuthorDeviceID: deviceA,
			AuthorCounter: "2", VersionVector: []vectorEntry{{DeviceID: deviceA, Counter: "2"}, {DeviceID: deviceB, Counter: "1"}},
			PayloadSchema: "1", CryptoSuite: cryptoSuite, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		},
		{
			RecordID: recordID, RevisionID: "e7000000-0000-4000-8000-00000000000a", AuthorDeviceID: deviceB,
			AuthorCounter: "1", VersionVector: []vectorEntry{{DeviceID: deviceA, Counter: "1"}, {DeviceID: deviceB, Counter: "1"}},
			PayloadSchema: "1", CryptoSuite: cryptoSuite, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		},
	}
	transaction, err := opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	zero := EncodeUint64(0)
	for index, revision := range revisions {
		body, _ := marshalJSON(revision)
		contentHash := sha256.Sum256(body)
		vectorBody, _ := json.Marshal(revision.VersionVector)
		vectorHash := sha256.Sum256(vectorBody)
		authorCounter, _ := parseUint64(revision.AuthorCounter)
		counter := EncodeUint64(authorCounter)
		cursor := EncodeUint64(uint64(index + 3))
		undominated := index == 1
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{"INSERT INTO revision_objects (content_hash, revision_json) VALUES (?, ?)", []any{contentHash[:], body}},
			{`INSERT INTO record_revisions (
				revision_id, record_id, author_device_id, author_counter, vector_json,
				collection_witness_authenticator, tombstone, content_hash, received_at_ms,
				accepted_uptime_ms, change_cursor, retained, undominated
			) VALUES (?, ?, ?, ?, ?, NULL, 0, ?, ?, ?, ?, 1, ?)`, []any{
				revision.RevisionID, recordID, revision.AuthorDeviceID, counter[:], vectorBody,
				contentHash[:], protocolFixtureTime.UnixMilli(), zero[:], cursor[:], boolToInt(undominated),
			}},
			{"INSERT INTO record_vector_index (record_id, vector_hash, revision_id) VALUES (?, ?, ?)", []any{recordID, vectorHash[:], revision.RevisionID}},
			{"INSERT INTO collection_candidates (record_id, accepted_uptime_ms, revision_id) VALUES (?, ?, ?)", []any{recordID, zero[:], revision.RevisionID}},
			{"INSERT INTO change_origins (cursor, kind) VALUES (?, 'record_revision')", []any{cursor[:]}},
			{"INSERT INTO changes (cursor, kind, received_at_ms, record_revision_id) VALUES (?, 'record_revision', ?, ?)", []any{cursor[:], protocolFixtureTime.UnixMilli(), revision.RevisionID}},
		} {
			if _, err := transaction.Exec(statement.query, statement.args...); err != nil {
				transaction.Rollback()
				t.Fatal(err)
			}
		}
	}
	one := EncodeUint64(1)
	two := EncodeUint64(2)
	five := EncodeUint64(5)
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{"UPDATE devices SET max_author_counter = ? WHERE device_id = ?", []any{two[:], deviceA}},
		{"UPDATE devices SET max_author_counter = ? WHERE device_id = ?", []any{one[:], deviceB}},
		{"INSERT INTO record_heads (record_id, revision_id) VALUES (?, ?)", []any{recordID, revisions[1].RevisionID}},
		{"INSERT INTO collection_records (record_id, barrier_cursor) VALUES (?, ?)", []any{recordID, five[:]}},
		{"UPDATE runtime_state SET server_cursor = ? WHERE singleton = 1", []any{five[:]}},
	} {
		if _, err := transaction.Exec(statement.query, statement.args...); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), path, testIdentity)
	if reopened != nil {
		reopened.Close()
	}
	if !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "duplicate record vector index") {
		t.Fatalf("equal-vector duplicate startup error=%v", err)
	}
}

func TestHistoricalFrontierRejectsCollectedThirtyThirdSiblingBeforeResolution(t *testing.T) {
	opened, path := openDataPlane(t)
	transaction, err := opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	wantScopes, _ := json.Marshal(auth.FixedScopes())
	zero := EncodeUint64(0)
	one := EncodeUint64(1)
	recordID := "f3000000-0000-4000-8000-000000000001"
	deviceIDs := make([]string, 33)
	resolutionVector := make([]vectorEntry, 33)
	for index := range deviceIDs {
		deviceIDs[index] = fmt.Sprintf("f4000000-0000-4000-8000-%012x", index+1)
		maximum := one
		if index == 0 {
			maximum = EncodeUint64(2)
		}
		hash := make([]byte, 32)
		hash[31] = byte(index + 1)
		if _, err := transaction.Exec(`
			INSERT INTO devices (device_id, token_hash, scopes_json, created_at_ms, last_ack_cursor, max_author_counter)
			VALUES (?, ?, ?, ?, ?, ?)`, deviceIDs[index], hash, string(wantScopes), protocolFixtureTime.UnixMilli(), zero[:], maximum[:]); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
		if _, err := transaction.Exec("INSERT INTO device_origins (device_id, origin_kind, baseline_revoked) VALUES (?, 'baseline', 0)", deviceIDs[index]); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
		if _, err := transaction.Exec("INSERT INTO device_sync_state (device_id, max_returned_cursor) VALUES (?, ?)", deviceIDs[index], zero[:]); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
		revisionID := fmt.Sprintf("f5000000-0000-4000-8000-%012x", index+1)
		entries := []vectorEntry{{DeviceID: deviceIDs[index], Counter: "1"}}
		vectorBody, _ := json.Marshal(entries)
		contentHash := sha256.Sum256([]byte(revisionID))
		cursor := EncodeUint64(uint64(index + 1))
		if _, err := transaction.Exec(`
			INSERT INTO record_revisions (
				revision_id, record_id, author_device_id, author_counter, vector_json,
				collection_witness_authenticator, tombstone, content_hash, received_at_ms,
				accepted_uptime_ms, change_cursor, collected_generation, retained, undominated
			) VALUES (?, ?, ?, ?, ?, NULL, 0, ?, ?, ?, ?, ?, 0, 0)`,
			revisionID, recordID, deviceIDs[index], one[:], vectorBody, contentHash[:], protocolFixtureTime.UnixMilli(), zero[:], cursor[:], one[:],
		); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
		if _, err := transaction.Exec("INSERT INTO change_origins (cursor, kind) VALUES (?, 'record_revision')", cursor[:]); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
		vectorHash := sha256.Sum256(vectorBody)
		if _, err := transaction.Exec("INSERT INTO record_vector_index (record_id, vector_hash, revision_id) VALUES (?, ?, ?)", recordID, vectorHash[:], revisionID); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
		counter := "1"
		if index == 0 {
			counter = "2"
		}
		resolutionVector[index] = vectorEntry{DeviceID: deviceIDs[index], Counter: counter}
	}

	resolutionID := "f6000000-0000-4000-8000-000000000001"
	resolution := recordRevision{
		RecordID: recordID, RevisionID: resolutionID, AuthorDeviceID: deviceIDs[0], AuthorCounter: "2", VersionVector: resolutionVector,
		PayloadSchema: "1", CryptoSuite: cryptoSuite, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	resolutionBody, _ := marshalJSON(resolution)
	resolutionVectorBody, _ := json.Marshal(resolutionVector)
	resolutionHash := sha256.Sum256(resolutionBody)
	resolutionVectorHash := sha256.Sum256(resolutionVectorBody)
	two := EncodeUint64(2)
	cursor34 := EncodeUint64(34)
	if _, err := transaction.Exec("INSERT INTO revision_objects (content_hash, revision_json) VALUES (?, ?)", resolutionHash[:], resolutionBody); err != nil {
		transaction.Rollback()
		t.Fatal(err)
	}
	if _, err := transaction.Exec(`
		INSERT INTO record_revisions (
			revision_id, record_id, author_device_id, author_counter, vector_json,
			collection_witness_authenticator, tombstone, content_hash, received_at_ms,
			accepted_uptime_ms, change_cursor, retained, undominated
		) VALUES (?, ?, ?, ?, ?, NULL, 0, ?, ?, ?, ?, 1, 1)`,
		resolutionID, recordID, deviceIDs[0], two[:], resolutionVectorBody, resolutionHash[:], protocolFixtureTime.UnixMilli(), zero[:], cursor34[:],
	); err != nil {
		transaction.Rollback()
		t.Fatal(err)
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{"INSERT INTO record_vector_index (record_id, vector_hash, revision_id) VALUES (?, ?, ?)", []any{recordID, resolutionVectorHash[:], resolutionID}},
		{"INSERT INTO record_heads (record_id, revision_id) VALUES (?, ?)", []any{recordID, resolutionID}},
		{"INSERT INTO collection_records (record_id, barrier_cursor) VALUES (?, ?)", []any{recordID, cursor34[:]}},
		{"INSERT INTO collection_candidates (record_id, accepted_uptime_ms, revision_id) VALUES (?, ?, ?)", []any{recordID, zero[:], resolutionID}},
		{"INSERT INTO change_origins (cursor, kind) VALUES (?, 'record_revision')", []any{cursor34[:]}},
		{"INSERT INTO changes (cursor, kind, received_at_ms, record_revision_id) VALUES (?, 'record_revision', ?, ?)", []any{cursor34[:], protocolFixtureTime.UnixMilli(), resolutionID}},
	} {
		if _, err := transaction.Exec(statement.query, statement.args...); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
	}
	floor := EncodeUint64(33)
	if _, err := transaction.Exec("UPDATE runtime_state SET server_cursor = ?, cursor_floor = ?, collection_generation = ? WHERE singleton = 1", cursor34[:], floor[:], one[:]); err != nil {
		transaction.Rollback()
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "too many reconstructed undominated revisions") {
		t.Fatalf("collected historical 33rd sibling startup error=%v", err)
	}
}
