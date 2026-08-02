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
		check  func(context.Context, boundedPersistenceSeed, uint64, uint64, map[string]validatedDeviceRow, map[string]validatedMarkerChange) error
	}{
		{name: "revision replay", detail: "invalid revision row", check: func(ctx context.Context, seed boundedPersistenceSeed, cursor, _ uint64, devices map[string]validatedDeviceRow, _ map[string]validatedMarkerChange) error {
			_, err := validatePersistentRevisions(ctx, seed.opened.db, devices, cursor)
			return err
		}},
		{name: "permanent vector index", detail: "invalid record vector index", check: func(ctx context.Context, seed boundedPersistenceSeed, _, _ uint64, _ map[string]validatedDeviceRow, _ map[string]validatedMarkerChange) error {
			return validatePersistentRecordVectorIndex(ctx, seed.opened.db)
		}},
		{name: "marker witness join", detail: "invalid marker row", check: func(ctx context.Context, seed boundedPersistenceSeed, cursor, _ uint64, devices map[string]validatedDeviceRow, changes map[string]validatedMarkerChange) error {
			return validatePersistentMarkers(ctx, seed.opened.db, devices, cursor, changes)
		}},
		{name: "snapshot reference join", detail: "invalid snapshot reference", check: func(ctx context.Context, seed boundedPersistenceSeed, cursor, generation uint64, devices map[string]validatedDeviceRow, _ map[string]validatedMarkerChange) error {
			_ = generation
			return validatePersistentSnapshots(ctx, seed.opened.db, testIdentity, devices, cursor)
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
			cursor, generation, _, err := validatePersistentRuntime(ctx, seed.opened.db)
			if err != nil {
				t.Fatal(err)
			}
			devices, err := validatePersistentDevices(ctx, seed.opened.db, cursor)
			if err != nil {
				t.Fatal(err)
			}
			changes, err := validatePersistentChanges(ctx, seed.opened.db, cursor)
			if err != nil {
				t.Fatal(err)
			}
			err = test.check(ctx, seed, cursor, generation, devices, changes)
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
				accepted_uptime_ms, change_cursor, retained, undominated
			) VALUES (?, ?, ?, ?, ?, NULL, 0, ?, ?, ?, ?, 0, 0)`,
			revisionID, recordID, deviceIDs[index], one[:], vectorBody, contentHash[:], protocolFixtureTime.UnixMilli(), zero[:], cursor[:],
		); err != nil {
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
		{"INSERT INTO changes (cursor, kind, received_at_ms, record_revision_id) VALUES (?, 'record_revision', ?, ?)", []any{cursor34[:], protocolFixtureTime.UnixMilli(), resolutionID}},
	} {
		if _, err := transaction.Exec(statement.query, statement.args...); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
	}
	floor := EncodeUint64(33)
	if _, err := transaction.Exec("UPDATE runtime_state SET server_cursor = ?, cursor_floor = ? WHERE singleton = 1", cursor34[:], floor[:]); err != nil {
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
