package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
	"github.com/kciceblue/sshserver/runtime/internal/auth"
	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/httpapi"
)

var protocolFixtureTime = time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)

func openDataPlane(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.db")
	opened, err := Open(context.Background(), path, testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.StartBoot(context.Background()); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	return opened, path
}

func tokenWithByte(value byte) []byte {
	return bytes.Repeat([]byte{value}, 32)
}

func authorization(token []byte) string {
	return "Bearer " + base64.RawURLEncoding.EncodeToString(token)
}

func createGrant(t *testing.T, opened *Store, now time.Time) EnrollmentGrant {
	t.Helper()
	grant, err := opened.CreateEnrollmentGrant(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func enrollDevice(t *testing.T, opened *Store, now time.Time, enrollmentID, deviceID, requestID string, token []byte) api.Response {
	t.Helper()
	grant := createGrant(t, opened, now)
	defer clear(grant.Grant)
	body, err := marshalJSON(enrollmentRequest{
		ProtocolVersion: "1",
		EnrollmentID:    enrollmentID,
		DeviceID:        deviceID,
		DeviceToken:     base64.RawURLEncoding.EncodeToString(token),
		Scopes:          auth.FixedScopes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	response, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method:        "POST",
		Path:          "/v1/enrollments",
		RequestID:     requestID,
		Authorization: "JAT-Enrollment " + base64.RawURLEncoding.EncodeToString(grant.Grant),
		Body:          body,
		Now:           now,
	})
	if protocolErr != nil {
		t.Fatalf("enroll %s: %v", deviceID, protocolErr)
	}
	return response
}

func TestEnrollmentFixtureRetryRestartRecoveryAndHashOnlyPersistence(t *testing.T) {
	opened, path := openDataPlane(t)
	var fixture struct {
		Request         enrollmentRequest  `json:"request"`
		CreatedResponse enrollmentResponse `json:"created_response"`
	}
	loadFixture(t, "enrollment.json", &fixture)
	body, err := marshalJSON(fixture.Request)
	if err != nil {
		t.Fatal(err)
	}
	grant := createGrant(t, opened, protocolFixtureTime)
	grantAuthorization := "JAT-Enrollment " + base64.RawURLEncoding.EncodeToString(grant.Grant)
	call := api.Request{
		Method:        "POST",
		Path:          "/v1/enrollments",
		RequestID:     "00000000-0000-4000-8000-000000000005",
		Authorization: grantAuthorization,
		Body:          body,
		Now:           protocolFixtureTime,
	}
	created, protocolErr := opened.HandleAPI(context.Background(), call)
	if protocolErr != nil || created.Status != 201 {
		t.Fatalf("created enrollment: response=%+v error=%v", created, protocolErr)
	}
	var actual enrollmentResponse
	if err := json.Unmarshal(created.Body, &actual); err != nil {
		t.Fatal(err)
	}
	if !deepJSONEqual(t, actual, fixture.CreatedResponse) {
		t.Fatalf("created response = %+v, want fixture %+v", actual, fixture.CreatedResponse)
	}
	retried, protocolErr := opened.HandleAPI(context.Background(), call)
	if protocolErr != nil || retried.Status != 200 || !bytes.Equal(retried.Body, created.Body) {
		t.Fatalf("same-grant retry: response=%+v error=%v", retried, protocolErr)
	}
	mismatch := call
	mismatch.Body = append(append([]byte(nil), body...), '\n')
	if _, protocolErr := opened.HandleAPI(context.Background(), mismatch); protocolErr == nil || protocolErr.Code != "enrollment_replay_mismatch" {
		t.Fatalf("non-byte-equivalent retry error = %v", protocolErr)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	assertCredentialAbsentFromSQLite(t, path, grant.Grant)
	fixtureToken, err := base64.RawURLEncoding.DecodeString(fixture.Request.DeviceToken)
	if err != nil {
		t.Fatal(err)
	}
	// The all-zero shape fixture is unsuitable for a raw byte absence search,
	// but the database must still contain its reviewed domain-separated hash.
	wantHash, err := auth.DeviceTokenHash(testIdentity.InstanceID, testIdentity.VaultID, fixture.Request.DeviceID, fixtureToken)
	if err != nil {
		t.Fatal(err)
	}
	if database, err := os.ReadFile(path); err != nil || !bytes.Contains(database, wantHash[:]) {
		t.Fatalf("database does not contain expected token hash: err=%v", err)
	}

	reopened, err := Open(context.Background(), path, testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.StartBoot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, protocolErr := reopened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "unauthorized" {
		t.Fatalf("prior-boot grant error = %v", protocolErr)
	}
	replacement := createGrant(t, reopened, protocolFixtureTime.Add(time.Minute))
	call.Authorization = "JAT-Enrollment " + base64.RawURLEncoding.EncodeToString(replacement.Grant)
	call.Now = protocolFixtureTime.Add(time.Minute)
	recovered, protocolErr := reopened.HandleAPI(context.Background(), call)
	if protocolErr != nil || recovered.Status != 200 || !bytes.Equal(recovered.Body, created.Body) {
		t.Fatalf("replacement-grant recovery: response=%+v error=%v", recovered, protocolErr)
	}
	var count int
	if err := reopened.db.QueryRow("SELECT count(*) FROM devices").Scan(&count); err != nil || count != 1 {
		t.Fatalf("device count = %d, err=%v", count, err)
	}
}

func TestEnvelopeSyncSnapshotRevocationAndRotationFixtures(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	device3 := "00000000-0000-4000-8000-000000000003"
	device10 := "00000000-0000-4000-8000-000000000010"
	device11 := "00000000-0000-4000-8000-000000000011"
	token3 := tokenWithByte(0)
	token10 := tokenWithByte(1)
	token11 := tokenWithByte(2)
	enrollDevice(t, opened, protocolFixtureTime, "00000000-0000-4000-8000-000000000004", device3, "00000000-0000-4000-8000-000000000005", token3)
	enrollDevice(t, opened, protocolFixtureTime, "00000000-0000-4000-8000-000000000014", device10, "00000000-0000-4000-8000-000000000015", token10)
	enrollDevice(t, opened, protocolFixtureTime, "00000000-0000-4000-8000-000000000016", device11, "00000000-0000-4000-8000-000000000017", token11)

	var envelopeFixture struct {
		BaseMode putEnvelopeRequest `json:"base_mode"`
	}
	loadFixture(t, "vault-envelope.json", &envelopeFixture)
	envelopeBody, _ := marshalJSON(envelopeFixture.BaseMode)
	putEnvelope := api.Request{Method: "PUT", Path: "/v1/vault-envelope", RequestID: "00000000-0000-4000-8000-000000000018", Authorization: authorization(token3), Body: envelopeBody, Now: protocolFixtureTime}
	envelopeResponse, protocolErr := opened.HandleAPI(context.Background(), putEnvelope)
	if protocolErr != nil || envelopeResponse.Status != 200 {
		t.Fatalf("put envelope: response=%+v error=%v", envelopeResponse, protocolErr)
	}
	retriedEnvelope, protocolErr := opened.HandleAPI(context.Background(), putEnvelope)
	if protocolErr != nil || !bytes.Equal(retriedEnvelope.Body, envelopeResponse.Body) {
		t.Fatalf("envelope retry: response=%+v error=%v", retriedEnvelope, protocolErr)
	}

	var conflictFixture struct {
		ConcurrentSiblings []recordRevision `json:"concurrent_siblings"`
		Resolution         recordRevision   `json:"resolution"`
	}
	loadFixture(t, "sync-conflict.json", &conflictFixture)
	syncMutation(t, opened, device10, token10, "00000000-0000-4000-8000-000000000050", conflictFixture.ConcurrentSiblings[0], protocolFixtureTime)
	syncMutation(t, opened, device11, token11, "00000000-0000-4000-8000-000000000051", conflictFixture.ConcurrentSiblings[1], protocolFixtureTime)

	createRequest := snapshotCreateRequest{
		ProtocolVersion:      "1",
		DeviceID:             device3,
		RequestID:            "00000000-0000-4000-8000-000000000040",
		RequiredCapabilities: append([]string(nil), requiredSnapshotCapabilities...),
	}
	createBody, _ := marshalJSON(createRequest)
	createdSnapshot, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/snapshot-reads", RequestID: createRequest.RequestID, Authorization: authorization(token3), Body: createBody, Now: protocolFixtureTime})
	if protocolErr != nil || createdSnapshot.Status != 201 {
		t.Fatalf("create snapshot: response=%+v error=%v", createdSnapshot, protocolErr)
	}
	var snapshot snapshotCreateResponse
	if json.Unmarshal(createdSnapshot.Body, &snapshot) != nil {
		t.Fatal("decode snapshot create response")
	}
	retriedSnapshot, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/snapshot-reads", RequestID: createRequest.RequestID, Authorization: authorization(token3), Body: createBody, Now: protocolFixtureTime.Add(time.Minute)})
	if protocolErr != nil || retriedSnapshot.Status != 200 || !bytes.Equal(retriedSnapshot.Body, createdSnapshot.Body) {
		t.Fatalf("snapshot exact retry: response=%+v error=%v", retriedSnapshot, protocolErr)
	}
	mismatchedSnapshotBody := append(append([]byte(nil), createBody...), '\n')
	if _, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/snapshot-reads", RequestID: createRequest.RequestID, Authorization: authorization(token3), Body: mismatchedSnapshotBody, Now: protocolFixtureTime.Add(time.Minute)}); protocolErr == nil || protocolErr.Code != "request_id_reused" {
		t.Fatalf("snapshot request-ID mismatch error = %v", protocolErr)
	}
	beforePages, revisions, sources := readAllSnapshotPages(t, opened, snapshot, device3, token3, protocolFixtureTime)
	if len(revisions) != 2 || len(sources) != 3 {
		t.Fatalf("snapshot membership: revisions=%d sources=%d", len(revisions), len(sources))
	}
	wantRevisionIDs := []string{conflictFixture.ConcurrentSiblings[0].RevisionID, conflictFixture.ConcurrentSiblings[1].RevisionID}
	gotRevisionIDs := []string{revisions[0].RevisionID, revisions[1].RevisionID}
	if !slices.Equal(gotRevisionIDs, wantRevisionIDs) {
		t.Fatalf("snapshot revisions = %#v, want %#v", gotRevisionIDs, wantRevisionIDs)
	}

	syncMutation(t, opened, device10, token10, "00000000-0000-4000-8000-000000000052", conflictFixture.Resolution, protocolFixtureTime.Add(time.Second))
	afterPages, _, _ := readAllSnapshotPages(t, opened, snapshot, device3, token3, protocolFixtureTime.Add(time.Second))
	if !pageBodiesEqual(beforePages, afterPages) {
		t.Fatal("snapshot page replay changed after a concurrent resolution")
	}

	revokeBody, _ := marshalJSON(revokeDeviceRequest{RequestID: "00000000-0000-4000-8000-000000000053", AllowZeroActive: false})
	if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/devices/" + device3 + "/revoke", RequestID: "00000000-0000-4000-8000-000000000053", Authorization: authorization(token10), Body: revokeBody, Now: protocolFixtureTime.Add(2 * time.Second)}); protocolErr != nil || response.Status != 200 {
		t.Fatalf("revoke snapshot owner: response=%+v error=%v", response, protocolErr)
	}
	pageBody, _ := marshalJSON(snapshotPageRequest{ProtocolVersion: "1", DeviceID: device3, PageToken: snapshot.FirstPageToken})
	if _, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/snapshot-reads/" + snapshot.SnapshotID + "/pages", RequestID: "00000000-0000-4000-8000-000000000054", Authorization: authorization(token3), Body: pageBody, Now: protocolFixtureTime.Add(2 * time.Second)}); protocolErr == nil || protocolErr.Code != "token_revoked" {
		t.Fatalf("revoked snapshot owner page error = %v", protocolErr)
	}

	newToken10 := tokenWithByte(3)
	rotation := tokenRotationRequest{RotationID: "00000000-0000-4000-8000-000000000031", DeviceID: device10, NewDeviceToken: base64.RawURLEncoding.EncodeToString(newToken10)}
	rotationBody, _ := marshalJSON(rotation)
	rotationCall := api.Request{Method: "POST", Path: "/v1/device-token-rotations", RequestID: "00000000-0000-4000-8000-000000000055", Authorization: authorization(token10), Body: rotationBody, Now: protocolFixtureTime.Add(3 * time.Second)}
	rotated, protocolErr := opened.HandleAPI(context.Background(), rotationCall)
	if protocolErr != nil || rotated.Status != 200 {
		t.Fatalf("rotate token: response=%+v error=%v", rotated, protocolErr)
	}
	retriedRotation, protocolErr := opened.HandleAPI(context.Background(), rotationCall)
	if protocolErr != nil || !bytes.Equal(retriedRotation.Body, rotated.Body) {
		t.Fatalf("old-token rotation retry: response=%+v error=%v", retriedRotation, protocolErr)
	}
	if _, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "GET", Path: "/v1/devices", RequestID: "00000000-0000-4000-8000-000000000056", Authorization: authorization(token10), Now: protocolFixtureTime}); protocolErr == nil || protocolErr.Code != "unauthorized" {
		t.Fatalf("old token remained authorized: %v", protocolErr)
	}
	if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "GET", Path: "/v1/devices", RequestID: "00000000-0000-4000-8000-000000000057", Authorization: authorization(newToken10), Now: protocolFixtureTime}); protocolErr != nil || response.Status != 200 {
		t.Fatalf("new token list devices: response=%+v error=%v", response, protocolErr)
	}
	mismatchedRotation := rotation
	mismatchedRotation.DeviceID = device11
	mismatchedRotationBody, _ := marshalJSON(mismatchedRotation)
	if _, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "POST", Path: "/v1/device-token-rotations", RequestID: "00000000-0000-4000-8000-000000000057",
		Authorization: authorization(token10), Body: mismatchedRotationBody, Now: protocolFixtureTime,
	}); protocolErr == nil || protocolErr.Code != "authenticated_device_mismatch" {
		t.Fatalf("old-token mismatched rotation device error = %v", protocolErr)
	}

	revokeDevice(t, opened, device11, newToken10, false, "00000000-0000-4000-8000-000000000058", protocolFixtureTime.Add(4*time.Second))
	selfRequestID := "00000000-0000-4000-8000-000000000059"
	selfBody, _ := marshalJSON(revokeDeviceRequest{RequestID: selfRequestID, AllowZeroActive: true})
	selfCall := api.Request{Method: "POST", Path: "/v1/devices/" + device10 + "/revoke", RequestID: selfRequestID, Authorization: authorization(newToken10), Body: selfBody, Now: protocolFixtureTime.Add(5 * time.Second)}
	selfResponse, protocolErr := opened.HandleAPI(context.Background(), selfCall)
	if protocolErr != nil || selfResponse.Status != 200 {
		t.Fatalf("self revoke: response=%+v error=%v", selfResponse, protocolErr)
	}
	if _, protocolErr := opened.HandleAPI(context.Background(), rotationCall); protocolErr == nil || protocolErr.Code != "token_revoked" {
		t.Fatalf("revoked old-token rotation retry error = %v", protocolErr)
	}
	selfRetry, protocolErr := opened.HandleAPI(context.Background(), selfCall)
	if protocolErr != nil || !bytes.Equal(selfRetry.Body, selfResponse.Body) {
		t.Fatalf("self-revocation receipt: response=%+v error=%v", selfRetry, protocolErr)
	}
	selfCall.Body = append(selfCall.Body, '\n')
	if _, protocolErr := opened.HandleAPI(context.Background(), selfCall); protocolErr == nil || protocolErr.Code != "token_revoked" {
		t.Fatalf("non-exact self-revocation retry error = %v", protocolErr)
	}
	selfCall.Body = selfBody
	selfCall.RequestID = "00000000-0000-4000-8000-000000000060"
	if _, protocolErr := opened.HandleAPI(context.Background(), selfCall); protocolErr == nil || protocolErr.Code != "token_revoked" {
		t.Fatalf("self-revocation header/body ID mismatch error = %v", protocolErr)
	}
	selfCall.RequestID = selfRequestID
	selfCall.Authorization = "Bearer invalid"
	if _, protocolErr := opened.HandleAPI(context.Background(), selfCall); protocolErr == nil || protocolErr.Code != "unauthorized" {
		t.Fatalf("self-revocation token mismatch error = %v", protocolErr)
	}
}

func TestTombstoneCollectionMarkerCursorFloorAndRestartBoundSnapshot(t *testing.T) {
	opened, path := openDataPlane(t)
	deviceID := "00000000-0000-4000-8000-000000000003"
	token := tokenWithByte(7)
	enrollDevice(t, opened, protocolFixtureTime, "00000000-0000-4000-8000-000000000004", deviceID, "00000000-0000-4000-8000-000000000005", token)

	var envelopeFixture struct {
		BaseMode putEnvelopeRequest `json:"base_mode"`
	}
	loadFixture(t, "vault-envelope.json", &envelopeFixture)
	envelopeBody, _ := marshalJSON(envelopeFixture.BaseMode)
	if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "PUT", Path: "/v1/vault-envelope", RequestID: "00000000-0000-4000-8000-000000000006",
		Authorization: authorization(token), Body: envelopeBody, Now: protocolFixtureTime,
	}); protocolErr != nil || response.Status != 200 {
		t.Fatalf("put envelope: response=%+v error=%v", response, protocolErr)
	}

	revision := recordRevision{
		RecordID:       "00000000-0000-4000-8000-000000000020",
		RevisionID:     "00000000-0000-4000-8000-000000000022",
		AuthorDeviceID: deviceID,
		AuthorCounter:  "1",
		VersionVector:  []vectorEntry{{DeviceID: deviceID, Counter: "1"}},
		PayloadSchema:  "1",
		CryptoSuite:    cryptoSuite,
		Tombstone:      true,
		Nonce:          base64.RawURLEncoding.EncodeToString(make([]byte, 24)),
		Ciphertext:     base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	authenticator := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	revision.CollectionWitnessAuthenticator = &authenticator
	mutationID := "00000000-0000-4000-8000-000000000007"
	mutationBody, _ := marshalJSON(syncRequest{
		ProtocolVersion: "1", DeviceID: deviceID, RequestID: mutationID,
		AfterCursor: "0", AckCursor: "0", Mutations: []recordRevision{revision},
	})
	mutationResponse, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "POST", Path: "/v1/sync", RequestID: mutationID,
		Authorization: authorization(token), Body: mutationBody, Now: protocolFixtureTime,
	})
	if protocolErr != nil || mutationResponse.Status != 200 {
		t.Fatalf("tombstone mutation: response=%+v error=%v", mutationResponse, protocolErr)
	}
	var mutationResult syncResponse
	if err := json.Unmarshal(mutationResponse.Body, &mutationResult); err != nil || mutationResult.ServerCursor != "3" || mutationResult.NextCursor != "3" {
		t.Fatalf("tombstone cursors: response=%s error=%v", mutationResponse.Body, err)
	}
	stableCreateID := "00000000-0000-4000-8000-000000000061"
	stableCreateBody, _ := marshalJSON(snapshotCreateRequest{
		ProtocolVersion: "1", DeviceID: deviceID, RequestID: stableCreateID,
		RequiredCapabilities: append([]string(nil), requiredSnapshotCapabilities...),
	})
	stableCreated, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "POST", Path: "/v1/snapshot-reads", RequestID: stableCreateID,
		Authorization: authorization(token), Body: stableCreateBody, Now: protocolFixtureTime,
	})
	if protocolErr != nil || stableCreated.Status != 201 {
		t.Fatalf("snapshot before collection: response=%+v error=%v", stableCreated, protocolErr)
	}
	var stableSnapshot snapshotCreateResponse
	if err := json.Unmarshal(stableCreated.Body, &stableSnapshot); err != nil {
		t.Fatal(err)
	}
	stablePagesBefore, stableRevisions, _ := readAllSnapshotPages(t, opened, stableSnapshot, deviceID, token, protocolFixtureTime)
	if len(stableRevisions) != 1 || stableRevisions[0].RevisionID != revision.RevisionID {
		t.Fatalf("pre-collection snapshot revisions = %+v", stableRevisions)
	}

	retention := EncodeUint64(uint64(minimumRetentionUptime / time.Millisecond))
	if _, err := opened.db.Exec("UPDATE runtime_state SET accumulated_uptime_ms = ? WHERE singleton = 1", retention[:]); err != nil {
		t.Fatal(err)
	}
	staleID := "00000000-0000-4000-8000-00000000000c"
	staleBody, _ := marshalJSON(syncRequest{
		ProtocolVersion: "1", DeviceID: deviceID, RequestID: staleID,
		AfterCursor: "0", AckCursor: "3", Mutations: []recordRevision{},
	})
	if _, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "POST", Path: "/v1/sync", RequestID: staleID,
		Authorization: authorization(token), Body: staleBody, Now: protocolFixtureTime,
	}); protocolErr == nil || protocolErr.Code != "cursor_expired" {
		t.Fatalf("cursor made stale by same-request collection error = %v", protocolErr)
	}
	var preCollectionRetained int
	if err := opened.db.QueryRow("SELECT retained FROM record_revisions WHERE revision_id = ?", revision.RevisionID).Scan(&preCollectionRetained); err != nil || preCollectionRetained != 1 {
		t.Fatalf("failed stale delta partially collected revision: retained=%d error=%v", preCollectionRetained, err)
	}
	ackID := "00000000-0000-4000-8000-000000000008"
	ackBody, _ := marshalJSON(syncRequest{
		ProtocolVersion: "1", DeviceID: deviceID, RequestID: ackID,
		AfterCursor: "3", AckCursor: "3", Mutations: []recordRevision{},
	})
	collectedResponse, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "POST", Path: "/v1/sync", RequestID: ackID,
		Authorization: authorization(token), Body: ackBody, Now: protocolFixtureTime,
	})
	if protocolErr != nil || collectedResponse.Status != 200 {
		t.Fatalf("collection sync: response=%+v error=%v", collectedResponse, protocolErr)
	}
	var collected syncResponse
	if err := json.Unmarshal(collectedResponse.Body, &collected); err != nil {
		t.Fatal(err)
	}
	if collected.ServerCursor != "4" || len(collected.Changes) != 1 || collected.Changes[0].Kind != "collection_marker" || collected.Changes[0].CollectionMarker == nil {
		t.Fatalf("collection response = %s", collectedResponse.Body)
	}
	marker := collected.Changes[0].CollectionMarker
	if marker.WitnessRevisionID != revision.RevisionID || marker.BarrierCursor != "3" || !slices.Equal(marker.Frontier, revision.VersionVector) || marker.CollectionWitnessAuthenticator != authenticator {
		t.Fatalf("collection marker = %+v", marker)
	}
	var retained, objectCount int
	if err := opened.db.QueryRow("SELECT retained FROM record_revisions WHERE revision_id = ?", revision.RevisionID).Scan(&retained); err != nil || retained != 0 {
		t.Fatalf("collected revision retained=%d error=%v", retained, err)
	}
	if err := opened.db.QueryRow("SELECT count(*) FROM revision_objects").Scan(&objectCount); err != nil || objectCount != 1 {
		t.Fatalf("snapshot-referenced revision objects=%d error=%v", objectCount, err)
	}
	stablePagesAfter, stableRevisionsAfter, _ := readAllSnapshotPages(t, opened, stableSnapshot, deviceID, token, protocolFixtureTime)
	if !pageBodiesEqual(stablePagesBefore, stablePagesAfter) || len(stableRevisionsAfter) != 1 || stableRevisionsAfter[0].RevisionID != revision.RevisionID {
		t.Fatal("active snapshot changed after live revision collection")
	}
	var cursorFloor []byte
	if err := opened.db.QueryRow("SELECT cursor_floor FROM runtime_state WHERE singleton = 1").Scan(&cursorFloor); err != nil {
		t.Fatal(err)
	}
	if value, err := DecodeUint64(cursorFloor); err != nil || value != 3 {
		t.Fatalf("cursor floor = %d, error=%v", value, err)
	}

	expiredID := "00000000-0000-4000-8000-000000000009"
	expiredBody, _ := marshalJSON(syncRequest{
		ProtocolVersion: "1", DeviceID: deviceID, RequestID: expiredID,
		AfterCursor: "0", AckCursor: "3", Mutations: []recordRevision{},
	})
	if _, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "POST", Path: "/v1/sync", RequestID: expiredID,
		Authorization: authorization(token), Body: expiredBody, Now: protocolFixtureTime,
	}); protocolErr == nil || protocolErr.Code != "cursor_expired" {
		t.Fatalf("old cursor error = %v", protocolErr)
	}

	createID := "00000000-0000-4000-8000-00000000000a"
	createBody, _ := marshalJSON(snapshotCreateRequest{
		ProtocolVersion: "1", DeviceID: deviceID, RequestID: createID,
		RequiredCapabilities: append([]string(nil), requiredSnapshotCapabilities...),
	})
	expiredSnapshotTime := protocolFixtureTime.Add(snapshotLifetime + time.Millisecond)
	created, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "POST", Path: "/v1/snapshot-reads", RequestID: createID,
		Authorization: authorization(token), Body: createBody, Now: expiredSnapshotTime,
	})
	if protocolErr != nil || created.Status != 201 {
		t.Fatalf("snapshot after collection: response=%+v error=%v", created, protocolErr)
	}
	var snapshot snapshotCreateResponse
	if err := json.Unmarshal(created.Body, &snapshot); err != nil {
		t.Fatal(err)
	}
	if err := opened.db.QueryRow("SELECT count(*) FROM revision_objects").Scan(&objectCount); err != nil || objectCount != 0 {
		t.Fatalf("expired snapshot retained collected revision objects=%d error=%v", objectCount, err)
	}
	pageBody, _ := marshalJSON(snapshotPageRequest{ProtocolVersion: "1", DeviceID: deviceID, PageToken: snapshot.FirstPageToken})
	pageCall := api.Request{
		Method: "POST", Path: "/v1/snapshot-reads/" + snapshot.SnapshotID + "/pages",
		RequestID: "00000000-0000-4000-8000-00000000000b", Authorization: authorization(token),
		Body: pageBody, Now: expiredSnapshotTime,
	}
	pageResponse, protocolErr := opened.HandleAPI(context.Background(), pageCall)
	if protocolErr != nil || pageResponse.Status != 200 {
		t.Fatalf("marker snapshot page: response=%+v error=%v", pageResponse, protocolErr)
	}
	var page snapshotPageResponse
	if err := json.Unmarshal(pageResponse.Body, &page); err != nil || len(page.Revisions) != 0 || len(page.CollectionMarkers) != 1 {
		t.Fatalf("marker snapshot page = %s error=%v", pageResponse.Body, err)
	}

	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), path, testIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.StartBoot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, protocolErr := reopened.HandleAPI(context.Background(), pageCall); protocolErr == nil || protocolErr.Code != "snapshot_not_found" {
		t.Fatalf("prior-boot snapshot error = %v", protocolErr)
	}
}

func TestMarkerFallbackPreservesLiveWitnessAndPrunesTombstoneWitness(t *testing.T) {
	setUptime := func(t *testing.T, opened *Store, elapsed time.Duration) {
		t.Helper()
		encoded := EncodeUint64(uint64(elapsed / time.Millisecond))
		if _, err := opened.db.Exec("UPDATE runtime_state SET accumulated_uptime_ms = ? WHERE singleton = 1", encoded[:]); err != nil {
			t.Fatal(err)
		}
	}
	syncCall := func(t *testing.T, opened *Store, deviceID string, token []byte, requestID, after, ack string, mutations []recordRevision) syncResponse {
		t.Helper()
		body, err := marshalJSON(syncRequest{
			ProtocolVersion: "1", DeviceID: deviceID, RequestID: requestID,
			AfterCursor: after, AckCursor: ack, Mutations: mutations,
		})
		if err != nil {
			t.Fatal(err)
		}
		response, protocolErr := opened.HandleAPI(context.Background(), api.Request{
			Method: "POST", Path: "/v1/sync", RequestID: requestID,
			Authorization: authorization(token), Body: body, Now: protocolFixtureTime,
		})
		if protocolErr != nil || response.Status != http.StatusOK {
			t.Fatalf("sync %s: response=%+v error=%v", requestID, response, protocolErr)
		}
		var decoded syncResponse
		if err := json.Unmarshal(response.Body, &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	makeRevision := func(deviceID, recordID, revisionID string, counter uint64, tombstone, authorized bool) recordRevision {
		revision := recordRevision{
			RecordID: recordID, RevisionID: revisionID, AuthorDeviceID: deviceID,
			AuthorCounter: encodeUint64Text(counter),
			VersionVector: []vectorEntry{{DeviceID: deviceID, Counter: encodeUint64Text(counter)}},
			PayloadSchema: "1", CryptoSuite: cryptoSuite, Tombstone: tombstone,
			Nonce:      base64.RawURLEncoding.EncodeToString(make([]byte, 24)),
			Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		}
		if authorized {
			value := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			revision.CollectionWitnessAuthenticator = &value
		}
		return revision
	}

	t.Run("live marker witness remains snapshot-visible", func(t *testing.T) {
		opened, _ := openDataPlane(t)
		defer opened.Close()
		deviceID := "e1000000-0000-4000-8000-000000000001"
		token := tokenWithByte(0xe1)
		enrollDevice(t, opened, protocolFixtureTime,
			"e1000000-0000-4000-8000-000000000002", deviceID,
			"e1000000-0000-4000-8000-000000000003", token,
		)
		var envelopeFixture struct {
			BaseMode putEnvelopeRequest `json:"base_mode"`
		}
		loadFixture(t, "vault-envelope.json", &envelopeFixture)
		envelopeBody, _ := marshalJSON(envelopeFixture.BaseMode)
		if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{
			Method: "PUT", Path: "/v1/vault-envelope", RequestID: "e1000000-0000-4000-8000-000000000004",
			Authorization: authorization(token), Body: envelopeBody, Now: protocolFixtureTime,
		}); protocolErr != nil || response.Status != http.StatusOK {
			t.Fatalf("put envelope: response=%+v error=%v", response, protocolErr)
		}
		recordID := "e1000000-0000-4000-8000-000000000005"
		first := makeRevision(deviceID, recordID, "e1000000-0000-4000-8000-000000000006", 1, false, false)
		liveWitness := makeRevision(deviceID, recordID, "e1000000-0000-4000-8000-000000000007", 2, false, true)
		seed := syncCall(t, opened, deviceID, token, "e1000000-0000-4000-8000-000000000008", "0", "0", []recordRevision{first, liveWitness})
		if seed.ServerCursor != "4" || seed.NextCursor != "4" {
			t.Fatalf("seed cursors = %+v", seed)
		}
		setUptime(t, opened, minimumRetentionUptime)
		firstPass := syncCall(t, opened, deviceID, token, "e1000000-0000-4000-8000-000000000009", "4", "4", []recordRevision{})
		if firstPass.ServerCursor != "5" || len(firstPass.Changes) != 1 || firstPass.Changes[0].CollectionMarker == nil {
			t.Fatalf("first collection pass = %+v", firstPass)
		}
		secondPass := syncCall(t, opened, deviceID, token, "e1000000-0000-4000-8000-00000000000a", "5", "5", []recordRevision{})
		if secondPass.ServerCursor != "5" || len(secondPass.Changes) != 0 {
			t.Fatalf("second collection pass = %+v", secondPass)
		}
		var firstRetained, witnessRetained int
		if err := opened.db.QueryRow("SELECT retained FROM record_revisions WHERE revision_id = ?", first.RevisionID).Scan(&firstRetained); err != nil {
			t.Fatal(err)
		}
		if err := opened.db.QueryRow("SELECT retained FROM record_revisions WHERE revision_id = ?", liveWitness.RevisionID).Scan(&witnessRetained); err != nil {
			t.Fatal(err)
		}
		if firstRetained != 0 || witnessRetained != 1 {
			t.Fatalf("live collection retention: first=%d witness=%d", firstRetained, witnessRetained)
		}

		createID := "e1000000-0000-4000-8000-00000000000b"
		createBody, _ := marshalJSON(snapshotCreateRequest{
			ProtocolVersion: "1", DeviceID: deviceID, RequestID: createID,
			RequiredCapabilities: append([]string(nil), requiredSnapshotCapabilities...),
		})
		created, protocolErr := opened.HandleAPI(context.Background(), api.Request{
			Method: "POST", Path: "/v1/snapshot-reads", RequestID: createID,
			Authorization: authorization(token), Body: createBody, Now: protocolFixtureTime,
		})
		if protocolErr != nil || created.Status != http.StatusCreated {
			t.Fatalf("create live-witness snapshot: response=%+v error=%v", created, protocolErr)
		}
		var snapshot snapshotCreateResponse
		if err := json.Unmarshal(created.Body, &snapshot); err != nil {
			t.Fatal(err)
		}
		_, revisions, _ := readAllSnapshotPages(t, opened, snapshot, deviceID, token, protocolFixtureTime)
		if len(revisions) != 1 || revisions[0].RevisionID != liveWitness.RevisionID {
			t.Fatalf("snapshot live revisions = %+v", revisions)
		}
	})

	t.Run("exact tombstone marker witness is pruned once eligible", func(t *testing.T) {
		opened, _ := openDataPlane(t)
		defer opened.Close()
		deviceID := "e2000000-0000-4000-8000-000000000001"
		token := tokenWithByte(0xe2)
		enrollDevice(t, opened, protocolFixtureTime,
			"e2000000-0000-4000-8000-000000000002", deviceID,
			"e2000000-0000-4000-8000-000000000003", token,
		)
		var envelopeFixture struct {
			BaseMode putEnvelopeRequest `json:"base_mode"`
		}
		loadFixture(t, "vault-envelope.json", &envelopeFixture)
		envelopeBody, _ := marshalJSON(envelopeFixture.BaseMode)
		if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{
			Method: "PUT", Path: "/v1/vault-envelope", RequestID: "e2000000-0000-4000-8000-00000000000e",
			Authorization: authorization(token), Body: envelopeBody, Now: protocolFixtureTime,
		}); protocolErr != nil || response.Status != http.StatusOK {
			t.Fatalf("put envelope: response=%+v error=%v", response, protocolErr)
		}
		recordID := "e2000000-0000-4000-8000-000000000004"
		first := makeRevision(deviceID, recordID, "e2000000-0000-4000-8000-000000000005", 1, false, false)
		seed := syncCall(t, opened, deviceID, token, "e2000000-0000-4000-8000-000000000006", "0", "0", []recordRevision{first})
		if seed.ServerCursor != "3" || seed.NextCursor != "3" {
			t.Fatalf("seed cursors = %+v", seed)
		}
		setUptime(t, opened, minimumRetentionUptime)
		tombstone := makeRevision(deviceID, recordID, "e2000000-0000-4000-8000-000000000007", 2, true, true)
		withTombstone := syncCall(t, opened, deviceID, token, "e2000000-0000-4000-8000-000000000008", "3", "3", []recordRevision{tombstone})
		if withTombstone.ServerCursor != "4" || withTombstone.NextCursor != "4" {
			t.Fatalf("tombstone cursors = %+v", withTombstone)
		}
		firstPass := syncCall(t, opened, deviceID, token, "e2000000-0000-4000-8000-000000000009", "4", "4", []recordRevision{})
		if firstPass.ServerCursor != "5" || len(firstPass.Changes) != 1 || firstPass.Changes[0].CollectionMarker == nil {
			t.Fatalf("first collection pass = %+v", firstPass)
		}
		var firstRetained, tombstoneRetained int
		if err := opened.db.QueryRow("SELECT retained FROM record_revisions WHERE revision_id = ?", first.RevisionID).Scan(&firstRetained); err != nil {
			t.Fatal(err)
		}
		if err := opened.db.QueryRow("SELECT retained FROM record_revisions WHERE revision_id = ?", tombstone.RevisionID).Scan(&tombstoneRetained); err != nil {
			t.Fatal(err)
		}
		if firstRetained != 0 || tombstoneRetained != 1 {
			t.Fatalf("first-pass retention: first=%d tombstone=%d", firstRetained, tombstoneRetained)
		}
		liveRevision := makeRevision(deviceID,
			"e2000000-0000-4000-8000-00000000000f",
			"e2000000-0000-4000-8000-000000000010", 3, false, false)
		withLiveRevision := syncCall(t, opened, deviceID, token,
			"e2000000-0000-4000-8000-000000000011", "5", "5", []recordRevision{liveRevision})
		if withLiveRevision.ServerCursor != "6" || withLiveRevision.NextCursor != "6" {
			t.Fatalf("live-revision cursors = %+v", withLiveRevision)
		}
		secondDeviceID := "e2000000-0000-4000-8000-000000000013"
		secondToken := tokenWithByte(0xe4)
		enrollDevice(t, opened, protocolFixtureTime,
			"e2000000-0000-4000-8000-000000000012", secondDeviceID,
			"e2000000-0000-4000-8000-000000000014", secondToken,
		)
		bootstrapSnapshot := createBoundedSnapshot(t, opened, secondDeviceID, secondToken,
			"e2000000-0000-4000-8000-000000000015", protocolFixtureTime)
		transaction, err := opened.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if protocolErr := deleteSnapshotAndReleaseObjects(context.Background(), transaction, bootstrapSnapshot.SnapshotID); protocolErr != nil {
			transaction.Rollback()
			t.Fatalf("release bootstrap snapshot: %v", protocolErr)
		}
		if err := transaction.Commit(); err != nil {
			t.Fatal(err)
		}
		retainedSnapshot := createBoundedSnapshot(t, opened, deviceID, token,
			"e2000000-0000-4000-8000-00000000000d", protocolFixtureTime)
		setUptime(t, opened, 2*minimumRetentionUptime)
		secondPass := syncCall(t, opened, secondDeviceID, secondToken,
			"e2000000-0000-4000-8000-000000000016", "7", "7", []recordRevision{})
		if secondPass.ServerCursor != "7" || secondPass.NextCursor != "7" || len(secondPass.Changes) != 0 {
			t.Fatalf("second collection pass = %+v", secondPass)
		}
		markerSnapshot := createBoundedSnapshot(t, opened, secondDeviceID, secondToken,
			"e2000000-0000-4000-8000-000000000017", protocolFixtureTime)
		if retainedSnapshot.CutCursor != "7" || markerSnapshot.CutCursor != retainedSnapshot.CutCursor {
			t.Fatalf("same-cursor snapshots: retained=%s marker=%s", retainedSnapshot.CutCursor, markerSnapshot.CutCursor)
		}
		markerSnapshotBodies, markerSnapshotRevisions, _ := readAllSnapshotPages(
			t, opened, markerSnapshot, secondDeviceID, secondToken, protocolFixtureTime,
		)
		var markerSnapshotMarkers []collectionMarker
		for _, body := range markerSnapshotBodies {
			var page snapshotPageResponse
			if err := json.Unmarshal(body, &page); err != nil {
				t.Fatal(err)
			}
			markerSnapshotMarkers = append(markerSnapshotMarkers, page.CollectionMarkers...)
		}
		if slices.ContainsFunc(markerSnapshotRevisions, func(revision recordRevision) bool {
			return revision.RevisionID == tombstone.RevisionID
		}) || len(markerSnapshotMarkers) != 1 || markerSnapshotMarkers[0].WitnessRevisionID != tombstone.RevisionID {
			t.Fatalf("post-prune marker snapshot: revisions=%+v markers=%+v", markerSnapshotRevisions, markerSnapshotMarkers)
		}
		var snapshotCollectionBytes, markerSnapshotCollectionBytes, tombstoneCollectionBytes []byte
		if err := opened.db.QueryRow("SELECT collection_generation FROM snapshots WHERE snapshot_id = ?", retainedSnapshot.SnapshotID).Scan(&snapshotCollectionBytes); err != nil {
			t.Fatal(err)
		}
		if err := opened.db.QueryRow("SELECT collection_generation FROM snapshots WHERE snapshot_id = ?", markerSnapshot.SnapshotID).Scan(&markerSnapshotCollectionBytes); err != nil {
			t.Fatal(err)
		}
		if err := opened.db.QueryRow("SELECT collected_generation FROM record_revisions WHERE revision_id = ?", tombstone.RevisionID).Scan(&tombstoneCollectionBytes); err != nil {
			t.Fatal(err)
		}
		snapshotCollectionGeneration, snapshotCollectionErr := DecodeUint64(snapshotCollectionBytes)
		markerSnapshotCollectionGeneration, markerSnapshotCollectionErr := DecodeUint64(markerSnapshotCollectionBytes)
		tombstoneCollectionGeneration, tombstoneCollectionErr := DecodeUint64(tombstoneCollectionBytes)
		if snapshotCollectionErr != nil || markerSnapshotCollectionErr != nil || tombstoneCollectionErr != nil ||
			snapshotCollectionGeneration >= tombstoneCollectionGeneration || markerSnapshotCollectionGeneration != tombstoneCollectionGeneration {
			t.Fatalf("collection ordering: retained_snapshot=%d marker_snapshot=%d tombstone=%d retained_error=%v marker_error=%v tombstone_error=%v",
				snapshotCollectionGeneration, markerSnapshotCollectionGeneration, tombstoneCollectionGeneration,
				snapshotCollectionErr, markerSnapshotCollectionErr, tombstoneCollectionErr)
		}
		if err := validateSnapshotsAtCurrentState(t, opened); err != nil {
			t.Fatalf("pre-collection snapshot after tombstone collection: %v", err)
		}
		var tombstoneObjectCount, markerCount int
		if err := opened.db.QueryRow("SELECT retained FROM record_revisions WHERE revision_id = ?", tombstone.RevisionID).Scan(&tombstoneRetained); err != nil {
			t.Fatal(err)
		}
		if err := opened.db.QueryRow(`
			SELECT count(*) FROM revision_objects o
			JOIN record_revisions r USING (content_hash)
			WHERE r.revision_id = ?`, tombstone.RevisionID).Scan(&tombstoneObjectCount); err != nil {
			t.Fatal(err)
		}
		if err := opened.db.QueryRow("SELECT count(*) FROM collection_markers WHERE record_id = ?", recordID).Scan(&markerCount); err != nil {
			t.Fatal(err)
		}
		if tombstoneRetained != 0 || tombstoneObjectCount != 1 || markerCount != 1 {
			t.Fatalf("snapshot-pinned tombstone fallback: retained=%d objects=%d markers=%d", tombstoneRetained, tombstoneObjectCount, markerCount)
		}
		equivocation := tombstone
		equivocation.RevisionID = "e2000000-0000-4000-8000-00000000000b"
		equivocationID := "e2000000-0000-4000-8000-00000000000c"
		equivocationBody, _ := marshalJSON(syncRequest{
			ProtocolVersion: "1", DeviceID: deviceID, RequestID: equivocationID,
			AfterCursor: "7", AckCursor: "7", Mutations: []recordRevision{equivocation},
		})
		if _, protocolErr := opened.HandleAPI(context.Background(), api.Request{
			Method: "POST", Path: "/v1/sync", RequestID: equivocationID,
			Authorization: authorization(token), Body: equivocationBody, Now: protocolFixtureTime,
		}); protocolErr == nil || protocolErr.Code != "revision_equivocation" {
			t.Fatalf("post-collection equal-vector error = %v", protocolErr)
		}

		rewriteSnapshotPageDescriptor(t, opened, retainedSnapshot.SnapshotID,
			func(descriptor snapshotPageDescriptor) bool {
				return slices.Contains(descriptor.RevisionIDs, tombstone.RevisionID)
			},
			func(descriptor *snapshotPageDescriptor) {
				retained := descriptor.RevisionIDs[:0]
				for _, revisionID := range descriptor.RevisionIDs {
					if revisionID != tombstone.RevisionID {
						retained = append(retained, revisionID)
					}
				}
				descriptor.RevisionIDs = retained
			})
		deleteSnapshotRevisionReference(t, opened, retainedSnapshot.SnapshotID, tombstone.RevisionID)
		if err := validateSnapshotsAtCurrentState(t, opened); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "snapshot frontier head is missing at cut") {
			t.Fatalf("pre-collection snapshot omission after later collection error=%v", err)
		}
	})

	t.Run("collection generation exhaustion freezes collection", func(t *testing.T) {
		opened, _ := openDataPlane(t)
		defer opened.Close()
		deviceID := "e3000000-0000-4000-8000-000000000001"
		token := tokenWithByte(0xe3)
		enrollDevice(t, opened, protocolFixtureTime,
			"e3000000-0000-4000-8000-000000000002", deviceID,
			"e3000000-0000-4000-8000-000000000003", token,
		)
		var envelopeFixture struct {
			BaseMode putEnvelopeRequest `json:"base_mode"`
		}
		loadFixture(t, "vault-envelope.json", &envelopeFixture)
		envelopeBody, _ := marshalJSON(envelopeFixture.BaseMode)
		if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{
			Method: "PUT", Path: "/v1/vault-envelope", RequestID: "e3000000-0000-4000-8000-000000000004",
			Authorization: authorization(token), Body: envelopeBody, Now: protocolFixtureTime,
		}); protocolErr != nil || response.Status != http.StatusOK {
			t.Fatalf("put envelope: response=%+v error=%v", response, protocolErr)
		}
		tombstone := makeRevision(deviceID,
			"e3000000-0000-4000-8000-000000000005",
			"e3000000-0000-4000-8000-000000000006", 1, true, true)
		seed := syncCall(t, opened, deviceID, token,
			"e3000000-0000-4000-8000-000000000007", "0", "0", []recordRevision{tombstone})
		if seed.ServerCursor != "3" || seed.NextCursor != "3" {
			t.Fatalf("seed cursors = %+v", seed)
		}
		setUptime(t, opened, minimumRetentionUptime)
		exhausted := EncodeUint64(math.MaxUint64)
		if _, err := opened.db.Exec("UPDATE runtime_state SET collection_generation = ? WHERE singleton = 1", exhausted[:]); err != nil {
			t.Fatal(err)
		}
		frozen := syncCall(t, opened, deviceID, token,
			"e3000000-0000-4000-8000-000000000008", "3", "3", []recordRevision{})
		if frozen.ServerCursor != "3" || frozen.NextCursor != "3" || len(frozen.Changes) != 0 {
			t.Fatalf("frozen collection response = %+v", frozen)
		}
		var retained, markerCount int
		if err := opened.db.QueryRow("SELECT retained FROM record_revisions WHERE revision_id = ?", tombstone.RevisionID).Scan(&retained); err != nil {
			t.Fatal(err)
		}
		if err := opened.db.QueryRow("SELECT count(*) FROM collection_markers WHERE record_id = ?", tombstone.RecordID).Scan(&markerCount); err != nil {
			t.Fatal(err)
		}
		if retained != 1 || markerCount != 0 {
			t.Fatalf("exhausted generation collection: retained=%d markers=%d", retained, markerCount)
		}
	})
}

func TestBackwardWallClockAndRevokedNoOpReceipt(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	managerID := "60000000-0000-4000-8000-000000000001"
	targetID := "60000000-0000-4000-8000-000000000002"
	managerToken := tokenWithByte(0x61)
	targetToken := tokenWithByte(0x62)
	enrollDevice(t, opened, protocolFixtureTime, "60000000-0000-4000-8000-000000000003", managerID, "60000000-0000-4000-8000-000000000004", managerToken)
	enrollDevice(t, opened, protocolFixtureTime, "60000000-0000-4000-8000-000000000005", targetID, "60000000-0000-4000-8000-000000000006", targetToken)

	backward := protocolFixtureTime.Add(-24 * time.Hour)
	syncID := "60000000-0000-4000-8000-000000000007"
	syncBody, _ := marshalJSON(syncRequest{
		ProtocolVersion: "1", DeviceID: managerID, RequestID: syncID,
		AfterCursor: "0", AckCursor: "0", Mutations: []recordRevision{},
	})
	if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "POST", Path: "/v1/sync", RequestID: syncID,
		Authorization: authorization(managerToken), Body: syncBody, Now: backward,
	}); protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("backward-clock sync: response=%+v error=%v", response, protocolErr)
	}
	manager, _, protocolErr := readDevice(context.Background(), opened.db, managerID)
	if protocolErr != nil || manager.LastSyncAt == nil || *manager.LastSyncAt != formatTimestamp(protocolFixtureTime.UnixMilli()) {
		t.Fatalf("clamped last-sync device=%+v error=%v", manager, protocolErr)
	}

	revokeID := "60000000-0000-4000-8000-000000000008"
	revokeBody, _ := marshalJSON(revokeDeviceRequest{RequestID: revokeID, AllowZeroActive: false})
	response, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "POST", Path: "/v1/devices/" + targetID + "/revoke", RequestID: revokeID,
		Authorization: authorization(managerToken), Body: revokeBody, Now: backward,
	})
	if protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("backward-clock revoke: response=%+v error=%v", response, protocolErr)
	}
	var revoked device
	if err := json.Unmarshal(response.Body, &revoked); err != nil || revoked.RevokedAt == nil || *revoked.RevokedAt != formatTimestamp(protocolFixtureTime.UnixMilli()) {
		t.Fatalf("clamped revoked device=%+v error=%v", revoked, err)
	}

	noOpID := "60000000-0000-4000-8000-000000000009"
	noOpBody, _ := marshalJSON(revokeDeviceRequest{RequestID: noOpID, AllowZeroActive: false})
	noOpCall := api.Request{
		Method: "POST", Path: "/v1/devices/" + targetID + "/revoke", RequestID: noOpID,
		Authorization: authorization(managerToken), Body: noOpBody, Now: protocolFixtureTime,
	}
	if noOp, protocolErr := opened.HandleAPI(context.Background(), noOpCall); protocolErr != nil || noOp.Status != http.StatusOK {
		t.Fatalf("already-revoked no-op: response=%+v error=%v", noOp, protocolErr)
	}
	crossTarget := noOpCall
	crossTarget.Path = "/v1/devices/" + managerID + "/revoke"
	if _, protocolErr := opened.HandleAPI(context.Background(), crossTarget); protocolErr == nil || protocolErr.Code != "request_id_reused" {
		t.Fatalf("cross-target revocation request-ID reuse error = %v", protocolErr)
	}
	noOpCall.Body = append(noOpCall.Body, '\n')
	if _, protocolErr := opened.HandleAPI(context.Background(), noOpCall); protocolErr == nil || protocolErr.Code != "request_id_reused" {
		t.Fatalf("already-revoked request-ID reuse error = %v", protocolErr)
	}
}

func TestSyncRejectsOutOfOrderMutationsBeforeAuthentication(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	deviceID := "70000000-0000-4000-8000-000000000001"
	makeRevision := func(counter uint64, revisionID string) recordRevision {
		return recordRevision{
			RecordID: "70000000-0000-4000-8000-000000000002", RevisionID: revisionID,
			AuthorDeviceID: deviceID, AuthorCounter: encodeUint64Text(counter),
			VersionVector: []vectorEntry{{DeviceID: deviceID, Counter: encodeUint64Text(counter)}},
			PayloadSchema: "1", CryptoSuite: cryptoSuite,
			Nonce:      base64.RawURLEncoding.EncodeToString(make([]byte, 24)),
			Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		}
	}
	requestID := "70000000-0000-4000-8000-000000000005"
	body, _ := marshalJSON(syncRequest{
		ProtocolVersion: "1", DeviceID: deviceID, RequestID: requestID,
		AfterCursor: "18446744073709551615", AckCursor: "0",
		Mutations: []recordRevision{
			makeRevision(2, "70000000-0000-4000-8000-000000000004"),
			makeRevision(1, "70000000-0000-4000-8000-000000000003"),
		},
	})
	if _, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "POST", Path: "/v1/sync", RequestID: requestID,
		Authorization: "Bearer invalid", Body: body, Now: protocolFixtureTime,
	}); protocolErr == nil || protocolErr.Code != "invalid_request" {
		t.Fatalf("out-of-order prevalidation error = %v", protocolErr)
	}
}

func TestEnrollmentGrantAndAPIConcurrencyDoesNotInvertLocks(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	deviceID := "80000000-0000-4000-8000-000000000001"
	token := tokenWithByte(0x81)
	enrollDevice(t, opened, protocolFixtureTime, "80000000-0000-4000-8000-000000000002", deviceID, "80000000-0000-4000-8000-000000000003", token)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errorsChannel := make(chan error, 2)
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for index := 0; index < 64; index++ {
			grant, err := opened.CreateEnrollmentGrant(ctx, protocolFixtureTime)
			if err != nil {
				errorsChannel <- err
				return
			}
			clear(grant.Grant)
		}
	}()
	go func() {
		defer wait.Done()
		for index := 0; index < 64; index++ {
			requestID := fmt.Sprintf("80000000-0000-4000-8000-%012x", index+4)
			body, _ := marshalJSON(syncRequest{
				ProtocolVersion: "1", DeviceID: deviceID, RequestID: requestID,
				AfterCursor: "0", AckCursor: "0", Mutations: []recordRevision{},
			})
			if _, protocolErr := opened.HandleAPI(ctx, api.Request{
				Method: "POST", Path: "/v1/sync", RequestID: requestID,
				Authorization: authorization(token), Body: body, Now: protocolFixtureTime,
			}); protocolErr != nil {
				errorsChannel <- protocolErr
				return
			}
		}
	}()
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal("concurrent enrollment and API work exceeded lock-order deadline")
	}
}

func TestEnrollmentGrantIssuancePrunesExpiredRetention(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	issuedAt := time.Now()
	for index := 0; index < 8; index++ {
		grant, err := opened.CreateEnrollmentGrant(context.Background(), issuedAt)
		if err != nil {
			t.Fatal(err)
		}
		clear(grant.Grant)
		issuedAt = issuedAt.Add(enrollmentGrantLifetime)
	}

	var durableCount int
	if err := opened.db.QueryRow("SELECT count(*) FROM enrollment_grants").Scan(&durableCount); err != nil {
		t.Fatal(err)
	}
	opened.ephemeral.mu.Lock()
	deadlineCount := len(opened.ephemeral.grantDeadlines)
	opened.ephemeral.mu.Unlock()
	if durableCount != 1 {
		t.Errorf("durable enrollment grant count=%d, want 1", durableCount)
	}
	if deadlineCount != 1 {
		t.Errorf("in-memory enrollment grant deadline count=%d, want 1", deadlineCount)
	}
}

func TestSelfRevocationReceiptReplaysIdenticalRawHTTP(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	deviceID := "90000000-0000-4000-8000-000000000001"
	token := tokenWithByte(0x91)
	enrollDevice(t, opened, protocolFixtureTime, "90000000-0000-4000-8000-000000000002", deviceID, "90000000-0000-4000-8000-000000000003", token)
	settings := config.Settings{
		ConfigVersion: config.ConfigVersion, InstanceID: testIdentity.InstanceID,
		VaultID: testIdentity.VaultID, Listeners: []string{"127.0.0.1:37421"},
	}
	handler, err := httpapi.New(settings, opened)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = false
	server.Start()
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")
	requestID := "90000000-0000-4000-8000-000000000004"
	body, _ := marshalJSON(revokeDeviceRequest{RequestID: requestID, AllowZeroActive: true})
	rawRequest := fmt.Sprintf("POST /v1/devices/%s/revoke HTTP/1.1\r\nHost: %s\r\nJAT-Protocol-Version: 1\r\nJAT-Request-ID: %s\r\nAuthorization: %s\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", deviceID, address, requestID, authorization(token), len(body), body)
	doRaw := func() []byte {
		connection, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(connection, rawRequest); err != nil {
			connection.Close()
			t.Fatal(err)
		}
		response, err := io.ReadAll(connection)
		connection.Close()
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	first := doRaw()
	wantHeaderBlock := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nJAT-Protocol-Version: 1\r\nJAT-Request-ID: %s\r\nContent-Length: 314\r\n\r\n", requestID)
	if !bytes.HasPrefix(first, []byte(wantHeaderBlock)) {
		t.Fatalf("self-revocation wire headers do not match frozen vector: %q", first)
	}
	var retainedHeadersJSON []byte
	if err := opened.db.QueryRow("SELECT response_headers_json FROM self_revocation_receipts WHERE device_id = ?", deviceID).Scan(&retainedHeadersJSON); err != nil {
		t.Fatal(err)
	}
	var retainedHeaders []api.Header
	if err := json.Unmarshal(retainedHeadersJSON, &retainedHeaders); err != nil || !slices.Equal(retainedHeaders, api.V1ResponseHeaders(requestID, 314)) {
		t.Fatalf("retained frozen header artifact=%+v error=%v", retainedHeaders, err)
	}
	time.Sleep(20 * time.Millisecond)
	second := doRaw()
	if !bytes.Equal(first, second) {
		t.Fatalf("self-revocation raw response changed\nfirst=%q\nsecond=%q", first, second)
	}
	if bytes.Contains(first, []byte("\r\nDate:")) {
		t.Fatalf("self-revocation response contains dynamic Date header: %q", first)
	}
	if bytes.Contains(first, []byte("Cache-Control:")) || bytes.Contains(first, []byte("X-Content-Type-Options:")) {
		t.Fatalf("self-revocation response contains non-frozen headers: %q", first)
	}
}

func TestRetiredSelfRevocationBearerNeverFallsBackToDeviceRegistry(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	deviceID := "91000000-0000-4000-8000-000000000001"
	wrongTarget := "91000000-0000-4000-8000-000000000002"
	token := tokenWithByte(0x92)
	enrollDevice(t, opened, protocolFixtureTime, "91000000-0000-4000-8000-000000000003", deviceID, "91000000-0000-4000-8000-000000000004", token)
	requestID := "91000000-0000-4000-8000-000000000005"
	body, _ := marshalJSON(revokeDeviceRequest{RequestID: requestID, AllowZeroActive: true})
	if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "POST", Path: "/v1/devices/" + deviceID + "/revoke", RequestID: requestID,
		Authorization: authorization(token), Body: body, Now: protocolFixtureTime,
	}); protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("self revoke: response=%+v error=%v", response, protocolErr)
	}
	// Make any fallback registry scan fail loudly. The endpoint-local retired
	// receipt path must still return token_revoked for a wrong target.
	if _, err := opened.db.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.db.Exec("UPDATE devices SET token_hash = zeroblob(31) WHERE device_id = ?", deviceID); err != nil {
		t.Fatal(err)
	}
	var beforeCursor []byte
	var beforeChanges, beforeReceipts int
	if err := opened.db.QueryRow("SELECT server_cursor FROM runtime_state WHERE singleton = 1").Scan(&beforeCursor); err != nil {
		t.Fatal(err)
	}
	if err := opened.db.QueryRow("SELECT count(*) FROM changes").Scan(&beforeChanges); err != nil {
		t.Fatal(err)
	}
	if err := opened.db.QueryRow("SELECT count(*) FROM operation_receipts").Scan(&beforeReceipts); err != nil {
		t.Fatal(err)
	}
	wrongBody, _ := marshalJSON(revokeDeviceRequest{RequestID: requestID, AllowZeroActive: true})
	if _, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "POST", Path: "/v1/devices/" + wrongTarget + "/revoke", RequestID: requestID,
		Authorization: authorization(token), Body: wrongBody, Now: protocolFixtureTime.Add(time.Hour),
	}); protocolErr == nil || protocolErr.Code != "token_revoked" {
		t.Fatalf("wrong-target retired retry error = %v", protocolErr)
	}
	var afterCursor []byte
	var afterChanges, afterReceipts int
	if err := opened.db.QueryRow("SELECT server_cursor FROM runtime_state WHERE singleton = 1").Scan(&afterCursor); err != nil {
		t.Fatal(err)
	}
	if err := opened.db.QueryRow("SELECT count(*) FROM changes").Scan(&afterChanges); err != nil {
		t.Fatal(err)
	}
	if err := opened.db.QueryRow("SELECT count(*) FROM operation_receipts").Scan(&afterReceipts); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeCursor, afterCursor) || beforeChanges != afterChanges || beforeReceipts != afterReceipts {
		t.Fatalf("retired mismatch mutated state: cursor %x/%x changes %d/%d receipts %d/%d", beforeCursor, afterCursor, beforeChanges, afterChanges, beforeReceipts, afterReceipts)
	}
}

func TestSyncAndSnapshotResponsesHonorFourMiBBound(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	deviceID := "00000000-0000-4000-8000-000000000003"
	token := tokenWithByte(9)
	enrollDevice(t, opened, protocolFixtureTime, "00000000-0000-4000-8000-000000000004", deviceID, "00000000-0000-4000-8000-000000000005", token)
	var envelopeFixture struct {
		BaseMode putEnvelopeRequest `json:"base_mode"`
	}
	loadFixture(t, "vault-envelope.json", &envelopeFixture)
	envelopeBody, _ := marshalJSON(envelopeFixture.BaseMode)
	if _, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "PUT", Path: "/v1/vault-envelope", RequestID: "00000000-0000-4000-8000-000000000006",
		Authorization: authorization(token), Body: envelopeBody, Now: protocolFixtureTime,
	}); protocolErr != nil {
		t.Fatal(protocolErr)
	}

	ciphertext := base64.RawURLEncoding.EncodeToString(make([]byte, 512*1024))
	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 24))
	var lastResponse api.Response
	for index := 1; index <= 7; index++ {
		revision := recordRevision{
			RecordID:       fmt.Sprintf("20000000-0000-4000-8000-%012x", index),
			RevisionID:     fmt.Sprintf("30000000-0000-4000-8000-%012x", index),
			AuthorDeviceID: deviceID,
			AuthorCounter:  encodeUint64Text(uint64(index)),
			VersionVector:  []vectorEntry{{DeviceID: deviceID, Counter: encodeUint64Text(uint64(index))}},
			PayloadSchema:  "1", CryptoSuite: cryptoSuite, Tombstone: false,
			Nonce: nonce, Ciphertext: ciphertext,
		}
		requestID := fmt.Sprintf("40000000-0000-4000-8000-%012x", index)
		body, _ := marshalJSON(syncRequest{
			ProtocolVersion: "1", DeviceID: deviceID, RequestID: requestID,
			AfterCursor: "0", AckCursor: "0", Mutations: []recordRevision{revision},
		})
		var protocolErr *api.Error
		lastResponse, protocolErr = opened.HandleAPI(context.Background(), api.Request{
			Method: "POST", Path: "/v1/sync", RequestID: requestID,
			Authorization: authorization(token), Body: body, Now: protocolFixtureTime,
		})
		if protocolErr != nil || lastResponse.Status != 200 {
			t.Fatalf("large mutation %d: response=%+v error=%v", index, lastResponse, protocolErr)
		}
	}
	if len(lastResponse.Body) > maxBodyBytes {
		t.Fatalf("sync response bytes = %d, max=%d", len(lastResponse.Body), maxBodyBytes)
	}
	var syncResult syncResponse
	if err := json.Unmarshal(lastResponse.Body, &syncResult); err != nil || !syncResult.HasMore {
		t.Fatalf("bounded sync response has_more=%v error=%v", syncResult.HasMore, err)
	}

	createID := "50000000-0000-4000-8000-000000000001"
	createBody, _ := marshalJSON(snapshotCreateRequest{
		ProtocolVersion: "1", DeviceID: deviceID, RequestID: createID,
		RequiredCapabilities: append([]string(nil), requiredSnapshotCapabilities...),
	})
	created, protocolErr := opened.HandleAPI(context.Background(), api.Request{
		Method: "POST", Path: "/v1/snapshot-reads", RequestID: createID,
		Authorization: authorization(token), Body: createBody, Now: protocolFixtureTime,
	})
	if protocolErr != nil || created.Status != 201 {
		t.Fatalf("large snapshot create: response=%+v error=%v", created, protocolErr)
	}
	var snapshot snapshotCreateResponse
	if err := json.Unmarshal(created.Body, &snapshot); err != nil {
		t.Fatal(err)
	}
	pageBodies, revisions, _ := readAllSnapshotPages(t, opened, snapshot, deviceID, token, protocolFixtureTime)
	if len(revisions) != 7 {
		t.Fatalf("large snapshot revisions = %d", len(revisions))
	}
	for index, body := range pageBodies {
		if len(body) > maxBodyBytes {
			t.Fatalf("snapshot page %d bytes = %d, max=%d", index, len(body), maxBodyBytes)
		}
	}
}

func TestSyncRejectsCursorLaunderingBeforeAcknowledgement(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	writerID := "c0000000-0000-4000-8000-000000000001"
	observerID := "c0000000-0000-4000-8000-000000000002"
	writerToken := tokenWithByte(0xc1)
	observerToken := tokenWithByte(0xc2)
	enrollDevice(t, opened, protocolFixtureTime, "c1000000-0000-4000-8000-000000000001", writerID, "c2000000-0000-4000-8000-000000000001", writerToken)
	enrollDevice(t, opened, protocolFixtureTime, "c1000000-0000-4000-8000-000000000002", observerID, "c2000000-0000-4000-8000-000000000002", observerToken)

	mutations := make([]recordRevision, 0, 126)
	for index := 1; index <= 126; index++ {
		mutations = append(mutations, recordRevision{
			RecordID:       fmt.Sprintf("d0000000-0000-4000-8000-%012x", index),
			RevisionID:     fmt.Sprintf("e0000000-0000-4000-8000-%012x", index),
			AuthorDeviceID: writerID,
			AuthorCounter:  encodeUint64Text(uint64(index)),
			VersionVector:  []vectorEntry{{DeviceID: writerID, Counter: encodeUint64Text(uint64(index))}},
			PayloadSchema:  "1", CryptoSuite: cryptoSuite,
			Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		})
	}
	fillerID := "f0000000-0000-4000-8000-000000000001"
	fillerBody, _ := marshalJSON(syncRequest{ProtocolVersion: "1", DeviceID: writerID, RequestID: fillerID, AfterCursor: "0", AckCursor: "0", Mutations: mutations})
	if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/sync", RequestID: fillerID, Authorization: authorization(writerToken), Body: fillerBody, Now: protocolFixtureTime}); protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("filler sync: response=%+v error=%v", response, protocolErr)
	}
	observerSyncID := "f0000000-0000-4000-8000-000000000002"
	observerSyncBody, _ := marshalJSON(syncRequest{ProtocolVersion: "1", DeviceID: observerID, RequestID: observerSyncID, AfterCursor: "0", AckCursor: "0", Mutations: []recordRevision{}})
	observerResponse, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/sync", RequestID: observerSyncID, Authorization: authorization(observerToken), Body: observerSyncBody, Now: protocolFixtureTime})
	var observerResult syncResponse
	if protocolErr != nil || json.Unmarshal(observerResponse.Body, &observerResult) != nil || observerResult.NextCursor != "128" {
		t.Fatalf("observer bounded page: response=%s error=%v", observerResponse.Body, protocolErr)
	}
	tombstone := recordRevision{
		RecordID: "dfffffff-0000-4000-8000-000000000001", RevisionID: "efffffff-0000-4000-8000-000000000001",
		AuthorDeviceID: writerID, AuthorCounter: "127", VersionVector: []vectorEntry{{DeviceID: writerID, Counter: "127"}},
		PayloadSchema: "1", CryptoSuite: cryptoSuite, Tombstone: true,
		Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	authenticator := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tombstone.CollectionWitnessAuthenticator = &authenticator
	tombstoneID := "f0000000-0000-4000-8000-000000000003"
	tombstoneBody, _ := marshalJSON(syncRequest{ProtocolVersion: "1", DeviceID: writerID, RequestID: tombstoneID, AfterCursor: "128", AckCursor: "128", Mutations: []recordRevision{tombstone}})
	if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/sync", RequestID: tombstoneID, Authorization: authorization(writerToken), Body: tombstoneBody, Now: protocolFixtureTime}); protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("tombstone sync: response=%+v error=%v", response, protocolErr)
	}
	revokeID := "f0000000-0000-4000-8000-000000000004"
	revokeBody, _ := marshalJSON(revokeDeviceRequest{RequestID: revokeID})
	if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/devices/" + writerID + "/revoke", RequestID: revokeID, Authorization: authorization(observerToken), Body: revokeBody, Now: protocolFixtureTime}); protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("writer revoke: response=%+v error=%v", response, protocolErr)
	}
	retention := EncodeUint64(uint64(minimumRetentionUptime / time.Millisecond))
	if _, err := opened.db.Exec("UPDATE runtime_state SET accumulated_uptime_ms = ? WHERE singleton = 1", retention[:]); err != nil {
		t.Fatal(err)
	}
	for index, cursors := range [][2]string{{"130", "0"}, {"0", "130"}} {
		requestID := fmt.Sprintf("f0000000-0000-4000-8000-%012x", index+5)
		body, _ := marshalJSON(syncRequest{ProtocolVersion: "1", DeviceID: observerID, RequestID: requestID, AfterCursor: cursors[0], AckCursor: cursors[1], Mutations: []recordRevision{}})
		if _, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/sync", RequestID: requestID, Authorization: authorization(observerToken), Body: body, Now: protocolFixtureTime}); protocolErr == nil || protocolErr.Code != "invalid_request" {
			t.Fatalf("launder attempt %d error = %v", index, protocolErr)
		}
	}
	var retained int
	var floorBytes []byte
	var markers int
	if err := opened.db.QueryRow("SELECT retained FROM record_revisions WHERE revision_id = ?", tombstone.RevisionID).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if err := opened.db.QueryRow("SELECT cursor_floor FROM runtime_state WHERE singleton = 1").Scan(&floorBytes); err != nil {
		t.Fatal(err)
	}
	floor, err := DecodeUint64(floorBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.db.QueryRow("SELECT count(*) FROM collection_markers WHERE record_id = ?", tombstone.RecordID).Scan(&markers); err != nil {
		t.Fatal(err)
	}
	if retained != 1 || floor != 0 || markers != 0 {
		t.Fatalf("cursor laundering changed retention: retained=%d floor=%d markers=%d", retained, floor, markers)
	}
}

func TestRevisionEquivocationPrecedesCounterConflict(t *testing.T) {
	t.Run("same batch revision ID changes bytes", func(t *testing.T) {
		opened, _ := openDataPlane(t)
		defer opened.Close()
		deviceID := "a1000000-0000-4000-8000-000000000001"
		token := tokenWithByte(0xa1)
		enrollDevice(t, opened, protocolFixtureTime, "a1000000-0000-4000-8000-000000000002", deviceID, "a1000000-0000-4000-8000-000000000003", token)
		revisionID := "a1000000-0000-4000-8000-000000000004"
		makeRevision := func(counter uint64, recordSuffix int) recordRevision {
			return recordRevision{RecordID: fmt.Sprintf("a2000000-0000-4000-8000-%012x", recordSuffix), RevisionID: revisionID, AuthorDeviceID: deviceID,
				AuthorCounter: encodeUint64Text(counter), VersionVector: []vectorEntry{{DeviceID: deviceID, Counter: encodeUint64Text(counter)}}, PayloadSchema: "1", CryptoSuite: cryptoSuite,
				Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16))}
		}
		requestID := "a1000000-0000-4000-8000-000000000005"
		body, _ := marshalJSON(syncRequest{ProtocolVersion: "1", DeviceID: deviceID, RequestID: requestID, AfterCursor: "0", AckCursor: "0", Mutations: []recordRevision{makeRevision(1, 1), makeRevision(2, 2)}})
		if _, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/sync", RequestID: requestID, Authorization: authorization(token), Body: body, Now: protocolFixtureTime}); protocolErr == nil || protocolErr.Code != "revision_equivocation" {
			t.Fatalf("same-batch revision-ID reuse error = %v", protocolErr)
		}
	})
	t.Run("equal vector changed revision ID", func(t *testing.T) {
		opened, _ := openDataPlane(t)
		defer opened.Close()
		deviceID := "a3000000-0000-4000-8000-000000000001"
		token := tokenWithByte(0xa3)
		enrollDevice(t, opened, protocolFixtureTime, "a3000000-0000-4000-8000-000000000002", deviceID, "a3000000-0000-4000-8000-000000000003", token)
		recordID := "a3000000-0000-4000-8000-000000000004"
		makeRevision := func(revisionID string) recordRevision {
			return recordRevision{RecordID: recordID, RevisionID: revisionID, AuthorDeviceID: deviceID, AuthorCounter: "1", VersionVector: []vectorEntry{{DeviceID: deviceID, Counter: "1"}},
				PayloadSchema: "1", CryptoSuite: cryptoSuite, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16))}
		}
		syncMutation(t, opened, deviceID, token, "a3000000-0000-4000-8000-000000000005", makeRevision("a3000000-0000-4000-8000-000000000006"), protocolFixtureTime)
		requestID := "a3000000-0000-4000-8000-000000000007"
		body, _ := marshalJSON(syncRequest{ProtocolVersion: "1", DeviceID: deviceID, RequestID: requestID, AfterCursor: "0", AckCursor: "0", Mutations: []recordRevision{makeRevision("a3000000-0000-4000-8000-000000000008")}})
		if _, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/sync", RequestID: requestID, Authorization: authorization(token), Body: body, Now: protocolFixtureTime}); protocolErr == nil || protocolErr.Code != "revision_equivocation" {
			t.Fatalf("equal-vector changed-ID error = %v", protocolErr)
		}
	})
}

func TestEmptySyncCollectionWorkIsVaultSizeIndependent(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	deviceID := "b1000000-0000-4000-8000-000000000001"
	token := tokenWithByte(0xb1)
	enrollDevice(t, opened, protocolFixtureTime, "b1000000-0000-4000-8000-000000000002", deviceID, "b1000000-0000-4000-8000-000000000003", token)
	mutations := make([]recordRevision, 0, 64)
	for index := 1; index <= 64; index++ {
		mutations = append(mutations, recordRevision{RecordID: fmt.Sprintf("b2000000-0000-4000-8000-%012x", index), RevisionID: fmt.Sprintf("b3000000-0000-4000-8000-%012x", index),
			AuthorDeviceID: deviceID, AuthorCounter: encodeUint64Text(uint64(index)), VersionVector: []vectorEntry{{DeviceID: deviceID, Counter: encodeUint64Text(uint64(index))}},
			PayloadSchema: "1", CryptoSuite: cryptoSuite, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16))})
	}
	requestID := "b1000000-0000-4000-8000-000000000004"
	body, _ := marshalJSON(syncRequest{ProtocolVersion: "1", DeviceID: deviceID, RequestID: requestID, AfterCursor: "0", AckCursor: "0", Mutations: mutations})
	if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/sync", RequestID: requestID, Authorization: authorization(token), Body: body, Now: protocolFixtureTime}); protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("seed vault: response=%+v error=%v", response, protocolErr)
	}
	if _, err := opened.db.Exec("UPDATE runtime_state SET collection_scan_after_record_id = '' WHERE singleton = 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.db.Exec("UPDATE record_revisions SET vector_json = ? WHERE record_id = ?", []byte("{"), "b2000000-0000-4000-8000-000000000040"); err != nil {
		t.Fatal(err)
	}
	emptyID := "b1000000-0000-4000-8000-000000000005"
	emptyBody, _ := marshalJSON(syncRequest{ProtocolVersion: "1", DeviceID: deviceID, RequestID: emptyID, AfterCursor: "65", AckCursor: "0", Mutations: []recordRevision{}})
	if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/sync", RequestID: emptyID, Authorization: authorization(token), Body: emptyBody, Now: protocolFixtureTime}); protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("bounded empty sync reached later corrupt row: response=%+v error=%v", response, protocolErr)
	}
	var scanAfter string
	if err := opened.db.QueryRow("SELECT collection_scan_after_record_id FROM runtime_state WHERE singleton = 1").Scan(&scanAfter); err != nil {
		t.Fatal(err)
	}
	if scanAfter != "b2000000-0000-4000-8000-000000000020" {
		t.Fatalf("bounded collection scan stopped at %q", scanAfter)
	}
}

func TestSnapshotStreamsUndominatedMembershipAndAccountsEveryIndex(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	deviceID := "b4000000-0000-4000-8000-000000000001"
	token := tokenWithByte(0xb4)
	enrollDevice(t, opened, protocolFixtureTime, "b4000000-0000-4000-8000-000000000002", deviceID, "b4000000-0000-4000-8000-000000000003", token)
	var envelopeFixture struct {
		BaseMode putEnvelopeRequest `json:"base_mode"`
	}
	loadFixture(t, "vault-envelope.json", &envelopeFixture)
	envelopeBody, _ := marshalJSON(envelopeFixture.BaseMode)
	if _, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "PUT", Path: "/v1/vault-envelope", RequestID: "b4000000-0000-4000-8000-000000000004", Authorization: authorization(token), Body: envelopeBody, Now: protocolFixtureTime}); protocolErr != nil {
		t.Fatal(protocolErr)
	}
	mutations := make([]recordRevision, 0, 256)
	for index := 1; index <= 256; index++ {
		mutations = append(mutations, recordRevision{RecordID: "b4000000-0000-4000-8000-000000000005", RevisionID: fmt.Sprintf("b5000000-0000-4000-8000-%012x", index), AuthorDeviceID: deviceID,
			AuthorCounter: encodeUint64Text(uint64(index)), VersionVector: []vectorEntry{{DeviceID: deviceID, Counter: encodeUint64Text(uint64(index))}}, PayloadSchema: "1", CryptoSuite: cryptoSuite,
			Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16))})
	}
	syncID := "b4000000-0000-4000-8000-000000000006"
	syncBody, _ := marshalJSON(syncRequest{ProtocolVersion: "1", DeviceID: deviceID, RequestID: syncID, AfterCursor: "0", AckCursor: "0", Mutations: mutations})
	if response, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/sync", RequestID: syncID, Authorization: authorization(token), Body: syncBody, Now: protocolFixtureTime}); protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("seed dominated chain: response=%+v error=%v", response, protocolErr)
	}
	createID := "b4000000-0000-4000-8000-000000000007"
	createBody, _ := marshalJSON(snapshotCreateRequest{ProtocolVersion: "1", DeviceID: deviceID, RequestID: createID, RequiredCapabilities: append([]string(nil), requiredSnapshotCapabilities...)})
	created, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/snapshot-reads", RequestID: createID, Authorization: authorization(token), Body: createBody, Now: protocolFixtureTime})
	if protocolErr != nil || created.Status != http.StatusCreated {
		t.Fatalf("create snapshot: response=%+v error=%v", created, protocolErr)
	}
	var create snapshotCreateResponse
	if err := json.Unmarshal(created.Body, &create); err != nil {
		t.Fatal(err)
	}
	var metadataBytes int64
	var retainedCreate []byte
	if err := opened.db.QueryRow("SELECT metadata_bytes, create_response_json FROM snapshots WHERE snapshot_id = ?", create.SnapshotID).Scan(&metadataBytes, &retainedCreate); err != nil {
		t.Fatal(err)
	}
	pageRows, err := opened.db.Query("SELECT page_token, response_json FROM snapshot_pages WHERE snapshot_id = ? ORDER BY page_index", create.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	var pages []storedSnapshotPage
	for pageRows.Next() {
		var page storedSnapshotPage
		if err := pageRows.Scan(&page.token, &page.body); err != nil || decodeStoredSnapshotPageDescriptor(page.body, &page.descriptor) != nil {
			pageRows.Close()
			t.Fatalf("read retained page: %v", err)
		}
		pages = append(pages, page)
	}
	if err := pageRows.Close(); err != nil {
		t.Fatal(err)
	}
	refRows, err := opened.db.Query("SELECT revision_id, content_hash FROM snapshot_revision_refs WHERE snapshot_id = ? ORDER BY revision_id", create.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	var references []snapshotRevisionReference
	for refRows.Next() {
		var reference snapshotRevisionReference
		var hash []byte
		if err := refRows.Scan(&reference.revisionID, &hash); err != nil || len(hash) != 32 {
			refRows.Close()
			t.Fatalf("read retained ref: %v", err)
		}
		copy(reference.contentHash[:], hash)
		references = append(references, reference)
	}
	if err := refRows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(references) != 1 || references[0].revisionID != "b5000000-0000-4000-8000-000000000100" {
		t.Fatalf("snapshot retained refs = %+v", references)
	}
	wantMetadata, ok := snapshotMetadataBytes(create.SnapshotID, deviceID, createID, retainedCreate, pages, references)
	if !ok || metadataBytes != wantMetadata {
		t.Fatalf("snapshot metadata=%d want exact accounting=%d ok=%v", metadataBytes, wantMetadata, ok)
	}
}

func TestSnapshotGraphCorruptionFailsClosedAtStartup(t *testing.T) {
	seed := func(t *testing.T) (*Store, string, snapshotCreateResponse) {
		t.Helper()
		opened, path := openDataPlane(t)
		deviceID := "b8000000-0000-4000-8000-000000000001"
		token := tokenWithByte(0xb8)
		enrollDevice(t, opened, protocolFixtureTime, "b8000000-0000-4000-8000-000000000002", deviceID, "b8000000-0000-4000-8000-000000000003", token)
		var envelopeFixture struct {
			BaseMode putEnvelopeRequest `json:"base_mode"`
		}
		loadFixture(t, "vault-envelope.json", &envelopeFixture)
		envelopeBody, _ := marshalJSON(envelopeFixture.BaseMode)
		if _, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "PUT", Path: "/v1/vault-envelope", RequestID: "b8000000-0000-4000-8000-000000000004", Authorization: authorization(token), Body: envelopeBody, Now: protocolFixtureTime}); protocolErr != nil {
			opened.Close()
			t.Fatal(protocolErr)
		}
		revision := recordRevision{RecordID: "b8000000-0000-4000-8000-000000000005", RevisionID: "b8000000-0000-4000-8000-000000000006", AuthorDeviceID: deviceID,
			AuthorCounter: "1", VersionVector: []vectorEntry{{DeviceID: deviceID, Counter: "1"}}, PayloadSchema: "1", CryptoSuite: cryptoSuite,
			Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 24)), Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16))}
		syncMutation(t, opened, deviceID, token, "b8000000-0000-4000-8000-000000000007", revision, protocolFixtureTime)
		createID := "b8000000-0000-4000-8000-000000000008"
		createBody, _ := marshalJSON(snapshotCreateRequest{ProtocolVersion: "1", DeviceID: deviceID, RequestID: createID, RequiredCapabilities: append([]string(nil), requiredSnapshotCapabilities...)})
		response, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/snapshot-reads", RequestID: createID, Authorization: authorization(token), Body: createBody, Now: protocolFixtureTime})
		if protocolErr != nil {
			opened.Close()
			t.Fatal(protocolErr)
		}
		var created snapshotCreateResponse
		if err := json.Unmarshal(response.Body, &created); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		return opened, path, created
	}
	assertRejectedWithDetail := func(t *testing.T, opened *Store, path, detail string) {
		t.Helper()
		if err := opened.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(context.Background(), path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) || detail != "" && !strings.Contains(err.Error(), detail) {
			t.Fatalf("corrupt snapshot startup error = %v", err)
		}
	}
	assertRejected := func(t *testing.T, opened *Store, path string) {
		t.Helper()
		assertRejectedWithDetail(t, opened, path, "")
	}
	t.Run("metadata accounting", func(t *testing.T) {
		opened, path, created := seed(t)
		if _, err := opened.db.Exec("UPDATE snapshots SET metadata_bytes = metadata_bytes + 1 WHERE snapshot_id = ?", created.SnapshotID); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		assertRejected(t, opened, path)
	})
	t.Run("declared page budget", func(t *testing.T) {
		opened, path, created := seed(t)
		var ownerID, requestID string
		var createBody []byte
		if err := opened.db.QueryRow(`
			SELECT owner_device_id, request_id, create_response_json
			FROM snapshots WHERE snapshot_id = ?`, created.SnapshotID,
		).Scan(&ownerID, &requestID, &createBody); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		account := snapshotMetadataAccounting{}
		accountSnapshotBase(&account, created.SnapshotID, ownerID, requestID, createBody)
		if !account.ok() {
			opened.Close()
			t.Fatal("snapshot base accounting overflow")
		}
		if _, err := opened.db.Exec("UPDATE snapshots SET metadata_bytes = ? WHERE snapshot_id = ?", account.total, created.SnapshotID); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		assertRejected(t, opened, path)
	})
	t.Run("oversized create response", func(t *testing.T) {
		opened, path, created := seed(t)
		if _, err := opened.db.Exec(
			"UPDATE snapshots SET create_response_json = zeroblob(?) WHERE snapshot_id = ?",
			snapshotMetadataLimit+1, created.SnapshotID,
		); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		assertRejectedWithDetail(t, opened, path, "snapshot create response exceeds declared metadata")
	})
	t.Run("oversized page response", func(t *testing.T) {
		opened, path, created := seed(t)
		if _, err := opened.db.Exec(
			"UPDATE snapshot_pages SET response_json = zeroblob(?) WHERE snapshot_id = ? AND page_index = 0",
			snapshotMetadataLimit+1, created.SnapshotID,
		); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		assertRejectedWithDetail(t, opened, path, "snapshot page response exceeds declared metadata")
	})
	t.Run("page token chain", func(t *testing.T) {
		opened, path, created := seed(t)
		var body []byte
		if err := opened.db.QueryRow("SELECT response_json FROM snapshot_pages WHERE snapshot_id = ? AND page_index = 0", created.SnapshotID).Scan(&body); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		var descriptor snapshotPageDescriptor
		if err := decodeStoredSnapshotPageDescriptor(body, &descriptor); err != nil || !descriptor.HasMore {
			opened.Close()
			t.Fatalf("seed page descriptor: %+v error=%v", descriptor, err)
		}
		wrong := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xee}, 32))
		descriptor.NextPageToken = &wrong
		body, _ = marshalJSON(descriptor)
		if _, err := opened.db.Exec("UPDATE snapshot_pages SET response_json = ? WHERE snapshot_id = ? AND page_index = 0", body, created.SnapshotID); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		assertRejected(t, opened, path)
	})
	t.Run("orphan reference", func(t *testing.T) {
		opened, path, created := seed(t)
		if _, err := opened.db.Exec("UPDATE snapshot_revision_refs SET revision_id = ? WHERE snapshot_id = ?", "b8000000-0000-4000-8000-000000000099", created.SnapshotID); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		assertRejected(t, opened, path)
	})
}

func TestReconstructedFrontierRejectsTheThirtyThirdMemberImmediately(t *testing.T) {
	opened, path := openDataPlane(t)
	transaction, err := opened.db.Begin()
	if err != nil {
		opened.Close()
		t.Fatal(err)
	}
	defer transaction.Rollback()

	scopesJSON, err := json.Marshal(auth.FixedScopes())
	if err != nil {
		opened.Close()
		t.Fatal(err)
	}
	zero := EncodeUint64(0)
	one := EncodeUint64(1)
	recordID := "c3000000-0000-4000-8000-000000000001"
	for index := 0; index < 33; index++ {
		deviceID := fmt.Sprintf("c1000000-0000-4000-8000-%012x", index+1)
		revisionID := fmt.Sprintf("c2000000-0000-4000-8000-%012x", index+1)
		tokenHash := tokenWithByte(byte(index + 1))
		if _, err := transaction.Exec(`
			INSERT INTO devices (
				device_id, token_hash, scopes_json, created_at_ms,
				last_ack_cursor, max_author_counter
			) VALUES (?, ?, ?, ?, ?, ?)`,
			deviceID, tokenHash, string(scopesJSON), protocolFixtureTime.UnixMilli(), zero[:], one[:],
		); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		if _, err := transaction.Exec(
			"INSERT INTO device_origins (device_id, origin_kind, baseline_revoked) VALUES (?, 'baseline', 0)", deviceID,
		); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		if _, err := transaction.Exec(
			"INSERT INTO device_sync_state (device_id, max_returned_cursor) VALUES (?, ?)", deviceID, zero[:],
		); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		revision := recordRevision{
			RecordID: recordID, RevisionID: revisionID, AuthorDeviceID: deviceID,
			AuthorCounter: "1", VersionVector: []vectorEntry{{DeviceID: deviceID, Counter: "1"}},
			PayloadSchema: "1", CryptoSuite: cryptoSuite,
			Nonce:      base64.RawURLEncoding.EncodeToString(make([]byte, 24)),
			Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		}
		body, err := marshalJSON(revision)
		if err != nil {
			opened.Close()
			t.Fatal(err)
		}
		vectorBody, err := json.Marshal(revision.VersionVector)
		if err != nil {
			opened.Close()
			t.Fatal(err)
		}
		contentHash := sha256.Sum256(body)
		cursor := EncodeUint64(uint64(index + 1))
		if _, err := transaction.Exec(
			"INSERT INTO revision_objects (content_hash, revision_json) VALUES (?, ?)", contentHash[:], body,
		); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		if _, err := transaction.Exec(`
			INSERT INTO record_revisions (
				revision_id, record_id, author_device_id, author_counter,
				vector_json, collection_witness_authenticator, tombstone,
				content_hash, received_at_ms, accepted_uptime_ms,
				change_cursor, retained, undominated
			) VALUES (?, ?, ?, ?, ?, NULL, 0, ?, ?, ?, ?, 1, 0)`,
			revisionID, recordID, deviceID, one[:], vectorBody, contentHash[:],
			protocolFixtureTime.UnixMilli(), zero[:], cursor[:],
		); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		if _, err := transaction.Exec(`
			INSERT INTO change_origins (cursor, kind)
			VALUES (?, 'record_revision')`, cursor[:]); err != nil {
			opened.Close()
			t.Fatal(err)
		}
		if _, err := transaction.Exec(`
			INSERT INTO changes (cursor, kind, received_at_ms, record_revision_id)
			VALUES (?, 'record_revision', ?, ?)`, cursor[:], protocolFixtureTime.UnixMilli(), revisionID,
		); err != nil {
			opened.Close()
			t.Fatal(err)
		}
	}
	serverCursor := EncodeUint64(33)
	if _, err := transaction.Exec("UPDATE runtime_state SET server_cursor = ? WHERE singleton = 1", serverCursor[:]); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	if err := transaction.Commit(); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "too many reconstructed undominated revisions") {
		t.Fatalf("33-member frontier startup error = %v", err)
	}
}

func TestReconstructedFrontierUsesAcceptanceOrder(t *testing.T) {
	opened, path := openDataPlane(t)
	const recordID = "d8000000-0000-4000-8000-000000000001"
	tokens := make([][]byte, 33)
	deviceIDs := make([]string, 33)
	for index := range deviceIDs {
		deviceIDs[index] = fmt.Sprintf("d4000000-0000-4000-8000-%012x", index+1)
		tokens[index] = tokenWithByte(byte(index + 40))
		enrollDevice(
			t, opened, protocolFixtureTime.Add(time.Duration(index)*2*time.Minute),
			fmt.Sprintf("d9000000-0000-4000-8000-%012x", index+1),
			deviceIDs[index],
			fmt.Sprintf("da000000-0000-4000-8000-%012x", index+1),
			tokens[index],
		)
	}
	syncBaseTime := protocolFixtureTime.Add(70 * time.Minute)
	makeRevision := func(revisionID, authorID, authorCounter string, vector []vectorEntry) recordRevision {
		return recordRevision{
			RecordID: recordID, RevisionID: revisionID, AuthorDeviceID: authorID,
			AuthorCounter: authorCounter, VersionVector: vector,
			PayloadSchema: "1", CryptoSuite: cryptoSuite,
			Nonce:      base64.RawURLEncoding.EncodeToString(make([]byte, 24)),
			Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		}
	}
	for index := 0; index < 2; index++ {
		revision := makeRevision(
			fmt.Sprintf("d5000000-0000-4000-8000-%012x", index+1),
			deviceIDs[index], "1",
			[]vectorEntry{{DeviceID: deviceIDs[index], Counter: "1"}},
		)
		syncMutation(
			t, opened, deviceIDs[index], tokens[index],
			fmt.Sprintf("db000000-0000-4000-8000-%012x", index+1),
			revision, syncBaseTime.Add(time.Duration(index+1)*time.Millisecond),
		)
	}
	resolution := makeRevision(
		"d7000000-0000-4000-8000-000000000001", deviceIDs[0], "2",
		[]vectorEntry{
			{DeviceID: deviceIDs[0], Counter: "2"},
			{DeviceID: deviceIDs[1], Counter: "1"},
		},
	)
	syncMutation(
		t, opened, deviceIDs[0], tokens[0],
		"db000000-0000-4000-8000-000000000003",
		resolution, syncBaseTime.Add(3*time.Millisecond),
	)
	for index := 2; index < len(deviceIDs); index++ {
		revision := makeRevision(
			fmt.Sprintf("d6000000-0000-4000-8000-%012x", index-1),
			deviceIDs[index], "1",
			[]vectorEntry{{DeviceID: deviceIDs[index], Counter: "1"}},
		)
		syncMutation(
			t, opened, deviceIDs[index], tokens[index],
			fmt.Sprintf("dc000000-0000-4000-8000-%012x", index-1),
			revision, syncBaseTime.Add(time.Duration(index+2)*time.Millisecond),
		)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), path, testIdentity)
	if err != nil {
		t.Fatalf("valid acceptance-order frontier failed to reopen: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRolledBackUptimeCheckpointRetainsElapsedTime(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	checkpointStart := protocolFixtureTime
	checkpointEnd := checkpointStart.Add(time.Hour)
	opened.ephemeral.mu.Lock()
	opened.ephemeral.uptimeCheckpoint = checkpointStart
	opened.ephemeral.mu.Unlock()

	transaction, err := opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	accumulated, _, protocolErr := opened.checkpointUptimeTx(context.Background(), transaction, checkpointEnd)
	if protocolErr != nil || accumulated != uint64(time.Hour/time.Millisecond) {
		transaction.Rollback()
		t.Fatalf("tentative uptime checkpoint = %d error=%v", accumulated, protocolErr)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	opened.ephemeral.mu.Lock()
	checkpointAfterRollback := opened.ephemeral.uptimeCheckpoint
	opened.ephemeral.mu.Unlock()
	if !checkpointAfterRollback.Equal(checkpointStart) {
		t.Fatalf("rolled-back in-memory checkpoint = %v want %v", checkpointAfterRollback, checkpointStart)
	}
	if err := opened.CheckpointUptime(context.Background(), checkpointEnd); err != nil {
		t.Fatal(err)
	}
	var encoded []byte
	if err := opened.db.QueryRow("SELECT accumulated_uptime_ms FROM runtime_state WHERE singleton = 1").Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	durable, err := DecodeUint64(encoded)
	if err != nil || durable != uint64(time.Hour/time.Millisecond) {
		t.Fatalf("durable uptime after retry = %d error=%v", durable, err)
	}
}

func TestOversizedRevisionObjectFailsClosedBeforeBodyScan(t *testing.T) {
	opened, path := openDataPlane(t)
	deviceID := "de000000-0000-4000-8000-000000000001"
	token := tokenWithByte(0xde)
	enrollDevice(
		t, opened, protocolFixtureTime,
		"de000000-0000-4000-8000-000000000002",
		deviceID,
		"de000000-0000-4000-8000-000000000003",
		token,
	)
	revision := recordRevision{
		RecordID: "de000000-0000-4000-8000-000000000004", RevisionID: "de000000-0000-4000-8000-000000000005", AuthorDeviceID: deviceID,
		AuthorCounter: "1", VersionVector: []vectorEntry{{DeviceID: deviceID, Counter: "1"}},
		PayloadSchema: "1", CryptoSuite: cryptoSuite,
		Nonce:      base64.RawURLEncoding.EncodeToString(make([]byte, 24)),
		Ciphertext: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	syncMutation(t, opened, deviceID, token, "de000000-0000-4000-8000-000000000006", revision, protocolFixtureTime)
	if _, err := opened.db.Exec("UPDATE revision_objects SET revision_json = zeroblob(?)", maxBodyBytes+1); err != nil {
		opened.Close()
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) || !strings.Contains(err.Error(), "revision object exceeds body limit") {
		t.Fatalf("oversized revision startup error = %v", err)
	}
}

func TestOperationReceiptRetentionClassesAreIndependent(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	transaction, err := opened.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "b6000000-0000-4000-8000-000000000001"
	for index := 0; index < 8; index++ {
		operation := "sync"
		if index%2 != 0 {
			operation = "vault-envelope"
		}
		requestID := fmt.Sprintf("b6000000-0000-4000-8000-%012x", index+2)
		createdUptimeValue := uint64(0)
		if index < 2 {
			createdUptimeValue = uint64((24 * time.Hour) / time.Millisecond)
		}
		createdUptime := EncodeUint64(createdUptimeValue)
		result, err := transaction.Exec(`
			INSERT INTO operation_receipts (
				device_id, operation, request_id, request_fingerprint,
				response_status, response_json, created_at_ms, created_uptime_ms
			) VALUES (?, ?, ?, zeroblob(32), 200, ?, ?, ?)`, deviceID, operation, requestID, []byte("{}"), protocolFixtureTime.UnixMilli(), createdUptime[:])
		if err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
		sequence, err := result.LastInsertId()
		if err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
		receiptClass := "other"
		if operation == "sync" {
			receiptClass = "sync"
		}
		if _, err := transaction.Exec(`
			INSERT INTO operation_receipt_retention (
				device_id, receipt_class, receipt_sequence, created_uptime_ms
			) VALUES (?, ?, ?, ?)`, deviceID, receiptClass, sequence, createdUptime[:]); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
	}
	accumulated := uint64((31 * 24 * time.Hour) / time.Millisecond)
	if protocolErr := pruneOperationReceipts(context.Background(), transaction, deviceID, "sync", accumulated, 3, receiptMinimumUptime); protocolErr != nil {
		transaction.Rollback()
		t.Fatal(protocolErr)
	}
	var syncCount, otherCount int
	if err := transaction.QueryRow("SELECT count(*) FROM operation_receipts WHERE operation = 'sync'").Scan(&syncCount); err != nil {
		transaction.Rollback()
		t.Fatal(err)
	}
	if err := transaction.QueryRow("SELECT count(*) FROM operation_receipts WHERE operation <> 'sync'").Scan(&otherCount); err != nil {
		transaction.Rollback()
		t.Fatal(err)
	}
	if syncCount != 3 || otherCount != 4 {
		transaction.Rollback()
		t.Fatalf("after sync prune: sync=%d other=%d", syncCount, otherCount)
	}
	if protocolErr := pruneOperationReceipts(context.Background(), transaction, deviceID, "vault-envelope", accumulated, 3, receiptMinimumUptime); protocolErr != nil {
		transaction.Rollback()
		t.Fatal(protocolErr)
	}
	if err := transaction.QueryRow("SELECT count(*) FROM operation_receipts WHERE operation = 'sync'").Scan(&syncCount); err != nil {
		transaction.Rollback()
		t.Fatal(err)
	}
	if err := transaction.QueryRow("SELECT count(*) FROM operation_receipts WHERE operation <> 'sync'").Scan(&otherCount); err != nil {
		transaction.Rollback()
		t.Fatal(err)
	}
	if syncCount != 3 || otherCount != 3 {
		transaction.Rollback()
		t.Fatalf("after other prune: sync=%d other=%d", syncCount, otherCount)
	}
	var boundaryRows int
	if err := transaction.QueryRow(`
		SELECT count(*) FROM operation_receipts
		WHERE request_id IN (?, ?)`,
		"b6000000-0000-4000-8000-000000000002", "b6000000-0000-4000-8000-000000000003",
	).Scan(&boundaryRows); err != nil || boundaryRows != 0 {
		transaction.Rollback()
		t.Fatalf("age-boundary receipts retained=%d error=%v", boundaryRows, err)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
}

func TestOperationReceiptReplayRejectsStatusCanonicalAndSizeCorruption(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	deviceID := "b7000000-0000-4000-8000-000000000001"
	token := tokenWithByte(0xb7)
	enrollDevice(t, opened, protocolFixtureTime, "b7000000-0000-4000-8000-000000000002", deviceID, "b7000000-0000-4000-8000-000000000003", token)
	requestID := "b7000000-0000-4000-8000-000000000004"
	body, _ := marshalJSON(syncRequest{ProtocolVersion: "1", DeviceID: deviceID, RequestID: requestID, AfterCursor: "0", AckCursor: "0", Mutations: []recordRevision{}})
	call := api.Request{Method: "POST", Path: "/v1/sync", RequestID: requestID, Authorization: authorization(token), Body: body, Now: protocolFixtureTime}
	if response, protocolErr := opened.HandleAPI(context.Background(), call); protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("seed receipt: response=%+v error=%v", response, protocolErr)
	}
	var originalBody []byte
	if err := opened.db.QueryRow("SELECT response_json FROM operation_receipts WHERE device_id = ? AND operation = 'sync' AND request_id = ?", deviceID, requestID).Scan(&originalBody); err != nil {
		t.Fatal(err)
	}
	if _, err := opened.db.Exec("PRAGMA ignore_check_constraints = ON"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		status int
		body   []byte
	}{
		{name: "status", status: http.StatusCreated, body: originalBody},
		{name: "canonical body", status: http.StatusOK, body: append(append([]byte(nil), originalBody...), '\n')},
		{name: "body size", status: http.StatusOK, body: make([]byte, maxBodyBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := opened.db.Exec("UPDATE operation_receipts SET response_status = ?, response_json = ? WHERE device_id = ? AND operation = 'sync' AND request_id = ?", test.status, test.body, deviceID, requestID); err != nil {
				t.Fatal(err)
			}
			if _, protocolErr := opened.HandleAPI(context.Background(), call); protocolErr == nil || protocolErr.Code != "internal_error" {
				t.Fatalf("corrupt replay error = %v", protocolErr)
			}
		})
	}
}

func TestOpenRejectsMissingCounterHistoryAndInventedCursorFloor(t *testing.T) {
	t.Run("missing middle author counter", func(t *testing.T) {
		opened, path := openDataPlane(t)
		deviceID := "d1000000-0000-4000-8000-000000000001"
		token := tokenWithByte(0xd1)
		enrollDevice(t, opened, protocolFixtureTime,
			"d1000000-0000-4000-8000-000000000002",
			deviceID,
			"d1000000-0000-4000-8000-000000000003",
			token,
		)
		makeRevision := func(counter uint64) recordRevision {
			return recordRevision{
				RecordID:       "d1000000-0000-4000-8000-000000000004",
				RevisionID:     fmt.Sprintf("d1000000-0000-4000-8000-%012x", counter+4),
				AuthorDeviceID: deviceID,
				AuthorCounter:  encodeUint64Text(counter),
				VersionVector:  []vectorEntry{{DeviceID: deviceID, Counter: encodeUint64Text(counter)}},
				PayloadSchema:  "1",
				CryptoSuite:    cryptoSuite,
				Nonce:          base64.RawURLEncoding.EncodeToString(make([]byte, 24)),
				Ciphertext:     base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
			}
		}
		first := makeRevision(1)
		syncMutation(t, opened, deviceID, token, "d1000000-0000-4000-8000-000000000007", first, protocolFixtureTime)
		syncMutation(t, opened, deviceID, token, "d1000000-0000-4000-8000-000000000008", makeRevision(2), protocolFixtureTime)

		var contentHash []byte
		if err := opened.db.QueryRow("SELECT content_hash FROM record_revisions WHERE revision_id = ?", first.RevisionID).Scan(&contentHash); err != nil {
			t.Fatal(err)
		}
		transaction, err := opened.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range []string{
			"DELETE FROM changes WHERE record_revision_id = ?",
			"DELETE FROM collection_candidates WHERE revision_id = ?",
			"DELETE FROM record_vector_index WHERE revision_id = ?",
			"DELETE FROM record_revisions WHERE revision_id = ?",
		} {
			if _, err := transaction.Exec(statement, first.RevisionID); err != nil {
				transaction.Rollback()
				t.Fatal(err)
			}
		}
		if _, err := transaction.Exec("DELETE FROM revision_objects WHERE content_hash = ?", contentHash); err != nil {
			transaction.Rollback()
			t.Fatal(err)
		}
		if err := transaction.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := opened.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(context.Background(), path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) {
			t.Fatalf("missing counter history error = %v", err)
		}
	})

	t.Run("cursor floor without collected change", func(t *testing.T) {
		opened, path := openDataPlane(t)
		enrollDevice(t, opened, protocolFixtureTime,
			"d2000000-0000-4000-8000-000000000001",
			"d2000000-0000-4000-8000-000000000002",
			"d2000000-0000-4000-8000-000000000003",
			tokenWithByte(0xd2),
		)
		one := EncodeUint64(1)
		if _, err := opened.db.Exec("UPDATE runtime_state SET cursor_floor = ? WHERE singleton = 1", one[:]); err != nil {
			t.Fatal(err)
		}
		if err := opened.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(context.Background(), path, testIdentity); !errors.Is(err, ErrUnexpectedSchema) {
			t.Fatalf("invented cursor floor error = %v", err)
		}
	})
}

func syncMutation(t *testing.T, opened *Store, deviceID string, token []byte, requestID string, revision recordRevision, now time.Time) {
	t.Helper()
	body, _ := marshalJSON(syncRequest{ProtocolVersion: "1", DeviceID: deviceID, RequestID: requestID, AfterCursor: "0", AckCursor: "0", Mutations: []recordRevision{revision}})
	response, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/sync", RequestID: requestID, Authorization: authorization(token), Body: body, Now: now})
	if protocolErr != nil || response.Status != 200 {
		t.Fatalf("sync mutation %s: response=%+v error=%v", revision.RevisionID, response, protocolErr)
	}
}

func readAllSnapshotPages(t *testing.T, opened *Store, snapshot snapshotCreateResponse, deviceID string, token []byte, now time.Time) ([][]byte, []recordRevision, []sourceDevice) {
	t.Helper()
	pageToken := snapshot.FirstPageToken
	var bodies [][]byte
	var revisions []recordRevision
	var sources []sourceDevice
	for pageIndex := 0; ; pageIndex++ {
		body, _ := marshalJSON(snapshotPageRequest{ProtocolVersion: "1", DeviceID: deviceID, PageToken: pageToken})
		response, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/snapshot-reads/" + snapshot.SnapshotID + "/pages", RequestID: "10000000-0000-4000-8000-00000000000" + encodeUint64Text(uint64(pageIndex)), Authorization: authorization(token), Body: body, Now: now})
		if protocolErr != nil || response.Status != 200 {
			t.Fatalf("snapshot page %d: response=%+v error=%v", pageIndex, response, protocolErr)
		}
		bodies = append(bodies, append([]byte(nil), response.Body...))
		var page snapshotPageResponse
		if json.Unmarshal(response.Body, &page) != nil {
			t.Fatalf("decode snapshot page %d", pageIndex)
		}
		revisions = append(revisions, page.Revisions...)
		sources = append(sources, page.SourceDevices...)
		if !page.HasMore {
			break
		}
		if page.NextPageToken == nil {
			t.Fatal("snapshot page omitted next token")
		}
		pageToken = *page.NextPageToken
	}
	return bodies, revisions, sources
}

func revokeDevice(t *testing.T, opened *Store, target string, token []byte, allowZero bool, requestID string, now time.Time) {
	t.Helper()
	body, _ := marshalJSON(revokeDeviceRequest{RequestID: requestID, AllowZeroActive: allowZero})
	response, protocolErr := opened.HandleAPI(context.Background(), api.Request{Method: "POST", Path: "/v1/devices/" + target + "/revoke", RequestID: requestID, Authorization: authorization(token), Body: body, Now: now})
	if protocolErr != nil || response.Status != 200 {
		t.Fatalf("revoke %s: response=%+v error=%v", target, response, protocolErr)
	}
}

func loadFixture(t *testing.T, name string, destination any) {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "..", "..", "protocol", "v1", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, destination); err != nil {
		t.Fatal(err)
	}
}

func deepJSONEqual(t *testing.T, left, right any) bool {
	t.Helper()
	leftBody, _ := json.Marshal(left)
	rightBody, _ := json.Marshal(right)
	return bytes.Equal(leftBody, rightBody)
}

func pageBodiesEqual(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

func assertCredentialAbsentFromSQLite(t *testing.T, path string, credential []byte) {
	t.Helper()
	for _, suffix := range []string{"", "-wal", "-shm"} {
		payload, err := os.ReadFile(path + suffix)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if bytes.Contains(payload, credential) {
			t.Fatalf("plaintext credential present in %s", filepath.Base(path+suffix))
		}
	}
}
