package store

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
)

func revocationCall(t *testing.T, deviceID, requestID string, token []byte, allowZero bool, now time.Time) api.Request {
	t.Helper()
	body, err := marshalJSON(revokeDeviceRequest{RequestID: requestID, AllowZeroActive: allowZero})
	if err != nil {
		t.Fatal(err)
	}
	return api.Request{
		Method:        "POST",
		Path:          "/v1/devices/" + deviceID + "/revoke",
		RequestID:     requestID,
		Authorization: authorization(token),
		Body:          body,
		Now:           now,
	}
}

func TestActiveManagerGetsStableNoOpForSelfRevokedTarget(t *testing.T) {
	opened, _ := openDataPlane(t)
	defer opened.Close()
	managerID := "f7590000-0000-4000-8000-000000000001"
	targetID := "f7590000-0000-4000-8000-000000000002"
	otherID := "f7590000-0000-4000-8000-000000000003"
	managerToken := tokenWithByte(0x91)
	targetToken := tokenWithByte(0x92)
	otherToken := tokenWithByte(0x93)
	enrollDevice(t, opened, protocolFixtureTime,
		"f7590000-0000-4000-8000-000000000004", managerID,
		"f7590000-0000-4000-8000-000000000005", managerToken)
	enrollDevice(t, opened, protocolFixtureTime,
		"f7590000-0000-4000-8000-000000000006", targetID,
		"f7590000-0000-4000-8000-000000000007", targetToken)
	enrollDevice(t, opened, protocolFixtureTime,
		"f7590000-0000-4000-8000-000000000008", otherID,
		"f7590000-0000-4000-8000-000000000009", otherToken)

	otherCall := revocationCall(t, otherID,
		"f7590000-0000-4000-8000-00000000000a", managerToken, false,
		protocolFixtureTime.Add(time.Second))
	if response, protocolErr := opened.HandleAPI(context.Background(), otherCall); protocolErr != nil || response.Status != http.StatusOK {
		t.Fatalf("revoke unrelated device: response=%+v error=%v", response, protocolErr)
	}

	selfCall := revocationCall(t, targetID,
		"f7590000-0000-4000-8000-00000000000b", targetToken, false,
		protocolFixtureTime.Add(2*time.Second))
	selfResponse, protocolErr := opened.HandleAPI(context.Background(), selfCall)
	if protocolErr != nil || selfResponse.Status != http.StatusOK || len(selfResponse.Headers) == 0 {
		t.Fatalf("self revoke target: response=%+v error=%v", selfResponse, protocolErr)
	}

	var cursorBefore []byte
	var changesBefore, operationReceiptsBefore, selfReceiptsBefore int
	if err := opened.db.QueryRow("SELECT server_cursor FROM runtime_state WHERE singleton = 1").Scan(&cursorBefore); err != nil {
		t.Fatal(err)
	}
	if err := opened.db.QueryRow("SELECT count(*) FROM changes").Scan(&changesBefore); err != nil {
		t.Fatal(err)
	}
	if err := opened.db.QueryRow("SELECT count(*) FROM operation_receipts").Scan(&operationReceiptsBefore); err != nil {
		t.Fatal(err)
	}
	if err := opened.db.QueryRow("SELECT count(*) FROM self_revocation_receipts").Scan(&selfReceiptsBefore); err != nil {
		t.Fatal(err)
	}

	managerCall := revocationCall(t, targetID,
		"f7590000-0000-4000-8000-00000000000c", managerToken, false,
		protocolFixtureTime.Add(3*time.Second))
	managerResponse, protocolErr := opened.HandleAPI(context.Background(), managerCall)
	if protocolErr != nil || managerResponse.Status != http.StatusOK {
		t.Fatalf("manager no-op for self-revoked target: response=%+v error=%v", managerResponse, protocolErr)
	}
	if !bytes.Equal(managerResponse.Body, selfResponse.Body) {
		t.Fatalf("manager no-op body differs from target state: manager=%s self=%s", managerResponse.Body, selfResponse.Body)
	}
	var cursorAfter []byte
	var changesAfter, operationReceiptsAfter, selfReceiptsAfter int
	if err := opened.db.QueryRow("SELECT server_cursor FROM runtime_state WHERE singleton = 1").Scan(&cursorAfter); err != nil {
		t.Fatal(err)
	}
	if err := opened.db.QueryRow("SELECT count(*) FROM changes").Scan(&changesAfter); err != nil {
		t.Fatal(err)
	}
	if err := opened.db.QueryRow("SELECT count(*) FROM operation_receipts").Scan(&operationReceiptsAfter); err != nil {
		t.Fatal(err)
	}
	if err := opened.db.QueryRow("SELECT count(*) FROM self_revocation_receipts").Scan(&selfReceiptsAfter); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cursorBefore, cursorAfter) || changesAfter != changesBefore ||
		operationReceiptsAfter != operationReceiptsBefore+1 || selfReceiptsAfter != selfReceiptsBefore {
		t.Fatalf("manager no-op state: cursor=%x/%x changes=%d/%d operation_receipts=%d/%d self_receipts=%d/%d",
			cursorBefore, cursorAfter, changesBefore, changesAfter,
			operationReceiptsBefore, operationReceiptsAfter, selfReceiptsBefore, selfReceiptsAfter)
	}

	stable := markerKeyDurableDigest(t, opened.db)
	if replay, protocolErr := opened.HandleAPI(context.Background(), managerCall); protocolErr != nil ||
		replay.Status != managerResponse.Status || !bytes.Equal(replay.Body, managerResponse.Body) {
		t.Fatalf("manager no-op replay: response=%+v error=%v", replay, protocolErr)
	}
	if after := markerKeyDurableDigest(t, opened.db); after != stable {
		t.Fatalf("manager replay mutated state: before=%x after=%x", stable, after)
	}

	reused := managerCall
	reused.Body = append(append([]byte(nil), reused.Body...), '\n')
	if _, protocolErr := opened.HandleAPI(context.Background(), reused); protocolErr == nil || protocolErr.Code != "request_id_reused" {
		t.Fatalf("manager no-op request reuse error=%v", protocolErr)
	}
	if after := markerKeyDurableDigest(t, opened.db); after != stable {
		t.Fatalf("manager reuse rejection mutated state: before=%x after=%x", stable, after)
	}

	if replay, protocolErr := opened.HandleAPI(context.Background(), selfCall); protocolErr != nil ||
		replay.Status != selfResponse.Status || !bytes.Equal(replay.Body, selfResponse.Body) ||
		!headersEqual(replay.Headers, selfResponse.Headers) {
		t.Fatalf("retired self bearer replay: response=%+v error=%v", replay, protocolErr)
	}
	retiredMismatch := selfCall
	retiredMismatch.RequestID = "f7590000-0000-4000-8000-00000000000d"
	retiredMismatch.Body = revocationCall(t, targetID, retiredMismatch.RequestID, targetToken, false, retiredMismatch.Now).Body
	if _, protocolErr := opened.HandleAPI(context.Background(), retiredMismatch); protocolErr == nil || protocolErr.Code != "token_revoked" {
		t.Fatalf("retired self bearer mismatch error=%v", protocolErr)
	}

	invalidCredential := revocationCall(t, targetID,
		"f7590000-0000-4000-8000-00000000000e", tokenWithByte(0xee), false,
		protocolFixtureTime.Add(4*time.Second))
	if _, protocolErr := opened.HandleAPI(context.Background(), invalidCredential); protocolErr == nil || protocolErr.Code != "unauthorized" {
		t.Fatalf("unrelated invalid credential error=%v", protocolErr)
	}
	revokedCredential := revocationCall(t, targetID,
		"f7590000-0000-4000-8000-00000000000f", otherToken, false,
		protocolFixtureTime.Add(4*time.Second))
	if _, protocolErr := opened.HandleAPI(context.Background(), revokedCredential); protocolErr == nil || protocolErr.Code != "token_revoked" {
		t.Fatalf("unrelated revoked credential error=%v", protocolErr)
	}
	invalidRequest := managerCall
	invalidRequest.RequestID = "f7590000-0000-4000-8000-000000000010"
	invalidRequest.Body = []byte("{}")
	if _, protocolErr := opened.HandleAPI(context.Background(), invalidRequest); protocolErr == nil || protocolErr.Code != "invalid_request" {
		t.Fatalf("active manager invalid request error=%v", protocolErr)
	}
	if after := markerKeyDurableDigest(t, opened.db); after != stable {
		t.Fatalf("credential/order rejections mutated state: before=%x after=%x", stable, after)
	}
}

func headersEqual(left, right []api.Header) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
