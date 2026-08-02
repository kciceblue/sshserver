package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/api"
	"github.com/kciceblue/sshserver/runtime/internal/config"
)

type readyStub struct{ err error }

func (stub readyStub) Ready(context.Context) error { return stub.err }

type dataPlaneStub struct {
	request  api.Request
	response api.Response
	err      *api.Error
	calls    int
}

func (*dataPlaneStub) Ready(context.Context) error { return nil }

func (stub *dataPlaneStub) HandleAPI(_ context.Context, request api.Request) (api.Response, *api.Error) {
	stub.calls++
	stub.request = request
	return stub.response, stub.err
}

func testHandler(t *testing.T, readiness Readiness) *Handler {
	t.Helper()
	settings := config.Settings{
		ConfigVersion: config.ConfigVersion,
		InstanceID:    "00000000-0000-4000-8000-000000000001",
		VaultID:       "00000000-0000-4000-8000-000000000002",
		Listeners:     []string{"127.0.0.1:37421"},
	}
	handler, err := New(settings, readiness)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func validRequest(path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("JAT-Protocol-Version", "1")
	request.Header.Set("JAT-Request-ID", "00000000-0000-4000-8000-000000000003")
	return request
}

func TestHealthResponseIsBoundedAndReady(t *testing.T) {
	recorder := httptest.NewRecorder()
	testHandler(t, readyStub{}).ServeHTTP(recorder, validRequest("/v1/healthz"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("health response emitted CORS permission")
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 2 || body["status"] != "ok" || body["protocol_version"] != "1" {
		t.Fatalf("unexpected health body: %#v", body)
	}
}

func TestCapabilitiesAdvertiseNoUnimplementedFeature(t *testing.T) {
	recorder := httptest.NewRecorder()
	testHandler(t, readyStub{}).ServeHTTP(recorder, validRequest("/v1/capabilities"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Capabilities == nil || len(body.Capabilities) != 0 {
		t.Fatalf("unexpected capabilities: %#v", body.Capabilities)
	}
}

func TestDataPlaneCapabilitiesAndRawRequestTransport(t *testing.T) {
	dataPlane := &dataPlaneStub{response: api.Response{Status: http.StatusOK, Body: []byte(`{"devices":[]}`)}}
	recorder := httptest.NewRecorder()
	testHandler(t, dataPlane).ServeHTTP(recorder, validRequest("/v1/capabilities"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("capabilities status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var capabilities capabilitiesResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &capabilities); err != nil {
		t.Fatal(err)
	}
	wantCapabilities := []string{
		"authenticated-collection-frontiers-v2",
		"conflict-siblings-v1",
		"device-token-rotation-v1",
		"envelope-cas-v1",
		"snapshot-collection-markers-v1",
		"snapshot-device-registry-v1",
		"snapshot-read-v1",
		"tombstone-ack-v1",
	}
	if strings.Join(capabilities.Capabilities, "\n") != strings.Join(wantCapabilities, "\n") || capabilities.Limits.MaxBodyBytes != MaxBodyBytes {
		t.Fatalf("unexpected data-plane capabilities: %+v", capabilities)
	}

	rawBody := ` {"request_id":"00000000-0000-4000-8000-000000000003"} `
	request := httptest.NewRequest(http.MethodPost, "/v1/sync", strings.NewReader(rawBody))
	request.Header.Set("JAT-Protocol-Version", "1")
	request.Header.Set("JAT-Request-ID", "00000000-0000-4000-8000-000000000003")
	request.Header.Set("Authorization", "Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	recorder = httptest.NewRecorder()
	testHandler(t, dataPlane).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != `{"devices":[]}` {
		t.Fatalf("data-plane response=%d %s", recorder.Code, recorder.Body.String())
	}
	if dataPlane.calls != 1 || dataPlane.request.Path != "/v1/sync" || dataPlane.request.Method != http.MethodPost ||
		dataPlane.request.RequestID != "00000000-0000-4000-8000-000000000003" ||
		dataPlane.request.Authorization != "Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ||
		string(dataPlane.request.Body) != rawBody || dataPlane.request.Now.IsZero() {
		t.Fatalf("transport request = %+v calls=%d", dataPlane.request, dataPlane.calls)
	}
	for name, want := range map[string]string{
		"Content-Type":         "application/json; charset=utf-8",
		"Content-Length":       "14",
		"JAT-Protocol-Version": "1",
		"JAT-Request-ID":       "00000000-0000-4000-8000-000000000003",
	} {
		if got := recorder.Header().Get(name); got != want {
			t.Fatalf("%s=%q, want %q", name, got, want)
		}
	}
}

func TestDataPlaneBodyAuthorizationAndErrorsFailClosed(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
		authorize   bool
		wantStatus  int
		wantCode    string
	}{
		{name: "missing authorization", body: `{}`, contentType: "application/json; charset=utf-8", wantStatus: http.StatusUnauthorized, wantCode: "unauthorized"},
		{name: "wrong content type", body: `{}`, contentType: "application/json", authorize: true, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "oversize body", body: strings.Repeat("x", MaxBodyBytes+1), contentType: "application/json; charset=utf-8", authorize: true, wantStatus: http.StatusRequestEntityTooLarge, wantCode: "limit_exceeded"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dataPlane := &dataPlaneStub{response: api.Response{Status: http.StatusOK, Body: []byte(`{}`)}}
			request := httptest.NewRequest(http.MethodPost, "/v1/sync", strings.NewReader(test.body))
			request.Header.Set("JAT-Protocol-Version", "1")
			request.Header.Set("JAT-Request-ID", "00000000-0000-4000-8000-000000000003")
			request.Header.Set("Content-Type", test.contentType)
			if test.authorize {
				request.Header.Set("Authorization", "Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
			}
			recorder := httptest.NewRecorder()
			testHandler(t, dataPlane).ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus || !strings.Contains(recorder.Body.String(), `"code":"`+test.wantCode+`"`) || dataPlane.calls != 0 {
				t.Fatalf("response=%d %s calls=%d", recorder.Code, recorder.Body.String(), dataPlane.calls)
			}
		})
	}

	dataPlane := &dataPlaneStub{err: api.NewError("generation_conflict", true)}
	request := httptest.NewRequest(http.MethodPut, "/v1/vault-envelope", strings.NewReader(`{}`))
	request.Header.Set("JAT-Protocol-Version", "1")
	request.Header.Set("JAT-Request-ID", "00000000-0000-4000-8000-000000000003")
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("Authorization", "Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	recorder := httptest.NewRecorder()
	testHandler(t, dataPlane).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), `"code":"generation_conflict"`) || !strings.Contains(recorder.Body.String(), `"retryable":true`) {
		t.Fatalf("protocol error response=%d %s", recorder.Code, recorder.Body.String())
	}
}

func TestTransportAndHeaderValidationFailClosed(t *testing.T) {
	tests := map[string]func(*http.Request){
		"HTTP/1.0": func(request *http.Request) {
			request.Proto = "HTTP/1.0"
			request.ProtoMajor = 1
			request.ProtoMinor = 0
		},
		"origin":             func(request *http.Request) { request.Header["Origin"] = []string{""} },
		"upgrade":            func(request *http.Request) { request.Header.Set("Connection", "keep-alive, Upgrade") },
		"proxy":              func(request *http.Request) { request.Header.Set("Proxy-Connection", "keep-alive") },
		"missing protocol":   func(request *http.Request) { request.Header.Del("JAT-Protocol-Version") },
		"duplicate protocol": func(request *http.Request) { request.Header["Jat-Protocol-Version"] = []string{"1", "1"} },
		"duplicate request ID": func(request *http.Request) {
			request.Header["Jat-Request-Id"] = []string{
				"00000000-0000-4000-8000-000000000003",
				"00000000-0000-4000-8000-000000000003",
			}
		},
		"bad request ID":    func(request *http.Request) { request.Header.Set("JAT-Request-ID", "not-a-uuid") },
		"query":             func(request *http.Request) { request.URL.RawQuery = "debug=true" },
		"encoded path":      func(request *http.Request) { request.URL.RawPath = "/v1/%68ealthz" },
		"transfer encoding": func(request *http.Request) { request.TransferEncoding = []string{"chunked"} },
		"trailer": func(request *http.Request) {
			request.Trailer = http.Header{"X-Test": []string{"value"}}
		},
		"expect": func(request *http.Request) { request.Header.Set("Expect", "100-continue") },
		"TE":     func(request *http.Request) { request.Header.Set("TE", "trailers") },
		"body": func(request *http.Request) {
			request.Body = ioNopCloser{strings.NewReader("x")}
			request.ContentLength = 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := validRequest("/v1/healthz")
			mutate(request)
			recorder := httptest.NewRecorder()
			testHandler(t, readyStub{}).ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestUnsupportedProtocolAndReadinessErrorsAreStable(t *testing.T) {
	request := validRequest("/v1/healthz")
	request.Header.Set("JAT-Protocol-Version", "2")
	recorder := httptest.NewRecorder()
	testHandler(t, readyStub{}).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUpgradeRequired || !strings.Contains(recorder.Body.String(), "unsupported_protocol") {
		t.Fatalf("unexpected unsupported-protocol response: %d %s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	testHandler(t, readyStub{err: errors.New("database unavailable")}).ServeHTTP(recorder, validRequest("/v1/healthz"))
	if recorder.Code != http.StatusInternalServerError || strings.Contains(recorder.Body.String(), "database unavailable") {
		t.Fatalf("readiness detail leaked: %d %s", recorder.Code, recorder.Body.String())
	}
}

type ioNopCloser struct{ *strings.Reader }

func (ioNopCloser) Close() error { return nil }
