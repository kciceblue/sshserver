package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/config"
)

type readyStub struct{ err error }

func (stub readyStub) Ready(context.Context) error { return stub.err }

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
