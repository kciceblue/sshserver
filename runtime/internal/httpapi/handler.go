// Package httpapi implements the bounded, loopback-only frozen V1 HTTP
// transport. Opaque persistence and authorization remain behind DataPlane.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/api"
	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/uuidv4"
)

const (
	MaxHeaderBytes = 16 * 1024
	MaxBodyBytes   = 4 * 1024 * 1024
)

type Readiness interface {
	Ready(context.Context) error
}

type Handler struct {
	settings  config.Settings
	readiness Readiness
	dataPlane api.DataPlane
}

type errorEnvelope struct {
	Error protocolError `json:"error"`
}

type protocolError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	RequestID string `json:"request_id"`
}

type capabilitiesResponse struct {
	InstanceID    string   `json:"instance_id"`
	VaultID       string   `json:"vault_id"`
	ProtocolMin   string   `json:"protocol_min"`
	ProtocolMax   string   `json:"protocol_max"`
	StorageSchema string   `json:"storage_schema"`
	CryptoSuites  []string `json:"crypto_suites"`
	Capabilities  []string `json:"capabilities"`
	Limits        limits   `json:"limits"`
}

type limits struct {
	MaxBodyBytes                              int `json:"max_body_bytes"`
	MaxMutations                              int `json:"max_mutations"`
	MaxPageChanges                            int `json:"max_page_changes"`
	MaxSnapshotPageRevisions                  int `json:"max_snapshot_page_revisions"`
	MaxSnapshotPageCollectionMarkers          int `json:"max_snapshot_page_collection_markers"`
	MaxSnapshotPageSourceDevices              int `json:"max_snapshot_page_source_devices"`
	MaxActiveSnapshotsPerDevice               int `json:"max_active_snapshots_per_device"`
	MaxActiveSnapshotsPerInstance             int `json:"max_active_snapshots_per_instance"`
	MaxSnapshotCreatesPerMinutePerDevice      int `json:"max_snapshot_creates_per_minute_per_device"`
	MaxActiveSnapshotMetadataBytesPerInstance int `json:"max_active_snapshot_metadata_bytes_per_instance"`
	MaxDevices                                int `json:"max_devices"`
}

func New(settings config.Settings, readiness Readiness) (*Handler, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if readiness == nil {
		return nil, errors.New("readiness provider is required")
	}
	handler := &Handler{settings: settings, readiness: readiness}
	if dataPlane, ok := readiness.(api.DataPlane); ok {
		handler.dataPlane = dataPlane
	}
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	requestID := RequestIDOrFallback(request.Header.Values("JAT-Request-ID"))
	if err := validateTransport(request); err != nil {
		handler.writeError(response, http.StatusBadRequest, "invalid_request", false, requestID)
		return
	}
	protocolValues := request.Header.Values("JAT-Protocol-Version")
	if len(protocolValues) != 1 || protocolValues[0] == "" {
		handler.writeError(response, http.StatusBadRequest, "invalid_request", false, requestID)
		return
	}
	if protocolValues[0] != config.ProtocolMajor {
		handler.writeError(response, http.StatusUpgradeRequired, "unsupported_protocol", false, requestID)
		return
	}
	requestIDValues := request.Header.Values("JAT-Request-ID")
	if len(requestIDValues) != 1 {
		handler.writeError(response, http.StatusBadRequest, "invalid_request", false, requestID)
		return
	}
	if _, err := uuidv4.Parse(requestIDValues[0]); err != nil {
		handler.writeError(response, http.StatusBadRequest, "invalid_request", false, requestID)
		return
	}
	requestID = requestIDValues[0]
	switch request.URL.Path {
	case "/v1/healthz":
		if request.Method != http.MethodGet || requireEmptyBody(response, request) != nil {
			handler.writeError(response, http.StatusBadRequest, "invalid_request", false, requestID)
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), 500*time.Millisecond)
		defer cancel()
		if err := handler.readiness.Ready(ctx); err != nil {
			handler.writeError(response, http.StatusInternalServerError, "internal_error", true, requestID)
			return
		}
		writeJSON(response, http.StatusOK, requestID, struct {
			Status          string `json:"status"`
			ProtocolVersion string `json:"protocol_version"`
		}{Status: "ok", ProtocolVersion: config.ProtocolMajor})
	case "/v1/capabilities":
		if request.Method != http.MethodGet || requireEmptyBody(response, request) != nil {
			handler.writeError(response, http.StatusBadRequest, "invalid_request", false, requestID)
			return
		}
		capabilities := []string{}
		if handler.dataPlane != nil {
			capabilities = []string{
				"authenticated-collection-frontiers-v2",
				"conflict-siblings-v1",
				"device-token-rotation-v1",
				"envelope-cas-v1",
				"snapshot-collection-markers-v1",
				"snapshot-device-registry-v1",
				"snapshot-read-v1",
				"tombstone-ack-v1",
			}
		}
		writeJSON(response, http.StatusOK, requestID, capabilitiesResponse{
			InstanceID:    handler.settings.InstanceID,
			VaultID:       handler.settings.VaultID,
			ProtocolMin:   config.ProtocolMajor,
			ProtocolMax:   config.ProtocolMajor,
			StorageSchema: config.StorageSchema,
			CryptoSuites:  []string{"jat-xchacha-hkdf-argon2id-draft2"},
			Capabilities:  capabilities,
			Limits: limits{
				MaxBodyBytes:                              MaxBodyBytes,
				MaxMutations:                              256,
				MaxPageChanges:                            128,
				MaxSnapshotPageRevisions:                  128,
				MaxSnapshotPageCollectionMarkers:          128,
				MaxSnapshotPageSourceDevices:              64,
				MaxActiveSnapshotsPerDevice:               1,
				MaxActiveSnapshotsPerInstance:             8,
				MaxSnapshotCreatesPerMinutePerDevice:      5,
				MaxActiveSnapshotMetadataBytesPerInstance: 64 * 1024 * 1024,
				MaxDevices:                                64,
			},
		})
	default:
		if handler.dataPlane == nil {
			handler.writeError(response, http.StatusBadRequest, "invalid_request", false, requestID)
			return
		}
		var body []byte
		if request.Method == http.MethodGet {
			if requireEmptyBody(response, request) != nil {
				handler.writeError(response, http.StatusBadRequest, "invalid_request", false, requestID)
				return
			}
		} else {
			var protocolErr *api.Error
			body, protocolErr = readJSONBody(response, request)
			if protocolErr != nil {
				handler.writeError(response, protocolErr.Status(), protocolErr.Code, protocolErr.Retryable, requestID)
				return
			}
		}
		authorizationValues := request.Header.Values("Authorization")
		if len(authorizationValues) != 1 {
			handler.writeError(response, http.StatusUnauthorized, "unauthorized", false, requestID)
			return
		}
		result, protocolErr := handler.dataPlane.HandleAPI(request.Context(), api.Request{
			Method:        request.Method,
			Path:          request.URL.Path,
			RequestID:     requestID,
			Authorization: authorizationValues[0],
			Body:          body,
			Now:           time.Now(),
		})
		if protocolErr != nil {
			handler.writeError(response, protocolErr.Status(), protocolErr.Code, protocolErr.Retryable, requestID)
			return
		}
		writeJSONBytes(response, result.Status, requestID, result.Body, result.Headers)
	}
}

func validateTransport(request *http.Request) error {
	if request.ProtoMajor != 1 || request.ProtoMinor != 1 {
		return errors.New("HTTP/1.1 is required")
	}
	if request.URL.IsAbs() || strings.HasPrefix(request.RequestURI, "http://") || strings.HasPrefix(request.RequestURI, "https://") {
		return errors.New("absolute-form request target is forbidden")
	}
	if request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.Fragment != "" || request.URL.RawPath != "" {
		return errors.New("query, fragment, and encoded paths are forbidden")
	}
	if request.Method == http.MethodConnect {
		return errors.New("CONNECT is forbidden")
	}
	if _, exists := request.Header[http.CanonicalHeaderKey("Origin")]; exists {
		return errors.New("Origin is forbidden")
	}
	if request.Header.Get("Upgrade") != "" || headerContainsToken(request.Header.Values("Connection"), "upgrade") {
		return errors.New("protocol upgrade is forbidden")
	}
	if request.Header.Get("Proxy-Connection") != "" {
		return errors.New("proxy mode is forbidden")
	}
	if len(request.TransferEncoding) != 0 || len(request.Trailer) != 0 || request.Header.Get("Expect") != "" || request.Header.Get("TE") != "" {
		return errors.New("streamed request framing is forbidden")
	}
	if request.ContentLength < 0 {
		return errors.New("request body length is invalid")
	}
	return nil
}

func headerContainsToken(values []string, token string) bool {
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(item), token) {
				return true
			}
		}
	}
	return false
}

func requireEmptyBody(response http.ResponseWriter, request *http.Request) error {
	if request.ContentLength != 0 {
		return errors.New("request body is forbidden")
	}
	if request.Body == nil {
		return nil
	}
	request.Body = http.MaxBytesReader(response, request.Body, MaxBodyBytes)
	defer request.Body.Close()
	var one [1]byte
	count, err := request.Body.Read(one[:])
	if count != 0 {
		return errors.New("request body is forbidden")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func readJSONBody(response http.ResponseWriter, request *http.Request) ([]byte, *api.Error) {
	if request.Method != http.MethodPost && request.Method != http.MethodPut {
		return nil, api.NewError("invalid_request", false)
	}
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 || contentTypes[0] != "application/json; charset=utf-8" {
		return nil, api.NewError("invalid_request", false)
	}
	if request.ContentLength <= 0 {
		return nil, api.NewError("invalid_request", false)
	}
	request.Body = http.MaxBytesReader(response, request.Body, MaxBodyBytes)
	defer request.Body.Close()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			return nil, api.NewError("limit_exceeded", false)
		}
		return nil, api.NewError("invalid_request", false)
	}
	if len(body) == 0 {
		return nil, api.NewError("invalid_request", false)
	}
	return body, nil
}

// RequestIDOrFallback returns the sole canonical V4 request ID, or a fresh
// identifier when the request cannot safely supply one. The server's bounded
// request-head reader also uses this helper before net/http parses the request.
func RequestIDOrFallback(values []string) string {
	if len(values) == 1 {
		if _, err := uuidv4.Parse(values[0]); err == nil {
			return values[0]
		}
	}
	generated, err := uuidv4.New()
	if err == nil {
		return generated
	}
	return "00000000-0000-4000-8000-000000000000"
}

func (handler *Handler) writeError(response http.ResponseWriter, status int, code string, retryable bool, requestID string) {
	writeProtocolError(response, status, code, retryable, requestID)
}

func writeProtocolError(response http.ResponseWriter, status int, code string, retryable bool, requestID string) {
	protocolErr := api.NewError(code, retryable)
	writeJSON(response, status, requestID, errorEnvelope{Error: protocolError{
		Code:      code,
		Message:   protocolErr.Message(),
		Retryable: retryable,
		RequestID: requestID,
	}})
}

// WriteLimitExceeded emits the V1 error contract for a request rejected by a
// transport limit before the regular HTTP handler can validate it.
func WriteLimitExceeded(response http.ResponseWriter, requestID string) {
	writeProtocolError(response, http.StatusRequestEntityTooLarge, "limit_exceeded", false, requestID)
}

func writeJSON(response http.ResponseWriter, status int, requestID string, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		writeJSONBytes(response, http.StatusInternalServerError, requestID, []byte(`{"error":{"code":"internal_error","message":"The service could not complete the request.","retryable":true,"request_id":"`+requestID+`"}}`))
		return
	}
	writeJSONBytes(response, status, requestID, body)
}

func writeJSONBytes(response http.ResponseWriter, status int, requestID string, body []byte, retainedHeaders ...[]api.Header) {
	if len(retainedHeaders) == 1 && slices.Equal(retainedHeaders[0], api.V1ResponseHeaders(requestID, len(body))) &&
		writeRetainedHTTPResponse(response, status, body, retainedHeaders[0]) {
		return
	}
	// V1 self-revocation receipts require a byte-equivalent HTTP replay. Keep
	// every response header deterministic and suppress net/http's wall-clock
	// Date injection; the body already carries any informational timestamps.
	response.Header()["Date"] = nil
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	headers := api.V1ResponseHeaders(requestID, len(body))
	for _, header := range headers {
		response.Header().Set(header.Name, header.Value)
	}
	response.WriteHeader(status)
	_, _ = response.Write(body)
}

func writeRetainedHTTPResponse(response http.ResponseWriter, status int, body []byte, headers []api.Header) bool {
	hijacker, ok := response.(http.Hijacker)
	if !ok {
		return false
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		return false
	}
	defer connection.Close()
	if _, err := fmt.Fprintf(buffered, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status)); err != nil {
		return true
	}
	for _, header := range headers {
		if _, err := fmt.Fprintf(buffered, "%s: %s\r\n", header.Name, header.Value); err != nil {
			return true
		}
	}
	if _, err := buffered.WriteString("\r\n"); err != nil {
		return true
	}
	if _, err := buffered.Write(body); err != nil {
		return true
	}
	_ = buffered.Flush()
	return true
}
