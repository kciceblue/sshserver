// Package httpapi implements the bounded, loopback-only Task 2.1 HTTP
// surface. It intentionally exposes only health and honest capability data.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

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
	return &Handler{settings: settings, readiness: readiness}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	requestID := requestIDOrFallback(request.Header.Values("JAT-Request-ID"))
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
	if request.Method != http.MethodGet {
		handler.writeError(response, http.StatusBadRequest, "invalid_request", false, requestID)
		return
	}
	if err := requireEmptyBody(response, request); err != nil {
		handler.writeError(response, http.StatusBadRequest, "invalid_request", false, requestID)
		return
	}

	switch request.URL.Path {
	case "/v1/healthz":
		ctx, cancel := context.WithTimeout(request.Context(), 500*time.Millisecond)
		defer cancel()
		if err := handler.readiness.Ready(ctx); err != nil {
			handler.writeError(response, http.StatusInternalServerError, "internal_error", true, requestID)
			return
		}
		writeJSON(response, http.StatusOK, struct {
			Status          string `json:"status"`
			ProtocolVersion string `json:"protocol_version"`
		}{Status: "ok", ProtocolVersion: config.ProtocolMajor})
	case "/v1/capabilities":
		writeJSON(response, http.StatusOK, capabilitiesResponse{
			InstanceID:    handler.settings.InstanceID,
			VaultID:       handler.settings.VaultID,
			ProtocolMin:   config.ProtocolMajor,
			ProtocolMax:   config.ProtocolMajor,
			StorageSchema: config.StorageSchema,
			CryptoSuites:  []string{"jat-xchacha-hkdf-argon2id-draft2"},
			Capabilities:  []string{},
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
		handler.writeError(response, http.StatusBadRequest, "invalid_request", false, requestID)
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
	contentLengthValues := request.Header.Values("Content-Length")
	if len(contentLengthValues) > 1 || (len(contentLengthValues) == 1 && strings.TrimSpace(contentLengthValues[0]) != "0") || request.ContentLength != 0 {
		return errors.New("request body framing is forbidden")
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

func requestIDOrFallback(values []string) string {
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
	messages := map[string]string{
		"invalid_request":      "The request did not match protocol version 1.",
		"unsupported_protocol": "The requested protocol version is not supported.",
		"internal_error":       "The service could not complete the request.",
	}
	writeJSON(response, status, errorEnvelope{Error: protocolError{
		Code:      code,
		Message:   messages[code],
		Retryable: retryable,
		RequestID: requestID,
	}})
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
