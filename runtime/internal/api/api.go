// Package api defines the small boundary between the HTTP transport and the
// persistent V1 data plane. It deliberately contains no vault cryptography.
package api

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

type Request struct {
	Method        string
	Path          string
	RequestID     string
	Authorization string
	Body          []byte
	Now           time.Time
}

type Response struct {
	Status  int
	Body    []byte
	Headers []Header
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// V1ResponseHeaders is the frozen ordered application header artifact. The
// transport suppresses dynamic headers so an exact self-revocation receipt can
// replay these bytes for the lifetime of the retired row.
func V1ResponseHeaders(requestID string, bodyLength int) []Header {
	return []Header{
		{Name: "Content-Type", Value: "application/json; charset=utf-8"},
		{Name: "JAT-Protocol-Version", Value: "1"},
		{Name: "JAT-Request-ID", Value: requestID},
		{Name: "Content-Length", Value: strconv.Itoa(bodyLength)},
	}
}

type DataPlane interface {
	HandleAPI(context.Context, Request) (Response, *Error)
}

type Error struct {
	Code      string
	Retryable bool
}

func NewError(code string, retryable bool) *Error {
	return &Error{Code: code, Retryable: retryable}
}

func (err *Error) Error() string { return err.Code }

func (err *Error) Status() int {
	if status, ok := errorStatuses[err.Code]; ok {
		return status
	}
	return http.StatusInternalServerError
}

func (err *Error) Message() string {
	if message, ok := errorMessages[err.Code]; ok {
		return message
	}
	return errorMessages["internal_error"]
}

var errorStatuses = map[string]int{
	"invalid_request":                   http.StatusBadRequest,
	"unsupported_protocol":              http.StatusUpgradeRequired,
	"unsupported_capability":            http.StatusUpgradeRequired,
	"unauthorized":                      http.StatusUnauthorized,
	"token_revoked":                     http.StatusUnauthorized,
	"scope_denied":                      http.StatusForbidden,
	"authenticated_device_mismatch":     http.StatusForbidden,
	"rate_limited":                      http.StatusTooManyRequests,
	"grant_expired":                     http.StatusGone,
	"grant_consumed":                    http.StatusGone,
	"enrollment_replay_mismatch":        http.StatusConflict,
	"request_id_reused":                 http.StatusConflict,
	"generation_conflict":               http.StatusConflict,
	"generation_exhausted":              http.StatusConflict,
	"counter_conflict":                  http.StatusConflict,
	"counter_exhausted":                 http.StatusConflict,
	"revision_equivocation":             http.StatusConflict,
	"too_many_siblings":                 http.StatusConflict,
	"limit_exceeded":                    http.StatusRequestEntityTooLarge,
	"cursor_expired":                    http.StatusGone,
	"envelope_missing":                  http.StatusNotFound,
	"device_not_found":                  http.StatusNotFound,
	"snapshot_not_found":                http.StatusNotFound,
	"snapshot_expired":                  http.StatusGone,
	"stale_after_collection":            http.StatusConflict,
	"zero_active_confirmation_required": http.StatusConflict,
	"instance_mismatch":                 http.StatusConflict,
	"server_cursor_exhausted":           http.StatusInsufficientStorage,
	"internal_error":                    http.StatusInternalServerError,
}

var errorMessages = map[string]string{
	"invalid_request":                   "The request did not match protocol version 1.",
	"unsupported_protocol":              "The requested protocol version is not supported.",
	"unsupported_capability":            "A required protocol capability is unavailable.",
	"unauthorized":                      "The supplied credential was not accepted.",
	"token_revoked":                     "The device token has been revoked.",
	"scope_denied":                      "The device token lacks the required scope.",
	"authenticated_device_mismatch":     "The request device does not match the authenticated device.",
	"rate_limited":                      "The operation exceeded its rate limit.",
	"grant_expired":                     "The enrollment grant has expired.",
	"grant_consumed":                    "The enrollment grant has already been consumed.",
	"enrollment_replay_mismatch":        "The enrollment retry did not match the recorded enrollment.",
	"request_id_reused":                 "The request identifier was reused with different bytes.",
	"generation_conflict":               "The requested generation does not match the stored generation.",
	"generation_exhausted":              "The generation has no valid successor.",
	"counter_conflict":                  "The author counter did not advance exactly once.",
	"counter_exhausted":                 "The author counter has no valid successor.",
	"revision_equivocation":             "A revision identifier or vector was reused with different bytes.",
	"too_many_siblings":                 "The record has too many undominated siblings.",
	"limit_exceeded":                    "The request exceeded a protocol limit.",
	"cursor_expired":                    "The requested cursor is no longer retained.",
	"envelope_missing":                  "The vault envelope is unavailable.",
	"device_not_found":                  "The requested device does not exist.",
	"snapshot_not_found":                "The requested snapshot does not exist.",
	"snapshot_expired":                  "The requested snapshot has expired.",
	"stale_after_collection":            "The mutation does not dominate the retained collection frontier.",
	"zero_active_confirmation_required": "Revoking the last active device requires explicit confirmation.",
	"instance_mismatch":                 "The request identity does not match this server instance.",
	"server_cursor_exhausted":           "The server change cursor has no remaining capacity.",
	"internal_error":                    "The service could not complete the request.",
}
