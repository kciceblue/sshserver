package server

import (
	"bytes"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/deployment"
	"github.com/kciceblue/sshserver/runtime/internal/httpapi"
	"github.com/kciceblue/sshserver/runtime/internal/uuidv4"
)

type requestHeadFuzzConn struct {
	*bytes.Reader
}

func (connection *requestHeadFuzzConn) Write(payload []byte) (int, error) {
	return len(payload), nil
}
func (connection *requestHeadFuzzConn) Close() error                     { return nil }
func (connection *requestHeadFuzzConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (connection *requestHeadFuzzConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (connection *requestHeadFuzzConn) SetDeadline(time.Time) error      { return nil }
func (connection *requestHeadFuzzConn) SetReadDeadline(time.Time) error  { return nil }
func (connection *requestHeadFuzzConn) SetWriteDeadline(time.Time) error { return nil }

func FuzzDecodeAdminRequest(f *testing.F) {
	direct, err := EncodeEnrollmentCreateRequest(nil)
	if err != nil {
		f.Fatal(err)
	}
	managed, err := EncodeEnrollmentCreateRequest(&deployment.ActiveExecutableBinding{
		Generation:   2,
		BinaryPath:   "/home/alice/deployment/versions/v1.2.3/sshserver-linux-amd64",
		BinarySHA256: strings.Repeat("a", 64),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(direct)
	f.Add(managed)

	f.Fuzz(func(t *testing.T, payload []byte) {
		parsed, err := decodeAdminRequest(payload)
		if err != nil {
			return
		}
		canonical, err := encodeAdminRequest(parsed)
		if err != nil {
			t.Fatalf("accepted admin request cannot be re-encoded: %v", err)
		}
		if !bytes.Equal(payload, canonical) {
			t.Fatal("accepted admin request changed across canonical re-encoding")
		}
		reparsed, err := decodeAdminRequest(canonical)
		if err != nil || !reflect.DeepEqual(reparsed, parsed) {
			t.Fatalf("accepted admin request does not round trip: parsed=%+v reparsed=%+v error=%v", parsed, reparsed, err)
		}
	})
}

func FuzzHTTP1RequestHead(f *testing.F) {
	const retainedRequestID = "123e4567-e89b-42d3-a456-426614174000"
	f.Add([]byte("GET /v1/health HTTP/1.1\r\nHost: localhost\r\nJAT-Request-ID: 0123456789abcdef0123456789abcdef\r\n\r\n"))
	f.Add(bytes.Repeat([]byte("A"), httpapi.MaxHeaderBytes+1))
	oversizedWithRequestID := []byte("GET /v1/health HTTP/1.1\r\nHost: localhost\r\nJAT-Request-ID: " + retainedRequestID + "\r\nX-Fill: ")
	oversizedWithRequestID = append(oversizedWithRequestID, bytes.Repeat([]byte("A"), httpapi.MaxHeaderBytes)...)
	oversizedWithRequestID = append(oversizedWithRequestID, []byte("\r\n\r\n")...)
	f.Add(oversizedWithRequestID)

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > httpapi.MaxHeaderBytes+4096 {
			return
		}
		firstIDs := requestIDValues(payload)
		secondIDs := requestIDValues(payload)
		if !reflect.DeepEqual(firstIDs, secondIDs) {
			t.Fatal("request-ID header parsing changed across identical input")
		}

		first := &headerLimitConn{
			Conn:     &requestHeadFuzzConn{Reader: bytes.NewReader(payload)},
			maxBytes: httpapi.MaxHeaderBytes,
		}
		second := &headerLimitConn{
			Conn:     &requestHeadFuzzConn{Reader: bytes.NewReader(payload)},
			maxBytes: httpapi.MaxHeaderBytes,
		}
		firstOutput, firstErr := io.ReadAll(first)
		secondOutput, secondErr := io.ReadAll(second)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatal("request-head limit acceptance changed across identical input")
		}
		if firstErr != nil && firstErr.Error() != secondErr.Error() {
			t.Fatal("request-head limit error changed across identical input")
		}
		if !bytes.Equal(firstOutput, secondOutput) || first.limit.exceeded != second.limit.exceeded {
			t.Fatal("request-head limit output changed across identical input")
		}
		for _, limit := range []headerLimitState{first.limit, second.limit} {
			if !limit.exceeded {
				if limit.requestID != "" {
					t.Fatal("non-limited request unexpectedly retained a request ID")
				}
				continue
			}
			if _, err := uuidv4.Parse(limit.requestID); err != nil {
				t.Fatal("limited request did not retain or generate a canonical request ID")
			}
			if len(firstIDs) == 1 {
				if _, err := uuidv4.Parse(firstIDs[0]); err == nil && limit.requestID != firstIDs[0] {
					t.Fatalf("limited request discarded canonical request ID: got %q want %q", limit.requestID, firstIDs[0])
				}
			}
		}
	})
}
