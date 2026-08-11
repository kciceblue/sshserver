package server

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/deployment"
)

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
