package deployment

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
)

func TestBuildIdentityParserAndPinnedComparison(t *testing.T) {
	layout := testLayout(t)
	expected := testInstalledRelease(t, layout, "v1.2.3", "a")
	identity := buildinfo.Identity{
		Release:         expected.Release,
		SourceRevision:  expected.SourceRevision,
		BuildToolchain:  expected.BuildToolchain,
		BuildIdentity:   expected.BuildIdentity,
		ProtocolVersion: expected.ProtocolVersion,
		StorageSchema:   expected.StorageSchema,
	}
	payload, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseIdentity(append(payload, '\n'))
	if err != nil {
		t.Fatal(err)
	}
	if parsed != identity {
		t.Fatalf("parsed identity = %+v", parsed)
	}
	if err := ValidateReleaseIdentity(parsed, expected); err != nil {
		t.Fatal(err)
	}
	parsed.BuildIdentity = strings.Repeat("f", 64)
	if err := ValidateReleaseIdentity(parsed, expected); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatch error = %v", err)
	}
}

func TestBuildIdentityParserRejectsUnboundedUnknownAndTrailingData(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload []byte
		want    string
	}{
		{name: "empty", payload: nil, want: "size boundary"},
		{name: "oversized", payload: make([]byte, maxIdentityBytes+1), want: "size boundary"},
		{name: "unknown", payload: []byte(`{"release":"v1","source_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","build_toolchain":"go1.25.0","build_identity":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","protocol_version":"1","storage_schema":"1","future":true}`), want: "unknown field"},
		{name: "trailing", payload: []byte(`{} {}`), want: "trailing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseIdentity(test.payload); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestBoundedIdentityBufferRetainsOnlyLimit(t *testing.T) {
	buffer := boundedBuffer{limit: 4}
	if written, err := buffer.Write([]byte("abcdef")); err != nil || written != 6 {
		t.Fatalf("write = %d, %v", written, err)
	}
	if string(buffer.Bytes()) != "abcd" || !buffer.exceeded {
		t.Fatalf("buffer=%q exceeded=%v", buffer.Bytes(), buffer.exceeded)
	}
}
