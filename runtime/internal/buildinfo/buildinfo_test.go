package buildinfo

import (
	"strings"
	"testing"
)

func TestEncodedReleaseIdentityRoundTripsAsOneExactRecord(t *testing.T) {
	identity := Identity{
		Release:         "v1.2.3",
		SourceRevision:  strings.Repeat("a", 40),
		BuildToolchain:  "go1.25.0",
		BuildIdentity:   strings.Repeat("b", 64),
		ProtocolVersion: "1",
		StorageSchema:   "1",
	}
	encoded, err := Encode(identity)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(encoded)
	if err != nil || parsed != identity {
		t.Fatalf("parsed=%+v err=%v", parsed, err)
	}
	for _, invalid := range []string{
		"", "dev|extra", strings.Replace(encoded, "v1.2.3", "latest", 1),
		strings.Replace(encoded, strings.Repeat("a", 40), strings.Repeat("A", 40), 1),
		encoded + "|future",
	} {
		if _, err := Parse(invalid); err == nil {
			t.Fatalf("invalid attestation accepted: %q", invalid)
		}
	}
}

func TestValidatedCurrentSupportsDevAndRejectsMalformedRelease(t *testing.T) {
	original := EncodedIdentity
	t.Cleanup(func() { EncodedIdentity = original })
	EncodedIdentity = "dev"
	if identity, err := ValidatedCurrent(); err != nil || identity.Release != "dev" {
		t.Fatalf("dev identity=%+v err=%v", identity, err)
	}
	EncodedIdentity = "jat-release-v1|broken"
	if _, err := ValidatedCurrent(); err == nil {
		t.Fatal("malformed linked identity accepted")
	}
}
