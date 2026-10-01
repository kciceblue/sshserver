package buildinfo

import (
	"strings"
	"testing"
)

func FuzzParseAttestation(f *testing.F) {
	identity := Identity{
		Release: "v1.2.3", SourceRevision: strings.Repeat("a", 40),
		BuildToolchain: "go1.25.0", BuildIdentity: strings.Repeat("b", 64),
		ProtocolVersion: "1", StorageSchema: "1",
	}
	seed, err := Encode(identity)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, value string) {
		first, firstErr := Parse(value)
		second, secondErr := Parse(value)
		if (firstErr == nil) != (secondErr == nil) || first != second {
			t.Fatalf("attestation parser is nondeterministic: first=%+v/%v second=%+v/%v", first, firstErr, second, secondErr)
		}
		if firstErr == nil {
			encoded, err := Encode(first)
			if err != nil || encoded != value {
				t.Fatalf("accepted attestation did not canonically round trip: encoded=%q error=%v", encoded, err)
			}
		}
	})
}
