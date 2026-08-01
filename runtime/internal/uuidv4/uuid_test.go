package uuidv4

import "testing"

func TestNewRoundTripsCanonicalUUIDv4(t *testing.T) {
	for range 32 {
		value, err := New()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Parse(value)
		if err != nil {
			t.Fatalf("Parse(%q): %v", value, err)
		}
		if Format(decoded) != value {
			t.Fatalf("round trip changed %q", value)
		}
	}
}

func TestParseRejectsNonCanonicalOrNonV4Values(t *testing.T) {
	for _, value := range []string{
		"",
		"00000000-0000-0000-0000-000000000000",
		"00000000-0000-4000-7000-000000000000",
		"00000000-0000-4000-8000-00000000000G",
		"00000000-0000-4000-8000-00000000000A",
		"00000000000040008000000000000000",
	} {
		if _, err := Parse(value); err == nil {
			t.Fatalf("Parse(%q) unexpectedly succeeded", value)
		}
	}
}
