package uuidv4

import "testing"

func FuzzParseUUIDv4(f *testing.F) {
	f.Add("00000000-0000-4000-8000-000000000001")
	f.Fuzz(func(t *testing.T, value string) {
		first, firstErr := Parse(value)
		second, secondErr := Parse(value)
		if (firstErr == nil) != (secondErr == nil) || first != second {
			t.Fatalf("UUID parser is nondeterministic: first=%x/%v second=%x/%v", first, firstErr, second, secondErr)
		}
		if firstErr == nil && Format(first) != value {
			t.Fatalf("accepted UUID did not canonically round trip: %q", value)
		}
	})
}
