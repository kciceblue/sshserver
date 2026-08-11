package releaseid

import "testing"

func FuzzReleaseIdentifier(f *testing.F) {
	f.Add("v1.2.3")
	f.Fuzz(func(t *testing.T, value string) {
		first := Valid(value)
		second := Valid(value)
		if first != second {
			t.Fatal("release identifier acceptance changed across identical input")
		}
		if first && (len(value) == 0 || len(value) > maxBytes || !pattern.MatchString(value)) {
			t.Fatalf("accepted release identifier violates the published grammar: %q", value)
		}
	})
}
