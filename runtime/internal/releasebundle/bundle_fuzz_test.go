//go:build darwin || linux

package releasebundle

import (
	"strings"
	"testing"
	"time"
)

func FuzzValidLocalMainVersion(f *testing.F) {
	revision := strings.Repeat("a", 40)
	accepted := []struct {
		version  string
		revision string
		vcsTime  string
	}{
		{version: "", revision: revision},
		{version: "(devel)", revision: revision},
		{
			version:  "v0.0.0-20260803123456-aaaaaaaaaaaa",
			revision: revision,
			vcsTime:  "2026-08-03T12:34:56Z",
		},
		{
			version:  "v1.2.4-0.20260803123456-aaaaaaaaaaaa",
			revision: revision,
			vcsTime:  "2026-08-03T12:34:56+00:00",
		},
	}
	for _, seed := range accepted {
		if !validLocalMainVersion(seed.version, seed.revision, seed.vcsTime) {
			f.Fatalf("canonical local-main version seed was rejected: %+v", seed)
		}
		f.Add(seed.version, seed.revision, seed.vcsTime)
	}
	f.Fuzz(func(t *testing.T, version, sourceRevision, vcsTime string) {
		if len(version) > 4096 || len(sourceRevision) > 4096 || len(vcsTime) > 4096 {
			return
		}
		first := validLocalMainVersion(version, sourceRevision, vcsTime)
		second := validLocalMainVersion(version, sourceRevision, vcsTime)
		if first != second {
			t.Fatal("local-main build-metadata acceptance changed across identical input")
		}
		if !first || version == "" || version == "(devel)" {
			return
		}
		matches := goPseudoVersionPattern.FindStringSubmatch(version)
		if len(matches) != 3 || len(sourceRevision) != 40 ||
			matches[2] != sourceRevision[:12] {
			t.Fatal("accepted pseudo-version was not bound to the source revision")
		}
		if _, err := time.Parse("20060102150405", matches[1]); err != nil {
			t.Fatal("accepted pseudo-version timestamp was invalid")
		}
		if vcsTime != "" {
			parsed, err := time.Parse(time.RFC3339, vcsTime)
			if err != nil || parsed.UTC().Format("20060102150405") != matches[1] {
				t.Fatal("accepted pseudo-version was not bound to VCS time")
			}
		}
	})
}
