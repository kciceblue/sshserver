//go:build darwin || linux

package releasebundle

import (
	"os"
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
	f.Add("/tmp/artifacts", "/tmp/dist", "/tmp/LICENSE")
	f.Add("sshserver-linux-amd64", "payload", string([]byte{0, 0, 1, 64}))
	f.Add("LICENSE", "payload", string([]byte{0, 0, 1, 0}))
	f.Add("../artifact", "payload", string([]byte{0, 0, 1, 64}))
	f.Add("/", "payload", string([]byte{0, 0, 1, 64}))
	f.Add(".", "payload", string([]byte{0, 0, 1, 0}))
	f.Add(string([]byte{'n', 'a', 'm', 'e', 0}), "payload", string([]byte{0, 0, 1, 64}))
	f.Add(strings.Repeat("a", 129), "payload", string([]byte{0, 0, 1, 64}))
	f.Fuzz(func(t *testing.T, version, sourceRevision, vcsTime string) {
		if len(version) > 4096 || len(sourceRevision) > 4096 || len(vcsTime) > 4096 {
			return
		}
		first := validLocalMainVersion(version, sourceRevision, vcsTime)
		second := validLocalMainVersion(version, sourceRevision, vcsTime)
		if first != second {
			t.Fatal("local-main build-metadata acceptance changed across identical input")
		}
		options := Options{
			ArtifactDir: version,
			DistDir:     sourceRevision,
			LicensePath: vcsTime,
			NoticePath:  version,
		}
		firstPathErr := validateBundleInputPaths(options)
		secondPathErr := validateBundleInputPaths(options)
		wantPaths := exactBundleInputPaths(options)
		if (firstPathErr == nil) != wantPaths || (secondPathErr == nil) != wantPaths {
			t.Fatalf("bundle input-path acceptance first=%v second=%v want=%v", firstPathErr == nil, secondPathErr == nil, wantPaths)
		}
		output := bundleOutput{name: version, payload: []byte(sourceRevision), mode: bundleOutputFuzzMode(vcsTime)}
		firstOutputErr := validateBundleOutput(output)
		secondOutputErr := validateBundleOutput(output)
		wantOutput := exactBundleOutput(output)
		if (firstOutputErr == nil) != wantOutput || (secondOutputErr == nil) != wantOutput {
			t.Fatalf("bundle output grammar first=%v second=%v want=%v", firstOutputErr == nil, secondOutputErr == nil, wantOutput)
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

func bundleOutputFuzzMode(value string) os.FileMode {
	var mode uint32
	for index := 0; index < len(value) && index < 4; index++ {
		mode = mode<<8 | uint32(value[index])
	}
	return os.FileMode(mode)
}

func exactBundleOutput(output bundleOutput) bool {
	return output.name != "" && output.name != "." && output.name != ".." && len(output.name) <= 128 &&
		strings.IndexByte(output.name, 0) < 0 && !strings.Contains(output.name, "/") &&
		(output.mode == 0o400 || output.mode == 0o500) && len(output.payload) > 0
}

func exactBundleInputPaths(options Options) bool {
	for _, candidate := range []string{options.ArtifactDir, options.DistDir, options.LicensePath, options.NoticePath} {
		if !exactBundleCanonicalPath(candidate) {
			return false
		}
	}
	return true
}

func exactBundleCanonicalPath(value string) bool {
	if value == "" || value[0] != '/' || strings.IndexByte(value, 0) >= 0 {
		return false
	}
	if value == "/" {
		return true
	}
	if strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return false
	}
	for _, component := range strings.Split(value[1:], "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}
