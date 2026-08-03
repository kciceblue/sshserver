package deployment

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPinnedReleaseManifestSelectsEveryCanonicalTarget(t *testing.T) {
	manifest := testReleaseManifest()
	payload, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePinnedManifest(payload, SHA256Hex(payload))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Release != manifest.Release {
		t.Fatalf("release = %q, want %q", parsed.Release, manifest.Release)
	}
	for _, target := range SupportedTargets() {
		artifact, err := parsed.Artifact(target)
		if err != nil {
			t.Fatal(err)
		}
		wantSuffix := "/sshserver-" + target.OS + "-" + target.Architecture
		if !strings.HasSuffix(artifact.URL, wantSuffix) || artifact.Bytes != 1024 {
			t.Fatalf("artifact for %+v = %+v", target, artifact)
		}
	}
}

func TestPinnedReleaseManifestRejectsUntrustedBytes(t *testing.T) {
	manifest := testReleaseManifest()
	payload, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		payload []byte
		pin     string
		want    string
	}{
		{name: "invalid pin", payload: payload, pin: strings.Repeat("A", 64), want: "lowercase"},
		{name: "wrong pin", payload: payload, pin: strings.Repeat("0", 64), want: "does not match"},
		{name: "noncanonical", payload: append([]byte(" "), payload...), pin: SHA256Hex(append([]byte(" "), payload...)), want: "canonical"},
		{name: "trailing", payload: append(append([]byte(nil), payload...), []byte("{}")...), pin: SHA256Hex(append(append([]byte(nil), payload...), []byte("{}")...)), want: "trailing"},
		{name: "empty", payload: nil, pin: strings.Repeat("0", 64), want: "size boundary"},
		{name: "oversized", payload: make([]byte, maxManifestBytes+1), pin: strings.Repeat("0", 64), want: "size boundary"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParsePinnedManifest(test.payload, test.pin); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}

	var object map[string]any
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	object["future_field"] = true
	unknown, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePinnedManifest(unknown, SHA256Hex(unknown)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown-field error = %v", err)
	}
}

func TestReleaseManifestRejectsMovingIncompleteAndUnsafeArtifacts(t *testing.T) {
	valid := testReleaseManifest()
	tests := []struct {
		name   string
		mutate func(*ReleaseManifest)
		want   string
	}{
		{name: "latest", mutate: func(value *ReleaseManifest) { value.Release = "latest" }, want: "immutable"},
		{name: "path release", mutate: func(value *ReleaseManifest) { value.Release = "v1..2" }, want: "path-safe"},
		{name: "uppercase release", mutate: func(value *ReleaseManifest) { value.Release = "V1.2.3" }, want: "path-safe"},
		{name: "source revision", mutate: func(value *ReleaseManifest) { value.SourceRevision = strings.Repeat("a", 39) }, want: "source revision"},
		{name: "toolchain", mutate: func(value *ReleaseManifest) { value.BuildToolchain = "go1.25" }, want: "toolchain"},
		{name: "protocol", mutate: func(value *ReleaseManifest) { value.ProtocolVersion = "2" }, want: "protocol"},
		{name: "schema", mutate: func(value *ReleaseManifest) { value.StorageSchema = "2" }, want: "storage schema"},
		{name: "origin path", mutate: func(value *ReleaseManifest) { value.DownloadOrigin += "/release" }, want: "origin"},
		{name: "origin port", mutate: func(value *ReleaseManifest) { value.DownloadOrigin = "https://downloads.example.test:443" }, want: "canonical"},
		{name: "missing target", mutate: func(value *ReleaseManifest) { value.Artifacts = value.Artifacts[:3] }, want: "exactly four"},
		{name: "target order", mutate: func(value *ReleaseManifest) {
			value.Artifacts[0], value.Artifacts[1] = value.Artifacts[1], value.Artifacts[0]
		}, want: "canonically ordered"},
		{name: "empty bytes", mutate: func(value *ReleaseManifest) { value.Artifacts[0].Bytes = 0 }, want: "size"},
		{name: "huge bytes", mutate: func(value *ReleaseManifest) { value.Artifacts[0].Bytes = maxArtifactBytes + 1 }, want: "size"},
		{name: "uppercase hash", mutate: func(value *ReleaseManifest) { value.Artifacts[0].SHA256 = strings.Repeat("A", 64) }, want: "lowercase"},
		{name: "build identity", mutate: func(value *ReleaseManifest) { value.Artifacts[0].BuildIdentity = "dev" }, want: "build identity"},
		{name: "other origin", mutate: func(value *ReleaseManifest) {
			value.Artifacts[0].URL = "https://other.example.test/sshserver-linux-amd64"
		}, want: "approved origin"},
		{name: "query", mutate: func(value *ReleaseManifest) { value.Artifacts[0].URL += "?download=1" }, want: "direct download"},
		{name: "fragment", mutate: func(value *ReleaseManifest) { value.Artifacts[0].URL += "#binary" }, want: "direct download"},
		{name: "escaped path", mutate: func(value *ReleaseManifest) {
			value.Artifacts[0].URL = strings.Replace(value.Artifacts[0].URL, "/releases/", "/%72eleases/", 1)
		}, want: "direct download"},
		{name: "moving path", mutate: func(value *ReleaseManifest) {
			value.Artifacts[0].URL = strings.Replace(value.Artifacts[0].URL, "/v1.0.0-test.1/", "/current/", 1)
		}, want: "direct download"},
		{name: "extra path prefix", mutate: func(value *ReleaseManifest) {
			value.Artifacts[0].URL = strings.Replace(value.Artifacts[0].URL, "/releases/", "/archive/releases/", 1)
		}, want: "direct download"},
		{name: "wrong name", mutate: func(value *ReleaseManifest) { value.Artifacts[0].URL += ".bin" }, want: "must end"},
		{name: "missing release file", mutate: func(value *ReleaseManifest) { value.ReleaseFiles = value.ReleaseFiles[:1] }, want: "LICENSE and NOTICE"},
		{name: "release file order", mutate: func(value *ReleaseManifest) {
			value.ReleaseFiles[0], value.ReleaseFiles[1] = value.ReleaseFiles[1], value.ReleaseFiles[0]
		}, want: "canonical order"},
		{name: "release file hash", mutate: func(value *ReleaseManifest) { value.ReleaseFiles[0].SHA256 = "bad" }, want: "SHA-256"},
		{name: "release file path", mutate: func(value *ReleaseManifest) {
			value.ReleaseFiles[0].URL = strings.Replace(value.ReleaseFiles[0].URL, "/v1.0.0-test.1/", "/latest/", 1)
		}, want: "direct download"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			value.Artifacts = append([]ReleaseArtifact(nil), valid.Artifacts...)
			value.ReleaseFiles = append([]ReleaseFile(nil), valid.ReleaseFiles...)
			test.mutate(&value)
			if err := value.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func testReleaseManifest() ReleaseManifest {
	artifacts := make([]ReleaseArtifact, 0, len(supportedTargets))
	for index, target := range supportedTargets {
		artifacts = append(artifacts, ReleaseArtifact{
			OS:            target.OS,
			Architecture:  target.Architecture,
			BuildIdentity: strings.Repeat(string(rune('1'+index)), 64),
			URL:           "https://downloads.example.test/releases/v1.0.0-test.1/sshserver-" + target.OS + "-" + target.Architecture,
			Bytes:         1024,
			SHA256:        strings.Repeat(string(rune('a'+index)), 64),
		})
	}
	manifest := ReleaseManifest{
		ManifestVersion: ManifestVersion,
		Release:         "v1.0.0-test.1",
		SourceRevision:  strings.Repeat("e", 40),
		BuildToolchain:  "go1.25.0",
		ProtocolVersion: "1",
		StorageSchema:   "1",
		DownloadOrigin:  "https://downloads.example.test",
		Artifacts:       artifacts,
		ReleaseFiles: []ReleaseFile{
			{Name: "LICENSE", URL: "https://downloads.example.test/releases/v1.0.0-test.1/LICENSE", Bytes: 11358, SHA256: strings.Repeat("5", 64)},
			{Name: "NOTICE", URL: "https://downloads.example.test/releases/v1.0.0-test.1/NOTICE", Bytes: 2048, SHA256: strings.Repeat("6", 64)},
		},
	}
	refreshTestBuildIdentities(&manifest)
	return manifest
}

func refreshTestBuildIdentities(manifest *ReleaseManifest) {
	for index, target := range supportedTargets {
		identity, err := DeriveBuildIdentity(manifest.Release, manifest.SourceRevision, manifest.BuildToolchain, target)
		if err != nil {
			panic(err)
		}
		manifest.Artifacts[index].BuildIdentity = identity
	}
}
