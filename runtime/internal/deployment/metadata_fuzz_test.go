//go:build darwin || linux

package deployment

import (
	"encoding/json"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
)

func FuzzDecodeDeploymentMetadata(f *testing.F) {
	layout, err := NewLayout(
		"/home/jat-fuzz",
		"/home/jat-fuzz/deployment",
		"/home/jat-fuzz/state",
	)
	if err != nil {
		f.Fatal(err)
	}
	binaryPath, err := layout.BinaryPath(
		"v1.2.3",
		Target{OS: "linux", Architecture: "amd64"},
	)
	if err != nil {
		f.Fatal(err)
	}
	release := InstalledRelease{
		Release: "v1.2.3", SourceRevision: strings.Repeat("a", 40),
		BuildToolchain: "go1.25.0", BuildIdentity: strings.Repeat("b", 64),
		ManifestSHA256: strings.Repeat("c", 64), ProtocolVersion: "1",
		StorageSchema: "1", OS: "linux", Architecture: "amd64",
		BinaryPath: binaryPath, BinaryBytes: 1,
		BinarySHA256: strings.Repeat("d", 64), LicenseBytes: 1,
		LicenseSHA256: strings.Repeat("e", 64), NoticeBytes: 1,
		NoticeSHA256: strings.Repeat("f", 64),
	}
	state := DeploymentState{
		StateVersion: DeploymentStateVersion, Generation: 1,
		Status: StatusForeground, Manager: ManagerForeground,
		StateDir: layout.StateDir, Active: &release,
	}
	journal := DeploymentJournal{
		StateVersion:  DeploymentStateVersion,
		TransactionID: strings.Repeat("1", 32),
		Operation:     OperationApply, Phase: PhaseArtifactStaged,
		Manager:           ManagerForeground,
		SourcePath:        "/home/jat-fuzz/input/sshserver",
		LicenseSourcePath: "/home/jat-fuzz/input/LICENSE",
		NoticeSourcePath:  "/home/jat-fuzz/input/NOTICE",
		Desired:           &release, PriorState: &state,
	}
	targets := []struct {
		name           string
		value          any
		newDestination func() any
		validate       func(any) error
	}{
		{
			name: "deployment state", value: state,
			newDestination: func() any { return &DeploymentState{} },
			validate: func(value any) error {
				return value.(*DeploymentState).Validate(layout)
			},
		},
		{
			name: "deployment journal", value: journal,
			newDestination: func() any { return &DeploymentJournal{} },
			validate: func(value any) error {
				return value.(*DeploymentJournal).Validate(layout)
			},
		},
	}
	for _, target := range targets {
		seed, err := canonicalDeploymentJSON(target.value)
		if err != nil {
			f.Fatal(err)
		}
		destination := target.newDestination()
		if err := decodeCanonicalDeploymentJSON(seed, destination); err != nil {
			f.Fatalf("decode %s seed: %v", target.name, err)
		}
		if err := target.validate(destination); err != nil {
			f.Fatalf("validate %s seed: %v", target.name, err)
		}
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		for _, target := range targets {
			first := target.newDestination()
			firstErr := decodeCanonicalDeploymentJSON(payload, first)
			if firstErr == nil {
				firstErr = target.validate(first)
			}
			second := target.newDestination()
			secondErr := decodeCanonicalDeploymentJSON(payload, second)
			if secondErr == nil {
				secondErr = target.validate(second)
			}
			if (firstErr == nil) != (secondErr == nil) {
				t.Fatalf("%s acceptance changed across identical input", target.name)
			}
			if firstErr != nil {
				continue
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatalf("%s output changed across identical input", target.name)
			}
			canonical, err := canonicalDeploymentJSON(first)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(payload, canonical) {
				t.Fatalf("accepted %s was not canonical", target.name)
			}
		}
	})
}

func FuzzParseBuildIdentityJSON(f *testing.F) {
	seedIdentity := buildinfo.Identity{
		Release: "v1.2.3", SourceRevision: strings.Repeat("a", 40),
		BuildToolchain: "go1.25.0", BuildIdentity: strings.Repeat("b", 64),
		ProtocolVersion: "1", StorageSchema: "1",
	}
	seed, err := json.Marshal(seedIdentity)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, payload []byte) {
		first, firstErr := parseIdentity(payload)
		second, secondErr := parseIdentity(payload)
		if (firstErr == nil) != (secondErr == nil) || first != second {
			t.Fatalf("build identity parser is nondeterministic: first=%+v/%v second=%+v/%v", first, firstErr, second, secondErr)
		}
		if firstErr == nil {
			encoded, err := json.Marshal(first)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip, err := parseIdentity(encoded)
			if err != nil || roundTrip != first {
				t.Fatalf("build identity did not round trip: value=%+v parsed=%+v error=%v", first, roundTrip, err)
			}
		}
	})
}

func FuzzParseArtifactGoBuildInfo(f *testing.F) {
	executablePath, err := os.Executable()
	if err != nil {
		f.Fatal(err)
	}
	executable, err := os.ReadFile(executablePath)
	if err != nil {
		f.Fatal(err)
	}
	if len(executable) > maximumStagedArtifactBytes {
		f.Fatal("current test executable exceeds the production artifact bound")
	}
	if _, err := parseArtifactGoBuildInfo(executable); err != nil {
		f.Fatalf("current test executable must contain accepted Go build metadata: %v", err)
	}
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > maximumStagedArtifactBytes {
			return
		}
		first, firstErr := parseArtifactGoBuildInfo(payload)
		second, secondErr := parseArtifactGoBuildInfo(payload)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatal("Go build-metadata acceptance changed across identical input")
		}
		if firstErr == nil && !reflect.DeepEqual(first, second) {
			t.Fatal("Go build-metadata output changed across identical input")
		}
	})
}

func FuzzDeploymentScalarParsers(f *testing.F) {
	f.Add("https://downloads.example.test", "https://downloads.example.test/releases/v1.2.3/sshserver-linux-amd64", "v1.2.3", strings.Repeat("a", 64), int64(1))
	f.Fuzz(func(t *testing.T, originText, releaseURLText, release, digest string, expectedBytes int64) {
		// Keep integer mutations within the production bound before exercising
		// the size parser; arbitrary fuzz integers otherwise add no grammar
		// coverage beyond the two rejected extrema.
		expectedBytes %= maximumStagedArtifactBytes + 2
		firstOrigin, firstOriginErr := parseDownloadOrigin(originText)
		secondOrigin, secondOriginErr := parseDownloadOrigin(originText)
		if (firstOriginErr == nil) != (secondOriginErr == nil) {
			t.Fatal("download-origin acceptance changed across identical input")
		}
		if firstOriginErr == nil && firstOrigin.String() != secondOrigin.String() {
			t.Fatal("download-origin output changed across identical input")
		}
		origin := firstOrigin
		if origin == nil {
			origin, _ = url.Parse("https://downloads.example.test")
		}
		firstRelease, firstReleaseErr := parseReleaseURL(releaseURLText, origin, release)
		secondRelease, secondReleaseErr := parseReleaseURL(releaseURLText, origin, release)
		if (firstReleaseErr == nil) != (secondReleaseErr == nil) {
			t.Fatal("release-URL acceptance changed across identical input")
		}
		if firstReleaseErr == nil && firstRelease.String() != secondRelease.String() {
			t.Fatal("release-URL output changed across identical input")
		}
		firstArtifact, firstArtifactErr := parseArtifactExpectation(expectedBytes, digest)
		secondArtifact, secondArtifactErr := parseArtifactExpectation(expectedBytes, digest)
		if (firstArtifactErr == nil) != (secondArtifactErr == nil) || firstArtifact != secondArtifact {
			t.Fatal("artifact expectation parser changed across identical input")
		}
	})
}
