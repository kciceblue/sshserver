//go:build darwin || linux

package deployment

import (
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
)

func FuzzDecodeDeploymentMetadata(f *testing.F) {
	stateSeed, err := canonicalDeploymentJSON(DeploymentState{})
	if err != nil {
		f.Fatal(err)
	}
	journalSeed, err := canonicalDeploymentJSON(DeploymentJournal{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(stateSeed)
	f.Add(journalSeed)

	f.Fuzz(func(t *testing.T, payload []byte) {
		for _, newDestination := range []func() any{
			func() any { return &DeploymentState{} },
			func() any { return &DeploymentJournal{} },
		} {
			first := newDestination()
			firstErr := decodeCanonicalDeploymentJSON(payload, first)
			second := newDestination()
			secondErr := decodeCanonicalDeploymentJSON(payload, second)
			if (firstErr == nil) != (secondErr == nil) {
				t.Fatal("deployment metadata acceptance changed across identical input")
			}
			if firstErr != nil {
				continue
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatal("deployment metadata output changed across identical input")
			}
			canonical, err := canonicalDeploymentJSON(first)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(payload, canonical) {
				t.Fatal("accepted deployment metadata was not canonical")
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
