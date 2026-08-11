//go:build darwin || linux

package releasebundle

import (
	"os"
	"reflect"
	"testing"
)

func FuzzParseReleaseBundleGoBuildInfo(f *testing.F) {
	executablePath, err := os.Executable()
	if err != nil {
		f.Fatal(err)
	}
	executable, err := os.ReadFile(executablePath)
	if err != nil {
		f.Fatal(err)
	}
	if len(executable) > maxBundleArtifactBytes {
		f.Fatal("current test executable exceeds the production bundle-artifact bound")
	}
	if _, err := parseReleaseBundleGoBuildInfo(executable); err != nil {
		f.Fatalf("current test executable must contain accepted Go build metadata: %v", err)
	}
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, mutation []byte) {
		for _, payload := range [][]byte{
			mutation,
			mutateAcceptedReleaseBundleExecutable(executable, mutation),
		} {
			if len(payload) > maxBundleArtifactBytes {
				continue
			}
			first, firstErr := parseReleaseBundleGoBuildInfo(payload)
			second, secondErr := parseReleaseBundleGoBuildInfo(payload)
			if (firstErr == nil) != (secondErr == nil) {
				t.Fatal("release-bundle Go build-metadata acceptance changed across identical input")
			}
			if firstErr == nil && !reflect.DeepEqual(first, second) {
				t.Fatal("release-bundle Go build-metadata output changed across identical input")
			}
		}
	})
}

func mutateAcceptedReleaseBundleExecutable(executable, mutation []byte) []byte {
	candidate := append([]byte(nil), executable...)
	if len(candidate) == 0 || len(mutation) == 0 {
		return candidate
	}
	offset := 0
	for index, value := range mutation {
		if index == 8 {
			break
		}
		offset = (offset*257 + int(value)) % len(candidate)
	}
	patch := mutation
	if len(patch) > 4096 {
		patch = patch[:4096]
	}
	if len(patch) > len(candidate)-offset {
		patch = patch[:len(candidate)-offset]
	}
	copy(candidate[offset:], patch)
	return candidate
}
