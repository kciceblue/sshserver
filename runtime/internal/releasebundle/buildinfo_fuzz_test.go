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

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > maxBundleArtifactBytes {
			return
		}
		first, firstErr := parseReleaseBundleGoBuildInfo(payload)
		second, secondErr := parseReleaseBundleGoBuildInfo(payload)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatal("release-bundle Go build-metadata acceptance changed across identical input")
		}
		if firstErr == nil && !reflect.DeepEqual(first, second) {
			t.Fatal("release-bundle Go build-metadata output changed across identical input")
		}
	})
}
