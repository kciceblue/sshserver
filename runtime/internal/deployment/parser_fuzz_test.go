//go:build darwin || linux

package deployment

import (
	"bytes"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func FuzzParsePinnedManifest(f *testing.F) {
	valid, err := testReleaseManifest().CanonicalBytes()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)

	f.Fuzz(func(t *testing.T, payload []byte) {
		parsed, err := ParsePinnedManifest(payload, SHA256Hex(payload))
		if err != nil {
			return
		}
		canonical, err := parsed.CanonicalBytes()
		if err != nil {
			t.Fatalf("accepted manifest cannot be re-encoded: %v", err)
		}
		if !bytes.Equal(payload, canonical) {
			t.Fatal("accepted manifest changed across canonical re-encoding")
		}
		reparsed, err := ParsePinnedManifest(canonical, SHA256Hex(canonical))
		if err != nil || !reflect.DeepEqual(reparsed, parsed) {
			t.Fatalf("accepted manifest does not round trip: parsed=%+v reparsed=%+v error=%v", parsed, reparsed, err)
		}
	})
}

func FuzzParseDeploymentPreview(f *testing.F) {
	valid, err := canonicalDeploymentPreviewSeed()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)

	f.Fuzz(func(t *testing.T, payload []byte) {
		parsed, err := ParseDeploymentPreview(payload)
		if err != nil {
			return
		}
		canonical, err := parsed.CanonicalBytes()
		if err != nil {
			t.Fatalf("accepted deployment preview cannot be re-encoded: %v", err)
		}
		if !bytes.Equal(payload, canonical) {
			t.Fatal("accepted deployment preview changed across canonical re-encoding")
		}
		reparsed, err := ParseDeploymentPreview(canonical)
		if err != nil || !reflect.DeepEqual(reparsed, parsed) {
			t.Fatalf("accepted deployment preview does not round trip: parsed=%+v reparsed=%+v error=%v", parsed, reparsed, err)
		}
	})
}

func canonicalDeploymentPreviewSeed() ([]byte, error) {
	home := "/home/alice"
	installRoot := filepath.Join(home, "deployment")
	stateDir := filepath.Join(home, "state")
	releaseDir := filepath.Join(installRoot, "versions", "v1.2.3")
	binaryPath := filepath.Join(releaseDir, "sshserver-linux-amd64")
	buildIdentity, err := DeriveBuildIdentity(
		"v1.2.3",
		strings.Repeat("a", 40),
		"go1.25.0",
		Target{OS: "linux", Architecture: "amd64"},
	)
	if err != nil {
		return nil, err
	}
	preview := DeploymentPreview{
		Version:        DeploymentPreviewVersion,
		Classification: PreviewBlocked,
		ApplyAllowed:   false,
		BlockReason:    "installed_release_verification_failed",
		Release: PreviewReleaseIdentity{
			Release: "v1.2.3", SourceRevision: strings.Repeat("a", 40), BuildToolchain: "go1.25.0",
			BuildIdentity: buildIdentity, ProtocolVersion: "1", StorageSchema: "1",
		},
		Target: PreviewTargetIdentity{OS: "linux", Architecture: "amd64"},
		Inputs: PreviewInputs{
			Manifest: PreviewManifestIdentity{Path: filepath.Join(home, "upload", "manifest.json"), Bytes: 100, SHA256: strings.Repeat("c", 64)},
			Artifact: PreviewArtifactIdentity{SourcePath: filepath.Join(home, "upload", "sshserver"), URL: "https://downloads.example.test/releases/v1.2.3/sshserver-linux-amd64", Bytes: 200, SHA256: strings.Repeat("d", 64)},
			License:  PreviewSupportFileIdentity{SourcePath: filepath.Join(home, "upload", "LICENSE"), URL: "https://downloads.example.test/releases/v1.2.3/LICENSE", Bytes: 300, SHA256: strings.Repeat("e", 64)},
			Notice:   PreviewSupportFileIdentity{SourcePath: filepath.Join(home, "upload", "NOTICE"), URL: "https://downloads.example.test/releases/v1.2.3/NOTICE", Bytes: 400, SHA256: strings.Repeat("f", 64)},
		},
		Paths: PreviewPaths{
			HomeDir: home, InstallRoot: installRoot, VersionsDir: filepath.Join(installRoot, "versions"), ReleaseDir: releaseDir,
			StateDir: stateDir, BinaryPath: binaryPath, LicensePath: filepath.Join(releaseDir, "LICENSE"), NoticePath: filepath.Join(releaseDir, "NOTICE"),
			DeploymentState: filepath.Join(installRoot, "deployment.json"), DeploymentJournal: filepath.Join(installRoot, "deployment-journal.json"),
			LifecycleLock: filepath.Join(installRoot, ".deployment.lock"), InitializationLock: filepath.Join(stateDir, ".instance.lock"),
			AdminSocket: filepath.Join(stateDir, ".enrollment.sock"),
		},
		Manager: ManagerAvailability{
			Manager: ManagerForeground,
			Foreground: &ForegroundFallback{
				Required: true, Reason: "user_service_manager_unavailable",
				Command: []string{binaryPath, "serve", "--state-dir", stateDir}, Supervised: true,
			},
		},
		Existing: PreviewExisting{InstanceState: "missing"},
		Actions:  []PreviewAction{},
		Assertions: PreviewAssertions{
			Data: PreviewDataAssertions{
				PreserveStateDirectory: true, PreserveInstanceIDs: true, PreserveDatabase: true,
				PreserveDeviceRegistry: true, PreserveInstanceSecret: true,
			},
			Network: PreviewNetworkAssertions{LoopbackOnly: true, Listeners: []string{"127.0.0.1:37421", "[::1]:37421"}},
			Scope:   PreviewScopeAssertions{CurrentUserOnly: true},
		},
	}
	return preview.CanonicalBytes()
}
