//go:build darwin || linux

package deployment

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveInstalledArtifactsDeletesOnlyVersionsAndPreservesState(t *testing.T) {
	layout := testLayout(t)
	versionDir, err := PrepareVersionDirectory(layout, "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{
		"sshserver-linux-amd64": 0o500,
		"LICENSE":               0o400,
		"NOTICE":                0o400,
	} {
		path := filepath.Join(versionDir, name)
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	identityPath := filepath.Join(layout.StateDir, "identity-sentinel")
	if err := os.WriteFile(identityPath, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveInstalledArtifacts(layout); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(layout.VersionsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("versions remain: %v", entries)
	}
	if payload, err := os.ReadFile(identityPath); err != nil || string(payload) != "preserve" {
		t.Fatalf("state sentinel=%q err=%v", payload, err)
	}
}

func TestRemoveInstalledArtifactsPreflightsBeforeDeleting(t *testing.T) {
	layout := testLayout(t)
	first, err := PrepareVersionDirectory(layout, "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	firstBinary := filepath.Join(first, "sshserver-linux-amd64")
	if err := os.WriteFile(firstBinary, []byte("first"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(firstBinary, 0o500); err != nil {
		t.Fatal(err)
	}
	second, err := PrepareVersionDirectory(layout, "v1.2.4")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(firstBinary, filepath.Join(second, "sshserver-linux-amd64")); err != nil {
		t.Fatal(err)
	}
	if err := RemoveInstalledArtifacts(layout); err == nil {
		t.Fatal("unsafe installed tree unexpectedly removed")
	}
	if _, err := os.Lstat(firstBinary); err != nil {
		t.Fatalf("preflight failure partially deleted trusted version: %v", err)
	}
}

func TestRemoveInstalledArtifactsRejectsMovingReleaseDirectoryBeforeDeleting(t *testing.T) {
	layout := testLayout(t)
	trusted, err := PrepareVersionDirectory(layout, "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	trustedBinary := filepath.Join(trusted, "sshserver-linux-amd64")
	if err := os.WriteFile(trustedBinary, []byte("trusted"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(layout.VersionsDir, "stable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RemoveInstalledArtifacts(layout); err == nil {
		t.Fatal("moving release directory unexpectedly accepted")
	}
	if _, err := os.Lstat(trustedBinary); err != nil {
		t.Fatalf("release-name preflight partially deleted trusted version: %v", err)
	}
}

func TestRemoveInstalledArtifactsRejectsUnexpectedAndHardLinkedFiles(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{name: "unexpected", setup: func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, "notes.txt"), []byte("x"), 0o400); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hard link", setup: func(t *testing.T, directory string) {
			binary := filepath.Join(directory, "sshserver-linux-amd64")
			if err := os.WriteFile(binary, []byte("x"), 0o500); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(binary, 0o500); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(binary, filepath.Join(directory, "NOTICE")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := testLayout(t)
			directory, err := PrepareVersionDirectory(layout, "v1.2.3")
			if err != nil {
				t.Fatal(err)
			}
			test.setup(t, directory)
			if err := RemoveInstalledArtifacts(layout); err == nil {
				t.Fatal("unsafe installed tree unexpectedly removed")
			}
		})
	}

	layout := testLayout(t)
	if err := os.Remove(layout.VersionsDir); err != nil {
		t.Fatal(err)
	}
	if err := RemoveInstalledArtifacts(layout); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent versions error=%v", err)
	}
}
