//go:build darwin || linux

package deployment

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadPinnedManifestFileRejectsLinksModesAndWrongPins(t *testing.T) {
	home := secureTestHome(t)
	manifest := testReleaseManifest()
	payload, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "manifest.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if loaded, err := ReadPinnedManifestFile(path, SHA256Hex(payload)); err != nil || string(loaded) != string(payload) {
		t.Fatalf("loaded=%q err=%v", loaded, err)
	}
	if _, err := ReadPinnedManifestFile(path, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong manifest pin unexpectedly accepted")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPinnedManifestFile(path, SHA256Hex(payload)); err == nil {
		t.Fatal("broad manifest mode unexpectedly accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "manifest-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPinnedManifestFile(link, SHA256Hex(payload)); err == nil {
		t.Fatal("manifest symlink unexpectedly accepted")
	}
}
