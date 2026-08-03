package config

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"
)

func TestSettingsRejectNonLoopbackAndNonCanonicalListeners(t *testing.T) {
	settings, err := NewSettings([]string{"127.0.0.1:37421"})
	if err != nil {
		t.Fatal(err)
	}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{
		"0.0.0.0:37421",
		"192.0.2.1:37421",
		"localhost:37421",
		"127.000.000.001:37421",
		"[0:0:0:0:0:0:0:1]:37421",
		"127.0.0.1:0",
	} {
		if err := ValidateListener(address); err == nil {
			t.Fatalf("ValidateListener(%q) unexpectedly succeeded", address)
		}
	}
}

func TestProtectedFileReadRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := LoadSettings(path)
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("FIFO unexpectedly accepted as protected config")
		}
	case <-time.After(time.Second):
		t.Fatal("protected config read blocked on FIFO")
	}
}

func TestSettingsRequiresOneSharedListenerPort(t *testing.T) {
	settings, err := NewSettings([]string{
		"127.0.0.1:37421",
		"[::1]:37422",
	})
	if err == nil || settings.Listeners != nil {
		t.Fatalf("different listener ports unexpectedly accepted: settings=%#v err=%v", settings, err)
	}
}

func TestListenerSetIsCanonicalAndOrderIndependent(t *testing.T) {
	settings, err := NewSettings([]string{"[::1]:37421", "127.0.0.1:37421"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1:37421", "[::1]:37421"}
	if !slices.Equal(settings.Listeners, want) {
		t.Fatalf("canonical listeners = %#v, want %#v", settings.Listeners, want)
	}
	if !SameListeners(settings.Listeners, []string{"[::1]:37421", "127.0.0.1:37421"}) {
		t.Fatal("same listener set changed when input order changed")
	}
}

func TestProtectedFilesRoundTripAndRejectSymlinks(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := EnsureStateDirectory(stateDir); err != nil {
		t.Fatal(err)
	}
	paths := ForStateDir(stateDir)
	settings, err := NewSettings([]string{"127.0.0.1:37421"})
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveSettings(paths.Config, settings); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSettings(paths.Config)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.InstanceID != settings.InstanceID || loaded.VaultID != settings.VaultID {
		t.Fatalf("loaded settings changed identity: %#v", loaded)
	}

	secret := make([]byte, 32)
	if err := WriteSecret(paths.InstanceSecret, secret); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecret(paths.InstanceSecret); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.InstanceSecret, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecret(paths.InstanceSecret); err == nil {
		t.Fatal("world-readable instance secret unexpectedly accepted")
	}

	target := filepath.Join(stateDir, "target")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(stateDir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSettings(link); err == nil {
		t.Fatal("symlinked config unexpectedly accepted")
	}
	hardLink := filepath.Join(stateDir, "hard-link")
	if err := os.Link(target, hardLink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSettings(hardLink); err == nil {
		t.Fatal("hard-linked config unexpectedly accepted")
	}
	if err := WriteFileAtomic(link, []byte("replacement"), 0o600); err == nil {
		t.Fatal("atomic writer unexpectedly replaced a symlink")
	}
}

func TestEnsureStateDirectoryRejectsInsecureExistingDirectory(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(stateDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := EnsureStateDirectory(stateDir); !errors.Is(err, ErrInsecureDirectory) {
		t.Fatalf("insecure directory error = %v", err)
	}
}

func TestLoadSettingsRejectsUnknownAndTrailingJSON(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := EnsureStateDirectory(stateDir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, "config.json")
	for _, payload := range []string{
		`{"config_version":1,"instance_id":"00000000-0000-4000-8000-000000000001","vault_id":"00000000-0000-4000-8000-000000000002","listeners":["127.0.0.1:37421"],"extra":true}`,
		`{"config_version":1} {"config_version":1}`,
	} {
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSettings(path); err == nil {
			t.Fatalf("invalid payload unexpectedly accepted: %s", payload)
		}
	}
	if _, err := LoadSettings(filepath.Join(stateDir, "missing")); !errors.Is(err, ErrUninitialized) {
		t.Fatalf("missing config error = %v", err)
	}
}
