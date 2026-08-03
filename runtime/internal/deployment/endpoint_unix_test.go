//go:build darwin || linux

package deployment

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestStateDirForExecutableUsesRecordedCustomDeploymentPath(t *testing.T) {
	home := secureTestHome(t)
	layout, err := NewLayout(
		home,
		filepath.Join(home, "custom-install", "sshserver"),
		filepath.Join(home, "custom-state", "instance"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareLayout(layout); err != nil {
		t.Fatal(err)
	}
	release := testInstalledRelease(t, layout, "v1.2.3", "a")
	if err := os.MkdirAll(filepath.Dir(release.BinaryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(release.BinaryPath, []byte("test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	state := DeploymentState{
		StateVersion: DeploymentStateVersion,
		Generation:   1,
		Status:       StatusForeground,
		Manager:      ManagerForeground,
		StateDir:     layout.StateDir,
		Active:       &release,
	}
	if err := SaveState(layout, state); err != nil {
		t.Fatal(err)
	}

	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "unrelated-state-default"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "unrelated-data-default"))
	resolved, err := StateDirForExecutable(release.BinaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != layout.StateDir {
		t.Fatalf("resolved state directory = %q, want recorded %q", resolved, layout.StateDir)
	}

	otherHome := secureTestHome(t)
	t.Setenv("HOME", otherHome)
	if _, err := StateDirForExecutable(release.BinaryPath); err == nil || errors.Is(err, ErrNotDeployedExecutable) {
		t.Fatalf("changed HOME must fail closed without non-deployment fallback: %v", err)
	}
}

func TestStateDirForExecutableRejectsNonDeploymentAndInactivePaths(t *testing.T) {
	arbitrary := filepath.Join(t.TempDir(), "sshserver")
	if err := os.WriteFile(arbitrary, []byte("test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := StateDirForExecutable(arbitrary); !errors.Is(err, ErrNotDeployedExecutable) {
		t.Fatalf("arbitrary executable error = %v", err)
	}

	layout := testLayout(t)
	active := testInstalledRelease(t, layout, "v1.2.3", "a")
	previous := testInstalledRelease(t, layout, "v1.2.2", "b")
	for _, path := range []string{active.BinaryPath, previous.BinaryPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("test executable"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	state := DeploymentState{
		StateVersion: DeploymentStateVersion,
		Generation:   2,
		Status:       StatusForeground,
		Manager:      ManagerForeground,
		StateDir:     layout.StateDir,
		Active:       &active,
		Previous:     &previous,
	}
	if err := SaveState(layout, state); err != nil {
		t.Fatal(err)
	}
	if _, err := StateDirForExecutable(previous.BinaryPath); err == nil {
		t.Fatal("inactive previous executable unexpectedly resolved deployment state")
	}
}

func TestStateDirForExecutableRejectsFIFODeploymentStateWithoutBlocking(t *testing.T) {
	home := secureTestHome(t)
	layout, err := NewLayout(home, filepath.Join(home, "deployment"), filepath.Join(home, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareLayout(layout); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(layout.VersionsDir, "v1.2.3", "sshserver-linux-amd64")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(layout.StatePath, 0o600); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := StateDirForExecutable(executable)
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("FIFO deployment state unexpectedly accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("deployment-state resolution blocked on FIFO")
	}
}
