package instance

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestInitializationLeaseSerializesValidationThroughInitialize(t *testing.T) {
	ctx := context.Background()
	stateDir := filepath.Join(t.TempDir(), "state")
	lease, err := AcquireInitializationLease(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(ctx, stateDir, nil); err == nil || !strings.Contains(err.Error(), "another initialization is already running") {
		lease.Close()
		t.Fatalf("parallel initializer error=%v", err)
	}
	settings, err := lease.Initialize(ctx, nil)
	if err != nil {
		lease.Close()
		t.Fatal(err)
	}
	if settings.InstanceID == "" || settings.VaultID == "" {
		lease.Close()
		t.Fatalf("lease initialization settings=%+v", settings)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.Initialize(ctx, nil); err == nil || !strings.Contains(err.Error(), "lease is closed") {
		t.Fatalf("closed lease initialize error=%v", err)
	}
	if _, err := Initialize(ctx, stateDir, nil); err != nil {
		t.Fatalf("initializer after lease release: %v", err)
	}
}

func TestInitializeIsIdempotentAndKeepsSecretOutsideDatabase(t *testing.T) {
	ctx := context.Background()
	stateDir := filepath.Join(t.TempDir(), "state")
	listeners := []string{"127.0.0.1:37421"}
	first, err := Initialize(ctx, stateDir, listeners)
	if err != nil {
		t.Fatal(err)
	}
	paths := configPaths(stateDir)
	secretBefore, err := os.ReadFile(paths.secret)
	if err != nil {
		t.Fatal(err)
	}
	databaseBefore, err := os.ReadFile(paths.database)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(databaseBefore, secretBefore) {
		t.Fatal("database contains the separate instance secret")
	}

	second, err := Initialize(ctx, stateDir, listeners)
	if err != nil {
		t.Fatal(err)
	}
	if first.ConfigVersion != second.ConfigVersion ||
		first.InstanceID != second.InstanceID ||
		first.VaultID != second.VaultID ||
		len(first.Listeners) != len(second.Listeners) ||
		first.Listeners[0] != second.Listeners[0] {
		t.Fatalf("identity changed on repeated init: %#v != %#v", first, second)
	}
	secretAfter, err := os.ReadFile(paths.secret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secretBefore, secretAfter) {
		t.Fatal("instance secret changed on repeated init")
	}
}

func TestInitializeTreatsDualStackListenersAsOneCanonicalSet(t *testing.T) {
	ctx := context.Background()
	stateDir := filepath.Join(t.TempDir(), "state")
	first, err := Initialize(ctx, stateDir, []string{"[::1]:37421", "127.0.0.1:37421"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1:37421", "[::1]:37421"}
	if !slices.Equal(first.Listeners, want) {
		t.Fatalf("persisted listeners = %#v, want %#v", first.Listeners, want)
	}
	second, err := Initialize(ctx, stateDir, []string{"127.0.0.1:37421", "[::1]:37421"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(second.Listeners, want) {
		t.Fatalf("repeated listeners = %#v, want %#v", second.Listeners, want)
	}
}

func TestOpenForServeRejectsSecondDaemon(t *testing.T) {
	ctx := context.Background()
	stateDir := filepath.Join(t.TempDir(), "state")
	if _, err := Initialize(ctx, stateDir, []string{"127.0.0.1:37421"}); err != nil {
		t.Fatal(err)
	}
	first, err := OpenForServe(ctx, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := OpenForServe(ctx, stateDir); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second daemon error = %v", err)
	}
}

func TestInitializeResumesAfterConfigOnlyPartialState(t *testing.T) {
	ctx := context.Background()
	stateDir := filepath.Join(t.TempDir(), "state")
	settings, err := Initialize(ctx, stateDir, []string{"127.0.0.1:37421"})
	if err != nil {
		t.Fatal(err)
	}
	paths := configPaths(stateDir)
	if err := os.Remove(paths.secret); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(paths.database); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(paths.database + suffix)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "install-state.json"), []byte("{\n  \"generation\": \"1\",\n  \"phase\": \"initializing\",\n  \"state\": \"resume\"\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resumed, err := Initialize(ctx, stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.InstanceID != settings.InstanceID || resumed.VaultID != settings.VaultID {
		t.Fatal("partial-state resume replaced identity")
	}
}

type testPaths struct {
	secret   string
	database string
}

func configPaths(stateDir string) testPaths {
	return testPaths{
		secret:   filepath.Join(stateDir, "instance-secret"),
		database: filepath.Join(stateDir, "server.db"),
	}
}
