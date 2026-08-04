package instance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/config"
)

func TestInitializationLeaseSerializesValidationThroughInitialize(t *testing.T) {
	ctx := context.Background()
	stateDir := filepath.Join(t.TempDir(), "state")
	lease, err := AcquireInitializationLease(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !lease.InitializationLockCreated() {
		lease.Close()
		t.Fatal("first initialization lease did not report creating its lock")
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
	reopened, err := AcquireInitializationLease(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.InitializationLockCreated() {
		reopened.Close()
		t.Fatal("reopened initialization lease reported recreating its existing lock")
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInitializationLeaseRejectsUnlinkedOrReplacedLockPath(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	lease, err := AcquireInitializationLease(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := lease.AttestLockPath(); err != nil {
		t.Fatalf("initial lease attestation: %v", err)
	}

	lockPath := filepath.Join(stateDir, ".instance.lock")
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	replacement, err := AcquireInitializationLeaseWithLockPresence(stateDir, true)
	if err != nil {
		t.Fatalf("replacement lock was not independently acquirable: %v", err)
	}
	defer replacement.Close()

	if err := lease.AttestLockPath(); err == nil || !strings.Contains(err.Error(), "leased") {
		t.Fatalf("orphaned lease attestation error=%v", err)
	}
	if _, err := lease.Initialize(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "attest initialization lease") {
		t.Fatalf("orphaned lease initialize error=%v", err)
	}
}

func TestInitializeWithLeaseReattestsBeforeEveryMutationAndSuccess(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		targetCall    int
		markerPhase   string
		configPresent bool
		secretPresent bool
		databaseFound bool
	}{
		{name: "initializing marker", targetCall: 1},
		{name: "settings", targetCall: 2, markerPhase: "initializing"},
		{name: "secret", targetCall: 3, markerPhase: "initializing", configPresent: true},
		{name: "database", targetCall: 4, markerPhase: "initializing", configPresent: true, secretPresent: true},
		{name: "ready marker", targetCall: 5, markerPhase: "initializing", configPresent: true, secretPresent: true, databaseFound: true},
		{name: "successful return", targetCall: 6, markerPhase: "ready", configPresent: true, secretPresent: true, databaseFound: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			lease, err := AcquireInitializationLease(stateDir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if closeErr := lease.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			})
			attestationCalls := 0
			var replacement *InitializationLease
			attest := func() error {
				attestationCalls++
				if attestationCalls == testCase.targetCall {
					lockPath := filepath.Join(stateDir, ".instance.lock")
					if err := os.Remove(lockPath); err != nil {
						return err
					}
					if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
						return err
					}
					var err error
					replacement, err = AcquireInitializationLeaseWithLockPresence(stateDir, true)
					if err != nil {
						return err
					}
				}
				if err := lease.AttestLockPath(); err != nil {
					return fmt.Errorf("attest initialization lease: %w", err)
				}
				return nil
			}

			_, err = initializeWithLease(context.Background(), stateDir, []string{"127.0.0.1:37421"}, attest)
			if replacement == nil {
				t.Fatal("initialization boundary did not acquire the replacement lease")
			}
			if closeErr := replacement.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if attestationCalls != testCase.targetCall || err == nil || !strings.Contains(err.Error(), "attest initialization lease") {
				t.Fatalf("initialization boundary calls=%d error=%v", attestationCalls, err)
			}

			paths := config.ForStateDir(stateDir)
			marker, markerErr := config.LoadMarker(paths.InstallMarker)
			if testCase.markerPhase == "" {
				if !errors.Is(markerErr, os.ErrNotExist) {
					t.Fatalf("initialization boundary created marker=%+v err=%v", marker, markerErr)
				}
			} else if markerErr != nil || marker.Phase != testCase.markerPhase {
				t.Fatalf("initialization boundary marker=%+v err=%v", marker, markerErr)
			}
			for _, expected := range []struct {
				path    string
				present bool
			}{
				{path: paths.Config, present: testCase.configPresent},
				{path: paths.InstanceSecret, present: testCase.secretPresent},
				{path: paths.Database, present: testCase.databaseFound},
			} {
				_, statErr := os.Lstat(expected.path)
				if expected.present && statErr != nil {
					t.Fatalf("initialization boundary missing %s: %v", expected.path, statErr)
				}
				if !expected.present && !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("initialization boundary unexpectedly created %s: %v", expected.path, statErr)
				}
			}
		})
	}

	for _, targetCall := range []int{1, 2} {
		name := "ready validation"
		if targetCall == 2 {
			name = "ready successful return"
		}
		t.Run(name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			if _, err := Initialize(context.Background(), stateDir, []string{"127.0.0.1:37421"}); err != nil {
				t.Fatal(err)
			}
			lease, err := AcquireInitializationLease(stateDir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if closeErr := lease.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			})
			paths := config.ForStateDir(stateDir)
			protectedPaths := []string{paths.InstallMarker, paths.Config, paths.InstanceSecret, paths.Database}
			atReplacement := make(map[string][]byte, len(protectedPaths))
			attestationCalls := 0
			var replacement *InitializationLease
			attest := func() error {
				attestationCalls++
				if attestationCalls == targetCall {
					for _, path := range protectedPaths {
						payload, err := os.ReadFile(path)
						if err != nil {
							return err
						}
						atReplacement[path] = payload
					}
					lockPath := filepath.Join(stateDir, ".instance.lock")
					if err := os.Remove(lockPath); err != nil {
						return err
					}
					if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
						return err
					}
					var err error
					replacement, err = AcquireInitializationLeaseWithLockPresence(stateDir, true)
					if err != nil {
						return err
					}
				}
				if err := lease.AttestLockPath(); err != nil {
					return fmt.Errorf("attest initialization lease: %w", err)
				}
				return nil
			}

			_, err = initializeWithLease(context.Background(), stateDir, []string{"127.0.0.1:37421"}, attest)
			if replacement == nil {
				t.Fatal("ready initialization boundary did not acquire the replacement lease")
			}
			if closeErr := replacement.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if attestationCalls != targetCall || err == nil || !strings.Contains(err.Error(), "attest initialization lease") {
				t.Fatalf("ready initialization boundary calls=%d error=%v", attestationCalls, err)
			}
			for _, path := range protectedPaths {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(after, atReplacement[path]) {
					t.Fatalf("ready initialization mutated %s after replacement: equal=%v err=%v", path, bytes.Equal(after, atReplacement[path]), err)
				}
			}
		})
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
