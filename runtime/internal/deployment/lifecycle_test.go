//go:build darwin || linux

package deployment

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/instance"
	_ "github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/embed"
)

func applyConfirmed(t *testing.T, lifecycle *Lifecycle, request ApplyRequest) (ApplyResult, error) {
	t.Helper()
	var savedCalls []string
	var savedDetectResults []ManagerAvailability
	var savedFailures map[string]int
	manager, hasFakeManager := lifecycle.manager.(*fakeServiceManager)
	if hasFakeManager {
		savedCalls = append([]string(nil), manager.calls...)
		savedDetectResults = append([]ManagerAvailability(nil), manager.detectResults...)
		savedFailures = make(map[string]int, len(manager.failures))
		for operation, count := range manager.failures {
			savedFailures[operation] = count
		}
	}
	preview, err := lifecycle.Preview(context.Background(), request.previewRequest())
	if err == nil {
		canonical, canonicalErr := preview.CanonicalBytes()
		if canonicalErr != nil {
			t.Fatal(canonicalErr)
		}
		request.ConfirmedPreviewSHA256 = SHA256Hex(canonical)
	} else {
		// Invalid preflight fixtures still enter Apply so the test can assert the
		// exact read-only validation error. A valid preview digest cannot exist.
		request.ConfirmedPreviewSHA256 = strings.Repeat("0", 64)
	}
	if hasFakeManager {
		manager.calls = savedCalls
		manager.detectResults = savedDetectResults
		manager.failures = savedFailures
	}
	return lifecycle.Apply(context.Background(), request)
}

func TestApplyTransactionCommitsExactNativeReleaseAndIsIdempotent(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, desired := fixture.release(t, "v1.2.3", "a")
	result, err := applyConfirmed(t, fixture.lifecycle, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "active" || result.State.Status != StatusActive || result.State.Active == nil || *result.State.Active != desired {
		t.Fatalf("apply result = %+v", result)
	}
	assertDeploymentLocator(t, result.DeploymentLocator, fixture.layout, desired)
	if result.State.Generation != 1 || result.State.Previous != nil || result.Foreground != nil {
		t.Fatalf("unexpected first generation = %+v", result.State)
	}
	fixture.manager.assertCallsContainInOrder(t, "detect", "install", "is-active", "activate", "is-active")
	if fixture.stageCalls != 1 || fixture.initializeCalls != 1 || fixture.inspectCalls < 1 || fixture.probeCalls != 1 {
		t.Fatalf("stage/init/inspect/probe = %d/%d/%d/%d", fixture.stageCalls, fixture.initializeCalls, fixture.inspectCalls, fixture.probeCalls)
	}
	if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("completed journal error = %v", err)
	}

	beforeCalls := len(fixture.manager.calls)
	second, err := applyConfirmed(t, fixture.lifecycle, request)
	if err != nil {
		t.Fatal(err)
	}
	if second.State.Generation != 1 || fixture.stageCalls != 2 || fixture.initializeCalls != 1 {
		t.Fatalf("idempotent result=%+v stage/init=%d/%d", second, fixture.stageCalls, fixture.initializeCalls)
	}
	assertDeploymentLocator(t, second.DeploymentLocator, fixture.layout, desired)
	for _, call := range fixture.manager.calls[beforeCalls:] {
		if call == "install" || call == "activate" || call == "stop" || call == "remove" {
			t.Fatalf("idempotent apply mutated service manager: %v", fixture.manager.calls[beforeCalls:])
		}
	}
}

func TestApplyRequiresExactCanonicalPreviewDigestBeforePersistentMutation(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		confirmed func([]byte) string
		wantError string
	}{
		{name: "missing", confirmed: func([]byte) string { return "" }, wantError: "64 lowercase hexadecimal"},
		{name: "malformed", confirmed: func([]byte) string { return strings.Repeat("A", 64) }, wantError: "64 lowercase hexadecimal"},
		{name: "canonical bytes without terminal LF", confirmed: func(payload []byte) string { return SHA256Hex(payload[:len(payload)-1]) }, wantError: ErrDeploymentPreviewConfirmationMismatch.Error()},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newLifecycleFixture(t, false)
			request, _ := fixture.release(t, "v1.2.3", testCase.name)
			preview, err := fixture.lifecycle.Preview(context.Background(), request.previewRequest())
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := preview.CanonicalBytes()
			if err != nil || len(canonical) == 0 || canonical[len(canonical)-1] != '\n' {
				t.Fatalf("canonical preview boundary bytes=%q err=%v", canonical, err)
			}
			request.ConfirmedPreviewSHA256 = testCase.confirmed(canonical)
			before := snapshotPreviewTree(t, fixture.layout.HomeDir)
			if _, err := fixture.lifecycle.Apply(context.Background(), request); err == nil || !strings.Contains(err.Error(), testCase.wantError) {
				t.Fatalf("confirmation error=%v", err)
			}
			if after := snapshotPreviewTree(t, fixture.layout.HomeDir); !reflect.DeepEqual(after, before) {
				t.Fatalf("rejected confirmation mutated target\n before=%+v\n after=%+v", before, after)
			}
			if fixture.stageCalls != 0 || fixture.supportStageCalls != 0 || fixture.initializeCalls != 0 {
				t.Fatalf("rejected confirmation reached mutation stage/support/init=%d/%d/%d", fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls)
			}
		})
	}
}

func TestApplyRejectsStalePreviewWhenManagerPlanChanges(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, _ := fixture.release(t, "v1.2.3", "stale-manager")
	preview, err := fixture.lifecycle.Preview(context.Background(), request.previewRequest())
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := preview.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	request.ConfirmedPreviewSHA256 = SHA256Hex(canonical)
	fixture.manager.availability = foregroundAvailability(fixture.layout, "/pending")
	before := snapshotPreviewTree(t, fixture.layout.HomeDir)
	if _, err := fixture.lifecycle.Apply(context.Background(), request); !errors.Is(err, ErrDeploymentPreviewConfirmationMismatch) {
		t.Fatalf("stale manager confirmation error=%v", err)
	}
	if after := snapshotPreviewTree(t, fixture.layout.HomeDir); !reflect.DeepEqual(after, before) {
		t.Fatalf("stale manager confirmation mutated target\n before=%+v\n after=%+v", before, after)
	}
	for _, call := range fixture.manager.calls {
		if call == "install" || call == "activate" || call == "stop" || call == "remove" {
			t.Fatalf("stale confirmation reached manager mutation: %v", fixture.manager.calls)
		}
	}
}

func TestApplyRejectsReplayOfFreshPreviewAfterSuccessfulCommit(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, _ := fixture.release(t, "v1.2.3", "replayed-fresh")
	preview, err := fixture.lifecycle.Preview(context.Background(), request.previewRequest())
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := preview.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	request.ConfirmedPreviewSHA256 = SHA256Hex(canonical)
	if _, err := fixture.lifecycle.Apply(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	stageBefore, supportBefore, initializeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls
	before := snapshotPreviewTree(t, fixture.layout.HomeDir)
	if _, err := fixture.lifecycle.Apply(context.Background(), request); !errors.Is(err, ErrDeploymentPreviewConfirmationMismatch) {
		t.Fatalf("replayed fresh confirmation error=%v", err)
	}
	if after := snapshotPreviewTree(t, fixture.layout.HomeDir); !reflect.DeepEqual(after, before) {
		t.Fatalf("replayed fresh confirmation mutated target\n before=%+v\n after=%+v", before, after)
	}
	if fixture.stageCalls != stageBefore || fixture.supportStageCalls != supportBefore || fixture.initializeCalls != initializeBefore {
		t.Fatalf("replayed confirmation reached mutation stage/support/init=%d/%d/%d", fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
	}
}

func TestConcurrentFirstApplyLosesBootstrapAdmissionWithoutMutation(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, _ := fixture.release(t, "v1.2.3", "bootstrap-contention")
	preview, err := fixture.lifecycle.Preview(context.Background(), request.previewRequest())
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := preview.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	request.ConfirmedPreviewSHA256 = SHA256Hex(canonical)
	bootstrap, err := acquireDeploymentBootstrapLock(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	defer bootstrap.Close()
	before := snapshotPreviewTree(t, fixture.layout.HomeDir)
	if _, err := fixture.lifecycle.Apply(context.Background(), request); err == nil || !strings.Contains(err.Error(), "bootstrap operation") {
		t.Fatalf("contended bootstrap error=%v", err)
	}
	if after := snapshotPreviewTree(t, fixture.layout.HomeDir); !reflect.DeepEqual(after, before) {
		t.Fatalf("losing first apply mutated target\n before=%+v\n after=%+v", before, after)
	}
}

func TestConcurrentFreshMutationsLoseBootstrapAdmissionWithoutMutation(t *testing.T) {
	for _, operation := range []string{"rollback", "uninstall"} {
		t.Run(operation, func(t *testing.T) {
			fixture := newLifecycleFixture(t, false)
			bootstrap, err := acquireDeploymentBootstrapLock(fixture.layout)
			if err != nil {
				t.Fatal(err)
			}
			defer bootstrap.Close()
			before := snapshotPreviewTree(t, fixture.layout.HomeDir)
			switch operation {
			case "rollback":
				_, err = fixture.lifecycle.Rollback(context.Background())
			case "uninstall":
				_, err = fixture.lifecycle.Uninstall(context.Background())
			}
			if err == nil || !strings.Contains(err.Error(), "bootstrap operation") {
				t.Fatalf("contended %s error=%v", operation, err)
			}
			if after := snapshotPreviewTree(t, fixture.layout.HomeDir); !reflect.DeepEqual(after, before) {
				t.Fatalf("losing first %s mutated target\n before=%+v\n after=%+v", operation, before, after)
			}
		})
	}
}

func TestFirstApplyRevalidatesInputsUnderBootstrapBeforePersistentMutation(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, _ := fixture.release(t, "v1.2.3", "bootstrap-input-drift")
	preview, err := fixture.lifecycle.Preview(context.Background(), request.previewRequest())
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := preview.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	request.ConfirmedPreviewSHA256 = SHA256Hex(canonical)
	verificationCalls := 0
	fixture.lifecycle.verifySourceArtifact = func(string, InstalledRelease) error {
		verificationCalls++
		if verificationCalls == 2 {
			return errors.New("input changed under bootstrap admission")
		}
		return nil
	}
	before := snapshotPreviewTree(t, fixture.layout.HomeDir)
	if _, err := fixture.lifecycle.Apply(context.Background(), request); err == nil ||
		!strings.Contains(err.Error(), "input changed under bootstrap admission") {
		t.Fatalf("bootstrap input revalidation error=%v", err)
	}
	if verificationCalls != 2 {
		t.Fatalf("artifact verification calls=%d, want 2", verificationCalls)
	}
	if after := snapshotPreviewTree(t, fixture.layout.HomeDir); !reflect.DeepEqual(after, before) {
		t.Fatalf("bootstrap input rejection mutated target\n before=%+v\n after=%+v", before, after)
	}
}

func TestApplyRejectsDamagedRecordedReleaseBeforeMutation(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	first, _ := fixture.release(t, "v1.2.3", "apply-damaged-prior")
	if _, err := applyConfirmed(t, fixture.lifecycle, first); err != nil {
		t.Fatal(err)
	}
	upgrade, _ := fixture.release(t, "v1.2.4", "apply-damaged-upgrade")
	fixture.lifecycle.verifyPreviewRelease = func(context.Context, InstalledRelease) error {
		return errors.New("damaged installed release")
	}
	before := snapshotPreviewTree(t, fixture.layout.HomeDir)
	managerCallsBefore := len(fixture.manager.calls)
	stageBefore, supportBefore, initializeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls

	if _, err := applyConfirmed(t, fixture.lifecycle, upgrade); err == nil ||
		!strings.Contains(err.Error(), "verify recorded active release before apply") {
		t.Fatalf("damaged recorded-release apply error=%v", err)
	}
	if len(fixture.manager.calls) != managerCallsBefore {
		t.Fatalf("damaged recorded release reached manager preflight: %v", fixture.manager.calls[managerCallsBefore:])
	}
	if fixture.stageCalls != stageBefore || fixture.supportStageCalls != supportBefore || fixture.initializeCalls != initializeBefore {
		t.Fatalf("damaged recorded release reached mutation stage/support/init=%d/%d/%d", fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
	}
	if after := snapshotPreviewTree(t, fixture.layout.HomeDir); !reflect.DeepEqual(after, before) {
		t.Fatalf("damaged recorded-release preflight mutated target\n before=%+v\n after=%+v", before, after)
	}
	if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("damaged recorded-release preflight created journal: %v", err)
	}
}

func TestApplyRevalidatesInstanceUnderInitializationLeaseBeforeJournal(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	first, _ := fixture.release(t, "v1.2.3", "instance-lease-race-first")
	if _, err := applyConfirmed(t, fixture.lifecycle, first); err != nil {
		t.Fatal(err)
	}
	upgrade, desired := fixture.release(t, "v1.2.4", "instance-lease-race-upgrade")
	originalAcquire := fixture.lifecycle.acquireInstanceLease
	fixture.lifecycle.acquireInstanceLease = func(stateDir string, initializationLockPresent bool) (instanceInitializationLease, error) {
		lease, err := originalAcquire(stateDir, initializationLockPresent)
		if err != nil {
			return nil, err
		}
		paths := config.ForStateDir(stateDir)
		if err := os.WriteFile(paths.Database, []byte("not a SQLite database"), 0o600); err != nil {
			lease.Close()
			return nil, err
		}
		return lease, nil
	}
	stageBefore, supportBefore, initializeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls
	managerCallsBefore := len(fixture.manager.calls)

	_, err := applyConfirmed(t, fixture.lifecycle, upgrade)
	if !errors.Is(err, ErrDeploymentPreviewConfirmationMismatch) {
		t.Fatalf("instance lease race error=%v", err)
	}
	if fixture.stageCalls != stageBefore || fixture.supportStageCalls != supportBefore || fixture.initializeCalls != initializeBefore {
		t.Fatalf("instance lease race reached stage/support/init=%d/%d/%d", fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
	}
	for _, call := range fixture.manager.calls[managerCallsBefore:] {
		if call == "install" || call == "activate" || call == "stop" || call == "remove" {
			t.Fatalf("instance lease race reached manager mutation: %v", fixture.manager.calls[managerCallsBefore:])
		}
	}
	if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("instance lease race created journal: %v", err)
	}
	if _, err := os.Lstat(desired.BinaryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("instance lease race published desired binary: %v", err)
	}
}

func TestApplyRejectsInitializationLockCreationRaceBeforeJournal(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, desired := fixture.release(t, "v1.2.3", "initialization-lock-creation-race")
	originalAcquire := fixture.lifecycle.acquireInstanceLease
	fixture.lifecycle.acquireInstanceLease = func(stateDir string, initializationLockPresent bool) (instanceInitializationLease, error) {
		if err := os.WriteFile(filepath.Join(stateDir, ".instance.lock"), nil, 0o600); err != nil {
			return nil, err
		}
		return originalAcquire(stateDir, initializationLockPresent)
	}

	_, err := applyConfirmed(t, fixture.lifecycle, request)
	if !errors.Is(err, ErrDeploymentPreviewConfirmationMismatch) || !strings.Contains(err.Error(), "initialization lock presence") {
		t.Fatalf("initialization-lock creation race error=%v", err)
	}
	if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("initialization-lock creation race created journal: %v", err)
	}
	if _, err := os.Lstat(desired.BinaryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("initialization-lock creation race published desired binary: %v", err)
	}
	if fixture.stageCalls != 0 || fixture.supportStageCalls != 0 || fixture.initializeCalls != 0 {
		t.Fatalf("initialization-lock creation race reached stage/support/init=%d/%d/%d", fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls)
	}
}

func TestApplyDoesNotRecreateRemovedConfirmedInitializationLock(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	installedRequest, installed := fixture.release(t, "v1.2.3", "initialization-lock-open-only-installed")
	if _, err := applyConfirmed(t, fixture.lifecycle, installedRequest); err != nil {
		t.Fatal(err)
	}
	upgrade, desired := fixture.release(t, "v1.2.4", "initialization-lock-open-only-upgrade")
	initializationLock := filepath.Join(fixture.layout.StateDir, ".instance.lock")
	originalAcquire := fixture.lifecycle.acquireInstanceLease
	removedBeforeAcquire := false
	fixture.lifecycle.acquireInstanceLease = func(stateDir string, initializationLockPresent bool) (instanceInitializationLease, error) {
		if !initializationLockPresent {
			return nil, errors.New("preview did not confirm the existing initialization lock")
		}
		if err := os.Remove(initializationLock); err != nil {
			return nil, err
		}
		removedBeforeAcquire = true
		return originalAcquire(stateDir, initializationLockPresent)
	}
	stageBefore, supportBefore, initializeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls

	_, err := applyConfirmed(t, fixture.lifecycle, upgrade)
	if !errors.Is(err, ErrDeploymentPreviewConfirmationMismatch) || !strings.Contains(err.Error(), "initialization lock presence") {
		t.Fatalf("removed initialization-lock apply error=%v", err)
	}
	if !removedBeforeAcquire {
		t.Fatal("test race did not remove the confirmed initialization lock")
	}
	if _, err := os.Lstat(initializationLock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Apply recreated the unconfirmed initialization lock: %v", err)
	}
	if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("removed initialization-lock race created journal: %v", err)
	}
	if _, err := os.Lstat(desired.BinaryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed initialization-lock race published desired binary: %v", err)
	}
	if fixture.stageCalls != stageBefore || fixture.supportStageCalls != supportBefore || fixture.initializeCalls != initializeBefore {
		t.Fatalf("removed initialization-lock race reached stage/support/init=%d/%d/%d", fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
	}
	state, err := LoadState(fixture.layout)
	if err != nil || state.Active == nil || state.Active.Release != installed.Release {
		t.Fatalf("removed initialization-lock race changed deployment state=%+v err=%v", state, err)
	}
}

func TestApplyRejectsReplacementOfAcquiredInitializationLockBeforeJournal(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		lockPresent bool
	}{
		{name: "new lock", lockPresent: false},
		{name: "preexisting lock", lockPresent: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newLifecycleFixture(t, false)
			var request ApplyRequest
			var desired InstalledRelease
			var stateBefore []byte
			priorRelease := ""
			if testCase.lockPresent {
				installedRequest, installed := fixture.release(t, "v1.2.3", "initialization-lock-replacement-installed")
				if _, err := applyConfirmed(t, fixture.lifecycle, installedRequest); err != nil {
					t.Fatal(err)
				}
				priorRelease = installed.Release
				stateBytes, readErr := os.ReadFile(fixture.layout.StatePath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				stateBefore = stateBytes
				request, desired = fixture.release(t, "v1.2.4", "initialization-lock-replacement-upgrade")
			} else {
				request, desired = fixture.release(t, "v1.2.3", "initialization-lock-replacement-fresh")
			}

			initializationLock := filepath.Join(fixture.layout.StateDir, ".instance.lock")
			originalAcquire := fixture.lifecycle.acquireInstanceLease
			var replacement *instance.InitializationLease
			fixture.lifecycle.acquireInstanceLease = func(stateDir string, initializationLockPresent bool) (instanceInitializationLease, error) {
				lease, err := originalAcquire(stateDir, initializationLockPresent)
				if err != nil {
					return nil, err
				}
				if initializationLockPresent != testCase.lockPresent {
					lease.Close()
					return nil, fmt.Errorf("preview initialization lock presence=%t, want %t", initializationLockPresent, testCase.lockPresent)
				}
				if err := os.Remove(initializationLock); err != nil {
					lease.Close()
					return nil, err
				}
				if err := os.WriteFile(initializationLock, nil, 0o600); err != nil {
					lease.Close()
					return nil, err
				}
				replacement, err = instance.AcquireInitializationLeaseWithLockPresence(stateDir, true)
				if err != nil {
					lease.Close()
					return nil, fmt.Errorf("acquire replacement initialization lock: %w", err)
				}
				return lease, nil
			}
			stageBefore, supportBefore, initializeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls

			_, err := applyConfirmed(t, fixture.lifecycle, request)
			if replacement == nil {
				t.Fatal("replacement initialization lock was not acquired")
			}
			if closeErr := replacement.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if !errors.Is(err, ErrDeploymentPreviewConfirmationMismatch) || !strings.Contains(err.Error(), "leased initialization lock path changed") {
				t.Fatalf("replaced initialization-lock apply error=%v", err)
			}
			if fixture.stageCalls != stageBefore || fixture.supportStageCalls != supportBefore || fixture.initializeCalls != initializeBefore {
				t.Fatalf("replaced initialization lock reached stage/support/init=%d/%d/%d", fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
			}
			if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
				t.Fatalf("replaced initialization-lock race created journal: %v", err)
			}
			if _, err := os.Lstat(desired.BinaryPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("replaced initialization-lock race published desired binary: %v", err)
			}
			state, err := LoadState(fixture.layout)
			if testCase.lockPresent {
				if err != nil || state.Active == nil || state.Active.Release != priorRelease {
					t.Fatalf("replaced initialization-lock race changed deployment state=%+v err=%v", state, err)
				}
				stateAfter, err := os.ReadFile(fixture.layout.StatePath)
				if err != nil || !bytes.Equal(stateAfter, stateBefore) {
					t.Fatalf("replaced initialization-lock race changed deployment state bytes err=%v", err)
				}
			} else if !errors.Is(err, ErrNoDeploymentState) {
				t.Fatalf("fresh replaced initialization-lock race created deployment state=%+v err=%v", state, err)
			}
		})
	}
}

func TestApplyReattestsInitializationLeaseAtJournalAndStagingBoundaries(t *testing.T) {
	installReplacementHook := func(
		fixture *lifecycleFixture,
		attestationCalls *int,
		replacement **instance.InitializationLease,
	) {
		originalAcquire := fixture.lifecycle.acquireInstanceLease
		fixture.lifecycle.acquireInstanceLease = func(stateDir string, initializationLockPresent bool) (instanceInitializationLease, error) {
			lease, err := originalAcquire(stateDir, initializationLockPresent)
			if err != nil {
				return nil, err
			}
			return replaceInitializationLockAtAttestation(lease, stateDir, 3, attestationCalls, replacement), nil
		}
	}
	finishReplacement := func(t *testing.T, err error, attestationCalls, wantAttestationCalls int, replacement *instance.InitializationLease) {
		t.Helper()
		if replacement == nil {
			t.Fatal("replacement initialization lock was not acquired at the mutation boundary")
		}
		if closeErr := replacement.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if attestationCalls != wantAttestationCalls || !errors.Is(err, ErrDeploymentPreviewConfirmationMismatch) ||
			!strings.Contains(err.Error(), "leased initialization lock path changed") {
			t.Fatalf("boundary attestation calls=%d error=%v", attestationCalls, err)
		}
	}

	t.Run("new journal save", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		request, desired := fixture.release(t, "v1.2.3", "boundary-new-journal")
		attestationCalls := 0
		var replacement *instance.InitializationLease
		installReplacementHook(fixture, &attestationCalls, &replacement)
		stageBefore, supportBefore, initializeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls

		_, err := applyConfirmed(t, fixture.lifecycle, request)
		finishReplacement(t, err, attestationCalls, 3, replacement)
		if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
			t.Fatalf("new-journal boundary created journal: %v", err)
		}
		if _, err := LoadState(fixture.layout); !errors.Is(err, ErrNoDeploymentState) {
			t.Fatalf("new-journal boundary created deployment state: %v", err)
		}
		if fixture.stageCalls != stageBefore || fixture.supportStageCalls != supportBefore || fixture.initializeCalls != initializeBefore {
			t.Fatalf("new-journal boundary reached stage/support/init=%d/%d/%d", fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
		}
		if _, err := os.Lstat(desired.BinaryPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("new-journal boundary published desired binary: %v", err)
		}
	})

	for _, rebind := range []bool{false, true} {
		name := "matching journal staging"
		if rebind {
			name = "existing journal rebind"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newLifecycleFixture(t, false)
			request, desired := fixture.release(t, "v1.2.3", "boundary-existing-journal")
			fixture.lifecycle.failAfterPhase = PhasePlanned
			if _, err := applyConfirmed(t, fixture.lifecycle, request); !errors.Is(err, ErrInjectedDeploymentCrash) {
				t.Fatalf("injected planned apply error=%v", err)
			}
			fixture.lifecycle.failAfterPhase = ""
			if rebind {
				alternate := filepath.Join(fixture.layout.HomeDir, "alternate-boundary-inputs")
				request.ArtifactPath = filepath.Join(alternate, "sshserver")
				request.LicensePath = filepath.Join(alternate, "LICENSE")
				request.NoticePath = filepath.Join(alternate, "NOTICE")
			}
			journalBefore, err := os.ReadFile(fixture.layout.JournalPath)
			if err != nil {
				t.Fatal(err)
			}
			attestationCalls := 0
			var replacement *instance.InitializationLease
			installReplacementHook(fixture, &attestationCalls, &replacement)
			stageBefore, supportBefore, initializeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls

			_, err = applyConfirmed(t, fixture.lifecycle, request)
			wantAttestationCalls := 4
			if rebind {
				wantAttestationCalls = 3
			}
			finishReplacement(t, err, attestationCalls, wantAttestationCalls, replacement)
			journalAfter, readErr := os.ReadFile(fixture.layout.JournalPath)
			if readErr != nil || !bytes.Equal(journalAfter, journalBefore) {
				t.Fatalf("%s changed journal bytes err=%v", name, readErr)
			}
			journal, loadErr := LoadJournal(fixture.layout)
			if loadErr != nil || journal.Phase != PhasePlanned {
				t.Fatalf("%s journal=%+v err=%v", name, journal, loadErr)
			}
			if fixture.stageCalls != stageBefore || fixture.supportStageCalls != supportBefore || fixture.initializeCalls != initializeBefore {
				t.Fatalf("%s reached stage/support/init=%d/%d/%d", name, fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
			}
			if _, err := os.Lstat(desired.BinaryPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s published desired binary: %v", name, err)
			}
		})
	}

	t.Run("idempotent staging", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		request, _ := fixture.release(t, "v1.2.3", "boundary-idempotent")
		if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
			t.Fatal(err)
		}
		stateBefore, err := os.ReadFile(fixture.layout.StatePath)
		if err != nil {
			t.Fatal(err)
		}
		attestationCalls := 0
		var replacement *instance.InitializationLease
		installReplacementHook(fixture, &attestationCalls, &replacement)
		stageBefore, supportBefore, initializeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls

		_, err = applyConfirmed(t, fixture.lifecycle, request)
		finishReplacement(t, err, attestationCalls, 3, replacement)
		if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
			t.Fatalf("idempotent boundary created journal: %v", err)
		}
		stateAfter, readErr := os.ReadFile(fixture.layout.StatePath)
		if readErr != nil || !bytes.Equal(stateAfter, stateBefore) {
			t.Fatalf("idempotent boundary changed state bytes err=%v", readErr)
		}
		if fixture.stageCalls != stageBefore || fixture.supportStageCalls != supportBefore || fixture.initializeCalls != initializeBefore {
			t.Fatalf("idempotent boundary reached stage/support/init=%d/%d/%d", fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
		}
	})
}

func TestIdempotentRepairReattestsInitializationLeaseAtEveryMutationAndReturn(t *testing.T) {
	for _, testCase := range []struct {
		name            string
		targetCall      int
		wantStage       int
		wantSupport     int
		wantInitialize  int
		wantManagerLive bool
	}{
		{name: "artifact publication", targetCall: 4, wantStage: 0, wantSupport: 0, wantManagerLive: true},
		{name: "license publication", targetCall: 5, wantStage: 1, wantSupport: 0, wantManagerLive: true},
		{name: "notice publication", targetCall: 6, wantStage: 1, wantSupport: 1, wantManagerLive: true},
		{name: "successful return", targetCall: 7, wantStage: 1, wantSupport: 2, wantManagerLive: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newLifecycleFixture(t, false)
			request, desired := fixture.release(t, "v1.2.3", "idempotent-repair-"+testCase.name)
			if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
				t.Fatal(err)
			}
			stateBefore, err := os.ReadFile(fixture.layout.StatePath)
			if err != nil {
				t.Fatal(err)
			}
			fixture.lifecycle.verifyPreviewRelease = func(context.Context, InstalledRelease) error {
				return errInstalledReleaseFilesMissing
			}
			originalAcquire := fixture.lifecycle.acquireInstanceLease
			attestationCalls := 0
			var replacement *instance.InitializationLease
			fixture.lifecycle.acquireInstanceLease = func(stateDir string, initializationLockPresent bool) (instanceInitializationLease, error) {
				lease, err := originalAcquire(stateDir, initializationLockPresent)
				if err != nil {
					return nil, err
				}
				return replaceInitializationLockAtAttestation(
					lease,
					stateDir,
					testCase.targetCall,
					&attestationCalls,
					&replacement,
				), nil
			}
			stageBefore, supportBefore, initializeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls

			_, err = applyConfirmed(t, fixture.lifecycle, request)
			if replacement == nil {
				t.Fatal("idempotent repair did not acquire the replacement initialization lock")
			}
			if closeErr := replacement.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if attestationCalls != testCase.targetCall || !errors.Is(err, ErrDeploymentPreviewConfirmationMismatch) ||
				!strings.Contains(err.Error(), "leased initialization lock path changed") {
				t.Fatalf("idempotent repair attestation calls=%d error=%v", attestationCalls, err)
			}
			if fixture.stageCalls-stageBefore != testCase.wantStage || fixture.supportStageCalls-supportBefore != testCase.wantSupport ||
				fixture.initializeCalls-initializeBefore != testCase.wantInitialize {
				t.Fatalf("idempotent repair stage/support/init=%d/%d/%d", fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
			}
			if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
				t.Fatalf("idempotent repair created journal: %v", err)
			}
			stateAfter, err := os.ReadFile(fixture.layout.StatePath)
			if err != nil || !bytes.Equal(stateAfter, stateBefore) {
				t.Fatalf("idempotent repair changed state bytes: equal=%v err=%v", bytes.Equal(stateAfter, stateBefore), err)
			}
			if fixture.manager.active != testCase.wantManagerLive || fixture.manager.current != identityFor(desired) {
				t.Fatalf("idempotent repair changed active service: active=%t identity=%+v", fixture.manager.active, fixture.manager.current)
			}
		})
	}
}

func TestApplyReattestsInitializationLeaseAfterVersionDirectoryBeforeArtifactPublication(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, desired := fixture.release(t, "v1.2.3", "forward-artifact-publication")
	fixture.lifecycle.failAfterPhase = PhasePlanned
	if _, err := applyConfirmed(t, fixture.lifecycle, request); !errors.Is(err, ErrInjectedDeploymentCrash) {
		t.Fatalf("injected planned apply error=%v", err)
	}
	fixture.lifecycle.failAfterPhase = ""
	journalBefore, err := os.ReadFile(fixture.layout.JournalPath)
	if err != nil {
		t.Fatal(err)
	}
	attestationCalls := 0
	var replacement *instance.InitializationLease
	originalAcquire := fixture.lifecycle.acquireInstanceLease
	fixture.lifecycle.acquireInstanceLease = func(stateDir string, initializationLockPresent bool) (instanceInitializationLease, error) {
		lease, err := originalAcquire(stateDir, initializationLockPresent)
		if err != nil {
			return nil, err
		}
		return replaceInitializationLockAtAttestation(lease, stateDir, 4, &attestationCalls, &replacement), nil
	}
	stageBefore, supportBefore, initializeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls

	_, err = applyConfirmed(t, fixture.lifecycle, request)
	if replacement == nil {
		t.Fatal("forward artifact boundary did not acquire the replacement initialization lock")
	}
	if closeErr := replacement.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if attestationCalls != 5 || !errors.Is(err, ErrDeploymentPreviewConfirmationMismatch) ||
		!strings.Contains(err.Error(), "leased initialization lock path changed") {
		t.Fatalf("forward artifact boundary attestation calls=%d error=%v", attestationCalls, err)
	}
	journalAfter, err := os.ReadFile(fixture.layout.JournalPath)
	if err != nil || !bytes.Equal(journalAfter, journalBefore) {
		t.Fatalf("forward artifact boundary changed journal: equal=%v err=%v", bytes.Equal(journalAfter, journalBefore), err)
	}
	journal, err := LoadJournal(fixture.layout)
	if err != nil || journal.Phase != PhasePlanned || journal.Desired == nil || *journal.Desired != desired {
		t.Fatalf("forward artifact recovery journal=%+v err=%v", journal, err)
	}
	if fixture.stageCalls != stageBefore || fixture.supportStageCalls != supportBefore || fixture.initializeCalls != initializeBefore {
		t.Fatalf("forward artifact boundary stage/support/init=%d/%d/%d", fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
	}
	if _, err := LoadState(fixture.layout); !errors.Is(err, ErrNoDeploymentState) {
		t.Fatalf("forward artifact boundary created state: %v", err)
	}
	if _, err := os.Lstat(desired.BinaryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("forward artifact boundary published binary: %v", err)
	}
}

func TestApplyReattestsInitializationLeaseBeforeForwardServiceMutations(t *testing.T) {
	replaceInitializationLock := func(stateDir string) (*instance.InitializationLease, error) {
		lockPath := filepath.Join(stateDir, ".instance.lock")
		if err := os.Remove(lockPath); err != nil {
			return nil, err
		}
		if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
			return nil, err
		}
		return instance.AcquireInitializationLeaseWithLockPresence(stateDir, true)
	}
	installPhaseReplacement := func(fixture *lifecycleFixture, target Phase) **instance.InitializationLease {
		replacement := new(*instance.InitializationLease)
		originalAcquire := fixture.lifecycle.acquireInstanceLease
		fixture.lifecycle.acquireInstanceLease = func(stateDir string, initializationLockPresent bool) (instanceInitializationLease, error) {
			lease, err := originalAcquire(stateDir, initializationLockPresent)
			if err != nil {
				return nil, err
			}
			return &testInitializationLease{
				initialize: lease.Initialize,
				created:    lease.InitializationLockCreated(),
				attest: func() error {
					journal, journalErr := LoadJournal(fixture.layout)
					if *replacement == nil && journalErr == nil && journal.Phase == target {
						acquired, replaceErr := replaceInitializationLock(stateDir)
						if replaceErr != nil {
							return replaceErr
						}
						*replacement = acquired
					}
					return lease.AttestLockPath()
				},
				close: lease.Close,
			}, nil
		}
		return replacement
	}
	assertReplacementMismatch := func(t *testing.T, err error, replacement **instance.InitializationLease) {
		t.Helper()
		if replacement == nil || *replacement == nil {
			t.Fatal("forward service boundary did not acquire the replacement initialization lock")
		}
		if closeErr := (*replacement).Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if !errors.Is(err, ErrDeploymentPreviewConfirmationMismatch) || !strings.Contains(err.Error(), "leased initialization lock path changed") {
			t.Fatalf("forward service mutation attestation error=%v", err)
		}
	}
	countCall := func(calls []string, target string) int {
		count := 0
		for _, call := range calls {
			if call == target {
				count++
			}
		}
		return count
	}

	for _, testCase := range []struct {
		name         string
		targetPhase  Phase
		wantPhase    Phase
		wantStop     int
		wantInstall  int
		wantActivate int
		wantActive   bool
		wantPending  string
	}{
		{name: "stop prior", targetPhase: PhaseInstanceReady, wantPhase: PhaseInstanceReady, wantActive: true},
		{name: "install definition", targetPhase: PhasePriorServiceStopped, wantPhase: PhasePriorServiceStopped, wantStop: 1},
		{name: "activate desired", targetPhase: PhaseDefinitionInstalled, wantPhase: PhaseDefinitionInstalled, wantStop: 1, wantInstall: 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newLifecycleFixture(t, false)
			installedRequest, installed := fixture.release(t, "v1.2.3", "forward-service-installed-"+testCase.name)
			if _, err := applyConfirmed(t, fixture.lifecycle, installedRequest); err != nil {
				t.Fatal(err)
			}
			stateBefore, err := os.ReadFile(fixture.layout.StatePath)
			if err != nil {
				t.Fatal(err)
			}
			upgrade, desired := fixture.release(t, "v1.2.4", "forward-service-upgrade-"+testCase.name)
			if testCase.name == "stop prior" || testCase.name == "install definition" {
				testCase.wantPending = installed.BinaryPath
			} else {
				testCase.wantPending = desired.BinaryPath
			}
			replacement := installPhaseReplacement(fixture, testCase.targetPhase)
			managerCallsBefore := len(fixture.manager.calls)

			_, err = applyConfirmed(t, fixture.lifecycle, upgrade)
			assertReplacementMismatch(t, err, replacement)
			journal, err := LoadJournal(fixture.layout)
			if err != nil || journal.Phase != testCase.wantPhase || journal.Desired == nil || *journal.Desired != desired {
				t.Fatalf("forward service recovery journal=%+v err=%v", journal, err)
			}
			stateAfter, err := os.ReadFile(fixture.layout.StatePath)
			if err != nil || !bytes.Equal(stateAfter, stateBefore) {
				t.Fatalf("forward service mutation changed state: equal=%v err=%v", bytes.Equal(stateAfter, stateBefore), err)
			}
			calls := fixture.manager.calls[managerCallsBefore:]
			if countCall(calls, "stop") != testCase.wantStop || countCall(calls, "install") != testCase.wantInstall ||
				countCall(calls, "activate") != testCase.wantActivate || countCall(calls, "remove") != 0 {
				t.Fatalf("forward service calls=%v", calls)
			}
			if fixture.manager.active != testCase.wantActive || fixture.manager.pending != testCase.wantPending {
				t.Fatalf("forward service state active=%t pending=%q", fixture.manager.active, fixture.manager.pending)
			}
		})
	}

	t.Run("stop conflicting active service before activation", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		installedRequest, installed := fixture.release(t, "v1.2.3", "forward-activation-conflict-installed")
		if _, err := applyConfirmed(t, fixture.lifecycle, installedRequest); err != nil {
			t.Fatal(err)
		}
		stateBefore, err := os.ReadFile(fixture.layout.StatePath)
		if err != nil {
			t.Fatal(err)
		}
		upgrade, desired := fixture.release(t, "v1.2.4", "forward-activation-conflict-upgrade")
		var replacement *instance.InitializationLease
		injectedConflict := false
		originalAcquire := fixture.lifecycle.acquireInstanceLease
		fixture.lifecycle.acquireInstanceLease = func(stateDir string, initializationLockPresent bool) (instanceInitializationLease, error) {
			lease, err := originalAcquire(stateDir, initializationLockPresent)
			if err != nil {
				return nil, err
			}
			return &testInitializationLease{
				initialize: lease.Initialize,
				created:    lease.InitializationLockCreated(),
				attest: func() error {
					journal, journalErr := LoadJournal(fixture.layout)
					if journalErr == nil && journal.Phase == PhasePriorServiceStopped && fixture.manager.pending == desired.BinaryPath && !injectedConflict {
						fixture.manager.active = true
						fixture.manager.current = identityFor(installed)
						injectedConflict = true
					}
					if journalErr == nil && journal.Phase == PhaseDefinitionInstalled && injectedConflict && replacement == nil {
						acquired, replaceErr := replaceInitializationLock(stateDir)
						if replaceErr != nil {
							return replaceErr
						}
						replacement = acquired
					}
					return lease.AttestLockPath()
				},
				close: lease.Close,
			}, nil
		}
		managerCallsBefore := len(fixture.manager.calls)

		_, err = applyConfirmed(t, fixture.lifecycle, upgrade)
		if !injectedConflict {
			t.Fatal("activation test did not inject the conflicting active service")
		}
		if replacement == nil {
			t.Fatal("activation conflict did not acquire the replacement initialization lock")
		}
		if closeErr := replacement.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if !errors.Is(err, ErrDeploymentPreviewConfirmationMismatch) || !strings.Contains(err.Error(), "leased initialization lock path changed") {
			t.Fatalf("activation conflict attestation error=%v", err)
		}
		journal, err := LoadJournal(fixture.layout)
		if err != nil || journal.Phase != PhaseDefinitionInstalled || journal.Desired == nil || *journal.Desired != desired {
			t.Fatalf("activation conflict recovery journal=%+v err=%v", journal, err)
		}
		stateAfter, err := os.ReadFile(fixture.layout.StatePath)
		if err != nil || !bytes.Equal(stateAfter, stateBefore) {
			t.Fatalf("activation conflict changed state: equal=%v err=%v", bytes.Equal(stateAfter, stateBefore), err)
		}
		calls := fixture.manager.calls[managerCallsBefore:]
		if countCall(calls, "stop") != 1 || countCall(calls, "install") != 1 || countCall(calls, "activate") != 0 || countCall(calls, "remove") != 0 {
			t.Fatalf("activation conflict service calls=%v", calls)
		}
		if !fixture.manager.active || fixture.manager.current != identityFor(installed) || fixture.manager.pending != desired.BinaryPath {
			t.Fatalf("activation conflict mutated protected service: active=%t current=%+v pending=%q", fixture.manager.active, fixture.manager.current, fixture.manager.pending)
		}
	})
}

func TestApplyPreservesArtifactStagedJournalWhenInitializationLeasePathChanges(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, _ := fixture.release(t, "v1.2.3", "initialize-attestation-evidence")
	originalAcquire := fixture.lifecycle.acquireInstanceLease
	var replacement *instance.InitializationLease
	fixture.lifecycle.acquireInstanceLease = func(stateDir string, initializationLockPresent bool) (instanceInitializationLease, error) {
		lease, err := originalAcquire(stateDir, initializationLockPresent)
		if err != nil {
			return nil, err
		}
		return &testInitializationLease{
			initialize: func(ctx context.Context, listeners []string) (config.Settings, error) {
				journal, err := LoadJournal(fixture.layout)
				if err != nil || journal.Phase != PhaseArtifactStaged {
					return config.Settings{}, fmt.Errorf("initialize reached before artifact-staged checkpoint: journal=%+v err=%v", journal, err)
				}
				lockPath := filepath.Join(stateDir, ".instance.lock")
				if err := os.Remove(lockPath); err != nil {
					return config.Settings{}, err
				}
				if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
					return config.Settings{}, err
				}
				replacement, err = instance.AcquireInitializationLeaseWithLockPresence(stateDir, true)
				if err != nil {
					return config.Settings{}, err
				}
				return lease.Initialize(ctx, listeners)
			},
			created: lease.InitializationLockCreated(),
			attest:  lease.AttestLockPath,
			close:   lease.Close,
		}, nil
	}
	stageBefore, supportBefore, initializeBefore, removeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls, fixture.removeCalls

	_, err := applyConfirmed(t, fixture.lifecycle, request)
	if replacement == nil {
		t.Fatal("replacement initialization lock was not acquired before Initialize")
	}
	if closeErr := replacement.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if !errors.Is(err, ErrDeploymentPreviewConfirmationMismatch) || !strings.Contains(err.Error(), "leased initialization lock path changed") {
		t.Fatalf("initialization attestation error=%v", err)
	}
	journal, err := LoadJournal(fixture.layout)
	if err != nil || journal.Phase != PhaseArtifactStaged {
		t.Fatalf("initialization attestation lost recovery journal=%+v err=%v", journal, err)
	}
	if fixture.stageCalls-stageBefore != 1 || fixture.supportStageCalls-supportBefore != 2 || fixture.initializeCalls-initializeBefore != 1 {
		t.Fatalf("initialization attestation stage/support/init=%d/%d/%d", fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
	}
	if fixture.removeCalls != removeBefore {
		t.Fatalf("initialization attestation ran artifact rollback: remove calls=%d", fixture.removeCalls-removeBefore)
	}
	if _, err := LoadState(fixture.layout); !errors.Is(err, ErrNoDeploymentState) {
		t.Fatalf("initialization attestation created deployment state: %v", err)
	}
	paths := config.ForStateDir(fixture.layout.StateDir)
	for _, path := range []string{paths.InstallMarker, paths.Config, paths.InstanceSecret, paths.Database} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("initialization attestation mutated instance path %s: %v", path, err)
		}
	}
}

func TestApplyReattestsInitializationLeaseAfterRunApplyFailureBeforeRollback(t *testing.T) {
	replaceInitializationLock := func(stateDir string) (*instance.InitializationLease, error) {
		lockPath := filepath.Join(stateDir, ".instance.lock")
		if err := os.Remove(lockPath); err != nil {
			return nil, err
		}
		if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
			return nil, err
		}
		return instance.AcquireInitializationLeaseWithLockPresence(stateDir, true)
	}
	assertLeaseMismatch := func(t *testing.T, err error, replacement *instance.InitializationLease) {
		t.Helper()
		if replacement == nil {
			t.Fatal("replacement initialization lock was not acquired during the failing operation")
		}
		if closeErr := replacement.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if !errors.Is(err, ErrDeploymentPreviewConfirmationMismatch) || !strings.Contains(err.Error(), "leased initialization lock path changed") {
			t.Fatalf("post-runApply lease attestation error=%v", err)
		}
	}
	assertNoManagerRollback := func(t *testing.T, calls []string) {
		t.Helper()
		for _, call := range calls {
			if call == "install" || call == "activate" || call == "remove" {
				t.Fatalf("orphaned initialization lease reached manager rollback: %v", calls)
			}
		}
	}

	for _, matchingJournal := range []bool{false, true} {
		name := "new transaction artifact publication"
		if matchingJournal {
			name = "matching journal artifact publication"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newLifecycleFixture(t, false)
			request, desired := fixture.release(t, "v1.2.3", "post-runApply-artifact-failure")
			var journalBefore []byte
			if matchingJournal {
				fixture.lifecycle.failAfterPhase = PhasePlanned
				if _, err := applyConfirmed(t, fixture.lifecycle, request); !errors.Is(err, ErrInjectedDeploymentCrash) {
					t.Fatalf("injected planned apply error=%v", err)
				}
				fixture.lifecycle.failAfterPhase = ""
				var err error
				journalBefore, err = os.ReadFile(fixture.layout.JournalPath)
				if err != nil {
					t.Fatal(err)
				}
			}
			originalStage := fixture.lifecycle.stageArtifact
			var replacement *instance.InitializationLease
			fixture.lifecycle.stageArtifact = func(source, destination, artifactName string, artifactBytes int64, artifactSHA256 string) (string, error) {
				var err error
				replacement, err = replaceInitializationLock(fixture.layout.StateDir)
				if err != nil {
					return "", err
				}
				if _, err := originalStage(source, destination, artifactName, artifactBytes, artifactSHA256); err != nil {
					return "", err
				}
				return "", errors.New("injected artifact publication failure")
			}
			stageBefore, supportBefore, initializeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls
			managerCallsBefore := len(fixture.manager.calls)

			_, err := applyConfirmed(t, fixture.lifecycle, request)
			assertLeaseMismatch(t, err, replacement)
			journal, err := LoadJournal(fixture.layout)
			if err != nil || journal.Phase != PhasePlanned || journal.Desired == nil || *journal.Desired != desired {
				t.Fatalf("artifact failure recovery journal=%+v err=%v", journal, err)
			}
			if matchingJournal {
				journalAfter, err := os.ReadFile(fixture.layout.JournalPath)
				if err != nil || !bytes.Equal(journalAfter, journalBefore) {
					t.Fatalf("matching artifact failure changed journal bytes: equal=%v err=%v", bytes.Equal(journalAfter, journalBefore), err)
				}
			}
			if fixture.stageCalls-stageBefore != 1 || fixture.supportStageCalls != supportBefore || fixture.initializeCalls != initializeBefore {
				t.Fatalf("artifact failure stage/support/init=%d/%d/%d", fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
			}
			if _, err := LoadState(fixture.layout); !errors.Is(err, ErrNoDeploymentState) {
				t.Fatalf("artifact failure created deployment state: %v", err)
			}
			assertNoManagerRollback(t, fixture.manager.calls[managerCallsBefore:])
		})
	}

	t.Run("service rendering after prior service stopped", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		installedRequest, installed := fixture.release(t, "v1.2.3", "post-runApply-service-installed")
		if _, err := applyConfirmed(t, fixture.lifecycle, installedRequest); err != nil {
			t.Fatal(err)
		}
		stateBefore, err := os.ReadFile(fixture.layout.StatePath)
		if err != nil {
			t.Fatal(err)
		}
		upgrade, desired := fixture.release(t, "v1.2.4", "post-runApply-service-upgrade")
		originalRender := fixture.lifecycle.renderService
		var replacement *instance.InitializationLease
		renderCalls := 0
		fixture.lifecycle.renderService = func(targetOS, binaryPath, stateDir string) ([]byte, error) {
			renderCalls++
			if renderCalls == 1 {
				var err error
				replacement, err = replaceInitializationLock(stateDir)
				if err != nil {
					return nil, err
				}
				return nil, errors.New("injected service rendering failure")
			}
			return originalRender(targetOS, binaryPath, stateDir)
		}
		managerCallsBefore := len(fixture.manager.calls)

		_, err = applyConfirmed(t, fixture.lifecycle, upgrade)
		assertLeaseMismatch(t, err, replacement)
		journal, err := LoadJournal(fixture.layout)
		if err != nil || journal.Phase != PhasePriorServiceStopped || journal.Desired == nil || *journal.Desired != desired ||
			journal.PriorState == nil || journal.PriorState.Active == nil || *journal.PriorState.Active != installed {
			t.Fatalf("service failure recovery journal=%+v err=%v", journal, err)
		}
		stateAfter, err := os.ReadFile(fixture.layout.StatePath)
		if err != nil || !bytes.Equal(stateAfter, stateBefore) {
			t.Fatalf("service failure changed deployment state: equal=%v err=%v", bytes.Equal(stateAfter, stateBefore), err)
		}
		if fixture.manager.active {
			t.Fatal("service failure rollback reactivated the stopped prior service under an orphaned lease")
		}
		if renderCalls != 1 {
			t.Fatalf("service failure entered rollback rendering: calls=%d", renderCalls)
		}
		calls := fixture.manager.calls[managerCallsBefore:]
		stopped := false
		for _, call := range calls {
			stopped = stopped || call == "stop"
		}
		if !stopped {
			t.Fatalf("service failure did not reach the post-stop window: %v", calls)
		}
		assertNoManagerRollback(t, calls)
	})
}

func TestApplyReattestsInitializationLeaseAtRollbackMutationBoundaries(t *testing.T) {
	replaceInitializationLock := func(stateDir string) (*instance.InitializationLease, error) {
		lockPath := filepath.Join(stateDir, ".instance.lock")
		if err := os.Remove(lockPath); err != nil {
			return nil, err
		}
		if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
			return nil, err
		}
		return instance.AcquireInitializationLeaseWithLockPresence(stateDir, true)
	}
	installRollbackReplacement := func(
		fixture *lifecycleFixture,
		failureObserved *bool,
		replaceWhen func(int) bool,
	) **instance.InitializationLease {
		replacement := new(*instance.InitializationLease)
		postFailureAttestations := 0
		originalAcquire := fixture.lifecycle.acquireInstanceLease
		fixture.lifecycle.acquireInstanceLease = func(stateDir string, initializationLockPresent bool) (instanceInitializationLease, error) {
			lease, err := originalAcquire(stateDir, initializationLockPresent)
			if err != nil {
				return nil, err
			}
			return &testInitializationLease{
				initialize: lease.Initialize,
				created:    lease.InitializationLockCreated(),
				attest: func() error {
					if *failureObserved {
						postFailureAttestations++
						if *replacement == nil && replaceWhen(postFailureAttestations) {
							acquired, replaceErr := replaceInitializationLock(stateDir)
							if replaceErr != nil {
								return replaceErr
							}
							*replacement = acquired
						}
					}
					return lease.AttestLockPath()
				},
				close: lease.Close,
			}, nil
		}
		return replacement
	}
	assertReplacementMismatch := func(t *testing.T, err error, replacement **instance.InitializationLease) {
		t.Helper()
		if replacement == nil || *replacement == nil {
			t.Fatal("rollback mutation boundary did not acquire the replacement initialization lock")
		}
		if closeErr := (*replacement).Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if !errors.Is(err, ErrDeploymentPreviewConfirmationMismatch) || !strings.Contains(err.Error(), "leased initialization lock path changed") {
			t.Fatalf("rollback mutation attestation error=%v", err)
		}
	}

	t.Run("journal removal", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		request, desired := fixture.release(t, "v1.2.3", "rollback-boundary-journal")
		failureObserved := false
		replacement := installRollbackReplacement(fixture, &failureObserved, func(postFailureAttestations int) bool {
			// The first attestation is the post-runApply classification; the
			// second is immediately before rollback removes the journal.
			return postFailureAttestations == 2
		})
		originalStage := fixture.lifecycle.stageArtifact
		fixture.lifecycle.stageArtifact = func(source, destination, artifactName string, artifactBytes int64, artifactSHA256 string) (string, error) {
			if _, err := originalStage(source, destination, artifactName, artifactBytes, artifactSHA256); err != nil {
				return "", err
			}
			failureObserved = true
			return "", errors.New("injected artifact failure before rollback journal removal")
		}

		_, err := applyConfirmed(t, fixture.lifecycle, request)
		assertReplacementMismatch(t, err, replacement)
		journal, err := LoadJournal(fixture.layout)
		if err != nil || journal.Phase != PhasePlanned || journal.Desired == nil || *journal.Desired != desired {
			t.Fatalf("journal-boundary recovery evidence=%+v err=%v", journal, err)
		}
		if _, err := LoadState(fixture.layout); !errors.Is(err, ErrNoDeploymentState) {
			t.Fatalf("journal-boundary rollback created state: %v", err)
		}
	})

	t.Run("service removal", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		installedRequest, installed := fixture.release(t, "v1.2.3", "rollback-boundary-service-installed")
		if _, err := applyConfirmed(t, fixture.lifecycle, installedRequest); err != nil {
			t.Fatal(err)
		}
		stateBefore, err := os.ReadFile(fixture.layout.StatePath)
		if err != nil {
			t.Fatal(err)
		}
		upgrade, desired := fixture.release(t, "v1.2.4", "rollback-boundary-service-upgrade")
		failureObserved := false
		replacement := installRollbackReplacement(fixture, &failureObserved, func(postFailureAttestations int) bool {
			// The first attestation accepts the ordinary runApply error; the
			// second protects rollback's first service mutation.
			return postFailureAttestations == 2
		})
		fixture.lifecycle.renderService = func(_, binaryPath, _ string) ([]byte, error) {
			if binaryPath == desired.BinaryPath {
				failureObserved = true
				return nil, errors.New("injected service rendering failure before rollback removal")
			}
			return []byte(binaryPath), nil
		}
		managerCallsBefore := len(fixture.manager.calls)

		_, err = applyConfirmed(t, fixture.lifecycle, upgrade)
		assertReplacementMismatch(t, err, replacement)
		journal, err := LoadJournal(fixture.layout)
		if err != nil || journal.Phase != PhasePriorServiceStopped || journal.PriorState == nil ||
			journal.PriorState.Active == nil || *journal.PriorState.Active != installed {
			t.Fatalf("service-boundary recovery evidence=%+v err=%v", journal, err)
		}
		stateAfter, err := os.ReadFile(fixture.layout.StatePath)
		if err != nil || !bytes.Equal(stateAfter, stateBefore) {
			t.Fatalf("service-boundary rollback changed state: equal=%v err=%v", bytes.Equal(stateAfter, stateBefore), err)
		}
		if fixture.manager.active {
			t.Fatal("service-boundary rollback reactivated the stopped prior service")
		}
		calls := fixture.manager.calls[managerCallsBefore:]
		for _, call := range calls {
			if call == "remove" || call == "install" || call == "activate" {
				t.Fatalf("service-boundary rollback mutated manager state: %v", calls)
			}
		}
	})

	t.Run("deployment state save", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		installedRequest, installed := fixture.release(t, "v1.2.3", "rollback-boundary-state-installed")
		if _, err := applyConfirmed(t, fixture.lifecycle, installedRequest); err != nil {
			t.Fatal(err)
		}
		stateBefore, err := os.ReadFile(fixture.layout.StatePath)
		if err != nil {
			t.Fatal(err)
		}
		stateInfoBefore, err := os.Stat(fixture.layout.StatePath)
		if err != nil {
			t.Fatal(err)
		}
		upgrade, desired := fixture.release(t, "v1.2.4", "rollback-boundary-state-upgrade")
		failureObserved := false
		replacement := installRollbackReplacement(fixture, &failureObserved, func(_ int) bool {
			// Rollback reactivates the prior service before attempting to save
			// its state. Replace the lock only at that state-save boundary.
			return fixture.manager.active
		})
		renderCalls := 0
		fixture.lifecycle.renderService = func(_, binaryPath, _ string) ([]byte, error) {
			renderCalls++
			if binaryPath == desired.BinaryPath {
				failureObserved = true
				return nil, errors.New("injected service rendering failure before rollback state save")
			}
			return []byte(binaryPath), nil
		}

		_, err = applyConfirmed(t, fixture.lifecycle, upgrade)
		assertReplacementMismatch(t, err, replacement)
		journal, err := LoadJournal(fixture.layout)
		if err != nil || journal.Phase != PhasePriorServiceStopped || journal.PriorState == nil ||
			journal.PriorState.Active == nil || *journal.PriorState.Active != installed {
			t.Fatalf("state-boundary recovery evidence=%+v err=%v", journal, err)
		}
		stateAfter, err := os.ReadFile(fixture.layout.StatePath)
		if err != nil || !bytes.Equal(stateAfter, stateBefore) {
			t.Fatalf("state-boundary rollback changed state bytes: equal=%v err=%v", bytes.Equal(stateAfter, stateBefore), err)
		}
		stateInfoAfter, err := os.Stat(fixture.layout.StatePath)
		if err != nil || !os.SameFile(stateInfoBefore, stateInfoAfter) {
			t.Fatalf("state-boundary rollback replaced deployment state: same=%v err=%v", err == nil && os.SameFile(stateInfoBefore, stateInfoAfter), err)
		}
		if !fixture.manager.active || fixture.manager.current != identityFor(installed) {
			t.Fatalf("state-boundary setup did not complete service rollback: active=%t identity=%+v", fixture.manager.active, fixture.manager.current)
		}
		if renderCalls != 2 {
			t.Fatalf("state-boundary rollback render calls=%d", renderCalls)
		}
	})
}

func TestApplyResumesReviewedDatabaseStatesUnderInitializationLease(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*testing.T, config.Paths)
	}{
		{
			name: "empty protected database",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				if err := os.WriteFile(paths.Database, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "reviewed prior acceptance-origin schema",
			mutate: func(t *testing.T, paths config.Paths) {
				t.Helper()
				database, err := sql.Open("sqlite3", "file:"+paths.Database)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := database.Exec("DROP TABLE revision_acceptance_origins"); err != nil {
					database.Close()
					t.Fatal(err)
				}
				if err := database.Close(); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newLifecycleFixture(t, false)
			first, _ := fixture.release(t, "v1.2.3", "resumable-database-first-"+testCase.name)
			if _, err := applyConfirmed(t, fixture.lifecycle, first); err != nil {
				t.Fatal(err)
			}
			paths := config.ForStateDir(fixture.layout.StateDir)
			for _, suffix := range []string{"-wal", "-shm", "-journal"} {
				if err := os.Remove(paths.Database + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
			}
			testCase.mutate(t, paths)
			if err := config.SaveMarker(paths.InstallMarker, config.InstallMarker{Generation: "1", Phase: "initializing", State: "resume"}); err != nil {
				t.Fatal(err)
			}
			upgrade, desired := fixture.release(t, "v1.2.4", "resumable-database-upgrade-"+testCase.name)
			result, err := applyConfirmed(t, fixture.lifecycle, upgrade)
			if err != nil {
				t.Fatal(err)
			}
			if result.State.Active == nil || *result.State.Active != desired {
				t.Fatalf("resumable database apply result=%+v", result)
			}
			opened, err := instance.Open(context.Background(), fixture.layout.StateDir)
			if err != nil {
				t.Fatalf("open resumed instance: %v", err)
			}
			if err := opened.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVerifiedLocatorSurvivesRepeatedUpgradesAndStatusRefreshesNewestActivePath(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	var installed []InstalledRelease
	var newestLocator DeploymentLocator
	for index, version := range []string{"v1.2.3", "v1.2.4", "v1.2.5"} {
		request, release := fixture.release(t, version, fmt.Sprint(index))
		result, err := applyConfirmed(t, fixture.lifecycle, request)
		if err != nil {
			t.Fatal(err)
		}
		if result.State.Active == nil || *result.State.Active != release {
			t.Fatalf("upgrade %s active state=%+v", version, result.State.Active)
		}
		assertDeploymentLocator(t, result.DeploymentLocator, fixture.layout, release)
		newestLocator = result.DeploymentLocator
		installed = append(installed, release)
	}
	if fixture.removeCalls != 0 {
		t.Fatalf("supported upgrades removed immutable release artifacts %d times", fixture.removeCalls)
	}
	for _, release := range installed {
		identity, err := fixture.lifecycle.inspector.Inspect(
			context.Background(),
			release.BinaryPath,
		)
		if err != nil || identity != identityFor(release) {
			t.Fatalf("retained locator %s identity=%+v err=%v", release.BinaryPath, identity, err)
		}
	}
	status, err := fixture.lifecycle.Status(context.Background())
	if err != nil || status.Status != "active" || !status.Running || status.State == nil ||
		status.State.Active == nil || status.State.Active.BinaryPath != installed[len(installed)-1].BinaryPath {
		t.Fatalf("refreshed newest status=%+v err=%v", status, err)
	}
	assertDeploymentLocator(t, newestLocator, fixture.layout, installed[len(installed)-1])
	if _, err := fixture.lifecycle.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fixture.removeCalls != 1 {
		t.Fatalf("explicit uninstall artifact removals=%d want=1", fixture.removeCalls)
	}
}

func TestApplyTransactionResumesAfterEveryDurablePhase(t *testing.T) {
	phases := []Phase{
		PhasePlanned,
		PhaseArtifactStaged,
		PhaseInstanceReady,
		PhasePriorServiceStopped,
		PhaseDefinitionInstalled,
		PhaseActivated,
		PhaseHealthVerified,
		PhaseCommitting,
		PhaseStateSaved,
	}
	for _, phase := range phases {
		t.Run(string(phase), func(t *testing.T) {
			fixture := newLifecycleFixture(t, false)
			request, desired := fixture.release(t, "v1.2.3", "b")
			fixture.lifecycle.failAfterPhase = phase
			if _, err := applyConfirmed(t, fixture.lifecycle, request); !errors.Is(err, ErrInjectedDeploymentCrash) {
				t.Fatalf("crash error = %v", err)
			}
			journal, err := LoadJournal(fixture.layout)
			if err != nil {
				t.Fatal(err)
			}
			if journal.Phase != phase {
				t.Fatalf("journal phase=%s want=%s", journal.Phase, phase)
			}
			fixture.lifecycle.failAfterPhase = ""
			request.ArtifactPath = filepath.Join(fixture.layout.HomeDir, "download-retry", "sshserver")
			result, err := applyConfirmed(t, fixture.lifecycle, request)
			if err != nil {
				t.Fatal(err)
			}
			if result.State.Active == nil || *result.State.Active != desired || result.State.Status != StatusActive {
				t.Fatalf("resumed result=%+v", result)
			}
			assertDeploymentLocator(t, result.DeploymentLocator, fixture.layout, desired)
			if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
				t.Fatalf("resumed journal error=%v", err)
			}
		})
	}
}

func TestApplyFailureRollsBackExactPriorReleaseAndPreservesInstance(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	firstRequest, firstRelease := fixture.release(t, "v1.2.3", "c")
	if _, err := applyConfirmed(t, fixture.lifecycle, firstRequest); err != nil {
		t.Fatal(err)
	}
	openedBefore, err := instance.Open(context.Background(), fixture.layout.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	instanceID, vaultID := openedBefore.Settings.InstanceID, openedBefore.Settings.VaultID
	if err := openedBefore.Close(); err != nil {
		t.Fatal(err)
	}

	secondRequest, _ := fixture.release(t, "v1.2.4", "d")
	fixture.manager.failures["activate"] = 1
	failed, err := applyConfirmed(t, fixture.lifecycle, secondRequest)
	if err == nil || !strings.Contains(err.Error(), "activate") {
		t.Fatalf("failed upgrade error = %v", err)
	}
	if failed.DeploymentLocator != (DeploymentLocator{}) {
		t.Fatalf("failed apply returned deployment locator: %+v", failed.DeploymentLocator)
	}
	state, err := LoadState(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if state.Active == nil || *state.Active != firstRelease || state.Generation != 1 {
		t.Fatalf("state after rollback=%+v", state)
	}
	if fixture.manager.current != identityFor(firstRelease) || !fixture.manager.active {
		t.Fatalf("running identity after rollback=%+v active=%v", fixture.manager.current, fixture.manager.active)
	}
	openedAfter, err := instance.Open(context.Background(), fixture.layout.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer openedAfter.Close()
	if openedAfter.Settings.InstanceID != instanceID || openedAfter.Settings.VaultID != vaultID {
		t.Fatal("failed upgrade changed the protected instance identity")
	}
	if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("rollback journal error=%v", err)
	}
}

func TestApplyForegroundFallbackIsStructuredAndNeverClaimsActivation(t *testing.T) {
	fixture := newLifecycleFixture(t, true)
	request, desired := fixture.release(t, "v1.2.3", "e")
	result, err := applyConfirmed(t, fixture.lifecycle, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "foreground_required" || result.State.Status != StatusForeground || result.Foreground == nil ||
		!result.Foreground.Required || !result.Foreground.Supervised {
		t.Fatalf("foreground result=%+v", result)
	}
	assertDeploymentLocator(t, result.DeploymentLocator, fixture.layout, desired)
	wantCommand := []string{desired.BinaryPath, "serve", "--state-dir", fixture.layout.StateDir}
	if fmt.Sprint(result.Foreground.Command) != fmt.Sprint(wantCommand) {
		t.Fatalf("foreground command=%q want=%q", result.Foreground.Command, wantCommand)
	}
	for _, call := range fixture.manager.calls {
		if call == "install" || call == "activate" || call == "is-active" {
			t.Fatalf("foreground apply invoked native manager: %v", fixture.manager.calls)
		}
	}
	if fixture.probeCalls != 0 {
		t.Fatalf("foreground install claimed running health with %d probes", fixture.probeCalls)
	}
}

func TestApplyRefusesImplicitFallbackForActiveNativeService(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	first, _ := fixture.release(t, "v1.2.3", "1")
	if _, err := applyConfirmed(t, fixture.lifecycle, first); err != nil {
		t.Fatal(err)
	}
	fixture.manager.availability = foregroundAvailability(fixture.layout, "/unused")
	second, _ := fixture.release(t, "v1.2.4", "2")
	if _, err := applyConfirmed(t, fixture.lifecycle, second); err == nil || !strings.Contains(err.Error(), "active_native_manager_unavailable") {
		t.Fatalf("implicit fallback error=%v", err)
	}
	state, err := LoadState(fixture.layout)
	if err != nil || state.Active.Release != "v1.2.3" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestApplyRejectsRecordedActiveServiceDefinitionDriftBeforeMutation(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	firstRequest, _ := fixture.release(t, "v1.2.3", "definition-drift-prior")
	if _, err := applyConfirmed(t, fixture.lifecycle, firstRequest); err != nil {
		t.Fatal(err)
	}
	state, err := LoadState(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	state.ServiceDefinition = filepath.Join(fixture.layout.HomeDir, ".config", "systemd", "user", "drifted.service")
	if err := SaveState(fixture.layout, state); err != nil {
		t.Fatal(err)
	}
	secondRequest, secondRelease := fixture.release(t, "v1.2.4", "definition-drift-desired")
	secondReleaseDir, err := fixture.layout.VersionDir(secondRelease.Release)
	if err != nil {
		t.Fatal(err)
	}
	fixture.manager.calls = nil
	stageBefore, supportBefore, initializeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls

	if _, err := applyConfirmed(t, fixture.lifecycle, secondRequest); err == nil || !strings.Contains(err.Error(), "recorded active service definition") {
		t.Fatalf("definition drift error=%v", err)
	}
	if len(fixture.manager.calls) != 0 || fixture.stageCalls != stageBefore || fixture.supportStageCalls != supportBefore || fixture.initializeCalls != initializeBefore {
		t.Fatalf("definition drift reached mutation manager=%v stage/support/init=%d/%d/%d", fixture.manager.calls, fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
	}
	if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("definition drift created journal: %v", err)
	}
	if _, err := os.Lstat(secondReleaseDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("definition drift created desired release directory: %v", err)
	}
	retained, err := LoadState(fixture.layout)
	if err != nil || retained.ServiceDefinition != state.ServiceDefinition || retained.Generation != state.Generation {
		t.Fatalf("definition drift changed state=%+v err=%v", retained, err)
	}
}

func TestApplyRejectsMatchingJournalPriorServiceDefinitionDriftBeforeResume(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	firstRequest, _ := fixture.release(t, "v1.2.3", "journal-definition-prior")
	if _, err := applyConfirmed(t, fixture.lifecycle, firstRequest); err != nil {
		t.Fatal(err)
	}
	prior, err := LoadState(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	prior.ServiceDefinition = filepath.Join(fixture.layout.HomeDir, ".config", "systemd", "user", "drifted.service")
	secondRequest, desired := fixture.release(t, "v1.2.4", "journal-definition-desired")
	journal := DeploymentJournal{
		StateVersion:      DeploymentStateVersion,
		TransactionID:     strings.Repeat("c", 32),
		Operation:         OperationApply,
		Phase:             PhasePlanned,
		Manager:           fixture.manager.kind,
		ServiceDefinition: fixture.manager.definition,
		SourcePath:        secondRequest.ArtifactPath,
		LicenseSourcePath: secondRequest.LicensePath,
		NoticeSourcePath:  secondRequest.NoticePath,
		Desired:           &desired,
		PriorState:        &prior,
	}
	if err := SaveJournal(fixture.layout, journal); err != nil {
		t.Fatal(err)
	}
	if err := RemoveState(fixture.layout); err != nil {
		t.Fatal(err)
	}
	before, err := canonicalDeploymentJSON(journal)
	if err != nil {
		t.Fatal(err)
	}
	desiredReleaseDir, err := fixture.layout.VersionDir(desired.Release)
	if err != nil {
		t.Fatal(err)
	}
	fixture.manager.calls = nil
	stageBefore, supportBefore, initializeBefore := fixture.stageCalls, fixture.supportStageCalls, fixture.initializeCalls

	if _, err := applyConfirmed(t, fixture.lifecycle, secondRequest); err == nil || !strings.Contains(err.Error(), "recorded active service definition") {
		t.Fatalf("journal definition drift error=%v", err)
	}
	if len(fixture.manager.calls) != 0 || fixture.stageCalls != stageBefore || fixture.supportStageCalls != supportBefore || fixture.initializeCalls != initializeBefore {
		t.Fatalf("journal definition drift resumed manager=%v stage/support/init=%d/%d/%d", fixture.manager.calls, fixture.stageCalls-stageBefore, fixture.supportStageCalls-supportBefore, fixture.initializeCalls-initializeBefore)
	}
	afterJournal, err := LoadJournal(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	after, err := canonicalDeploymentJSON(afterJournal)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("rejected journal resume changed journal\n before=%s\n after=%s", before, after)
	}
	if _, err := os.Lstat(desiredReleaseDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal definition drift created desired release directory: %v", err)
	}
}

func TestApplyRequiresExistingForegroundRuntimeToStopBeforeUpgrade(t *testing.T) {
	fixture := newLifecycleFixture(t, true)
	first, firstRelease := fixture.release(t, "v1.2.3", "3")
	if _, err := applyConfirmed(t, fixture.lifecycle, first); err != nil {
		t.Fatal(err)
	}
	fixture.manager.active = true
	fixture.manager.current = identityFor(firstRelease)
	second, _ := fixture.release(t, "v1.2.4", "4")
	if _, err := applyConfirmed(t, fixture.lifecycle, second); err == nil || !strings.Contains(err.Error(), "supervised_foreground_runtime_must_stop_before_apply") {
		t.Fatalf("running foreground error=%v", err)
	}
	if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("failed foreground upgrade left journal: %v", err)
	}
}

func TestDeploymentStatusDistinguishesRunningStoppedAndRecovery(t *testing.T) {
	t.Run("native", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		request, _ := fixture.release(t, "v1.2.3", "5")
		if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
			t.Fatal(err)
		}
		status, err := fixture.lifecycle.Status(context.Background())
		if err != nil || status.Status != "active" || !status.Running {
			t.Fatalf("running status=%+v err=%v", status, err)
		}
		fixture.manager.active = false
		status, err = fixture.lifecycle.Status(context.Background())
		if err != nil || status.Status != "inactive" || status.Running {
			t.Fatalf("inactive status=%+v err=%v", status, err)
		}
	})

	t.Run("foreground", func(t *testing.T) {
		fixture := newLifecycleFixture(t, true)
		request, desired := fixture.release(t, "v1.2.3", "6")
		if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
			t.Fatal(err)
		}
		status, err := fixture.lifecycle.Status(context.Background())
		if err != nil || status.Status != "foreground_stopped" || status.Running {
			t.Fatalf("stopped foreground status=%+v err=%v", status, err)
		}
		fixture.manager.active = true
		fixture.manager.current = identityFor(desired)
		status, err = fixture.lifecycle.Status(context.Background())
		if err != nil || status.Status != "foreground_running" || !status.Running {
			t.Fatalf("running foreground status=%+v err=%v", status, err)
		}
	})

	t.Run("recovery", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		request, _ := fixture.release(t, "v1.2.3", "7")
		fixture.lifecycle.failAfterPhase = PhaseArtifactStaged
		if _, err := applyConfirmed(t, fixture.lifecycle, request); !errors.Is(err, ErrInjectedDeploymentCrash) {
			t.Fatalf("crash error=%v", err)
		}
		status, err := fixture.lifecycle.Status(context.Background())
		if err != nil || status.Status != "recovery_required" || !status.RecoveryRequired || status.Journal == nil {
			t.Fatalf("recovery status=%+v err=%v", status, err)
		}
		assertJSONHasNoDeploymentLocator(t, status)
	})

	t.Run("uninstalled", func(t *testing.T) {
		fixture := newLifecycleFixture(t, false)
		status, err := fixture.lifecycle.Status(context.Background())
		if err != nil || status.Status != "uninstalled" {
			t.Fatalf("uninstalled status=%+v err=%v", status, err)
		}
		assertJSONHasNoDeploymentLocator(t, status)
	})
}

func TestRollbackSwitchesToVerifiedPreviousRelease(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	firstRequest, first := fixture.release(t, "v1.2.3", "8")
	secondRequest, second := fixture.release(t, "v1.2.4", "9")
	if _, err := applyConfirmed(t, fixture.lifecycle, firstRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := applyConfirmed(t, fixture.lifecycle, secondRequest); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.lifecycle.Rollback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.State.Generation != 3 || result.State.Active == nil || *result.State.Active != first ||
		result.State.Previous == nil || *result.State.Previous != second {
		t.Fatalf("rollback state=%+v", result.State)
	}
	assertDeploymentLocator(t, result.DeploymentLocator, fixture.layout, first)
	if !fixture.manager.active || fixture.manager.current != identityFor(first) {
		t.Fatalf("rollback runtime=%+v active=%v", fixture.manager.current, fixture.manager.active)
	}
	if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("rollback journal error=%v", err)
	}
}

func TestRollbackResumesEveryDurablePhase(t *testing.T) {
	phases := []Phase{
		PhasePlanned,
		PhasePriorServiceStopped,
		PhaseDefinitionInstalled,
		PhaseActivated,
		PhaseHealthVerified,
		PhaseCommitting,
		PhaseStateSaved,
	}
	for _, phase := range phases {
		t.Run(string(phase), func(t *testing.T) {
			fixture := newLifecycleFixture(t, false)
			firstRequest, first := fixture.release(t, "v1.2.3", "a")
			secondRequest, second := fixture.release(t, "v1.2.4", "b")
			if _, err := applyConfirmed(t, fixture.lifecycle, firstRequest); err != nil {
				t.Fatal(err)
			}
			if _, err := applyConfirmed(t, fixture.lifecycle, secondRequest); err != nil {
				t.Fatal(err)
			}
			fixture.lifecycle.failAfterPhase = phase
			if _, err := fixture.lifecycle.Rollback(context.Background()); !errors.Is(err, ErrInjectedDeploymentCrash) {
				t.Fatalf("rollback crash error=%v", err)
			}
			journal, err := LoadJournal(fixture.layout)
			if err != nil || journal.Phase != phase {
				t.Fatalf("journal=%+v err=%v", journal, err)
			}
			fixture.lifecycle.failAfterPhase = ""
			result, err := fixture.lifecycle.Rollback(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if result.State.Active == nil || *result.State.Active != first || result.State.Previous == nil || *result.State.Previous != second {
				t.Fatalf("resumed rollback=%+v", result)
			}
			assertDeploymentLocator(t, result.DeploymentLocator, fixture.layout, first)
		})
	}
}

func TestRollbackFailureRestoresCurrentRelease(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	firstRequest, _ := fixture.release(t, "v1.2.3", "c")
	secondRequest, second := fixture.release(t, "v1.2.4", "d")
	if _, err := applyConfirmed(t, fixture.lifecycle, firstRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := applyConfirmed(t, fixture.lifecycle, secondRequest); err != nil {
		t.Fatal(err)
	}
	fixture.manager.failures["activate"] = 1
	failed, err := fixture.lifecycle.Rollback(context.Background())
	if err == nil || !strings.Contains(err.Error(), "activate") {
		t.Fatalf("rollback failure=%v", err)
	}
	if failed.DeploymentLocator != (DeploymentLocator{}) {
		t.Fatalf("failed rollback returned deployment locator: %+v", failed.DeploymentLocator)
	}
	state, err := LoadState(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if state.Active == nil || *state.Active != second || state.Generation != 2 || !fixture.manager.active || fixture.manager.current != identityFor(second) {
		t.Fatalf("state/runtime after failed rollback=%+v / %+v", state, fixture.manager.current)
	}
}

func TestUninstallRemovesRuntimeAndPreservesProtectedInstance(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, release := fixture.release(t, "v1.2.3", "e")
	if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
		t.Fatal(err)
	}
	openedBefore, err := instance.Open(context.Background(), fixture.layout.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	instanceID, vaultID := openedBefore.Settings.InstanceID, openedBefore.Settings.VaultID
	if err := openedBefore.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.lifecycle.Uninstall(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "uninstalled" || result.State.Status != StatusUninstalled || result.State.Generation != 2 ||
		result.State.Active != nil || result.State.Previous == nil || *result.State.Previous != release {
		t.Fatalf("uninstall result=%+v", result)
	}
	assertJSONHasNoDeploymentLocator(t, result)
	if fixture.manager.active || fixture.removeCalls != 1 {
		t.Fatalf("manager active=%v remove calls=%d", fixture.manager.active, fixture.removeCalls)
	}
	openedAfter, err := instance.Open(context.Background(), fixture.layout.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer openedAfter.Close()
	if openedAfter.Settings.InstanceID != instanceID || openedAfter.Settings.VaultID != vaultID {
		t.Fatal("uninstall changed protected instance identity")
	}
	second, err := fixture.lifecycle.Uninstall(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.State.Generation != 2 || fixture.removeCalls != 1 {
		t.Fatalf("idempotent uninstall=%+v remove calls=%d", second, fixture.removeCalls)
	}
	assertJSONHasNoDeploymentLocator(t, second)
}

func TestUninstallResumesEveryDurablePhase(t *testing.T) {
	phases := []Phase{
		PhasePlanned,
		PhasePriorServiceStopped,
		PhaseDefinitionRemoved,
		PhaseRemovingArtifacts,
		PhaseArtifactsRemoved,
		PhaseCommitting,
		PhaseStateSaved,
	}
	for _, phase := range phases {
		t.Run(string(phase), func(t *testing.T) {
			fixture := newLifecycleFixture(t, false)
			request, _ := fixture.release(t, "v1.2.3", "f")
			if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
				t.Fatal(err)
			}
			fixture.lifecycle.failAfterPhase = phase
			if _, err := fixture.lifecycle.Uninstall(context.Background()); !errors.Is(err, ErrInjectedDeploymentCrash) {
				t.Fatalf("uninstall crash error=%v", err)
			}
			journal, err := LoadJournal(fixture.layout)
			if err != nil || journal.Phase != phase {
				t.Fatalf("journal=%+v err=%v", journal, err)
			}
			fixture.lifecycle.failAfterPhase = ""
			result, err := fixture.lifecycle.Uninstall(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if result.State.Status != StatusUninstalled || result.State.Active != nil {
				t.Fatalf("resumed uninstall=%+v", result)
			}
			if phase == PhaseRemovingArtifacts && fixture.removeCalls != 1 {
				t.Fatalf("removing phase resume calls=%d", fixture.removeCalls)
			}
		})
	}
}

func TestUninstallManagerFailureRestoresActiveRelease(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, release := fixture.release(t, "v1.2.3", "0")
	if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
		t.Fatal(err)
	}
	fixture.manager.failures["remove"] = 1
	if _, err := fixture.lifecycle.Uninstall(context.Background()); err == nil || !strings.Contains(err.Error(), "remove") {
		t.Fatalf("uninstall failure=%v", err)
	}
	state, err := LoadState(fixture.layout)
	if err != nil {
		t.Fatal(err)
	}
	if state.Active == nil || *state.Active != release || !fixture.manager.active || fixture.manager.current != identityFor(release) {
		t.Fatalf("state/runtime after failed uninstall=%+v / %+v", state, fixture.manager.current)
	}
	if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("failed uninstall journal=%v", err)
	}
}

func TestUninstallArtifactFailureRequiresResumeWithoutDataLoss(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, _ := fixture.release(t, "v1.2.3", "1")
	if _, err := applyConfirmed(t, fixture.lifecycle, request); err != nil {
		t.Fatal(err)
	}
	failed := true
	fixture.lifecycle.removeArtifacts = func(Layout) error {
		fixture.removeCalls++
		if failed {
			return errors.New("injected partial artifact removal")
		}
		return nil
	}
	if _, err := fixture.lifecycle.Uninstall(context.Background()); err == nil || !strings.Contains(err.Error(), "partial artifact") {
		t.Fatalf("artifact removal failure=%v", err)
	}
	journal, err := LoadJournal(fixture.layout)
	if err != nil || journal.Phase != PhaseRemovingArtifacts {
		t.Fatalf("journal=%+v err=%v", journal, err)
	}
	opened, err := instance.Open(context.Background(), fixture.layout.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	failed = false
	result, err := fixture.lifecycle.Uninstall(context.Background())
	if err != nil || result.State.Status != StatusUninstalled {
		t.Fatalf("resumed uninstall=%+v err=%v", result, err)
	}
}

func TestDeploymentLocatorRejectsInvalidLayoutAndActiveMetadata(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, desired := fixture.release(t, "v1.2.3", "locator")
	result, err := applyConfirmed(t, fixture.lifecycle, request)
	if err != nil {
		t.Fatal(err)
	}
	assertDeploymentLocator(t, result.DeploymentLocator, fixture.layout, desired)

	invalidLayout := fixture.layout
	invalidLayout.VersionsDir = filepath.Join(fixture.layout.InstallRoot, "other-versions")
	if locator, err := deploymentLocatorForState(invalidLayout, result.State); err == nil || locator != (DeploymentLocator{}) {
		t.Fatalf("inconsistent layout locator=%+v err=%v", locator, err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*InstalledRelease)
	}{
		{name: "upload path", mutate: func(active *InstalledRelease) { active.BinaryPath = request.ArtifactPath }},
		{name: "uppercase manifest digest", mutate: func(active *InstalledRelease) { active.ManifestSHA256 = strings.ToUpper(active.ManifestSHA256) }},
		{name: "zero binary bytes", mutate: func(active *InstalledRelease) { active.BinaryBytes = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := result.State
			active := *state.Active
			test.mutate(&active)
			state.Active = &active
			if locator, err := deploymentLocatorForState(fixture.layout, state); err == nil || locator != (DeploymentLocator{}) {
				t.Fatalf("invalid active metadata locator=%+v err=%v", locator, err)
			}
		})
	}
}

func assertDeploymentLocator(t *testing.T, got DeploymentLocator, layout Layout, active InstalledRelease) {
	t.Helper()
	want := DeploymentLocator{
		Version:             "1",
		LifecycleBinaryPath: active.BinaryPath,
		HomeDir:             layout.HomeDir,
		InstallRoot:         layout.InstallRoot,
		StateDir:            layout.StateDir,
		Release:             active.Release,
		OS:                  active.OS,
		Architecture:        active.Architecture,
		ManifestSHA256:      active.ManifestSHA256,
		BinarySHA256:        active.BinarySHA256,
		BinaryBytes:         active.BinaryBytes,
	}
	if got != want {
		t.Fatalf("deployment locator=%+v want=%+v", got, want)
	}
	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	exactKeys := []string{
		"version", "lifecycle_binary_path", "home_dir", "install_root", "state_dir",
		"release", "os", "architecture", "manifest_sha256", "binary_sha256", "binary_bytes",
	}
	if len(object) != len(exactKeys) {
		t.Fatalf("deployment locator keys=%v", object)
	}
	for _, key := range exactKeys {
		if _, ok := object[key]; !ok {
			t.Fatalf("deployment locator is missing %q: %s", key, payload)
		}
	}
}

func assertJSONHasNoDeploymentLocator(t *testing.T, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	if _, ok := object["deployment_locator"]; ok {
		t.Fatalf("unexpected deployment locator: %s", payload)
	}
}

type lifecycleFixture struct {
	layout            Layout
	target            Target
	lifecycle         *Lifecycle
	manager           *fakeServiceManager
	identities        map[string]buildinfo.Identity
	stageCalls        int
	supportStageCalls int
	verifyCalls       int
	initializeCalls   int
	inspectCalls      int
	probeCalls        int
	removeCalls       int
}

type testInitializationLease struct {
	initialize func(context.Context, []string) (config.Settings, error)
	created    bool
	attest     func() error
	close      func() error
}

func replaceInitializationLockAtAttestation(
	lease instanceInitializationLease,
	stateDir string,
	targetCall int,
	attestationCalls *int,
	replacement **instance.InitializationLease,
) instanceInitializationLease {
	return &testInitializationLease{
		initialize: lease.Initialize,
		created:    lease.InitializationLockCreated(),
		attest: func() error {
			*attestationCalls = *attestationCalls + 1
			if *attestationCalls == targetCall {
				lockPath := filepath.Join(stateDir, ".instance.lock")
				if err := os.Remove(lockPath); err != nil {
					return err
				}
				if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
					return err
				}
				acquired, err := instance.AcquireInitializationLeaseWithLockPresence(stateDir, true)
				if err != nil {
					return err
				}
				*replacement = acquired
			}
			return lease.AttestLockPath()
		},
		close: lease.Close,
	}
}

func (lease *testInitializationLease) Initialize(ctx context.Context, listeners []string) (config.Settings, error) {
	return lease.initialize(ctx, listeners)
}

func (lease *testInitializationLease) InitializationLockCreated() bool {
	return lease.created
}

func (lease *testInitializationLease) AttestLockPath() error {
	return lease.attest()
}

func (lease *testInitializationLease) Close() error {
	return lease.close()
}

func newLifecycleFixture(t *testing.T, foreground bool) *lifecycleFixture {
	t.Helper()
	layout := testLayout(t)
	target := Target{OS: "linux", Architecture: "amd64"}
	identities := make(map[string]buildinfo.Identity)
	manager := &fakeServiceManager{
		kind:       ManagerSystemd,
		definition: filepath.Join(layout.HomeDir, ".config", "systemd", "user", "com.kciceblue.sshserver.service"),
		identities: identities,
		failures:   make(map[string]int),
	}
	if foreground {
		manager.availability = foregroundAvailability(layout, "/pending")
	} else {
		manager.availability = ManagerAvailability{Manager: ManagerSystemd, Available: true, ServiceDefinition: manager.definition}
	}
	fixture := &lifecycleFixture{layout: layout, target: target, manager: manager, identities: identities}
	lifecycle := newLifecycle(layout, target, manager)
	lifecycle.stageArtifact = func(_ string, destination, name string, _ int64, _ string) (string, error) {
		fixture.stageCalls++
		return filepath.Join(destination, name), nil
	}
	lifecycle.verifyArtifact = func(string, int64, string) error {
		fixture.verifyCalls++
		return nil
	}
	lifecycle.stageReleaseFile = func(_ string, destination, name string, _ int64, _ string) (string, error) {
		fixture.supportStageCalls++
		return filepath.Join(destination, name), nil
	}
	lifecycle.verifyReleaseFile = func(string, int64, string) error { return nil }
	lifecycle.verifySourceArtifact = func(string, InstalledRelease) error { return nil }
	lifecycle.verifySourceReleaseFile = func(string, int64, string) error { return nil }
	lifecycle.verifyPreviewRelease = func(context.Context, InstalledRelease) error { return nil }
	lifecycle.acquireInstanceLease = func(stateDir string, initializationLockPresent bool) (instanceInitializationLease, error) {
		lease, err := instance.AcquireInitializationLeaseWithLockPresence(stateDir, initializationLockPresent)
		if err != nil {
			return nil, err
		}
		return &testInitializationLease{
			initialize: func(ctx context.Context, listeners []string) (config.Settings, error) {
				fixture.initializeCalls++
				return lease.Initialize(ctx, listeners)
			},
			created: lease.InitializationLockCreated(),
			attest:  lease.AttestLockPath,
			close:   lease.Close,
		}, nil
	}
	lifecycle.renderService = func(_, binary, _ string) ([]byte, error) { return []byte(binary), nil }
	lifecycle.inspector = identityInspectorFunc(func(_ context.Context, path string) (buildinfo.Identity, error) {
		fixture.inspectCalls++
		identity, ok := identities[path]
		if !ok {
			return buildinfo.Identity{}, errors.New("missing fake binary identity")
		}
		return identity, nil
	})
	lifecycle.probeRunning = func(context.Context, string) (buildinfo.Identity, error) {
		fixture.probeCalls++
		if !manager.active {
			return buildinfo.Identity{}, ErrRuntimeUnavailable
		}
		return manager.current, nil
	}
	lifecycle.removeArtifacts = func(Layout) error {
		fixture.removeCalls++
		return nil
	}
	fixture.lifecycle = lifecycle
	return fixture
}

func (fixture *lifecycleFixture) release(t *testing.T, version, manifestDigit string) (ApplyRequest, InstalledRelease) {
	t.Helper()
	manifest := testReleaseManifest()
	manifest.Release = version
	manifest.Artifacts = append([]ReleaseArtifact(nil), manifest.Artifacts...)
	manifest.ReleaseFiles = append([]ReleaseFile(nil), manifest.ReleaseFiles...)
	refreshTestBuildIdentities(&manifest)
	for index := range manifest.Artifacts {
		manifest.Artifacts[index].URL = strings.Replace(manifest.Artifacts[index].URL, "/v1.0.0-test.1/", "/"+version+"/", 1)
	}
	for index := range manifest.ReleaseFiles {
		manifest.ReleaseFiles[index].URL = strings.Replace(manifest.ReleaseFiles[index].URL, "/v1.0.0-test.1/", "/"+version+"/", 1)
	}
	payload, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	pin := SHA256Hex(payload)
	if manifestDigit != "" {
		// The manifest pin is derived from exact bytes. The argument is retained
		// only to keep subtest fixture names visibly distinct.
		_ = manifestDigit
	}
	desired, err := InstalledFromManifest(fixture.layout, manifest, pin, fixture.target)
	if err != nil {
		t.Fatal(err)
	}
	fixture.identities[desired.BinaryPath] = identityFor(desired)
	manifestDirectory := filepath.Join(fixture.layout.HomeDir, "download", version)
	if err := os.MkdirAll(manifestDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(manifestDirectory, "release-manifest.json")
	if err := os.WriteFile(manifestPath, payload, 0o400); err != nil {
		t.Fatal(err)
	}
	return ApplyRequest{
		ManifestPath:    manifestPath,
		ManifestPayload: payload,
		ManifestSHA256:  pin,
		ArtifactPath:    filepath.Join(manifestDirectory, "sshserver"),
		LicensePath:     filepath.Join(manifestDirectory, "LICENSE"),
		NoticePath:      filepath.Join(manifestDirectory, "NOTICE"),
	}, desired
}

func identityFor(release InstalledRelease) buildinfo.Identity {
	return buildinfo.Identity{
		Release:         release.Release,
		SourceRevision:  release.SourceRevision,
		BuildToolchain:  release.BuildToolchain,
		BuildIdentity:   release.BuildIdentity,
		ProtocolVersion: release.ProtocolVersion,
		StorageSchema:   release.StorageSchema,
	}
}

type identityInspectorFunc func(context.Context, string) (buildinfo.Identity, error)

func (function identityInspectorFunc) Inspect(ctx context.Context, path string) (buildinfo.Identity, error) {
	return function(ctx, path)
}

type fakeServiceManager struct {
	kind          ManagerKind
	definition    string
	availability  ManagerAvailability
	detectResults []ManagerAvailability
	identities    map[string]buildinfo.Identity
	failures      map[string]int
	calls         []string
	active        bool
	pending       string
	current       buildinfo.Identity
}

func (manager *fakeServiceManager) Kind() ManagerKind      { return manager.kind }
func (manager *fakeServiceManager) DefinitionPath() string { return manager.definition }

func (manager *fakeServiceManager) Detect(_ context.Context, binaryPath, stateDir string) (ManagerAvailability, error) {
	manager.calls = append(manager.calls, "detect")
	if err := manager.fail("detect"); err != nil {
		return ManagerAvailability{}, err
	}
	availability := cloneManagerAvailability(manager.availability)
	if len(manager.detectResults) > 0 {
		availability = cloneManagerAvailability(manager.detectResults[0])
		manager.detectResults = manager.detectResults[1:]
	}
	if availability.Foreground != nil {
		availability.Foreground.Command = []string{binaryPath, "serve", "--state-dir", stateDir}
	}
	return availability, nil
}

func (manager *fakeServiceManager) InstallDefinition(payload []byte) (string, error) {
	manager.calls = append(manager.calls, "install")
	if err := manager.fail("install"); err != nil {
		return "", err
	}
	manager.pending = string(payload)
	return manager.definition, nil
}

func (manager *fakeServiceManager) Activate(context.Context) error {
	manager.calls = append(manager.calls, "activate")
	if err := manager.fail("activate"); err != nil {
		return err
	}
	identity, ok := manager.identities[manager.pending]
	if !ok {
		return errors.New("fake manager has no identity for installed binary")
	}
	manager.current = identity
	manager.active = true
	return nil
}

func (manager *fakeServiceManager) Stop(context.Context) error {
	manager.calls = append(manager.calls, "stop")
	if err := manager.fail("stop"); err != nil {
		return err
	}
	manager.active = false
	return nil
}

func (manager *fakeServiceManager) Remove(ctx context.Context) error {
	manager.calls = append(manager.calls, "remove")
	if err := manager.fail("remove"); err != nil {
		return err
	}
	manager.active = false
	manager.pending = ""
	return nil
}

func (manager *fakeServiceManager) IsActive(context.Context) (bool, error) {
	manager.calls = append(manager.calls, "is-active")
	if err := manager.fail("is-active"); err != nil {
		return false, err
	}
	return manager.active, nil
}

func (manager *fakeServiceManager) fail(operation string) error {
	if manager.failures[operation] > 0 {
		manager.failures[operation]--
		return fmt.Errorf("fake %s failure", operation)
	}
	return nil
}

func (manager *fakeServiceManager) assertCallsContainInOrder(t *testing.T, expected ...string) {
	t.Helper()
	index := 0
	for _, call := range manager.calls {
		if index < len(expected) && call == expected[index] {
			index++
		}
	}
	if index != len(expected) {
		t.Fatalf("manager calls=%v, want subsequence=%v", manager.calls, expected)
	}
}

func foregroundAvailability(layout Layout, binary string) ManagerAvailability {
	return ManagerAvailability{
		Manager:   ManagerForeground,
		Available: false,
		Foreground: &ForegroundFallback{
			Required:   true,
			Reason:     "user_service_manager_unavailable",
			Command:    []string{binary, "serve", "--state-dir", layout.StateDir},
			Supervised: true,
		},
	}
}
