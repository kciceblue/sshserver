//go:build darwin || linux

package deployment

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/instance"
)

func TestApplyTransactionCommitsExactNativeReleaseAndIsIdempotent(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	request, desired := fixture.release(t, "v1.2.3", "a")
	result, err := fixture.lifecycle.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "active" || result.State.Status != StatusActive || result.State.Active == nil || *result.State.Active != desired {
		t.Fatalf("apply result = %+v", result)
	}
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
	second, err := fixture.lifecycle.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if second.State.Generation != 1 || fixture.stageCalls != 2 || fixture.initializeCalls != 1 {
		t.Fatalf("idempotent result=%+v stage/init=%d/%d", second, fixture.stageCalls, fixture.initializeCalls)
	}
	for _, call := range fixture.manager.calls[beforeCalls:] {
		if call == "install" || call == "activate" || call == "stop" || call == "remove" {
			t.Fatalf("idempotent apply mutated service manager: %v", fixture.manager.calls[beforeCalls:])
		}
	}
}

func TestVerifiedLocatorSurvivesRepeatedUpgradesAndStatusRefreshesNewestActivePath(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	var installed []InstalledRelease
	for index, version := range []string{"v1.2.3", "v1.2.4", "v1.2.5"} {
		request, release := fixture.release(t, version, fmt.Sprint(index))
		result, err := fixture.lifecycle.Apply(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if result.State.Active == nil || *result.State.Active != release {
			t.Fatalf("upgrade %s active state=%+v", version, result.State.Active)
		}
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
			if _, err := fixture.lifecycle.Apply(context.Background(), request); !errors.Is(err, ErrInjectedDeploymentCrash) {
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
			result, err := fixture.lifecycle.Apply(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if result.State.Active == nil || *result.State.Active != desired || result.State.Status != StatusActive {
				t.Fatalf("resumed result=%+v", result)
			}
			if _, err := LoadJournal(fixture.layout); !errors.Is(err, ErrNoDeploymentJournal) {
				t.Fatalf("resumed journal error=%v", err)
			}
		})
	}
}

func TestApplyFailureRollsBackExactPriorReleaseAndPreservesInstance(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	firstRequest, firstRelease := fixture.release(t, "v1.2.3", "c")
	if _, err := fixture.lifecycle.Apply(context.Background(), firstRequest); err != nil {
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
	if _, err := fixture.lifecycle.Apply(context.Background(), secondRequest); err == nil || !strings.Contains(err.Error(), "activate") {
		t.Fatalf("failed upgrade error = %v", err)
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
	result, err := fixture.lifecycle.Apply(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "foreground_required" || result.State.Status != StatusForeground || result.Foreground == nil ||
		!result.Foreground.Required || !result.Foreground.Supervised {
		t.Fatalf("foreground result=%+v", result)
	}
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
	if _, err := fixture.lifecycle.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	fixture.manager.availability = foregroundAvailability(fixture.layout, "/unused")
	second, _ := fixture.release(t, "v1.2.4", "2")
	if _, err := fixture.lifecycle.Apply(context.Background(), second); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("implicit fallback error=%v", err)
	}
	state, err := LoadState(fixture.layout)
	if err != nil || state.Active.Release != "v1.2.3" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestApplyRequiresExistingForegroundRuntimeToStopBeforeUpgrade(t *testing.T) {
	fixture := newLifecycleFixture(t, true)
	first, firstRelease := fixture.release(t, "v1.2.3", "3")
	if _, err := fixture.lifecycle.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	fixture.manager.active = true
	fixture.manager.current = identityFor(firstRelease)
	second, _ := fixture.release(t, "v1.2.4", "4")
	if _, err := fixture.lifecycle.Apply(context.Background(), second); err == nil || !strings.Contains(err.Error(), "must be stopped") {
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
		if _, err := fixture.lifecycle.Apply(context.Background(), request); err != nil {
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
		if _, err := fixture.lifecycle.Apply(context.Background(), request); err != nil {
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
		if _, err := fixture.lifecycle.Apply(context.Background(), request); !errors.Is(err, ErrInjectedDeploymentCrash) {
			t.Fatalf("crash error=%v", err)
		}
		status, err := fixture.lifecycle.Status(context.Background())
		if err != nil || status.Status != "recovery_required" || !status.RecoveryRequired || status.Journal == nil {
			t.Fatalf("recovery status=%+v err=%v", status, err)
		}
	})
}

func TestRollbackSwitchesToVerifiedPreviousRelease(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	firstRequest, first := fixture.release(t, "v1.2.3", "8")
	secondRequest, second := fixture.release(t, "v1.2.4", "9")
	if _, err := fixture.lifecycle.Apply(context.Background(), firstRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.lifecycle.Apply(context.Background(), secondRequest); err != nil {
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
			if _, err := fixture.lifecycle.Apply(context.Background(), firstRequest); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.lifecycle.Apply(context.Background(), secondRequest); err != nil {
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
		})
	}
}

func TestRollbackFailureRestoresCurrentRelease(t *testing.T) {
	fixture := newLifecycleFixture(t, false)
	firstRequest, _ := fixture.release(t, "v1.2.3", "c")
	secondRequest, second := fixture.release(t, "v1.2.4", "d")
	if _, err := fixture.lifecycle.Apply(context.Background(), firstRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.lifecycle.Apply(context.Background(), secondRequest); err != nil {
		t.Fatal(err)
	}
	fixture.manager.failures["activate"] = 1
	if _, err := fixture.lifecycle.Rollback(context.Background()); err == nil || !strings.Contains(err.Error(), "activate") {
		t.Fatalf("rollback failure=%v", err)
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
	if _, err := fixture.lifecycle.Apply(context.Background(), request); err != nil {
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
			if _, err := fixture.lifecycle.Apply(context.Background(), request); err != nil {
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
	if _, err := fixture.lifecycle.Apply(context.Background(), request); err != nil {
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
	if _, err := fixture.lifecycle.Apply(context.Background(), request); err != nil {
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
	lifecycle.initialize = func(ctx context.Context, stateDir string, listeners []string) (settings config.Settings, err error) {
		fixture.initializeCalls++
		return instance.Initialize(ctx, stateDir, listeners)
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
	return ApplyRequest{
		ManifestPayload: payload,
		ManifestSHA256:  pin,
		ArtifactPath:    filepath.Join(fixture.layout.HomeDir, "download", version, "sshserver"),
		LicensePath:     filepath.Join(fixture.layout.HomeDir, "download", version, "LICENSE"),
		NoticePath:      filepath.Join(fixture.layout.HomeDir, "download", version, "NOTICE"),
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
	kind         ManagerKind
	definition   string
	availability ManagerAvailability
	identities   map[string]buildinfo.Identity
	failures     map[string]int
	calls        []string
	active       bool
	pending      string
	current      buildinfo.Identity
}

func (manager *fakeServiceManager) Kind() ManagerKind      { return manager.kind }
func (manager *fakeServiceManager) DefinitionPath() string { return manager.definition }

func (manager *fakeServiceManager) Detect(context.Context, string, string) (ManagerAvailability, error) {
	manager.calls = append(manager.calls, "detect")
	if err := manager.fail("detect"); err != nil {
		return ManagerAvailability{}, err
	}
	return manager.availability, nil
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
