//go:build darwin || linux

package deployment

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/instance"
)

func TestRealNativeBinaryUpgradesRollsBackRunsAndUninstalls(t *testing.T) {
	// These are two differently attested, same-schema builds from this checkout.
	// The test proves the current host's real artifact/process lifecycle; it does
	// not claim a published cross-release or four-platform native matrix.
	if testing.Short() {
		t.Skip("real two-release lifecycle integration is disabled in short mode")
	}
	layout := testLayout(t)
	uploadRoot := filepath.Join(layout.HomeDir, "verified-ac3-uploads")
	if err := os.Mkdir(uploadRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	goVersionCommand := exec.Command("go", "env", "GOVERSION")
	goVersionCommand.Env = integrationGoEnvironment("GOENV=off", "GOTOOLCHAIN=local")
	goVersionOutput, err := goVersionCommand.Output()
	if err != nil {
		t.Fatal(err)
	}
	toolchain := strings.TrimSpace(string(goVersionOutput))
	first := buildTask25NativeRelease(
		t,
		layout,
		uploadRoot,
		"v0.0.0-ac3.1",
		strings.Repeat("a", 40),
		toolchain,
	)
	second := buildTask25NativeRelease(
		t,
		layout,
		uploadRoot,
		"v0.0.0-ac3.2",
		strings.Repeat("b", 40),
		toolchain,
	)
	if first.installed.StorageSchema != config.StorageSchema || second.installed.StorageSchema != config.StorageSchema {
		t.Fatalf("native AC3 fixtures are not same-schema V1 releases: %q/%q", first.installed.StorageSchema, second.installed.StorageSchema)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddress := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := instance.Initialize(context.Background(), layout.StateDir, []string{listenAddress}); err != nil {
		t.Fatal(err)
	}
	protectedBefore := captureProtectedInstance(t, layout.StateDir)

	manager := &fakeServiceManager{
		kind:         ManagerForeground,
		availability: foregroundAvailability(layout, "/pending"),
		failures:     make(map[string]int),
	}
	lifecycle := newLifecycle(layout, Target{OS: runtime.GOOS, Architecture: runtime.GOARCH}, manager)

	firstResult, err := applyConfirmed(t, lifecycle, first.request)
	if err != nil {
		t.Fatal(err)
	}
	assertTask25NativeForegroundResult(t, firstResult, layout, first.installed, 1, nil)
	exerciseTask25NativeForeground(t, lifecycle, firstResult, first.installed)
	assertTask25NativeProtectedIdentityUnchanged(t, protectedBefore, captureProtectedInstance(t, layout.StateDir), layout.StateDir)

	secondResult, err := applyConfirmed(t, lifecycle, second.request)
	if err != nil {
		t.Fatal(err)
	}
	assertTask25NativeForegroundResult(t, secondResult, layout, second.installed, 2, &first.installed)
	exerciseTask25NativeForeground(t, lifecycle, secondResult, second.installed)
	assertTask25NativeProtectedIdentityUnchanged(t, protectedBefore, captureProtectedInstance(t, layout.StateDir), layout.StateDir)

	rolledBack, err := lifecycle.Rollback(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	assertTask25NativeForegroundResult(t, rolledBack, layout, first.installed, 3, &second.installed)
	exerciseTask25NativeForeground(t, lifecycle, rolledBack, first.installed)
	assertTask25NativeProtectedIdentityUnchanged(t, protectedBefore, captureProtectedInstance(t, layout.StateDir), layout.StateDir)

	uninstalled, err := lifecycle.Uninstall(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if uninstalled.Status != "uninstalled" || uninstalled.State.Status != StatusUninstalled ||
		uninstalled.State.Generation != 4 || uninstalled.State.Active != nil || uninstalled.State.Previous == nil ||
		*uninstalled.State.Previous != first.installed {
		t.Fatalf("native two-release uninstall=%+v", uninstalled)
	}
	for _, release := range []InstalledRelease{first.installed, second.installed} {
		versionDir, err := layout.VersionDir(release.Release)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(versionDir); !os.IsNotExist(err) {
			t.Fatalf("native release directory %s remains after uninstall: %v", release.Release, err)
		}
	}
	entries, err := os.ReadDir(layout.VersionsDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("native versions directory after uninstall entries=%v err=%v", entries, err)
	}
	if _, err := LoadJournal(layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("native two-release uninstall journal error=%v", err)
	}
	assertTask25NativeProtectedIdentityUnchanged(t, protectedBefore, captureProtectedInstance(t, layout.StateDir), layout.StateDir)
}

type task25NativeRelease struct {
	request   ApplyRequest
	installed InstalledRelease
}

func buildTask25NativeRelease(
	t *testing.T,
	layout Layout,
	uploadRoot string,
	release string,
	sourceRevision string,
	toolchain string,
) task25NativeRelease {
	t.Helper()
	target := Target{OS: runtime.GOOS, Architecture: runtime.GOARCH}
	buildIdentity, err := DeriveBuildIdentity(release, sourceRevision, toolchain, target)
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := buildinfo.Encode(buildinfo.Identity{
		Release:         release,
		SourceRevision:  sourceRevision,
		BuildToolchain:  toolchain,
		BuildIdentity:   buildIdentity,
		ProtocolVersion: config.ProtocolMajor,
		StorageSchema:   config.StorageSchema,
	})
	if err != nil {
		t.Fatal(err)
	}

	uploadDir := filepath.Join(uploadRoot, release)
	if err := os.Mkdir(uploadDir, 0o700); err != nil {
		t.Fatal(err)
	}
	binarySource := filepath.Join(uploadDir, "sshserver")
	runtimeRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command(
		"go", "build", "-mod=readonly", "-buildmode=exe", "-buildvcs=true", "-tags=", "-trimpath",
		"-ldflags=-X github.com/kciceblue/sshserver/runtime/internal/buildinfo.EncodedIdentity="+attestation,
		"-o", binarySource, "./cmd/sshserver",
	)
	build.Dir = runtimeRoot
	build.Env = integrationGoEnvironment(
		"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=", "GOTOOLCHAIN=local",
		"CGO_ENABLED=0", "GOOS="+target.OS, "GOARCH="+target.Architecture,
		"GOAMD64=v1", "GOARM64=v8.0",
	)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native AC3 release %s: %v\n%s", release, err, output)
	}
	if err := os.Chmod(binarySource, 0o500); err != nil {
		t.Fatal(err)
	}
	binaryPayload, err := os.ReadFile(binarySource)
	if err != nil {
		t.Fatal(err)
	}
	licensePayload := []byte(fmt.Sprintf("Apache-2.0 AC3 license fixture for %s\n", release))
	noticePayload := []byte(fmt.Sprintf("AC3 notice fixture for %s\n", release))
	licenseSource := writeIntegrationUpload(t, uploadDir, "LICENSE", licensePayload)
	noticeSource := writeIntegrationUpload(t, uploadDir, "NOTICE", noticePayload)

	manifest := ReleaseManifest{
		ManifestVersion: ManifestVersion,
		Release:         release,
		SourceRevision:  sourceRevision,
		BuildToolchain:  toolchain,
		ProtocolVersion: config.ProtocolMajor,
		StorageSchema:   config.StorageSchema,
		DownloadOrigin:  "https://downloads.example.test",
		ReleaseFiles: []ReleaseFile{
			{Name: "LICENSE", URL: integrationReleaseURL(release, "LICENSE"), Bytes: int64(len(licensePayload)), SHA256: SHA256Hex(licensePayload)},
			{Name: "NOTICE", URL: integrationReleaseURL(release, "NOTICE"), Bytes: int64(len(noticePayload)), SHA256: SHA256Hex(noticePayload)},
		},
	}
	for _, supported := range SupportedTargets() {
		identity, err := DeriveBuildIdentity(release, sourceRevision, toolchain, supported)
		if err != nil {
			t.Fatal(err)
		}
		artifact := ReleaseArtifact{
			OS: supported.OS, Architecture: supported.Architecture, BuildIdentity: identity,
			URL:   integrationReleaseURL(release, "sshserver-"+supported.OS+"-"+supported.Architecture),
			Bytes: 1, SHA256: strings.Repeat("f", 64),
		}
		if supported == target {
			artifact.Bytes = int64(len(binaryPayload))
			artifact.SHA256 = SHA256Hex(binaryPayload)
		}
		manifest.Artifacts = append(manifest.Artifacts, artifact)
	}
	manifestPayload, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	manifestSHA256 := SHA256Hex(manifestPayload)
	manifestSource := writeIntegrationUpload(t, uploadDir, "release-manifest.json", manifestPayload)
	installed, err := InstalledFromManifest(layout, manifest, manifestSHA256, target)
	if err != nil {
		t.Fatal(err)
	}
	return task25NativeRelease{
		request: ApplyRequest{
			ManifestPath:    manifestSource,
			ManifestPayload: manifestPayload,
			ManifestSHA256:  manifestSHA256,
			ArtifactPath:    binarySource,
			LicensePath:     licenseSource,
			NoticePath:      noticeSource,
		},
		installed: installed,
	}
}

func assertTask25NativeForegroundResult(
	t *testing.T,
	result ApplyResult,
	layout Layout,
	active InstalledRelease,
	generation uint64,
	previous *InstalledRelease,
) {
	t.Helper()
	if result.Status != "foreground_required" || result.State.Status != StatusForeground ||
		result.State.Manager != ManagerForeground || result.State.Generation != generation ||
		result.State.Active == nil || *result.State.Active != active || result.Foreground == nil ||
		!result.Foreground.Required || !result.Foreground.Supervised ||
		result.Foreground.Reason != "user_service_manager_unavailable" {
		t.Fatalf("native foreground result=%+v", result)
	}
	if previous == nil {
		if result.State.Previous != nil {
			t.Fatalf("native foreground result retained unexpected previous release=%+v", result.State.Previous)
		}
	} else if result.State.Previous == nil || *result.State.Previous != *previous {
		t.Fatalf("native foreground previous=%+v want=%+v", result.State.Previous, previous)
	}
	wantCommand := []string{active.BinaryPath, "serve", "--state-dir", layout.StateDir}
	if fmt.Sprint(result.Foreground.Command) != fmt.Sprint(wantCommand) {
		t.Fatalf("native foreground command=%q want=%q", result.Foreground.Command, wantCommand)
	}
	assertDeploymentLocator(t, result.DeploymentLocator, layout, active)
	if _, err := LoadJournal(layout); !errors.Is(err, ErrNoDeploymentJournal) {
		t.Fatalf("completed native foreground journal error=%v", err)
	}
}

func exerciseTask25NativeForeground(
	t *testing.T,
	lifecycle *Lifecycle,
	result ApplyResult,
	want InstalledRelease,
) {
	t.Helper()
	if result.Foreground == nil || len(result.Foreground.Command) == 0 {
		t.Fatal("native foreground result has no command")
	}
	var stdout, stderr bytes.Buffer
	server := exec.Command(result.Foreground.Command[0], result.Foreground.Command[1:]...)
	server.Stdout = &stdout
	server.Stderr = &stderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Wait() }()
	stopped := false
	defer func() {
		if !stopped && server.Process != nil {
			_ = server.Process.Kill()
			<-done
		}
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		running, probeErr := ProbeRunningIdentity(context.Background(), lifecycle.layout.StateDir)
		if probeErr == nil {
			if running != identityFor(want) {
				t.Fatalf("native foreground running identity=%+v want=%+v", running, identityFor(want))
			}
			break
		}
		select {
		case exitErr := <-done:
			stopped = true
			t.Fatalf("native foreground exited before health: %v\nstdout=%s\nstderr=%s", exitErr, stdout.String(), stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("native foreground did not become healthy: %v\nstderr=%s", probeErr, stderr.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	status, err := lifecycle.Status(context.Background())
	if err != nil || status.Status != "foreground_running" || !status.Running {
		t.Fatalf("native foreground running status=%+v err=%v", status, err)
	}

	if err := server.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatalf("native foreground stop: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("native foreground did not stop after SIGTERM")
	}
	status, err = lifecycle.Status(context.Background())
	if err != nil || status.Status != "foreground_stopped" || status.Running {
		t.Fatalf("native foreground stopped status=%+v err=%v", status, err)
	}
}

func assertTask25NativeProtectedIdentityUnchanged(
	t *testing.T,
	before protectedInstanceSnapshot,
	after protectedInstanceSnapshot,
	stateDir string,
) {
	t.Helper()
	// Opening the real runtime may legitimately update SQLite bookkeeping even
	// without user-data mutations. The deployment invariant here is the
	// protected instance identity and secret; separately reopen the database to
	// prove every lifecycle transition left it valid and usable.
	if !reflect.DeepEqual(after.settings, before.settings) || after.marker != before.marker ||
		after.secretSHA256 != before.secretSHA256 {
		t.Fatal("native lifecycle changed protected instance identity, secret, or marker")
	}
	opened, err := instance.Open(context.Background(), stateDir)
	if err != nil {
		t.Fatalf("open protected instance after native lifecycle transition: %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
}
