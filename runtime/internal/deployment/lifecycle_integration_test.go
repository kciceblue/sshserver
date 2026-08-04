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
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/instance"
)

func TestRealNativeBinaryStagesAttestsRunsAndUninstalls(t *testing.T) {
	if testing.Short() {
		t.Skip("real release-binary integration is disabled in short mode")
	}
	layout := testLayout(t)
	uploadDir := filepath.Join(layout.HomeDir, "verified-upload")
	if err := os.Mkdir(uploadDir, 0o700); err != nil {
		t.Fatal(err)
	}

	goVersionCommand := exec.Command("go", "env", "GOVERSION")
	goVersionCommand.Env = integrationGoEnvironment("GOENV=off", "GOTOOLCHAIN=local")
	goVersionOutput, err := goVersionCommand.Output()
	if err != nil {
		t.Fatal(err)
	}
	toolchain := strings.TrimSpace(string(goVersionOutput))
	release := "v0.0.0-lifecycle-test"
	sourceRevision := strings.Repeat("a", 40)
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
		ProtocolVersion: "1",
		StorageSchema:   "1",
	})
	if err != nil {
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
		t.Fatalf("build real native release fixture: %v\n%s", err, output)
	}
	if err := os.Chmod(binarySource, 0o500); err != nil {
		t.Fatal(err)
	}
	licensePayload := []byte("Apache-2.0 release license fixture\n")
	noticePayload := []byte("release notice fixture\n")
	licenseSource := writeIntegrationUpload(t, uploadDir, "LICENSE", licensePayload)
	noticeSource := writeIntegrationUpload(t, uploadDir, "NOTICE", noticePayload)
	binaryPayload, err := os.ReadFile(binarySource)
	if err != nil {
		t.Fatal(err)
	}

	manifest := ReleaseManifest{
		ManifestVersion: ManifestVersion,
		Release:         release,
		SourceRevision:  sourceRevision,
		BuildToolchain:  toolchain,
		ProtocolVersion: "1",
		StorageSchema:   "1",
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
	manifestSource := writeIntegrationUpload(t, uploadDir, "release-manifest.json", manifestPayload)

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

	installedBinary, err := layout.BinaryPath(release, target)
	if err != nil {
		t.Fatal(err)
	}
	manager := &fakeServiceManager{
		kind:         ManagerForeground,
		availability: foregroundAvailability(layout, installedBinary),
		failures:     make(map[string]int),
	}
	lifecycle := newLifecycle(layout, target, manager)
	applyRequest := ApplyRequest{
		ManifestPath:    manifestSource,
		ManifestPayload: manifestPayload,
		ManifestSHA256:  SHA256Hex(manifestPayload),
		ArtifactPath:    binarySource,
		LicensePath:     licenseSource,
		NoticePath:      noticeSource,
	}
	configBefore, err := os.ReadFile(config.ForStateDir(layout.StateDir).Config)
	if err != nil {
		t.Fatal(err)
	}
	previewRequest := PreviewRequest{
		ManifestPath: manifestSource, ManifestPayload: manifestPayload, ManifestSHA256: SHA256Hex(manifestPayload),
		ArtifactPath: binarySource, LicensePath: licenseSource, NoticePath: noticeSource,
	}
	preview, err := lifecycle.Preview(context.Background(), previewRequest)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Classification != PreviewFresh || !preview.ApplyAllowed || preview.Existing.InstanceState != "ready" {
		t.Fatalf("real artifact preview=%+v", preview)
	}
	firstCanonical, err := preview.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	secondCanonical, err := preview.CanonicalBytes()
	if err != nil || !bytes.Equal(firstCanonical, secondCanonical) {
		t.Fatalf("real artifact preview is nondeterministic: %v", err)
	}
	configAfter, err := os.ReadFile(config.ForStateDir(layout.StateDir).Config)
	if err != nil || !bytes.Equal(configBefore, configAfter) {
		t.Fatalf("preview changed protected instance config: %v", err)
	}
	for _, path := range []string{installedBinary, layout.StatePath, layout.JournalPath, layout.LockPath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("preview created target-layout artifact %s: %v", path, err)
		}
	}

	result, err := applyConfirmed(t, lifecycle, applyRequest)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "foreground_required" || result.Foreground == nil ||
		fmt.Sprint(result.Foreground.Command) != fmt.Sprint([]string{installedBinary, "serve", "--state-dir", layout.StateDir}) {
		t.Fatalf("apply result=%+v", result)
	}
	installedLicense := filepath.Join(filepath.Dir(installedBinary), "LICENSE")
	installedNotice := filepath.Join(filepath.Dir(installedBinary), "NOTICE")
	for _, repair := range []struct {
		name   string
		path   string
		verify func() error
	}{
		{
			name: "binary", path: installedBinary,
			verify: func() error {
				if err := VerifyStagedArtifact(installedBinary, int64(len(binaryPayload)), SHA256Hex(binaryPayload)); err != nil {
					return err
				}
				return VerifyArtifactSource(installedBinary, *result.State.Active)
			},
		},
		{name: "LICENSE", path: installedLicense, verify: func() error {
			return VerifyStagedReleaseFile(installedLicense, int64(len(licensePayload)), SHA256Hex(licensePayload))
		}},
		{name: "NOTICE", path: installedNotice, verify: func() error {
			return VerifyStagedReleaseFile(installedNotice, int64(len(noticePayload)), SHA256Hex(noticePayload))
		}},
	} {
		t.Run("idempotent repair missing "+repair.name, func(t *testing.T) {
			if err := os.Remove(repair.path); err != nil {
				t.Fatal(err)
			}
			repairPreview, err := lifecycle.Preview(context.Background(), previewRequest)
			if err != nil {
				t.Fatal(err)
			}
			if repairPreview.Classification != PreviewIdempotent || !repairPreview.ApplyAllowed || repairPreview.BlockReason != "" {
				t.Fatalf("missing %s preview=%+v", repair.name, repairPreview)
			}
			assertPreviewAction(t, repairPreview.Actions, "verify_or_reuse_artifact", installedBinary, binarySource)
			assertPreviewAction(t, repairPreview.Actions, "verify_or_reuse_license", installedLicense, licenseSource)
			assertPreviewAction(t, repairPreview.Actions, "verify_or_reuse_notice", installedNotice, noticeSource)
			if _, err := applyConfirmed(t, lifecycle, applyRequest); err != nil {
				t.Fatalf("repair missing %s: %v", repair.name, err)
			}
			if err := repair.verify(); err != nil {
				t.Fatalf("verify repaired %s: %v", repair.name, err)
			}
		})
	}

	if err := os.Chmod(installedNotice, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installedNotice, bytes.Repeat([]byte{'x'}, len(noticePayload)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(installedNotice, 0o400); err != nil {
		t.Fatal(err)
	}
	tamperedPreview, err := lifecycle.Preview(context.Background(), previewRequest)
	if err != nil {
		t.Fatal(err)
	}
	if tamperedPreview.Classification != PreviewBlocked || tamperedPreview.ApplyAllowed ||
		tamperedPreview.BlockReason != "installed_release_verification_failed" {
		t.Fatalf("tampered installed NOTICE preview=%+v", tamperedPreview)
	}
	if _, err := applyConfirmed(t, lifecycle, applyRequest); err == nil {
		t.Fatal("idempotent apply replaced a present tampered NOTICE")
	}
	if err := os.Remove(installedNotice); err != nil {
		t.Fatal(err)
	}
	if _, err := applyConfirmed(t, lifecycle, applyRequest); err != nil {
		t.Fatalf("repair removed tampered NOTICE: %v", err)
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
	serverStopped := false
	t.Cleanup(func() {
		if !serverStopped && server.Process != nil {
			_ = server.Process.Kill()
			<-done
		}
	})

	deadline := time.Now().Add(10 * time.Second)
	for {
		runningIdentity, probeErr := ProbeRunningIdentity(context.Background(), layout.StateDir)
		if probeErr == nil {
			if runningIdentity != identityFor(*result.State.Active) {
				t.Fatalf("running identity=%+v", runningIdentity)
			}
			break
		}
		select {
		case exitErr := <-done:
			serverStopped = true
			t.Fatalf("foreground server exited before attestation: %v\nstdout=%s\nstderr=%s", exitErr, stdout.String(), stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("foreground server did not become ready: %v\nstderr=%s", probeErr, stderr.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	status, err := lifecycle.Status(context.Background())
	if err != nil || status.Status != "foreground_running" || !status.Running {
		t.Fatalf("running status=%+v err=%v", status, err)
	}

	if err := server.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		serverStopped = true
		if err != nil {
			t.Fatalf("foreground server stop: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("foreground server did not stop after SIGTERM")
	}
	status, err = lifecycle.Status(context.Background())
	if err != nil || status.Status != "foreground_stopped" || status.Running {
		t.Fatalf("stopped status=%+v err=%v", status, err)
	}
	uninstalled, err := lifecycle.Uninstall(context.Background())
	if err != nil || uninstalled.Status != "uninstalled" || uninstalled.State.Status != StatusUninstalled {
		t.Fatalf("uninstall=%+v err=%v", uninstalled, err)
	}
	if _, err := os.Lstat(filepath.Dir(installedBinary)); !os.IsNotExist(err) {
		t.Fatalf("immutable release directory remains after uninstall: %v", err)
	}
	opened, err := instance.Open(context.Background(), layout.StateDir)
	if err != nil {
		t.Fatalf("protected instance was not preserved: %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeIntegrationUpload(t *testing.T, directory, name string, payload []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, payload, 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

func integrationReleaseURL(release, name string) string {
	return "https://downloads.example.test/releases/" + release + "/" + name
}

func integrationGoEnvironment(overrides ...string) []string {
	replaced := make(map[string]bool, len(overrides))
	for _, override := range overrides {
		key, _, _ := strings.Cut(override, "=")
		replaced[key] = true
	}
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !replaced[key] {
			environment = append(environment, entry)
		}
	}
	return append(environment, overrides...)
}
