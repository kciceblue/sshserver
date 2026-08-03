package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kciceblue/sshserver/runtime/internal/auth"
	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/deployment"
	"github.com/kciceblue/sshserver/runtime/internal/instance"
	serverpkg "github.com/kciceblue/sshserver/runtime/internal/server"
)

func TestVersionJSONReportsExactBuildIdentity(t *testing.T) {
	original := buildinfo.EncodedIdentity
	expected := buildinfo.Identity{
		Release:         "v1.2.3",
		SourceRevision:  strings.Repeat("a", 40),
		BuildToolchain:  "go1.25.0",
		BuildIdentity:   strings.Repeat("b", 64),
		ProtocolVersion: "1",
		StorageSchema:   "1",
	}
	encoded, err := buildinfo.Encode(expected)
	if err != nil {
		t.Fatal(err)
	}
	buildinfo.EncodedIdentity = encoded
	t.Cleanup(func() { buildinfo.EncodedIdentity = original })
	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{"version", "--format=json"})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("version code=%d stderr=%q", code, stderr.String())
	}
	var identity buildinfo.Identity
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&identity); err != nil {
		t.Fatal(err)
	}
	if identity != expected {
		t.Fatalf("identity=%+v want=%+v", identity, expected)
	}
}

func TestDeployPreviewCLIIsCanonicalAndNeverMutatesTargetLayout(t *testing.T) {
	if testing.Short() {
		t.Skip("real release-binary preview is disabled in short mode")
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	physicalHome, err := filepath.EvalSymlinks(userHome)
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.MkdirTemp(physicalHome, ".sshserver-cli-preview-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	upload := filepath.Join(home, "upload")
	if err := os.Mkdir(upload, 0o700); err != nil {
		t.Fatal(err)
	}
	installRoot := filepath.Join(home, "deployment")
	stateDir := filepath.Join(home, "state")

	goVersion := exec.Command("go", "env", "GOVERSION")
	goVersion.Env = cliGoEnvironment("GOENV=off", "GOTOOLCHAIN=local")
	goVersionOutput, err := goVersion.Output()
	if err != nil {
		t.Fatal(err)
	}
	toolchain := strings.TrimSpace(string(goVersionOutput))
	release := "v0.0.0-preview-cli-test"
	sourceRevision := strings.Repeat("a", 40)
	target := deployment.Target{OS: runtime.GOOS, Architecture: runtime.GOARCH}
	buildIdentity, err := deployment.DeriveBuildIdentity(release, sourceRevision, toolchain, target)
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := buildinfo.Encode(buildinfo.Identity{
		Release: release, SourceRevision: sourceRevision, BuildToolchain: toolchain, BuildIdentity: buildIdentity,
		ProtocolVersion: config.ProtocolMajor, StorageSchema: config.StorageSchema,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(upload, "sshserver")
	runtimeRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command(
		"go", "build", "-mod=readonly", "-buildmode=exe", "-buildvcs=true", "-tags=", "-trimpath",
		"-ldflags=-X github.com/kciceblue/sshserver/runtime/internal/buildinfo.EncodedIdentity="+attestation,
		"-o", artifactPath, "./cmd/sshserver",
	)
	build.Dir = runtimeRoot
	build.Env = cliGoEnvironment(
		"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=", "GOTOOLCHAIN=local", "CGO_ENABLED=0",
		"GOOS="+target.OS, "GOARCH="+target.Architecture, "GOAMD64=v1", "GOARM64=v8.0",
	)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build preview CLI artifact: %v\n%s", err, output)
	}
	if err := os.Chmod(artifactPath, 0o500); err != nil {
		t.Fatal(err)
	}
	artifactPayload, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	licensePayload := []byte("Apache-2.0 preview CLI license fixture\n")
	noticePayload := []byte("preview CLI notice fixture\n")
	licensePath := writeCLIProtectedInput(t, upload, "LICENSE", licensePayload, 0o400)
	noticePath := writeCLIProtectedInput(t, upload, "NOTICE", noticePayload, 0o400)
	manifest := deployment.ReleaseManifest{
		ManifestVersion: deployment.ManifestVersion,
		Release:         release, SourceRevision: sourceRevision, BuildToolchain: toolchain,
		ProtocolVersion: config.ProtocolMajor, StorageSchema: config.StorageSchema,
		DownloadOrigin: "https://downloads.example.test",
		ReleaseFiles: []deployment.ReleaseFile{
			{Name: "LICENSE", URL: cliReleaseURL(release, "LICENSE"), Bytes: int64(len(licensePayload)), SHA256: deployment.SHA256Hex(licensePayload)},
			{Name: "NOTICE", URL: cliReleaseURL(release, "NOTICE"), Bytes: int64(len(noticePayload)), SHA256: deployment.SHA256Hex(noticePayload)},
		},
	}
	for _, supported := range deployment.SupportedTargets() {
		identity, err := deployment.DeriveBuildIdentity(release, sourceRevision, toolchain, supported)
		if err != nil {
			t.Fatal(err)
		}
		artifact := deployment.ReleaseArtifact{
			OS: supported.OS, Architecture: supported.Architecture, BuildIdentity: identity,
			URL:   cliReleaseURL(release, "sshserver-"+supported.OS+"-"+supported.Architecture),
			Bytes: 1, SHA256: strings.Repeat("f", 64),
		}
		if supported == target {
			artifact.Bytes = int64(len(artifactPayload))
			artifact.SHA256 = deployment.SHA256Hex(artifactPayload)
		}
		manifest.Artifacts = append(manifest.Artifacts, artifact)
	}
	manifestPayload, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := writeCLIProtectedInput(t, upload, "release-manifest.json", manifestPayload, 0o400)
	manifestSHA256 := deployment.SHA256Hex(manifestPayload)
	args := []string{
		"deploy", "preview", "--home-dir", home, "--install-root", installRoot, "--state-dir", stateDir,
		"--manifest", manifestPath, "--manifest-sha256", manifestSHA256, "--artifact", artifactPath,
		"--license", licensePath, "--notice", noticePath,
	}
	run := func() ([]byte, string, int) {
		var stdout, stderr bytes.Buffer
		code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), args)
		return append([]byte(nil), stdout.Bytes()...), stderr.String(), code
	}
	first, firstStderr, firstCode := run()
	second, secondStderr, secondCode := run()
	if firstCode != 0 || secondCode != 0 || firstStderr != "" || secondStderr != "" || !bytes.Equal(first, second) {
		t.Fatalf("preview runs code=%d/%d stderr=%q/%q equal=%t", firstCode, secondCode, firstStderr, secondStderr, bytes.Equal(first, second))
	}
	preview, err := deployment.ParseDeploymentPreview(first)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Classification != deployment.PreviewFresh || !preview.ApplyAllowed || preview.Target.OS != target.OS ||
		preview.Target.Architecture != target.Architecture || preview.Paths.HomeDir != home || preview.Paths.InstallRoot != installRoot ||
		preview.Paths.StateDir != stateDir || !preview.Assertions.Network.LoopbackOnly {
		t.Fatalf("CLI preview=%+v", preview)
	}
	for _, path := range []string{installRoot, stateDir, filepath.Join(installRoot, ".deployment.lock"), preview.Paths.ServiceDefinition} {
		if path == "" {
			continue
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("preview CLI created %s: %v", path, err)
		}
	}

	badArtifact := writeCLIProtectedInput(t, upload, "bad-sshserver", append(append([]byte(nil), artifactPayload...), 0), 0o500)
	badArgs := append([]string(nil), args...)
	for index := range badArgs {
		if badArgs[index] == artifactPath {
			badArgs[index] = badArtifact
		}
	}
	var badStdout, badStderr bytes.Buffer
	badCode := (Runner{Stdout: &badStdout, Stderr: &badStderr}).Run(context.Background(), badArgs)
	if badCode == 0 || badStdout.Len() != 0 || !strings.Contains(badStderr.String(), "artifact source size") {
		t.Fatalf("bad preview code=%d stdout=%q stderr=%q", badCode, badStdout.String(), badStderr.String())
	}
	for _, path := range []string{installRoot, stateDir} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed preview CLI created %s: %v", path, err)
		}
	}
}

func TestDeployStatusReportsUninstalledWithoutMutatingRuntime(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	testHome, err := os.MkdirTemp(home, ".sshserver-cli-deploy-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(testHome) })
	if err := os.Chmod(testHome, 0o700); err != nil {
		t.Fatal(err)
	}
	installRoot := filepath.Join(testHome, "deployment")
	stateDir := filepath.Join(testHome, "state")
	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{
		"deploy", "status",
		"--home-dir", testHome,
		"--install-root", installRoot,
		"--state-dir", stateDir,
	})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("deploy status code=%d stderr=%q", code, stderr.String())
	}
	var result struct {
		Status           string `json:"status"`
		Running          bool   `json:"running"`
		RecoveryRequired bool   `json:"recovery_required"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "uninstalled" || result.Running || result.RecoveryRequired {
		t.Fatalf("deploy status=%+v", result)
	}
	if _, err := os.Lstat(installRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only status created deployment root: %v", err)
	}
}

func TestDeployStatusExplicitLayoutDoesNotConsultBrokenAmbientDefaults(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	explicitHome := t.TempDir()
	if err := os.Chmod(explicitHome, 0o700); err != nil {
		t.Fatal(err)
	}
	installRoot := filepath.Join(explicitHome, "deployment")
	stateDir := filepath.Join(explicitHome, "state")
	t.Setenv("HOME", filepath.Join(t.TempDir(), "missing-home"))
	t.Setenv("XDG_DATA_HOME", "relative-data-home")
	t.Setenv("XDG_STATE_HOME", "relative-state-home")
	t.Setenv("XDG_CONFIG_HOME", "relative-config-home")

	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{
		"deploy", "status",
		"--home-dir", explicitHome,
		"--install-root", installRoot,
		"--state-dir", stateDir,
	})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("explicit deploy status code=%d stderr=%q", code, stderr.String())
	}
	var result struct {
		Status           string `json:"status"`
		Running          bool   `json:"running"`
		RecoveryRequired bool   `json:"recovery_required"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "uninstalled" || result.Running || result.RecoveryRequired {
		t.Fatalf("explicit deploy status=%+v", result)
	}
	if _, err := os.Lstat(installRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only explicit status created deployment root: %v", err)
	}
}

func TestDeployStatusRejectsPartialExplicitLayoutWithoutConsultingDefaults(t *testing.T) {
	t.Setenv("HOME", filepath.Join(t.TempDir(), "missing-home"))
	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{
		"deploy", "status", "--home-dir", t.TempDir(),
	})
	if code == 0 || stdout.Len() != 0 || !strings.Contains(
		stderr.String(),
		"--home-dir, --install-root, and --state-dir must be supplied together",
	) {
		t.Fatalf("partial deploy status code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestMutatingDeployCommandsKeepIndependentLayoutOverrides(t *testing.T) {
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	physicalHome, err := filepath.EvalSymlinks(userHome)
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.MkdirTemp(physicalHome, ".sshserver-cli-flags-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	defaults, err := deployment.DefaultLayout()
	if err != nil {
		t.Fatal(err)
	}
	overrideState := filepath.Join(home, "independent-state-override")
	for _, operation := range []string{"preview", "apply", "recover", "rollback", "uninstall"} {
		t.Run(operation, func(t *testing.T) {
			values, flags, err := (Runner{Stderr: io.Discard}).newDeploymentFlags("deploy " + operation)
			if err != nil {
				t.Fatal(err)
			}
			if err := flags.Parse([]string{"--state-dir", overrideState}); err != nil {
				t.Fatal(err)
			}
			if values.homeDir != defaults.HomeDir || values.installRoot != defaults.InstallRoot || values.stateDir != overrideState {
				t.Fatalf("merged %s layout = %+v, defaults=%+v", operation, values, defaults)
			}
			if _, err := values.lifecycle(); err != nil {
				t.Fatalf("single-field %s override rejected: %v", operation, err)
			}
		})
	}
}

func TestDeployApplyRequiresExactPinnedInputs(t *testing.T) {
	for _, operation := range []string{"preview", "apply", "recover"} {
		t.Run(operation, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{"deploy", operation})
			if code == 0 || !strings.Contains(stderr.String(), "requires --manifest") || stdout.Len() != 0 {
				t.Fatalf("deploy %s code=%d stdout=%q stderr=%q", operation, code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestDeployApplyResultWritesOneCredentialFreeLocatorLine(t *testing.T) {
	locator := deployment.DeploymentLocator{
		Version:             "1",
		LifecycleBinaryPath: "/home/alice/.local/share/jat/sshserver-deployment/versions/v1.2.3/sshserver-linux-amd64",
		HomeDir:             "/home/alice",
		InstallRoot:         "/home/alice/.local/share/jat/sshserver-deployment",
		StateDir:            "/home/alice/.local/state/jat/sshserver",
		Release:             "v1.2.3",
		OS:                  "linux",
		Architecture:        "amd64",
		ManifestSHA256:      strings.Repeat("a", 64),
		BinarySHA256:        strings.Repeat("b", 64),
		BinaryBytes:         12345,
	}
	var stdout bytes.Buffer
	runner := Runner{Stdout: &stdout, Stderr: io.Discard}
	if err := runner.writeApplyResult(deployment.ApplyResult{
		Status:            "active",
		DeploymentLocator: locator,
		State: deployment.DeploymentState{
			StateVersion: deployment.DeploymentStateVersion,
			Generation:   1,
			Status:       deployment.StatusActive,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Count(stdout.String(), "\n") != 1 || !strings.HasSuffix(stdout.String(), "\n") {
		t.Fatalf("deploy result is not exact one-line JSON: %q", stdout.String())
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	var encodedLocator map[string]json.RawMessage
	if err := json.Unmarshal(result["deployment_locator"], &encodedLocator); err != nil {
		t.Fatal(err)
	}
	exactKeys := []string{
		"version", "lifecycle_binary_path", "home_dir", "install_root", "state_dir",
		"release", "os", "architecture", "manifest_sha256", "binary_sha256", "binary_bytes",
	}
	if len(encodedLocator) != len(exactKeys) {
		t.Fatalf("deployment locator keys=%v", encodedLocator)
	}
	for _, key := range exactKeys {
		if _, ok := encodedLocator[key]; !ok {
			t.Fatalf("deployment locator missing %q: %s", key, stdout.Bytes())
		}
	}
	for _, forbidden := range []string{
		"instance_secret", "enrollment_grant", "device_token", "bearer", "password",
		"service_definition", "transaction_id", "instance_id", "vault_id", "host_id", "endpoint_port",
	} {
		if _, ok := encodedLocator[forbidden]; ok {
			t.Fatalf("deployment locator exposes forbidden field %q", forbidden)
		}
	}
}

func TestDeployPreviewWriterEmitsDeterministicCanonicalJSON(t *testing.T) {
	home := "/home/alice"
	installRoot := filepath.Join(home, "deployment")
	stateDir := filepath.Join(home, "state")
	releaseDir := filepath.Join(installRoot, "versions", "v1.2.3")
	binaryPath := filepath.Join(releaseDir, "sshserver-linux-amd64")
	buildIdentity, err := deployment.DeriveBuildIdentity(
		"v1.2.3",
		strings.Repeat("a", 40),
		"go1.25.0",
		deployment.Target{OS: "linux", Architecture: "amd64"},
	)
	if err != nil {
		t.Fatal(err)
	}
	preview := deployment.DeploymentPreview{
		Version:        deployment.DeploymentPreviewVersion,
		Classification: deployment.PreviewBlocked,
		ApplyAllowed:   false,
		BlockReason:    "installed_release_verification_failed",
		Release: deployment.PreviewReleaseIdentity{
			Release: "v1.2.3", SourceRevision: strings.Repeat("a", 40), BuildToolchain: "go1.25.0",
			BuildIdentity: buildIdentity, ProtocolVersion: "1", StorageSchema: "1",
		},
		Target: deployment.PreviewTargetIdentity{OS: "linux", Architecture: "amd64"},
		Inputs: deployment.PreviewInputs{
			Manifest: deployment.PreviewManifestIdentity{Path: filepath.Join(home, "upload", "manifest.json"), Bytes: 100, SHA256: strings.Repeat("c", 64)},
			Artifact: deployment.PreviewArtifactIdentity{SourcePath: filepath.Join(home, "upload", "sshserver"), URL: "https://downloads.example.test/releases/v1.2.3/sshserver-linux-amd64", Bytes: 200, SHA256: strings.Repeat("d", 64)},
			License:  deployment.PreviewSupportFileIdentity{SourcePath: filepath.Join(home, "upload", "LICENSE"), URL: "https://downloads.example.test/releases/v1.2.3/LICENSE", Bytes: 300, SHA256: strings.Repeat("e", 64)},
			Notice:   deployment.PreviewSupportFileIdentity{SourcePath: filepath.Join(home, "upload", "NOTICE"), URL: "https://downloads.example.test/releases/v1.2.3/NOTICE", Bytes: 400, SHA256: strings.Repeat("f", 64)},
		},
		Paths: deployment.PreviewPaths{
			HomeDir: home, InstallRoot: installRoot, VersionsDir: filepath.Join(installRoot, "versions"), ReleaseDir: releaseDir,
			StateDir: stateDir, BinaryPath: binaryPath, LicensePath: filepath.Join(releaseDir, "LICENSE"), NoticePath: filepath.Join(releaseDir, "NOTICE"),
			DeploymentState: filepath.Join(installRoot, "deployment.json"), DeploymentJournal: filepath.Join(installRoot, "deployment-journal.json"),
			LifecycleLock: filepath.Join(installRoot, ".deployment.lock"), AdminSocket: filepath.Join(stateDir, ".enrollment.sock"),
		},
		Manager: deployment.ManagerAvailability{
			Manager: deployment.ManagerForeground,
			Foreground: &deployment.ForegroundFallback{
				Required: true, Reason: "user_service_manager_unavailable",
				Command: []string{binaryPath, "serve", "--state-dir", stateDir}, Supervised: true,
			},
		},
		Existing: deployment.PreviewExisting{InstanceState: "missing"},
		Actions:  []deployment.PreviewAction{},
		Assertions: deployment.PreviewAssertions{
			Data: deployment.PreviewDataAssertions{
				PreserveStateDirectory: true, PreserveInstanceIDs: true, PreserveDatabase: true,
				PreserveDeviceRegistry: true, PreserveInstanceSecret: true,
			},
			Network: deployment.PreviewNetworkAssertions{LoopbackOnly: true, Listeners: []string{"127.0.0.1:37421", "[::1]:37421"}},
			Scope:   deployment.PreviewScopeAssertions{CurrentUserOnly: true},
		},
	}
	var first, second bytes.Buffer
	if err := (Runner{Stdout: &first, Stderr: io.Discard}).writePreviewResult(preview); err != nil {
		t.Fatal(err)
	}
	if err := (Runner{Stdout: &second, Stderr: io.Discard}).writePreviewResult(preview); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() || strings.Count(first.String(), "\n") != 1 {
		t.Fatalf("preview output is not deterministic one-line JSON: %q / %q", first.String(), second.String())
	}
	parsed, err := deployment.ParseDeploymentPreview(first.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, preview) {
		t.Fatalf("preview changed after CLI round trip\n got=%+v\nwant=%+v", parsed, preview)
	}
}

func TestInitOutputContainsNoSecretAndIsIdempotent(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	var first, second bytes.Buffer
	runner := Runner{Stdout: &first, Stderr: &bytes.Buffer{}}
	args := []string{"init", "--state-dir", stateDir, "--listen", "127.0.0.1:37421"}
	if code := runner.Run(context.Background(), args); code != 0 {
		t.Fatalf("first init exit = %d", code)
	}
	runner.Stdout = &second
	if code := runner.Run(context.Background(), args); code != 0 {
		t.Fatalf("second init exit = %d", code)
	}
	for _, output := range []string{first.String(), second.String()} {
		if strings.Contains(output, "secret") || strings.Contains(output, "token") || strings.Contains(output, "grant") {
			t.Fatalf("init output exposes a credential field: %s", output)
		}
	}
	var firstBody, secondBody map[string]any
	if err := json.Unmarshal(first.Bytes(), &firstBody); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second.Bytes(), &secondBody); err != nil {
		t.Fatal(err)
	}
	if firstBody["instance_id"] != secondBody["instance_id"] || firstBody["vault_id"] != secondBody["vault_id"] {
		t.Fatal("repeated init changed identity")
	}
}

func TestEndpointShowReportsDefaultAndCustomLoopbackPorts(t *testing.T) {
	tests := []struct {
		name      string
		listeners []string
		wantPort  int
	}{
		{name: "default", listeners: nil, wantPort: config.DefaultPort},
		{
			name:      "custom dual stack",
			listeners: []string{"[::1]:45231", "127.0.0.1:45231"},
			wantPort:  45231,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			settings, err := instance.Initialize(context.Background(), stateDir, test.listeners)
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{
				"endpoint", "show", "--format=json", "--state-dir", stateDir,
			})
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("endpoint show code=%d stderr=%q", code, stderr.String())
			}
			if !strings.HasSuffix(stdout.String(), "\n") || strings.Count(stdout.String(), "\n") != 1 {
				t.Fatalf("endpoint output is not strict one-line JSON: %q", stdout.String())
			}
			var response struct {
				ProtocolVersion string `json:"protocol_version"`
				InstanceID      string `json:"instance_id"`
				VaultID         string `json:"vault_id"`
				LoopbackPort    int    `json:"loopback_port"`
			}
			decoder := json.NewDecoder(&stdout)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&response); err != nil {
				t.Fatal(err)
			}
			if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
				t.Fatalf("endpoint output has trailing JSON: %v", err)
			}
			if response.ProtocolVersion != config.ProtocolMajor || response.InstanceID != settings.InstanceID ||
				response.VaultID != settings.VaultID || response.LoopbackPort != test.wantPort {
				t.Fatalf("endpoint response=%+v settings=%+v", response, settings)
			}
		})
	}
}

func TestCommandStateDirForExecutableFallsBackOnlyOutsideDeployment(t *testing.T) {
	arbitrary := filepath.Join(t.TempDir(), "sshserver")
	if err := os.WriteFile(arbitrary, []byte("test executable"), 0o700); err != nil {
		t.Fatal(err)
	}
	defaultState := filepath.Join(t.TempDir(), "default-state")
	t.Setenv("XDG_STATE_HOME", filepath.Dir(filepath.Dir(defaultState)))
	resolved, err := stateDirForExecutable(arbitrary)
	if err != nil {
		t.Fatal(err)
	}
	want, err := config.DefaultStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if resolved != want {
		t.Fatalf("resolved state directory = %q, want default %q", resolved, want)
	}
}

func TestEndpointShowIsReadOnlyAndEmitsNoSecret(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if _, err := instance.Initialize(context.Background(), stateDir, []string{"127.0.0.1:40123"}); err != nil {
		t.Fatal(err)
	}
	paths := config.ForStateDir(stateDir)
	secret, err := config.ReadSecret(paths.InstanceSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	secretText := base64.RawURLEncoding.EncodeToString(secret)

	if err := os.Chmod(paths.Config, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.InstallMarker, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(stateDir, 0o700) })
	before := snapshotStateTree(t, stateDir)

	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{
		"endpoint", "show", "--state-dir", stateDir,
	})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("read-only endpoint show code=%d stderr=%q", code, stderr.String())
	}
	after := snapshotStateTree(t, stateDir)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("endpoint discovery changed state tree\nbefore=%#v\nafter=%#v", before, after)
	}
	output := stdout.String()
	for _, forbidden := range []string{secretText, "instance_secret", "enrollment_grant", "token"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("endpoint discovery exposed %q in %q", forbidden, output)
		}
	}
}

func TestEndpointShowFailsClosedWithoutUsableCompletedConfig(t *testing.T) {
	t.Run("missing state remains missing", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "missing")
		assertEndpointShowFails(t, stateDir, "endpoint instance state is unavailable")
		if _, err := os.Lstat(stateDir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read-only endpoint created missing state: %v", err)
		}
	})

	t.Run("incomplete marker", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "state")
		if _, err := instance.Initialize(context.Background(), stateDir, []string{"127.0.0.1:40124"}); err != nil {
			t.Fatal(err)
		}
		marker := []byte("{\"generation\":\"1\",\"phase\":\"initializing\",\"state\":\"resume\"}\n")
		if err := os.WriteFile(config.ForStateDir(stateDir).InstallMarker, marker, 0o600); err != nil {
			t.Fatal(err)
		}
		assertEndpointShowFails(t, stateDir, "endpoint instance state is unavailable")
	})

	t.Run("corrupt config", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "state")
		if _, err := instance.Initialize(context.Background(), stateDir, []string{"127.0.0.1:40125"}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(config.ForStateDir(stateDir).Config, []byte("{not-json\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		assertEndpointShowFails(t, stateDir, "endpoint instance state is unavailable")
	})

	t.Run("IPv6 only", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "state")
		if _, err := instance.Initialize(context.Background(), stateDir, []string{"[::1]:40126"}); err != nil {
			t.Fatal(err)
		}
		assertEndpointShowFails(t, stateDir, "no usable 127.0.0.1 listener")
	})

	t.Run("insecure state directory", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "state")
		if _, err := instance.Initialize(context.Background(), stateDir, []string{"127.0.0.1:40127"}); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(stateDir, 0o777); err != nil {
			t.Fatal(err)
		}
		assertEndpointShowFails(t, stateDir, "endpoint instance state is unavailable")
	})

	t.Run("symlinked state directory", func(t *testing.T) {
		root := t.TempDir()
		stateDir := filepath.Join(root, "state")
		if _, err := instance.Initialize(context.Background(), stateDir, []string{"127.0.0.1:40128"}); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "state-link")
		if err := os.Symlink(stateDir, link); err != nil {
			t.Fatal(err)
		}
		assertEndpointShowFails(t, link, "endpoint instance state is unavailable")
	})

	t.Run("symlinked protected config", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "state")
		if _, err := instance.Initialize(context.Background(), stateDir, []string{"127.0.0.1:40129"}); err != nil {
			t.Fatal(err)
		}
		configPath := config.ForStateDir(stateDir).Config
		target := filepath.Join(stateDir, "config-target.json")
		if err := os.Rename(configPath, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, configPath); err != nil {
			t.Fatal(err)
		}
		assertEndpointShowFails(t, stateDir, "endpoint instance state is unavailable")
	})

	t.Run("insecure protected config", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "state")
		if _, err := instance.Initialize(context.Background(), stateDir, []string{"127.0.0.1:40130"}); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(config.ForStateDir(stateDir).Config, 0o644); err != nil {
			t.Fatal(err)
		}
		assertEndpointShowFails(t, stateDir, "endpoint instance state is unavailable")
	})

	t.Run("FIFO protected marker", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(config.ForStateDir(stateDir).InstallMarker, 0o600); err != nil {
			t.Fatal(err)
		}
		result := make(chan struct {
			stdout string
			stderr string
			code   int
		}, 1)
		go func() {
			var stdout, stderr bytes.Buffer
			code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{
				"endpoint", "show", "--state-dir", stateDir,
			})
			result <- struct {
				stdout string
				stderr string
				code   int
			}{stdout: stdout.String(), stderr: stderr.String(), code: code}
		}()
		select {
		case got := <-result:
			if got.code == 0 || got.stdout != "" || !strings.Contains(got.stderr, "endpoint instance state is unavailable") {
				t.Fatalf("FIFO endpoint result code=%d stdout=%q stderr=%q", got.code, got.stdout, got.stderr)
			}
		case <-time.After(time.Second):
			t.Fatal("endpoint discovery blocked on FIFO marker")
		}
	})
}

func TestEndpointCommandRejectsUnknownFormsAndAppearsInUsage(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{args: []string{"endpoint"}, want: "endpoint requires show"},
		{args: []string{"endpoint", "unknown"}, want: "endpoint supports only show"},
		{args: []string{"endpoint", "show", "extra"}, want: "accepts no positional arguments"},
		{args: []string{"endpoint", "show", "--format=text"}, want: "supports only --format=json"},
		{args: []string{"endpoint", "show", "--unknown=" + strings.Repeat("x", 1_024)}, want: "has invalid options"},
	}
	for _, test := range tests {
		var stdout, stderr bytes.Buffer
		code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), test.args)
		if code == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), test.want) {
			t.Fatalf("args=%q code=%d stdout=%q stderr=%q", test.args, code, stdout.String(), stderr.String())
		}
		if stderr.Len() > 256 {
			t.Fatalf("args=%q produced unbounded stderr: %q", test.args, stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{"help"})
	if code != 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "endpoint") {
		t.Fatalf("help code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestDiscoverableIPv4LoopbackPortRejectsUnsafeListenerSets(t *testing.T) {
	for _, test := range []struct {
		name      string
		listeners []string
		want      string
	}{
		{name: "empty", listeners: nil, want: "no usable"},
		{name: "IPv6 only", listeners: []string{"[::1]:37421"}, want: "no usable"},
		{
			name:      "different ports",
			listeners: []string{"127.0.0.1:37421", "[::1]:37422"},
			want:      "do not share",
		},
		{name: "malformed", listeners: []string{"127.0.0.1"}, want: "invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := discoverableIPv4LoopbackPort(test.listeners); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("listeners=%q error=%v", test.listeners, err)
			}
		})
	}
}

type stateTreeEntry struct {
	Mode    os.FileMode
	ModTime int64
	Bytes   []byte
}

func snapshotStateTree(t *testing.T, root string) map[string]stateTreeEntry {
	t.Helper()
	entries := make(map[string]stateTreeEntry)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entry := stateTreeEntry{Mode: info.Mode(), ModTime: info.ModTime().UnixNano()}
		if info.Mode().IsRegular() {
			entry.Bytes, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		entries[relative] = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func writeCLIProtectedInput(t *testing.T, directory, name string, payload []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, payload, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func cliReleaseURL(release, name string) string {
	return "https://downloads.example.test/releases/" + release + "/" + name
}

func cliGoEnvironment(overrides ...string) []string {
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

func assertEndpointShowFails(t *testing.T, stateDir, want string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{
		"endpoint", "show", "--state-dir", stateDir,
	})
	if code == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), want) {
		t.Fatalf("endpoint show code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stderr.Len() > 256 || strings.Contains(stderr.String(), stateDir) {
		t.Fatalf("endpoint error is unbounded or exposes the state path: %q", stderr.String())
	}
}

func managedEnrollmentCLIFixture(t *testing.T) (deployment.Layout, deployment.ActiveExecutableBinding) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	testHome, err := os.MkdirTemp(home, ".sshserver-cli-managed-enrollment-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(testHome) })
	if err := os.Chmod(testHome, 0o700); err != nil {
		t.Fatal(err)
	}
	layout, err := deployment.NewLayout(testHome, filepath.Join(testHome, "deployment"), filepath.Join(testHome, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := deployment.PrepareLayout(layout); err != nil {
		t.Fatal(err)
	}
	target := deployment.Target{OS: runtime.GOOS, Architecture: runtime.GOARCH}
	binaryPath, err := layout.BinaryPath("v1.2.3", target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	binary := []byte("test executable")
	if err := os.WriteFile(binaryPath, binary, 0o700); err != nil {
		t.Fatal(err)
	}
	release := deployment.InstalledRelease{
		Release:         "v1.2.3",
		SourceRevision:  strings.Repeat("a", 40),
		BuildToolchain:  "go1.25.0",
		BuildIdentity:   strings.Repeat("a", 64),
		ManifestSHA256:  strings.Repeat("a", 64),
		ProtocolVersion: config.ProtocolMajor,
		StorageSchema:   "1",
		OS:              target.OS,
		Architecture:    target.Architecture,
		BinaryPath:      binaryPath,
		BinaryBytes:     int64(len(binary)),
		BinarySHA256:    strings.Repeat("a", 64),
		LicenseBytes:    1,
		LicenseSHA256:   strings.Repeat("a", 64),
		NoticeBytes:     1,
		NoticeSHA256:    strings.Repeat("a", 64),
	}
	if err := deployment.SaveState(layout, deployment.DeploymentState{
		StateVersion: deployment.DeploymentStateVersion,
		Generation:   7,
		Status:       deployment.StatusForeground,
		Manager:      deployment.ManagerForeground,
		StateDir:     layout.StateDir,
		Active:       &release,
	}); err != nil {
		t.Fatal(err)
	}
	binding, err := deployment.ActiveExecutableForExecutable(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	return layout, binding
}

func TestRenderServiceRejectsRelativePaths(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{
		"service", "render", "--platform", "linux", "--binary", "relative", "--state-dir", "/tmp/state",
	})
	if code == 0 || !strings.Contains(stderr.String(), "absolute") {
		t.Fatalf("relative binary result: code=%d stderr=%q", code, stderr.String())
	}
}

func TestHealthRejectsResponseLargerThanLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = writer.Write([]byte(`{"status":"ok","protocol_version":"1"}` + strings.Repeat(" ", 1025)))
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := (Runner{Stdout: &stdout, Stderr: &stderr}).Run(context.Background(), []string{
		"health", "--address", strings.TrimPrefix(server.URL, "http://"),
	})
	if code == 0 || !strings.Contains(stderr.String(), "exceeds 1024 bytes") {
		t.Fatalf("oversized health result: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestManagedEnrollmentCreateAcceptsOnlyRecordedExplicitStateDir(t *testing.T) {
	layout, binding := managedEnrollmentCLIFixture(t)
	listener, err := net.Listen("unix", config.ForStateDir(layout.StateDir).AdminSocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	type adminResult struct {
		request []byte
		err     error
	}
	adminResultCh := make(chan adminResult, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			adminResultCh <- adminResult{err: err}
			return
		}
		defer connection.Close()
		request, err := io.ReadAll(connection)
		if err == nil {
			response := struct {
				ProtocolVersion string `json:"protocol_version"`
				InstanceID      string `json:"instance_id"`
				VaultID         string `json:"vault_id"`
				InstanceSecret  string `json:"instance_secret"`
				EnrollmentGrant string `json:"enrollment_grant"`
				ExpiresAt       string `json:"expires_at"`
				LoopbackPort    int    `json:"loopback_port"`
			}{
				ProtocolVersion: config.ProtocolMajor,
				InstanceID:      "00000000-0000-4000-8000-000000000001",
				VaultID:         "00000000-0000-4000-8000-000000000002",
				InstanceSecret:  base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
				EnrollmentGrant: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32)),
				ExpiresAt:       "2026-08-03T00:00:00.000Z",
				LoopbackPort:    37421,
			}
			err = json.NewEncoder(connection).Encode(response)
		}
		adminResultCh <- adminResult{request: request, err: err}
	}()

	var stdout, stderr bytes.Buffer
	runner := Runner{
		Stdout: &stdout,
		Stderr: &stderr,
		executablePath: func() (string, error) {
			return binding.BinaryPath, nil
		},
	}
	if code := runner.Run(context.Background(), []string{
		"enrollment", "create", "--format=json", "--state-dir", layout.StateDir,
	}); code != 0 {
		t.Fatalf("managed enrollment create exit=%d stderr=%q", code, stderr.String())
	}
	if stderr.Len() != 0 || stdout.Len() == 0 {
		t.Fatalf("managed enrollment stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	admin := <-adminResultCh
	if admin.err != nil {
		t.Fatal(admin.err)
	}
	var request struct {
		Operation  string                              `json:"operation"`
		DirectInit bool                                `json:"direct_init"`
		Deployment *deployment.ActiveExecutableBinding `json:"deployment"`
	}
	decoder := json.NewDecoder(bytes.NewReader(admin.request))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		t.Fatal(err)
	}
	if request.Operation != "enrollment_create" || request.DirectInit || request.Deployment == nil ||
		request.Deployment.Generation != binding.Generation || request.Deployment.BinaryPath != binding.BinaryPath ||
		request.Deployment.BinarySHA256 != binding.BinarySHA256 {
		t.Fatalf("managed enrollment request = %+v, want binding %+v", request, binding)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	mismatchedStateDir := filepath.Join(layout.HomeDir, "other-state")
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run(context.Background(), []string{
		"enrollment", "create", "--format=json", "--state-dir", mismatchedStateDir,
	}); code == 0 {
		t.Fatal("managed enrollment accepted a mismatched explicit state directory")
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "enrollment instance state is unavailable") {
		t.Fatalf("mismatched managed enrollment stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(mismatchedStateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched managed enrollment touched the requested state directory: %v", err)
	}
}

func TestEnrollmentCreateUsesOwnerSocketAndBootstrapsRealHTTPDataPlane(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	testRoot, err := os.MkdirTemp("/tmp", "jat-runtime-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(testRoot) })
	stateDir := filepath.Join(testRoot, "state")
	settings, err := instance.Initialize(context.Background(), stateDir, []string{address})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := instance.OpenForServe(context.Background(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- serverpkg.RunWithAdmin(ctx, opened.Settings, opened.Store, opened.Paths) }()
	runtimeStopped := false
	instanceClosed := false
	defer func() {
		cancel()
		if !runtimeStopped {
			select {
			case <-errCh:
			case <-time.After(5 * time.Second):
			}
		}
		if !instanceClosed {
			_ = opened.Close()
		}
	}()
	waitForAdminSocket(t, opened.Paths.AdminSocket, errCh)
	waitForRuntimeHealth(t, address)
	t.Setenv("HOME", filepath.Join(t.TempDir(), "missing-home"))
	t.Setenv("XDG_STATE_HOME", "relative-state-home")

	var stdout, stderr bytes.Buffer
	runner := Runner{Stdout: &stdout, Stderr: &stderr}
	if code := runner.Run(context.Background(), []string{"enrollment", "create", "--format=json", "--state-dir", stateDir}); code != 0 {
		t.Fatalf("enrollment create exit=%d stderr=%q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("enrollment stderr=%q", stderr.String())
	}
	var bootstrap struct {
		ProtocolVersion string `json:"protocol_version"`
		InstanceID      string `json:"instance_id"`
		VaultID         string `json:"vault_id"`
		InstanceSecret  string `json:"instance_secret"`
		EnrollmentGrant string `json:"enrollment_grant"`
		ExpiresAt       string `json:"expires_at"`
		LoopbackPort    int    `json:"loopback_port"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &bootstrap); err != nil {
		t.Fatal(err)
	}
	_, portText, _ := net.SplitHostPort(address)
	if bootstrap.ProtocolVersion != "1" || bootstrap.InstanceID != settings.InstanceID || bootstrap.VaultID != settings.VaultID ||
		portText != fmt.Sprint(bootstrap.LoopbackPort) || strings.Count(strings.TrimSpace(stdout.String()), "\n") != 0 {
		t.Fatalf("bootstrap=%+v output=%q", bootstrap, stdout.String())
	}
	secret, err := config.ReadSecret(opened.Paths.InstanceSecret)
	if err != nil {
		t.Fatal(err)
	}
	if bootstrap.InstanceSecret != base64.RawURLEncoding.EncodeToString(secret) {
		clear(secret)
		t.Fatal("bootstrap instance secret does not match protected host state")
	}
	clear(secret)
	grant, err := base64.RawURLEncoding.Strict().DecodeString(bootstrap.EnrollmentGrant)
	if err != nil || len(grant) != 32 {
		t.Fatalf("grant length=%d error=%v", len(grant), err)
	}
	socketInfo, err := os.Lstat(opened.Paths.AdminSocket)
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm() != 0o600 {
		t.Fatalf("admin socket mode=%v error=%v", socketInfo, err)
	}

	deviceToken := bytes.Repeat([]byte{0x5a}, 32)
	deviceID := "00000000-0000-4000-8000-000000000003"
	enrollmentID := "00000000-0000-4000-8000-000000000004"
	enrollmentBody, _ := json.Marshal(struct {
		ProtocolVersion string   `json:"protocol_version"`
		EnrollmentID    string   `json:"enrollment_id"`
		DeviceID        string   `json:"device_id"`
		DeviceToken     string   `json:"device_token"`
		Scopes          []string `json:"scopes"`
	}{"1", enrollmentID, deviceID, base64.RawURLEncoding.EncodeToString(deviceToken), auth.FixedScopes()})
	enrollmentRequest := newRuntimeRequest(t, http.MethodPost, address, "/v1/enrollments", "00000000-0000-4000-8000-000000000005", enrollmentBody)
	enrollmentRequest.Header.Set("Authorization", "JAT-Enrollment "+bootstrap.EnrollmentGrant)
	client := &http.Client{Timeout: 3 * time.Second}
	enrollmentResponse, err := client.Do(enrollmentRequest)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentResponseBody, _ := io.ReadAll(enrollmentResponse.Body)
	enrollmentResponse.Body.Close()
	if enrollmentResponse.StatusCode != http.StatusCreated {
		t.Fatalf("enrollment response=%d %s", enrollmentResponse.StatusCode, enrollmentResponseBody)
	}

	syncID := "00000000-0000-4000-8000-000000000006"
	syncBody, _ := json.Marshal(struct {
		ProtocolVersion string `json:"protocol_version"`
		DeviceID        string `json:"device_id"`
		RequestID       string `json:"request_id"`
		AfterCursor     string `json:"after_cursor"`
		AckCursor       string `json:"ack_cursor"`
		Mutations       []any  `json:"mutations"`
	}{"1", deviceID, syncID, "0", "0", []any{}})
	syncRequest := newRuntimeRequest(t, http.MethodPost, address, "/v1/sync", syncID, syncBody)
	syncRequest.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(deviceToken))
	syncResponse, err := client.Do(syncRequest)
	if err != nil {
		t.Fatal(err)
	}
	syncResponseBody, _ := io.ReadAll(syncResponse.Body)
	syncResponse.Body.Close()
	if syncResponse.StatusCode != http.StatusOK || !bytes.Contains(syncResponseBody, []byte(`"server_cursor":"1"`)) {
		t.Fatalf("sync response=%d %s", syncResponse.StatusCode, syncResponseBody)
	}

	cancel()
	select {
	case err := <-errCh:
		runtimeStopped = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runtime did not stop")
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	instanceClosed = true
	if _, err := os.Lstat(opened.Paths.AdminSocket); !os.IsNotExist(err) {
		t.Fatalf("admin socket survived shutdown: %v", err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		payload, err := os.ReadFile(opened.Paths.Database + suffix)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		if bytes.Contains(payload, grant) || bytes.Contains(payload, deviceToken) {
			t.Fatalf("plaintext bootstrap credential persisted in %s", filepath.Base(opened.Paths.Database+suffix))
		}
	}
	clear(grant)
	clear(deviceToken)
}

func waitForAdminSocket(t *testing.T, path string, errCh chan error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return
		}
		select {
		case err := <-errCh:
			errCh <- err
			t.Fatalf("runtime exited before admin socket: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("admin socket did not appear")
}

func waitForRuntimeHealth(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequest(http.MethodGet, "http://"+address+"/v1/healthz", nil)
		request.Header.Set("JAT-Protocol-Version", "1")
		request.Header.Set("JAT-Request-ID", "00000000-0000-4000-8000-000000000010")
		response, err := (&http.Client{Timeout: 250 * time.Millisecond}).Do(request)
		if err == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("runtime health did not become ready")
}

func newRuntimeRequest(t *testing.T, method, address, path, requestID string, body []byte) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, "http://"+address+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("JAT-Protocol-Version", "1")
	request.Header.Set("JAT-Request-ID", requestID)
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	return request
}
