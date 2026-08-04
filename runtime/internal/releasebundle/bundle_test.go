package releasebundle

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	internalbuildinfo "github.com/kciceblue/sshserver/runtime/internal/buildinfo"
	"github.com/kciceblue/sshserver/runtime/internal/deployment"
)

func TestGenerateProducesDeterministicPinnedBundleForFourTargets(t *testing.T) {
	options := testBundleOptions(t)
	result, err := generate(options, acceptTestMetadata)
	if err != nil {
		t.Fatal(err)
	}
	manifestPayload, err := os.ReadFile(result.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := deployment.ParsePinnedManifest(manifestPayload, result.ManifestSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Artifacts) != 4 || len(result.PreviewPaths) != 4 || len(result.UploadFiles) != 4 || manifest.SourceRevision != options.SourceRevision {
		t.Fatalf("manifest/result=%+v / %+v", manifest, result)
	}
	firstManifest := append([]byte(nil), manifestPayload...)
	firstPreviews := make(map[string][]byte)
	for key, path := range result.PreviewPaths {
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		firstPreviews[key] = payload
		if deployment.SHA256Hex(payload) != result.PreviewSHA256[key] {
			t.Fatalf("preview %s hash mismatch", key)
		}
	}
	second, err := generate(options, acceptTestMetadata)
	if err != nil {
		t.Fatal(err)
	}
	secondManifest, _ := os.ReadFile(second.ManifestPath)
	if !bytes.Equal(firstManifest, secondManifest) || result.ManifestSHA256 != second.ManifestSHA256 {
		t.Fatal("identical release inputs produced different manifest bytes")
	}
	for key, first := range firstPreviews {
		secondPayload, _ := os.ReadFile(second.PreviewPaths[key])
		if !bytes.Equal(first, secondPayload) || result.PreviewSHA256[key] != second.PreviewSHA256[key] {
			t.Fatalf("identical release inputs produced different %s preview", key)
		}
	}
	for _, name := range []string{"release-manifest.json", "LICENSE", "NOTICE"} {
		info, err := os.Lstat(filepath.Join(options.DistDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o400 {
			t.Fatalf("%s mode=%o", name, info.Mode().Perm())
		}
	}
	for _, target := range deployment.SupportedTargets() {
		name := "sshserver-" + target.OS + "-" + target.Architecture
		info, err := os.Lstat(filepath.Join(options.DistDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o500 {
			t.Fatalf("%s mode=%o", name, info.Mode().Perm())
		}
	}
}

func TestPreviewAndConfirmedActivationLinesArePinnedTargetSpecificAndUseNoHostTool(t *testing.T) {
	options := testBundleOptions(t)
	result, err := generate(options, acceptTestMetadata)
	if err != nil {
		t.Fatal(err)
	}
	manifestPayload, _ := os.ReadFile(result.ManifestPath)
	if _, err := deployment.ParsePinnedManifest(manifestPayload, result.ManifestSHA256); err != nil {
		t.Fatal(err)
	}
	for _, target := range deployment.SupportedTargets() {
		key := targetKey(target)
		payload, err := os.ReadFile(result.PreviewPaths[key])
		if err != nil {
			t.Fatal(err)
		}
		previewLine := string(payload)
		if strings.Count(previewLine, "\n") != 1 || !strings.HasSuffix(previewLine, "\n") {
			t.Fatalf("%s preview is not exactly one line", key)
		}
		for _, forbidden := range []string{
			"curl", "wget", "fetch", "openssl", "sh ", "bash", "sudo", "sha256sum", "shasum",
			"chmod ", "mkdir ", "rm ", "uname ", "latest", "instance_secret", "enrollment_grant",
			"device_token", "bearer", "password", "|", ";", ">", "<", "(", ")", "$", "'", `"`,
		} {
			if strings.Contains(previewLine, forbidden) {
				t.Fatalf("%s preview contains forbidden %q: %s", key, forbidden, previewLine)
			}
		}
		if strings.Contains(previewLine, "--consume-inputs") || strings.Contains(previewLine, "--confirmed-preview-sha256") ||
			!strings.Contains(previewLine, result.ManifestSHA256) || strings.Count(previewLine, " deploy preview ") != 1 ||
			strings.Count(previewLine, " --artifact ") != 1 {
			t.Fatalf("%s preview lacks the pinned read-only command: %s", key, previewLine)
		}
		files := result.UploadFiles[key]
		for _, name := range []string{files.Directory, files.Manifest, files.Artifact, files.License, files.Notice} {
			if name == "" || !strings.Contains(previewLine, "~/"+name) || !strings.Contains(name, result.ManifestSHA256[:16]) {
				t.Fatalf("%s preview/upload contract lacks %q", key, name)
			}
		}
		if files.DirectoryMode != "0700" || files.ManifestMode != "0400" || files.ArtifactMode != "0500" || files.LicenseMode != "0400" || files.NoticeMode != "0400" {
			t.Fatalf("%s upload modes=%+v", key, files)
		}
		for otherKey, otherFiles := range result.UploadFiles {
			if otherKey != key && strings.Contains(previewLine, "~/"+otherFiles.Artifact) {
				t.Fatalf("%s preview contains another target upload %s", key, otherFiles.Artifact)
			}
		}
		manifest, err := deployment.ParsePinnedManifest(manifestPayload, result.ManifestSHA256)
		if err != nil {
			t.Fatal(err)
		}
		artifact, err := manifest.Artifact(target)
		if err != nil {
			t.Fatal(err)
		}
		confirmed := strings.Repeat("c", 64)
		activation, err := ActivationLine(manifest, int64(len(manifestPayload)), result.ManifestSHA256, artifact, confirmed)
		if err != nil {
			t.Fatal(err)
		}
		activationLine := string(activation)
		if strings.Count(activationLine, " deploy apply ") != 1 || !strings.Contains(activationLine, "--confirmed-preview-sha256 "+confirmed) ||
			!strings.Contains(activationLine, "--consume-inputs") || strings.Contains(activationLine, " deploy preview ") {
			t.Fatalf("%s activation is not bound to the confirmed preview: %s", key, activationLine)
		}
	}
}

func TestGenerateRejectsArtifactWithoutDeterministicIdentity(t *testing.T) {
	options := testBundleOptions(t)
	path := filepath.Join(options.ArtifactDir, "sshserver-linux-amd64")
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("wrong build"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := generate(options, acceptTestMetadata); err == nil || !strings.Contains(err.Error(), "build identity") {
		t.Fatalf("identity error=%v", err)
	}
	if _, err := os.Lstat(options.DistDir); !os.IsNotExist(err) {
		t.Fatalf("failed generation published partial distribution: %v", err)
	}
}

func TestGenerateNeverOverwritesAnImmutablePublishedRelease(t *testing.T) {
	options := testBundleOptions(t)
	first, err := generate(options, acceptTestMetadata)
	if err != nil {
		t.Fatal(err)
	}
	manifestBefore, err := os.ReadFile(first.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	target := deployment.Target{OS: "linux", Architecture: "amd64"}
	identity, err := deployment.DeriveBuildIdentity(options.Release, options.SourceRevision, options.BuildToolchain, target)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(options.ArtifactDir, "sshserver-linux-amd64")
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("different fake Go binary\x00"+identity), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := generate(options, acceptTestMetadata); err == nil || !strings.Contains(err.Error(), "different") {
		t.Fatalf("immutable overwrite error=%v", err)
	}
	manifestAfter, err := os.ReadFile(first.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifestBefore, manifestAfter) {
		t.Fatal("immutable manifest changed after rejected same-release publication")
	}
}

func TestGenerateConcurrentIdenticalPublishersConvergeWithoutReplacement(t *testing.T) {
	options := testBundleOptions(t)
	const publishers = 8
	errorsByPublisher := make(chan error, publishers)
	for range publishers {
		go func() {
			_, err := generate(options, acceptTestMetadata)
			errorsByPublisher <- err
		}()
	}
	for range publishers {
		if err := <-errorsByPublisher; err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(options.DistDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 11 {
		t.Fatalf("published entries=%d want=11", len(entries))
	}
}

func TestReadBundleInputRejectsLinksAndWritableFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "input")
	if err := os.WriteFile(path, []byte("input"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBundleInput(path, 1024); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o622); err != nil {
		t.Fatal(err)
	}
	if _, err := readBundleInput(path, 1024); err == nil {
		t.Fatal("writable release input accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readBundleInput(link, 1024); err == nil {
		t.Fatal("release input symlink accepted")
	}
	second := filepath.Join(root, "second")
	if err := os.Link(path, second); err != nil {
		t.Fatal(err)
	}
	if _, err := readBundleInput(path, 1024); err == nil {
		t.Fatal("hard-linked release input accepted")
	}
}

func TestFrozenGoBuildMetadataValidationIsExact(t *testing.T) {
	target := deployment.Target{OS: "linux", Architecture: "amd64"}
	release := "v1.2.3"
	sourceRevision := strings.Repeat("a", 40)
	toolchain := "go1.25.0"
	identity, err := deployment.DeriveBuildIdentity(release, sourceRevision, toolchain, target)
	if err != nil {
		t.Fatal(err)
	}
	valid := testGoBuildInfo(target, sourceRevision, toolchain)
	if err := validateGoBuildInfo(valid, target, sourceRevision, toolchain); err != nil {
		t.Fatal(err)
	}
	withoutVCS := *valid
	withoutVCS.Settings = append([]debug.BuildSetting(nil), valid.Settings...)
	for _, key := range []string{"vcs", "vcs.revision", "vcs.time", "vcs.modified"} {
		removeBuildSetting(&withoutVCS, key)
	}
	if err := validateGoBuildInfo(&withoutVCS, target, sourceRevision, toolchain); err != nil {
		t.Fatalf("nested-module build metadata without VCS fields was rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*debug.BuildInfo)
	}{
		{name: "main package", mutate: func(info *debug.BuildInfo) { info.Path += "/other" }},
		{name: "module version", mutate: func(info *debug.BuildInfo) { info.Main.Version = "v1.2.3" }},
		{name: "pseudo-version revision", mutate: func(info *debug.BuildInfo) {
			info.Main.Version = "v0.0.0-20260803000000-" + strings.Repeat("b", 12)
		}},
		{name: "pseudo-version timestamp", mutate: func(info *debug.BuildInfo) {
			info.Main.Version = "v0.0.0-20260804000000-" + sourceRevision[:12]
		}},
		{name: "duplicate", mutate: func(info *debug.BuildInfo) {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: "GOOS", Value: "linux"})
		}},
		{name: "dirty", mutate: func(info *debug.BuildInfo) { setBuildSetting(info, "vcs.modified", "true") }},
		{name: "partial VCS", mutate: func(info *debug.BuildInfo) { removeBuildSetting(info, "vcs.time") }},
		{name: "microarchitecture", mutate: func(info *debug.BuildInfo) { setBuildSetting(info, "GOAMD64", "v3") }},
		{name: "tags", mutate: func(info *debug.BuildInfo) {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: "-tags", Value: "unexpected"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := *valid
			candidate.Settings = append([]debug.BuildSetting(nil), valid.Settings...)
			test.mutate(&candidate)
			if err := validateGoBuildInfo(&candidate, target, sourceRevision, toolchain); err == nil {
				t.Fatal("drifted build metadata accepted")
			}
		})
	}
	emptyMainVersion := *valid
	emptyMainVersion.Settings = append([]debug.BuildSetting(nil), valid.Settings...)
	emptyMainVersion.Main.Version = ""
	if err := validateGoBuildInfo(&emptyMainVersion, target, sourceRevision, toolchain); err != nil {
		t.Fatalf("supported empty local main-module version was rejected: %v", err)
	}
	pseudoMainVersion := *valid
	pseudoMainVersion.Settings = append([]debug.BuildSetting(nil), valid.Settings...)
	pseudoMainVersion.Main.Version = "v0.0.0-20260803000000-" + sourceRevision[:12]
	if err := validateGoBuildInfo(&pseudoMainVersion, target, sourceRevision, toolchain); err != nil {
		t.Fatalf("exact VCS-derived local main-module version was rejected: %v", err)
	}
	pseudoWithoutVCS := withoutVCS
	pseudoWithoutVCS.Settings = append([]debug.BuildSetting(nil), withoutVCS.Settings...)
	pseudoWithoutVCS.Main.Version = pseudoMainVersion.Main.Version
	if err := validateGoBuildInfo(&pseudoWithoutVCS, target, sourceRevision, toolchain); err != nil {
		t.Fatalf("exact pseudo-version without nested-module VCS fields was rejected: %v", err)
	}
	if err := verifyGoBuildMetadata([]byte("not a Go executable"), target, release, sourceRevision, toolchain, identity); err == nil {
		t.Fatal("non-Go artifact metadata accepted")
	}
}

func TestRealFourTargetBuildsContainExactFrozenAttestations(t *testing.T) {
	if testing.Short() {
		t.Skip("real four-target build validation is disabled in short mode")
	}
	goVersion := exec.Command("go", "env", "GOVERSION")
	goVersion.Env = testGoEnvironment("GOENV=off", "GOTOOLCHAIN=local")
	output, err := goVersion.Output()
	if err != nil {
		t.Fatal(err)
	}
	toolchain := strings.TrimSpace(string(output))
	runtimeRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	release := "v0.0.0-metadata-test"
	sourceRevision := currentTestSourceRevision(runtimeRoot)
	for _, target := range deployment.SupportedTargets() {
		t.Run(target.OS+"-"+target.Architecture, func(t *testing.T) {
			identity, err := deployment.DeriveBuildIdentity(release, sourceRevision, toolchain, target)
			if err != nil {
				t.Fatal(err)
			}
			attestation, err := internalbuildinfo.Encode(internalbuildinfo.Identity{
				Release:         release,
				SourceRevision:  sourceRevision,
				BuildToolchain:  toolchain,
				BuildIdentity:   identity,
				ProtocolVersion: "1",
				StorageSchema:   "1",
			})
			if err != nil {
				t.Fatal(err)
			}
			binaryPath := filepath.Join(t.TempDir(), "sshserver-"+target.OS+"-"+target.Architecture)
			build := exec.Command(
				"go", "build", "-mod=readonly", "-buildmode=exe", "-buildvcs=true", "-tags=", "-trimpath",
				"-ldflags=-X github.com/kciceblue/sshserver/runtime/internal/buildinfo.EncodedIdentity="+attestation,
				"-o", binaryPath, "./cmd/sshserver",
			)
			build.Dir = runtimeRoot
			build.Env = testGoEnvironment(
				"GOENV=off", "GOWORK=off", "GOFLAGS=", "GOEXPERIMENT=", "GOTOOLCHAIN=local",
				"CGO_ENABLED=0", "GOOS="+target.OS, "GOARCH="+target.Architecture,
				"GOAMD64=v1", "GOARM64=v8.0",
			)
			if buildOutput, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build exact target fixture: %v\n%s", err, buildOutput)
			}
			payload, err := os.ReadFile(binaryPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyGoBuildMetadata(payload, target, release, sourceRevision, toolchain, identity); err != nil {
				t.Fatal(err)
			}
			if target.OS == runtime.GOOS && target.Architecture == runtime.GOARCH {
				wrongIdentity := strings.Repeat("0", 64)
				if err := verifyGoBuildMetadata(payload, target, release, sourceRevision, toolchain, wrongIdentity); err == nil || !strings.Contains(err.Error(), "exact frozen build attestation") {
					t.Fatalf("wrong frozen attestation error=%v", err)
				}
			}
		})
	}
}

func currentTestSourceRevision(runtimeRoot string) string {
	command := exec.Command("git", "-C", runtimeRoot, "rev-parse", "--verify", "HEAD")
	output, err := command.Output()
	revision := strings.TrimSpace(string(output))
	if err == nil && len(revision) == 40 && strings.IndexFunc(revision, func(character rune) bool {
		return character < '0' || character > '9' && character < 'a' || character > 'f'
	}) == -1 {
		return revision
	}
	return strings.Repeat("b", 40)
}

func testGoBuildInfo(target deployment.Target, sourceRevision, toolchain string) *debug.BuildInfo {
	const runtimeModule = "github.com/kciceblue/sshserver/runtime"
	return &debug.BuildInfo{
		GoVersion: toolchain,
		Path:      runtimeModule + "/cmd/sshserver",
		Main:      debug.Module{Path: runtimeModule, Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "-buildmode", Value: "exe"},
			{Key: "-compiler", Value: "gc"},
			{Key: "-trimpath", Value: "true"},
			{Key: "CGO_ENABLED", Value: "0"},
			{Key: "GOOS", Value: target.OS},
			{Key: "GOARCH", Value: target.Architecture},
			{Key: "GOAMD64", Value: "v1"},
			{Key: "vcs", Value: "git"},
			{Key: "vcs.revision", Value: sourceRevision},
			{Key: "vcs.time", Value: "2026-08-03T00:00:00Z"},
			{Key: "vcs.modified", Value: "false"},
		},
	}
}

func setBuildSetting(info *debug.BuildInfo, key, value string) {
	for index := range info.Settings {
		if info.Settings[index].Key == key {
			info.Settings[index].Value = value
			return
		}
	}
	info.Settings = append(info.Settings, debug.BuildSetting{Key: key, Value: value})
}

func removeBuildSetting(info *debug.BuildInfo, key string) {
	for index, setting := range info.Settings {
		if setting.Key == key {
			info.Settings = append(info.Settings[:index], info.Settings[index+1:]...)
			return
		}
	}
}

func TestDeploymentCommandsRejectWrongManifestPinAndConfirmation(t *testing.T) {
	options := testBundleOptions(t)
	result, err := generate(options, acceptTestMetadata)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := os.ReadFile(result.ManifestPath)
	manifest, _ := deployment.ParsePinnedManifest(payload, result.ManifestSHA256)
	if _, err := PreviewLine(manifest, int64(len(payload)), strings.Repeat("A", 64), manifest.Artifacts[0]); err == nil {
		t.Fatal("uppercase manifest pin accepted")
	}
	if _, err := PreviewLine(manifest, int64(len(payload)), strings.Repeat("0", 64), manifest.Artifacts[0]); err == nil {
		t.Fatal("wrong lowercase manifest pin accepted")
	}
	if _, err := PreviewLine(manifest, int64(len(payload))+1, result.ManifestSHA256, manifest.Artifacts[0]); err == nil {
		t.Fatal("wrong manifest byte count accepted")
	}
	if _, err := ActivationLine(manifest, int64(len(payload)), result.ManifestSHA256, manifest.Artifacts[0], strings.Repeat("A", 64)); err == nil {
		t.Fatal("uppercase preview confirmation accepted")
	}
	if _, err := ActivationLine(manifest, int64(len(payload)), result.ManifestSHA256, manifest.Artifacts[0], strings.Repeat("0", 63)); err == nil {
		t.Fatal("short preview confirmation accepted")
	}
}

func testBundleOptions(t *testing.T) Options {
	t.Helper()
	root := t.TempDir()
	artifacts := filepath.Join(root, "artifacts")
	dist := filepath.Join(root, "dist")
	if err := os.Mkdir(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	licensePath := filepath.Join(root, "LICENSE-source")
	noticePath := filepath.Join(root, "NOTICE-source")
	if err := os.WriteFile(licensePath, []byte("Apache License fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(noticePath, []byte("NOTICE fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := Options{
		ArtifactDir:    artifacts,
		DistDir:        dist,
		LicensePath:    licensePath,
		NoticePath:     noticePath,
		Release:        "v1.2.3",
		SourceRevision: strings.Repeat("a", 40),
		BuildToolchain: "go1.25.0",
		DownloadOrigin: "https://downloads.example.test",
	}
	for _, target := range deployment.SupportedTargets() {
		identity, err := deployment.DeriveBuildIdentity(options.Release, options.SourceRevision, options.BuildToolchain, target)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(artifacts, "sshserver-"+target.OS+"-"+target.Architecture)
		if err := os.WriteFile(path, []byte("fake Go binary\x00"+identity+"\x00"+targetKey(target)), 0o500); err != nil {
			t.Fatal(err)
		}
	}
	return options
}

func acceptTestMetadata([]byte, deployment.Target, string, string, string, string) error {
	return nil
}

func testGoEnvironment(overrides ...string) []string {
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
