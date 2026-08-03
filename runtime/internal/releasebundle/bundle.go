// Package releasebundle generates deterministic, immutable server release
// metadata and target-specific SSH activation commands.
package releasebundle

import (
	"bytes"
	debugbuildinfo "debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	runtimedebug "runtime/debug"
	"strings"

	"golang.org/x/sys/unix"

	internalbuildinfo "github.com/kciceblue/sshserver/runtime/internal/buildinfo"
	"github.com/kciceblue/sshserver/runtime/internal/deployment"
)

const maxBundleArtifactBytes = 256 * 1024 * 1024

type Options struct {
	ArtifactDir    string
	DistDir        string
	LicensePath    string
	NoticePath     string
	Release        string
	SourceRevision string
	BuildToolchain string
	DownloadOrigin string
}

type Result struct {
	ManifestPath     string                 `json:"manifest_path"`
	ManifestSHA256   string                 `json:"manifest_sha256"`
	ActivationPaths  map[string]string      `json:"activation_paths"`
	ActivationSHA256 map[string]string      `json:"activation_sha256"`
	UploadFiles      map[string]UploadFiles `json:"upload_files"`
}

// UploadFiles are the exact owner-only names that the SSH client must create
// in the selected sync host's physical home before invoking ActivationLine.
// The remote command performs no network fetch and executes no transfer or
// checksum utility; the authenticated SSH client verifies bytes before upload.
type UploadFiles struct {
	Directory     string `json:"directory"`
	DirectoryMode string `json:"directory_mode"`
	Manifest      string `json:"manifest"`
	ManifestMode  string `json:"manifest_mode"`
	Artifact      string `json:"artifact"`
	ArtifactMode  string `json:"artifact_mode"`
	License       string `json:"license"`
	LicenseMode   string `json:"license_mode"`
	Notice        string `json:"notice"`
	NoticeMode    string `json:"notice_mode"`
}

type metadataVerifier func([]byte, deployment.Target, string, string, string, string) error

func Generate(options Options) (Result, error) {
	return generate(options, verifyGoBuildMetadata)
}

func generate(options Options, verifyMetadata metadataVerifier) (Result, error) {
	for name, value := range map[string]string{
		"artifact directory":     options.ArtifactDir,
		"distribution directory": options.DistDir,
		"license path":           options.LicensePath,
		"notice path":            options.NoticePath,
	} {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsRune(value, '\x00') {
			return Result{}, fmt.Errorf("%s must be canonical and absolute", name)
		}
	}
	if verifyMetadata == nil {
		return Result{}, errors.New("release metadata verifier is required")
	}
	if options.ArtifactDir == options.DistDir {
		return Result{}, errors.New("artifact and immutable distribution directories must be distinct")
	}
	if err := validateBundleDirectory(options.ArtifactDir); err != nil {
		return Result{}, fmt.Errorf("validate release artifact directory: %w", err)
	}
	distributionParent := filepath.Dir(options.DistDir)
	if err := os.MkdirAll(distributionParent, 0o700); err != nil {
		return Result{}, fmt.Errorf("create release distribution parent: %w", err)
	}
	if err := validateBundleDirectory(distributionParent); err != nil {
		return Result{}, fmt.Errorf("validate release distribution parent: %w", err)
	}
	stageDir, err := os.MkdirTemp(distributionParent, "."+filepath.Base(options.DistDir)+".stage-")
	if err != nil {
		return Result{}, fmt.Errorf("create release bundle staging directory: %w", err)
	}
	stagePresent := true
	defer func() {
		if stagePresent {
			_ = os.RemoveAll(stageDir)
		}
	}()
	if err := os.Chmod(stageDir, 0o700); err != nil {
		return Result{}, fmt.Errorf("protect release bundle staging directory: %w", err)
	}
	license, err := readBundleInput(options.LicensePath, 4*1024*1024)
	if err != nil {
		return Result{}, fmt.Errorf("read release LICENSE: %w", err)
	}
	notice, err := readBundleInput(options.NoticePath, 4*1024*1024)
	if err != nil {
		return Result{}, fmt.Errorf("read release NOTICE: %w", err)
	}
	if len(license) == 0 || len(notice) == 0 {
		return Result{}, errors.New("release LICENSE and NOTICE must not be empty")
	}
	outputs := []bundleOutput{
		{name: "LICENSE", payload: license, mode: 0o400},
		{name: "NOTICE", payload: notice, mode: 0o400},
	}

	manifest := deployment.ReleaseManifest{
		ManifestVersion: deployment.ManifestVersion,
		Release:         options.Release,
		SourceRevision:  options.SourceRevision,
		BuildToolchain:  options.BuildToolchain,
		ProtocolVersion: "1",
		StorageSchema:   "1",
		DownloadOrigin:  options.DownloadOrigin,
		ReleaseFiles: []deployment.ReleaseFile{
			{
				Name: "LICENSE", URL: releaseURL(options, "LICENSE"), Bytes: int64(len(license)), SHA256: deployment.SHA256Hex(license),
			},
			{
				Name: "NOTICE", URL: releaseURL(options, "NOTICE"), Bytes: int64(len(notice)), SHA256: deployment.SHA256Hex(notice),
			},
		},
	}
	for _, target := range deployment.SupportedTargets() {
		name := "sshserver-" + target.OS + "-" + target.Architecture
		path := filepath.Join(options.ArtifactDir, name)
		identity, err := deployment.DeriveBuildIdentity(options.Release, options.SourceRevision, options.BuildToolchain, target)
		if err != nil {
			return Result{}, err
		}
		payload, err := readBundleInput(path, maxBundleArtifactBytes)
		if err != nil {
			return Result{}, fmt.Errorf("read %s release artifact: %w", targetKey(target), err)
		}
		if !bytes.Contains(payload, []byte(identity)) {
			return Result{}, fmt.Errorf("%s release artifact does not contain its deterministic build identity", targetKey(target))
		}
		if err := verifyMetadata(payload, target, options.Release, options.SourceRevision, options.BuildToolchain, identity); err != nil {
			return Result{}, err
		}
		outputs = append(outputs, bundleOutput{name: name, payload: payload, mode: 0o500})
		manifest.Artifacts = append(manifest.Artifacts, deployment.ReleaseArtifact{
			OS:            target.OS,
			Architecture:  target.Architecture,
			BuildIdentity: identity,
			URL:           releaseURL(options, name),
			Bytes:         int64(len(payload)),
			SHA256:        deployment.SHA256Hex(payload),
		})
	}
	manifestPayload, err := manifest.CanonicalBytes()
	if err != nil {
		return Result{}, err
	}
	manifestSHA256 := deployment.SHA256Hex(manifestPayload)
	result := Result{
		ManifestPath:     filepath.Join(options.DistDir, "release-manifest.json"),
		ManifestSHA256:   manifestSHA256,
		ActivationPaths:  make(map[string]string),
		ActivationSHA256: make(map[string]string),
		UploadFiles:      make(map[string]UploadFiles),
	}
	outputs = append(outputs, bundleOutput{name: "release-manifest.json", payload: manifestPayload, mode: 0o400})
	for _, target := range deployment.SupportedTargets() {
		artifact, err := manifest.Artifact(target)
		if err != nil {
			return Result{}, err
		}
		activation, err := ActivationLine(manifest, int64(len(manifestPayload)), manifestSHA256, artifact)
		if err != nil {
			return Result{}, err
		}
		key := targetKey(target)
		name := "activation-" + target.OS + "-" + target.Architecture + ".txt"
		path := filepath.Join(options.DistDir, name)
		outputs = append(outputs, bundleOutput{name: name, payload: activation, mode: 0o400})
		result.ActivationPaths[key] = path
		result.ActivationSHA256[key] = deployment.SHA256Hex(activation)
		result.UploadFiles[key] = uploadFiles(manifest, manifestSHA256, artifact)
	}
	for _, output := range outputs {
		if err := writeNewBundleFile(stageDir, output); err != nil {
			return Result{}, err
		}
	}
	if err := syncDirectory(stageDir); err != nil {
		return Result{}, fmt.Errorf("sync complete release bundle staging directory: %w", err)
	}
	if err := publishDirectoryNoReplace(stageDir, options.DistDir); err != nil {
		if _, statErr := os.Lstat(options.DistDir); statErr != nil {
			return Result{}, fmt.Errorf("publish immutable release bundle: %w", err)
		}
		if compareErr := compareBundleDirectory(options.DistDir, outputs); compareErr != nil {
			return Result{}, fmt.Errorf("immutable release bundle already exists with different or unsafe contents: %w", compareErr)
		}
	} else {
		stagePresent = false
		if err := syncDirectory(distributionParent); err != nil {
			return Result{}, fmt.Errorf("sync published release bundle parent: %w", err)
		}
	}
	return result, nil
}

// ActivationLine is the shell-neutral SSH exec command for release bytes that
// the client has already SHA-256 verified and uploaded over its authenticated
// SSH connection. The release binary re-verifies every named input before it
// publishes anything. Download, target detection, upload, and local checksum
// verification remain client-side so a clean sync host needs only SSH.
func ActivationLine(manifest deployment.ReleaseManifest, manifestBytes int64, manifestSHA256 string, artifact deployment.ReleaseArtifact) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	canonical, err := manifest.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	if manifestBytes != int64(len(canonical)) || manifestBytes <= 0 || manifestBytes > 64*1024 ||
		deployment.SHA256Hex(canonical) != manifestSHA256 {
		return nil, errors.New("activation manifest size or pin does not match its canonical bytes")
	}
	if artifact.OS == "" || artifact.Architecture == "" {
		return nil, errors.New("activation artifact target is missing")
	}
	selected, err := manifest.Artifact(deployment.Target{OS: artifact.OS, Architecture: artifact.Architecture})
	if err != nil || selected != artifact {
		return nil, errors.New("activation artifact is not the exact manifest target")
	}
	files := uploadFiles(manifest, manifestSHA256, artifact)
	prefixHome := func(path string) string { return "~/" + path }
	parts := []string{
		prefixHome(files.Artifact),
		"deploy", "apply",
		"--manifest", prefixHome(files.Manifest),
		"--manifest-sha256", manifestSHA256,
		"--artifact", prefixHome(files.Artifact),
		"--license", prefixHome(files.License),
		"--notice", prefixHome(files.Notice),
		"--consume-inputs",
	}
	return []byte(strings.Join(parts, " ") + "\n"), nil
}

func uploadFiles(manifest deployment.ReleaseManifest, manifestSHA256 string, artifact deployment.ReleaseArtifact) UploadFiles {
	directory := ".jat-sshserver-upload-" + manifest.Release + "-" + artifact.OS + "-" + artifact.Architecture + "-" + manifestSHA256[:16]
	return UploadFiles{
		Directory:     directory,
		DirectoryMode: "0700",
		Manifest:      directory + "/release-manifest.json",
		ManifestMode:  "0400",
		Artifact:      directory + "/sshserver",
		ArtifactMode:  "0500",
		License:       directory + "/LICENSE",
		LicenseMode:   "0400",
		Notice:        directory + "/NOTICE",
		NoticeMode:    "0400",
	}
}

func verifyGoBuildMetadata(payload []byte, target deployment.Target, release, sourceRevision, toolchain, identity string) error {
	attestation, err := internalbuildinfo.Encode(internalbuildinfo.Identity{
		Release:         release,
		SourceRevision:  sourceRevision,
		BuildToolchain:  toolchain,
		BuildIdentity:   identity,
		ProtocolVersion: "1",
		StorageSchema:   "1",
	})
	if err != nil {
		return fmt.Errorf("construct frozen build attestation for %s: %w", targetKey(target), err)
	}
	if !bytes.Contains(payload, []byte(attestation)) {
		return fmt.Errorf("%s release artifact does not contain its exact frozen build attestation", targetKey(target))
	}
	info, err := debugbuildinfo.Read(bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("read Go build metadata for %s: %w", targetKey(target), err)
	}
	return validateGoBuildInfo(info, target, sourceRevision, toolchain)
}

func validateGoBuildInfo(info *runtimedebug.BuildInfo, target deployment.Target, sourceRevision, toolchain string) error {
	if info == nil {
		return errors.New("Go build metadata is required")
	}
	if info.GoVersion != toolchain {
		return fmt.Errorf("%s Go version %q does not match %q", targetKey(target), info.GoVersion, toolchain)
	}
	const runtimeModule = "github.com/kciceblue/sshserver/runtime"
	if info.Path != runtimeModule+"/cmd/sshserver" || info.Main.Path != runtimeModule || info.Main.Version != "(devel)" || info.Main.Replace != nil {
		return fmt.Errorf("%s main package metadata is not the exact sshserver runtime module", targetKey(target))
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		if _, duplicate := settings[setting.Key]; duplicate {
			return fmt.Errorf("%s build metadata repeats %s", targetKey(target), setting.Key)
		}
		settings[setting.Key] = setting.Value
	}
	for key, want := range map[string]string{
		"-buildmode": "exe", "-compiler": "gc", "-trimpath": "true",
		"CGO_ENABLED": "0", "GOOS": target.OS, "GOARCH": target.Architecture,
	} {
		if settings[key] != want {
			return fmt.Errorf("%s build metadata %s=%q, want %q", targetKey(target), key, settings[key], want)
		}
	}
	vcsFields := []string{"vcs", "vcs.revision", "vcs.time", "vcs.modified"}
	vcsFieldCount := 0
	for _, key := range vcsFields {
		if _, present := settings[key]; present {
			vcsFieldCount++
		}
	}
	// The runtime is a nested Go module, so current Go toolchains omit VCS
	// settings even with -buildvcs=true. When they are present they must form
	// one complete, clean record; the separate release-source gate binds the
	// encoded attestation when all four fields are absent.
	if vcsFieldCount != 0 {
		if vcsFieldCount != len(vcsFields) || settings["vcs"] != "git" ||
			settings["vcs.revision"] != sourceRevision || settings["vcs.time"] == "" ||
			settings["vcs.modified"] != "false" {
			return fmt.Errorf("%s build metadata has incomplete, mismatched, or dirty VCS provenance", targetKey(target))
		}
	}
	baselineKey, baselineValue := "GOAMD64", "v1"
	if target.Architecture == "arm64" {
		baselineKey, baselineValue = "GOARM64", "v8.0"
	}
	if settings[baselineKey] != baselineValue {
		return fmt.Errorf("%s build metadata %s=%q, want baseline %q", targetKey(target), baselineKey, settings[baselineKey], baselineValue)
	}
	for _, forbidden := range []string{"-overlay", "-tags", "GOEXPERIMENT", "GOFLAGS"} {
		if _, present := settings[forbidden]; present {
			return fmt.Errorf("%s build metadata contains forbidden setting %s", targetKey(target), forbidden)
		}
	}
	return nil
}

type bundleOutput struct {
	name    string
	payload []byte
	mode    os.FileMode
}

func validateBundleDirectory(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o022 != 0 {
		return errors.New("directory must be owner-controlled, non-writable by group or others, and not a symbolic link")
	}
	return nil
}

func writeNewBundleFile(directory string, output bundleOutput) error {
	if output.name == "" || filepath.Base(output.name) != output.name || output.mode != 0o400 && output.mode != 0o500 || len(output.payload) == 0 {
		return errors.New("release bundle output is invalid")
	}
	path := filepath.Join(directory, output.name)
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(output.mode.Perm()))
	if err != nil {
		return fmt.Errorf("create immutable release output %s: %w", output.name, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("wrap immutable release output %s", output.name)
	}
	defer file.Close()
	if err := file.Chmod(output.mode); err != nil {
		return err
	}
	if _, err := file.Write(output.payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return nil
}

func compareBundleDirectory(published string, outputs []bundleOutput) error {
	if err := validateBundleDirectory(published); err != nil {
		return err
	}
	info, err := os.Lstat(published)
	if err != nil || info.Mode().Perm() != 0o700 {
		return errors.New("published bundle directory is not exactly mode 0700")
	}
	entries, err := os.ReadDir(published)
	if err != nil {
		return err
	}
	if len(entries) != len(outputs) {
		return errors.New("published bundle file set is incomplete or contains extras")
	}
	expected := make(map[string]bundleOutput, len(outputs))
	for _, output := range outputs {
		expected[output.name] = output
	}
	for _, entry := range entries {
		output, ok := expected[entry.Name()]
		if !ok || entry.IsDir() {
			return fmt.Errorf("unexpected published bundle entry %q", entry.Name())
		}
		payload, err := readExactBundleOutput(filepath.Join(published, entry.Name()), output)
		if err != nil {
			return err
		}
		if !bytes.Equal(payload, output.payload) {
			return fmt.Errorf("published bundle entry %q has different bytes", entry.Name())
		}
	}
	return nil
}

func readExactBundleOutput(path string, output bundleOutput) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap published bundle descriptor")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Geteuid()) || uint64(before.Nlink) != 1 ||
		os.FileMode(before.Mode).Perm() != output.mode.Perm() || before.Size != int64(len(output.payload)) {
		return nil, errors.New("published bundle entry metadata is unsafe or different")
	}
	payload, err := io.ReadAll(io.LimitReader(file, int64(len(output.payload))+1))
	if err != nil {
		return nil, err
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, err
	}
	if len(payload) != len(output.payload) || !sameBundleFile(before, after) {
		return nil, errors.New("published bundle entry changed while it was read")
	}
	return payload, nil
}

func sameBundleFile(first, second unix.Stat_t) bool {
	return first.Dev == second.Dev && first.Ino == second.Ino && first.Size == second.Size && first.Mode == second.Mode &&
		first.Uid == second.Uid && first.Gid == second.Gid && first.Nlink == second.Nlink
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func readBundleInput(path string, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("wrap release input descriptor")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Geteuid()) || uint64(before.Nlink) != 1 || before.Mode&0o022 != 0 || before.Size <= 0 || before.Size > limit {
		return nil, errors.New("release input must be a bounded, single-link, non-writable regular file owned by the current user")
	}
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, err
	}
	if int64(len(payload)) != before.Size || !sameBundleFile(before, after) ||
		after.Mode&unix.S_IFMT != unix.S_IFREG || after.Uid != uint32(os.Geteuid()) || uint64(after.Nlink) != 1 || after.Mode&0o022 != 0 {
		return nil, errors.New("release input changed while it was read")
	}
	return payload, nil
}

func releaseURL(options Options, name string) string {
	return options.DownloadOrigin + "/releases/" + options.Release + "/" + name
}

func targetKey(target deployment.Target) string {
	return target.OS + "/" + target.Architecture
}
