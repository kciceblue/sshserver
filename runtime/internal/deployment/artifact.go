//go:build darwin || linux

package deployment

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	debugbuildinfo "debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
)

const (
	maximumStagedArtifactBytes = 256 * 1024 * 1024
	temporaryNameAttempts      = 16
)

type artifactExpectation struct {
	bytes  int64
	digest [sha256.Size]byte
}

type artifactFileIdentity struct {
	device uint64
	inode  uint64
}

// StageVerifiedArtifact verifies an already downloaded release artifact and
// atomically publishes it as an owner-only executable. It never executes the
// artifact. Verification and copying use the same no-follow source descriptor,
// and every destination operation is relative to one validated directory
// descriptor.
func StageVerifiedArtifact(sourcePath, destinationDir, finalName string, expectedBytes int64, expectedSHA256 string) (string, error) {
	return stageVerifiedFile(sourcePath, destinationDir, finalName, expectedBytes, expectedSHA256, maximumStagedArtifactBytes, 0o500)
}

func StageVerifiedReleaseFile(sourcePath, destinationDir, finalName string, expectedBytes int64, expectedSHA256 string) (string, error) {
	if finalName != "LICENSE" && finalName != "NOTICE" {
		return "", errors.New("release support file must be LICENSE or NOTICE")
	}
	return stageVerifiedFile(sourcePath, destinationDir, finalName, expectedBytes, expectedSHA256, maxReleaseFileBytes, 0o400)
}

func stageVerifiedFile(sourcePath, destinationDir, finalName string, expectedBytes int64, expectedSHA256 string, maximumBytes int64, finalMode os.FileMode) (string, error) {
	if expectedBytes <= 0 || expectedBytes > maximumBytes {
		return "", errors.New("artifact size expectation is outside the supported boundary")
	}
	expectation, err := parseArtifactExpectation(expectedBytes, expectedSHA256)
	if err != nil {
		return "", err
	}
	if err := validateArtifactName(finalName); err != nil {
		return "", err
	}
	source, sourceStat, err := openVerifiedArtifactSource(sourcePath, expectation.bytes)
	if err != nil {
		return "", err
	}
	defer source.Close()
	return stageOpenedArtifact(source, sourceStat, destinationDir, finalName, expectation, finalMode)
}

// VerifyStagedArtifact reopens an immutable published artifact through its
// validated owner directory and proves its metadata, byte count, and digest.
// Lifecycle resume and status paths use this instead of trusting recorded
// deployment metadata.
func VerifyStagedArtifact(path string, expectedBytes int64, expectedSHA256 string) error {
	return verifyStagedFile(path, expectedBytes, expectedSHA256, maximumStagedArtifactBytes, 0o500)
}

func VerifyStagedReleaseFile(path string, expectedBytes int64, expectedSHA256 string) error {
	if name := filepath.Base(path); name != "LICENSE" && name != "NOTICE" {
		return errors.New("release support file must be LICENSE or NOTICE")
	}
	return verifyStagedFile(path, expectedBytes, expectedSHA256, maxReleaseFileBytes, 0o400)
}

// VerifyArtifactSource proves that an installer input is the exact release
// artifact selected by the manifest without executing or copying it. It takes
// one bounded in-memory snapshot from a no-follow descriptor, verifies that
// snapshot's digest, then performs frozen-attestation and Go build-metadata
// inspection only against those immutable bytes. Preview therefore remains
// genuinely read-only and an in-place source rewrite cannot make hashing and
// semantic inspection observe different content.
func VerifyArtifactSource(path string, expected InstalledRelease) error {
	expectation, err := parseArtifactExpectation(expected.BinaryBytes, expected.BinarySHA256)
	if err != nil {
		return err
	}
	source, initial, err := openVerifiedArtifactSource(path, expectation.bytes)
	if err != nil {
		return err
	}
	defer source.Close()
	snapshot, err := readVerifiedSourceSnapshot(source, initial, expectation, "artifact")
	if err != nil {
		return err
	}

	identity := buildinfo.Identity{
		Release:         expected.Release,
		SourceRevision:  expected.SourceRevision,
		BuildToolchain:  expected.BuildToolchain,
		BuildIdentity:   expected.BuildIdentity,
		ProtocolVersion: expected.ProtocolVersion,
		StorageSchema:   expected.StorageSchema,
	}
	attestation, err := buildinfo.Encode(identity)
	if err != nil {
		return fmt.Errorf("construct expected artifact attestation: %w", err)
	}
	if !bytes.Contains(snapshot, []byte(attestation)) {
		return errors.New("artifact does not contain its exact frozen release attestation")
	}
	metadata, err := debugbuildinfo.Read(bytes.NewReader(snapshot))
	if err != nil {
		return fmt.Errorf("read artifact Go build metadata: %w", err)
	}
	if err := validateArtifactBuildMetadata(metadata, expected); err != nil {
		return err
	}
	return nil
}

// VerifyReleaseFileSource applies the same immutable installer-input checks to
// LICENSE and NOTICE while performing no target-layout mutation.
func VerifyReleaseFileSource(path string, expectedBytes int64, expectedSHA256 string) error {
	expectation, err := parseArtifactExpectation(expectedBytes, expectedSHA256)
	if err != nil {
		return err
	}
	if expectedBytes > maxReleaseFileBytes {
		return errors.New("release support-file size expectation is outside the supported boundary")
	}
	source, initial, err := openVerifiedArtifactSource(path, expectation.bytes)
	if err != nil {
		return err
	}
	defer source.Close()
	_, err = readVerifiedSourceSnapshot(source, initial, expectation, "release support-file")
	return err
}

func readVerifiedSourceSnapshot(
	source *os.File,
	initial unix.Stat_t,
	expectation artifactExpectation,
	kind string,
) ([]byte, error) {
	if source == nil {
		return nil, fmt.Errorf("%s source descriptor is required", kind)
	}
	var snapshot bytes.Buffer
	snapshot.Grow(int(expectation.bytes))
	hash := sha256.New()
	read, err := io.Copy(
		io.MultiWriter(&snapshot, hash),
		io.NewSectionReader(source, 0, expectation.bytes+1),
	)
	if err != nil {
		return nil, fmt.Errorf("hash %s source: %w", kind, err)
	}
	if read != expectation.bytes || !bytes.Equal(hash.Sum(nil), expectation.digest[:]) {
		return nil, fmt.Errorf("%s SHA-256 does not match the release manifest", kind)
	}
	final, err := statFile(source)
	if err != nil {
		return nil, fmt.Errorf("reinspect %s source descriptor: %w", kind, err)
	}
	if err := validateOwnedRegularFile(final, 0, false); err != nil || final.Size != expectation.bytes || !sameArtifactIdentity(initial, final) {
		return nil, fmt.Errorf("%s source descriptor changed during preview verification", kind)
	}
	return snapshot.Bytes(), nil
}

func validateArtifactBuildMetadata(metadata *debugbuildinfo.BuildInfo, expected InstalledRelease) error {
	if metadata == nil || metadata.GoVersion != expected.BuildToolchain {
		return errors.New("artifact Go toolchain does not match the pinned release")
	}
	const runtimeModule = "github.com/kciceblue/sshserver/runtime"
	if metadata.Path != runtimeModule+"/cmd/sshserver" || metadata.Main.Path != runtimeModule || metadata.Main.Replace != nil {
		return errors.New("artifact is not the exact local sshserver runtime module")
	}
	settings := make(map[string]string, len(metadata.Settings))
	for _, setting := range metadata.Settings {
		if _, duplicate := settings[setting.Key]; duplicate {
			return fmt.Errorf("artifact build metadata repeats %s", setting.Key)
		}
		settings[setting.Key] = setting.Value
	}
	for key, want := range map[string]string{
		"-buildmode":  "exe",
		"-compiler":   "gc",
		"-trimpath":   "true",
		"CGO_ENABLED": "0",
		"GOOS":        expected.OS,
		"GOARCH":      expected.Architecture,
	} {
		if settings[key] != want {
			return fmt.Errorf("artifact build metadata %s=%q, want %q", key, settings[key], want)
		}
	}
	baselineKey, baselineValue := "GOAMD64", "v1"
	if expected.Architecture == "arm64" {
		baselineKey, baselineValue = "GOARM64", "v8.0"
	}
	if settings[baselineKey] != baselineValue {
		return fmt.Errorf("artifact build metadata %s=%q, want %q", baselineKey, settings[baselineKey], baselineValue)
	}
	for _, forbidden := range []string{"-overlay", "-tags", "GOEXPERIMENT", "GOFLAGS"} {
		if _, present := settings[forbidden]; present {
			return fmt.Errorf("artifact build metadata contains forbidden setting %s", forbidden)
		}
	}
	return nil
}

func verifyStagedFile(path string, expectedBytes int64, expectedSHA256 string, maximumBytes int64, finalMode os.FileMode) error {
	if expectedBytes <= 0 || expectedBytes > maximumBytes {
		return errors.New("artifact size expectation is outside the supported boundary")
	}
	expectation, err := parseArtifactExpectation(expectedBytes, expectedSHA256)
	if err != nil {
		return err
	}
	if err := validateAbsoluteCanonicalPath(path); err != nil {
		return err
	}
	directory, err := openVerifiedDirectory(filepath.Dir(path), true)
	if err != nil {
		return fmt.Errorf("verify staged artifact directory: %w", err)
	}
	defer directory.Close()
	exists, identical, err := inspectExistingArtifact(directory, filepath.Base(path), expectation, finalMode)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("staged artifact does not exist")
	}
	if !identical {
		return errors.New("staged artifact does not match its pinned release metadata")
	}
	return nil
}

func parseArtifactExpectation(expectedBytes int64, expectedSHA256 string) (artifactExpectation, error) {
	var expectation artifactExpectation
	if expectedBytes <= 0 || expectedBytes > maximumStagedArtifactBytes {
		return expectation, errors.New("artifact size expectation is outside the supported boundary")
	}
	if len(expectedSHA256) != sha256.Size*2 || strings.ToLower(expectedSHA256) != expectedSHA256 {
		return expectation, errors.New("artifact SHA-256 expectation must be lowercase hexadecimal")
	}
	digest, err := hex.DecodeString(expectedSHA256)
	if err != nil || len(digest) != sha256.Size {
		return expectation, errors.New("artifact SHA-256 expectation must be lowercase hexadecimal")
	}
	expectation.bytes = expectedBytes
	copy(expectation.digest[:], digest)
	return expectation, nil
}

func validateArtifactName(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > 128 || strings.ContainsRune(name, 0) ||
		filepath.Base(name) != name || filepath.Clean(name) != name {
		return errors.New("staged artifact name must be a safe single path component")
	}
	return nil
}

func openVerifiedArtifactSource(path string, expectedBytes int64) (*os.File, unix.Stat_t, error) {
	var empty unix.Stat_t
	if err := validateAbsoluteCanonicalPath(path); err != nil {
		return nil, empty, fmt.Errorf("artifact source path: %w", err)
	}
	parent, err := openVerifiedDirectory(filepath.Dir(path), false)
	if err != nil {
		return nil, empty, fmt.Errorf("artifact source directory: %w", err)
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path),
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, empty, fmt.Errorf("open artifact source without following links: %w", err)
	}
	source := os.NewFile(uintptr(fd), path)
	if source == nil {
		_ = unix.Close(fd)
		return nil, empty, errors.New("wrap artifact source descriptor")
	}
	stat, err := statFile(source)
	if err != nil {
		source.Close()
		return nil, empty, fmt.Errorf("inspect artifact source descriptor: %w", err)
	}
	if err := validateOwnedRegularFile(stat, 0, false); err != nil {
		source.Close()
		return nil, empty, fmt.Errorf("artifact source: %w", err)
	}
	if stat.Size != expectedBytes {
		source.Close()
		return nil, empty, fmt.Errorf("artifact source size is %d bytes, expected %d", stat.Size, expectedBytes)
	}
	return source, stat, nil
}

func stageOpenedArtifact(source *os.File, initialSourceStat unix.Stat_t, destinationDir, finalName string, expectation artifactExpectation, finalMode os.FileMode) (string, error) {
	if source == nil {
		return "", errors.New("artifact source descriptor is required")
	}
	if err := validateArtifactName(finalName); err != nil {
		return "", err
	}
	if err := validateOwnedRegularFile(initialSourceStat, 0, false); err != nil || initialSourceStat.Size != expectation.bytes {
		return "", errors.New("artifact source descriptor changed before staging")
	}
	destination, err := openVerifiedDirectory(destinationDir, true)
	if err != nil {
		return "", fmt.Errorf("artifact destination directory: %w", err)
	}
	defer destination.Close()

	temporaryName, temporary, temporaryStat, err := createArtifactTemporary(destination, finalName)
	if err != nil {
		return "", err
	}
	temporaryPresent := true
	defer func() {
		_ = temporary.Close()
		if temporaryPresent {
			_ = unix.Unlinkat(int(destination.Fd()), temporaryName, 0)
		}
	}()

	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(source, expectation.bytes+1))
	if copyErr != nil {
		return "", fmt.Errorf("copy artifact from verified descriptor: %w", copyErr)
	}
	if written != expectation.bytes {
		return "", fmt.Errorf("artifact source changed size during verification: copied %d bytes, expected %d", written, expectation.bytes)
	}
	finalSourceStat, err := statFile(source)
	if err != nil {
		return "", fmt.Errorf("reinspect artifact source descriptor: %w", err)
	}
	if err := validateOwnedRegularFile(finalSourceStat, 0, false); err != nil ||
		finalSourceStat.Size != expectation.bytes || !sameArtifactIdentity(initialSourceStat, finalSourceStat) {
		return "", errors.New("artifact source descriptor changed during verification")
	}
	if !bytes.Equal(hash.Sum(nil), expectation.digest[:]) {
		return "", errors.New("artifact SHA-256 does not match the release manifest")
	}
	temporaryAfterCopy, err := statFile(temporary)
	if err != nil {
		return "", fmt.Errorf("inspect copied artifact: %w", err)
	}
	if err := validateOwnedRegularFile(temporaryAfterCopy, 0o600, true); err != nil ||
		temporaryAfterCopy.Size != expectation.bytes || !sameArtifactIdentity(temporaryStat, temporaryAfterCopy) {
		return "", errors.New("artifact temporary file changed during verification")
	}
	if err := temporary.Sync(); err != nil {
		return "", fmt.Errorf("sync verified artifact contents: %w", err)
	}
	if err := temporary.Chmod(finalMode); err != nil {
		return "", fmt.Errorf("make verified artifact executable: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return "", fmt.Errorf("sync verified artifact mode: %w", err)
	}
	verifiedTemporaryStat, err := statFile(temporary)
	if err != nil {
		return "", fmt.Errorf("inspect executable artifact: %w", err)
	}
	if err := validateOwnedRegularFile(verifiedTemporaryStat, uint32(finalMode.Perm()), true); err != nil ||
		verifiedTemporaryStat.Size != expectation.bytes || !sameArtifactIdentity(temporaryStat, verifiedTemporaryStat) {
		return "", errors.New("verified artifact changed before publication")
	}
	if err := unix.Linkat(int(destination.Fd()), temporaryName, int(destination.Fd()), finalName, 0); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return "", fmt.Errorf("publish verified artifact without replacing an existing file: %w", err)
		}
		exists, identical, inspectErr := inspectExistingArtifact(destination, finalName, expectation, finalMode)
		if inspectErr != nil {
			return "", inspectErr
		}
		if !exists || !identical {
			return "", errors.New("staged artifact destination already contains different bytes or metadata")
		}
		if err := unix.Unlinkat(int(destination.Fd()), temporaryName, 0); err != nil {
			return "", fmt.Errorf("remove redundant verified artifact temporary: %w", err)
		}
		temporaryPresent = false
		if err := temporary.Close(); err != nil {
			return "", fmt.Errorf("close redundant verified artifact temporary: %w", err)
		}
		if err := destination.Sync(); err != nil {
			return "", fmt.Errorf("sync existing artifact directory: %w", err)
		}
		return filepath.Join(destinationDir, finalName), nil
	}
	if err := unix.Unlinkat(int(destination.Fd()), temporaryName, 0); err != nil {
		rollbackErr := unix.Unlinkat(int(destination.Fd()), finalName, 0)
		if rollbackErr != nil {
			return "", fmt.Errorf("remove artifact temporary name after publication: %w (rollback final name: %v)", err, rollbackErr)
		}
		return "", fmt.Errorf("remove artifact temporary name after publication: %w", err)
	}
	temporaryPresent = false
	publishedDescriptorStat, err := statFile(temporary)
	if err != nil {
		return "", fmt.Errorf("reinspect published artifact descriptor: %w", err)
	}
	var published unix.Stat_t
	if err := unix.Fstatat(int(destination.Fd()), finalName, &published, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "", fmt.Errorf("inspect published artifact: %w", err)
	}
	if err := validateOwnedRegularFile(publishedDescriptorStat, uint32(finalMode.Perm()), true); err != nil ||
		publishedDescriptorStat.Size != expectation.bytes || !sameArtifactIdentity(temporaryStat, publishedDescriptorStat) ||
		validateOwnedRegularFile(published, uint32(finalMode.Perm()), true) != nil || published.Size != expectation.bytes ||
		!sameArtifactIdentity(publishedDescriptorStat, published) {
		return "", errors.New("published artifact does not match the verified temporary file")
	}
	if err := destination.Sync(); err != nil {
		return "", fmt.Errorf("sync artifact destination directory: %w", err)
	}
	return filepath.Join(destinationDir, finalName), nil
}

func createArtifactTemporary(destination *os.File, finalName string) (string, *os.File, unix.Stat_t, error) {
	var empty unix.Stat_t
	for range temporaryNameAttempts {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, empty, fmt.Errorf("generate artifact temporary name: %w", err)
		}
		name := "." + finalName + ".stage-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat(int(destination.Fd()), name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", nil, empty, fmt.Errorf("create artifact temporary file: %w", err)
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(int(destination.Fd()), name, 0)
			return "", nil, empty, errors.New("wrap artifact temporary descriptor")
		}
		if err := file.Chmod(0o600); err != nil {
			file.Close()
			_ = unix.Unlinkat(int(destination.Fd()), name, 0)
			return "", nil, empty, fmt.Errorf("protect artifact temporary file: %w", err)
		}
		stat, err := statFile(file)
		if err != nil || validateOwnedRegularFile(stat, 0o600, true) != nil || stat.Size != 0 {
			file.Close()
			_ = unix.Unlinkat(int(destination.Fd()), name, 0)
			return "", nil, empty, errors.New("artifact temporary file is not a new owner-only regular file")
		}
		return name, file, stat, nil
	}
	return "", nil, empty, errors.New("artifact temporary name collision limit reached")
}

func inspectExistingArtifact(destination *os.File, finalName string, expectation artifactExpectation, finalMode os.FileMode) (bool, bool, error) {
	fd, err := unix.Openat(int(destination.Fd()), finalName,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("inspect existing staged artifact: %w", err)
	}
	file := os.NewFile(uintptr(fd), finalName)
	if file == nil {
		_ = unix.Close(fd)
		return false, false, errors.New("wrap existing artifact descriptor")
	}
	defer file.Close()
	initial, err := statFile(file)
	if err != nil {
		return false, false, fmt.Errorf("inspect existing artifact descriptor: %w", err)
	}
	if err := validateOwnedRegularFile(initial, uint32(finalMode.Perm()), true); err != nil || initial.Size != expectation.bytes {
		return true, false, nil
	}
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(file, expectation.bytes+1))
	if err != nil {
		return false, false, fmt.Errorf("hash existing staged artifact: %w", err)
	}
	final, err := statFile(file)
	if err != nil {
		return false, false, fmt.Errorf("reinspect existing artifact descriptor: %w", err)
	}
	identical := read == expectation.bytes && bytes.Equal(hash.Sum(nil), expectation.digest[:]) &&
		validateOwnedRegularFile(final, uint32(finalMode.Perm()), true) == nil && final.Size == expectation.bytes && sameArtifactIdentity(initial, final)
	return true, identical, nil
}

func openVerifiedDirectory(path string, requireOwner bool) (*os.File, error) {
	if err := validateAbsoluteCanonicalPath(path); err != nil {
		return nil, err
	}
	rootFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	current := os.NewFile(uintptr(rootFD), string(filepath.Separator))
	if current == nil {
		_ = unix.Close(rootFD)
		return nil, errors.New("wrap filesystem root descriptor")
	}
	rootStat, err := statFile(current)
	if err != nil || validateDirectory(rootStat, false) != nil {
		current.Close()
		return nil, errors.New("filesystem root is not a trusted directory")
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(components) == 1 && components[0] == "" {
		components = nil
	}
	for index, component := range components {
		fd, err := unix.Openat(int(current.Fd()), component,
			unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if err != nil {
			current.Close()
			return nil, fmt.Errorf("open directory component %q without following links: %w", component, err)
		}
		next := os.NewFile(uintptr(fd), component)
		if next == nil {
			_ = unix.Close(fd)
			current.Close()
			return nil, fmt.Errorf("wrap directory component %q", component)
		}
		stat, err := statFile(next)
		finalComponent := index == len(components)-1
		if err != nil || validateDirectory(stat, requireOwner && finalComponent) != nil {
			next.Close()
			current.Close()
			return nil, fmt.Errorf("directory component %q is not trusted", component)
		}
		current.Close()
		current = next
	}
	if requireOwner {
		stat, err := statFile(current)
		if err != nil || validateDirectory(stat, true) != nil {
			current.Close()
			return nil, errors.New("artifact destination is not an owner-controlled directory")
		}
	}
	return current, nil
}

func validateAbsoluteCanonicalPath(path string) error {
	if path == "" || strings.ContainsRune(path, 0) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path must be absolute, canonical, and contain no NUL")
	}
	return nil
}

func statFile(file *os.File) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return unix.Stat_t{}, err
	}
	return stat, nil
}

func validateDirectory(stat unix.Stat_t, requireOwner bool) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("not a directory")
	}
	if stat.Mode&0o022 != 0 {
		return errors.New("directory is group- or world-writable")
	}
	owner := uint32(os.Geteuid())
	if requireOwner {
		if stat.Uid != owner {
			return errors.New("directory is not owned by the current user")
		}
	} else if stat.Uid != owner && stat.Uid != 0 {
		return errors.New("directory component has a foreign owner")
	}
	return nil
}

func validateOwnedRegularFile(stat unix.Stat_t, exactPermissions uint32, requireExactPermissions bool) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("not a regular file")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("file is not owned by the current user")
	}
	if uint64(stat.Nlink) != 1 {
		return errors.New("file has multiple hard links")
	}
	permissions := uint32(stat.Mode) & 0o777
	if permissions&0o022 != 0 {
		return errors.New("file is group- or world-writable")
	}
	if requireExactPermissions && permissions != exactPermissions {
		return fmt.Errorf("file permissions are %04o, expected %04o", permissions, exactPermissions)
	}
	return nil
}

func sameArtifactIdentity(first, second unix.Stat_t) bool {
	return uint64(first.Dev) == uint64(second.Dev) && uint64(first.Ino) == uint64(second.Ino)
}
