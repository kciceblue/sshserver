//go:build darwin || linux

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type artifactFixture struct {
	root        string
	sourceDir   string
	destination string
}

func newArtifactFixture(t *testing.T) artifactFixture {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(home, ".sshserver-artifact-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		os.RemoveAll(root)
		t.Fatal(err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		os.RemoveAll(root)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove artifact fixture: %v", err)
		}
	})
	fixture := artifactFixture{
		root:        root,
		sourceDir:   filepath.Join(root, "source"),
		destination: filepath.Join(root, "destination"),
	}
	for _, directory := range []string{fixture.sourceDir, fixture.destination} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func writeArtifactTestFile(t *testing.T, path string, payload []byte, mode os.FileMode) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(payload); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func artifactDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func assertNoArtifactTemporary(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".stage-") {
			t.Fatalf("artifact temporary remains: %q", entry.Name())
		}
	}
}

func TestStageVerifiedArtifactPublishesOwnerOnlyWithoutExecuting(t *testing.T) {
	fixture := newArtifactFixture(t)
	sentinel := filepath.Join(fixture.root, "executed")
	payload := []byte("#!/bin/sh\nprintf executed > " + sentinel + "\n")
	source := filepath.Join(fixture.sourceDir, "download")
	writeArtifactTestFile(t, source, payload, 0o600)

	final, err := StageVerifiedArtifact(source, fixture.destination, "sshserver", int64(len(payload)), artifactDigest(payload))
	if err != nil {
		t.Fatal(err)
	}
	if final != filepath.Join(fixture.destination, "sshserver") {
		t.Fatalf("staged path = %q", final)
	}
	staged, err := os.ReadFile(final)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(staged, payload) {
		t.Fatalf("staged bytes = %q", staged)
	}
	info, err := os.Lstat(final)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o500 {
		t.Fatalf("staged mode = %v, want regular 0500", info.Mode())
	}
	var stat unix.Stat_t
	if err := unix.Lstat(final, &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Uid != uint32(os.Geteuid()) || uint64(stat.Nlink) != 1 {
		t.Fatalf("staged ownership/link count = %d/%d", stat.Uid, stat.Nlink)
	}
	if _, err := os.Lstat(sentinel); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact was executed while staging: %v", err)
	}
	assertNoArtifactTemporary(t, fixture.destination)
}

func TestStageVerifiedReleaseFilesAreReadOnlyAndBounded(t *testing.T) {
	fixture := newArtifactFixture(t)
	for _, name := range []string{"LICENSE", "NOTICE"} {
		payload := []byte("release support file " + name)
		source := filepath.Join(fixture.sourceDir, strings.ToLower(name))
		writeArtifactTestFile(t, source, payload, 0o600)
		staged, err := StageVerifiedReleaseFile(source, fixture.destination, name, int64(len(payload)), artifactDigest(payload))
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(staged)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o400 {
			t.Fatalf("%s mode=%o", name, info.Mode().Perm())
		}
		if err := VerifyStagedReleaseFile(staged, int64(len(payload)), artifactDigest(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := StageVerifiedReleaseFile(filepath.Join(fixture.sourceDir, "license"), fixture.destination, "README", 1, strings.Repeat("0", 64)); err == nil {
		t.Fatal("unexpected release support filename accepted")
	}
	if _, err := StageVerifiedReleaseFile(filepath.Join(fixture.sourceDir, "license"), fixture.destination, "LICENSE", maxReleaseFileBytes+1, strings.Repeat("0", 64)); err == nil {
		t.Fatal("oversized release support file accepted")
	}
}

func TestStageVerifiedArtifactIdempotentlyKeepsIdenticalFinal(t *testing.T) {
	fixture := newArtifactFixture(t)
	payload := []byte("verified-release-artifact")
	source := filepath.Join(fixture.sourceDir, "download")
	writeArtifactTestFile(t, source, payload, 0o400)
	expectedHash := artifactDigest(payload)
	final, err := StageVerifiedArtifact(source, fixture.destination, "sshserver", int64(len(payload)), expectedHash)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(final)
	if err != nil {
		t.Fatal(err)
	}
	second, err := StageVerifiedArtifact(source, fixture.destination, "sshserver", int64(len(payload)), expectedHash)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(second)
	if err != nil {
		t.Fatal(err)
	}
	if second != final || !os.SameFile(before, after) {
		t.Fatal("idempotent staging replaced the identical final artifact")
	}
	if err := VerifyStagedArtifact(final, int64(len(payload)), expectedHash); err != nil {
		t.Fatal(err)
	}
	assertNoArtifactTemporary(t, fixture.destination)

	if err := os.Chmod(source, 0o600); err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Repeat([]byte{'x'}, len(payload))
	if err := os.WriteFile(source, wrong, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := StageVerifiedArtifact(source, fixture.destination, "sshserver", int64(len(payload)), expectedHash); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("unverified source with existing final error = %v", err)
	}
	unchanged, err := os.Lstat(final)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, unchanged) {
		t.Fatal("unverified idempotent attempt replaced the final artifact")
	}
	if err := os.Chmod(final, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := VerifyStagedArtifact(final, int64(len(payload)), expectedHash); err == nil {
		t.Fatal("staged artifact with broadened mode unexpectedly verified")
	}
}

func TestStageVerifiedArtifactConcurrentPublishersDoNotOverwrite(t *testing.T) {
	fixture := newArtifactFixture(t)
	const publisherCount = 16
	type publicationResult struct {
		index int
		path  string
		err   error
	}
	payloads := make([][]byte, publisherCount)
	sources := make([]string, publisherCount)
	for index := range publisherCount {
		payloads[index] = bytes.Repeat([]byte{byte(index + 1)}, 64*1024)
		sources[index] = filepath.Join(fixture.sourceDir, fmt.Sprintf("download-%02d", index))
		writeArtifactTestFile(t, sources[index], payloads[index], 0o600)
	}

	start := make(chan struct{})
	results := make(chan publicationResult, publisherCount)
	for index := range publisherCount {
		go func() {
			<-start
			path, err := StageVerifiedArtifact(
				sources[index], fixture.destination, "sshserver",
				int64(len(payloads[index])), artifactDigest(payloads[index]),
			)
			results <- publicationResult{index: index, path: path, err: err}
		}()
	}
	close(start)

	successes := make([]publicationResult, 0, publisherCount)
	for range publisherCount {
		result := <-results
		if result.err == nil {
			successes = append(successes, result)
		}
	}
	if len(successes) != 1 {
		t.Fatalf("successful concurrent publishers = %d, want exactly one", len(successes))
	}
	winner := successes[0]
	if winner.path != filepath.Join(fixture.destination, "sshserver") {
		t.Fatalf("published path = %q", winner.path)
	}
	staged, err := os.ReadFile(filepath.Join(fixture.destination, "sshserver"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(staged, payloads[winner.index]) {
		t.Fatalf("final bytes do not belong to successful publisher %d", winner.index)
	}
	assertNoArtifactTemporary(t, fixture.destination)
}

func TestStageVerifiedArtifactRejectsSizeDigestAndPathExpectations(t *testing.T) {
	payload := []byte("artifact expectation fixture")
	tests := []struct {
		name          string
		expectedBytes int64
		expectedHash  string
		finalName     string
		want          string
	}{
		{name: "short size", expectedBytes: int64(len(payload) - 1), expectedHash: artifactDigest(payload), finalName: "sshserver", want: "size"},
		{name: "long size", expectedBytes: int64(len(payload) + 1), expectedHash: artifactDigest(payload), finalName: "sshserver", want: "size"},
		{name: "wrong digest", expectedBytes: int64(len(payload)), expectedHash: strings.Repeat("0", 64), finalName: "sshserver", want: "SHA-256"},
		{name: "uppercase digest", expectedBytes: int64(len(payload)), expectedHash: strings.Repeat("A", 64), finalName: "sshserver", want: "lowercase"},
		{name: "short digest", expectedBytes: int64(len(payload)), expectedHash: "00", finalName: "sshserver", want: "lowercase"},
		{name: "zero size", expectedBytes: 0, expectedHash: artifactDigest(payload), finalName: "sshserver", want: "boundary"},
		{name: "oversized expectation", expectedBytes: maximumStagedArtifactBytes + 1, expectedHash: artifactDigest(payload), finalName: "sshserver", want: "boundary"},
		{name: "parent name", expectedBytes: int64(len(payload)), expectedHash: artifactDigest(payload), finalName: "../sshserver", want: "component"},
		{name: "nested name", expectedBytes: int64(len(payload)), expectedHash: artifactDigest(payload), finalName: "bin/sshserver", want: "component"},
		{name: "empty name", expectedBytes: int64(len(payload)), expectedHash: artifactDigest(payload), finalName: "", want: "component"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newArtifactFixture(t)
			source := filepath.Join(fixture.sourceDir, "download")
			writeArtifactTestFile(t, source, payload, 0o600)
			if _, err := StageVerifiedArtifact(source, fixture.destination, test.finalName, test.expectedBytes, test.expectedHash); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("staging error = %v, want containing %q", err, test.want)
			}
			assertNoArtifactTemporary(t, fixture.destination)
		})
	}

	fixture := newArtifactFixture(t)
	source := filepath.Join(fixture.sourceDir, "download")
	writeArtifactTestFile(t, source, payload, 0o600)
	if _, err := StageVerifiedArtifact("relative", fixture.destination, "sshserver", int64(len(payload)), artifactDigest(payload)); err == nil {
		t.Fatal("relative source path was accepted")
	}
	if _, err := StageVerifiedArtifact(source, "relative", "sshserver", int64(len(payload)), artifactDigest(payload)); err == nil {
		t.Fatal("relative destination path was accepted")
	}
}

func TestStageVerifiedArtifactRejectsUnsafeSources(t *testing.T) {
	payload := []byte("secure source fixture")
	tests := []struct {
		name  string
		setup func(*testing.T, artifactFixture) string
	}{
		{
			name: "symlink file",
			setup: func(t *testing.T, fixture artifactFixture) string {
				target := filepath.Join(fixture.sourceDir, "target")
				writeArtifactTestFile(t, target, payload, 0o600)
				link := filepath.Join(fixture.sourceDir, "download")
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				return link
			},
		},
		{
			name: "symlink directory component",
			setup: func(t *testing.T, fixture artifactFixture) string {
				real := filepath.Join(fixture.root, "real-source")
				if err := os.Mkdir(real, 0o700); err != nil {
					t.Fatal(err)
				}
				writeArtifactTestFile(t, filepath.Join(real, "download"), payload, 0o600)
				link := filepath.Join(fixture.root, "linked-source")
				if err := os.Symlink(real, link); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(link, "download")
			},
		},
		{
			name: "hard-linked file",
			setup: func(t *testing.T, fixture artifactFixture) string {
				source := filepath.Join(fixture.sourceDir, "download")
				writeArtifactTestFile(t, source, payload, 0o600)
				if err := os.Link(source, filepath.Join(fixture.sourceDir, "second-link")); err != nil {
					t.Fatal(err)
				}
				return source
			},
		},
		{
			name: "group-writable file",
			setup: func(t *testing.T, fixture artifactFixture) string {
				source := filepath.Join(fixture.sourceDir, "download")
				writeArtifactTestFile(t, source, payload, 0o620)
				return source
			},
		},
		{
			name: "world-writable file",
			setup: func(t *testing.T, fixture artifactFixture) string {
				source := filepath.Join(fixture.sourceDir, "download")
				writeArtifactTestFile(t, source, payload, 0o602)
				return source
			},
		},
		{
			name: "writable directory component",
			setup: func(t *testing.T, fixture artifactFixture) string {
				source := filepath.Join(fixture.sourceDir, "download")
				writeArtifactTestFile(t, source, payload, 0o600)
				if err := os.Chmod(fixture.sourceDir, 0o770); err != nil {
					t.Fatal(err)
				}
				return source
			},
		},
		{
			name: "directory instead of file",
			setup: func(t *testing.T, fixture artifactFixture) string {
				source := filepath.Join(fixture.sourceDir, "download")
				if err := os.Mkdir(source, 0o700); err != nil {
					t.Fatal(err)
				}
				return source
			},
		},
		{
			name: "fifo instead of file",
			setup: func(t *testing.T, fixture artifactFixture) string {
				source := filepath.Join(fixture.sourceDir, "download")
				if err := unix.Mkfifo(source, 0o600); err != nil {
					t.Fatal(err)
				}
				return source
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newArtifactFixture(t)
			source := test.setup(t, fixture)
			if _, err := StageVerifiedArtifact(source, fixture.destination, "sshserver", int64(len(payload)), artifactDigest(payload)); err == nil {
				t.Fatal("unsafe source was accepted")
			}
			assertNoArtifactTemporary(t, fixture.destination)
		})
	}
}

func TestStageVerifiedArtifactRejectsForeignSourceAndDestinationOwners(t *testing.T) {
	payload := []byte("foreign owner fixture")
	t.Run("source", func(t *testing.T) {
		fixture := newArtifactFixture(t)
		source := filepath.Join(fixture.sourceDir, "download")
		sourcePayload := payload
		if os.Geteuid() == 0 {
			writeArtifactTestFile(t, source, sourcePayload, 0o600)
			if err := os.Chown(source, 1, -1); err != nil {
				t.Fatal(err)
			}
		} else {
			var err error
			source, err = filepath.EvalSymlinks("/etc/passwd")
			if err != nil {
				t.Fatal(err)
			}
			sourcePayload, err = os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := StageVerifiedArtifact(source, fixture.destination, "sshserver", int64(len(sourcePayload)), artifactDigest(sourcePayload)); err == nil {
			t.Fatal("foreign-owned source was accepted")
		}
	})

	t.Run("destination", func(t *testing.T) {
		fixture := newArtifactFixture(t)
		source := filepath.Join(fixture.sourceDir, "download")
		writeArtifactTestFile(t, source, payload, 0o600)
		destination := ""
		if os.Geteuid() == 0 {
			destination = filepath.Join(fixture.root, "foreign-destination")
			if err := os.Mkdir(destination, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(destination, 1, -1); err != nil {
				t.Fatal(err)
			}
		} else {
			var err error
			destination, err = filepath.EvalSymlinks("/etc")
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, err := StageVerifiedArtifact(source, destination, "sshserver", int64(len(payload)), artifactDigest(payload)); err == nil {
			t.Fatal("foreign-owned destination was accepted")
		}
	})
}

func TestStageVerifiedArtifactRejectsUnsafeDestinationsAndExistingFinals(t *testing.T) {
	payload := []byte("destination fixture")
	t.Run("symlink destination", func(t *testing.T) {
		fixture := newArtifactFixture(t)
		source := filepath.Join(fixture.sourceDir, "download")
		writeArtifactTestFile(t, source, payload, 0o600)
		link := filepath.Join(fixture.root, "destination-link")
		if err := os.Symlink(fixture.destination, link); err != nil {
			t.Fatal(err)
		}
		if _, err := StageVerifiedArtifact(source, link, "sshserver", int64(len(payload)), artifactDigest(payload)); err == nil {
			t.Fatal("symlink destination was accepted")
		}
	})

	t.Run("writable destination", func(t *testing.T) {
		fixture := newArtifactFixture(t)
		source := filepath.Join(fixture.sourceDir, "download")
		writeArtifactTestFile(t, source, payload, 0o600)
		if err := os.Chmod(fixture.destination, 0o770); err != nil {
			t.Fatal(err)
		}
		if _, err := StageVerifiedArtifact(source, fixture.destination, "sshserver", int64(len(payload)), artifactDigest(payload)); err == nil {
			t.Fatal("group-writable destination was accepted")
		}
	})

	t.Run("writable destination parent", func(t *testing.T) {
		fixture := newArtifactFixture(t)
		source := filepath.Join(fixture.sourceDir, "download")
		writeArtifactTestFile(t, source, payload, 0o600)
		parent := filepath.Join(fixture.root, "writable-parent")
		destination := filepath.Join(parent, "destination")
		if err := os.Mkdir(parent, 0o770); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o770); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(destination, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := StageVerifiedArtifact(source, destination, "sshserver", int64(len(payload)), artifactDigest(payload)); err == nil {
			t.Fatal("destination below writable parent was accepted")
		}
	})

	t.Run("file destination", func(t *testing.T) {
		fixture := newArtifactFixture(t)
		source := filepath.Join(fixture.sourceDir, "download")
		writeArtifactTestFile(t, source, payload, 0o600)
		notDirectory := filepath.Join(fixture.root, "not-directory")
		writeArtifactTestFile(t, notDirectory, []byte("x"), 0o600)
		if _, err := StageVerifiedArtifact(source, notDirectory, "sshserver", int64(len(payload)), artifactDigest(payload)); err == nil {
			t.Fatal("regular file destination was accepted")
		}
	})

	for _, test := range []struct {
		name  string
		setup func(*testing.T, artifactFixture, string)
	}{
		{
			name: "different final bytes",
			setup: func(t *testing.T, _ artifactFixture, final string) {
				writeArtifactTestFile(t, final, bytes.Repeat([]byte{'x'}, len(payload)), 0o500)
			},
		},
		{
			name: "writable final",
			setup: func(t *testing.T, _ artifactFixture, final string) {
				writeArtifactTestFile(t, final, payload, 0o700)
			},
		},
		{
			name: "hard-linked final",
			setup: func(t *testing.T, fixture artifactFixture, final string) {
				writeArtifactTestFile(t, final, payload, 0o500)
				if err := os.Link(final, filepath.Join(fixture.destination, "second-link")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlink final",
			setup: func(t *testing.T, fixture artifactFixture, final string) {
				target := filepath.Join(fixture.destination, "target")
				writeArtifactTestFile(t, target, payload, 0o500)
				if err := os.Symlink(target, final); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newArtifactFixture(t)
			source := filepath.Join(fixture.sourceDir, "download")
			writeArtifactTestFile(t, source, payload, 0o600)
			final := filepath.Join(fixture.destination, "sshserver")
			test.setup(t, fixture, final)
			before, _ := os.Lstat(final)
			if _, err := StageVerifiedArtifact(source, fixture.destination, "sshserver", int64(len(payload)), artifactDigest(payload)); err == nil {
				t.Fatal("unsafe existing final was accepted")
			}
			after, err := os.Lstat(final)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(before, after) {
				t.Fatal("failed staging replaced the existing final")
			}
			assertNoArtifactTemporary(t, fixture.destination)
		})
	}
}

func TestStageOpenedArtifactCopiesFromHeldSourceDescriptor(t *testing.T) {
	fixture := newArtifactFixture(t)
	original := []byte("descriptor-bound-release")
	replacement := bytes.Repeat([]byte{'x'}, len(original))
	sourcePath := filepath.Join(fixture.sourceDir, "download")
	writeArtifactTestFile(t, sourcePath, original, 0o600)
	expectation, err := parseArtifactExpectation(int64(len(original)), artifactDigest(original))
	if err != nil {
		t.Fatal(err)
	}
	source, sourceStat, err := openVerifiedArtifactSource(sourcePath, expectation.bytes)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := os.Rename(sourcePath, filepath.Join(fixture.sourceDir, "original-unlinked")); err != nil {
		t.Fatal(err)
	}
	writeArtifactTestFile(t, sourcePath, replacement, 0o600)
	final, err := stageOpenedArtifact(source, sourceStat, fixture.destination, "sshserver", expectation, 0o500)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := os.ReadFile(final)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(staged, original) {
		t.Fatalf("staged pathname replacement bytes %q", staged)
	}
	assertNoArtifactTemporary(t, fixture.destination)
}
