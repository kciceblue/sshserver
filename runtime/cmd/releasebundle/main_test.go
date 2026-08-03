package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kciceblue/sshserver/runtime/internal/buildinfo"
)

func TestIdentityCommandProducesExactDeterministicDigest(t *testing.T) {
	args := []string{
		"identity",
		"--release", "v1.2.3",
		"--source-revision", strings.Repeat("a", 40),
		"--build-toolchain", "go1.25.0",
		"--os", "linux",
		"--architecture", "amd64",
	}
	var stdout, stderr bytes.Buffer
	if exit := run(args, &stdout, &stderr); exit != 0 {
		t.Fatalf("exit=%d stderr=%s", exit, stderr.String())
	}
	identity := strings.TrimSpace(stdout.String())
	if len(identity) != 64 || strings.ToLower(identity) != identity {
		t.Fatalf("identity=%q", identity)
	}
	stdout.Reset()
	stderr.Reset()
	if exit := run(args, &stdout, &stderr); exit != 0 || strings.TrimSpace(stdout.String()) != identity {
		t.Fatalf("repeat exit=%d identity=%q stderr=%s", exit, stdout.String(), stderr.String())
	}
}

func TestAttestationCommandProducesOneParsedRecord(t *testing.T) {
	args := []string{
		"attestation",
		"--release", "v1.2.3",
		"--source-revision", strings.Repeat("a", 40),
		"--build-toolchain", "go1.25.0",
		"--os", "darwin",
		"--architecture", "arm64",
	}
	var stdout, stderr bytes.Buffer
	if exit := run(args, &stdout, &stderr); exit != 0 {
		t.Fatalf("exit=%d stderr=%s", exit, stderr.String())
	}
	encoded := strings.TrimSpace(stdout.String())
	if !strings.HasPrefix(encoded, buildinfo.AttestationPrefix) || strings.Count(encoded, "\n") != 0 {
		t.Fatalf("attestation=%q", encoded)
	}
	parsed, err := buildinfo.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Release != "v1.2.3" || parsed.SourceRevision != strings.Repeat("a", 40) ||
		parsed.BuildToolchain != "go1.25.0" || len(parsed.BuildIdentity) != 64 ||
		parsed.ProtocolVersion != "1" || parsed.StorageSchema != "1" {
		t.Fatalf("parsed=%+v", parsed)
	}
}

func TestIdentityCommandRejectsUnsupportedTarget(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exit := run([]string{
		"identity",
		"--release", "v1.2.3",
		"--source-revision", strings.Repeat("a", 40),
		"--build-toolchain", "go1.25.0",
		"--os", "windows",
		"--architecture", "amd64",
	}, &stdout, &stderr)
	if exit != 1 || !strings.Contains(stderr.String(), "unsupported") || stdout.Len() != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}
