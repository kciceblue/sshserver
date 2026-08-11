//go:build darwin || linux

package deployment

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func FuzzValidateRemovableArtifactName(f *testing.F) {
	executablePath, err := os.Executable()
	if err != nil {
		f.Fatal(err)
	}
	var base unix.Stat_t
	if err := unix.Stat(executablePath, &base); err != nil {
		f.Fatal(err)
	}
	base.Uid = uint32(os.Geteuid())
	base.Nlink = 1
	executable := base
	executable.Mode = (executable.Mode &^ 0o777) | 0o500
	staged := base
	staged.Mode = (staged.Mode &^ 0o777) | 0o600
	document := base
	document.Mode = (document.Mode &^ 0o777) | 0o400
	unsafe := base
	unsafe.Mode = (unsafe.Mode &^ 0o777) | 0o777
	stats := []unix.Stat_t{executable, staged, document, unsafe}
	accepted := []struct {
		name string
		stat unix.Stat_t
	}{
		{name: "sshserver-linux-amd64", stat: executable},
		{name: ".sshserver-darwin-arm64.stage-0123456789abcdef0123456789abcdef", stat: staged},
		{name: "LICENSE", stat: document},
	}
	for _, seed := range accepted {
		if err := validateRemovableArtifact(seed.name, seed.stat); err != nil {
			f.Fatalf("canonical removable artifact %q must be accepted: %v", seed.name, err)
		}
	}
	if err := validateRemovableArtifact("unexpected", document); err == nil {
		f.Fatal("unexpected removable artifact name must be rejected")
	}

	for _, seed := range []string{
		"sshserver-linux-amd64",
		".sshserver-darwin-arm64.stage-0123456789abcdef0123456789abcdef",
		"LICENSE",
		"unexpected",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > 4096 {
			return
		}
		for _, stat := range stats {
			firstErr := validateRemovableArtifact(name, stat)
			secondErr := validateRemovableArtifact(name, stat)
			if (firstErr == nil) != (secondErr == nil) {
				t.Fatalf("removable-artifact acceptance changed across identical input %q", name)
			}
		}
	})
}
