//go:build darwin || linux

package deployment

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

var exactInstalledArtifactNames = map[string]struct{}{
	"sshserver-linux-amd64":  {},
	"sshserver-linux-arm64":  {},
	"sshserver-darwin-amd64": {},
	"sshserver-darwin-arm64": {},
}

func exactStagedArtifactName(name string) bool {
	if !strings.HasPrefix(name, ".") {
		return false
	}
	installedName, suffix, found := strings.Cut(name[1:], ".stage-")
	if !found {
		return false
	}
	if _, found := exactInstalledArtifactNames[installedName]; !found || len(suffix) != 32 {
		return false
	}
	for _, character := range suffix {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// exactRemovableArtifactOracle intentionally does not reuse either production
// filename regexp. It is a second, literal statement of the complete set that
// uninstall may classify for deletion.
func exactRemovableArtifactOracle(name string, stat unix.Stat_t) bool {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != uint32(os.Geteuid()) ||
		uint64(stat.Nlink) != 1 ||
		stat.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0 {
		return false
	}
	permissions := uint32(stat.Mode) & 0o777
	if _, found := exactInstalledArtifactNames[name]; found {
		return permissions == 0o500
	}
	if exactStagedArtifactName(name) {
		return permissions == 0o600
	}
	return (name == "LICENSE" || name == "NOTICE") && permissions == 0o400
}

// removableArtifactFuzzStat maps all relevant mode, owner, and hard-link
// dimensions from one bounded integer while remaining portable across the
// platform-specific unix.Stat_t field widths.
func removableArtifactFuzzStat(base unix.Stat_t, shape uint16) unix.Stat_t {
	stat := base
	stat.Mode &^= unix.S_IFMT | 0o777 | unix.S_ISUID | unix.S_ISGID | unix.S_ISVTX
	switch (shape >> 9) & 0x3 {
	case 0:
		stat.Mode |= unix.S_IFREG
	case 1:
		stat.Mode |= unix.S_IFDIR
	case 2:
		stat.Mode |= unix.S_IFLNK
	}
	for bit := uint(0); bit < 9; bit++ {
		if shape&(1<<bit) != 0 {
			stat.Mode |= 1 << bit
		}
	}
	stat.Uid = uint32(os.Geteuid())
	if shape&(1<<11) != 0 {
		stat.Uid ^= 1
	}
	stat.Nlink = 1
	if shape&(1<<12) != 0 {
		stat.Nlink++
	}
	if shape&(1<<13) != 0 {
		stat.Mode |= unix.S_ISUID
	}
	if shape&(1<<14) != 0 {
		stat.Mode |= unix.S_ISGID
	}
	if shape&(1<<15) != 0 {
		stat.Mode |= unix.S_ISVTX
	}
	return stat
}

func FuzzValidateRemovableArtifactName(f *testing.F) {
	executablePath, err := os.Executable()
	if err != nil {
		f.Fatal(err)
	}
	var base unix.Stat_t
	if err := unix.Stat(executablePath, &base); err != nil {
		f.Fatal(err)
	}
	accepted := []struct {
		name  string
		shape uint16
	}{
		{name: "sshserver-linux-amd64", shape: 0o500},
		{name: "sshserver-linux-arm64", shape: 0o500},
		{name: "sshserver-darwin-amd64", shape: 0o500},
		{name: "sshserver-darwin-arm64", shape: 0o500},
		{name: ".sshserver-linux-amd64.stage-0123456789abcdef0123456789abcdef", shape: 0o600},
		{name: ".sshserver-darwin-arm64.stage-fedcba9876543210fedcba9876543210", shape: 0o600},
		{name: "LICENSE", shape: 0o400},
		{name: "NOTICE", shape: 0o400},
	}
	for _, seed := range accepted {
		stat := removableArtifactFuzzStat(base, seed.shape)
		if !exactRemovableArtifactOracle(seed.name, stat) {
			f.Fatalf("exact removable-artifact oracle rejected canonical pair %q/%#o", seed.name, seed.shape)
		}
		if err := validateRemovableArtifact(seed.name, stat); err != nil {
			f.Fatalf("canonical removable artifact %q must be accepted: %v", seed.name, err)
		}
		f.Add(seed.name, seed.shape)
	}
	for _, seed := range []struct {
		name  string
		shape uint16
	}{
		{name: "sshserver-linux-amd64.backup", shape: 0o500},
		{name: "sshserver-linux-amd64", shape: 0o600},
		{name: ".sshserver-linux-amd64.stage-0123456789abcdef0123456789abcde", shape: 0o600},
		{name: ".sshserver-linux-amd64.stage-0123456789abcdef0123456789abcdeF", shape: 0o600},
		{name: "LICENSE", shape: 0o400 | 2<<9},
		{name: "NOTICE", shape: 0o400 | 1<<11},
		{name: "unexpected", shape: 0o400 | 1<<12},
		{name: "LICENSE", shape: 0o400 | 1<<13},
	} {
		f.Add(seed.name, seed.shape)
	}

	f.Fuzz(func(t *testing.T, name string, shape uint16) {
		if len(name) > 4096 {
			return
		}
		stat := removableArtifactFuzzStat(base, shape)
		acceptedByProduction := validateRemovableArtifact(name, stat) == nil
		acceptedByExactOracle := exactRemovableArtifactOracle(name, stat)
		if acceptedByProduction != acceptedByExactOracle {
			t.Fatalf(
				"removable-artifact production/oracle mismatch for name=%q mode=%#o uid=%d nlink=%d: production=%t oracle=%t",
				name,
				uint32(stat.Mode),
				stat.Uid,
				uint64(stat.Nlink),
				acceptedByProduction,
				acceptedByExactOracle,
			)
		}
	})
}
