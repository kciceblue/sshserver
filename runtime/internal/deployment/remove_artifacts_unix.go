//go:build darwin || linux

package deployment

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"

	"golang.org/x/sys/unix"

	"github.com/kciceblue/sshserver/runtime/internal/releaseid"
)

var installedArtifactNamePattern = regexp.MustCompile(`^sshserver-(linux|darwin)-(amd64|arm64)$`)
var stagedArtifactTemporaryPattern = regexp.MustCompile(`^\.sshserver-(linux|darwin)-(amd64|arm64)\.stage-[0-9a-f]{32}$`)

type removableVersion struct {
	name  string
	files []string
}

// RemoveInstalledArtifacts removes only the validated immutable version tree.
// It preflights the complete tree before deletion, refuses links or unexpected
// entries, and never touches the separate protected instance state directory.
func RemoveInstalledArtifacts(layout Layout) error {
	versions, err := openVerifiedDirectory(layout.VersionsDir, true)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("open installed versions: %w", err)
	}
	defer versions.Close()
	plan, err := preflightInstalledVersions(versions)
	if err != nil {
		return err
	}
	for _, version := range plan {
		versionFD, err := unix.Openat(int(versions.Fd()), version.name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if err != nil {
			return fmt.Errorf("reopen release %q for removal: %w", version.name, err)
		}
		versionDirectory := os.NewFile(uintptr(versionFD), version.name)
		if versionDirectory == nil {
			unix.Close(versionFD)
			return errors.New("wrap release directory for removal")
		}
		for _, name := range version.files {
			var stat unix.Stat_t
			if err := unix.Fstatat(versionFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				versionDirectory.Close()
				return fmt.Errorf("reinspect installed artifact %q: %w", name, err)
			}
			if err := validateRemovableArtifact(name, stat); err != nil {
				versionDirectory.Close()
				return err
			}
			if err := unix.Unlinkat(versionFD, name, 0); err != nil {
				versionDirectory.Close()
				return fmt.Errorf("remove installed artifact %q: %w", name, err)
			}
		}
		if err := versionDirectory.Sync(); err != nil {
			versionDirectory.Close()
			return fmt.Errorf("sync emptied release directory %q: %w", version.name, err)
		}
		if err := versionDirectory.Close(); err != nil {
			return err
		}
		if err := unix.Unlinkat(int(versions.Fd()), version.name, unix.AT_REMOVEDIR); err != nil {
			return fmt.Errorf("remove release directory %q: %w", version.name, err)
		}
	}
	if err := versions.Sync(); err != nil {
		return fmt.Errorf("sync installed versions directory: %w", err)
	}
	return nil
}

func preflightInstalledVersions(versions *os.File) ([]removableVersion, error) {
	if _, err := versions.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	names, err := versions.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	plan := make([]removableVersion, 0, len(names))
	for _, name := range names {
		if !releaseid.Valid(name) {
			return nil, fmt.Errorf("installed versions contains unexpected entry %q", name)
		}
		fd, err := unix.Openat(int(versions.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if err != nil {
			return nil, fmt.Errorf("open installed release %q: %w", name, err)
		}
		directory := os.NewFile(uintptr(fd), name)
		if directory == nil {
			unix.Close(fd)
			return nil, errors.New("wrap installed release directory")
		}
		stat, statErr := statFile(directory)
		if statErr != nil || validateDirectory(stat, true) != nil {
			directory.Close()
			return nil, fmt.Errorf("installed release directory %q is not trusted", name)
		}
		files, readErr := directory.Readdirnames(-1)
		if readErr != nil {
			directory.Close()
			return nil, readErr
		}
		sort.Strings(files)
		for _, fileName := range files {
			var fileStat unix.Stat_t
			if err := unix.Fstatat(fd, fileName, &fileStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				directory.Close()
				return nil, err
			}
			if err := validateRemovableArtifact(fileName, fileStat); err != nil {
				directory.Close()
				return nil, err
			}
		}
		if err := directory.Close(); err != nil {
			return nil, err
		}
		plan = append(plan, removableVersion{name: name, files: files})
	}
	return plan, nil
}

func validateRemovableArtifact(name string, stat unix.Stat_t) error {
	if !installedArtifactNamePattern.MatchString(name) && !stagedArtifactTemporaryPattern.MatchString(name) && name != "LICENSE" && name != "NOTICE" {
		return fmt.Errorf("installed release contains unexpected file %q", name)
	}
	if err := validateOwnedRegularFile(stat, 0, false); err != nil {
		return fmt.Errorf("installed artifact %q is not trusted: %w", name, err)
	}
	permissions := uint32(stat.Mode) & 0o777
	if installedArtifactNamePattern.MatchString(name) {
		if permissions != 0o500 {
			return fmt.Errorf("installed executable %q must have mode 0500", name)
		}
	} else if stagedArtifactTemporaryPattern.MatchString(name) {
		if permissions != 0o600 {
			return fmt.Errorf("staged artifact temporary %q must have mode 0600", name)
		}
	} else if permissions != 0o400 {
		return fmt.Errorf("installed release file %q must have mode 0400", name)
	}
	return nil
}
