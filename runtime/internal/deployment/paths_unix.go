//go:build darwin || linux

package deployment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/releaseid"
)

const directoryMode = 0o700

type Layout struct {
	HomeDir     string
	InstallRoot string
	StateDir    string
	VersionsDir string
	StatePath   string
	JournalPath string
	LockPath    string
}

func DefaultLayout() (Layout, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Layout{}, fmt.Errorf("resolve home directory: %w", err)
	}
	resolvedHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return Layout{}, fmt.Errorf("resolve physical home directory: %w", err)
	}
	stateDir, err := config.DefaultStateDir()
	if err != nil {
		return Layout{}, err
	}
	if home != resolvedHome && (stateDir == home || strings.HasPrefix(stateDir, home+string(filepath.Separator))) {
		stateDir = resolvedHome + strings.TrimPrefix(stateDir, home)
	}
	home = resolvedHome
	var installRoot string
	switch runtime.GOOS {
	case "darwin":
		installRoot = filepath.Join(home, "Library", "Application Support", "JustAnotherTerminal", "sshserver-deployment")
	case "linux":
		dataHome := os.Getenv("XDG_DATA_HOME")
		if dataHome == "" {
			dataHome = filepath.Join(home, ".local", "share")
		}
		installRoot = filepath.Join(dataHome, "jat", "sshserver-deployment")
	default:
		return Layout{}, fmt.Errorf("unsupported operating system %q", runtime.GOOS)
	}
	return NewLayout(home, installRoot, stateDir)
}

func NewLayout(homeDir, installRoot, stateDir string) (Layout, error) {
	for name, value := range map[string]string{
		"home directory":  homeDir,
		"install root":    installRoot,
		"state directory": stateDir,
	} {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsRune(value, '\x00') {
			return Layout{}, fmt.Errorf("%s must be a canonical absolute path without NUL", name)
		}
	}
	if err := requireStrictDescendant(homeDir, installRoot, "install root"); err != nil {
		return Layout{}, err
	}
	if err := requireStrictDescendant(homeDir, stateDir, "state directory"); err != nil {
		return Layout{}, err
	}
	return Layout{
		HomeDir:     homeDir,
		InstallRoot: installRoot,
		StateDir:    stateDir,
		VersionsDir: filepath.Join(installRoot, "versions"),
		StatePath:   filepath.Join(installRoot, "deployment.json"),
		JournalPath: filepath.Join(installRoot, "deployment-journal.json"),
		LockPath:    filepath.Join(installRoot, ".deployment.lock"),
	}, nil
}

func (layout Layout) VersionDir(release string) (string, error) {
	if !releaseid.Valid(release) {
		return "", errors.New("release identifier is not path-safe")
	}
	return filepath.Join(layout.VersionsDir, release), nil
}

func (layout Layout) BinaryPath(release string, target Target) (string, error) {
	versionDir, err := layout.VersionDir(release)
	if err != nil {
		return "", err
	}
	if !isSupportedTarget(target) {
		return "", fmt.Errorf("unsupported deployment target %s/%s", target.OS, target.Architecture)
	}
	return filepath.Join(versionDir, "sshserver-"+target.OS+"-"+target.Architecture), nil
}

func PrepareLayout(layout Layout) error {
	if err := validateLayoutShape(layout); err != nil {
		return err
	}
	verifiedHome, err := openVerifiedDirectory(layout.HomeDir, true)
	if err != nil {
		return fmt.Errorf("validate home directory: %w", err)
	}
	defer verifiedHome.Close()
	homeFD := int(verifiedHome.Fd())
	for _, entry := range []struct {
		name   string
		target string
	}{
		{name: "install root", target: layout.InstallRoot},
		{name: "versions directory", target: layout.VersionsDir},
		{name: "state directory", target: layout.StateDir},
	} {
		name, target := entry.name, entry.target
		relative, _ := filepath.Rel(layout.HomeDir, target)
		if err := ensureDirectoryBelow(homeFD, relative); err != nil {
			return fmt.Errorf("prepare %s: %w", name, err)
		}
	}
	return nil
}

// PrepareDeploymentLockRoot creates only the owner-only install root needed to
// create the lifecycle lock. Apply calls it only after the exact read-only
// preview has matched while holding the non-persistent bootstrap lock.
func PrepareDeploymentLockRoot(layout Layout) error {
	return prepareLayoutDirectory(layout, layout.InstallRoot, "install root")
}

// PrepareDeploymentStateDirectory creates only the owner-only state directory
// needed to acquire the initialization lease. Artifact/version directories are
// deliberately deferred until the locked preview confirmation has matched.
func PrepareDeploymentStateDirectory(layout Layout) error {
	return prepareLayoutDirectory(layout, layout.StateDir, "state directory")
}

func prepareLayoutDirectory(layout Layout, target, name string) error {
	if err := validateLayoutShape(layout); err != nil {
		return err
	}
	verifiedHome, err := openVerifiedDirectory(layout.HomeDir, true)
	if err != nil {
		return fmt.Errorf("validate home directory: %w", err)
	}
	defer verifiedHome.Close()
	relative, _ := filepath.Rel(layout.HomeDir, target)
	if err := ensureDirectoryBelow(int(verifiedHome.Fd()), relative); err != nil {
		return fmt.Errorf("prepare %s: %w", name, err)
	}
	return nil
}

// ValidateLayoutReadOnly proves that every existing layout component has the
// ownership, type, and permission properties required by PrepareLayout while
// allowing absent descendants which apply would create. It never creates or
// changes a filesystem object.
func ValidateLayoutReadOnly(layout Layout) error {
	if err := validateLayoutShape(layout); err != nil {
		return err
	}
	verifiedHome, err := openVerifiedDirectory(layout.HomeDir, true)
	if err != nil {
		return fmt.Errorf("validate home directory: %w", err)
	}
	defer verifiedHome.Close()
	for _, entry := range []struct {
		name   string
		target string
	}{
		{name: "install root", target: layout.InstallRoot},
		{name: "versions directory", target: layout.VersionsDir},
		{name: "state directory", target: layout.StateDir},
	} {
		name, target := entry.name, entry.target
		relative, _ := filepath.Rel(layout.HomeDir, target)
		if err := validateExistingDirectoryBelow(int(verifiedHome.Fd()), relative); err != nil {
			return fmt.Errorf("validate prospective %s: %w", name, err)
		}
	}
	return nil
}

func validateLayoutShape(layout Layout) error {
	if os.Geteuid() == 0 {
		return errors.New("refusing user-scoped deployment as root")
	}
	rebuilt, err := NewLayout(layout.HomeDir, layout.InstallRoot, layout.StateDir)
	if err != nil {
		return err
	}
	if rebuilt != layout {
		return errors.New("deployment layout contains inconsistent derived paths")
	}
	return nil
}

func validateExistingDirectoryBelow(rootFD int, relative string) error {
	components := strings.Split(filepath.ToSlash(relative), "/")
	currentFD, err := unix.Dup(rootFD)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(currentFD) }()
	for _, component := range components {
		if component == "" || component == "." || component == ".." || strings.ContainsRune(component, '\x00') {
			return errors.New("directory path contains an unsafe component")
		}
		nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if errors.Is(openErr, unix.ENOENT) {
			return nil
		}
		if openErr != nil {
			return openErr
		}
		if err := validateDirectoryFD(nextFD); err != nil {
			unix.Close(nextFD)
			return err
		}
		unix.Close(currentFD)
		currentFD = nextFD
	}
	return nil
}

func PrepareVersionDirectory(layout Layout, release string) (string, error) {
	if err := PrepareLayout(layout); err != nil {
		return "", err
	}
	versionDir, err := layout.VersionDir(release)
	if err != nil {
		return "", err
	}
	rootFD, err := openSecureDirectory(layout.VersionsDir)
	if err != nil {
		return "", err
	}
	defer unix.Close(rootFD)
	if err := ensureDirectoryBelow(rootFD, release); err != nil {
		return "", fmt.Errorf("prepare release directory: %w", err)
	}
	return versionDir, nil
}

func requireStrictDescendant(parent, child, name string) error {
	relative, err := filepath.Rel(parent, child)
	if err != nil || relative == "." || relative == "" || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return fmt.Errorf("%s must be strictly beneath the current user's home directory", name)
	}
	return nil
}

func isSupportedTarget(target Target) bool {
	for _, supported := range supportedTargets {
		if target == supported {
			return true
		}
	}
	return false
}

func openSecureDirectory(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, err
	}
	if err := validateDirectoryFD(fd); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func ensureDirectoryBelow(rootFD int, relative string) error {
	components := strings.Split(filepath.ToSlash(relative), "/")
	currentFD, err := unix.Dup(rootFD)
	if err != nil {
		return err
	}
	defer unix.Close(currentFD)
	for _, component := range components {
		if component == "" || component == "." || component == ".." || strings.ContainsRune(component, '\x00') {
			return errors.New("directory path contains an unsafe component")
		}
		nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if errors.Is(openErr, unix.ENOENT) {
			if err := unix.Mkdirat(currentFD, component, directoryMode); err != nil && !errors.Is(err, unix.EEXIST) {
				return err
			}
			nextFD, openErr = unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		}
		if openErr != nil {
			return openErr
		}
		if err := validateDirectoryFD(nextFD); err != nil {
			unix.Close(nextFD)
			return err
		}
		unix.Close(currentFD)
		currentFD = nextFD
	}
	return nil
}

func validateDirectoryFD(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("deployment path component must be a directory")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("deployment directory must be owned by the current user")
	}
	if stat.Mode&0o022 != 0 {
		return errors.New("deployment directory must not be group- or world-writable")
	}
	return nil
}
