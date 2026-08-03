// Package config owns the non-secret listener configuration and protected
// on-host file layout for one sync-server instance.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/kciceblue/sshserver/runtime/internal/uuidv4"
)

const (
	ConfigVersion  = 1
	ProtocolMajor  = "1"
	StorageSchema  = "1"
	DefaultPort    = 37421
	secretFileMode = 0o600
	stateDirMode   = 0o700
	maxConfigBytes = 1024 * 1024
)

var (
	ErrInsecureDirectory = errors.New("state directory must be owned by the current user and not group- or world-writable")
	ErrNonLoopback       = errors.New("listener address must contain a literal loopback IP")
	ErrUninitialized     = errors.New("server instance is not initialized")
)

type Settings struct {
	ConfigVersion int      `json:"config_version"`
	InstanceID    string   `json:"instance_id"`
	VaultID       string   `json:"vault_id"`
	Listeners     []string `json:"listeners"`
}

type InstallMarker struct {
	Generation string `json:"generation"`
	Phase      string `json:"phase"`
	State      string `json:"state"`
}

type Paths struct {
	StateDir       string
	Config         string
	Database       string
	InstanceSecret string
	InstallMarker  string
	AdminSocket    string
}

func ForStateDir(stateDir string) Paths {
	return Paths{
		StateDir:       stateDir,
		Config:         filepath.Join(stateDir, "config.json"),
		Database:       filepath.Join(stateDir, "server.db"),
		InstanceSecret: filepath.Join(stateDir, "instance-secret"),
		InstallMarker:  filepath.Join(stateDir, "install-state.json"),
		AdminSocket:    filepath.Join(stateDir, ".enrollment.sock"),
	}
}

func DefaultStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "JustAnotherTerminal", "sshserver"), nil
	case "linux":
		if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
			if !filepath.IsAbs(xdg) {
				return "", errors.New("XDG_STATE_HOME must be absolute")
			}
			return filepath.Join(xdg, "jat", "sshserver"), nil
		}
		return filepath.Join(home, ".local", "state", "jat", "sshserver"), nil
	default:
		return "", fmt.Errorf("unsupported operating system %q", runtime.GOOS)
	}
}

func DefaultListeners() []string {
	return []string{
		net.JoinHostPort("127.0.0.1", strconv.Itoa(DefaultPort)),
		net.JoinHostPort("::1", strconv.Itoa(DefaultPort)),
	}
}

func NewSettings(listeners []string) (Settings, error) {
	instanceID, err := uuidv4.New()
	if err != nil {
		return Settings{}, err
	}
	vaultID, err := uuidv4.New()
	if err != nil {
		return Settings{}, err
	}
	settings := Settings{
		ConfigVersion: ConfigVersion,
		InstanceID:    instanceID,
		VaultID:       vaultID,
		Listeners:     append([]string(nil), listeners...),
	}
	slices.Sort(settings.Listeners)
	if err := settings.Validate(); err != nil {
		return Settings{}, err
	}
	return settings, nil
}

func (settings Settings) Validate() error {
	if settings.ConfigVersion != ConfigVersion {
		return fmt.Errorf("unsupported config version %d", settings.ConfigVersion)
	}
	if _, err := uuidv4.Parse(settings.InstanceID); err != nil {
		return fmt.Errorf("invalid instance ID: %w", err)
	}
	if _, err := uuidv4.Parse(settings.VaultID); err != nil {
		return fmt.Errorf("invalid vault ID: %w", err)
	}
	if settings.InstanceID == settings.VaultID {
		return errors.New("instance and vault IDs must differ")
	}
	if len(settings.Listeners) == 0 || len(settings.Listeners) > 2 {
		return errors.New("one or two listener addresses are required")
	}
	seen := make(map[string]struct{}, len(settings.Listeners))
	sharedPort := ""
	for _, address := range settings.Listeners {
		if err := ValidateListener(address); err != nil {
			return fmt.Errorf("listener %q: %w", address, err)
		}
		_, port, _ := net.SplitHostPort(address)
		if sharedPort == "" {
			sharedPort = port
		} else if port != sharedPort {
			return errors.New("all listener addresses must use one shared port")
		}
		if _, exists := seen[address]; exists {
			return fmt.Errorf("duplicate listener %q", address)
		}
		seen[address] = struct{}{}
	}
	return nil
}

func ValidateListener(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("split host and port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return ErrNonLoopback
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("listener port must be between 1 and 65535")
	}
	if canonical := net.JoinHostPort(ip.String(), strconv.Itoa(port)); canonical != address {
		return fmt.Errorf("listener is not canonical; use %q", canonical)
	}
	return nil
}

func EnsureStateDirectory(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("state directory must be an absolute path")
	}
	created := false
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("state directory must be a real directory, not a symlink")
		}
		if info.Mode().Perm()&0o022 != 0 {
			return ErrInsecureDirectory
		}
		if owner, ok := fileOwner(info); !ok || owner != uint32(os.Geteuid()) {
			return ErrInsecureDirectory
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect state directory: %w", err)
	} else {
		created = true
	}
	if err := os.MkdirAll(path, stateDirMode); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if created {
		if err := os.Chmod(path, stateDirMode); err != nil {
			return fmt.Errorf("protect state directory: %w", err)
		}
	}
	return ValidateStateDirectory(path)
}

// ValidateStateDirectory performs the state-directory ownership and mode
// checks without creating or changing any filesystem object. Read-only CLI
// surfaces use it instead of EnsureStateDirectory so a discovery attempt can
// never turn a missing or insecure path into initialized state.
func ValidateStateDirectory(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("state directory must be an absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("state directory must be a real directory, not a symlink")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return ErrInsecureDirectory
	}
	if owner, ok := fileOwner(info); !ok || owner != uint32(os.Geteuid()) {
		return ErrInsecureDirectory
	}
	return nil
}

// PrepareProtectedFile creates an empty owner-only regular file atomically or
// validates an existing one. O_EXCL prevents following a pre-existing symlink.
func PrepareProtectedFile(path string, mode os.FileMode) error {
	if strings.ContainsRune(path, '\x00') || !filepath.IsAbs(path) {
		return errors.New("protected file path must be absolute and contain no NUL")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, mode)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ValidateProtectedFile(path, mode)
		}
		return fmt.Errorf("create protected file: %w", err)
	}
	if chmodErr := file.Chmod(mode); chmodErr != nil {
		file.Close()
		return fmt.Errorf("protect file: %w", chmodErr)
	}
	if syncErr := file.Sync(); syncErr != nil {
		file.Close()
		return fmt.Errorf("sync protected file: %w", syncErr)
	}
	if closeErr := file.Close(); closeErr != nil {
		return fmt.Errorf("close protected file: %w", closeErr)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return ValidateProtectedFile(path, mode)
}

// RestrictProtectedFile safely tightens a regular file to mode and rejects
// symlinks, hard links, foreign ownership, and non-regular files.
func RestrictProtectedFile(path string, mode os.FileMode) error {
	file, err := openProtectedFile(path, os.O_RDWR, 0o777)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("protect file: %w", err)
	}
	return validateOpenedProtectedFile(file, mode)
}

func LoadSettings(path string) (Settings, error) {
	var settings Settings
	if err := readStrictJSON(path, &settings); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Settings{}, ErrUninitialized
		}
		return Settings{}, fmt.Errorf("load config: %w", err)
	}
	if err := settings.Validate(); err != nil {
		return Settings{}, fmt.Errorf("validate config: %w", err)
	}
	return settings, nil
}

func SaveSettings(path string, settings Settings) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	return writeJSONAtomic(path, settings, secretFileMode)
}

func LoadMarker(path string) (InstallMarker, error) {
	var marker InstallMarker
	if err := readStrictJSON(path, &marker); err != nil {
		return InstallMarker{}, err
	}
	if marker.Generation != "1" {
		return InstallMarker{}, errors.New("unsupported install-marker generation")
	}
	if marker.Phase != "initializing" && marker.Phase != "ready" {
		return InstallMarker{}, errors.New("invalid install-marker phase")
	}
	if marker.State != "resume" && marker.State != "complete" {
		return InstallMarker{}, errors.New("invalid install-marker state")
	}
	if (marker.Phase == "ready") != (marker.State == "complete") {
		return InstallMarker{}, errors.New("inconsistent install marker")
	}
	return marker, nil
}

func SaveMarker(path string, marker InstallMarker) error {
	return writeJSONAtomic(path, marker, secretFileMode)
}

func ReadSecret(path string) ([]byte, error) {
	value, err := readProtectedFile(path, secretFileMode, 33)
	if err != nil {
		return nil, err
	}
	if len(value) != 32 {
		clear(value)
		return nil, errors.New("instance-secret file must contain exactly 32 bytes")
	}
	return value, nil
}

func WriteSecret(path string, value []byte) error {
	if len(value) != 32 {
		return errors.New("instance secret must contain exactly 32 bytes")
	}
	return WriteFileAtomic(path, value, secretFileMode)
}

func WriteFileAtomic(path string, value []byte, mode os.FileMode) error {
	if strings.ContainsRune(path, '\x00') || !filepath.IsAbs(path) {
		return errors.New("path must be absolute and contain no NUL")
	}
	if err := ValidateProtectedFile(path, mode); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("validate existing protected file: %w", err)
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".jat-write-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return fmt.Errorf("protect temporary file: %w", err)
	}
	if _, err := temporary.Write(value); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("install file: %w", err)
	}
	removeTemporary = false
	if err := syncDirectory(directory); err != nil {
		return err
	}
	return ValidateProtectedFile(path, mode)
}

func SameListeners(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	slices.Sort(leftCopy)
	slices.Sort(rightCopy)
	return slices.Equal(leftCopy, rightCopy)
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	payload = append(payload, '\n')
	return WriteFileAtomic(path, payload, mode)
}

func readStrictJSON(path string, destination any) error {
	payload, err := readProtectedFile(path, secretFileMode, maxConfigBytes)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open parent directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync parent directory: %w", err)
	}
	return nil
}
