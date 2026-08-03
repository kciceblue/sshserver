//go:build darwin || linux

package deployment

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kciceblue/sshserver/runtime/internal/config"
	"github.com/kciceblue/sshserver/runtime/internal/service"
)

const (
	maxServiceDefinitionBytes    = 256 * 1024
	maxManagerCommandOutputBytes = 64 * 1024
)

var ErrManagerCommandOutputExceeded = errors.New("service-manager command output exceeds its size boundary")

// CommandResult preserves bounded native-manager output for classification and
// explicit error reporting. CommandRunner never invokes a shell.
type CommandResult struct {
	Stdout string
	Stderr string
}

// CommandRunner makes native-manager discovery and execution injectable.
type CommandRunner interface {
	LookPath(string) (string, error)
	Run(context.Context, string, ...string) (CommandResult, error)
}

// ExecCommandRunner executes an already-separated argv without a shell.
type ExecCommandRunner struct{}

func (ExecCommandRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (ExecCommandRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	command := exec.CommandContext(ctx, name, args...)
	stdout := boundedCommandBuffer{limit: maxManagerCommandOutputBytes}
	stderr := boundedCommandBuffer{limit: maxManagerCommandOutputBytes}
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if stdout.overflow || stderr.overflow {
		err = errors.Join(err, ErrManagerCommandOutputExceeded)
	}
	return CommandResult{Stdout: stdout.String(), Stderr: stderr.String()}, err
}

type boundedCommandBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (buffer *boundedCommandBuffer) Write(payload []byte) (int, error) {
	written := len(payload)
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.overflow = true
		return written, nil
	}
	if len(payload) > remaining {
		buffer.overflow = true
		payload = payload[:remaining]
	}
	_, _ = buffer.buffer.Write(payload)
	return written, nil
}

func (buffer *boundedCommandBuffer) Len() int       { return buffer.buffer.Len() }
func (buffer *boundedCommandBuffer) String() string { return buffer.buffer.String() }

// ForegroundFallback is returned only when the current user's native service
// manager is absent or its user domain is recognizably unavailable. The caller
// must supervise Command for its full lifetime over the verified SSH session.
type ForegroundFallback struct {
	Required   bool     `json:"required"`
	Reason     string   `json:"reason"`
	Command    []string `json:"command"`
	Supervised bool     `json:"supervised"`
}

// ManagerAvailability describes either an available current-user manager or a
// structured foreground requirement. It never represents a failed activation
// as a successful fallback.
type ManagerAvailability struct {
	Manager           ManagerKind         `json:"manager"`
	Available         bool                `json:"available"`
	ServiceDefinition string              `json:"service_definition,omitempty"`
	Foreground        *ForegroundFallback `json:"foreground,omitempty"`
}

// ServiceManagerAdapter owns only the current user's systemd unit or LaunchAgent.
type ServiceManagerAdapter struct {
	platform       string
	homeDir        string
	uid            int
	runner         CommandRunner
	commandName    string
	definitionPath string
	domain         string
	target         string
}

func NewServiceManagerAdapter(platform, homeDir string, runner CommandRunner) (ServiceManagerAdapter, error) {
	if platform != "linux" && platform != "darwin" {
		return ServiceManagerAdapter{}, fmt.Errorf("unsupported service-manager platform %q", platform)
	}
	if runner == nil {
		return ServiceManagerAdapter{}, errors.New("service-manager command runner is required")
	}
	if err := validateAbsoluteCanonicalPath(homeDir); err != nil {
		return ServiceManagerAdapter{}, fmt.Errorf("validate user home: %w", err)
	}
	homeFD, err := openSecureDirectory(homeDir)
	if err != nil {
		return ServiceManagerAdapter{}, fmt.Errorf("validate user home: %w", err)
	}
	if err := unix.Close(homeFD); err != nil {
		return ServiceManagerAdapter{}, fmt.Errorf("close user home: %w", err)
	}

	adapter := ServiceManagerAdapter{
		platform: platform,
		homeDir:  homeDir,
		uid:      os.Geteuid(),
		runner:   runner,
	}
	if platform == "linux" {
		adapter.commandName = "systemctl"
		adapter.definitionPath = filepath.Join(homeDir, ".config", "systemd", "user", service.Label+".service")
		adapter.target = service.Label + ".service"
	} else {
		adapter.commandName = "launchctl"
		adapter.definitionPath = filepath.Join(homeDir, "Library", "LaunchAgents", service.Label+".plist")
		adapter.domain = "gui/" + strconv.Itoa(adapter.uid)
		adapter.target = adapter.domain + "/" + service.Label
	}
	if err := requireStrictDescendant(homeDir, adapter.definitionPath, "service definition"); err != nil {
		return ServiceManagerAdapter{}, err
	}
	if err := validateAbsoluteCanonicalPath(adapter.definitionPath); err != nil {
		return ServiceManagerAdapter{}, fmt.Errorf("validate service definition path: %w", err)
	}
	return adapter, nil
}

func NewNativeServiceManagerAdapter(homeDir string) (ServiceManagerAdapter, error) {
	return NewServiceManagerAdapter(runtime.GOOS, homeDir, ExecCommandRunner{})
}

func (adapter ServiceManagerAdapter) Kind() ManagerKind {
	if adapter.platform == "linux" {
		return ManagerSystemd
	}
	return ManagerLaunchd
}

func (adapter ServiceManagerAdapter) DefinitionPath() string {
	return adapter.definitionPath
}

// Detect checks only the current-user manager domain. A missing command or a
// recognized unavailable user domain yields a supervised foreground command;
// unexpected probe failures remain errors.
func (adapter ServiceManagerAdapter) Detect(ctx context.Context, binaryPath, stateDir string) (ManagerAvailability, error) {
	foreground, err := adapter.foreground(binaryPath, stateDir)
	if err != nil {
		return ManagerAvailability{}, err
	}
	command, err := adapter.lookupCommand()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return adapter.foregroundAvailability("user_service_manager_not_installed", foreground), nil
		}
		return ManagerAvailability{}, fmt.Errorf("discover %s: %w", adapter.Kind(), err)
	}
	result, runErr := adapter.runProbe(ctx, command)
	if runErr != nil {
		if managerUnavailable(adapter.platform, result) {
			return adapter.foregroundAvailability("user_service_manager_unavailable", foreground), nil
		}
		return ManagerAvailability{}, commandError(adapter.Kind(), "probe", result, runErr)
	}
	return ManagerAvailability{
		Manager:           adapter.Kind(),
		Available:         true,
		ServiceDefinition: adapter.definitionPath,
	}, nil
}

func (adapter ServiceManagerAdapter) foregroundAvailability(reason string, command []string) ManagerAvailability {
	return ManagerAvailability{
		Manager:   ManagerForeground,
		Available: false,
		Foreground: &ForegroundFallback{
			Required:   true,
			Reason:     reason,
			Command:    append([]string(nil), command...),
			Supervised: true,
		},
	}
}

func (adapter ServiceManagerAdapter) foreground(binaryPath, stateDir string) ([]string, error) {
	for name, value := range map[string]string{"foreground binary": binaryPath, "foreground state directory": stateDir} {
		if err := validateAbsoluteCanonicalPath(value); err != nil {
			return nil, fmt.Errorf("validate %s: %w", name, err)
		}
		if err := requireStrictDescendant(adapter.homeDir, value, name); err != nil {
			return nil, err
		}
	}
	return []string{binaryPath, "serve", "--state-dir", stateDir}, nil
}

// InstallDefinition publishes already-rendered, bounded service-manager bytes
// beneath the validated user home. Parents are created owner-only without
// following symlinks and the final definition is atomically written as 0600.
func (adapter ServiceManagerAdapter) InstallDefinition(payload []byte) (string, error) {
	if len(payload) == 0 || len(payload) > maxServiceDefinitionBytes {
		return "", errors.New("service definition is empty or exceeds its size boundary")
	}
	homeFD, err := openSecureDirectory(adapter.homeDir)
	if err != nil {
		return "", fmt.Errorf("validate user home: %w", err)
	}
	relativeParent, err := filepath.Rel(adapter.homeDir, filepath.Dir(adapter.definitionPath))
	if err != nil {
		unix.Close(homeFD)
		return "", fmt.Errorf("resolve service definition parent: %w", err)
	}
	if err := ensureDirectoryBelow(homeFD, relativeParent); err != nil {
		unix.Close(homeFD)
		return "", fmt.Errorf("prepare service definition parent: %w", err)
	}
	if err := unix.Close(homeFD); err != nil {
		return "", fmt.Errorf("close user home: %w", err)
	}
	if err := config.WriteFileAtomic(adapter.definitionPath, payload, 0o600); err != nil {
		return "", fmt.Errorf("install service definition: %w", err)
	}
	installed, err := readDeploymentFile(adapter.definitionPath, maxServiceDefinitionBytes)
	if err != nil {
		return "", fmt.Errorf("validate installed service definition: %w", err)
	}
	if !bytes.Equal(installed, payload) {
		return "", errors.New("installed service definition does not match rendered bytes")
	}
	return adapter.definitionPath, nil
}

func (adapter ServiceManagerAdapter) Activate(ctx context.Context) error {
	command, err := adapter.lookupCommand()
	if err != nil {
		return fmt.Errorf("discover %s for activation: %w", adapter.Kind(), err)
	}
	if adapter.platform == "linux" {
		if err := adapter.runRequired(ctx, command, "reload definitions", "--user", "daemon-reload"); err != nil {
			return err
		}
		return adapter.runRequired(ctx, command, "enable and start", "--user", "enable", "--now", adapter.target)
	}
	if err := adapter.runRequired(ctx, command, "bootstrap", "bootstrap", adapter.domain, adapter.definitionPath); err != nil {
		return err
	}
	return adapter.runRequired(ctx, command, "kickstart", "kickstart", "-k", adapter.target)
}

func (adapter ServiceManagerAdapter) Stop(ctx context.Context) error {
	command, err := adapter.lookupCommand()
	if err != nil {
		return fmt.Errorf("discover %s for stop: %w", adapter.Kind(), err)
	}
	var result CommandResult
	if adapter.platform == "linux" {
		result, err = adapter.runner.Run(ctx, command, "--user", "disable", "--now", adapter.target)
	} else {
		result, err = adapter.runner.Run(ctx, command, "bootout", adapter.target)
	}
	if err == nil || managerNotLoaded(adapter.platform, result) {
		return nil
	}
	return commandError(adapter.Kind(), "stop", result, err)
}

// Remove stops the user service, securely removes only this adapter's protected
// definition, and refreshes systemd's user manager when applicable.
func (adapter ServiceManagerAdapter) Remove(ctx context.Context) error {
	if err := adapter.Stop(ctx); err != nil {
		return err
	}
	if err := removeDeploymentFile(adapter.definitionPath); err != nil {
		return fmt.Errorf("remove service definition: %w", err)
	}
	if adapter.platform == "linux" {
		command, err := adapter.lookupCommand()
		if err != nil {
			return fmt.Errorf("discover %s for definition reload: %w", adapter.Kind(), err)
		}
		return adapter.runRequired(ctx, command, "reload definitions", "--user", "daemon-reload")
	}
	return nil
}

func (adapter ServiceManagerAdapter) IsActive(ctx context.Context) (bool, error) {
	command, err := adapter.lookupCommand()
	if err != nil {
		return false, fmt.Errorf("discover %s for status: %w", adapter.Kind(), err)
	}
	if adapter.platform == "linux" {
		result, runErr := adapter.runner.Run(ctx, command, "--user", "is-active", adapter.target)
		state := strings.TrimSpace(result.Stdout)
		if runErr == nil {
			return state == "active", nil
		}
		if managerNotLoaded(adapter.platform, result) || systemdInactiveState(state) {
			return false, nil
		}
		return false, commandError(adapter.Kind(), "check status", result, runErr)
	}
	result, runErr := adapter.runner.Run(ctx, command, "print", adapter.target)
	if runErr != nil {
		if managerNotLoaded(adapter.platform, result) {
			return false, nil
		}
		return false, commandError(adapter.Kind(), "check status", result, runErr)
	}
	return strings.Contains(result.Stdout, "state = running"), nil
}

func (adapter ServiceManagerAdapter) lookupCommand() (string, error) {
	command, err := adapter.runner.LookPath(adapter.commandName)
	if err != nil {
		return "", err
	}
	if err := validateAbsoluteCanonicalPath(command); err != nil {
		return "", fmt.Errorf("resolved manager command is unsafe: %w", err)
	}
	return command, nil
}

func (adapter ServiceManagerAdapter) runProbe(ctx context.Context, command string) (CommandResult, error) {
	if adapter.platform == "linux" {
		return adapter.runner.Run(ctx, command, "--user", "show-environment")
	}
	return adapter.runner.Run(ctx, command, "print", adapter.domain)
}

func (adapter ServiceManagerAdapter) runRequired(ctx context.Context, command, operation string, args ...string) error {
	result, err := adapter.runner.Run(ctx, command, args...)
	if err != nil {
		return commandError(adapter.Kind(), operation, result, err)
	}
	return nil
}

func managerUnavailable(platform string, result CommandResult) bool {
	text := strings.ToLower(result.Stdout + "\n" + result.Stderr)
	if platform == "linux" {
		return strings.Contains(text, "failed to connect to bus") ||
			strings.Contains(text, "no medium found") ||
			strings.Contains(text, "system has not been booted with systemd") ||
			strings.Contains(text, "xdg_runtime_dir") && strings.Contains(text, "not set")
	}
	return strings.Contains(text, "could not find domain for") ||
		strings.Contains(text, "domain does not exist")
}

func managerNotLoaded(platform string, result CommandResult) bool {
	text := strings.ToLower(result.Stdout + "\n" + result.Stderr)
	if platform == "linux" {
		return strings.Contains(text, "not loaded") ||
			(strings.Contains(text, "unit file") && strings.Contains(text, "does not exist")) ||
			(strings.Contains(text, "unit ") && strings.Contains(text, "could not be found")) ||
			strings.TrimSpace(result.Stdout) == "unknown"
	}
	return strings.Contains(text, "could not find service") ||
		strings.Contains(text, "could not find specified service") ||
		strings.Contains(text, "no such process")
}

func systemdInactiveState(state string) bool {
	switch state {
	case "inactive", "failed", "deactivating", "unknown", "not-found":
		return true
	default:
		return false
	}
}

func commandError(kind ManagerKind, operation string, result CommandResult, err error) error {
	detail := strings.TrimSpace(result.Stderr)
	if detail == "" {
		detail = strings.TrimSpace(result.Stdout)
	}
	if len(detail) > 4096 {
		detail = detail[:4096] + "..."
	}
	if detail == "" {
		return fmt.Errorf("%s %s: %w", kind, operation, err)
	}
	return fmt.Errorf("%s %s: %w: %s", kind, operation, err, detail)
}
