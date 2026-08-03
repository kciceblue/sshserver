//go:build darwin || linux

package deployment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrNotDeployedExecutable means the executable is not running from the
// immutable versions directory managed by the deployment lifecycle. Callers
// may use a non-deployment fallback only for this specific condition.
var ErrNotDeployedExecutable = errors.New("executable is not in a deployment layout")

// StateDirForExecutable resolves the state directory recorded for the active
// immutable deployment containing executable. It does not consult XDG paths,
// create files, open the instance database, or read instance secrets.
func StateDirForExecutable(executable string) (string, error) {
	if executable == "" || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return "", ErrNotDeployedExecutable
	}
	resolvedExecutable, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	versionDir := filepath.Dir(resolvedExecutable)
	versionsDir := filepath.Dir(versionDir)
	if filepath.Base(versionsDir) != "versions" || filepath.Base(versionDir) == "" || filepath.Base(versionDir) == "." {
		return "", ErrNotDeployedExecutable
	}
	installRoot := filepath.Dir(versionsDir)

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	physicalHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return "", fmt.Errorf("resolve physical home directory: %w", err)
	}
	if err := requireStrictDescendant(physicalHome, installRoot, "install root"); err != nil {
		return "", fmt.Errorf("validate executable deployment root: %w", err)
	}
	verifiedRoot, err := openVerifiedDirectory(installRoot, true)
	if err != nil {
		return "", fmt.Errorf("verify executable deployment root: %w", err)
	}
	if err := verifiedRoot.Close(); err != nil {
		return "", fmt.Errorf("close verified deployment root: %w", err)
	}
	verifiedVersion, err := openVerifiedDirectory(versionDir, true)
	if err != nil {
		return "", fmt.Errorf("verify executable version directory: %w", err)
	}
	if err := verifiedVersion.Close(); err != nil {
		return "", fmt.Errorf("close verified version directory: %w", err)
	}

	var state DeploymentState
	statePath := filepath.Join(installRoot, "deployment.json")
	if err := loadCanonicalDeploymentJSON(statePath, &state); err != nil {
		return "", fmt.Errorf("load executable deployment state: %w", err)
	}
	layout, err := NewLayout(physicalHome, installRoot, state.StateDir)
	if err != nil {
		return "", fmt.Errorf("validate executable deployment layout: %w", err)
	}
	if err := state.Validate(layout); err != nil {
		return "", fmt.Errorf("validate executable deployment state: %w", err)
	}
	activeStatus := state.Status == StatusActive || state.Status == StatusForeground
	if !activeStatus || state.Active == nil || state.Active.BinaryPath != resolvedExecutable {
		return "", errors.New("executable is not the active deployed release")
	}
	return state.StateDir, nil
}
