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

// ActiveExecutableBinding is the non-secret deployment identity carried by a
// managed enrollment request. StateDir is local routing state and is never
// serialized onto the owner-only admin socket.
type ActiveExecutableBinding struct {
	Generation   uint64 `json:"generation"`
	BinaryPath   string `json:"binary_path"`
	BinarySHA256 string `json:"binary_sha256"`
	StateDir     string `json:"-"`
}

type deploymentExecutableLocation struct {
	resolvedExecutable string
	physicalHome       string
	installRoot        string
}

// StateDirForExecutable resolves the state directory recorded for the active
// immutable deployment containing executable. It does not consult XDG paths,
// create files, open the instance database, or read instance secrets.
func StateDirForExecutable(executable string) (string, error) {
	binding, err := ActiveExecutableForExecutable(executable)
	if err != nil {
		return "", err
	}
	return binding.StateDir, nil
}

// ActiveExecutableForExecutable resolves the active deployment generation,
// exact immutable binary path, artifact digest, and protected state directory.
// It is a point-in-time observation; callers that mutate credentials must use
// AcquireManagedActiveLease to close the check/use race.
func ActiveExecutableForExecutable(executable string) (ActiveExecutableBinding, error) {
	location, err := locateDeploymentExecutable(executable)
	if err != nil {
		return ActiveExecutableBinding{}, err
	}
	var state DeploymentState
	statePath := filepath.Join(location.installRoot, "deployment.json")
	if err := loadCanonicalDeploymentJSON(statePath, &state); err != nil {
		return ActiveExecutableBinding{}, fmt.Errorf("load executable deployment state: %w", err)
	}
	layout, err := NewLayout(location.physicalHome, location.installRoot, state.StateDir)
	if err != nil {
		return ActiveExecutableBinding{}, fmt.Errorf("validate executable deployment layout: %w", err)
	}
	if err := state.Validate(layout); err != nil {
		return ActiveExecutableBinding{}, fmt.Errorf("validate executable deployment state: %w", err)
	}
	return activeExecutableBinding(state, location.resolvedExecutable)
}

// ManagedActiveLease holds the deployment lifecycle's shared lock after
// revalidating a managed executable against the active deployment record.
// Supported apply, recover, rollback, and uninstall paths take the exclusive
// side of this lock, so Close must follow the protected credential mutation.
type ManagedActiveLease struct {
	lock *deploymentLock
}

// AcquireManagedActiveLease atomically revalidates the serving executable,
// state directory, and request binding while holding the shared lifecycle
// lock. A recovery journal, or missing, stale, malformed, or non-managed
// state, fails closed.
func AcquireManagedActiveLease(executable, stateDir string, expected ActiveExecutableBinding) (*ManagedActiveLease, error) {
	location, err := locateDeploymentExecutable(executable)
	if err != nil {
		return nil, err
	}
	layout, err := NewLayout(location.physicalHome, location.installRoot, stateDir)
	if err != nil {
		return nil, fmt.Errorf("validate managed enrollment layout: %w", err)
	}
	lock, err := acquireDeploymentSharedLock(layout)
	if err != nil {
		return nil, fmt.Errorf("acquire managed enrollment lease: %w", err)
	}
	fail := func(cause error) (*ManagedActiveLease, error) {
		if closeErr := lock.Close(); closeErr != nil {
			cause = errors.Join(cause, fmt.Errorf("release managed enrollment lease: %w", closeErr))
		}
		return nil, cause
	}
	if _, err := LoadJournal(layout); err == nil {
		return fail(errors.New("managed enrollment requires deployment recovery"))
	} else if !errors.Is(err, ErrNoDeploymentJournal) {
		return fail(fmt.Errorf("inspect managed enrollment journal: %w", err))
	}
	state, err := LoadState(layout)
	if err != nil {
		return fail(fmt.Errorf("reload managed enrollment state: %w", err))
	}
	actual, err := activeExecutableBinding(state, location.resolvedExecutable)
	if err != nil {
		return fail(err)
	}
	if expected.Generation != actual.Generation || expected.BinaryPath != actual.BinaryPath ||
		expected.BinarySHA256 != actual.BinarySHA256 {
		return fail(errors.New("managed enrollment binding is stale"))
	}
	return &ManagedActiveLease{lock: lock}, nil
}

func (lease *ManagedActiveLease) Close() error {
	if lease == nil || lease.lock == nil {
		return nil
	}
	lock := lease.lock
	lease.lock = nil
	return lock.Close()
}

func locateDeploymentExecutable(executable string) (deploymentExecutableLocation, error) {
	if executable == "" || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return deploymentExecutableLocation{}, ErrNotDeployedExecutable
	}
	resolvedExecutable, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return deploymentExecutableLocation{}, fmt.Errorf("resolve executable path: %w", err)
	}
	versionDir := filepath.Dir(resolvedExecutable)
	versionsDir := filepath.Dir(versionDir)
	if filepath.Base(versionsDir) != "versions" || filepath.Base(versionDir) == "" || filepath.Base(versionDir) == "." {
		return deploymentExecutableLocation{}, ErrNotDeployedExecutable
	}
	installRoot := filepath.Dir(versionsDir)

	home, err := os.UserHomeDir()
	if err != nil {
		return deploymentExecutableLocation{}, fmt.Errorf("resolve home directory: %w", err)
	}
	physicalHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		return deploymentExecutableLocation{}, fmt.Errorf("resolve physical home directory: %w", err)
	}
	if err := requireStrictDescendant(physicalHome, installRoot, "install root"); err != nil {
		return deploymentExecutableLocation{}, fmt.Errorf("validate executable deployment root: %w", err)
	}
	verifiedRoot, err := openVerifiedDirectory(installRoot, true)
	if err != nil {
		return deploymentExecutableLocation{}, fmt.Errorf("verify executable deployment root: %w", err)
	}
	if err := verifiedRoot.Close(); err != nil {
		return deploymentExecutableLocation{}, fmt.Errorf("close verified deployment root: %w", err)
	}
	verifiedVersion, err := openVerifiedDirectory(versionDir, true)
	if err != nil {
		return deploymentExecutableLocation{}, fmt.Errorf("verify executable version directory: %w", err)
	}
	if err := verifiedVersion.Close(); err != nil {
		return deploymentExecutableLocation{}, fmt.Errorf("close verified version directory: %w", err)
	}
	return deploymentExecutableLocation{
		resolvedExecutable: resolvedExecutable,
		physicalHome:       physicalHome,
		installRoot:        installRoot,
	}, nil
}

func activeExecutableBinding(state DeploymentState, resolvedExecutable string) (ActiveExecutableBinding, error) {
	activeStatus := state.Status == StatusActive || state.Status == StatusForeground
	if !activeStatus || state.Active == nil || state.Active.BinaryPath != resolvedExecutable {
		return ActiveExecutableBinding{}, errors.New("executable is not the active deployed release")
	}
	return ActiveExecutableBinding{
		Generation:   state.Generation,
		BinaryPath:   state.Active.BinaryPath,
		BinarySHA256: state.Active.BinarySHA256,
		StateDir:     state.StateDir,
	}, nil
}
