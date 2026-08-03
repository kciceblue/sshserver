//go:build darwin || linux

package deployment

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type deploymentLock struct {
	file *os.File
}

// acquireDeploymentBootstrapLock serializes the first lifecycle operation
// without creating deployment metadata. The current user's already-validated
// home directory is a stable advisory-lock inode on every supported target.
// Once the lifecycle lock exists, it remains the narrower long-lived lock.
func acquireDeploymentBootstrapLock(layout Layout) (*deploymentLock, error) {
	fd, err := unix.Open(layout.HomeDir, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open deployment bootstrap lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), layout.HomeDir)
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("wrap deployment bootstrap lock descriptor")
	}
	if err := validateDirectoryFD(fd); err != nil {
		file.Close()
		return nil, fmt.Errorf("validate deployment bootstrap lock: %w", err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("another deployment bootstrap operation is already running")
		}
		return nil, fmt.Errorf("lock deployment bootstrap: %w", err)
	}
	return &deploymentLock{file: file}, nil
}

// acquireDeploymentMutationLocks takes the process-wide first-operation
// admission lock before it creates or acquires the persistent lifecycle lock.
// Rollback and uninstall use the same ordering as Apply so a losing operation
// cannot create layout directories before reporting contention.
func acquireDeploymentMutationLocks(layout Layout) (*deploymentLock, *deploymentLock, error) {
	bootstrap, err := acquireDeploymentBootstrapLock(layout)
	if err != nil {
		return nil, nil, err
	}
	closeBootstrapOnError := func(operationErr error) (*deploymentLock, *deploymentLock, error) {
		if closeErr := bootstrap.Close(); closeErr != nil {
			operationErr = errors.Join(operationErr, fmt.Errorf("release deployment bootstrap lock: %w", closeErr))
		}
		return nil, nil, operationErr
	}

	var lifecycle *deploymentLock
	if _, statErr := os.Lstat(layout.LockPath); statErr == nil {
		lifecycle, err = acquireExistingDeploymentLock(layout)
	} else if errors.Is(statErr, os.ErrNotExist) {
		if err := PrepareDeploymentLockRoot(layout); err != nil {
			return closeBootstrapOnError(err)
		}
		lifecycle, err = acquireDeploymentLock(layout)
	} else {
		return closeBootstrapOnError(fmt.Errorf("inspect deployment lock: %w", statErr))
	}
	if err != nil {
		return closeBootstrapOnError(err)
	}
	return bootstrap, lifecycle, nil
}

func acquireDeploymentLock(layout Layout) (*deploymentLock, error) {
	return acquireDeploymentFileLock(layout, unix.O_CREAT, unix.LOCK_EX)
}

func acquireExistingDeploymentLock(layout Layout) (*deploymentLock, error) {
	return acquireDeploymentFileLock(layout, 0, unix.LOCK_EX)
}

func acquireDeploymentSharedLock(layout Layout) (*deploymentLock, error) {
	// An active deployment has already created the lifecycle lock. Refuse a
	// missing file instead of manufacturing deployment metadata from the
	// enrollment path.
	return acquireDeploymentFileLock(layout, 0, unix.LOCK_SH)
}

// acquireDeploymentSharedLockIfPresent validates and shares an existing
// lifecycle lock without creating it. Read-only preflight surfaces use this to
// take a coherent snapshot while preserving the missing-layout cancellation
// guarantee.
func acquireDeploymentSharedLockIfPresent(layout Layout) (*deploymentLock, bool, error) {
	lock, err := acquireDeploymentFileLock(layout, 0, unix.LOCK_SH)
	if errors.Is(err, unix.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	return lock, true, nil
}

func validateExistingDeploymentLock(layout Layout) error {
	lock, _, err := acquireDeploymentSharedLockIfPresent(layout)
	if err != nil {
		return err
	}
	if lock == nil {
		return nil
	}
	if err := lock.Close(); err != nil {
		return fmt.Errorf("release deployment preflight lock: %w", err)
	}
	return nil
}

func acquireDeploymentFileLock(layout Layout, openFlags, lockMode int) (*deploymentLock, error) {
	fd, err := unix.Open(layout.LockPath, openFlags|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open deployment lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), layout.LockPath)
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("wrap deployment lock descriptor")
	}
	if err := validateDeploymentFileFD(fd); err != nil {
		file.Close()
		return nil, fmt.Errorf("validate deployment lock: %w", err)
	}
	if err := unix.Flock(fd, lockMode|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("another deployment lifecycle operation is already running")
		}
		return nil, fmt.Errorf("lock deployment lifecycle: %w", err)
	}
	return &deploymentLock{file: file}, nil
}

func (lock *deploymentLock) Close() error {
	unlockErr := unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	closeErr := lock.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}

func newTransactionID() (string, error) {
	payload := make([]byte, 16)
	if _, err := rand.Read(payload); err != nil {
		return "", fmt.Errorf("generate deployment transaction ID: %w", err)
	}
	return hex.EncodeToString(payload), nil
}
