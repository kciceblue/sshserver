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

func acquireDeploymentLock(layout Layout) (*deploymentLock, error) {
	return acquireDeploymentFileLock(layout, unix.O_CREAT, unix.LOCK_EX)
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
