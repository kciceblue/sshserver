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
	fd, err := unix.Open(layout.LockPath, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
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
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
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
