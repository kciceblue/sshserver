//go:build darwin || linux

package instance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type fileLock struct {
	file *os.File
}

func acquireLock(stateDir string) (*fileLock, error) {
	return acquireNamedLock(stateDir, ".instance.lock", "another initialization is already running")
}

func acquireNamedLock(stateDir, name, busyMessage string) (*fileLock, error) {
	path := filepath.Join(stateDir, name)
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open instance lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("wrap instance lock descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("stat instance lock: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || uint64(stat.Nlink) != 1 || info.Mode().Perm()&0o077 != 0 {
		file.Close()
		return nil, errors.New("instance lock must be an owner-only, single-link regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New(busyMessage)
		}
		return nil, fmt.Errorf("lock instance: %w", err)
	}
	return &fileLock{file: file}, nil
}

func (lock *fileLock) Close() error {
	unlockErr := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
