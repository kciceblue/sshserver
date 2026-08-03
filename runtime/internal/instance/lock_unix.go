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
	file    *os.File
	path    string
	created bool
}

type lockOpenMode uint8

const (
	lockCreateOrOpen lockOpenMode = iota
	lockCreateOnly
	lockOpenOnly
)

func acquireLock(stateDir string) (*fileLock, error) {
	return acquireNamedLock(stateDir, ".instance.lock", "another initialization is already running")
}

func acquireLockWithPresence(stateDir string, present bool) (*fileLock, error) {
	mode := lockCreateOnly
	if present {
		mode = lockOpenOnly
	}
	return acquireNamedLockMode(stateDir, ".instance.lock", "another initialization is already running", mode)
}

func acquireNamedLock(stateDir, name, busyMessage string) (*fileLock, error) {
	return acquireNamedLockMode(stateDir, name, busyMessage, lockCreateOrOpen)
}

func acquireNamedLockMode(stateDir, name, busyMessage string, mode lockOpenMode) (*fileLock, error) {
	path := filepath.Join(stateDir, name)
	flags := syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	created := false
	var fd int
	var err error
	switch mode {
	case lockCreateOnly:
		fd, err = syscall.Open(path, flags|syscall.O_CREAT|syscall.O_EXCL, 0o600)
		created = err == nil
	case lockOpenOnly:
		fd, err = syscall.Open(path, flags, 0)
	default:
		fd, err = syscall.Open(path, flags|syscall.O_CREAT|syscall.O_EXCL, 0o600)
		created = err == nil
		if errors.Is(err, syscall.EEXIST) {
			fd, err = syscall.Open(path, flags, 0)
		}
	}
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
	lock := &fileLock{file: file, path: path, created: created}
	if err := lock.attestPathIdentity(); err != nil {
		if closeErr := lock.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("release unattested instance lock: %w", closeErr))
		}
		return nil, err
	}
	return lock, nil
}

// attestPathIdentity proves that the protected path still names the exact
// descriptor carrying the flock. A same-user unlink or replacement otherwise
// leaves the lock held on an orphaned inode while a second process can lock the
// replacement path.
func (lock *fileLock) attestPathIdentity() error {
	if lock == nil || lock.file == nil || lock.path == "" {
		return errors.New("instance lock is closed")
	}
	descriptorInfo, err := lock.file.Stat()
	if err != nil {
		return fmt.Errorf("stat leased instance lock: %w", err)
	}
	pathInfo, err := os.Lstat(lock.path)
	if err != nil {
		return fmt.Errorf("stat leased instance lock path: %w", err)
	}
	if !os.SameFile(descriptorInfo, pathInfo) {
		return errors.New("instance lock path no longer names the leased descriptor")
	}
	stat, ok := descriptorInfo.Sys().(*syscall.Stat_t)
	if !ok || !descriptorInfo.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || uint64(stat.Nlink) != 1 || descriptorInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("leased instance lock must remain an owner-only, single-link regular file")
	}
	return nil
}

func (lock *fileLock) Close() error {
	unlockErr := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
