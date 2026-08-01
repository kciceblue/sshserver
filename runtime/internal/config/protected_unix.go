//go:build darwin || linux

package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// ValidateProtectedFile rejects symlinks, hard links, foreign ownership,
// special files, and permissions broader than allowedMode.
func ValidateProtectedFile(path string, allowedMode os.FileMode) error {
	file, err := openProtectedFile(path, os.O_RDONLY, allowedMode)
	if err != nil {
		return err
	}
	return file.Close()
}

func readProtectedFile(path string, allowedMode os.FileMode, limit int64) ([]byte, error) {
	file, err := openProtectedFile(path, os.O_RDONLY, allowedMode)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, errors.New("protected file exceeds size limit")
	}
	return payload, nil
}

func openProtectedFile(path string, flags int, allowedMode os.FileMode) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("wrap protected file descriptor")
	}
	if err := validateOpenedProtectedFile(file, allowedMode); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func validateOpenedProtectedFile(file *os.File, allowedMode os.FileMode) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("protected path must be a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot validate protected file metadata")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("protected file must be owned by the current user")
	}
	if uint64(stat.Nlink) != 1 {
		return errors.New("protected file must have exactly one hard link")
	}
	if info.Mode().Perm()&^allowedMode.Perm() != 0 {
		return fmt.Errorf("protected file permissions %04o are broader than %04o", info.Mode().Perm(), allowedMode.Perm())
	}
	return nil
}
