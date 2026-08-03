//go:build darwin || linux

package deployment

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func readDeploymentFile(path string, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("wrap deployment file descriptor")
	}
	defer file.Close()
	if err := validateDeploymentFileFD(fd); err != nil {
		return nil, err
	}
	payload, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, errors.New("deployment metadata exceeds its size boundary")
	}
	return payload, nil
}

func validateDeploymentFileFD(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("deployment metadata must be a regular file")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("deployment metadata must be owned by the current user")
	}
	if uint64(stat.Nlink) != 1 {
		return errors.New("deployment metadata must have exactly one hard link")
	}
	if stat.Mode&0o077 != 0 {
		return errors.New("deployment metadata must be owner-only")
	}
	return nil
}

func removeDeploymentFile(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if err := validateDeploymentFileFD(fd); err != nil {
		unix.Close(fd)
		return err
	}
	if err := unix.Close(fd); err != nil {
		return err
	}
	if err := unix.Unlink(path); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	directoryFD, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open deployment metadata directory: %w", err)
	}
	defer unix.Close(directoryFD)
	if err := unix.Fsync(directoryFD); err != nil {
		return fmt.Errorf("sync deployment metadata directory: %w", err)
	}
	return nil
}

// RemoveConsumedInput deletes one already-validated installer input after a
// successful transaction. The current executable may safely unlink itself on
// Unix after its verified immutable copy has been published.
func RemoveConsumedInput(path string) error {
	if err := validateAbsoluteCanonicalPath(path); err != nil {
		return err
	}
	return removeDeploymentFile(path)
}
