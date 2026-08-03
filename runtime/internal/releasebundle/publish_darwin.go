//go:build darwin

package releasebundle

import "golang.org/x/sys/unix"

func publishDirectoryNoReplace(staged, destination string) error {
	return unix.RenamexNp(staged, destination, unix.RENAME_EXCL)
}
