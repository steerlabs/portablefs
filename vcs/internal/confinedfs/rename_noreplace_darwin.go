//go:build darwin

package confinedfs

import "golang.org/x/sys/unix"

func platformRenameNoReplace(oldDir int, oldName string, newDir int, newName string) error {
	return unix.RenameatxNp(oldDir, oldName, newDir, newName, unix.RENAME_EXCL)
}
