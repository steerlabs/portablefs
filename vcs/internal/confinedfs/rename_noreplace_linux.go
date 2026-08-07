//go:build linux

package confinedfs

import "golang.org/x/sys/unix"

func platformRenameNoReplace(oldDir int, oldName string, newDir int, newName string) error {
	return unix.Renameat2(oldDir, oldName, newDir, newName, unix.RENAME_NOREPLACE)
}
