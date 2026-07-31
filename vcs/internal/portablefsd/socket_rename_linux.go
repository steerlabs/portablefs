//go:build linux

package portablefsd

import "golang.org/x/sys/unix"

func renameSocketNoReplace(fromDirFD int, from string, toDirFD int, to string) error {
	return unix.Renameat2(fromDirFD, from, toDirFD, to, unix.RENAME_NOREPLACE)
}
