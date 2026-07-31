//go:build darwin

package portablefsd

import "golang.org/x/sys/unix"

func renameSocketNoReplace(fromDirFD int, from string, toDirFD int, to string) error {
	return unix.RenameatxNp(fromDirFD, from, toDirFD, to, unix.RENAME_EXCL)
}
