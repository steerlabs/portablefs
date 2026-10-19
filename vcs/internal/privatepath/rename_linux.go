package privatepath

import "golang.org/x/sys/unix"

func renameNoReplace(fromDir int, from string, toDir int, to string) error {
	return unix.Renameat2(fromDir, from, toDir, to, unix.RENAME_NOREPLACE)
}
