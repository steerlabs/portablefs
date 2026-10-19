package privatepath

import "golang.org/x/sys/unix"

func renameNoReplace(fromDir int, from string, toDir int, to string) error {
	return unix.RenameatxNp(fromDir, from, toDir, to, unix.RENAME_EXCL)
}
