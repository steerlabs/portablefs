//go:build !darwin && !linux

package portablefsd

import "golang.org/x/sys/unix"

func renameSocketNoReplace(int, string, int, string) error {
	return unix.ENOTSUP
}
