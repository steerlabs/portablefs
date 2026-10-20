//go:build darwin

package cli

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func processStartIdentity(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid pid %d", pid)
	}
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return "", err
	}
	const szomb = 5 // SZOMB in <sys/proc.h>: awaiting collection by the parent.
	if info.Proc.P_stat == szomb {
		return "", unix.ESRCH
	}
	start := info.Proc.P_starttime
	return fmt.Sprintf("%d:%d", start.Sec, start.Usec), nil
}
