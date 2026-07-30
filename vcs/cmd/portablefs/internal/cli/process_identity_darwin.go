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
	start := info.Proc.P_starttime
	return fmt.Sprintf("%d:%d", start.Sec, start.Usec), nil
}
