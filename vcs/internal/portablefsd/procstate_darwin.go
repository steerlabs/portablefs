//go:build darwin

package portablefsd

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// P_WEXIT is sys/proc.h's "process is working on exiting" flag. It is set by
// exit1() before the task is torn down and is exactly what `ps` reports as the
// `E` state — the state the unkillable daemon sat in for 44 minutes. A process
// carrying it has already left user space for the last time.
const darwinPWExit = 0x00002000

// SZOMB is sys/proc.h's zombie state: exit is complete and only the exit status
// remains. Also decisive.
const darwinSZomb = 5

func processStartIdentity(pid int) (string, error) {
	state, err := inspectProcessState(pid)
	if err != nil {
		return "", err
	}
	return state.startIdentity, nil
}

func inspectProcessState(pid int) (processState, error) {
	if pid <= 0 {
		return processState{}, fmt.Errorf("invalid pid %d", pid)
	}
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.EINVAL) {
			return processState{}, errNoSuchProcess
		}
		return processState{}, err
	}
	if info == nil || info.Proc.P_pid != int32(pid) {
		// kern.proc.pid answers with an empty record rather than ESRCH for a
		// pid that no longer exists.
		return processState{}, errNoSuchProcess
	}
	start := info.Proc.P_starttime
	return processState{
		startIdentity: fmt.Sprintf("%d:%d", start.Sec, start.Usec),
		exiting:       info.Proc.P_flag&darwinPWExit != 0 || info.Proc.P_stat == darwinSZomb,
	}, nil
}
