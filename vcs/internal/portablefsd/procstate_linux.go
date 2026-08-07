//go:build linux

package portablefsd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func processStartIdentity(pid int) (string, error) {
	state, err := inspectProcessState(pid)
	if err != nil {
		return "", err
	}
	return state.startIdentity, nil
}

// inspectProcessState reads /proc/<pid>/stat. Field 3 is the run state and
// field 22 is the process start time in clock ticks since boot — the value that
// makes a recycled pid distinguishable from the original holder.
//
// States Z (zombie) and X (dead) both mean do_exit() has run to the point where
// the process can no longer execute user code, which is the Linux twin of
// macOS's P_WEXIT.
func inspectProcessState(pid int) (processState, error) {
	if pid <= 0 {
		return processState{}, fmt.Errorf("invalid pid %d", pid)
	}
	body, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		if os.IsNotExist(err) {
			return processState{}, errNoSuchProcess
		}
		return processState{}, err
	}
	text := string(body)
	// comm is parenthesized and may contain spaces; everything after the last
	// ')' is positionally stable.
	close := strings.LastIndex(text, ")")
	if close < 0 || close+2 >= len(text) {
		return processState{}, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(text[close+2:])
	// fields[0] is field 3 (state); field 22 is fields[19].
	if len(fields) < 20 {
		return processState{}, fmt.Errorf("truncated /proc/%d/stat", pid)
	}
	return processState{
		startIdentity: fields[19],
		exiting:       fields[0] == "Z" || fields[0] == "X" || fields[0] == "x",
	}, nil
}
