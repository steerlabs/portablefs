//go:build !darwin && !linux

package portablefsd

import "fmt"

func processStartIdentity(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid pid %d", pid)
	}
	// An identity that cannot be proven must not be silently synthesized: it
	// would make every recycled pid look like the original lock holder.
	return "", errProcessStateUnsupported
}

func inspectProcessState(pid int) (processState, error) {
	if pid <= 0 {
		return processState{}, fmt.Errorf("invalid pid %d", pid)
	}
	return processState{}, errProcessStateUnsupported
}
