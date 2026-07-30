//go:build !darwin && !linux

package cli

import (
	"fmt"
	"syscall"
)

func signalMountProcessExact(st *mountState, _ syscall.Signal) error {
	return fmt.Errorf("exact mount process signaling is unsupported for pid %d on this platform", st.PID)
}
