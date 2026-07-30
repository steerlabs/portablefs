//go:build darwin

package cli

import (
	"fmt"
	"syscall"
)

// FSKit wrappers are never signaled by pid. The external unmount path removes
// the exact kernel mount/attach and the wrapper observes that disappearance.
func signalMountProcessExact(st *mountState, _ syscall.Signal) error {
	return fmt.Errorf("direct pid signaling is disabled for FSKit mount process %d", st.PID)
}
