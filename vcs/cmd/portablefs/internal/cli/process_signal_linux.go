//go:build linux

package cli

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// signalMountProcessExact opens an immutable process handle before checking
// the recorded start identity. The signal therefore cannot cross a PID reuse
// boundary between verification and delivery.
func signalMountProcessExact(st *mountState, signal syscall.Signal) error {
	fd, err := unix.PidfdOpen(st.PID, 0)
	if err != nil {
		return fmt.Errorf("open pidfd for mount process %d: %w", st.PID, err)
	}
	defer unix.Close(fd)
	identity, err := processStartIdentity(st.PID)
	if err != nil || identity != st.ProcessStartIdentity {
		return fmt.Errorf("refusing to signal pid %d: its process start identity does not match the mount record", st.PID)
	}
	if err := unix.PidfdSendSignal(fd, unix.Signal(signal), nil, 0); err != nil {
		return fmt.Errorf("signal mount process pid %d through pidfd: %w", st.PID, err)
	}
	return nil
}
