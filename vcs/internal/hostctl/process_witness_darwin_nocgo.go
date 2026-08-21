//go:build darwin && !cgo

package hostctl

import "fmt"

// ProcessWitness is unavailable without the native audit-token boundary. The
// shape remains present so Darwin cross-compilation succeeds, but every attempt
// to use it fails closed before an update session can be admitted.
type ProcessWitness struct {
	PID            int
	PIDVersion     int
	ExecutablePath string
	auditToken     [8]uint32
}

func captureSocketPeerProcessWitness(int) (ProcessWitness, uint32, error) {
	return ProcessWitness{}, 0, fmt.Errorf("Darwin host process witnesses require cgo")
}

func (ProcessWitness) RequireCurrentExecutable(string) error {
	return fmt.Errorf("Darwin host process witnesses require cgo")
}
