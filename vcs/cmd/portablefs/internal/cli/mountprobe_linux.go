//go:build linux

package cli

import (
	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"github.com/steerlabs/portablefs/vcs/internal/mounthost"
)

// probeMountTransport completes a real FUSE INIT handshake on a private
// throwaway mount. See fusev3.ProbeKernelFUSE for exactly what that proves.
func probeMountTransport(transport mounthost.Transport) (any, error) {
	if transport != mounthost.FUSE {
		return nil, errUnprobableTransport(transport)
	}
	probe, err := fusev3.ProbeKernelFUSE()
	if err != nil {
		return nil, err
	}
	return probe, nil
}
