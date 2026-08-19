//go:build !linux

package cli

import "github.com/steerlabs/portablefs/vcs/internal/mounthost"

// probeMountTransport has no implementation off Linux. FSKit installs its
// mount through the system extension, so there is no in-process handshake this
// CLI could complete on its own; a macOS mount is proved by the live matrix.
func probeMountTransport(transport mounthost.Transport) (any, error) {
	return nil, errUnprobableTransport(transport)
}
