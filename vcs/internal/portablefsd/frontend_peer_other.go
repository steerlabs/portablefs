//go:build !darwin && !linux

package portablefsd

import (
	"errors"
	"net"
)

func frontendPeerPID(*net.UnixConn) (int, error) {
	return 0, errors.New("portablefsd: frontend kernel peer credentials unavailable")
}
