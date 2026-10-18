//go:build darwin

package portablefsd

import (
	"net"

	"golang.org/x/sys/unix"
)

func frontendPeerPID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid int
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		pid, credentialErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return 0, err
	}
	return pid, credentialErr
}
