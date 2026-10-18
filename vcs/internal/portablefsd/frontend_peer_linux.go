//go:build linux

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
		var credential *unix.Ucred
		credential, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if credentialErr == nil {
			pid = int(credential.Pid)
		}
	}); err != nil {
		return 0, err
	}
	return pid, credentialErr
}
