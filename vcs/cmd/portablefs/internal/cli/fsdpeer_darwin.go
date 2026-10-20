//go:build darwin

package cli

import (
	"fmt"
	"net"

	"github.com/steerlabs/portablefs/vcs/internal/hostctl"
)

func authenticateFSDPeer(conn net.Conn, expectedPath, expectedCDHash string) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("daemon control connection is not a Unix stream")
	}
	return hostctl.AuthenticateSocketPeer(unixConn, expectedPath, expectedCDHash)
}
