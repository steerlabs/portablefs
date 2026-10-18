//go:build darwin

package cli

import (
	"fmt"
	"github.com/steerlabs/portablefs/vcs/internal/hostctl"
	"net"
)

func authenticateFSDPeer(conn net.Conn, expectedSHA256 string) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("daemon control connection is not a Unix stream")
	}
	return hostctl.AuthenticateSocketPeer(unixConn, expectedSHA256)
}
