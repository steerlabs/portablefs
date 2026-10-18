//go:build !darwin

package cli

import (
	"fmt"
	"net"
)

func authenticateFSDPeer(net.Conn, string) error {
	return fmt.Errorf("authenticated FSKit daemon control requires macOS")
}
