//go:build darwin

package cli

import "fmt"

func daemonStopPolicy() error {
	return fmt.Errorf(
		"portablefsd is an always-running ServiceManagement agent on macOS; only the host-owned, zero-mount update transaction may unregister it",
	)
}
