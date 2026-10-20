//go:build !darwin

package cli

import (
	"fmt"
	"runtime"
)

func requireSupportedFSKit() error {
	return fmt.Errorf("FSKit is unsupported on %s", runtime.GOOS)
}
