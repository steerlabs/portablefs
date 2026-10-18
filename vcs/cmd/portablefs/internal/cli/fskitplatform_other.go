//go:build !darwin

package cli

import (
	"fmt"
	"runtime"
)

func requireSupportedFSKit() error {
	return fmt.Errorf("FSKit cache policy selection is unsupported on %s", runtime.GOOS)
}
