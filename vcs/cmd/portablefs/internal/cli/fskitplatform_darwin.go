//go:build darwin

package cli

import (
	"fmt"
	"syscall"
)

func requireSupportedFSKit() error {
	productVersion, err := syscall.Sysctl("kern.osproductversion")
	if err != nil {
		return fmt.Errorf("read kern.osproductversion: %w", err)
	}
	return validateFSKitProductVersion(productVersion)
}
