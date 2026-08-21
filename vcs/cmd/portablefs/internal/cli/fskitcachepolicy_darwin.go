//go:build darwin

package cli

import (
	"fmt"
	"syscall"
)

func currentFSKitCachePolicy() (string, error) {
	productVersion, err := syscall.Sysctl("kern.osproductversion")
	if err != nil {
		return "", fmt.Errorf("read kern.osproductversion: %w", err)
	}
	return fskitCachePolicyForProductVersion(
		productVersion,
		nativeFSKitPolicyQualification,
	)
}
