//go:build !darwin && !linux

package cli

import "fmt"

func kernelMountBoundaries() ([]kernelMountBoundary, error) {
	return nil, fmt.Errorf("kernel mount boundary inventory is unsupported on this platform")
}
