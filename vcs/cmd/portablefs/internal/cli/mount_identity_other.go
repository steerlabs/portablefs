//go:build !linux

package cli

import "fmt"

func captureFUSEKernelMountID(_, _ string) (string, error) {
	return "", fmt.Errorf("exact FUSE kernel mount identity is supported only on Linux")
}
