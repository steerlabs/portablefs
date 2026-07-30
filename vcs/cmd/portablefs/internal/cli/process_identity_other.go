//go:build !darwin && !linux

package cli

import "fmt"

func processStartIdentity(pid int) (string, error) {
	return "", fmt.Errorf("process start identity is unsupported for pid %d on this platform", pid)
}
