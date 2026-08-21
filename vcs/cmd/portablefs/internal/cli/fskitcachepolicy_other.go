//go:build !darwin

package cli

import (
	"fmt"
	"runtime"
)

func currentFSKitCachePolicy() (string, error) {
	return "", fmt.Errorf("FSKit cache policy selection is unsupported on %s", runtime.GOOS)
}
