//go:build !darwin

package cli

import "fmt"

func newFSKitMountWatcher() (fsKitMountWatcher, error) {
	return nil, fmt.Errorf("kernel FSKit mount notification requires macOS")
}
