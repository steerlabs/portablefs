//go:build unix

package cli

import (
	"fmt"
	"os"
)

func syncConfigDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open config directory for sync: %w", err)
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("sync config directory: %w", err)
	}
	return nil
}
