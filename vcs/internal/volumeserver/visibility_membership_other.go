//go:build !darwin && !linux

package volumeserver

import (
	"errors"
	"os"
)

func lockVisibilityFile(string) (*os.File, error) {
	return nil, errors.New("volumeserver: durable visibility membership requires a Unix host")
}
func unlockVisibilityFile(file *os.File) error               { return file.Close() }
func openVisibilityMembership(path string) (*os.File, error) { return os.Open(path) }
