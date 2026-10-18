//go:build !darwin && !linux

package volumeserver

import (
	"errors"
	"os"
)

func lockMembershipFile(string) (*os.File, error) {
	return nil, errors.New("volumeserver: durable mount membership requires a Unix host")
}
func unlockMembershipFile(file *os.File) error          { return file.Close() }
func openMountMembership(path string) (*os.File, error) { return os.Open(path) }
