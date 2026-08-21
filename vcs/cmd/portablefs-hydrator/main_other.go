//go:build !linux

package main

import (
	"fmt"
	"os"
)

// The hydrator is a Linux cell component: it depends on openat2 confinement,
// name_to_handle_at inode identity, and a systemd unit that binds the volume
// state directory. The package it drives builds elsewhere so its suite can run
// there; the command refuses, so nothing can half-restore a volume on a host
// that cannot honour the contract.
func main() {
	_, _ = fmt.Fprintln(os.Stderr, "portablefs-hydrator: supported only on Linux")
	os.Exit(1)
}
