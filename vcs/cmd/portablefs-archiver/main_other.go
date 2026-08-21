//go:build !linux

package main

import (
	"fmt"
	"os"
)

// The archiver is a Linux cell component: it depends on openat2 confinement,
// SEEK_DATA sparseness, and a systemd unit that binds the volume tree read
// only. The package it drives builds elsewhere so its suite can run there; the
// command refuses, so nothing can half-run an archive on a host that cannot
// honour the contract.
func main() {
	_, _ = fmt.Fprintln(os.Stderr, "portablefs-archiver: supported only on Linux")
	os.Exit(1)
}
