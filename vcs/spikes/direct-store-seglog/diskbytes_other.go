//go:build (!darwin && !linux) || (darwin && !cgo)

package main

import "fmt"

func diskBytesWritten() (uint64, error) {
	return 0, fmt.Errorf("kernel disk-write accounting is unsupported on this platform")
}
