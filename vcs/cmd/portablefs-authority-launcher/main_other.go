//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "portablefs-authority-launcher is supported only on Linux")
	os.Exit(1)
}
