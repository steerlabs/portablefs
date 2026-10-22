//go:build linux

package fusev3

import "runtime"

func runtimeStack(buf []byte) int { return runtime.Stack(buf, true) }
