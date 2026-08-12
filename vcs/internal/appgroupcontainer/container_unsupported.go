//go:build !darwin || !cgo

package appgroupcontainer

import (
	"fmt"
	"runtime"
)

func resolveNative(identifier string) (string, error) {
	return "", fmt.Errorf(
		"resolve app-group container %q: the documented Foundation resolver is unavailable in this %s build",
		identifier,
		runtime.GOOS,
	)
}
