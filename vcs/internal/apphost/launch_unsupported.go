//go:build !darwin || !cgo

package apphost

import (
	"fmt"
	"runtime"
)

func launchExactApp(string) error {
	return fmt.Errorf("native exact-app launch is unavailable in this %s build", runtime.GOOS)
}
