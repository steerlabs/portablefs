//go:build darwin && cgo

package apphost

import (
	"errors"
	"runtime"

	"github.com/steerlabs/portablefs/vcs/internal/darwinnative"
)

// NSWorkspace requires the process main RunLoop. Package initialization runs
// on the program's startup goroutine, so retaining it on the main thread makes
// the ordinary CLI and LSBackgroundOnly helper entrypoints eligible to drive
// the documented launch boundary. Calls from any other goroutine still fail
// natively before issuing a request.
func init() {
	runtime.LockOSThread()
}

var requestNativeExactApp = darwinnative.LaunchExactApp

func launchExactApp(path string) error {
	err := requestNativeExactApp(path)
	var timeout *darwinnative.AppLaunchCompletionTimeoutError
	if errors.As(err, &timeout) {
		return &LaunchCompletionAmbiguousError{Cause: timeout}
	}
	return err
}
