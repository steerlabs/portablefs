//go:build darwin && cgo

// Package darwinnative is the single Objective-C/cgo boundary for PortableFS
// Darwin processes. Policy and path validation remain in the domain packages
// that call it; this package only invokes documented platform APIs.
package darwinnative

/*
#cgo CFLAGS: -fblocks
#cgo LDFLAGS: -framework AppKit -framework Foundation
#include <stdlib.h>

char *portablefs_app_group_container_path(const char *identifier);
int portablefs_launch_exact_host(const char *path, char **error_out);
*/
import "C"

import (
	"fmt"
	"unsafe"
)

const (
	exactAppLaunchCompleted = iota
	exactAppLaunchRejected
	exactAppLaunchCompletionTimedOut
	exactAppLaunchWrongThread
)

// AppLaunchCompletionTimeoutError means NSWorkspace accepted the asynchronous
// open request but its completion handler was not delivered before the bounded
// wait elapsed. It is not success: callers may continue only to an independent
// authenticated proof that the exact requested app became live.
type AppLaunchCompletionTimeoutError struct{}

func (*AppLaunchCompletionTimeoutError) Error() string {
	return "NSWorkspace exact-app launch completion was not delivered within 10 seconds"
}

// AppLaunchWrongThreadError means the request was refused before NSWorkspace
// because AppKit was not being driven from the process main thread. There is
// no ambiguous launch to reconcile in this case.
type AppLaunchWrongThreadError struct{}

func (*AppLaunchWrongThreadError) Error() string {
	return "NSWorkspace exact-app launch requires the process main thread"
}

// ResolveAppGroupContainer invokes FileManager's documented app-group
// resolver. The caller owns identifier validation and returned-path policy.
func ResolveAppGroupContainer(identifier string) (string, error) {
	cIdentifier := C.CString(identifier)
	defer C.free(unsafe.Pointer(cIdentifier))
	cPath := C.portablefs_app_group_container_path(cIdentifier)
	if cPath == nil {
		return "", fmt.Errorf("FileManager returned no authorized container")
	}
	defer C.free(unsafe.Pointer(cPath))
	return C.GoString(cPath), nil
}

// LaunchExactApp invokes NSWorkspace for the supplied app URL. The caller
// owns bundle-layout validation; the native bridge disables application
// substitution and activation.
func LaunchExactApp(path string) error {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))
	var cError *C.char
	status := int(C.portablefs_launch_exact_host(cPath, &cError))
	detail := ""
	if cError != nil {
		detail = C.GoString(cError)
		C.free(unsafe.Pointer(cError))
	}
	return exactAppLaunchStatusError(status, detail)
}

func exactAppLaunchStatusError(status int, detail string) error {
	switch status {
	case exactAppLaunchCompleted:
		if detail != "" {
			return fmt.Errorf("NSWorkspace returned an error for a completed exact-app launch: %s", detail)
		}
		return nil
	case exactAppLaunchRejected:
		if detail == "" {
			detail = "exact-app launch was rejected"
		}
		return fmt.Errorf("NSWorkspace: %s", detail)
	case exactAppLaunchCompletionTimedOut:
		return &AppLaunchCompletionTimeoutError{}
	case exactAppLaunchWrongThread:
		return &AppLaunchWrongThreadError{}
	default:
		return fmt.Errorf("NSWorkspace returned unknown exact-app launch status %d", status)
	}
}
