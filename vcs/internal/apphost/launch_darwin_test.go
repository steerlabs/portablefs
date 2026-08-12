//go:build darwin && cgo

package apphost

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/darwinnative"
)

func TestLaunchExactAppExposesNativeCompletionAmbiguity(t *testing.T) {
	app := filepath.Join(t.TempDir(), "PortableFS.app")
	if err := os.Mkdir(app, 0o700); err != nil {
		t.Fatal(err)
	}
	original := requestNativeExactApp
	t.Cleanup(func() { requestNativeExactApp = original })
	requestNativeExactApp = func(got string) error {
		if got != app {
			t.Fatalf("launch path = %q, want %q", got, app)
		}
		return &darwinnative.AppLaunchCompletionTimeoutError{}
	}
	err := LaunchExactApp(app)
	if !errors.Is(err, ErrLaunchCompletionAmbiguous) {
		t.Fatalf("launch error = %v", err)
	}
	var ambiguous *LaunchCompletionAmbiguousError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("launch error type = %T", err)
	}
	var timeout *darwinnative.AppLaunchCompletionTimeoutError
	if !errors.As(err, &timeout) {
		t.Fatalf("native timeout was not preserved: %v", err)
	}
}

func TestLaunchExactAppRefusesANonMainThreadBeforeRequest(t *testing.T) {
	app := filepath.Join(t.TempDir(), "PortableFS.app")
	if err := os.Mkdir(app, 0o700); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		result <- LaunchExactApp(app)
	}()
	err := <-result
	var wrongThread *darwinnative.AppLaunchWrongThreadError
	if !errors.As(err, &wrongThread) || errors.Is(err, ErrLaunchCompletionAmbiguous) {
		t.Fatalf("non-main-thread launch = %T %v", err, err)
	}
}

func TestLaunchExactAppDoesNotMisclassifyNativeRejection(t *testing.T) {
	app := filepath.Join(t.TempDir(), "PortableFS.app")
	if err := os.Mkdir(app, 0o700); err != nil {
		t.Fatal(err)
	}
	original := requestNativeExactApp
	t.Cleanup(func() { requestNativeExactApp = original })
	rejected := errors.New("request rejected")
	requestNativeExactApp = func(string) error { return rejected }
	err := LaunchExactApp(app)
	if !errors.Is(err, rejected) || errors.Is(err, ErrLaunchCompletionAmbiguous) {
		t.Fatalf("launch error = %v", err)
	}
}
