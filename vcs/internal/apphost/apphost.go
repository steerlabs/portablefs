// Package apphost launches the exact macOS host app that contains the running
// PortableFS CLI. It never performs a bundle-identifier lookup: a different
// installed build must not satisfy the daemon-wake boundary.
package apphost

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrLaunchCompletionAmbiguous means the exact NSWorkspace request was issued,
// but its asynchronous completion callback did not arrive before the bounded
// wait elapsed. Callers must not treat it as success. They may continue only to
// an exact authenticated host or daemon proof for the requested app release.
var ErrLaunchCompletionAmbiguous = errors.New("exact app launch completion is ambiguous")

// LaunchCompletionAmbiguousError preserves the native timeout while supporting
// errors.Is(err, ErrLaunchCompletionAmbiguous) at policy boundaries.
type LaunchCompletionAmbiguousError struct {
	Cause error
}

func (e *LaunchCompletionAmbiguousError) Error() string {
	return fmt.Sprintf("%v: %v", ErrLaunchCompletionAmbiguous, e.Cause)
}

func (e *LaunchCompletionAmbiguousError) Unwrap() error { return e.Cause }

func (e *LaunchCompletionAmbiguousError) Is(target error) bool {
	return target == ErrLaunchCompletionAmbiguous
}

// LaunchContainingApp asks the platform to launch (or reuse) the exact app
// bundle containing executable. The executable must be the embedded
// Contents/Helpers/portablefs helper from that bundle.
func LaunchContainingApp(executable string) error {
	app, err := containingApp(executable)
	if err != nil {
		return err
	}
	if err := launchExactApp(app); err != nil {
		return fmt.Errorf("launch exact PortableFS host %s: %w", app, err)
	}
	return nil
}

// LaunchExactApp launches one already-resolved app bundle path. Installers use
// this to wake the currently installed host before replacement and the newly
// published host after replacement; neither case can be derived from the
// source installer's containing bundle.
func LaunchExactApp(app string) error {
	if !filepath.IsAbs(app) || filepath.Clean(app) != app ||
		!strings.HasSuffix(filepath.Base(app), ".app") {
		return fmt.Errorf("PortableFS host is not an absolute clean app path: %q", app)
	}
	info, err := os.Lstat(app)
	if err != nil {
		return fmt.Errorf("inspect exact PortableFS host %s: %w", app, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("exact PortableFS host is not a real app directory: %s", app)
	}
	if err := launchExactApp(app); err != nil {
		return fmt.Errorf("launch exact PortableFS host %s: %w", app, err)
	}
	return nil
}

func containingApp(executable string) (string, error) {
	if executable == "" {
		return "", fmt.Errorf("PortableFS executable path is empty")
	}
	real, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("resolve PortableFS executable %s: %w", executable, err)
	}
	if !filepath.IsAbs(real) || filepath.Clean(real) != real {
		return "", fmt.Errorf("resolved PortableFS executable is not an absolute clean path: %q", real)
	}
	executableInfo, err := os.Lstat(real)
	if err != nil {
		return "", fmt.Errorf("inspect PortableFS executable %s: %w", real, err)
	}
	if executableInfo.Mode()&os.ModeSymlink != 0 ||
		!executableInfo.Mode().IsRegular() ||
		executableInfo.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("PortableFS executable is not a real executable file: %s", real)
	}
	if filepath.Base(real) != "portablefs" || filepath.Base(filepath.Dir(real)) != "Helpers" {
		return "", fmt.Errorf("PortableFS executable is not an embedded Contents/Helpers/portablefs: %s", real)
	}
	contents := filepath.Dir(filepath.Dir(real))
	if filepath.Base(contents) != "Contents" {
		return "", fmt.Errorf("PortableFS executable has no exact Contents ancestor: %s", real)
	}
	app := filepath.Dir(contents)
	if !strings.HasSuffix(filepath.Base(app), ".app") {
		return "", fmt.Errorf("PortableFS executable is not contained by an app bundle: %s", real)
	}
	info, err := os.Lstat(app)
	if err != nil {
		return "", fmt.Errorf("inspect containing app %s: %w", app, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("containing app is not a real directory: %s", app)
	}
	return app, nil
}
