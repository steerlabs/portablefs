//go:build !darwin

package cli

import "fmt"

func (e *cmdEnv) verifyWorkspaceBundle(app string) int {
	return e.fail("lifecycle", fmt.Errorf("workspace bundles require macOS"))
}

func (e *cmdEnv) verifyMacOSReleaseBundle(app string) int { return e.verifyWorkspaceBundle(app) }
