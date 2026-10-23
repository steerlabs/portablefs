//go:build !linux

package cli

import "errors"

func (e *cmdEnv) runWorkspaceMount(*mountOpts, string, string) int {
	return e.fail("mount", errors.New("workspace mounts require Linux"))
}

func (e *cmdEnv) runWorkspaceReconcile(int, string, string) int {
	return e.fail("mount", errors.New("workspace reconciliation requires Linux"))
}
