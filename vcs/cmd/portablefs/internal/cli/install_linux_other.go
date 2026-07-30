//go:build !linux

package cli

import "fmt"

func cmdInstallLinuxRelease(e *cmdEnv, _ []string) int {
	return e.fail("install-linux-release", fmt.Errorf("Linux release installation is only available on Linux"))
}
