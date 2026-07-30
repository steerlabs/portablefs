//go:build !darwin

package cli

import (
	"fmt"
	"runtime"
)

func runInstallMacOSApp(_ *cmdEnv, _, _ string) (macOSInstallResult, error) {
	return macOSInstallResult{}, fmt.Errorf("macOS app installation is unsupported on %s", runtime.GOOS)
}
