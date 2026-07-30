//go:build !linux

package cli

import "fmt"

func recoverFUSEMountingIdentity(mountPath, mountInstanceID string) (string, bool, error) {
	return "", false, fmt.Errorf("FUSE mounting-intent recovery is unavailable on this platform")
}
