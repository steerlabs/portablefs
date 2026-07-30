//go:build !darwin && !linux

package cli

import "fmt"

func verifyFSKitMountIdentity(_, _, _ string) error {
	return nil
}

func verifyRecordedMountIdentity(st *mountState) error {
	return fmt.Errorf("recorded mount strategy %q is unsupported on this platform", st.Strategy)
}
