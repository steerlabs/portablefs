//go:build !darwin

package cli

func verifyFSKitMountIdentity(_, _, _ string) error {
	return nil
}
