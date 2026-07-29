//go:build !unix

package cli

func syncConfigDirectory(string) error {
	return nil
}
