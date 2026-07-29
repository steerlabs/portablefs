//go:build !unix

package cli

import "os"

// Windows ACL ownership is enforced by the user's private profile directory;
// the portable checks still reject symlinks and non-regular config paths.
// FileMode permission bits are synthetic on Windows, so applying Unix 0600
// and 0700 assertions there would reject ordinary user-owned files.
func verifyConfigFilePermissions(string, os.FileInfo) error {
	return nil
}

func verifyConfigDirectoryPermissions(string, os.FileInfo, bool) error {
	return nil
}

func secureTemporaryConfigFile(string, *os.File) error {
	return nil
}
