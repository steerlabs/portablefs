//go:build !linux && !darwin

package powerloss

import (
	"io/fs"
	"os"
)

// rawStatOf reports no raw attributes here, so a mutation cut verified on such
// a platform fails on every mode, link-count and atime expectation instead of
// silently skipping them.
func rawStatOf(fs.FileInfo) (rawAttributes, bool) { return rawAttributes{}, false }

func openNoAtime(name string) (*os.File, error) { return os.Open(name) }
