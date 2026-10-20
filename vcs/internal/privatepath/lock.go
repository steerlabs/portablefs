package privatepath

import (
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// WithFileLock holds the stable companion .lock inode through fn. Mutable
// private records use EX for publication/removal and SH for open/validate/read.
// SH skips fn when the directory is absent; only that directory lookup may
// report absence here. Lock-open and post-flock validation errors propagate.
// Callers never remove companion locks or acquire operation locks inside fn.
func WithFileLock(recordPath string, operation int, fn func() error) error {
	if operation != unix.LOCK_SH && operation != unix.LOCK_EX {
		return fmt.Errorf("invalid private record lock operation %d", operation)
	}
	dir, _, err := privateFileParts(recordPath)
	if err != nil {
		return err
	}
	openDir := OpenExistingDir
	if operation == unix.LOCK_EX {
		openDir = OpenDir
	}
	parent, err := openDir(dir)
	if operation == unix.LOCK_SH && errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("pin private record directory: %w", err)
	}
	defer parent.Close()
	name := filepath.Base(recordPath) + ".lock"
	file, err := OpenLockFile(parent, dir, name)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := unix.Flock(int(file.Fd()), operation); err != nil {
		return fmt.Errorf("lock private record %s: %w", recordPath, err)
	}
	defer unix.Flock(int(file.Fd()), unix.LOCK_UN)
	if err := validateRecordLock(parent, dir, name, file); err != nil {
		return err
	}
	return fn()
}

// Seam for deterministic post-flock tampering tests.
var validateRecordLock = ValidateOpenFile
