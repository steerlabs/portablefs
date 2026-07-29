package writeback

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// writeFileAtomicDurable is the single small-file persistence primitive for
// engine identity and recovery metadata: file data reaches storage before
// rename, and the directory entry reaches storage before success.
func writeFileAtomicDurable(path string, body []byte, perm os.FileMode) (err error) {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(perm); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod %s: %w", filepath.Base(tmp), err)
	}
	var n int
	if n, err = f.Write(body); err == nil && n != len(body) {
		err = io.ErrShortWrite
	}
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(tmp), err)
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync %s: %w", filepath.Base(tmp), err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", filepath.Base(tmp), err)
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace %s: %w", filepath.Base(path), err)
	}
	if err = fsyncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync directory for %s: %w", filepath.Base(path), err)
	}
	return nil
}
