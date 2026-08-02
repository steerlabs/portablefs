package workfs

import (
	"os"
	"testing"
)

func overwrite(t *testing.T, fs *FS, name, data string) {
	t.Helper()
	f, err := fs.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	if _, err := f.Write([]byte(data)); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", name, err)
	}
}
