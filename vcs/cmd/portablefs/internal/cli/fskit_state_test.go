package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectLegacyPortablefsdState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "portablefsd")
	if err := rejectLegacyPortablefsdStateAt(path); err != nil {
		t.Fatalf("absent state: %v", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rejectLegacyPortablefsdStateAt(path); err != nil {
		t.Fatalf("empty legacy dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "registry.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := rejectLegacyPortablefsdStateAt(path)
	if err == nil || !strings.Contains(err.Error(), "installer state migration") ||
		!strings.Contains(err.Error(), "will not copy, merge, or delete") {
		t.Fatalf("legacy state error = %v", err)
	}
}

func TestRejectLegacyPortablefsdStateRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "portablefsd")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := rejectLegacyPortablefsdStateAt(path); err == nil {
		t.Fatal("legacy symlink was accepted")
	}
}
