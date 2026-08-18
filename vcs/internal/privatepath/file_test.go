package privatepath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(dir, "state.json")
	if err := WriteFileAtomic(path, []byte("one\n")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("two\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "two\n" {
		t.Fatalf("data = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o", info.Mode().Perm())
	}
}

func TestWriteFileAtomicRejectsLooseOrSymlinkTarget(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(loose, []byte("y")); err == nil {
		t.Fatal("loose target accepted")
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(link, []byte("y")); err == nil {
		t.Fatal("symlink target accepted")
	}
}

func TestRemoveFileDurable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "state")
	if err := WriteFileAtomic(path, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := RemoveFileDurable(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("removed file still exists: %v", err)
	}
	if err := RemoveFileDurable(path); err != nil {
		t.Fatalf("missing removal: %v", err)
	}
}

func TestTruncatedLogRemainsAppendOnlyAcrossIndependentWriters(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "mount.log")
	first, err := OpenFileTruncate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenFileAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := second.WriteString("daemon\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.WriteString("supervisor\n"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "daemon\nsupervisor\n" {
		t.Fatalf("append-only log = %q", body)
	}
}
