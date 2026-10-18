package daemonctl

import (
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryAbsenceInspectsEveryExistingKindWithoutReading(t *testing.T) {
	for _, kind := range []string{"absent", "zero bytes", "malformed", "unknown format", "current empty", "dangling symlink", "directory", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(registryTestRoot(t), "state")
			parent, err := privatepath.OpenDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			path := filepath.Join(dir, PersistedAttachesFilename)
			switch kind {
			case "zero bytes":
				err = os.WriteFile(path, nil, 0600)
			case "malformed":
				err = os.WriteFile(path, []byte("not-json"), 0600)
			case "unknown format":
				err = os.WriteFile(path, []byte(`{"private_format":99,"records":[]}`), 0600)
			case "current empty":
				err = os.WriteFile(path, []byte(`{"version":3,"attaches":[]}`), 0600)
			case "dangling symlink":
				err = os.Symlink(filepath.Join(dir, "missing"), path)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "fifo":
				err = unix.Mkfifo(path, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, _ := os.Lstat(path)
			err = RequireRegistryAbsent(parent)
			if (err == nil) != (kind == "absent") {
				t.Fatalf("%s: %v", kind, err)
			}
			if kind != "absent" {
				after, err := os.Lstat(path)
				if err != nil || !os.SameFile(before, after) {
					t.Fatal("inspection changed entry")
				}
			}
		})
	}
	if err := RequireRegistryAbsent(nil); err == nil {
		t.Fatal("missing pinned directory admitted")
	}
	dir := filepath.Join(registryTestRoot(t), "state")
	parent, err := privatepath.OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = parent.Close()
	if err := RequireRegistryAbsent(parent); err == nil {
		t.Fatal("bad descriptor treated as ENOENT")
	}
}

func TestRegistryAbsenceRemainsRelativeToPinnedDirectory(t *testing.T) {
	root := registryTestRoot(t)
	dir := filepath.Join(root, "state")
	parent, err := privatepath.OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := os.WriteFile(filepath.Join(dir, PersistedAttachesFilename), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, filepath.Join(root, "displaced")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := RequireRegistryAbsent(parent); err == nil {
		t.Fatal("path substitution changed the pinned registry witness")
	}
}

func registryTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}
