package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateMountTarget(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "mounts")
	t.Run("new path", func(t *testing.T) {
		if err := validateMountTarget(stateDir, filepath.Join(t.TempDir(), "new")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("empty directory", func(t *testing.T) {
		if err := validateMountTarget(stateDir, t.TempDir()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("root", func(t *testing.T) {
		if err := validateMountTarget(stateDir, "/"); err == nil {
			t.Fatal("root accepted")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := validateMountTarget(stateDir, link); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("nonempty", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "important"), []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := validateMountTarget(stateDir, dir); err == nil || !strings.Contains(err.Error(), "not empty") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("writable ancestor", func(t *testing.T) {
		root := t.TempDir()
		ancestor := filepath.Join(root, "writable")
		if err := os.Mkdir(ancestor, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(ancestor, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := validateMountTarget(stateDir, filepath.Join(ancestor, "mount")); err == nil ||
			!strings.Contains(err.Error(), "group/world-writable") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("writable final directory", func(t *testing.T) {
		target := t.TempDir()
		if err := os.Chmod(target, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := validateMountTarget(stateDir, target); err == nil ||
			!strings.Contains(err.Error(), "group/world-writable") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestPinnedMountTargetRejectsReplacement(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "mounts")
	target := filepath.Join(t.TempDir(), "mount")
	pinned, identity, err := openValidatedMountTarget(stateDir, target)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	displaced := target + ".old"
	if err := os.Rename(target, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := revalidatePinnedMountTarget(target, identity); err == nil ||
		!strings.Contains(err.Error(), "changed before mount") {
		t.Fatalf("replacement error = %v", err)
	}
}

func TestMountPathsOverlap(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"/work", "/work", true},
		{"/work", "/work/sub", true},
		{"/work/sub", "/work", true},
		{"/work", "/workspace", false},
		{"/a", "/b", false},
	}
	for _, tc := range tests {
		if got := mountPathsOverlap(tc.a, tc.b); got != tc.want {
			t.Fatalf("mountPathsOverlap(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}

func TestKernelMountBoundaryPreflight(t *testing.T) {
	t.Run("exact mountpoint", func(t *testing.T) {
		err := validateKernelMountTargetAgainst("/work/mount", []kernelMountBoundary{{
			path: "/work/mount", fsType: "ext4", source: "/dev/test",
		}})
		if err == nil || !strings.Contains(err.Error(), "already a kernel mountpoint") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("would cover child mount", func(t *testing.T) {
		err := validateKernelMountTargetAgainst("/work", []kernelMountBoundary{{
			path: "/work/sub/mount", fsType: "tmpfs", source: "tmpfs",
		}})
		if err == nil || !strings.Contains(err.Error(), "cover child kernel mount") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unrecorded portablefs ancestor", func(t *testing.T) {
		err := validateKernelMountTargetAgainst("/work/pfs/nested", []kernelMountBoundary{{
			path: "/work/pfs", fsType: "fuse.portablefs", source: "portablefs:mnt_AAAAAAAAAAAAAAAAAAAAAA", portableFS: true,
		}})
		if err == nil || !strings.Contains(err.Error(), "nested under PortableFS") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("ordinary ancestor mount allowed", func(t *testing.T) {
		err := validateKernelMountTargetAgainst("/work/project/mount", []kernelMountBoundary{
			{path: "/", fsType: "ext4", source: "/dev/root"},
			{path: "/work", fsType: "ext4", source: "/dev/work"},
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestCanonicalMountPathResolvesAncestors(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	got, err := canonicalMountPath(filepath.Join(link, "new", "mount"))
	if err != nil {
		t.Fatal(err)
	}
	resolvedReal, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(resolvedReal, "new", "mount")
	if got != want {
		t.Fatalf("canonical path = %q, want %q", got, want)
	}
	if _, err := canonicalMountPath(link); err == nil {
		t.Fatal("terminal symlink accepted")
	}
}
