//go:build linux

package cellhost

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRemoveTreeRemovesSymlinksWithoutFollowingThem is the confinement test.
// The volume tree is written by the volume's own service user, so it can
// contain a symlink to anywhere on the cell. unlinkat removes the link; a
// path-string recursion, or an opendir that followed, would remove somebody
// else's data instead.
func TestRemoveTreeRemovesSymlinksWithoutFollowingThem(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	outsideFile := filepath.Join(outside, "keep.txt")
	writeTestFile(t, outsideFile, "must survive")
	writeTestFile(t, filepath.Join(root, "tree", "sub", "payload"), "volume data")
	if err := os.Symlink(outside, filepath.Join(root, "tree", "escape-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(root, "tree", "sub", "escape-file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent", filepath.Join(root, "tree", "dangling")); err != nil {
		t.Fatal(err)
	}
	if err := removeTreeBeneath(root, "tree"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "tree")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tree survived removal: %v", err)
	}
	if _, err := os.Stat(outsideFile); err != nil {
		t.Fatalf("the remover followed a symlink out of the tree: %v", err)
	}
}

// A symlink where a directory is expected is removed as the symlink it is: a
// planted link at the volume's own name must never redirect the removal.
func TestRemoveTreeRemovesASymlinkedEntryItself(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	writeTestFile(t, filepath.Join(outside, "keep.txt"), "must survive")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, testVolumeID)); err != nil {
		t.Fatal(err)
	}
	if err := removeTreeBeneath(root, testVolumeID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, testVolumeID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("planted symlink survived: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep.txt")); err != nil {
		t.Fatalf("the remover followed the planted symlink: %v", err)
	}
}

func TestRemoveTreeIsIdempotentAndBoundedToOneComponent(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := removeTreeBeneath(root, testVolumeID); err != nil {
		t.Fatalf("removing an absent entry is not satisfied: %v", err)
	}
	if err := removeTreeBeneath(filepath.Join(base, "no-such-root"), testVolumeID); err != nil {
		t.Fatalf("removing beneath an absent root is not satisfied: %v", err)
	}
	for _, name := range []string{"", ".", "..", "sub/entry", "/etc", "../escape", "weird name"} {
		if err := removeTreeBeneath(root, name); !errors.Is(err, ErrInvalid) {
			t.Fatalf("removeTreeBeneath(root, %q) = %v, want ErrInvalid", name, err)
		}
	}
	for _, unsafe := range []string{"relative/root", "/root/../escape", ""} {
		if err := removeTreeBeneath(unsafe, testVolumeID); !errors.Is(err, ErrInvalid) {
			t.Fatalf("removeTreeBeneath(%q, volume) = %v, want ErrInvalid", unsafe, err)
		}
	}
}

// A directory with far more entries than one getdents batch exercises the
// rescan loop: the walk must make progress on every pass and terminate.
func TestRemoveTreeEmptiesDirectoriesLargerThanOneBatch(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	wide := filepath.Join(root, "tree", "wide")
	if err := os.MkdirAll(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2000; index++ {
		writeTestFile(t, filepath.Join(wide, fmt.Sprintf("entry-%04d", index)), "x")
	}
	for index := 0; index < 8; index++ {
		writeTestFile(t, filepath.Join(wide, fmt.Sprintf("dir-%d", index), "leaf"), "x")
	}
	if err := removeTreeBeneath(root, "tree"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "tree")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wide tree survived removal: %v", err)
	}
}

// The depth bound is a fail-closed guard, not a best effort: past it the
// remover reports an error instead of recursing without limit or exhausting
// descriptors, and the postcondition check then refuses the destroy.
func TestRemoveTreeRefusesToDescendPastTheDepthBound(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	deep := filepath.Join(root, "tree")
	for index := 0; index < maxRemoveDepth+8; index++ {
		deep = filepath.Join(deep, "d")
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	err := removeTreeBeneath(root, "tree")
	if err == nil || !strings.Contains(err.Error(), "directory levels") {
		t.Fatalf("removeTreeBeneath on an over-deep tree = %v, want a depth refusal", err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "tree")); statErr != nil {
		t.Fatalf("a refused removal still removed the tree root: %v", statErr)
	}
}

func TestAbsentBeneathAnswersFromAFreshLstat(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	writeTestFile(t, filepath.Join(root, testVolumeID, "file"), "x")
	absent, err := absentBeneath(root, testVolumeID)
	if err != nil || absent {
		t.Fatalf("absentBeneath on a present directory = %v, %v", absent, err)
	}
	if err := removeTreeBeneath(root, testVolumeID); err != nil {
		t.Fatal(err)
	}
	absent, err = absentBeneath(root, testVolumeID)
	if err != nil || !absent {
		t.Fatalf("absentBeneath after removal = %v, %v", absent, err)
	}
	// A dangling symlink is present, not absent: something still occupies the
	// name, and the placement is not clean.
	if err := os.Symlink("/nonexistent", filepath.Join(root, testVolumeID)); err != nil {
		t.Fatal(err)
	}
	if absent, err := absentBeneath(root, testVolumeID); err != nil || absent {
		t.Fatalf("absentBeneath on a dangling symlink = %v, %v", absent, err)
	}
}
