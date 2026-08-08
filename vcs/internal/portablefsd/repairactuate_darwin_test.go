//go:build darwin

package portablefsd

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func encodedRepairName(name string) string {
	return base64.StdEncoding.EncodeToString([]byte(name))
}

func testEvictionPlan(name, itemKind string) repairActuationPlan {
	return repairActuationPlan{
		Kind:     "evict",
		Name:     encodedRepairName(name),
		ItemKind: itemKind,
		Operand:  encodedRepairName(repairReservedPrefix + "unit"),
	}
}

func openRepairTestRoot(t *testing.T) (string, int) {
	t.Helper()
	root := t.TempDir()
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return root, fd
}

func TestActuateRepairUsesTheItemKindsSingleCorrectRemoval(t *testing.T) {
	root, rootFD := openRepairTestRoot(t)
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "target"), []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(root, "symlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, kind string
	}{
		{"file", repairItemFile},
		{"symlink", repairItemSymlink},
		{"directory", repairItemDirectory},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			if _, err := actuateRepair(rootFD, testEvictionPlan(tc.name, tc.kind)); err != nil {
				t.Fatalf("typed eviction failed: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(root, tc.name)); !os.IsNotExist(err) {
				t.Fatalf("evicted entry still exists: %v", err)
			}
		})
	}
	if data, err := os.ReadFile(filepath.Join(root, "target")); err != nil || string(data) != "target" {
		t.Fatalf("symlink eviction touched its target: data=%q err=%v", data, err)
	}
}

func TestActuateRepairRefusesItemKindMismatchWithoutMutation(t *testing.T) {
	root, rootFD := openRepairTestRoot(t)
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, kind string
	}{
		{"file", repairItemDirectory},
		{"directory", repairItemFile},
		{"file", ""},
		{"file", "device"},
	} {
		t.Run(tc.name+"-as-"+tc.kind, func(t *testing.T) {
			if _, err := actuateRepair(rootFD, testEvictionPlan(tc.name, tc.kind)); err == nil {
				t.Fatal("mismatched eviction unexpectedly succeeded")
			}
			if _, err := os.Lstat(filepath.Join(root, tc.name)); err != nil {
				t.Fatalf("mismatch mutated its target: %v", err)
			}
		})
	}
}

func TestTypedDirectoryEvictionAcceptsAlreadyAbsent(t *testing.T) {
	_, rootFD := openRepairTestRoot(t)
	if _, err := actuateRepair(rootFD, testEvictionPlan("absent", repairItemDirectory)); err != nil {
		t.Fatalf("already-absent directory eviction failed: %v", err)
	}
}

func TestDataInvalidationRefusesDirectoryKindBeforeMutation(t *testing.T) {
	root, rootFD := openRepairTestRoot(t)
	path := filepath.Join(root, "directory")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	plan := testEvictionPlan("directory", repairItemDirectory)
	plan.Kind = "invalidate"
	if _, err := actuateRepair(rootFD, plan); err == nil {
		t.Fatal("directory data invalidation unexpectedly succeeded")
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Fatalf("refused data invalidation mutated directory: info=%v err=%v", info, err)
	}
}

func TestAttributeRefreshRefusesStaleRenameLocatorAndAcceptsAttestedHardLink(t *testing.T) {
	root, rootFD := openRepairTestRoot(t)
	oldPath := filepath.Join(root, "old")
	movedPath := filepath.Join(root, "moved")
	aliasPath := filepath.Join(root, "alias")
	if err := os.WriteFile(oldPath, []byte("data"), 0o640); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(oldPath, &stat); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(oldPath, movedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(movedPath, aliasPath); err != nil {
		t.Fatal(err)
	}

	stale := testEvictionPlan("old", repairItemFile)
	stale.Kind = "refresh"
	stale.ExpectedFileID = stat.Ino
	err := func() error {
		_, err := actuateRepair(rootFD, stale)
		return err
	}()
	if !errors.Is(err, unix.ENOENT) {
		t.Fatalf("stale locator refresh error = %v, want ENOENT", err)
	}
	for _, path := range []string{movedPath, aliasPath} {
		info, statErr := os.Stat(path)
		if statErr != nil || info.Mode().Perm() != 0o640 {
			t.Fatalf("stale refresh mutated %s: info=%v err=%v", path, info, statErr)
		}
	}

	attestedAlias := testEvictionPlan("alias", repairItemFile)
	attestedAlias.Kind = "refresh"
	attestedAlias.ExpectedFileID = stat.Ino
	if _, err := actuateRepair(rootFD, attestedAlias); err != nil {
		t.Fatalf("attested hard-link refresh failed: %v", err)
	}
}

func TestAttributeRefreshAttestsInodePreservesModeAndRefusesSymlink(t *testing.T) {
	root, rootFD := openRepairTestRoot(t)
	path := filepath.Join(root, "file")
	if err := os.WriteFile(path, []byte("data"), 0o640); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		t.Fatal(err)
	}
	plan := testEvictionPlan("file", repairItemFile)
	plan.Kind = "refresh"
	plan.ExpectedFileID = stat.Ino
	if _, err := actuateRepair(rootFD, plan); err != nil {
		t.Fatalf("attribute refresh failed: %v", err)
	}
	if after, err := os.Stat(path); err != nil || after.Mode().Perm() != 0o640 {
		t.Fatalf("refresh changed mode: info=%v err=%v", after, err)
	}

	plan.ExpectedFileID++
	if _, err := actuateRepair(rootFD, plan); err == nil {
		t.Fatal("mismatched inode refresh unexpectedly succeeded")
	}
	if err := os.Symlink("file", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	plan = testEvictionPlan("link", repairItemSymlink)
	plan.Kind = "refresh"
	if _, err := actuateRepair(rootFD, plan); err == nil {
		t.Fatal("symlink attribute refresh unexpectedly succeeded")
	}
}
