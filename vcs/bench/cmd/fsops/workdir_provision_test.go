package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestProvisionWorkDirNeverRemovesPreexistingTree pins the destructive-safety
// invariant of the benchmark tool: it operates in a directory it created and
// uniquely owns, and cleanup removes only that directory. A pre-existing tree
// handed to -dir is a workspace to work *inside*, never something the tool may
// delete.
func TestProvisionWorkDirNeverRemovesPreexistingTree(t *testing.T) {
	parent := t.TempDir()
	victim := filepath.Join(parent, "precious.txt")
	if err := os.WriteFile(victim, []byte("do not delete"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(parent, "subtree")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	work, cleanup, err := provisionWorkDir(parent, false)
	if err != nil {
		t.Fatalf("provisionWorkDir: %v", err)
	}
	if work == parent {
		t.Fatalf("work dir must be a uniquely-owned child of %s, got the parent itself", parent)
	}
	rel, err := filepath.Rel(parent, work)
	if err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("work dir %s is not inside the parent %s", work, parent)
	}
	if st, err := os.Stat(work); err != nil || !st.IsDir() {
		t.Fatalf("work dir %s was not created: %v", work, err)
	}
	// Phases write into the work dir; cleanup must take that with it.
	if err := os.WriteFile(filepath.Join(work, "f00000"), []byte("probe"), 0o644); err != nil {
		t.Fatal(err)
	}

	cleanup()

	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("cleanup destroyed a pre-existing file the tool did not create: %v", err)
	}
	if _, err := os.Stat(sub); err != nil {
		t.Fatalf("cleanup destroyed a pre-existing subtree the tool did not create: %v", err)
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatalf("cleanup left the tool's own work dir %s behind: %v", work, err)
	}
}

// TestProvisionWorkDirKeepLeavesEverything proves -keep removes nothing at all.
func TestProvisionWorkDirKeepLeavesEverything(t *testing.T) {
	parent := t.TempDir()
	work, cleanup, err := provisionWorkDir(parent, true)
	if err != nil {
		t.Fatalf("provisionWorkDir: %v", err)
	}
	probe := filepath.Join(work, "bulk.bin")
	if err := os.WriteFile(probe, []byte("probe"), 0o644); err != nil {
		t.Fatal(err)
	}

	cleanup()

	if _, err := os.Stat(probe); err != nil {
		t.Fatalf("-keep must leave the work dir intact: %v", err)
	}
}

// TestProvisionWorkDirCreatesParent allows a not-yet-existing workspace path:
// the parent may be created, it is simply never removed.
func TestProvisionWorkDirCreatesParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "nested", "workspace")
	work, cleanup, err := provisionWorkDir(parent, false)
	if err != nil {
		t.Fatalf("provisionWorkDir: %v", err)
	}
	cleanup()
	if _, err := os.Stat(parent); err != nil {
		t.Fatalf("parent workspace must survive cleanup: %v", err)
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatalf("work dir %s must be removed: %v", work, err)
	}
}

// TestProvisionWorkDirIsUnique proves two concurrent runs against the same
// workspace never share (and so never delete) each other's directory.
func TestProvisionWorkDirIsUnique(t *testing.T) {
	parent := t.TempDir()
	a, cleanupA, err := provisionWorkDir(parent, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupA()
	b, cleanupB, err := provisionWorkDir(parent, false)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupB()
	if a == b {
		t.Fatalf("two runs shared the same work dir %s", a)
	}
}
