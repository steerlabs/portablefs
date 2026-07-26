package fsproto

import (
	"path/filepath"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/delegation"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

func newEnforceServer(t *testing.T) (*Server, *delegation.Manager) {
	t.Helper()
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.New(nil, nopBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	deleg := delegation.New()
	return NewServer(fs, fs, deleg), deleg
}

// TestCheckoutEnforcedOnMutations: checkout becomes non-advisory. Once a subtree is
// checked out by owner A, only A may mutate paths under it; a non-owner mutation is
// refused with EBUSY (previously it was silently allowed). Un-checked-out paths stay
// unrestricted, so existing write-through flows are unaffected until a checkout exists.
func TestCheckoutEnforcedOnMutations(t *testing.T) {
	s, deleg := newEnforceServer(t)
	if r := s.dispatch(&Request{Op: OpMkdir, Path: "work", Mode: 0o755}); r.Status != OK {
		t.Fatalf("seed mkdir: status %d", r.Status)
	}
	if granted, _ := deleg.Checkout("work", "A"); !granted {
		t.Fatal("A checkout should grant")
	}

	// Non-owner write under the checked-out subtree → EBUSY (with the holder reported).
	if r := s.dispatch(&Request{Op: OpWrite, Path: "work/db", Data: []byte("x"), Mode: 0o644, Owner: "B"}); r.Status != EBUSY || r.Owner != "A" {
		t.Fatalf("non-owner write: status=%d owner=%q, want EBUSY held-by A", r.Status, r.Owner)
	}
	// A descendant create by a non-owner is refused BEFORE touching the fs (covers
	// SQLite's -wal/-journal/-shm siblings under a parent-dir checkout).
	if r := s.dispatch(&Request{Op: OpCreate, Path: "work/db-wal", Mode: 0o644, Owner: "B"}); r.Status != EBUSY {
		t.Fatalf("non-owner sibling create: status=%d, want EBUSY", r.Status)
	}
	// The owner may mutate freely under its checkout. Real flow creates before writing (an OpWrite
	// no longer resurrects an absent path), so the owner creates work/db, then writes it.
	if r := s.dispatch(&Request{Op: OpCreate, Path: "work/db", Mode: 0o644, Owner: "A"}); r.Status != OK {
		t.Fatalf("owner create: status %d, want OK", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpWrite, Path: "work/db", Data: []byte("x"), Mode: 0o644, Owner: "A"}); r.Status != OK {
		t.Fatalf("owner write: status %d, want OK", r.Status)
	}
	// An un-checked-out path is writable by anyone (no regression for write-through).
	if r := s.dispatch(&Request{Op: OpCreate, Path: "free.txt", Mode: 0o644, Owner: "B"}); r.Status != OK {
		t.Fatalf("free-path create: status %d, want OK", r.Status)
	}
	// Rename is enforced on BOTH source and destination.
	if r := s.dispatch(&Request{Op: OpRename, Path: "free.txt", NewPath: "work/moved", Owner: "B"}); r.Status != EBUSY {
		t.Fatalf("rename INTO a non-owned checkout: status=%d, want EBUSY", r.Status)
	}
}
