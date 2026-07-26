package main

import "testing"

// A lock taken through an open file must be remembered so it can be released when that file is
// closed — go-fuse strips the kernel lock_owner on FLUSH/RELEASE, so the per-handle record is the
// only way the mount can reconstruct the unlock.
func TestLockHandleAddDrain(t *testing.T) {
	h := &lockHandle{}
	h.add(7, 0, ^uint64(0), "f")
	h.add(7, 100, 200, "f")
	got := h.drain()
	if len(got) != 2 {
		t.Fatalf("drain returned %d locks, want 2", len(got))
	}
	// The acquire-time path is recorded per lock so release targets the path the authority holds
	// the lock at, even after a rename between acquire and close.
	for _, l := range got {
		if l.path != "f" {
			t.Fatalf("held lock did not record its acquire path: %+v", l)
		}
	}
	if len(h.drain()) != 0 {
		t.Fatalf("drain did not clear the handle")
	}
}

// An explicit F_UNLCK removes the matching record so close does not re-issue a stale unlock.
func TestLockHandleRemoveContained(t *testing.T) {
	h := &lockHandle{}
	h.add(7, 0, ^uint64(0), "f") // whole-file (flock)
	h.add(7, 100, 200, "f")      // a byte range
	h.add(9, 100, 200, "f")      // a different owner, same range

	h.remove(7, 0, ^uint64(0)) // unlock everything owner 7 holds within the whole file

	left := h.drain()
	// owner 9's lock must survive (different owner); owner 7's both fall inside [0,EOF].
	if len(left) != 1 || left[0].owner != 9 {
		t.Fatalf("remove dropped the wrong locks: %+v", left)
	}
}

// remove must not touch another owner's lock even when ranges coincide.
func TestLockHandleRemoveIsOwnerScoped(t *testing.T) {
	h := &lockHandle{}
	h.add(1, 0, 10, "f")
	h.remove(2, 0, 10) // a different owner unlocking the same range
	if len(h.drain()) != 1 {
		t.Fatalf("remove released another owner's lock")
	}
}
