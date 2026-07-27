package clientcore

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

func TestLockHandleAddDrain(t *testing.T) {
	h := &LockHandle{}
	h.Add(7, 0, ^uint64(0), "f", true)
	h.Add(7, 100, 200, "f", false)
	got := h.Drain()
	if len(got) != 2 {
		t.Fatalf("Drain returned %d locks, want 2", len(got))
	}
	for _, l := range got {
		if l.Path != "f" {
			t.Fatalf("held lock did not record acquire path: %+v", l)
		}
	}
	if len(h.Drain()) != 0 {
		t.Fatalf("Drain did not clear the handle")
	}
}

func TestLockHandleRemoveIsOwnerScoped(t *testing.T) {
	h := &LockHandle{}
	h.Add(7, 0, ^uint64(0), "f", true)
	h.Add(9, 100, 200, "f", true)

	h.Remove(7, 0, ^uint64(0))

	left := h.Drain()
	if len(left) != 1 || left[0].Owner != 9 {
		t.Fatalf("Remove dropped the wrong locks: %+v", left)
	}
}

func TestUnlockForwardsAcquirePath(t *testing.T) {
	auth := &recordingLockAuthority{}
	h := &LockHandle{}
	if res, err := SetLock(auth, h, "old", 7, 0, 100, true, false); err != nil || res.Status != fsproto.OK {
		t.Fatalf("SetLock: res=%+v err=%v", res, err)
	}
	if err := Unlock(auth, h, 7, 0, 50, "new"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if len(auth.calls) != 2 {
		t.Fatalf("got %d authority calls, want 2", len(auth.calls))
	}
	if c := auth.calls[1]; c.path != "old" || !c.unlock || c.start != 0 || c.end != 50 {
		t.Fatalf("unlock did not target acquire path/range: %+v", c)
	}
	left := h.Drain()
	if len(left) != 1 || left[0].Start != 51 || left[0].End != 100 {
		t.Fatalf("partial unlock left wrong local record: %+v", left)
	}
}

type lockCall struct {
	path       string
	mode       uint8
	owner      uint64
	start, end uint64
	write      bool
	unlock     bool
}

type recordingLockAuthority struct {
	calls []lockCall
}

func (a *recordingLockAuthority) Lock(path string, mode uint8, lkID, start, end uint64, write, unlock bool) (fsproto.LockResult, error) {
	a.calls = append(a.calls, lockCall{
		path: path, mode: mode, owner: lkID, start: start, end: end, write: write, unlock: unlock,
	})
	return fsproto.LockResult{Status: fsproto.OK}, nil
}
