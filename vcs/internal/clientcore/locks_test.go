package clientcore

import (
	"context"
	"errors"
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
	if res, err := SetLock(context.Background(), auth, h, "old", 7, 0, 100, true, false); err != nil || res.Status != fsproto.OK {
		t.Fatalf("SetLock: res=%+v err=%v", res, err)
	}
	if err := Unlock(context.Background(), auth, h, 7, 0, 50, "new"); err != nil {
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

func TestUnlockPreCanceledPreservesHandleAndSendsNothing(t *testing.T) {
	auth := &recordingLockAuthority{}
	h := &LockHandle{}
	h.Add(7, 0, 100, "old", true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := Unlock(ctx, auth, h, 7, 0, 50, "new"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Unlock error = %v, want context.Canceled", err)
	}
	if len(auth.calls) != 0 {
		t.Fatalf("pre-canceled unlock sent %d authority calls", len(auth.calls))
	}
	got := h.Snapshot()
	if len(got) != 1 || got[0] != (HeldLock{Owner: 7, Start: 0, End: 100, Path: "old", Write: true}) {
		t.Fatalf("pre-canceled unlock changed local ownership: %+v", got)
	}
}

func TestUnlockCancellationAfterCommitCompletesEveryAuthorityRelease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	auth := &cancelAfterFirstLockAuthority{cancel: cancel}
	h := &LockHandle{}
	h.Add(7, 0, 100, "first", true)
	h.Add(7, 0, 100, "second", true)

	if err := Unlock(ctx, auth, h, 7, 0, 100, "live"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if len(auth.calls) != 2 {
		t.Fatalf("cancellation after first release produced %d calls, want 2", len(auth.calls))
	}
	for i, call := range auth.calls {
		if call.ctxErr != nil {
			t.Fatalf("release %d inherited caller cancellation: %v", i, call.ctxErr)
		}
	}
	if got := h.Snapshot(); len(got) != 0 {
		t.Fatalf("completed unlock retained local records: %+v", got)
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

func (a *recordingLockAuthority) Lock(_ context.Context, path string, mode uint8, lkID, start, end uint64, write, unlock bool) (fsproto.LockResult, error) {
	a.calls = append(a.calls, lockCall{
		path: path, mode: mode, owner: lkID, start: start, end: end, write: write, unlock: unlock,
	})
	return fsproto.LockResult{Status: fsproto.OK}, nil
}

type cancelAfterFirstLockAuthority struct {
	cancel context.CancelFunc
	calls  []unlockCancellationCall
}

type unlockCancellationCall struct {
	path   string
	ctxErr error
}

func (a *cancelAfterFirstLockAuthority) Lock(ctx context.Context, path string, _ uint8, _, _, _ uint64, _, _ bool) (fsproto.LockResult, error) {
	a.calls = append(a.calls, unlockCancellationCall{path: path, ctxErr: ctx.Err()})
	if len(a.calls) == 1 {
		a.cancel()
	}
	return fsproto.LockResult{Status: fsproto.OK}, nil
}

type failPathLockAuthority struct {
	failPath string
	calls    []lockCall
}

func (a *failPathLockAuthority) Lock(_ context.Context, path string, mode uint8, lkID, start, end uint64, write, unlock bool) (fsproto.LockResult, error) {
	a.calls = append(a.calls, lockCall{
		path: path, mode: mode, owner: lkID, start: start, end: end, write: write, unlock: unlock,
	})
	if path == a.failPath {
		return fsproto.LockResult{}, errors.New("authority unreachable for this release")
	}
	return fsproto.LockResult{Status: fsproto.OK}, nil
}

// A failed authority release must not surrender the local record: it is the
// only thing that lets close/reclaim reconstruct and retry the release.
func TestUnlockFailedReleaseRetainsLocalOwnership(t *testing.T) {
	auth := &failPathLockAuthority{failPath: "a"}
	h := &LockHandle{}
	h.Add(7, 0, 100, "a", true)
	h.Add(7, 0, 100, "b", true)

	err := Unlock(context.Background(), auth, h, 7, 0, 100, "live")
	if err == nil {
		t.Fatal("failed release reported success")
	}
	left := h.Snapshot()
	if len(left) != 1 || left[0].Path != "a" || !left[0].Write {
		t.Fatalf("ownership after failed release = %+v, want only path a retained", left)
	}
	// close/reclaim can now converge the release.
	auth.failPath = ""
	ReleaseHandleLocks(auth, h)
	last := auth.calls[len(auth.calls)-1]
	if last.path != "a" || !last.unlock {
		t.Fatalf("reclaim did not release the retained lock: %+v", last)
	}
}

// A partial unlock's split remainders keep their lock type so a post-failover
// reclaim re-asserts a write lock as a write lock.
func TestUnlockSplitPreservesWriteType(t *testing.T) {
	auth := &recordingLockAuthority{}
	h := &LockHandle{}
	h.Add(7, 0, 100, "f", true)
	if err := Unlock(context.Background(), auth, h, 7, 40, 60, "f"); err != nil {
		t.Fatal(err)
	}
	left := h.Snapshot()
	if len(left) != 2 {
		t.Fatalf("split remainders = %+v, want 2", left)
	}
	for _, l := range left {
		if !l.Write {
			t.Fatalf("split remainder lost its write type: %+v", l)
		}
	}
}
