package main

import (
	"context"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// A lock taken through an open file that is then renamed BEFORE it is closed must be released at the
// path the lock was ACQUIRED at: the path-addressed authority records the lock there and does NOT
// rekey it on rename. Likewise the open-count pin must be decremented at the OPEN-time path so it
// stays symmetric with the increment. Keying either off the live (post-rename) path instead would
// strand the lock under the old name until the mount disconnects, and pin the open-count forever
// (permanently blocking idle-release / write-back handoff of that subtree).
//
// This pins codex's MUST-FIX-NOW finding for the path-follow refactor: data ops correctly follow
// the rename via curPath(), but the open/lock *lifecycle* is anchored to the acquire-time path
// stored on the handle. The test would fail before the fix, because Release would target the live
// (renamed) path where neither the lock nor the open-count lives.
func TestLockAndOpenReleasedAtAcquirePathAfterRename(t *testing.T) {
	cli := newAuthority(t)
	ctx := context.Background()
	const (
		oldPath = "renlk_f"
		newPath = "renlk_g"
		owner1  = uint64(0x1111)
		owner2  = uint64(0x2222)
	)
	if _, st, err := cli.Create(oldPath, 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}

	// Open (read-through path: sessions is nil in unit tests; O_RDONLY also skips the write-intent
	// branch) then take a whole-file exclusive lock at the OLD path.
	n := &node{c: cli, path: oldPath}
	fh, _, e := n.Open(ctx, 0)
	if e != 0 {
		t.Fatalf("Open: errno=%d", e)
	}
	if e := n.Setlk(ctx, fh, owner1, &fuse.FileLock{Start: 0, End: ^uint64(0), Typ: lockWrite}, 0); e != 0 {
		t.Fatalf("Setlk: errno=%d", e)
	}
	// Preconditions: a different owner conflicts with owner1's lock, and the open-count pins oldPath.
	if res, err := cli.Lock(oldPath, fsproto.LkGetlk, owner2, 0, ^uint64(0), true, false); err != nil || !res.Conflict {
		t.Fatalf("precondition: owner2 should conflict at %q (res=%+v err=%v)", oldPath, res, err)
	}
	if !opens.busyUnder(oldPath) {
		t.Fatalf("precondition: %q should read as busy while open", oldPath)
	}

	// Rename WHILE the lock is held and the file is open. The authority moves the file but keeps the
	// lock under the old name (no rekey on rename).
	if st, err := cli.Rename(oldPath, newPath); err != nil || st != fsproto.OK {
		t.Fatalf("rename: st=%d err=%v", st, err)
	}

	// Close through a node that now reports the NEW path (curPath() == newPath via the field
	// fallback for a standalone node). The handle must still release against the acquire path.
	nG := &node{c: cli, path: newPath}
	if e := nG.Release(ctx, fh); e != 0 {
		t.Fatalf("Release: errno=%d", e)
	}

	// The lock must be gone at the old path: owner2 no longer conflicts. Before the fix Release
	// targeted newPath, leaving owner1's lock stranded under oldPath → still conflicting.
	if res, err := cli.Lock(oldPath, fsproto.LkGetlk, owner2, 0, ^uint64(0), true, false); err != nil || res.Conflict {
		t.Fatalf("lock leaked: owner1's lock still held at %q after rename-before-close (res=%+v err=%v)", oldPath, res, err)
	}
	// The open-count pin must be gone too (decremented at the open-time path, symmetric with inc).
	if opens.busyUnder(oldPath) {
		t.Fatalf("open-count leaked at %q after close: subtree still reads as busy", oldPath)
	}
}

// (The non-session Create open-count pin reuses this exact mechanism — opens.inc(cp) at Create +
// &lockHandle{openPath: cp} + opens.dec(h.openPath) at Release — so it is covered by the Open path
// above; a standalone Create unit test is not possible because newChild→NewInode needs a mounted FS.)

// EXPLICIT F_UNLCK (not close) after a rename must release at the lock's ACQUIRE path. This is the
// exact case codex flagged: Setlk's unlock branch used to forward to the live (renamed) path and drop
// the record, stranding the authority lock under the old name. The fix routes unlock through
// n.unlock, which releases each matching held lock at its recorded path.
func TestExplicitUnlockAfterRenameReleasesAtAcquirePath(t *testing.T) {
	cli := newAuthority(t)
	ctx := context.Background()
	const (
		oldPath = "unlk_f"
		newPath = "unlk_g"
		owner1  = uint64(0x3331)
		owner2  = uint64(0x3332)
	)
	if _, st, err := cli.Create(oldPath, 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}
	n := &node{c: cli, path: oldPath}
	fh, _, e := n.Open(ctx, 0)
	if e != 0 {
		t.Fatalf("Open: errno=%d", e)
	}
	if e := n.Setlk(ctx, fh, owner1, &fuse.FileLock{Start: 0, End: ^uint64(0), Typ: lockWrite}, 0); e != 0 {
		t.Fatalf("Setlk: errno=%d", e)
	}
	if st, err := cli.Rename(oldPath, newPath); err != nil || st != fsproto.OK {
		t.Fatalf("rename: st=%d err=%v", st, err)
	}
	// Explicit unlock issued through a node that reports the NEW path.
	nG := &node{c: cli, path: newPath}
	if e := nG.Setlk(ctx, fh, owner1, &fuse.FileLock{Start: 0, End: ^uint64(0), Typ: lockUnlock}, 0); e != 0 {
		t.Fatalf("explicit unlock: errno=%d", e)
	}
	// Released at the acquire path: owner2 no longer conflicts there.
	if res, err := cli.Lock(oldPath, fsproto.LkGetlk, owner2, 0, ^uint64(0), true, false); err != nil || res.Conflict {
		t.Fatalf("explicit unlock-after-rename leaked the lock at %q (res=%+v err=%v)", oldPath, res, err)
	}
	// The handle record is cleared, so a subsequent close does not re-issue a stale unlock.
	if rem := fh.(*lockHandle).drain(); len(rem) != 0 {
		t.Fatalf("explicit unlock left %d stale record(s) on the handle: %+v", len(rem), rem)
	}
	_ = n.Release(ctx, fh)
}

// Multiple disjoint byte-range locks on one handle, then rename, then close: releaseHandleLocks must
// release EVERY range at its acquire path (codex case 3).
func TestMultipleRangeLocksReleasedAtAcquirePathAfterRename(t *testing.T) {
	cli := newAuthority(t)
	ctx := context.Background()
	const (
		oldPath = "multi_f"
		newPath = "multi_g"
		owner   = uint64(0x4441)
		other   = uint64(0x4442)
	)
	if _, st, err := cli.Create(oldPath, 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}
	n := &node{c: cli, path: oldPath}
	fh, _, e := n.Open(ctx, 0)
	if e != 0 {
		t.Fatalf("Open: errno=%d", e)
	}
	ranges := [][2]uint64{{0, 99}, {200, 299}}
	for _, r := range ranges {
		if e := n.Setlk(ctx, fh, owner, &fuse.FileLock{Start: r[0], End: r[1], Typ: lockWrite}, 0); e != 0 {
			t.Fatalf("Setlk [%d,%d]: errno=%d", r[0], r[1], e)
		}
	}
	if st, err := cli.Rename(oldPath, newPath); err != nil || st != fsproto.OK {
		t.Fatalf("rename: st=%d err=%v", st, err)
	}
	// Close through the renamed node: both ranges must be released at the acquire path.
	nG := &node{c: cli, path: newPath}
	if e := nG.Release(ctx, fh); e != 0 {
		t.Fatalf("Release: errno=%d", e)
	}
	for _, r := range ranges {
		if res, err := cli.Lock(oldPath, fsproto.LkGetlk, other, r[0], r[1], true, false); err != nil || res.Conflict {
			t.Fatalf("range [%d,%d] leaked at %q after close (res=%+v err=%v)", r[0], r[1], oldPath, res, err)
		}
	}
}

// Cross-DIRECTORY rename (da/f → db/g): the lock release must still target the acquire path da/f
// (the authority is path-keyed and does not rekey on rename). Validates the A2 fix is path-agnostic.
// NOTE: the open-TRACKER cross-directory busyUnder rekey (so a write-back sweep of db/ sees the live
// file) is a known, documented refinement deferred to P4 (rename rekeys opens+lock keys); it is not a
// regression from Stage 1 (the pre-refactor fixed-path field had the same gap) and is not asserted here.
func TestLockReleasedAcrossCrossDirectoryRename(t *testing.T) {
	cli := newAuthority(t)
	ctx := context.Background()
	const (
		oldPath = "da/f"
		newPath = "db/g"
		owner   = uint64(0x5551)
		other   = uint64(0x5552)
	)
	for _, d := range []string{"da", "db"} {
		if _, st, err := cli.Mkdir(d, 0o755); err != nil || st != fsproto.OK {
			t.Fatalf("mkdir %q: st=%d err=%v", d, st, err)
		}
	}
	if _, st, err := cli.Create(oldPath, 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}
	n := &node{c: cli, path: oldPath}
	fh, _, e := n.Open(ctx, 0)
	if e != 0 {
		t.Fatalf("Open: errno=%d", e)
	}
	if e := n.Setlk(ctx, fh, owner, &fuse.FileLock{Start: 0, End: ^uint64(0), Typ: lockWrite}, 0); e != 0 {
		t.Fatalf("Setlk: errno=%d", e)
	}
	if st, err := cli.Rename(oldPath, newPath); err != nil || st != fsproto.OK {
		t.Fatalf("rename: st=%d err=%v", st, err)
	}
	nG := &node{c: cli, path: newPath}
	if e := nG.Release(ctx, fh); e != 0 {
		t.Fatalf("Release: errno=%d", e)
	}
	if res, err := cli.Lock(oldPath, fsproto.LkGetlk, other, 0, ^uint64(0), true, false); err != nil || res.Conflict {
		t.Fatalf("cross-dir rename leaked the lock at %q after close (res=%+v err=%v)", oldPath, res, err)
	}
}

// A PARTIAL F_UNLCK of a larger held range, on a handle whose file was renamed, must release the
// unlocked sub-range at the ACQUIRE path (the authority splits the held lock there), leaving the rest
// held. Before the fix, a partial unlock matched no fully-contained record and fell back to the live
// (renamed) path, so the sub-range was never actually released at the authority. (codex final must-fix)
func TestPartialUnlockAfterRenameReleasesSubrangeAtAcquirePath(t *testing.T) {
	cli := newAuthority(t)
	ctx := context.Background()
	const (
		oldPath = "prt_f"
		newPath = "prt_g"
		owner1  = uint64(0x6661)
		owner2  = uint64(0x6662)
	)
	if _, st, err := cli.Create(oldPath, 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}
	n := &node{c: cli, path: oldPath}
	fh, _, e := n.Open(ctx, 0)
	if e != 0 {
		t.Fatalf("Open: errno=%d", e)
	}
	// Hold a write lock on [0,100] at the old path.
	if e := n.Setlk(ctx, fh, owner1, &fuse.FileLock{Start: 0, End: 100, Typ: lockWrite}, 0); e != 0 {
		t.Fatalf("Setlk: errno=%d", e)
	}
	if st, err := cli.Rename(oldPath, newPath); err != nil || st != fsproto.OK {
		t.Fatalf("rename: st=%d err=%v", st, err)
	}
	// Partially unlock [0,50] through a node reporting the NEW path.
	nG := &node{c: cli, path: newPath}
	if e := nG.Setlk(ctx, fh, owner1, &fuse.FileLock{Start: 0, End: 50, Typ: lockUnlock}, 0); e != 0 {
		t.Fatalf("partial unlock: errno=%d", e)
	}
	// At the acquire path: the unlocked sub-range [0,50] is free, the rest [51,100] is still held.
	if res, err := cli.Lock(oldPath, fsproto.LkGetlk, owner2, 0, 50, true, false); err != nil || res.Conflict {
		t.Fatalf("partial unlock did not release [0,50] at the acquire path %q (res=%+v err=%v)", oldPath, res, err)
	}
	if res, err := cli.Lock(oldPath, fsproto.LkGetlk, owner2, 51, 100, true, false); err != nil || !res.Conflict {
		t.Fatalf("partial unlock wrongly released the retained range [51,100] at %q (res=%+v err=%v)", oldPath, res, err)
	}
	// The handle record now reflects only the retained suffix, so close releases exactly that.
	if e := nG.Release(ctx, fh); e != 0 {
		t.Fatalf("Release: errno=%d", e)
	}
	if res, err := cli.Lock(oldPath, fsproto.LkGetlk, owner2, 51, 100, true, false); err != nil || res.Conflict {
		t.Fatalf("close did not release the retained range [51,100] at %q (res=%+v err=%v)", oldPath, res, err)
	}
}
