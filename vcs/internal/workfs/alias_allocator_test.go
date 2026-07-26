package workfs

// Dirent-owned names, hard-link aliases, and the explicit inode-identity
// allocator: names live only in parent dirents (an inode record is nameless),
// so several aliases resolve to ONE inode-table record; allocator state is
// {namespace, nextLocal, maxInoSeen, durableFloor} with typed capture/import
// and never-reuse across delete/restart/compaction.

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/pfc2"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

func statInfo(t *testing.T, fs *FS, name string) os.FileInfo {
	t.Helper()
	fi, err := fs.Lstat(name)
	if err != nil {
		t.Fatalf("lstat %q: %v", name, err)
	}
	return fi
}

func inoNlink(t *testing.T, fi os.FileInfo) (uint64, uint32) {
	t.Helper()
	sys, ok := fi.Sys().(interface {
		Ino() uint64
		LinkCount() uint32
	})
	if !ok {
		t.Fatalf("FileInfo.Sys() %T does not expose Ino/LinkCount", fi.Sys())
	}
	return sys.Ino(), sys.LinkCount()
}

// Three aliases are one inode: shared identity, shared nlink, and every
// content/metadata mutation through ANY alias is visible through all others.
func TestAliasSharedInodeContentAndMetadata(t *testing.T) {
	fs := newInoTestFS(t)
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644})
	if err := fs.Link("f", "g"); err != nil {
		t.Fatalf("link f->g: %v", err)
	}
	if err := fs.Link("g", "h"); err != nil {
		t.Fatalf("link g->h: %v", err)
	}

	base, _ := inoNlink(t, statInfo(t, fs, "f"))
	for _, name := range []string{"f", "g", "h"} {
		fi := statInfo(t, fs, name)
		ino, nlink := inoNlink(t, fi)
		if ino != base {
			t.Fatalf("%q ino %d, want shared %d", name, ino, base)
		}
		if nlink != 3 {
			t.Fatalf("%q nlink %d, want 3", name, nlink)
		}
		if fi.Name() != name {
			t.Fatalf("stat via %q reports name %q (must be the dirent resolved through)", name, fi.Name())
		}
	}

	// Content written via one alias reads back through the others.
	if _, _, err := fs.WriteAt("g", 0, []byte("shared-bytes"), 0o644); err != nil {
		t.Fatalf("write via g: %v", err)
	}
	for _, name := range []string{"f", "h"} {
		if got := string(readAllAt(t, fs, name)); got != "shared-bytes" {
			t.Fatalf("read via %q = %q, want %q", name, got, "shared-bytes")
		}
	}
	// Metadata via one alias is visible through the others.
	if err := fs.Chmod("h", 0o600); err != nil {
		t.Fatalf("chmod via h: %v", err)
	}
	if got := statInfo(t, fs, "f").Mode().Perm(); got != 0o600 {
		t.Fatalf("mode via f = %o, want 600", got)
	}
	if err := fs.Chown("f", 42, 43); err != nil {
		t.Fatalf("chown via f: %v", err)
	}
	uid, gid := statInfo(t, fs, "h").(interface{ OwnerIDs() (uint32, uint32) }).OwnerIDs()
	if uid != 42 || gid != 43 {
		t.Fatalf("owner via h = %d:%d, want 42:43", uid, gid)
	}

	// ReadDir reports every alias under its own dirent name with the shared ino.
	infos, err := fs.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]uint64{}
	for _, fi := range infos {
		ino, _ := inoNlink(t, fi)
		seen[fi.Name()] = ino
	}
	for _, name := range []string{"f", "g", "h"} {
		if seen[name] != base {
			t.Fatalf("readdir %q ino %d, want %d", name, seen[name], base)
		}
	}

	// Directories cannot hardlink (EPERM), and a busy destination is EEXIST.
	apply(t, fs, wal.Record{Op: wal.OpMkdir, Path: "d", Mode: 0o755})
	if err := fs.Link("d", "d2"); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("dir hardlink err = %v, want EPERM", err)
	}
	if err := fs.Link("f", "g"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("link onto existing name err = %v, want EEXIST", err)
	}
}

// Rename/unlink over aliases in every ordering: identity survives, nlink
// accounts each dirent exactly once, nothing parks until the LAST link dies,
// and renaming one alias onto another alias of the same inode is the POSIX
// no-op that keeps both names.
func TestAliasRenameUnlinkOrderings(t *testing.T) {
	type step struct {
		op       string // "rename" | "remove"
		from, to string
	}
	cases := []struct {
		name      string
		steps     []step
		survivors map[string]uint32 // surviving alias -> want nlink
		parked    bool              // inode parked after the last step
		indexed   bool              // inode still in the stable-handle index
	}{
		{
			name:      "rename-first-alias-then-unlink-second",
			steps:     []step{{op: "rename", from: "a", to: "c"}, {op: "remove", from: "b"}},
			survivors: map[string]uint32{"c": 1},
			indexed:   true,
		},
		{
			name:      "unlink-second-then-rename-first",
			steps:     []step{{op: "remove", from: "b"}, {op: "rename", from: "a", to: "c"}},
			survivors: map[string]uint32{"c": 1},
			indexed:   true,
		},
		{
			// The WAL-backed store destroys a not-open inode on its LAST
			// unlink (the managed store parks deterministically instead;
			// its policy is pinned by the managed suites).
			name:      "unlink-first-then-unlink-renamed-last",
			steps:     []step{{op: "remove", from: "a"}, {op: "rename", from: "b", to: "c"}, {op: "remove", from: "c"}},
			survivors: map[string]uint32{},
		},
		{
			name:      "rename-alias-onto-its-other-alias-is-noop",
			steps:     []step{{op: "rename", from: "a", to: "b"}},
			survivors: map[string]uint32{"a": 2, "b": 2},
			indexed:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newInoTestFS(t)
			apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "a", Mode: 0o644})
			if _, _, err := fs.WriteAt("a", 0, []byte("payload"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := fs.Link("a", "b"); err != nil {
				t.Fatal(err)
			}
			ino, nlink := inoNlink(t, statInfo(t, fs, "a"))
			if nlink != 2 {
				t.Fatalf("setup nlink %d, want 2", nlink)
			}
			for _, s := range tc.steps {
				switch s.op {
				case "rename":
					if err := fs.Rename(s.from, s.to); err != nil {
						t.Fatalf("rename %s->%s: %v", s.from, s.to, err)
					}
				case "remove":
					// Remove parks only the LAST link (deterministic detach);
					// earlier links just drop their dirent.
					if err := fs.Remove(s.from); err != nil {
						t.Fatalf("remove %s: %v", s.from, err)
					}
				}
			}
			for name, wantNlink := range tc.survivors {
				fi := statInfo(t, fs, name)
				gotIno, gotNlink := inoNlink(t, fi)
				if gotIno != ino {
					t.Fatalf("%q ino %d, want stable %d", name, gotIno, ino)
				}
				if gotNlink != wantNlink {
					t.Fatalf("%q nlink %d, want %d", name, gotNlink, wantNlink)
				}
				if got := string(readAllAt(t, fs, name)); got != "payload" {
					t.Fatalf("content via %q = %q, want payload", name, got)
				}
			}
			fs.mu.RLock()
			_, parked := fs.orphans[ino]
			_, indexed := fs.byIno[ino]
			fs.mu.RUnlock()
			if parked != tc.parked {
				t.Fatalf("parked=%v, want %v (park only at last link)", parked, tc.parked)
			}
			if indexed != tc.indexed {
				t.Fatalf("indexed=%v, want %v", indexed, tc.indexed)
			}
		})
	}
}

// Rename of one alias ONTO an unrelated file replaces that file (the
// WAL-backed store destroys a not-open victim; the managed store parks it —
// pinned by the managed suites) while the moved inode keeps its full alias
// count.
func TestAliasRenameOverUnrelatedDestination(t *testing.T) {
	fs := newInoTestFS(t)
	apply(t, fs,
		wal.Record{Op: wal.OpCreate, Path: "a", Mode: 0o644},
		wal.Record{Op: wal.OpCreate, Path: "victim", Mode: 0o644},
	)
	if err := fs.Link("a", "b"); err != nil {
		t.Fatal(err)
	}
	srcIno, _ := inoNlink(t, statInfo(t, fs, "a"))
	victimIno, _ := inoNlink(t, statInfo(t, fs, "victim"))
	if err := fs.Rename("a", "victim"); err != nil {
		t.Fatal(err)
	}
	fs.mu.RLock()
	_, victimParked := fs.orphans[victimIno]
	_, victimIndexed := fs.byIno[victimIno]
	fs.mu.RUnlock()
	if victimParked || victimIndexed {
		t.Fatalf("replaced not-open destination ino %d parked=%v indexed=%v, want destroyed", victimIno, victimParked, victimIndexed)
	}
	for _, name := range []string{"victim", "b"} {
		gotIno, gotNlink := inoNlink(t, statInfo(t, fs, name))
		if gotIno != srcIno || gotNlink != 2 {
			t.Fatalf("%q ino/nlink = %d/%d, want %d/2", name, gotIno, gotNlink, srcIno)
		}
	}
}

// Open-after-unlink across aliases: unlinking one alias parks nothing (the
// inode is still named), the open handle keeps writing by ino; only the last
// link parks the inode, whose bytes stay readable until explicit reap.
func TestAliasOpenAfterUnlinkAndLastLinkReap(t *testing.T) {
	fs := newInoTestFS(t)
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644})
	if _, _, err := fs.WriteAt("f", 0, []byte("keep-me"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fs.Link("f", "g"); err != nil {
		t.Fatal(err)
	}
	ino, _ := inoNlink(t, statInfo(t, fs, "f"))

	// Unlink alias f: NOT parked (g still names the inode), handle writes by
	// ino keep landing, and g observes them.
	if orphanIno, err := fs.Orphan("f", ""); err != nil || orphanIno != 0 {
		t.Fatalf("orphan of one alias parked ino %d (err %v), want no park while g remains", orphanIno, err)
	}
	fs.mu.RLock()
	_, parked := fs.orphans[ino]
	live := fs.byIno[ino] != nil
	fs.mu.RUnlock()
	if parked || !live {
		t.Fatalf("alias unlink parked=%v live=%v, want unparked+live", parked, live)
	}
	if _, _, err := fs.WriteAtHandleExistingAs("f", ino, int64(len("keep-me")), []byte("+more"), ""); err != nil {
		t.Fatalf("handle write by ino after alias unlink: %v", err)
	}
	if got := string(readAllAt(t, fs, "g")); got != "keep-me+more" {
		t.Fatalf("content via surviving alias = %q, want %q", got, "keep-me+more")
	}
	if _, gotNlink := inoNlink(t, statInfo(t, fs, "g")); gotNlink != 1 {
		t.Fatalf("nlink after alias unlink = %d, want 1", gotNlink)
	}

	// Unlink the LAST alias with the fd conceptually open: parks under the
	// same ino; reads/writes continue by ino; OrphanInfo reports nlink 0.
	orphanIno, err := fs.Orphan("g", "")
	if err != nil || orphanIno != ino {
		t.Fatalf("last-link orphan = %d (err %v), want parked ino %d", orphanIno, err, ino)
	}
	buf := make([]byte, 64)
	n, rerr := fs.ReadOrphanAt(ino, buf, 0)
	if rerr != nil && rerr != io.EOF {
		t.Fatalf("read parked orphan: %v", rerr)
	}
	if got := string(buf[:n]); got != "keep-me+more" {
		t.Fatalf("parked orphan content = %q, want %q", got, "keep-me+more")
	}
	fi, ok := fs.OrphanInfo(ino)
	if !ok {
		t.Fatal("OrphanInfo lost the parked inode")
	}
	if fi.Name() != "" {
		t.Fatalf("parked orphan reports name %q, want empty (no dirent)", fi.Name())
	}
	// POSIX fstat truth after the last unlink: the parked inode has ZERO
	// directory entries and must say so (the legacy zero-means-unset
	// coercion applies only to NAMED inodes).
	if nlink := fi.Sys().(interface{ LinkCount() uint32 }).LinkCount(); nlink != 0 {
		t.Fatalf("parked orphan nlink = %d, want 0", nlink)
	}
	if hfi, err := fs.HandleInfo("", ino); err != nil {
		t.Fatalf("handle stat of parked inode: %v", err)
	} else if nlink := hfi.Sys().(interface{ LinkCount() uint32 }).LinkCount(); nlink != 0 {
		t.Fatalf("handle stat of parked inode nlink = %d, want 0", nlink)
	}

	// Last close: explicit reap destroys it and frees the identity FORWARD
	// only (the id is never reused).
	if err := fs.Reap(ino, ""); err != nil {
		t.Fatal(err)
	}
	fs.mu.RLock()
	_, stillParked := fs.orphans[ino]
	_, stillIndexed := fs.byIno[ino]
	fs.mu.RUnlock()
	if stillParked || stillIndexed {
		t.Fatal("reap left the parked inode behind")
	}
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "fresh", Mode: 0o644})
	if freshIno := inoAt(t, fs, "fresh"); freshIno <= ino {
		t.Fatalf("post-reap create got ino %d, want > reaped %d (never reuse)", freshIno, ino)
	}
}

// Managed coordination state keys by inode identity: locks and open pins
// survive alias rename, alias unlink, and last-link parking, and remain
// operable by ino afterwards.
func TestAliasLocksAndPinsSurviveRenameAndDeath(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	a := openManagedSession(t, fs, "pfs-alias", 1)
	exact := func(slot uint32, seq uint64, seed byte, r wal.Record) MutationResult {
		t.Helper()
		hash := make([]byte, 32)
		hash[0], hash[1] = seed, byte(slot)
		r.Env = coordEnv(a, slot, seq, hash)
		res, merr := fs.MutateEnv(r, "")
		if merr != nil {
			t.Fatalf("op %v: %v", r.Op, merr)
		}
		return res
	}

	ino := exact(0, 1, 0x11, wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644}).Ino
	exact(1, 1, 0x12, wal.Record{Op: wal.OpLink, Path: "f", NewPath: "g"})

	// Lock by ino and pin the inode open.
	lockE := lockEnv(t, a, 2, 1, ino, 7, pfc2.LockSetWrite, 0, 0)
	if d, lerr := fs.ManagedLockDecide(lockE, ino, 7, pfc2.LockSetWrite, 0, 0); lerr != nil || d.Status != 0 {
		t.Fatalf("lock: %+v %v", d, lerr)
	}
	pinHash := make([]byte, 32)
	pinHash[0] = 0x21
	if perr := fs.ManagedPinChange(coordEnv(a, 3, 1, pinHash), ino, false, pinHash); perr != nil {
		t.Fatalf("pin: %v", perr)
	}

	verifyHeld := func(stage string) {
		t.Helper()
		control, cerr := fs.ManagedControl()
		if cerr != nil {
			t.Fatal(cerr)
		}
		if held := control.HeldLocks(ino); len(held) != 1 || held[0].Owner.Session != a {
			t.Fatalf("%s: lock not held by ino: %+v", stage, held)
		}
		if !control.HasPin(a, ino) {
			t.Fatalf("%s: open pin lost", stage)
		}
	}
	verifyHeld("initial")

	// Rename one alias; the coordination key (ino) is untouched.
	exact(4, 1, 0x13, wal.Record{Op: wal.OpRename, Path: "g", NewPath: "renamed"})
	verifyHeld("after alias rename")

	// Unlink one alias (inode still named by "renamed"): still held.
	exact(5, 1, 0x14, wal.Record{Op: wal.OpOrphan, Path: "f"})
	verifyHeld("after one alias unlink")

	// Unlink the LAST alias: the inode parks, and the lock+pin still key it.
	exact(6, 1, 0x15, wal.Record{Op: wal.OpOrphan, Path: "renamed"})
	fs.mu.RLock()
	_, parked := fs.orphans[ino]
	fs.mu.RUnlock()
	if !parked {
		t.Fatal("last alias unlink did not park the inode")
	}
	verifyHeld("after last-link park")

	// Both remain operable BY INO after every name died.
	unpinHash := make([]byte, 32)
	unpinHash[0] = 0x22
	if perr := fs.ManagedPinChange(coordEnv(a, 7, 1, unpinHash), ino, true, unpinHash); perr != nil {
		t.Fatalf("unpin parked inode: %v", perr)
	}
	unlockE := lockEnv(t, a, 2, 2, ino, 7, pfc2.LockUnlock, 0, 0)
	if d, lerr := fs.ManagedLockDecide(unlockE, ino, 7, pfc2.LockUnlock, 0, 0); lerr != nil || d.Status != 0 {
		t.Fatalf("unlock parked inode: %+v %v", d, lerr)
	}
	control, cerr := fs.ManagedControl()
	if cerr != nil {
		t.Fatal(cerr)
	}
	if held := control.HeldLocks(ino); len(held) != 0 {
		t.Fatalf("unlock by ino failed after all names died: %+v", held)
	}
}

// Capture/import of allocator state: the high-water round-trips, a deleted
// id is never re-handed after restart-via-import, and an imported compacted
// floor (PFT2 MaxInoSeen) dominates fresh allocation.
func TestAllocatorCaptureImportHighWaterAndFloor(t *testing.T) {
	fs := newInoTestFS(t)
	apply(t, fs,
		wal.Record{Op: wal.OpCreate, Path: "a", Mode: 0o644},
		wal.Record{Op: wal.OpCreate, Path: "b", Mode: 0o644},
	)
	deleted := inoAt(t, fs, "b")
	apply(t, fs, wal.Record{Op: wal.OpRemove, Path: "b"})
	state := fs.CaptureRecoveryState()
	if state.Allocator.MaxInoSeen < deleted {
		t.Fatalf("captured high-water %d below deleted id %d", state.Allocator.MaxInoSeen, deleted)
	}

	// "Restart": a fresh empty FS imports the captured allocator; the next
	// create allocates ABOVE the old high-water — the deleted id is dead.
	fs2 := newInoTestFS(t)
	if err := fs2.ImportAllocatorState(state.Allocator); err != nil {
		t.Fatal(err)
	}
	apply(t, fs2, wal.Record{Op: wal.OpCreate, Path: "fresh", Mode: 0o644})
	if got := inoAt(t, fs2, "fresh"); got <= state.Allocator.MaxInoSeen {
		t.Fatalf("post-import create ino %d, want > %d (deleted ids never return)", got, state.Allocator.MaxInoSeen)
	}

	// A compacted-manifest floor (PFT2 MaxInoSeen) imported as DurableFloor
	// dominates allocation even when the live tree never saw those ids.
	fs3 := newInoTestFS(t)
	if err := fs3.ImportAllocatorState(AllocatorState{Namespace: 0, NextLocal: 2, MaxInoSeen: 1, DurableFloor: 5000}); err != nil {
		t.Fatal(err)
	}
	apply(t, fs3, wal.Record{Op: wal.OpCreate, Path: "x", Mode: 0o644})
	if got := inoAt(t, fs3, "x"); got != 5001 {
		t.Fatalf("create above imported floor got ino %d, want 5001", got)
	}
	// Import is monotonic: re-importing an OLDER snapshot cannot lower state.
	if err := fs3.ImportAllocatorState(AllocatorState{Namespace: 0, NextLocal: 2, MaxInoSeen: 1}); err != nil {
		t.Fatal(err)
	}
	apply(t, fs3, wal.Record{Op: wal.OpCreate, Path: "y", Mode: 0o644})
	if got := inoAt(t, fs3, "y"); got != 5002 {
		t.Fatalf("create after stale re-import got ino %d, want 5002 (no regression)", got)
	}
}

// Delete → WAL restart → allocate: replay observes every logged identity, so
// the restarted allocator never re-hands a deleted id.
func TestAllocatorDeletedThenRestartThenAllocate(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.Open(filepath.Join(dir, "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	apply(t, fs,
		wal.Record{Op: wal.OpCreate, Path: "a", Mode: 0o644},
		wal.Record{Op: wal.OpCreate, Path: "doomed", Mode: 0o644},
	)
	doomed := inoAt(t, fs, "doomed")
	apply(t, fs, wal.Record{Op: wal.OpRemove, Path: "doomed"})
	if err := fileWAL(t, fs).Close(); err != nil {
		t.Fatal(err)
	}

	w2, err := wal.Open(filepath.Join(dir, "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs2, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w2)
	if err != nil {
		t.Fatal(err)
	}
	apply(t, fs2, wal.Record{Op: wal.OpCreate, Path: "next", Mode: 0o644})
	if got := inoAt(t, fs2, "next"); got <= doomed {
		t.Fatalf("post-restart create ino %d, want > deleted %d", got, doomed)
	}
}

// Namespace mismatch, torn state, and out-of-bounds imports are rejected
// without mutating the live allocator; invalid recovery references (unknown
// inode, unsorted, zero) are rejected before any state changes.
func TestAllocatorImportRejectsMismatchTornAndInvalid(t *testing.T) {
	fs := newInoTestFS(t)
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "a", Mode: 0o644})
	// Burn one identity completely (orphan + reap) so an id exists that is
	// below the high-water yet in NO table — the "unknown inode" reference.
	apply(t, fs, wal.Record{Op: wal.OpCreate, Path: "gap", Mode: 0o644})
	reaped := inoAt(t, fs, "gap")
	if _, err := fs.Orphan("gap", ""); err != nil {
		t.Fatal(err)
	}
	if err := fs.Reap(reaped, ""); err != nil {
		t.Fatal(err)
	}
	before := fs.CaptureRecoveryState().Allocator

	badAllocator := []struct {
		name  string
		state AllocatorState
	}{
		{"namespace-mismatch", AllocatorState{Namespace: 3, NextLocal: 1, MaxInoSeen: 1}},
		{"namespace-out-of-range", AllocatorState{Namespace: 1 << 31, NextLocal: 1, MaxInoSeen: 1}},
		{"next-local-zero", AllocatorState{Namespace: 0, NextLocal: 0, MaxInoSeen: 1}},
		{"next-local-overflow", AllocatorState{Namespace: 0, NextLocal: maxInodeLocalCounter + 2, MaxInoSeen: maxInodeLocalCounter}},
		{"high-water-overflow", AllocatorState{Namespace: 0, NextLocal: 2, MaxInoSeen: maxIno + 1}},
		{"floor-overflow", AllocatorState{Namespace: 0, NextLocal: 2, MaxInoSeen: 1, DurableFloor: maxIno + 1}},
		{"torn-last-above-high-water", AllocatorState{Namespace: 0, NextLocal: 100, MaxInoSeen: 5}},
	}
	for _, tc := range badAllocator {
		if err := fs.ImportAllocatorState(tc.state); err == nil {
			t.Fatalf("%s: import accepted invalid state %+v", tc.name, tc.state)
		}
	}
	if after := fs.CaptureRecoveryState().Allocator; after != before {
		t.Fatalf("rejected imports mutated the allocator: %+v -> %+v", before, after)
	}

	valid := AllocatorState{Namespace: 0, NextLocal: before.NextLocal, MaxInoSeen: before.MaxInoSeen}
	badRefs := []struct {
		name  string
		state RecoveryState
	}{
		{"orphan-zero", RecoveryState{Allocator: valid, OrphanInos: []uint64{0}}},
		{"orphan-not-parked", RecoveryState{Allocator: valid, OrphanInos: []uint64{inoAt(t, fs, "a")}}},
		{"orphan-above-high-water", RecoveryState{Allocator: valid, OrphanInos: []uint64{before.MaxInoSeen + 10}}},
		{"pin-unknown-inode", RecoveryState{Allocator: valid, PinnedInos: []uint64{reaped}}},
		{"pin-unsorted-duplicate", RecoveryState{Allocator: valid, PinnedInos: []uint64{1, 1}}},
	}
	for _, tc := range badRefs {
		if err := fs.ImportRecoveryState(tc.state); err == nil {
			t.Fatalf("%s: import accepted invalid refs %+v", tc.name, tc.state)
		}
	}
	if after := fs.CaptureRecoveryState().Allocator; after != before {
		t.Fatal("rejected recovery imports mutated the allocator")
	}

	// The success path: a real parked orphan + live pin round-trips.
	if _, err := fs.Orphan("a", ""); err != nil {
		t.Fatal(err)
	}
	state := fs.CaptureRecoveryState()
	if len(state.OrphanInos) != 1 {
		t.Fatalf("captured orphans %v, want exactly the parked inode", state.OrphanInos)
	}
	if err := fs.ImportRecoveryState(state); err != nil {
		t.Fatalf("round-trip import of own capture failed: %v", err)
	}
}

// Identity exhaustion fails BEFORE mutation: nothing is created, nothing is
// logged, and the allocator itself is unchanged by the failed attempts.
func TestAllocatorOverflowFailsBeforeMutation(t *testing.T) {
	fs := newInoTestFS(t)
	fs.mu.Lock()
	fs.alloc.maxInoSeen = maxInodeLocalCounter // flat namespace fully consumed
	fs.mu.Unlock()
	before := fs.CaptureRecoveryState().Allocator
	watermarkBefore := fileWAL(t, fs).Watermark()

	if err := fs.mutate(wal.Record{Op: wal.OpCreate, Path: "too-late", Mode: 0o644}); !errors.Is(err, ErrInodeExhausted) {
		t.Fatalf("create at exhaustion err = %v, want ErrInodeExhausted", err)
	}
	if err := fs.MkdirAll("d1/d2/d3", 0o755); !errors.Is(err, ErrInodeExhausted) {
		t.Fatalf("mkdir-all at exhaustion err = %v, want ErrInodeExhausted", err)
	}
	if fs.resolve("too-late") != nil || fs.resolve("d1") != nil {
		t.Fatal("exhausted allocation still mutated the tree")
	}
	if got := fileWAL(t, fs).Watermark(); got != watermarkBefore {
		t.Fatalf("exhausted allocation reached the WAL: watermark %d -> %d", watermarkBefore, got)
	}
	if after := fs.CaptureRecoveryState().Allocator; after != before {
		t.Fatalf("failed allocation mutated allocator: %+v -> %+v", before, after)
	}
	// The FS is NOT poisoned: ops that need no fresh identity still work.
	if _, _, err := fs.WriteAt("survivor", 0, nil, 0o644); !errors.Is(err, ErrInodeExhausted) {
		// WriteAt creates first — also exhausted; a write to an EXISTING
		// file must still succeed.
		t.Fatalf("unexpected: %v", err)
	}
}

// Rollback and lost-response (exact-once duplicate) replay never allocate a
// second inode or change a recorded outcome.
func TestRollbackAndDuplicateReplayNeverDoubleAllocate(t *testing.T) {
	// White-box rollback: a transaction that allocated during apply restores
	// the allocator (and the tree) exactly on rollback.
	fs := newInoTestFS(t)
	fs.mu.Lock()
	allocBefore := fs.alloc
	tx := newMutationTransaction(fs)
	rec := wal.Record{Op: wal.OpCreate, Path: "tx-file", Mode: 0o644, TsMs: 1}
	if err := tx.captureMutation(rec); err != nil {
		fs.mu.Unlock()
		t.Fatal(err)
	}
	if _, _, err := fs.applyMutationAs(rec, ""); err != nil {
		fs.mu.Unlock()
		t.Fatal(err)
	}
	if fs.alloc == allocBefore {
		fs.mu.Unlock()
		t.Fatal("apply did not allocate (test premise broken)")
	}
	tx.rollback()
	allocAfter := fs.alloc
	gone := fs.resolve("tx-file") == nil
	fs.mu.Unlock()
	if allocAfter != allocBefore {
		t.Fatalf("rollback did not restore allocator: %+v -> %+v", allocBefore, allocAfter)
	}
	if !gone {
		t.Fatal("rollback left the created dirent behind")
	}

	// Lost-response replay (managed exact-once): a duplicate retry returns
	// the recorded ino and does not advance the allocator.
	log := newFakeEntryLog()
	mfs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	ref := openManagedSession(t, mfs, "pfs-dup", 1)
	hash := make([]byte, 32)
	hash[0] = 0x5A
	rec2 := wal.Record{
		Op: wal.OpCreate, Path: "once.txt", Mode: 0o644,
		Env: &wal.Envelope{SessionID: ref.SessionID, Generation: ref.Generation, Slot: 0, SlotSeq: 1, ReqHash: hash},
	}
	first, err := mfs.MutateEnv(rec2, "")
	if err != nil {
		t.Fatal(err)
	}
	allocAfterFirst := mfs.CaptureRecoveryState().Allocator

	// The protocol's lost-response retry path: the consumed identity replays
	// its recorded outcome verbatim — same ino, no new allocation.
	if res, out := mfs.CheckSlot(rec2.Env); res != SlotDuplicate || out.Ino != first.Ino {
		t.Fatalf("duplicate replay: res=%v ino=%d, want recorded ino %d", res, out.Ino, first.Ino)
	}
	// A raw re-submission of the consumed identity is rejected at admission
	// (pre-reservation) — and must not allocate or change the outcome either.
	if _, err := mfs.MutateEnv(rec2, ""); err == nil {
		t.Fatal("re-submitted consumed identity was accepted as a new mutation")
	}
	if got := mfs.CaptureRecoveryState().Allocator; got != allocAfterFirst {
		t.Fatalf("duplicate handling advanced the allocator: %+v -> %+v", allocAfterFirst, got)
	}
	if res, out := mfs.CheckSlot(rec2.Env); res != SlotDuplicate || out.Ino != first.Ino {
		t.Fatalf("recorded outcome changed: res=%v ino=%d", res, out.Ino)
	}
}
