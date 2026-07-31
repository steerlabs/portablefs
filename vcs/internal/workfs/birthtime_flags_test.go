package workfs

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// The two metadata facts the authority now OWNS rather than leaving to a
// client convention: a per-inode birth time stamped once at creation, and a
// per-inode BSD file-flag word set by chflags(2). Both ride the Sys()
// interfaces the protocol layer's attrOf already probes.
type birthFlagInfo interface {
	BirthTime() time.Time
	Flags() uint32
}

func statBirthFlags(t *testing.T, fs *FS, name string) (time.Time, uint32) {
	t.Helper()
	fi, err := fs.Stat(name)
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	sys, ok := fi.Sys().(birthFlagInfo)
	if !ok {
		t.Fatalf("stat %s: FileInfo exposes neither a birth time nor flags", name)
	}
	return sys.BirthTime(), sys.Flags()
}

func statIno(t *testing.T, fs *FS, name string) uint64 {
	t.Helper()
	fi, err := fs.Stat(name)
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	return fi.Sys().(interface{ Ino() uint64 }).Ino()
}

// TestBirthTimeIsStampedAtCreateAndNeverMoves is the root-behavior proof for
// the birth time: it is a REAL stored fact, not mtime read under a different
// name. Every later mutation deliberately advances mtime (and, where POSIX says
// so, ctime) while the birth time stays pinned to the creating record — so a
// test that merely compared birth to mtime after a create could not tell the
// two apart, but this one can.
func TestBirthTimeIsStampedAtCreateAndNeverMoves(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})

	f, err := fs.Create("f")
	if err != nil {
		t.Fatal(err)
	}
	birth, flags := statBirthFlags(t, fs, "f")
	if birth.IsZero() {
		t.Fatal("a freshly created inode reported no birth time")
	}
	if flags != 0 {
		t.Fatalf("a freshly created inode reported flags %#x, want 0", flags)
	}
	mtime0, _, _ := statTimes(t, fs, "f")
	if birth.UnixMilli() != mtime0.UnixMilli() {
		t.Fatalf("birth %d must equal the creating record's time %d", birth.UnixMilli(), mtime0.UnixMilli())
	}

	// Advance the clock past the creation millisecond, then move mtime with
	// every kind of mutation. If birth were being derived from mtime, each of
	// these would drag it forward.
	waitAfterMs(t, mtime0)
	if _, err := f.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if err := fs.Chmod("f", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpTruncate, Path: "f", Size: 2}, ""); err != nil {
		t.Fatal(err)
	}
	if err := fs.Chtimes("f", time.UnixMilli(1900000000000), time.UnixMilli(1900000000000)); err != nil {
		t.Fatal(err)
	}

	mtime1, _, _ := statTimes(t, fs, "f")
	if mtime1.UnixMilli() == mtime0.UnixMilli() {
		t.Fatal("mtime did not move; the test cannot distinguish birth from mtime")
	}
	afterBirth, _ := statBirthFlags(t, fs, "f")
	if afterBirth.UnixMilli() != birth.UnixMilli() {
		t.Fatalf("birth time moved to %d after write/chmod/truncate/chtimes, want %d",
			afterBirth.UnixMilli(), birth.UnixMilli())
	}
	if afterBirth.UnixMilli() == mtime1.UnixMilli() {
		t.Fatalf("birth time %d coincides with the advanced mtime — it is being derived, not stored",
			afterBirth.UnixMilli())
	}
}

// TestBirthTimeAndFlagsSurviveRenameAndHardLink: both facts belong to the
// INODE, so neither a new name nor a second name disturbs them.
func TestBirthTimeAndFlagsSurviveRenameAndHardLink(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	f, err := fs.Create("orig")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("payload"))
	_ = f.Close()
	if err := fs.MutateAs(wal.Record{Op: wal.OpChflags, Path: "orig", Flags: 0x8000}, ""); err != nil {
		t.Fatal(err)
	}
	birth, flags := statBirthFlags(t, fs, "orig")
	if flags != 0x8000 {
		t.Fatalf("flags = %#x, want 0x8000", flags)
	}
	ino := statIno(t, fs, "orig")

	mtimeBefore, _, _ := statTimes(t, fs, "orig")
	waitAfterMs(t, mtimeBefore)

	if err := fs.Rename("orig", "renamed"); err != nil {
		t.Fatal(err)
	}
	gotBirth, gotFlags := statBirthFlags(t, fs, "renamed")
	if gotBirth.UnixMilli() != birth.UnixMilli() || gotFlags != flags {
		t.Fatalf("after rename birth=%d flags=%#x, want %d/%#x",
			gotBirth.UnixMilli(), gotFlags, birth.UnixMilli(), flags)
	}

	if err := fs.Link("renamed", "alias"); err != nil {
		t.Fatal(err)
	}
	aliasBirth, aliasFlags := statBirthFlags(t, fs, "alias")
	if aliasBirth.UnixMilli() != birth.UnixMilli() || aliasFlags != flags {
		t.Fatalf("hard link birth=%d flags=%#x, want %d/%#x",
			aliasBirth.UnixMilli(), aliasFlags, birth.UnixMilli(), flags)
	}
	if statIno(t, fs, "alias") != ino {
		t.Fatal("the hard link does not share the source inode")
	}
}

// TestChflagsPersistsAcrossManagedJournalReplay is the durability proof on the
// store whose replay is DETERMINISTIC: the managed reducer times every record
// by its stamped op time (replayTs), so a replacement authority replaying the
// same journal reconstructs both the flag word and the birth time exactly —
// not approximately, and not re-clocked.
func TestChflagsPersistsAcrossManagedJournalReplay(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	commitTree(t, fs, wal.Record{Op: wal.OpCreate, Path: "locked", Mode: 0o644})
	commitTree(t, fs, wal.Record{Op: wal.OpCreate, Path: "cleared", Mode: 0o644})

	// UF_IMMUTABLE|UF_HIDDEN plus a high bit: the authority stores the FULL
	// uint32 it was handed, because bit policy lives client-side.
	const stored = uint32(0x8000_8002)
	commitTree(t, fs, wal.Record{Op: wal.OpChflags, Path: "locked", Flags: stored})
	// Clearing back to zero is itself a durable state, not an absence replay
	// could confuse with "never set".
	commitTree(t, fs, wal.Record{Op: wal.OpChflags, Path: "cleared", Flags: 0x2})
	commitTree(t, fs, wal.Record{Op: wal.OpChflags, Path: "cleared", Flags: 0})

	// Later mutations move mtime; neither the flag word nor the birth time
	// may follow.
	commitTree(t, fs, wal.Record{Op: wal.OpWrite, Path: "locked", Data: []byte("bytes")})
	commitTree(t, fs, wal.Record{Op: wal.OpChmod, Path: "locked", Mode: 0o600})

	lockedBirth, lockedFlags := statBirthFlags(t, fs, "locked")
	if lockedFlags != stored {
		t.Fatalf("flags = %#x, want %#x (no server-side masking)", lockedFlags, stored)
	}
	if lockedBirth.IsZero() {
		t.Fatal("managed create stamped no birth time")
	}
	clearedBirth, clearedFlags := statBirthFlags(t, fs, "cleared")
	if clearedFlags != 0 {
		t.Fatalf("cleared flags = %#x, want 0", clearedFlags)
	}

	// Failover: a replacement authority replays the identical journal cold.
	fs2, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatalf("failover replay: %v", err)
	}
	replayedBirth, replayedFlags := statBirthFlags(t, fs2, "locked")
	if replayedFlags != stored {
		t.Fatalf("replayed flags = %#x, want %#x", replayedFlags, stored)
	}
	if replayedBirth.UnixMilli() != lockedBirth.UnixMilli() {
		t.Fatalf("replayed birth = %d, want %d (the record's stamped op time, not a fresh clock)",
			replayedBirth.UnixMilli(), lockedBirth.UnixMilli())
	}
	replayedClearBirth, replayedClearFlags := statBirthFlags(t, fs2, "cleared")
	if replayedClearFlags != 0 {
		t.Fatalf("replayed cleared flags = %#x, want 0", replayedClearFlags)
	}
	if replayedClearBirth.UnixMilli() != clearedBirth.UnixMilli() {
		t.Fatalf("replayed cleared birth = %d, want %d", replayedClearBirth.UnixMilli(), clearedBirth.UnixMilli())
	}

	// Replaying the SAME journal a third time lands on the same state: the
	// stamped op times make the apply idempotent rather than re-clocked.
	fs3, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	againBirth, againFlags := statBirthFlags(t, fs3, "locked")
	if againFlags != replayedFlags || againBirth.UnixMilli() != replayedBirth.UnixMilli() {
		t.Fatalf("second replay diverged: birth=%d flags=%#x", againBirth.UnixMilli(), againFlags)
	}
}

// TestChflagsBindsTheFlagWordToItsOp keeps the appended record field pinned to
// the op that owns it at the authority's ingress gate: no other mutation may
// smuggle a flag word past admission.
func TestChflagsBindsTheFlagWordToItsOp(t *testing.T) {
	fs, err := NewManaged(nil, nil, newFakeEntryLog())
	if err != nil {
		t.Fatal(err)
	}
	commitTree(t, fs, wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644})
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpChmod, Path: "f", Mode: 0o600, Flags: 0x2}, nil, ""); err == nil {
		t.Fatal("a chmod carrying a flag word was admitted")
	}
	// A chflags on a missing path is a deterministic per-leaf ENOENT outcome,
	// never an authority fault.
	if res, err := fs.managedMutateEnvLikeForTest(wal.Record{Op: wal.OpChflags, Path: "missing", Flags: 0x2}); err != nil {
		t.Fatalf("managed chflags on a missing path: %v", err)
	} else if !os.IsNotExist(res) {
		t.Fatalf("managed chflags outcome = %v, want ErrNotExist", res)
	}
}

// TestDurablePft2BaseCarriesBirthTimeAndFlags closes the loop through the
// STORAGE FORMAT: records fold into an immutable PFT2 base through the shared
// transition engine, a replacement authority adopts that base cold, and the
// hydrated inodes report the birth time and flag word the tree stored. Without
// the format revision this test cannot pass — there would be nowhere for either
// fact to live between the fold and the adopt.
func TestDurablePft2BaseCarriesBirthTimeAndFlags(t *testing.T) {
	base := buildLazyTestBase(t, []wal.Record{
		{Op: wal.OpMkdir, Path: "dir", Mode: 0o755},
		{Op: wal.OpCreate, Path: "dir/f", Mode: 0o644},
		{Op: wal.OpChflags, Path: "dir/f", Flags: 0x8000_0002},
		// mtime moves after the flag word is set; birth must not follow.
		{Op: wal.OpWrite, Path: "dir/f", Data: []byte("bytes"), TsMs: lazyTsBase + 5_000},
	})
	fs, _ := newLazyFS(t, base, newFakeEntryLog())

	birth, flags := statBirthFlags(t, fs, "dir/f")
	if flags != 0x8000_0002 {
		t.Fatalf("adopted flags = %#x, want 0x80000002", flags)
	}
	if birth.UnixMilli() != lazyTsBase {
		t.Fatalf("adopted birth = %d, want the creating record's op time %d", birth.UnixMilli(), lazyTsBase)
	}
	mtime, _, _ := statTimes(t, fs, "dir/f")
	if mtime.UnixMilli() != lazyTsBase+5_000 {
		t.Fatalf("adopted mtime = %d, want %d", mtime.UnixMilli(), lazyTsBase+5_000)
	}
	if birth.UnixMilli() == mtime.UnixMilli() {
		t.Fatal("birth coincides with the advanced mtime — the base is not storing it")
	}
	dirBirth, _ := statBirthFlags(t, fs, "dir")
	if dirBirth.UnixMilli() != lazyTsBase {
		t.Fatalf("adopted directory birth = %d, want %d", dirBirth.UnixMilli(), lazyTsBase)
	}
}

// buildLegacyPft2Base writes a base the way a PRE-REVISION authority did:
// inodes with no birth time and no flag word (both fields simply absent from
// the encoding). It is the fixture for the format's backward direction.
func buildLegacyPft2Base(t *testing.T) *lazyTestBase {
	t.Helper()
	ctx := context.Background()
	store := pft2.NewMemoryStore()
	editor, err := pft2.NewEditor(ctx, nil, nil, pft2.EditorLimits{})
	if err != nil {
		t.Fatal(err)
	}
	root := pft2.Inode{
		Ino: pft2.RootIno, Kind: pft2.FileKindDirectory, Mode: 0o755, Nlink: 1,
		MtimeMs: lazyTsBase, CtimeMs: lazyTsBase, AtimeMs: lazyTsBase,
	}
	child := pft2.Inode{
		Ino: 2, Kind: pft2.FileKindRegular, Mode: 0o644, Nlink: 1,
		MtimeMs: lazyTsBase, CtimeMs: lazyTsBase, AtimeMs: lazyTsBase,
	}
	if err := editor.PutInode(ctx, root); err != nil {
		t.Fatal(err)
	}
	if err := editor.PutInode(ctx, child); err != nil {
		t.Fatal(err)
	}
	if err := editor.PutDirEntry(ctx, pft2.RootIno, pft2.DirEntry{Name: "old", Ino: 2, Kind: pft2.FileKindRegular}); err != nil {
		t.Fatal(err)
	}
	res, err := editor.Commit(ctx, store, store)
	if err != nil {
		t.Fatal(err)
	}
	return &lazyTestBase{store: store, root: res.Root, facts: res.RootFacts, paths: []string{"old"}}
}

// TestLegacyPft2BaseHydratesWithUnknownBirthTimeAndNoFlags is the backward
// half of the compat contract: a tree written before fields 14/15 existed still
// adopts, and its inodes report the ABSENT sentinel — a zero birth time the
// protocol layer leaves at 0 so the client keeps its own convention, and a zero
// flag word — rather than a fabricated 1970 creation.
func TestLegacyPft2BaseHydratesWithUnknownBirthTimeAndNoFlags(t *testing.T) {
	fs, _ := newLazyFS(t, buildLegacyPft2Base(t), newFakeEntryLog())

	birth, flags := statBirthFlags(t, fs, "old")
	if !birth.IsZero() {
		t.Fatalf("legacy inode reported birth %d, want the zero/unknown sentinel", birth.UnixMilli())
	}
	if flags != 0 {
		t.Fatalf("legacy inode reported flags %#x, want 0", flags)
	}
	mtime, _, _ := statTimes(t, fs, "old")
	if mtime.UnixMilli() != lazyTsBase {
		t.Fatalf("legacy mtime = %d, want %d", mtime.UnixMilli(), lazyTsBase)
	}

	// A chflags on an inode from the old tree still takes: the fields are
	// per-inode, so an upgrade needs no migration pass.
	commitTree(t, fs, wal.Record{Op: wal.OpChflags, Path: "old", Flags: 0x2})
	if _, flags := statBirthFlags(t, fs, "old"); flags != 0x2 {
		t.Fatalf("flags after chflags on a legacy inode = %#x, want 0x2", flags)
	}
	if birth, _ := statBirthFlags(t, fs, "old"); !birth.IsZero() {
		t.Fatalf("chflags invented a birth time %d for a legacy inode", birth.UnixMilli())
	}
}
