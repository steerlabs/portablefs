package clientcore

// Semantic authority diversions, and the structural guarantee that none of them
// can put a delegation release beneath a frontend lock.
//
// A delegation answers "is this name inside a grant I hold?". For most
// mutations that is the whole classification. For four of them it is not:
// link(2), unlink-while-open, rename over an open destination and setattr on a
// hard-linked inode are AUTHORITY-ONLY BY SEMANTICS — the handler diverts to the
// write-through lane whatever any grant says. Classifying those from path
// coverage produced LaneDelegated, and the handler then discovered the diversion
// INSIDE the frontend's namespace and name locks and drained the covering
// delegations there.
//
// Two things close it, and both are tested here: the intent classifier decides
// the diversion out of the locks, and beginAuthorityMutation refuses to perform
// one under them at all.

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// TestLinkAdmissionResolvesTheAuthorityLaneOutOfTheLocks is the auditor's
// hard-link interleaving. A link whose operands are both covered by one retained
// grant classified LaneDelegated on path coverage alone; Volume.Link then
// discovered — unconditionally, because one hard-linked inode may span
// delegation scopes — that it had to release, and took that drain under the
// caller's nsMu and name stripes.
func TestLinkAdmissionResolvesTheAuthorityLaneOutOfTheLocks(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{})
	watchInvalidationsForTest(t, v)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	if _, st := v.Create(ctx, "d/a", 0o644); st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	if !v.wb.Covers("d/a") {
		t.Skip("the seed create did not install a delegation; the interleaving needs one")
	}

	// Exactly what a frontend does before it takes a single lock. Both operands
	// are inside the retained grant, and the source has nlink == 1, so nothing
	// about the PATHS says this cannot be delegated.
	opCtx, settle, err := v.AdmitMutation(
		ctx, MutationIntent{Kind: MutationLink}, nil, false, "d/a", "d/b",
	)
	if err != nil {
		t.Fatalf("classify link: %v", err)
	}
	defer settle()

	if lane := writeback.LaneOf(opCtx); lane != writeback.LaneAuthority {
		t.Fatalf("link classified lane %v, want LaneAuthority: link(2) always "+
			"releases every scope covering either end, so a delegated answer "+
			"guarantees that release happens under the frontend's locks instead "+
			"of out here", lane)
	}
	if v.wb.Covers("d/a") || v.wb.Covers("d/b") {
		t.Fatal("the classifier resolved the authority lane without releasing " +
			"the operand scopes; the release is still owed inside the locks")
	}
}

// TestUnlinkWhileOpenAdmissionResolvesTheAuthorityLane is the same defect on the
// orphan protocol, which never runs INSIDE a held delegation.
func TestUnlinkWhileOpenAdmissionResolvesTheAuthorityLane(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{})
	watchInvalidationsForTest(t, v)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	attr, st := v.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	if !v.wb.Covers("d/f") {
		t.Skip("the seed create did not install a delegation; the interleaving needs one")
	}
	n := NewNodeState(attr.Ino, attr.Ino != 0)
	if st := v.Open(ctx, "d/f", n, true); st != fsproto.OK {
		t.Fatalf("open: %d", st)
	}
	defer v.CloseHandle("d/f", n)

	opCtx, settle, err := v.AdmitMutation(
		ctx, MutationIntent{Kind: MutationUnlink, Target: n}, []*NodeState{n}, false, "d/f",
	)
	if err != nil {
		t.Fatalf("classify unlink: %v", err)
	}
	defer settle()
	if lane := writeback.LaneOf(opCtx); lane != writeback.LaneAuthority {
		t.Fatalf("unlink-while-open classified lane %v, want LaneAuthority: the "+
			"orphan protocol runs write-through and cannot run inside a held "+
			"grant, so Volume.Remove would have released under the locks", lane)
	}
}

// TestDelegatedLaneCannotBeginAnAuthorityMutation is the structural half, and it
// is what makes the class impossible rather than merely rare. Whatever route
// discovers that a frontend-locked operation needs the authority lane — a node
// that became a hard-link alias, an open handle that appeared, an engine that
// cannot acknowledge locally — the answer beneath the locks is the unwind, never
// the claim and never the drain.
func TestDelegatedLaneCannotBeginAnAuthorityMutation(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	delegatedCtx := writeback.WithResolvedLane(ctx, writeback.LaneDelegated)
	_, _, err := v.beginAuthorityMutation(delegatedCtx, nil, "d/f")
	if err == nil {
		t.Fatal("a delegated-lane operation was allowed to begin an authority " +
			"mutation inside the frontend's locks: it would take the transition " +
			"claim (a wait) and release every operand (a drain) with a.nsMu held")
	}
	if st := statusErr(err); !LaneChanged(st) {
		t.Fatalf("delegated-lane authority mutation = %v (status %d), want the "+
			"ErrLaneChanged unwind", err, st)
	}
}

// TestSemanticAuthorityLaneCoversEveryDivertingOperation pins the classifier
// against the diversions the handlers actually perform. Each row names a
// handler arm; if one is ever added or removed without updating the classifier,
// the release it implies goes back under the locks.
func TestSemanticAuthorityLaneCoversEveryDivertingOperation(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{})

	plain := NewNodeState(1001, true)
	open := NewNodeState(1002, true)
	open.mu.Lock()
	open.nopen = 1
	open.mu.Unlock()
	orphan := NewNodeState(1003, true)
	orphan.orphanIno.Store(9999)
	linked := NewNodeState(1004, true)
	v.hardlinks.observe("d/x", fsproto.Attr{Ino: 1004, Kind: "file", Nlink: 2})
	sameA := NewNodeState(1005, true)
	sameB := NewNodeState(1005, true)

	cases := []struct {
		name   string
		intent MutationIntent
		want   bool
	}{
		{"link is always authority-only", MutationIntent{Kind: MutationLink}, true},
		{"link of a plain node is still authority-only", MutationIntent{Kind: MutationLink, Source: plain}, true},
		{"unlink of a closed plain node is path-classified", MutationIntent{Kind: MutationUnlink, Target: plain}, false},
		{"unlink while open needs the orphan protocol", MutationIntent{Kind: MutationUnlink, Target: open}, true},
		{"unlink of a hard-linked inode spans scopes", MutationIntent{Kind: MutationUnlink, Target: linked}, true},
		{"rename over an open destination needs the orphan protocol", MutationIntent{Kind: MutationRename, Source: plain, Target: open}, true},
		{"rename of an open SOURCE is ordinary", MutationIntent{Kind: MutationRename, Source: open, Target: nil}, false},
		{"rename of two names for one inode is a POSIX no-op", MutationIntent{Kind: MutationRename, Source: sameA, Target: sameB}, true},
		{"rename onto a hard-linked destination spans scopes", MutationIntent{Kind: MutationRename, Source: plain, Target: linked}, true},
		{"ordinary rename is path-classified", MutationIntent{Kind: MutationRename, Source: plain}, false},
		{"setattr on a hard-linked inode spans scopes", MutationIntent{Kind: MutationSetattr, Target: linked}, true},
		{"setattr on an orphan is inode-addressed", MutationIntent{Kind: MutationSetattr, Target: orphan}, true},
		{"setattr on an open plain node is path-classified", MutationIntent{Kind: MutationSetattr, Target: open}, false},
		{"a create has no diversion", MutationIntent{Kind: MutationOther, Target: plain}, false},
	}
	for _, tc := range cases {
		if got := v.semanticAuthorityLane(tc.intent); got != tc.want {
			t.Errorf("%s: semanticAuthorityLane = %v, want %v", tc.name, got, tc.want)
		}
	}
}
