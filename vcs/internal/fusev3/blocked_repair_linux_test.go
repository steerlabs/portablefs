//go:build linux

package fusev3

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// Reporting a repair this mount cannot make.
//
// The condition is a genuine cycle: a peer's COMPLETE needs a name invalidated
// in directory D, invalidating a name takes D's i_rwsem for write, and one of
// this mount's own namespace syscalls is holding that semaphore while it waits
// for the authority to order it. Nobody can break it from inside -- the syscall
// is waiting on the authority, the authority is waiting on this repair.
//
// The authority cannot decide it alone. It sees the parked mutation, but its
// audience index is a monotone filter with no false negatives and therefore many
// false positives, so it cannot tell whether this mount holds the named binding
// at all; deciding from that half would fence mounts that could have repaired.
// This frontend holds both facts, so this frontend reports -- and only when both
// are true, because the authority treats an unsupported report as a cursor
// violation, and because saying nothing is always safe: the bound is then the
// repair budget this mount declared.

// blockedFixture is a strict frontend with one namespace mutation parked in a
// named directory, which is condition (1) of a reportable phase.
type blockedFixture struct {
	*strictFixture
	// directory is the volume-relative path of the parked directory, and
	// parentInode is the coordination inode a visibility target names it by.
	directory   string
	parentInode uint64
	nodeID      uint64
	// release lets the parked mutation finish. Every test defers it so the
	// mount tears down cleanly rather than leaving a goroutine on a dead
	// authority.
	release func()
}

// newBlockedFixture resolves whatever the test needs cached, THEN parks a
// namespace mutation in the directory. The order matters: the parked mutation is
// modelled by holding every authority call, so anything this mount is supposed
// to have cached has to be resolved while the authority is still answering --
// which is also the real sequence, since a mount caches names long before it
// happens to have a mutation outstanding.
func newBlockedFixture(t *testing.T, directory string, budget time.Duration, precache func(f *strictFixture, parentNodeID uint64)) *blockedFixture {
	t.Helper()
	f := newStrictFixture(t)
	f.rpc.byName = map[string]*authoritypb.Item{}
	f.rpc.mu.Lock()
	f.rpc.events = make(chan *authoritypb.VisibilityEvent, 4)
	f.rpc.mu.Unlock()

	parent := f.lookup(t, fuse.FUSE_ROOT_ID, directory)
	record := f.raw.acquire(parent.NodeId)
	if record == nil {
		t.Fatal("the directory under test was not interned")
	}
	parentInode := record.key.inode
	f.raw.release(record)
	if precache != nil {
		precache(f, parent.NodeId)
	}

	block := make(chan struct{})
	f.rpc.mu.Lock()
	f.rpc.block = block
	f.rpc.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		out := &fuse.EntryOut{}
		f.raw.Mkdir(nil, &fuse.MkdirIn{InHeader: fuse.InHeader{NodeId: parent.NodeId}, Mode: 0o755}, "child", out)
	}()
	waitFor(t, "the directory mutation to park in the authority", func() bool {
		return len(f.raw.parkedDirectories()) != 0
	})

	f.mount.wg.Add(1)
	go (&coherence{mount: f.mount, session: testSelfSession, budget: budget}).run(f.mount.ctx)

	var once sync.Once
	return &blockedFixture{
		strictFixture: f, directory: directory, parentInode: parentInode, nodeID: parent.NodeId,
		release: func() {
			once.Do(func() { close(block) })
			<-done
		},
	}
}

func (f *blockedFixture) reports() []*authoritypb.VisibilityCursor {
	f.rpc.mu.Lock()
	defer f.rpc.mu.Unlock()
	return append([]*authoritypb.VisibilityCursor(nil), f.rpc.blocked...)
}

func (f *blockedFixture) acks() int {
	f.rpc.mu.Lock()
	defer f.rpc.mu.Unlock()
	return len(f.rpc.acked)
}

// (a) the genuine cycle

func TestACompleteThisMountCannotRepairIsReportedAndEndsTheSession(t *testing.T) {
	// A budget far longer than this test will wait. If the mount reached the
	// fenced state by letting the budget expire instead of by reporting, the
	// assertions below would time out rather than pass.
	const budget = 5 * time.Minute
	// The binding the peer's COMPLETE names is one this mount really did cache,
	// in the very directory its own mkdir goes on to hold.
	f := newBlockedFixture(t, "packages", budget, func(f *strictFixture, parentNodeID uint64) {
		f.lookup(t, parentNodeID, "victim")
	})
	defer f.release()

	targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(f.parentInode, "victim")}
	f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE, testPeerSession, targets...)
	f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE, testPeerSession, targets...)

	started := time.Now()
	waitFor(t, "the mount to report that it cannot repair", func() bool { return len(f.reports()) == 1 })
	if elapsed := time.Since(started); elapsed > budget/10 {
		t.Fatalf("the report took %s of a %s budget; a blocked frontend must revoke immediately even though the authority retains the current obligation for its fencing grace", elapsed, budget)
	}
	if phase := f.reports()[0].GetPhase(); phase != authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE {
		t.Fatalf("reported phase = %v, want COMPLETE; PREPARE takes no lock this mount can be holding and is never reportable", phase)
	}

	// Reporting always ends the session. A mount that said it cannot repair must
	// stop serving what it can no longer take back.
	waitFor(t, "the mount to revoke itself after reporting", f.mount.isRevoked)
	if errno := f.mount.acquireBulk(context.Background()); errno != revokedErrno {
		t.Fatalf("a mount that reported itself blocked answered a request with %v, want %v", errno, revokedErrno)
	}
	waitFor(t, "the terminal cause to be recorded", func() bool { return f.mount.fatalError() != nil })
	cause := f.mount.fatalError().Error()
	if !strings.Contains(cause, f.directory) {
		t.Fatalf("terminal cause %q does not name the directory; the authority knows it only as a coordination identity, so naming it is the reason the frontend is the party that reports", cause)
	}
	for _, want := range []string{"i_rwsem", "unmount and mount again"} {
		if !strings.Contains(cause, want) {
			t.Fatalf("terminal cause %q does not mention %q", cause, want)
		}
	}
	// The COMPLETE was reported, not acknowledged: the report IS the
	// acknowledgment, and sending both would be a cursor violation.
	if acks := f.acks(); acks != 1 {
		t.Fatalf("acknowledgments = %d, want exactly 1 (the PREPARE); the COMPLETE was reported instead", acks)
	}
}

// (b) parked, but holding nothing this phase names

func TestAParkedMountThatHasNothingCachedAcknowledgesNormally(t *testing.T) {
	f := newBlockedFixture(t, "packages", 5*time.Minute, nil)
	defer f.release()

	// Same directory, same parked mutation -- but this mount never resolved the
	// name, so there is no binding to invalidate and no cycle. Reporting here
	// would fence a mount that had nothing to do, which is exactly the mistake
	// the authority cannot avoid on its own: its audience is full of names a
	// mount never looked up.
	targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(f.parentInode, "never-resolved")}
	f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE, testPeerSession, targets...)
	f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE, testPeerSession, targets...)

	waitFor(t, "both phases to be acknowledged normally", func() bool { return f.acks() == 2 })
	if reports := f.reports(); len(reports) != 0 {
		t.Fatalf("a mount with nothing cached reported itself blocked (%d times); not reporting is always safe, and an unsupported report is a cursor violation", len(reports))
	}
	if f.mount.isRevoked() {
		t.Fatal("a mount that could acknowledge normally was fenced")
	}
}

// (c) parked, but the phase touches only inode state

func TestAParkedMountStillRepairsDataAndAttributeTargets(t *testing.T) {
	var content uint64
	f := newBlockedFixture(t, "packages", 5*time.Minute, func(f *strictFixture, _ uint64) {
		entry := f.lookup(t, fuse.FUSE_ROOT_ID, "content")
		content = entry.Attr.Ino
	})
	defer f.release()

	// fuse_reverse_inval_inode takes no parent lock, so a parked mount can
	// always service data and attribute repair. A blanket "I am parked, I cannot
	// repair" would give up work it is perfectly able to do.
	targets := []*authoritypb.VisibilityTarget{
		inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, content, 16),
		inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, content, 0),
	}
	f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE, testPeerSession, targets...)
	f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE, testPeerSession, targets...)

	waitFor(t, "the inode repair to be made and acknowledged", func() bool { return f.acks() == 2 })
	if reports := f.reports(); len(reports) != 0 {
		t.Fatalf("a phase with only inode targets was reported as unrepairable %d times", len(reports))
	}
	if f.mount.isRevoked() {
		t.Fatal("a mount that repaired inode state normally was fenced")
	}
	f.notify.mu.Lock()
	defer f.notify.mu.Unlock()
	repaired := false
	for _, call := range f.notify.calls {
		if call.kind == "inode" {
			repaired = true
		}
	}
	if !repaired {
		t.Fatal("the inode repair was never made")
	}
}

// (d) cached, but in a directory whose lock is free

func TestACachedNameInAnUnparkedDirectoryIsRepairedNormally(t *testing.T) {
	// The binding is cached and the mount is parked -- but not in THIS
	// directory, so the semaphore the repair needs is free.
	f := newBlockedFixture(t, "packages", 5*time.Minute, func(f *strictFixture, _ uint64) {
		f.lookup(t, fuse.FUSE_ROOT_ID, "elsewhere")
	})
	defer f.release()

	targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(1, "elsewhere")}
	f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE, testPeerSession, targets...)
	f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE, testPeerSession, targets...)

	waitFor(t, "the name repair to be made and acknowledged", func() bool { return f.acks() == 2 })
	if reports := f.reports(); len(reports) != 0 {
		t.Fatalf("a repair in a directory this mount is not parked in was reported as blocked %d times", len(reports))
	}
	if f.mount.isRevoked() {
		t.Fatal("a mount that repaired a free directory normally was fenced")
	}
}
