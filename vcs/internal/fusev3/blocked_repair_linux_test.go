//go:build linux

package fusev3

import (
	"context"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// Draining a parent-exclusive callback before repair.
//
// The condition is a genuine cycle: a peer's COMPLETE needs a name invalidated
// in directory D, invalidating a name takes D's i_rwsem for write, and one of
// this mount's own namespace syscalls is holding that semaphore while it waits
// for the authority to order it. COMPLETE breaks that cycle at its only clean
// edge: it closes local admission, asks the authority to refuse the already-
// admitted operation before apply, drains it, and then notifies the kernel.
//
// The authority cannot decide it alone. It sees the parked mutation, but its
// audience index is a monotone filter with no false negatives and therefore many
// false positives, so it cannot tell whether this mount holds the named binding
// at all; deciding from that half would fence mounts that could have repaired.
// This frontend holds both facts, so only it can arm the exact parent scope. A
// false-positive audience match therefore neither interrupts an operation nor
// fences a mount.

// blockedFixture is a strict frontend with one namespace mutation parked in a
// named directory, which is condition (1) of a reportable phase.
type blockedFixture struct {
	*strictFixture
	// parentInode is the coordination inode a visibility target names the parked
	// directory by.
	parentInode uint64
	// release lets the parked mutation finish. Every test defers it so the
	// mount tears down cleanly rather than leaving a goroutine on a dead
	// authority.
	release func()
	status  <-chan fuse.Status
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
	done := make(chan fuse.Status, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		out := &fuse.EntryOut{}
		done <- f.mkdir(parent.NodeId, "child", out)
	}()
	waitFor(t, "the directory mutation to park in the authority", func() bool {
		return len(f.raw.parkedDirectories()) != 0
	})

	f.mount.wg.Add(1)
	go (&coherence{mount: f.mount, session: testSelfSession, budget: budget}).run(f.mount.ctx)

	var once sync.Once
	return &blockedFixture{
		strictFixture: f, parentInode: parentInode,
		status: done,
		release: func() {
			once.Do(func() { close(block) })
			<-finished
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

// (a) an admitted callback in the exact repair parent is interrupted, not fenced

func TestACompleteInterruptsTheOverlappingOperationAndRepairs(t *testing.T) {
	const budget = 5 * time.Minute
	// The binding the peer's COMPLETE names is one this mount really did cache,
	// in the very directory its own mkdir goes on to hold.
	f := newBlockedFixture(t, "packages", budget, func(f *strictFixture, parentNodeID uint64) {
		f.lookup(t, parentNodeID, "victim")
	})
	defer f.release()
	f.rpc.mu.Lock()
	f.rpc.onBlocked = func() {
		f.rpc.mu.Lock()
		f.rpc.mkdirFailure = syscall.EINTR
		f.rpc.mu.Unlock()
		f.release()
	}
	f.rpc.mu.Unlock()

	targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(f.parentInode, "victim")}
	f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE, testPeerSession, targets...)
	f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE, testPeerSession, targets...)

	waitFor(t, "the mount to request a pre-apply cycle break", func() bool { return len(f.reports()) == 1 })
	if phase := f.reports()[0].GetPhase(); phase != authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE {
		t.Fatalf("reported phase = %v, want COMPLETE; PREPARE takes no lock this mount can be holding and is never reportable", phase)
	}
	f.rpc.mu.Lock()
	reportedParents := f.rpc.blockedParents
	f.rpc.mu.Unlock()
	if len(reportedParents) != 1 || len(reportedParents[0]) != 1 ||
		reportedParents[0][0] != targets[0].GetParentKernelIno() {
		t.Fatalf("reported parents = %v, want exact kernel parent %d", reportedParents, targets[0].GetParentKernelIno())
	}
	waitFor(t, "both phases to be acknowledged after the drain", func() bool { return f.acks() == 2 })
	select {
	case status := <-f.status:
		if status != fuse.Status(syscall.EINTR) {
			t.Fatalf("overlapping mkdir = %v, want definite pre-apply EINTR", status)
		}
	case <-time.After(time.Second):
		t.Fatal("the authority cycle break did not release the parked mkdir")
	}
	if f.mount.isRevoked() {
		t.Fatalf("one pre-apply namespace interruption revoked the mount: %v", f.mount.fatalError())
	}
	if calls := f.notify.snapshot(); len(calls) != 1 || calls[0].kind != "delete" || calls[0].name != "victim" {
		t.Fatalf("repairs = %+v, want the exact cached binding invalidated after the parked callback drained", calls)
	}
}

func TestRepairGateRefusesLaterSameParentBeforeAuthorityRPC(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.byName = map[string]*authoritypb.Item{}
	parent := f.lookup(t, fuse.FUSE_ROOT_ID, "packages")
	f.lookup(t, parent.NodeId, "victim")
	targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(parent.Attr.Ino, "victim")}
	if err := f.raw.prepareVisibility(context.Background(), targets, false); err != nil {
		t.Fatal(err)
	}
	completion, blocked, err := f.raw.beginVisibilityComplete(targets, false)
	if err != nil {
		t.Fatal(err)
	}
	if blocked {
		t.Fatal("a repair with no admitted callback was reported blocked")
	}
	f.rpc.mu.Lock()
	before := f.rpc.calls
	f.rpc.mu.Unlock()
	status := f.mkdir(parent.NodeId, "later", &fuse.EntryOut{})
	if status != fuse.Status(syscall.EINTR) {
		t.Fatalf("same-parent mkdir after the repair gate = %v, want EINTR", status)
	}
	f.rpc.mu.Lock()
	after := f.rpc.calls
	f.rpc.mu.Unlock()
	if after != before {
		t.Fatalf("refused callback made %d authority calls, want zero", after-before)
	}
	if err := f.raw.finishVisibilityComplete(context.Background(), completion); err != nil {
		t.Fatal(err)
	}
	if status := f.mkdir(parent.NodeId, "after", &fuse.EntryOut{}); !status.Ok() {
		t.Fatalf("same-parent mkdir after COMPLETE reopened admission = %v", status)
	}
}

func TestRepairGateIsExactToCachedWorkAndParent(t *testing.T) {
	t.Run("different parent", func(t *testing.T) {
		f := newStrictFixture(t)
		f.rpc.byName = map[string]*authoritypb.Item{}
		first := f.lookup(t, fuse.FUSE_ROOT_ID, "first")
		second := f.lookup(t, fuse.FUSE_ROOT_ID, "second")
		f.lookup(t, first.NodeId, "victim")
		targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(first.Attr.Ino, "victim")}
		completion, _, err := f.raw.beginVisibilityComplete(targets, false)
		if err != nil {
			t.Fatal(err)
		}
		if status := f.mkdir(second.NodeId, "allowed", &fuse.EntryOut{}); !status.Ok() {
			t.Fatalf("different-parent mkdir = %v, want success", status)
		}
		if err := f.raw.finishVisibilityComplete(context.Background(), completion); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("unpublished namespace target", func(t *testing.T) {
		f := newStrictFixture(t)
		f.rpc.byName = map[string]*authoritypb.Item{}
		parent := f.lookup(t, fuse.FUSE_ROOT_ID, "packages")
		targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(parent.Attr.Ino, "never-cached")}
		completion, blocked, err := f.raw.beginVisibilityComplete(targets, false)
		if err != nil {
			t.Fatal(err)
		}
		if blocked || len(completion.parents) != 0 {
			t.Fatalf("unpublished target armed parents=%v blocked=%v", completion.parents, blocked)
		}
		if status := f.mkdir(parent.NodeId, "allowed", &fuse.EntryOut{}); !status.Ok() {
			t.Fatalf("same-parent mkdir with no exact cached repair = %v", status)
		}
		if err := f.raw.finishVisibilityComplete(context.Background(), completion); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("inode-only target", func(t *testing.T) {
		f := newStrictFixture(t)
		f.rpc.byName = map[string]*authoritypb.Item{}
		parent := f.lookup(t, fuse.FUSE_ROOT_ID, "packages")
		targets := []*authoritypb.VisibilityTarget{inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, parent.Attr.Ino, 0)}
		completion, blocked, err := f.raw.beginVisibilityComplete(targets, false)
		if err != nil {
			t.Fatal(err)
		}
		if blocked || len(completion.parents) != 0 {
			t.Fatalf("inode repair armed namespace parents=%v blocked=%v", completion.parents, blocked)
		}
		if status := f.mkdir(parent.NodeId, "allowed", &fuse.EntryOut{}); !status.Ok() {
			t.Fatalf("mkdir beside inode-only repair = %v", status)
		}
		if err := f.raw.finishVisibilityComplete(context.Background(), completion); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRepairGateRefusesRenameWhenEitherParentIsRepairing(t *testing.T) {
	for _, repairOld := range []bool{true, false} {
		name := "new parent"
		if repairOld {
			name = "old parent"
		}
		t.Run(name, func(t *testing.T) {
			f := newStrictFixture(t)
			f.rpc.byName = map[string]*authoritypb.Item{}
			oldParent := f.lookup(t, fuse.FUSE_ROOT_ID, "old")
			newParent := f.lookup(t, fuse.FUSE_ROOT_ID, "new")
			repairParent := newParent
			if repairOld {
				repairParent = oldParent
			}
			f.lookup(t, repairParent.NodeId, "victim")
			targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(repairParent.Attr.Ino, "victim")}
			completion, _, err := f.raw.beginVisibilityComplete(targets, false)
			if err != nil {
				t.Fatal(err)
			}
			status := f.rename(oldParent.NodeId, newParent.NodeId, "source", "dest", 0)
			if status != fuse.Status(syscall.EINTR) {
				t.Fatalf("rename with repairing %s = %v, want EINTR", name, status)
			}
			if err := f.raw.finishVisibilityComplete(context.Background(), completion); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParentRepairAdmissionLinearizesEveryRace(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.byName = map[string]*authoritypb.Item{}
	parent := f.lookup(t, fuse.FUSE_ROOT_ID, "packages")
	parentRecord := f.raw.acquire(parent.NodeId)
	if parentRecord == nil {
		t.Fatal("parent was not interned")
	}
	defer f.raw.release(parentRecord)
	targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(parent.Attr.Ino, "victim")}
	victim := f.lookup(t, parent.NodeId, "victim")
	victimRecord := f.raw.acquire(victim.NodeId)
	if victimRecord == nil {
		t.Fatal("victim was not interned")
	}
	defer f.raw.release(victimRecord)
	key := nameKey{parent: parent.Attr.Ino, name: "victim"}

	for iteration := 0; iteration < 1000; iteration++ {
		// Republish the exact registry fact each COMPLETE will own. The real
		// lookup path establishing it is tested separately; doing 1,000 synthetic
		// authority lookups here would test reclaim backpressure, not this lock.
		f.raw.mu.Lock()
		f.raw.cachedNames[key] = victimRecord
		if victimRecord.names == nil {
			victimRecord.names = make(map[nameKey]struct{})
		}
		victimRecord.names[key] = struct{}{}
		f.raw.mu.Unlock()
		start := make(chan struct{})
		release := make(chan struct{})
		admitted := make(chan syscall.Errno, 1)
		go func() {
			<-start
			leave, errno := f.raw.enterParentExclusive(parentRecord)
			admitted <- errno
			if errno == 0 {
				<-release
				leave()
			}
		}()
		type begun struct {
			completion visibilityCompletion
			blocked    bool
			err        error
		}
		begunResult := make(chan begun, 1)
		go func() {
			<-start
			completion, blocked, err := f.raw.beginVisibilityComplete(targets, false)
			begunResult <- begun{completion: completion, blocked: blocked, err: err}
		}()
		close(start)
		errno := <-admitted
		result := <-begunResult
		if result.err != nil {
			t.Fatalf("iteration %d begin COMPLETE: %v", iteration, result.err)
		}
		switch errno {
		case 0:
			if !result.blocked {
				t.Fatalf("iteration %d admitted callback won but COMPLETE did not see it parked", iteration)
			}
		case syscall.EINTR:
			if result.blocked {
				t.Fatalf("iteration %d COMPLETE won but also reported a parked callback", iteration)
			}
		default:
			t.Fatalf("iteration %d admission errno = %v", iteration, errno)
		}
		close(release)
		if err := f.raw.finishVisibilityComplete(context.Background(), result.completion); err != nil {
			t.Fatalf("iteration %d finish COMPLETE: %v", iteration, err)
		}
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

func TestAParkedMountRepairsDataAndAttributeTargetsAfterItsUnknownBindingPublishes(t *testing.T) {
	var content uint64
	f := newBlockedFixture(t, "packages", 5*time.Minute, func(f *strictFixture, _ uint64) {
		entry := f.lookup(t, fuse.FUSE_ROOT_ID, "content")
		content = entry.Attr.Ino
	})
	defer f.release()

	// fuse_reverse_inval_inode takes no parent lock. The peer must nevertheless
	// wait while the parked mkdir's returned binding is still unknown: that
	// namespace wildcard could resolve to the item the phase names. Once the
	// mkdir reply physically publishes and resolves the wildcard, inode repair
	// proceeds without a blocked-parent report.
	targets := []*authoritypb.VisibilityTarget{
		inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, content, 16),
		inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, content, 0),
	}
	f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE, testPeerSession, targets...)
	f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE, testPeerSession, targets...)
	waitFor(t, "the peer cut to close before draining the unknown source binding", func() bool {
		f.raw.mu.Lock()
		defer f.raw.mu.Unlock()
		return len(f.raw.peerHeldPhase) != 0
	})
	f.release()

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
		if call.kind == "size" {
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
