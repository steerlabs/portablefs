//go:build linux

package fusev3

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// recordedNotify is one reverse notification the frontend sent to its kernel.
type recordedNotify struct {
	kind   string
	parent uint64
	child  uint64
	name   string
	inode  uint64
	off    int64
	length int64
}

// fakeNotifier stands in for the kernel's reverse channel. block, when
// non-nil, holds every notification, which is how the deadlock-shaped
// behaviours are made observable without a kernel.
type fakeNotifier struct {
	mu       sync.Mutex
	calls    []recordedNotify
	deleteST fuse.Status
	entryST  fuse.Status
	inodeST  fuse.Status
	block    chan struct{}
	// onDelete, when set, runs on the goroutine issuing a namespace
	// notification. It is how the ordering of a deferred repair relative to
	// this frontend's own reply is observed without a kernel.
	onDelete func()
}

func (n *fakeNotifier) wait() {
	n.mu.Lock()
	block := n.block
	n.mu.Unlock()
	if block != nil {
		<-block
	}
}

func (n *fakeNotifier) record(call recordedNotify) {
	n.wait()
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, call)
}

func (n *fakeNotifier) InodeNotify(node uint64, off, length int64) fuse.Status {
	n.record(recordedNotify{kind: "inode", inode: node, off: off, length: length})
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.inodeST
}

func (n *fakeNotifier) EntryNotify(parent uint64, name string) fuse.Status {
	n.record(recordedNotify{kind: "entry", parent: parent, name: name})
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.entryST
}

func (n *fakeNotifier) DeleteNotify(parent, child uint64, name string) fuse.Status {
	n.mu.Lock()
	hook := n.onDelete
	n.mu.Unlock()
	if hook != nil {
		hook()
	}
	n.record(recordedNotify{kind: "delete", parent: parent, child: child, name: name})
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.deleteST == 0 {
		return fuse.OK
	}
	return n.deleteST
}

func (n *fakeNotifier) snapshot() []recordedNotify {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]recordedNotify(nil), n.calls...)
}

func (n *fakeNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.calls)
}

const testDeviceMajorMinor = 0x00fd0001

// testIdentity is an export-handle-shaped stable identity: a type word plus
// opaque handle bytes, deliberately containing neither a device prefix nor a
// bare inode number — exactly like the authority's real XFS identities. The
// frontend must repair from the explicit kernel_ino / parent_kernel_ino /
// device fields, never by parsing these bytes.
func testIdentity(inode uint64) []byte {
	identity := make([]byte, 16)
	binary.BigEndian.PutUint32(identity[0:4], 0x81)
	binary.BigEndian.PutUint64(identity[4:12], inode^0xa5a5_a5a5_a5a5_a5a5)
	binary.BigEndian.PutUint32(identity[12:16], 0x0badf00d)
	return identity
}

func namespaceVisibilityTarget(parent uint64, name string) *authoritypb.VisibilityTarget {
	return &authoritypb.VisibilityTarget{
		Scope: authoritypb.VisibilityScope_VISIBILITY_SCOPE_NAMESPACE, ParentIdentity: testIdentity(parent), Name: []byte(name),
		ParentKernelIno: parent, Device: testDeviceMajorMinor,
	}
}

func inodeVisibilityTarget(scope authoritypb.VisibilityScope, inode uint64, size int64) *authoritypb.VisibilityTarget {
	return &authoritypb.VisibilityTarget{
		Scope: scope, Identity: testIdentity(inode), Size: size,
		KernelIno: inode, Device: testDeviceMajorMinor,
	}
}

func visibilityEvent(sequence uint64, phase authoritypb.VisibilityPhase, initiator []byte, targets ...*authoritypb.VisibilityTarget) *authoritypb.VisibilityEvent {
	return &authoritypb.VisibilityEvent{
		Cursor:             &authoritypb.VisibilityCursor{Sequence: sequence, Phase: phase},
		InitiatorSessionId: initiator,
		Targets:            targets,
	}
}

var (
	testSelfSession  = []byte("this-mount-0001x")
	testPeerSession  = []byte("other-mount-002x")
	testStrictConfig = func(watermark int) Config {
		cfg := testConfig(watermark)
		cfg.Coherence = CoherenceStrict
		cfg.CachedNameCapacity = 32
		cfg.RepairBudget = 5 * time.Second
		return cfg
	}
)

// strictFixture is a strict frontend with no kernel: the raw filesystem, the
// notification channel it repairs through, and a programmable authority.
type strictFixture struct {
	raw    *rawFileSystem
	mount  *Mount
	rpc    *fakeRPC
	notify *fakeNotifier
}

func newStrictFixture(t *testing.T) *strictFixture {
	t.Helper()
	rpc := newFakeRPC()
	rpc.session = testSelfSession
	mount := newMount(context.Background(), rpc, testStrictConfig(8))
	t.Cleanup(mount.cancel)
	root := &node{mount: mount, item: testItem(1, authoritypb.Attr_DIRECTORY, 0), requestTimeout: time.Second, maxRead: 64 * 1024, maxWrite: 64 * 1024}
	raw := newRawFileSystem(mount, root)
	notify := &fakeNotifier{}
	mount.setNotifier(notify)
	return &strictFixture{raw: raw, mount: mount, rpc: rpc, notify: notify}
}

// lookup performs one LOOKUP through the raw filesystem exactly as the kernel
// would, and returns the entry the frontend published.
func (f *strictFixture) lookup(t *testing.T, parentNode uint64, name string) *fuse.EntryOut {
	t.Helper()
	out := &fuse.EntryOut{}
	if status := f.raw.Lookup(nil, &fuse.InHeader{NodeId: parentNode}, name, out); !status.Ok() {
		t.Fatalf("LOOKUP %q = %v", name, status)
	}
	return out
}

// --- the strict profile publishes lifetimes, and records what it published ---

func TestStrictLookupPublishesACacheableEntryAndRecordsIt(t *testing.T) {
	f := newStrictFixture(t)
	out := f.lookup(t, fuse.FUSE_ROOT_ID, "child")
	if out.EntryValid == 0 || out.AttrValid == 0 {
		t.Fatalf("strict entry timeouts = (%d.%09d, %d.%09d); a strict mount that publishes nothing cacheable has not removed the RPC multiplier",
			out.EntryValid, out.EntryValidNsec, out.AttrValid, out.AttrValidNsec)
	}
	if time.Duration(out.EntryValid)*time.Second != strictEntryTimeout {
		t.Fatalf("entry lifetime = %ds, want %s", out.EntryValid, strictEntryTimeout)
	}
	f.raw.mu.Lock()
	defer f.raw.mu.Unlock()
	if _, ok := f.raw.cachedNames[nameKey{parent: 1, name: "child"}]; !ok {
		t.Fatalf("cached names = %v; a binding the kernel may reuse must be recorded or it can never be repaired", f.raw.cachedNames)
	}
}

// --- PREPARE closes cache admission, COMPLETE repairs and reopens it --------

func TestLookupBetweenPrepareAndCompleteDoesNotRecacheTheOldValue(t *testing.T) {
	f := newStrictFixture(t)
	// The binding is cached first, exactly as an earlier path walk would.
	if out := f.lookup(t, fuse.FUSE_ROOT_ID, "victim"); out.EntryValid == 0 {
		t.Fatal("the pre-mutation lookup was not cacheable, so this test would prove nothing")
	}
	targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(1, "victim")}
	if err := f.raw.prepareVisibility(context.Background(), targets, false); err != nil {
		t.Fatalf("PREPARE: %v", err)
	}
	// A path walk inside the window still gets an answer -- the authority has
	// not applied yet, so the old value is still the truth -- but it must not
	// be allowed to survive the mutation.
	inWindow := f.lookup(t, fuse.FUSE_ROOT_ID, "victim")
	if inWindow.EntryValid != 0 || inWindow.EntryValidNsec != 0 || inWindow.AttrValid != 0 || inWindow.AttrValidNsec != 0 {
		t.Fatalf("a lookup between PREPARE and COMPLETE published (%d.%09d, %d.%09d); re-caching the pre-mutation value inside the barrier window is exactly what the barrier exists to prevent",
			inWindow.EntryValid, inWindow.EntryValidNsec, inWindow.AttrValid, inWindow.AttrValidNsec)
	}
	if err := f.raw.completeVisibility(targets, false); err != nil {
		t.Fatalf("COMPLETE: %v", err)
	}
	// Admission reopens on COMPLETE, not on a timer.
	if after := f.lookup(t, fuse.FUSE_ROOT_ID, "victim"); after.EntryValid == 0 {
		t.Fatal("cache admission was not reopened by COMPLETE")
	}
}

func TestCompleteInvalidatesExactlyWhatWasPublished(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, fuse.FUSE_ROOT_ID, "victim")
	targets := []*authoritypb.VisibilityTarget{
		namespaceVisibilityTarget(1, "victim"),
		inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, 7, 4096),
	}
	if err := f.raw.prepareVisibility(context.Background(), targets, false); err != nil {
		t.Fatalf("PREPARE: %v", err)
	}
	if err := f.raw.completeVisibility(targets, false); err != nil {
		t.Fatalf("COMPLETE: %v", err)
	}
	calls := f.notify.snapshot()
	if len(calls) != 2 {
		t.Fatalf("notifications = %+v, want one namespace repair and one inode repair", calls)
	}
	if calls[0].kind != "delete" || calls[0].parent != fuse.FUSE_ROOT_ID || calls[0].name != "victim" || calls[0].child != entry.NodeId {
		t.Fatalf("namespace repair = %+v; a removal must reach inotify, which only NotifyDelete does", calls[0])
	}
	if calls[1].kind != "inode" || calls[1].inode != entry.NodeId || calls[1].off != 0 || calls[1].length != 0 {
		t.Fatalf("inode repair = %+v; want a whole-file content and attribute invalidation", calls[1])
	}
	// A repaired binding is no longer cached, so a second event for the same
	// name costs nothing and, critically, takes no kernel lock.
	before := f.notify.count()
	if err := f.raw.completeVisibility(targets, false); err != nil {
		t.Fatalf("second COMPLETE: %v", err)
	}
	for _, call := range f.notify.snapshot()[before:] {
		if call.kind != "inode" {
			t.Fatalf("a binding this mount no longer caches was repaired again: %+v", call)
		}
	}
}

func TestNamespaceRepairFallsBackToEntryInvalidationWhenDeleteIsRefused(t *testing.T) {
	f := newStrictFixture(t)
	f.notify.deleteST = fuse.Status(syscall.ENOSYS)
	f.lookup(t, fuse.FUSE_ROOT_ID, "victim")
	targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(1, "victim")}
	if err := f.raw.completeVisibility(targets, false); err != nil {
		t.Fatalf("COMPLETE: %v", err)
	}
	calls := f.notify.snapshot()
	if len(calls) != 2 || calls[0].kind != "delete" || calls[1].kind != "entry" || calls[1].name != "victim" {
		t.Fatalf("notifications = %+v; when the delete half is refused the invalidation still has to happen", calls)
	}
}

func TestMissingKernelInodeAlreadySatisfiesInvalidation(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, fuse.FUSE_ROOT_ID, "victim")
	f.notify.inodeST = fuse.ENOENT
	targets := []*authoritypb.VisibilityTarget{
		namespaceVisibilityTarget(1, "victim"),
		inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, 7, 0),
	}
	if err := f.raw.completeVisibility(targets, false); err != nil {
		t.Fatalf("COMPLETE over an inode removed by its namespace repair: %v", err)
	}
	calls := f.notify.snapshot()
	if len(calls) != 2 || calls[0].kind != "delete" || calls[0].child != entry.NodeId ||
		calls[1].kind != "inode" || calls[1].inode != entry.NodeId {
		t.Fatalf("notifications = %+v, want namespace removal followed by the now-absent inode", calls)
	}
}

// A route declaration that moved is terminal for this mount by design — but
// the mount must say so through the blocked report, which fences it at the
// authority immediately, rather than dying silently and leaving the authority
// holding this participant's PREPARE until the declared repair budget expires.
// Silent death converted every routing change into one budget-long stall per
// strict mount.
func TestARoutesChangeReportsBlockedBeforeRevoking(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.mu.Lock()
	f.rpc.events = make(chan *authoritypb.VisibilityEvent, 1)
	f.rpc.mu.Unlock()
	f.mount.wg.Add(1)
	go (&coherence{mount: f.mount, session: testSelfSession, budget: 5 * time.Second}).run(f.mount.ctx)

	event := visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE, testPeerSession)
	event.Routes = &authoritypb.RoutesChange{Revision: []byte{9, 9, 9}}
	f.rpc.events <- event
	waitFor(t, "the routes change to revoke the mount", f.mount.isRevoked)

	f.rpc.mu.Lock()
	blocked := append([]*authoritypb.VisibilityCursor(nil), f.rpc.blocked...)
	acked := append([]*authoritypb.VisibilityCursor(nil), f.rpc.acked...)
	f.rpc.mu.Unlock()
	if len(blocked) != 1 || blocked[0].GetSequence() != 1 {
		t.Fatalf("blocked reports = %v, want exactly the routes event's cursor reported before revocation", blocked)
	}
	if len(acked) != 0 {
		t.Fatalf("acknowledgments = %v; the blocked report replaces the acknowledgment", acked)
	}
}

func TestEvictedDentryAlreadySatisfiesNameInvalidation(t *testing.T) {
	// The kernel evicts dentries independently of FORGET: the second alias of
	// a hard link, a name whose inode an open descriptor pins, and ordinary
	// dcache pressure all leave cachedNames entries whose dentry is gone. Both
	// notification halves then answer ENOENT, which is the invalidated state —
	// the regression this guards against treated it as a repair failure and
	// revoked a healthy mount (the same defect the inode path already fixed).
	f := newStrictFixture(t)
	f.lookup(t, fuse.FUSE_ROOT_ID, "victim")
	f.notify.deleteST = fuse.ENOENT
	f.notify.entryST = fuse.ENOENT
	targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(1, "victim")}
	if err := f.raw.completeVisibility(targets, false); err != nil {
		t.Fatalf("COMPLETE over an evicted dentry: %v", err)
	}
	calls := f.notify.snapshot()
	if len(calls) != 2 || calls[0].kind != "delete" || calls[1].kind != "entry" || calls[1].name != "victim" {
		t.Fatalf("notifications = %+v, want the delete then entry pair, each answered ENOENT", calls)
	}
	if f.mount.isRevoked() {
		t.Fatal("an already-evicted binding revoked a healthy mount")
	}
}

func TestFailedFinalRepairRevokesWithoutAcknowledgingComplete(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*strictFixture) []*authoritypb.VisibilityTarget
	}{
		{
			name: "namespace delete and fallback both fail",
			prepare: func(f *strictFixture) []*authoritypb.VisibilityTarget {
				f.lookup(t, fuse.FUSE_ROOT_ID, "victim")
				f.notify.deleteST = fuse.Status(syscall.ENOSYS)
				f.notify.entryST = fuse.Status(syscall.EIO)
				return []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(1, "victim")}
			},
		},
		{
			name: "inode invalidation fails",
			prepare: func(f *strictFixture) []*authoritypb.VisibilityTarget {
				f.lookup(t, fuse.FUSE_ROOT_ID, "victim")
				f.notify.inodeST = fuse.Status(syscall.EIO)
				return []*authoritypb.VisibilityTarget{inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, 7, 0)}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newStrictFixture(t)
			targets := test.prepare(f)
			f.rpc.mu.Lock()
			f.rpc.events = make(chan *authoritypb.VisibilityEvent, 2)
			f.rpc.mu.Unlock()
			f.mount.wg.Add(1)
			go (&coherence{mount: f.mount, session: testSelfSession, budget: 5 * time.Second}).run(f.mount.ctx)

			f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE, testPeerSession, targets...)
			waitFor(t, "PREPARE acknowledgment", func() bool {
				f.rpc.mu.Lock()
				defer f.rpc.mu.Unlock()
				return len(f.rpc.acked) == 1
			})
			f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE, testPeerSession, targets...)
			waitFor(t, "failed repair to revoke the mount", f.mount.isRevoked)

			f.rpc.mu.Lock()
			acked := append([]*authoritypb.VisibilityCursor(nil), f.rpc.acked...)
			f.rpc.mu.Unlock()
			if len(acked) != 1 || acked[0].GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE {
				t.Fatalf("acknowledged phases after the final repair failed = %v, want PREPARE only", acked)
			}
			f.raw.mu.Lock()
			held := len(f.raw.heldNames)+len(f.raw.heldInodes) > 0
			f.raw.mu.Unlock()
			if !held {
				t.Fatal("failed COMPLETE reopened cache admission before revocation")
			}
		})
	}
}

func sourceComplete(slot uint32, mutationSequence uint64, targets ...*authoritypb.VisibilityTarget) *authoritypb.VisibilityEvent {
	event := visibilityEvent(99, authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE, testSelfSession, targets...)
	event.MutationSlot = slot
	event.MutationSequence = mutationSequence
	return event
}

func startMkdirCallback(f *strictFixture, name string) <-chan fuse.Status {
	done := make(chan fuse.Status, 1)
	go func() {
		out := &fuse.EntryOut{}
		done <- f.raw.Mkdir(nil, &fuse.MkdirIn{InHeader: fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}, Mode: 0o755}, name, out)
	}()
	return done
}

func startVisibilityLoop(f *strictFixture) {
	f.rpc.mu.Lock()
	f.rpc.events = make(chan *authoritypb.VisibilityEvent, 2)
	f.rpc.mu.Unlock()
	f.mount.wg.Add(1)
	go (&coherence{mount: f.mount, session: testSelfSession, budget: 5 * time.Second}).run(f.mount.ctx)
}

func assertNoVisibilityAck(t *testing.T, f *strictFixture, why string) {
	t.Helper()
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()
	<-timer.C
	f.rpc.mu.Lock()
	defer f.rpc.mu.Unlock()
	if len(f.rpc.acked) != 0 {
		t.Fatalf("visibility was acknowledged %s: %v", why, f.rpc.acked)
	}
}

func TestSelfCompleteWaitsWhenMutationResponseArrivesBeforeEvent(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.item = testItem(7, authoritypb.Attr_DIRECTORY, 7)
	f.rpc.mutationStates = []*authoritypb.MutationState{{Slot: 3, AcceptedSequence: 1}}

	// The transport returns while holding raw.mu, placing the callback after its
	// response (and after ticket registration) but before intern/publish can
	// finish filling the FUSE reply.
	responseDelivered := make(chan struct{})
	var once sync.Once
	f.rpc.afterMutation = func() {
		once.Do(func() {
			f.raw.mu.Lock()
			close(responseDelivered)
		})
	}
	done := startMkdirCallback(f, "response-first")
	<-responseDelivered
	waitFor(t, "the response ticket to enter the publication ledger", func() bool {
		f.mount.publications.mu.Lock()
		defer f.mount.publications.mu.Unlock()
		return f.mount.publications.bySlot[3] != nil
	})

	startVisibilityLoop(f)
	f.rpc.events <- sourceComplete(3, 1, namespaceVisibilityTarget(1, "response-first"))
	assertNoVisibilityAck(t, f, "while the matching raw callback was still publishing its reply")
	f.raw.mu.Unlock()
	if status := <-done; !status.Ok() {
		t.Fatalf("MKDIR callback = %v", status)
	}
	waitFor(t, "COMPLETE acknowledgment after raw reply publication", func() bool {
		f.rpc.mu.Lock()
		defer f.rpc.mu.Unlock()
		return len(f.rpc.acked) == 1
	})
}

func TestSelfCompleteWaitsWhenEventArrivesBeforeMutationResponse(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.item = testItem(7, authoritypb.Attr_DIRECTORY, 7)
	f.rpc.mutationStates = []*authoritypb.MutationState{{Slot: 5, AcceptedSequence: 1}}
	responseGate := make(chan struct{})
	f.rpc.block = responseGate
	done := startMkdirCallback(f, "event-first")

	startVisibilityLoop(f)
	f.rpc.events <- sourceComplete(5, 1, namespaceVisibilityTarget(1, "event-first"))
	assertNoVisibilityAck(t, f, "before the matching mutation response had reached its raw callback")
	close(responseGate)
	if status := <-done; !status.Ok() {
		t.Fatalf("MKDIR callback = %v", status)
	}
	waitFor(t, "COMPLETE acknowledgment after the late response was published", func() bool {
		f.rpc.mu.Lock()
		defer f.rpc.mu.Unlock()
		return len(f.rpc.acked) == 1
	})
}

func TestMutationPublicationLedgerCollapsesOutOfOrderResponsesToOneWatermark(t *testing.T) {
	ledger := &mutationPublicationLedger{}
	// A replay slot is released by the transport before the raw callback which
	// used it necessarily returns, so sequence 2 can be observed and published
	// while sequence 1 is still filling its FUSE reply.
	if err := ledger.accept(mutationTicket{slot: 4, sequence: 2}, true); err != nil {
		t.Fatal(err)
	}
	if err := ledger.accept(mutationTicket{slot: 4, sequence: 1}, false); err != nil {
		t.Fatal(err)
	}
	ledger.complete(mutationTicket{slot: 4, sequence: 1})

	ledger.mu.Lock()
	slot := ledger.bySlot[4]
	through, tail := slot.through, len(slot.seen)
	ledger.mu.Unlock()
	if through != 2 || tail != 0 {
		t.Fatalf("collapsed slot = (through %d, tail %d), want (2, 0)", through, tail)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := ledger.wait(ctx, mutationTicket{slot: 4, sequence: 1}); err != nil {
		t.Fatalf("wait for collapsed sequence 1: %v", err)
	}
	if err := ledger.wait(ctx, mutationTicket{slot: 4, sequence: 2}); err != nil {
		t.Fatalf("wait for collapsed sequence 2: %v", err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if err := ledger.wait(cancelled, mutationTicket{slot: 999, sequence: 1}); err == nil {
		t.Fatal("an event with no matching response unexpectedly completed")
	}
	ledger.mu.Lock()
	entries := len(ledger.bySlot)
	ledger.mu.Unlock()
	if entries != 1 {
		t.Fatalf("an event-first unknown ticket grew the per-slot ledger to %d entries, want 1", entries)
	}
}

// --- the initiator exemption ------------------------------------------------

func TestTheInitiatorNeverRepairsItsOwnMutation(t *testing.T) {
	f := newStrictFixture(t)
	f.lookup(t, fuse.FUSE_ROOT_ID, "victim")
	targets := []*authoritypb.VisibilityTarget{
		namespaceVisibilityTarget(1, "victim"),
		inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, 7, 0),
	}
	// A mount that notified here would be asking the kernel for the parent
	// directory's i_rwsem, which the syscall that caused this very mutation
	// holds for the whole authority round trip.
	if err := f.raw.prepareVisibility(context.Background(), targets, true); err != nil {
		t.Fatalf("PREPARE: %v", err)
	}
	if _, held := f.raw.heldNames[nameKey{parent: 1, name: "victim"}]; held {
		t.Fatal("the initiating mount gated its own name; its own reply is what rebinds that name, under the same lock")
	}
	if err := f.raw.completeVisibility(targets, true); err != nil {
		t.Fatalf("COMPLETE: %v", err)
	}
	if calls := f.notify.snapshot(); len(calls) != 0 {
		t.Fatalf("the initiating mount issued %+v; the VFS already repaired all of it from this operation's own reply", calls)
	}
}

func TestInitiatorStillGatesInodeStateItCannotSerialiseWithALock(t *testing.T) {
	f := newStrictFixture(t)
	targets := []*authoritypb.VisibilityTarget{inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, 7, 8)}
	if err := f.raw.prepareVisibility(context.Background(), targets, true); err != nil {
		t.Fatalf("PREPARE: %v", err)
	}
	// stat(2) takes no inode lock, so a concurrent local stat is not ordered
	// against the write the way a lookup is ordered against a create.
	out := &fuse.AttrOut{}
	if status := f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}}, out); !status.Ok() {
		t.Fatalf("GETATTR = %v", status)
	}
	if out.AttrValid != 0 || out.AttrValidNsec != 0 {
		t.Fatalf("GETATTR inside the initiator's own barrier published %d.%09d", out.AttrValid, out.AttrValidNsec)
	}
}

// --- self-initiated namespace mutations keep the registry exact -------------

func TestSelfUnlinkDropsTheBindingSoNoRepairIsAttempted(t *testing.T) {
	f := newStrictFixture(t)
	f.lookup(t, fuse.FUSE_ROOT_ID, "doomed")
	if status := f.raw.Unlink(nil, &fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}, "doomed"); !status.Ok() {
		t.Fatalf("UNLINK = %v", status)
	}
	f.raw.mu.Lock()
	_, cached := f.raw.cachedNames[nameKey{parent: 1, name: "doomed"}]
	f.raw.mu.Unlock()
	if cached {
		t.Fatal("a name this mount unlinked itself is still recorded as kernel-cached; the VFS already dropped it and a repair would take a lock this syscall held")
	}
}

func TestSelfRenameMovesTheBindingInsteadOfLosingIt(t *testing.T) {
	f := newStrictFixture(t)
	f.lookup(t, fuse.FUSE_ROOT_ID, "before")
	if status := f.raw.Rename(nil, &fuse.RenameIn{InHeader: fuse.InHeader{NodeId: fuse.FUSE_ROOT_ID}, Newdir: fuse.FUSE_ROOT_ID}, "before", "after"); !status.Ok() {
		t.Fatalf("RENAME = %v", status)
	}
	f.raw.mu.Lock()
	_, old := f.raw.cachedNames[nameKey{parent: 1, name: "before"}]
	_, moved := f.raw.cachedNames[nameKey{parent: 1, name: "after"}]
	f.raw.mu.Unlock()
	if old {
		t.Fatal("the pre-rename name is still recorded; d_move took the dentry away from it")
	}
	if !moved {
		t.Fatal("the post-rename name is not recorded; d_move carried the dentry and its lifetime there, so a later remote change to it would go unrepaired")
	}
}

// --- the declared capacity is a hard bound ---------------------------------

func TestCachedNamesNeverExceedTheDeclaredCapacity(t *testing.T) {
	f := newStrictFixture(t)
	capacity := f.raw.nameCapacity
	uncacheable := 0
	for i := range capacity * 2 {
		name := fmt.Sprintf("entry-%03d", i)
		// Each lookup must resolve to a distinct object, or they all collapse
		// onto one record and the capacity is never reached.
		f.rpc.mu.Lock()
		f.rpc.item = testItem(uint64(100+i), authoritypb.Attr_REGULAR, uint64(100+i))
		f.rpc.mu.Unlock()
		if out := f.lookup(t, fuse.FUSE_ROOT_ID, name); out.EntryValid == 0 {
			uncacheable++
		}
	}
	f.raw.mu.Lock()
	held := len(f.raw.cachedNames)
	f.raw.mu.Unlock()
	if held > capacity {
		t.Fatalf("cached names = %d, declared capacity = %d; the number this mount declares to the authority is the amount of stale state it promises it can withdraw", held, capacity)
	}
	if uncacheable == 0 {
		t.Fatal("the capacity bound was never reached, so this test proved nothing")
	}
}

// --- liveness: acknowledging is never queued behind bulk I/O ---------------

func TestVisibilityLoopKeepsAcknowledgingUnderSaturatedBulkIO(t *testing.T) {
	f := newStrictFixture(t)
	// Every bulk permit is taken and never released, which is what a mount
	// saturated with kernel I/O looks like from the visibility loop's side.
	for range cap(f.mount.bulk) {
		f.mount.bulk <- struct{}{}
	}
	f.rpc.mu.Lock()
	f.rpc.events = make(chan *authoritypb.VisibilityEvent, 4)
	f.rpc.mu.Unlock()
	f.mount.wg.Add(1)
	go (&coherence{mount: f.mount, session: testSelfSession, budget: 5 * time.Second}).run(f.mount.ctx)

	targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(1, "under-load")}
	f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE, testPeerSession, targets...)
	f.rpc.events <- visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE, testPeerSession, targets...)
	waitFor(t, "both phases to be acknowledged while every bulk permit is held", func() bool {
		f.rpc.mu.Lock()
		defer f.rpc.mu.Unlock()
		return len(f.rpc.acked) == 2
	})
	f.rpc.mu.Lock()
	defer f.rpc.mu.Unlock()
	if f.rpc.acked[0].GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE ||
		f.rpc.acked[1].GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE {
		t.Fatalf("acknowledged phases = %v; the authority enforces exact ordering", f.rpc.acked)
	}
}

func TestVisibilityStreamFailureRevokesTheMount(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.mu.Lock()
	f.rpc.visibilityErr = errors.New("fenced")
	f.rpc.mu.Unlock()
	f.mount.wg.Add(1)
	go (&coherence{mount: f.mount, session: testSelfSession, budget: 5 * time.Second}).run(f.mount.ctx)
	waitFor(t, "the mount to revoke itself when it can no longer repair", f.mount.isRevoked)
	if errno := f.mount.acquireBulk(context.Background()); errno != revokedErrno {
		t.Fatalf("a revoked mount answered a request with %v, want %v", errno, revokedErrno)
	}
}

func TestRepairBudgetBreachRevokesTheMount(t *testing.T) {
	f := newStrictFixture(t)
	f.lookup(t, fuse.FUSE_ROOT_ID, "stuck")
	// A notification parked on a VFS lock held by an unrelated local process is
	// the only thing that can make a phase slow. The budget is the commitment
	// this mount made about that case, so it must be enforced, not hoped for.
	blocked := make(chan struct{})
	f.notify.mu.Lock()
	f.notify.block = blocked
	f.notify.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = (&coherence{mount: f.mount, session: testSelfSession, budget: 50 * time.Millisecond}).applyWithinBudget(
			context.Background(),
			visibilityEvent(1, authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE, testPeerSession, namespaceVisibilityTarget(1, "stuck")))
	}()
	waitFor(t, "the declared repair budget to revoke the mount", f.mount.isRevoked)
	close(blocked)
	<-done
}

// --- detaching with evidence ------------------------------------------------

func TestStrictDetachRequiresObservedMountAbsence(t *testing.T) {
	f := newStrictFixture(t)
	f.mount.profile = CoherenceStrict
	// No kernel mount was ever recorded, so no absence can be observed and the
	// session must be left to die rather than released.
	if err := f.mount.detach(); err == nil {
		t.Fatal("strict detach without a kernel mount identity succeeded")
	}
	f.rpc.mu.Lock()
	proofs := len(f.rpc.detachProofs)
	f.rpc.mu.Unlock()
	if proofs != 0 {
		t.Fatalf("a strict mount detached with %d proofs and no observation; the authority must keep treating it as a possible holder of stale names", proofs)
	}
	// A mount ID that is not in mountinfo is exactly the observation the
	// authority needs, provided the serving connection is also terminal.
	f.mount.kernelMount = kernelMount{id: "999999999", device: "0:999", point: "/nonexistent-portablefs-mount"}
	done := make(chan struct{})
	close(done)
	f.mount.kernelConnectionDone = done
	if err := f.mount.detach(); err != nil {
		t.Fatalf("detach after exact mount and connection termination: %v", err)
	}
	f.rpc.mu.Lock()
	defer f.rpc.mu.Unlock()
	if len(f.rpc.detachProofs) != 1 {
		t.Fatalf("detach proofs = %d, want 1", len(f.rpc.detachProofs))
	}
	proof := f.rpc.detachProofs[0]
	if !proof.valid() || proof.Component != mountInfoPath || !strings.Contains(string(proof.Observation), "present=false") {
		t.Fatalf("proof = %+v; it must name the component it came from and say what was observed", proof)
	}
}

func TestStrictDetachWaitsForTheExactFUSEConnection(t *testing.T) {
	f := newStrictFixture(t)
	f.mount.kernelMount = kernelMount{id: "999999998", device: "0:998", point: "/nonexistent-portablefs-lazy-mount"}
	f.mount.kernelConnectionDone = make(chan struct{})

	result := make(chan error, 1)
	go func() { result <- f.mount.detach() }()
	time.Sleep(50 * time.Millisecond)
	f.rpc.mu.Lock()
	proofsBeforeConnectionExit := len(f.rpc.detachProofs)
	f.rpc.mu.Unlock()
	if proofsBeforeConnectionExit != 0 {
		t.Fatal("a mount hidden by lazy unmount detached while its FUSE connection could still serve retained references")
	}
	close(f.mount.kernelConnectionDone)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("detach after FUSE connection exit: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("detach did not proceed after the exact FUSE connection terminated")
	}
	f.rpc.mu.Lock()
	defer f.rpc.mu.Unlock()
	if len(f.rpc.detachProofs) != 1 {
		t.Fatalf("detach proofs after connection exit = %d, want 1", len(f.rpc.detachProofs))
	}
}

func TestStrictClosePreservesDetachDeliveryFailure(t *testing.T) {
	f := newStrictFixture(t)
	f.mount.kernelMount = kernelMount{id: "999999997", device: "0:997", point: "/nonexistent-portablefs-detach-failure"}
	done := make(chan struct{})
	close(done)
	f.mount.kernelConnectionDone = done
	delivery := errors.New("authority refused clean detach")
	f.rpc.detachErr = delivery

	first := f.mount.Close()
	if !errors.Is(first, delivery) {
		t.Fatalf("first Close = %v, want detach delivery failure", first)
	}
	if second := f.mount.Close(); !errors.Is(second, delivery) {
		t.Fatalf("second Close = %v, want preserved detach delivery failure", second)
	}
	f.rpc.mu.Lock()
	defer f.rpc.mu.Unlock()
	if len(f.rpc.detachProofs) != 1 || f.rpc.closes != 1 {
		t.Fatalf("detach deliveries = %d, RPC closes = %d; Close must execute teardown once", len(f.rpc.detachProofs), f.rpc.closes)
	}
}

func TestMountAbsenceRefusesAMountThatIsStillInstalled(t *testing.T) {
	// The root mount is always present, so this is a self-checking case: its
	// mount ID must never be reported absent.
	installed, err := observeKernelMount("/")
	if err != nil {
		t.Skipf("this environment does not report a mount at /: %v", err)
	}
	if _, err := installed.absent(); err == nil {
		t.Fatal("a mount that is still installed was reported absent")
	}
}

func TestMountInfoPathsAreUnescaped(t *testing.T) {
	if got := unescapeMountField(`/tmp/with\040space`); got != "/tmp/with space" {
		t.Fatalf("unescaped %q, want %q", got, "/tmp/with space")
	}
	if got := unescapeMountField("/plain/path"); got != "/plain/path" {
		t.Fatalf("unescaped %q, want %q", got, "/plain/path")
	}
}

// --- the one-volume assumption is checked, not assumed ---------------------

func TestASecondCoordinationDeviceIsRefused(t *testing.T) {
	f := newStrictFixture(t)
	first := []*authoritypb.VisibilityTarget{inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, 7, 0)}
	if err := f.raw.prepareVisibility(context.Background(), first, false); err != nil {
		t.Fatalf("PREPARE: %v", err)
	}
	f.raw.releaseHeld()
	foreign := &authoritypb.VisibilityTarget{
		Scope:     authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA,
		Identity:  testIdentity(7),
		KernelIno: 7, Device: testDeviceMajorMinor + 1,
	}
	if err := f.raw.prepareVisibility(context.Background(), []*authoritypb.VisibilityTarget{foreign}, false); err == nil {
		t.Fatal("a coordination device disagreeing with the pinned one was accepted; the kernel inode alone keys this frontend's tables, so two devices would alias two objects")
	}
}

// --- a reclaim settles its replay sequence immediately ---------------------

// A reclaim runs on no raw FUSE callback, so nothing ever calls finish() for
// it. Its accepted sequence must settle the moment its response is recorded,
// or the slot's publication watermark stops advancing and the deferred self
// COMPLETE of the next visible mutation on that slot waits forever.
func TestReclaimResponseSettlesItsReplaySequenceImmediately(t *testing.T) {
	m := &Mount{profile: CoherenceStrict}
	request := &authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Item: testToken(1)}}}
	response := &authoritypb.Response{Mutation: &authoritypb.MutationState{Slot: 4, AcceptedSequence: 1}}
	if err := m.recordMutationResponse(context.Background(), request, response, nil); err != nil {
		t.Fatalf("record reclaim response: %v", err)
	}
	if err := m.publications.wait(context.Background(), mutationTicket{slot: 4, sequence: 1}); err != nil {
		t.Fatalf("a reclaim's sequence did not settle on acceptance: %v", err)
	}
}

// --- targets missing their coordination facts fail closed ------------------

func TestVisibilityTargetsMissingCoordinationFactsAreRefused(t *testing.T) {
	f := newStrictFixture(t)
	cases := []struct {
		name   string
		target *authoritypb.VisibilityTarget
	}{
		{"namespace target without a parent kernel inode", &authoritypb.VisibilityTarget{
			Scope: authoritypb.VisibilityScope_VISIBILITY_SCOPE_NAMESPACE, ParentIdentity: testIdentity(1),
			Name: []byte("victim"), Device: testDeviceMajorMinor,
		}},
		{"namespace target without a device", &authoritypb.VisibilityTarget{
			Scope: authoritypb.VisibilityScope_VISIBILITY_SCOPE_NAMESPACE, ParentIdentity: testIdentity(1),
			Name: []byte("victim"), ParentKernelIno: 1,
		}},
		{"data target without a kernel inode", &authoritypb.VisibilityTarget{
			Scope: authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, Identity: testIdentity(7),
			Device: testDeviceMajorMinor,
		}},
		{"attributes target without a device", &authoritypb.VisibilityTarget{
			Scope: authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, Identity: testIdentity(7),
			KernelIno: 7,
		}},
	}
	for _, tc := range cases {
		if _, err := f.raw.translate([]*authoritypb.VisibilityTarget{tc.target}); err == nil {
			t.Fatalf("%s was translated; a target without its coordination facts must fail closed, because repairing a guessed coordinate leaves the real one stale", tc.name)
		}
	}
}

// --- revocation withdraws what it published --------------------------------

func TestRevocationWithdrawsEveryPublishedBinding(t *testing.T) {
	f := newStrictFixture(t)
	for i := range 4 {
		f.rpc.mu.Lock()
		f.rpc.item = testItem(uint64(200+i), authoritypb.Attr_REGULAR, uint64(200+i))
		f.rpc.mu.Unlock()
		f.lookup(t, fuse.FUSE_ROOT_ID, fmt.Sprintf("live-%d", i))
	}
	f.raw.revokeCachedNames(time.Now().Add(time.Second))
	withdrawn := 0
	for _, call := range f.notify.snapshot() {
		if call.kind == "delete" || call.kind == "entry" {
			withdrawn++
		}
	}
	if withdrawn < 4 {
		t.Fatalf("revocation withdrew %d of 4 published bindings; a mount that cannot repair must stop serving what it cached", withdrawn)
	}
	f.raw.mu.Lock()
	defer f.raw.mu.Unlock()
	if len(f.raw.cachedNames) != 0 {
		t.Fatalf("cached names after revocation = %d, want 0", len(f.raw.cachedNames))
	}
}

// --- the mount refuses to be strict without the exemption ticket -----------

func TestStrictMountIsRefusedWithoutASessionIdentity(t *testing.T) {
	rpc := newFakeRPC()
	rpc.session = nil
	_, err := MountVolume(context.Background(), t.TempDir(), rpc, testStrictConfig(8))
	if err == nil || !strings.Contains(err.Error(), "session identity") {
		t.Fatalf("MountVolume error = %v; a strict mount with no way to recognise its own mutations must be refused, not served", err)
	}
}

// --- the visibility lane is reserved out of the transport budget -----------

func TestStrictMountReservesAVisibilityLane(t *testing.T) {
	uncached := newMount(context.Background(), newFakeRPC(), testConfig(8))
	defer uncached.cancel()
	strict := newMount(context.Background(), newFakeRPC(), testStrictConfig(8))
	defer strict.cancel()
	if cap(strict.bulk) != cap(uncached.bulk)-visibilityReserve {
		t.Fatalf("strict bulk lane = %d, uncached = %d; the visibility loop's slot must come out of the bulk budget or it is not reserved at all",
			cap(strict.bulk), cap(uncached.bulk))
	}
}
