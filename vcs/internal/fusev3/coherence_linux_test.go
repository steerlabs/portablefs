//go:build linux

package fusev3

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// recordedNotify is one reverse notification the frontend sent to its kernel.
type recordedNotify struct {
	kind     string
	parent   uint64
	child    uint64
	name     string
	inode    uint64
	off      int64
	length   int64
	size     uint64
	sequence uint64
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
	sizeST   fuse.Status
	block    chan struct{}
	// onDelete, when set, runs on the goroutine issuing a namespace
	// notification. It is how the ordering of a deferred repair relative to
	// this frontend's own reply is observed without a kernel.
	onDelete func()
	// onSize is the corresponding deterministic arrival hook for exact-size
	// repair. It runs before the potentially blocking physical notification.
	onSize func()
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

func (n *fakeNotifier) PFSSizeNotify(node uint64, size uint64, sequence uint64) fuse.Status {
	n.mu.Lock()
	hook := n.onSize
	n.mu.Unlock()
	if hook != nil {
		hook()
	}
	n.record(recordedNotify{kind: "size", inode: node, size: size, sequence: sequence})
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.sizeST
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
	t      *testing.T
	raw    *rawFileSystem
	mount  *Mount
	rpc    *fakeRPC
	notify *fakeNotifier
	unique atomic.Uint64
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
	fixture := &strictFixture{t: t, raw: raw, mount: mount, rpc: rpc, notify: notify}
	fixture.unique.Store(2)
	return fixture
}

// lookup performs one LOOKUP through the raw filesystem exactly as the kernel
// would, and returns the entry the frontend published.
func (f *strictFixture) lookup(t *testing.T, parentNode uint64, name string) *fuse.EntryOut {
	t.Helper()
	out := &fuse.EntryOut{}
	status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: parentNode}, name, out)
	})
	if !status.Ok() {
		t.Fatalf("LOOKUP %q = %v", name, status)
	}
	return out
}

// rawCall models the part of go-fuse below RawFileSystem in unit tests: the
// method returns, its response is successfully written to /dev/fuse, and only
// then does ReplyWritten settle publication ownership.
func (f *strictFixture) rawCall(call func(unique uint64) fuse.Status) fuse.Status {
	unique := f.unique.Add(2)
	status := call(unique)
	completeTestReply(f.t, f.raw, unique, fuse.OK)
	return status
}

func (f *strictFixture) mkdir(parent uint64, name string, out *fuse.EntryOut) fuse.Status {
	return f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.Mkdir(nil, &fuse.MkdirIn{InHeader: fuse.InHeader{Unique: unique, NodeId: parent}, Mode: 0o755}, name, out)
	})
}

func (f *strictFixture) unlink(parent uint64, name string) fuse.Status {
	return f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.Unlink(nil, &fuse.InHeader{Unique: unique, NodeId: parent}, name)
	})
}

func (f *strictFixture) rename(oldParent, newParent uint64, oldName, newName string, flags uint32) fuse.Status {
	return f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.Rename(nil, &fuse.RenameIn{InHeader: fuse.InHeader{Unique: unique, NodeId: oldParent}, Newdir: newParent, Flags: flags}, oldName, newName)
	})
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
	// be allowed to survive the mutation. Zero TTL does not eliminate the
	// postprocessing race: fuse_iget/d_add still install transient state after
	// wake, so the result must retain a generic PFS_PUBLISH obligation too.
	unique := f.unique.Add(2)
	inWindow := &fuse.EntryOut{}
	if status := f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID}, "victim", inWindow); !status.Ok() {
		t.Fatalf("in-window LOOKUP = %v", status)
	}
	if inWindow.EntryValid != 0 || inWindow.EntryValidNsec != 0 || inWindow.AttrValid != 0 || inWindow.AttrValidNsec != 0 {
		t.Fatalf("a lookup between PREPARE and COMPLETE published (%d.%09d, %d.%09d); re-caching the pre-mutation value inside the barrier window is exactly what the barrier exists to prevent",
			inWindow.EntryValid, inWindow.EntryValidNsec, inWindow.AttrValid, inWindow.AttrValidNsec)
	}
	if !f.raw.ReplyWriteOrdered(unique) || !f.raw.ReplyPublishMarked(unique, testPublicationNodeID, testPublicationOpcode) {
		t.Fatal("zero-TTL LOOKUP did not retain a post-VFS publication receipt")
	}
	f.raw.ReplyWritten(unique, fuse.OK)
	acknowledgeTestPublication(t, f.raw, unique)
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
	if calls[1].kind != "size" || calls[1].inode != entry.NodeId || calls[1].size != 4096 || calls[1].sequence != 1 {
		t.Fatalf("inode repair = %+v; want exact size 4096 at the visibility sequence", calls[1])
	}
	// A repaired binding is no longer cached, so a second event for the same
	// name costs nothing and, critically, takes no kernel lock.
	before := f.notify.count()
	if err := f.raw.completeVisibility(targets, false); err != nil {
		t.Fatalf("second COMPLETE: %v", err)
	}
	for _, call := range f.notify.snapshot()[before:] {
		if call.kind != "size" {
			t.Fatalf("a binding this mount no longer caches was repaired again: %+v", call)
		}
	}
}

func TestCompleteNormalizesInodeRepairs(t *testing.T) {
	tests := []struct {
		name     string
		targets  func(uint64) []*authoritypb.VisibilityTarget
		wantKind string
		wantOff  int64
		wantSize uint64
	}{
		{
			name: "duplicate attributes stay attribute-only",
			targets: func(inode uint64) []*authoritypb.VisibilityTarget {
				return []*authoritypb.VisibilityTarget{
					inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, inode, 0),
					inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, inode, 0),
				}
			},
			wantKind: "inode",
			wantOff:  -1,
		},
		{
			name: "data dominates attributes",
			targets: func(inode uint64) []*authoritypb.VisibilityTarget {
				return []*authoritypb.VisibilityTarget{
					inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, inode, 0),
					inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, inode, 4096),
					inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, inode, 0),
				}
			},
			wantKind: "size",
			wantSize: 4096,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newStrictFixture(t)
			entry := f.lookup(t, fuse.FUSE_ROOT_ID, "victim")
			if err := f.raw.completeVisibility(test.targets(entry.Attr.Ino), false); err != nil {
				t.Fatalf("COMPLETE: %v", err)
			}
			calls := f.notify.snapshot()
			if len(calls) != 1 {
				t.Fatalf("notifications = %+v, want one normalized inode repair", calls)
			}
			if call := calls[0]; call.kind != test.wantKind || call.inode != entry.NodeId || call.off != test.wantOff || call.length != 0 || call.size != test.wantSize {
				t.Fatalf("normalized inode repair = %+v, want kind %q for inode %d", call, test.wantKind, entry.NodeId)
			}
		})
	}
}

func TestTranslateValidatesDominatedRawTargetsBeforeNormalization(t *testing.T) {
	f := newStrictFixture(t)
	data := inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, 7, 4096)
	malformedAttributes := inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, 7, 0)
	malformedAttributes.Size = 1
	if _, err := f.raw.translate([]*authoritypb.VisibilityTarget{data, malformedAttributes}); err == nil {
		t.Fatal("a malformed ATTRIBUTES target hidden behind a dominant DATA target was accepted")
	}
	f.raw.mu.Lock()
	defer f.raw.mu.Unlock()
	if f.raw.identityDeviceKnown {
		t.Fatal("a rejected raw event pinned frontend state before every target was validated")
	}
}

func TestNamespaceRepairNeverFallsBackFromExactChildExpiration(t *testing.T) {
	f := newStrictFixture(t)
	f.notify.deleteST = fuse.Status(syscall.ENOSYS)
	f.lookup(t, fuse.FUSE_ROOT_ID, "victim")
	targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(1, "victim")}
	if err := f.raw.completeVisibility(targets, false); err == nil {
		t.Fatal("COMPLETE accepted an exact-child repair the kernel refused")
	}
	calls := f.notify.snapshot()
	if len(calls) != 1 || calls[0].kind != "delete" || calls[0].name != "victim" {
		t.Fatalf("notifications = %+v; an exact-child refusal must not degrade to name-only invalidation", calls)
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

func TestMissingKernelInodeAlreadySatisfiesExactSizeRepair(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, fuse.FUSE_ROOT_ID, "victim")
	f.notify.sizeST = fuse.ENOENT
	targets := []*authoritypb.VisibilityTarget{
		inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, 7, 19),
	}
	if err := f.raw.prepareVisibility(context.Background(), targets, false); err != nil {
		t.Fatal(err)
	}
	completion, blocked, err := f.raw.beginVisibilityCompleteAt(targets, false, 27)
	if err != nil || blocked {
		t.Fatalf("begin exact-size COMPLETE = (blocked=%t, err=%v)", blocked, err)
	}
	if err := f.raw.finishVisibilityComplete(context.Background(), completion); err != nil {
		t.Fatalf("exact-size COMPLETE for an evicted inode = %v", err)
	}
	calls := f.notify.snapshot()
	if len(calls) != 1 || calls[0].kind != "size" || calls[0].inode != entry.NodeId || calls[0].size != 19 || calls[0].sequence != 27 {
		t.Fatalf("exact-size repair = %+v, want absent inode acknowledged at size 19 sequence 27", calls)
	}
	f.raw.mu.Lock()
	held := len(f.raw.peerHeldPhase) != 0 || len(f.raw.peerHolds) != 0
	completed := f.raw.completedVisibilitySequence
	f.raw.mu.Unlock()
	if held {
		t.Fatal("ENOENT exact-size repair left the peer visibility cut held")
	}
	if completed != 27 {
		t.Fatalf("local completed visibility sequence = %d, want 27", completed)
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
	// the exact notification answers ENOENT, which is the invalidated state —
	// the regression this guards against treated it as a repair failure and
	// revoked a healthy mount (the same defect the inode path already fixed).
	f := newStrictFixture(t)
	f.lookup(t, fuse.FUSE_ROOT_ID, "victim")
	f.notify.deleteST = fuse.ENOENT
	targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(1, "victim")}
	if err := f.raw.completeVisibility(targets, false); err != nil {
		t.Fatalf("COMPLETE over an evicted dentry: %v", err)
	}
	calls := f.notify.snapshot()
	if len(calls) != 1 || calls[0].kind != "delete" || calls[0].name != "victim" {
		t.Fatalf("notifications = %+v, want one exact expiration answered ENOENT", calls)
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
			name: "exact namespace expiration fails",
			prepare: func(f *strictFixture) []*authoritypb.VisibilityTarget {
				f.lookup(t, fuse.FUSE_ROOT_ID, "victim")
				f.notify.deleteST = fuse.Status(syscall.ENOSYS)
				return []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(1, "victim")}
			},
		},
		{
			name: "exact data publication fails",
			prepare: func(f *strictFixture) []*authoritypb.VisibilityTarget {
				f.lookup(t, fuse.FUSE_ROOT_ID, "victim")
				f.notify.sizeST = fuse.Status(syscall.EIO)
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

func TestSourceFilesystemVisibilityPhaseIsAProtocolViolation(t *testing.T) {
	f := newStrictFixture(t)
	event := visibilityEvent(99, authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE, testSelfSession,
		namespaceVisibilityTarget(1, "source-owned"))
	if err := (&coherence{mount: f.mount, session: testSelfSession, budget: time.Second}).apply(context.Background(), event); err == nil {
		t.Fatal("the source received a filesystem visibility phase even though its local publication gate owns that cut")
	}
}

// --- self-initiated namespace mutations keep the registry exact -------------

func TestSelfUnlinkDropsTheBindingSoNoRepairIsAttempted(t *testing.T) {
	f := newStrictFixture(t)
	f.lookup(t, fuse.FUSE_ROOT_ID, "doomed")
	if status := f.unlink(fuse.FUSE_ROOT_ID, "doomed"); !status.Ok() {
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
	if status := f.rename(fuse.FUSE_ROOT_ID, fuse.FUSE_ROOT_ID, "before", "after", 0); !status.Ok() {
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

func TestPlannedMountSourceAbsenceProducesExactStartupProof(t *testing.T) {
	fsName := fmt.Sprintf("portablefs-unit-never-installed-%d", time.Now().UnixNano())
	proof, err := observePlannedKernelMountAbsent(fsName, "/nonexistent-portablefs-startup-target")
	if err != nil {
		t.Fatalf("observe planned source absence: %v", err)
	}
	if !proof.valid() || proof.Component != mountInfoPath ||
		!strings.Contains(string(proof.Observation), "mount-source="+fsName) ||
		!strings.Contains(string(proof.Observation), "stage=startup") {
		t.Fatalf("startup absence proof = %+v", proof)
	}
}

func TestPlannedMountSourceAbsenceRefusesAnInstalledSource(t *testing.T) {
	data, err := os.ReadFile(mountInfoPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		for separator := 6; separator+2 < len(fields); separator++ {
			if fields[separator] != "-" {
				continue
			}
			source := unescapeMountField(fields[separator+2])
			if _, err := observePlannedKernelMountAbsent(source, "/irrelevant-to-source-identity"); err == nil {
				t.Fatalf("installed mount source %q was reported absent", source)
			}
			return
		}
	}
	t.Fatal("mountinfo contained no installed source to test")
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

// --- absence is cached under the same contract as existence ----------------

// markMissing makes the authority answer ENOENT for these names, and unmark
// makes them exist again. Together they replay what a probing workload does:
// ask for a name that is not there, then create it.
func (f *strictFixture) markMissing(names ...string) {
	f.rpc.mu.Lock()
	defer f.rpc.mu.Unlock()
	if f.rpc.missingNames == nil {
		f.rpc.missingNames = make(map[string]bool)
	}
	for _, name := range names {
		f.rpc.missingNames[name] = true
	}
}

func (f *strictFixture) unmarkMissing(names ...string) {
	f.rpc.mu.Lock()
	defer f.rpc.mu.Unlock()
	for _, name := range names {
		delete(f.rpc.missingNames, name)
	}
}

// probe performs one LOOKUP for a name the authority does not have. A cacheable
// absence is a successful reply carrying a zero NodeId, which is how FUSE says
// "not there, and that answer is good for this long"; an uncacheable one is
// ENOENT. Both shapes come back here so a test can assert which was published.
func (f *strictFixture) probe(t *testing.T, parentNode uint64, name string) (fuse.Status, *fuse.EntryOut) {
	t.Helper()
	out := &fuse.EntryOut{}
	status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: parentNode}, name, out)
	})
	return status, out
}

// cachedAbsence reports whether this frontend recorded the absence it published.
func (f *strictFixture) cachedAbsence(parent uint64, name string) bool {
	f.raw.mu.Lock()
	defer f.raw.mu.Unlock()
	_, absent := f.raw.cachedNegatives[nameKey{parent: parent, name: name}]
	return absent
}

func TestStrictLookupPublishesACacheableAbsenceAndRecordsIt(t *testing.T) {
	f := newStrictFixture(t)
	f.markMissing("db-journal")
	status, out := f.probe(t, fuse.FUSE_ROOT_ID, "db-journal")
	// The kernel serves a negative dentry from its own cache -- with no upcall
	// at all -- exactly when the reply was a success with a zero NodeId and a
	// nonzero entry lifetime. Answering ENOENT instead makes every probe a full
	// authority round trip forever, which is what a SQLite transaction, a
	// Python import scan, and a linker search path spend their syscalls on.
	if !status.Ok() {
		t.Fatalf("negative LOOKUP = %v; an ENOENT reply carries no lifetime, so the kernel must ask again on every probe", status)
	}
	if out.NodeId != 0 {
		t.Fatalf("negative LOOKUP published NodeId %d, want 0", out.NodeId)
	}
	if time.Duration(out.EntryValid)*time.Second != strictEntryTimeout {
		t.Fatalf("absence lifetime = %ds, want %s", out.EntryValid, strictEntryTimeout)
	}
	if !f.cachedAbsence(fuse.FUSE_ROOT_ID, "db-journal") {
		t.Fatal("a published absence was not recorded; an answer this mount cannot find again is an answer it can never repair")
	}
}

func TestCreatingANameWithdrawsThisMountsOwnCachedAbsence(t *testing.T) {
	f := newStrictFixture(t)
	f.markMissing("build.lock")
	if status, _ := f.probe(t, fuse.FUSE_ROOT_ID, "build.lock"); !status.Ok() {
		t.Fatalf("negative LOOKUP = %v; this test proves nothing unless the absence was cached", status)
	}
	// The authority excludes the source of a mutation from its own visibility
	// phases, so no repair will ever arrive for this name on this mount. The
	// reply that installs the new binding is the only moment the absence can be
	// taken back, and it must be, whether or not the binding itself is cached.
	f.unmarkMissing("build.lock")
	out := &fuse.EntryOut{}
	if status := f.mkdir(fuse.FUSE_ROOT_ID, "build.lock", out); !status.Ok() {
		t.Fatalf("MKDIR = %v", status)
	}
	if f.cachedAbsence(fuse.FUSE_ROOT_ID, "build.lock") {
		t.Fatal("this mount created the name and kept caching its absence; nothing else would ever correct that")
	}
	f.raw.mu.Lock()
	defer f.raw.mu.Unlock()
	if _, bound := f.raw.cachedNames[nameKey{parent: 1, name: "build.lock"}]; !bound {
		t.Fatal("the created binding was not recorded in place of the absence it replaced")
	}
}

func TestCompleteExpiresACachedAbsenceForACreatedName(t *testing.T) {
	f := newStrictFixture(t)
	f.markMissing("appeared")
	if status, _ := f.probe(t, fuse.FUSE_ROOT_ID, "appeared"); !status.Ok() {
		t.Fatalf("negative LOOKUP = %v; this test proves nothing unless the absence was cached", status)
	}
	// This is the whole correctness claim. Another mount is creating the name;
	// its create(2) cannot return until every audience member has acknowledged
	// COMPLETE, and this mount is in that audience because its failed
	// resolution entered the authority's resolved index exactly as a successful
	// one would. So by the time the creator's syscall returns, this kernel can
	// no longer answer "not there" from cache.
	targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(1, "appeared")}
	if err := f.raw.prepareVisibility(context.Background(), targets, false); err != nil {
		t.Fatalf("PREPARE: %v", err)
	}
	// Admission is closed for the name in the same way it is for a binding: a
	// probe inside the window still gets the pre-mutation truth, but must not
	// be allowed to survive the mutation.
	unique := f.unique.Add(2)
	inWindow := &fuse.EntryOut{}
	status := f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID}, "appeared", inWindow)
	if status != fuse.Status(syscall.ENOENT) || inWindow.EntryValid != 0 || inWindow.EntryValidNsec != 0 {
		t.Fatalf("in-window probe = %v with lifetime %d.%09d; re-caching an absence inside the barrier window is exactly what the barrier exists to prevent",
			status, inWindow.EntryValid, inWindow.EntryValidNsec)
	}
	if !f.raw.ReplyWriteOrdered(unique) || !f.raw.ReplyPublishMarked(unique, testPublicationNodeID, testPublicationOpcode) {
		t.Fatal("an uncacheable in-window absence did not retain its post-VFS publication receipt")
	}
	f.raw.ReplyWritten(unique, fuse.OK)
	acknowledgeTestPublication(t, f.raw, unique)
	if err := f.raw.completeVisibility(targets, false); err != nil {
		t.Fatalf("COMPLETE: %v", err)
	}
	calls := f.notify.snapshot()
	if len(calls) != 1 {
		t.Fatalf("notifications = %+v, want exactly one namespace expiry", calls)
	}
	// An absence has no child identity, so the exact-child NotifyDelete is not
	// the primitive here: expiring the name is, and it is safe precisely
	// because there is no binding whose lifetime could be wrongly lost.
	if call := calls[0]; call.kind != "entry" || call.parent != fuse.FUSE_ROOT_ID || call.name != "appeared" || call.child != 0 {
		t.Fatalf("absence repair = %+v; want a name-only expiry under the root", call)
	}
	if f.cachedAbsence(fuse.FUSE_ROOT_ID, "appeared") {
		t.Fatal("the repaired absence is still recorded, so a second event would spend another notification on nothing")
	}
	// Admission reopens on COMPLETE, not on a timer.
	f.unmarkMissing("appeared")
	if out := f.lookup(t, fuse.FUSE_ROOT_ID, "appeared"); out.EntryValid == 0 {
		t.Fatal("cache admission was not reopened by COMPLETE")
	}
}

func TestProbeAfterUnlinkIsCachedAndRecreationTakesItBack(t *testing.T) {
	f := newStrictFixture(t)
	// The sequence a transactional workload actually performs: the file is
	// there, it is removed, it is probed for repeatedly, and then it is
	// recreated.
	if out := f.lookup(t, fuse.FUSE_ROOT_ID, "wal"); out.EntryValid == 0 {
		t.Fatal("the pre-unlink binding was not cacheable, so this test would prove nothing")
	}
	if status := f.unlink(fuse.FUSE_ROOT_ID, "wal"); !status.Ok() {
		t.Fatalf("UNLINK = %v", status)
	}
	f.markMissing("wal")
	status, out := f.probe(t, fuse.FUSE_ROOT_ID, "wal")
	if !status.Ok() || out.NodeId != 0 || out.EntryValid == 0 {
		t.Fatalf("post-unlink probe = %v with NodeId %d and lifetime %d; the miss after a removal is the one every later probe repeats",
			status, out.NodeId, out.EntryValid)
	}
	if !f.cachedAbsence(fuse.FUSE_ROOT_ID, "wal") {
		t.Fatal("the post-unlink absence was not recorded")
	}
	f.unmarkMissing("wal")
	if status := f.mkdir(fuse.FUSE_ROOT_ID, "wal", &fuse.EntryOut{}); !status.Ok() {
		t.Fatalf("recreate = %v", status)
	}
	if f.cachedAbsence(fuse.FUSE_ROOT_ID, "wal") {
		t.Fatal("the recreated name is still cached as absent")
	}
	if again := f.lookup(t, fuse.FUSE_ROOT_ID, "wal"); again.EntryValid == 0 || again.NodeId == 0 {
		t.Fatalf("post-recreate LOOKUP published NodeId %d with lifetime %d, want a cacheable binding", again.NodeId, again.EntryValid)
	}
}

func TestCachedAbsencesAreBoundedByTheirDeclaredShare(t *testing.T) {
	f := newStrictFixture(t)
	// Nothing reclaims an absence the way FORGET reclaims a binding, so the
	// bound is the only thing that stops a probing workload from spending the
	// whole declared capacity on names that do not exist and starving the
	// bindings that do.
	share := f.raw.negativeCapacity
	if share <= 0 || share >= f.raw.nameCapacity {
		t.Fatalf("negative share = %d of capacity %d; it must be a real fraction of the declared total", share, f.raw.nameCapacity)
	}
	cached := 0
	for i := range share * 2 {
		name := fmt.Sprintf("absent-%d", i)
		f.markMissing(name)
		status, out := f.probe(t, fuse.FUSE_ROOT_ID, name)
		if status.Ok() && out.EntryValid != 0 {
			cached++
			continue
		}
		if status != fuse.Status(syscall.ENOENT) || out.EntryValid != 0 {
			t.Fatalf("refused absence %q = %v with lifetime %d; beyond the bound the only legal answer is an uncacheable ENOENT", name, status, out.EntryValid)
		}
	}
	if cached != share {
		t.Fatalf("cached absences = %d, want exactly the declared share %d", cached, share)
	}
	// Bindings are still cacheable: the bound exists to protect them.
	if out := f.lookup(t, fuse.FUSE_ROOT_ID, "present"); out.EntryValid == 0 {
		t.Fatal("a saturated absence registry stopped this mount caching a name that exists")
	}
}

// --- revocation withdraws what it published --------------------------------

func TestRevocationWithdrawsCachedAbsences(t *testing.T) {
	f := newStrictFixture(t)
	f.markMissing("gone-a", "gone-b")
	for _, name := range []string{"gone-a", "gone-b"} {
		if status, _ := f.probe(t, fuse.FUSE_ROOT_ID, name); !status.Ok() {
			t.Fatalf("negative LOOKUP %q = %v", name, status)
		}
	}
	f.lookup(t, fuse.FUSE_ROOT_ID, "still-here")
	f.raw.revokeCachedNames(time.Now().Add(time.Second))
	expired := map[string]bool{}
	deletes := 0
	for _, call := range f.notify.snapshot() {
		switch call.kind {
		case "entry":
			expired[call.name] = true
		case "delete":
			deletes++
		}
	}
	// A dying mount that leaves a cached "not there" behind is exactly as wrong
	// as one that leaves a cached binding: the name may already exist.
	if !expired["gone-a"] || !expired["gone-b"] {
		t.Fatalf("revocation expired %v; every published absence must be withdrawn", expired)
	}
	if deletes == 0 {
		t.Fatal("revocation withdrew absences but not bindings")
	}
	f.raw.mu.Lock()
	defer f.raw.mu.Unlock()
	if len(f.raw.cachedNegatives) != 0 {
		t.Fatalf("cached absences after revocation = %d, want 0", len(f.raw.cachedNegatives))
	}
}

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
	strict := newMount(context.Background(), newFakeRPC(), testStrictConfig(8))
	defer strict.cancel()
	want := testStrictConfig(8).MaxInFlight - reclaimLaneWidth(testStrictConfig(8).MaxInFlight) - livenessReserve - visibilityReserve
	if cap(strict.bulk) != want {
		t.Fatalf("bulk lane = %d, want %d; visibility and liveness slots must be structurally reserved", cap(strict.bulk), want)
	}
}
