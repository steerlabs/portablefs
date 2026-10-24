//go:build linux

package fusev3

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

func bindWorkspaceTestGate(t *testing.T, m *Mount) *workspaceadmission.Supervisor {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root gate owner; run in the Linux race container")
	}
	start, err := mountcontrol.ProcessStart(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	binding := workspaceadmission.Binding{Boot: [16]byte{1}, HostService: [16]byte{2}, GuestService: [16]byte{3}, Incarnation: [16]byte{4}, SupervisorPID: int32(os.Getpid()), SupervisorStart: start}
	g, err := workspaceadmission.New(binding)
	if err != nil {
		t.Fatal(err)
	}
	files, err := g.ChildFiles()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := workspaceadmission.Adopt(files[0], files[1], binding, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.workspace = reader
	selected := m.raw.fileSystemForServer()
	if _, ok := selected.(*workspaceFileSystem); !ok {
		t.Fatal("managed mount did not select admission adapter")
	}
	if _, ok := selected.(fuse.ReplyWriteLifecycle); !ok {
		t.Fatal("adapter lost physical reply lifecycle")
	}
	if _, ok := selected.(fuse.ReplyPayloadPreparer); !ok {
		t.Fatal("adapter lost payload preparation")
	}
	proof, err := g.Recovery(1)
	if err != nil {
		t.Fatal(err)
	}
	m.subscription.mu.Lock()
	m.subscription.workspaceProof = &proof
	m.subscription.mu.Unlock()
	if err := g.Prepared(proof); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(1, proof.Serial()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.cancel(); m.delegations.Stop(); _ = g.Dispose(); _ = reader.Retire() })
	return g
}

func TestWorkspaceFastAnswersCloseBeforeServing(t *testing.T) {
	for _, kind := range []string{"positive", "negative", "complete-directory", "getattr", "holder-lookup", "holder-getattr"} {
		t.Run(kind, func(t *testing.T) {
			f := newStockFixture(t)
			f.rpc.missingNames["missing"] = true
			entry := f.lookup(t, 1, "cached")
			f.lookup(t, 1, "missing")
			if kind == "holder-lookup" || kind == "holder-getattr" {
				opened := openDelegatedWriter(t, f, entry.NodeId)
				writeDelegated(t, f, entry.NodeId, opened.Fh, 0, []byte("held"))
				if s := f.rawCall(func(unique uint64) fuse.Status {
					return testEntryFileSystem(f.raw).GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &fuse.AttrOut{})
				}); s != fuse.OK {
					t.Fatal(s)
				}
			}
			if kind == "complete-directory" {
				f.raw.completeDirectories[f.raw.nodesByID[1].identity] = &directoryCompleteness{valid: true, stamp: f.mount.subscription.stamp().withVersion(1)}
			}
			g := bindWorkspaceTestGate(t, f.mount)
			// Warm facts were installed before the gate was attached. Rebind only this
			// test's facts to its initial proof; production does so during cold Subscribe.
			g.Close(1)
			calls := f.rpcCalls()
			record := f.raw.nodesByID[entry.NodeId]
			lookups := record.lookups
			unique := f.unique.Add(2)
			var status fuse.Status
			switch kind {
			case "getattr", "holder-getattr":
				status = testEntryFileSystem(f.raw).GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &fuse.AttrOut{})
			default:
				name := "cached"
				if kind == "negative" {
					name = "missing"
				}
				if kind == "complete-directory" {
					name = "not-enumerated"
				}
				status = testEntryFileSystem(f.raw).Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, name, &fuse.EntryOut{})
			}
			if status != fuse.EIO || f.rpcCalls() != calls || record.lookups != lookups || f.raw.ReplyWriteTracked(unique) {
				t.Fatalf("closed %s changed answer/owner: %v calls=%d lookups=%d", kind, status, f.rpcCalls()-calls, record.lookups-lookups)
			}
		})
	}
}

func TestWorkspaceCachedReplyRollbackAndFixedCohort(t *testing.T) {
	f := newStockFixture(t)
	entry := f.lookup(t, 1, "cached")
	g := bindWorkspaceTestGate(t, f.mount)
	record := f.raw.nodesByID[entry.NodeId]
	before := record.lookups
	unique := f.unique.Add(2)
	if status := testEntryFileSystem(f.raw).Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "cached", &fuse.EntryOut{}); status != fuse.OK {
		t.Fatal(status)
	}
	p := f.raw.replyPublications[unique]
	if !p.cachedArena || record.lookups != before+1 {
		t.Fatal("fast answer lost arena/reference owner")
	}
	g.Close(1)
	cut := f.mount.workspaceFS().captureWorkspaceReplies()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := cut.wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled wait pretended to join")
	}
	if f.raw.replyPublications[unique] != p {
		t.Fatal("cancelled waiter released physical owner")
	}
	for i := 0; i < 10; i++ {
		u := f.unique.Add(2)
		if status := testEntryFileSystem(f.raw).Lookup(nil, &fuse.InHeader{Unique: u, NodeId: 1}, "cached", &fuse.EntryOut{}); status != fuse.EIO {
			t.Fatal(status)
		}
	}
	_, reply, prepare := f.raw.PrepareReplyPayload(unique, 1, 1, nil, nil, 0)
	if reply != fuse.EIO || prepare != fuse.OK {
		t.Fatal("arena shortcut bypassed final gate")
	}
	f.raw.ReplyWritten(unique, fuse.OK)
	if err := cut.wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	if record.lookups != before || len(f.raw.replyPublications) != 0 {
		t.Fatal("cached refusal leaked lookup or cohort")
	}
	t.Run("transfer-and-response-settlement", func(t *testing.T) {
		f := newStockFixture(t)
		g := bindWorkspaceTestGate(t, f.mount)
		unique := f.unique.Add(2)
		reservation, status := f.mount.workspaceFS().beginWorkspaceEntry(unique)
		if status != fuse.OK {
			t.Fatal(status)
		}
		g.Close(1)
		cut := f.mount.workspaceFS().captureWorkspaceReplies()
		ctx, finish, status := f.raw.mutationContext(unique)
		if status != fuse.OK {
			t.Fatal(status)
		}
		entered, release := make(chan struct{}), make(chan struct{})
		if err := retainAuthorityResponse(ctx, workspaceConsumeFunc(func() { close(entered); <-release })); err != nil {
			t.Fatal(err)
		}
		finish()
		f.mount.workspaceFS().finishWorkspaceEntry(unique, reservation)
		f.raw.PrepareReplyPayload(unique, 1, 20, nil, nil, 0)
		settled := make(chan struct{})
		go func() { f.raw.ReplyWritten(unique, fuse.OK); close(settled) }()
		<-entered
		canceled, cancel := context.WithCancel(t.Context())
		cancel()
		if err := cut.wait(canceled); !errors.Is(err, context.Canceled) {
			t.Fatal("cohort joined only the write observation", err)
		}
		close(release)
		<-settled
		if err := cut.wait(t.Context()); err != nil {
			t.Fatal(err)
		}
	})

}

func TestWorkspaceEmptyPublicationsRetainOwner(t *testing.T) {
	for _, opcode := range []uint32{16, 20, 31, 50} {
		t.Run(syscall.Errno(opcode).Error(), func(t *testing.T) {
			f := newStockFixture(t)
			g := bindWorkspaceTestGate(t, f.mount)
			unique := f.unique.Add(2)
			entry, status := f.mount.workspaceFS().beginWorkspaceEntry(unique)
			if status != fuse.OK {
				t.Fatal(status)
			}
			_, finish, status := f.raw.mutationContext(unique)
			if status != fuse.OK {
				t.Fatal(status)
			}
			finish()
			f.mount.workspaceFS().finishWorkspaceEntry(unique, entry)
			if p := f.raw.replyPublications[unique]; p == nil || !p.callbackOwned || !p.workspaceBound {
				t.Fatal("empty admitted reply lost transferred owner")
			}
			g.Close(1)
			cut := f.mount.workspaceFS().captureWorkspaceReplies()
			_, reply, prepare := f.raw.PrepareReplyPayload(unique, 1, opcode, nil, nil, 0)
			if reply != fuse.OK || prepare != fuse.OK {
				t.Fatal("empty accepted result fabricated no-change failure")
			}
			f.raw.ReplyWritten(unique, fuse.OK)
			if err := cut.wait(t.Context()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWorkspaceLatePhysicalReadPurgesAfterWrite(t *testing.T) {
	for _, size := range []int{0, 1, 4} {
		t.Run(syscall.Errno(size).Error(), func(t *testing.T) {
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "cached")
			opened := f.openForData(t, entry.NodeId)
			g := bindWorkspaceTestGate(t, f.mount)
			f.rpc.mu.Lock()
			f.rpc.fileData = make([]byte, size)
			f.rpc.mu.Unlock()
			unique := f.unique.Add(2)
			result, status := f.raw.Read(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Fh: opened.Fh, Offset: 0, Size: 4}, make([]byte, 4))
			if status != fuse.OK {
				t.Fatal(status)
			}
			if result != nil {
				defer result.Done()
			}
			if _, reply, prepare := f.raw.PrepareReplyPayload(unique, entry.NodeId, 15, nil, nil, size); reply != fuse.OK || prepare != fuse.OK {
				t.Fatal(reply, prepare)
			}
			before := len(f.notify.snapshot())
			g.Close(1)
			if len(f.notify.snapshot()) != before {
				t.Fatal("purge preceded physical write")
			}
			f.raw.ReplyWritten(unique, fuse.OK)
			calls := f.notify.snapshot()
			if len(calls) <= before || calls[len(calls)-1].kind != "inode" {
				t.Fatal("late READ lost its post-write purge")
			}
			if f.raw.ReplyWriteTracked(unique) {
				t.Fatal("physical READ retained reply owner")
			}
		})
	}
}

func TestWorkspaceClosedCleanupAndFlushUnlock(t *testing.T) {
	// The successful cleanup fixture must return the paired delegation-release
	// reply before its asynchronous final CLOSE can preserve the incarnation.
	f, g, _ := coldFixture(t)
	entry := f.lookup(t, 1, "cached")
	opened := openDelegatedWriter(t, f, entry.NodeId)
	var directory fuse.OpenOut
	if s := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: unique, NodeId: 1}}, &directory)
	}); s != fuse.OK {
		t.Fatal(s)
	}
	record := f.raw.nodesByID[entry.NodeId]
	key := record.node.posixLockKey(7)
	f.mount.notePOSIXLock(key)
	g.Close(1)
	status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.Flush(nil, &fuse.FlushIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Fh: opened.Fh, LockOwner: 7})
	})
	if status != fuse.OK || f.mount.possiblePOSIXLock(key) != 0 {
		t.Fatal("closed clean FLUSH lost success/unlock", status)
	}
	f.rawCall(func(unique uint64) fuse.Status {
		f.raw.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{Unique: unique}, Fh: opened.Fh})
		return fuse.OK
	})
	f.rawCall(func(unique uint64) fuse.Status {
		f.raw.ReleaseDir(&fuse.ReleaseIn{InHeader: fuse.InHeader{Unique: unique}, Fh: directory.Fh})
		return fuse.OK
	})
	f.raw.mu.RLock()
	_, filePresent := f.raw.handles[opened.Fh]
	_, dirPresent := f.raw.handles[directory.Fh]
	f.raw.mu.RUnlock()
	if filePresent || dirPresent {
		t.Fatal("closed RELEASE stranded a handle")
	}
	before := record.lookups
	f.raw.Forget(entry.NodeId, 1)
	if record.lookups != before-1 {
		t.Fatal("closed FORGET stranded lookup")
	}
	if f.mount.delegations.incarnation() == 0 {
		t.Fatal("Close erased cleanup incarnation", f.mount.fatalError())
	}
}

func TestWorkspaceRecoveryAndDrainAreNotServing(t *testing.T) {
	f := newStockFixture(t)
	g := bindWorkspaceTestGate(t, f.mount)
	g.Close(1)
	proof, err := g.Recovery(1)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(t.Context(), workspaceRecoveryKey{}, proof)
	if err := f.mount.subscription.subscribe(ctx); err != nil {
		t.Fatal(err)
	}
	if f.mount.subscription.stamp().incarnation != 0 {
		t.Fatal("cold recovery served files")
	}
	if _, _, _, active := f.mount.subscription.currentIncarnation(); !active {
		t.Fatal("closed recovery lost control liveness")
	}
	deadline := f.mount.subscription.config.clock.Now().Add(time.Hour)
	drain := f.mount.workspaceFS().captureWorkspaceDrain(deadline)
	if f.mount.workspaceFS().drainIncarnation(drain) == 0 {
		t.Fatal("closed drain lost captured incarnation")
	}
	_, controlDeadline, _, controlLive := f.mount.subscription.currentIncarnation()
	if !controlLive || !controlDeadline.Equal(drain.deadline) || !drain.deadline.Equal(f.mount.subscription.cacheUntil) {
		t.Fatal("CONTROL replaced the captured drain deadline", controlDeadline, drain.deadline)
	}
	if f.mount.subscription.acceptRenewal(drain.incarnation, deadline.Add(time.Minute)) {
		t.Fatal("drain renewed the old horizon")
	}
	f.mount.subscription.config.clock = &subscriptionTestClock{now: drain.deadline.Add(time.Nanosecond)}
	if _, _, _, live := f.mount.subscription.currentIncarnation(); live {
		t.Fatal("expired drain fell back to recovery permission")
	}
	if f.mount.workspaceFS().drainIncarnation(drain) != 0 {
		t.Fatal("expired drain remained usable")
	}

	if drain.allows(&writeback.Buffer{}, drain.incarnation, time.Now()) || drain.allows(drain.buffer, drain.incarnation, deadline) {
		t.Fatal("drain widened buffer/deadline")
	}
	g.Close(1)
	f.mount.subscription.mu.Lock()
	f.mount.subscription.workspaceDrain = nil
	f.mount.subscription.mu.Unlock()
	if _, _, _, active := f.mount.subscription.currentIncarnation(); active {
		t.Fatal("later Close revived recovery proof")
	}
}

func TestWorkspaceCapacityWaitChecksActualAcceptance(t *testing.T) {
	for _, kind := range []string{"write", "truncate", "metadata"} {
		t.Run(kind, func(t *testing.T) {
			f := newStockFixture(t)
			f.mount.delegations.Stop()
			m, err := newDelegationManager(f.rpc, time.Second, f.mount.subscription.stamp().incarnation, writeback.Options{MaxEntries: 1, MaxBytes: 1024})
			if err != nil {
				t.Fatal(err)
			}
			f.mount.delegations, f.mount.subscription.control, m.subscription = m, m, f.mount.subscription
			t.Cleanup(m.Stop)
			entry := f.lookup(t, 1, "cached")
			g := bindWorkspaceTestGate(t, f.mount)
			opened := openDelegatedWriter(t, f, entry.NodeId)
			writeDelegated(t, f, entry.NodeId, opened.Fh, 0, []byte("old"))
			unique := f.unique.Add(2)
			reservation, status := f.mount.workspaceFS().beginWorkspaceEntry(unique)
			if status != fuse.OK {
				t.Fatal(status)
			}
			ctx, finish, status := f.raw.mutationContext(unique)
			if status != fuse.OK {
				t.Fatal(status)
			}
			identity := f.raw.nodesByID[entry.NodeId].identity
			done := make(chan error, 1)
			go func() {
				var err error
				switch kind {
				case "write":
					_, err = m.Write(ctx, identity[:], 10, []byte("new"), false)
				case "truncate":
					_, err = m.Truncate(ctx, identity[:], 100)
				default:
					_, err = m.SetAttr(ctx, identity[:], writeback.Attributes{HasMode: true, Mode: 0600})
				}
				done <- err
			}()
			waitUntil(t, time.Second, "buffer capacity waiter", func() bool { return m.buf.Stats().WaitingAdmissions == 1 })
			sequence := m.buf.Snapshot().Sequence
			g.Close(1)
			// Free capacity without fencing the Buffer. Only the captured full-word
			// predicate can reject this waiter before it accepts another sequence.
			m.buf.Drop(writeback.Identity(identity), "test releases old capacity")
			if err := <-done; !errors.Is(err, workspaceadmission.ErrClosed) {
				t.Fatalf("waiter accepted after Close: %v", err)
			}
			if m.buf.Snapshot().Sequence != sequence {
				t.Fatal("closed waiter assigned a sequence")
			}
			finish()
			f.mount.workspaceFS().finishWorkspaceEntry(unique, reservation)
			f.raw.PrepareReplyPayload(unique, entry.NodeId, 16, nil, nil, 0)
			f.raw.ReplyWritten(unique, fuse.OK)
		})
	}
}

func TestWorkspaceScratchOpenLoopStopsOnClose(t *testing.T) {
	f := newStockFixture(t)
	entry := f.lookup(t, 1, "cached")
	opened := openDelegatedWriter(t, f, entry.NodeId)
	state := f.mount.delegations.retainState(writeback.Identity(f.raw.nodesByID[entry.NodeId].identity), false)
	state.admission.Lock()
	state.clearGrantLocked()
	state.admission.Unlock()
	f.mount.delegations.releaseState(state)
	g := bindWorkspaceTestGate(t, f.mount)
	f.rpc.mu.Lock()
	var opens atomic.Int32
	var once sync.Once
	f.rpc.hook = func(req *authoritypb.Request) {
		if req.GetOpen() != nil {
			opens.Add(1)
		}
	}
	f.rpc.afterMutation = func() { once.Do(func() { g.Close(1) }) }
	f.rpc.mu.Unlock()
	unique := f.unique.Add(2)
	_, status := f.raw.Write(nil, &fuse.WriteIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Fh: opened.Fh, Size: 1, Flags: syscall.O_RDWR}, []byte("x"))
	if status == fuse.OK || opens.Load() != 1 {
		t.Fatalf("closed reacquisition loop status=%v scratch opens=%d", status, opens.Load())
	}
	if f.raw.ReplyWriteTracked(unique) {
		f.raw.PrepareReplyPayload(unique, entry.NodeId, 16, nil, nil, 0)
		f.raw.ReplyWritten(unique, fuse.OK)
	}
}

func TestWorkspaceAcceptedCreateAndWriteKeepPhysicalOwner(t *testing.T) {
	for _, kind := range []string{"create", "write"} {
		t.Run(kind, func(t *testing.T) {
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "cached")
			g := bindWorkspaceTestGate(t, f.mount)
			var opened *fuse.OpenOut
			if kind == "write" {
				opened = openDelegatedWriter(t, f, entry.NodeId)
			}
			unique := f.unique.Add(2)
			opcode := uint32(16)
			if kind == "create" {
				f.rpc.mu.Lock()
				f.rpc.afterMutation = func() { g.Close(1) }
				f.rpc.mu.Unlock()
				status := f.raw.Create(nil, &fuse.CreateIn{InHeader: fuse.InHeader{Unique: unique, NodeId: 1}, Mode: 0600, Flags: syscall.O_RDWR}, "accepted", &fuse.CreateOut{})
				if status != fuse.OK {
					t.Fatal("accepted CREATE fabricated refusal", status)
				}
				opcode = 35
			} else {
				count, status := f.raw.Write(nil, &fuse.WriteIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Fh: opened.Fh, Size: 1, Flags: syscall.O_RDWR}, []byte("x"))
				if status != fuse.OK || count != 1 {
					t.Fatal(count, status)
				}
				g.Close(1)
			}
			p := f.raw.replyPublications[unique]
			if p == nil || p.source == nil {
				t.Fatal("accepted effect lost physical/source owner")
			}
			cut := f.mount.workspaceFS().captureWorkspaceReplies()
			_, reply, prepare := f.raw.PrepareReplyPayload(unique, entry.NodeId, opcode, nil, nil, 0)
			if reply != fuse.OK || prepare != fuse.OK {
				t.Fatal("accepted effect became no-change error", reply, prepare)
			}
			f.raw.ReplyWritten(unique, fuse.OK)
			if err := cut.wait(t.Context()); err != nil {
				t.Fatal(err)
			}
			if f.raw.ReplyWriteTracked(unique) {
				t.Fatal("settled effect retained reply")
			}
		})
	}
}

type workspaceSubscribeBarrier struct {
	subscriptionRPC
	entered, release chan struct{}
}

func (b workspaceSubscribeBarrier) Subscribe(ctx context.Context, snapshot, after []byte) (*authoritypb.SubscribeReply, time.Time, error) {
	close(b.entered)
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, time.Time{}, ctx.Err()
	}
	return b.subscriptionRPC.Subscribe(ctx, snapshot, after)
}
func TestWorkspaceInitialSubscribeLosesToPark(t *testing.T) {
	f := newStockFixture(t)
	g := bindWorkspaceTestGate(t, f.mount)
	g.Close(1)
	proof, err := g.Recovery(1)
	if err != nil {
		t.Fatal(err)
	}
	barrier := workspaceSubscribeBarrier{subscriptionRPC: f.rpc, entered: make(chan struct{}), release: make(chan struct{})}
	f.mount.subscription.rpc = barrier
	done := make(chan error, 1)
	go func() {
		done <- f.mount.subscription.subscribe(context.WithValue(t.Context(), workspaceRecoveryKey{}, proof))
	}()
	<-barrier.entered
	g.Close(1)
	f.mount.subscription.suspend()
	close(barrier.release)
	err = <-done
	var loss *workspaceadmission.PermitOvertaken
	if !errors.As(err, &loss) || loss.Generation != 1 || loss.Serial != proof.Serial() || loss.Successor != proof.Serial()+1 || workspaceSubscribeAttempt(err).Disposition != authorityrpc.AttemptOvertaken {
		t.Fatal("Subscribe lost its exact overtaking disposition", err)
	}
	if f.mount.subscription.stamp().incarnation != 0 {
		t.Fatal("parked initial Subscribe served")
	}
}

func TestWorkspaceCloseAfterLastInstallationCheckIsInert(t *testing.T) {
	for _, owner := range []string{"subscription", "delegation"} {
		t.Run(owner, func(t *testing.T) {
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "cached")
			g := bindWorkspaceTestGate(t, f.mount)
			if owner == "subscription" {
				g.Close(1)
				proof, err := g.Recovery(1)
				if err != nil {
					t.Fatal(err)
				}
				f.mount.subscription.config.beforeWorkspaceInstall = func() { g.Close(1) }
				if err := f.mount.subscription.subscribe(context.WithValue(t.Context(), workspaceRecoveryKey{}, proof)); err != nil {
					t.Fatal(err)
				}
				if stamp := f.mount.subscription.stamp(); stamp.incarnation != 0 {
					t.Fatal("post-check subscription store became usable for serving")
				}
				// currentIncarnation describes old CONTROL, not cache-serving
				// authority. Closing the gate cannot create a CONTROL gap.
				if _, _, _, live := f.mount.subscription.currentIncarnation(); !live {
					t.Fatal("post-check Close revoked the retained CONTROL capability")
				}
				if err := g.Prepared(proof); !errors.Is(err, workspaceadmission.ErrClosed) {
					t.Fatal("obsolete local install opened gate")
				}
			} else {
				f.mount.delegations.beforeWorkspaceInstall = func() { g.Close(1) }
				opened := openDelegatedWriter(t, f, entry.NodeId)
				identity := f.raw.nodesByID[entry.NodeId].identity
				if !f.mount.delegations.Owns(identity[:]) {
					t.Fatal("post-check grant lost retained cleanup ownership")
				}
				if st := f.rawCall(func(u uint64) fuse.Status {
					_, st := f.raw.Write(nil, &fuse.WriteIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}, Fh: opened.Fh, Size: 1}, []byte("x"))
					return st
				}); st != fuse.EIO {
					t.Fatal("new write used closed install", st)
				}
				if st := f.rawCall(func(u uint64) fuse.Status {
					return testEntryFileSystem(f.raw).GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}}, &fuse.AttrOut{})
				}); st != fuse.EIO {
					t.Fatal("new holder GETATTR used closed install", st)
				}
				state := f.mount.delegations.retainState(writeback.Identity(identity), false)
				state.admission.RLock()
				retained := state.ref != nil
				state.admission.RUnlock()
				f.mount.delegations.releaseState(state)
				if !retained || f.mount.delegations.incarnation() == 0 {
					t.Fatal("inert install lost exact cleanup identity")
				}
				f.raw.Release(nil, &fuse.ReleaseIn{Fh: opened.Fh})
			}
			if f.mount.subscription.stamp().incarnation != 0 {
				t.Fatal("post-close assignment served")
			}
		})
	}
}

func TestWorkspaceSlowHelperCannotInventServingAdmission(t *testing.T) {
	f := newStockFixture(t)
	g := bindWorkspaceTestGate(t, f.mount)
	g.Close(1)
	unique := f.unique.Add(2)
	_, finish, status := f.raw.mutationContext(unique)
	finish()
	if status != fuse.EIO || f.raw.ReplyWriteTracked(unique) || f.mount.isRevoked() {
		t.Fatal("slow helper bypassed or terminalized closed admission", status)
	}
	_, cleanup, status := f.raw.cleanupContext(f.unique.Add(2))
	if status != fuse.OK {
		t.Fatal("cleanup acquired a serving requirement", status)
	}
	cleanup()
}

type workspaceConsumeFunc func()

func (consume workspaceConsumeFunc) Consume() { consume() }
