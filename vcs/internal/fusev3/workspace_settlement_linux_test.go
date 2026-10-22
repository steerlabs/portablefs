//go:build linux

package fusev3

import (
	"context"
	"errors"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

func assertWorkspaceCompletionOpen(t *testing.T, done <-chan struct{}) {
	t.Helper()
	if done == nil {
		t.Fatal("missing workspace completion")
	}
	select {
	case <-done:
		t.Fatal("settlement completed while its claimant still holds a reference")
	default:
	}
}

func waitSourceWaiter(t *testing.T, r *rawFileSystem, previous <-chan struct{}) <-chan struct{} {
	t.Helper()
	var next <-chan struct{}
	waitUntil(t, time.Second, "drain rechecked the registry predicate", func() bool {
		r.mu.RLock()
		defer r.mu.RUnlock()
		next = r.sourceChanged
		return next != nil && next != previous
	})
	return next
}

// Adapted from zz_review_r2_terminal_linux_test.go. Every variant uses the
// real raw entry, including machine-local replies with no authority response.
func TestReviewR2TerminalRacesWrittenTail(t *testing.T) {
	for _, variant := range []string{"arena-getattr", "arena-lookup", "heap-estale", "heap-graft"} {
		t.Run(variant, func(t *testing.T) {
			var r *rawFileSystem
			var node, unique uint64
			var record *inodeRecord
			var lookups uint64
			if variant == "heap-graft" {
				f := newGraftFixture(t, mustRoutes(t, "node_modules/\n"), false)
				parent := f.mkdir(t, 1, "node_modules")
				node = f.createFile(t, parent.NodeId, "local", []byte("local")).NodeId
				bindWorkspaceTestGate(t, f.mount)
				r = f.raw
				unique = nextTestRequestUnique()
			} else {
				f := newStockFixture(t)
				entry := f.lookup(t, 1, "cached")
				f.lookup(t, 1, "cached")
				node, r = entry.NodeId, f.raw
				bindWorkspaceTestGate(t, f.mount)
				// Holder GETATTR/LOOKUP also exercise exact admission-pin release.
				opened := openDelegatedWriter(t, f, node)
				writeDelegated(t, f, node, opened.Fh, 0, []byte("seed"))
				if st := f.rawCall(func(u uint64) fuse.Status {
					return testEntryFileSystem(r).GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: u, NodeId: node}}, &fuse.AttrOut{})
				}); st != fuse.OK {
					t.Fatal(st)
				}
				record = r.nodesByID[node]
				lookups = record.lookups
				unique = f.unique.Add(2)
			}
			if variant == "heap-estale" || variant == "heap-graft" {
				for i := range r.cachedReplyArena {
					if _, st := r.mount.managed.beginWorkspaceEntry(1<<50 + uint64(i)); st != fuse.OK {
						t.Fatal(st)
					}
				}
			}
			opcode := uint32(3)
			switch variant {
			case "arena-lookup":
				opcode = 1
				if st := testEntryFileSystem(r).Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "cached", &fuse.EntryOut{}); st != fuse.OK {
					t.Fatal(st)
				}
			default:
				if variant == "heap-estale" {
					node = 1 << 40
				}
				st := testEntryFileSystem(r).GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: node}}, &fuse.AttrOut{})
				if variant == "heap-estale" && st != fuse.Status(syscall.ESTALE) || variant != "heap-estale" && st != fuse.OK {
					t.Fatal(st)
				}
			}
			r.mu.Lock()
			p := r.replyPublications[unique]
			if p == nil {
				t.Fatal("entry not tracked")
			}
			arena := p.cachedArena
			if arena != (variant == "arena-getattr" || variant == "arena-lookup") {
				t.Fatal("wrong storage variant")
			}
			if variant == "arena-lookup" {
				p.cacheRejected = true
			}
			pin := p.holderAdmission
			done := p.workspaceDone
			r.mu.Unlock()
			cut := r.mount.managed.captureWorkspaceReplies()
			r.PrepareReplyPayload(unique, node, opcode, nil, nil, 0)
			entered, release := make(chan struct{}), make(chan struct{})
			r.beforeReplySettlement = func(q *replyPublication) {
				if q == p {
					close(entered)
					<-release
				}
			}
			settled := make(chan struct{})
			go func() { r.ReplyWritten(unique, fuse.OK); close(settled) }()
			<-entered
			if !r.terminalizeReplyCacheOwnership(time.Now().Add(time.Second)) {
				t.Fatal("terminal write join failed")
			}
			assertWorkspaceCompletionOpen(t, done)
			r.mu.RLock()
			if r.replyPublications[unique] != p || !p.settlementClaimed || p.requestUnique != unique {
				t.Error("claimant lost its publication")
			}
			for free := r.cachedReplyFree; free != nil; free = free.cachedNext {
				if free == p {
					t.Error("storage recycled under its claimant")
				}
			}
			if variant == "arena-lookup" && record.lookups != lookups+1 {
				t.Error("terminalization rolled back the claimant's lookup")
			}
			r.mu.RUnlock()
			if pin != nil {
				assertMetadataPinReleased(t, pin)
			}
			close(release)
			<-settled
			if err := cut.wait(t.Context()); err != nil {
				t.Fatal(err)
			}
			if variant == "arena-lookup" && record.lookups != lookups {
				t.Fatal("lookup rollback was not exactly once")
			}
			if reviewArenaFree(r) != len(r.cachedReplyArena) {
				t.Fatal("arena owners leaked or recycled twice")
			}
			if len(r.replyPublications) != 0 {
				t.Fatal("terminal cohort retained an owner")
			}
		})
	}
}

func TestWorkspaceConsumedResponseThenTerminalWrite(t *testing.T) {
	f := newStockFixture(t)
	entry := f.lookup(t, 1, "cached")
	bindWorkspaceTestGate(t, f.mount)
	u := f.unique.Add(2)
	ctx, finish, st := f.raw.mutationContext(u)
	if st != fuse.OK {
		t.Fatal(st)
	}
	p := replyPublicationFromContext(ctx)
	gate, err := itemSourceGate(f.raw.nodesByID[entry.NodeId].node.item, true)
	if err != nil {
		t.Fatal(err)
	}
	callback := ctx.Value(mutationCallbackKey{}).(*mutationCallback)
	lease, err := callback.acquireSource(ctx, f.raw, gate)
	if err != nil {
		t.Fatal(err)
	}
	if err := completeDefiniteNoChangePublication(ctx); err != nil {
		t.Fatal(err)
	}
	var consumed atomic.Int32
	if err := retainAuthorityResponse(ctx, workspaceConsumeFunc(func() { consumed.Add(1) })); err != nil {
		t.Fatal(err)
	}
	finish()
	p.consumeAuthorityResponse()
	f.raw.PrepareReplyPayload(u, entry.NodeId, 4, nil, nil, 0)
	cut := f.mount.managed.captureWorkspaceReplies()
	if f.raw.terminalizeReplyCacheOwnership(time.Now()) {
		t.Fatal("unwritten reply unexpectedly joined")
	}
	f.raw.ReplyWritten(u, fuse.OK) // terminalizing records the write; it does not claim settlement
	f.raw.mu.RLock()
	claimed := p.settlementClaimed
	f.raw.mu.RUnlock()
	if claimed {
		t.Fatal("write observer claimed terminal settlement")
	}
	if !f.raw.finishReplyCacheTerminalization(false) {
		t.Fatal("terminal settlement failed")
	}
	if err := cut.wait(t.Context()); err != nil {
		t.Fatal(err)
	}
	if consumed.Load() != 1 || !lease.revoked || lease.released || len(f.raw.replyPublications) != 0 {
		t.Fatal("terminal claimant lost exact response/source cleanup")
	}
	f.raw.ReplyWritten(u, fuse.OK)
	f.raw.terminalizeReplyCacheOwnershipAfterConnectionGone()
	if consumed.Load() != 1 || reviewArenaFree(f.raw) != len(f.raw.cachedReplyArena) {
		t.Fatal("terminal cleanup ran twice")
	}
}

// The terminal claimant is paused directly, so this transfer test does not
// depend on map iteration order or retry until it happens to find a window.
func TestReviewR2TransferAfterTerminalLockedPhase(t *testing.T) {
	for _, phase := range []string{"terminalizing", "terminal"} {
		t.Run(phase, func(t *testing.T) {
			f := newStockFixture(t)
			bindWorkspaceTestGate(t, f.mount)
			u := f.unique.Add(2)
			entry, st := f.mount.managed.beginWorkspaceEntry(u)
			if st != fuse.OK {
				t.Fatal(st)
			}
			done := entry.workspaceDone
			cut := f.mount.managed.captureWorkspaceReplies()
			release, entered := make(chan struct{}), make(chan struct{})
			var terminal <-chan bool
			if phase == "terminalizing" {
				f.raw.mu.Lock()
				f.raw.replyTerminalizing = true
				f.raw.replyTerminalDone = make(chan struct{})
				f.raw.mu.Unlock()
			} else {
				f.raw.beforeReplySettlement = func(p *replyPublication) { close(entered); <-release }
				result := make(chan bool, 1)
				terminal = result
				go func() { result <- f.raw.terminalizeReplyCacheOwnership(time.Now().Add(time.Second)) }()
				<-entered
			}
			calls := f.rpcCalls()
			_, finish, status := f.raw.mutationContext(u)
			finish()
			if status != fuse.Status(syscall.ENOTCONN) || f.rpcCalls() != calls {
				t.Fatal("terminal callback acquired a serving owner", status)
			}
			assertWorkspaceCompletionOpen(t, done)
			if phase == "terminalizing" {
				if !f.raw.finishReplyCacheTerminalization(false) {
					t.Fatal("terminal settlement failed")
				}
			} else {
				close(release)
				if !<-terminal {
					t.Fatal("terminal settlement failed")
				}
			}
			f.mount.managed.finishWorkspaceEntry(u, entry)
			if err := cut.wait(t.Context()); err != nil {
				t.Fatal(err)
			}
			if len(f.raw.replyPublications) != 0 || reviewArenaFree(f.raw) != len(f.raw.cachedReplyArena) {
				t.Fatal("refused transfer leaked its old owner")
			}
		})
	}
}

// Adapted from zz_review_r2_wakeup_linux_test.go. A fresh sourceChanged channel
// proves the waiter has rechecked during the unlocked tail, without a sleep.
func TestReviewR2DrainLostWakeupAfterWrittenTail(t *testing.T) {
	for _, kind := range []string{"source", "buffered-data"} {
		for _, terminal := range []bool{false, true} {
			name := "written"
			if terminal {
				name = "terminal"
			}
			t.Run(kind+"/"+name, func(t *testing.T) {
				f := newStockFixture(t)
				entry := f.lookup(t, 1, "cached")
				bindWorkspaceTestGate(t, f.mount)
				opened := openDelegatedWriter(t, f, entry.NodeId)
				writeDelegated(t, f, entry.NodeId, opened.Fh, 0, []byte("seed"))
				u := f.unique.Add(2)
				opcode := uint32(3)
				coordinate := publicationCoordinate{kind: publicationItemAttributes, item: f.raw.nodesByID[entry.NodeId].identity}
				if kind == "source" {
					if st := testEntryFileSystem(f.raw).GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}}, &fuse.AttrOut{}); st != fuse.OK {
						t.Fatal(st)
					}
				} else {
					opcode, coordinate.kind = 15, publicationItemData
					opened = f.openForData(t, entry.NodeId)
					u = f.unique.Add(2)
					if _, st := f.raw.Read(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}, Fh: opened.Fh, Size: 4}, make([]byte, 4)); st != fuse.OK {
						t.Fatal(st)
					}
				}
				p := f.raw.replyPublications[u]
				cut := f.mount.managed.captureWorkspaceReplies()
				if !terminal {
					f.raw.PrepareReplyPayload(u, entry.NodeId, opcode, nil, nil, 0)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				drained := make(chan error, 1)
				go func() {
					if kind == "source" {
						lease := &sourcePublicationLease{r: f.raw, coordinates: map[publicationCoordinate]struct{}{coordinate: {}}}
						drained <- lease.drain(ctx)
					} else {
						drained <- f.raw.drainDataPublicationsContext(ctx, coordinate)
					}
				}()
				prior := waitSourceWaiter(t, f.raw, nil)
				entered, release := make(chan struct{}), make(chan struct{})
				f.raw.beforeReplySettlement = func(q *replyPublication) {
					if q == p {
						close(entered)
						<-release
					}
				}
				settled := make(chan struct{})
				go func() {
					if terminal {
						f.raw.terminalizeReplyCacheOwnership(time.Now().Add(time.Second))
					} else {
						f.raw.ReplyWritten(u, fuse.OK)
					}
					close(settled)
				}()
				<-entered
				waitSourceWaiter(t, f.raw, prior)
				assertWorkspaceCompletionOpen(t, p.workspaceDone)
				close(release)
				<-settled
				select {
				case err := <-drained:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("registry removal did not wake its waiter")
				}
				if err := cut.wait(ctx); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestWorkspaceSourceAcquisitionCancellationRemovesOnlyItsHolds(t *testing.T) {
	for _, refusal := range []string{"close", "cancel"} {
		t.Run(refusal, func(t *testing.T) {
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "cached")
			g := bindWorkspaceTestGate(t, f.mount)
			prior := f.unique.Add(2)
			if st := testEntryFileSystem(f.raw).GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: prior, NodeId: entry.NodeId}}, &fuse.AttrOut{}); st != fuse.OK {
				t.Fatal(st)
			}
			f.raw.PrepareReplyPayload(prior, entry.NodeId, 3, nil, nil, 0)
			before := f.mount.delegations.buf.Snapshot()
			calls := f.rpcCalls()
			unrelated := publicationCoordinate{kind: publicationItemAttributes, item: f.raw.nodesByID[1].identity}
			other := &sourcePublicationLease{r: f.raw, coordinates: map[publicationCoordinate]struct{}{unrelated: {}}, ready: true}
			f.raw.mu.Lock()
			f.raw.sourceHolds[unrelated] = other
			f.raw.mu.Unlock()
			u := f.unique.Add(2)
			finished := make(chan fuse.Status, 1)
			cancelOperation := make(chan context.CancelFunc, 1)
			go func() {
				if refusal == "close" {
					in := &fuse.SetAttrIn{SetAttrInCommon: fuse.SetAttrInCommon{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}, Valid: fuse.FATTR_MODE, Mode: 0600}}
					finished <- f.raw.SetAttr(nil, in, &fuse.AttrOut{})
				} else {
					operation, finish, st := f.raw.mutationContext(u)
					if st == fuse.OK {
						operation, stop := context.WithCancel(operation)
						cancelOperation <- stop
						callback := operation.Value(mutationCallbackKey{}).(*mutationCallback)
						gate, _ := itemSourceGate(f.raw.nodesByID[entry.NodeId].node.item, false)
						lease, err := callback.acquireSource(operation, f.raw, gate)
						if lease != nil || !errors.Is(err, context.Canceled) {
							t.Error("cancelled acquisition returned an effect owner", lease, err)
						}
						stop()
						finish()
					}
					finished <- fuse.EINTR
				}
			}()
			coordinate := publicationCoordinate{kind: publicationItemAttributes, item: f.raw.nodesByID[entry.NodeId].identity}
			var lease *sourcePublicationLease
			waitUntil(t, time.Second, "source hold installed before acquisition returns", func() bool {
				f.raw.mu.RLock()
				defer f.raw.mu.RUnlock()
				lease = f.raw.sourceHolds[coordinate]
				return lease != nil
			})
			waitSourceWaiter(t, f.raw, nil)
			if refusal == "close" {
				g.Close(1)
			} else {
				(<-cancelOperation)()
			}
			f.raw.ReplyWritten(prior, fuse.OK)
			if st := <-finished; st == fuse.OK {
				t.Fatal("refused acquisition accepted work")
			}
			f.raw.mu.RLock()
			if !lease.released || lease.assigned || lease.ready || lease.revoked || f.raw.sourceHolds[coordinate] != nil || f.raw.sourceHolds[unrelated] != other {
				t.Error("no-effect cancellation did not remove exactly its holds")
			}
			f.raw.mu.RUnlock()
			if f.rpcCalls() != calls || f.mount.delegations.buf.Snapshot() != before || f.mount.isRevoked() {
				t.Fatal("acquisition refusal applied work or terminalized")
			}
			if f.raw.ReplyWriteTracked(u) {
				f.raw.PrepareReplyPayload(u, entry.NodeId, 4, nil, nil, 0)
				f.raw.ReplyWritten(u, fuse.OK)
			}
			other.release()
			if refusal == "close" {
				recovery, err := g.Recovery(1)
				if err != nil {
					t.Fatal(err)
				}
				child, err := f.mount.workspace.Recovery(1, recovery.Serial())
				if err != nil {
					t.Fatal(err)
				}
				if err := f.mount.subscription.subscribe(context.WithValue(t.Context(), workspaceRecoveryKey{}, child)); err != nil {
					t.Fatal(err)
				}
				if err := g.Prepared(recovery); err != nil {
					t.Fatal(err)
				}
				if err := g.Open(1, recovery.Serial()); err != nil {
					t.Fatal(err)
				}
			}
			if st := f.rawCall(func(u uint64) fuse.Status {
				return f.raw.SetAttr(nil, &fuse.SetAttrIn{SetAttrInCommon: fuse.SetAttrInCommon{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}, Valid: fuse.FATTR_MODE, Mode: 0600}}, &fuse.AttrOut{})
			}); st != fuse.OK {
				t.Fatal("same-session source use failed after recovery", st)
			}
			if len(f.raw.sourceHolds) != 0 || f.mount.isRevoked() {
				t.Fatal("recovery retained an orphan hold")
			}
		})
	}
}

// File FSYNC can retire an exact prefix while background volume durability
// stays parked. This fixes the pending-data assertions independently of timers.
type workspaceFlushCutRPC struct {
	*fakeRPC
	barrier <-chan struct{}
}

func (r *workspaceFlushCutRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetBarrier() != nil {
		select {
		case <-r.barrier:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return r.fakeRPC.CallMutation(ctx, request)
}

// Imported from zz_review_r2_flush_linux_test.go, with failing assertions for
// the fixed result and for separate clean and dirty writer descriptions.
func TestReviewR2ClosedReadOnlyFlushOnDirtyFile(t *testing.T) {
	for _, mode := range []string{"pending", "durable-prefix", "cold", "cold-reuse", "cold-loss"} {
		t.Run(mode, func(t *testing.T) {
			f := newStockFixture(t)
			barrier := make(chan struct{})
			defer close(barrier)
			f.mount.delegations.rpc = &workspaceFlushCutRPC{fakeRPC: f.rpc, barrier: barrier}
			entry := f.lookup(t, 1, "cached")
			g := bindWorkspaceTestGate(t, f.mount)
			writer := openDelegatedWriter(t, f, entry.NodeId)
			other := openDelegatedWriter(t, f, entry.NodeId)
			writeDelegated(t, f, entry.NodeId, writer.Fh, 0, []byte("dirty"))
			writerResult, otherResult := fuse.EIO, fuse.OK
			if mode != "pending" && mode != "cold-loss" {
				// Keep the old sequence above the successor sequences. A maximum
				// across epochs would then charge A for B even after reusing A.
				for i := 0; i < 4; i++ {
					writeDelegated(t, f, entry.NodeId, writer.Fh, 0, []byte("dirty"))
				}
				if st := f.rawCall(func(u uint64) fuse.Status {
					return f.raw.Fsync(nil, &fuse.FsyncIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}, Fh: writer.Fh})
				}); st != fuse.OK {
					t.Fatal(st)
				}
				writeDelegated(t, f, entry.NodeId, other.Fh, 0, []byte("later"))
				writerResult, otherResult = fuse.OK, fuse.EIO
			}
			if mode == "cold" || mode == "cold-reuse" || mode == "cold-loss" {
				// Retain both frontend descriptions across the real same-session
				// cold transition, including FenceSubscription/resetBuffer.
				if mode != "cold-loss" {
					if st := f.rawCall(func(u uint64) fuse.Status {
						return f.raw.Fsync(nil, &fuse.FsyncIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}, Fh: other.Fh})
					}); st != fuse.OK {
						t.Fatal(st)
					}
				}
				old := f.mount.delegations.buf
				g.Close(1)
				proof, err := g.Recovery(1)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.mount.subscription.subscribe(context.WithValue(t.Context(), workspaceRecoveryKey{}, proof)); err != nil {
					t.Fatal(err)
				}
				if f.mount.delegations.buf == old {
					t.Fatal("cold subscribe did not replace buffer")
				}
				if err := g.Prepared(proof); err != nil {
					t.Fatal(err)
				}
				if err := g.Open(1, proof.Serial()); err != nil {
					t.Fatal(err)
				}
				if mode == "cold-loss" {
					// Loss remains an independent, once-per-description observation.
					for _, fh := range []uint64{writer.Fh, other.Fh} {
						if st := f.rawCall(func(u uint64) fuse.Status {
							return f.raw.Flush(nil, &fuse.FlushIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}, Fh: fh})
						}); st != fuse.EIO {
							t.Fatal("lost prefix escaped observer", st)
						}
					}
				}
				// A scratch OPEN is a distinct authority description; the fixture's
				// default shared token would close the retained handle as well.
				f.rpc.mu.Lock()
				f.rpc.handle = testToken(901)
				f.rpc.mu.Unlock()
				writeDelegated(t, f, entry.NodeId, other.Fh, 0, []byte("later"))
				if mode == "cold-reuse" {
					writeDelegated(t, f, entry.NodeId, writer.Fh, 0, []byte("reuse"))
					if st := f.rawCall(func(u uint64) fuse.Status {
						return f.raw.Fsync(nil, &fuse.FsyncIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}, Fh: writer.Fh})
					}); st != fuse.OK {
						t.Fatal(st)
					}
					writeDelegated(t, f, entry.NodeId, other.Fh, 0, []byte("newer"))
				}
				writerResult, otherResult = fuse.OK, fuse.EIO
			}
			ro := &fuse.OpenOut{}
			if st := f.rawCall(func(u uint64) fuse.Status {
				return f.raw.Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}}, ro)
			}); st != fuse.OK {
				t.Fatal(st)
			}
			g.Close(1)
			for _, description := range []struct {
				fh   uint64
				want fuse.Status
			}{{ro.Fh, fuse.OK}, {other.Fh, otherResult}, {writer.Fh, writerResult}} {
				if st := f.rawCall(func(u uint64) fuse.Status {
					return f.raw.Flush(nil, &fuse.FlushIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}, Fh: description.fh})
				}); st != description.want {
					t.Fatal("closed FLUSH used another description's dirty state", st, description.want)
				}
			}
		})
	}
}

// Adapted from the RELEASE rows of zz_review_r2_parity_linux_test.go.
func TestReviewR2ReleaseRequestIdentityParity(t *testing.T) {
	for _, directory := range []bool{false, true} {
		for _, condition := range []string{"zero", "duplicate", "terminal"} {
			name := "file/"
			if directory {
				name = "directory/"
			}
			t.Run(name+condition, func(t *testing.T) {
				f := newStockFixture(t)
				node := uint64(1)
				if !directory {
					node = f.lookup(t, 1, "cached").NodeId
				}
				opened := &fuse.OpenOut{}
				if st := f.rawCall(func(u uint64) fuse.Status {
					in := &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: node}}
					if directory {
						return f.raw.OpenDir(nil, in, opened)
					}
					return f.raw.Open(nil, in, opened)
				}); st != fuse.OK {
					t.Fatal(st)
				}
				u := f.unique.Add(2)
				switch condition {
				case "zero":
					u = 0
				case "duplicate":
					ctx, finish, st := f.raw.mutationContext(u)
					if st != fuse.OK {
						t.Fatal(st)
					}
					// An unprepared retained response keeps the duplicate's original owner.
					if err := retainAuthorityResponse(ctx, workspaceConsumeFunc(func() {})); err != nil {
						t.Fatal(err)
					}
					finish()
				case "terminal":
					f.raw.terminalizeReplyCacheOwnership(time.Now().Add(time.Second))
				}
				in := &fuse.ReleaseIn{InHeader: fuse.InHeader{Unique: u, NodeId: node}, Fh: opened.Fh}
				if directory {
					f.raw.ReleaseDir(in)
				} else {
					f.raw.Release(nil, in)
				}
				if !f.mount.isRevoked() {
					t.Fatal("invalid RELEASE request identity did not revoke")
				}
				if condition == "duplicate" {
					f.raw.terminalizeReplyCacheOwnershipAfterConnectionGone()
				}
			})
		}
	}
}

// A callback can reserve a name before appending its candidate outside raw.mu.
// Cold invalidation must find that reservation without inspecting the mutable
// slice, and final refusal must retire the lookup and metadata pin exactly once.
func TestWorkspacePendingMetadataColdInvalidation(t *testing.T) {
	f := newStockFixture(t)
	entry := f.lookup(t, 1, "cached")
	f.lookup(t, 1, "cached")
	g := bindWorkspaceTestGate(t, f.mount)
	u := f.unique.Add(2)
	ctx, finish, st := f.raw.mutationContext(u)
	if st != fuse.OK {
		t.Fatal(st)
	}
	parent := f.raw.nodesByID[1]
	record, _, negative := f.raw.cachedLookup(ctx, parent, "cached")
	if record == nil || negative {
		t.Fatal("cached slow-path sample unavailable")
	}
	p := replyPublicationFromContext(ctx)
	state := f.mount.delegations.retainState(writeback.Identity(record.identity), true)
	state.admission.RLock()
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: record.identity}
	f.raw.mu.Lock()
	_, candidate, admitted := f.raw.admitNameLocked(ctx, parent, "cached", record)
	f.raw.pinMetadataLocked(p, state, record, coordinate, publicationCoordinate{}, 1)
	f.raw.mu.Unlock()
	if !admitted {
		t.Fatal("candidate was not reserved")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	f.notify.onEntry = func(uint64, string) { close(entered); <-release }
	g.Close(1)
	f.mount.subscription.deactivate()
	cold := make(chan error, 1)
	go func() { cold <- f.raw.invalidateAllCaches(t.Context()) }()
	<-entered
	f.raw.mu.RLock()
	revoked := candidate.reservation.revoked
	f.raw.mu.RUnlock()
	if !revoked || len(p.names) != 0 || p.originalFinalized {
		t.Fatal("cold cut missed pending construction")
	}
	p.names = append(p.names, candidate)
	close(release)
	if err := <-cold; err != nil {
		t.Fatal(err)
	}
	finish()
	if _, reply, prepare := f.raw.PrepareReplyPayload(u, entry.NodeId, 1, nil, nil, 0); reply != fuse.EIO || prepare != fuse.OK {
		t.Fatal("obsolete pending metadata escaped refusal", reply, prepare)
	}
	if state.admission.TryLock() {
		state.admission.Unlock()
		t.Fatal("metadata pin retired before physical refusal")
	}
	f.raw.ReplyWritten(u, fuse.OK)
	assertMetadataPinReleased(t, state)
	if len(f.raw.cacheReservations) != 0 || len(f.raw.replyPublications) != 0 || record.lookups != 2 {
		t.Fatal("pending candidate or lookup leaked after refusal")
	}
}

func TestWorkspaceLookupReferenceRefusesTerminalClaim(t *testing.T) {
	f := newStockFixture(t)
	entry := f.lookup(t, 1, "cached")
	f.lookup(t, 1, "cached")
	bindWorkspaceTestGate(t, f.mount)
	ctx, finish, st := f.raw.mutationContext(f.unique.Add(2))
	if st != fuse.OK {
		t.Fatal(st)
	}
	record := f.raw.nodesByID[entry.NodeId]
	lookups := record.lookups
	if !f.raw.terminalizeReplyCacheOwnership(time.Now().Add(time.Second)) {
		t.Fatal("terminal claim failed")
	}
	if late, _, negative := f.raw.cachedLookup(ctx, f.raw.nodesByID[1], "cached"); late != nil || negative {
		t.Fatal("settled publication acquired a late lookup reference")
	}
	finish()
	if record.lookups != lookups || len(f.raw.replyPublications) != 0 {
		t.Fatal("late callback leaked a lookup reference")
	}
}
