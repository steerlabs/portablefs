//go:build linux

package fusev3

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// Refuse only the foreground FSYNC. Keep background durability parked until
// the assertion observes the failed cut; an independent successful barrier may
// legitimately retire it afterward.
type workspaceFsyncRefusalRPC struct {
	*fakeRPC
	barrier <-chan struct{}
}

func (r *workspaceFsyncRefusalRPC) CallIdempotent(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if fsync := request.GetFsync(); fsync != nil {
		r.mu.Lock()
		r.fsyncs = append(r.fsyncs, fsync)
		r.mu.Unlock()
		return &authoritypb.Response{Errno: int32(syscall.EIO)}, nil
	}
	return r.fakeRPC.CallIdempotent(ctx, request)
}
func (r *workspaceFsyncRefusalRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetBarrier() != nil {
		select {
		case <-r.barrier:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return r.fakeRPC.CallMutation(ctx, request)
}

// Adapted from the Opus PR #122 review repros.
func TestWorkspaceAdmittedFsyncKeepsDirtyCut(t *testing.T) {
	for _, mode := range []string{"open", "closed", "closed-fsync-refusal"} {
		t.Run(mode, func(t *testing.T) {
			closeIt := mode != "open"
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "cached")
			g := bindWorkspaceTestGate(t, f.mount)
			opened := openDelegatedWriter(t, f, entry.NodeId)
			writeDelegated(t, f, entry.NodeId, opened.Fh, 0, []byte("dirty"))
			writesBefore, fsyncsBefore := 0, 0
			f.rpc.snapshot(func(rpc *fakeRPC) { writesBefore, fsyncsBefore = len(rpc.writes), len(rpc.fsyncs) })
			if writesBefore != 0 {
				t.Fatal("FULL write was not buffered")
			}
			if mode == "closed-fsync-refusal" {
				barrier := make(chan struct{})
				defer close(barrier)
				f.mount.delegations.rpc = &workspaceFsyncRefusalRPC{fakeRPC: f.rpc, barrier: barrier}
			}
			unique := f.unique.Add(2)
			// Hold the epoch writer so the real raw FSYNC callback is admitted at
			// entry and then parks before mutationContext.
			f.mount.epochMu.Lock()
			done := make(chan fuse.Status, 1)
			go func() {
				done <- f.raw.Fsync(nil, &fuse.FsyncIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Fh: opened.Fh})
			}()
			waitUntil(t, time.Second, "FSYNC admitted at entry", func() bool { return f.raw.ReplyWriteTracked(unique) })
			if closeIt {
				g.Close(1)
			}
			f.mount.epochMu.Unlock()
			status := <-done
			if f.raw.ReplyWriteTracked(unique) {
				f.raw.PrepareReplyPayload(unique, entry.NodeId, 20, nil, nil, 0)
				f.raw.ReplyWritten(unique, fuse.OK)
			}
			writesAfter, fsyncsAfter := 0, 0
			f.rpc.snapshot(func(rpc *fakeRPC) { writesAfter, fsyncsAfter = len(rpc.writes), len(rpc.fsyncs) })
			t.Logf("closed=%v FSYNC status=%v authorityFSYNCs=%d flushedWrites=%d", closeIt, status, fsyncsAfter-fsyncsBefore, writesAfter-writesBefore)
			if mode == "closed-fsync-refusal" {
				if status != fuse.EIO || writesAfter-writesBefore != 1 || fsyncsAfter-fsyncsBefore != 1 || f.mount.delegations.buf.Stats().Entries == 0 {
					t.Fatalf("FSYNC refusal lost its retained failure: status=%v entries=%d revoked=%v fatal=%v", status, f.mount.delegations.buf.Stats().Entries, f.mount.isRevoked(), f.mount.fatalError())
				}
				return
			}
			if status != fuse.OK || writesAfter-writesBefore != 1 || fsyncsAfter-fsyncsBefore != 1 {
				t.Fatal("admitted FSYNC did not flush and persist the dirty cut")
			}
			id := f.raw.nodesByID[entry.NodeId].identity
			if !f.mount.delegations.Owns(id[:]) {
				t.Fatal("Close lost retained owner")
			}
			if f.mount.delegations.buf.Stats().Entries != 0 {
				t.Fatal("FSYNC succeeded without retiring its durable accepted cut")
			}
		})
	}
}

// Close retains the accepted overlay and size independently of serving permission.
func TestWorkspaceRetainsDirtyReadOwnership(t *testing.T) {
	f := newStockFixture(t)
	entry := f.lookup(t, 1, "cached")
	g := bindWorkspaceTestGate(t, f.mount)
	opened := openDelegatedWriter(t, f, entry.NodeId)
	writeDelegated(t, f, entry.NodeId, opened.Fh, 0, []byte("dirty"))
	identity := f.raw.nodesByID[entry.NodeId].identity
	fetches := 0
	fetch := func(context.Context, int64, int) ([]byte, error) { fetches++; return []byte("STALE"), nil }
	before, _ := f.mount.delegations.Read(t.Context(), identity[:], 0, 5, fetch)
	g.Close(1)
	after, _ := f.mount.delegations.Read(t.Context(), identity[:], 0, 5, fetch)
	size, _ := f.mount.delegations.Size(identity[:], 0)
	t.Logf("before=%q after=%q fetches=%d size-after-close=%d", before, after, fetches, size)
	if string(before) != "dirty" || string(after) != "dirty" || size != 5 || fetches != 2 {
		t.Errorf("BUG: post-Close delegated read bypassed accepted overlay: %q", after)
	}
}

// Every terminal path settles the same fixed completion exactly once.
func TestWorkspaceCohortJoinsTerminalSettlement(t *testing.T) {
	for _, boundary := range []string{"before-prepare", "written-during-terminalization", "connection-gone"} {
		t.Run(boundary, func(t *testing.T) {
			f := newStockFixture(t)
			bindWorkspaceTestGate(t, f.mount)
			u := f.unique.Add(2)
			entry, status := f.raw.beginWorkspaceEntry(u)
			if status != fuse.OK {
				t.Fatal(status)
			}
			cut := f.raw.captureWorkspaceReplies()
			if boundary == "before-prepare" {
				if !f.raw.terminalizeReplyCacheOwnership(time.Now().Add(time.Second)) {
					t.Fatal("terminalization did not complete")
				}
			} else {
				f.raw.PrepareReplyPayload(u, 1, 20, nil, nil, 0)
				if f.raw.terminalizeReplyCacheOwnership(time.Now()) {
					t.Fatal("terminalization skipped outstanding writer")
				}
				if boundary == "written-during-terminalization" {
					f.raw.ReplyWritten(u, fuse.OK)
					if !f.raw.terminalizeReplyCacheOwnership(time.Now().Add(time.Second)) {
						t.Fatal("terminal writer did not settle")
					}
				} else {
					f.raw.terminalizeReplyCacheOwnershipAfterConnectionGone()
				}
			}
			f.raw.finishWorkspaceEntry(u, entry)
			f.raw.terminalizeReplyCacheOwnershipAfterConnectionGone()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if err := cut.wait(ctx); err != nil {
				t.Fatal("terminal settlement stranded cohort", err)
			}
		})
	}
}

// Captured drain control cannot extend the local withdrawal deadline.
func TestWorkspaceDrainKeepsWithdrawalLead(t *testing.T) {
	f := newStockFixture(t)
	g := bindWorkspaceTestGate(t, f.mount)
	s := f.mount.subscription
	inc, _, _, live := s.currentIncarnation()
	g.Close(1)
	_, _, _, liveAfter := s.currentIncarnation()
	s.mu.RLock()
	cacheUntil, horizon := s.cacheUntil, s.horizon
	s.mu.RUnlock()
	renewed := s.acceptRenewal(inc, horizon.Add(time.Minute))
	drain := f.mount.delegations.captureWorkspaceDrain(time.Now().Add(time.Hour))
	_, deadline, _, liveDrain := s.currentIncarnation()
	t.Logf("live=%v liveAfterClose=%v renewalAccepted=%v liveWithDrain=%v cacheUntil=%v horizon=%v drainDeadline=%v (drain-cacheUntil=%v)",
		live, liveAfter, renewed, liveDrain, cacheUntil.Format(time.RFC3339Nano), horizon.Format(time.RFC3339Nano), deadline.Format(time.RFC3339Nano), drain.deadline.Sub(cacheUntil))
	if !live || liveAfter || renewed || !liveDrain || !deadline.Equal(cacheUntil) {
		t.Errorf("NOTE: drain horizon loop deadline %v exceeds local withdrawal deadline by %v", deadline, deadline.Sub(cacheUntil))
	}
}

// Park the raw READ after its subscription check and before ownership selection.
func TestWorkspaceAdmittedReadKeepsOverlayAndEOF(t *testing.T) {
	f := newStockFixture(t)
	entry := f.lookup(t, 1, "cached")
	g := bindWorkspaceTestGate(t, f.mount)
	opened := openDelegatedWriter(t, f, entry.NodeId)
	writeDelegated(t, f, entry.NodeId, opened.Fh, 0, []byte("dirty"))
	unique := f.unique.Add(2)
	f.mount.delegations.epoch.Lock()
	type result struct {
		data   []byte
		status fuse.Status
	}
	done := make(chan result, 1)
	go func() {
		buf := make([]byte, 32)
		res, status := f.raw.Read(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Fh: opened.Fh, Offset: 0, Size: 32}, buf)
		var data []byte
		if res != nil {
			data, _ = res.Bytes(buf)
		}
		done <- result{append([]byte(nil), data...), status}
	}()
	waitUntil(t, time.Second, "READ admitted", func() bool { return f.raw.ReplyWriteTracked(unique) })
	waitUntil(t, time.Second, "READ parked after its subscription check", func() bool {
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		for _, goroutine := range strings.Split(string(stack[:n]), "\n\n") {
			if strings.Contains(goroutine, "(*delegationManager).Read(") && strings.Contains(goroutine, "sync.(*RWMutex).RLock") {
				return true
			}
		}
		return false
	})
	g.Close(1)
	f.mount.delegations.epoch.Unlock()
	r := <-done
	if f.raw.ReplyWriteTracked(unique) {
		if n, reply, prepare := f.raw.PrepareReplyPayload(unique, entry.NodeId, 15, nil, nil, len(r.data)); n != 5 || reply != fuse.OK || prepare != fuse.OK {
			t.Fatal("admitted dirty READ lost its physical payload", n, reply, prepare)
		}
		f.raw.ReplyWritten(unique, fuse.OK)
	}
	t.Logf("admitted READ after Close: status=%v data=%q", r.status, r.data)
	if r.status != fuse.OK || string(r.data) != "dirty" {
		t.Errorf("BUG: admitted READ delivered bytes that omit this mount's accepted write: %q", r.data)
	}
}

func TestWorkspaceSetattrRefusalKeepsNoChangeOwner(t *testing.T) {
	for _, boundary := range []string{"before-assignment", "before-acceptance"} {
		t.Run(boundary, func(t *testing.T) {
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "cached")
			g := bindWorkspaceTestGate(t, f.mount)
			opened := openDelegatedWriter(t, f, entry.NodeId)
			before := f.mount.delegations.buf.Snapshot()
			u := f.unique.Add(2)
			var lease *sourcePublicationLease
			var consumed atomic.Int32
			f.raw.beforeSourceAssignment = func(l *sourcePublicationLease) {
				lease = l
				f.raw.mu.Lock()
				p := f.raw.replyPublications[u]
				p.responseConsumptions = append(p.responseConsumptions, workspaceConsumeFunc(func() { consumed.Add(1) }))
				f.raw.mu.Unlock()
				if boundary == "before-assignment" {
					g.Close(1)
				} else {
					check := l.workspaceCheck
					l.workspaceCheck = func() error {
						err := check()
						g.Close(1)
						return err
					}
				}
			}
			in := &fuse.SetAttrIn{}
			in.InHeader = fuse.InHeader{Unique: u, NodeId: entry.NodeId}
			in.Valid, in.Fh, in.Size = fuse.FATTR_FH|fuse.FATTR_SIZE, opened.Fh, 3
			if st := f.raw.SetAttr(nil, in, &fuse.AttrOut{}); st != fuse.EIO {
				t.Fatal("closed truncate was accepted", st)
			}
			if lease == nil || lease.assigned != (boundary == "before-acceptance") || !lease.ready || lease.released || lease.revoked {
				t.Fatalf("refusal lost no-change source owner: %+v", lease)
			}
			if f.mount.delegations.buf.Snapshot() != before || consumed.Load() != 0 || f.mount.isRevoked() || f.mount.fatalError() != nil {
				t.Fatal("pre-acceptance refusal mutated or terminalized")
			}
			if !f.raw.ReplyWriteTracked(u) || len(f.raw.sourceHolds) == 0 {
				t.Fatal("error reply released its source before physical settlement")
			}
			f.raw.PrepareReplyPayload(u, entry.NodeId, 4, nil, nil, 0)
			f.raw.ReplyWritten(u, fuse.OK)
			if !lease.released || lease.revoked || consumed.Load() != 1 || len(f.raw.sourceHolds) != 0 || f.mount.isRevoked() {
				t.Fatal("physical error reply did not clean up once")
			}
			f.raw.terminalizeReplyCacheOwnership(time.Now().Add(time.Second))
			if consumed.Load() != 1 {
				t.Fatal("terminal settlement consumed the response twice")
			}
		})
	}
}

func TestWorkspaceCohortIncludesWrittenSettlement(t *testing.T) {
	for _, boundary := range []string{"response-consumption", "response-already-consumed", "source-release", "lookup-rollback"} {
		t.Run(boundary, func(t *testing.T) {
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "cached")
			g := bindWorkspaceTestGate(t, f.mount)
			u := f.unique.Add(2)
			entered, release := make(chan struct{}), make(chan struct{})
			var consumed atomic.Int32
			var lease *sourcePublicationLease
			var p *replyPublication
			record := f.raw.nodesByID[entry.NodeId]
			lookups := record.lookups
			if boundary == "lookup-rollback" {
				if st := f.raw.Lookup(nil, &fuse.InHeader{Unique: u, NodeId: 1}, "cached", &fuse.EntryOut{}); st != fuse.OK {
					t.Fatal(st)
				}
				p = f.raw.replyPublications[u]
				g.Close(1)
			} else {
				ctx, finish, st := f.raw.mutationContext(u)
				if st != fuse.OK {
					t.Fatal(st)
				}
				p = replyPublicationFromContext(ctx)
				gate, err := itemSourceGate(record.node.item, true)
				if err != nil {
					t.Fatal(err)
				}
				callback, _ := ctx.Value(mutationCallbackKey{}).(*mutationCallback)
				lease, err = callback.acquireSource(ctx, f.raw, gate)
				if err != nil {
					t.Fatal(err)
				}
				if err := completeDefiniteNoChangePublication(ctx); err != nil {
					t.Fatal(err)
				}
				if err := retainAuthorityResponse(ctx, workspaceConsumeFunc(func() {
					consumed.Add(1)
					if boundary == "response-consumption" {
						close(entered)
						<-release
					}
				})); err != nil {
					t.Fatal(err)
				}
				finish()
				if boundary == "response-already-consumed" {
					p.consumeAuthorityResponse()
				}
			}
			if boundary != "response-consumption" {
				f.raw.beforeReplySettlement = func(*replyPublication) { close(entered); <-release }
			}
			f.raw.PrepareReplyPayload(u, entry.NodeId, 1, nil, nil, 0)
			settled := make(chan struct{})
			go func() { f.raw.ReplyWritten(u, fuse.OK); close(settled) }()
			<-entered
			g.Close(1)
			cut := f.raw.captureWorkspaceReplies()
			if len(cut.replies) != 1 {
				t.Fatalf("cut has %d replies, want the settling publication", len(cut.replies))
			}
			select {
			case <-cut.replies[0]:
				t.Fatal("settlement completion closed at the paused boundary")
			default:
			}
			canceled, cancel := context.WithCancel(t.Context())
			cancel()
			if err := cut.wait(canceled); !errors.Is(err, context.Canceled) {
				t.Fatal("cut omitted written settlement", err)
			}
			f.raw.mu.RLock()
			retained := f.raw.replyPublications[u] == p
			f.raw.mu.RUnlock()
			if !retained {
				t.Fatal("cancellation lost the sole settlement owner")
			}
			if (boundary == "source-release" || boundary == "response-already-consumed") && lease.released {
				t.Fatal("source released before settlement boundary")
			}
			if boundary == "lookup-rollback" && record.lookups != lookups+1 {
				t.Fatal("lookup rolled back before settlement boundary")
			}
			close(release)
			<-settled
			if err := cut.wait(t.Context()); err != nil {
				t.Fatal(err)
			}
			if boundary == "lookup-rollback" {
				if record.lookups != lookups {
					t.Fatal("lookup rollback was not exact")
				}
			} else if !lease.released || lease.revoked || consumed.Load() != 1 {
				t.Fatal("settlement lost source release or exact response consumption")
			}
			if len(f.raw.replyPublications) != 0 {
				t.Fatal("settlement retained an owner")
			}
		})
	}
}

type workspaceRenewRPC struct {
	*subscriptionTestRPC
	calls atomic.Int32
}

func (r *workspaceRenewRPC) RenewSubscription(_ context.Context, _ uint64) (time.Time, error) {
	r.calls.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.horizon = r.horizon.Add(time.Hour)
	return r.horizon, nil
}

type workspaceRecallRPC struct {
	*fakeRPC
	recalls atomic.Int32
}

func (r *workspaceRecallRPC) CallIdempotent(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetDelegationRecallAck() != nil {
		r.recalls.Add(1)
		return &authoritypb.Response{Body: &authoritypb.Response_DelegationRecallAck{DelegationRecallAck: &authoritypb.DelegationRecallAckReply{}}}, nil
	}
	return r.fakeRPC.CallIdempotent(ctx, request)
}

func TestWorkspaceRenewLoopSkipsClosedControl(t *testing.T) {
	for _, mode := range []string{"closed", "captured-drain"} {
		t.Run(mode, func(t *testing.T) {
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "cached")
			g := bindWorkspaceTestGate(t, f.mount)
			opened := openDelegatedWriter(t, f, entry.NodeId)
			writeDelegated(t, f, entry.NodeId, opened.Fh, 0, []byte("dirty"))
			timers := make(chan *subscriptionTestTimer, 2)
			s := f.mount.subscription
			remoteHorizon := s.horizon
			rpc := &workspaceRenewRPC{subscriptionTestRPC: &subscriptionTestRPC{horizon: remoteHorizon}}
			s.config.clock = &subscriptionTestClock{now: s.config.clock.Now(), timers: timers}
			s.rpc = rpc
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.renewLoop(ctx, s.incarnation) }()
			timer := <-timers
			g.Close(1)
			if mode == "captured-drain" {
				drain := f.mount.delegations.captureWorkspaceDrain(remoteHorizon)
				if _, deadline, _, live := s.currentIncarnation(); !live || !deadline.Equal(drain.deadline) {
					t.Fatal("drain lost old CONTROL permission")
				}
			}
			timer.fired <- s.config.clock.Now()
			<-timers
			rpc.mu.Lock()
			horizon := rpc.horizon
			rpc.mu.Unlock()
			if rpc.calls.Load() != 0 || !horizon.Equal(remoteHorizon) || !s.horizon.Equal(remoteHorizon) {
				t.Fatal("drain dispatched renewal or extended exclusion")
			}
			cancel()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if mode == "captured-drain" {
				// The real recall path must still flush and acknowledge its old grant.
				m := f.mount.delegations
				controlRPC := &workspaceRecallRPC{fakeRPC: f.rpc}
				m.rpc = controlRPC
				identity := f.raw.nodesByID[entry.NodeId].identity
				state := m.retainState(writeback.Identity(identity), false)
				state.admission.RLock()
				ref := cloneDelegationRef(state.ref)
				state.admission.RUnlock()
				m.releaseState(state)
				event := &authoritypb.ControlEvent{Incarnation: s.incarnation, Sequence: 1, Event: &authoritypb.ControlEvent_DelegationRecall{DelegationRecall: &authoritypb.DelegationRecall{Identity: identity[:], Delegation: ref, BudgetNanos: uint64(time.Second)}}}
				<-m.HandleControlEvent(t.Context(), event)
				if controlRPC.recalls.Load() != 1 {
					t.Fatal("drain suppressed recall acknowledgement")
				}
				batch := &authoritypb.ChangeBatch{Incarnation: s.incarnation, Entries: []*authoritypb.ChangeEntry{{Position: s.lastChangeSeen + 1, VolumeVersion: 100, Kind: authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED, Identity: identity[:]}}}
				if err := s.registerChangeBatch(s.incarnation, batch); err != nil {
					t.Fatal(err)
				}
				if err := s.applyChangeBatch(t.Context(), s.incarnation, batch); err != nil {
					t.Fatal(err)
				}
				if err := s.ackChanges(t.Context(), s.incarnation, batch.Entries[0].Position); err != nil {
					t.Fatal(err)
				}
				rpc.mu.Lock()
				acks := len(rpc.acks)
				horizon = rpc.horizon
				rpc.mu.Unlock()
				if acks != 1 || rpc.calls.Load() != 0 || !horizon.Equal(remoteHorizon) {
					t.Fatal("old change/ack control lost or renewed its horizon")
				}
			}
		})
	}
}

func TestWorkspaceClosedCleanFlushSucceeds(t *testing.T) {
	for _, kind := range []string{"read-only", "clean-writer", "dirty-writer", "clean-posix"} {
		t.Run(kind, func(t *testing.T) {
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "cached")
			g := bindWorkspaceTestGate(t, f.mount)
			var opened *fuse.OpenOut
			if kind == "read-only" {
				opened = &fuse.OpenOut{}
				if st := f.rawCall(func(u uint64) fuse.Status {
					return f.raw.Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}}, opened)
				}); st != fuse.OK {
					t.Fatal(st)
				}
			} else {
				opened = openDelegatedWriter(t, f, entry.NodeId)
			}
			if kind == "dirty-writer" {
				writeDelegated(t, f, entry.NodeId, opened.Fh, 0, []byte("dirty"))
			}
			key := f.raw.nodesByID[entry.NodeId].node.posixLockKey(7)
			if kind == "clean-posix" {
				f.mount.notePOSIXLock(key)
			}
			g.Close(1)
			st := f.rawCall(func(u uint64) fuse.Status {
				return f.raw.Flush(nil, &fuse.FlushIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}, Fh: opened.Fh, LockOwner: 7})
			})
			want := fuse.OK
			if kind == "dirty-writer" {
				want = fuse.EIO
			}
			if st != want || f.mount.possiblePOSIXLock(key) != 0 {
				t.Fatal("closed FLUSH lost clean/dirty distinction or unlock", st)
			}
		})
	}
}

func TestOrdinaryEntrySkipsWorkspaceAndPreservesRefusals(t *testing.T) {
	f := newStockFixture(t)
	f.raw.mu.Lock()
	done := make(chan struct{})
	go func() {
		p, status := f.raw.beginWorkspaceEntry(0)
		if p != nil || status != fuse.OK {
			t.Error("ordinary entry acquired workspace ownership")
		}
		f.raw.finishWorkspaceEntry(0, p)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		f.raw.mu.Unlock()
		t.Fatal("ordinary entry took registry lock")
	}
	f.raw.mu.Unlock()
	for _, refusal := range []string{"zero", "duplicate", "terminal"} {
		t.Run(refusal, func(t *testing.T) {
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "cached")
			u := f.unique.Add(2)
			if refusal == "zero" {
				u = 0
			}
			if refusal == "duplicate" {
				if st := f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}}, &fuse.AttrOut{}); st != fuse.OK {
					t.Fatal(st)
				}
			}
			if refusal == "terminal" {
				f.raw.terminalizeReplyCacheOwnership(time.Now().Add(time.Second))
			}
			st := f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}}, &fuse.AttrOut{})
			if st != fuse.Status(syscall.ENOTCONN) || !f.mount.isRevoked() {
				t.Fatal("ordinary invariant refusal changed", st)
			}
		})
	}
}
