//go:build linux

package fusev3

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// Observe the blocked call itself, rather than using a sleep to guess whether
// it passed the earlier admission check. These tests run one such call at a time.
func waitRecoveryStack(t *testing.T, call string) {
	t.Helper()
	waitUntil(t, time.Second, call+" parked", func() bool {
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		for _, gr := range strings.Split(string(stack[:n]), "\n\n") {
			if strings.Contains(gr, call) && (strings.Contains(gr, "RLock") || strings.Contains(gr, "[select]")) {
				return true
			}
		}
		return false
	})
}

// Adapted from the PR #122 R1 review repro. InterruptSubscription must wake
// blocked admissions without changing where an admitted READ finds dirty bytes.
func TestOrdinaryReadDuringInterruptKeepsOverlay(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		for _, offset := range []uint64{0, 2, 5, 8} {
			t.Run(fmt.Sprintf("buffered=%t/offset=%d", buffered, offset), func(t *testing.T) {
				f := newStockFixture(t)
				entry := f.lookup(t, 1, "cached")
				opened := openDelegatedWriter(t, f, entry.NodeId)
				writeDelegated(t, f, entry.NodeId, opened.Fh, 0, []byte("dirty"))
				// Exercise the same callback with a pre-existing cacheable description.
				// The stock fixture retains FULL ownership without starting background I/O.
				f.raw.handles[opened.Fh].file.buffered = buffered
				f.rpc.snapshot(func(rpc *fakeRPC) {
					if len(rpc.writes) != 0 {
						t.Fatal("dirty write already reached storage")
					}
				})
				u := f.unique.Add(2)
				m := f.mount.delegations
				m.epoch.Lock()
				locked := true
				defer func() {
					if locked {
						m.epoch.Unlock()
					}
				}()
				type result struct {
					data   []byte
					status fuse.Status
				}
				done := make(chan result, 1)
				go func() {
					buf := make([]byte, 32)
					res, status := f.raw.Read(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}, Fh: opened.Fh, Offset: offset, Size: 32}, buf)
					var data []byte
					if res != nil {
						data, _ = res.Bytes(buf)
						res.Done()
					}
					done <- result{append([]byte(nil), data...), status}
				}()
				waitRecoveryStack(t, "(*delegationManager).Read(")
				reset := make(chan error, 1)
				go func() { reset <- f.mount.subscription.subscribe(t.Context()) }()
				waitUntil(t, time.Second, "interruption cleared incarnation", func() bool { return m.inc.Load() == 0 })
				m.epoch.Unlock()
				locked = false
				r := <-done
				if f.raw.ReplyWriteTracked(u) {
					f.raw.PrepareReplyPayload(u, entry.NodeId, 15, nil, r.data, len(r.data))
					f.raw.ReplyWritten(u, fuse.OK)
				}
				if err := <-reset; err != nil {
					t.Fatal(err)
				}
				want := "dirty"[min(offset, 5):]
				if r.status != fuse.OK || string(r.data) != want {
					t.Errorf("admitted READ = %v %q, want OK %q", r.status, r.data, want)
				}
				if loss := m.LossSequence(); loss != 1 {
					t.Errorf("loss = %d, want exactly 1", loss)
				}
				if err := f.mount.subscription.subscribe(t.Context()); err != nil {
					t.Fatal(err)
				}
				if loss := m.LossSequence(); loss != 1 {
					t.Errorf("second reset recounted loss: %d", loss)
				}
			})
		}
	}
}

// Adapted from zz_opus3_source_after_terminal. The old callback waits behind a
// real overlapping gate until terminal settlement has claimed its publication.
func TestSourceAcquisitionRefusesTerminalClaim(t *testing.T) {
	t.Run("attachment-first", func(t *testing.T) {
		f := newStockFixture(t)
		entry := f.lookup(t, 1, "cached")
		ctx, finish, status := f.raw.mutationContext(f.unique.Add(2))
		if status != fuse.OK {
			t.Fatal(status)
		}
		defer finish()
		gate, err := itemSourceGate(f.raw.nodesByID[entry.NodeId].node.item, false)
		if err != nil {
			t.Fatal(err)
		}
		callback := ctx.Value(mutationCallbackKey{}).(*mutationCallback)
		lease, err := callback.acquireSource(ctx, f.raw, gate)
		if err != nil {
			t.Fatal(err)
		}
		if !f.raw.terminalizeReplyCacheOwnership(time.Now().Add(time.Second)) {
			t.Fatal("terminal join failed")
		}
		f.raw.mu.RLock()
		defer f.raw.mu.RUnlock()
		if callback.publication.source != lease || !lease.revoked || !callback.publication.settlementClaimed {
			t.Error("terminal claimant did not revoke its attached source")
		}
	})
	t.Run("claim-first", func(t *testing.T) {
		f := newStockFixture(t)
		entry := f.lookup(t, 1, "cached")
		r := f.raw
		gate, err := itemSourceGate(r.nodesByID[entry.NodeId].node.item, false)
		if err != nil {
			t.Fatal(err)
		}
		blocker, err := r.acquireSourcePublication(t.Context(), gate)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.cancelAcquisition()
		ctx, finish, status := r.mutationContext(f.unique.Add(2))
		if status != fuse.OK {
			t.Fatal(status)
		}
		defer finish()
		callback := ctx.Value(mutationCallbackKey{}).(*mutationCallback)
		acquired := make(chan error, 1)
		go func() { _, err := callback.acquireSource(ctx, r, gate); acquired <- err }()
		waitRecoveryStack(t, "(*rawFileSystem).acquireSourcePublication(")
		if !r.terminalizeReplyCacheOwnership(time.Now().Add(time.Second)) {
			t.Fatal("terminal join failed")
		}
		blocker.cancelAcquisition()
		if err := <-acquired; err == nil {
			t.Error("source acquisition succeeded after terminal claim")
		}
		r.mu.RLock()
		defer r.mu.RUnlock()
		if callback.publication.source != nil || len(r.sourceHolds) != 0 || len(r.sourceSharedHolds) != 0 {
			t.Errorf("late source escaped claimant: source=%p holds=%d shared=%d", callback.publication.source, len(r.sourceHolds), len(r.sourceSharedHolds))
		}
	})
}

func TestCandidatesRefuseTerminalClaim(t *testing.T) {
	for _, kind := range []string{"name", "negative", "attr", "data"} {
		t.Run(kind, func(t *testing.T) {
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "cached")
			r := f.raw
			ctx, finish, status := r.mutationContext(f.unique.Add(2))
			if status != fuse.OK {
				t.Fatal(status)
			}
			defer finish()
			p := replyPublicationFromContext(ctx)
			p.servedVersion = 2
			p.cacheStamp = &cacheSnapshot{SnapshotSequence: 2, ObjectVersion: 1}
			if !r.terminalizeReplyCacheOwnership(time.Now().Add(time.Second)) {
				t.Fatal("terminal join failed")
			}
			record, parent := r.nodesByID[entry.NodeId], r.nodesByID[1]
			admitted := false
			if kind == "data" {
				admitted = r.beginBufferedRead(ctx, record)
			} else {
				r.mu.Lock()
				switch kind {
				case "name":
					_, _, admitted = r.admitNameLocked(ctx, parent, "late", record)
				case "negative":
					_, _, admitted = r.admitNegativeNameLocked(ctx, parent, "late")
				case "attr":
					_, _, _, admitted = r.admitAttrLocked(ctx, record.key.inode, record.identity)
				}
				r.mu.Unlock()
			}
			if admitted {
				t.Error("candidate admitted after terminal claim")
			}
			r.mu.RLock()
			defer r.mu.RUnlock()
			if len(r.cacheReservations) != 0 || len(r.dataPublications) != 0 || len(r.sourcePublishing) != 0 || r.pendingAttrs != 0 || r.pendingNames != 0 || r.pendingNegatives != 0 {
				t.Error("late candidate retained publication resources")
			}
		})
	}
}

// Adapted from zz_opus3_join, with an observed terminal cut and actual writer
// reporting. A cached writer which samples tracking late must release the join;
// the production withdrawal ladder must still invalidate before aborting.
func TestCachedWriterTrackingDuringTerminalWithdrawal(t *testing.T) {
	for _, writeStarted := range []bool{false, true} {
		t.Run(fmt.Sprintf("writeStarted=%t", writeStarted), func(t *testing.T) {
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "cached")
			f.openForData(t, entry.NodeId)
			r := f.raw
			// Warm GETATTR separately, then retain its finalized cached reply.
			if st := f.rawCall(func(u uint64) fuse.Status {
				return r.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}}, &fuse.AttrOut{})
			}); st != fuse.OK {
				t.Fatal(st)
			}
			u := f.unique.Add(2)
			if st := r.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}}, &fuse.AttrOut{}); st != fuse.OK {
				t.Fatal(st)
			}
			r.mu.RLock()
			p := r.replyPublications[u]
			finalized := p != nil && p.originalFinalized && p.cachedArena
			r.mu.RUnlock()
			if !finalized {
				t.Fatal("cached reply was not finalized at registration")
			}
			tracked := false
			if writeStarted {
				tracked = r.ReplyWriteTracked(u)
				r.PrepareReplyPayload(u, entry.NodeId, 3, nil, nil, 0)
			}
			fake := &fakeWithdrawal{installed: true}
			ops := fake.ops()
			abortedAfter := -1
			abort := ops.abort
			ops.abort = func(k kernelMount) error { abortedAfter = len(f.notify.snapshot()); return abort(k) }
			f.mount.kernelMount = kernelMount{id: "271", device: "0:57", point: t.TempDir()}
			f.mount.withdrawal, f.mount.withdrawalTimeout = ops, 2*time.Second
			done := make(chan withdrawalOutcome, 1)
			go func() { done <- f.mount.withdrawKernelState() }()
			waitUntil(t, time.Second, "terminal writer join", func() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.replyTerminalizing && p.originalDone != nil })
			if !writeStarted {
				tracked = r.ReplyWriteTracked(u)
			}
			if !tracked {
				t.Error("cached writer escaped tracking after terminalization began")
			}
			if tracked {
				status := fuse.OK
				if !writeStarted {
					_, _, status = r.PrepareReplyPayload(u, entry.NodeId, 3, nil, nil, 0)
				}
				r.ReplyWritten(u, status)
			}
			select {
			case out := <-done:
				if !out.withdrawn {
					t.Errorf("withdrawal failed: %+v", out)
				}
			case <-time.After(time.Second):
				t.Error("writer join waited for its withdrawal deadline")
				<-done
			}
			withdrawn := false
			for i, call := range f.notify.snapshot() {
				if call.kind == "inode" && call.off == 0 && call.length == 0 && i < abortedAfter {
					withdrawn = true
				}
			}
			if !withdrawn {
				t.Error("cached data withdrawal did not precede abort")
			}
			r.mu.RLock()
			defer r.mu.RUnlock()
			if len(r.replyPublications) != 0 {
				t.Error("terminal claimant retained reply")
			}
		})
	}
}

func BenchmarkSourceCallbackAdmission(b *testing.B) {
	mount := newMount(context.Background(), newFakeRPC(), testConfig(8))
	b.Cleanup(func() { mount.cancel(); mount.delegations.Stop() })
	parent := testItem(200, authoritypb.Attr_DIRECTORY, 200)
	raw := newRawFileSystem(mount, &node{mount: mount, item: parent, requestTimeout: time.Second})
	gate, err := namespaceSourceGate(parent, "bench", false)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		callback := &mutationCallback{}
		lease, err := callback.acquireSource(context.Background(), raw, gate)
		if err != nil {
			b.Fatal(err)
		}
		lease.cancelAcquisition()
	}
}
