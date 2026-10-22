//go:build linux

package fusev3

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/continuous"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// R1: a waiter-cancelled cache withdrawal is retained as a finished join with
// the waiter's context error. A later healthy Suspend can never complete.
func TestOpusR1RetryAfterCanceledWithdrawal(t *testing.T) {
	f, g, _ := coldFixture(t)
	f.lookup(t, 1, "warm")
	release := make(chan struct{})
	f.notify.mu.Lock()
	f.notify.block = release
	f.notify.mu.Unlock()
	serial := g.Close(1)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	o, err := f.mount.SuspendWorkspace(ctx, 1, serial, continuous.Time().Add(10*time.Second))
	cancel()
	t.Logf("first Suspend: cold=%v err=%v", o.ColdComplete, err)
	if err == nil {
		t.Fatal("blocked notification acknowledged")
	}
	f.notify.mu.Lock()
	f.notify.block = nil
	f.notify.mu.Unlock()
	close(release)
	w := f.mount.workspaceLifecycle
	if w.withdrawal != nil {
		<-w.withdrawal.done
		t.Logf("retained withdrawal owner finished with err=%v", w.withdrawal.err)
	}
	o, err = f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(10*time.Second))
	t.Logf("healthy retry: cold=%v err=%v", o.ColdComplete, err)
	if err != nil || !o.ColdComplete {
		t.Fatalf("REPRO R1: healthy retry after a cancelled waiter can never prove cold: %v", err)
	}
}

// R2: a Recover interrupted by generation cancellation (newer sleep) clears the
// cold proof before doing anything; the following Suspend needs a live old
// horizon that has necessarily expired across the sleep, so the incarnation
// can never recover although nothing was served or dirtied.
func TestOpusR1CancelledRecoverThenSuspend(t *testing.T) {
	for _, variant := range []string{"horizon-live", "horizon-expired"} {
		t.Run(variant, func(t *testing.T) {
			f, g, rpc := coldFixture(t)
			serial := g.Close(1)
			o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second))
			if err != nil || !o.ColdComplete {
				t.Fatal(o, err)
			}
			// Wake: network not yet back. A newer sleep cancels the Recover.
			rpc.outageUntil = time.Now().Add(time.Hour)
			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
			o, err = f.mount.RecoverWorkspace(ctx, 1, serial)
			cancel()
			t.Logf("cancelled Recover: prepared=%v err=%v", o.Prepared, err)
			if variant == "horizon-expired" {
				f.mount.subscription.mu.Lock()
				f.mount.subscription.cacheUntil = continuous.Time().Add(-time.Second)
				f.mount.subscription.mu.Unlock()
			}
			serial2 := g.Close(1)
			o, err = f.mount.SuspendWorkspace(t.Context(), 1, serial2, continuous.Time().Add(5*time.Second))
			t.Logf("re-Suspend after cancelled Recover: cold=%v err=%v", o.ColdComplete, err)
			rpc.outageUntil = time.Time{}
			o2, err2 := f.mount.RecoverWorkspace(t.Context(), 1, serial2)
			t.Logf("later Recover: prepared=%v err=%v", o2.Prepared, err2)
			if err != nil || !o.ColdComplete || err2 != nil || !o2.Prepared {
				t.Fatalf("REPRO R2(%s): interrupted Recover leaves the incarnation unrecoverable: suspend=%v recover=%v", variant, err, err2)
			}
		})
	}
}

// R3: a lost Suspend response retried by the driver must be idempotent. After
// the old horizon passes, the retry destroys the existing cold proof.
func TestOpusR1DuplicateSuspendAfterCold(t *testing.T) {
	for _, variant := range []string{"immediate", "after-old-horizon"} {
		t.Run(variant, func(t *testing.T) {
			f, g, _ := coldFixture(t)
			serial := g.Close(1)
			o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second))
			if err != nil || !o.ColdComplete {
				t.Fatal(o, err)
			}
			if variant == "after-old-horizon" {
				f.mount.subscription.mu.Lock()
				f.mount.subscription.cacheUntil = continuous.Time().Add(-time.Second)
				f.mount.subscription.mu.Unlock()
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			o, err = f.mount.SuspendWorkspace(ctx, 1, serial, continuous.Time().Add(5*time.Second))
			cancel()
			t.Logf("duplicate Suspend: cold=%v err=%v", o.ColdComplete, err)
			o2, err2 := f.mount.RecoverWorkspace(t.Context(), 1, serial)
			t.Logf("Recover: prepared=%v err=%v", o2.Prepared, err2)
			if err != nil || !o.ColdComplete || err2 != nil || !o2.Prepared {
				t.Fatalf("REPRO R3(%s): retried Suspend destroyed the cold proof: suspend=%v recover=%v", variant, err, err2)
			}
		})
	}
}

// R4: goroutine / fd accounting over repeated park/resume cycles (fake RPC).
func TestOpusR1CycleLeaks(t *testing.T) {
	f, g, _ := coldFixture(t)
	// coldFixture owns a raw frontend, not MountVolume's worker startup. These
	// real reclaim lanes are required for duplicate LOOKUP capabilities to
	// retire across cycles; raising queue capacity would hide that omission.
	f.mount.wg.Add(f.mount.reclaimWorkers)
	for range f.mount.reclaimWorkers {
		go f.mount.reclaimLoop(f.mount.ctx)
	}
	t.Cleanup(func() { f.mount.cancel(); f.mount.wg.Wait() })

	countFDs := func() int {
		entries, _ := os.ReadDir("/proc/self/fd")
		return len(entries)
	}
	n := 0
	cycle := func() {
		n++
		t.Logf("cycle %d", n)
		serial := g.Close(1)
		if o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second)); err != nil || !o.ColdComplete {
			t.Fatal(o, err)
		}
		if o, err := f.mount.RecoverWorkspace(t.Context(), 1, serial); err != nil || !o.Prepared {
			t.Fatal(o, err)
		}
		p, err := g.Recovery(1)
		if err != nil {
			t.Fatal(err)
		}
		if err := g.Prepared(p); err != nil {
			t.Fatal(err)
		}
		if err := g.Open(1, serial); err != nil {
			t.Fatal(err)
		}
		f.lookup(t, 1, "warm")
	}
	cycle()
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	g0, fd0 := runtime.NumGoroutine(), countFDs()
	for i := 0; i < 30; i++ {
		cycle()
	}
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	g1, fd1 := runtime.NumGoroutine(), countFDs()
	t.Logf("goroutines %d -> %d, fds %d -> %d over 30 cycles", g0, g1, fd0, fd1)
	if g1 > g0+5 || fd1 > fd0+2 {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Logf("%s", buf[:n])
		t.Fatalf("REPRO R4: leak over cycles goroutines %d->%d fds %d->%d", g0, g1, fd0, fd1)
	}
}

func TestOpusR1LookupAfterRecover(t *testing.T) {
	f, g, _ := coldFixture(t)
	f.lookup(t, 1, "warm")
	serial := g.Close(1)
	if o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second)); err != nil || !o.ColdComplete {
		t.Fatal(o, err)
	}
	if o, err := f.mount.RecoverWorkspace(t.Context(), 1, serial); err != nil || !o.Prepared {
		t.Fatal(o, err)
	}
	p, _ := g.Recovery(1)
	if err := g.Prepared(p); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(1, serial); err != nil {
		t.Fatal(err)
	}
	f.lookup(t, 1, "warm2")
}

// R5: one historical lost delegation (already accounted as loss) refuses every
// later cold proof for the incarnation's lifetime.
func TestOpusR1StickyAbandonedRefusesCold(t *testing.T) {
	f, g, _ := coldFixture(t)
	e := f.lookup(t, 1, "file")
	opened := openDelegatedWriter(t, f, e.NodeId)
	writeDelegated(t, f, e.NodeId, opened.Fh, 0, []byte("accepted"))
	f.raw.mu.RLock()
	h := f.raw.handles[opened.Fh].file
	f.raw.mu.RUnlock()
	id, _ := delegationIdentity(h.node.item.GetStableIdentity())
	s := f.mount.delegations.retainState(id, false)
	if s == nil {
		t.Fatal("no delegated state")
	}
	f.mount.delegations.loseDelegation(s, "delegation recall budget missed")
	f.mount.delegations.releaseState(s)
	serial := g.Close(1)
	o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second))
	t.Logf("Suspend after earlier lost delegation: cold=%v err=%v loss=%d outcome=%v", o.ColdComplete, err, len(o.Loss), o.Outcome)
	if err != nil || !o.ColdComplete {
		t.Fatalf("REPRO R5: earlier accounted delegation loss permanently refuses cold: %v", err)
	}
	if o.Outcome.Release != "abandoned" {
		t.Fatal("cold erased current interval abandonment", o)
	}
	o, err = f.mount.RecoverWorkspace(t.Context(), 1, serial)
	if err != nil || !o.Prepared {
		t.Fatal(o, err)
	}
	proof, err := g.Recovery(1)
	if err != nil {
		t.Fatal(err)
	}
	if err = g.Prepared(proof); err != nil {
		t.Fatal(err)
	}
	if err = g.Open(1, serial); err != nil {
		t.Fatal(err)
	}
	f.lookup(t, 1, "fresh-interval")
	serial = g.Close(1)
	o, err = f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second))
	if err != nil || !o.ColdComplete || o.Outcome.Release != "released" || len(o.Loss) != 1 {
		t.Fatal("historical abandonment contaminated fresh interval", o, err)
	}

}

// R6: the bounded aggregate is the specified representation of cumulative loss,
// but reaching it latches every later lifecycle transition as failed.
func TestOpusR1LossAggregationLatchesFailure(t *testing.T) {
	f, g, _ := coldFixture(t)
	w := f.mount.workspaceLifecycle
	for i := uint64(1); i <= 33; i++ {
		w.recordDrop(writeback.DropReport{LossSequence: i, Entries: 1, Bytes: 4, Reason: "delegated mutation capacity refusal"})
	}
	serial := g.Close(1)
	o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second))
	t.Logf("Suspend after 33 accounted losses: cold=%v err=%v losses=%d", o.ColdComplete, err, len(o.Loss))
	if err != nil || !o.ColdComplete {
		t.Fatalf("REPRO R6: aggregated (bounded) loss refuses cold: %v", err)
	}
	var entries, bytes uint64
	for _, loss := range o.Loss {
		entries += loss.AcceptedEntries
		bytes += loss.AcceptedBytes
	}
	if len(o.Loss) != 32 || !o.Loss[31].Aggregated || entries != 33 || bytes != 132 {
		t.Fatal("aggregate lost counted evidence", o.Loss)
	}
	w.recordDrop(writeback.DropReport{LossSequence: 34, Entries: 1, Bytes: 4, Reason: "later accepted loss"})
	again, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(5*time.Second))
	if err != nil || !again.ColdComplete || len(again.Loss) != 32 || again.Loss[31].Sequence != 34 || again.Loss[31].AcceptedEntries != 3 {
		t.Fatal("advancing aggregate invalidated cold", again, err)
	}

}

// R7: §9 "Initial Prepare must remain interruptible by a later Suspend".
func TestOpusR1InterruptedInitialPrepareThenSuspend(t *testing.T) {
	f, g, rpc := coldFixture(t)
	serial := g.Close(1)
	rpc.outageUntil = time.Now().Add(time.Hour)
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	o, err := f.mount.PrepareWorkspace(ctx, 1, serial)
	cancel()
	t.Logf("interrupted Prepare: prepared=%v err=%v", o.Prepared, err)
	// The outage outlived the startup subscription's short horizon.
	f.mount.subscription.mu.Lock()
	f.mount.subscription.cacheUntil = continuous.Time().Add(-time.Second)
	f.mount.subscription.mu.Unlock()
	serial2 := g.Close(1)
	o, err = f.mount.SuspendWorkspace(t.Context(), 1, serial2, continuous.Time().Add(5*time.Second))
	t.Logf("newer Suspend: cold=%v err=%v", o.ColdComplete, err)
	rpc.outageUntil = time.Time{}
	o2, err2 := f.mount.RecoverWorkspace(t.Context(), 1, serial2)
	t.Logf("Recover after wake: prepared=%v err=%v", o2.Prepared, err2)
	if err != nil || !o.ColdComplete || err2 != nil || !o2.Prepared {
		t.Fatalf("REPRO R7: interrupted initial Prepare strands the incarnation: suspend=%v recover=%v", err, err2)
	}
}
