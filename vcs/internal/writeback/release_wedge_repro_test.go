package writeback

// Minimal repros for the two release-drain findings observed on the
// 2026-07-31 live FSKit saturation battery (HEAD bfac96b).
//
// Both are properties of ONE function: Engine.finishRelease
// (delegation.go), which is spawned by prepareReleaseLocked as a
// detached goroutine carrying the ENGINE lifetime context:
//
//	go func() { _ = e.finishRelease(e.ctx, d, attempt) }()
//
// and which drains the whole stream before it may check in:
//
//	targets = e.fl.scopeTails(d.scope)   // per lane, since round 7
//	e.fl.drainLanesThrough(ctx, targets)
//
// Repro A (wedge): e.ctx has no deadline and drainThrough has no
// no-progress bound of its own, so an authority that stops applying
// leaves the scope `draining` FOREVER. Nothing ever sets drainErr, so
// the scope never becomes usable again and never fails definitely.
//
// Repro B (head-of-line): the drain target is the last sequence of the
// WHOLE shared stream, not the releasing scope's own tail. Releasing a
// metadata-only scope whose records are already applied therefore waits
// for unrelated BULK DATA appended to a different scope. Live, with the
// data lane paced at the measured applied rate, this is what turned a
// single cold-scope mkdir into a 26.6 s syscall while the mount was
// otherwise healthy.
//
// These tests only OBSERVE current behaviour; they are written to fail
// once the behaviour is fixed, and each says what the fixed shape is.

import (
	"context"
	"errors"
	"testing"
	"time"
)

// engineWAL is the stream a barrier drains. It is deliberately no longer used
// to compute a drain TARGET: round 3 narrowed the target from the stream's tail
// to the scope's, and round 7 narrowed it again to the scope's tail PER LANE
// (flusher.scopeTails). Only an explicit fsync-class barrier still drains
// everything, and it asks the WAL for each lane's tail rather than one global
// sequence.
func engineWAL(t *testing.T, e *Engine) *streamWAL {
	t.Helper()
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.wal == nil {
		t.Fatal("engine has no stream")
	}
	return e.wal
}

// shutUplink installs a FRESH closed gate on an authority whose original gate
// the fixture already opened, so a test can re-saturate mid-run. The returned
// closer is registered for cleanup so teardown never blocks.
func shutUplink(t *testing.T, a *fakeAuthority) {
	t.Helper()
	g := make(chan struct{})
	a.mu.Lock()
	a.flushGate = g
	a.mu.Unlock()
	var once bool
	t.Cleanup(func() {
		if !once {
			once = true
			close(g)
		}
	})
}

// drainingScopes reports every scope the engine currently has parked in a
// release drain.
func drainingScopes(e *Engine) []string {
	var out []string
	for _, d := range e.Status().Delegations {
		if d.Draining {
			out = append(out, d.Scope)
		}
	}
	return out
}

// TestReleaseDrainIsUnboundedWhenTheAuthorityStopsApplying is repro A.
//
// With the uplink shut, a delegation release is triggered and the caller's
// own bounded context expires — as the 50 s operationAdmissionBudget does
// live. The RELEASE ITSELF, however, runs under e.ctx, so it keeps waiting.
// The scope stays `draining` past the flusher's 30 s no-progress window with
// no drainErr, which is exactly the state the wedged production mount was
// found in: ~100 frontend goroutines queued on the namespace lock behind
// release goroutines that had been in drainThrough for 13-14 minutes.
//
// A fixed engine must give the release a DEFINITE outcome on its own —
// either a bound, or the watchdog's ErrUplinkStalled recorded as drainErr —
// so the scope stops being draining and later callers get a typed failure
// instead of an unbounded wait.
func TestReleaseDrainIsUnboundedWhenTheAuthorityStopsApplying(t *testing.T) {
	pinCreditTimings(t, 150*time.Millisecond, 25*time.Second, 200*time.Millisecond)
	f := newSaturationFixture(t, 4<<20)
	ctx := context.Background()

	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if _, _, err := f.e.WriteAppend(ctx, "d/f", make([]byte, 64<<10)); err != nil {
		t.Fatalf("seed append: %v", err)
	}
	if !f.e.Covers("d/f") {
		t.Fatal("fixture did not acquire the delegation under test")
	}

	// The caller's bounded attempt. Live this is the 50 s operation budget;
	// compressed here. It is EXPECTED to time out — the finding is what
	// happens to the release afterwards.
	relCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	err := f.e.ReleaseFor(relCtx, "d/f")
	cancel()
	if err == nil {
		t.Skip("the uplink applied the release; fixture did not reach the saturated state")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Logf("caller's release attempt ended with %v (a definite typed answer here is fine)", err)
	}

	// The release goroutine outlives the caller by design. The question is
	// whether it ever REACHES A VERDICT. noProgressWindow is the flusher's
	// declared window for calling an uplink stalled; wait past it.
	deadline := time.Now().Add(noProgressWindow + 10*time.Second)
	for time.Now().Before(deadline) {
		if len(drainingScopes(f.e)) == 0 {
			t.Log("the scope left the draining state on its own; behaviour is bounded")
			return
		}
		time.Sleep(200 * time.Millisecond)
	}

	stuck := drainingScopes(f.e)
	if len(stuck) > 0 {
		t.Fatalf("FINDING: scope(s) %v are still draining %s after the release was "+
			"triggered against an authority that has applied nothing — past the %s "+
			"no-progress window — with no drainErr recorded. finishRelease runs under "+
			"e.ctx (delegation.go, prepareReleaseLocked) and drainThrough (flush.go) "+
			"has no bound of its own, so the scope never reaches a definite outcome "+
			"and every later operation on it waits forever. Live this wedged the whole "+
			"mount: umount --force could not break in either, because attach.detach "+
			"takes frontendSerial+nsMu before it looks at the force flag.",
			stuck, noProgressWindow+10*time.Second, noProgressWindow)
	}
}

// TestMetadataScopeReleaseWaitsForUnrelatedBulkData is repro B.
//
// Two disjoint scopes share one dense WAL stream. The metadata scope's own
// records are applied and durable BEFORE the data flood starts. Releasing it
// should therefore be immediate — nothing of its own is unshipped. It is not:
// finishRelease drains through w.LastSeq(), which by then covers the bulk
// bytes of the OTHER scope.
//
// Live, the data backlog is held at the credit setpoint (~180-220 MiB) and
// applied at the measured uplink rate (~7 MB/s), so this head-of-line is
// worth 25-30 s per transition — and Engine.admit takes a transition every
// time a mutation lands outside the currently granted scope (the ancestor
// push-down at engine.go, "The active grant is a strict ancestor..."), which
// is exactly what walking into fresh directories does.
func TestMetadataScopeReleaseWaitsForUnrelatedBulkData(t *testing.T) {
	pinCreditTimings(t, 150*time.Millisecond, 25*time.Second, 200*time.Millisecond)
	f := newSaturationFixture(t, 8<<20)
	ctx := context.Background()

	// 1. Metadata-only scope, applied and durable while the uplink is open.
	f.openUplink()
	if _, handled, err := f.e.Create(ctx, "meta/only", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create meta/only: handled=%v err=%v", handled, err)
	}
	if !f.e.Covers("meta/only") {
		t.Fatal("metadata scope was not delegated")
	}
	drainCtx, cancelDrain := context.WithTimeout(ctx, 20*time.Second)
	if err := f.e.fl.drainAll(drainCtx, engineWAL(t, f.e)); err != nil {
		cancelDrain()
		t.Fatalf("drain the metadata scope's own tail: %v", err)
	}
	cancelDrain()

	// 2. A DIFFERENT scope floods bulk data that cannot ship.
	shutUplink(t, f.auth)
	if _, handled, err := f.e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create d/f: handled=%v err=%v", handled, err)
	}
	chunk := make([]byte, 256<<10)
	for i := 0; i < 8; i++ {
		wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, _, err := f.e.WriteAppend(wctx, "d/f", chunk)
		cancel()
		if err != nil {
			break
		}
	}

	// 3. Release the metadata scope. Its own tail is already applied, so a
	//    scope-scoped drain returns at once.
	relCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	start := time.Now()
	err := f.e.ReleaseFor(relCtx, "meta/only")
	elapsed := time.Since(start)
	cancel()

	if err == nil {
		return // fixed: the release did not wait for the other scope's bytes
	}
	t.Fatalf("FINDING: releasing metadata-only scope %q took %s and ended %v, even "+
		"though every record of that scope was applied and durable before the flood "+
		"began. finishRelease (delegation.go) sets target = w.LastSeq() — the last "+
		"sequence of the WHOLE shared stream — instead of the releasing scope's own "+
		"admitted tail, so the release is head-of-line blocked behind unrelated bulk "+
		"data held at the data lane's credit setpoint. That is the 26.6 s cold-scope "+
		"mkdir measured live under a 3 GiB flood.",
		"meta/only", elapsed.Round(time.Millisecond), err)
}
