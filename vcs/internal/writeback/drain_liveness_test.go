package writeback

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

type observedDoneContext struct {
	context.Context
	observed chan struct{}
	once     sync.Once
}

func (c *observedDoneContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.observed) })
	return c.Context.Done()
}

type writeOutcome struct {
	handled bool
	err     error
}

// firstReleaseGateRemote blocks and fails only the first release. Later
// releases delegate to fakeAuthority so tests can prove failed release state
// is retryable without weakening ownership.
type firstReleaseGateRemote struct {
	*fakeAuthority
	releaseErr     error
	releaseEntered chan struct{}
	releaseGate    chan struct{}
	releaseOnce    sync.Once
}

func (r *firstReleaseGateRemote) ReleaseDelegation(ctx context.Context, scope, epoch string) error {
	first := false
	r.releaseOnce.Do(func() { first = true })
	if !first {
		return r.fakeAuthority.ReleaseDelegation(ctx, scope, epoch)
	}
	select {
	case r.releaseEntered <- struct{}{}:
	default:
	}
	select {
	case <-r.releaseGate:
		return r.releaseErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// committedReleaseLostReplyRemote models the only ambiguous Checkin edge:
// the authority commits the release, but the client never receives the
// response. The call remains blocked until engine shutdown interrupts it.
type committedReleaseLostReplyRemote struct {
	*fakeAuthority
	committed chan struct{}
	once      sync.Once
}

func (r *committedReleaseLostReplyRemote) ReleaseDelegation(ctx context.Context, scope, epoch string) error {
	r.fakeAuthority.mu.Lock()
	wbID := r.fakeAuthority.grants[scope].wbID
	r.fakeAuthority.mu.Unlock()
	if err := r.fakeAuthority.ReleaseDelegation(ctx, scope, epoch); err != nil {
		return err
	}
	// Final Checkin terminalizes the authority stream ledger before the reply
	// is lost. Recovery must rely on the local APPLIED+RELEASE certificate,
	// not on an authority watermark that no longer exists.
	r.fakeAuthority.mu.Lock()
	delete(r.fakeAuthority.streams, wbID)
	r.fakeAuthority.mu.Unlock()
	r.once.Do(func() { close(r.committed) })
	<-ctx.Done()
	return ctx.Err()
}

// committedRecoveryReleaseErrorRemote commits the first recovery Checkin and
// then loses its outcome. It optionally retires the stream ledger to model
// final-scope session terminalization.
type committedRecoveryReleaseErrorRemote struct {
	*fakeAuthority
	releaseErr       error
	deleteStream     bool
	firstReleaseOnce sync.Once
}

func (r *committedRecoveryReleaseErrorRemote) ReleaseDelegation(ctx context.Context, scope, epoch string) error {
	first := false
	r.firstReleaseOnce.Do(func() { first = true })
	r.fakeAuthority.mu.Lock()
	wbID := r.fakeAuthority.grants[scope].wbID
	r.fakeAuthority.mu.Unlock()
	if err := r.fakeAuthority.ReleaseDelegation(ctx, scope, epoch); err != nil {
		return err
	}
	if !first {
		return nil
	}
	if r.deleteStream {
		r.fakeAuthority.mu.Lock()
		delete(r.fakeAuthority.streams, wbID)
		r.fakeAuthority.mu.Unlock()
	}
	return r.releaseErr
}

// lateRecoveryFlushRemote commits one prior recovery batch immediately before
// the next attach's first Rebind. It models an attach cancellation that
// terminalized its client while a possibly-sent authority flush was already
// executing.
type lateRecoveryFlushRemote struct {
	*fakeAuthority
	late FlushRequest
	once sync.Once
	err  error
}

func (r *lateRecoveryFlushRemote) Rebind(ctx context.Context, writebackID string, scopes []RebindScope, through uint64, digest [32]byte) (RebindReply, error) {
	r.once.Do(func() {
		reply, err := r.fakeAuthority.FlushResolved(ctx, r.late)
		if err != nil {
			r.err = err
			return
		}
		if reply.Status != 0 {
			r.err = fmt.Errorf("late recovery flush status %d", reply.Status)
		}
	})
	if r.err != nil {
		return RebindReply{}, r.err
	}
	return r.fakeAuthority.Rebind(ctx, writebackID, scopes, through, digest)
}

func openDrainLivenessEngine(t *testing.T, remote Remote) *Engine {
	t.Helper()
	e, err := Open(context.Background(), Config{
		StateDir:    t.TempDir(),
		VolumeID:    "vol",
		Branch:      "main",
		Remote:      remote,
		BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() {
		_, _ = e.ForceClose("test teardown")
	})
	return e
}

func TestRecoveryReconcilesLatePriorFlushBeforeRebind(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushErr = errors.New("park initial tail")
	auth.mu.Unlock()
	dir := t.TempDir()
	e1, err := Open(context.Background(), Config{
		StateDir: dir, VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open first engine: %v", err)
	}
	if _, handled, err := e1.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if _, handled, err := e1.WriteAt(context.Background(), "d/file", 0, []byte("late")); err != nil || !handled {
		t.Fatalf("write: handled=%v err=%v", handled, err)
	}
	wbID := e1.writebackID
	if _, err := e1.ForceClose("park late-flush race"); err != nil {
		t.Fatalf("force close: %v", err)
	}

	streamDir := filepath.Join(dir, streamDirName(1))
	scan, err := scanStream(streamDir)
	if err != nil {
		t.Fatalf("scan parked stream: %v", err)
	}
	live, mutations, marks, _, err := decodeStreamFrames(scan.frames)
	if err != nil {
		t.Fatalf("decode parked stream: %v", err)
	}
	records := make([]wal.Record, 0, len(mutations))
	runs := make([]FlushScope, 0, len(mutations))
	for _, mutation := range mutations {
		rec, err := wal.DecodePFR1(mutation.payload)
		if err != nil {
			t.Fatalf("decode mutation %d: %v", mutation.seq, err)
		}
		rec.Seq = mutation.seq
		scope := coveringScope(live, decodePathOf(mutation))
		records = append(records, rec)
		if len(runs) != 0 && runs[len(runs)-1].Scope == scope {
			runs[len(runs)-1].Through = mutation.seq
		} else {
			runs = append(runs, FlushScope{Scope: scope, Epoch: live[scope], Through: mutation.seq})
		}
	}
	end, err := digestAt(scan, marks, scan.lastSeq)
	if err != nil {
		t.Fatalf("rebuild parked digest: %v", err)
	}
	auth.mu.Lock()
	auth.flushErr = nil
	auth.mu.Unlock()
	remote := &lateRecoveryFlushRemote{
		fakeAuthority: auth,
		late: FlushRequest{
			WritebackID: wbID, PrevDigest: digestZero(), EndDigest: end,
			Records: records, ScopeRuns: runs,
		},
	}

	e2, err := Open(context.Background(), Config{
		StateDir: dir, VolumeID: "vol", Branch: "main",
		Remote: remote, BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("recovery treated a provable late flush as terminal: %v", err)
	}
	defer func() { _, _ = e2.ForceClose("test teardown") }()
	if jobs := e2.Status().Jobs; len(jobs) != 0 {
		t.Fatalf("late flush race left a recovery conflict: %+v", jobs)
	}
	auth.mu.Lock()
	rebinds := auth.rebinds
	auth.mu.Unlock()
	if rebinds != 2 {
		t.Fatalf("rebind attempts = %d, want stale rejection plus reconciled retry", rebinds)
	}
	if err := auth.equalFile("d/file", []byte("late")); err != nil {
		t.Fatalf("late committed flush content: %v", err)
	}
}

func waitForDrainAttempt(t *testing.T, e *Engine, scope string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		e.mu.RLock()
		d := e.delegations[scope]
		ready := d != nil && d.draining && d.attempt != nil
		e.mu.RUnlock()
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("delegation %q did not enter a drain attempt", scope)
		}
		time.Sleep(time.Millisecond)
	}
}

func startObservedWrite(t *testing.T, e *Engine, path string) (<-chan writeOutcome, context.CancelFunc) {
	t.Helper()
	base, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	ctx := &observedDoneContext{
		Context:  base,
		observed: make(chan struct{}),
	}
	out := make(chan writeOutcome, 1)
	go func() {
		_, handled, err := e.WriteAt(ctx, path, 0, []byte("must-not-write-through"))
		out <- writeOutcome{handled: handled, err: err}
	}()
	select {
	case <-ctx.observed:
		return out, cancel
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("write did not block on the release attempt")
		return nil, func() {}
	}
}

func requireWriteFailure(t *testing.T, out <-chan writeOutcome, want error) {
	t.Helper()
	select {
	case got := <-out:
		if got.handled {
			t.Fatal("write was handled locally while delegation was draining")
		}
		if got.err == nil {
			t.Fatal("write escaped into write-through while delegation remained held")
		}
		if !errors.Is(got.err, want) {
			t.Fatalf("write error = %v, want errors.Is(_, %v)", got.err, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked write was not woken by the failed release")
	}
}

func TestDrainThroughCancellationUnregistersWaiters(t *testing.T) {
	f := &flusher{
		wake:   make(chan struct{}, 1),
		stopCh: make(chan struct{}),
	}
	for i := 0; i < 100; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := f.drainThrough(ctx, 1); !errors.Is(err, context.Canceled) {
			t.Fatalf("drain %d error = %v, want context canceled", i, err)
		}
	}
	f.mu.Lock()
	waiters := len(f.waiters)
	f.mu.Unlock()
	if waiters != 0 {
		t.Fatalf("canceled drains leaked %d waiters", waiters)
	}
}

func TestFlusherStopWakesDrainWaiters(t *testing.T) {
	f := &flusher{
		wake:   make(chan struct{}, 1),
		stopCh: make(chan struct{}),
	}
	out := make(chan error, 1)
	go func() { out <- f.drainThrough(context.Background(), 1) }()
	deadline := time.Now().Add(time.Second)
	for {
		f.mu.Lock()
		registered := len(f.waiters) == 1
		f.mu.Unlock()
		if registered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("drain waiter was not registered")
		}
		time.Sleep(time.Millisecond)
	}
	f.stop()
	select {
	case err := <-out:
		if !errors.Is(err, ErrFenced) {
			t.Fatalf("stopped drain error = %v, want fenced", err)
		}
	case <-time.After(time.Second):
		t.Fatal("flusher stop left drain waiter blocked")
	}
}

func TestForceCloseJoinsReleaseWorkerBeforeClosingWAL(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	prepareEntered := make(chan struct{})
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
		ProtectOpenPins: func(ctx context.Context, _, _ string) (func(bool), error) {
			close(prepareEntered)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	if _, handled, err := e.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if err := e.DrainAll(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	releaseOut := make(chan error, 1)
	go func() { releaseOut <- e.ReleaseFor(context.Background(), "d/file") }()
	select {
	case <-prepareEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("release worker did not reach open-pin protection")
	}
	forceOut := make(chan error, 1)
	go func() {
		_, err := e.ForceClose("test shutdown")
		forceOut <- err
	}()
	select {
	case err := <-forceOut:
		if err != nil {
			t.Fatalf("force close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("force close did not cancel and join release worker")
	}
	select {
	case err := <-releaseOut:
		if !errors.Is(err, ErrFenced) {
			t.Fatalf("release after force close = %v, want fenced", err)
		}
	case <-time.After(time.Second):
		t.Fatal("release caller remained blocked after force close")
	}
}

// TestForcedShutdownCancelsIdleReleaseBeforeJoiningLoop pins the shutdown
// ordering: the idle loop may itself be waiting for an engine-owned release
// worker, so forced teardown must cancel the worker before joining the loop.
func TestForcedShutdownCancelsIdleReleaseBeforeJoiningLoop(t *testing.T) {
	for _, tc := range []struct {
		name     string
		shutdown func(*Engine) error
	}{
		{
			name: "force-close",
			shutdown: func(e *Engine) error {
				_, err := e.ForceClose("test shutdown")
				return err
			},
		},
		{
			name: "abandon",
			shutdown: func(e *Engine) error {
				e.Abandon()
				return nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := newFakeAuthority()
			auth.mu.Lock()
			auth.dirs["d"] = true
			auth.mu.Unlock()
			protectEntered := make(chan struct{})
			var protectOnce sync.Once
			e, err := Open(context.Background(), Config{
				StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
				Remote: auth, BudgetBytes: 1 << 30,
				ProtectOpenPins: func(ctx context.Context, _, _ string) (func(bool), error) {
					protectOnce.Do(func() { close(protectEntered) })
					<-ctx.Done()
					return nil, ctx.Err()
				},
			})
			if err != nil {
				t.Fatalf("open engine: %v", err)
			}
			if _, handled, err := e.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
				t.Fatalf("create: handled=%v err=%v", handled, err)
			}
			if err := e.DrainAll(context.Background()); err != nil {
				t.Fatalf("drain: %v", err)
			}
			e.mu.Lock()
			d := e.delegations["d"]
			if d == nil {
				e.mu.Unlock()
				t.Fatal("delegation disappeared before idle release")
			}
			d.lastActive = time.Now().Add(-idleReleaseAfter - time.Second)
			e.mu.Unlock()

			// Count this deterministic idle pass in the same lifecycle join as
			// the periodic loop, avoiding a test-time wait for the ticker.
			e.idleWG.Add(1)
			go func() {
				defer e.idleWG.Done()
				e.releaseIdle()
			}()
			select {
			case <-protectEntered:
			case <-time.After(2 * time.Second):
				t.Fatal("idle release did not reach open-pin protection")
			}

			done := make(chan error, 1)
			go func() { done <- tc.shutdown(e) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("shutdown: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("shutdown joined the idle loop before canceling its release worker")
			}
		})
	}
}

func TestCommittedCheckinLostReplyRecoversWithoutScopeConflict(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	remote := &committedReleaseLostReplyRemote{
		fakeAuthority: auth,
		committed:     make(chan struct{}),
	}
	dir := t.TempDir()
	e1, err := Open(context.Background(), Config{
		StateDir: dir, VolumeID: "vol", Branch: "main",
		Remote: remote, BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open first engine: %v", err)
	}
	if _, handled, err := e1.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if _, handled, err := e1.WriteAt(context.Background(), "d/file", 0, []byte("durable")); err != nil || !handled {
		t.Fatalf("write: handled=%v err=%v", handled, err)
	}
	releaseOut := make(chan error, 1)
	go func() { releaseOut <- e1.ReleaseFor(context.Background(), "d/file") }()
	select {
	case <-remote.committed:
	case <-time.After(2 * time.Second):
		t.Fatal("Checkin did not commit")
	}

	if _, err := e1.ForceClose("lost Checkin reply"); err != nil {
		t.Fatalf("force close: %v", err)
	}
	select {
	case err := <-releaseOut:
		if !errors.Is(err, ErrFenced) && !errors.Is(err, context.Canceled) {
			t.Fatalf("release error = %v, want shutdown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("release worker survived ForceClose")
	}

	// The durable pre-send RELEASE makes the old scope locally final. A new
	// attach therefore sweeps the already-absent authority scope instead of
	// trying to rebind it and surfacing SCOPE_MISSING.
	e2, err := Open(context.Background(), Config{
		StateDir: dir, VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open recovery engine: %v", err)
	}
	defer func() { _, _ = e2.ForceClose("test teardown") }()
	deadline := time.Now().Add(5 * time.Second)
	for len(e2.Status().Jobs) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("lost-reply recovery did not resolve: %+v", e2.Status().Jobs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := auth.equalFile("d/file", []byte("durable")); err != nil {
		t.Fatalf("drained write was lost: %v", err)
	}
	if got := auth.grantCount(); got != 0 {
		t.Fatalf("recovery left %d grants", got)
	}
	auth.mu.Lock()
	rebinds := auth.rebinds
	auth.mu.Unlock()
	if rebinds != 0 {
		t.Fatalf("already-final release attempted %d rebinds", rebinds)
	}
}

func TestLocalReleaseCertificateSweepsUncommittedCheckin(t *testing.T) {
	releaseErr := errors.New("injected pre-commit Checkin failure")
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	remote := &firstReleaseGateRemote{
		fakeAuthority:  auth,
		releaseErr:     releaseErr,
		releaseEntered: make(chan struct{}, 1),
		releaseGate:    make(chan struct{}),
	}
	dir := t.TempDir()
	e1, err := Open(context.Background(), Config{
		StateDir: dir, VolumeID: "vol", Branch: "main",
		Remote: remote, BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open first engine: %v", err)
	}
	if _, handled, err := e1.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if _, handled, err := e1.WriteAt(context.Background(), "d/file", 0, []byte("durable")); err != nil || !handled {
		t.Fatalf("write: handled=%v err=%v", handled, err)
	}
	releaseOut := make(chan error, 1)
	go func() { releaseOut <- e1.ReleaseFor(context.Background(), "d/file") }()
	select {
	case <-remote.releaseEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("Checkin did not reach pre-commit failure seam")
	}
	close(remote.releaseGate)
	if err := <-releaseOut; !errors.Is(err, releaseErr) {
		t.Fatalf("release error = %v, want injected failure", err)
	}
	e1.mu.RLock()
	d := e1.delegations["d"]
	localFinal := d != nil && d.localFinal
	e1.mu.RUnlock()
	if !localFinal {
		t.Fatal("failed Checkin was not preceded by a durable local release certificate")
	}
	if _, err := e1.ForceClose("Checkin not committed"); err != nil {
		t.Fatalf("force close: %v", err)
	}

	e2, err := Open(context.Background(), Config{
		StateDir: dir, VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open recovery engine: %v", err)
	}
	defer func() { _, _ = e2.ForceClose("test teardown") }()
	deadline := time.Now().Add(5 * time.Second)
	for len(e2.Status().Jobs) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("uncommitted-Checkin recovery did not resolve: %+v", e2.Status().Jobs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := auth.equalFile("d/file", []byte("durable")); err != nil {
		t.Fatalf("drained write was lost: %v", err)
	}
	if got := auth.grantCount(); got != 0 {
		t.Fatalf("recovery did not sweep the uncommitted grant: %d remain", got)
	}
}

func TestRecoveryReleaseCertificateSurvivesCommittedCheckinFailure(t *testing.T) {
	for _, tc := range []struct {
		name         string
		scopes       []string
		deleteStream bool
	}{
		{name: "final-scope-ledger-retired", scopes: []string{"d"}, deleteStream: true},
		{name: "mixed-scopes-partial-release", scopes: []string{"a", "b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := newFakeAuthority()
			auth.mu.Lock()
			auth.flushErr = errors.New("park initial tail")
			for _, scope := range tc.scopes {
				auth.dirs[scope] = true
			}
			auth.mu.Unlock()
			dir := t.TempDir()
			e1, err := Open(context.Background(), Config{
				StateDir: dir, VolumeID: "vol", Branch: "main",
				Remote: auth, BudgetBytes: 1 << 30,
			})
			if err != nil {
				t.Fatalf("open first engine: %v", err)
			}
			for _, scope := range tc.scopes {
				path := scope + "/file"
				if _, handled, err := e1.Create(context.Background(), path, 0o644, false, false); err != nil || !handled {
					t.Fatalf("create %s: handled=%v err=%v", path, handled, err)
				}
				if _, handled, err := e1.WriteAt(context.Background(), path, 0, []byte(scope)); err != nil || !handled {
					t.Fatalf("write %s: handled=%v err=%v", path, handled, err)
				}
			}
			if _, err := e1.ForceClose("park for recovery release test"); err != nil {
				t.Fatalf("force close: %v", err)
			}
			auth.mu.Lock()
			auth.flushErr = nil
			auth.mu.Unlock()

			releaseErr := errors.New("committed recovery Checkin reply lost")
			remote := &committedRecoveryReleaseErrorRemote{
				fakeAuthority: auth,
				releaseErr:    releaseErr,
				deleteStream:  tc.deleteStream,
			}
			if e2, err := Open(context.Background(), Config{
				StateDir: dir, VolumeID: "vol", Branch: "main",
				Remote: remote, BudgetBytes: 1 << 30,
			}); err == nil {
				_, _ = e2.ForceClose("unexpected successful recovery")
				t.Fatal("recovery unexpectedly succeeded after injected Checkin failure")
			}

			streamDir := filepath.Join(dir, streamDirName(1))
			scan, err := scanStream(streamDir)
			if err != nil {
				t.Fatalf("scan recovery-certified stream: %v", err)
			}
			live, _, marks, _, err := decodeStreamFrames(scan.frames)
			if err != nil {
				t.Fatalf("decode recovery-certified stream: %v", err)
			}
			if len(live) != 0 {
				t.Fatalf("recovery certificate left scopes live locally: %+v", live)
			}
			through, _, err := highestAppliedCertificate(marks, scan.lastSeq)
			if err != nil || through != scan.lastSeq {
				t.Fatalf("recovery certificate through=%d tail=%d err=%v", through, scan.lastSeq, err)
			}
			job, ok := loadJob(streamDir)
			if !ok {
				t.Fatal("recovery-certified stream lost its job registry")
			}
			if _, err := analyzeAbandonedStream(streamDir, 1, scan, job); err != nil {
				t.Fatalf("force-park analysis rejected recovery-certified stream: %v", err)
			}
			auth.mu.Lock()
			rebindsAfterFailure := auth.rebinds
			auth.mu.Unlock()

			e3, err := Open(context.Background(), Config{
				StateDir: dir, VolumeID: "vol", Branch: "main",
				Remote: auth, BudgetBytes: 1 << 30,
			})
			if err != nil {
				t.Fatalf("reopen after committed recovery Checkin failure: %v", err)
			}
			defer func() { _, _ = e3.ForceClose("test teardown") }()
			if jobs := e3.Status().Jobs; len(jobs) != 0 {
				t.Fatalf("recovery certificate remained parked: %+v", jobs)
			}
			auth.mu.Lock()
			rebindsAfterRetry := auth.rebinds
			auth.mu.Unlock()
			if rebindsAfterRetry != rebindsAfterFailure {
				t.Fatalf("locally-final retry attempted %d additional rebinds", rebindsAfterRetry-rebindsAfterFailure)
			}
			if got := auth.grantCount(); got != 0 {
				t.Fatalf("recovery retry left %d grants", got)
			}
			for _, scope := range tc.scopes {
				if err := auth.equalFile(scope+"/file", []byte(scope)); err != nil {
					t.Fatalf("recovered %s: %v", scope, err)
				}
			}
		})
	}
}

func TestFailedIdleReleaseBeforeLocalFinalCanRearm(t *testing.T) {
	prepareErr := errors.New("injected prepare failure")
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
		ProtectOpenPins: func(context.Context, string, string) (func(bool), error) {
			return nil, prepareErr
		},
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })
	if _, handled, err := e.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if err := e.DrainAll(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	e.mu.Lock()
	d := e.delegations["d"]
	if d == nil {
		e.mu.Unlock()
		t.Fatal("delegation disappeared before idle release")
	}
	d.lastActive = time.Now().Add(-idleReleaseAfter - time.Second)
	e.mu.Unlock()

	e.releaseIdle()
	e.mu.RLock()
	draining, localFinal, drainErr := d.draining, d.localFinal, d.drainErr
	e.mu.RUnlock()
	if draining || localFinal || drainErr != nil {
		t.Fatalf("pre-final idle failure was not safely re-armed: draining=%v localFinal=%v err=%v", draining, localFinal, drainErr)
	}
	if _, handled, err := e.WriteAt(context.Background(), "d/file", 0, []byte("still-delegated")); err != nil || !handled {
		t.Fatalf("write after pre-final idle failure: handled=%v err=%v", handled, err)
	}
}

func TestIdleWaitTimeoutNeverRearmsRunningRelease(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	prepareEntered := make(chan struct{})
	prepareGate := make(chan struct{})
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
		ProtectOpenPins: func(context.Context, string, string) (func(bool), error) {
			close(prepareEntered)
			<-prepareGate
			return func(bool) {}, nil
		},
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })
	if _, handled, err := e.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if err := e.DrainAll(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	e.mu.Lock()
	d := e.delegations["d"]
	if d == nil {
		e.mu.Unlock()
		t.Fatal("delegation disappeared before idle release")
	}
	d.lastActive = time.Now().Add(-idleReleaseAfter - time.Second)
	e.mu.Unlock()

	idleDone := make(chan struct{})
	go func() {
		e.releaseIdleWithWait(20 * time.Millisecond)
		close(idleDone)
	}()
	select {
	case <-prepareEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("idle release did not reach open-pin protection")
	}
	select {
	case <-idleDone:
	case <-time.After(time.Second):
		t.Fatal("idle waiter did not honor its timeout")
	}

	e.mu.RLock()
	attempt := d.attempt
	draining, localFinal := d.draining, d.localFinal
	e.mu.RUnlock()
	if !draining || localFinal || attempt == nil {
		t.Fatalf("timed-out waiter changed running release: draining=%v localFinal=%v attempt=%p", draining, localFinal, attempt)
	}
	select {
	case <-attempt.done:
		t.Fatal("idle waiter timeout completed the engine-owned release attempt")
	default:
	}
	writeCtx, cancelWrite := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelWrite()
	if _, handled, err := e.WriteAt(writeCtx, "d/file", 0, []byte("must-block")); !errors.Is(err, context.DeadlineExceeded) || handled {
		t.Fatalf("write while release worker still running = handled=%v err=%v", handled, err)
	}

	close(prepareGate)
	select {
	case <-attempt.done:
		if attempt.err != nil {
			t.Fatalf("release after waiter timeout: %v", attempt.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("engine-owned release did not finish after protection unblocked")
	}
	if got := auth.grantCount(); got != 0 {
		t.Fatalf("completed release left %d grants", got)
	}
}

func TestFailedIdleReleaseNeverThawsDelegatedAdmission(t *testing.T) {
	releaseErr := errors.New("injected idle release failure")
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	remote := &firstReleaseGateRemote{
		fakeAuthority:  auth,
		releaseErr:     releaseErr,
		releaseEntered: make(chan struct{}, 1),
		releaseGate:    make(chan struct{}),
	}
	e := openDrainLivenessEngine(t, remote)
	if _, handled, err := e.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if err := e.DrainAll(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}
	e.mu.Lock()
	d := e.delegations["d"]
	if d == nil {
		e.mu.Unlock()
		t.Fatal("delegation disappeared before idle release")
	}
	d.lastActive = time.Now().Add(-idleReleaseAfter - time.Second)
	e.mu.Unlock()

	done := make(chan struct{})
	go func() {
		e.releaseIdle()
		close(done)
	}()
	select {
	case <-remote.releaseEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("idle release did not reach authority")
	}
	close(remote.releaseGate)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("failed idle release did not finish")
	}

	e.mu.RLock()
	stillDraining := d.draining
	drainErr := d.drainErr
	e.mu.RUnlock()
	if !stillDraining || !errors.Is(drainErr, releaseErr) {
		t.Fatalf("idle failure thawed scope: draining=%v err=%v", stillDraining, drainErr)
	}
	if _, handled, err := e.WriteAt(context.Background(), "d/file", 0, []byte("must-not-admit")); !errors.Is(err, releaseErr) || handled {
		t.Fatalf("write after locally-final release = handled=%v err=%v, want draining failure", handled, err)
	}
}

func TestDelegatedRenamePublishesCallbackBeforeRecallCanSnapshot(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	prepareEntered := make(chan struct{}, 1)
	prepareGate := make(chan struct{})
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
		ProtectOpenPins: func(_ context.Context, _, _ string) (func(bool), error) {
			prepareEntered <- struct{}{}
			<-prepareGate
			return func(bool) {}, nil
		},
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })
	if _, handled, err := e.Create(context.Background(), "d/a", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if err := e.DrainAll(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	callbackEntered := make(chan struct{})
	callbackGate := make(chan struct{})
	renameOut := make(chan error, 1)
	go func() {
		_, handled, err := e.Rename(context.Background(), "d/a", "d/b", func() {
			close(callbackEntered)
			<-callbackGate
		})
		if err == nil && !handled {
			err = errors.New("rename unexpectedly selected shared lane")
		}
		renameOut <- err
	}()
	select {
	case <-callbackEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("rename did not reach publication callback")
	}
	recallOut := make(chan error, 1)
	go func() { recallOut <- e.Recall(context.Background(), "d") }()
	select {
	case <-prepareEntered:
		t.Fatal("recall entered open-pin snapshot before rename publication completed")
	case <-time.After(50 * time.Millisecond):
	}
	close(callbackGate)
	if err := <-renameOut; err != nil {
		t.Fatalf("rename: %v", err)
	}
	select {
	case <-prepareEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("recall did not proceed after rename publication")
	}
	close(prepareGate)
	if err := <-recallOut; err != nil {
		t.Fatalf("recall: %v", err)
	}
}

func TestCanceledRecallLeavesEngineOwnedReleaseRunning(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushGate = make(chan struct{})
	auth.flushEntered = make(chan struct{}, 1)
	flushGate := auth.flushGate
	auth.mu.Unlock()
	e := testEngine(t, auth)

	if _, handled, err := e.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	select {
	case <-auth.flushEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("flusher did not enter the blocked authority call")
	}

	recallCtx, cancelRecall := context.WithCancel(context.Background())
	recallOut := make(chan error, 1)
	go func() { recallOut <- e.Recall(recallCtx, "d") }()
	waitForDrainAttempt(t, e, "d")

	writeOut, cancelWrite := startObservedWrite(t, e, "d/file")
	defer cancelWrite()
	cancelRecall()
	select {
	case err := <-recallOut:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("recall error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled recall did not return")
	}

	auth.mu.Lock()
	_, stillHeld := auth.grants["d"]
	auth.mu.Unlock()
	if !stillHeld {
		t.Fatal("canceled caller unexpectedly released the authority grant before the engine resolver completed")
	}

	followerOut := make(chan error, 1)
	go func() { followerOut <- e.Recall(context.Background(), "d") }()
	close(flushGate)
	select {
	case err := <-followerOut:
		if err != nil {
			t.Fatalf("long-lived follower inherited first caller cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("long-lived follower did not observe the engine-owned release")
	}
	select {
	case got := <-writeOut:
		if got.handled || got.err != nil {
			t.Fatalf("write after engine-owned release = handled=%v err=%v, want shared-lane handoff", got.handled, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("engine-owned release did not wake blocked admission")
	}
	auth.mu.Lock()
	_, stillHeld = auth.grants["d"]
	auth.mu.Unlock()
	if stillHeld {
		t.Fatal("engine-owned release stopped when its first caller canceled")
	}
}

func TestDuplicateRecallsJoinOneContextAwareAttempt(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	prepareEntered := make(chan struct{})
	prepareGate := make(chan struct{})
	var prepareMu sync.Mutex
	prepareCalls := 0
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
		ProtectOpenPins: func(context.Context, string, string) (func(bool), error) {
			prepareMu.Lock()
			prepareCalls++
			prepareMu.Unlock()
			select {
			case prepareEntered <- struct{}{}:
			default:
			}
			<-prepareGate
			return func(bool) {}, nil
		},
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })
	if _, handled, err := e.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if err := e.DrainAll(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	ownerOut := make(chan error, 1)
	go func() { ownerOut <- e.Recall(context.Background(), "d") }()
	select {
	case <-prepareEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("owner recall did not reach open-pin protection")
	}

	const followers = 24
	followerOut := make(chan error, followers)
	for i := 0; i < followers; i++ {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			followerOut <- e.Recall(ctx, "d")
		}()
	}
	for i := 0; i < followers; i++ {
		select {
		case err := <-followerOut:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("follower %d error = %v, want deadline exceeded", i, err)
			}
		case <-time.After(time.Second):
			t.Fatalf("follower %d queued behind a non-context-aware release mutex", i)
		}
	}
	prepareMu.Lock()
	gotPrepareCalls := prepareCalls
	prepareMu.Unlock()
	if gotPrepareCalls != 1 {
		t.Fatalf("duplicate recalls ran %d open-pin phases, want 1", gotPrepareCalls)
	}

	close(prepareGate)
	select {
	case err := <-ownerOut:
		if err != nil {
			t.Fatalf("owner recall: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("owner recall did not finish")
	}
	_, _, releases := auth.calls()
	if releases != 1 {
		t.Fatalf("duplicate recalls sent %d authority releases, want 1", releases)
	}
}

func TestRootRecallStartsAllOwnedScopeAttemptsBeforeWaiting(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["a"] = true
	auth.dirs["b"] = true
	auth.mu.Unlock()
	entered := make(chan string, 2)
	gate := make(chan struct{})
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main",
		Remote: auth, BudgetBytes: 1 << 30,
		ProtectOpenPins: func(_ context.Context, scope, _ string) (func(bool), error) {
			entered <- scope
			<-gate
			return func(bool) {}, nil
		},
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })
	if _, handled, err := e.Create(context.Background(), "a/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create a: handled=%v err=%v", handled, err)
	}
	if _, handled, err := e.Create(context.Background(), "b/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create b: handled=%v err=%v", handled, err)
	}
	if err := e.DrainAll(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	out := make(chan error, 1)
	go func() { out <- e.Recall(context.Background(), "") }()
	seen := map[string]bool{}
	for len(seen) < 2 {
		select {
		case scope := <-entered:
			seen[scope] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("root recall started only %+v before waiting", seen)
		}
	}
	close(gate)
	select {
	case err := <-out:
		if err != nil {
			t.Fatalf("root recall: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("root recall did not finish")
	}
}

func TestFailedReleaseWakesAdmissionWithoutWriteThrough(t *testing.T) {
	releaseErr := errors.New("injected release failure")
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	remote := &firstReleaseGateRemote{
		fakeAuthority:  auth,
		releaseErr:     releaseErr,
		releaseEntered: make(chan struct{}, 1),
		releaseGate:    make(chan struct{}),
	}
	e := openDrainLivenessEngine(t, remote)

	if _, handled, err := e.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if err := e.DrainAll(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	releaseOut := make(chan error, 1)
	go func() { releaseOut <- e.ReleaseFor(context.Background(), "d/file") }()
	select {
	case <-remote.releaseEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("release did not reach the authority")
	}

	writeOut, cancelWrite := startObservedWrite(t, e, "d/file")
	defer cancelWrite()
	close(remote.releaseGate)
	select {
	case err := <-releaseOut:
		if !errors.Is(err, releaseErr) {
			t.Fatalf("release error = %v, want injected failure", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("failed release did not return")
	}
	requireWriteFailure(t, writeOut, releaseErr)

	auth.mu.Lock()
	_, stillHeld := auth.grants["d"]
	content := append([]byte(nil), auth.files["d/file"]...)
	auth.mu.Unlock()
	if !stillHeld {
		t.Fatal("failed release unexpectedly dropped the authority grant")
	}
	if len(content) != 0 {
		t.Fatalf("failed write reached authority content: %q", content)
	}

	retryCtx, cancelRetry := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelRetry()
	if err := e.ReleaseFor(retryCtx, "d/file"); err != nil {
		t.Fatalf("release retry: %v", err)
	}
	auth.mu.Lock()
	_, stillHeld = auth.grants["d"]
	auth.mu.Unlock()
	if stillHeld {
		t.Fatal("successful release retry left the authority grant held")
	}
}

func TestTerminalParkWakesAlreadyBlockedAdmission(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	remote := &firstReleaseGateRemote{
		fakeAuthority:  auth,
		releaseEntered: make(chan struct{}, 1),
		releaseGate:    make(chan struct{}),
	}
	e := openDrainLivenessEngine(t, remote)

	if _, handled, err := e.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if err := e.DrainAll(context.Background()); err != nil {
		t.Fatalf("drain: %v", err)
	}

	releaseOut := make(chan error, 1)
	go func() { releaseOut <- e.ReleaseFor(context.Background(), "d/file") }()
	select {
	case <-remote.releaseEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("release did not reach the authority")
	}
	writeOut, cancelWrite := startObservedWrite(t, e, "d/file")
	defer cancelWrite()

	terminal := errors.Join(ErrFenced, errors.New("injected terminal park"))
	e.fl.park(terminal)
	requireWriteFailure(t, writeOut, ErrFenced)

	auth.mu.Lock()
	_, stillHeld := auth.grants["d"]
	auth.mu.Unlock()
	if !stillHeld {
		t.Fatal("terminal park unexpectedly released the authority grant")
	}

	select {
	case err := <-releaseOut:
		if !errors.Is(err, ErrFenced) {
			t.Fatalf("release error after park = %v, want fenced", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("terminal park did not wake the release caller")
	}
}
