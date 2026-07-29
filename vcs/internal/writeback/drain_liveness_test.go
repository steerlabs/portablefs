package writeback

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
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

func waitForDrainAttempt(t *testing.T, e *Engine, scope string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		e.mu.RLock()
		d := e.delegations[scope]
		ready := d != nil && d.draining && d.done != nil
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

func TestFailedRecallWakesAdmissionAndCanRetry(t *testing.T) {
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
		t.Fatal("failed recall did not return")
	}
	requireWriteFailure(t, writeOut, context.Canceled)

	auth.mu.Lock()
	_, stillHeld := auth.grants["d"]
	auth.mu.Unlock()
	if !stillHeld {
		t.Fatal("failed recall unexpectedly released the authority grant")
	}

	close(flushGate)
	retryCtx, cancelRetry := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelRetry()
	if err := e.Recall(retryCtx, "d"); err != nil {
		t.Fatalf("retry recall: %v", err)
	}
	auth.mu.Lock()
	_, stillHeld = auth.grants["d"]
	auth.mu.Unlock()
	if stillHeld {
		t.Fatal("successful recall retry left the authority grant held")
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

	releaseCtx, cancelRelease := context.WithCancel(context.Background())
	releaseOut := make(chan error, 1)
	go func() { releaseOut <- e.ReleaseFor(releaseCtx, "d/file") }()
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

	cancelRelease()
	select {
	case err := <-releaseOut:
		if !errors.Is(err, ErrFenced) {
			t.Fatalf("release error after park = %v, want fenced", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("release did not return after cancellation")
	}
}
