package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/backend"
	"github.com/trendup-ai/portablefs/vcs/internal/managerlease"
)

// fakeLeaseRenewer scripts Renew behavior per call: an optional delay, then
// the scripted error (nil = success). Calls past the script reuse the last
// entry.
type fakeLeaseRenewer struct {
	mu     sync.Mutex
	calls  int
	script []fakeRenewStep
}

type fakeRenewStep struct {
	delay time.Duration
	err   error
}

func (f *fakeLeaseRenewer) Renew(ctx context.Context) error {
	f.mu.Lock()
	step := f.script[min(f.calls, len(f.script)-1)]
	f.calls++
	f.mu.Unlock()
	if step.delay > 0 {
		select {
		case <-time.After(step.delay):
		case <-ctx.Done():
			// The loop bounds each renew with its own timeout; a timed-out
			// renew reports the context error like a stalled backend would.
			return ctx.Err()
		}
	}
	return step.err
}

func (f *fakeLeaseRenewer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func leaseLostErr() error {
	return &backend.HTTPError{Method: "POST", Path: "/renew", Status: http.StatusConflict, Body: "VOLUME_LEASE_STALE"}
}

func TestInitialManagerLeaseWaitStopsImmediatelyOnWriterLeaseLoss(t *testing.T) {
	guard := managerlease.NewGuard(managerlease.Identity{
		ManagerEpoch:        "1",
		ManagerRuntimeID:    "manager-runtime",
		AuthorityInstanceID: "authority-instance",
		AuthorityRuntimeSeq: "1",
		AuthorityRuntimeID:  "authority-runtime",
	}, 0)
	leaseLost := make(chan struct{})
	close(leaseLost)
	started := time.Now()
	err := waitForInitialManagerLease(context.Background(), guard, leaseLost)
	if err == nil || !strings.Contains(err.Error(), "writer lease lost") {
		t.Fatalf("wait error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("writer lease loss was not observed promptly: %s", elapsed)
	}
}

// TestRenewLoopKeepsSlowRecoveryAlive: the non-serving keeper renews
// continuously while a long recovery phase (cold replay stand-in) runs, and
// never fences on a healthy backend — this is what lets a slow cold replay
// hold the writer lease.
func TestRenewLoopKeepsSlowRecoveryAlive(t *testing.T) {
	renewer := &fakeLeaseRenewer{script: []fakeRenewStep{{}}} // instant success forever
	fenced := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go renewLoop(ctx, renewer, 50*time.Millisecond, 300*time.Millisecond, func() { close(fenced) })

	time.Sleep(600 * time.Millisecond) // two full lease TTLs of "recovery"
	select {
	case <-fenced:
		t.Fatal("keeper fenced although every renewal succeeded")
	default:
	}
	if renewer.callCount() < 5 {
		t.Fatalf("keeper renewed only %d times across 600ms at a 50ms interval", renewer.callCount())
	}
}

// TestRenewLoopDefinitiveLossFencesImmediately: a lease-lost classification
// fences on the spot (recovery cancellation), never waiting for the watchdog.
func TestRenewLoopDefinitiveLossFencesImmediately(t *testing.T) {
	renewer := &fakeLeaseRenewer{script: []fakeRenewStep{{err: leaseLostErr()}}}
	fenced := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	go renewLoop(ctx, renewer, 50*time.Millisecond, 5*time.Second, func() { close(fenced) })
	select {
	case <-fenced:
	case <-time.After(2 * time.Second):
		t.Fatal("definitive lease loss did not fence")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("definitive loss took %s to fence; must not wait for the watchdog", elapsed)
	}
}

// TestRenewLoopWatchdogAnchorsPreCall: a successful renewal whose RESPONSE
// arrived late must reset the watchdog from the PRE-CALL instant. Here the
// only successful renew starts at ~100ms and takes 600ms; with pre-call
// anchoring the watchdog fires ~100ms+900ms=1s; response-time anchoring
// would push it to ~1.6s. Every later renew fails (ambiguously), so nothing
// else can extend the deadline.
func TestRenewLoopWatchdogAnchorsPreCall(t *testing.T) {
	renewer := &fakeLeaseRenewer{script: []fakeRenewStep{
		{delay: 600 * time.Millisecond},          // call 1: slow success
		{err: fmt.Errorf("backend unreachable")}, // later calls: ambiguous failure
	}}
	fenced := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	// every=100ms, ttl=1s → watchdog deadline 900ms.
	go renewLoop(ctx, renewer, 100*time.Millisecond, time.Second, func() { close(fenced) })
	select {
	case <-fenced:
	case <-time.After(3 * time.Second):
		t.Fatal("watchdog never fenced")
	}
	elapsed := time.Since(start)
	// Pre-call anchor: renew #1 started ~100ms, so the fence lands ~1s.
	// Response-time anchoring would land ~1.6s. Allow generous CI jitter but
	// stay strictly below the response-anchored bound.
	if elapsed < 800*time.Millisecond {
		t.Fatalf("fence at %s: earlier than the granted window allows", elapsed)
	}
	if elapsed > 1400*time.Millisecond {
		t.Fatalf("fence at %s: the slow response extended the deadline past the pre-call anchor", elapsed)
	}
}

// TestWatchRecoveryAbortCancelsOnEveryTrigger: SIGTERM (a DB-blackholed
// claim/replay must die with the signal, never hang on the detached journal
// context), definitive lease loss, and a manager guard fence each cancel
// BOTH recovery and journal lifecycle during recovery; completing recovery
// first stands the watcher down without canceling anything.
func TestWatchRecoveryAbortCancelsOnEveryTrigger(t *testing.T) {
	triggers := []string{"signal", "leaseLost", "guardFenced"}
	for _, trigger := range triggers {
		signalCh := make(chan struct{})
		leaseLost := make(chan struct{})
		guardFenced := make(chan struct{})
		recoveryDone := make(chan struct{})
		canceled := make(chan string, 2)
		go watchRecoveryAbort(signalCh, leaseLost, guardFenced, recoveryDone,
			func() { canceled <- "recovery" },
			func() { canceled <- "journal" },
		)
		switch trigger {
		case "signal":
			close(signalCh)
		case "leaseLost":
			close(leaseLost)
		case "guardFenced":
			close(guardFenced)
		}
		got := map[string]bool{}
		for i := 0; i < 2; i++ {
			select {
			case name := <-canceled:
				got[name] = true
			case <-time.After(2 * time.Second):
				t.Fatalf("%s during recovery did not cancel recovery+journal", trigger)
			}
		}
		if !got["recovery"] || !got["journal"] {
			t.Fatalf("%s canceled %v, want recovery AND journal", trigger, got)
		}
	}

	// A nil guard channel (development run without a manager pipe) must
	// never fire; recovery completion stands the watcher down and a LATER
	// signal/loss cancels nothing (the serving-phase fence handles it).
	leaseLost := make(chan struct{})
	signalCh := make(chan struct{})
	recoveryDone := make(chan struct{})
	canceled := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		watchRecoveryAbort(signalCh, leaseLost, nil, recoveryDone, func() { canceled <- "recovery" })
		close(done)
	}()
	close(recoveryDone)
	<-done
	close(leaseLost)
	close(signalCh)
	select {
	case <-canceled:
		t.Fatal("watcher canceled recovery after recovery completed")
	default:
	}
}

// TestRenewLeaseBeforeReadyDelayedResponseProjectsConservatively: the
// pre-ready validation anchors at the PRE-CALL instant — a delayed response
// only shrinks the proven window. A response slower than (ttl − guard)
// refuses readiness outright: slow cold replay (or a stalled backend) can
// never roll into ready on an expired lease proof.
func TestRenewLeaseBeforeReadyDelayedResponseProjectsConservatively(t *testing.T) {
	// 300ms delay against a 1s TTL and 100ms guard: 600ms of proof remains.
	ok := &fakeLeaseRenewer{script: []fakeRenewStep{{delay: 300 * time.Millisecond}}}
	if err := renewLeaseBeforeReady(context.Background(), ok, time.Second, 100*time.Millisecond); err != nil {
		t.Fatalf("a delayed-but-inside-window validation must pass: %v", err)
	}

	// 950ms delay against the same window: the round trip consumed the
	// lease; readiness must refuse.
	tooSlow := &fakeLeaseRenewer{script: []fakeRenewStep{{delay: 950 * time.Millisecond}}}
	err := renewLeaseBeforeReady(context.Background(), tooSlow, time.Second, 100*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "consumed") {
		t.Fatalf("a round trip consuming the window must refuse readiness, got %v", err)
	}
}

// TestRenewLeaseBeforeReadyRefusesOnFailure: a failed or fenced pre-ready
// renewal (e.g. the lease was lost during the replay) refuses readiness.
func TestRenewLeaseBeforeReadyRefusesOnFailure(t *testing.T) {
	lost := &fakeLeaseRenewer{script: []fakeRenewStep{{err: leaseLostErr()}}}
	err := renewLeaseBeforeReady(context.Background(), lost, time.Second, 100*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "pre-ready writer lease validation failed") {
		t.Fatalf("a lost lease at pre-ready must refuse readiness, got %v", err)
	}
}
