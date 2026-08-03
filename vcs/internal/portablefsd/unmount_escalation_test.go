package portablefsd

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
)

// unmountEscalationRegistry builds a revived, unprepared attach whose normal
// unmount reaches the authority drain barrier, with that barrier replaced by a
// controllable seam.
func unmountEscalationRegistry(t *testing.T) *registry {
	t.Helper()
	stateDir := privateTestDir(t)
	writeFSKitDetachFixture(t, stateDir, false, false)
	r := newRegistry(stateDir)
	t.Cleanup(r.stopPersister)
	a := r.get(testFSKitAttachRef)
	if a == nil {
		t.Fatal("missing revived attach")
	}
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{
		Addr: serveAuthority(t), Pool: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = vol.Close() })
	a.mu.Lock()
	a.vol = vol
	a.credentialPending = false
	a.mu.Unlock()
	return r
}

// TestForcePreemptsTheNormalUnmountTransaction is the --force defect.
//
// Force used to start a SEPARATE transaction. Both then took the registry's
// global mutationMu, and the normal transaction holds it across the authority
// drain barrier and the exact detach — so --force blocked for its whole request
// budget behind exactly the wait it exists to escape, and returned having
// fenced nothing and parked nothing.
//
// Force must ESCALATE the running transaction: one transaction per attach, the
// drain cancelled in place, and the journal-first park/fence path reached
// without ever waiting on the normal drain's mutex.
func TestForcePreemptsTheNormalUnmountTransaction(t *testing.T) {
	restoreBudget := unmountTransactionBudget
	unmountTransactionBudget = 10 * time.Second
	t.Cleanup(func() { unmountTransactionBudget = restoreBudget })

	r := unmountEscalationRegistry(t)
	var drains atomic.Int32
	drainEntered := make(chan struct{})
	r.testUnmountDrain = func(ctx context.Context, _ func() error) (string, error) {
		if drains.Add(1) == 1 {
			close(drainEntered)
		}
		// The normal drain barrier: it makes no progress until it is cancelled.
		<-ctx.Done()
		return "", ctx.Err()
	}
	ops := fskitKernelOps{
		present:      func(string, string) (bool, error) { return true, nil },
		unmountExact: func(string, string, bool) error { return nil },
	}

	normal := make(chan error, 1)
	go func() {
		_, _, err := r.unmountFSKitWith(testFSKitAttachRef, false, ops)
		normal <- err
	}()
	select {
	case <-drainEntered:
	case <-time.After(4 * time.Second):
		t.Fatal("the normal unmount never reached its drain barrier")
	}

	forced := make(chan struct{})
	var forceJobID string
	var forceErr error
	go func() {
		_, forceJobID, forceErr = r.unmountFSKitWith(testFSKitAttachRef, true, ops)
		close(forced)
	}()

	select {
	case <-forced:
	case <-time.After(4 * time.Second):
		t.Fatal("--force parked behind the normal unmount's drain: it waited out " +
			"its whole budget on the mutex it exists to escape, and returned " +
			"having fenced and parked nothing")
	}
	if forceErr != nil {
		t.Fatalf("forced unmount failed: %v", forceErr)
	}
	select {
	case err := <-normal:
		if err != nil {
			t.Fatalf("the escalated transaction reported a failure to its normal "+
				"joiner instead of the force outcome: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the escalated transaction never resolved its original joiner")
	}
	if drains.Load() != 1 {
		t.Fatalf("the drain barrier ran %d times: --force started a SECOND "+
			"transaction instead of escalating the running one", drains.Load())
	}
	if r.get(testFSKitAttachRef) != nil {
		t.Fatal("the forced detach left the attach registered")
	}
	_ = forceJobID
}

// TestUnmountOutcomeIsPublishedBeforeUndiscoverability closes the
// duplicate-start window: the transaction used to be removed from the
// discoverable map BEFORE its outcome was written and its done channel closed,
// so a retry landing in that gap saw no running transaction and started a
// SECOND one against an attach the first had already detached.
func TestUnmountOutcomeIsPublishedBeforeUndiscoverability(t *testing.T) {
	restoreBudget := unmountTransactionBudget
	unmountTransactionBudget = 10 * time.Second
	t.Cleanup(func() { unmountTransactionBudget = restoreBudget })

	r := unmountEscalationRegistry(t)
	var drains atomic.Int32
	release := make(chan struct{})
	entered := make(chan struct{})
	r.testUnmountDrain = func(context.Context, func() error) (string, error) {
		if drains.Add(1) == 1 {
			close(entered)
		}
		<-release
		return "", nil
	}
	ops := fskitKernelOps{
		present:      func(string, string) (bool, error) { return true, nil },
		unmountExact: func(string, string, bool) error { return nil },
	}

	const joiners = 8
	results := make(chan error, joiners)
	for i := 0; i < joiners; i++ {
		go func() {
			_, _, err := r.unmountFSKitWith(testFSKitAttachRef, false, ops)
			results <- err
		}()
	}
	select {
	case <-entered:
	case <-time.After(4 * time.Second):
		t.Fatal("no transaction started")
	}
	r.unmountMu.Lock()
	tx := r.unmounting[testFSKitAttachRef]
	r.unmountMu.Unlock()
	if tx == nil {
		t.Fatal("the running transaction was not discoverable")
	}

	// Watch the publish/remove boundary. The instant the transaction stops
	// being discoverable, its outcome must ALREADY be published — otherwise a
	// request landing in that gap sees no running transaction and starts a
	// second one against an attach the first has already detached (and a timer
	// racing completion reports "unknown attach" for a detach that succeeded).
	boundary := make(chan error, 1)
	go func() {
		stop := time.Now().Add(6 * time.Second)
		for time.Now().Before(stop) {
			r.unmountMu.Lock()
			_, discoverable := r.unmounting[testFSKitAttachRef]
			r.unmountMu.Unlock()
			if discoverable {
				continue
			}
			select {
			case <-tx.done:
				boundary <- nil
			default:
				boundary <- errors.New(
					"the transaction became undiscoverable BEFORE its outcome was " +
						"published: a request in this window starts a second " +
						"transaction and a joiner's timer reports an unknown attach")
			}
			return
		}
		boundary <- errors.New("the transaction never became undiscoverable")
	}()
	close(release)
	if err := <-boundary; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < joiners; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("joiner %d: %v", i, err)
			}
		case <-time.After(4 * time.Second):
			t.Fatalf("joiner %d never got the transaction's outcome", i)
		}
	}
	if drains.Load() != 1 {
		t.Fatalf("the drain barrier ran %d times: a retry started a second "+
			"transaction against an attach the first had already detached",
			drains.Load())
	}
}

// TestUnmountJoinerGetsTheAbsoluteRemainingBudget pins that a joiner does not
// get a FRESH request budget. Each joiner used to arm its own full timer, so a
// caller following the verdict's own advice to "re-run to join it" could wait
// another whole budget every time and never reach a verdict.
func TestUnmountJoinerGetsTheAbsoluteRemainingBudget(t *testing.T) {
	restoreBudget := unmountTransactionBudget
	unmountTransactionBudget = 600 * time.Millisecond
	t.Cleanup(func() { unmountTransactionBudget = restoreBudget })

	r := unmountEscalationRegistry(t)
	release := make(chan struct{})
	r.testUnmountDrain = func(context.Context, func() error) (string, error) {
		<-release
		return "", nil
	}
	ops := fskitKernelOps{
		present:      func(string, string) (bool, error) { return true, nil },
		unmountExact: func(string, string, bool) error { return nil },
	}

	start := time.Now()
	first := make(chan struct{})
	go func() {
		defer close(first)
		_, _, _ = r.unmountFSKitWith(testFSKitAttachRef, false, ops)
	}()
	// The transaction outlives this test's own request, so it must be resolved
	// and joined before the compressed budget is restored.
	t.Cleanup(func() {
		close(release)
		<-first
	})
	// Join more than halfway through the transaction's budget.
	time.Sleep(unmountTransactionBudget * 2 / 3)
	joined := time.Now()
	_, _, err := r.unmountFSKitWith(testFSKitAttachRef, false, ops)
	if err == nil {
		t.Fatal("the joiner did not reach the in-progress verdict")
	}
	waited := time.Since(joined)
	total := time.Since(start)
	if waited >= unmountTransactionBudget {
		t.Fatalf("the joiner armed a FRESH %s budget (waited %s, %s after the "+
			"transaction started) instead of the transaction's absolute remaining "+
			"budget", unmountTransactionBudget, waited, total)
	}
}

// TestUnmountWaiterCancellationDoesNotAbandonTheTransaction pins that a
// joiner's own context ending stops only that waiter.
func TestUnmountWaiterCancellationDoesNotAbandonTheTransaction(t *testing.T) {
	restoreBudget := unmountTransactionBudget
	unmountTransactionBudget = 10 * time.Second
	t.Cleanup(func() { unmountTransactionBudget = restoreBudget })

	r := unmountEscalationRegistry(t)
	release := make(chan struct{})
	entered := make(chan struct{})
	var once atomic.Bool
	r.testUnmountDrain = func(context.Context, func() error) (string, error) {
		if once.CompareAndSwap(false, true) {
			close(entered)
		}
		<-release
		return "", nil
	}
	ops := fskitKernelOps{
		present:      func(string, string) (bool, error) { return true, nil },
		unmountExact: func(string, string, bool) error { return nil },
	}

	survivor := make(chan error, 1)
	go func() {
		_, _, err := r.unmountFSKitWithContext(
			context.Background(), testFSKitAttachRef, false, ops,
		)
		survivor <- err
	}()
	select {
	case <-entered:
	case <-time.After(4 * time.Second):
		t.Fatal("no transaction started")
	}

	quitterCtx, cancel := context.WithCancel(context.Background())
	quitter := make(chan error, 1)
	go func() {
		_, _, err := r.unmountFSKitWithContext(quitterCtx, testFSKitAttachRef, false, ops)
		quitter <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-quitter:
		if err == nil {
			t.Fatal("the cancelled waiter reported success")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("cancelling a waiter did not stop that waiter")
	}

	close(release)
	select {
	case err := <-survivor:
		if err != nil {
			t.Fatalf("a departing joiner abandoned the transaction: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("a departing joiner abandoned the transaction")
	}
	if r.get(testFSKitAttachRef) != nil {
		t.Fatal("the transaction did not complete its detach")
	}
}

// TestUnmountInProgressVerdictNeverClaimsUnknownAttach pins the misreport: the
// attach is removed from the registry as the transaction finishes, so a timer
// racing completion asked about a ref that was no longer there and answered
// "unmount in progress for unknown attach" for a detach that had just
// succeeded.
func TestUnmountInProgressVerdictNeverClaimsUnknownAttach(t *testing.T) {
	r := newRegistry(privateTestDir(t))
	t.Cleanup(r.stopPersister)
	err := r.unmountInProgressVerdict(testFSKitAttachRef, false, nil)
	if err == nil {
		t.Fatal("no verdict")
	}
	if strings.Contains(err.Error(), "unknown attach") {
		t.Fatalf("a verdict for an attach the transaction already detached claims "+
			"it was never known: %v", err)
	}
	waiter := r.unmountInProgressVerdict(testFSKitAttachRef, false, errors.New("client hung up"))
	if !strings.Contains(waiter.Error(), "client hung up") {
		t.Fatalf("the verdict hid why THIS waiter stopped waiting: %v", waiter)
	}
}
