package volumeserver

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func testRoutesChange(seed byte) RoutesChange {
	var revision [32]byte
	revision[0] = seed
	return RoutesChange{Revision: revision, Canonical: []byte("node_modules\n")}
}

// A topology reader is the admission ticket held by both filesystem requests
// and attaches. The writer must not even evaluate its CAS while one is paused;
// otherwise a request can be admitted under the old routes and run after the
// new routes commit. Strict registration is deliberately exercised while the
// topology reader is held to prove the topology and participant locks are
// independent rather than recursively deadlocking.
func TestTopologyReadGuardExcludesRouteCASForPausedRequestsAndAttaches(t *testing.T) {
	for _, operation := range []string{"request", "attach"} {
		t.Run(operation, func(t *testing.T) {
			h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
			id := SessionID{1}
			var cancel context.CancelFunc
			if operation == "request" {
				h.register(t, id, testRepairBudget)
				var ctx context.Context
				ctx, cancel = context.WithCancel(context.Background())
				go serviceVisibility(ctx, h.coordinator, id)
			}
			guard := h.coordinator.AcquireTopologyRead()
			if operation == "attach" {
				h.register(t, id, testRepairBudget)
				var ctx context.Context
				ctx, cancel = context.WithCancel(context.Background())
				go serviceVisibility(ctx, h.coordinator, id)
			}
			if cancel != nil {
				defer cancel()
			}

			checked := make(chan struct{})
			done := make(chan error, 1)
			change := testRoutesChange(40)
			go func() {
				_, err := h.coordinator.ExecuteRoutesChecked(context.Background(), change, func() (bool, error) {
					close(checked)
					return true, nil
				}, func() (RoutesChange, error) { return change, nil })
				done <- err
			}()
			select {
			case <-checked:
				t.Fatal("route CAS ran while old-topology admission was still pinned")
			case <-time.After(50 * time.Millisecond):
			}
			guard.Release()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("route writer did not resume after topology admission ended")
			}
		})
	}
}

func TestExecuteRoutesCheckedSerializesConcurrentCompareAndSwap(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	old := testRoutesChange(1)
	first, second := testRoutesChange(2), testRoutesChange(3)
	active := old
	start := make(chan struct{})
	results := make(chan error, 2)
	apply := func(next RoutesChange) {
		<-start
		_, err := h.coordinator.ExecuteRoutesChecked(context.Background(), next, func() (bool, error) {
			if active.Revision != old.Revision {
				return false, errors.New("compare-and-swap lost")
			}
			return true, nil
		}, func() (RoutesChange, error) {
			active = next
			return next, nil
		})
		results <- err
	}
	go apply(first)
	go apply(second)
	close(start)
	var succeeded, lost int
	for range 2 {
		if err := <-results; err == nil {
			succeeded++
		} else if err.Error() == "compare-and-swap lost" {
			lost++
		} else {
			t.Fatalf("unexpected Apply result: %v", err)
		}
	}
	if succeeded != 1 || lost != 1 {
		t.Fatalf("concurrent CAS results = %d success, %d lost; want exactly one of each", succeeded, lost)
	}
}

// A routing change is volume-wide, so every strict mount is in its audience
// whatever it has resolved. The resolved-name index answers "could this mount
// be caching this coordinate"; routing topology is not a coordinate, and a
// mount that has read nothing still routes.
func TestRoutesChangeQuiescesEveryStrictParticipantAndCommitsBetweenPhases(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	first, second := SessionID{1}, SessionID{2}
	h.register(t, first, testRepairBudget)
	h.register(t, second, testRepairBudget)
	// Deliberately no resolve() anywhere: neither mount has cached a thing.

	change := testRoutesChange(7)
	var prepared, committed, completed atomic.Int64
	observe := func(id SessionID) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		after, err := h.coordinator.InitialCursor(id)
		if err != nil {
			t.Errorf("%x: initial cursor: %v", id, err)
			return
		}
		for range 2 {
			event, err := h.coordinator.Next(ctx, id, after)
			if err != nil {
				t.Errorf("%x: %v", id, err)
				return
			}
			if event.Routes == nil {
				t.Errorf("%x: phase %v carried no routes change", id, event.Cursor.Phase)
				return
			}
			if len(event.Targets) != 0 {
				t.Errorf("%x: a routing change must not be encoded as repair targets", id)
				return
			}
			if event.Routes.Revision != change.Revision {
				t.Errorf("%x: revision %x, want %x", id, event.Routes.Revision, change.Revision)
				return
			}
			switch event.Cursor.Phase {
			case VisibilityPrepare:
				prepared.Add(1)
			case VisibilityComplete:
				// COMPLETE must not arrive before the declaration is durable:
				// a frontend that reopened publication first would serve the
				// new topology from a volume that does not have it yet.
				if committed.Load() == 0 {
					t.Errorf("%x: COMPLETE arrived before the declaration was committed", id)
				}
				completed.Add(1)
			}
			if err := h.coordinator.Ack(id, event.Cursor); err != nil {
				t.Errorf("%x: ack %v: %v", id, event.Cursor, err)
				return
			}
			after = event.Cursor
		}
	}
	go observe(first)
	go observe(second)

	acknowledged, err := h.coordinator.ExecuteRoutes(context.Background(), change, func() (RoutesChange, error) {
		if prepared.Load() != 2 {
			t.Errorf("commit ran with %d of 2 mounts quiesced", prepared.Load())
		}
		committed.Add(1)
		return change, nil
	})
	if err != nil {
		t.Fatalf("apply routes: %v", err)
	}
	if acknowledged != 2 {
		t.Fatalf("%d participants acknowledged, want 2", acknowledged)
	}
	if completed.Load() != 2 {
		t.Fatalf("%d mounts reopened publication, want 2", completed.Load())
	}
}

// One mount that will not acknowledge must cost exactly itself. It is fenced on
// the budget it committed to at attach, the change still lands for everyone
// else, and the epoch is untouched - freezing the volume because one machine
// stopped answering would stop the machines that are healthy.
func TestRoutesChangeFencesOnlyTheParticipantThatMissedItsOwnBudget(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	healthy, silent := SessionID{1}, SessionID{2}
	const silentBudget = 150 * time.Millisecond
	h.register(t, healthy, testRepairBudget)
	h.register(t, silent, silentBudget)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go serviceVisibility(ctx, h.coordinator, healthy)
	// The silent mount answers PREPARE and then stops, so what expires is its
	// COMPLETE budget rather than its PREPARE one.
	go func() {
		event, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, silent)
		if err != nil {
			return
		}
		_ = h.coordinator.Ack(silent, event.Cursor)
	}()

	change := testRoutesChange(9)
	started := time.Now()
	acknowledged, err := h.coordinator.ExecuteRoutes(context.Background(), change, func() (RoutesChange, error) {
		return change, nil
	})
	if err != nil {
		t.Fatalf("apply routes: %v", err)
	}
	if acknowledged != 1 {
		t.Fatalf("%d participants acknowledged, want 1", acknowledged)
	}
	if !h.fencer.wasFenced(silent) {
		t.Fatal("the mount that never acknowledged is still in the barrier")
	}
	if reason := h.fenceReasonFor(silent); !errors.Is(reason, ErrVisibilityDeadline) {
		t.Fatalf("the silent mount was fenced for %v, want ErrVisibilityDeadline", reason)
	}
	if !h.fencer.live(healthy) {
		t.Fatal("fencing the silent mount also took down the mount that answered")
	}
	// Its own budget, not the other mount's and not a volume-wide one.
	if waited := time.Since(started); waited > testRepairBudget/2 {
		t.Fatalf("waited %s for a mount that committed to %s", waited, silentBudget)
	}
	if err := h.coordinator.Execute(context.Background(), SessionID{9}, MutationID{Sequence: 1},
		testMutationDependencies("after"),
		testVisibilityPrepare("after"), func() ([]VisibilityTarget, bool) {
			return testVisibilityTargets("after"), true
		}); err != nil {
		t.Fatalf("the epoch did not survive one fenced mount: %v", err)
	}
}

// This synthetic participant models a future frontend that can stage PREPARE
// without revoking and explicitly roll back to the active declaration. Current
// FUSE and FSKit frontends are covered separately: they terminate during route
// PREPARE and never reach this COMPLETE path.
func TestRoutesChangeCommitFailureSendsTruthfulCompleteToReversibleParticipant(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	mount := SessionID{1}
	h.register(t, mount, testRepairBudget)

	active, attempted := testRoutesChange(1), testRoutesChange(2)
	seen := make(chan VisibilityEvent, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	initial := initialVisibilityCursor(t, h.coordinator, mount)
	go func() {
		after := initial
		for range 2 {
			event, err := h.coordinator.Next(ctx, mount, after)
			if err != nil {
				return
			}
			seen <- event
			if err := h.coordinator.Ack(mount, event.Cursor); err != nil {
				return
			}
			after = event.Cursor
		}
	}()

	refusal := errors.New("no space left on device")
	acknowledged, err := h.coordinator.ExecuteRoutes(context.Background(), attempted, func() (RoutesChange, error) {
		return active, refusal
	})
	if !errors.Is(err, refusal) {
		t.Fatalf("ExecuteRoutes = %v, want the commit failure", err)
	}
	if acknowledged != 0 {
		t.Fatalf("failed commit returned %d acknowledgements", acknowledged)
	}
	prepare, complete := <-seen, <-seen
	if prepare.Cursor.Phase != VisibilityPrepare || prepare.Routes == nil ||
		prepare.Routes.Revision != attempted.Revision {
		t.Fatalf("PREPARE = %+v, want attempted revision %x", prepare, attempted.Revision)
	}
	if complete.Cursor.Phase != VisibilityComplete || complete.Routes == nil ||
		complete.Routes.Revision != active.Revision {
		t.Fatalf("COMPLETE = %+v, want still-active revision %x", complete, active.Revision)
	}
	if h.fencer.wasFenced(mount) {
		t.Fatal("explicitly reversible protocol participant was fenced")
	}
}

func TestRoutesCommitFailurePreservesProductionPrepareFencing(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	mount := SessionID{1}
	h.register(t, mount, 40*time.Millisecond)
	active, attempted := testRoutesChange(1), testRoutesChange(2)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	reported := make(chan error, 1)
	go func() {
		prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, mount)
		if err != nil {
			reported <- err
			return
		}
		reported <- h.coordinator.ReportBlocked(ctx, mount, prepare.Cursor)
	}()

	refusal := errors.New("definite route commit refusal")
	acknowledged, err := h.coordinator.ExecuteRoutes(ctx, attempted, func() (RoutesChange, error) {
		if !h.fencer.wasFenced(mount) {
			t.Error("commit ran before production-style PREPARE fencing completed")
		}
		return active, refusal
	})
	if !errors.Is(err, refusal) {
		t.Fatalf("ExecuteRoutes = %v, want commit refusal", err)
	}
	if acknowledged != 0 {
		t.Fatalf("commit failure returned %d live production participants", acknowledged)
	}
	if reportErr := <-reported; !errors.Is(reportErr, ErrVisibilityBlocked) {
		t.Fatalf("production PREPARE report = %v, want ErrVisibilityBlocked", reportErr)
	}
	if reason := h.fenceReasonFor(mount); !errors.Is(reason, ErrVisibilityBlocked) {
		t.Fatalf("production PREPARE fence = %v", reason)
	}
	if _, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, mount); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("departed production participant received COMPLETE: %v", err)
	}
}

// A routing change withdraws whole subtrees, and a rule set may name any of
// them, so a mount that cannot make a binding unservable in a directory it is
// holding cannot service this COMPLETE either. It is the same proven cycle as
// an ordinary mutation's, reported the same way and ended just as immediately -
// and, just as with an ordinary mutation, the mount is the one that decides,
// because it is the only party that knows whether it has anything cached to
// withdraw.
func TestRoutesChangeAcceptsABlockedReportFromAParkedMount(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	parked := SessionID{1}
	const parkedBudget = 80 * time.Millisecond
	h.register(t, parked, parkedBudget)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reported := make(chan time.Time, 1)
	go func() {
		// It can answer PREPARE - that needs no kernel lock - and reports the
		// cycle on COMPLETE.
		prepare, err := nextFromInitialVisibilityCursor(t, h.coordinator, ctx, parked)
		if err != nil {
			return
		}
		if err := h.coordinator.Ack(parked, prepare.Cursor); err != nil {
			return
		}
		complete, err := h.coordinator.Next(ctx, parked, prepare.Cursor)
		if err != nil {
			return
		}
		reported <- time.Now()
		_ = h.coordinator.ReportBlocked(context.Background(), parked, complete.Cursor)
	}()

	change := testRoutesChange(3)
	started := time.Now()
	acknowledged, err := h.coordinator.ExecuteRoutes(context.Background(), change, func() (RoutesChange, error) {
		return change, nil
	})
	if err != nil {
		t.Fatalf("apply routes: %v", err)
	}
	if acknowledged != 0 {
		t.Fatalf("%d participants acknowledged, want 0", acknowledged)
	}
	if reason := h.fenceReasonFor(parked); !errors.Is(reason, ErrVisibilityBlocked) {
		t.Fatalf("the parked mount was fenced for %v, want ErrVisibilityBlocked", reason)
	}
	<-reported
	if waited := time.Since(started); waited < parkedBudget || waited > 4*parkedBudget {
		t.Fatalf("the change waited %s after a blocked report, want one %s fencing grace", waited, parkedBudget)
	}
}

// A mount that is busy but can still withdraw its own cached bindings must not
// be fenced by a routing change. Applying a rule set on an active volume is
// exactly when every mount is busy.
func TestRoutesChangeDoesNotFenceABusyMountThatAcknowledges(t *testing.T) {
	h := newVisibilityHarness(t, PriorEpochStrictMountsFenced)
	busy := SessionID{1}
	h.register(t, busy, testRepairBudget)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go serviceVisibility(ctx, h.coordinator, busy)
	change := testRoutesChange(4)
	acknowledged, err := h.coordinator.ExecuteRoutes(context.Background(), change, func() (RoutesChange, error) {
		return change, nil
	})
	if err != nil {
		t.Fatalf("apply routes: %v", err)
	}
	if acknowledged != 1 {
		t.Fatalf("%d participants acknowledged, want 1", acknowledged)
	}
	if h.fencer.wasFenced(busy) {
		t.Fatalf("a mount that acknowledged the routing change was fenced for %v", h.fenceReasonFor(busy))
	}
}
