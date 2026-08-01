package clientcore

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDelegationTransitionOverlapAndConcurrency(t *testing.T) {
	t.Run("authority claims share an overlapping lane", func(t *testing.T) {
		var gate delegationTransitionGate
		first, err := gate.begin(context.Background(), authorityTransition, []string{"d/file"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer first.end()
		second, err := gate.begin(context.Background(), authorityTransition, []string{"d"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		second.end()
	})

	t.Run("unrelated acquisition and authority claims proceed", func(t *testing.T) {
		var gate delegationTransitionGate
		acquire, err := gate.begin(context.Background(), acquireTransition, []string{"left"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer acquire.end()
		authority, err := gate.begin(context.Background(), authorityTransition, []string{"right/file"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		authority.end()
	})

	for _, tc := range []struct {
		name        string
		heldKind    delegationTransitionKind
		heldPath    string
		waitingKind delegationTransitionKind
		waitingPath string
	}{
		{
			name:        "ancestor authority excludes descendant acquire",
			heldKind:    authorityTransition,
			heldPath:    "d",
			waitingKind: acquireTransition,
			waitingPath: "d/sub",
		},
		{
			name:        "ancestor acquire excludes descendant authority",
			heldKind:    acquireTransition,
			heldPath:    "d",
			waitingKind: authorityTransition,
			waitingPath: "d/sub/file",
		},
		{
			name:        "overlapping acquisitions serialize",
			heldKind:    acquireTransition,
			heldPath:    "d",
			waitingKind: acquireTransition,
			waitingPath: "d/sub",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gate delegationTransitionGate
			held, err := gate.begin(
				context.Background(),
				tc.heldKind,
				[]string{tc.heldPath},
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan *delegationTransitionClaim, 1)
			go func() {
				claim, beginErr := gate.begin(
					context.Background(),
					tc.waitingKind,
					[]string{tc.waitingPath},
					nil,
				)
				if beginErr == nil {
					entered <- claim
				}
			}()
			select {
			case claim := <-entered:
				claim.end()
				held.end()
				t.Fatal("overlapping transition crossed active ownership")
			case <-time.After(20 * time.Millisecond):
			}
			held.end()
			select {
			case claim := <-entered:
				claim.end()
			case <-time.After(time.Second):
				t.Fatal("overlapping transition did not resume")
			}
		})
	}
}

func TestDelegationTransitionCancellationRemovesWaiter(t *testing.T) {
	var gate delegationTransitionGate
	held, err := gate.begin(context.Background(), acquireTransition, []string{"d"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, beginErr := gate.begin(ctx, authorityTransition, []string{"d/file"}, nil)
		result <- beginErr
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("wait error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled transition waiter did not return")
	}
	held.end()
	next, err := gate.begin(context.Background(), authorityTransition, []string{"d/file"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	next.end()
}

func TestDelegationTransitionNeverAdmitsCanceledContext(t *testing.T) {
	t.Run("pre-canceled begin and extend", func(t *testing.T) {
		var gate delegationTransitionGate
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if claim, err := gate.begin(
			ctx,
			authorityTransition,
			[]string{"d/file"},
			nil,
		); !errors.Is(err, context.Canceled) || claim != nil {
			t.Fatalf("pre-canceled begin: claim=%v err=%v", claim, err)
		}
		claim, err := gate.begin(
			context.Background(),
			acquireTransition,
			[]string{"other"},
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		defer claim.end()
		if err := claim.extend(ctx, []string{"other/file"}, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-canceled extend: %v", err)
		}
	})

	t.Run("cancel wins release wakeup", func(t *testing.T) {
		for iteration := 0; iteration < 100; iteration++ {
			var gate delegationTransitionGate
			held, err := gate.begin(
				context.Background(),
				acquireTransition,
				[]string{"d"},
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan struct {
				claim *delegationTransitionClaim
				err   error
			}, 1)
			go func() {
				claim, beginErr := gate.begin(
					ctx,
					authorityTransition,
					[]string{"d/file"},
					nil,
				)
				result <- struct {
					claim *delegationTransitionClaim
					err   error
				}{claim: claim, err: beginErr}
			}()
			time.Sleep(time.Millisecond)
			cancel()
			held.end()
			select {
			case got := <-result:
				if got.claim != nil {
					got.claim.end()
				}
				if got.claim != nil || !errors.Is(got.err, context.Canceled) {
					t.Fatalf(
						"iteration %d admitted canceled begin: claim=%v err=%v",
						iteration,
						got.claim,
						got.err,
					)
				}
			case <-time.After(time.Second):
				t.Fatalf("iteration %d canceled waiter did not return", iteration)
			}
		}
	})
}

func TestDelegationTransitionDoesNotBargePastAcquire(t *testing.T) {
	var gate delegationTransitionGate
	held, err := gate.begin(context.Background(), authorityTransition, []string{"d"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	acquireEntered := make(chan *delegationTransitionClaim, 1)
	go func() {
		claim, beginErr := gate.begin(context.Background(), acquireTransition, []string{"d"}, nil)
		if beginErr == nil {
			acquireEntered <- claim
		}
	}()
	time.Sleep(20 * time.Millisecond)

	laterAuthority := make(chan *delegationTransitionClaim, 1)
	go func() {
		claim, beginErr := gate.begin(context.Background(), authorityTransition, []string{"d/file"}, nil)
		if beginErr == nil {
			laterAuthority <- claim
		}
	}()
	unrelated, err := gate.begin(context.Background(), authorityTransition, []string{"other/file"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	unrelated.end()
	select {
	case claim := <-laterAuthority:
		claim.end()
		held.end()
		t.Fatal("later authority claim barged past queued acquisition")
	case <-time.After(20 * time.Millisecond):
	}

	held.end()
	var acquire *delegationTransitionClaim
	select {
	case acquire = <-acquireEntered:
	case <-time.After(time.Second):
		t.Fatal("queued acquisition did not enter")
	}
	select {
	case claim := <-laterAuthority:
		claim.end()
		acquire.end()
		t.Fatal("authority crossed active acquisition")
	case <-time.After(20 * time.Millisecond):
	}
	acquire.end()
	select {
	case claim := <-laterAuthority:
		claim.end()
	case <-time.After(time.Second):
		t.Fatal("authority did not resume after acquisition")
	}
}

func TestDelegationAcquirePromotionRejectsHiddenAliasCollision(t *testing.T) {
	var gate delegationTransitionGate
	authority, err := gate.begin(
		context.Background(),
		authorityTransition,
		[]string{"a/file"},
		[]uint64{42},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.end()
	acquire, err := gate.begin(
		context.Background(),
		acquireTransition,
		[]string{"b"},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer acquire.end()
	var published atomic.Bool
	if install := acquire.reconcileAcquire(
		[]string{"b/alias"},
		[]uint64{42},
		func() { published.Store(true) },
	); install {
		t.Fatal("hidden hardlink alias collision was admitted")
	}
	if !published.Load() {
		t.Fatal("rejected acquire did not retain its alias observation")
	}
}

func TestDelegationAcquirePromotionRejectsMutationCompletedAfterSnapshot(t *testing.T) {
	var gate delegationTransitionGate
	acquire, err := gate.begin(
		context.Background(),
		acquireTransition,
		[]string{"b"},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer acquire.end()
	authority, err := gate.begin(
		context.Background(),
		authorityTransition,
		[]string{"a/file"},
		[]uint64{42},
	)
	if err != nil {
		t.Fatal(err)
	}
	// The remote acquire snapshot may already exist even though its reply is
	// delayed. Complete the disjoint alias mutation before promoting that
	// reply; completion history must still reject the stale snapshot.
	authority.end()
	var published atomic.Bool
	if install := acquire.reconcileAcquire(
		[]string{"b/alias"},
		[]uint64{42},
		func() { published.Store(true) },
	); install {
		t.Fatal("snapshot predating a completed same-inode mutation was admitted")
	}
	if !published.Load() {
		t.Fatal("rejected delayed reply did not retain its alias observation")
	}
}
