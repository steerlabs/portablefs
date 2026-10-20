package volumeserver

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// cut checks cancellation immediately before locking the selected record.
// Pausing that existing boundary leaves promotion free to acquire c.mu.
// Set readers first check cancellation at loop entry; reserve first checks
// the prior-cache horizon. Skip exactly those earlier checks.
type promotionCutContext struct {
	context.Context
	checks  atomic.Int32
	entered chan struct{}
	proceed chan struct{}
}

func newPromotionCutContext(ctx context.Context, checks int32) *promotionCutContext {
	c := &promotionCutContext{Context: ctx, entered: make(chan struct{}), proceed: make(chan struct{})}
	c.checks.Store(checks)
	return c
}
func (c *promotionCutContext) Err() error {
	if c.checks.Add(-1) == 0 {
		close(c.entered)
		<-c.proceed
	}
	return c.Context.Err()
}
func promotionBoundary(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("promotion boundary was not reached")
	}
}
func promotionReserved(t *testing.T, c *CoherenceCoordinator, record *delegationRecord, position, request uint64) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if record.retired || record.ephemeral || record.active != 0 || record.pending != nil || record.grant.State != DelegationReserved || c.position != position || c.nextRequest != request || record.owner.loss != 0 {
		t.Fatalf("reserved cut changed ownership: state=%v active=%d ephemeral=%v retired=%v pending=%+v position=%d/%d request=%d/%d loss=%d", record.grant.State, record.active, record.ephemeral, record.retired, record.pending, c.position, position, c.nextRequest, request, record.owner.loss)
	}
}

func TestCoherenceStaleCutSelectionAfterPrivatePromotion(t *testing.T) {
	for _, recall := range []bool{false, true} {
		name := "break"
		if recall {
			name = "recall"
		}
		t.Run(name, func(t *testing.T) {
			c, clock := cv2Coordinator(t)
			holder := cv2Subscribe(t, c, 1)
			pin, err := c.BeginSynchronousMutation(t.Context(), holder, [16]byte{0x6e})
			if err != nil {
				t.Fatal(err)
			}
			selected := pin.record
			if !selected.ephemeral || selected.grant.State != DelegationActive {
				t.Fatal("not an active private selection")
			}
			reservation, _, err := pin.RetainDelegation()
			if err != nil {
				t.Fatal(err)
			}
			defer reservation.Abort()
			pin.End(17)
			position, request, start := c.position, c.nextRequest, clock.Now()
			done := make(chan error, 1)
			go func() { _, err := c.cut(t.Context(), selected, recall); done <- err }()
			watchdog := time.NewTimer(5 * time.Second)
			defer watchdog.Stop()
		waitCut:
			for {
				c.mu.Lock()
				pending := selected.pending != nil
				changed := c.notificationLocked()
				c.mu.Unlock()
				if pending {
					t.Fatal("stale selection published CONTROL against Reserved")
				}
				select {
				case err := <-done:
					if !errors.Is(err, errDelegationRetry) {
						t.Fatalf("cut=%v, want internal re-admission", err)
					}
					break waitCut
				case <-changed:
				case <-watchdog.C:
					t.Fatal("reserved cut did not re-admit")
				}
			}
			promotionReserved(t, c, selected, position, request)
			if clock.Now() != start || clock.timerCount() != 0 {
				t.Fatal("reserved cut armed a deadline or advanced time")
			}
		})
	}
}

func TestCoherenceStaleSelectionReadmissionDrainsReservedReaders(t *testing.T) {
	for _, kind := range []string{"single", "set", "cacheless set"} {
		for _, enteredWait := range []bool{false, true} {
			boundary := "selection gap"
			if enteredWait {
				boundary = "ephemeral wait"
			}
			t.Run(kind+"/"+boundary, func(t *testing.T) {
				c, clock := cv2Coordinator(t)
				holder := cv2Subscribe(t, c, 1)
				identity := [16]byte{0x6e}
				pin, err := c.BeginSynchronousMutation(t.Context(), holder, identity)
				if err != nil {
					t.Fatal(err)
				}
				peer := cv2Subscribe(t, c, 2)
				checks := int32(1)
				if kind != "single" {
					checks = 2
				}
				ctx := newPromotionCutContext(t.Context(), checks)
				read := make(chan cv2GuardResult, 1)
				go func() {
					var g *DataGuard
					var err error
					switch kind {
					case "single":
						g, err = c.DataConsumed(ctx, peer, identity)
					case "set":
						g, err = c.DataConsumedSet(ctx, peer, [][16]byte{identity, {0x6f}, identity})
					default:
						g, err = c.BreakForReadSet(ctx, [][16]byte{identity, {0x6f}, identity})
					}
					read <- cv2GuardResult{g, err}
				}()
				promotionBoundary(t, ctx.entered)
				selected := pin.record
				if !selected.ephemeral || selected.grant.State != DelegationActive {
					t.Fatal("reader did not select the active private generation")
				}
				if enteredWait {
					close(ctx.proceed)
					clock.waitForTimers(t, 1)
				}
				reservation, _, err := pin.RetainDelegation()
				if err != nil {
					t.Fatal(err)
				}
				defer reservation.Abort()
				pin.End(17)
				position, request, start := c.position, c.nextRequest, clock.Now()
				if !enteredWait {
					close(ctx.proceed)
				}
				guard := cv2ReceiveGuard(t, read)
				defer guard.Release()
				promotionReserved(t, c, selected, position, request)
				c.mu.Lock()
				readers := selected.readers
				c.mu.Unlock()
				if readers != 1 {
					t.Fatalf("reserved storage sample pins=%d, want 1", readers)
				}
				granted := make(chan error, 1)
				go func() { _, err := reservation.Grant(t.Context()); granted <- err }()
				clock.waitForTimers(t, 1)
				c.mu.Lock()
				closing := selected.closingReaders
				c.mu.Unlock()
				if !closing {
					t.Fatal("final Grant did not join the reserved read")
				}
				select {
				case err := <-granted:
					t.Fatalf("grant passed the storage sample: %v", err)
				default:
				}
				guard.Release()
				if err := cv2Result(t, granted); err != nil {
					t.Fatal(err)
				}
				if clock.Now() != start {
					t.Fatal("completion advanced coherence time")
				}
				c.mu.Lock()
				defer c.mu.Unlock()
				if selected.pending != nil || selected.owner.loss != 0 || selected.readers != 0 || selected.grant.State != DelegationActive {
					t.Fatal("re-admission lost ownership or leaked a reader")
				}
			})
		}
	}
}

func TestCoherenceStaleRecallAndReserveReadmitAfterPromotion(t *testing.T) {
	for _, kind := range []string{"recall", "reserve"} {
		t.Run(kind, func(t *testing.T) {
			c, clock := cv2Coordinator(t)
			holder := cv2Subscribe(t, c, 1)
			identity := [16]byte{0x6e}
			pin, err := c.BeginSynchronousMutation(t.Context(), holder, identity)
			if err != nil {
				t.Fatal(err)
			}
			peer := cv2Subscribe(t, c, 2)
			checks := int32(1)
			if kind == "reserve" {
				checks = 2
			}
			ctx := newPromotionCutContext(t.Context(), checks)
			done := make(chan error, 1)
			reserved := make(chan *DelegationReservation, 1)
			go func() {
				if kind == "recall" {
					done <- c.Recall(ctx, identity)
					return
				}
				r, err := c.Reserve(ctx, peer, identity)
				reserved <- r
				done <- err
			}()
			promotionBoundary(t, ctx.entered)
			reservation, _, err := pin.RetainDelegation()
			if err != nil {
				t.Fatal(err)
			}
			defer reservation.Abort()
			pin.End(17)
			position, request, start := c.position, c.nextRequest, clock.Now()
			close(ctx.proceed)
			clock.waitForTimers(t, 1)
			promotionReserved(t, c, pin.record, position, request)
			grant, err := reservation.Grant(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			event := cv2Event(t, c, holder, StreamRecall)
			cv2CutAck(t, c, holder, event, 17)
			if err := cv2Result(t, done); err != nil {
				t.Fatal(err)
			}
			if kind == "reserve" {
				r := <-reserved
				if r == nil || r.record.grant.Generation == grant.Generation {
					t.Fatal("reserve did not acquire a successor")
				}
				r.Abort()
			}
			if clock.Now() != start {
				t.Fatal("completion advanced coherence time")
			}
			c.mu.Lock()
			loss := pin.record.owner.loss
			c.mu.Unlock()
			if loss != 0 {
				t.Fatalf("healthy promotion reported loss %d", loss)
			}
		})
	}
}
