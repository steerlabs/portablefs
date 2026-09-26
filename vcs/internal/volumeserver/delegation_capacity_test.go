package volumeserver

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Assert both indices, ownership charges, and observability against the actual
// live records. Retired pinned records are deliberately included in the model.
func assertDelegationCapacity(t *testing.T, c *CoherenceCoordinator, reservations, records uint64) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.delegations) != int(records) || len(c.delegationsByID) != int(records) || c.stats.DelegationCapacityReservations != reservations {
		t.Fatalf("capacity: identities=%d ids=%d reservations=%d; want records=%d reservations=%d", len(c.delegations), len(c.delegationsByID), c.stats.DelegationCapacityReservations, records, reservations)
	}
	var total int
	for _, n := range c.delegationCharges {
		if n <= 0 || n > c.maxDelegationsPerSession {
			t.Fatalf("invalid session charge %d", n)
		}
		total += n
	}
	if total != int(records+reservations) || total > c.maxDelegations {
		t.Fatalf("charged=%d, retained=%d; volume limit=%d", total, records+reservations, c.maxDelegations)
	}
	var reserved, active, recalling, retiring uint64
	for identity, record := range c.delegations {
		if c.delegationsByID[record.grant.ID] != record || identity != record.grant.Identity {
			t.Fatal("delegation indices diverged")
		}
		if record.retired {
			retiring++
		} else {
			if record.owner.held[identity] != record {
				t.Fatal("live record missing from owner")
			}
			switch record.grant.State {
			case DelegationReserved:
				reserved++
			case DelegationActive:
				active++
			case DelegationRecalling:
				recalling++
			default:
				t.Fatal("invalid live delegation state")
			}
		}
	}
	if c.stats.DelegationsReserved != reserved || c.stats.DelegationsActive != active || c.stats.DelegationsRecalling != recalling || c.stats.DelegationsRetiring != retiring {
		t.Fatalf("state counters diverged: %+v; want reserved=%d active=%d recalling=%d retiring=%d", c.stats, reserved, active, recalling, retiring)
	}
}

func TestDelegationCapacityLimitsAndAtomicAdmission(t *testing.T) {
	c := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock(), MaxDelegationsPerSession: 1, MaxDelegations: 2})
	a, b, d := cv2Subscribe(t, c, 1), cv2Subscribe(t, c, 2), cv2Subscribe(t, c, 3)
	first, err := c.ReserveNew(a, [16]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	before := c.position
	if _, err := c.ReserveNew(a, [16]byte{2}); !errors.Is(err, ErrSessionDelegationLimit) {
		t.Fatalf("session reservation overflow: %v", err)
	}
	if c.position != before {
		t.Fatal("refused reservation published withdrawal")
	}
	second, err := c.ReserveDelegationCapacity(b)
	if err != nil {
		t.Fatal(err)
	}
	assertDelegationCapacity(t, c, 1, 1)
	if _, err := c.ReserveNew(d, [16]byte{3}); !errors.Is(err, ErrVolumeDelegationLimit) {
		t.Fatalf("volume overflow excluding future CREATE identity: %v", err)
	}
	if _, err := second.ReserveNew([16]byte{}); !errors.Is(err, ErrCoherenceIdentity) {
		t.Fatalf("zero identity accepted: %v", err)
	}
	if _, err := second.ReserveNew([16]byte{1}); !errors.Is(err, ErrDelegationBusy) {
		t.Fatalf("duplicate identity accepted: %v", err)
	}
	transferred, err := second.ReserveNew([16]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	second.Release()
	second.Release()
	assertDelegationCapacity(t, c, 0, 2)
	first.Abort()
	first.Abort()
	transferred.Abort()
	assertDelegationCapacity(t, c, 0, 0)
	if len(c.delegationCharges) != 0 {
		t.Fatal("zero session charge retained")
	}
}

func TestDelegationCapacityCancellationAndColdReservation(t *testing.T) {
	c := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock(), MaxDelegationsPerSession: 1})
	a := cv2Subscribe(t, c, 1)
	capacity, err := c.ReserveDelegationCapacity(a)
	if err != nil {
		t.Fatal(err)
	}
	cold, err := c.Subscribe(a.Session)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReserveDelegationCapacity(cold.Token); !errors.Is(err, ErrSessionDelegationLimit) {
		t.Fatalf("cold reset evaded admitted CREATE charge: %v", err)
	}
	if _, err := capacity.ReserveNew([16]byte{1}); !errors.Is(err, ErrSubscription) {
		t.Fatalf("old CREATE crossed cold boundary: %v", err)
	}
	capacity.Release()
	assertDelegationCapacity(t, c, 0, 0)
	peer := cv2Subscribe(t, c, 2)
	reservation, err := c.ReserveNew(cold.Token, [16]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reservation.Grant(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("unwithdrawn grant after cancellation: %v", err)
	}
	reservation.Abort()
	assertDelegationCapacity(t, c, 0, 0)
	cv2AckAll(t, c, peer)
}

func TestDelegationCapacityRetainsTerminalPinsAcrossColdAndForget(t *testing.T) {
	for _, pinKind := range []string{"flush", "read", "ordered-flush"} {
		t.Run(pinKind, func(t *testing.T) {
			c := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock(), MaxDelegationsPerSession: 1, MaxDelegations: 1})
			a := cv2Subscribe(t, c, 1)
			g := cv2Grant(t, c, a, [16]byte{1})
			var release func()
			switch pinKind {
			case "flush":
				pin, err := c.BeginFlush(a, g.Identity, g.ID, g.Generation)
				if err != nil {
					t.Fatal(err)
				}
				release = func() { pin.End(1) }
			case "read":
				pin, err := c.DataConsumedSet(t.Context(), a, [][16]byte{g.Identity})
				if err != nil {
					t.Fatal(err)
				}
				release = pin.Release
			case "ordered-flush":
				pin, err := c.BeginOrderedFlush(a, g.ID, g.Generation, 1, MutationID{Sequence: 1})
				if err != nil {
					t.Fatal(err)
				}
				release = pin.Abort
			}
			c.ExpireSession(a.Session)
			assertDelegationCapacity(t, c, 0, 1)
			if c.Stats().DelegationsRetiring != 1 {
				t.Fatal("terminal pin not observable")
			}
			cold, err := c.Subscribe(a.Session)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.ReserveNew(cold.Token, [16]byte{2}); !errors.Is(err, ErrSessionDelegationLimit) {
				t.Fatalf("cold evaded retired pin: %v", err)
			}
			clock := c.clock.(*cv2Clock)
			clock.Advance(SubscriptionTTL)
			if err := c.ForgetSession(a.Session); err != nil {
				t.Fatal(err)
			}
			third := cv2Subscribe(t, c, 1)
			if _, err := c.ReserveDelegationCapacity(third); !errors.Is(err, ErrSessionDelegationLimit) {
				t.Fatalf("forgotten session evaded retired pin: %v", err)
			}
			release()
			release()
			assertDelegationCapacity(t, c, 0, 0)
			r, err := c.ReserveNew(third, [16]byte{3})
			if err != nil {
				t.Fatal(err)
			}
			r.Abort()
			assertDelegationCapacity(t, c, 0, 0)
		})
	}
}

func TestDelegationCapacityReuseAndRefusalBeforeRecall(t *testing.T) {
	c := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock(), MaxDelegationsPerSession: 1, MaxDelegations: 1})
	a := cv2Subscribe(t, c, 1)
	g := cv2Grant(t, c, a, [16]byte{1})
	b := cv2Subscribe(t, c, 2)
	reused, err := c.Reserve(t.Context(), a, g.Identity)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reused.Grant(t.Context()); err != nil || got.ID != g.ID {
		t.Fatalf("same-holder capacity reuse = %+v %v", got, err)
	}
	if _, err := c.Reserve(t.Context(), b, g.Identity); !errors.Is(err, ErrVolumeDelegationLimit) {
		t.Fatalf("receiver at volume limit: %v", err)
	}
	if got, ok := c.LookupDelegation(g.Identity); !ok || got.State != DelegationActive || got.ID != g.ID {
		t.Fatalf("refused admission recalled healthy owner: %+v %v", got, ok)
	}
	if _, err := c.LookupOwnedDelegation(b, g.ID, g.Generation); !errors.Is(err, ErrDelegationStale) {
		t.Fatalf("peer resolved owner's release reference: %v", err)
	}
	if _, err := c.ReleaseBatch(a, []Delegation{g}); err != nil {
		t.Fatal(err)
	}
	assertDelegationCapacity(t, c, 0, 0)
}

func TestDelegationCapacityConcurrentReservations(t *testing.T) {
	c := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock(), MaxDelegationsPerSession: 3, MaxDelegations: 7})
	tokens := []SubscriptionToken{cv2Subscribe(t, c, 1), cv2Subscribe(t, c, 2), cv2Subscribe(t, c, 3)}
	var wg sync.WaitGroup
	admitted := make(chan *DelegationCapacity, 100)
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			capacity, err := c.ReserveDelegationCapacity(tokens[i%len(tokens)])
			if err == nil {
				admitted <- capacity
			} else if !errors.Is(err, ErrSessionDelegationLimit) && !errors.Is(err, ErrVolumeDelegationLimit) {
				t.Errorf("reserve: %v", err)
			}
		}()
	}
	wg.Wait()
	close(admitted)
	assertDelegationCapacity(t, c, 7, 0)
	for capacity := range admitted {
		capacity.Release()
	}
	assertDelegationCapacity(t, c, 0, 0)
}

func TestCoherenceStatsExpiryAndColdReset(t *testing.T) {
	c, clock := cv2Coordinator(t)
	a := cv2Subscribe(t, c, 1)
	_ = cv2Subscribe(t, c, 1)
	if stats := c.Stats(); stats.SubscriptionHorizons != 1 || stats.SubscriptionResets != 1 || stats.SubscriptionExpirations != 0 {
		t.Fatalf("cold stats: %+v", stats)
	}
	clock.Advance(SubscriptionTTL)
	if c.Stats().SubscriptionHorizons != 1 {
		t.Fatal("scrape mutated expired-but-retained horizon")
	}
	c.Sweep()
	c.Sweep()
	if stats := c.Stats(); stats.SubscriptionHorizons != 0 || stats.SubscriptionExpirations != 1 {
		t.Fatalf("expiry counted more than once: %+v", stats)
	}
	if _, err := c.Renew(a); err == nil {
		t.Fatal("old token renewed")
	}
	clock.Advance(time.Second)
}

func TestDelegationCapacityProductionSessionLimit(t *testing.T) {
	c := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock()})
	a := cv2Subscribe(t, c, 1)
	reservations := make([]*DelegationReservation, 0, 65_536)
	for i := range 65_536 {
		r, err := c.ReserveNew(a, coherenceBenchmarkIdentity(uint64(i+1)))
		if err != nil {
			t.Fatalf("reservation %d: %v", i, err)
		}
		reservations = append(reservations, r)
	}
	if _, err := c.ReserveNew(a, coherenceBenchmarkIdentity(65_537)); !errors.Is(err, ErrSessionDelegationLimit) {
		t.Fatalf("documented 65,536 session bound not enforced: %v", err)
	}
	assertDelegationCapacity(t, c, 0, 65_536)
	for _, r := range reservations {
		r.Abort()
	}
	assertDelegationCapacity(t, c, 0, 0)
}

func TestDelegationCapacityRecallAndBreakOutcomes(t *testing.T) {
	for _, kind := range []string{"recall", "break"} {
		for _, outcome := range []string{"ack", "release", "timeout"} {
			t.Run(kind+"-"+outcome, func(t *testing.T) {
				c := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock(), MaxDelegationsPerSession: 1, MaxDelegations: 2})
				clock := c.clock.(*cv2Clock)
				a := cv2Subscribe(t, c, 1)
				g := cv2Grant(t, c, a, [16]byte{1})
				b := cv2Subscribe(t, c, 2)
				done := make(chan error, 1)
				if kind == "recall" {
					go func() {
						r, err := c.Reserve(t.Context(), b, g.Identity)
						if err == nil {
							r.Abort()
						}
						done <- err
					}()
				} else {
					go func() { done <- c.BreakForRead(t.Context(), g.Identity) }()
				}
				eventKind := StreamBreakForRead
				if kind == "recall" {
					eventKind = StreamRecall
				}
				event := cv2Event(t, c, a, eventKind)
				switch outcome {
				case "ack":
					cv2CutAck(t, c, a, event, 0)
				case "release":
					if _, err := c.ReleaseBatch(a, []Delegation{g}); err != nil {
						t.Fatal(err)
					}
				case "timeout":
					clock.Advance(DelegationRecallBudget)
					c.Sweep()
				}
				if err := cv2Result(t, done); err != nil {
					t.Fatal(err)
				}
				stats := c.Stats()
				completed, lost := stats.BreakCompleted, stats.BreakLost
				if kind == "recall" {
					completed, lost = stats.RecallCompleted, stats.RecallLost
				}
				if outcome == "timeout" {
					if lost != 1 || completed != 0 {
						t.Fatalf("lost cut counters: %+v", stats)
					}
				} else if completed != 1 || lost != 0 {
					t.Fatalf("completed cut counters: %+v", stats)
				}
				if kind == "break" && outcome == "ack" {
					assertDelegationCapacity(t, c, 0, 1)
					if _, err := c.ReleaseBatch(a, []Delegation{g}); err != nil {
						t.Fatal(err)
					}
				}
				assertDelegationCapacity(t, c, 0, 0)
			})
		}
	}
}

func TestCanceledRecallRetainsCapacityUntilHolderCutFinishes(t *testing.T) {
	c := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock(), MaxDelegationsPerSession: 1, MaxDelegations: 2})
	a := cv2Subscribe(t, c, 1)
	grant := cv2Grant(t, c, a, [16]byte{1})
	b := cv2Subscribe(t, c, 2)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		r, err := c.Reserve(ctx, b, grant.Identity)
		if r != nil {
			r.Abort()
		}
		done <- err
	}()
	event := cv2Event(t, c, a, StreamRecall)
	cancel()
	// A canceled requester must let an already-issued holder recall drain.
	// Its capacity reservation cannot be reused by concurrent admissions yet.
	assertDelegationCapacity(t, c, 1, 1)
	if _, err := c.ReserveNew(b, [16]byte{2}); !errors.Is(err, ErrSessionDelegationLimit) {
		t.Fatalf("canceled but outstanding recall reused charge: %v", err)
	}
	cv2CutAck(t, c, a, event, 0)
	if err := cv2Result(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled recall result: %v", err)
	}
	assertDelegationCapacity(t, c, 0, 0)
}

func TestDelegationCapacityOwnOpenReusesGrantAfterPendingModeChange(t *testing.T) {
	c := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock(), MaxDelegationsPerSession: 1, MaxDelegations: 1})
	a := cv2Subscribe(t, c, 1)
	b := cv2Subscribe(t, c, 2)
	identity := [16]byte{1}
	if admitted, err := c.OpenCacheCapable(b, identity); err != nil || !admitted {
		t.Fatal(admitted, err)
	}
	grant := cv2Grant(t, c, a, identity, b)
	if err := c.CloseCacheCapable(b, identity); err != nil {
		t.Fatal(err)
	}
	event := cv2Event(t, c, a, StreamDelegationMode)
	openDone := make(chan error, 1)
	go func() {
		r, err := c.Reserve(t.Context(), a, grant.Identity)
		if err == nil {
			var g Delegation
			g, err = r.Grant(t.Context())
			if err == nil && g.ID != grant.ID {
				err = errors.New("pending mode change replaced same-holder grant")
			}
		}
		openDone <- err
	}()
	c.clock.(*cv2Clock).waitForTimers(t, 1)
	assertDelegationCapacity(t, c, 0, 1)
	cv2CutAck(t, c, a, event, 0)
	if err := cv2Result(t, openDone); err != nil {
		t.Fatal(err)
	}
	assertDelegationCapacity(t, c, 0, 1)
}
