package volumeserver

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRenewalOverlappingWithdrawalsAndPartialAcknowledgment(t *testing.T) {
	c, clock := cv2Coordinator(t)
	source := cv2Subscribe(t, c, 1)
	peer := cv2Subscribe(t, c, 2)
	unrelated := cv2Subscribe(t, c, 3)
	id := [16]byte{8}
	if err := c.AdmitCache(peer, CacheAdmission{Attributes: [][16]byte{id}}); err != nil {
		t.Fatal(err)
	}
	start := clock.Now()
	first := c.OnCommitTargeted([]ChangeEntry{{Kind: AttributesChanged, Identity: id}}, source, CacheAdmission{})
	clock.Advance(3 * time.Second)
	second := c.OnCommitTargeted([]ChangeEntry{{Kind: AttributesChanged, Identity: id}}, source, CacheAdmission{})
	assertHorizon := func(token SubscriptionToken, want time.Time) {
		t.Helper()
		if got, err := c.Renew(token); err != nil || !got.Equal(want) {
			t.Fatalf("Renew(%v) = %v, %v; want %v", token, got, err, want)
		}
	}
	assertHorizon(peer, start.Add(SubscriptionTTL))
	assertHorizon(source, clock.Now().Add(SubscriptionTTL))
	assertHorizon(unrelated, clock.Now().Add(SubscriptionTTL))
	if _, err := c.Poll(t.Context(), peer, 0, nil, 8); err != nil {
		t.Fatal(err)
	}
	if err := c.Ack(peer, first.Position); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Second)
	assertHorizon(peer, start.Add(3*time.Second+SubscriptionTTL))
	if err := c.WaitTargeted(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := c.WaitTargeted(ctx, second); !errors.Is(err, context.Canceled) {
		t.Fatalf("second withdrawal completed without its acknowledgment: %v", err)
	}
	// Canceling one writer's wait cannot withdraw another client's permission.
	assertHorizon(peer, start.Add(3*time.Second+SubscriptionTTL))
	if err := c.Ack(peer, second.Position); err != nil {
		t.Fatal(err)
	}
	assertHorizon(peer, clock.Now().Add(SubscriptionTTL))
	if err := c.WaitTargeted(t.Context(), second); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalNeverRetractsAnAlreadyIssuedHorizon(t *testing.T) {
	c, clock := cv2Coordinator(t)
	source := cv2Subscribe(t, c, 1)
	peer := cv2Subscribe(t, c, 2)
	id := [16]byte{9}
	start := clock.Now()
	// At first this subscriber has no matching facts. A subsequent admission
	// makes the retained older entry conservative, after a longer promise exists.
	older := c.OnCommitTargeted([]ChangeEntry{{Kind: AttributesChanged, Identity: id}}, source, CacheAdmission{})
	if len(older.targets) != 0 {
		t.Fatal("empty footprint was targeted")
	}
	clock.Advance(9 * time.Second)
	promised, err := c.Renew(peer)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AdmitCache(peer, CacheAdmission{Attributes: [][16]byte{id}}); err != nil {
		t.Fatal(err)
	}
	withdrawal := c.OnCommitTargeted([]ChangeEntry{{Kind: AttributesChanged, Identity: id}}, source, CacheAdmission{})
	if got, err := c.Renew(peer); err != nil || !got.Equal(promised) {
		t.Fatalf("prior promise shortened: %v, %v; want %v", got, err, promised)
	}
	clock.AdvanceTo(start.Add(SubscriptionTTL))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := c.WaitTargeted(ctx, withdrawal); !errors.Is(err, context.Canceled) {
		t.Fatalf("withdrawal completed before outstanding promise %v: %v", promised, err)
	}
	clock.AdvanceTo(promised.Add(-time.Nanosecond))
	if err := c.WaitTargeted(ctx, withdrawal); !errors.Is(err, context.Canceled) {
		t.Fatalf("withdrawal completed just before promise: %v", err)
	}
	clock.Advance(time.Nanosecond)
	if err := c.WaitTargeted(t.Context(), withdrawal); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalBoundAppliesToBroadcastAndDelegationWithdrawals(t *testing.T) {
	for _, kind := range []string{"broadcast", "grant", "release"} {
		t.Run(kind, func(t *testing.T) {
			c, clock := cv2Coordinator(t)
			source := cv2Subscribe(t, c, 1)
			var grant Delegation
			if kind == "release" {
				grant = cv2Grant(t, c, source, [16]byte{1})
			}
			peer := cv2Subscribe(t, c, 2)
			initial := clock.Now().Add(SubscriptionTTL)
			var position uint64
			var reservation *DelegationReservation
			switch kind {
			case "broadcast":
				position = c.OnCommitFrom([]ChangeEntry{{Kind: DataChanged, Identity: [16]byte{1}}}, source.Session)
			case "grant":
				var err error
				reservation, err = c.ReserveNew(source, [16]byte{1})
				if err != nil {
					t.Fatal(err)
				}
				defer reservation.Abort()
				position = reservation.record.position
			case "release":
				var err error
				position, err = c.ReleaseBatch(source, []Delegation{grant})
				if err != nil {
					t.Fatal(err)
				}
			}
			for range 3 {
				clock.Advance(3 * time.Second)
				if got, err := c.Renew(peer); err != nil || !got.Equal(initial) {
					t.Fatalf("pending %s renewal = %v, %v; want %v", kind, got, err, initial)
				}
				if _, err := c.Renew(source); err != nil {
					t.Fatal(err)
				}
			}
			clock.Advance(time.Second)
			if err := c.WaitWithdrawn(t.Context(), position, source.Session); err != nil {
				t.Fatal(err)
			}
			if reservation != nil {
				if _, err := reservation.Grant(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestRenewalColdResetAndLogOverrun(t *testing.T) {
	c := NewCoherenceCoordinator(CoherenceConfig{Clock: newCV2Clock(), MaxLogEntries: 1})
	source := cv2Subscribe(t, c, 1)
	peer := cv2Subscribe(t, c, 2)
	if err := c.AdmitCache(peer, CacheAdmission{Data: [][16]byte{{1}}}); err != nil {
		t.Fatal(err)
	}
	w := c.OnCommitTargeted([]ChangeEntry{{Kind: DataChanged, Identity: [16]byte{1}}}, source, CacheAdmission{})
	c.OnCommitFrom([]ChangeEntry{{Kind: DataChanged, Identity: [16]byte{2}}}, source.Session)
	if _, err := c.Renew(peer); !errors.Is(err, ErrSessionFenced) {
		t.Fatalf("overrun reader renewed lost obligations: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := c.WaitTargeted(ctx, w); !errors.Is(err, context.Canceled) {
		t.Fatalf("fencing alone removed cache promise: %v", err)
	}
	cold, err := c.Subscribe(peer.Session)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WaitTargeted(t.Context(), w); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Renew(peer); !errors.Is(err, ErrSubscription) {
		t.Fatalf("old incarnation renewed: %v", err)
	}
	if horizon, err := c.Renew(cold.Token); err != nil || !horizon.Equal(cold.Horizon) {
		t.Fatalf("cold incarnation inherited old obligations: %v %v", horizon, err)
	}
}

// This model tracks only client-visible promises, completed acknowledgments,
// and attested cold resets. It deliberately does not inspect server horizons
// or its private deadline fields when deciding whether a writer may complete.
func TestWithdrawalModelNeverOutlivesPermissionEvidence(t *testing.T) {
	type readerPromise struct {
		token   SubscriptionToken
		horizon time.Time
		acked   uint64
		cold    bool
		cached  byte
	}
	type writePromise struct {
		withdrawal Withdrawal
		readers    []*readerPromise
	}
	c, clock := cv2Coordinator(t)
	readers := make([]*readerPromise, 5)
	reset := func(i int) {
		t.Helper()
		if readers[i] != nil {
			readers[i].cold = true
		}
		snapshot, err := c.SubscribeWithCache(SessionID{byte(i + 1)}, CacheAdmission{Attributes: [][16]byte{{byte(i%3 + 1)}}})
		if err != nil {
			t.Fatal(err)
		}
		readers[i] = &readerPromise{token: snapshot.Token, horizon: snapshot.Horizon, acked: snapshot.Position, cached: byte(i%3 + 1)}
	}
	for i := range readers {
		reset(i)
	}
	var writes []writePromise
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for step := range 120 {
		clock.Advance(250 * time.Millisecond)
		for i, reader := range readers {
			// One live reader deliberately renews without polling. Others
			// acknowledge at different rates, including overlapping withdrawals.
			if i != 0 && step%(i+4) == 0 && reader.acked < c.position {
				events, err := c.Poll(t.Context(), reader.token, reader.acked, nil, 256)
				if err == nil {
					position := events[len(events)-1].Position
					if err := c.Ack(reader.token, position); err != nil {
						t.Fatal(err)
					}
					reader.acked = position
				}
			}
			if step%(i+3) == 0 {
				horizon, err := c.Renew(reader.token)
				if err != nil {
					reset(i)
					continue
				}
				if horizon.Before(reader.horizon) {
					t.Fatalf("step %d reader %d retracted promise %v to %v", step, i, reader.horizon, horizon)
				}
				reader.horizon = horizon
			}
		}
		identity := byte(step%3 + 1)
		write := writePromise{withdrawal: c.OnCommitTargeted([]ChangeEntry{{Kind: AttributesChanged, Identity: [16]byte{identity}}}, SubscriptionToken{}, CacheAdmission{})}
		for _, reader := range readers {
			if reader.cached == identity && clock.Now().Before(reader.horizon) {
				write.readers = append(write.readers, reader)
			}
		}
		writes = append(writes, write)
		for _, write := range writes {
			err := c.WaitTargeted(ctx, write.withdrawal)
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			permitted := true
			for _, reader := range write.readers {
				if !reader.cold && reader.acked < write.withdrawal.Position && clock.Now().Before(reader.horizon) {
					permitted = false
				}
			}
			if (err == nil) != permitted {
				t.Fatalf("step %d writer position %d completed=%v; client-visible evidence permits=%v", step, write.withdrawal.Position, err == nil, permitted)
			}
		}
	}
}

func TestRenewalSourceExclusionUsesExactIncarnation(t *testing.T) {
	c, clock := cv2Coordinator(t)
	old := cv2Subscribe(t, c, 1)
	current, err := c.SubscribeWithCache(old.Session, CacheAdmission{Attributes: [][16]byte{{1}}})
	if err != nil {
		t.Fatal(err)
	}
	c.OnCommitTargeted([]ChangeEntry{{Kind: AttributesChanged, Identity: [16]byte{1}}}, old, CacheAdmission{})
	clock.Advance(3 * time.Second)
	if horizon, err := c.Renew(current.Token); err != nil || !horizon.Equal(current.Horizon) {
		t.Fatalf("cold successor inherited old source exclusion: %v %v; want %v", horizon, err, current.Horizon)
	}
}
