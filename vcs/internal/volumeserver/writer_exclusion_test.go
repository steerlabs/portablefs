package volumeserver

import (
	"errors"
	"math"
	"sync/atomic"
	"testing"
	"time"
)

type exclusionTestClock struct {
	wall    atomic.Int64
	elapsed atomic.Int64
	failed  atomic.Bool
}

func (c *exclusionTestClock) now() time.Time { return time.Unix(1000, c.wall.Load()) }
func (c *exclusionTestClock) continuous() (time.Duration, error) {
	if c.failed.Load() {
		return 0, errors.New("clock failed")
	}
	return time.Duration(c.elapsed.Load()), nil
}

func writerSession(t *testing.T, lease, authorization time.Duration) (*Authority, SessionCredential, *WriterRegistry, *WriterExclusion, *exclusionTestClock) {
	t.Helper()
	clock := &exclusionTestClock{}
	clock.elapsed.Store(int64(time.Second))
	a, err := New("exclusion", Config{SessionLease: lease, MaxReplaySlots: 2, MaxSessions: 4, MaxLockRecords: 8, Now: clock.now, ContinuousNow: clock.continuous})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := a.AttachActiveForTest(2, PeerIdentity{1}, Authorization{Access: AccessRead | AccessWrite, Deadline: clock.now().Add(authorization)})
	if err != nil {
		t.Fatal(err)
	}
	exclusion, err := a.WriterExclusion(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewWriterRegistry(WriterRegistryConfig{Prior: PriorEpochStrictMountsFenced, Fencer: a, ContinuousNow: clock.continuous})
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := a.SessionTerminal(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Activate(cred.ID, terminal, exclusion, func() error { return nil }, func() {}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Fence(cred.ID) })
	return a, cred, c, exclusion, clock
}

func TestKeepAliveProofCapsAndQuantizesValidity(t *testing.T) {
	for _, test := range []struct {
		name              string
		lease, auth, want time.Duration
	}{
		{"cap", 10 * time.Minute, time.Hour, MaxCacheProof},
		{"lease", 12500*time.Millisecond + 999999*time.Nanosecond, time.Hour, 12500 * time.Millisecond},
		{"authorization", 2 * time.Minute, 2345*time.Millisecond + 999999*time.Nanosecond, 2345 * time.Millisecond},
		{"submillisecond", time.Minute, time.Microsecond, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, cred, _, _, _ := writerSession(t, test.lease, test.auth)
			use, err := a.Begin(cred)
			if err != nil {
				t.Fatal(err)
			}
			defer use.End()
			proof, err := use.RenewalProof()
			if proof != test.want || test.want > 0 && err != nil || test.want == 0 && !errors.Is(err, ErrSessionExpired) {
				t.Fatalf("proof=%v, %v; want %v", proof, err, test.want)
			}
		})
	}
}

func TestWriterFenceRetainsMaximumProofAndApplyDrain(t *testing.T) {
	a, cred, c, _, clock := writerSession(t, 10*time.Minute, time.Hour)
	apply, err := a.Begin(cred)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := apply.RenewalProof()
	if err != nil || proof != MaxCacheProof {
		t.Fatalf("proof=%v, %v", proof, err)
	}
	clock.elapsed.Store(int64(11 * time.Second))
	clock.wall.Store(int64(10 * time.Second))
	if err := a.Reauthorize(cred, Authorization{Access: AccessRead | AccessWrite, Deadline: clock.now().Add(2 * time.Second)}, 1, [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	if proof, err := apply.RenewalProof(); err != nil || proof != 2*time.Second {
		t.Fatalf("short proof=%v, %v", proof, err)
	}
	c.Fence(cred.ID)
	if proof, err := apply.RenewalProof(); proof != 0 || !errors.Is(err, ErrSessionFenced) {
		t.Fatalf("fenced proof=%v, %v", proof, err)
	}
	for _, now := range []time.Duration{13 * time.Second, 61*time.Second - time.Nanosecond, 61 * time.Second} {
		clock.elapsed.Store(int64(now))
		if err := c.CheckWriter(SessionID{2}); !errors.Is(err, ErrWriterExcluded) {
			t.Fatalf("writer before drain at %v: %v", now, err)
		}
		if err := c.Activate(SessionID{2}, make(chan struct{}), &WriterExclusion{now: clock.continuous}, func() error { return nil }, func() {}); !errors.Is(err, ErrWriterExcluded) {
			t.Fatalf("second Mac at %v: %v", now, err)
		}
	}
	apply.End()
	if err := c.CheckWriter(SessionID{2}); err != nil {
		t.Fatalf("writer after deadline and drain: %v", err)
	}
	if _, err := a.Begin(cred); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("fenced session revived: %v", err)
	}
}

func TestWriterOrdinaryRenewalGrantsNoCacheProof(t *testing.T) {
	a, cred, c, _, clock := writerSession(t, 10*time.Minute, time.Hour)
	use, err := a.Begin(cred)
	if err != nil {
		t.Fatal(err)
	}
	use.End()
	c.Fence(cred.ID)
	clock.elapsed.Store(int64(2 * time.Second))
	if err := c.CheckWriter(SessionID{2}); err != nil {
		t.Fatalf("ordinary lease retained as cache proof: %v", err)
	}
}

func TestWriterCleanAbsenceDischargesProofAfterDrain(t *testing.T) {
	a, cred, c, _, _ := writerSession(t, time.Minute, time.Hour)
	use, err := a.Begin(cred)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := use.RenewalProof(); err != nil {
		t.Fatal(err)
	}
	if err := c.Remove(cred.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.Detach(cred); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckWriter(SessionID{2}); !errors.Is(err, ErrWriterExcluded) {
		t.Fatalf("old apply escaped absence: %v", err)
	}
	use.End()
	if err := c.CheckWriter(SessionID{2}); err != nil {
		t.Fatal(err)
	}
}

func TestWriterClockFailureCannotReleaseOrGrant(t *testing.T) {
	for _, fault := range []string{"failure", "regression", "overflow"} {
		t.Run(fault, func(t *testing.T) {
			a, cred, c, _, clock := writerSession(t, time.Minute, time.Hour)
			use, err := a.Begin(cred)
			if err != nil {
				t.Fatal(err)
			}
			defer use.End()
			if _, err := use.RenewalProof(); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "failure":
				clock.failed.Store(true)
			case "regression":
				clock.elapsed.Store(0)
			case "overflow":
				clock.elapsed.Store(math.MaxInt64)
			}
			if _, err := use.RenewalProof(); err == nil {
				t.Fatal("bad clock granted proof")
			}
			c.Fence(cred.ID)
			use.End()
			clock.failed.Store(false)
			clock.elapsed.Store(int64(time.Hour))
			if err := c.CheckWriter(SessionID{2}); !errors.Is(err, ErrWriterExcluded) {
				t.Fatalf("bad clock released exclusion: %v", err)
			}
		})
	}
}

func TestWriterLastMomentProofRetainsGrantTimeDespiteLateDelivery(t *testing.T) {
	a, cred, c, e, clock := writerSession(t, 10*time.Minute, time.Hour)
	first, err := a.Begin(cred)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.RenewalProof(); err != nil {
		t.Fatal(err)
	}
	first.End()
	clock.elapsed.Store(int64(60 * time.Second))
	clock.wall.Store(int64(59 * time.Second))
	last, err := a.Begin(cred)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := last.RenewalProof()
	if err != nil || proof != MaxCacheProof {
		t.Fatalf("last proof=%v,%v", proof, err)
	}
	last.End()
	// Delivery is deliberately still withheld when the session is fenced.
	c.Fence(cred.ID)
	clock.elapsed.Store(int64(119 * time.Second))
	if err := c.CheckWriter(SessionID{2}); !errors.Is(err, ErrWriterExcluded) {
		t.Fatalf("late proof lost retention: %v", err)
	}
	e.mu.Lock()
	deadline := e.deadline
	e.mu.Unlock()
	if deadline != 120*time.Second {
		t.Fatalf("grant deadline=%v, want 120s", deadline)
	}
	clock.elapsed.Store(int64(deadline))
	if err := c.CheckWriter(SessionID{2}); err != nil {
		t.Fatal(err)
	}
}

func TestWriterUnprovenTimeExclusionEndsOnlyAfterApplyDrain(t *testing.T) {
	a, cred, c, _, clock := writerSession(t, time.Minute, time.Hour)
	apply, err := a.Begin(cred)
	if err != nil {
		t.Fatal(err)
	}
	c.Fence(cred.ID)
	clock.elapsed.Store(int64(24 * time.Hour))
	if err := c.CheckWriter(SessionID{2}); !errors.Is(err, ErrWriterExcluded) {
		t.Fatalf("unproven-time writer apply escaped fence: %v", err)
	}
	apply.End()
	if err := c.CheckWriter(SessionID{2}); err != nil {
		t.Fatalf("unproven-time writer retained an ungranted time promise: %v", err)
	}
}
