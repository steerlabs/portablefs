package clientcore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/coherence"
)

// flakySub refuses Subscribe a configured number of times before handing out
// a live stream — a router refusing connections while a manager recovers.
type flakySub struct {
	mu       sync.Mutex
	failures int
	ch       chan []coherence.Invalidation
}

func (f *flakySub) Subscribe() (<-chan []coherence.Invalidation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failures > 0 {
		f.failures--
		return nil, errors.New("router refusing connections")
	}
	return f.ch, nil
}

func (f *flakySub) setFailures(n int) {
	f.mu.Lock()
	f.failures = n
	f.mu.Unlock()
}

// TestWatchInvalidationsResubscribeBackoff replaces the old fixed 500ms
// resubscribe timer with the shared full-jitter schedule and pins it: delays
// stay inside the exponential bounds (base 250ms doubling to the 15s cap),
// genuinely grow (a fleet must decay, not resubscribe in lockstep), and a
// successful subscribe resets the schedule so the next blip recovers fast.
func TestWatchInvalidationsResubscribeBackoff(t *testing.T) {
	const (
		base    = 250 * time.Millisecond
		ceiling = 15 * time.Second
	)
	bound := func(attempt int) time.Duration {
		d := base
		for i := 0; i < attempt && d < ceiling; i++ {
			d *= 2
		}
		if d > ceiling {
			return ceiling
		}
		return d
	}

	sub := &flakySub{failures: 10, ch: make(chan []coherence.Invalidation)}
	delays := make(chan time.Duration, 64)
	opts := InvalidationOptions{
		// The seam records the schedule and skips the real sleep, so the test
		// observes attempt spacing without wall-clock waits.
		sleep: func(ctx context.Context, d time.Duration) { delays <- d },
	}
	h := &fakeHandler{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go WatchInvalidations(ctx, sub, NewVersionCache(), NewAttrCache(), h, opts)

	recorded := make([]time.Duration, 0, 10)
	for i := 0; i < 10; i++ {
		select {
		case d := <-delays:
			recorded = append(recorded, d)
		case <-time.After(5 * time.Second):
			t.Fatalf("resubscribe attempt %d never waited", i)
		}
	}
	for i, d := range recorded {
		if d < 0 || d >= bound(i) {
			t.Fatalf("attempt %d waited %v, outside the full-jitter bound [0, %v)", i, d, bound(i))
		}
	}
	// Growth must actually happen: with bounds of 8s..15s for attempts 5..9,
	// five draws all under the base is a ~1e-8 event, never a real schedule.
	grew := false
	for _, d := range recorded[5:] {
		if d > base {
			grew = true
		}
	}
	if !grew {
		t.Fatalf("delays never grew beyond the base: %v", recorded)
	}

	// The 11th attempt succeeds (failures exhausted). Wait until the success
	// is observable (FlushAll fires right after a subscribe lands) so the
	// upcoming failures are unambiguously POST-success, then sever the
	// stream: the schedule must restart from the base — reset-on-success is
	// what keeps single-blip recovery snappy.
	waitFor := time.Now().Add(5 * time.Second)
	for {
		h.mu.Lock()
		flushed := h.flushes > 0
		h.mu.Unlock()
		if flushed {
			break
		}
		if time.Now().After(waitFor) {
			t.Fatal("subscribe never succeeded after failures were exhausted")
		}
		time.Sleep(time.Millisecond)
	}
	sub.setFailures(4)
	close(sub.ch)
	post := make([]time.Duration, 0, 4)
	for i := 0; i < 4; i++ {
		select {
		case d := <-delays:
			post = append(post, d)
		case <-time.After(5 * time.Second):
			t.Fatalf("post-success resubscribe attempt %d never waited", i)
		}
	}
	cancel() // stop the watcher before it spins on the now-closed stream
	for i, d := range post {
		if d >= bound(i) {
			t.Fatalf("post-success attempt %d waited %v, want the schedule reset to [0, %v)", i, d, bound(i))
		}
	}
}
