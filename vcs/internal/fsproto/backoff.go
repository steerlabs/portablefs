package fsproto

import (
	"math/rand/v2"
	"sync"
	"time"
)

// Reconnect backoff parameters shared by every client-side reconnect path
// (per-op redial, invalidation resubscribe, credential re-resolve). One set of
// numbers so a fleet of mounts recovering from the same event decays at the
// same rate; the small base keeps single-blip recovery snappy while the cap
// turns a sustained outage into a trickle of attempts instead of a storm.
const (
	DefaultReconnectBase = 250 * time.Millisecond
	DefaultReconnectCap  = 15 * time.Second
)

// Backoff is a thread-safe full-jitter exponential backoff: each Next() draws
// a delay uniformly from [0, min(cap, base<<attempt)) and advances the attempt
// counter. Full jitter (rather than a jittered floor) is deliberate — when
// 1,000 mounts lose the same manager at the same instant, their retries must
// de-correlate immediately, and the first retry staying within the base keeps
// recovery from a single blip fast.
//
// A Backoff may be shared by concurrent retriers (the point, for a connection
// pool): failures anywhere deepen the shared attempt count, and any success
// calls Reset so the next failure starts from the base again.
type Backoff struct {
	base  time.Duration
	limit time.Duration

	mu      sync.Mutex
	attempt int
	// rand overrides the jitter draw in tests (deterministic bounds checks);
	// nil uses math/rand/v2. It receives the exclusive upper bound in
	// nanoseconds and must return a value in [0, n).
	rand func(n int64) int64
}

// NewBackoff returns a Backoff with the given base delay and cap. Non-positive
// arguments fall back to the shared reconnect defaults.
func NewBackoff(base, limit time.Duration) *Backoff {
	if base <= 0 {
		base = DefaultReconnectBase
	}
	if limit <= 0 {
		limit = DefaultReconnectCap
	}
	if limit < base {
		limit = base
	}
	return &Backoff{base: base, limit: limit}
}

// Next returns the delay to wait before the upcoming retry and advances the
// attempt counter. The delay is full-jitter: uniform in [0, bound) where
// bound = min(cap, base*2^attempt).
func (b *Backoff) Next() time.Duration {
	b.mu.Lock()
	bound := b.bound(b.attempt)
	b.attempt++
	draw := b.rand
	b.mu.Unlock()
	if draw == nil {
		draw = rand.Int64N
	}
	return time.Duration(draw(int64(bound)))
}

// bound computes min(cap, base<<attempt) without overflowing the shift.
func (b *Backoff) bound(attempt int) time.Duration {
	bound := b.base
	for i := 0; i < attempt; i++ {
		if bound >= b.limit {
			return b.limit
		}
		bound *= 2
	}
	if bound > b.limit {
		return b.limit
	}
	return bound
}

// Reset zeroes the attempt counter. Call it on success so the next failure
// starts from the base delay again.
func (b *Backoff) Reset() {
	b.mu.Lock()
	b.attempt = 0
	b.mu.Unlock()
}
