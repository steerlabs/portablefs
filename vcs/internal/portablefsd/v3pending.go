package portablefsd

import (
	"context"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/bench/lantrace"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

const v3PendingRequestLimit = 1024

// Frontend cancellation governs reservation admission even though an assigned
// authority request must later settle independently on its original session.
type v3PendingAdmissionContextKey struct{}

// One reservation covers a request's disposition record and at most two new
// authority tokens. It precedes source holds, operation lanes and replay
// admission. Live accepted resources use the existing item/handle accounting;
// releases still have exactly one owner with one forming and one in-flight batch.
type v3PendingBudget struct {
	mu      sync.Mutex
	limit   int
	changed chan struct{}
	closed  bool
	active  map[*v3PendingReservation]struct{}
	stats   v3PendingMetrics
}

type v3PendingMetrics struct {
	Limit           int    `json:"limit"`
	Pending         int    `json:"pending"`
	Peak            int    `json:"peak"`
	Waiters         int    `json:"waiters"`
	Reserved        uint64 `json:"reserved"`
	Retired         uint64 `json:"retired"`
	Teardown        uint64 `json:"teardown"`
	AdmissionWaitNS uint64 `json:"admission_wait_ns"`
	CleanupWaitNS   uint64 `json:"cleanup_wait_ns"`
}

type v3PendingReservation struct {
	budget *v3PendingBudget
	trace  v3RequestTrace
}

func newV3PendingBudget(limit int) *v3PendingBudget {
	return &v3PendingBudget{limit: max(1, limit), changed: make(chan struct{}), active: make(map[*v3PendingReservation]struct{})}
}

func (b *v3PendingBudget) signalLocked() {
	close(b.changed)
	b.changed = make(chan struct{})
}

func (b *v3PendingBudget) reserve(ctx context.Context) (*v3PendingReservation, error) {
	started := time.Now()
	trace, _ := ctx.Value(v3RequestTraceContextKey{}).(v3RequestTrace)
	b.mu.Lock()
	waited := false
	defer func() {
		if waited {
			b.stats.Waiters--
			b.stats.AdmissionWaitNS += uint64(time.Since(started))
		}
		count := len(b.active)
		b.mu.Unlock()
		trace.wait(lantrace.WaitReservation, time.Since(started))
		trace.pending(count, b.limit)
	}()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if b.closed {
			return nil, errV3ReleaseClosed
		}
		if len(b.active) < b.limit {
			r := &v3PendingReservation{budget: b, trace: trace}
			b.active[r] = struct{}{}
			b.stats.Reserved++
			b.stats.Peak = max(b.stats.Peak, len(b.active))
			return r, nil
		}
		firstWait := !waited
		if firstWait {
			waited = true
			b.stats.Waiters++
		}
		changed := b.changed
		b.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
		}
		b.mu.Lock()
	}
}

// retire is reached by the sole current owner: handler, disposition, or
// cleanup. Teardown can have taken ownership first, in which case no second
// retirement is counted and no new resource admission is possible.
func (r *v3PendingReservation) retire() {
	if r == nil {
		return
	}
	b := r.budget
	b.mu.Lock()
	if _, live := b.active[r]; !live {
		closed := b.closed
		b.mu.Unlock()
		if !closed {
			panic("portablefsd: pending reservation retired twice")
		}
		return
	}
	delete(b.active, r)
	b.stats.Retired++
	b.signalLocked()
	count := len(b.active)
	b.mu.Unlock()
	r.trace.pending(count, b.limit)
}

// takeForTeardown explicitly owns all pending tokens and records, including
// handlers still settling on the original session. It never waits on DATA.
func (b *v3PendingBudget) takeForTeardown() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	b.stats.Teardown += uint64(len(b.active))
	b.stats.Retired += uint64(len(b.active))
	traces := make([]v3RequestTrace, 0, len(b.active))
	for r := range b.active {
		traces = append(traces, r.trace)
		delete(b.active, r)
	}
	b.signalLocked()
	b.mu.Unlock()
	for _, trace := range traces {
		trace.pending(0, b.limit)
	}
}

func (b *v3PendingBudget) metrics() v3PendingMetrics {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := b.stats
	result.Limit, result.Pending = b.limit, len(b.active)
	return result
}

func v3RequestProducesResources(body any) bool {
	switch body.(type) {
	case *pfslocal.LookupRequest, *pfslocal.OpenRequest, *pfslocal.CreateRequest,
		*pfslocal.MkdirRequest, *pfslocal.SymlinkRequest, *pfslocal.HardLinkRequest:
		return true
	default:
		// Enumeration requires an existing handle and requests no item tokens.
		return false
	}
}

func (c *v3ReplyResourceCollector) retirePending() {
	if c != nil && c.reservation != nil {
		c.reservation.retire()
		c.reservation = nil
	}
}

// Duplicate capabilities never enter a disposition table. Their request keeps
// its reservation while the same release owner accepts the redundant token.
func (d *v3DataPlane) submitPendingRelease(ctx context.Context, closes, reclaims [][]byte) error {
	started := time.Now()
	err := d.releases.submit(closes, reclaims)
	elapsed := time.Since(started)
	d.pending.mu.Lock()
	d.pending.stats.CleanupWaitNS += uint64(elapsed)
	d.pending.mu.Unlock()
	t, _ := ctx.Value(v3RequestTraceContextKey{}).(v3RequestTrace)
	t.wait(lantrace.WaitReservation, elapsed)
	return err
}
