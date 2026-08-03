package writeback

// The CAPACITY half of the flush-reply status contract (round 18g).
//
// flush_status_classification_test.go establishes the general rule: a status
// this client cannot interpret says nothing about the batch, so it is retried
// under the watchdog rather than latched terminal. This file establishes the
// enumerated exception that rule always allowed for — a status that DOES name a
// condition precisely.

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestCapacityStatusIsDefiniteNotRetriedForever is the round-18g contract on
// the client side of fsproto's capacity classification.
//
// ENOSPC (28) and EDQUOT (122) are the authority's ENUMERATED capacity
// vocabulary — the exact statuses fsproto's ONE quota classifier issues, from
// the exact path and (since 18g) the write-back flush path alike. Unlike the
// catch-all EIO or a status this client has never seen, they name a condition:
// the batch was not applied because a bounded resource is full.
//
// Retrying that forever is the failure this test exists to prevent. The
// authority's resident dirty-block pool does not fold for a live generation, so
// a flush refused at the bound is refused identically on every re-offer; the
// watermark freezes, the no-progress watchdog latches degraded, and the mount
// answers EIO for a condition POSIX has had a name for since 1988. The
// application must be handed that name.
func TestCapacityStatusIsDefiniteNotRetriedForever(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int32
	}{
		{"ENOSPC: a bounded store on the authority is full", 28},
		{"EDQUOT: the durable journal backlog quota is exhausted", 122},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, remote := newStatusFixture(t, tc.status)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := e.DrainAll(ctx)
			if err == nil {
				t.Fatalf("status %d drained successfully; the fixture never applies", tc.status)
			}
			if errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("status %d was still being retried when the drain deadline "+
					"expired: the client is holding a definite capacity verdict as a transient", tc.status)
			}
			if !errors.Is(err, ErrNoSpace) {
				t.Fatalf("status %d drained with %v; a capacity refusal must reach the "+
					"application as ErrNoSpace (ENOSPC), never as an unexplained stall", tc.status, err)
			}
			// Definite means the flusher STOPS. A handful of attempts before
			// the verdict latches is fine; an unbounded stream of them is the
			// bug. The bound is generous on purpose: this asserts termination,
			// not a retry count.
			if n := remote.flushCalls(); n > 8 {
				t.Fatalf("status %d produced %d flush attempts; a definite capacity "+
					"refusal must not be re-offered indefinitely", tc.status, n)
			}
			// Every subsequent WRITE carries the same definite answer, so the
			// frontend's errno mapping (clientcore statusErr, which tests
			// ErrNoSpace before its EIO default) answers ENOSPC.
			//
			// Round 21b moved this assertion off MutationError deliberately.
			// MutationError is the mount-lifetime FAIL-CLOSED latch, and it is
			// consulted by clientcore's beginExactOperation — the gate in front
			// of the exact-handle read, getattr and getxattr paths, and in front
			// of Truncate. Latching it here delivered "the application sees
			// ENOSPC" as "ls, stat, read and the documented truncate remedy are
			// all EIO until remount". The verdict now lives on CapacityRefusal,
			// which is asked by writes and by nothing else. See
			// capacity_degradation_test.go for the full contract.
			if merr := e.MutationError(); merr != nil {
				t.Fatalf("status %d fail-closed the engine (MutationError = %v); a "+
					"capacity refusal must not fence the mount", tc.status, merr)
			}
			if cerr := e.CapacityRefusal(); !errors.Is(cerr, ErrNoSpace) {
				t.Fatalf("status %d left CapacityRefusal = %v, want ErrNoSpace so writes "+
					"fail as ENOSPC instead of EIO", tc.status, cerr)
			}
		})
	}
}
