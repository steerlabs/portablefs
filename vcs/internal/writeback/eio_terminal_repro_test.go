package writeback

// Minimal repro for the live-battery wedge observed on 81e235b against
// production (portablefs-cloud-3, 2.5 GiB delegated flood): the authority
// answered one OpFlushBatch with status 5 (EIO) and the mount went
// permanently EIO with 47 records / 48 MB never drained.
//
// EIO is the authority's CATCH-ALL mapping for any error it did not classify
// (vcs/internal/fsproto/fsproto.go:523 toErrno -> default EIO at :556, reached
// from vcs/internal/fsproto/coordinate.go:770 when ManagedFlushApply returns
// an error that is not stale/corrupt/expiry-pending/unknown). The flusher's
// reply switch (vcs/internal/writeback/flush.go:383-401) special-cases only
// 116 (ESTALE) and 11 (EAGAIN); every other status -- including that
// catch-all EIO -- parks the stream as a terminal ErrConflict, which latches
// ErrFailedClosed (vcs/internal/writeback/engine.go:67-70,598) and takes the
// whole live mount to EIO for good.
//
// Contract asserted here: a single unclassified authority error must not be
// terminal. The stream must retry and drain. This test FAILS on 81e235b.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// eioOnceRemote answers the first flush with the authority's catch-all EIO
// status and every later flush normally.
type eioOnceRemote struct {
	*fakeAuthority
	mu    sync.Mutex
	calls int
}

func (r *eioOnceRemote) Flush(ctx context.Context, req FlushRequest) (FlushReply, error) {
	r.mu.Lock()
	r.calls++
	call := r.calls
	r.mu.Unlock()
	if call == 1 {
		// Exactly what production returned: a well-formed reply carrying
		// status 5, no transport error.
		return FlushReply{Status: 5}, nil
	}
	return r.fakeAuthority.Flush(ctx, req)
}

func (r *eioOnceRemote) flushCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func TestSingleUnclassifiedAuthorityErrorIsNotTerminal(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	remote := &eioOnceRemote{fakeAuthority: auth}

	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main", Remote: remote,
		BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if _, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("payload")); err != nil || !handled {
		t.Fatalf("write: handled=%v err=%v", handled, err)
	}

	// The one rejected flush must be retried, not latched terminal.
	drainErr := e.DrainAll(ctx)

	if errors.Is(drainErr, ErrFailedClosed) || errors.Is(drainErr, ErrConflict) {
		t.Fatalf("REPRO: one authority status-5 (EIO) reply made the engine terminal: %v\n"+
			"flush attempts=%d (a retry would show >1)\n"+
			"EIO is the authority's catch-all for unclassified errors; treating it as a "+
			"typed recovery conflict permanently kills a live mount with undrained data",
			drainErr, remote.flushCalls())
	}
	if drainErr != nil {
		t.Fatalf("drain: %v", drainErr)
	}
	if n := remote.flushCalls(); n < 2 {
		t.Fatalf("expected the rejected flush to be retried, saw %d flush call(s)", n)
	}
	if st := e.Status(); st.PendingRecords != 0 || st.PendingBytes != 0 {
		t.Fatalf("stream did not drain: pendingRecords=%d pendingBytes=%d",
			st.PendingRecords, st.PendingBytes)
	}
}
