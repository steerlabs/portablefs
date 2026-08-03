package writeback

// The flush-reply status contract.
//
// A status may end a stream only when it is a statement ABOUT THIS BATCH that
// re-sending the identical bytes cannot change. Everything else — including the
// authority's catch-all EIO and any status this client does not yet know — is
// retryable under the flusher's watchdog. See flush.go's reply switch.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// statusRemote answers every flush with a fixed status.
type statusRemote struct {
	*fakeAuthority
	status int32
	mu     sync.Mutex
	calls  int
}

func (r *statusRemote) Flush(ctx context.Context, req FlushRequest) (FlushReply, error) {
	r.mu.Lock()
	r.calls++
	status := r.status
	r.mu.Unlock()
	if status == 0 {
		// The authority released whatever it was refusing for and now applies
		// normally. Delegating to the fake keeps the watermark arithmetic real,
		// which is what a relief test has to exercise.
		return r.fakeAuthority.Flush(ctx, req)
	}
	return FlushReply{Status: status}, nil
}

// setStatus retunes the fixture mid-test: the authority's bounded store is
// relieved (0) or refuses again.
func (r *statusRemote) setStatus(status int32) {
	r.mu.Lock()
	r.status = status
	r.mu.Unlock()
}

func (r *statusRemote) flushCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func newStatusFixture(t *testing.T, status int32) (*Engine, *statusRemote) {
	t.Helper()
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	remote := &statusRemote{fakeAuthority: auth, status: status}
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main", Remote: remote,
		BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if _, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("payload")); err != nil || !handled {
		t.Fatalf("write: handled=%v err=%v", handled, err)
	}
	return e, remote
}

// TestProvenContradictionStaysTerminal keeps the terminal path terminal. These
// two statuses are decided by the authority FROM THE BATCH'S OWN CONTENT, so
// re-sending the identical bytes gets the identical answer forever; parking is
// the only honest outcome.
func TestProvenContradictionStaysTerminal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int32
	}{
		{"EINVAL: typed writeback corruption", 22},
		{"EPERM: records outside the granted subtree", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newStatusFixture(t, tc.status)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := e.DrainAll(ctx)
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("status %d drained with %v, want the terminal ErrConflict: "+
					"nothing on either side can ever relieve it", tc.status, err)
			}
		})
	}
}

// TestUnclassifiedStatusIsRetriedNotLatched is the inverted rule. An authority
// status this client cannot interpret says nothing about the batch, so reading
// it as a proven contradiction is the client inventing a verdict — and the cost
// of being wrong is a permanently destroyed mount.
func TestUnclassifiedStatusIsRetriedNotLatched(t *testing.T) {
	// 5 is the authority's catch-all (the live trigger); 250 stands for any
	// status a future authority adds that this client does not know.
	//
	// 28 (ENOSPC) used to sit in this list and no longer does. That was not a
	// tightening of the rule but a correction of a MISCLASSIFICATION: 28 is not
	// a status this client cannot interpret, it is the authority's named answer
	// for a full bounded store, and holding a named capacity refusal as a
	// transient is what wedged production at the dirty-block bound. It is now
	// covered by TestCapacityStatusIsDefiniteNotRetriedForever, which asserts
	// the opposite behaviour for exactly that reason.
	for _, status := range []int32{5, 250} {
		t.Run("status "+itoa(int(status)), func(t *testing.T) {
			e, remote := newStatusFixture(t, status)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err := e.DrainAll(ctx)
			if errors.Is(err, ErrConflict) || errors.Is(err, ErrFailedClosed) {
				t.Fatalf("an unclassified status %d latched the engine terminal (%v); "+
					"one bad reply then takes the whole live mount to EIO for good",
					status, err)
			}
			if err == nil {
				t.Fatalf("status %d drained successfully; the fixture never applies", status)
			}
			if n := remote.flushCalls(); n < 2 {
				t.Fatalf("status %d produced %d flush attempt(s); an unclassified "+
					"refusal must be retried under the watchdog", status, n)
			}
			// The engine is NOT poisoned: the far end recovering is all it takes.
			if merr := e.MutationError(); errors.Is(merr, ErrFailedClosed) {
				t.Fatalf("an unclassified status left the engine fail-closed: %v", merr)
			}
		})
	}
}
