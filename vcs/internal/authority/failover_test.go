package authority

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/backend"
)

// fakeBackend drives Attach outcomes for the failover poll; the other methods
// are unused here.
type fakeBackend struct {
	calls  int32
	attach func() (*backend.AttachResult, error)
}

func (f *fakeBackend) Attach(context.Context, string, string, string, int64) (*backend.AttachResult, error) {
	atomic.AddInt32(&f.calls, 1)
	return f.attach()
}
func (f *fakeBackend) AttachReceipted(context.Context, string, string, string, int64, string) (*backend.AttachResult, error) {
	atomic.AddInt32(&f.calls, 1)
	return f.attach()
}
func (f *fakeBackend) Commit(context.Context, string, backend.CommitInput) (string, error) {
	return "", nil
}
func (f *fakeBackend) Detach(context.Context, string) error                   { return nil }
func (f *fakeBackend) RenewLease(context.Context, string, int64, int64) error { return nil }
func (f *fakeBackend) PutBlob(context.Context, string, []byte) error          { return nil }

func busyErr() error {
	return &backend.HTTPError{Method: http.MethodPost, Path: "/attach", Status: http.StatusLocked, Body: "VOLUME_WRITE_LEASE_BUSY"}
}

// TestAcquireWhenFreePromotesAfterPrimaryReleases: the poll waits while the lease
// is busy (primary alive) and acquires the instant it frees (primary gone).
func TestAcquireWhenFreePromotesAfterPrimaryReleases(t *testing.T) {
	f := &fakeBackend{}
	f.attach = func() (*backend.AttachResult, error) {
		if atomic.LoadInt32(&f.calls) < 3 {
			return nil, busyErr()
		}
		return &backend.AttachResult{SessionID: "s", LeaseID: "l", FencingToken: 7, HeadCommitID: "c1"}, nil
	}
	auth, err := AcquireWhenFree(context.Background(), f, "vol", "main", "standby", DefaultLeaseTTLMs, time.Millisecond)
	if err != nil {
		t.Fatalf("AcquireWhenFree: %v", err)
	}
	if auth.Head() != "c1" {
		t.Fatalf("promoted authority head = %q, want c1", auth.Head())
	}
	if got := atomic.LoadInt32(&f.calls); got < 3 {
		t.Fatalf("attach called %d times, want >= 3 (polled while busy)", got)
	}
}

// TestAcquireWhenFreeFailsHard: a non-busy error aborts immediately rather than
// polling forever.
func TestAcquireWhenFreeFailsHard(t *testing.T) {
	f := &fakeBackend{attach: func() (*backend.AttachResult, error) {
		return nil, errors.New("boom: bad gateway")
	}}
	_, err := AcquireWhenFree(context.Background(), f, "vol", "main", "standby", DefaultLeaseTTLMs, time.Millisecond)
	if err == nil {
		t.Fatal("AcquireWhenFree returned nil on a hard error")
	}
	if backend.IsLeaseBusy(err) {
		t.Fatalf("classified a hard error as lease-busy: %v", err)
	}
	if got := atomic.LoadInt32(&f.calls); got != 1 {
		t.Fatalf("attach called %d times on a hard error, want 1", got)
	}
}

// TestAcquireWhenFreeStopsOnContext: a cancelled context ends the poll while busy.
func TestAcquireWhenFreeStopsOnContext(t *testing.T) {
	f := &fakeBackend{attach: func() (*backend.AttachResult, error) { return nil, busyErr() }}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := AcquireWhenFree(ctx, f, "vol", "main", "standby", DefaultLeaseTTLMs, time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context deadline exceeded", err)
	}
}
