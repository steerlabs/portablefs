package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authority"
	"github.com/steerlabs/portablefs/vcs/internal/backend"
)

// fenceBackend is an authority.Backend whose lease renewals fail with a chosen
// error, so renewLoop's fencing behaviour can be exercised without real infra.
type fenceBackend struct{ renewErr error }

func (f fenceBackend) Attach(context.Context, string, string, string, int64) (*backend.AttachResult, error) {
	return &backend.AttachResult{SessionID: "s", LeaseID: "l", FencingToken: 1}, nil
}
func (f fenceBackend) AttachReceipted(context.Context, string, string, string, int64, string) (*backend.AttachResult, error) {
	return &backend.AttachResult{SessionID: "s", LeaseID: "l", FencingToken: 1}, nil
}
func (f fenceBackend) Commit(context.Context, string, backend.CommitInput) (string, error) {
	return "", nil
}
func (f fenceBackend) Detach(context.Context, string) error                   { return nil }
func (f fenceBackend) RenewLease(context.Context, string, int64, int64) error { return f.renewErr }
func (f fenceBackend) PutBlob(context.Context, string, []byte) error          { return nil }

func acquireWith(t *testing.T, renewErr error) *authority.Authority {
	t.Helper()
	auth, err := authority.Acquire(context.Background(), fenceBackend{renewErr: renewErr}, "vol", "main", "h", 1000)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	return auth
}

// TestRenewLoopFencesOnLeaseLost: a definitive lease-lost error fences the data
// plane immediately (a deposed primary must stop serving at once).
func TestRenewLoopFencesOnLeaseLost(t *testing.T) {
	auth := acquireWith(t, &backend.HTTPError{Status: 409, Body: "VOLUME_LEASE_STALE"})
	fenced := make(chan struct{})
	go renewLoop(context.Background(), auth, 5*time.Millisecond, 10*time.Second, func() { close(fenced) })
	select {
	case <-fenced:
	case <-time.After(2 * time.Second):
		t.Fatal("renewLoop did not fence on a lease-lost error")
	}
}

// TestRenewLoopFencesOnTTLTimeout: a non-lease-lost failure (e.g. a partition)
// still fences once the lease would have expired — the safety net that prevents a
// partitioned primary from serving past its lease while a standby promotes.
func TestRenewLoopFencesOnTTLTimeout(t *testing.T) {
	auth := acquireWith(t, errors.New("connection refused")) // not classified as lease-lost
	fenced := make(chan struct{})
	start := time.Now()
	// every=5ms, ttl=40ms -> self-fence deadline = 35ms.
	go renewLoop(context.Background(), auth, 5*time.Millisecond, 40*time.Millisecond, func() { close(fenced) })
	select {
	case <-fenced:
		if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
			t.Fatalf("fenced too early (%s); should wait ~one TTL before self-fencing", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("renewLoop did not self-fence after the TTL elapsed without a renewal")
	}
}

// hangBackend models a wedged backend whose lease renewal blocks far longer than
// the lease TTL (the real client's 60s HTTP timeout exceeds the 30s TTL). It honours
// the per-call context, so renewLoop's bounded renew timeout still unblocks it.
type hangBackend struct{ fenceBackend }

func (hangBackend) RenewLease(ctx context.Context, _ string, _, _ int64) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return nil
	}
}

// TestRenewLoopFencesWhenRenewHangs is the regression for the fencing window: even
// when every renew call hangs (longer than the lease), the watchdog must self-fence
// within ~the deadline rather than block inside Renew until the backend timeout —
// the deposed primary must stop serving before its lease expires and a standby promotes.
func TestRenewLoopFencesWhenRenewHangs(t *testing.T) {
	auth, err := authority.Acquire(context.Background(), hangBackend{}, "vol", "main", "h", 1000)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	fenced := make(chan struct{})
	start := time.Now()
	// every=10ms, ttl=60ms -> deadline=50ms, per-renew timeout=25ms. The hung renew
	// must NOT delay the fence anywhere near its 10s block.
	go renewLoop(context.Background(), auth, 10*time.Millisecond, 60*time.Millisecond, func() { close(fenced) })
	select {
	case <-fenced:
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("fenced after %s — the loop blocked on the hung renew instead of self-fencing", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("renewLoop never fenced while every renew hung — the lease window is unguarded")
	}
}

// TestRenewLoopStopsOnContextCancel: a clean shutdown stops the loop without fencing.
func TestRenewLoopStopsOnContextCancel(t *testing.T) {
	auth := acquireWith(t, nil) // renewals succeed
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		renewLoop(ctx, auth, 5*time.Millisecond, 1*time.Second, func() { t.Error("should not fence on clean shutdown") })
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("renewLoop did not return on context cancel")
	}
}
