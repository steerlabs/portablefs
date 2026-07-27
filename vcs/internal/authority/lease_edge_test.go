package authority

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
)

// recordingBackend captures the arguments the Authority forwards, so we can assert
// the held session/lease/fencing token + locally-tracked head flow into each call.
// All methods are guarded so it is safe to share across goroutines (-race).
type recordingBackend struct {
	mu sync.Mutex

	attachResult *backend.AttachResult
	attachErr    error

	// per-method capture
	attachVol, attachBranch, attachHolder string
	attachTTL                             int64

	commitSessions []string
	commitInputs   []backend.CommitInput
	commitReturn   func(in backend.CommitInput) (string, error)

	renewLease []string
	renewToken []int64
	renewTTL   []int64
	renewErr   error

	detachSession []string
	detachErr     error

	putDigests []string
	putErr     error
}

func (b *recordingBackend) Attach(_ context.Context, vol, branch, holder string, ttl int64) (*backend.AttachResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attachVol, b.attachBranch, b.attachHolder, b.attachTTL = vol, branch, holder, ttl
	if b.attachErr != nil {
		return nil, b.attachErr
	}
	return b.attachResult, nil
}
func (b *recordingBackend) AttachReceipted(ctx context.Context, vol, branch, holder string, ttl int64, _ string) (*backend.AttachResult, error) {
	return b.Attach(ctx, vol, branch, holder, ttl)
}

func (b *recordingBackend) Commit(_ context.Context, sessionID string, in backend.CommitInput) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.commitSessions = append(b.commitSessions, sessionID)
	b.commitInputs = append(b.commitInputs, in)
	if b.commitReturn != nil {
		return b.commitReturn(in)
	}
	return fmt.Sprintf("commit_%d", len(b.commitInputs)), nil
}

func (b *recordingBackend) Detach(_ context.Context, sessionID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.detachSession = append(b.detachSession, sessionID)
	return b.detachErr
}

func (b *recordingBackend) RenewLease(_ context.Context, leaseID string, token, ttl int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.renewLease = append(b.renewLease, leaseID)
	b.renewToken = append(b.renewToken, token)
	b.renewTTL = append(b.renewTTL, ttl)
	return b.renewErr
}

func (b *recordingBackend) PutBlob(_ context.Context, digest string, _ []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.putDigests = append(b.putDigests, digest)
	return b.putErr
}

func okAttach() *backend.AttachResult {
	return &backend.AttachResult{
		SessionID: "sess_1", LeaseID: "lease_1", FencingToken: 7,
		HeadCommitID: "head_0", ManifestVersion: "v3",
	}
}

// TestAcquireMapsAttachResult: the Authority surfaces Head/Version from Attach and
// passes the requested branch/holder/ttl through.
func TestAcquireMapsAttachResult(t *testing.T) {
	b := &recordingBackend{attachResult: okAttach()}
	a, err := Acquire(context.Background(), b, "vol_1", "feature", "holder_1", 5000)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if a.Head() != "head_0" {
		t.Errorf("Head = %q, want head_0", a.Head())
	}
	if a.Version() != "v3" {
		t.Errorf("Version = %q, want v3", a.Version())
	}
	if b.attachVol != "vol_1" || b.attachBranch != "feature" || b.attachHolder != "holder_1" || b.attachTTL != 5000 {
		t.Errorf("attach args wrong: vol=%q branch=%q holder=%q ttl=%d", b.attachVol, b.attachBranch, b.attachHolder, b.attachTTL)
	}
}

// TestAcquireDefaultsTTL: a non-positive ttl falls back to DefaultLeaseTTLMs both
// for the Attach call and for later Renew (which reuses the stored ttl).
func TestAcquireDefaultsTTL(t *testing.T) {
	for _, ttl := range []int64{0, -1, -1000} {
		b := &recordingBackend{attachResult: okAttach()}
		a, err := Acquire(context.Background(), b, "vol", "main", "h", ttl)
		if err != nil {
			t.Fatalf("Acquire(ttl=%d): %v", ttl, err)
		}
		if b.attachTTL != DefaultLeaseTTLMs {
			t.Errorf("ttl=%d -> attach ttl %d, want default %d", ttl, b.attachTTL, DefaultLeaseTTLMs)
		}
		if err := a.Renew(context.Background()); err != nil {
			t.Fatalf("Renew: %v", err)
		}
		if b.renewTTL[0] != DefaultLeaseTTLMs {
			t.Errorf("renew ttl = %d, want default %d", b.renewTTL[0], DefaultLeaseTTLMs)
		}
	}
}

// TestAcquirePropagatesError: an Attach failure is returned, no Authority built.
func TestAcquirePropagatesError(t *testing.T) {
	b := &recordingBackend{attachErr: errors.New("boom")}
	if _, err := Acquire(context.Background(), b, "vol", "main", "h", 0); err == nil {
		t.Fatal("want error from failed Attach")
	}
}

// TestCommitCarriesHeldLeaseAndAdvancesHead is the core authority invariant: every
// commit is stamped with the held session, lease id, fencing token, current
// version, and the locally-tracked head as ExpectedHeadCommitID; on success the
// head advances to the returned commit so the NEXT commit chains onto it.
func TestCommitCarriesHeldLeaseAndAdvancesHead(t *testing.T) {
	b := &recordingBackend{attachResult: okAttach()}
	a, err := Acquire(context.Background(), b, "vol", "main", "h", 0)
	if err != nil {
		t.Fatal(err)
	}

	entries := []backend.ManifestEntry{{Path: "a", Kind: "file", Mode: 0o644, Size: 1}}
	head1, err := a.Commit(context.Background(), "sha256:tree1", entries, 1, 1)
	if err != nil {
		t.Fatalf("first commit: %v", err)
	}

	in0 := b.commitInputs[0]
	if b.commitSessions[0] != "sess_1" {
		t.Errorf("commit session = %q, want sess_1", b.commitSessions[0])
	}
	if in0.LeaseID != "lease_1" || in0.FencingToken != 7 {
		t.Errorf("commit lease/token wrong: %+v", in0)
	}
	if in0.ExpectedHeadCommitID != "head_0" {
		t.Errorf("first commit expectedHead = %q, want head_0", in0.ExpectedHeadCommitID)
	}
	if in0.Manifest.Version != "v3" || in0.Manifest.TreeHash != "sha256:tree1" {
		t.Errorf("commit manifest header wrong: %+v", in0.Manifest)
	}
	if in0.MutationCount != 1 || in0.ByteCount != 1 {
		t.Errorf("commit counts wrong: %+v", in0)
	}
	if a.Head() != head1 {
		t.Errorf("head after commit = %q, want %q", a.Head(), head1)
	}

	// Second commit must chain onto the new head, not the original.
	head2, err := a.Commit(context.Background(), "sha256:tree2", entries, 1, 2)
	if err != nil {
		t.Fatalf("second commit: %v", err)
	}
	if b.commitInputs[1].ExpectedHeadCommitID != head1 {
		t.Errorf("second commit expectedHead = %q, want %q", b.commitInputs[1].ExpectedHeadCommitID, head1)
	}
	if a.Head() != head2 || head2 == head1 {
		t.Errorf("head did not advance: head2=%q head1=%q", head2, head1)
	}
}

// TestCommitFailureDoesNotAdvanceHead: a rejected commit (e.g. lease lost) leaves
// the tracked head unchanged so a retry/abort sees the true last-committed head.
func TestCommitFailureDoesNotAdvanceHead(t *testing.T) {
	b := &recordingBackend{attachResult: okAttach()}
	b.commitReturn = func(backend.CommitInput) (string, error) {
		return "", &backend.HTTPError{Status: http.StatusConflict, Body: "VOLUME_LEASE_STALE"}
	}
	a, err := Acquire(context.Background(), b, "vol", "main", "h", 0)
	if err != nil {
		t.Fatal(err)
	}
	before := a.Head()
	if _, err := a.Commit(context.Background(), "t", nil, 0, 0); err == nil {
		t.Fatal("want commit error")
	} else if !backend.IsLeaseLost(err) {
		t.Fatalf("err = %v, want lease-lost classification", err)
	}
	if a.Head() != before {
		t.Fatalf("head changed after failed commit: %q != %q", a.Head(), before)
	}
}

// TestRenewAndReleaseForwardHeldState: Renew passes the lease id + fencing token +
// stored ttl; Release detaches the held session.
func TestRenewAndReleaseForwardHeldState(t *testing.T) {
	b := &recordingBackend{attachResult: okAttach()}
	a, err := Acquire(context.Background(), b, "vol", "main", "h", 9000)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Renew(context.Background()); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if b.renewLease[0] != "lease_1" || b.renewToken[0] != 7 || b.renewTTL[0] != 9000 {
		t.Errorf("renew args wrong: lease=%v token=%v ttl=%v", b.renewLease, b.renewToken, b.renewTTL)
	}
	if err := a.Release(context.Background()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if len(b.detachSession) != 1 || b.detachSession[0] != "sess_1" {
		t.Errorf("detach sessions = %v, want [sess_1]", b.detachSession)
	}
}

// TestRenewAndReleasePropagateErrors: a backend rejection on renew/release/putblob
// surfaces to the caller (a primary that can't renew must learn it).
func TestRenewAndReleasePropagateErrors(t *testing.T) {
	b := &recordingBackend{
		attachResult: okAttach(),
		renewErr:     &backend.HTTPError{Status: http.StatusConflict, Body: "VOLUME_LEASE_STALE"},
		detachErr:    errors.New("detach boom"),
		putErr:       errors.New("put boom"),
	}
	a, _ := Acquire(context.Background(), b, "vol", "main", "h", 0)
	if err := a.Renew(context.Background()); !backend.IsLeaseLost(err) {
		t.Fatalf("Renew err = %v, want lease-lost", err)
	}
	if err := a.Release(context.Background()); err == nil {
		t.Fatal("want Release error")
	}
	if err := a.PutBlob(context.Background(), "sha256:x", []byte("y")); err == nil {
		t.Fatal("want PutBlob error")
	}
}

// TestPutBlobForwards: PutBlob delegates straight through to the backend.
func TestPutBlobForwards(t *testing.T) {
	b := &recordingBackend{attachResult: okAttach()}
	a, _ := Acquire(context.Background(), b, "vol", "main", "h", 0)
	if err := a.PutBlob(context.Background(), "sha256:abc", []byte("data")); err != nil {
		t.Fatalf("PutBlob: %v", err)
	}
	if len(b.putDigests) != 1 || b.putDigests[0] != "sha256:abc" {
		t.Errorf("put digests = %v", b.putDigests)
	}
}

// ---------------------------------------------------------------------------
// AcquireWhenFree (failover poll) boundaries.
// ---------------------------------------------------------------------------

// TestAcquireWhenFreeImmediate: a lease that is free on the very first attempt
// returns at once (exactly one attach), no spurious polling.
func TestAcquireWhenFreeImmediate(t *testing.T) {
	f := &fakeBackend{attach: func() (*backend.AttachResult, error) { return okAttach(), nil }}
	a, err := AcquireWhenFree(context.Background(), f, "vol", "main", "standby", 0, time.Millisecond)
	if err != nil {
		t.Fatalf("AcquireWhenFree: %v", err)
	}
	if a.Head() != "head_0" {
		t.Errorf("head = %q, want head_0", a.Head())
	}
	if got := atomic.LoadInt32(&f.calls); got != 1 {
		t.Fatalf("attach called %d times, want 1 (free immediately)", got)
	}
}

// TestAcquireWhenFreeCancelBeforeFirstAttempt: a context already cancelled still
// makes (at most) the first attach attempt, then a busy result honors the cancel
// rather than spinning. We assert it returns the context error promptly.
func TestAcquireWhenFreeCancelBeforeFirstAttempt(t *testing.T) {
	f := &fakeBackend{attach: func() (*backend.AttachResult, error) {
		return nil, &backend.HTTPError{Status: http.StatusLocked, Body: "VOLUME_WRITE_LEASE_BUSY"}
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled up front

	done := make(chan error, 1)
	go func() {
		_, err := AcquireWhenFree(ctx, f, "vol", "main", "standby", 0, time.Hour)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AcquireWhenFree did not honor a pre-cancelled context")
	}
}

// TestAcquireWhenFreePollsExactCount: busy for N attempts then frees on N+1; the
// poll must make exactly N+1 attach calls (boundary on the retry loop).
func TestAcquireWhenFreePollsExactCount(t *testing.T) {
	const freeOn = 5
	f := &fakeBackend{}
	f.attach = func() (*backend.AttachResult, error) {
		if atomic.LoadInt32(&f.calls) < freeOn {
			return nil, &backend.HTTPError{Status: http.StatusLocked, Body: "VOLUME_WRITE_LEASE_BUSY"}
		}
		return okAttach(), nil
	}
	if _, err := AcquireWhenFree(context.Background(), f, "vol", "main", "standby", 0, time.Microsecond); err != nil {
		t.Fatalf("AcquireWhenFree: %v", err)
	}
	if got := atomic.LoadInt32(&f.calls); got != freeOn {
		t.Fatalf("attach called %d times, want exactly %d", got, freeOn)
	}
}

// ---------------------------------------------------------------------------
// Concurrency: many goroutines hammering Head/Version/Renew while a serialized
// Commit loop advances the head. Commit holds the mutex, so the head sequence is
// race-free and the next ExpectedHeadCommitID always equals the previous result.
// ---------------------------------------------------------------------------

func TestAuthorityConcurrentCommitAndReaders(t *testing.T) {
	b := &recordingBackend{attachResult: okAttach()}
	// Deterministic chain: commit N returns head "h<N>" and must have seen "h<N-1>".
	var commitSeq atomic.Int64
	b.commitReturn = func(in backend.CommitInput) (string, error) {
		n := commitSeq.Add(1)
		return fmt.Sprintf("h%d", n), nil
	}
	a, err := Acquire(context.Background(), b, "vol", "main", "h", 0)
	if err != nil {
		t.Fatal(err)
	}

	const commits = 200
	var wg sync.WaitGroup

	// One committer goroutine (commits are inherently serialized by a single
	// authority's own write loop in production; the mutex makes head transitions
	// atomic). Plus many concurrent readers + renewers to surface races.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < commits; i++ {
			if _, err := a.Commit(context.Background(), "t", nil, 1, 1); err != nil {
				t.Errorf("commit %d: %v", i, err)
				return
			}
		}
	}()
	for r := 0; r < 16; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < commits; i++ {
				_ = a.Head()
				_ = a.Version()
				_ = a.Renew(context.Background())
			}
		}()
	}
	wg.Wait()

	if a.Head() != fmt.Sprintf("h%d", commits) {
		t.Fatalf("final head = %q, want h%d", a.Head(), commits)
	}
	// Verify the chain integrity: each commit's ExpectedHeadCommitID equals the
	// prior commit's returned head (head_0 for the first), proving no lost update.
	b.mu.Lock()
	defer b.mu.Unlock()
	prev := "head_0"
	for i, in := range b.commitInputs {
		if in.ExpectedHeadCommitID != prev {
			t.Fatalf("commit %d expectedHead = %q, want %q (broken chain)", i, in.ExpectedHeadCommitID, prev)
		}
		prev = fmt.Sprintf("h%d", i+1)
	}
}
