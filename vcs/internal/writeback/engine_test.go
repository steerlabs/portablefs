package writeback

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

func testEngine(t *testing.T, auth *fakeAuthority) *Engine {
	t.Helper()
	dir := t.TempDir()
	e, err := Open(context.Background(), Config{
		StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth,
		BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() {
		_, _ = e.ForceClose("test teardown")
	})
	return e
}

type firstFlushFailsRemote struct {
	*fakeAuthority
	mu           sync.Mutex
	requests     []FlushRequest
	firstEntered chan struct{}
	releaseFirst chan struct{}
	secondSeen   chan struct{}
}

func (r *firstFlushFailsRemote) Flush(ctx context.Context, req FlushRequest) (FlushReply, error) {
	r.mu.Lock()
	r.requests = append(r.requests, req)
	call := len(r.requests)
	r.mu.Unlock()
	if call == 1 {
		close(r.firstEntered)
		select {
		case <-r.releaseFirst:
			return FlushReply{}, errors.New("injected ambiguous flush failure")
		case <-ctx.Done():
			return FlushReply{}, ctx.Err()
		}
	}
	if call == 2 {
		close(r.secondSeen)
	}
	return r.fakeAuthority.Flush(ctx, req)
}

func (r *firstFlushFailsRemote) firstTwo() (FlushRequest, FlushRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests[0], r.requests[1]
}

func TestFlushRetryPinsExactBatchWhileNewWritesArrive(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	remote := &firstFlushFailsRemote{
		fakeAuthority: auth,
		firstEntered:  make(chan struct{}),
		releaseFirst:  make(chan struct{}),
		secondSeen:    make(chan struct{}),
	}
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
	select {
	case <-remote.firstEntered:
	case <-ctx.Done():
		t.Fatal("first flush did not start")
	}
	if _, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("new tail")); err != nil || !handled {
		t.Fatalf("write during ambiguous flush: handled=%v err=%v", handled, err)
	}
	close(remote.releaseFirst)
	select {
	case <-remote.secondSeen:
	case <-ctx.Done():
		t.Fatal("flush retry did not start")
	}

	first, second := remote.firstTwo()
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("ambiguous retry changed batch:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if err := e.Fsync(ctx, "d/f"); err != nil {
		t.Fatalf("drain after exact retry: %v", err)
	}
}

func mustHandled(t *testing.T, what string, handled bool, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if !handled {
		t.Fatalf("%s: not handled locally", what)
	}
}

func TestAdmissionRevalidatesAfterGrantInstallation(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()

	aliasUnsafe := false
	e, err := Open(context.Background(), Config{
		StateDir:    t.TempDir(),
		VolumeID:    "vol",
		Branch:      "main",
		Remote:      auth,
		BudgetBytes: 1 << 30,
		Events: Events{
			// Clientcore observes the grant snapshot before the acquire
			// resolver completes. Model that transition at OnGrant: the same
			// syscall must revalidate, release, and choose authority I/O.
			OnGrant: func(string) {
				aliasUnsafe = true
			},
			AllowDelegatedMutation: func(context.Context, string) bool {
				return !aliasUnsafe
			},
		},
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })

	if _, handled, err := e.Create(context.Background(), "d/file", 0o644, false, false); err != nil || handled {
		t.Fatalf("post-grant admission: handled=%v err=%v, want authority lane", handled, err)
	}
	if e.Covers("d/file") {
		t.Fatal("rejected grant remained installed")
	}
	acquires, _, releases := auth.calls()
	if acquires != 1 || releases != 1 {
		t.Fatalf("grant lifecycle: acquires=%d releases=%d, want 1/1", acquires, releases)
	}
}

func TestDelegationAcquireGateCoversRemoteGrantThroughLocalInstallation(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()

	gateEntered := make(chan struct{})
	allowAcquire := make(chan struct{})
	gateEnded := make(chan struct{})
	var grantEscapedGate atomic.Bool
	e, err := Open(context.Background(), Config{
		StateDir:    t.TempDir(),
		VolumeID:    "vol",
		Branch:      "main",
		Remote:      auth,
		BudgetBytes: 1 << 30,
		DelegationAcquireGate: func(
			context.Context,
			string,
		) (DelegationAcquireGuard, error) {
			close(gateEntered)
			<-allowAcquire
			return DelegationAcquireGuard{
				End: func() { close(gateEnded) },
			}, nil
		},
		Events: Events{
			OnGrant: func(string) {
				select {
				case <-gateEnded:
					grantEscapedGate.Store(true)
				default:
				}
			},
		},
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })

	type createResult struct {
		handled bool
		err     error
	}
	result := make(chan createResult, 1)
	go func() {
		_, handled, createErr := e.Create(
			context.Background(), "d/file", 0o644, false, false,
		)
		result <- createResult{handled: handled, err: createErr}
	}()
	select {
	case <-gateEntered:
	case <-time.After(time.Second):
		t.Fatal("delegation resolver did not enter acquire gate")
	}
	acquires, _, _ := auth.calls()
	if acquires != 0 {
		t.Fatalf("remote acquire crossed closed gate: %d", acquires)
	}
	close(allowAcquire)
	select {
	case got := <-result:
		if got.err != nil || !got.handled {
			t.Fatalf("create after gate: handled=%v err=%v", got.handled, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("create did not finish after acquire gate opened")
	}
	select {
	case <-gateEnded:
	case <-time.After(time.Second):
		t.Fatal("acquire gate did not end")
	}
	if grantEscapedGate.Load() {
		t.Fatal("grant became visible after acquire gate ended")
	}
	if !e.Covers("d/file") {
		t.Fatal("grant was not installed before acquire gate ended")
	}
}

func TestDelegationAcquireGuardRejectsAndReleasesBeforeInstallation(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	var granted atomic.Bool
	e, err := Open(context.Background(), Config{
		StateDir:    t.TempDir(),
		VolumeID:    "vol",
		Branch:      "main",
		Remote:      auth,
		BudgetBytes: 1 << 30,
		DelegationAcquireGate: func(
			context.Context,
			string,
		) (DelegationAcquireGuard, error) {
			return DelegationAcquireGuard{
				ReconcileReply: func(AcquireReply) bool { return false },
			}, nil
		},
		Events: Events{
			OnGrant: func(string) { granted.Store(true) },
		},
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })

	if _, handled, err := e.Create(
		context.Background(),
		"d/file",
		0o644,
		false,
		false,
	); err != nil || handled {
		t.Fatalf("rejected grant result: handled=%v err=%v", handled, err)
	}
	if granted.Load() {
		t.Fatal("rejected grant fired OnGrant")
	}
	if e.Covers("d/file") {
		t.Fatal("rejected grant became locally visible")
	}
	acquires, _, releases := auth.calls()
	if acquires != 1 || releases != 1 {
		t.Fatalf("grant lifecycle: acquires=%d releases=%d, want 1/1", acquires, releases)
	}
}

type grantedReplyErrorRemote struct {
	*fakeAuthority
}

func (r grantedReplyErrorRemote) DelegationAcquire(
	ctx context.Context,
	scope string,
	writebackID string,
) (AcquireReply, error) {
	reply, err := r.fakeAuthority.DelegationAcquire(ctx, scope, writebackID)
	if err != nil || !reply.Granted {
		return reply, err
	}
	return reply, errors.New("replay snapshot seed failed")
}

func TestDelegationAcquireErrorAfterGrantDefinitelyReleasesEpoch(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	remote := grantedReplyErrorRemote{fakeAuthority: auth}
	e, err := Open(context.Background(), Config{
		StateDir:    t.TempDir(),
		VolumeID:    "vol",
		Branch:      "main",
		Remote:      remote,
		BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })

	if _, handled, err := e.Create(
		context.Background(),
		"d/file",
		0o644,
		false,
		false,
	); err == nil || handled {
		t.Fatalf("post-grant error: handled=%v err=%v", handled, err)
	}
	if e.Covers("d/file") {
		t.Fatal("errored grant became locally visible")
	}
	acquires, _, releases := auth.calls()
	if acquires != 1 || releases != 1 {
		t.Fatalf("grant lifecycle: acquires=%d releases=%d, want 1/1", acquires, releases)
	}
	if got := auth.grantCount(); got != 0 {
		t.Fatalf("authority retained %d unknown grants", got)
	}
}

func TestDelegatedValidationAndAdmissionAreOneCriticalSection(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()

	armed := make(chan struct{})
	validatorEntered := make(chan struct{})
	resumeValidator := make(chan struct{})
	e, err := Open(context.Background(), Config{
		StateDir:    t.TempDir(),
		VolumeID:    "vol",
		Branch:      "main",
		Remote:      auth,
		BudgetBytes: 1 << 30,
		Events: Events{
			ValidateDelegatedMutation: func(
				_ context.Context,
				path string,
				entry Entry,
				present bool,
			) error {
				select {
				case <-armed:
				default:
					return nil
				}
				if path != "d/file" || !present || entry.Kind != "file" {
					return fmt.Errorf("unexpected delegated snapshot: path=%q present=%v entry=%+v", path, present, entry)
				}
				close(validatorEntered)
				<-resumeValidator
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, handled, err := e.Create(ctx, "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("seed delegated file: handled=%v err=%v", handled, err)
	}
	if err := e.Fsync(ctx, "d/file"); err != nil {
		t.Fatalf("flush seed before admission test: %v", err)
	}
	close(armed)

	type mutationResult struct {
		handled bool
		err     error
	}
	mutationDone := make(chan mutationResult, 1)
	go func() {
		_, handled, err := e.WriteAt(ctx, "d/file", 0, []byte("atomic"))
		mutationDone <- mutationResult{handled: handled, err: err}
	}()
	select {
	case <-validatorEntered:
	case <-ctx.Done():
		t.Fatal("validator did not enter")
	}
	if e.mu.TryLock() {
		e.mu.Unlock()
		t.Fatal("delegated validator ran outside the admission critical section")
	}

	releaseDone := make(chan error, 1)
	go func() { releaseDone <- e.ReleaseFor(ctx, "d/file") }()
	select {
	case err := <-releaseDone:
		t.Fatalf("grant release passed validation/admission lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(resumeValidator)

	select {
	case result := <-mutationDone:
		if result.err != nil || !result.handled {
			t.Fatalf("validated mutation: handled=%v err=%v", result.handled, result.err)
		}
	case <-ctx.Done():
		t.Fatal("validated mutation did not finish")
	}
	select {
	case err := <-releaseDone:
		if err != nil {
			t.Fatalf("release after validated mutation: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("release did not finish after validator resumed")
	}
	if err := auth.equalFile("d/file", []byte("atomic")); err != nil {
		t.Fatal(err)
	}
}

// TestDelegatedCreateStormZeroRemoteCalls is the zero-RPC acceptance shape:
// after one grant on the parent, creates+writes+lookups of new names touch
// the authority zero times until the flush.
func TestDelegatedCreateStormZeroRemoteCalls(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["w"] = true
	auth.dirs["w/pkg"] = true
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()

	if _, handled, err := e.Create(ctx, "w/pkg/first.js", 0o644, false, false); err != nil || !handled {
		t.Fatalf("first create: handled=%v err=%v", handled, err)
	}
	acquires0, _, _ := auth.calls()
	if acquires0 != 1 {
		t.Fatalf("first create acquired %d delegations, want 1", acquires0)
	}
	if scope, res := e.Lookup("w/pkg"); res != LookupHit || scope.Kind != "directory" {
		t.Fatalf("delegated scope getattr = %+v/%v, want authoritative directory hit", scope, res)
	}
	// Hold the flusher back during the storm so batch formation is
	// deterministic: the drain below must ship the backlog in full batches.
	auth.mu.Lock()
	auth.flushErr = errors.New("hold")
	auth.mu.Unlock()
	for i := 0; i < 200; i++ {
		p := fmt.Sprintf("w/pkg/mod%04d.js", i)
		if _, res := e.Lookup(p); res != LookupNegative {
			t.Fatalf("pre-create lookup %s: %v, want negative", p, res)
		}
		_, handled, err := e.Create(ctx, p, 0o644, false, false)
		mustHandled(t, "create "+p, handled, err)
		_, handled, err = e.WriteAt(ctx, p, 0, []byte("payload"))
		mustHandled(t, "write "+p, handled, err)
		if ent, res := e.Lookup(p); res != LookupHit || ent.Size != 7 {
			t.Fatalf("post-write lookup %s: %v size=%d", p, res, ent.Size)
		}
	}
	acquires, flushes0, releases := auth.calls()
	if acquires != acquires0 || releases != 0 {
		t.Fatalf("storm acquired %d released %d beyond the initial grant", acquires-acquires0, releases)
	}
	auth.mu.Lock()
	auth.flushErr = nil
	auth.mu.Unlock()
	if err := e.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if err := auth.equalFile("w/pkg/mod0199.js", []byte("payload")); err != nil {
		t.Fatal(err)
	}
	// 401 records (201 creates + 200 writes) at 128 records per batch = 4
	// RPCs; allow slack for a straggling admission window.
	_, flushes, _ := auth.calls()
	if got := flushes - flushes0; got < 1 || got > 8 {
		t.Fatalf("drain shipped the storm in %d RPCs, want ~4 full batches", got)
	}
}

func TestInterleavedDelegationsFlushAsOneGlobalBatch(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["a"] = true
	auth.dirs["b"] = true
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()

	// Prevent the age timer from dispatching a prefix while the test admits
	// the interleaved stream. DrainAll clears this steady-state backoff and
	// asks for an immediate global batch.
	e.fl.mu.Lock()
	e.fl.nextAttempt = time.Now().Add(time.Hour)
	e.fl.mu.Unlock()
	for i := 0; i < 8; i++ {
		scope := "a"
		if i%2 == 1 {
			scope = "b"
		}
		path := fmt.Sprintf("%s/f%d", scope, i)
		_, handled, err := e.Create(ctx, path, 0o644, false, false)
		mustHandled(t, "mixed create "+path, handled, err)
		_, handled, err = e.WriteAt(ctx, path, 0, []byte(path))
		mustHandled(t, "mixed write "+path, handled, err)
	}
	if err := e.DrainAll(ctx); err != nil {
		t.Fatalf("mixed drain: %v", err)
	}
	auth.mu.Lock()
	flushes := auth.flushes
	auth.mu.Unlock()
	if flushes != 1 {
		t.Fatalf("16 interleaved records shipped in %d authority RPCs, want one global batch", flushes)
	}
	for i := 0; i < 8; i++ {
		scope := "a"
		if i%2 == 1 {
			scope = "b"
		}
		path := fmt.Sprintf("%s/f%d", scope, i)
		if err := auth.equalFile(path, []byte(path)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCrashRecoveryReplaysInterleavedScopesAsOneBatch(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["a"] = true
	auth.dirs["b"] = true
	auth.mu.Unlock()
	dir := t.TempDir()
	ctx := context.Background()

	e1, err := Open(ctx, Config{
		StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth,
		BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open first engine: %v", err)
	}
	e1.fl.mu.Lock()
	e1.fl.nextAttempt = time.Now().Add(time.Hour)
	e1.fl.mu.Unlock()
	for i := 0; i < 8; i++ {
		scope := "a"
		if i%2 == 1 {
			scope = "b"
		}
		path := fmt.Sprintf("%s/recovered-%d", scope, i)
		_, handled, err := e1.Create(ctx, path, 0o644, false, false)
		mustHandled(t, "recovery create "+path, handled, err)
	}
	if err := e1.SyncLocal(); err != nil {
		t.Fatalf("sync crash tail: %v", err)
	}
	e1.cancelCtx()
	e1.fl.stop()
	if err := e1.wal.Close(); err != nil {
		t.Fatalf("close crash WAL: %v", err)
	}
	if err := e1.lock.Close(); err != nil {
		t.Fatalf("release crash lock: %v", err)
	}

	injectedPrepareErr := errors.New("injected recovered identity persistence failure")
	if failed, openErr := Open(ctx, Config{
		StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth,
		BudgetBytes: 1 << 30,
		Events: Events{
			OnHandoffPrepared: func(
				context.Context, string, string,
			) (func(bool), error) {
				return nil, injectedPrepareErr
			},
		},
	}); openErr == nil {
		_, _ = failed.ForceClose("unexpected successful recovery")
		t.Fatal("recovery served after identity persistence failure")
	} else if !strings.Contains(openErr.Error(), injectedPrepareErr.Error()) {
		t.Fatalf("recovery prepare failure=%v want %v", openErr, injectedPrepareErr)
	}

	var preparedScopes []string
	var completedScopes []string
	e2, err := Open(ctx, Config{
		StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth,
		BudgetBytes: 1 << 30,
		Events: Events{
			OnHandoffPrepared: func(
				_ context.Context, scope, epoch string,
			) (func(bool), error) {
				if epoch == "" {
					t.Fatalf("recovery prepared empty epoch for %q", scope)
				}
				preparedScopes = append(preparedScopes, scope)
				return func(released bool) {
					if !released {
						t.Fatalf("successful recovery retired %q as unreleased", scope)
					}
					completedScopes = append(completedScopes, scope)
				}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("open recovery engine: %v", err)
	}
	defer func() { _, _ = e2.ForceClose("test teardown") }()
	deadline := time.Now().Add(10 * time.Second)
	for len(e2.Status().Jobs) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("mixed recovery did not resolve: %+v", e2.Status().Jobs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	auth.mu.Lock()
	flushes := auth.flushes
	rebinds := auth.rebinds
	auth.mu.Unlock()
	if flushes != 1 || rebinds != 2 {
		t.Fatalf("mixed recovery RPCs: flushes=%d rebinds=%d, want one flush and two rebind attempts", flushes, rebinds)
	}
	sort.Strings(preparedScopes)
	sort.Strings(completedScopes)
	if !reflect.DeepEqual(preparedScopes, []string{"a", "b"}) ||
		!reflect.DeepEqual(completedScopes, []string{"a", "b"}) {
		t.Fatalf("recovery prepared/completed scopes=%v/%v want [a b]/[a b]",
			preparedScopes, completedScopes)
	}
	for i := 0; i < 8; i++ {
		scope := "a"
		if i%2 == 1 {
			scope = "b"
		}
		path := fmt.Sprintf("%s/recovered-%d", scope, i)
		if err := auth.equalFile(path, nil); err != nil {
			t.Fatal(err)
		}
	}
}

// TestWatermarkNeverOverAdvances pins invariant 5's client half: a Status-0
// flush reply whose watermark stops short of the batch end is a protocol
// violation — the stream parks typed and NOTHING above Through is dropped.
// The old max(reply.Through, batchEnd) behavior silently discarded records
// the authority never reported applied.
func TestWatermarkNeverOverAdvances(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.throughShortfall = 1
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()

	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: %v %v", handled, err)
	}
	if _, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("short")); err != nil || !handled {
		t.Fatalf("write: %v %v", handled, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.mu.RLock()
		dead := e.streamDead
		e.mu.RUnlock()
		if dead != nil {
			if !errors.Is(dead, ErrConflict) {
				t.Fatalf("short watermark parked as %v, want ErrConflict-typed", dead)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a watermark short of the batch end never parked the stream")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The un-covered record is retained, not discarded.
	if recs, _ := e.Pending(); recs == 0 {
		t.Fatal("records above the reported watermark were dropped")
	}
	if st := e.Status(); st.AppliedThrough >= 2 {
		t.Fatalf("client watermark %d advanced past the authority's report", st.AppliedThrough)
	}
}

func TestWatermarkPastBatchEndParks(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.throughExcess = 1
	auth.mu.Unlock()
	e := testEngine(t, auth)
	if _, handled, err := e.Create(context.Background(), "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.mu.RLock()
		dead := e.streamDead
		e.mu.RUnlock()
		if dead != nil {
			if !errors.Is(dead, ErrConflict) {
				t.Fatalf("past-end watermark parked as %v, want ErrConflict-typed", dead)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a watermark past the sent batch end never parked the stream")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if st := e.Status(); st.AppliedThrough != 0 {
		t.Fatalf("client accepted impossible past-end watermark %d", st.AppliedThrough)
	}
}

// TestSparseWriteDoesNotHydrate is the headline regression: writing 1 byte at
// offset 0 of a large cold file must not fetch the file.
func TestSparseWriteDoesNotHydrate(t *testing.T) {
	auth := newFakeAuthority()
	large := bytes.Repeat([]byte("x"), 8<<20)
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.files["d/large.bin"] = large
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()

	baseReads := 0
	base := func(basePath string, off int64, dst []byte) (int, error) {
		baseReads++
		content, _ := auth.fileContent(basePath)
		if off >= int64(len(content)) {
			return 0, nil
		}
		return copy(dst, content[off:]), nil
	}
	_, handled, err := e.WriteAt(ctx, "d/large.bin", 0, []byte("Y"))
	mustHandled(t, "1-byte write", handled, err)
	if baseReads != 0 {
		t.Fatalf("writing 1 byte hydrated the base (%d base reads)", baseReads)
	}
	if ent, res := e.Lookup("d/large.bin"); res != LookupHit || ent.Size != int64(len(large)) {
		t.Fatalf("size after sparse write: %+v %v", ent, res)
	}
	// Read-through composition: the dirty byte over the base.
	dst := make([]byte, 8)
	n, handled, err := e.ReadAt("d/large.bin", dst, 0, base)
	mustHandled(t, "composed read", handled, err)
	if n != 8 || string(dst[:n]) != "Yxxxxxxx" {
		t.Fatalf("composed read = %q (%d)", dst[:n], n)
	}
	if baseReads == 0 {
		t.Fatal("composed read did not consult the base for the clean gap")
	}
}

// TestReadComposition covers extents + zero holes + base + EOF clipping.
func TestReadComposition(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.files["d/f"] = []byte("0123456789")
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()

	if _, handled, err := e.WriteAt(ctx, "d/f", 2, []byte("AB")); err != nil || !handled {
		t.Fatalf("write: %v %v", handled, err)
	}
	// Extend past EOF with a hole: [10,16) zeros, then "ZZ" at 16.
	if _, handled, err := e.WriteAt(ctx, "d/f", 16, []byte("ZZ")); err != nil || !handled {
		t.Fatalf("write hole: %v %v", handled, err)
	}
	dst := make([]byte, 32)
	n, handled, err := e.ReadAt("d/f", dst, 0, auth.baseReader("d/f"))
	mustHandled(t, "read", handled, err)
	want := "01AB456789\x00\x00\x00\x00\x00\x00ZZ"
	if string(dst[:n]) != want {
		t.Fatalf("composed = %q, want %q", dst[:n], want)
	}
	// Truncate shrink then extend: old bytes must not resurrect.
	if _, handled, err := e.Truncate(ctx, "d/f", 4); err != nil || !handled {
		t.Fatalf("truncate shrink: %v %v", handled, err)
	}
	if _, handled, err := e.Truncate(ctx, "d/f", 8); err != nil || !handled {
		t.Fatalf("truncate extend: %v %v", handled, err)
	}
	n, handled, err = e.ReadAt("d/f", dst, 0, auth.baseReader("d/f"))
	mustHandled(t, "read after truncate", handled, err)
	if string(dst[:n]) != "01AB\x00\x00\x00\x00" {
		t.Fatalf("after shrink+extend = %q", dst[:n])
	}
	if err := e.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if err := auth.equalFile("d/f", []byte("01AB\x00\x00\x00\x00")); err != nil {
		t.Fatal(err)
	}
}

// TestRenameAndRemoveLocal exercises namespace deltas: create/rename-over/
// remove/recreate reach the authority in exact final form.
func TestRenameAndRemoveLocal(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()

	if _, handled, err := e.Create(ctx, "d/a", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create a: %v %v", handled, err)
	}
	if _, handled, err := e.WriteAt(ctx, "d/a", 0, []byte("alpha")); err != nil || !handled {
		t.Fatalf("write a: %v %v", handled, err)
	}
	if _, handled, err := e.Create(ctx, "d/b", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create b: %v %v", handled, err)
	}
	if _, handled, err := e.Rename(ctx, "d/a", "d/b", nil); err != nil || !handled {
		t.Fatalf("rename over: %v %v", handled, err)
	}
	if _, res := e.Lookup("d/a"); res != LookupNegative {
		t.Fatalf("lookup d/a after rename: %v", res)
	}
	if ent, res := e.Lookup("d/b"); res != LookupHit || ent.Size != 5 {
		t.Fatalf("lookup d/b after rename: %v %+v", res, ent)
	}
	if _, handled, err := e.Remove(ctx, "d/b"); err != nil || !handled {
		t.Fatalf("remove b: %v %v", handled, err)
	}
	if _, handled, err := e.Create(ctx, "d/b", 0o644, false, false); err != nil || !handled {
		t.Fatalf("recreate b: %v %v", handled, err)
	}
	if _, handled, err := e.WriteAt(ctx, "d/b", 0, []byte("fresh")); err != nil || !handled {
		t.Fatalf("write recreated b: %v %v", handled, err)
	}
	if err := e.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if _, ok := auth.fileContent("d/a"); ok {
		t.Fatal("d/a survived on the authority")
	}
	if err := auth.equalFile("d/b", []byte("fresh")); err != nil {
		t.Fatal(err)
	}
}

// TestFoldedRenameBaseReadsFollowOldName pins the fold-vs-rename race (the
// git index.lock churn failure): when the watermark covers a renamed file's
// WRITE but not yet the RENAME, folding drops the write's extents — and the
// base read must then target the OLD authority name (where the bytes still
// live), never the new name (which still binds the PREVIOUS file).
func TestFoldedRenameBaseReadsFollowOldName(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushErr = errors.New("hold") // the test drives application manually
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()

	mustAck := func(what string, handled bool, err error) {
		t.Helper()
		if err != nil || !handled {
			t.Fatalf("%s: handled=%v err=%v", what, handled, err)
		}
	}
	_, h, err := e.Create(ctx, "d/index", 0o644, false, false)
	mustAck("create index", h, err)
	_, h, err = e.WriteAt(ctx, "d/index", 0, []byte("index-000")) // seq 2
	mustAck("write index", h, err)
	_, h, err = e.Create(ctx, "d/index.lock", 0o644, false, false) // seq 3
	mustAck("create lock", h, err)
	_, h, err = e.WriteAt(ctx, "d/index.lock", 0, []byte("index-001")) // seq 4
	mustAck("write lock", h, err)
	_, h, err = e.Rename(ctx, "d/index.lock", "d/index", nil) // seq 5
	mustAck("rename", h, err)

	// The authority applied through seq 4 (both writes) but NOT the rename.
	auth.mu.Lock()
	auth.files["d/index"] = []byte("index-000")
	auth.files["d/index.lock"] = []byte("index-001")
	auth.mu.Unlock()
	e.noteApplied(4, [32]byte{})

	dst := make([]byte, 16)
	n, handled, err := e.ReadAt("d/index", dst, 0, auth.baseReader(""))
	if err != nil || !handled {
		t.Fatalf("read pre-rename-apply: handled=%v err=%v", handled, err)
	}
	if got := string(dst[:n]); got != "index-001" {
		t.Fatalf("read after fold-before-rename = %q, want %q (base reads must follow the OLD name until the rename applies)", got, "index-001")
	}

	// The rename applies: base reads move to the new name.
	auth.mu.Lock()
	auth.files["d/index"] = []byte("index-001")
	delete(auth.files, "d/index.lock")
	auth.mu.Unlock()
	e.noteApplied(5, [32]byte{})
	n, handled, err = e.ReadAt("d/index", dst, 0, auth.baseReader(""))
	if err != nil || !handled || string(dst[:n]) != "index-001" {
		t.Fatalf("read post-rename-apply = %q handled=%v err=%v", dst[:n], handled, err)
	}
}

// TestRecallDrainsAndReleases: a peer recall drains the captured tail and
// releases the grant; later mutations run write-through.
func TestRecallDrainsAndReleases(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()

	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: %v %v", handled, err)
	}
	if _, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("visible-to-peer")); err != nil || !handled {
		t.Fatalf("write: %v %v", handled, err)
	}
	if err := e.Recall(ctx, "d/f"); err != nil {
		t.Fatalf("recall: %v", err)
	}
	if auth.grantCount() != 0 {
		t.Fatalf("recall left %d grants held", auth.grantCount())
	}
	if err := auth.equalFile("d/f", []byte("visible-to-peer")); err != nil {
		t.Fatalf("peer would read stale state: %v", err)
	}
	if e.Covers("d/f") {
		t.Fatal("engine still covers the recalled scope")
	}
	// The recalled scope is backed off: the next mutation runs write-through.
	if _, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("X")); err != nil || handled {
		t.Fatalf("post-recall write: handled=%v err=%v, want write-through", handled, err)
	}
}

// TestRecallKeepsAcknowledgedOverlayReadableDuringDrain pins the handoff
// window found by the two-mount production stress test. Once a mutation is
// acknowledged, reads must keep using the holder's authoritative overlay
// while recall flushes its WAL. Falling through to the authority in this
// interval can expose the pre-create/pre-write state.
func TestRecallKeepsAcknowledgedOverlayReadableDuringDrain(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushGate = make(chan struct{})
	auth.flushEntered = make(chan struct{}, 1)
	flushGate := auth.flushGate
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()

	// Prevent the steady-state flusher from applying the overlay before the
	// recall establishes the deterministic drain window.
	e.fl.mu.Lock()
	e.fl.nextAttempt = time.Now().Add(time.Hour)
	e.fl.mu.Unlock()

	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if _, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("acked")); err != nil || !handled {
		t.Fatalf("write: handled=%v err=%v", handled, err)
	}
	if handled, err := e.Setxattr(ctx, "d/f", "user.test", []byte("value"), 0); err != nil || !handled {
		t.Fatalf("setxattr: handled=%v err=%v", handled, err)
	}
	if _, handled, err := e.Symlink(ctx, "d/link", "f"); err != nil || !handled {
		t.Fatalf("symlink: handled=%v err=%v", handled, err)
	}
	if _, handled, err := e.Create(ctx, "d/removed", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create removed: handled=%v err=%v", handled, err)
	}
	if _, handled, err := e.Remove(ctx, "d/removed"); err != nil || !handled {
		t.Fatalf("remove: handled=%v err=%v", handled, err)
	}

	recallOut := make(chan error, 1)
	go func() { recallOut <- e.Recall(ctx, "d") }()
	select {
	case <-auth.flushEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("recall did not enter the blocked authority flush")
	}
	permit, err := e.BeginRead(ctx, "d/f")
	if err != nil {
		t.Fatalf("begin draining read: %v", err)
	}
	permitOpen := true
	defer func() {
		if permitOpen {
			permit.Close()
		}
	}()
	if !e.Covers("d/f") {
		t.Fatal("draining delegation stopped covering acknowledged state before Checkin")
	}
	type writeResult struct {
		handled bool
		err     error
	}
	writeOut := make(chan writeResult, 1)
	go func() {
		_, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("later"))
		writeOut <- writeResult{handled: handled, err: err}
	}()
	select {
	case result := <-writeOut:
		t.Fatalf("mutation crossed draining handoff: handled=%v err=%v", result.handled, result.err)
	case <-time.After(50 * time.Millisecond):
	}

	if ent, result := e.Lookup("d/f"); result != LookupHit || ent.Size != 5 {
		t.Fatalf("lookup during drain = %+v/%v, want acknowledged file", ent, result)
	}
	if _, result := e.Lookup("d/removed"); result != LookupNegative {
		t.Fatalf("removed lookup during drain = %v, want acknowledged tombstone", result)
	}
	entries, ok := e.Readdir("d")
	if !ok {
		t.Fatal("readdir became undecidable during drain")
	}
	foundFile, foundLink := false, false
	for _, ent := range entries {
		foundFile = foundFile || ent.Name == "f"
		foundLink = foundLink || ent.Name == "link"
	}
	if !foundFile || !foundLink {
		t.Fatalf("readdir during drain omitted acknowledged entries: %+v", entries)
	}
	dst := make([]byte, 5)
	n, handled, err := e.ReadAt("d/f", dst, 0, func(string, int64, []byte) (int, error) {
		return 0, errors.New("authority base must not serve a born-local file during drain")
	})
	if err != nil || !handled || n != 5 || string(dst) != "acked" {
		t.Fatalf("read during drain = %q n=%d handled=%v err=%v", dst, n, handled, err)
	}
	if target, kind, ok := e.Readlink("d/link"); !ok || kind != "symlink" || target != "f" {
		t.Fatalf("readlink during drain = target=%q kind=%q ok=%v", target, kind, ok)
	}
	if value, result := e.Getxattr("d/f", "user.test"); result != LookupHit || string(value) != "value" {
		t.Fatalf("getxattr during drain = %q/%v", value, result)
	}
	if names, ok := e.Listxattr("d/f"); !ok || len(names) != 1 || names[0] != "user.test" {
		t.Fatalf("listxattr during drain = %v/%v", names, ok)
	}

	close(flushGate)
	deadline := time.Now().Add(2 * time.Second)
	for {
		e.mu.RLock()
		d := e.delegations["d"]
		e.mu.RUnlock()
		readClosing := false
		if d != nil {
			d.readMu.Lock()
			readClosing = d.readClosing
			d.readMu.Unlock()
		}
		if readClosing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("recall did not close read admission after draining")
		}
		time.Sleep(time.Millisecond)
	}
	nextRead := make(chan ReadPermit, 1)
	go func() {
		p, beginErr := e.BeginRead(ctx, "d/f")
		if beginErr != nil {
			nextRead <- nil
			return
		}
		nextRead <- p
	}()
	select {
	case <-recallOut:
		t.Fatal("Checkin passed an in-flight overlay read")
	case <-nextRead:
		t.Fatal("new read crossed the closed handoff barrier")
	case <-time.After(50 * time.Millisecond):
	}
	permit.Close()
	permitOpen = false
	if err := <-recallOut; err != nil {
		t.Fatalf("recall: %v", err)
	}
	select {
	case p := <-nextRead:
		if p == nil {
			t.Fatal("post-handoff reader failed")
		}
		p.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("post-handoff reader did not re-resolve after overlay drop")
	}
	if result := <-writeOut; result.handled || result.err != nil {
		t.Fatalf("post-handoff mutation = handled=%v err=%v, want shared lane", result.handled, result.err)
	}
	if err := auth.equalFile("d/f", []byte("acked")); err != nil {
		t.Fatal(err)
	}
}

func TestRecallRefusesCheckinWhenFrontendHandoffFails(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	e := testEngine(t, auth)
	handoffErr := errors.New("frontend cache barrier failed")
	e.cfg.Events.OnHandoff = func(scope string) error {
		if scope != "d" {
			t.Fatalf("handoff scope = %q, want d", scope)
		}
		return handoffErr
	}
	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if _, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("acked")); err != nil || !handled {
		t.Fatalf("write: handled=%v err=%v", handled, err)
	}
	if err := e.Recall(ctx, "d"); !errors.Is(err, handoffErr) {
		t.Fatalf("recall error = %v, want frontend barrier failure", err)
	}
	if got := auth.grantCount(); got != 1 {
		t.Fatalf("failed frontend barrier released authority grant: grants=%d", got)
	}
	permit, err := e.BeginRead(ctx, "d/f")
	if err != nil {
		t.Fatalf("begin read after failed handoff: %v", err)
	}
	defer permit.Close()
	if ent, result := permit.Lookup("d/f"); result != LookupHit || ent.Size != 5 {
		t.Fatalf("retained overlay after failed handoff = %+v/%v", ent, result)
	}
}

func TestRecallRefusesCheckinWhenPreparedIdentityPersistenceFails(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	e := testEngine(t, auth)
	prepared := false
	e.cfg.ProtectOpenPins = func(context.Context, string, string) (func(bool), error) {
		prepared = true
		return func(bool) {}, nil
	}
	persistErr := errors.New("identity journal disk full")
	e.cfg.Events.OnHandoffPrepared = func(
		_ context.Context, scope string, _ string,
	) (func(bool), error) {
		if scope != "d" {
			t.Fatalf("prepared handoff scope=%q want d", scope)
		}
		if !prepared {
			t.Fatal("identity persistence ran before release-pin identity assignment")
		}
		return nil, persistErr
	}
	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if _, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("acked")); err != nil || !handled {
		t.Fatalf("write: handled=%v err=%v", handled, err)
	}
	if err := e.Recall(ctx, "d"); !errors.Is(err, persistErr) {
		t.Fatalf("recall error=%v want identity persistence error", err)
	}
	if got := auth.grantCount(); got != 1 {
		t.Fatalf("failed identity persist released authority grant: grants=%d", got)
	}
}

func TestReadPermitInterfaceCopiesShareOneClose(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	permit, err := e.BeginRead(ctx, "d/f")
	if err != nil {
		t.Fatal(err)
	}
	copyOfPermit := permit
	permit.Close()
	copyOfPermit.Close()

	e.mu.RLock()
	d := e.delegations["d"]
	e.mu.RUnlock()
	d.readMu.Lock()
	readers := d.readers
	d.readMu.Unlock()
	if readers != 0 {
		t.Fatalf("reader count after copied closes = %d, want 0", readers)
	}
}

func TestSharedReadPermitFastPathDoesNotAllocate(t *testing.T) {
	auth := newFakeAuthority()
	e := testEngine(t, auth)
	ctx := context.Background()
	allocs := testing.AllocsPerRun(1000, func() {
		permit, err := e.BeginRead(ctx, "shared/file")
		if err != nil {
			panic(err)
		}
		permit.Close()
	})
	if allocs != 0 {
		t.Fatalf("shared BeginRead allocations = %v, want 0", allocs)
	}
}

// TestReleaseForLeavesDelegatedMode pins the P1 write-through contract: a
// caller about to run a write-through operation (hard link or orphan)
// releases the covering delegation FIRST — the acked tail drains, the grant
// releases durably, and no delegation covers the paths afterward.
func TestReleaseForLeavesDelegatedMode(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: %v %v", handled, err)
	}
	if _, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("acked")); err != nil || !handled {
		t.Fatalf("write: %v %v", handled, err)
	}
	if err := e.ReleaseFor(ctx, "d/f"); err != nil {
		t.Fatalf("release-for: %v", err)
	}
	if e.Covers("d/f") {
		t.Fatal("delegation still covers the path after ReleaseFor")
	}
	if auth.grantCount() != 0 {
		t.Fatalf("%d grants still held after ReleaseFor", auth.grantCount())
	}
	// The acked tail drained BEFORE the release: the write-through operation
	// that follows orders after it.
	if err := auth.equalFile("d/f", []byte("acked")); err != nil {
		t.Fatal(err)
	}
}

func TestBeginExactReleasesEveryDelegationAndHoldsAcquisitionGate(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.dirs["e"] = true
	auth.mu.Unlock()
	engine := testEngine(t, auth)
	ctx := context.Background()
	if _, handled, err := engine.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create d/f: handled=%v err=%v", handled, err)
	}
	if _, handled, err := engine.Create(ctx, "e/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create e/f: handled=%v err=%v", handled, err)
	}
	if err := engine.ReleaseFor(ctx, ""); err != nil {
		t.Fatalf("path-scoped empty release: %v", err)
	}
	if !engine.Covers("d/f") || !engine.Covers("e/f") {
		t.Fatal("ordinary empty-path ReleaseFor unexpectedly became mount-wide")
	}

	end, err := engine.BeginExact(ctx)
	if err != nil {
		t.Fatalf("begin exact: %v", err)
	}
	if engine.Covers("d/f") || engine.Covers("e/f") {
		end()
		t.Fatal("BeginExact left a retained delegation")
	}
	if got := auth.grantCount(); got != 0 {
		end()
		t.Fatalf("BeginExact left %d authority grants", got)
	}
	end()
}

func TestReleaseForIncludesDescendantDelegations(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["tree"] = true
	auth.dirs["tree/child"] = true
	auth.mu.Unlock()
	engine := testEngine(t, auth)
	ctx := context.Background()
	if _, handled, err := engine.Create(
		ctx,
		"tree/child/file",
		0o644,
		false,
		false,
	); err != nil || !handled {
		t.Fatalf("seed descendant grant: handled=%v err=%v", handled, err)
	}
	if !engine.Covers("tree/child/file") {
		t.Fatal("test precondition: descendant delegation was not installed")
	}
	if err := engine.ReleaseFor(ctx, "tree"); err != nil {
		t.Fatalf("release ancestor: %v", err)
	}
	if engine.Covers("tree/child/file") {
		t.Fatal("ancestor release retained a descendant delegation")
	}
	if got := auth.grantCount(); got != 0 {
		t.Fatalf("authority retained %d descendant grants", got)
	}
}

type blockedAcquireRemote struct {
	*fakeAuthority
	entered chan struct{}
	release chan struct{}
}

func (r *blockedAcquireRemote) DelegationAcquire(ctx context.Context, scope, writebackID string) (AcquireReply, error) {
	select {
	case <-r.entered:
	default:
		close(r.entered)
	}
	select {
	case <-r.release:
		return r.fakeAuthority.DelegationAcquire(ctx, scope, writebackID)
	case <-ctx.Done():
		return AcquireReply{}, ctx.Err()
	}
}

func TestBeginExactWaitsForDetachedAcquireResolverThenReleasesItsGrant(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	remote := &blockedAcquireRemote{
		fakeAuthority: auth,
		entered:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	engine, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main", Remote: remote,
		BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = engine.ForceClose("test teardown") })

	mutationCtx, cancelMutation := context.WithCancel(context.Background())
	createDone := make(chan error, 1)
	go func() {
		_, _, createErr := engine.Create(mutationCtx, "d/f", 0o644, false, false)
		createDone <- createErr
	}()
	select {
	case <-remote.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("delegation acquire did not enter")
	}
	cancelMutation()
	select {
	case err := <-createDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("create error=%v want context canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled mutation did not return")
	}

	type exactResult struct {
		end func()
		err error
	}
	exactDone := make(chan exactResult, 1)
	go func() {
		end, exactErr := engine.BeginExact(context.Background())
		exactDone <- exactResult{end: end, err: exactErr}
	}()
	select {
	case result := <-exactDone:
		if result.end != nil {
			result.end()
		}
		t.Fatalf("BeginExact passed an unresolved acquire: %v", result.err)
	case <-time.After(100 * time.Millisecond):
	}

	close(remote.release)
	var result exactResult
	select {
	case result = <-exactDone:
	case <-time.After(5 * time.Second):
		t.Fatal("BeginExact did not finish after acquire resolution")
	}
	if result.err != nil {
		t.Fatalf("BeginExact: %v", result.err)
	}
	defer result.end()
	if engine.Covers("d/f") {
		t.Fatal("late-installed grant survived BeginExact")
	}
	if got := auth.grantCount(); got != 0 {
		t.Fatalf("late-installed authority grant count=%d want 0", got)
	}
}

// TestRenameAuthorityLaneReleasesDestinationOnlyDelegation pins the
// multi-path admission contract. A top-level source is deliberately
// nondelegable, but the destination can still sit inside a retained grant.
// Rename must release that destination grant before returning handled=false;
// otherwise the authority rename recalls its own caller and deadlocks behind
// the frontend operation waiting for Rename to return.
func TestRenameAuthorityLaneReleasesDestinationOnlyDelegation(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["delegated"] = true
	auth.files["source"] = []byte("authority source")
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()

	if _, handled, err := e.Create(ctx, "delegated/acked", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create delegated tail: handled=%v err=%v", handled, err)
	}
	if _, handled, err := e.WriteAt(ctx, "delegated/acked", 0, []byte("drain me")); err != nil || !handled {
		t.Fatalf("write delegated tail: handled=%v err=%v", handled, err)
	}

	if _, handled, err := e.Rename(ctx, "source", "delegated/destination", nil); err != nil || handled {
		t.Fatalf("cross-lane rename: handled=%v err=%v, want clean authority lane", handled, err)
	}
	if e.Covers("delegated/destination") {
		t.Fatal("destination delegation survived authority-lane rename admission")
	}
	if got := auth.grantCount(); got != 0 {
		t.Fatalf("authority still holds %d destination grants, want 0", got)
	}
	if _, _, releases := auth.calls(); releases != 1 {
		t.Fatalf("rename released %d grants, want exactly 1", releases)
	}
	if err := auth.equalFile("delegated/acked", []byte("drain me")); err != nil {
		t.Fatalf("destination tail was not authoritative before rename fallthrough: %v", err)
	}
}

// A policy denial on the source scope is another normal authority-lane
// decision. It has the same multi-path release obligation as a nondelegable
// top-level source.
func TestRenameDeniedSourceReleasesDestinationOnlyDelegation(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["source-dir"] = true
	auth.dirs["delegated"] = true
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()

	if _, handled, err := e.Create(ctx, "delegated/held", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create destination delegation: handled=%v err=%v", handled, err)
	}
	auth.mu.Lock()
	auth.denyAll = true
	auth.mu.Unlock()

	if _, handled, err := e.Rename(ctx, "source-dir/source", "delegated/destination", nil); err != nil || handled {
		t.Fatalf("denied-source rename: handled=%v err=%v, want clean authority lane", handled, err)
	}
	if e.Covers("delegated/destination") {
		t.Fatal("destination delegation survived denied source admission")
	}
	if got := auth.grantCount(); got != 0 {
		t.Fatalf("authority still holds %d destination grants, want 0", got)
	}
}

// An indeterminate source-admission failure is not permission to switch to
// the authority lane. Preserve all grants and return the error; a caller must
// never execute rename after an acquisition whose outcome is unknown.
func TestRenameSourceAdmissionErrorPreservesDestinationDelegation(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["source-dir"] = true
	auth.dirs["delegated"] = true
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()

	if _, handled, err := e.Create(ctx, "delegated/held", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create destination delegation: handled=%v err=%v", handled, err)
	}
	acquireErr := errors.New("source acquire outcome unknown")
	auth.mu.Lock()
	auth.acquireErr = acquireErr
	auth.mu.Unlock()

	if _, handled, err := e.Rename(ctx, "source-dir/source", "delegated/destination", nil); !errors.Is(err, acquireErr) || handled {
		t.Fatalf("uncertain-source rename: handled=%v err=%v, want admission failure", handled, err)
	}
	if !e.Covers("delegated/destination") {
		t.Fatal("admission error incorrectly released the destination delegation")
	}
	if _, _, releases := auth.calls(); releases != 0 {
		t.Fatalf("admission error released %d grants, want 0", releases)
	}
}

// TestOverlayExtentBoundReleases pins the no-spill hard bound: a write that
// would grow a file's extent set past maxFileExtents stops acknowledging
// locally — it drains, releases the delegation, and falls through to
// write-through instead of growing without bound.
func TestOverlayExtentBoundReleases(t *testing.T) {
	oldExt := maxFileExtents
	maxFileExtents = 8
	defer func() { maxFileExtents = oldExt }()
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushErr = errors.New("hold") // nothing folds, extents accumulate
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: %v %v", handled, err)
	}
	fellThrough := false
	for i := 0; i < 2*maxFileExtents+2; i++ {
		// Disjoint 1-byte writes with gaps: every write is its own extent.
		// Once the bound trips, the engine tries to drain+release; the
		// blackholed authority stalls that, so bound the attempt and accept
		// either outcome shape — what may NOT happen is another local ack.
		wctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		_, handled, err := e.WriteAt(wctx, "d/f", int64(i*3), []byte("x"))
		cancel()
		if !handled {
			fellThrough = true
			_ = err
			break
		}
		if err != nil {
			t.Fatalf("handled write %d failed: %v", i, err)
		}
	}
	if !fellThrough {
		t.Fatal("extent bound never forced the fall-through")
	}
	e.mu.RLock()
	extents := len(e.files["d/f"].extents)
	e.mu.RUnlock()
	if extents > maxFileExtents {
		t.Fatalf("overlay grew to %d extents past the %d bound", extents, maxFileExtents)
	}
	// Heal the authority: the parked tail drains and the release completes.
	auth.mu.Lock()
	auth.flushErr = nil
	auth.mu.Unlock()
	if err := e.DrainAll(ctx); err != nil {
		t.Fatalf("drain after heal: %v", err)
	}
}

// TestDirViewBoundNeverClaimsOversizeListing: MergeReaddir refuses to claim
// completeness for a listing past the child bound.
func TestDirViewBoundNeverClaimsOversizeListing(t *testing.T) {
	oldChildren := maxDirViewChildren
	maxDirViewChildren = 4
	defer func() { maxDirViewChildren = oldChildren }()
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.omitChildren = true // duplicate-replay shape: grant without snapshot
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, true); err != nil || !handled {
		t.Fatalf("create: %v %v", handled, err)
	}
	big := make([]Entry, 0, 8)
	for i := 0; i < 8; i++ {
		big = append(big, Entry{Name: fmt.Sprintf("peer%02d", i), Kind: "file"})
	}
	_ = e.MergeReaddir("d", big)
	if _, ok := e.Readdir("d"); ok {
		t.Fatal("an oversize listing must not seed a complete view")
	}
}

// TestClientKillRecovery simulates a client kill -9: the engine is abandoned
// without any close, a fresh engine on the same store recovers the stream,
// and every accepted mutation reaches the authority byte-exactly.
func TestClientKillRecovery(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	dir := t.TempDir()
	ctx := context.Background()

	e1, err := Open(ctx, Config{StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth, BudgetBytes: 1 << 30})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var want [][]byte
	for i := 0; i < 50; i++ {
		p := fmt.Sprintf("d/f%03d", i)
		if _, handled, err := e1.Create(ctx, p, 0o644, false, false); err != nil || !handled {
			t.Fatalf("create %s: %v %v", p, handled, err)
		}
		content := bytes.Repeat([]byte{byte('a' + i%26)}, 100+i)
		if _, handled, err := e1.WriteAt(ctx, p, 0, content); err != nil || !handled {
			t.Fatalf("write %s: %v %v", p, handled, err)
		}
		want = append(want, content)
	}
	// Ensure local durability (the group sync window is POSIX loss budget for
	// machine crashes; a process kill keeps written fd bytes either way).
	if err := e1.SyncLocal(); err != nil {
		t.Fatalf("local sync: %v", err)
	}
	// Kill: release the flock without closing/draining anything.
	e1.cancelCtx()
	e1.fl.stop()
	_ = e1.wal.Close()
	_ = e1.lock.Close()

	e2, err := Open(ctx, Config{StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth, BudgetBytes: 1 << 30})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _, _ = e2.ForceClose("teardown") }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if len(e2.Status().Jobs) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery did not resolve: %+v", e2.Status().Jobs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i, content := range want {
		p := fmt.Sprintf("d/f%03d", i)
		if err := auth.equalFile(p, content); err != nil {
			t.Fatalf("acked write lost: %v", err)
		}
	}
	if auth.grantCount() != 0 {
		t.Fatalf("recovery left %d grants held", auth.grantCount())
	}
	if streams, _ := filepath.Glob(filepath.Join(dir, "stream-*")); len(streams) != 0 {
		t.Fatalf("recovered stream dirs not removed: %v", streams)
	}
}

func TestCleanCloseRemountNeverReusesWritebackIdentity(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	dir := t.TempDir()
	ctx := context.Background()

	e1, err := Open(ctx, Config{StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth})
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, handled, err := e1.Create(ctx, "d/first", 0o644, false, false); err != nil || !handled {
		t.Fatalf("first create: handled=%v err=%v", handled, err)
	}
	if err := e1.Close(ctx); err != nil {
		t.Fatalf("first clean close: %v", err)
	}
	firstID, firstEpoch := e1.writebackID, e1.epoch
	if streams, _ := filepath.Glob(filepath.Join(dir, "stream-*")); len(streams) != 0 {
		t.Fatalf("clean close retained stream directories: %v", streams)
	}

	e2, err := Open(ctx, Config{StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth})
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer func() { _, _ = e2.ForceClose("test teardown") }()
	if e2.writebackID == firstID || e2.epoch <= firstEpoch {
		t.Fatalf("clean remount reused stream identity: first=%s/%d second=%s/%d", firstID, firstEpoch, e2.writebackID, e2.epoch)
	}
	if _, handled, err := e2.Create(ctx, "d/second", 0o644, false, false); err != nil || !handled {
		t.Fatalf("second create: handled=%v err=%v", handled, err)
	}
	if err := e2.DrainAll(ctx); err != nil {
		t.Fatalf("second drain: %v", err)
	}
	if err := auth.equalFile("d/second", nil); err != nil {
		t.Fatalf("second stream did not reach authority: %v", err)
	}
}

// TestFencedStreamParksRefusesAndRebindsMonotonic pins the fence lifecycle:
// a definite ESTALE parks the stream terminally, mutations under its held
// scopes fail typed (never a silent ack onto a dead stream, never a
// write-through reordering around the parked history), and the next engine
// on the same store rebinds the SAME stream under a fresh session and drains
// the tail — the authority watermark continues exactly where it stopped and
// never resets.
func TestFencedStreamParksRefusesAndRebindsMonotonic(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	dir := t.TempDir()
	ctx := context.Background()

	e1, err := Open(ctx, Config{StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth, BudgetBytes: 1 << 30})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, handled, err := e1.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: %v %v", handled, err)
	}
	if _, handled, err := e1.WriteAt(ctx, "d/f", 0, []byte("one")); err != nil || !handled {
		t.Fatalf("write one: %v %v", handled, err)
	}
	if err := e1.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	wbID := e1.writebackID
	auth.mu.Lock()
	fencedAt := auth.streams[wbID].through
	auth.flushStat = 116 // every flush now answers ESTALE (definite fence)
	auth.mu.Unlock()

	// Acked before the flusher discovers the fence: stays parked locally.
	if _, handled, err := e1.WriteAt(ctx, "d/f", 0, []byte("two")); err != nil || !handled {
		t.Fatalf("write two: %v %v", handled, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		e1.mu.RLock()
		dead := e1.streamDead
		e1.mu.RUnlock()
		if dead != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fenced flush never parked the stream")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Under the dead stream's scope: typed refusal, no ack, no write-through.
	if _, handled, err := e1.WriteAt(ctx, "d/f", 0, []byte("XXX")); err == nil {
		t.Fatalf("write on a dead stream's scope: handled=%v err=nil, want typed error", handled)
	}
	if _, _, err := e1.Create(ctx, "d/other", 0o644, false, false); err == nil {
		t.Fatal("create on a dead stream's scope must fail typed")
	}
	if err := auth.equalFile("d/f", []byte("one")); err != nil {
		t.Fatalf("fenced tail leaked: %v", err)
	}
	e1.Abandon() // kill -9 equivalent

	// Authority heals; the parked grants and stream survive server-side.
	auth.mu.Lock()
	auth.flushStat = 0
	auth.mu.Unlock()

	e2, err := Open(ctx, Config{StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth, BudgetBytes: 1 << 30})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _, _ = e2.ForceClose("teardown") }()
	if e2.writebackID == wbID {
		t.Fatal("the fresh engine must mint a NEW stream; the parked one only drains")
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		if len(e2.Status().Jobs) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("recovery did not resolve: %+v", e2.Status().Jobs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := auth.equalFile("d/f", []byte("two")); err != nil {
		t.Fatalf("acked pre-fence write lost: %v", err)
	}
	auth.mu.Lock()
	finalThrough := auth.streams[wbID].through
	rebinds := auth.rebinds
	auth.mu.Unlock()
	if rebinds == 0 {
		t.Fatal("recovery did not rebind the parked stream")
	}
	// Monotonic continuation: the watermark advanced past the fence point
	// (the fake rejects any non-dense or reset sequence as corrupt, so
	// success itself proves the tail continued at fencedAt+1).
	if finalThrough <= fencedAt {
		t.Fatalf("watermark did not continue past the fence: %d <= %d", finalThrough, fencedAt)
	}
	if auth.grantCount() != 0 {
		t.Fatalf("recovery left %d grants held", auth.grantCount())
	}
}

// TestRecoverySweepsGrantOrphanedBeforeDelegationFrame pins the crash window
// between the authority journaling a grant and the client appending its
// DELEGATION frame: the local stream is validly empty, so recovery must
// discard every grant still bound to the stream (losslessly — nothing was
// ever acknowledged under it) instead of leaving an orphan that blocks the
// subtree for every peer forever.
func TestRecoverySweepsGrantOrphanedBeforeDelegationFrame(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	dir := t.TempDir()
	ctx := context.Background()

	e1, err := Open(ctx, Config{StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth, BudgetBytes: 1 << 30})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// The crash shape: the stream (and its registry) is durable, the
	// authority has journaled the grant, and the process dies before the
	// DELEGATION frame is appended.
	e1.mu.Lock()
	if err := e1.ensureStreamLocked(); err != nil {
		e1.mu.Unlock()
		t.Fatalf("ensure stream: %v", err)
	}
	e1.mu.Unlock()
	if _, err := auth.DelegationAcquire(ctx, "d", e1.writebackID); err != nil {
		t.Fatalf("authority grant: %v", err)
	}
	if auth.grantCount() != 1 {
		t.Fatal("precondition: authority holds the grant")
	}
	e1.Abandon()

	e2, err := Open(ctx, Config{StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth, BudgetBytes: 1 << 30})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _, _ = e2.ForceClose("teardown") }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if len(e2.Status().Jobs) == 0 && auth.grantCount() == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("orphaned grant not swept: grants=%d jobs=%+v", auth.grantCount(), e2.Status().Jobs)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestStickyDegradedClearsOnlyAfterExactDrain: an unreachable authority flips
// sticky degraded via the no-progress watchdog; an exact full drain after
// connectivity returns clears the transient verdict.
func TestStickyDegradedClearsOnlyAfterExactDrain(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()

	dir := t.TempDir()
	healthCh := make(chan error, 64)
	e, err := Open(context.Background(), Config{
		StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth,
		BudgetBytes: 1 << 30,
		Events:      Events{OnHealth: func(err error) { healthCh <- err }},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _, _ = e.ForceClose("teardown") }()
	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: %v %v", handled, err)
	}
	auth.mu.Lock()
	auth.flushErr = errors.New("blackhole")
	auth.mu.Unlock()
	if _, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("parked")); err != nil || !handled {
		t.Fatalf("write: %v %v", handled, err)
	}
	// Wait for at least one failed flush attempt, then force the watchdog
	// verdict without waiting out the 30 s window.
	attemptDeadline := time.Now().Add(5 * time.Second)
	for e.Status().LastFailure == "" {
		if time.Now().After(attemptDeadline) {
			t.Fatal("flusher never attempted the blackholed batch")
		}
		time.Sleep(5 * time.Millisecond)
	}
	e.fl.mu.Lock()
	e.fl.lastProgress = time.Now().Add(-2 * noProgressWindow)
	e.fl.mu.Unlock()
	e.fl.watchdog()
	select {
	case err := <-healthCh:
		if err == nil {
			t.Fatal("health cleared while stalled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no degraded verdict")
	}
	if !e.Status().Degraded {
		t.Fatal("status not degraded")
	}
	auth.mu.Lock()
	auth.flushErr = nil
	auth.mu.Unlock()
	if err := e.DrainAll(ctx); err != nil {
		t.Fatalf("drain after heal: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for e.Status().Degraded {
		if time.Now().After(deadline) {
			t.Fatal("degraded verdict did not clear after a full drain")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := auth.equalFile("d/f", []byte("parked")); err != nil {
		t.Fatal(err)
	}
	if e.Status().LastFailure == "" {
		t.Fatal("lastFailure must remain for diagnosis after recovery")
	}
}

// TestBoundedMemoryLargeSequentialWrite streams substantially more data than
// the permitted heap growth through the engine and asserts the heap stays
// bounded: dirty bytes live in the WAL, not the heap.
func TestBoundedMemoryLargeSequentialWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("large sequential stream in -short mode")
	}
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.discardContent = true
	auth.mu.Unlock()
	dir := t.TempDir()
	e, err := Open(context.Background(), Config{
		StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth,
		BudgetBytes: 4 << 30,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _, _ = e.ForceClose("teardown") }()
	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/big", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: %v %v", handled, err)
	}
	var m0 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	chunk := bytes.Repeat([]byte("z"), 1<<20)
	const (
		// Keep the stream eight times larger than the tolerated heap growth so
		// the test detects proportional retention without becoming an fsync
		// throughput benchmark.
		total         = int64(512) << 20
		maxHeapGrowth = int64(64) << 20
	)
	for off := int64(0); off < total; off += int64(len(chunk)) {
		if _, handled, err := e.WriteAt(ctx, "d/big", off, chunk); err != nil || !handled {
			t.Fatalf("write @%d: %v %v", off, handled, err)
		}
	}
	var m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	grew := int64(m1.HeapInuse) - int64(m0.HeapInuse)
	if grew > maxHeapGrowth {
		t.Fatalf("heap grew %d MiB while writing %d MiB (dirty data must live in the WAL)", grew>>20, total>>20)
	}
	if err := e.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	auth.mu.Lock()
	size := auth.sizes["d/big"]
	auth.mu.Unlock()
	if size != total {
		t.Fatalf("authority applied %d bytes, want %d", size, total)
	}
}

// TestBudgetENOSPC: at the hard WAL budget with nothing foldable the engine
// refuses new delegated mutations instead of evicting unshipped data.
func TestBudgetENOSPC(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushErr = errors.New("blackhole") // nothing can ship, nothing can fold
	auth.mu.Unlock()
	dir := t.TempDir()
	e, err := Open(context.Background(), Config{
		StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth,
		BudgetBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _, _ = e.ForceClose("teardown") }()
	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: %v %v", handled, err)
	}
	var sawNoSpace bool
	chunk := bytes.Repeat([]byte("b"), 256<<10)
	for off := int64(0); off < 8<<20; off += int64(len(chunk)) {
		_, handled, err := e.WriteAt(ctx, "d/f", off, chunk)
		if err != nil {
			if !errors.Is(err, ErrNoSpace) {
				t.Fatalf("write failed with %v, want ErrNoSpace", err)
			}
			sawNoSpace = true
			break
		}
		if !handled {
			t.Fatal("write fell through mid-delegation")
		}
	}
	if !sawNoSpace {
		t.Fatal("budget never enforced")
	}
}

// TestIdleVoluntaryRelease: a drained idle delegation releases so the
// authority's checkout table stays bounded.
func TestIdleVoluntaryRelease(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: %v %v", handled, err)
	}
	if err := e.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for auth.grantCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("idle delegation never released")
		}
		e.releaseIdle()
		time.Sleep(50 * time.Millisecond)
	}
}

// TestForceCloseLeavesDurableJob: a forced close writes the durable job +
// FORCED_CLOSE frame and the next open recovers it.
func TestForceCloseLeavesDurableJob(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushErr = errors.New("blackhole")
	auth.mu.Unlock()
	dir := t.TempDir()
	ctx := context.Background()
	e1, err := Open(ctx, Config{StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth, BudgetBytes: 1 << 30})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, handled, err := e1.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: %v %v", handled, err)
	}
	if _, handled, err := e1.WriteAt(ctx, "d/f", 0, []byte("parked")); err != nil || !handled {
		t.Fatalf("write: %v %v", handled, err)
	}
	jobID, err := e1.ForceClose("authority unreachable")
	if err != nil {
		t.Fatalf("force close: %v", err)
	}
	if jobID == "" {
		t.Fatal("forced close returned no job id")
	}
	job, ok := loadJob(filepath.Join(dir, streamDirName(1)))
	if !ok || job.State != JobForced || job.PendingRecords == 0 {
		t.Fatalf("job after forced close: %+v ok=%v", job, ok)
	}
	if job.JobID != jobID {
		t.Fatalf("returned job id %q != persisted id %q", jobID, job.JobID)
	}
	if job.JobID == job.WritebackID {
		t.Fatal("public recovery job id exposes the secret writeback capability")
	}

	auth.mu.Lock()
	auth.flushErr = nil
	auth.mu.Unlock()
	e2, err := Open(ctx, Config{StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth, BudgetBytes: 1 << 30})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _, _ = e2.ForceClose("teardown") }()
	deadline := time.Now().Add(10 * time.Second)
	for len(e2.Status().Jobs) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("forced job never drained: %+v", e2.Status().Jobs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := auth.equalFile("d/f", []byte("parked")); err != nil {
		t.Fatal(err)
	}
}

func TestFailedCloseLeavesEngineRetryable(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushErr = errors.New("authority unavailable")
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	failedCtx, cancelFailed := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancelFailed()
	if err := e.Close(failedCtx); err == nil {
		t.Fatal("close succeeded while the authority rejected the flush")
	}

	auth.mu.Lock()
	auth.flushErr = nil
	auth.mu.Unlock()
	if _, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("after retry")); err != nil || !handled {
		t.Fatalf("write after failed close: handled=%v err=%v", handled, err)
	}
	if err := e.Close(ctx); err != nil {
		t.Fatalf("retry close: %v", err)
	}
	if err := auth.equalFile("d/f", []byte("after retry")); err != nil {
		t.Fatal(err)
	}
}

// TestForceCloseDuringInFlightFlush pins the shutdown contract: a force
// close while a flush attempt is blocked inside the network call cancels the
// attempt, waits for ACTUAL flusher termination, and only then closes the
// WAL — a late flush can never run against a ForceClosed WAL.
func TestForceCloseDuringInFlightFlush(t *testing.T) {
	auth := newFakeAuthority()
	gate := make(chan struct{})
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushGate = gate
	auth.flushEntered = make(chan struct{}, 1)
	auth.mu.Unlock()
	defer close(gate)
	dir := t.TempDir()
	ctx := context.Background()
	e, err := Open(ctx, Config{StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth, BudgetBytes: 1 << 30})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: %v %v", handled, err)
	}
	select {
	case <-auth.flushEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("flusher never entered the gated flush")
	}
	done := make(chan error, 1)
	go func() {
		_, err := e.ForceClose("test: force close mid-flight")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("force close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("force close blocked behind the in-flight flush (context cancel + real termination wait broken)")
	}
	// The run loop has fully terminated: no goroutine can touch the WAL.
	e.fl.wg.Wait()
}

// TestRecoveryConflictSurfacesTyped: a scope discarded on the authority
// surfaces as a typed conflict; nothing merges silently.
func TestRecoveryConflictSurfacesTyped(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.flushErr = errors.New("blackhole")
	auth.mu.Unlock()
	dir := t.TempDir()
	ctx := context.Background()
	e1, err := Open(ctx, Config{StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth, BudgetBytes: 1 << 30})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, handled, err := e1.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: %v %v", handled, err)
	}
	if _, err := e1.ForceClose("kill"); err != nil {
		t.Fatalf("force close: %v", err)
	}
	// The authority discards the scope while the client is gone.
	auth.mu.Lock()
	auth.grants = map[string]fakeGrant{}
	auth.flushErr = nil
	auth.mu.Unlock()

	e2, err := Open(ctx, Config{StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth, BudgetBytes: 1 << 30})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _, _ = e2.ForceClose("teardown") }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		jobs := e2.Status().Jobs
		if len(jobs) == 1 && jobs[0].State == JobConflict {
			if len(jobs[0].Conflicts) == 0 {
				t.Fatalf("conflict job carries no typed details: %+v", jobs[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no typed conflict surfaced: %+v", jobs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := auth.fileContent("d/f"); ok {
		t.Fatal("conflicted tail was silently applied")
	}
}

// TestAdoptExistingFilePreservesContent: O_CREAT on an existing file under a
// complete view adopts (never truncates) with zero base fetches.
func TestAdoptExistingFilePreservesContent(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.files["d/existing"] = []byte("keep")
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/trigger", 0o644, false, false); err != nil || !handled {
		t.Fatalf("trigger: %v %v", handled, err)
	}
	res, handled, err := e.Create(ctx, "d/existing", 0o644, false, false)
	mustHandled(t, "adopt create", handled, err)
	if res.Entry.Size != 4 {
		t.Fatalf("adopt lost the size: %+v", res.Entry)
	}
	// A clean adopted file has no dirty state: reads pass through.
	if _, handled, _ := e.ReadAt("d/existing", make([]byte, 4), 0, auth.baseReader("d/existing")); handled {
		t.Fatal("clean adopted file claimed a dirty read")
	}
	// A partial write composes over the (unhydrated) base.
	if _, handled, err := e.WriteAt(ctx, "d/existing", 0, []byte("X")); err != nil || !handled {
		t.Fatalf("adopted write: %v %v", handled, err)
	}
	dst := make([]byte, 8)
	n, handled, err := e.ReadAt("d/existing", dst, 0, auth.baseReader("d/existing"))
	if err != nil || !handled || string(dst[:n]) != "Xeep" {
		t.Fatalf("adopted read = %q handled=%v err=%v", dst[:n], handled, err)
	}
}

// TestWALRotationAndReclaim: segments rotate at the target size and fully
// applied unpinned segments are reclaimed after the APPLIED checkpoint.
func TestWALRotationAndReclaim(t *testing.T) {
	old := segmentTargetBytes
	segmentTargetBytes = 256 << 10
	defer func() { segmentTargetBytes = old }()

	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	e := testEngine(t, auth)
	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/log", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: %v %v", handled, err)
	}
	chunk := bytes.Repeat([]byte("r"), 64<<10)
	for i := 0; i < 40; i++ {
		if _, handled, err := e.WriteAt(ctx, "d/log", int64(i*len(chunk)), chunk); err != nil || !handled {
			t.Fatalf("write %d: %v %v", i, handled, err)
		}
	}
	e.mu.RLock()
	segs := len(e.wal.segments)
	activeOrdinal := e.wal.segments[len(e.wal.segments)-1].ordinal
	e.mu.RUnlock()
	if activeOrdinal < 3 {
		t.Fatalf("no rotation: active segment ordinal=%d live_segments=%d", activeOrdinal, segs)
	}
	if err := e.DrainAll(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	// Fold + reclaim under budget relief must shrink to the active segment.
	e.mu.Lock()
	e.relieveBudgetLocked()
	e.mu.Unlock()
	e.mu.RLock()
	segsAfter := len(e.wal.segments)
	e.mu.RUnlock()
	if segsAfter != 1 {
		t.Fatalf("reclaim kept %d segments, want 1 (active)", segsAfter)
	}
	// The folded regions read through the base (the authority owns them now).
	dst := make([]byte, len(chunk))
	n, handled, err := e.ReadAt("d/log", dst, 0, auth.baseReader("d/log"))
	if err != nil || !handled || n != len(chunk) || !bytes.Equal(dst[:n], chunk) {
		t.Fatalf("post-fold read: n=%d handled=%v err=%v", n, handled, err)
	}
}

// TestCheckpointFailureBlocksReclaim pins the unified APPLIED+reclaim
// contract: when the APPLIED checkpoint cannot be appended and synced, NO
// segment is deleted — reclaim is unreachable past a failed checkpoint.
func TestCheckpointFailureBlocksReclaim(t *testing.T) {
	old := segmentTargetBytes
	segmentTargetBytes = 1 << 10
	defer func() { segmentTargetBytes = old }()
	dir := t.TempDir()
	var mountID [16]byte
	copy(mountID[:], "ckpt-fail-test--")
	sd := filepath.Join(dir, streamDirName(1))
	w, err := createStreamWAL(sd, mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var lastSeq uint64
	for i := 0; i < 4; i++ {
		res, err := w.appendMutations([][]byte{canonicalPayload(mkRec(fmt.Sprintf("d/f%d", i), bytes.Repeat([]byte("x"), 512)))})
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		lastSeq = res[0].seq
	}
	if len(w.segments) < 2 {
		t.Fatal("precondition: rotation produced a second segment")
	}
	before, _ := filepath.Glob(filepath.Join(sd, "wb-*.pfw"))
	// Inject a durable-media failure: the APPLIED append cannot reach disk.
	w.mu.Lock()
	w.syncErr = errors.New("injected media failure")
	w.mu.Unlock()
	if err := w.CheckpointAndReclaim(lastSeq, [32]byte{}, func(uint64) bool { return false }); err == nil {
		t.Fatal("checkpoint with a failing sync must return the error")
	}
	after, _ := filepath.Glob(filepath.Join(sd, "wb-*.pfw"))
	if len(after) != len(before) {
		t.Fatalf("reclaim proceeded past a failed APPLIED checkpoint: %d segments -> %d", len(before), len(after))
	}
	w.mu.Lock()
	w.syncErr = nil
	w.mu.Unlock()
	_ = w.Close()
}

// TestReadPinsBlockReclaim: a composed read's extent snapshot pins its
// segments; checkpoint+reclaim skips them until the read releases.
func TestReadPinsBlockReclaim(t *testing.T) {
	old := segmentTargetBytes
	segmentTargetBytes = 1 << 10
	defer func() { segmentTargetBytes = old }()
	dir := t.TempDir()
	var mountID [16]byte
	copy(mountID[:], "read-pin-test---")
	sd := filepath.Join(dir, streamDirName(1))
	w, err := createStreamWAL(sd, mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var lastSeq uint64
	for i := 0; i < 4; i++ {
		res, err := w.appendMutations([][]byte{canonicalPayload(mkRec(fmt.Sprintf("d/f%d", i), bytes.Repeat([]byte("x"), 512)))})
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		lastSeq = res[0].seq
	}
	if len(w.segments) < 2 {
		t.Fatal("precondition: rotation produced a second segment")
	}
	first := w.segments[0].ordinal
	w.pinSegments([]uint64{first})
	if err := w.CheckpointAndReclaim(lastSeq, [32]byte{}, func(uint64) bool { return false }); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if _, err := os.Stat(segmentPath(sd, first)); err != nil {
		t.Fatalf("read-pinned segment was reclaimed: %v", err)
	}
	w.unpinSegments([]uint64{first})
	if err := w.CheckpointAndReclaim(lastSeq, [32]byte{}, func(uint64) bool { return false }); err != nil {
		t.Fatalf("checkpoint after unpin: %v", err)
	}
	if _, err := os.Stat(segmentPath(sd, first)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("released segment survived reclaim: %v", err)
	}
	_ = w.Close()
}

// TestTornTailTruncates: a PHYSICALLY SHORT final frame (torn append) is
// discarded whole; the intact prefix recovers.
func TestTornTailTruncates(t *testing.T) {
	dir := t.TempDir()
	var mountID [16]byte
	copy(mountID[:], "torn-tail-test--")
	w, err := createStreamWAL(filepath.Join(dir, streamDirName(1)), mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	recA := canonicalPayload(mkRec("d/a", []byte("aaaa")))
	recB := canonicalPayload(mkRec("d/b", []byte("bbbb")))
	if _, err := w.appendMutations([][]byte{recA, recB}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	segPath := segmentPath(filepath.Join(dir, streamDirName(1)), 1)
	info, err := os.Stat(segPath)
	if err != nil {
		t.Fatal(err)
	}
	// Tear the last frame mid-payload.
	if err := os.Truncate(segPath, info.Size()-int64(len(recB))/2); err != nil {
		t.Fatal(err)
	}
	scan, err := scanStream(filepath.Join(dir, streamDirName(1)))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !scan.truncated || scan.lastSeq != 1 {
		t.Fatalf("torn tail: truncated=%v lastSeq=%d, want truncated with seq 1", scan.truncated, scan.lastSeq)
	}
}

// TestCorruptCompleteFinalFrameFailsClosed pins the strict scanner rule: a
// COMPLETE final frame with a bad payload CRC is corruption, never a torn
// tail — the frame may be an acknowledged mutation, so silently truncating
// it would drop acked data. Only physical shortage at EOF truncates.
func TestCorruptCompleteFinalFrameFailsClosed(t *testing.T) {
	dir := t.TempDir()
	var mountID [16]byte
	copy(mountID[:], "crc-final-test--")
	sd := filepath.Join(dir, streamDirName(1))
	w, err := createStreamWAL(sd, mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	res, err := w.appendMutations([][]byte{
		canonicalPayload(mkRec("d/a", []byte("aaaa"))),
		canonicalPayload(mkRec("d/b", []byte("bbbb"))),
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	segPath := segmentPath(sd, 1)
	f, err := os.OpenFile(segPath, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	// Flip one payload byte of the FINAL frame; its length is intact.
	if _, err := f.WriteAt([]byte{0xFF}, res[1].payloadOff); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := scanStream(sd); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("complete-but-corrupt final frame scanned as %v, want ErrCorrupt", err)
	}
}

// TestMalformedControlPayloadFailsClosed: a control frame whose CRC-valid
// payload does not decode is corruption (the writer wrote garbage), never a
// silently dropped grant/checkpoint.
func TestMalformedControlPayloadFailsClosed(t *testing.T) {
	dir := t.TempDir()
	var mountID [16]byte
	copy(mountID[:], "ctl-payload-test")
	sd := filepath.Join(dir, streamDirName(1))
	w, err := createStreamWAL(sd, mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := w.appendControl(frameDelegation, map[string]any{"bogus": true}); err != nil {
		t.Fatalf("append control: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	scan, err := scanStream(sd)
	if err != nil {
		t.Fatalf("scan (frames are CRC-intact): %v", err)
	}
	if _, _, _, _, derr := decodeStreamFrames(scan.frames); !errors.Is(derr, ErrCorrupt) {
		t.Fatalf("malformed DELEGATION payload decoded as %v, want ErrCorrupt", derr)
	}
}

// TestSegmentIdentityContinuityFailsClosed: a segment whose header names a
// different volume/branch than its predecessor is corruption.
func TestSegmentIdentityContinuityFailsClosed(t *testing.T) {
	old := segmentTargetBytes
	segmentTargetBytes = 1 << 10 // force rotation quickly
	defer func() { segmentTargetBytes = old }()
	dir := t.TempDir()
	var mountID [16]byte
	copy(mountID[:], "seg-ident-test--")
	sd := filepath.Join(dir, streamDirName(1))
	w, err := createStreamWAL(sd, mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for i := 0; i < 4; i++ {
		if _, err := w.appendMutations([][]byte{canonicalPayload(mkRec(fmt.Sprintf("d/f%d", i), bytes.Repeat([]byte("x"), 512)))}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if len(w.segments) < 2 {
		t.Fatal("precondition: rotation produced a second segment")
	}
	second := w.segments[1]
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Rewrite segment 2's header with a different branch (valid CRC).
	h := second.header
	h.Branch = "other"
	buf, err := encodeSegmentHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(second.path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(buf, 0); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := scanStream(sd); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("branch-mismatched segment chain scanned as %v, want ErrCorrupt", err)
	}
}

// TestMidLogCorruptionFailsClosed: a damaged frame followed by intact frames
// must never be scanned past.
func TestMidLogCorruptionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	var mountID [16]byte
	copy(mountID[:], "corruption-test-")
	sd := filepath.Join(dir, streamDirName(1))
	w, err := createStreamWAL(sd, mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var firstPayloadOff int64
	for i := 0; i < 3; i++ {
		res, err := w.appendMutations([][]byte{canonicalPayload(mkRec(fmt.Sprintf("d/f%d", i), bytes.Repeat([]byte("x"), 64)))})
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		if i == 0 {
			firstPayloadOff = res[0].payloadOff
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	segPath := segmentPath(sd, 1)
	f, err := os.OpenFile(segPath, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{0xFF, 0xFF, 0xFF, 0xFF}, firstPayloadOff); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := scanStream(sd); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("mid-log corruption scanned as %v, want ErrCorrupt", err)
	}
}

func mkRec(path string, data []byte) wal.Record {
	return wal.Record{Op: wal.OpWrite, Path: path, Data: data}
}
