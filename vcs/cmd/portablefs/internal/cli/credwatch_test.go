package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// watchHarness wires a credentialWatch to a log buffer and a real mount-state
// file, the exact production wiring of runMountForeground.
func watchHarness(t *testing.T) (*credentialWatch, *bytes.Buffer, string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	mountPath := "/tmp/watch-mount"
	if err := writeMountState(dir, validFuseMountState(t, mountPath)); err != nil {
		t.Fatal(err)
	}
	logBuf := &bytes.Buffer{}
	w := newCredentialWatch(
		func(format string, args ...any) { fmt.Fprintf(logBuf, format+"\n", args...) },
		func(status string, atMs int64) { setMountStatus(dir, mountPath, status, atMs) },
	)
	return w, logBuf, dir, mountPath
}

// TestLeaseKeeperMarksCredentialExpiredOnRevocation simulates a key
// revocation end-to-end at the keeper: the renew answers a typed terminal
// refusal. The watch must log exactly once, flip the persisted mount status,
// and the keeper must stop without any create/recovery path.
func TestLeaseKeeperMarksCredentialExpiredOnRevocation(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/renew", func(map[string]any) (int, string) {
		return 401, `{"error":{"code":"ACCESS_LEASE_UNAUTHORIZED","message":"Access lease credentials rejected."}}`
	})
	w, logBuf, stateDir, mountPath := watchHarness(t)
	m := newManagerClient(f.srv.URL, "mgr_tok")
	k := newLeaseKeeper(m, &sessionTokenSource{}, leaseState{
		AccessLeaseID: "pfal_1", AccessToken: "tok", ExpiresAtMs: 1, ControlSeq: "1",
	}, nil)
	k.credWatch = w

	k.renewOnce(context.Background())
	st, err := readMountState(stateDir, mountPath)
	if err != nil || st == nil {
		t.Fatalf("read state: %v %v", st, err)
	}
	if st.Status != mountStatusCredentialExpired || st.StatusChangedAtMs == 0 {
		t.Fatalf("state must record the credential expiry: %+v", st)
	}
	if got := strings.Count(logBuf.String(), "credentials revoked or expired"); got != 1 {
		t.Fatalf("revocation must log exactly once, got %d: %q", got, logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "portablefs login") {
		t.Fatalf("the log line must say what to do: %q", logBuf.String())
	}

	// A terminal keeper never ticks again.
	k.renewOnce(context.Background())
	k.renewOnce(context.Background())
	if got := strings.Count(logBuf.String(), "credentials revoked or expired"); got != 1 {
		t.Fatalf("repeat rejections must not re-log, got %d: %q", got, logBuf.String())
	}

}

// TestLeaseKeeperExpiredIsVisible verifies that terminal expiry is surfaced
// directly; there is no re-acquire whose outcome could hide it.
func TestLeaseKeeperExpiredIsVisible(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/renew", func(map[string]any) (int, string) {
		return 410, `{"error":{"code":"ACCESS_LEASE_EXPIRED","message":"lease expired"}}`
	})
	w, logBuf, stateDir, mountPath := watchHarness(t)
	m := newManagerClient(f.srv.URL, "mgr_tok")
	k := newLeaseKeeper(m, &sessionTokenSource{}, leaseState{
		AccessLeaseID: "pfal_1", AccessToken: "tok", ExpiresAtMs: 1, ControlSeq: "1",
	}, nil)
	k.credWatch = w

	k.renewOnce(context.Background())
	st, _ := readMountState(stateDir, mountPath)
	if st.Status != mountStatusCredentialExpired {
		t.Fatalf("terminal expiry must be visible: %+v", st)
	}
	if !strings.Contains(logBuf.String(), "credentials revoked or expired") {
		t.Fatalf("terminal expiry must be logged: %q", logBuf.String())
	}
}

// ── THE CREDENTIAL HANDOFF TO portablefsd ───────────────────────────────────
//
// The push used to be one fire-and-forget line whose error went to stderr and
// was dropped, run AFTER the keeper had committed the lease. These pin the
// three properties that replaced it: it retries, it does not block the keeper,
// and an undelivered credential ends in a reported definite failure rather than
// in silence.

// handoffRecord collects what the handoff reported, guarded because the loop
// runs on its own goroutine.
type handoffRecord struct {
	mu       sync.Mutex
	log      bytes.Buffer
	failures []error
}

func (r *handoffRecord) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintf(&r.log, format+"\n", args...)
}

func (r *handoffRecord) failed(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = append(r.failures, err)
}

func (r *handoffRecord) logged() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.log.String()
}

func (r *handoffRecord) failureCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.failures)
}

// handoffHarness builds a handoff whose retry pacing is injected, so nothing
// here waits on the wall clock.
func handoffHarness(t *testing.T, push func(leaseState) error) (*credentialHandoff, *handoffRecord) {
	t.Helper()
	rec := &handoffRecord{}
	h := newCredentialHandoff(push, rec.logf, rec.failed)
	// Retry pacing is not the property under test; fire immediately.
	h.after = func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}
	return h, rec
}

// TestCredentialHandoffRetriesUntilTheDaemonAcknowledges is the defect stated
// directly: a push that fails must not be dropped. Pre-fix the daemon simply
// never received this credential and every layer above believed it had.
func TestCredentialHandoffRetriesUntilTheDaemonAcknowledges(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	delivered := make(chan leaseState, 1)
	h, rec := handoffHarness(t, func(l leaseState) error {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n < 4 {
			// The production shape of this failure: the daemon's control
			// request queues behind a registry mutation and times out.
			return fmt.Errorf("push credential: control request timed out")
		}
		delivered <- l
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.run(ctx)

	lease := leaseState{AccessLeaseID: "pfal_1", AccessToken: "tok2", ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli()}
	h.deliver(lease)

	select {
	case got := <-delivered:
		if got.AccessToken != "tok2" {
			t.Fatalf("delivered the wrong credential: %+v", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the credential was never delivered to portablefsd.\n" +
			"A push that fails must be retried until the daemon acknowledges it: a daemon " +
			"holding a superseded token is a mount that will be fenced by a REACHABLE " +
			"authority with its backlog stranded.")
	}
	mu.Lock()
	got := attempts
	mu.Unlock()
	if got < 4 {
		t.Fatalf("expected the handoff to retry, saw %d attempts", got)
	}
	if rec.failureCount() != 0 {
		t.Fatalf("a delivery that eventually succeeded must not report failure: %v", rec.logged())
	}
}

// TestCredentialHandoffNeverBlocksTheKeeper pins the other half: delivering a
// credential must not wait on the daemon. The lease keeper's renewal path
// queuing behind data-plane work is the disease, not the cure.
func TestCredentialHandoffNeverBlocksTheKeeper(t *testing.T) {
	release := make(chan struct{})
	h, _ := handoffHarness(t, func(leaseState) error {
		<-release
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.run(ctx)
	defer close(release)

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.deliver(leaseState{AccessLeaseID: "pfal_1", AccessToken: "t", ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli()})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deliver blocked on the daemon; the keeper must never wait on data-plane work")
	}
}

// TestCredentialHandoffFailsDefinitelyAtTheCredentialsOwnExpiry pins the bound
// and the outcome. The replay is bounded by the credential's OWN expiry — the
// same house rule renewal and release follow — and reaching it is a DEFINITE,
// reported failure, never a silent one.
func TestCredentialHandoffFailsDefinitelyAtTheCredentialsOwnExpiry(t *testing.T) {
	h, rec := handoffHarness(t, func(leaseState) error {
		return fmt.Errorf("push credential: control request timed out")
	})
	// The credential is already past its own expiry: redelivering it cannot
	// help anyone.
	expired := leaseState{AccessLeaseID: "pfal_dead", AccessToken: "t", ExpiresAtMs: time.Now().Add(-time.Minute).UnixMilli()}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); h.run(ctx) }()
	h.deliver(expired)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if rec.failureCount() > 0 && !h.outstanding() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if rec.failureCount() == 0 {
		t.Fatal("an undelivered credential that reached its own expiry reported nothing.\n" +
			"A handoff that cannot complete must reach a DEFINITE failure with a truthful " +
			"status, not retry forever in silence.")
	}
	if !strings.Contains(rec.logged(), "FAILED definitively") {
		t.Fatalf("the definite failure must be logged: %q", rec.logged())
	}
	if h.outstanding() {
		t.Fatal("a definitely failed credential must not stay outstanding forever")
	}
}

// TestMountsShowsCredentialExpired pins the operator surface: a running
// daemon whose credentials were revoked renders credential-expired with the
// remediation, not "live"; JSON carries the same fields.
func TestMountsShowsCredentialExpired(t *testing.T) {
	e, stdout, _ := testEnv(t)
	e.mountHealthFn = func(st *mountState) string {
		if st.Status == mountStatusCredentialExpired {
			return mountStatusCredentialExpired
		}
		return "live"
	}
	stateHome := t.TempDir()
	baseGetenv := e.getenv
	e.getenv = func(k string) string {
		if k == "XDG_STATE_HOME" {
			return stateHome
		}
		return baseGetenv(k)
	}
	dir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	st := validFuseMountState(t, "/tmp/w1")
	st.VolumeID = "vol_revoked"
	st.Status = mountStatusCredentialExpired
	st.StatusChangedAtMs = 1700000000000
	if err := writeMountState(dir, st); err != nil {
		t.Fatal(err)
	}
	if rc := e.run([]string{"mounts"}); rc != 0 {
		t.Fatalf("mounts rc = %d", rc)
	}
	out := stdout.String()
	if !strings.Contains(out, "credential-expired") || !strings.Contains(out, "portablefs login") {
		t.Fatalf("mounts must render the degraded status with remediation: %q", out)
	}
	if strings.Contains(out, "  live") {
		t.Fatalf("a credential-expired mount must not be reported live: %q", out)
	}

	stdout.Reset()
	if rc := e.run([]string{"mounts", "--json"}); rc != 0 {
		t.Fatal("mounts --json failed")
	}
	if !strings.Contains(stdout.String(), `"status": "credential-expired"`) || !strings.Contains(stdout.String(), `"health": "credential-expired"`) {
		t.Fatalf("mounts --json must carry the status fields: %q", stdout.String())
	}
}
