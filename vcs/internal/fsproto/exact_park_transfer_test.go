package fsproto

// Park-transfer contract (the data-integrity window at the protocol layer).
//
// An exact mutation whose transport dies after a possible send parks its
// identity for background replay and returns ErrMutationUnknown. The identity
// may execute minutes later, so the exclusion state the caller issued it under
// must NOT be released to anyone else until that identity is definite. These
// tests pin the three definite ends — an authority reply, a session fence, and
// client teardown — and that the release fires exactly once on each.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// parkTransferProbe is a test stand-in for clientcore's exclusion owner.
type parkTransferProbe struct {
	acquires atomic.Int64
	releases atomic.Int64
}

func (p *parkTransferProbe) ctx() context.Context {
	return WithParkTransfer(context.Background(), func() func() {
		p.acquires.Add(1)
		return func() { p.releases.Add(1) }
	})
}

func (p *parkTransferProbe) awaitRelease(t *testing.T, within time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if p.releases.Load() >= 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: transferred exclusion was never released (acquires=%d)", what, p.acquires.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (p *parkTransferProbe) assertExactlyOnce(t *testing.T) {
	t.Helper()
	// Give any second (buggy) release a window to appear.
	time.Sleep(200 * time.Millisecond)
	if got := p.acquires.Load(); got != 1 {
		t.Fatalf("park acquired the exclusion %d times, want 1", got)
	}
	if got := p.releases.Load(); got != 1 {
		t.Fatalf("transferred exclusion released %d times, want exactly 1", got)
	}
}

// parkOneWrite parks a write identity by losing every reply while blocked is
// true. It returns the probe whose release the park now owns.
func parkOneWrite(t *testing.T, h *exactHarness, cli *Client, path string, blocked *atomic.Bool) *parkTransferProbe {
	t.Helper()
	blocked.Store(true)
	h.setDrop(func(req *Request, _ *Response) bool {
		return req.Op == OpWrite && req.Path == path && blocked.Load()
	})
	probe := &parkTransferProbe{}
	if _, _, _, _, err := cli.WriteVHandleContext(
		probe.ctx(), path, 0, 0, []byte("x"), 0o644,
	); !errors.Is(err, ErrMutationUnknown) {
		t.Fatalf("write with every reply lost: err=%v, want ErrMutationUnknown", err)
	}
	if got := probe.acquires.Load(); got != 1 {
		t.Fatalf("park took the caller's exclusion %d times, want 1", got)
	}
	if got := probe.releases.Load(); got != 0 {
		t.Fatalf("parked identity released the caller's exclusion %d times before any definite outcome", got)
	}
	return probe
}

// A parked identity keeps the caller's exclusion until the authority answers,
// then releases it exactly once.
func TestParkedIdentityHoldsTransferredExclusionUntilDefiniteReply(t *testing.T) {
	h := serveExact(t)
	cli := dialExact(t, h.addr, "M-park-transfer")
	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}

	var blocked atomic.Bool
	probe := parkOneWrite(t, h, cli, "f", &blocked)

	// While the outcome is unknown the exclusion stays owned by the park.
	time.Sleep(500 * time.Millisecond)
	if got := probe.releases.Load(); got != 0 {
		t.Fatalf("exclusion released %d times while the identity was still parked", got)
	}

	blocked.Store(false)
	probe.awaitRelease(t, 30*time.Second, "definite reply")
	probe.assertExactlyOnce(t)

	deadline := time.Now().Add(10 * time.Second)
	for {
		if data, st, _ := cli.Read("f", 0, 16); st == OK && string(data) == "x" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("parked identity released its exclusion without landing")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A fence is a definite outcome: the generation can never execute, so the
// parked identity hands the exclusion back — exactly once.
func TestFencedParkReleasesTransferredExclusionExactlyOnce(t *testing.T) {
	h := serveExact(t)
	cli := dialExact(t, h.addr, "M-park-fence")
	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}

	var blocked atomic.Bool
	probe := parkOneWrite(t, h, cli, "f", &blocked)
	defer blocked.Store(false)

	// Fence the mount session (clean unmount / lease loss shape). The identity
	// never resolves against the authority, but its generation is terminal.
	cli.ExpireSession()
	if !cli.SessionFenced() {
		t.Fatal("ExpireSession did not fence the session")
	}
	probe.awaitRelease(t, 30*time.Second, "session fence")
	probe.assertExactlyOnce(t)
}

// Client teardown must not strand a transferred exclusion: Close fences the
// session and JOINS the replayers, so the release has already happened by the
// time Close returns.
func TestClientCloseDuringParkReleasesTransferredExclusionBeforeReturning(t *testing.T) {
	h := serveExact(t)
	cli := dialExact(t, h.addr, "M-park-close")
	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}

	var blocked atomic.Bool
	probe := parkOneWrite(t, h, cli, "f", &blocked)
	defer blocked.Store(false)

	done := make(chan error, 1)
	go func() { done <- cli.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("close during park: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Close hung while an identity was parked")
	}
	if got := probe.releases.Load(); got != 1 {
		t.Fatalf("Close returned with the transferred exclusion released %d times, want 1 (orphaned claim)", got)
	}
	probe.assertExactlyOnce(t)
}

// A park issued after teardown must release inline: its replayer would never
// run, so holding the exclusion would strand it forever.
func TestParkAfterCloseReleasesTransferredExclusionInline(t *testing.T) {
	h := serveExact(t)
	cli := dialExact(t, h.addr, "M-park-post-close")
	if _, err := cli.EnsureExactSession(); err != nil {
		t.Fatalf("session: %v", err)
	}
	es := cli.exactState()
	slot, seq, err := es.acquire(time.Second)
	if err != nil {
		t.Fatalf("acquire slot: %v", err)
	}
	if err := cli.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	probe := &parkTransferProbe{}
	cli.parkExact(probe.ctx(), es, slot, seq, &Request{
		Op: OpWrite, Path: "f", Env: es.envelope(slot, seq),
	})
	if probe.acquires.Load() != 1 || probe.releases.Load() != 1 {
		t.Fatalf("post-close park: acquires=%d releases=%d, want 1/1",
			probe.acquires.Load(), probe.releases.Load())
	}
}

// No hook installed (FUSE/benchmount direct callers): parking must behave
// exactly as before — nothing to transfer, nothing retained.
func TestParkWithoutTransferHookIsUnchanged(t *testing.T) {
	h := serveExact(t)
	cli := dialExact(t, h.addr, "M-park-no-hook")
	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	var drops atomic.Int32
	drops.Store(int32(exactForegroundAttempts))
	h.setDrop(func(req *Request, _ *Response) bool {
		return req.Op == OpWrite && string(req.Data) == "x" && drops.Add(-1) >= 0
	})
	if _, _, _, _, err := cli.WriteV("f", 0, []byte("x"), 0o644); !errors.Is(err, ErrMutationUnknown) {
		t.Fatalf("write with all replies lost: err=%v, want ErrMutationUnknown", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if data, st, _ := cli.Read("f", 0, 16); st == OK && string(data) == "x" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("hookless park never landed its identity")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
