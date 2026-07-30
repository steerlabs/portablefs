package fsproto

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/metrics"
)

// TestOpNamesCoverEverySequentialOp guards the per-op counter map against new
// ops silently landing in vcs_fsproto_op_other: every op in the sequential
// block (plus the out-of-band version probe) must have a stable name.
func TestOpNamesCoverEverySequentialOp(t *testing.T) {
	for op := OpGetattr; op <= OpDelegationPrepareRelease; op++ {
		if _, ok := opNames[op]; !ok {
			t.Errorf("op %d has no counter name; add it to opNames", op)
		}
	}
	if _, ok := opNames[OpProtocolVersion]; !ok {
		t.Error("OpProtocolVersion has no counter name")
	}
}

func TestAbortDoesNotExpireAuthoritySession(t *testing.T) {
	fs := newManagedWorkFS(t, nil, nopBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = NewServer(fs, fs).Serve(ctx, ln) }()
	cli, err := Dial(ln.Addr().String(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if live, err := cli.EnsureExactSession(); err != nil || !live {
		t.Fatalf("establish session: live=%v err=%v", live, err)
	}
	before := counterValue("vcs_fsproto_op_session_expire")
	if err := cli.Abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if got := counterValue("vcs_fsproto_op_session_expire") - before; got != 0 {
		t.Fatalf("local abort sent %d session-expire operations", got)
	}
}

func TestAbortClosesDedicatedSubscriptionWithoutAuthorityCleanup(t *testing.T) {
	fs := newManagedWorkFS(t, nil, nopBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := NewServer(fs, fs)
	go func() { _ = srv.Serve(ctx, ln) }()
	cli, err := Dial(ln.Addr().String(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if live, err := cli.EnsureExactSession(); err != nil || !live {
		t.Fatalf("establish session: live=%v err=%v", live, err)
	}
	stream, _, err := cli.Subscribe()
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	select {
	case _, ok := <-stream:
		if !ok {
			t.Fatal("subscription closed before bootstrap")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("subscription did not deliver bootstrap")
	}

	expireBefore := counterValue("vcs_fsproto_op_session_expire")
	subscribeBefore := counterValue("vcs_fsproto_op_subscribe")
	abortDone := make(chan error, 1)
	go func() { abortDone <- cli.Abort() }()
	select {
	case err := <-abortDone:
		if err != nil {
			t.Fatalf("abort: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("abort did not interrupt and join the dedicated subscription")
	}

	streamClosed := false
	deadline := time.After(2 * time.Second)
	for !streamClosed {
		select {
		case _, ok := <-stream:
			streamClosed = !ok
		case <-deadline:
			t.Fatal("subscription channel remained open after abort")
		}
	}
	if _, _, err := cli.Subscribe(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("subscribe after abort error = %v, want net.ErrClosed", err)
	}
	if got := counterValue("vcs_fsproto_op_session_expire") - expireBefore; got != 0 {
		t.Fatalf("abort sent %d session-expire operations", got)
	}
	if got := counterValue("vcs_fsproto_op_subscribe") - subscribeBefore; got != 0 {
		t.Fatalf("subscribe after abort sent %d authority operations", got)
	}

	subDeadline := time.Now().Add(2 * time.Second)
	for {
		srv.subMu.Lock()
		n := len(srv.subscribers)
		srv.subMu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(subDeadline) {
			t.Fatalf("authority retained %d subscriber(s) after transport abort", n)
		}
		time.Sleep(time.Millisecond)
	}
}

func counterValue(name string) int64 {
	snap := metrics.Default.Snapshot()
	counters, _ := snap["counters"].(map[string]int64)
	return counters[name]
}

// TestCountOpAttributesKnownAndUnknownOps: countOp bumps the op's own counter,
// and an op outside the map lands in vcs_fsproto_op_other.
func TestCountOpAttributesKnownAndUnknownOps(t *testing.T) {
	mkdirBefore := counterValue("vcs_fsproto_op_mkdir")
	otherBefore := counterValue("vcs_fsproto_op_other")
	countOp(OpMkdir)
	countOp(Op(199)) // not a defined op
	if got := counterValue("vcs_fsproto_op_mkdir") - mkdirBefore; got != 1 {
		t.Fatalf("mkdir counter delta = %d, want 1", got)
	}
	if got := counterValue("vcs_fsproto_op_other") - otherBefore; got != 1 {
		t.Fatalf("other counter delta = %d, want 1", got)
	}
}

// TestServeCountsPerOp proves the wiring: ops served over a real connection land
// in their per-op counters (the benchmark harness reads these to attribute a
// workload's round-trips).
func TestServeCountsPerOp(t *testing.T) {
	fs := newManagedWorkFS(t, nil, nopBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = NewServer(fs, fs).Serve(ctx, ln) }()
	cli, err := Dial(ln.Addr().String(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	mkdirBefore := counterValue("vcs_fsproto_op_mkdir")
	getattrBefore := counterValue("vcs_fsproto_op_getattr")
	readdirBefore := counterValue("vcs_fsproto_op_readdir")

	if _, st, err := cli.Mkdir("d", 0o755); err != nil || st != OK {
		t.Fatalf("mkdir: st=%d err=%v", st, err)
	}
	if _, st, err := cli.Getattr("d"); err != nil || st != OK {
		t.Fatalf("getattr: st=%d err=%v", st, err)
	}
	if _, _, st, err := cli.Readdir(""); err != nil || st != OK {
		t.Fatalf("readdir: st=%d err=%v", st, err)
	}

	for _, c := range []struct {
		name   string
		before int64
	}{
		{"vcs_fsproto_op_mkdir", mkdirBefore},
		{"vcs_fsproto_op_getattr", getattrBefore},
		{"vcs_fsproto_op_readdir", readdirBefore},
	} {
		if got := counterValue(c.name) - c.before; got != 1 {
			t.Fatalf("%s delta = %d, want 1", c.name, got)
		}
	}
}
