package fsproto

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// TestUnmarkOpenBatchReachesADefiniteOutcome is the round-4 force-dump
// reproduction of ledger §10's silent wedge.
//
// LIVE SHAPE: on an otherwise IDLE, HEALTHY attach, one batched open-pin
// release sat inside unmarkOpenBatchManaged for 33+ MINUTES. Its retry loop had
// no exit but a session fence or client teardown, and the open registry holds
// its per-inode pending barrier across the whole call — so every frontend open,
// close and name change on those inodes queued behind it (~250 goroutines in
// the dump), each holding the volume's lifecycle lock shared, and
// `umount --force` — which needs that lock exclusively — queued behind THEM.
// No verdict was recorded anywhere: a silent wedge.
//
// The contract: this call reaches a DEFINITE outcome, bounded. It may succeed,
// it may answer ESTALE by resolving the sent identity through a session fence
// (the only resolution a sent-but-unanswered exact identity may take without
// being backgrounded, see unmarkOpenBatchManaged), but it may never wait
// without bound.
func TestUnmarkOpenBatchReachesADefiniteOutcome(t *testing.T) {
	restore := unmarkResolveBudget
	unmarkResolveBudget = 750 * time.Millisecond
	t.Cleanup(func() { unmarkResolveBudget = restore })

	_, fs, upstream := startPipeAuthority(t)
	_ = fs

	// A relay in front of the real authority. Requests ALWAYS reach it, so
	// every identity this test issues is provably SENT; once `dead` flips, the
	// REPLY direction is cut and the connection dropped right after the
	// request lands. That is the exact state the loop under test has no other
	// exit from: sent, unanswered, and the peer gone.
	var dead atomic.Bool
	dial := func() (net.Conn, error) {
		client, relay := net.Pipe()
		server, err := upstream()
		if err != nil {
			return nil, err
		}
		go func() {
			defer func() { _ = relay.Close() }()
			defer func() { _ = server.Close() }()
			buf := make([]byte, 32<<10)
			for {
				n, rerr := relay.Read(buf)
				if n > 0 {
					if _, werr := server.Write(buf[:n]); werr != nil {
						return
					}
					if dead.Load() {
						// Delivered, then the peer disappears.
						return
					}
				}
				if rerr != nil {
					return
				}
			}
		}()
		go func() {
			defer func() { _ = relay.Close() }()
			defer func() { _ = server.Close() }()
			buf := make([]byte, 32<<10)
			for {
				n, rerr := server.Read(buf)
				if n > 0 && !dead.Load() {
					if _, werr := relay.Write(buf[:n]); werr != nil {
						return
					}
				}
				if rerr != nil {
					return
				}
			}
		}()
		return client, nil
	}

	c := pipeClient(t, dial, "M-unmark-bounded")
	if live, err := c.EnsureExactSession(); err != nil || !live {
		t.Fatalf("session: live=%v err=%v", live, err)
	}
	if _, st, err := c.Create("pinned.txt", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	attr, st, err := c.Getattr("pinned.txt")
	if err != nil || st != OK || attr == nil {
		t.Fatalf("getattr: st=%d err=%v", st, err)
	}
	if st, err := c.MarkOpenManaged(attr.Ino, true); err != nil || st != OK {
		t.Fatalf("mark open: st=%d err=%v", st, err)
	}

	// No pool reset: the request must go out on the ALREADY-ATTACHED
	// connection, so it is provably SENT before the peer disappears.
	dead.Store(true)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.UnmarkOpenBatch([]uint64{attr.Ino})
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal(
			"UnmarkOpenBatch never reached an outcome against an authority " +
				"that stopped answering: it holds the open registry's per-inode " +
				"barrier for the whole call, so every later open/close on those " +
				"inodes — and force-detach behind them — waits with it",
		)
	}
}
