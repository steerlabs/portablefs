package fsproto

// ── ROUND 16, DEFECT B: THE LEASE WAS QUEUED BEHIND THE DATA PLANE ──────────
//
// Live: 768 MiB written unpaced at 110 MB/s had write(2) succeed for every byte
// while the daemon's write-back telemetry stayed flat at zero (the file was on
// the uncharged authority lane, so nothing paced it), and then close(2) returned
// ESTALE with only 34 MiB durable. The session had been fenced: the renewal ran
// through the SHARED four-connection pool, the burst held every connection for
// up to a 60-second operation timeout, the 90-second lease lapsed, and the
// authority swept the session terminal.
//
// The renewal now holds a reserved transport of its own. This test is the
// property, stated as bluntly as it can be: with the entire pool held, the lease
// still renews.

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// TestSessionLeaseRenewsWithTheWholePoolHeld pins that no amount of data-plane
// traffic can queue in front of the one call that keeps the mount alive.
//
// Every pooled connection is checked out and never given back — which is exactly
// what a burst of concurrent write-through mutations does, each holding its
// connection for up to opTimeout. The pre-fix renewal went through doRaw ->
// takeConn, an unbounded blocking receive on that same pool, so it simply never
// ran again and the lease died of silence.
func TestSessionLeaseRenewsWithTheWholePoolHeld(t *testing.T) {
	const pool = 4

	fs := newManagedWorkFS(t, nil, nopBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := NewServer(fs, fs)
	go func() { _ = srv.Serve(ctx, ln) }()

	cli, err := Dial(ln.Addr().String(), pool)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()
	if live, err := cli.EnsureExactSession(); err != nil || !live {
		t.Fatalf("establish session: live=%v err=%v", live, err)
	}
	es := cli.exactState()
	if es == nil {
		t.Fatal("no exact session after establish")
	}

	// The data plane takes the whole pool and keeps it. Nothing gives these back.
	held := make([]*conn, 0, pool)
	for i := 0; i < pool; i++ {
		cn, err := cli.takeConn()
		if err != nil {
			t.Fatalf("taking pooled conn %d: %v", i, err)
		}
		held = append(held, cn)
	}
	defer func() {
		for _, cn := range held {
			cli.conns <- cn
		}
	}()

	done := make(chan bool, 1)
	go func() { done <- cli.renewOnce(es, 5*time.Second) }()
	select {
	case fenced := <-done:
		if fenced {
			t.Fatal("the lease renewal fenced the session")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the session lease renewal never completed while the connection " +
			"pool was held by the data plane.\n" +
			"A write burst therefore starves the lease past its TTL, the authority " +
			"sweeps the session terminal, and the mount is fenced with acknowledged " +
			"data still in the kernel's dirty pages.")
	}
	if es.isFenced() {
		t.Fatal("the session was fenced by a successful renewal")
	}
}

// TestSessionLeaseTransportIsReservedAndReleased pins the reservation itself:
// the renewal's transport is dedicated (never handed back to the pool, so it can
// never be taken by a mutation) and it is retired on release.
func TestSessionLeaseTransportIsReservedAndReleased(t *testing.T) {
	const pool = 2

	fs := newManagedWorkFS(t, nil, nopBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := NewServer(fs, fs)
	go func() { _ = srv.Serve(ctx, ln) }()

	cli, err := Dial(ln.Addr().String(), pool)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()

	cn, err := cli.leaseConn()
	if err != nil {
		t.Fatalf("dialing the reserved lease transport: %v", err)
	}
	if cn == nil {
		t.Fatal("the reserved lease transport is nil")
	}
	again, err := cli.leaseConn()
	if err != nil || again != cn {
		t.Fatalf("leaseConn dialed a second transport: %v %v", again, err)
	}
	cli.lifecycleMu.Lock()
	_, dedicated := cli.dedicated[cn]
	cli.lifecycleMu.Unlock()
	if !dedicated {
		t.Fatal("the lease transport is not registered as dedicated: the client's " +
			"close would neither interrupt nor join it")
	}
	if len(cli.conns) != pool {
		t.Fatalf("the reserved lease transport came out of the pool: %d/%d idle",
			len(cli.conns), pool)
	}

	cli.releaseLeaseConn()
	cli.lifecycleMu.Lock()
	_, stillDedicated := cli.dedicated[cn]
	cli.lifecycleMu.Unlock()
	if stillDedicated {
		t.Fatal("releasing the lease transport left it registered")
	}
	if len(cli.conns) != pool {
		t.Fatalf("releasing the lease transport changed the pool: %d/%d idle",
			len(cli.conns), pool)
	}
}
