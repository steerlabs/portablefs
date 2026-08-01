package fsproto

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestIndependentReadsUseTheWholePool pins that the connection pool is not a
// serialization point: N independent reads issued concurrently are IN FLIGHT
// simultaneously, up to the pool size.
//
// It exists because a serial syscall trace looks exactly like a serialized
// transport — one round trip at a time, four idle connections — and the two have
// opposite fixes. This test settles which one the client is: the pool hands out
// a connection per in-flight request (a buffered channel of conns), so a serial
// trace is a serial CALLER, and the only way to make that trace faster is to
// need fewer round trips, not to dispatch the same ones differently.
//
// The reply hook blocks each read after it has been dispatched and before its
// response is written, which is precisely the in-flight window. If the pool
// admitted one request at a time, only the first would ever arrive and the
// barrier below would never open.
func TestIndependentReadsUseTheWholePool(t *testing.T) {
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

	var (
		inFlight atomic.Int64
		peak     atomic.Int64
		arrived  = make(chan struct{}, pool)
		release  = make(chan struct{})
	)
	srv.SetDropReply(func(req *Request, _ *Response) bool {
		if req.Op != OpGetattr {
			return false
		}
		n := inFlight.Add(1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-release
		inFlight.Add(-1)
		return false // never actually drop; this hook is only a barrier here
	})

	var wg sync.WaitGroup
	for i := 0; i < pool; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct absent paths: independent reads with no shared state.
			_, _, _ = cli.Getattr(string(rune('a'+i)) + "/missing")
		}(i)
	}

	deadline := time.After(20 * time.Second)
	for seen := 0; seen < pool; seen++ {
		select {
		case <-arrived:
		case <-deadline:
			close(release)
			wg.Wait()
			t.Fatalf("only %d of %d independent reads were in flight at once; "+
				"the pool serialized them", seen, pool)
		}
	}
	close(release)
	wg.Wait()

	if got := peak.Load(); got != pool {
		t.Fatalf("peak concurrent authority reads = %d, want %d (the whole pool)", got, pool)
	}
}
