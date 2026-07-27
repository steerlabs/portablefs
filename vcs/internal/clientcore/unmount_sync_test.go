package clientcore

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// freezeProxy is a TCP proxy that can BLACK-HOLE its backend on command:
// established connections stay open but stop moving bytes, and new
// connections accept but never reach the backend. This is the incident shape
// (dead authority TCP peer, packets dropped) — distinct from a closed
// listener, which fails dials fast.
type freezeProxy struct {
	ln      net.Listener
	backend string
	frozen  atomic.Bool
	mu      sync.Mutex
	conns   []net.Conn
	done    chan struct{}
}

func newFreezeProxy(t *testing.T, backend string) *freezeProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &freezeProxy{ln: ln, backend: backend, done: make(chan struct{})}
	go p.acceptLoop()
	t.Cleanup(p.close)
	return p
}

func (p *freezeProxy) addr() string { return p.ln.Addr().String() }

func (p *freezeProxy) freeze() { p.frozen.Store(true) }

func (p *freezeProxy) close() {
	select {
	case <-p.done:
		return
	default:
	}
	close(p.done)
	_ = p.ln.Close()
	p.mu.Lock()
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
	p.mu.Unlock()
}

func (p *freezeProxy) track(c net.Conn) {
	p.mu.Lock()
	p.conns = append(p.conns, c)
	p.mu.Unlock()
}

func (p *freezeProxy) acceptLoop() {
	for {
		client, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.track(client)
		if p.frozen.Load() {
			continue // hold the conn open, never dial the backend: black hole
		}
		server, err := net.Dial("tcp", p.backend)
		if err != nil {
			_ = client.Close()
			continue
		}
		p.track(server)
		go p.pump(client, server)
		go p.pump(server, client)
	}
}

// pump copies until error, STALLING (not closing) while frozen.
func (p *freezeProxy) pump(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			for p.frozen.Load() {
				select {
				case <-p.done:
					return
				case <-time.After(20 * time.Millisecond):
				}
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// TestSyncVolumeBoundedJournalFirstOnDeadAuthority pins the P1 journal-first
// unmount contract end to end:
//
//  1. With the authority BLACK-HOLED mid-attach (the incident shape), the
//     unmount-class volume barrier replies success within its ceiling —
//     never a network-liveness wait — because the pending write-back
//     mutations are made durable in the local session WAL.
//  2. CloseJournalDurable returns without draining to the dead authority and
//     keeps the WAL on disk.
//  3. The next clean start of the same (owner, walDir) volume replays the
//     WAL to the recovered authority: nothing acknowledged was lost.
func TestSyncVolumeBoundedJournalFirstOnDeadAuthority(t *testing.T) {
	authorityAddr := serveCore(t)
	proxy := newFreezeProxy(t, authorityAddr)
	walDir := t.TempDir()
	ctx := context.Background()

	v := dialCoreNoCleanup(t, proxy.addr(), Options{
		Owner:     "own-unmount-test",
		WriteBack: true,
		WALDir:    walDir,
		// Keep the background flusher quiet so the test deterministically owns
		// which flushes happen when.
		FlushInterval: time.Hour,
	})

	a, st := v.Create(ctx, "f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := v.Write(ctx, "f", n, 0, []byte("journal-first")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}

	// The authority's TCP peer goes dark: established conns black-hole.
	proxy.freeze()

	start := time.Now()
	degraded, err := v.SyncVolumeBounded(700 * time.Millisecond)
	if err != nil {
		t.Fatalf("journal-first volume barrier must succeed on WAL durability, got %v", err)
	}
	if !degraded {
		t.Fatal("a journal-first answer must report itself degraded (callers log it; it is not the authority barrier)")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("volume barrier took %v; must reply within its ceiling, never await the dead network", elapsed)
	}

	start = time.Now()
	if err := v.CloseJournalDurable(); err != nil {
		t.Fatalf("journal-durable close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("journal-durable close took %v; must not drain to the dead authority", elapsed)
	}

	// Next clean start (authority reachable again, same owner + walDir):
	// recovery replays the WAL tail before serving.
	v2 := dialCore(t, authorityAddr, Options{
		Owner:         "own-unmount-test",
		WriteBack:     true,
		WALDir:        walDir,
		FlushInterval: time.Hour,
	})
	data, st := v2.Read(ctx, "f", NewNodeState(a.Ino, a.Ino != 0), 0, 64)
	if st != fsproto.OK {
		t.Fatalf("read after recovery: %d", st)
	}
	if string(data) != "journal-first" {
		t.Fatalf("recovered content %q, want %q — the acknowledged write was lost", data, "journal-first")
	}
}

// TestSyncVolumeBoundedNormalPathFlushesToAuthority pins that a REACHABLE
// authority keeps today's synchronize semantics exactly: the bounded barrier
// completes the full flush to the authority before success (not merely local
// WAL durability).
func TestSyncVolumeBoundedNormalPathFlushesToAuthority(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{
		Owner:         "own-normal-sync",
		WriteBack:     true,
		WALDir:        t.TempDir(),
		FlushInterval: time.Hour,
	})
	a, st := v.Create(ctx, "g", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := v.Write(ctx, "g", n, 0, []byte("normal-path")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}
	degraded, err := v.SyncVolumeBounded(unmountTestCeiling)
	if err != nil {
		t.Fatalf("bounded barrier on a reachable authority: %v", err)
	}
	if degraded {
		t.Fatal("the normal path completed the full authority barrier; it must not report degraded")
	}
	// An INDEPENDENT write-through client must observe the bytes at the
	// authority (write-back flushed before success, not just WAL-fsynced).
	observer := dialCore(t, addr, Options{Owner: "own-observer"})
	data, st := observer.Read(ctx, "g", NewNodeState(0, false), 0, 64)
	if st != fsproto.OK {
		t.Fatalf("observer read: %d", st)
	}
	if string(data) != "normal-path" {
		t.Fatalf("authority holds %q, want %q — the normal-path barrier must flush before success", data, "normal-path")
	}
}

const unmountTestCeiling = 12 * time.Second

// TestSyncVolumeBoundedFencedSessionSurfacesError pins the m1 half of the
// split predicate: a FENCED session with a perfectly REACHABLE authority must
// never answer the volume barrier with bare success. The fence is a definite
// verdict — this generation's writes are rejected — so the barrier surfaces
// an error (mapped to EIO by frontends), exactly as the weaker per-file
// fsync=authority does on a superseded session. It must still answer fast:
// fenced can never mean a kernel-visible hang.
func TestSyncVolumeBoundedFencedSessionSurfacesError(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{
		Owner:         "own-fenced-barrier",
		WriteBack:     true,
		WALDir:        t.TempDir(),
		FlushInterval: time.Hour,
	})
	a, st := v.Create(ctx, "h", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := v.Write(ctx, "h", n, 0, []byte("fenced-pending")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}

	// Fence the mount session while the authority stays fully reachable (the
	// voluntary-expiry path fences exactly like a lease loss / supersession).
	v.Client().ExpireSession()
	if !v.SessionFenced() {
		t.Fatal("precondition: session fenced")
	}
	if v.AuthorityUnreachable() {
		t.Fatal("precondition: authority reachable (fail-fast must not be engaged)")
	}

	start := time.Now()
	degraded, err := v.SyncVolumeBounded(unmountTestCeiling)
	if err == nil {
		t.Fatal("fenced-but-reachable barrier answered success — the false durability guarantee m1 forbids")
	}
	if !errors.Is(err, fsproto.ErrSessionFenced) {
		t.Fatalf("fenced barrier error must wrap ErrSessionFenced, got %v", err)
	}
	if degraded {
		t.Fatal("a fenced barrier is an ERROR, not a degraded journal-first success")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("fenced barrier took %v; it must fail fast, never wedge the caller", elapsed)
	}
}

// TestSyncLocalDurableWriteThroughIsInert pins the write-through invariant:
// with no session manager nothing can be pending locally by construction
// (every acknowledged mutation was durable-before-reply at the authority),
// so the journal-first barrier is an immediate success with no network.
func TestSyncLocalDurableWriteThroughIsInert(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{Owner: "own-wt"})
	if v.Sessions() != nil {
		t.Fatal("precondition: write-through volume has no session manager")
	}
	if err := v.SyncLocalDurable(); err != nil {
		t.Fatalf("write-through journal-first barrier must be an immediate success: %v", err)
	}
}
