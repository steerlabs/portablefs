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
func (p *freezeProxy) thaw() {
	p.frozen.Store(false)
	// Connections accepted while frozen were deliberately never connected
	// to the backend, so merely clearing the flag cannot revive them. Model
	// a recovered network link by resetting the outage-era TCP cohort; the
	// client then redials through the now-healthy proxy.
	p.mu.Lock()
	stale := p.conns
	p.conns = nil
	p.mu.Unlock()
	for _, c := range stale {
		_ = c.Close()
	}
}

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

func compressBarrierTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := volumeBarrierTimeout
	volumeBarrierTimeout = d
	t.Cleanup(func() { volumeBarrierTimeout = prev })
}

// TestNormalBarrierFailsOnDeadAuthority pins invariants 6/9/10: with the
// authority BLACK-HOLED, the normal volume barrier (fsync / synchronize /
// unmount drain) returns an ERROR within its bound — never a local-only
// success. Only the EXPLICIT force path (CloseJournalDurable) detaches with
// the unshipped tail, parking it as a durable, visible recovery job whose ID
// it returns; the next attach on a healthy authority drains it byte-exact
// BEFORE serving (recovery is an attach-readiness gate).
func TestNormalBarrierFailsOnDeadAuthority(t *testing.T) {
	compressBarrierTimeout(t, 2*time.Second)
	authorityAddr := serveCore(t)
	proxy := newFreezeProxy(t, authorityAddr)
	walDir := t.TempDir()
	ctx := context.Background()

	v := dialCoreNoCleanup(t, proxy.addr(), Options{
		Owner:    "own-unmount-test",
		VolumeID: "vol-unmount",
		Branch:   "main",
		WALDir:   walDir,
	})

	// A DELEGATED subtree (top-level paths are deliberately nondelegable, so
	// they would prove nothing about the acknowledged write-back tail).
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create d/f: %d", st)
	}
	if !v.wb.Covers("d/f") {
		t.Fatal("precondition: d is delegated")
	}
	n := NewNodeState(a.Ino, a.Ino != 0)

	// The authority's TCP peer goes dark FIRST: everything acknowledged
	// after this point is a guaranteed-unshipped delegated tail.
	proxy.freeze()
	if _, st := v.Write(ctx, "d/f", n, 0, []byte("journal-first")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}

	start := time.Now()
	err := v.SyncVolume()
	if err == nil {
		t.Fatal("the normal barrier answered success against a black-holed authority — the local-only fsync outcome must not exist")
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("barrier failure took %v; it must fail within its bound, never hang", elapsed)
	}

	// Explicit force: park the tail durably with a visible job ID.
	start = time.Now()
	jobID, err := v.CloseJournalDurable()
	if err != nil {
		t.Fatalf("forced close: %v", err)
	}
	if jobID == "" {
		t.Fatal("forced close with an unshipped tail returned no recovery job ID")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("forced close took %v; it must not drain to the dead authority", elapsed)
	}

	// Next attach (authority reachable, same walDir): the attach-readiness
	// gate drains the parked stream BEFORE the mount serves.
	compressBarrierTimeout(t, 60*time.Second)
	v2 := dialCore(t, authorityAddr, Options{
		Owner:    "own-unmount-test",
		VolumeID: "vol-unmount",
		Branch:   "main",
		WALDir:   walDir,
	})
	if jobs := v2.RecoveryJobs(); len(jobs) != 0 {
		t.Fatalf("attach served with unresolved recovery jobs: %+v", jobs)
	}
	data, st := v2.Read(ctx, "d/f", NewNodeState(a.Ino, a.Ino != 0), 0, 64)
	if st != fsproto.OK || string(data) != "journal-first" {
		t.Fatalf("recovered content %q st=%d, want %q — the acknowledged write was lost", data, st, "journal-first")
	}
}

func TestFailedCloseLeavesVolumeServingForRetry(t *testing.T) {
	compressBarrierTimeout(t, time.Second)
	authorityAddr := serveCore(t)
	proxy := newFreezeProxy(t, authorityAddr)
	ctx := context.Background()
	v := dialCoreNoCleanup(t, proxy.addr(), Options{
		Owner:    "retry-close",
		VolumeID: "vol-retry-close",
		Branch:   "main",
		WALDir:   t.TempDir(),
	})
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if st := v.RegisterOpened("d/f", n); st != fsproto.OK {
		t.Fatalf("register open: %d", st)
	}
	if st := v.FsyncHandle("d/f", n); st != fsproto.OK {
		t.Fatalf("initial fsync: %d", st)
	}

	proxy.freeze()
	if _, st := v.Write(ctx, "d/f", n, 0, []byte("before retry")); st != fsproto.OK {
		t.Fatalf("delegated write: %d", st)
	}
	if err := v.Close(); err == nil {
		t.Fatal("close succeeded against a black-holed authority")
	}
	if !n.IsOpen() {
		t.Fatal("failed volume close altered live handle state")
	}
	if _, st := v.Write(ctx, "d/f", n, int64(len("before retry")), []byte("+alive")); st != fsproto.OK {
		t.Fatalf("write after refused close: %d", st)
	}

	proxy.thaw()
	volumeBarrierTimeout = 10 * time.Second
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for {
		lastErr = v.Fsync("d/f")
		if lastErr == nil {
			n.clearDirty()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("volume did not recover after authority connectivity returned: %v", lastErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if st := v.CloseHandle("d/f", n); st != fsproto.OK {
		t.Fatalf("close handle after recovery: %d", st)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("retry volume close: %v", err)
	}
}

func TestFailedDetachKeepsMutationsGatedThenReopensVolume(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCoreNoCleanup(t, addr, Options{
		Owner:    "retry-detach",
		VolumeID: "vol-retry-detach",
		Branch:   "main",
		WALDir:   t.TempDir(),
	})
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := v.Write(ctx, "d/f", n, 0, []byte("before")); st != fsproto.OK {
		t.Fatalf("initial write: %d", st)
	}

	detachEntered := make(chan struct{})
	releaseDetach := make(chan struct{})
	detachErr := errors.New("injected kernel detach failure")
	closeDone := make(chan error, 1)
	go func() {
		closeDone <- v.CloseWithFinalizer(func() error {
			close(detachEntered)
			<-releaseDetach
			return detachErr
		})
	}()
	select {
	case <-detachEntered:
	case <-time.After(10 * time.Second):
		t.Fatal("close never reached the frontend detach")
	}

	writeDone := make(chan Status, 1)
	go func() {
		_, st := v.Write(ctx, "d/f", n, int64(len("before")), []byte("+after"))
		writeDone <- st
	}()
	select {
	case st := <-writeDone:
		t.Fatalf("mutation escaped the close gate during detach: %d", st)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseDetach)
	if err := <-closeDone; !errors.Is(err, detachErr) {
		t.Fatalf("close error = %v, want injected detach failure", err)
	}
	select {
	case st := <-writeDone:
		if st != fsproto.OK {
			t.Fatalf("mutation after refused detach: %d", st)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("mutation gate did not reopen after refused detach")
	}

	if err := v.Close(); err != nil {
		t.Fatalf("retry close: %v", err)
	}
}

// TestSyncVolumeNormalPathFlushesToAuthority pins that a REACHABLE authority
// completes the full barrier: every accepted mutation is at the
// authority (and peer-visible) before success.
func TestSyncVolumeNormalPathFlushesToAuthority(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{
		Owner:  "own-normal-sync",
		WALDir: t.TempDir(),
	})
	a, st := v.Create(ctx, "g", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := v.Write(ctx, "g", n, 0, []byte("normal-path")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}
	if err := v.SyncVolume(); err != nil {
		t.Fatalf("barrier on a reachable authority: %v", err)
	}
	// An INDEPENDENT write-through client must observe the bytes at the
	// authority (write-back flushed before success, not just WAL-fsynced).
	observer := dialCore(t, addr, Options{Owner: "own-observer"})
	data, st := observer.Read(ctx, "g", NewNodeState(0, false), 0, 64)
	if st != fsproto.OK {
		t.Fatalf("observer read: %d", st)
	}
	if string(data) != "normal-path" {
		t.Fatalf("authority holds %q, want %q — the barrier must flush before success", data, "normal-path")
	}
}

// TestSyncVolumeFencedSessionSurfacesError: a FENCED session with a
// perfectly REACHABLE authority must never answer the volume barrier with
// success — the fence is a definite verdict that this generation's writes
// are rejected. It must still answer fast: fenced can never mean a
// kernel-visible hang.
func TestSyncVolumeFencedSessionSurfacesError(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{
		Owner:  "own-fenced-barrier",
		WALDir: t.TempDir(),
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

	start := time.Now()
	if err := v.SyncVolume(); err == nil {
		t.Fatal("fenced-but-reachable barrier answered success — a false durability guarantee")
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("fenced barrier took %v; it must fail fast, never wedge the caller", elapsed)
	}
}
