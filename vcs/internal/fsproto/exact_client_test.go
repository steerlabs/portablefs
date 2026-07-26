package fsproto

// Client-side tests for exact mount sessions: automatic establishment, lost
// replies (replay of the stored outcome), UNKNOWN outcomes (parked identities
// that never get reused), fenced mounts, socket flaps that must release
// nothing, multi-group setattr splitting, graceful downgrade against legacy
// authorities, and the VCS_CLIENT_DISABLE_EXACT_SESSIONS escape hatch.

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"

	"github.com/trendup-ai/portablefs/vcs/internal/delegation"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

// exactHarness is a live exact-session authority plus test seams.
type exactHarness struct {
	srv  *Server
	fs   *workfs.FS
	addr string
	// drop, when non-nil, loses the response for requests it matches (the
	// request has fully applied). Installed BEFORE Serve and read through an
	// atomic pointer, so tests can arm it mid-flight without a data race
	// against the server's connection goroutines.
	drop atomic.Pointer[func(req *Request, resp *Response) bool]
}

func (h *exactHarness) setDrop(fn func(req *Request, resp *Response) bool) { h.drop.Store(&fn) }

// awaitQuiesce blocks until every connection handler has exited and the lease
// sweeper stopped — the point after which no server goroutine reads shared
// package state (workfs.SessionLeaseTTL etc.). Tests that shorten those
// package variables MUST quiesce the server before restoring them, or the
// restore write races the server's reads.
func awaitQuiesce(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.conns)
		s.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Logf("awaitQuiesce: %d connection handlers still live", n)
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if s.exact != nil {
		select {
		case <-s.exact.sweeperDone:
		case <-time.After(10 * time.Second):
			t.Log("awaitQuiesce: lease sweeper did not stop")
		}
	}
}

// serveExact starts an exact-session authority and returns its harness.
func serveExact(t *testing.T) *exactHarness {
	t.Helper()
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.New(nil, nopBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := &exactHarness{fs: fs, addr: ln.Addr().String()}
	h.srv = NewServer(fs, fs, delegation.New())
	h.srv.SetDropReply(func(req *Request, resp *Response) bool {
		if fn := h.drop.Load(); fn != nil {
			return (*fn)(req, resp)
		}
		return false
	})
	go func() { _ = h.srv.Serve(ctx, ln) }()
	return h
}

func dialExact(t *testing.T, addr, owner string) *Client {
	t.Helper()
	cli, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	cli.SetOwner(owner)
	t.Cleanup(func() { _ = cli.Close() })
	return cli
}

func TestClientEstablishesExactSessionOnFirstMutation(t *testing.T) {
	h := serveExact(t)
	cli := dialExact(t, h.addr, "M1")

	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	if !cli.ExactSessionActive() {
		t.Fatal("first mutation must establish the exact session")
	}
	es := cli.exactState()
	info, ok := h.fs.CurrentSession(es.id)
	if !ok || info.Generation != es.gen || info.Owner != "M1" || info.Expired {
		t.Fatalf("authority session = %+v (ok=%v), want live gen %d owned by M1", info, ok, es.gen)
	}
	if es.gen == 0 {
		t.Fatal("session generation must be nonzero")
	}
}

func TestClientDowngradesAgainstLegacyAuthority(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = NewServer(memfs.New(), nil, nil).Serve(ctx, ln) }()
	cli := dialExact(t, ln.Addr().String(), "M1")

	// Graceful downgrade: against an authority without exact sessions the
	// client keeps plain v1 mutation behavior (this repository's
	// compatibility contract), and never establishes a session.
	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create against legacy authority: st=%d err=%v, want plain v1 success", st, err)
	}
	if cli.ExactSessionActive() {
		t.Fatal("no session may exist against a legacy authority")
	}
	if !cli.serverIsLegacy() {
		t.Fatal("client must remember the authority is legacy (sticky downgrade)")
	}
	if _, st, err := cli.Getattr("f"); err != nil || st != OK {
		t.Fatalf("read against legacy authority: st=%d err=%v", st, err)
	}
}

func TestClientDisableEnvVarForcesDowngrade(t *testing.T) {
	t.Setenv("VCS_CLIENT_DISABLE_EXACT_SESSIONS", "1")
	h := serveExact(t)
	cli := dialExact(t, h.addr, "M1")

	// The authority OFFERS sessions, but the escape hatch keeps the client on
	// plain v1 behavior: mutations succeed with no session.
	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create with sessions disabled: st=%d err=%v", st, err)
	}
	if cli.ExactSessionActive() {
		t.Fatal("VCS_CLIENT_DISABLE_EXACT_SESSIONS=1 must prevent session establishment")
	}
	if live, err := cli.EnsureExactSession(); live || err != nil {
		t.Fatalf("EnsureExactSession with sessions disabled: live=%v err=%v, want false/nil", live, err)
	}
}

func TestClientLostReplyReplaysStoredOutcome(t *testing.T) {
	h := serveExact(t)
	cli := dialExact(t, h.addr, "M1")
	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	if n, _, _, st, err := cli.WriteV("f", 0, []byte("hello"), 0o644); err != nil || st != OK || n != 5 {
		t.Fatalf("write: n=%d st=%d err=%v", n, st, err)
	}

	// Lose exactly one write reply AFTER the mutation applied.
	var drops atomic.Int32
	drops.Store(1)
	h.setDrop(func(req *Request, resp *Response) bool {
		return req.Op == OpWrite && string(req.Data) == "x" && drops.Add(-1) >= 0
	})

	// The client's replay of the identical identity gets the STORED outcome:
	// applied exactly once.
	n, _, _, st, err := cli.WriteV("f", 5, []byte("x"), 0o644)
	if err != nil || st != OK || n != 1 {
		t.Fatalf("write through lost reply: n=%d st=%d err=%v, want 1/OK", n, st, err)
	}
	if data, st, _ := cli.Read("f", 0, 64); st != OK || string(data) != "hellox" {
		t.Fatalf("file = %q (st=%d), want hellox — the lost-reply retry must not double-apply", data, st)
	}
}

func TestClientParksUnknownOutcomeAndReplaysIdentically(t *testing.T) {
	h := serveExact(t)
	cli := dialExact(t, h.addr, "M1")
	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}

	// Lose every reply for the whole foreground budget: the outcome is
	// UNKNOWN, the identity parks, and the caller gets a definite error.
	var drops atomic.Int32
	drops.Store(int32(exactForegroundAttempts))
	h.setDrop(func(req *Request, resp *Response) bool {
		return req.Op == OpWrite && string(req.Data) == "x" && drops.Add(-1) >= 0
	})
	_, _, _, st, err := cli.WriteV("f", 0, []byte("x"), 0o644)
	if !errors.Is(err, ErrMutationUnknown) {
		t.Fatalf("write with all replies lost: st=%d err=%v, want ErrMutationUnknown", st, err)
	}

	// The parked replayer must land the SAME identity exactly once.
	deadline := time.Now().Add(10 * time.Second)
	for {
		data, st, _ := cli.Read("f", 0, 64)
		if st == OK && string(data) == "x" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("parked identity never landed: file=%q st=%d", data, st)
		}
		time.Sleep(25 * time.Millisecond)
	}

	// After the park resolves, fresh mutations use fresh identities.
	deadline = time.Now().Add(10 * time.Second)
	for {
		// The slot frees only when the replayer commits; acquire may briefly
		// contend with it right at resolution.
		n, _, _, st, err := cli.WriteV("f", 1, []byte("y"), 0o644)
		if err == nil && st == OK {
			if n != 1 {
				t.Fatalf("write after park: n=%d, want 1", n)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("write after park never succeeded: st=%d err=%v", st, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if data, st, _ := cli.Read("f", 0, 64); st != OK || string(data) != "xy" {
		t.Fatalf("file = %q (st=%d), want xy (each identity exactly once)", data, st)
	}
}

func TestClientFencedSessionNeverMintsFreshGeneration(t *testing.T) {
	h := serveExact(t)
	cli := dialExact(t, h.addr, "M1")
	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	es := cli.exactState()

	// The authority fences the session (as a lease expiry / supersession would).
	if err := h.fs.ExpireSession(es.id, es.gen); err != nil {
		t.Fatalf("expire: %v", err)
	}

	// The next mutation gets a definite ESTALE and the client fences itself.
	if _, st, err := cli.Write("f", 0, []byte("zombie"), 0o644); err != nil || st != ESTALE {
		t.Fatalf("write after fence: st=%d err=%v, want ESTALE", st, err)
	}
	if !cli.SessionFenced() {
		t.Fatal("client must fence after a definite ESTALE")
	}
	// Every further mutation fails fast; the mount NEVER re-establishes a
	// fresh generation by itself (a zombie would overwrite its successor).
	if _, st, err := cli.Write("f", 0, []byte("again"), 0o644); err != nil || st != ESTALE {
		t.Fatalf("second write after fence: st=%d err=%v, want ESTALE", st, err)
	}
	if live, err := cli.EnsureExactSession(); live || err != nil {
		t.Fatalf("EnsureExactSession on fenced mount: live=%v err=%v, want false/nil", live, err)
	}
	if got := cli.exactState(); got.id != es.id || got.gen != es.gen {
		t.Fatalf("client minted a new identity: %s/%d -> %s/%d", es.id, es.gen, got.id, got.gen)
	}
	if info, ok := h.fs.CurrentSession(es.id); !ok || !info.Expired || info.Generation != es.gen {
		t.Fatalf("authority session = %+v, want the SAME generation, expired", info)
	}
	// And a fenced mount cannot flush old dirty write-back bytes either.
	batch := []wal.Record{{Seq: 0, Op: wal.OpCreate, Path: "wb-file", Mode: 0o644}}
	if _, st, err := cli.FlushBatch("wb", 1, "M1", batch); err != nil || st != ESTALE {
		t.Fatalf("flush after fence: st=%d err=%v, want ESTALE", st, err)
	}
}

func TestClientSocketFlapReleasesNothing(t *testing.T) {
	h := serveExact(t)
	cli := dialExact(t, h.addr, "M1")
	if _, st, err := cli.Create("db", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	if granted, heldBy, err := cli.Checkout("proj", "M1"); err != nil || !granted {
		t.Fatalf("checkout: granted=%v heldBy=%q err=%v", granted, heldBy, err)
	}
	if lr, err := cli.Lock("db", LkSetlk, 7, 0, 10, true, false); err != nil || lr.Status != OK {
		t.Fatalf("lock: %+v err=%v", lr, err)
	}

	// Socket flap: every pooled transport dies. The session survives it.
	for i := 0; i < 2; i++ {
		cn := <-cli.conns
		cn.reset()
		cli.conns <- cn
	}

	// Nothing was released: the checkout and the lock are still ours.
	if holder, _ := h.srv.deleg.HeldBy("proj"); holder != "M1" {
		t.Fatalf("checkout holder after flap = %q, want M1 (flap must release nothing)", holder)
	}
	other := dialExact(t, h.addr, "M2")
	if lr, err := other.Lock("db", LkGetlk, 9, 0, 10, true, false); err != nil || !lr.Conflict {
		t.Fatalf("peer getlk after flap: %+v err=%v, want conflict (lock still held)", lr, err)
	}
	// And the same mount keeps mutating over re-dialed, re-attached conns.
	if n, st, err := cli.Write("db", 0, []byte("post-flap"), 0o644); err != nil || st != OK || n != 9 {
		t.Fatalf("write after flap: n=%d st=%d err=%v", n, st, err)
	}
	if cli.SessionFenced() {
		t.Fatal("a socket flap must not fence the session")
	}
}

func TestClientSplitsMultiGroupSetattr(t *testing.T) {
	h := serveExact(t)
	cli := dialExact(t, h.addr, "M1")
	if _, st, err := cli.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	// chmod+utimes+chown in one kernel SETATTR: three exact identities.
	if st, err := cli.Setattr("f", 0o600, true, 123000, true, 1000, 2000, true, true); err != nil || st != OK {
		t.Fatalf("multi-group setattr: st=%d err=%v", st, err)
	}
	a, st, err := cli.Getattr("f")
	if err != nil || st != OK || a == nil {
		t.Fatalf("getattr: %+v st=%d err=%v", a, st, err)
	}
	if a.Mode != 0o600 || a.MtimeMs != 123000 || a.Uid != 1000 || a.Gid != 2000 {
		t.Fatalf("attrs = %+v, want mode 600 mtime 123000 uid 1000 gid 2000", a)
	}
	_ = h
}

// TestOpenUnlinkOrphanSurvivesFailover: a mount holds a file open, unlinks it
// (parking the inode as an orphan), the authority crashes, and a standby
// promotes from the replicated WAL. The parked inode — created by a replicated
// OpOrphan intent — must survive the failover: the mount keeps reading and
// writing it by ino and finally reaps it exactly once.
func TestOpenUnlinkOrphanSurvivesFailover(t *testing.T) {
	// Registered FIRST so it runs LAST (after the cancel/close cleanups):
	// every server goroutine must have exited before this test returns.
	var quiesce []*Server
	t.Cleanup(func() {
		for _, s := range quiesce {
			awaitQuiesce(t, s)
		}
	})

	walPath := filepath.Join(t.TempDir(), "replicated.wal")
	w1, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	fs1, err := workfs.New(nil, nopBlobs{}, w1)
	if err != nil {
		t.Fatal(err)
	}
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctxA, cancelA := context.WithCancel(context.Background())
	srvA := NewServer(fs1, fs1, delegation.New())
	quiesce = append(quiesce, srvA)
	go func() { _ = srvA.Serve(ctxA, lnA) }()

	cli, err := Dial(lnA.Addr().String()+","+lnB.Addr().String(), 2)
	if err != nil {
		t.Fatal(err)
	}
	cli.SetOwner("MA")
	t.Cleanup(func() { _ = cli.Close() })

	if _, st, err := cli.Create("scratch", 0o600); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	if n, _, _, st, err := cli.WriteV("scratch", 0, []byte("tempdata"), 0o600); err != nil || st != OK || n != 8 {
		t.Fatalf("write: n=%d st=%d err=%v", n, st, err)
	}
	// Open-unlink: the name goes away, the inode parks under a lease.
	ino, st, err := cli.Orphan("scratch")
	if err != nil || st != OK || ino == 0 {
		t.Fatalf("orphan: ino=%d st=%d err=%v", ino, st, err)
	}
	if _, st, _ := cli.Getattr("scratch"); st != ENOENT {
		t.Fatalf("name after orphan: st=%d, want ENOENT", st)
	}

	// CRASH the primary; PROMOTE a standby from the same replicated WAL.
	cancelA()
	_ = lnA.Close()
	if err := w1.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	fs2, err := workfs.New(nil, nopBlobs{}, w2)
	if err != nil {
		t.Fatal(err)
	}
	ctxB, cancelB := context.WithCancel(context.Background())
	t.Cleanup(cancelB)
	srvB := NewServer(fs2, fs2, delegation.New())
	quiesce = append(quiesce, srvB)
	go func() { _ = srvB.Serve(ctxB, lnB) }()

	// The parked inode survived: reads and exact writes keep addressing it by
	// ino on the promoted authority (the fd never noticed the failover).
	if data, st, err := cli.ReadOrphan(ino, 0, 64); err != nil || st != OK || string(data) != "tempdata" {
		t.Fatalf("orphan read after promotion: %q st=%d err=%v", data, st, err)
	}
	if n, st, err := cli.WriteOrphan(ino, 8, []byte("+more")); err != nil || st != OK || n != 5 {
		t.Fatalf("orphan write after promotion: n=%d st=%d err=%v", n, st, err)
	}
	if data, st, err := cli.ReadOrphan(ino, 0, 64); err != nil || st != OK || string(data) != "tempdata+more" {
		t.Fatalf("orphan reread: %q st=%d err=%v", data, st, err)
	}
	// Last close: reap the parked inode (an exact mutation), exactly once.
	if st, err := cli.Reap(ino); err != nil || st != OK {
		t.Fatalf("reap after promotion: st=%d err=%v", st, err)
	}
	if _, st, err := cli.ReadOrphan(ino, 0, 8); err != nil || st != ENOENT {
		t.Fatalf("read after reap: st=%d err=%v, want ENOENT", st, err)
	}
}

// TestClientReclaimReassertsAcrossPromotion is the end-to-end failover story:
// a mount holds coordination state, the authority dies, a standby promotes
// from the replicated WAL, the mount's lease renewal discovers the reclaim
// window, re-asserts its state through the registered hook, and a competing
// mount is held off until then — after which conflicts resolve normally.
func TestClientReclaimReassertsAcrossPromotion(t *testing.T) {
	// Registered FIRST so it runs LAST (after later cleanups shut both servers
	// down): it waits for every server goroutine to exit BEFORE restoring the
	// package variables — a still-running handler or sweeper reading them
	// during the restore would be a data race.
	var quiesce []*Server
	oldTTL, oldGrace := workfs.SessionLeaseTTL, workfs.SessionReclaimGrace
	t.Cleanup(func() {
		for _, s := range quiesce {
			awaitQuiesce(t, s)
		}
		workfs.SessionLeaseTTL, workfs.SessionReclaimGrace = oldTTL, oldGrace
	})
	workfs.SessionLeaseTTL = 1200 * time.Millisecond // renewals every ~400ms
	workfs.SessionReclaimGrace = 8 * time.Second

	walPath := filepath.Join(t.TempDir(), "replicated.wal")
	w1, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	fs1, err := workfs.New(nil, nopBlobs{}, w1)
	if err != nil {
		t.Fatal(err)
	}
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctxA, cancelA := context.WithCancel(context.Background())
	srvA := NewServer(fs1, fs1, delegation.New())
	quiesce = append(quiesce, srvA)
	go func() { _ = srvA.Serve(ctxA, lnA) }()

	// The mount knows both addresses (primary,standby) — no VIP.
	addrs := lnA.Addr().String() + "," + lnB.Addr().String()
	cli, err := Dial(addrs, 2)
	if err != nil {
		t.Fatal(err)
	}
	cli.SetOwner("MA")
	t.Cleanup(func() { _ = cli.Close() })

	if _, st, err := cli.Create("db", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	if granted, _, err := cli.Checkout("proj", "MA"); err != nil || !granted {
		t.Fatalf("checkout: %v", err)
	}
	if lr, err := cli.Lock("db", LkSetlk, 7, 0, 10, true, false); err != nil || lr.Status != OK {
		t.Fatalf("lock: %+v err=%v", lr, err)
	}

	// The reclaim hook re-asserts coordination state, then reports done.
	reclaimed := make(chan time.Duration, 1)
	cli.SetOnReclaim(func(window time.Duration) {
		if granted, _, err := cli.Checkout("proj", "MA"); err != nil || !granted {
			t.Errorf("reclaim checkout: granted=%v err=%v", granted, err)
		}
		if lr, err := cli.Lock("db", LkSetlk, 7, 0, 10, true, false); err != nil || lr.Status != OK {
			t.Errorf("reclaim lock: %+v err=%v", lr, err)
		}
		cli.ReclaimDone()
		select {
		case reclaimed <- window:
		default:
		}
	})

	// CRASH the primary; PROMOTE the standby from the same replicated WAL.
	cancelA()
	_ = lnA.Close()
	if err := w1.Close(); err != nil {
		t.Fatal(err)
	}
	w2, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	fs2, err := workfs.New(nil, nopBlobs{}, w2)
	if err != nil {
		t.Fatal(err)
	}
	srvB := NewServer(fs2, fs2, delegation.New())
	quiesce = append(quiesce, srvB)
	ctxB, cancelB := context.WithCancel(context.Background())
	t.Cleanup(cancelB)
	go func() { _ = srvB.Serve(ctxB, lnB) }()
	if !srvB.exact.inGrace(time.Now()) {
		t.Fatal("promoted authority must start in reclaim grace")
	}

	// A competitor on the promoted authority is held off while grace runs
	// (the gate answers EAGAIN, which the typed helper surfaces as not-granted).
	rival := dialExact(t, lnB.Addr().String(), "MB")
	if granted, _, _ := rival.Checkout("proj", "MB"); granted {
		t.Fatal("rival checkout during reclaim grace was granted, want held off")
	}

	// The mount's lease renewal finds the standby, learns ReclaimMs, and the
	// hook re-asserts + completes.
	select {
	case window := <-reclaimed:
		if window <= 0 {
			t.Fatalf("reclaim window = %v, want > 0", window)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reclaim hook never ran after promotion")
	}

	// Grace lifted early (all priors reclaimed): the rival now sees a normal
	// CONFLICT (held by MA), not a grace hold-off; other subtrees are free.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if granted, _, err := rival.Checkout("elsewhere", "MB"); err == nil && granted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("grace never lifted for non-conflicting acquisition")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if holder, _ := srvB.deleg.HeldBy("proj"); holder != "MA" {
		t.Fatalf("proj holder after reclaim = %q, want MA", holder)
	}
	// The mount's exact mutations continue seamlessly on the promoted node.
	if n, st, err := cli.Write("db", 0, []byte("hi"), 0o644); err != nil || st != OK || n != 2 {
		t.Fatalf("write after promotion: n=%d st=%d err=%v", n, st, err)
	}
	if lr, err := rival.Lock("db", LkGetlk, 9, 0, 10, true, false); err != nil || !lr.Conflict {
		t.Fatalf("rival getlk: %+v err=%v, want conflict with MA's reclaimed lock", lr, err)
	}
}
