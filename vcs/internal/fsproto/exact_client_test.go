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

	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
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
	fs := newManagedWorkFS(t, nil, nopBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := &exactHarness{fs: fs, addr: ln.Addr().String()}
	h.srv = NewServer(fs, fs)
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

// TestClientRefusesSessionlessAuthorityMutations: a reads-only server (no
// session store) answers the v6 probe but refuses session opens; the client
// surfaces that as a mutation error instead of downgrading to any legacy
// write path. Reads still flow.
func TestClientRefusesSessionlessAuthorityMutations(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = NewServer(memfs.New(), nil).Serve(ctx, ln) }()
	cli := dialExact(t, ln.Addr().String(), "M1")

	if _, st, err := cli.Create("f", 0o644); err == nil && st == OK {
		t.Fatal("create against a sessionless authority must not succeed")
	}
	if cli.ExactSessionActive() {
		t.Fatal("no session may exist against a sessionless authority")
	}
	if _, st, err := cli.Getattr("nope"); err != nil || st != ENOENT {
		t.Fatalf("read against sessionless authority: st=%d err=%v, want ENOENT", st, err)
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
	batch := []wal.Record{{Seq: 1, Op: wal.OpCreate, Path: "wb-file", Mode: 0o644}}
	if _, st, err := cli.FlushWriteback("wb", "wb-file", "1", wbZeroDigest(), wbTestDigest(t, wbZeroDigest(), batch), batch); err != nil || st != ESTALE {
		t.Fatalf("flush after fence: st=%d err=%v, want ESTALE", st, err)
	}
}

func TestClientSocketFlapReleasesNothing(t *testing.T) {
	h := serveExact(t)
	cli := dialExact(t, h.addr, "M1")
	if _, st, err := cli.Create("db", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	if granted, heldBy, _, err := cli.CheckoutManaged("proj"); err != nil || !granted {
		t.Fatalf("checkout: granted=%v heldBy=%q err=%v", granted, heldBy, err)
	}
	if lr, err := cli.LockManaged("db", 0, LkSetlk, 7, 0, 10, true, false); err != nil || lr.Status != OK {
		t.Fatalf("lock: %+v err=%v", lr, err)
	}

	// Socket flap: every pooled transport dies. The session survives it.
	for i := 0; i < 2; i++ {
		cn := <-cli.conns
		cn.reset()
		cli.conns <- cn
	}

	// Nothing was released: the checkout is still ours (a fresh contender
	// cannot acquire an overlapping grant).
	other0 := dialExact(t, h.addr, "M2")
	if granted, _, _, err := other0.CheckoutManaged("proj/sub"); err != nil || granted {
		t.Fatalf("peer checkout after flap: granted=%v err=%v, want refused (flap must release nothing)", granted, err)
	}
	other := dialExact(t, h.addr, "M2")
	if _, err := other.EnsureExactSession(); err != nil {
		t.Fatalf("peer session: %v", err)
	}
	if lr, err := other.LockManaged("db", 0, LkGetlk, 9, 0, 10, true, false); err != nil || !lr.Conflict {
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

// TestOpenUnlinkOrphanSurvivesFailover: an unlinked-but-open (pinned) inode
// parks under a durable journaled pin; the authority crashes and a successor
// cold-replays the SAME file entry log. The mount resumes its session, keeps
// reading and writing the parked inode by ino, and the unpin finally lets
// the authority's reap sweep destroy it.
func TestOpenUnlinkOrphanSurvivesFailover(t *testing.T) {
	// Registered FIRST so it runs LAST (after the cancel/close cleanups):
	// every server goroutine must have exited before this test returns.
	var quiesce []*Server
	t.Cleanup(func() {
		for _, s := range quiesce {
			awaitQuiesce(t, s)
		}
	})

	walPath := filepath.Join(t.TempDir(), "authority.wal")
	srvA, _, _, _ := reopenAuthority(t, walPath)
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctxA, cancelA := context.WithCancel(context.Background())
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
	a, st, err := cli.Getattr("scratch")
	if err != nil || st != OK || a.Ino == 0 {
		t.Fatalf("getattr: a=%+v st=%d err=%v", a, st, err)
	}
	// Open-state pin, then unlink: the inode parks under the durable pin.
	if st, err := cli.MarkOpen(a.Ino); err != nil || st != OK {
		t.Fatalf("mark open: st=%d err=%v", st, err)
	}
	if st, err := cli.Remove("scratch"); err != nil || st != OK {
		t.Fatalf("remove: st=%d err=%v", st, err)
	}
	ino := a.Ino
	if _, st, _ := cli.Getattr("scratch"); st != ENOENT {
		t.Fatalf("name after unlink: st=%d, want ENOENT", st)
	}
	if data, st, err := cli.ReadOrphan(ino, 0, 64); err != nil || st != OK || string(data) != "tempdata" {
		t.Fatalf("orphan read: %q st=%d err=%v", data, st, err)
	}

	// CRASH the authority; a successor cold-replays the SAME entry log.
	cancelA()
	_ = lnA.Close()
	awaitQuiesce(t, srvA)
	quiesce = quiesce[1:]
	srvB, _, _, _ := reopenAuthority(t, walPath)
	ctxB, cancelB := context.WithCancel(context.Background())
	t.Cleanup(cancelB)
	quiesce = append(quiesce, srvB)
	go func() { _ = srvB.Serve(ctxB, lnB) }()

	// The mount resumes its session against the successor (the renew loop's
	// job; done explicitly here so the test does not wait out its interval).
	es := cli.exactState()
	if resp, err := cli.doRaw(&Request{
		Op: OpSessionResume, SessionID: es.id, SessionGen: es.gen, SessionToken: es.token,
	}, true); err != nil || resp.Status != OK {
		t.Fatalf("resume after failover: %+v err=%v", resp, err)
	}

	// The parked inode survived: reads and exact writes keep addressing it by
	// ino on the successor (the fd never noticed the failover).
	if data, st, err := cli.ReadOrphan(ino, 0, 64); err != nil || st != OK || string(data) != "tempdata" {
		t.Fatalf("orphan read after failover: %q st=%d err=%v", data, st, err)
	}
	if n, st, err := cli.WriteOrphan(ino, 8, []byte("+more")); err != nil || st != OK || n != 5 {
		t.Fatalf("orphan write after failover: n=%d st=%d err=%v", n, st, err)
	}
	if data, st, err := cli.ReadOrphan(ino, 0, 64); err != nil || st != OK || string(data) != "tempdata+more" {
		t.Fatalf("orphan reread: %q st=%d err=%v", data, st, err)
	}
	// Last close: the unpin releases the durable pin and the authority's
	// reap sweep destroys the parked inode.
	if st, err := cli.UnmarkOpen(ino); err != nil || st != OK {
		t.Fatalf("unmark after failover: st=%d err=%v", st, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, st, err := cli.ReadOrphan(ino, 0, 8); err == nil && st == ENOENT {
			break
		}
		if time.Now().After(deadline) {
			_, st, err := cli.ReadOrphan(ino, 0, 8)
			t.Fatalf("orphan survived unpin: st=%d err=%v, want ENOENT", st, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
