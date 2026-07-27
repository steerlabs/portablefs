package fsproto

// Full client↔server semantics over a deterministic in-process transport
// (net.Pipe): sandboxed environments can block loopback listeners, so these
// tests cover the REAL Client machinery (session negotiation, exact slots,
// lost-reply replay, UNKNOWN park+replay, racing duplicates) without sockets.
// The live TCP/TLS paths remain covered by the *_client tests, which run
// where listeners are permitted.

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/delegation"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// pipeListener is a net.Listener fed by net.Pipe pairs.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn, 16), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, fmt.Errorf("pipe listener closed")
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

// dial hands the server one end and the client the other.
func (l *pipeListener) dial() (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.closed:
		_ = client.Close()
		return nil, fmt.Errorf("pipe listener closed")
	}
}

// startPipeAuthority serves an exact-session authority over pipes and returns
// the server, its workfs, and a dialer for clients.
func startPipeAuthority(t *testing.T) (*Server, *workfs.FS, func() (net.Conn, error)) {
	t.Helper()
	w, err := wal.Open(filepath.Join(t.TempDir(), "pipe.wal"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.New(nil, nopBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(fs, fs, delegation.New())
	ln := newPipeListener()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Serve(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Log("pipe authority did not stop in time")
		}
	})
	return s, fs, ln.dial
}

func pipeClient(t *testing.T, dial func() (net.Conn, error), owner string) *Client {
	t.Helper()
	c, err := DialWithTransport(2, dial)
	if err != nil {
		t.Fatalf("pipe client: %v", err)
	}
	c.SetOwner(owner)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestPipeClientExactEndToEnd(t *testing.T) {
	_, fs, dial := startPipeAuthority(t)
	c := pipeClient(t, dial, "M1")

	live, err := c.EnsureExactSession()
	if err != nil || !live {
		t.Fatalf("session: live=%v err=%v", live, err)
	}
	es := c.exactState()
	if info, ok := fs.CurrentSession(es.id); !ok || info.Expired || info.Owner != "M1" {
		t.Fatalf("authority session: %+v (ok=%v)", info, ok)
	}

	// Real exact mutations through the pipe transport.
	if _, st, err := c.Create("a", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	if n, _, _, st, err := c.WriteV("a", 0, []byte("hello"), 0o644); err != nil || st != OK || n != 5 {
		t.Fatalf("write: n=%d st=%d err=%v", n, st, err)
	}
	if st, err := c.Rename("a", "b"); err != nil || st != OK {
		t.Fatalf("rename: st=%d err=%v", st, err)
	}
	if data, st, err := c.Read("b", 0, 16); err != nil || st != OK || string(data) != "hello" {
		t.Fatalf("read: %q st=%d err=%v", data, st, err)
	}
	// A deterministic apply rejection is a definite consumed outcome; the
	// next fresh identity proceeds.
	if st, err := c.Remove("ghost"); err != nil || st != ENOENT {
		t.Fatalf("remove missing: st=%d err=%v", st, err)
	}
	if _, st, err := c.Create("c", 0o644); err != nil || st != OK {
		t.Fatalf("create after rejection: st=%d err=%v", st, err)
	}
}

func TestPipeClientLostReplyReplaysIdentically(t *testing.T) {
	s, _, dial := startPipeAuthority(t)
	c := pipeClient(t, dial, "M1")
	if _, err := c.EnsureExactSession(); err != nil {
		t.Fatalf("session: %v", err)
	}
	if _, st, err := c.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}

	// Drop exactly one OpWrite reply AFTER it fully applied.
	var mu sync.Mutex
	dropped := false
	s.SetDropReply(func(req *Request, resp *Response) bool {
		mu.Lock()
		defer mu.Unlock()
		if req.Op == OpWrite && !dropped {
			dropped = true
			return true
		}
		return false
	})
	// The foreground retries transparently: the replayed identity dedupes to
	// the SAME durable outcome (applied exactly once, no fence).
	if n, _, _, st, err := c.WriteV("f", 0, []byte("once"), 0o644); err != nil || st != OK || n != 4 {
		t.Fatalf("write with lost reply: n=%d st=%d err=%v", n, st, err)
	}
	mu.Lock()
	didDrop := dropped
	mu.Unlock()
	if !didDrop {
		t.Fatal("test seam never dropped a reply")
	}
	if data, st, _ := c.Read("f", 0, 16); st != OK || string(data) != "once" {
		t.Fatalf("file = %q (st=%d), want once", data, st)
	}
	if c.SessionFenced() {
		t.Fatal("lost-reply replay fenced the session")
	}
}

func TestPipeClientParksUnknownAndReplaysOverPipes(t *testing.T) {
	s, _, dial := startPipeAuthority(t)
	c := pipeClient(t, dial, "M1")
	if _, err := c.EnsureExactSession(); err != nil {
		t.Fatalf("session: %v", err)
	}
	if _, st, err := c.Create("f", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}

	// Lose every reply for the whole foreground budget: UNKNOWN, parked.
	var mu sync.Mutex
	remaining := exactForegroundAttempts
	s.SetDropReply(func(req *Request, resp *Response) bool {
		mu.Lock()
		defer mu.Unlock()
		if req.Op == OpWrite && remaining > 0 {
			remaining--
			return true
		}
		return false
	})
	if _, _, _, _, err := c.WriteV("f", 0, []byte("parked"), 0o644); err != ErrMutationUnknown {
		t.Fatalf("write with all replies lost: err=%v, want ErrMutationUnknown", err)
	}
	// The background replayer lands the identical identity exactly once.
	deadline := time.Now().Add(10 * time.Second)
	for {
		data, st, _ := c.Read("f", 0, 16)
		if st == OK && string(data) == "parked" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("parked identity never landed: %q st=%d", data, st)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestPipeTwoClientsRacingCreatesAndLocks(t *testing.T) {
	_, _, dial := startPipeAuthority(t)
	c1 := pipeClient(t, dial, "M1")
	c2 := pipeClient(t, dial, "M2")
	for _, c := range []*Client{c1, c2} {
		if _, err := c.EnsureExactSession(); err != nil {
			t.Fatalf("session: %v", err)
		}
	}

	// Race creates of the same name from two mounts: idempotent create means
	// both succeed, but the name resolves to ONE inode (exactly one creation).
	type result struct {
		st  int32
		ino uint64
		err error
	}
	results := make(chan result, 2)
	for _, c := range []*Client{c1, c2} {
		c := c
		go func() {
			a, st, err := c.Create("race.file", 0o644)
			var ino uint64
			if a != nil {
				ino = a.Ino
			}
			results <- result{st, ino, err}
		}()
	}
	var inos []uint64
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err != nil || r.st != OK {
			t.Fatalf("race create: st=%d err=%v", r.st, r.err)
		}
		inos = append(inos, r.ino)
	}
	if inos[0] != inos[1] || inos[0] == 0 {
		t.Fatalf("race create resolved to different inodes: %d vs %d", inos[0], inos[1])
	}

	// Race exclusive locks on the same range: exactly one grant; the loser
	// gets a definite EAGAIN and can retry after the winner releases.
	lockResults := make(chan result, 2)
	for _, c := range []*Client{c1, c2} {
		c := c
		go func() {
			res, err := c.Lock("race.file", LkSetlk, 1, 0, 100, true, false)
			lockResults <- result{st: res.Status, err: err}
		}()
	}
	var lockOK, lockBusy int
	for i := 0; i < 2; i++ {
		r := <-lockResults
		if r.err != nil {
			t.Fatalf("race lock: %v", r.err)
		}
		switch r.st {
		case OK:
			lockOK++
		case EAGAIN:
			lockBusy++
		default:
			t.Fatalf("race lock status %d", r.st)
		}
	}
	if lockOK != 1 || lockBusy != 1 {
		t.Fatalf("lock race: %d OK / %d EAGAIN, want exactly 1/1", lockOK, lockBusy)
	}
}
