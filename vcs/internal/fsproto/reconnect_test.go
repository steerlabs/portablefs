package fsproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/secure"
)

// fakeRouter emulates the authority manager's TCP data-plane router: it reads
// the client's token frame, answers a single ack byte (0 admit / 1 reject and
// close), and on admit bridges the connection to a real backend authority.
// rotate() swaps the accepted token and severs live tunnels — exactly what a
// manager restart does to every mount at once.
type fakeRouter struct {
	ln      net.Listener
	backend string

	mu             sync.Mutex
	accepted       string
	closeBeforeAck bool // reject by closing with NO ack byte (the clean-close case)
	tunnels        map[net.Conn]net.Conn

	rejected atomic.Int64
}

func newFakeRouter(t *testing.T, backend, accepted string) *fakeRouter {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeRouter{ln: ln, backend: backend, accepted: accepted, tunnels: map[net.Conn]net.Conn{}}
	go r.serve()
	t.Cleanup(func() {
		_ = ln.Close()
		r.rotate("")
	})
	return r
}

func (r *fakeRouter) addr() string { return r.ln.Addr().String() }

// rotate installs the token the router accepts from now on and destroys every
// live tunnel (a restarted manager keeps no predecessor tunnels).
func (r *fakeRouter) rotate(accepted string) {
	r.mu.Lock()
	r.accepted = accepted
	tunnels := r.tunnels
	r.tunnels = map[net.Conn]net.Conn{}
	r.mu.Unlock()
	for client, backend := range tunnels {
		_ = client.Close()
		_ = backend.Close()
	}
}

func (r *fakeRouter) setCloseBeforeAck(v bool) {
	r.mu.Lock()
	r.closeBeforeAck = v
	r.mu.Unlock()
}

func (r *fakeRouter) serve() {
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.handle(conn)
	}
}

func (r *fakeRouter) handle(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		_ = conn.Close()
		return
	}
	token := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(conn, token); err != nil {
		_ = conn.Close()
		return
	}
	r.mu.Lock()
	admit := r.accepted != "" && string(token) == r.accepted
	closeBeforeAck := r.closeBeforeAck
	r.mu.Unlock()
	if !admit {
		r.rejected.Add(1)
		if !closeBeforeAck {
			_, _ = conn.Write([]byte{1})
		}
		_ = conn.Close()
		return
	}
	backend, err := net.Dial("tcp", r.backend)
	if err != nil {
		_ = conn.Close()
		return
	}
	// The ROUTER authenticates to the backend authority (the mount's token
	// never crosses the router), exactly like production.
	if err := secure.ClientHandshake(backend, ""); err != nil {
		_ = backend.Close()
		_ = conn.Close()
		return
	}
	if _, err := conn.Write([]byte{0}); err != nil {
		_ = backend.Close()
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	r.mu.Lock()
	r.tunnels[conn] = backend
	r.mu.Unlock()
	go func() {
		_, _ = io.Copy(backend, conn)
		_ = backend.Close()
		_ = conn.Close()
	}()
	go func() {
		_, _ = io.Copy(conn, backend)
		_ = backend.Close()
		_ = conn.Close()
	}()
}

// tokenCell is a swappable credential source (what sessionTokenSource is to
// the CLI).
type tokenCell struct{ v atomic.Value }

func (c *tokenCell) set(s string) { c.v.Store(s) }
func (c *tokenCell) get() string  { s, _ := c.v.Load().(string); return s }

// TestRouterAcceptedTokenServesTraffic: ack byte 0 admits the tunnel and the
// full protocol flows through the router bridge.
func TestRouterAcceptedTokenServesTraffic(t *testing.T) {
	_, backend := serveFS(t)
	router := newFakeRouter(t, backend, "tok-epoch1")
	src := &tokenCell{}
	src.set("tok-epoch1")

	cli, err := DialTLSAuth(router.addr(), 2, nil, src.get)
	if err != nil {
		t.Fatalf("dial through router: %v", err)
	}
	defer cli.Close()
	if _, st, err := cli.Create("f.txt", 0o644); err != nil || st != OK {
		t.Fatalf("create through router: st=%d err=%v", st, err)
	}
	if n, st, err := cli.Write("f.txt", 0, []byte("hello"), 0o644); err != nil || st != OK || n != 5 {
		t.Fatalf("write through router: n=%d st=%d err=%v", n, st, err)
	}
	if data, st, err := cli.Read("f.txt", 0, 64); err != nil || st != OK || string(data) != "hello" {
		t.Fatalf("read through router: %q st=%d err=%v", data, st, err)
	}
}

// TestRouterRejectionSurfacesTypedError: ack byte 1 — and the clean-close-
// before-ack variant — surface ErrSessionTokenRejected instead of a generic
// transport error, and the op fails promptly (no pointless redial loop with a
// credential that can never be admitted).
func TestRouterRejectionSurfacesTypedError(t *testing.T) {
	_, backend := serveFS(t)
	router := newFakeRouter(t, backend, "tok-epoch1")
	src := &tokenCell{}
	src.set("tok-epoch1")

	cli, err := DialTLSAuth(router.addr(), 1, nil, src.get)
	if err != nil {
		t.Fatalf("dial through router: %v", err)
	}
	defer cli.Close()
	if _, st, err := cli.Create("f.txt", 0o644); err != nil || st != OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}

	// Manager restart: every predecessor token is dead. No re-resolver is
	// installed (a static-token mount), so the typed error must surface.
	router.rotate("tok-epoch2")
	start := time.Now()
	_, _, err = cli.Getattr("f.txt")
	if err == nil || !errors.Is(err, ErrSessionTokenRejected) {
		t.Fatalf("want ErrSessionTokenRejected, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("a hopeless credential must fail fast, took %v", elapsed)
	}

	// Clean close right after the token frame, before any ack: same meaning.
	router.setCloseBeforeAck(true)
	if _, _, err := cli.Getattr("f.txt"); err == nil || !errors.Is(err, ErrSessionTokenRejected) {
		t.Fatalf("clean close before ack must classify as rejection, got %v", err)
	}
}

// TestRouterRejectionFailsClosedAcrossPool verifies that a manager epoch
// change cannot trigger credential re-resolution or retry behind the caller.
func TestRouterRejectionFailsClosedAcrossPool(t *testing.T) {
	_, backend := serveFS(t)
	router := newFakeRouter(t, backend, "tok-epoch1")
	src := &tokenCell{}
	src.set("tok-epoch1")

	const pool = 8
	cli, err := DialTLSAuth(router.addr(), pool, nil, src.get)
	if err != nil {
		t.Fatalf("dial through router: %v", err)
	}
	defer cli.Close()
	if _, st, err := cli.Create("f.txt", 0o644); err != nil || st != OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}

	// Manager restart: new epoch accepts only tok-epoch2; all tunnels die.
	router.rotate("tok-epoch2")

	var wg sync.WaitGroup
	errs := make(chan error, pool)
	for i := 0; i < pool; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := cli.Getattr("f.txt"); !errors.Is(err, ErrSessionTokenRejected) {
				errs <- fmt.Errorf("getattr error = %v, want ErrSessionTokenRejected", err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	if got := src.get(); got != "tok-epoch1" {
		t.Fatalf("rejection mutated credential to %q", got)
	}
}
