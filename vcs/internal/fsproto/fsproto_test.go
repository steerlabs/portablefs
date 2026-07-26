package fsproto

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/delegation"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

type nopBlobs struct{}

func (nopBlobs) Blob(context.Context, string) ([]byte, error) {
	return nil, errors.New("no backed blobs in this test")
}

// serve starts an fsproto server over a fresh workfs and returns a connected
// client.
func serve(t *testing.T) *Client {
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
	go func() { _ = NewServer(fs, fs, delegation.New()).Serve(ctx, ln) }()

	cli, err := Dial(ln.Addr().String(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return cli
}

// serveFS is like serve but also returns the backing workfs and its address, for
// tests that drive invalidations or restart the server.
func serveFS(t *testing.T) (*workfs.FS, string) {
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
	go func() { _ = NewServer(fs, fs, delegation.New()).Serve(ctx, ln) }()
	return fs, ln.Addr().String()
}

// TestSubscribeStreamsInvalidations: a write made over the protocol pushes an
// invalidation for that path to a subscribed client.
func TestSubscribeStreamsInvalidations(t *testing.T) {
	_, addr := serveFS(t)
	cli, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	sub, err := cli.Subscribe()
	if err != nil {
		t.Fatal(err)
	}

	if _, st, _ := cli.Create("x.txt", 0o644); st != OK {
		t.Fatalf("create st=%d", st)
	}
	if _, st, _ := cli.Write("x.txt", 0, []byte("hi"), 0o644); st != OK {
		t.Fatalf("write st=%d", st)
	}

	got := map[string]bool{}
	timeout := time.After(2 * time.Second)
	for !got["x.txt"] {
		select {
		case ps := <-sub:
			for _, p := range ps {
				got[p.Path] = true
			}
		case <-timeout:
			t.Fatalf("no invalidation for x.txt; got %v", got)
		}
	}
}

// TestClientReconnectsForReads: an idempotent op transparently re-dials and
// succeeds after its connection is broken (as on a VCS restart/failover).
func TestClientReconnectsForReads(t *testing.T) {
	_, addr := serveFS(t)
	cli, err := Dial(addr, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// Seed a file, then forcibly break the pooled connection.
	if _, st, _ := cli.Create("f.txt", 0o644); st != OK {
		t.Fatalf("create st=%d", st)
	}
	cn := <-cli.conns
	cn.reset() // simulate a dropped connection
	cli.conns <- cn

	// A read should re-dial and still work.
	if a, st, err := cli.Getattr("f.txt"); err != nil || st != OK || a == nil {
		t.Fatalf("getattr after reconnect: a=%v st=%d err=%v", a, st, err)
	}

	// A write (idempotent) should also survive a broken connection.
	cn = <-cli.conns
	cn.reset()
	cli.conns <- cn
	if n, st, err := cli.Write("f.txt", 0, []byte("data"), 0o644); err != nil || st != OK || n != 4 {
		t.Fatalf("write after reconnect: n=%d st=%d err=%v", n, st, err)
	}
}

// serveStoppable starts an fsproto server and returns its fs, address, and a stop
// func (cancels Serve + closes the listener) so a test can simulate a node crash.
func serveStoppable(t *testing.T) (*workfs.FS, string, func()) {
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
	go func() { _ = NewServer(fs, fs, delegation.New()).Serve(ctx, ln) }()
	stop := func() { cancel(); _ = ln.Close() }
	t.Cleanup(stop)
	return fs, ln.Addr().String(), stop
}

// TestClientFollowsFailoverToSecondAddr: a client given two authority addresses
// (primary,standby) keeps serving when the primary dies — it re-dials and follows
// over to the standby with no reconfiguration. This is what lets 5+ mounts ride
// through a failover without an external VIP.
func TestClientFollowsFailoverToSecondAddr(t *testing.T) {
	fsA, addrA, stopA := serveStoppable(t)
	fsB, addrB, _ := serveStoppable(t)
	// Both authorities hold the file (B is a promoted standby mirror of A).
	for _, fs := range []*workfs.FS{fsA, fsB} {
		f, err := fs.Create("shared.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	cli, err := Dial(addrA+","+addrB, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// Served by A initially.
	if a, st, err := cli.Getattr("shared.txt"); err != nil || st != OK || a == nil {
		t.Fatalf("pre-failover getattr: a=%v st=%d err=%v", a, st, err)
	}
	// Crash the primary, then drop the now-dead pooled connections so the next op
	// re-dials and must fall through addrA (dead) to addrB.
	stopA()
	for i := 0; i < 2; i++ {
		cn := <-cli.conns
		cn.reset()
		cli.conns <- cn
	}
	if a, st, err := cli.Getattr("shared.txt"); err != nil || st != OK || a == nil {
		t.Fatalf("client did not follow over to the standby: a=%v st=%d err=%v", a, st, err)
	}
	// And writes are served by the standby too.
	if n, st, err := cli.Write("shared.txt", 0, []byte("world"), 0o644); err != nil || st != OK || n != 5 {
		t.Fatalf("post-failover write on standby: n=%d st=%d err=%v", n, st, err)
	}
}

// TestProtocolRoundTrip drives every operation over the wire against a real
// workfs, proving the FUSE client's translation layer has a correct backend.
func TestProtocolRoundTrip(t *testing.T) {
	c := serve(t)

	// Create + write + read.
	if _, st, err := c.Create("notes.txt", 0o644); err != nil || st != OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	if n, st, err := c.Write("notes.txt", 0, []byte("hello world"), 0o644); err != nil || st != OK || n != 11 {
		t.Fatalf("write: n=%d st=%d err=%v", n, st, err)
	}
	if data, st, _ := c.Read("notes.txt", 0, 256); st != OK || string(data) != "hello world" {
		t.Fatalf("read = %q (st=%d), want 'hello world'", data, st)
	}

	// Getattr.
	a, st, _ := c.Getattr("notes.txt")
	if st != OK || a == nil || a.Kind != "file" || a.Size != 11 {
		t.Fatalf("getattr = %+v st=%d", a, st)
	}

	// Offset write (overwrite within the file).
	if _, st, _ := c.Write("notes.txt", 6, []byte("there"), 0o644); st != OK {
		t.Fatalf("offset write st=%d", st)
	}
	if data, _, _ := c.Read("notes.txt", 0, 256); string(data) != "hello there" {
		t.Fatalf("after offset write = %q, want 'hello there'", data)
	}

	// Mkdir + nested file + readdir.
	if _, st, _ := c.Mkdir("docs", 0o755); st != OK {
		t.Fatalf("mkdir st=%d", st)
	}
	if _, st, _ := c.Create("docs/readme.md", 0o644); st != OK {
		t.Fatalf("nested create st=%d", st)
	}
	ents, _, st, _ := c.Readdir("docs")
	if st != OK || len(ents) != 1 || ents[0].Name != "readme.md" {
		t.Fatalf("readdir docs = %+v st=%d", ents, st)
	}

	// Symlink + readlink.
	if _, st, _ := c.Symlink("notes.txt", "link"); st != OK {
		t.Fatalf("symlink st=%d", st)
	}
	if target, st, _ := c.Readlink("link"); st != OK || target != "notes.txt" {
		t.Fatalf("readlink = %q st=%d", target, st)
	}

	// Truncate.
	if st, _ := c.Truncate("notes.txt", 5); st != OK {
		t.Fatalf("truncate st=%d", st)
	}
	if a, _, _ := c.Getattr("notes.txt"); a.Size != 5 {
		t.Fatalf("size after truncate = %d, want 5", a.Size)
	}

	// Rename.
	if st, _ := c.Rename("notes.txt", "renamed.txt"); st != OK {
		t.Fatalf("rename st=%d", st)
	}
	if _, st, _ := c.Getattr("renamed.txt"); st != OK {
		t.Fatalf("renamed missing st=%d", st)
	}
	if _, st, _ := c.Getattr("notes.txt"); st != ENOENT {
		t.Fatalf("old path still present st=%d, want ENOENT", st)
	}

	// Remove.
	if st, _ := c.Remove("renamed.txt"); st != OK {
		t.Fatalf("remove st=%d", st)
	}
	if _, st, _ := c.Getattr("renamed.txt"); st != ENOENT {
		t.Fatalf("removed file present st=%d, want ENOENT", st)
	}
}

// TestProtocolSetattr checks chmod over the protocol.
func TestProtocolSetattr(t *testing.T) {
	c := serve(t)
	if _, st, _ := c.Create("x", 0o644); st != OK {
		t.Fatalf("create st=%d", st)
	}
	if st, err := c.Setattr("x", 0o600, true, 0, false, 0, 0, false, false); err != nil || st != OK {
		t.Fatalf("setattr st=%d err=%v", st, err)
	}
	if a, _, _ := c.Getattr("x"); a == nil || a.Mode != 0o600 {
		t.Fatalf("mode = %+v, want 600", a)
	}
}

// TestProtocolChown checks ownership over the protocol: set uid+gid, then gid only
// (uid preserved), and that getattr reports the owner.
func TestProtocolChown(t *testing.T) {
	c := serve(t)
	if _, st, _ := c.Create("o", 0o644); st != OK {
		t.Fatalf("create st=%d", st)
	}
	if st, err := c.Setattr("o", 0, false, 0, false, 1000, 2000, true, true); err != nil || st != OK {
		t.Fatalf("chown st=%d err=%v", st, err)
	}
	if a, _, _ := c.Getattr("o"); a == nil || a.Uid != 1000 || a.Gid != 2000 {
		t.Fatalf("owner = %+v, want uid=1000 gid=2000", a)
	}
	// chgrp only: change gid, leave uid.
	if st, err := c.Setattr("o", 0, false, 0, false, 0, 3000, false, true); err != nil || st != OK {
		t.Fatalf("chgrp st=%d err=%v", st, err)
	}
	if a, _, _ := c.Getattr("o"); a == nil || a.Uid != 1000 || a.Gid != 3000 {
		t.Fatalf("owner after chgrp = %+v, want uid=1000 (preserved) gid=3000", a)
	}
}

// TestProtocolCheckout checks RECALL-based checkout/checkin coordination over the protocol: a
// contender does not get EBUSY — its OpCheckout recalls the holder and blocks until the holder
// relinquishes, then grants. Here A (a separate connection) checks in shortly after B starts
// waiting, simulating A responding to the recall; B then acquires the overlapping subtree.
func TestProtocolCheckout(t *testing.T) {
	_, addr := serveFS(t)
	ca, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer ca.Close()
	cb, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()

	if ok, _, err := ca.Checkout("work", "agent-A"); err != nil || !ok {
		t.Fatalf("A checkout: ok=%v err=%v", ok, err)
	}
	go func() {
		time.Sleep(150 * time.Millisecond) // A relinquishes in response to the recall
		_ = ca.Checkin("work", "agent-A")
	}()
	if ok, _, err := cb.Checkout("work/sub", "agent-B"); err != nil || !ok {
		t.Fatalf("B checkout should acquire after A relinquishes (recall handoff): ok=%v err=%v", ok, err)
	}
}

// TestConcurrentClientsStress hammers one server with many clients doing mixed
// ops at once, verifying every read-after-write is correct (run under -race to
// catch data races in the server + working tree under load).
func TestConcurrentClientsStress(t *testing.T) {
	_, addr := serveFS(t)
	const clients, opsPer = 16, 40
	var wg sync.WaitGroup
	errCh := make(chan error, clients)
	for c := 0; c < clients; c++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			cli, err := Dial(addr, 4)
			if err != nil {
				errCh <- err
				return
			}
			defer cli.Close()
			if _, st, _ := cli.Mkdir(fmt.Sprintf("c%d", id), 0o755); st != OK {
				errCh <- fmt.Errorf("mkdir c%d st=%d", id, st)
				return
			}
			for i := 0; i < opsPer; i++ {
				p := fmt.Sprintf("c%d/f%d", id, i)
				data := []byte(fmt.Sprintf("client %d op %d payload", id, i))
				if _, st, _ := cli.Create(p, 0o644); st != OK {
					errCh <- fmt.Errorf("create %s st=%d", p, st)
					return
				}
				if _, st, _ := cli.Write(p, 0, data, 0o644); st != OK {
					errCh <- fmt.Errorf("write %s st=%d", p, st)
					return
				}
				got, st, _ := cli.Read(p, 0, 256)
				if st != OK || string(got) != string(data) {
					errCh <- fmt.Errorf("read %s = %q, want %q", p, got, data)
					return
				}
			}
		}(c)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

// TestProtocolErrors checks errno mapping for missing paths.
func TestProtocolErrors(t *testing.T) {
	c := serve(t)
	if _, st, _ := c.Getattr("nope.txt"); st != ENOENT {
		t.Fatalf("getattr missing st=%d, want ENOENT", st)
	}
	if _, _, st, _ := c.Readdir("nodir"); st != ENOENT {
		t.Fatalf("readdir missing st=%d, want ENOENT", st)
	}
	if st, _ := c.Remove("ghost"); st != ENOENT {
		t.Fatalf("remove missing st=%d, want ENOENT", st)
	}
}
