package cli

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/fusefrontend"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// blockingReadFS is an authority whose content reads for one path park until
// the test releases them. It stands in for the real thing a read blocks on —
// a delegation recall traveling to another mount — with the same shape the
// frontend sees: the request is admitted, the reply cannot be produced yet.
type blockingReadFS struct {
	*workfs.FS

	path       string
	armed      atomic.Bool
	enterOnce  sync.Once
	releaseOne sync.Once
	entered    chan struct{}
	release    chan struct{}
}

// releaseAll unparks every held read; safe from the test body and cleanup.
func (f *blockingReadFS) releaseAll() {
	f.releaseOne.Do(func() { close(f.release) })
}

func (f *blockingReadFS) hold(name string) {
	if !f.armed.Load() || name != f.path {
		return
	}
	f.enterOnce.Do(func() { close(f.entered) })
	<-f.release
}

func (f *blockingReadFS) ReadHandleAt(name string, ino uint64, p []byte, off int64) (int, error) {
	f.hold(name)
	return f.FS.ReadHandleAt(name, ino, p, off)
}

func (f *blockingReadFS) Open(name string) (billy.File, error) {
	f.hold(name)
	return f.FS.Open(name)
}

// newBlockingReadAuthority serves the in-memory authority used by the other
// non-kernel tests in this package, with content reads for path parkable.
func newBlockingReadAuthority(t *testing.T, path string) (string, *blockingReadFS) {
	t.Helper()
	wfs := newManagedTestFS(t, noBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	blocked := &blockingReadFS{
		FS:      wfs,
		path:    path,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		blocked.releaseAll()
		cancel()
		_ = ln.Close()
	})
	go func() { _ = fsproto.NewServer(blocked, wfs).Serve(ctx, ln) }()
	return ln.Addr().String(), blocked
}

// TestFUSEReadSuspendsPublicationForAnAuthorityWait drives the whole chain the
// FUSE frontend was missing: fuseNode.Read binds a gate operation, clientcore
// reports the authority wait on that context, and the gate takes the admitted
// reply out of the drain set for exactly the length of the wait.
//
// It is the two-machine incident geometry reduced to one process: the drain
// must complete while the read is stuck on the authority, and the read must not
// reach the kernel until the handoff it unblocked has finished.
func TestFUSEReadSuspendsPublicationForAnAuthorityWait(t *testing.T) {
	const payload = "delegated bytes"
	addr, blocked := newBlockingReadAuthority(t, "f")
	seedFile(t, seedClient(t, addr), "f", payload)

	gate := &fusefrontend.ReplyGate{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// The exact hook set mountFUSE installs.
	vol, err := clientcore.Dial(ctx, clientcore.Options{
		Addr:            addr,
		Pool:            4,
		Owner:           "portablefs-replygate-test",
		WALDir:          t.TempDir(),
		VolumeID:        "replygate-test",
		OnHandoffStart:  gate.BeginHandoff,
		OnHandoffEnd:    gate.EndHandoff,
		OnOperationWait: gate.SuspendOperation,
	})
	if err != nil {
		t.Fatalf("dial authority: %v", err)
	}
	t.Cleanup(func() { _ = vol.Close() })

	attr, st := vol.Lookup(ctx, "f")
	if st != fsproto.OK {
		t.Fatalf("lookup: %d", st)
	}
	node := &fuseNode{
		v:         vol,
		path:      "f",
		state:     clientcore.NewNodeState(attr.Ino, attr.Ino != 0),
		replyGate: gate,
	}
	fh, _, eno := node.Open(ctx, uint32(syscall.O_RDONLY))
	if eno != 0 {
		t.Fatalf("open: %v", eno)
	}

	type readOutcome struct {
		result fuse.ReadResult
		eno    syscall.Errno
	}
	done := make(chan readOutcome, 1)
	blocked.armed.Store(true)
	go func() {
		result, eno := node.Read(ctx, fh, make([]byte, len(payload)), 0)
		done <- readOutcome{result: result, eno: eno}
	}()

	select {
	case <-blocked.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("read never reached the authority")
	}

	// The read is admitted and stuck on the authority. Before the fix this
	// drain waited on it forever.
	handoff := make(chan error, 1)
	go func() { handoff <- gate.BeginHandoff(ctx, "") }()
	select {
	case err := <-handoff:
		if err != nil {
			t.Fatalf("handoff drain: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handoff drain waited on a read that was waiting on the authority")
	}

	// A closed scope gates content replies only: an advisory-lock request,
	// which publishes nothing through the gate, still runs to the authority.
	if _, err := vol.Getlk(ctx, "f", 1, 0, 0, false); err != nil {
		t.Fatalf("advisory lock query blocked by a closed scope: %v", err)
	}

	blocked.releaseAll()
	select {
	case out := <-done:
		t.Fatalf("read published inside the closed scope: eno=%v result=%v", out.eno, out.result)
	case <-time.After(100 * time.Millisecond):
	}

	gate.EndHandoff("")
	var out readOutcome
	select {
	case out = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("read never resumed after the handoff ended")
	}
	if out.eno != 0 {
		t.Fatalf("read after handoff: %v", out.eno)
	}
	got, status := out.result.Bytes(make([]byte, len(payload)))
	if status != fuse.OK || string(got) != payload {
		t.Fatalf("read content = %q status=%v, want %q", got, status, payload)
	}

	// The resumed reply is admitted again: it holds the next drain until
	// go-fuse publishes it.
	next := make(chan error, 1)
	go func() { next <- gate.BeginHandoff(ctx, "") }()
	select {
	case err := <-next:
		t.Fatalf("resumed reply left the drain set early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	out.result.Done()
	select {
	case err := <-next:
		if err != nil {
			t.Fatalf("drain after publication: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("published reply never left the drain set")
	}
	gate.EndHandoff("")
}
