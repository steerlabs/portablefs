package cli

import (
	"context"
	"net"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/fusefrontend"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// zeroProgressFS is an authority that ADMITS a write and commits none of it.
// The record is ordered and journaled exactly as it arrived; it simply carries
// no bytes, so the reply is the one shape a frontend cannot pass on: status OK
// with a committed count of zero for a non-empty payload.
//
// It is not a contrived reply. Every lane that can reach a frontend write has a
// zero-count-with-OK outcome — the engine's paced write path returns one when a
// wait cap expires with a healthy uplink, and the authority lane returns
// whatever count the authority recorded — so the frontend must have an answer
// for it that is not "success".
type zeroProgressFS struct {
	*workfs.FS

	path  string
	armed atomic.Bool
}

func (f *zeroProgressFS) MutateEnvGated(
	r wal.Record,
	owner string,
	paths ...string,
) (workfs.MutationResult, error) {
	if f.armed.Load() && r.Op == wal.OpWrite && r.Path == f.path {
		r.Data = nil
	}
	return f.FS.MutateEnvGated(r, owner, paths...)
}

func newZeroProgressAuthority(t *testing.T, path string) (string, *zeroProgressFS) {
	t.Helper()
	wfs := newManagedTestFS(t, noBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	zp := &zeroProgressFS{FS: wfs, path: path}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})
	go func() { _ = fsproto.NewServer(zp, wfs).Serve(ctx, ln) }()
	return ln.Addr().String(), zp
}

// newZeroProgressNode dials a volume onto the zero-progress authority and
// builds the fuseNode for path, with no kernel mount anywhere in the picture.
//
// PORTABLEFS_DEBUG_WRITE_THROUGH pins the AUTHORITY lane, which is the lane
// whose count comes back over the wire. A delegated write would be absorbed by
// the local overlay and never reach the authority at all, so the outcome under
// test would be unreachable.
func newZeroProgressNode(t *testing.T, path string) (*fuseNode, *zeroProgressFS) {
	t.Helper()
	t.Setenv("PORTABLEFS_DEBUG_WRITE_THROUGH", "1")

	addr, zp := newZeroProgressAuthority(t, path)
	seedFile(t, seedClient(t, addr), path, "seed")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	vol, err := clientcore.Dial(ctx, clientcore.Options{
		Addr:     addr,
		Pool:     4,
		Owner:    "portablefs-zero-progress-test",
		WALDir:   t.TempDir(),
		VolumeID: "zero-progress-test",
	})
	if err != nil {
		t.Fatalf("dial authority: %v", err)
	}
	t.Cleanup(func() { _ = vol.Close() })

	attr, st := vol.Lookup(ctx, path)
	if st != fsproto.OK {
		t.Fatalf("lookup %s: %d", path, st)
	}
	return &fuseNode{
		v:         vol,
		path:      path,
		state:     clientcore.NewNodeState(attr.Ino, attr.Ino != 0),
		replyGate: &fusefrontend.ReplyGate{},
	}, zp
}

// TestFUSEWriteWithZeroCommittedProgressIsEIO pins the zero-progress rule on
// the FUSE frontend.
//
// A write(2) that returns 0 for a non-empty buffer is not a short write. POSIX
// gives an application no way to act on it: the buffer is non-empty, nothing
// was written, and no error says why. Every libc write loop and every
// io.Writer-shaped caller treats "make no progress and report no error" as a
// reason to call again with the same buffer, so the honest outcomes are a
// positive count or an errno — and this frontend has already made exactly that
// argument one layer up, where AdmitWrite refuses to hand back a zero grant
// without an error "because a zero-length successful write is not a signal any
// kernel write path can act on". The committed count must obey the same rule as
// the granted count.
func TestFUSEWriteWithZeroCommittedProgressIsEIO(t *testing.T) {
	node, zp := newZeroProgressNode(t, "f")
	ctx := context.Background()

	fh, _, eno := node.Open(ctx, uint32(syscall.O_WRONLY))
	if eno != 0 {
		t.Fatalf("open: %v", eno)
	}

	// Healthy first: a write that commits everything is a full write, and
	// nothing about this rule may change that.
	payload := []byte("bytes an application must never be told were written")
	cnt, eno := node.Write(ctx, fh, payload, 0)
	if eno != 0 || int(cnt) != len(payload) {
		t.Fatalf("committed write: cnt=%d eno=%v, want %d/0", cnt, eno, len(payload))
	}

	zp.armed.Store(true)
	cnt, eno = node.Write(ctx, fh, payload, 0)
	if eno != syscall.EIO {
		t.Fatalf("a write that committed nothing replied cnt=%d eno=%v; "+
			"want EIO — a zero-byte success for a %d-byte payload tells the "+
			"application no progress is possible and gives it no error to act on",
			cnt, eno, len(payload))
	}
	if cnt != 0 {
		t.Fatalf("a refused write reported %d bytes written", cnt)
	}
}

// TestFUSEAppendWithZeroCommittedProgressIsEIO is the same rule on the O_APPEND
// lane, which reaches a different clientcore entry point (WriteAppend) and is
// the lane where a retry cannot land on the first copy — so a frontend that
// answers "success, zero bytes" there invites the retry that duplicates the
// record.
func TestFUSEAppendWithZeroCommittedProgressIsEIO(t *testing.T) {
	node, zp := newZeroProgressNode(t, "f")
	ctx := context.Background()

	fh, _, eno := node.Open(ctx, uint32(syscall.O_WRONLY|syscall.O_APPEND))
	if eno != 0 {
		t.Fatalf("open: %v", eno)
	}
	if h, ok := fh.(*fuseHandle); !ok || !h.append {
		t.Fatalf("open did not produce an appending handle: %#v", fh)
	}

	payload := []byte("appended bytes")
	cnt, eno := node.Write(ctx, fh, payload, 0)
	if eno != 0 || int(cnt) != len(payload) {
		t.Fatalf("committed append: cnt=%d eno=%v, want %d/0", cnt, eno, len(payload))
	}

	zp.armed.Store(true)
	cnt, eno = node.Write(ctx, fh, payload, 0)
	if eno != syscall.EIO {
		t.Fatalf("an append that committed nothing replied cnt=%d eno=%v; want EIO", cnt, eno)
	}
	if cnt != 0 {
		t.Fatalf("a refused append reported %d bytes written", cnt)
	}
}
