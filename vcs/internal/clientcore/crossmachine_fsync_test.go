package clientcore

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// latencyProxy forwards TCP with a fixed delay on SERVER→CLIENT bytes: the
// realistic WAN shape in which an invalidation takes milliseconds to reach a
// peer — the window in which the peer's version-gated caches serve the
// previous content unless the fsync barrier waits for its acknowledgment.
type latencyProxy struct {
	ln    net.Listener
	delay time.Duration
}

func newLatencyProxy(t *testing.T, backend string, delay time.Duration) *latencyProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &latencyProxy{ln: ln, delay: delay}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			server, err := net.Dial("tcp", backend)
			if err != nil {
				_ = client.Close()
				continue
			}
			go func() { _, _ = io.Copy(server, client); _ = server.Close() }() // client→server: direct
			go func() {                                                        // server→client: delayed
				defer client.Close()
				buf := make([]byte, 32<<10)
				for {
					n, err := server.Read(buf)
					if n > 0 {
						time.Sleep(delay)
						if _, werr := client.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return p
}

func (p *latencyProxy) addr() string { return p.ln.Addr().String() }

// TestCrossMachineReadAfterFsyncExact is the e2e Flow C rewrite-loop shape as
// a two-client harness against one shared authority: the writer rewrites a
// file and fsyncs; the peer reads IMMEDIATELY after the fsync returns. A
// completed fsync must be visible to every connected peer's subsequent reads
// — the barrier waits for the peer's invalidation acknowledgment, so ZERO
// stale reads are tolerated (this closed a measured ~8.5% staleness in a
// ~13ms window). The loop crosses both lanes: the first iterations run under
// the writer's delegation (peer read recalls it), later ones write-through
// under the contention cooldown.
func TestCrossMachineReadAfterFsyncExact(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()

	writer := dialCore(t, addr, Options{
		Owner: "fsync-writer", VolumeID: "vol-xmach", Branch: "main",
		WALDir: t.TempDir(),
	})
	watchInvalidationsForTest(t, writer) // recalls ride this stream
	// The peer sits behind ~8ms of server→client latency: without the
	// barrier's ack wait, its version-gated disk cache serves the previous
	// acked content for that window after every fsync (the measured e2e
	// staleness shape). The neutered-barrier control run reads stale here.
	peerProxy := newLatencyProxy(t, addr, 8*time.Millisecond)
	peer := dialCore(t, peerProxy.addr(), Options{
		Owner: "fsync-peer", VolumeID: "vol-xmach", Branch: "main",
		DiskCacheDir: t.TempDir(), DiskCacheBytes: 64 << 20,
	})
	watchInvalidationsForTest(t, peer) // the peer's acks gate the barrier

	if _, st := writer.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := writer.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	wn := NewNodeState(a.Ino, a.Ino != 0)

	// The peer resolves the file once so it holds a cacheable identity.
	pattr, st := peer.Lookup(ctx, "d/f")
	if st != fsproto.OK {
		t.Fatalf("peer lookup: %d", st)
	}
	pn := NewNodeState(pattr.Ino, pattr.Ino != 0)
	// Reads request past EOF (the kernel shape), which is what makes the
	// short read cacheable — the peer then serves subsequent reads from its
	// version-gated disk cache until an invalidation advances the version.
	const readSpan = 4096

	const iterations = 200
	stale := 0
	for i := 0; i < iterations; i++ {
		content := fmt.Sprintf("rev-%06d-payload", i)
		if _, st := writer.Write(ctx, "d/f", wn, 0, []byte(content)); st != fsproto.OK {
			t.Fatalf("iteration %d write: %d", i, st)
		}
		if err := writer.Fsync("d/f"); err != nil {
			t.Fatalf("iteration %d fsync: %v", i, err)
		}
		data, st := peer.Read(ctx, "d/f", pn, 0, readSpan)
		if st != fsproto.OK {
			t.Fatalf("iteration %d peer read: %d", i, st)
		}
		if string(data) != content {
			stale++
			t.Errorf("iteration %d: peer read %q after fsync of %q — STALE", i, data, content)
		}
	}
	if stale != 0 {
		t.Fatalf("%d/%d stale peer reads after fsync; the barrier must make fsync cross-machine exact", stale, iterations)
	}
}
