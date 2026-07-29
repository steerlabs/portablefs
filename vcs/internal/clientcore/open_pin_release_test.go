package clientcore

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// TestDelegatedSelfReadNeverServesStaleCache pins the fold-then-read shape
// (the git index.lock churn failure): under a HELD delegation, our own
// flushed mutations are owner-suppressed on the invalidation stream, so the
// version-gated disk cache can never advance for them — after the overlay
// folds an applied write, a cached block from the previous revision would be
// served as current. Covered reads must bypass the disk cache entirely.
func TestDelegatedSelfReadNeverServesStaleCache(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{
		Owner: "self-read", VolumeID: "vol-selfread", Branch: "main",
		WALDir:       t.TempDir(),
		DiskCacheDir: t.TempDir(), DiskCacheBytes: 64 << 20,
	})
	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "d/index", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	for i := 0; i < 10; i++ {
		content := fmt.Sprintf("rev-%03d", i)
		if _, st := v.Write(ctx, "d/index", n, 0, []byte(content)); st != fsproto.OK {
			t.Fatalf("iter %d write: %d", i, st)
		}
		// Drain: the flush applies and the overlay FOLDS the extents, so the
		// next read composes entirely from the base lane. The fold runs just
		// after the drain waiter wakes; settle so the read deterministically
		// exercises the base path (the failure shape).
		if err := v.FlushToAuthority(ctx); err != nil {
			t.Fatalf("iter %d drain: %v", i, err)
		}
		time.Sleep(25 * time.Millisecond)
		data, st := v.Read(ctx, "d/index", n, 0, 4096)
		if st != fsproto.OK {
			t.Fatalf("iter %d read: %d", i, st)
		}
		if string(data) != content {
			t.Fatalf("iter %d: self read = %q after writing %q — a version-stale cached block served the previous revision", i, data, content)
		}
	}
}

// TestDelegatedCreateOpenSurvivesPeerUnlink pins the open-pin half of the
// delegation lifecycle: a file CREATED AND HELD OPEN under a delegation
// gains an authority open pin before the delegation releases, so a peer
// unlink PARKS the inode (open-after-unlink) instead of destroying it — the
// creator's handle keeps reading its bytes through the orphan redirect while
// the name is gone for everyone.
func TestDelegatedCreateOpenSurvivesPeerUnlink(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()

	var mu sync.Mutex
	orphaned := map[string]uint64{}
	writer := dialCore(t, addr, Options{
		Owner: "pin-writer", VolumeID: "vol-pin", Branch: "main",
		WALDir: t.TempDir(),
		OnMarkOrphan: func(path string, ino uint64) {
			mu.Lock()
			orphaned[path] = ino
			mu.Unlock()
		},
	})
	watchInvalidationsForTest(t, writer)

	if _, st := writer.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := writer.Create(ctx, "d/held", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	if !writer.wb.Covers("d/held") {
		t.Fatal("precondition: the create was delegated")
	}
	n := NewNodeState(InoOf("d/held"), a.Ino != 0)
	if st := writer.Open(ctx, "d/held", n, true); st != fsproto.OK {
		t.Fatalf("open: %d", st)
	}
	if _, st := writer.Write(ctx, "d/held", n, 0, []byte("survives")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}

	// The peer unlink: the gate recalls the writer's delegation; the writer
	// drains, PINS the open handle, and releases; the unlink then parks.
	peer := dialCore(t, addr, Options{Owner: "pin-peer"})
	if st := peer.Remove(ctx, "d/held", nil); st != fsproto.OK {
		t.Fatalf("peer remove: %d", st)
	}

	// The name is gone for everyone.
	if _, st := peer.Lookup(ctx, "d/held"); st != fsproto.ENOENT {
		t.Fatalf("peer lookup after unlink: %d, want ENOENT", st)
	}

	// The writer's live handle redirects to the parked orphan and keeps its
	// exact bytes (the invalidation stream delivers the orphan marker).
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		ino, ok := orphaned["d/held"]
		mu.Unlock()
		if ok {
			if !n.MatchesAuthorityIno(ino) {
				t.Fatalf("release-time pin did not bind local node to authority inode %d", ino)
			}
			n.MarkOrphan(ino, writer.OpenOrphans())
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no orphan invalidation reached the creator: the unlink DESTROYED an inode a client held open")
		}
		time.Sleep(10 * time.Millisecond)
	}
	data, st := writer.Read(ctx, "d/held", n, 0, 64)
	if st != fsproto.OK || string(data) != "survives" {
		t.Fatalf("open-after-unlink read = %q st=%d, want \"survives\"", data, st)
	}
	// The parked inode must SURVIVE the asynchronous reap sweep: without the
	// release-time pin, every unlink parks briefly and the sweep destroys
	// the unpinned orphan within milliseconds — the open handle would then
	// start failing. The durable pin is what keeps it alive while held open.
	deadline = time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		data, st := writer.Read(ctx, "d/held", n, 0, 64)
		if st != fsproto.OK || string(data) != "survives" {
			t.Fatalf("open handle lost its inode to the reap sweep (read = %q st=%d): no durable open pin protected it", data, st)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
