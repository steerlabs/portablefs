package clientcore

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"

	"github.com/steerlabs/portablefs/vcs/internal/delegation"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// serveWorkfs is serveCore returning the backing workfs.FS too, for tests
// that assert authority-side open/orphan state directly.
func serveWorkfs(t *testing.T) (*workfs.FS, string) {
	t.Helper()
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.New(nil, testBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := fsproto.NewServer(fs, fs, delegation.New())
	go func() { _ = srv.Serve(ctx, ln) }()
	return fs, ln.Addr().String()
}

// serveBilly serves a plain in-memory billy fs: no version stamps, no
// ParentVersion, no open-state — the capability-less legacy authority shape.
func serveBilly(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := fsproto.NewServer(memfs.New(), nil, nil)
	go func() { _ = srv.Serve(ctx, ln) }()
	return ln.Addr().String()
}

// createOpened drives the volume exactly like a kernel CREATE: create the
// name, then register the returned inode as opened. Returns the NodeState
// holding one open handle plus the inode.
func createOpened(t *testing.T, v *Volume, path string) (*NodeState, uint64) {
	t.Helper()
	a, st := v.Create(context.Background(), path, 0o644)
	if st != fsproto.OK {
		t.Fatalf("create %s: %d", path, st)
	}
	if a.Ino == 0 {
		t.Fatalf("create %s: authority assigned no inode", path)
	}
	n := NewNodeState(a.Ino, true)
	if st := v.RegisterOpened(path, n); st != fsproto.OK {
		t.Fatalf("register-open %s: %d", path, st)
	}
	return n, a.Ino
}

// TestRetainedReopenZeroRPCStillParksPeerUnlink is the frozen open-vs-unlink
// guarantee exercised through the NEW zero-RPC path: a re-open served from
// the retained registration (no MarkOpen round-trip at all) must still leave
// the mount protected — a peer unlink immediately after the open returns
// parks the inode, and the open handle keeps serving reads.
func TestRetainedReopenZeroRPCStillParksPeerUnlink(t *testing.T) {
	_, addr := serveWorkfs(t)
	a := dialCore(t, addr, Options{Owner: "client-a"})
	b := dialCore(t, addr, Options{Owner: "client-b"})
	ictx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.StartInvalidations(ictx, false)
	ctx := context.Background()

	n, ino := createOpened(t, a, "keep.txt")
	if _, st := a.Write(ctx, "keep.txt", n, 0, []byte("retained")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}
	a.CloseHandle("keep.txt", n) // last close: registration retained, unmark deferred

	// Re-open: must cost ZERO authority round-trips (the retained
	// registration is reused; the hold is already applied server-side).
	n2 := NewNodeState(ino, true)
	before := opCount(a)
	if st := a.Open(ctx, "keep.txt", n2, false); st != fsproto.OK {
		t.Fatalf("re-open: %d", st)
	}
	if got := opCount(a) - before; got != 0 {
		t.Fatalf("retained re-open cost %d authority ops, want 0", got)
	}

	// Peer unlink immediately after the open returned: the inode MUST park.
	if st := b.Remove(ctx, "keep.txt", nil); st != fsproto.OK {
		t.Fatalf("peer remove: %d", st)
	}
	if _, st, err := a.client.GetattrOrphan(ino); err != nil || st != fsproto.OK {
		t.Fatalf("inode not parked after peer unlink of a zero-RPC open: st=%d err=%v", st, err)
	}
	// The open handle keeps serving (path gone -> ino redirect), the frozen
	// "grep'd file unlinked mid-read" behavior.
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, st := a.Read(ctx, "keep.txt", n2, 0, 8)
		if st == fsproto.OK && string(data) == "retained" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("open handle broken after peer unlink: %q st=%d", data, st)
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.CloseHandle("keep.txt", n2)
}

// TestSelfRemoveOfRetainedFileDestroys: a retained (closed) registration must
// not make this mount's OWN remove park the inode — the release rides ahead
// of the remove (the op-order flush window), so the remove destroys exactly
// as it did before retention existed.
func TestSelfRemoveOfRetainedFileDestroys(t *testing.T) {
	_, addr := serveWorkfs(t)
	a := dialCore(t, addr, Options{Owner: "client-a"})
	ctx := context.Background()

	n, ino := createOpened(t, a, "gone.txt")
	a.CloseHandle("gone.txt", n) // retained

	if st := a.Remove(ctx, "gone.txt", nil); st != fsproto.OK {
		t.Fatalf("self remove: %d", st)
	}
	if _, st := a.Lookup(ctx, "gone.txt"); st != fsproto.ENOENT {
		t.Fatalf("lookup after remove: %d, want ENOENT", st)
	}
	if _, st, err := a.client.GetattrOrphan(ino); err != nil || st != fsproto.ENOENT {
		t.Fatalf("self-removed retained file must be DESTROYED, found parked orphan: st=%d err=%v", st, err)
	}
}

// TestPeerUnlinkOfRetainedFileReleasesViaInvalidation: a peer's unlink of a
// file this mount merely retains (no live handle) parks briefly, but the
// Orphaned invalidation drops the retention and unmarks, so orphan lease GC
// can reap — retention never pins another mount's delete indefinitely.
func TestPeerUnlinkOfRetainedFileReleasesViaInvalidation(t *testing.T) {
	prevTTL := workfs.OrphanLeaseTTL
	workfs.OrphanLeaseTTL = 100 * time.Millisecond
	t.Cleanup(func() { workfs.OrphanLeaseTTL = prevTTL })

	fs, addr := serveWorkfs(t)
	a := dialCore(t, addr, Options{Owner: "client-a"})
	b := dialCore(t, addr, Options{Owner: "client-b"})
	ictx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.StartInvalidations(ictx, false)
	ctx := context.Background()

	n, ino := createOpened(t, a, "peer-gone.txt")
	a.CloseHandle("peer-gone.txt", n) // retained; renewal would keep the hold alive

	if st := b.Remove(ctx, "peer-gone.txt", nil); st != fsproto.OK {
		t.Fatalf("peer remove: %d", st)
	}
	// A's Orphaned invalidation must release the retained hold; once the
	// unmark applies and the (shortened) orphan lease lapses, a sweep reaps.
	deadline := time.Now().Add(5 * time.Second)
	for {
		fs.SweepExpiredOrphans(time.Now())
		if _, st, err := a.client.GetattrOrphan(ino); err == nil && st == fsproto.ENOENT {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("retained registration pinned a peer-unlinked inode: never reaped")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestRetentionEvictionUnmarksSoRemoveDestroys: over-cap retained
// registrations are released (batched unmark), after which a peer remove
// destroys — eviction really gives the hold up.
func TestRetentionEvictionUnmarksSoRemoveDestroys(t *testing.T) {
	_, addr := serveWorkfs(t)
	a := dialCore(t, addr, Options{Owner: "client-a", OpenRetentionEntries: 1})
	b := dialCore(t, addr, Options{Owner: "client-b"})
	ctx := context.Background()

	n1, ino1 := createOpened(t, a, "evict-a.txt")
	a.CloseHandle("evict-a.txt", n1)
	n2, _ := createOpened(t, a, "evict-b.txt")
	a.CloseHandle("evict-b.txt", n2) // cap 1: evicts evict-a's registration

	// The eviction unmark is batched asynchronously; its completion is
	// observable as the registry entry disappearing (the reply arrived, so
	// the hold is gone server-side too — reply follows apply).
	deadline := time.Now().Add(5 * time.Second)
	for {
		a.openReg.mu.Lock()
		_, present := a.openReg.entries[ino1]
		a.openReg.mu.Unlock()
		if !present {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("eviction unmark never completed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := b.Remove(ctx, "evict-a.txt", nil); st != fsproto.OK {
		t.Fatalf("peer remove: %d", st)
	}
	if _, st, err := b.client.GetattrOrphan(ino1); err != nil || st != fsproto.ENOENT {
		t.Fatalf("evicted registration must not park: orphan stat st=%d err=%v", st, err)
	}
}

// TestNegativeCacheDefaultsOnAgainstStampingAuthority is the default-on
// cross-client coherence proof: with NO explicit option the volume enables
// the negative cache because the authority advertises FeatParentVersion —
// repeat ENOENT probes cost zero round-trips, and a peer's create of the
// probed name is observed promptly via the parent-version invalidation.
func TestNegativeCacheDefaultsOnAgainstStampingAuthority(t *testing.T) {
	addr := serveCore(t)
	a := dialCore(t, addr, Options{Owner: "client-a"}) // no NegativeCache flag: capability-auto
	b := dialCore(t, addr, Options{Owner: "client-b"})
	ictx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.StartInvalidations(ictx, false)
	time.Sleep(100 * time.Millisecond) // let the subscribe stream attach

	ctx := context.Background()
	if !a.negativeCache {
		t.Fatal("negative cache must default ON against a ParentVersion-stamping authority")
	}
	if _, st := b.Mkdir(ctx, "auto", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	if st := waitLookup(t, a, "auto", fsproto.OK); st != fsproto.OK {
		t.Fatalf("A never saw auto: %d", st)
	}
	if _, st := a.Lookup(ctx, "auto/missing.json"); st != fsproto.ENOENT {
		t.Fatalf("initial probe: %d", st)
	}
	cached := opCount(a)
	for i := 0; i < 5; i++ {
		if _, st := a.Lookup(ctx, "auto/missing.json"); st != fsproto.ENOENT {
			t.Fatalf("cached probe %d: %d", i, st)
		}
	}
	if got := opCount(a) - cached; got != 0 {
		t.Fatalf("default-on cached ENOENT probes cost %d authority ops, want 0", got)
	}
	// Coherence: B creates the exact probed name; A must observe it via the
	// parent-version invalidation, never serve the stale negative.
	if _, st := b.Create(ctx, "auto/missing.json", 0o644); st != fsproto.OK {
		t.Fatalf("B create: %d", st)
	}
	if st := waitLookup(t, a, "auto/missing.json", fsproto.OK); st != fsproto.OK {
		t.Fatalf("A still sees ENOENT after B's create: %d (stale negative)", st)
	}
}

// TestNegativeCacheAutoStaysOffWithoutCapability: against an authority that
// does not advertise FeatParentVersion the default must remain OFF (probes
// keep round-tripping; nothing is sniffed from response fields), and the
// explicit opt-out keeps it off even against a capable authority.
func TestNegativeCacheAutoStaysOffWithoutCapability(t *testing.T) {
	legacyAddr := serveBilly(t)
	a := dialCore(t, legacyAddr, Options{Owner: "client-a"})
	if a.negativeCache {
		t.Fatal("negative cache must stay OFF against an authority without FeatParentVersion")
	}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		before := opCount(a)
		if _, st := a.Lookup(ctx, "nope.json"); st != fsproto.ENOENT {
			t.Fatalf("probe %d: %d", i, st)
		}
		if got := opCount(a) - before; got == 0 {
			t.Fatalf("probe %d served without a round-trip against a capability-less authority", i)
		}
	}

	capableAddr := serveCore(t)
	off := dialCore(t, capableAddr, Options{Owner: "client-off", NoNegativeCache: true})
	if off.negativeCache {
		t.Fatal("NoNegativeCache must force the cache off even against a capable authority")
	}
}
