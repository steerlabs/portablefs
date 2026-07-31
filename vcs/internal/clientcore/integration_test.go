package clientcore

import (
	"context"
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

type testBlobs struct{}

func (testBlobs) Blob(context.Context, string) ([]byte, error) {
	return nil, errors.New("no backed blobs in clientcore tests")
}

func serveCore(t *testing.T) string {
	t.Helper()
	addr, _ := serveCoreServer(t)
	return addr
}

func serveCoreServer(t *testing.T) (string, *fsproto.Server) {
	t.Helper()
	fs := newManagedTestFS(t, testBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := fsproto.NewServer(fs, fs)
	go func() { _ = srv.Serve(ctx, ln) }()
	return ln.Addr().String(), srv
}

func dialCore(t *testing.T, addr string, opts Options) *Volume {
	t.Helper()
	opts.Addr = addr
	opts.Pool = 4
	v, err := Dial(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

// watchInvalidationsForTest starts the mount's invalidation stream and waits
// for the subscription to establish. Delegation recalls ride this stream, so
// any test that needs a holder to hand its scope to a contender (or that
// observes peer invalidations) starts it explicitly.
func watchInvalidationsForTest(t *testing.T, v *Volume) {
	t.Helper()
	ictx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go v.StartInvalidations(ictx, false)
	time.Sleep(50 * time.Millisecond)
}

func dialCoreNoCleanup(t *testing.T, addr string, opts Options) *Volume {
	t.Helper()
	opts.Addr = addr
	opts.Pool = 4
	v, err := Dial(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func opCount(v *Volume) int64 {
	return v.Metrics.Counter("authority_ops_total").Value()
}

func TestAuthorityMutationCannotRaceSameMountDelegationInstallation(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{})
	watchInvalidationsForTest(t, v)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	if _, st := v.Create(ctx, "d/seed", 0o644); st != fsproto.OK {
		t.Fatalf("delegated seed create: %d", st)
	}
	if !v.wb.Covers("d/seed") {
		t.Fatal("seed create did not install the prerequisite delegation")
	}

	authorityCtx, endAuthority, err := v.beginAuthorityMutation(ctx, nil, "d/authority")
	if err != nil {
		t.Fatalf("begin authority mutation: %v", err)
	}
	if v.wb.Covers("d/seed") {
		endAuthority()
		t.Fatal("authority lane retained an overlapping delegation")
	}

	concurrentDone := make(chan Status, 1)
	go func() {
		_, st := v.Create(ctx, "d/concurrent", 0o644)
		concurrentDone <- st
	}()
	select {
	case st := <-concurrentDone:
		endAuthority()
		t.Fatalf("delegation acquisition crossed authority RPC lane: %d", st)
	case <-time.After(30 * time.Millisecond):
	}

	resp, callErr := v.client.DoContext(authorityCtx, &fsproto.Request{
		Op: fsproto.OpCreate, Path: "d/authority", Mode: 0o644,
	})
	endAuthority()
	st := int32(fsproto.EIO)
	if resp != nil {
		st = resp.Status
	}
	if callErr != nil || st != fsproto.OK {
		t.Fatalf("authority create: status=%d err=%v", st, callErr)
	}
	select {
	case st := <-concurrentDone:
		if st != fsproto.OK {
			t.Fatalf("concurrent create after authority lane: %d", st)
		}
	case <-ctx.Done():
		t.Fatal("delegation acquisition did not resume after authority mutation")
	}
	if err := v.Fsync("d/concurrent"); err != nil {
		t.Fatalf("flush concurrent create: %v", err)
	}
	if _, st, err := v.client.Getattr("d/authority"); err != nil || st != fsproto.OK {
		t.Fatalf("authority file missing: status=%d err=%v", st, err)
	}
	if _, st, err := v.client.Getattr("d/concurrent"); err != nil || st != fsproto.OK {
		t.Fatalf("concurrent file missing: status=%d err=%v", st, err)
	}
}

func TestCoveredDelegatedReadsNeverSuspendTheirPublication(t *testing.T) {
	addr := serveCore(t)
	var waits atomic.Int64
	v := dialCore(t, addr, Options{
		OnOperationWait: func(context.Context) func() {
			waits.Add(1)
			return func() {}
		},
	})
	watchInvalidationsForTest(t, v)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	attr, st := v.Create(ctx, "d/local", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	if !v.wb.Covers("d/local") {
		t.Fatal("test precondition: local file is not covered by a delegation")
	}
	waits.Store(0)
	node := NewNodeState(attr.Ino, attr.Ino != 0)
	if _, st := v.Getattr(ctx, "d/local", node); st != fsproto.OK {
		t.Fatalf("covered getattr: %d", st)
	}
	if _, st := v.Read(ctx, "d/local", node, 0, 1); st != fsproto.OK {
		t.Fatalf("covered read: %d", st)
	}
	if got := waits.Load(); got != 0 {
		t.Fatalf("covered delegated reads suspended publication %d times", got)
	}
}

func TestAuthorityOperationContextsSuspendEveryAuthorityRPC(t *testing.T) {
	addr := serveCore(t)
	var waits atomic.Int64
	var resumes atomic.Int64
	v := dialCore(t, addr, Options{
		OnOperationWait: func(context.Context) func() {
			waits.Add(1)
			return func() { resumes.Add(1) }
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	authorityCtx, endAuthority, err := v.beginAuthorityMutation(ctx, nil, "missing")
	if err != nil {
		t.Fatalf("begin authority mutation: %v", err)
	}
	_, _, _, _, st, callErr := v.client.GetattrVContext(authorityCtx, "missing")
	endAuthority()
	if callErr != nil || st != fsproto.ENOENT {
		t.Fatalf("authority-lane getattr: status=%d err=%v", st, callErr)
	}
	// Three balanced pairs: transition-gate admission, the post-admission
	// extend, and the RPC's own authority-wait bracket. Admission counts
	// because a conflicting active claim can be a remote acquire mid-RPC.
	if waits.Load() != 3 || resumes.Load() != 3 {
		t.Fatalf("authority-lane RPC wait/resume = %d/%d, want 3/3", waits.Load(), resumes.Load())
	}

	exactCtx, endExact, err := v.beginExactOperation(ctx)
	if err != nil {
		t.Fatalf("begin exact operation: %v", err)
	}
	_, _, _, _, st, callErr = v.client.GetattrVContext(exactCtx, "missing")
	endExact()
	if callErr != nil || st != fsproto.ENOENT {
		t.Fatalf("exact-lane getattr: status=%d err=%v", st, callErr)
	}
	// The exact lane adds two more balanced pairs: the write-back engine's
	// exact-exclusion acquisition (whose lock can be held by an acquire
	// resolver across its authority round-trip) and the RPC bracket.
	if waits.Load() != 5 || resumes.Load() != 5 {
		t.Fatalf("exact-lane RPC wait/resume = %d/%d, want 5/5", waits.Load(), resumes.Load())
	}
}

func TestRenameDirectoryReleasesDescendantDelegationBeforeAuthorityRPC(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{})
	watchInvalidationsForTest(t, v)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tree, st := v.Mkdir(ctx, "tree", 0o755)
	if st != fsproto.OK {
		t.Fatalf("mkdir tree: %d", st)
	}
	if _, st := v.Mkdir(ctx, "tree/child", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir child: %d", st)
	}
	// Publish the locally-created child and release the parent grant so the
	// next create deliberately acquires the descendant scope.
	if err := v.wb.ReleaseFor(ctx, "tree"); err != nil {
		t.Fatalf("publish child: %v", err)
	}
	if _, st := v.Create(ctx, "tree/child/file", 0o644); st != fsproto.OK {
		t.Fatalf("create descendant file: %d", st)
	}
	if !v.wb.Covers("tree/child/file") {
		t.Fatal("test precondition: descendant grant was not installed")
	}

	if st := v.Rename(
		ctx,
		"tree",
		"moved",
		NewNodeState(tree.Ino, tree.Ino != 0),
		nil,
	); st != fsproto.OK {
		t.Fatalf("rename delegated ancestor: %d", st)
	}
	if v.wb.Covers("tree/child/file") {
		t.Fatal("rename retained the old descendant delegation")
	}
	if _, st := v.Lookup(ctx, "moved/child/file"); st != fsproto.OK {
		t.Fatalf("renamed descendant lookup: %d", st)
	}
}

func TestVolumePublicOpsEndToEnd(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{})
	ctx := context.Background()

	a, st := v.Create(ctx, "a.txt", 0o644)
	if st != fsproto.OK {
		t.Fatalf("Create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if st := v.Open(ctx, "a.txt", n, true); st != fsproto.OK {
		t.Fatalf("Open: %d", st)
	}
	if got, st := v.Write(ctx, "a.txt", n, 0, []byte("hello")); st != fsproto.OK || got != 5 {
		t.Fatalf("Write: n=%d st=%d", got, st)
	}
	if data, st := v.Read(ctx, "a.txt", n, 0, 5); st != fsproto.OK || string(data) != "hello" {
		t.Fatalf("Read: %q st=%d", data, st)
	}
	if st := v.FsyncPath("a.txt"); st != fsproto.OK {
		t.Fatalf("Fsync: %d", st)
	}
	if _, st := v.Getattr(ctx, "a.txt", n); st != fsproto.OK {
		t.Fatalf("Getattr: %d", st)
	}
	if a, st := v.Setattr(ctx, "a.txt", n, SetattrRequest{Size: 2, SetSize: true}); st != fsproto.OK || a.Size != 2 {
		t.Fatalf("Setattr truncate: size=%d st=%d", a.Size, st)
	}
	if data, st := v.Read(ctx, "a.txt", n, 0, 8); st != fsproto.OK || string(data) != "he" {
		t.Fatalf("Read after truncate: %q st=%d", data, st)
	}
	if _, st := v.Mkdir(ctx, "dir", 0o755); st != fsproto.OK {
		t.Fatalf("Mkdir: %d", st)
	}
	if _, st := v.Symlink(ctx, "target", "sym"); st != fsproto.OK {
		t.Fatalf("Symlink: %d", st)
	}
	if target, st := v.Readlink(ctx, "sym"); st != fsproto.OK || target != "target" {
		t.Fatalf("Readlink: %q st=%d", target, st)
	}
	if ents, st := v.Readdir(ctx, ""); st != fsproto.OK || len(ents) < 3 {
		t.Fatalf("Readdir: len=%d st=%d", len(ents), st)
	}
	if st := v.Rename(ctx, "a.txt", "dir/b.txt", n, nil); st != fsproto.OK {
		t.Fatalf("Rename: %d", st)
	}
	var lh LockHandle
	if res, err := v.Setlk(ctx, &lh, "dir/b.txt", 77, 0, ^uint64(0), true, false); err != nil || res.Status != fsproto.OK {
		t.Fatalf("Setlk: res=%+v err=%v", res, err)
	}
	if res, err := v.Getlk(ctx, "dir/b.txt", 88, 0, ^uint64(0), true); err != nil || !res.Conflict {
		t.Fatalf("Getlk conflict: res=%+v err=%v", res, err)
	}
	ReleaseHandleLocks(v.LockAuth(), &lh)
	v.CloseHandle("a.txt", n)
	if st := v.Remove(ctx, "sym", nil); st != fsproto.OK {
		t.Fatalf("Remove symlink: %d", st)
	}
	if st := v.Remove(ctx, "dir/b.txt", n); st != fsproto.OK {
		t.Fatalf("Remove file: %d", st)
	}
	if st := v.Remove(ctx, "dir", nil); st != fsproto.OK {
		t.Fatalf("Remove dir: %d", st)
	}
	if err := v.FlushToAuthority(ctx); err != nil {
		t.Fatalf("FlushToAuthority: %v", err)
	}
}

func TestRenameOverSameAuthorityInodePreservesAliasesAndOpenPaths(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{Owner: "same-inode-rename"})
	ctx := context.Background()

	source, st := v.Create(ctx, "source", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create source: %d", st)
	}
	sourceState := NewNodeState(source.Ino, source.Ino != 0)
	if n, st := v.Write(ctx, "source", sourceState, 0, []byte("payload")); st != fsproto.OK || n != len("payload") {
		t.Fatalf("write source: n=%d st=%d", n, st)
	}
	linked, st := v.Link(ctx, "source", "alias", sourceState)
	if st != fsproto.OK || linked.Ino != source.Ino || linked.Nlink != 2 {
		t.Fatalf("link alias: attr=%+v st=%d", linked, st)
	}
	aliasState := NewNodeState(linked.Ino, linked.Ino != 0)

	if st := v.Open(ctx, "source", sourceState, true); st != fsproto.OK {
		t.Fatalf("open source: %d", st)
	}
	sourceOpen := true
	defer func() {
		if sourceOpen {
			v.CloseHandle("source", sourceState)
		}
	}()
	if st := v.Open(ctx, "alias", aliasState, true); st != fsproto.OK {
		t.Fatalf("open alias: %d", st)
	}
	aliasOpen := true
	defer func() {
		if aliasOpen {
			v.CloseHandle("alias", aliasState)
		}
	}()

	assertOpenPath := func(openedPath string, node *NodeState) {
		t.Helper()
		got, ok := v.opens.CurrentPath(openedPath, node)
		if !ok || got != openedPath {
			t.Fatalf("current open path for %q = %q, present=%v", openedPath, got, ok)
		}
	}
	assertOpenPath("source", sourceState)
	assertOpenPath("alias", aliasState)

	// POSIX rename is a semantic no-op when old and new are hard-link
	// spellings of the same inode. The authority still validates both names,
	// but client-side rename-over bookkeeping must not remove either name.
	if st := v.Rename(ctx, "source", "alias", sourceState, aliasState); st != fsproto.OK {
		t.Fatalf("same-inode rename: %d", st)
	}

	sourceAfter, st := v.Lookup(ctx, "source")
	if st != fsproto.OK || sourceAfter.Ino != source.Ino || sourceAfter.Nlink != 2 {
		t.Fatalf("source after no-op rename: attr=%+v st=%d", sourceAfter, st)
	}
	aliasAfter, st := v.Lookup(ctx, "alias")
	if st != fsproto.OK || aliasAfter.Ino != source.Ino || aliasAfter.Nlink != 2 {
		t.Fatalf("alias after no-op rename: attr=%+v st=%d", aliasAfter, st)
	}
	assertOpenPath("source", sourceState)
	assertOpenPath("alias", aliasState)
	if sourceState.Orphan() != 0 || aliasState.Orphan() != 0 {
		t.Fatalf(
			"same-inode rename orphaned a live alias: source=%d alias=%d",
			sourceState.Orphan(),
			aliasState.Orphan(),
		)
	}

	aliases := v.hardlinks.pathsForInos([]uint64{source.Ino})
	gotAliases := make(map[string]bool, len(aliases))
	for _, path := range aliases {
		gotAliases[path] = true
	}
	if len(gotAliases) != 2 || !gotAliases["source"] || !gotAliases["alias"] {
		t.Fatalf("same-inode rename changed alias observations: %v", aliases)
	}
	for _, path := range []string{"source", "alias"} {
		data, st := v.Read(ctx, path, NewNodeState(source.Ino, true), 0, len("payload"))
		if st != fsproto.OK || string(data) != "payload" {
			t.Fatalf("read %s after no-op rename: data=%q st=%d", path, data, st)
		}
	}

	if st := v.CloseHandle("source", sourceState); st != fsproto.OK {
		t.Fatalf("close source: %d", st)
	}
	sourceOpen = false
	if st := v.CloseHandle("alias", aliasState); st != fsproto.OK {
		t.Fatalf("close alias: %d", st)
	}
	aliasOpen = false
}

func TestWriteBackAtomicAppendAddsNoHotPathRoundTrips(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{
		Owner:  "append-wb",
		WALDir: t.TempDir(),
	})
	ctx := context.Background()
	// A subtree path so the write-back engine delegates the parent directory
	// (a top-level file's parent is the un-delegable volume root).
	if _, st := v.Mkdir(ctx, "logs", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir logs: %d", st)
	}
	attr, st := v.Create(ctx, "logs/append.log", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	state := NewNodeState(attr.Ino, attr.Ino != 0)
	before := opCount(v)
	const records = 100
	for i := 0; i < records; i++ {
		payload := []byte{byte(i), byte(i >> 8), 0xA5, 0x5A}
		if n, st := v.WriteAppend(ctx, "logs/append.log", state, 0, payload); st != fsproto.OK || n != len(payload) {
			t.Fatalf("append %d: n=%d st=%d", i, n, st)
		}
	}
	if got := opCount(v) - before; got != 0 {
		t.Fatalf("100 write-back appends made %d authority RPCs on the hot path, want 0", got)
	}
	if err := v.FlushToAuthority(ctx); err != nil {
		t.Fatal(err)
	}
	peer := dialCore(t, addr, Options{Owner: "append-reader"})
	data, st := peer.Read(ctx, "logs/append.log", nil, 0, records*4)
	if st != fsproto.OK || len(data) != records*4 {
		t.Fatalf("peer read: len=%d st=%d", len(data), st)
	}
	for i := 0; i < records; i++ {
		record := data[i*4 : i*4+4]
		if record[0] != byte(i) || record[1] != byte(i>>8) || record[2] != 0xA5 || record[3] != 0x5A {
			t.Fatalf("record %d corrupt: %x", i, record)
		}
	}
}

func TestNegativeCacheJunkProbeAndParentVersionBump(t *testing.T) {
	addr := serveCore(t)
	a := dialCore(t, addr, Options{NegativeCache: true})
	b := dialCore(t, addr, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watchInvalidationsForTest(t, a)

	start := opCount(a)
	for i := 0; i < 5; i++ {
		if _, st := a.Lookup(ctx, ".DS_Store"); st != fsproto.ENOENT {
			t.Fatalf(".DS_Store lookup %d: %d", i, st)
		}
		if _, st := a.Lookup(ctx, "._foo"); st != fsproto.ENOENT {
			t.Fatalf("._foo lookup %d: %d", i, st)
		}
	}
	if got := opCount(a) - start; got != 2 {
		t.Fatalf("junk probes authority ops = %d, want 2", got)
	}
	if _, st := b.Create(context.Background(), "created", 0o644); st != fsproto.OK {
		t.Fatalf("remote create: %d", st)
	}
	time.Sleep(200 * time.Millisecond)
	mid := opCount(a)
	if _, st := a.Lookup(ctx, ".DS_Store"); st != fsproto.ENOENT {
		t.Fatalf(".DS_Store after parent bump: %d", st)
	}
	if got := opCount(a) - mid; got != 1 {
		t.Fatalf("post-bump .DS_Store authority ops = %d, want 1", got)
	}
}

func TestSameVolumeCreateEvictsCachedNegativeWithoutEcho(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{NegativeCache: true, Owner: "same-volume-negative"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.Sleep(100 * time.Millisecond)

	if _, st := v.Lookup(ctx, "ext.txt"); st != fsproto.ENOENT {
		t.Fatalf("initial lookup: %d, want ENOENT", st)
	}
	if _, st := v.Create(ctx, "ext.txt", 0o644); st != fsproto.OK {
		t.Fatalf("same-volume create: %d", st)
	}
	if attr, st := v.Lookup(ctx, "ext.txt"); st != fsproto.OK || attr.Kind != "file" {
		t.Fatalf("post-create lookup: attr=%+v st=%d, want file", attr, st)
	}
}

func TestPrefetchTreeLeavesWarmMetadataCache(t *testing.T) {
	addr := serveCore(t)
	seed := dialCoreNoCleanup(t, addr, Options{})
	ctx := context.Background()
	if _, st := seed.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir seed: %d", st)
	}
	for _, p := range []string{"a", "d/b", "d/c"} {
		if _, st := seed.Create(ctx, p, 0o644); st != fsproto.OK {
			t.Fatalf("create %s: %d", p, st)
		}
	}
	// Close the seeder BEFORE prefetching: its creates under d/ ran under a
	// delegation, and close drains + releases, so the tree the prefetcher
	// walks is settled (no mid-walk recall bumping versions and forcing a
	// revalidation).
	if err := seed.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}
	v := dialCore(t, addr, Options{PrefetchTree: true, PrefetchMaxEntries: 10, PrefetchMaxDepth: 4})
	deadline := time.Now().Add(3 * time.Second)
	for {
		if p := v.PrefetchProgress(); p.Done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("prefetch did not finish: %+v", v.PrefetchProgress())
		}
		time.Sleep(10 * time.Millisecond)
	}
	before := opCount(v)
	walkAllMetadata(t, v, "")
	after := opCount(v)
	if after-before != 0 {
		t.Fatalf("prefetched ls-equivalent authority ops = %d, want 0", after-before)
	}
	t.Logf("prefetched ls-equivalent authority ops: before=%d after=%d delta=%d", before, after, after-before)
}

func walkAllMetadata(t *testing.T, v *Volume, dir string) {
	t.Helper()
	ctx := context.Background()
	ents, st := v.Readdir(ctx, dir)
	if st != fsproto.OK {
		t.Fatalf("Readdir %q: %d", dir, st)
	}
	for _, e := range ents {
		p := e.Name
		if dir != "" {
			p = dir + "/" + e.Name
		}
		if _, st := v.Lookup(ctx, p); st != fsproto.OK {
			t.Fatalf("Lookup %q: %d", p, st)
		}
		if e.Attr.Kind == "directory" {
			walkAllMetadata(t, v, p)
		}
	}
}

func TestDiskCacheDoesNotServeStaleAfterRemoteContentChange(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	seed := dialCore(t, addr, Options{})
	a0, st := seed.Create(ctx, "big", 0o644)
	if st != fsproto.OK {
		t.Fatalf("seed create: %d", st)
	}
	n0 := NewNodeState(a0.Ino, a0.Ino != 0)
	blockA := make([]byte, DiskBlockSize)
	blockB := make([]byte, DiskBlockSize)
	for i := range blockA {
		blockA[i] = 'a'
		blockB[i] = 'b'
	}
	if _, st := seed.Write(ctx, "big", n0, 0, blockA); st != fsproto.OK {
		t.Fatalf("seed write: %d", st)
	}

	cacheDir := t.TempDir()
	a := dialCore(t, addr, Options{DiskCacheDir: cacheDir, DiskCacheBytes: int64(DiskBlockSize * 2), VolumeID: "vol"})
	b := dialCore(t, addr, Options{})
	watchInvalidationsForTest(t, a)

	attr, st := a.Lookup(ctx, "big")
	if st != fsproto.OK {
		t.Fatalf("lookup: %d", st)
	}
	an := NewNodeState(attr.Ino, attr.Ino != 0)
	data, st := a.Read(ctx, "big", an, 0, DiskBlockSize)
	if st != fsproto.OK || len(data) != DiskBlockSize || data[0] != 'a' {
		t.Fatalf("initial read: len=%d first=%q st=%d", len(data), data[:1], st)
	}
	bn := NewNodeState(attr.Ino, attr.Ino != 0)
	if _, st := b.Write(ctx, "big", bn, 0, blockB); st != fsproto.OK {
		t.Fatalf("remote write: %d", st)
	}
	time.Sleep(200 * time.Millisecond)
	data, st = a.Read(ctx, "big", an, 0, DiskBlockSize)
	if st != fsproto.OK || len(data) != DiskBlockSize || data[0] != 'b' {
		t.Fatalf("post-invalidation read served stale data: len=%d first=%q st=%d", len(data), data[:1], st)
	}

	reopened, err := NewDiskBlockCache(cacheDir, int64(DiskBlockSize*2))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Get("vol", a.VersionCache.CurrentGen(), attr.Ino, 0, 1); ok {
		t.Fatal("cache unexpectedly hit a guessed stale version")
	}
}

func TestCreateAfterNegativeEvictsAfterDelayedInvalidation(t *testing.T) {
	addr := serveCore(t)
	a := dialCore(t, addr, Options{NegativeCache: true})
	b := dialCore(t, addr, Options{})
	watchInvalidationsForTest(t, a)
	ctx := context.Background()
	if _, st := a.Lookup(ctx, "race"); st != fsproto.ENOENT {
		t.Fatalf("initial negative: %d", st)
	}

	// Delay A's stream deliberately: before A observes the parent-version bump,
	// it may still return the old miss. Once the delayed stream is released, the
	// parent version must evict that negative and the next lookup must see the file.
	if _, st := b.Create(ctx, "race", 0o644); st != fsproto.OK {
		t.Fatalf("remote create: %d", st)
	}
	time.Sleep(250 * time.Millisecond)
	if attr, st := a.Lookup(ctx, "race"); st != fsproto.OK || attr.Kind != "file" {
		t.Fatalf("lookup after delayed invalidation = attr=%+v st=%d", attr, st)
	}
}

func TestWriteBackWALReplayAfterSimulatedCrash(t *testing.T) {
	addr := serveCore(t)
	walDir := t.TempDir()
	ctx := context.Background()
	v := dialCoreNoCleanup(t, addr, Options{
		Owner:  "replay-owner",
		WALDir: walDir,
	})
	a, st := v.Create(ctx, "wb", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := v.Write(ctx, "wb", n, 0, []byte("from-wal")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}
	// Crash: no drain, no release, no CLOSE frame — the acknowledged tail
	// survives only in the mount stream WAL.
	v.Writeback().Abandon()
	_ = v.client.Close()
	v.cancel()

	// The next attach of the same (volume, branch) store recovers: it
	// rebinds the parked stream (fencing the dead session) and drains the
	// tail before anything is lost.
	replay := dialCore(t, addr, Options{
		Owner:  "replay-owner2",
		WALDir: walDir,
	})
	deadline := time.Now().Add(15 * time.Second)
	for len(replay.RecoveryJobs()) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("recovery did not resolve: %+v", replay.RecoveryJobs())
		}
		time.Sleep(20 * time.Millisecond)
	}
	reader := dialCore(t, addr, Options{})
	attr, st := reader.Lookup(ctx, "wb")
	if st != fsproto.OK {
		t.Fatalf("reader lookup: %d", st)
	}
	rn := NewNodeState(attr.Ino, attr.Ino != 0)
	data, st := reader.Read(ctx, "wb", rn, 0, 16)
	if st != fsproto.OK || string(data) != "from-wal" {
		t.Fatalf("reader read after replay: %q st=%d", data, st)
	}
}

// TestFsyncBlocksOnAuthorityFlush pins the ONLY fsync meaning: local WAL
// durable AND the covering session drained to the authority — fsync returns
// only after the flush lands (no policy, no local-only mode).
func TestFsyncBlocksOnAuthorityFlush(t *testing.T) {
	addr, srv := serveCoreServer(t)
	blockFlush := make(chan struct{})
	entered := make(chan struct{}, 1)
	srv.SetBeforeFlushBatch(func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-blockFlush
	})
	ctx := context.Background()
	auth := dialCore(t, addr, Options{
		Owner:  "fsync-authority",
		WALDir: t.TempDir(),
	})
	if _, st := auth.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir d: %d", st)
	}
	a, st := auth.Create(ctx, "d/auth", 0o644)
	if st != fsproto.OK {
		t.Fatalf("auth create: %d", st)
	}
	an := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := auth.Write(ctx, "d/auth", an, 0, []byte("durable")); st != fsproto.OK {
		t.Fatalf("auth write: %d", st)
	}
	done := make(chan Status, 1)
	go func() { done <- auth.FsyncPath("d/auth") }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("authority fsync did not enter FlushBatch")
	}
	select {
	case st := <-done:
		t.Fatalf("authority fsync returned before flush release: %d", st)
	case <-time.After(100 * time.Millisecond):
	}
	close(blockFlush)
	select {
	case st := <-done:
		if st != fsproto.OK {
			t.Fatalf("authority fsync status: %d", st)
		}
	case <-time.After(time.Second):
		t.Fatal("authority fsync did not complete after flush release")
	}
	reader := dialCore(t, addr, Options{})
	attr, st := reader.Lookup(ctx, "d/auth")
	if st != fsproto.OK {
		t.Fatalf("reader lookup auth: %d", st)
	}
	data, st := reader.Read(ctx, "d/auth", NewNodeState(attr.Ino, attr.Ino != 0), 0, 16)
	if st != fsproto.OK || string(data) != "durable" {
		t.Fatalf("reader after authority fsync: %q st=%d", data, st)
	}
}

// TestCoherenceSampleUsesAcknowledgedDelegatedView pins the source-of-truth
// contract for daemon-driven local kernel refreshes. A control write can be
// acknowledged while its flush is blocked; sampling raw authority in that
// window would see the old size (or ENOENT) and clamp a live vnode backward.
func TestCoherenceSampleUsesAcknowledgedDelegatedView(t *testing.T) {
	addr, srv := serveCoreServer(t)
	ctx := context.Background()
	holder := dialCore(t, addr, Options{
		Owner:  "coherence-sample-holder",
		WALDir: t.TempDir(),
	})
	if _, st := holder.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir d: %d", st)
	}

	blockFlush := make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(blockFlush) }) })
	entered := make(chan struct{}, 1)
	srv.SetBeforeFlushBatch(func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-blockFlush
	})
	attr, st := holder.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create d/f: %d", st)
	}
	node := NewNodeState(attr.Ino, attr.Ino != 0)
	payload := []byte("acknowledged-before-authority")
	if _, st := holder.Write(ctx, "d/f", node, 0, payload); st != fsproto.OK {
		t.Fatalf("write d/f: %d", st)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("background flush did not enter authority gate")
	}

	sample, version, generation, st := holder.CoherenceSample(ctx, "d/f")
	if st != fsproto.OK || sample.Kind != "file" || sample.Size != int64(len(payload)) {
		t.Fatalf("composed sample = %+v version=%d generation=%d st=%d", sample, version, generation, st)
	}
	if version != 0 || generation != 0 {
		t.Fatalf("delegated sample exposed authority stamp version=%d generation=%d", version, generation)
	}

	if _, _, _, _, rawStatus, err := holder.Client().GetattrV("d/f"); err != nil || rawStatus != fsproto.ENOENT {
		t.Fatalf("raw authority before unblock = status=%d err=%v, want ENOENT", rawStatus, err)
	}
	unblock.Do(func() { close(blockFlush) })
}

func TestDelegationRecallForcesFlushBeforeContenderProceeds(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	a := dialCore(t, addr, Options{
		Owner:  "recall-a",
		WALDir: t.TempDir(),
	})
	// A must receive the authority's recall over its invalidation stream.
	watchInvalidationsForTest(t, a)
	// A subtree path so A actually holds a delegation on "d" to be recalled.
	if _, st := a.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("A mkdir d: %d", st)
	}
	attr, st := a.Create(ctx, "d/shared", 0o644)
	if st != fsproto.OK {
		t.Fatalf("A create: %d", st)
	}
	an := NewNodeState(attr.Ino, attr.Ino != 0)
	if _, st := a.Write(ctx, "d/shared", an, 0, []byte("from-a")); st != fsproto.OK {
		t.Fatalf("A write: %d", st)
	}
	if !a.wb.Covers("d/shared") {
		t.Fatal("precondition: A holds the d delegation")
	}

	b := dialCore(t, addr, Options{
		Owner:  "recall-b",
		WALDir: t.TempDir(),
	})
	bn := NewNodeState(attr.Ino, attr.Ino != 0)
	bctx, bcancel := context.WithTimeout(ctx, 6*time.Second)
	defer bcancel()
	// B's write overlaps A's delegation: the authority recalls A, A drains
	// its acknowledged create+write, and only then does B's write-through
	// apply. B's success itself proves the ordering — a gated write against
	// an undrained create would have found no file (WriteAtExistingAs).
	if _, st := b.Write(bctx, "d/shared", bn, 0, []byte("from-b")); st != fsproto.OK {
		t.Fatalf("B write after recall: %d", st)
	}
	if a.wb.Covers("d/shared") {
		t.Fatal("A still covers the recalled scope")
	}
	reader := dialCore(t, addr, Options{})
	ra, st := reader.Lookup(ctx, "d/shared")
	if st != fsproto.OK {
		t.Fatalf("reader lookup: %d", st)
	}
	data, st := reader.Read(ctx, "d/shared", NewNodeState(ra.Ino, ra.Ino != 0), 0, 16)
	if st != fsproto.OK || string(data) != "from-b" {
		t.Fatalf("authority must hold B's write ordered after A's drained state: %q st=%d", data, st)
	}
}

func TestTwoClientInvalidationOrdering(t *testing.T) {
	addr := serveCore(t)
	events := make(chan bool, 4)
	observer := dialCore(t, addr, Options{
		OnInvalidate: func(path string, inPlace bool) {
			if path == "ordered" {
				events <- inPlace
			}
		},
	})
	watchInvalidationsForTest(t, observer)

	b := dialCore(t, addr, Options{})
	attr, st := b.Create(context.Background(), "ordered", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	if _, st := b.Write(context.Background(), "ordered", NewNodeState(attr.Ino, attr.Ino != 0), 0, []byte("x")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}
	var got []bool
	deadline := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case e := <-events:
			got = append(got, e)
		case <-deadline:
			t.Fatalf("timed out waiting for two invalidations, got %v", got)
		}
	}
	if got[0] || !got[1] {
		t.Fatalf("invalidation order/inPlace = %v, want [false true]", got)
	}
}

func TestHardLinkInvalidationFansOutByInode(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	writer := dialCore(t, addr, Options{Owner: "hardlink-writer"})
	source, st := writer.Create(ctx, "source", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	sourceState := NewNodeState(source.Ino, source.Ino != 0)
	if _, st := writer.Write(ctx, "source", sourceState, 0, []byte("one")); st != fsproto.OK {
		t.Fatalf("initial write: %d", st)
	}
	if linked, st := writer.Link(ctx, "source", "alias", sourceState); st != fsproto.OK || linked.Nlink != 2 {
		t.Fatalf("link: attr=%+v st=%d", linked, st)
	}

	events := make(chan string, 16)
	reader := dialCore(t, addr, Options{
		Owner: "hardlink-reader",
		OnInvalidate: func(path string, inPlace bool) {
			if inPlace {
				events <- path
			}
		},
	})
	watchInvalidationsForTest(t, reader)
	if a, st := reader.Lookup(ctx, "source"); st != fsproto.OK || a.Nlink != 2 {
		t.Fatalf("reader source=%+v st=%d", a, st)
	}
	alias, st := reader.Lookup(ctx, "alias")
	if st != fsproto.OK || alias.Nlink != 2 {
		t.Fatalf("reader alias=%+v st=%d", alias, st)
	}

	if _, st := writer.Write(ctx, "source", sourceState, 0, []byte("two")); st != fsproto.OK {
		t.Fatalf("linked write: %d", st)
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case path := <-events:
			if path == "alias" {
				goto sawAliasWrite
			}
		case <-deadline:
			t.Fatal("write through source did not invalidate cached alias")
		}
	}

sawAliasWrite:
	if st := writer.Remove(ctx, "source", sourceState); st != fsproto.OK {
		t.Fatalf("unlink source: %d", st)
	}
	deadline = time.After(2 * time.Second)
	for {
		fresh, st := reader.Lookup(ctx, "alias")
		if st == fsproto.OK && fresh.Nlink == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("surviving alias did not refresh nlink: attr=%+v st=%d", fresh, st)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// A file born under a delegation has a frontend-stable local item identity
// before the authority assigns its inode. Linking it drains the delegation
// and publishes that authority identity. Every later operation must use the
// published inode and stay on the shared hard-link lane; otherwise the two
// names can diverge in separate delegated overlays.
func TestHardLinkPromotesDelegatedLocalIdentity(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{Owner: "hardlink-local-born"})

	if _, st := v.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	created, st := v.Create(ctx, "d/source", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	if created.Ino != 0 {
		t.Fatalf("delegated create inode=%d, want frontend-local identity", created.Ino)
	}
	source := NewNodeState(0xfeed, false)
	if _, st := v.Write(ctx, "d/source", source, 0, []byte("before")); st != fsproto.OK {
		t.Fatalf("delegated write: %d", st)
	}

	linked, st := v.Link(ctx, "d/source", "d/alias", source)
	if st != fsproto.OK || linked.Ino == 0 || linked.Nlink != 2 {
		t.Fatalf("link: attr=%+v st=%d", linked, st)
	}
	if got := source.AuthorityIno(); got != linked.Ino {
		t.Fatalf("promoted authority inode=%d, want %d", got, linked.Ino)
	}
	if got := authHandleIno(source); got != linked.Ino {
		t.Fatalf("handle inode=%d, want %d", got, linked.Ino)
	}

	// Re-acquire the directory through an unrelated ordinary file. The
	// hardlink write below must release this covering grant before taking
	// the authority lane; otherwise the server self-recall can wait on the
	// same NodeState lock held by the write.
	other, st := v.Create(ctx, "d/other", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create other: %d", st)
	}
	if _, st := v.Write(ctx, "d/other", NewNodeState(other.Ino, other.Ino != 0), 0, []byte("other")); st != fsproto.OK {
		t.Fatalf("write other: %d", st)
	}
	if !v.wb.Covers("d/source") {
		t.Fatal("test precondition: unrelated write did not acquire covering grant")
	}
	if _, st := v.Write(ctx, "d/source", source, 0, []byte("shared")); st != fsproto.OK {
		t.Fatalf("post-link write: %d", st)
	}
	if v.wb.Covers("d/source") {
		t.Fatal("hardlink write did not release covering grant")
	}
	buf, st := v.Read(ctx, "d/alias", source, 0, len("shared"))
	if st != fsproto.OK || string(buf) != "shared" {
		t.Fatalf("alias read=%q st=%d", buf, st)
	}
}

func TestHardlinkMutationReleasesEveryAliasDelegationScope(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{Owner: "hardlink-cross-scope-release"})

	for _, dir := range []string{"a", "b"} {
		if _, st := v.Mkdir(ctx, dir, 0o755); st != fsproto.OK {
			t.Fatalf("mkdir %s: %d", dir, st)
		}
	}
	_, st := v.Create(ctx, "a/source", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create source: %d", st)
	}
	source := NewNodeState(0xabc, false)
	if _, st := v.Write(ctx, "a/source", source, 0, []byte("v1")); st != fsproto.OK {
		t.Fatalf("write source: %d", st)
	}
	linked, st := v.Link(ctx, "a/source", "b/alias", source)
	if st != fsproto.OK || linked.Ino == 0 {
		t.Fatalf("link: attr=%+v st=%d", linked, st)
	}
	v.RememberHardlinkAlias("a/source", linked.Ino)
	v.RememberHardlinkAlias("b/alias", linked.Ino)

	for _, path := range []string{"a/other", "b/other"} {
		other, createStatus := v.Create(ctx, path, 0o644)
		if createStatus != fsproto.OK {
			t.Fatalf("create %s: %d", path, createStatus)
		}
		if _, writeStatus := v.Write(
			ctx,
			path,
			NewNodeState(other.Ino, other.Ino != 0),
			0,
			[]byte(path),
		); writeStatus != fsproto.OK {
			t.Fatalf("write %s: %d", path, writeStatus)
		}
	}
	if !v.wb.Covers("a/source") || !v.wb.Covers("b/alias") {
		t.Fatal("test precondition: both alias directory grants were not held")
	}

	if _, st := v.Write(ctx, "a/source", source, 0, []byte("v2")); st != fsproto.OK {
		t.Fatalf("hardlink write: %d", st)
	}
	if v.wb.Covers("a/source") || v.wb.Covers("b/alias") {
		t.Fatal("hardlink write retained a delegation covering an alias")
	}
	data, st := v.Read(ctx, "b/alias", source, 0, 2)
	if st != fsproto.OK || string(data) != "v2" {
		t.Fatalf("alias read=%q st=%d", data, st)
	}
}

func TestDelegationSnapshotsDiscoverPreexistingHardlinkAliases(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()

	writer := dialCoreNoCleanup(t, addr, Options{Owner: "hardlink-snapshot-seed"})
	for _, dir := range []string{"a", "b"} {
		if _, st := writer.Mkdir(ctx, dir, 0o755); st != fsproto.OK {
			t.Fatalf("seed mkdir %s: %d", dir, st)
		}
	}
	sourceAttr, st := writer.Create(ctx, "a/source", 0o644)
	if st != fsproto.OK {
		t.Fatalf("seed create source: %d", st)
	}
	source := NewNodeState(sourceAttr.Ino, sourceAttr.Ino != 0)
	if _, st := writer.Write(ctx, "a/source", source, 0, []byte("v1")); st != fsproto.OK {
		t.Fatalf("seed write source: %d", st)
	}
	if linked, st := writer.Link(ctx, "a/source", "b/alias", source); st != fsproto.OK || linked.Nlink != 2 {
		t.Fatalf("seed hardlink: attr=%+v st=%d", linked, st)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close seeding mount: %v", err)
	}

	v := dialCore(t, addr, Options{Owner: "hardlink-snapshot-observer"})
	for _, path := range []string{"a/unrelated", "b/unrelated"} {
		attr, createStatus := v.Create(ctx, path, 0o644)
		if createStatus != fsproto.OK {
			t.Fatalf("create %s: %d", path, createStatus)
		}
		if _, writeStatus := v.Write(
			ctx,
			path,
			NewNodeState(attr.Ino, attr.Ino != 0),
			0,
			[]byte(path),
		); writeStatus != fsproto.OK {
			t.Fatalf("write %s: %d", path, writeStatus)
		}
	}
	if !v.wb.Covers("a/source") || !v.wb.Covers("b/alias") {
		t.Fatal("test precondition: snapshot observer did not hold both directory grants")
	}

	observedSource, st := v.Lookup(ctx, "a/source")
	if st != fsproto.OK || observedSource.Nlink != 2 {
		t.Fatalf("snapshot lookup source: attr=%+v st=%d", observedSource, st)
	}
	observedAlias, st := v.Lookup(ctx, "b/alias")
	if st != fsproto.OK ||
		observedAlias.Ino != observedSource.Ino ||
		observedAlias.Nlink != 2 {
		t.Fatalf("snapshot lookup alias: attr=%+v source=%+v st=%d", observedAlias, observedSource, st)
	}
	observedNode := NewNodeState(observedSource.Ino, true)
	if !v.isHardlink(observedNode) {
		t.Fatal("delegated snapshot lookups did not populate the hardlink alias index")
	}

	if _, st := v.Write(ctx, "a/source", observedNode, 0, []byte("v2")); st != fsproto.OK {
		t.Fatalf("hardlink write after snapshot discovery: %d", st)
	}
	if v.wb.Covers("a/source") || v.wb.Covers("b/alias") {
		t.Fatal("hardlink write retained a delegation covering a discovered alias")
	}
	data, st := v.Read(ctx, "b/alias", observedNode, 0, 2)
	if st != fsproto.OK || string(data) != "v2" {
		t.Fatalf("alias read=%q st=%d", data, st)
	}
}

// A node first observed with nlink==1 must not remain eligible for delegated
// write-back after a peer adds an alias. The open NodeState does not receive a
// fresh getattr; RelatedInos is the only identity bridge between the peer's
// namespace mutation and this already-instantiated handle.
func TestPeerLinkMakesOpenNlinkOneNodeAliasUnsafe(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()

	seed := dialCoreNoCleanup(t, addr, Options{Owner: "hardlink-late-seed"})
	for _, dir := range []string{"a", "b"} {
		if _, st := seed.Mkdir(ctx, dir, 0o755); st != fsproto.OK {
			t.Fatalf("seed mkdir %s: %d", dir, st)
		}
	}
	seedAttr, st := seed.Create(ctx, "a/source", 0o644)
	if st != fsproto.OK {
		t.Fatalf("seed create source: %d", st)
	}
	if _, st := seed.Write(
		ctx,
		"a/source",
		NewNodeState(seedAttr.Ino, seedAttr.Ino != 0),
		0,
		[]byte("old"),
	); st != fsproto.OK {
		t.Fatalf("seed write source: %d", st)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed mount: %v", err)
	}

	a := dialCore(t, addr, Options{Owner: "hardlink-late-a"})
	watchInvalidationsForTest(t, a)
	observed, st := a.Lookup(ctx, "a/source")
	if st != fsproto.OK || observed.Ino == 0 || observed.Nlink != 1 {
		t.Fatalf("A initial lookup: attr=%+v st=%d", observed, st)
	}
	nodeA := NewNodeState(observed.Ino, true)
	if st := a.Open(ctx, "a/source", nodeA, true); st != fsproto.OK {
		t.Fatalf("A open source: %d", st)
	}
	defer a.CloseHandle("a/source", nodeA)

	// Acquire a real path-keyed delegation while the inode is still known to
	// A only as nlink==1. The peer Link below must recall this scope.
	if _, st := a.Write(ctx, "a/source", nodeA, 0, []byte("old")); st != fsproto.OK {
		t.Fatalf("A delegated write: %d", st)
	}
	if !a.wb.Covers("a/source") {
		t.Fatal("test precondition: A did not hold the source delegation")
	}

	b := dialCore(t, addr, Options{Owner: "hardlink-late-b"})
	sourceB, st := b.Lookup(ctx, "a/source")
	if st != fsproto.OK || sourceB.Ino != observed.Ino || sourceB.Nlink != 1 {
		t.Fatalf("B source lookup: attr=%+v A=%+v st=%d", sourceB, observed, st)
	}
	linked, st := b.Link(ctx, "a/source", "b/alias", NewNodeState(sourceB.Ino, true))
	if st != fsproto.OK || linked.Ino != observed.Ino || linked.Nlink != 2 {
		t.Fatalf("B cross-scope link: attr=%+v source=%+v st=%d", linked, sourceB, st)
	}

	deadline := time.Now().Add(3 * time.Second)
	for !a.isHardlink(nodeA) {
		if time.Now().After(deadline) {
			t.Fatal("A did not classify RelatedInos as alias-unsafe")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// No getattr/lookup occurs on A between the peer Link and this write. It
	// must release/bypass every delegated alias scope and mutate by authority
	// inode so both names continue to denote the same bytes.
	if _, st := a.Write(ctx, "a/source", nodeA, 0, []byte("new")); st != fsproto.OK {
		t.Fatalf("A post-link write: %d", st)
	}
	if a.wb.Covers("a/source") || a.wb.Covers("b/alias") {
		t.Fatal("A retained a delegation covering a hardlink name")
	}

	verify := dialCore(t, addr, Options{Owner: "hardlink-late-verify"})
	for _, path := range []string{"a/source", "b/alias"} {
		data, readStatus := verify.Read(
			ctx,
			path,
			NewNodeState(linked.Ino, true),
			0,
			len("new"),
		)
		if readStatus != fsproto.OK || string(data) != "new" {
			t.Fatalf("verify %s=%q st=%d", path, data, readStatus)
		}
	}
}

// Even without stream delivery, a post-link delegation snapshot is an
// authority proof that must be consumed before the acquiring mutation is
// admitted. Merely observing the snapshot is too late unless admission loops
// and re-validates the target after installation.
func TestGrantSnapshotRejectsImmediateHardlinkMutation(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()

	seed := dialCoreNoCleanup(t, addr, Options{Owner: "hardlink-grant-seed"})
	if _, st := seed.Mkdir(ctx, "a", 0o755); st != fsproto.OK {
		t.Fatalf("seed mkdir a: %d", st)
	}
	sourceAttr, st := seed.Create(ctx, "a/source", 0o644)
	if st != fsproto.OK {
		t.Fatalf("seed create source: %d", st)
	}
	if _, st := seed.Write(
		ctx,
		"a/source",
		NewNodeState(sourceAttr.Ino, sourceAttr.Ino != 0),
		0,
		[]byte("old"),
	); st != fsproto.OK {
		t.Fatalf("seed write source: %d", st)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed mount: %v", err)
	}

	a := dialCore(t, addr, Options{Owner: "hardlink-grant-a"})
	observed, st := a.Lookup(ctx, "a/source")
	if st != fsproto.OK || observed.Ino == 0 || observed.Nlink != 1 {
		t.Fatalf("A initial lookup: attr=%+v st=%d", observed, st)
	}
	nodeA := NewNodeState(observed.Ino, true)

	b := dialCore(t, addr, Options{Owner: "hardlink-grant-b"})
	sourceB, st := b.Lookup(ctx, "a/source")
	if st != fsproto.OK || sourceB.Ino != observed.Ino || sourceB.Nlink != 1 {
		t.Fatalf("B source lookup: attr=%+v A=%+v st=%d", sourceB, observed, st)
	}
	linked, st := b.Link(ctx, "a/source", "alias", NewNodeState(sourceB.Ino, true))
	if st != fsproto.OK || linked.Ino != observed.Ino || linked.Nlink != 2 {
		t.Fatalf("B link: attr=%+v source=%+v st=%d", linked, sourceB, st)
	}

	// A intentionally has no invalidation watcher and performs no fresh read.
	// Its acquisition snapshot contains nlink==2; the observer marks the path
	// unsafe, the admission loop releases the just-installed grant, and this
	// same syscall falls through to the inode-addressed authority lane.
	if _, st := a.Write(ctx, "a/source", nodeA, 0, []byte("new")); st != fsproto.OK {
		t.Fatalf("A immediate post-link write: %d", st)
	}
	if !a.isHardlink(nodeA) {
		t.Fatal("grant snapshot did not classify the target alias-unsafe")
	}
	if a.wb.Covers("a/source") {
		t.Fatal("grant snapshot left the hardlink mutation delegated")
	}

	verify := dialCore(t, addr, Options{Owner: "hardlink-grant-verify"})
	for _, path := range []string{"a/source", "alias"} {
		data, readStatus := verify.Read(
			ctx,
			path,
			NewNodeState(linked.Ino, true),
			0,
			len("new"),
		)
		if readStatus != fsproto.OK || string(data) != "new" {
			t.Fatalf("verify %s=%q st=%d", path, data, readStatus)
		}
	}
}

// An open descriptor's remembered pathname is only a scope hint. If a peer
// replaces that name before this mount consumes its invalidation, a fresh
// delegation snapshot contains the replacement inode and must not redirect
// descriptor I/O into that replacement's overlay.
func TestOpenHandleRejectsReplacementDelegationSnapshot(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()

	peer, err := fsproto.Dial(addr, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if _, st, err := peer.Mkdir("d", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("seed mkdir: st=%d err=%v", st, err)
	}
	if _, st, err := peer.Mkdir("other", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("seed other mkdir: st=%d err=%v", st, err)
	}
	oldAttr, st, err := peer.Create("d/target", 0o644)
	if err != nil || st != fsproto.OK || oldAttr == nil || oldAttr.Ino == 0 {
		t.Fatalf("seed target: attr=%+v st=%d err=%v", oldAttr, st, err)
	}
	if _, st, err := peer.Write("d/target", 0, []byte("old"), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed target write: st=%d err=%v", st, err)
	}

	// Deliberately do not start A's invalidation watcher. Its open NodeState
	// and caller-supplied path therefore remain stale after the peer rename.
	a := dialCore(t, addr, Options{Owner: "replacement-snapshot-a"})
	observed, st := a.Lookup(ctx, "d/target")
	if st != fsproto.OK || observed.Ino != oldAttr.Ino {
		t.Fatalf("A lookup: attr=%+v old=%+v st=%d", observed, oldAttr, st)
	}
	node := NewNodeState(observed.Ino, true)
	if st := a.Open(ctx, "d/target", node, true); st != fsproto.OK {
		t.Fatalf("A open target: %d", st)
	}
	defer a.CloseHandle("d/target", node)

	linked, st, err := peer.Link("d/target", "other/alias")
	if err != nil || st != fsproto.OK || linked == nil ||
		linked.Ino != oldAttr.Ino || linked.Nlink != 2 {
		t.Fatalf("peer old-inode alias: attr=%+v old=%+v st=%d err=%v", linked, oldAttr, st, err)
	}
	replacement, st, err := peer.Create("d/replacement", 0o644)
	if err != nil || st != fsproto.OK || replacement == nil ||
		replacement.Ino == 0 || replacement.Ino == oldAttr.Ino {
		t.Fatalf("peer replacement create: attr=%+v old=%+v st=%d err=%v", replacement, oldAttr, st, err)
	}
	if _, st, err := peer.Write("d/replacement", 0, []byte("new"), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("peer replacement write: st=%d err=%v", st, err)
	}
	if st, err := peer.Rename("d/replacement", "d/target"); err != nil || st != fsproto.OK {
		t.Fatalf("peer rename-over: st=%d err=%v", st, err)
	}

	// Retain a second, unrelated delegation whose snapshot contains the
	// surviving old-inode alias, then acknowledge an earlier dirty write
	// through it. A stale-path mismatch must release this scope too; a
	// pathname-only release would let EARLY flush after the descriptor write
	// and invert their acknowledged order.
	if _, st := a.Create(ctx, "other/probe", 0o644); st != fsproto.OK {
		t.Fatalf("other-scope probe create: %d", st)
	}
	if !a.wb.Covers("other/alias") {
		t.Fatal("test precondition: probe create did not retain other delegation")
	}
	if n, st := a.Write(ctx, "other/alias", node, 0, []byte("EARLY")); st != fsproto.OK || n != 5 {
		t.Fatalf("earlier alias write: n=%d st=%d", n, st)
	}
	if !a.wb.Covers("other/alias") {
		t.Fatal("test precondition: earlier alias write did not remain delegated")
	}

	// No d grant is held yet. This write acquires d, observes that d/target
	// now binds replacement.Ino, rejects that delegated view, releases it,
	// and escalates to the pathless exact lane. That lane must also drain the
	// retained other/alias grant before mutating the stable old inode.
	if n, st := a.WriteOpenHandle(ctx, "d/target", node, 0, []byte("FD-LATER")); st != fsproto.OK || n != 8 {
		t.Fatalf("stale-handle write: n=%d st=%d", n, st)
	}
	if a.wb.Covers("d/target") {
		t.Fatal("mismatched replacement snapshot remained delegated after handle write")
	}
	if a.wb.Covers("other/alias") {
		t.Fatal("old-inode alias delegation survived exact handle write")
	}
	if got, st, err := peer.Read("d/target", 0, 16); err != nil || st != fsproto.OK || string(got) != "new" {
		t.Fatalf("replacement after stale-handle write: data=%q st=%d err=%v", got, st, err)
	}
	if got, st, err := peer.Read("other/alias", 0, 16); err != nil || st != fsproto.OK || string(got) != "FD-LATER" {
		t.Fatalf("old alias after ordered handle write: data=%q st=%d err=%v", got, st, err)
	}

	// Reacquire both scopes through unrelated local creates, then read the
	// stale handle while both the replacement and old alias are represented
	// by retained overlays. The read must reject the replacement overlay,
	// release both scopes through the exact barrier, and return the old inode.
	if _, st := a.Create(ctx, "other/read-probe", 0o644); st != fsproto.OK {
		t.Fatalf("reacquire other probe: %d", st)
	}
	if _, st := a.Create(ctx, "d/read-probe", 0o644); st != fsproto.OK {
		t.Fatalf("reacquire d probe: %d", st)
	}
	if !a.wb.Covers("d/target") || !a.wb.Covers("other/alias") {
		t.Fatal("test precondition: read did not begin with both delegations retained")
	}
	got, st := a.ReadOpenHandle(ctx, "d/target", node, 0, 16)
	if st != fsproto.OK || string(got) != "FD-LATER" {
		t.Fatalf("stale-handle read: data=%q st=%d", got, st)
	}
	if a.wb.Covers("d/target") || a.wb.Covers("other/alias") {
		t.Fatal("exact handle read retained a mismatched or alias delegation")
	}
	if got, st, err := peer.Read("d/target", 0, 16); err != nil || st != fsproto.OK || string(got) != "new" {
		t.Fatalf("replacement after stale-handle read: data=%q st=%d err=%v", got, st, err)
	}
}

// newManagedTestFS opens the file-backed PFJ3 entry log at walPath and builds
// the MANAGED workfs over it — the only generation a v5 server serves.
func newManagedTestFS(t testing.TB, blobs content.BlobReader, walPath string) *workfs.FS {
	t.Helper()
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	flog, err := pfj3.NewFileEntryLog(w)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.NewManaged(nil, blobs, flog)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}
