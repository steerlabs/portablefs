package clientcore

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/delegation"
	"github.com/trendup-ai/portablefs/vcs/internal/fsproto"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
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
	if res, err := v.Getlk("dir/b.txt", 88, 0, ^uint64(0), true); err != nil || !res.Conflict {
		t.Fatalf("Getlk conflict: res=%+v err=%v", res, err)
	}
	ReleaseHandleLocks(v.Client(), &lh)
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

func TestWriteBackAtomicAppendAddsNoHotPathRoundTrips(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{
		Owner:         "append-wb",
		WriteBack:     true,
		WALDir:        t.TempDir(),
		FlushInterval: time.Hour,
		IdleInterval:  time.Hour,
	})
	ctx := context.Background()
	attr, st := v.Create(ctx, "append.log", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	state := NewNodeState(attr.Ino, attr.Ino != 0)
	before := opCount(v)
	const records = 100
	for i := 0; i < records; i++ {
		payload := []byte{byte(i), byte(i >> 8), 0xA5, 0x5A}
		if n, st := v.WriteAppend(ctx, "append.log", state, 0, payload); st != fsproto.OK || n != len(payload) {
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
	data, st := peer.Read(ctx, "append.log", nil, 0, records*4)
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
	go a.StartInvalidations(ctx, false)
	time.Sleep(100 * time.Millisecond)

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
	go v.StartInvalidations(ctx, false)
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
	seed := dialCore(t, addr, Options{})
	ctx := context.Background()
	if _, st := seed.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir seed: %d", st)
	}
	for _, p := range []string{"a", "d/b", "d/c"} {
		if _, st := seed.Create(ctx, p, 0o644); st != fsproto.OK {
			t.Fatalf("create %s: %d", p, st)
		}
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
	ictx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.StartInvalidations(ictx, false)
	time.Sleep(100 * time.Millisecond)

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
	ctx := context.Background()
	if _, st := a.Lookup(ctx, "race"); st != fsproto.ENOENT {
		t.Fatalf("initial negative: %d", st)
	}

	// Delay A's stream deliberately: before A observes the parent-version bump,
	// it may still return the old miss. Once the delayed stream is released, the
	// parent version must evict that negative and the next lookup must see the file.
	ictx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.StartInvalidations(ictx, false)
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
		Owner:         "replay-owner",
		WriteBack:     true,
		WALDir:        walDir,
		FlushInterval: time.Hour,
	})
	liveCtx, liveCancel := context.WithCancel(context.Background())
	go v.StartInvalidations(liveCtx, false)
	time.Sleep(100 * time.Millisecond)
	a, st := v.Create(ctx, "wb", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := v.Write(ctx, "wb", n, 0, []byte("from-wal")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}
	_ = v.client.Close()
	time.Sleep(200 * time.Millisecond)
	liveCancel()
	v.cancel()

	replay := dialCore(t, addr, Options{
		Owner:         "replay-owner",
		WriteBack:     true,
		WALDir:        walDir,
		FlushInterval: time.Hour,
	})
	if err := replay.FlushToAuthority(ctx); err != nil {
		t.Fatalf("replay flush: %v", err)
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

func TestFsyncPolicyAuthorityBlocksOnFlushAndLocalDoesNot(t *testing.T) {
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
		Owner:         "fsync-authority",
		WriteBack:     true,
		WALDir:        t.TempDir(),
		FlushInterval: time.Hour,
		FsyncPolicy:   FsyncAuthority,
	})
	a, st := auth.Create(ctx, "auth", 0o644)
	if st != fsproto.OK {
		t.Fatalf("auth create: %d", st)
	}
	an := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := auth.Write(ctx, "auth", an, 0, []byte("durable")); st != fsproto.OK {
		t.Fatalf("auth write: %d", st)
	}
	done := make(chan Status, 1)
	go func() { done <- auth.FsyncPath("auth") }()
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
	attr, st := reader.Lookup(ctx, "auth")
	if st != fsproto.OK {
		t.Fatalf("reader lookup auth: %d", st)
	}
	data, st := reader.Read(ctx, "auth", NewNodeState(attr.Ino, attr.Ino != 0), 0, 16)
	if st != fsproto.OK || string(data) != "durable" {
		t.Fatalf("reader after authority fsync: %q st=%d", data, st)
	}
}

func TestFsyncPolicyLocalReturnsBeforeAuthorityFlush(t *testing.T) {
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
	local := dialCore(t, addr, Options{
		Owner:         "fsync-local",
		WriteBack:     true,
		WALDir:        t.TempDir(),
		FlushInterval: time.Hour,
		FsyncPolicy:   FsyncLocal,
	})
	a, st := local.Create(ctx, "local", 0o644)
	if st != fsproto.OK {
		t.Fatalf("local create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := local.Write(ctx, "local", n, 0, []byte("local-only")); st != fsproto.OK {
		t.Fatalf("local write: %d", st)
	}
	done := make(chan Status, 1)
	go func() { done <- local.FsyncPath("local") }()
	select {
	case st := <-done:
		if st != fsproto.OK {
			t.Fatalf("local fsync status: %d", st)
		}
	case <-time.After(time.Second):
		t.Fatal("local fsync blocked on authority flush")
	}
	select {
	case <-entered:
		t.Fatal("local fsync unexpectedly entered FlushBatch")
	default:
	}
	close(blockFlush)
	if err := local.FlushToAuthority(ctx); err != nil {
		t.Fatalf("final flush: %v", err)
	}
}

func TestDelegationRecallForcesFlushBeforeContenderProceeds(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	a := dialCore(t, addr, Options{
		Owner:         "recall-a",
		WriteBack:     true,
		WALDir:        t.TempDir(),
		FlushInterval: 50 * time.Millisecond,
	})
	actx, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	go a.StartInvalidations(actx, false)
	time.Sleep(100 * time.Millisecond)
	attr, st := a.Create(ctx, "shared", 0o644)
	if st != fsproto.OK {
		t.Fatalf("A create: %d", st)
	}
	an := NewNodeState(attr.Ino, attr.Ino != 0)
	if _, st := a.Write(ctx, "shared", an, 0, []byte("from-a")); st != fsproto.OK {
		t.Fatalf("A write: %d", st)
	}

	b := dialCore(t, addr, Options{
		Owner:         "recall-b",
		WriteBack:     true,
		WALDir:        t.TempDir(),
		FlushInterval: time.Hour,
	})
	bn := NewNodeState(attr.Ino, attr.Ino != 0)
	bctx, bcancel := context.WithTimeout(ctx, 6*time.Second)
	defer bcancel()
	if _, st := b.Write(bctx, "shared", bn, 0, []byte("from-b")); st != fsproto.OK {
		t.Fatalf("B write after recall: %d", st)
	}
	reader := dialCore(t, addr, Options{})
	ra, st := reader.Lookup(ctx, "shared")
	if st != fsproto.OK {
		t.Fatalf("reader lookup: %d", st)
	}
	data, st := reader.Read(ctx, "shared", NewNodeState(ra.Ino, ra.Ino != 0), 0, 16)
	if st != fsproto.OK || string(data) != "from-a" {
		t.Fatalf("authority did not contain recalled A data before B flush: %q st=%d", data, st)
	}
}

func TestTwoClientInvalidationOrdering(t *testing.T) {
	addr := serveCore(t)
	events := make(chan bool, 4)
	a := dialCore(t, addr, Options{
		OnInvalidate: func(path string, inPlace bool) {
			if path == "ordered" {
				events <- inPlace
			}
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.StartInvalidations(ctx, false)
	time.Sleep(100 * time.Millisecond)

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
	watchCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reader.StartInvalidations(watchCtx, false)
	time.Sleep(100 * time.Millisecond)
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
