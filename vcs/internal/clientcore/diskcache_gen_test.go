package clientcore

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/coherence"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// TestDiskCacheGenerationFencedAcrossAuthorityRestart pins C2: the persistent disk cache must not
// serve one authority incarnation's bytes to another. Versions restart per incarnation (the gen is a
// per-process nonce, fs.version restarts at 0), so a reused (ino, block, version) tuple recurs across
// a restart with DIFFERENT content. With the same cache directory, reading that tuple after the
// restart must return the NEW bytes, never the stale block keyed only by (ino, block, version).
func TestDiskCacheGenerationFencedAcrossAuthorityRestart(t *testing.T) {
	ctx := context.Background()
	cacheDir := t.TempDir()

	blockA := make([]byte, DiskBlockSize)
	blockB := make([]byte, DiskBlockSize)
	for i := range blockA {
		blockA[i] = 'a'
		blockB[i] = 'b'
	}

	// --- Authority incarnation 1: "big" holds blockA. ---
	addr1 := serveCore(t)
	seed1 := dialCore(t, addr1, Options{})
	a1, st := seed1.Create(ctx, "big", 0o644)
	if st != fsproto.OK {
		t.Fatalf("gen1 create: %d", st)
	}
	n1 := NewNodeState(a1.Ino, a1.Ino != 0)
	if _, st := seed1.Write(ctx, "big", n1, 0, blockA); st != fsproto.OK {
		t.Fatalf("gen1 write: %d", st)
	}
	client1 := dialCoreNoCleanup(t, addr1, Options{DiskCacheDir: cacheDir, DiskCacheBytes: int64(DiskBlockSize * 4), VolumeID: "vol"})
	la1, st := client1.Lookup(ctx, "big")
	if st != fsproto.OK {
		t.Fatalf("gen1 lookup: %d", st)
	}
	cn1 := NewNodeState(la1.Ino, la1.Ino != 0)
	data, st := client1.Read(ctx, "big", cn1, 0, DiskBlockSize)
	if st != fsproto.OK || data[0] != 'a' {
		t.Fatalf("gen1 read: first=%q st=%d", data[:1], st)
	}
	gen1 := client1.VersionCache.CurrentGen()
	_, ver1 := client1.VersionCache.GenAndVersion("big")
	_ = client1.Close() // release the cache dir before the second incarnation reuses it

	// --- Authority incarnation 2 (fresh workfs ⇒ new gen nonce): same "big" holds blockB. ---
	addr2 := serveCore(t)
	seed2 := dialCore(t, addr2, Options{})
	a2, st := seed2.Create(ctx, "big", 0o644)
	if st != fsproto.OK {
		t.Fatalf("gen2 create: %d", st)
	}
	n2 := NewNodeState(a2.Ino, a2.Ino != 0)
	if _, st := seed2.Write(ctx, "big", n2, 0, blockB); st != fsproto.OK {
		t.Fatalf("gen2 write: %d", st)
	}
	client2 := dialCore(t, addr2, Options{DiskCacheDir: cacheDir, DiskCacheBytes: int64(DiskBlockSize * 4), VolumeID: "vol"})
	la2, st := client2.Lookup(ctx, "big")
	if st != fsproto.OK {
		t.Fatalf("gen2 lookup: %d", st)
	}
	gen2 := client2.VersionCache.CurrentGen()
	_, ver2 := client2.VersionCache.GenAndVersion("big")

	// Preconditions that make the test meaningful: a fresh incarnation reuses the ino and version
	// (so the version-only key would collide) but under a distinct generation.
	if la2.Ino != la1.Ino || ver2 != ver1 {
		t.Fatalf("test precondition: restart must reuse ino/version (ino %d->%d, ver %d->%d)", la1.Ino, la2.Ino, ver1, ver2)
	}
	if gen2 == gen1 {
		t.Fatalf("test precondition: a restart must mint a new generation (both %d)", gen1)
	}

	cn2 := NewNodeState(la2.Ino, la2.Ino != 0)
	data, st = client2.Read(ctx, "big", cn2, 0, DiskBlockSize)
	if st != fsproto.OK || len(data) != DiskBlockSize {
		t.Fatalf("gen2 read status: len=%d st=%d", len(data), st)
	}
	if data[0] != 'b' {
		t.Fatalf("disk cache served a prior generation's bytes: got %q want 'b'", data[:1])
	}
}

func TestLatePreGrantGetattrCannotResurrectHandoffCache(t *testing.T) {
	ctx := context.Background()
	addr, server := serveCoreServer(t)
	seed := dialCoreNoCleanup(t, addr, Options{Owner: "late-fill-seed", WALDir: t.TempDir()})
	if _, st := seed.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("seed mkdir: %d", st)
	}
	attr, st := seed.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("seed create: %d", st)
	}
	if _, st := seed.Write(ctx, "d/f", NewNodeState(attr.Ino, attr.Ino != 0), 0, []byte("old")); st != fsproto.OK {
		t.Fatalf("seed write: %d", st)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}

	holder := dialCore(t, addr, Options{
		Owner:    "late-fill-holder",
		WALDir:   t.TempDir(),
		VolumeID: "late-fill-volume",
	})
	attr, st = holder.Lookup(ctx, "d/f")
	if st != fsproto.OK {
		t.Fatalf("warm lookup: %d", st)
	}
	node := NewNodeState(attr.Ino, attr.Ino != 0)
	holder.AttrCache.Evict("d/f")

	entered := make(chan struct{})
	unblock := make(chan struct{})
	var unblockOnce sync.Once
	t.Cleanup(func() { unblockOnce.Do(func() { close(unblock) }) })
	var blockNext atomic.Bool
	blockNext.Store(true)
	server.SetDropReply(func(req *fsproto.Request, _ *fsproto.Response) bool {
		if req.Op == fsproto.OpGetattr && req.Path == "d/f" && blockNext.CompareAndSwap(true, false) {
			close(entered)
			<-unblock
		}
		return false
	})

	type lookupResult struct {
		attr fsproto.Attr
		st   Status
	}
	lateResult := make(chan lookupResult, 1)
	go func() {
		got, gotStatus := holder.Lookup(ctx, "d/f")
		lateResult <- lookupResult{attr: got, st: gotStatus}
	}()
	select {
	case <-entered: // the server has already captured the pre-grant response
	case <-time.After(2 * time.Second):
		t.Fatal("pre-grant getattr did not reach the authority")
	}

	if _, st := holder.Write(ctx, "d/f", node, 0, []byte("new-content")); st != fsproto.OK {
		t.Fatalf("delegated write: %d", st)
	}
	if err := holder.wb.ReleaseFor(ctx, "d/f"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, gotVersion := holder.VersionCache.GenAndVersion("d/f"); gotVersion != 0 {
		t.Fatalf("handoff left cache reachable at version %d", gotVersion)
	}

	unblockOnce.Do(func() { close(unblock) })
	late := <-lateResult
	if late.st != fsproto.OK || late.attr.Size != 3 {
		t.Fatalf("late pre-grant lookup = size %d status %d, want old linearized result", late.attr.Size, late.st)
	}
	if _, gotVersion := holder.VersionCache.GenAndVersion("d/f"); gotVersion != 0 {
		t.Fatalf("late response resurrected reachable version %d", gotVersion)
	}
	fresh, st := holder.Lookup(ctx, "d/f")
	if st != fsproto.OK || fresh.Size != int64(len("new-content")) {
		t.Fatalf("post-handoff lookup = size %d status %d, want fresh authority state", fresh.Size, st)
	}
}

func TestDiskCacheVersionBecomesUnreachableAcrossDelegationHandoff(t *testing.T) {
	ctx := context.Background()
	addr := serveCore(t)
	seed := dialCoreNoCleanup(t, addr, Options{Owner: "disk-handoff-seed", WALDir: t.TempDir()})
	if _, st := seed.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir d: %d", st)
	}
	oldData := make([]byte, DiskBlockSize)
	newData := make([]byte, DiskBlockSize)
	for i := range oldData {
		oldData[i] = 'o'
		newData[i] = 'n'
	}
	attr, st := seed.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("seed create: %d", st)
	}
	if _, st := seed.Write(ctx, "d/f", NewNodeState(attr.Ino, attr.Ino != 0), 0, oldData); st != fsproto.OK {
		t.Fatalf("seed write: %d", st)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}

	holder := dialCore(t, addr, Options{
		Owner:          "disk-handoff-holder",
		WALDir:         t.TempDir(),
		DiskCacheDir:   t.TempDir(),
		DiskCacheBytes: int64(4 * DiskBlockSize),
		VolumeID:       "disk-handoff-volume",
	})
	attr, st = holder.Lookup(ctx, "d/f")
	if st != fsproto.OK {
		t.Fatalf("holder lookup: %d", st)
	}
	node := NewNodeState(attr.Ino, attr.Ino != 0)
	if data, st := holder.Read(ctx, "d/f", node, 0, DiskBlockSize); st != fsproto.OK || len(data) != DiskBlockSize || data[0] != 'o' {
		t.Fatalf("warm read len=%d st=%d", len(data), st)
	}
	gen, oldVersion := holder.VersionCache.GenAndVersion("d/f")
	if gen == 0 || oldVersion == 0 {
		t.Fatalf("warm read did not establish disk-cache key gen=%d version=%d", gen, oldVersion)
	}

	if _, st := holder.Write(ctx, "d/f", node, 0, newData); st != fsproto.OK {
		t.Fatalf("delegated overwrite: %d", st)
	}
	if err := holder.wb.ReleaseFor(ctx, "d/f"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if gotGen, gotVersion := holder.VersionCache.GenAndVersion("d/f"); gotGen != gen || gotVersion != 0 {
		t.Fatalf("handoff version = (%d,%d), want (%d,0)", gotGen, gotVersion, gen)
	}
	data, st := holder.Read(ctx, "d/f", node, 0, DiskBlockSize)
	if st != fsproto.OK || len(data) != DiskBlockSize || data[0] != 'n' {
		t.Fatalf("post-handoff read len=%d st=%d", len(data), st)
	}
}

// A disk block is keyed by authority inode as well as the per-path version
// floor. Hard-link aliases share the inode but have distinct path floors, so
// an in-place invalidation through one name must advance every observed
// alias. Otherwise alias B can keep addressing its V1 block after alias A
// changes the shared inode to V2.
func TestDiskCacheHardlinkAliasAdvancesVersion(t *testing.T) {
	ctx := context.Background()
	addr := serveCore(t)
	writer := dialCore(t, addr, Options{Owner: "disk-hardlink-writer"})

	v1 := make([]byte, DiskBlockSize)
	v2 := make([]byte, DiskBlockSize)
	for i := range v1 {
		v1[i] = '1'
		v2[i] = '2'
	}
	source, st := writer.Create(ctx, "alias-a", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create alias-a: %d", st)
	}
	sourceState := NewNodeState(source.Ino, source.Ino != 0)
	if _, st := writer.Write(ctx, "alias-a", sourceState, 0, v1); st != fsproto.OK {
		t.Fatalf("write V1 through alias-a: %d", st)
	}
	if linked, st := writer.Link(ctx, "alias-a", "alias-b", sourceState); st != fsproto.OK || linked.Ino != source.Ino {
		t.Fatalf("link alias-b: attr=%+v st=%d", linked, st)
	}

	aliasInvalidated := make(chan struct{}, 1)
	reader := dialCore(t, addr, Options{
		Owner:          "disk-hardlink-reader",
		DiskCacheDir:   t.TempDir(),
		DiskCacheBytes: int64(4 * DiskBlockSize),
		VolumeID:       "disk-hardlink-volume",
		OnInvalidate: func(path string, inPlace bool) {
			if path == "alias-b" && inPlace {
				select {
				case aliasInvalidated <- struct{}{}:
				default:
				}
			}
		},
	})
	watchInvalidationsForTest(t, reader)

	// Observe both names so the reader's bounded inode→paths index can fan an
	// invalidation for alias A out to alias B.
	if attr, st := reader.Lookup(ctx, "alias-a"); st != fsproto.OK || attr.Ino != source.Ino {
		t.Fatalf("reader lookup alias-a: attr=%+v st=%d", attr, st)
	}
	aliasB, st := reader.Lookup(ctx, "alias-b")
	if st != fsproto.OK || aliasB.Ino != source.Ino || aliasB.Nlink != 2 {
		t.Fatalf("reader lookup alias-b: attr=%+v st=%d", aliasB, st)
	}
	aliasBState := NewNodeState(aliasB.Ino, true)
	data, st := reader.Read(ctx, "alias-b", aliasBState, 0, DiskBlockSize)
	if st != fsproto.OK || len(data) != DiskBlockSize || data[0] != '1' {
		var first byte
		if len(data) != 0 {
			first = data[0]
		}
		t.Fatalf("warm alias-b read: len=%d first=%q st=%d", len(data), first, st)
	}
	gen, v1Version := reader.VersionCache.GenAndVersion("alias-b")
	if gen == 0 || v1Version == 0 {
		t.Fatalf("warm alias-b version = (%d,%d), want nonzero", gen, v1Version)
	}
	if cached, ok := reader.DiskCache.GetRange(
		reader.volumeID, gen, aliasB.Ino, 0, DiskBlockSize, v1Version,
	); !ok || len(cached) != DiskBlockSize || cached[0] != '1' {
		t.Fatalf("alias-b V1 block was not cached: hit=%v len=%d", ok, len(cached))
	}

	if _, st := writer.Write(ctx, "alias-a", sourceState, 0, v2); st != fsproto.OK {
		t.Fatalf("write V2 through alias-a: %d", st)
	}
	select {
	case <-aliasInvalidated:
	case <-time.After(2 * time.Second):
		t.Fatal("alias-b did not receive related-inode invalidation")
	}
	gotGen, v2Version := reader.VersionCache.GenAndVersion("alias-b")
	if gotGen != gen || v2Version <= v1Version {
		t.Fatalf("alias-b version after alias-a mutation = (%d,%d), want (%d, >%d)", gotGen, v2Version, gen, v1Version)
	}

	data, st = reader.Read(ctx, "alias-b", aliasBState, 0, DiskBlockSize)
	if st != fsproto.OK || len(data) != DiskBlockSize || data[0] != '2' {
		t.Fatalf("post-mutation alias-b read: len=%d first=%q st=%d", len(data), data[:1], st)
	}
}

// A current authority read can install the event path's version before the
// ordered invalidation stream delivers that same mutation. The primary Apply
// then returns false, but every hardlink alias still needs the related inode's
// version and cache eviction or it can keep serving an old disk block.
func TestDiskCacheHardlinkAliasAdvancesWhenPrimaryVersionAlreadyCurrent(t *testing.T) {
	ctx := context.Background()
	addr := serveCore(t)
	writer := dialCore(t, addr, Options{Owner: "disk-hardlink-race-writer"})

	v1 := make([]byte, DiskBlockSize)
	v2 := make([]byte, DiskBlockSize)
	for i := range v1 {
		v1[i] = '1'
		v2[i] = '2'
	}
	source, st := writer.Create(ctx, "alias-a", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create alias-a: %d", st)
	}
	sourceState := NewNodeState(source.Ino, source.Ino != 0)
	if _, st := writer.Write(ctx, "alias-a", sourceState, 0, v1); st != fsproto.OK {
		t.Fatalf("write V1 through alias-a: %d", st)
	}
	linked, st := writer.Link(ctx, "alias-a", "alias-b", sourceState)
	if st != fsproto.OK || linked.Ino != source.Ino {
		t.Fatalf("link alias-b: attr=%+v st=%d", linked, st)
	}

	initialFlush := make(chan struct{}, 1)
	aliasInvalidated := make(chan struct{}, 1)
	reader := dialCore(t, addr, Options{
		Owner:          "disk-hardlink-race-reader",
		DiskCacheDir:   t.TempDir(),
		DiskCacheBytes: int64(4 * DiskBlockSize),
		VolumeID:       "disk-hardlink-race-volume",
		OnFlushAll: func(scope string) {
			if scope == "" {
				select {
				case initialFlush <- struct{}{}:
				default:
				}
			}
		},
		OnInvalidate: func(path string, inPlace bool) {
			if path == "alias-b" && inPlace {
				select {
				case aliasInvalidated <- struct{}{}:
				default:
				}
			}
		},
	})
	sub := &fakeSub{ch: make(chan coherence.Batch, 4)}
	watchCtx, cancelWatch := context.WithCancel(context.Background())
	go WatchInvalidations(
		watchCtx,
		sub,
		reader.VersionCache,
		reader.AttrCache,
		volumeInvalidationHandler{v: reader},
		InvalidationOptions{},
	)
	defer func() {
		cancelWatch()
		close(sub.ch)
	}()
	select {
	case <-initialFlush:
	case <-time.After(2 * time.Second):
		t.Fatal("fake invalidation watcher did not initialize")
	}

	if attr, st := reader.Lookup(ctx, "alias-a"); st != fsproto.OK || attr.Ino != source.Ino {
		t.Fatalf("reader lookup alias-a: attr=%+v st=%d", attr, st)
	}
	aliasB, st := reader.Lookup(ctx, "alias-b")
	if st != fsproto.OK || aliasB.Ino != source.Ino || aliasB.Nlink != 2 {
		t.Fatalf("reader lookup alias-b: attr=%+v st=%d", aliasB, st)
	}
	aliasBState := NewNodeState(aliasB.Ino, true)
	data, st := reader.Read(ctx, "alias-b", aliasBState, 0, DiskBlockSize)
	if st != fsproto.OK || len(data) != DiskBlockSize || data[0] != '1' {
		t.Fatalf("warm alias-b read: len=%d first=%q st=%d", len(data), data[:1], st)
	}
	gen, v1Version := reader.VersionCache.GenAndVersion("alias-b")
	if gen == 0 || v1Version == 0 {
		t.Fatalf("warm alias-b version = (%d,%d), want nonzero", gen, v1Version)
	}
	if cached, ok := reader.DiskCache.GetRange(
		reader.volumeID,
		gen,
		aliasB.Ino,
		0,
		DiskBlockSize,
		v1Version,
	); !ok || len(cached) != DiskBlockSize || cached[0] != '1' {
		t.Fatalf("alias-b V1 block was not cached: hit=%v len=%d", ok, len(cached))
	}

	if _, st := writer.Write(ctx, "alias-a", sourceState, 0, v2); st != fsproto.OK {
		t.Fatalf("write V2 through alias-a: %d", st)
	}
	_, v2Version, v2Gen, _, getattrStatus, err := reader.client.GetattrV("alias-a")
	if err != nil || getattrStatus != fsproto.OK || v2Gen != gen || v2Version <= v1Version {
		t.Fatalf(
			"authority alias-a V2 stamp: gen=%d version=%d status=%d err=%v; want gen=%d version>%d",
			v2Gen,
			v2Version,
			getattrStatus,
			err,
			gen,
			v1Version,
		)
	}
	if !reader.VersionCache.FillOK(v2Gen, "alias-a", v2Version) {
		t.Fatal("could not pre-advance primary alias version")
	}
	if reader.VersionCache.Apply(v2Gen, "alias-a", v2Version) {
		t.Fatal("test precondition: primary invalidation unexpectedly advanced")
	}

	sub.ch <- coherence.Batch{Invs: []coherence.Invalidation{{
		Path:        "alias-a",
		Version:     v2Version,
		Gen:         v2Gen,
		InPlace:     true,
		RelatedInos: []uint64{aliasB.Ino},
	}}}
	select {
	case <-aliasInvalidated:
	case <-time.After(2 * time.Second):
		t.Fatal("same-version primary event did not invalidate alias-b")
	}
	gotGen, gotVersion := reader.VersionCache.GenAndVersion("alias-b")
	if gotGen != gen || gotVersion != v2Version {
		t.Fatalf(
			"alias-b version after same-version primary = (%d,%d), want (%d,%d)",
			gotGen,
			gotVersion,
			gen,
			v2Version,
		)
	}

	data, st = reader.Read(ctx, "alias-b", aliasBState, 0, DiskBlockSize)
	if st != fsproto.OK || len(data) != DiskBlockSize || data[0] != '2' {
		var first byte
		if len(data) != 0 {
			first = data[0]
		}
		t.Fatalf("post-invalidation alias-b read: len=%d first=%q st=%d", len(data), first, st)
	}
}
