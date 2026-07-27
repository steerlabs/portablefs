package clientcore

import (
	"context"
	"testing"

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
