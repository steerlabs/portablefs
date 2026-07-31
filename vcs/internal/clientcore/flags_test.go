package clientcore

// Client-side coverage for chflags(2): the delegated lane cannot carry a BSD
// flag word, so a flags setattr is routed WRITE-THROUGH — the correct lane,
// because only the authority persists flags — and the feature bit is what a
// frontend gates on before ever issuing one.

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// noInodeMetadataFS models an authority PREDATING the PFT2 inode-record
// revision that added durable BSD flags and birth times. Embedding keeps the
// managed coordination surface identical, so the only difference a client can
// observe is the missing capability bit.
type noInodeMetadataFS struct{ *workfs.FS }

func (noInodeMetadataFS) PersistsInodeMetadata() bool { return false }

func serveCoreWithoutFlagPersistence(t *testing.T) string {
	t.Helper()
	fs := newManagedTestFS(t, testBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	wrapped := noInodeMetadataFS{FS: fs}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = fsproto.NewServer(wrapped, wrapped).Serve(ctx, ln) }()
	return ln.Addr().String()
}

// TestSetattrFlagsRoutesWriteThroughAndRoundTrips: a chflags inside a scope the
// mount holds delegated must NOT be acknowledged locally. The engine has no
// durable lane for a flag word, so it releases the delegation and the mutation
// goes to the authority — where it is immediately visible to a peer that never
// participated in the handoff. That visibility is the proof: an overlay
// acknowledgement would leave the peer reading the old value.
func TestSetattrFlagsRoutesWriteThroughAndRoundTrips(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{Owner: "flags-writer", WALDir: t.TempDir()})
	ctx := context.Background()

	if !v.SupportsFlagPersistence() {
		t.Fatal("authority does not advertise FeatureFlagPersistence")
	}
	if _, st := v.Mkdir(ctx, "wb", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "wb/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	if got := v.WritebackStatus().Delegations; len(got) != 1 || got[0].Scope != "wb" {
		t.Fatalf("create did not enter the delegated lane: %+v", got)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)

	const flags = uint32(0x8000_0002)
	attr, st := v.Setattr(ctx, "wb/f", n, SetattrRequest{Flags: flags, SetFlags: true})
	if st != fsproto.OK {
		t.Fatalf("chflags: %d", st)
	}
	if attr.Flags != flags {
		t.Fatalf("chflags reply flags = %#x, want %#x", attr.Flags, flags)
	}
	if got := v.WritebackStatus().Delegations; len(got) != 0 {
		t.Fatalf("chflags was acknowledged in the overlay instead of written through: %+v", got)
	}

	// Durable at the authority right now, with no fsync and no handoff.
	peer := dialCore(t, addr, Options{Owner: "flags-peer"})
	if pa, st := peer.Getattr(ctx, "wb/f", nil); st != fsproto.OK || pa.Flags != flags {
		t.Fatalf("peer getattr = %+v st=%d, want flags %#x", pa, st, flags)
	}
	// And the writer reads back the same word rather than the overlay's zero.
	if own, st := v.Getattr(ctx, "wb/f", n); st != fsproto.OK || own.Flags != flags {
		t.Fatalf("own getattr = %+v st=%d, want flags %#x", own, st, flags)
	}

	// Clearing is a real durable state, not "no change".
	if attr, st := v.Setattr(ctx, "wb/f", n, SetattrRequest{SetFlags: true}); st != fsproto.OK || attr.Flags != 0 {
		t.Fatalf("clear: attr=%+v st=%d", attr, st)
	}
	// A FRESH peer: the first peer cached the attr and is not watching
	// invalidations, so re-asking it would prove nothing about durability.
	fresh := dialCore(t, addr, Options{Owner: "flags-peer-2"})
	if pa, st := fresh.Getattr(ctx, "wb/f", nil); st != fsproto.OK || pa.Flags != 0 {
		t.Fatalf("fresh peer after clear: flags=%#x st=%d, want 0", pa.Flags, st)
	}
}

// TestSetattrFlagsWithPendingWritesFlushesFirst: the delegated file has bytes
// that exist only in the local stream when the chflags arrives. Releasing the
// delegation to write the flags through must carry those bytes to the authority
// too — otherwise the write-through would silently discard them.
func TestSetattrFlagsWithPendingWritesFlushesFirst(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{Owner: "flags-pending", WALDir: t.TempDir()})
	ctx := context.Background()

	if _, st := v.Mkdir(ctx, "wb", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	a, st := v.Create(ctx, "wb/pending.txt", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := v.Write(ctx, "wb/pending.txt", n, 0, []byte("unflushed")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}
	if got := v.WritebackStatus().Delegations; len(got) != 1 {
		t.Fatalf("write did not stay delegated: %+v", got)
	}

	const flags = uint32(0x2)
	if _, st := v.Setattr(ctx, "wb/pending.txt", n, SetattrRequest{Flags: flags, SetFlags: true}); st != fsproto.OK {
		t.Fatalf("chflags over pending writes: %d", st)
	}

	peer := dialCore(t, addr, Options{Owner: "flags-pending-peer"})
	data, st := peer.Read(ctx, "wb/pending.txt", nil, 0, 32)
	if st != fsproto.OK || string(data) != "unflushed" {
		t.Fatalf("peer read = %q st=%d, want the flushed bytes", data, st)
	}
	if pa, st := peer.Getattr(ctx, "wb/pending.txt", nil); st != fsproto.OK || pa.Flags != flags {
		t.Fatalf("peer getattr = %+v st=%d, want flags %#x", pa, st, flags)
	}
}

// TestSetattrFlagsSplitsFromOtherGroups: one syscall carrying mode + times +
// flags reaches the authority as separate exact identities and every group
// lands. A fused request would be EINVAL; a dropped flag word would leave the
// stored value at zero.
func TestSetattrFlagsSplitsFromOtherGroups(t *testing.T) {
	addr := serveCore(t)
	v := dialCore(t, addr, Options{Owner: "flags-split", WALDir: t.TempDir()})
	ctx := context.Background()

	a, st := v.Create(ctx, "multi.txt", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	const flags = uint32(0x8000_0002)
	attr, st := v.Setattr(ctx, "multi.txt", n, SetattrRequest{
		Mode: 0o600, SetMode: true,
		MtimeMs: 456_000, SetMTime: true,
		Size: 3, SetSize: true,
		Flags: flags, SetFlags: true,
	})
	if st != fsproto.OK {
		t.Fatalf("multi-group setattr with flags: %d", st)
	}
	if attr.Mode&0o777 != 0o600 || attr.MtimeMs != 456_000 || attr.Size != 3 || attr.Flags != flags {
		t.Fatalf("attr = %+v, want mode 600 mtime 456000 size 3 flags %#x", attr, flags)
	}
}

// TestSetattrFlagsAgainstAuthorityWithoutTheFeature: the refusal a frontend
// must be able to make BEFORE mutating. The capability answer is a definite
// pre-flight fact from the version probe, and if a client ignored it the
// authority still fails closed rather than logging a flag word it cannot serve.
func TestSetattrFlagsAgainstAuthorityWithoutTheFeature(t *testing.T) {
	addr := serveCoreWithoutFlagPersistence(t)
	v := dialCore(t, addr, Options{Owner: "old-authority", WALDir: t.TempDir()})
	ctx := context.Background()

	if v.SupportsFlagPersistence() {
		t.Fatal("an authority without the inode-metadata revision advertised FeatureFlagPersistence")
	}
	// The bitmap is a SET of independent capabilities: only this one is gone.
	if v.client.Features()&fsproto.FeatureDelegatedXattrs == 0 {
		t.Fatal("the delegated-xattr lane was collaterally disabled")
	}

	a, st := v.Create(ctx, "old.txt", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := v.Setattr(ctx, "old.txt", n, SetattrRequest{Flags: 0x2, SetFlags: true}); st != fsproto.EOPNOTSUPP {
		t.Fatalf("chflags against a non-persisting authority: %d, want EOPNOTSUPP", st)
	}
	if attr, st := v.Getattr(ctx, "old.txt", n); st != fsproto.OK || attr.Flags != 0 {
		t.Fatalf("a refused chflags still changed something: attr=%+v st=%d", attr, st)
	}
	// Everything else about setattr is unaffected by the missing bit.
	if attr, st := v.Setattr(ctx, "old.txt", n, SetattrRequest{Mode: 0o600, SetMode: true}); st != fsproto.OK ||
		attr.Mode&0o777 != 0o600 {
		t.Fatalf("chmod against a non-persisting authority: attr=%+v st=%d", attr, st)
	}
}
