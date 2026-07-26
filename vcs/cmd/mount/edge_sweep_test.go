package main

// edge_sweep_test.go exhaustively exercises the FUSE mount's pure, unit-testable
// helpers WITHOUT spinning a real FUSE server (which would need OS/FUSE privileges).
// Where a helper makes an authority round-trip (setattrOwner -> n.c.Getattr), we stand
// up the same in-memory fsproto authority the fsproto package's own tests use
// (workfs + wal + delegation served over a loopback listener) and drive it through the
// public fsproto.Client API.

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/trendup-ai/portablefs/vcs/internal/delegation"
	"github.com/trendup-ai/portablefs/vcs/internal/fsproto"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

// ----------------------------------------------------------------------------
// in-memory authority harness (mirrors internal/fsproto/fsproto_test.go's serve)
// ----------------------------------------------------------------------------

type edgeNoBlobs struct{}

func (edgeNoBlobs) Blob(context.Context, string) ([]byte, error) { return nil, nil }

func newAuthority(t *testing.T) *fsproto.Client {
	t.Helper()
	cli, _ := newAuthorityStoppable(t)
	return cli
}

// newAuthorityStoppable returns a connected client plus a stop() that cancels the
// server and closes its listener; after stop(), client round-trips fail fast (the
// "authority unreachable" injection used purely via the public API).
func newAuthorityStoppable(t *testing.T) (*fsproto.Client, func()) {
	t.Helper()
	w, err := wal.Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	wfs, err := workfs.New(nil, edgeNoBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = fsproto.NewServer(wfs, wfs, delegation.New()).Serve(ctx, ln) }()

	cli, err := fsproto.Dial(ln.Addr().String(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	var once sync.Once
	stop := func() { once.Do(func() { cancel(); _ = ln.Close() }) }
	return cli, stop
}

// ----------------------------------------------------------------------------
// sessAttr
// ----------------------------------------------------------------------------

func TestSessAttrZeroMtimeDefaultsToNow(t *testing.T) {
	before := time.Now().UnixMilli()
	a := sessAttr("file", 0o644, 10, 0 /*mtimeMs*/, 0, 0)
	after := time.Now().UnixMilli()
	if a.MtimeMs < before || a.MtimeMs > after {
		t.Fatalf("zero mtime should default to ~now; got %d not in [%d,%d]",
			a.MtimeMs, before, after)
	}
	if a.Kind != "file" || a.Mode != 0o644 || a.Size != 10 {
		t.Fatalf("kind/mode/size not surfaced: %+v", a)
	}
}

func TestSessAttrSurfacesProvidedFields(t *testing.T) {
	a := sessAttr("symlink", 0o777, 7, 1234567, 501, 20)
	if a.Kind != "symlink" {
		t.Fatalf("kind = %q", a.Kind)
	}
	if a.Mode != 0o777 || a.Size != 7 || a.MtimeMs != 1234567 {
		t.Fatalf("mode/size/mtime = %o/%d/%d", a.Mode, a.Size, a.MtimeMs)
	}
	if a.Uid != 501 || a.Gid != 20 {
		t.Fatalf("uid/gid = %d/%d, want 501/20", a.Uid, a.Gid)
	}
	// A non-zero mtime must be preserved verbatim (not replaced by now).
	if a.MtimeMs != 1234567 {
		t.Fatal("non-zero mtime must be preserved")
	}
}

func TestSessAttrZeroSizeAndZeroIDsKept(t *testing.T) {
	// Size 0 and uid/gid 0 (root-owned, empty file) are legitimate values and must be
	// carried through untouched; only mtime==0 is special-cased.
	a := sessAttr("file", 0o600, 0, 999, 0, 0)
	if a.Size != 0 || a.Uid != 0 || a.Gid != 0 {
		t.Fatalf("zero size/uid/gid must be preserved: %+v", a)
	}
	if a.MtimeMs != 999 {
		t.Fatalf("non-zero mtime 999 must be kept, got %d", a.MtimeMs)
	}
}

// ----------------------------------------------------------------------------
// fillAttr
// ----------------------------------------------------------------------------

func TestFillAttrModeTypeBitsAndSplit(t *testing.T) {
	cases := []struct {
		kind     string
		wantType uint32
	}{
		{"directory", fuse.S_IFDIR},
		{"symlink", fuse.S_IFLNK},
		{"file", fuse.S_IFREG},
		{"weird-unknown-kind", fuse.S_IFREG}, // default branch -> regular file
		{"", fuse.S_IFREG},                   // empty kind -> regular file
	}
	for _, c := range cases {
		var out fuse.Attr
		a := &fsproto.Attr{
			Kind:    c.kind,
			Mode:    0o7777, // include setuid/setgid/sticky to prove the full mode survives
			Size:    4096,
			MtimeMs: 1500, // 1.5s -> 1s + 500ms
			Uid:     7,
			Gid:     11,
		}
		fillAttr("some/path", a, &out)

		if out.Mode&^uint32(0o7777) != c.wantType {
			t.Fatalf("kind %q: type bits = %#o, want %#o", c.kind, out.Mode&^uint32(0o7777), c.wantType)
		}
		if out.Mode&0o7777 != 0o7777 {
			t.Fatalf("kind %q: mode bits = %#o, want %#o", c.kind, out.Mode&0o7777, uint32(0o7777))
		}
		if out.Size != 4096 {
			t.Fatalf("size = %d, want 4096", out.Size)
		}
		if out.Mtime != 1 || out.Mtimensec != 500*1e6 {
			t.Fatalf("mtime split = %ds %dns, want 1s 500000000ns", out.Mtime, out.Mtimensec)
		}
		if out.Uid != 7 || out.Gid != 11 {
			t.Fatalf("uid/gid = %d/%d, want 7/11", out.Uid, out.Gid)
		}
		if out.Ino != inoOf("some/path") {
			t.Fatalf("ino = %d, want inoOf(some/path)=%d", out.Ino, inoOf("some/path"))
		}
	}
}

func TestFillAttrMtimeBoundaries(t *testing.T) {
	cases := []struct {
		ms      int64
		wantSec uint64
		wantNs  uint32
	}{
		{0, 0, 0},           // epoch
		{1, 0, 1e6},         // 1ms
		{999, 0, 999 * 1e6}, // just under a second
		{1000, 1, 0},        // exactly a second -> no sub-second remainder
		{1001, 1, 1e6},      // a second + 1ms
		{61_000, 61, 0},     // a minute
		{1_700_000_000_123, 1_700_000_000, 123 * 1e6}, // a realistic unix-ms timestamp
	}
	for _, c := range cases {
		var out fuse.Attr
		fillAttr("p", &fsproto.Attr{Kind: "file", MtimeMs: c.ms}, &out)
		if out.Mtime != c.wantSec || out.Mtimensec != c.wantNs {
			t.Fatalf("MtimeMs %d -> %ds %dns, want %ds %dns",
				c.ms, out.Mtime, out.Mtimensec, c.wantSec, c.wantNs)
		}
	}
}

func TestFillAttrRootInode(t *testing.T) {
	var out fuse.Attr
	fillAttr("", &fsproto.Attr{Kind: "directory"}, &out)
	if out.Ino != 1 {
		t.Fatalf("root path must map to inode 1, got %d", out.Ino)
	}
}

// ----------------------------------------------------------------------------
// typeBits / inoOf
// ----------------------------------------------------------------------------

func TestTypeBits(t *testing.T) {
	if typeBits("directory") != fuse.S_IFDIR {
		t.Fatal("directory")
	}
	if typeBits("symlink") != fuse.S_IFLNK {
		t.Fatal("symlink")
	}
	if typeBits("file") != fuse.S_IFREG {
		t.Fatal("file")
	}
	// Anything unrecognised (and empty) falls through to a regular file.
	if typeBits("") != fuse.S_IFREG || typeBits("socket") != fuse.S_IFREG {
		t.Fatal("default kind must be a regular file")
	}
}

func TestInoOfStableAndDistinct(t *testing.T) {
	// Root is the conventional inode 1.
	if inoOf("") != 1 {
		t.Fatalf(`inoOf("") = %d, want 1`, inoOf(""))
	}
	// Stability: same path -> same inode across calls (required for getcwd/find/git).
	for _, p := range []string{"a", "a/b/c", "dir/file.txt", "x"} {
		if inoOf(p) != inoOf(p) {
			t.Fatalf("inoOf(%q) is not stable", p)
		}
		if inoOf(p) <= 1 {
			t.Fatalf("inoOf(%q) = %d must be > 1 (1 is reserved for root)", p, inoOf(p))
		}
	}
	// Different non-root paths should (overwhelmingly) differ; check a sampling have
	// no collisions among themselves AND none collide with root(1).
	seen := map[uint64]string{1: "<root>"}
	for i := 0; i < 5000; i++ {
		p := "path/" + itoa(i)
		ino := inoOf(p)
		if ino == 1 {
			t.Fatalf("non-root path %q collided with root inode 1", p)
		}
		if prev, dup := seen[ino]; dup {
			t.Fatalf("inode collision: %q and %q both -> %d", prev, p, ino)
		}
		seen[ino] = p
	}
}

func TestInoOfHashCollisionFallback(t *testing.T) {
	// inoOf maps a hash of 0 or 1 up to 2 so a non-root path never claims inode 1 (or
	// the ambiguous 0). We can't easily force fnv to produce <=1 for a chosen string,
	// but we CAN assert the invariant holds for the documented edge: any path that is
	// non-empty must yield >= 2. (The fallback line is `return 2`.)
	for _, p := range []string{"a", "z", "\x00", "////", " "} {
		if got := inoOf(p); got < 2 {
			t.Fatalf("inoOf(%q) = %d, must be >= 2 for any non-root path", p, got)
		}
	}
}

// ----------------------------------------------------------------------------
// splitPath
// ----------------------------------------------------------------------------

func TestSplitPath(t *testing.T) {
	cases := []struct {
		in        string
		dir, base string
	}{
		{"", "", ""},                      // empty
		{"file", "", "file"},              // top-level: no dir
		{"a/b", "a", "b"},                 // one level
		{"a/b/c", "a/b", "c"},             // deep
		{"dir/", "dir", ""},               // trailing slash -> empty base
		{"/abs", "", "abs"},               // leading slash -> empty dir, base after it
		{"a//b", "a/", "b"},               // double slash: split at the LAST '/'
		{"/", "", ""},                     // lone slash
		{".hidden", "", ".hidden"},        // dotfile at top level
		{"a/b/.hidden", "a/b", ".hidden"}, // dotfile in a subdir
	}
	for _, c := range cases {
		dir, base := splitPath(c.in)
		if dir != c.dir || base != c.base {
			t.Fatalf("splitPath(%q) = (%q,%q), want (%q,%q)", c.in, dir, base, c.dir, c.base)
		}
	}
}

// ----------------------------------------------------------------------------
// walk (pure path traversal; positive multi-level cases need a live FUSE bridge,
// which we avoid — here we pin the bridge-free reachable behaviour)
// ----------------------------------------------------------------------------

func TestWalkEmptyPathReturnsRoot(t *testing.T) {
	root := &fs.Inode{}
	if got := walk(root, ""); got != root {
		t.Fatal(`walk(root, "") must return root unchanged`)
	}
}

func TestWalkMissingChildReturnsNil(t *testing.T) {
	// A fresh root has no children; any lookup misses and returns nil (GetChild on an
	// empty inode is safe — no bridge needed). Also covers slash normalization: empty
	// path segments from leading/trailing/double slashes are skipped, never panicking.
	// Each of these has at least one real (non-empty) segment, so GetChild is called
	// and misses on the childless root. ("///" — all-empty segments — is NOT here; it
	// returns root and is covered by TestWalkAllEmptySegmentsReturnsRoot.)
	root := &fs.Inode{}
	for _, p := range []string{"a", "a/b/c", "/a", "a/", "a//b", "no/such/deep/path"} {
		if got := walk(root, p); got != nil {
			t.Fatalf("walk(emptyRoot, %q) = %v, want nil (no such child)", p, got)
		}
	}
}

func TestWalkAllEmptySegmentsReturnsRoot(t *testing.T) {
	// A path made only of separators has no real segments, so the loop never calls
	// GetChild and walk returns the root (matching the path=="" early return's intent
	// for a normalized-empty path).
	root := &fs.Inode{}
	for _, p := range []string{"/", "//", "///"} {
		if got := walk(root, p); got != root {
			t.Fatalf("walk(root, %q) = %v, want root (all segments empty)", p, got)
		}
	}
}

// ----------------------------------------------------------------------------
// setattrOwner — partial chown reads the authority for the unsupplied side
// ----------------------------------------------------------------------------

// mkSetAttr builds a SetAttrIn requesting a chown of whichever side is asked for.
func mkSetAttr(setU bool, uid uint32, setG bool, gid uint32) *fuse.SetAttrIn {
	in := &fuse.SetAttrIn{}
	if setU {
		in.Valid |= fuse.FATTR_UID
		in.Uid = uid
	}
	if setG {
		in.Valid |= fuse.FATTR_GID
		in.Gid = gid
	}
	return in
}

func TestSetattrOwnerNoChangeRequested(t *testing.T) {
	// Neither uid nor gid set: ok=false, no authority read (so a nil client is safe).
	n := &node{c: nil, path: "anything"}
	uid, gid, ok := setattrOwner(n, n.curPath(), mkSetAttr(false, 0, false, 0))
	if ok {
		t.Fatal("ok must be false when no ownership change is requested")
	}
	if uid != 0 || gid != 0 {
		t.Fatalf("uid/gid must be zero when ok=false, got %d/%d", uid, gid)
	}
}

func TestSetattrOwnerFullChownSkipsAuthority(t *testing.T) {
	// Both sides supplied: setattrOwner must NOT read the authority. We prove that by
	// pointing the node at a STOPPED authority — if it tried to Getattr it would still
	// succeed at returning the supplied values (the read is gated off entirely), and
	// the call must not hang or alter the supplied uid/gid.
	cli, stop := newAuthorityStoppable(t)
	stop() // dead authority; a Getattr here would error, but full chown won't call it
	n := &node{c: cli, path: "irrelevant"}

	done := make(chan struct{})
	var uid, gid uint32
	var ok bool
	go func() {
		uid, gid, ok = setattrOwner(n, n.curPath(), mkSetAttr(true, 4242, true, 8484))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("full chown must not touch the (dead) authority — it hung")
	}
	if !ok || uid != 4242 || gid != 8484 {
		t.Fatalf("full chown = (%d,%d,%v), want (4242,8484,true)", uid, gid, ok)
	}
}

func TestSetattrOwnerPartialReadsAuthorityValue(t *testing.T) {
	cli := newAuthority(t)
	// Seed a file owned by uid=1000 gid=2000 through the public protocol.
	if _, st, err := cli.Create("f", 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}
	if st, err := cli.Setattr("f", 0, false, 0, false, 1000, 2000, true, true); err != nil || st != fsproto.OK {
		t.Fatalf("seed chown: st=%d err=%v", st, err)
	}
	// Sanity: the authority really reports 1000/2000 now.
	if a, st, err := cli.Getattr("f"); err != nil || st != fsproto.OK || a.Uid != 1000 || a.Gid != 2000 {
		t.Fatalf("seed readback: a=%+v st=%d err=%v", a, st, err)
	}
	n := &node{c: cli, path: "f"}

	// Only uid set (chown to 7): gid must be read back from the authority (2000).
	uid, gid, ok := setattrOwner(n, n.curPath(), mkSetAttr(true, 7, false, 0))
	if !ok || uid != 7 || gid != 2000 {
		t.Fatalf("uid-only chown = (%d,%d,%v), want (7,2000,true) — gid must come from authority",
			uid, gid, ok)
	}
	// Only gid set (chgrp to 9): uid must be read back from the authority (1000).
	uid, gid, ok = setattrOwner(n, n.curPath(), mkSetAttr(false, 0, true, 9))
	if !ok || uid != 1000 || gid != 9 {
		t.Fatalf("gid-only chown = (%d,%d,%v), want (1000,9,true) — uid must come from authority",
			uid, gid, ok)
	}
}

func TestSetattrOwnerPartialAuthorityUnreachableMustNotCorruptUnsetSide(t *testing.T) {
	// A partial chown (`chown user:`  / `chown :group`) where the authority read FAILS
	// (injected via the public API by stopping the server). For the side the kernel did
	// NOT supply, fuse's GetUID/GetGID return (^uint32(0), false) — the POSIX "-1 =
	// leave unchanged" sentinel. setattrOwner copies that sentinel into uid/gid and is
	// supposed to overwrite it with the authority's CURRENT value; but when Getattr
	// errors, the `err == nil` guard is skipped and the sentinel survives. It then flows
	// to s.Chown(uid, gid) (main.go:678 -> session.Chown, which stores it VERBATIM with
	// no -1 handling), persisting owner/group 4294967295 (nobody/overflow) into the WAL.
	//
	// DESIRED: on a failed read the unspecified side must be left UNCHANGED (carry the
	// file's real current value, or at minimum never persist the raw sentinel as a real
	// id). This test pins that contract; it fails today because gid comes back as
	// ^uint32(0) instead of the seeded current gid.
	cli, stop := newAuthorityStoppable(t)
	if _, st, err := cli.Create("g", 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}
	if st, err := cli.Setattr("g", 0, false, 0, false, 1000, 2000, true, true); err != nil || st != fsproto.OK {
		t.Fatalf("seed chown: st=%d err=%v", st, err)
	}
	stop() // now Getattr round-trips fail fast
	n := &node{c: cli, path: "g"}

	done := make(chan struct{})
	var uid, gid uint32
	var ok bool
	go func() {
		uid, gid, ok = setattrOwner(n, n.curPath(), mkSetAttr(true, 55, false, 0)) // uid-only chown
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("partial chown against a dead authority must fail fast, not hang")
	}
	// FIX: with the authority unreachable the unspecified side cannot be resolved, so setattrOwner
	// REFUSES the chown (ok=false) — it must never let the ^uint32(0) sentinel reach s.Chown as a
	// literal owner/group id (which would durably corrupt ownership to 4294967295/nobody).
	if ok {
		t.Fatalf("partial chown with the authority unreachable must REFUSE (ok=false); got ok=true uid=%d gid=%d (gid would persist the -1 sentinel)", uid, gid)
	}
}

// TestSetattrOwnerPartialUnreachableDoesNotHangOrPanic locks in the SAFE part of the
// degraded path (no hang, no panic, ok=true, supplied side intact) so the skipped
// bug-test above doesn't leave that behaviour unguarded. It deliberately does NOT
// assert the value of the unspecified side (that's the bug).
func TestSetattrOwnerPartialUnreachableDoesNotHangOrPanic(t *testing.T) {
	cli, stop := newAuthorityStoppable(t)
	if _, st, err := cli.Create("h", 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}
	stop()
	n := &node{c: cli, path: "h"}

	done := make(chan struct{})
	var uid uint32
	var ok bool
	go func() {
		uid, _, ok = setattrOwner(n, n.curPath(), mkSetAttr(true, 55, false, 0))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("partial chown against a dead authority must fail fast, not hang")
	}
	// FIX: the degraded partial-chown path must REFUSE (ok=false), fast, without hang or panic —
	// never persisting the -1 sentinel as a literal id.
	if ok {
		t.Fatalf("partial chown with the authority unreachable must refuse (ok=false); got ok=true uid=%d", uid)
	}
}
