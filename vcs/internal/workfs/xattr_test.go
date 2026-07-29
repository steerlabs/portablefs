package workfs

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/fstransition"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// xattrTestBlobs satisfies content.BlobReader for tests that never fetch.
type xattrTestBlobs struct{}

func (xattrTestBlobs) Blob(context.Context, string) ([]byte, error) {
	return nil, errors.New("no blobs in xattr tests")
}

func openXattrWAL(t *testing.T, path string) *wal.WAL {
	t.Helper()
	w, err := wal.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Replay(); err != nil {
		t.Fatal(err)
	}
	return w
}

// TestXattrLegacyApplySemantics drives set/get/list/remove — overwrite,
// remove-missing, and the frozen bounds — through the legacy WAL store's
// write path (MutateAs) and read surface.
func TestXattrLegacyApplySemantics(t *testing.T) {
	w := openXattrWAL(t, filepath.Join(t.TempDir(), "wal.log"))
	fs, err := New(nil, xattrTestBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644}, "M"); err != nil {
		t.Fatal(err)
	}

	// Set + get + list (sorted), on a file, a directory, and the root.
	if err := fs.MutateAs(wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.b", Data: []byte("vb")}, "M"); err != nil {
		t.Fatalf("setxattr: %v", err)
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.a", Data: []byte("va")}, "M"); err != nil {
		t.Fatalf("setxattr: %v", err)
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpMkdir, Path: "d", Mode: 0o755}, "M"); err != nil {
		t.Fatal(err)
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpSetxattr, Path: "d", XattrName: "user.dir", Data: []byte("dv")}, "M"); err != nil {
		t.Fatalf("setxattr on dir: %v", err)
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpSetxattr, Path: "", XattrName: "user.root", Data: []byte("rv")}, "M"); err != nil {
		t.Fatalf("setxattr on root: %v", err)
	}
	if v, err := fs.GetxattrHandle("f", 0, "user.a"); err != nil || string(v) != "va" {
		t.Fatalf("getxattr = %q, %v", v, err)
	}
	if names, err := fs.ListxattrHandle("f", 0); err != nil || strings.Join(names, ",") != "user.a,user.b" {
		t.Fatalf("listxattr = %v, %v", names, err)
	}

	// Overwrite: last writer wins, case-sensitive names stay distinct.
	if err := fs.MutateAs(wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.a", Data: []byte("v2")}, "M"); err != nil {
		t.Fatal(err)
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.A", Data: []byte("upper")}, "M"); err != nil {
		t.Fatal(err)
	}
	if v, _ := fs.GetxattrHandle("f", 0, "user.a"); string(v) != "v2" {
		t.Fatalf("overwrite lost: %q", v)
	}
	if v, _ := fs.GetxattrHandle("f", 0, "user.A"); string(v) != "upper" {
		t.Fatalf("case-sensitive name collapsed: %q", v)
	}

	// Missing-name semantics: getxattr and removexattr answer ENODATA.
	if _, err := fs.GetxattrHandle("f", 0, "user.absent"); !errors.Is(err, syscall.ENODATA) {
		t.Fatalf("get of missing = %v, want ENODATA", err)
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpRemovexattr, Path: "f", XattrName: "user.absent"}, "M"); !errors.Is(err, syscall.ENODATA) {
		t.Fatalf("remove of missing = %v, want ENODATA", err)
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpRemovexattr, Path: "f", XattrName: "user.b"}, "M"); err != nil {
		t.Fatalf("removexattr: %v", err)
	}
	if _, err := fs.GetxattrHandle("f", 0, "user.b"); !errors.Is(err, syscall.ENODATA) {
		t.Fatalf("removed name still present: %v", err)
	}

	// Missing file: ENOENT for reads and writes.
	if _, err := fs.GetxattrHandle("missing", 0, "user.a"); err == nil {
		t.Fatal("getxattr of a missing path succeeded")
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpSetxattr, Path: "missing", XattrName: "user.a", Data: []byte("v")}, "M"); err == nil {
		t.Fatal("setxattr of a missing path succeeded")
	}

	// Bounds: name (ERANGE via admission), value (E2BIG via admission), and
	// the deterministic per-inode total (ENOSPC at apply).
	longName := strings.Repeat("n", wal.MaxXattrNameBytes+1)
	if err := fs.MutateAs(wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: longName, Data: []byte("v")}, "M"); err == nil {
		t.Fatal("over-long name accepted")
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.big", Data: make([]byte, wal.MaxXattrValueBytes+1)}, "M"); err == nil {
		t.Fatal("over-size value accepted")
	}
	full := make([]byte, wal.MaxXattrValueBytes)
	if err := fs.MutateAs(wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.fill1", Data: full}, "M"); err != nil {
		t.Fatalf("first 64KiB value: %v", err)
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.fill2", Data: full}, "M"); !errors.Is(err, syscall.ENOSPC) {
		// fill1 + fill2 (+ the small survivors) exceed the 128 KiB per-inode total.
		t.Fatalf("total-bound overflow = %v, want ENOSPC", err)
	}

	// Rename keeps xattrs (ino-keyed); remove destroys them with the inode.
	if err := fs.MutateAs(wal.Record{Op: wal.OpRename, Path: "f", NewPath: "g"}, "M"); err != nil {
		t.Fatal(err)
	}
	if v, err := fs.GetxattrHandle("g", 0, "user.a"); err != nil || string(v) != "v2" {
		t.Fatalf("xattr lost across rename: %q, %v", v, err)
	}
	gIno := func() uint64 {
		fi, err := fs.Lstat("g")
		if err != nil {
			t.Fatal(err)
		}
		return fi.Sys().(interface{ Ino() uint64 }).Ino()
	}()
	if err := fs.MutateAs(wal.Record{Op: wal.OpRemove, Path: "g"}, "M"); err != nil {
		t.Fatal(err)
	}
	if got := fs.XattrsByIno(gIno); got != nil {
		t.Fatalf("destroyed inode kept xattrs: %v", got)
	}
}

// TestXattrLegacyReplayPreservesState proves the WAL replay path: xattr
// records written by one incarnation are reapplied by the next.
func TestXattrLegacyReplayPreservesState(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "wal.log")
	w := openXattrWAL(t, walPath)
	fs, err := New(nil, xattrTestBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644}, "M"); err != nil {
		t.Fatal(err)
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.keep", Data: []byte("v")}, "M"); err != nil {
		t.Fatal(err)
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.drop", Data: []byte("x")}, "M"); err != nil {
		t.Fatal(err)
	}
	if err := fs.MutateAs(wal.Record{Op: wal.OpRemovexattr, Path: "f", XattrName: "user.drop"}, "M"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	w2 := openXattrWAL(t, walPath)
	defer w2.Close()
	fs2, err := New(nil, xattrTestBlobs{}, w2)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if v, err := fs2.GetxattrHandle("f", 0, "user.keep"); err != nil || string(v) != "v" {
		t.Fatalf("replayed getxattr = %q, %v", v, err)
	}
	if names, err := fs2.ListxattrHandle("f", 0); err != nil || strings.Join(names, ",") != "user.keep" {
		t.Fatalf("replayed listxattr = %v, %v", names, err)
	}
}

// TestXattrManagedParityAndFailoverReplay proves the managed generation:
// the same xattr intents apply identically through CommitEntry, and a
// replacement authority cold-replaying the SAME journal reproduces the
// exact xattr state (failover preserves live xattrs).
func TestXattrManagedParityAndFailoverReplay(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, xattrTestBlobs{}, log)
	if err != nil {
		t.Fatal(err)
	}
	commitTree(t, fs, wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644})
	commitTree(t, fs, wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.a", Data: []byte("v1")})
	commitTree(t, fs, wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.b", Data: []byte("vb")})
	commitTree(t, fs, wal.Record{Op: wal.OpSetxattr, Path: "f", XattrName: "user.a", Data: []byte("v2")})
	commitTree(t, fs, wal.Record{Op: wal.OpRemovexattr, Path: "f", XattrName: "user.b"})

	// Deterministic rejections surface as MutationResult statuses through
	// the managed session-store bridge, never authority faults.
	if res, err := fs.managedMutateEnvLikeForTest(wal.Record{Op: wal.OpRemovexattr, Path: "f", XattrName: "user.gone"}); err != nil {
		t.Fatalf("managed remove-missing: %v", err)
	} else if !errors.Is(res, syscall.ENODATA) {
		t.Fatalf("managed remove-missing outcome = %v, want ENODATA", res)
	}

	if v, err := fs.GetxattrHandle("f", 0, "user.a"); err != nil || string(v) != "v2" {
		t.Fatalf("managed getxattr = %q, %v", v, err)
	}
	live := fs.XattrsByIno(lazyLstatIno(t, fs, "f"))

	// Failover: a replacement authority replays the identical journal.
	fs2, err := NewManaged(nil, xattrTestBlobs{}, log)
	if err != nil {
		t.Fatalf("failover replay: %v", err)
	}
	if v, err := fs2.GetxattrHandle("f", 0, "user.a"); err != nil || string(v) != "v2" {
		t.Fatalf("failover getxattr = %q, %v", v, err)
	}
	if names, err := fs2.ListxattrHandle("f", 0); err != nil || strings.Join(names, ",") != "user.a" {
		t.Fatalf("failover listxattr = %v, %v", names, err)
	}
	replayed := fs2.XattrsByIno(lazyLstatIno(t, fs2, "f"))
	if !reflect.DeepEqual(live, replayed) {
		t.Fatalf("failover xattr state diverged:\n live %v\n replay %v", live, replayed)
	}
}

// managedMutateEnvLikeForTest applies one envelope-less record through the
// managed commit path and returns the per-leaf deterministic outcome.
func (fs *FS) managedMutateEnvLikeForTest(r wal.Record) (error, error) {
	out, err := fs.commitEntry(&r, nil, "")
	if err != nil {
		return nil, err
	}
	if len(out.tree) != 1 {
		return nil, errors.New("expected one leaf outcome")
	}
	return out.tree[0].err, nil
}

// TestXattrEngineLiveDifferential folds one record stream through BOTH the
// shared transition engine and the live legacy reducer and asserts the
// resulting per-inode xattr states are byte-identical — the differential
// discipline that keeps HistoryCut materialization honest.
func TestXattrEngineLiveDifferential(t *testing.T) {
	stream := []wal.Record{
		{Op: wal.OpCreate, Path: "a", Mode: 0o644, Ino: 2},
		{Op: wal.OpMkdir, Path: "dir", Mode: 0o755, Inos: []uint64{3}},
		{Op: wal.OpSetxattr, Path: "a", XattrName: "user.one", Data: []byte("1")},
		{Op: wal.OpSetxattr, Path: "dir", XattrName: "user.two", Data: []byte("2")},
		{Op: wal.OpSetxattr, Path: "a", XattrName: "user.one", Data: []byte("1b")}, // overwrite
		{Op: wal.OpRemovexattr, Path: "a", XattrName: "user.gone"},                 // ENODATA phantom
		{Op: wal.OpSetxattr, Path: "a", XattrName: "user.three", Data: nil},        // empty value
		{Op: wal.OpRemovexattr, Path: "dir", XattrName: "user.two"},
		{Op: wal.OpRename, Path: "a", NewPath: "b"},
		{Op: wal.OpSetxattr, Path: "b", XattrName: "user.four", Data: bytes.Repeat([]byte{0xFF}, 10)},
	}

	// Engine side (the HistoryCut materializer's fold).
	ctx := context.Background()
	editor, err := pft2.NewEditor(ctx, nil, nil, pft2.EditorLimits{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := fstransition.New(fstransition.Config{Tx: editor})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range stream {
		outs, err := engine.Apply(ctx, r)
		if err != nil {
			t.Fatalf("engine apply %v %q: %v", r.Op, r.Path, err)
		}
		for _, out := range outs {
			if out.Err != nil && !fstransition.BenignEnvlessOutcome(r.Op, r.TsMs, out.Err) {
				t.Fatalf("engine outcome %v %q: %v", r.Op, r.Path, out.Err)
			}
		}
	}

	// Live legacy side (the authority's reducer).
	w := openXattrWAL(t, filepath.Join(t.TempDir(), "wal.log"))
	defer w.Close()
	fs, err := New(nil, xattrTestBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range stream {
		if err := fs.MutateAs(r, "M"); err != nil && !errors.Is(err, syscall.ENODATA) {
			t.Fatalf("live apply %v %q: %v", r.Op, r.Path, err)
		}
	}

	engineState := map[uint64]map[string][]byte{}
	for _, row := range engine.Xattrs() {
		m := engineState[row.Ino]
		if m == nil {
			m = map[string][]byte{}
			engineState[row.Ino] = m
		}
		m[row.Name] = append([]byte(nil), row.Value...)
	}
	liveState := map[uint64]map[string][]byte{}
	for _, ino := range []uint64{2, 3} {
		if m := fs.XattrsByIno(ino); m != nil {
			liveState[ino] = m
		}
	}
	normalize := func(s map[uint64]map[string][]byte) map[uint64]map[string]string {
		out := map[uint64]map[string]string{}
		for ino, m := range s {
			om := map[string]string{}
			for k, v := range m {
				om[k] = string(v)
			}
			out[ino] = om
		}
		return out
	}
	if !reflect.DeepEqual(normalize(engineState), normalize(liveState)) {
		t.Fatalf("engine and live xattr states diverged:\n engine %v\n live   %v", normalize(engineState), normalize(liveState))
	}
}

// TestXattrAdoptionAndForkRestore is the workfs half of the snapshot
// contract: an anchored base restores the recovery copy on ADOPTION, while a
// FORK reads the user-root copy without touching the source branch's anchor.
func TestXattrAdoptionAndForkRestore(t *testing.T) {
	const namespace = uint32(9)
	base := buildNamespacedBase(t, namespace, []wal.Record{
		{Op: wal.OpCreate, Path: "kept", Mode: 0o644},
	})
	keptIno := uint64(namespace)<<32 | 1
	xattrLeaf := putNode(t, base.store, &pft2.Node{Kind: pft2.KindXattrLeaf, XattrLeaf: &pft2.XattrLeaf{
		Entries: []pft2.XattrEntry{
			{Ino: keptIno, Name: "com.apple.FinderInfo", Value: bytes.Repeat([]byte{0xAB}, 32)},
			{Ino: keptIno, Name: "user.tag", Value: []byte("anchored")},
		},
	}})
	rootFacts := base.facts
	rootFacts.XattrLeaves = []pft2.Ref{xattrLeaf}
	userRoot := putNode(t, base.store, &pft2.Node{Kind: pft2.KindRoot, Root: &rootFacts})
	anchor := putNode(t, base.store, &pft2.Node{Kind: pft2.KindRecoveryRoot, RecoveryRoot: &pft2.RecoveryRoot{
		AsOfSeq:        7,
		FilesystemRoot: userRoot,
		InoNamespace:   namespace,
		NextLocal:      40,
		XattrLeaves:    []pft2.Ref{xattrLeaf},
	}})

	adopted, err := NewManagedFromPft2(context.Background(), Pft2Base{
		Fetcher:             &lazyTestFetcher{inner: base.store},
		Root:                userRoot,
		BaseSeq:             7,
		RootMaxInoSeen:      base.facts.MaxInoSeen,
		RecoveryRoot:        &anchor,
		AnchorAsOfSeq:       7,
		InodeNamespace:      namespace,
		NextLocal:           40,
		AllocatorMaxInoSeen: base.facts.MaxInoSeen,
	}, nil, newFakeEntryLog(), content.NewCache(1<<20))
	if err != nil {
		t.Fatalf("adopted cold start: %v", err)
	}
	if v, err := adopted.GetxattrHandle("kept", 0, "user.tag"); err != nil || string(v) != "anchored" {
		t.Fatalf("adoption lost anchored xattr: %q, %v", v, err)
	}
	if names, err := adopted.ListxattrHandle("kept", 0); err != nil || strings.Join(names, ",") != "com.apple.FinderInfo,user.tag" {
		t.Fatalf("adoption listxattr = %v, %v", names, err)
	}

	// The FORK of the same user root never reads the anchor, but the
	// filesystem-homed attributes are part of that root's closure.
	fork, err := NewManagedFromPft2(context.Background(), Pft2Base{
		Fetcher:             &lazyTestFetcher{inner: base.store},
		Root:                userRoot,
		BaseSeq:             0,
		RootMaxInoSeen:      base.facts.MaxInoSeen,
		InodeNamespace:      namespace + 1,
		NextLocal:           1,
		AllocatorMaxInoSeen: 1,
	}, nil, newFakeEntryLog(), content.NewCache(1<<20))
	if err != nil {
		t.Fatalf("fork cold start: %v", err)
	}
	if names, err := fork.ListxattrHandle("kept", 0); err != nil || strings.Join(names, ",") != "com.apple.FinderInfo,user.tag" {
		t.Fatalf("fork listxattr = %v, %v", names, err)
	}
	if value, err := fork.GetxattrHandle("kept", 0, "user.tag"); err != nil || string(value) != "anchored" {
		t.Fatalf("fork getxattr = %q, %v", value, err)
	}
}
