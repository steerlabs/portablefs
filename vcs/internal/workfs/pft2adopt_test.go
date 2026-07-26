package workfs

// Exact base binding for adopted/conversion/fork PFT2 cold starts: every
// externally proven fact must agree with the hashed objects (ROOT facts,
// RecoveryRoot bindings) and a fork must become WRITABLE under its fresh
// DB-issued allocator namespace even when the reused source root's inode
// high-water sits far beyond the flat 2^32 cap (the P0 fork-writability
// regression).

import (
	"context"
	"strings"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/content"
	"github.com/trendup-ai/portablefs/vcs/internal/fstransition"
	"github.com/trendup-ai/portablefs/vcs/internal/pfc2"
	"github.com/trendup-ai/portablefs/vcs/internal/pft2"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// buildNamespacedBase commits a base whose inode ids compose in the given
// namespace, so root facts carry a high-water far above 2^32 — exactly what
// a production source branch looks like.
func buildNamespacedBase(t *testing.T, namespace uint32, records []wal.Record) *lazyTestBase {
	t.Helper()
	ctx := context.Background()
	store := pft2.NewMemoryStore()
	editor, err := pft2.NewEditor(ctx, nil, nil, pft2.EditorLimits{})
	if err != nil {
		t.Fatal(err)
	}
	local := uint64(1)
	engine, err := fstransition.New(fstransition.Config{
		Tx: editor,
		Alloc: func() (uint64, error) {
			ino, err := pft2.ComposeIno(namespace, local)
			local++
			return ino, err
		},
		FallbackTsMs: lazyTsBase,
	})
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]struct{}{}
	for _, r := range records {
		if _, err := engine.Apply(ctx, r); err != nil {
			t.Fatalf("engine apply %v %q: %v", r.Op, r.Path, err)
		}
		if r.Op == wal.OpCreate || r.Op == wal.OpMkdir || r.Op == wal.OpSymlink {
			paths[r.Path] = struct{}{}
		}
	}
	res, err := editor.Commit(ctx, store, store)
	if err != nil {
		t.Fatal(err)
	}
	sorted := make([]string, 0, len(paths))
	for p := range paths {
		sorted = append(sorted, p)
	}
	return &lazyTestBase{store: store, root: res.Root, facts: res.RootFacts, paths: sorted}
}

// putNode encodes and stores one canonical node, returning its exact ref.
func putNode(t *testing.T, store *pft2.MemoryStore, node *pft2.Node) pft2.Ref {
	t.Helper()
	encoded, err := pft2.EncodeNode(node)
	if err != nil {
		t.Fatalf("encode %v node: %v", node.Kind, err)
	}
	ref := pft2.RefOf(encoded)
	if err := store.PutNode(ref, encoded); err != nil {
		t.Fatal(err)
	}
	return ref
}

// anchorSpec builds a hashed RecoveryRoot (optionally with parked orphans)
// bound to the given filesystem root.
type anchorSpec struct {
	asOfSeq    uint64
	fsRoot     pft2.Ref
	namespace  uint32
	nextLocal  uint64
	orphanInos []uint64
}

func buildAnchor(t *testing.T, store *pft2.MemoryStore, spec anchorSpec) pft2.Ref {
	t.Helper()
	var orphanIndex *pft2.Ref
	if len(spec.orphanInos) > 0 {
		entries := make([]pft2.InodeIndexEntry, 0, len(spec.orphanInos))
		for _, ino := range spec.orphanInos {
			inodeRef := putNode(t, store, &pft2.Node{Kind: pft2.KindInode, Inode: &pft2.Inode{
				Ino: ino, Kind: pft2.FileKindRegular, Mode: 0o600, Nlink: 1,
				MtimeMs: lazyTsBase, CtimeMs: lazyTsBase, AtimeMs: lazyTsBase,
			}})
			entries = append(entries, pft2.InodeIndexEntry{Ino: ino, Inode: inodeRef})
		}
		leaf := putNode(t, store, &pft2.Node{Kind: pft2.KindInodeIndexLeaf,
			InodeIndexLeaf: &pft2.InodeIndexLeaf{Entries: entries}})
		orphanIndex = &leaf
	}
	return putNode(t, store, &pft2.Node{Kind: pft2.KindRecoveryRoot, RecoveryRoot: &pft2.RecoveryRoot{
		AsOfSeq:        spec.asOfSeq,
		FilesystemRoot: spec.fsRoot,
		OrphanIndex:    orphanIndex,
		InoNamespace:   spec.namespace,
		NextLocal:      spec.nextLocal,
	}})
}

func TestForkOfNamespacedRootIsWritable(t *testing.T) {
	const sourceNamespace, forkNamespace = uint32(5), uint32(6)
	base := buildNamespacedBase(t, sourceNamespace, []wal.Record{
		{Op: wal.OpMkdir, Path: "src", Mode: 0o755},
		{Op: wal.OpCreate, Path: "src/data", Mode: 0o644},
		{Op: wal.OpWrite, Path: "src/data", Data: []byte("source-bytes")},
	})
	if base.facts.MaxInoSeen <= 1<<32 {
		t.Fatalf("source root high-water %d does not exceed the flat cap; the scenario is wrong", base.facts.MaxInoSeen)
	}
	log := newFakeEntryLog()
	fs, err := NewManagedFromPft2(context.Background(), Pft2Base{
		Fetcher:             &lazyTestFetcher{inner: base.store},
		Root:                base.root,
		BaseSeq:             0,
		RootMaxInoSeen:      base.facts.MaxInoSeen,
		InodeNamespace:      forkNamespace,
		NextLocal:           1,
		AllocatorMaxInoSeen: 1,
	}, nil, log, content.NewCache(1<<20))
	if err != nil {
		t.Fatalf("fork cold start: %v", err)
	}

	// Fresh controls and no orphans: a fork starts its recovery plane empty.
	control, err := fs.ManagedControl()
	if err != nil {
		t.Fatal(err)
	}
	if entries := control.Project().Entries; len(entries) != 0 {
		t.Fatalf("fork inherited %d control entries", len(entries))
	}
	if sources := fs.LiveOrphanSources(); len(sources) != 0 {
		t.Fatalf("fork inherited %d orphans", len(sources))
	}

	// The P0 regression: the FIRST create must succeed (the flat allocator
	// would report identity exhaustion here) and compose in the fork's
	// fresh namespace at exactly nextLocal.
	commitTree(t, fs, wal.Record{Op: wal.OpCreate, Path: "fresh", Mode: 0o644})
	wantIno := uint64(forkNamespace)<<32 | 1
	if got := lazyLstatIno(t, fs, "fresh"); got != wantIno {
		t.Fatalf("first fork create ino %d, want %d (namespace %d, local 1)", got, wantIno, forkNamespace)
	}
	// Source content still serves lazily under its ORIGINAL namespaced ids.
	if got := lazyReadFile(t, fs, "src/data"); got != "source-bytes" {
		t.Fatalf("fork lost source bytes: %q", got)
	}
	if got := lazyLstatIno(t, fs, "src/data"); got>>32 != uint64(sourceNamespace) {
		t.Fatalf("source inode namespace %d, want %d", got>>32, sourceNamespace)
	}
}

func TestAdoptedBaseBindsAnchorExactly(t *testing.T) {
	const namespace = uint32(9)
	// The parked orphan reuses a burned (created, removed, reaped) identity:
	// inside the root's monotone high-water, named by nothing — exactly how
	// a real anchor's parked ids relate to the filesystem arm. The victim
	// allocates FIRST so the surviving file's id keeps the committed root
	// high-water above the burned one.
	orphanIno := uint64(namespace)<<32 | 1
	base := buildNamespacedBase(t, namespace, []wal.Record{
		{Op: wal.OpCreate, Path: "victim", Mode: 0o644},
		{Op: wal.OpRemove, Path: "victim"},
		{Op: wal.OpReap, Ino: orphanIno},
		{Op: wal.OpCreate, Path: "kept", Mode: 0o644},
	})
	rootMax := base.facts.MaxInoSeen
	if orphanIno > rootMax {
		t.Fatalf("fixture broke its own contract: orphan %d above root high-water %d", orphanIno, rootMax)
	}
	anchor := buildAnchor(t, base.store, anchorSpec{
		asOfSeq: 7, fsRoot: base.root, namespace: namespace, nextLocal: 40,
		orphanInos: []uint64{orphanIno},
	})
	valid := Pft2Base{
		Fetcher:             &lazyTestFetcher{inner: base.store},
		Root:                base.root,
		BaseSeq:             7,
		RootMaxInoSeen:      rootMax,
		RecoveryRoot:        &anchor,
		AnchorAsOfSeq:       7,
		InodeNamespace:      namespace,
		NextLocal:           40,
		AllocatorMaxInoSeen: rootMax,
	}
	fs, err := NewManagedFromPft2(context.Background(), valid, nil, newFakeEntryLog(), content.NewCache(1<<20))
	if err != nil {
		t.Fatalf("valid adopted cold start: %v", err)
	}
	if _, ok := fs.OrphanInfo(orphanIno); !ok {
		t.Fatalf("anchor orphan %d not restored", orphanIno)
	}
	commitTree(t, fs, wal.Record{Op: wal.OpCreate, Path: "next", Mode: 0o644})
	if got, want := lazyLstatIno(t, fs, "next"), uint64(namespace)<<32|40; got != want {
		t.Fatalf("adopted allocation ino %d, want %d (anchor nextLocal must seed)", got, want)
	}

	// A conversion origin (seq-0 base) may carry the source cut's as-of
	// sequence; the hashed/proof agreement still binds it exactly.
	conversion := valid
	conversion.BaseSeq = 0
	if _, err := NewManagedFromPft2(context.Background(), conversion, nil, newFakeEntryLog(), content.NewCache(1<<20)); err != nil {
		t.Fatalf("conversion-shaped cold start: %v", err)
	}

	// Pre-020 provenance rows recorded the branch ALLOCATOR watermark on the
	// user commit arm, which dominates the root's own high-water whenever
	// the cut burned identities. The proof tolerates above (conservative),
	// never below.
	pre020 := valid
	pre020.RootMaxInoSeen = rootMax + 1
	pre020.AllocatorMaxInoSeen = rootMax + 1
	if _, err := NewManagedFromPft2(context.Background(), pre020, nil, newFakeEntryLog(), content.NewCache(1<<20)); err != nil {
		t.Fatalf("pre-020 allocator-watermark proof cold start: %v", err)
	}
}

func TestAdoptedAnchorFloorAndEpochSurviveEmptyControlMap(t *testing.T) {
	// A cut whose reduced control map is EMPTY still anchors the next
	// checkout epoch and the database-time floor on the CONTROL_ROOT node
	// itself. Adoption must resume both — resetting the floor would accept
	// stale minted times; resetting the epoch would reissue retired
	// checkout epochs.
	const namespace = uint32(9)
	const floorMs = uint64(1_702_000_111_222)
	base := buildNamespacedBase(t, namespace, []wal.Record{
		{Op: wal.OpCreate, Path: "kept", Mode: 0o644},
	})
	controlRef := putNode(t, base.store, &pft2.Node{Kind: pft2.KindControlRoot, ControlRoot: &pft2.ControlRoot{
		Schema: pft2.ControlSchemaVersion, NextCheckoutEpoch: 9, DbTimeFloorMs: floorMs,
	}})
	anchor := putNode(t, base.store, &pft2.Node{Kind: pft2.KindRecoveryRoot, RecoveryRoot: &pft2.RecoveryRoot{
		AsOfSeq:        7,
		FilesystemRoot: base.root,
		ControlRoot:    &controlRef,
		InoNamespace:   namespace,
		NextLocal:      40,
	}})
	fs, err := NewManagedFromPft2(context.Background(), Pft2Base{
		Fetcher:             &lazyTestFetcher{inner: base.store},
		Root:                base.root,
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
	control, err := fs.ManagedControl()
	if err != nil {
		t.Fatal(err)
	}
	if got := control.DbTimeFloorMs(); got != int64(floorMs) {
		t.Fatalf("adopted database-time floor %d, want %d", got, floorMs)
	}
	if got := control.NextCheckoutEpoch(); got != pfc2.Epoch("9") {
		t.Fatalf("adopted next checkout epoch %s, want 9", got)
	}
	if entries := control.Project().Entries; len(entries) != 0 {
		t.Fatalf("empty anchor map rebuilt %d entries", len(entries))
	}
}

func TestAdoptedBaseFailsClosedOnEveryBindingMismatch(t *testing.T) {
	const namespace = uint32(9)
	base := buildNamespacedBase(t, namespace, []wal.Record{
		{Op: wal.OpCreate, Path: "kept", Mode: 0o644},
	})
	rootMax := base.facts.MaxInoSeen
	anchor := buildAnchor(t, base.store, anchorSpec{
		asOfSeq: 7, fsRoot: base.root, namespace: namespace, nextLocal: 40,
	})
	valid := Pft2Base{
		Root:                base.root,
		BaseSeq:             7,
		RootMaxInoSeen:      rootMax,
		RecoveryRoot:        &anchor,
		AnchorAsOfSeq:       7,
		InodeNamespace:      namespace,
		NextLocal:           40,
		AllocatorMaxInoSeen: rootMax,
	}

	foreignRoot := putNode(t, base.store, &pft2.Node{Kind: pft2.KindInode, Inode: &pft2.Inode{
		Ino: 1, Kind: pft2.FileKindDirectory, Mode: 0o755, Nlink: 1,
		MtimeMs: lazyTsBase, CtimeMs: lazyTsBase, AtimeMs: lazyTsBase,
	}})
	mismatchedRootAnchor := buildAnchor(t, base.store, anchorSpec{
		asOfSeq: 7, fsRoot: foreignRoot, namespace: namespace, nextLocal: 40,
	})
	wrongSeqAnchor := buildAnchor(t, base.store, anchorSpec{
		asOfSeq: 6, fsRoot: base.root, namespace: namespace, nextLocal: 40,
	})
	wrongAllocAnchor := buildAnchor(t, base.store, anchorSpec{
		asOfSeq: 7, fsRoot: base.root, namespace: namespace, nextLocal: 41,
	})
	highOrphanAnchor := buildAnchor(t, base.store, anchorSpec{
		asOfSeq: 7, fsRoot: base.root, namespace: namespace, nextLocal: 40,
		orphanInos: []uint64{rootMax + 1},
	})

	cases := []struct {
		name    string
		mutate  func(*Pft2Base)
		errPart string
	}{
		{"too-low proven root high-water", func(b *Pft2Base) { b.RootMaxInoSeen = rootMax - 1 }, "below the hashed ROOT"},
		{"anchor binds a different filesystem root", func(b *Pft2Base) { b.RecoveryRoot = &mismatchedRootAnchor }, "binds filesystem root"},
		{"hashed as-of disagrees with the proof", func(b *Pft2Base) { b.RecoveryRoot = &wrongSeqAnchor }, "as-of"},
		{"adopted as-of disagrees with the base sequence", func(b *Pft2Base) { b.AnchorAsOfSeq = 6 }, "does not equal base sequence"},
		{"hashed allocator disagrees with the proof", func(b *Pft2Base) { b.RecoveryRoot = &wrongAllocAnchor }, "recovery allocator"},
		{"proof namespace disagrees with the object", func(b *Pft2Base) { b.InodeNamespace = namespace + 1 }, "recovery allocator"},
		{"orphan above the authenticated high-water", func(b *Pft2Base) { b.RecoveryRoot = &highOrphanAnchor }, "exceeds the authenticated high-water"},
		{"anchor allocator below the root high-water", func(b *Pft2Base) { b.AllocatorMaxInoSeen = rootMax - 1 }, "below the root high-water"},
		{"missing namespace", func(b *Pft2Base) { b.InodeNamespace = 0 }, "proven inode namespace"},
		{"zero next local", func(b *Pft2Base) { b.NextLocal = 0 }, "next-local"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := valid
			mutated.Fetcher = &lazyTestFetcher{inner: base.store}
			tc.mutate(&mutated)
			_, err := NewManagedFromPft2(context.Background(), mutated, nil, newFakeEntryLog(), content.NewCache(1<<20))
			if err == nil {
				t.Fatal("mismatched base accepted")
			}
			if !strings.Contains(err.Error(), tc.errPart) {
				t.Fatalf("mismatch classified wrongly: %v (want %q)", err, tc.errPart)
			}
		})
	}

	t.Run("fork with nonzero base sequence", func(t *testing.T) {
		mutated := valid
		mutated.Fetcher = &lazyTestFetcher{inner: base.store}
		mutated.RecoveryRoot = nil
		mutated.AnchorAsOfSeq = 0
		mutated.AllocatorMaxInoSeen = 1
		if _, err := NewManagedFromPft2(context.Background(), mutated, nil, newFakeEntryLog(), content.NewCache(1<<20)); err == nil ||
			!strings.Contains(err.Error(), "nonzero base sequence") {
			t.Fatalf("fork-shaped base with seq 7 accepted: %v", err)
		}
	})

	t.Run("corrupt anchor bytes fail closed", func(t *testing.T) {
		mutated := valid
		fetcher := &lazyTestFetcher{inner: base.store}
		fetcher.setCorrupt(true)
		mutated.Fetcher = fetcher
		if _, err := NewManagedFromPft2(context.Background(), mutated, nil, newFakeEntryLog(), content.NewCache(1<<20)); err == nil {
			t.Fatal("corrupt objects accepted")
		}
	})
}

func TestForkColdStartValidatesRootFacts(t *testing.T) {
	base := buildNamespacedBase(t, 5, []wal.Record{
		{Op: wal.OpCreate, Path: "a", Mode: 0o644},
	})
	fetcher := &lazyTestFetcher{inner: base.store}
	shape := forkPft2Base(base, fetcher)
	shape.RootMaxInoSeen = base.facts.MaxInoSeen - 1 // too-low proof
	_, err := NewManagedFromPft2(context.Background(), shape, nil, newFakeEntryLog(), content.NewCache(1<<20))
	if err == nil || !strings.Contains(err.Error(), "below the hashed ROOT") {
		t.Fatalf("too-low fork root proof accepted: %v", err)
	}
}
