package historycut

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/treehash"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// ─── fakes ───────────────────────────────────────────────────────────────────

type fakeJournal struct {
	records []PageRecord
}

func (f *fakeJournal) ReadPage(_ context.Context, fromSeq uint64, maxRecords int, _ int64) ([]PageRecord, error) {
	var out []PageRecord
	for _, r := range f.records {
		if r.Seq >= fromSeq && len(out) < maxRecords {
			out = append(out, r)
		}
	}
	return out, nil
}

// buildJournal chains encoded payloads from a base digest.
func buildJournal(t *testing.T, baseDigest [32]byte, baseSeq uint64, payloads [][]byte) ([]PageRecord, string) {
	t.Helper()
	chain := baseDigest
	var out []PageRecord
	for i, payload := range payloads {
		chain = ChainStep(chain, payload)
		out = append(out, PageRecord{
			Seq:         baseSeq + uint64(i),
			Payload:     payload,
			RecordHash:  hexDigest(RecordHash(payload)),
			ChainDigest: hexDigest(chain),
		})
	}
	return out, hexDigest(chain)
}

type fakeLegacy struct {
	entries      []LegacyEntry
	cursor       json.RawMessage
	verifiedHash string
	wantHash     string
	cursorPuts   int
}

func (f *fakeLegacy) EntriesPage(_ context.Context, afterOrd int64, limit int) ([]LegacyEntry, error) {
	var out []LegacyEntry
	for _, e := range f.entries {
		if e.Ord > afterOrd && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeLegacy) ImportCursor(_ context.Context) (json.RawMessage, error) { return f.cursor, nil }

func (f *fakeLegacy) PutImportCursor(_ context.Context, cursor json.RawMessage) error {
	f.cursor = append(json.RawMessage(nil), cursor...)
	f.cursorPuts++
	return nil
}

func (f *fakeLegacy) VerifyTreeHash(_ context.Context, treeHash string) error {
	f.verifiedHash = treeHash
	if f.wantHash != "" && treeHash != f.wantHash {
		return corruptf("tree hash mismatch: %s want %s", treeHash, f.wantHash)
	}
	return nil
}

type fakeBlobs struct {
	blobs map[string][]byte
}

func (f *fakeBlobs) Blob(_ context.Context, digest string, _ int64) ([]byte, error) {
	data, ok := f.blobs[digest]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNeedBlobs, digest)
	}
	return data, nil
}

func sha256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hexDigest(sum)
}

func containsDigest(list []string, digest string) bool {
	for _, d := range list {
		if d == digest {
			return true
		}
	}
	return false
}

// ─── managed journal cuts ────────────────────────────────────────────────────

func managedFacts(baseDigest, cutDigest string, baseSeq, cutSeq uint64) CutFacts {
	return CutFacts{
		CutID: "hcut_test", Kind: "user", SourceKind: "managed_journal",
		GenerationID: "gen_1", RecordCodec: "pfj3", ControlCodec: "pfc2",
		SourceBaseSeq: strconv.FormatUint(baseSeq, 10), SourceBaseDig: baseDigest,
		CutSeqExclusive: strconv.FormatUint(cutSeq, 10), CutDigest: cutDigest,
		InodeNamespace: "7", NamespaceNext: "1",
	}
}

func encodeEntries(t *testing.T, seqStart uint64, records ...wal.Record) [][]byte {
	t.Helper()
	var payloads [][]byte
	for i, r := range records {
		r.Seq = seqStart + uint64(i)
		entry := pfj3.JournalEntry{LSN: r.Seq, Tree: &r}
		payload, err := pfj3.Encode(&entry)
		if err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, payload)
	}
	return payloads
}

func TestManagedCutFromEmptyBase(t *testing.T) {
	var zero [32]byte
	payloads := encodeEntries(t, 0,
		wal.Record{Op: wal.OpMkdir, Path: "docs", Mode: 0o755, Inos: []uint64{0x700000002}, TsMs: 111},
		wal.Record{Op: wal.OpCreate, Path: "docs/readme.txt", Mode: 0o644, Ino: 0x700000003, TsMs: 222},
		wal.Record{Op: wal.OpWrite, Path: "docs/readme.txt", Data: bytes.Repeat([]byte("hello "), 2000), TsMs: 333},
		wal.Record{Op: wal.OpRemove, Path: "docs/readme.txt", TsMs: 444},
		wal.Record{Op: wal.OpCreate, Path: "docs/kept.txt", Mode: 0o600, Ino: 0x700000004, TsMs: 555},
	)
	records, cutDigest := buildJournal(t, zero, 0, payloads)
	m := &Materializer{
		Facts:   managedFacts(hexDigest(zero), cutDigest, 0, uint64(len(records))),
		Journal: &fakeJournal{records: records},
		Spool:   NewSpool(),
	}
	res, err := m.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.OrphanIndex == nil {
		t.Fatal("unreaped orphan must persist an orphan index")
	}
	if res.MaxInoSeen < 0x700000004 {
		t.Fatalf("MaxInoSeen = %#x", res.MaxInoSeen)
	}
	if res.UserObjectCount != uint64(len(res.UserClosure)) || res.UserObjectCount == 0 {
		t.Fatalf("user closure accounting: count=%d closure=%d", res.UserObjectCount, len(res.UserClosure))
	}
	if res.RecoveryObjectCount != uint64(len(res.RecoveryClosure)) || res.RecoveryObjectCount == 0 {
		t.Fatalf("recovery closure accounting: count=%d closure=%d",
			res.RecoveryObjectCount, len(res.RecoveryClosure))
	}
	// Each root sits in ITS OWN closure; the recovery-only closure never
	// contains user objects and vice versa (distinct roots).
	rootDigest := "sha256:" + res.Root.Hex()
	recoveryDigest := "sha256:" + res.RecoveryRoot.Hex()
	if !containsDigest(res.UserClosure, rootDigest) {
		t.Fatal("user closure misses the user root")
	}
	if containsDigest(res.UserClosure, recoveryDigest) {
		t.Fatal("user closure reaches the recovery root")
	}
	if !containsDigest(res.RecoveryClosure, recoveryDigest) {
		t.Fatal("recovery closure misses the recovery root")
	}
	if containsDigest(res.RecoveryClosure, rootDigest) {
		t.Fatal("recovery-only closure re-lists the user root")
	}
	for _, d := range res.RecoveryClosure {
		if containsDigest(res.UserClosure, d) {
			t.Fatalf("closures overlap at %s", d)
		}
	}
	// Verify tree content through the strict reader.
	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: m.Spool}, res.Root)
	if err != nil {
		t.Fatal(err)
	}
	rootView, err := reader.GetInode(context.Background(), pft2.RootIno)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := reader.Lookup(context.Background(), rootView.Ref, "docs")
	if err != nil || docs.Ino != 0x700000002 {
		t.Fatalf("docs = %+v err=%v", docs, err)
	}
	docsView, err := reader.GetInode(context.Background(), docs.Ino)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Lookup(context.Background(), docsView.Ref, "readme.txt"); !errors.Is(err, pft2.ErrNotFound) {
		t.Fatalf("removed name still resolves: %v", err)
	}
	kept, err := reader.Lookup(context.Background(), docsView.Ref, "kept.txt")
	if err != nil || kept.Ino != 0x700000004 {
		t.Fatalf("kept = %+v err=%v", kept, err)
	}

	// Determinism: a fresh rerun over the same inputs emits identical roots.
	m2 := &Materializer{
		Facts:   m.Facts,
		Journal: &fakeJournal{records: records},
		Spool:   NewSpool(),
	}
	res2, err := m2.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res2.Root != res.Root || res2.RecoveryRoot != res.RecoveryRoot {
		t.Fatal("rerun produced different roots")
	}
}

func TestManagedCutRejectsChainAndHashLies(t *testing.T) {
	var zero [32]byte
	payloads := encodeEntries(t, 0,
		wal.Record{Op: wal.OpCreate, Path: "f", Mode: 0o644, Ino: 0x700000002, TsMs: 1},
		wal.Record{Op: wal.OpWrite, Path: "f", Data: []byte("x"), TsMs: 2},
	)
	records, cutDigest := buildJournal(t, zero, 0, payloads)

	run := func(mutate func([]PageRecord) []PageRecord, wantCut string) error {
		rows := append([]PageRecord(nil), records...)
		rows = mutate(rows)
		m := &Materializer{
			Facts:   managedFacts(hexDigest(zero), wantCut, 0, uint64(len(rows))),
			Journal: &fakeJournal{records: rows},
			Spool:   NewSpool(),
		}
		_, err := m.Run(context.Background())
		return err
	}

	if err := run(func(r []PageRecord) []PageRecord { return r }, cutDigest); err != nil {
		t.Fatalf("healthy journal failed: %v", err)
	}
	// Tampered payload: record hash catches it.
	if err := run(func(r []PageRecord) []PageRecord {
		r[1].Payload = append([]byte(nil), r[1].Payload...)
		r[1].Payload[len(r[1].Payload)-1] ^= 1
		return r
	}, cutDigest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered payload: %v", err)
	}
	// Lying chain digest.
	if err := run(func(r []PageRecord) []PageRecord {
		r[1].ChainDigest = hexDigest([32]byte{1})
		return r
	}, cutDigest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("lying chain: %v", err)
	}
	// A gap (missing seq 0).
	if err := run(func(r []PageRecord) []PageRecord { return r[1:] }, cutDigest); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("gap: %v", err)
	}
	// The frozen cut digest itself disagrees with the folded chain.
	if err := run(func(r []PageRecord) []PageRecord { return r }, hexDigest([32]byte{2})); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("cut digest mismatch: %v", err)
	}
}

// ─── legacy conversion ───────────────────────────────────────────────────────

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// legacyFixture builds the resolved+assigned entry stream, the blob store,
// and the expected canonical tree hash for a representative volume: nested
// dirs, a plain file, a gzip-compressed blob, a chunked file, a symlink,
// hardlink aliases, and a synthesized parent.
func legacyFixture(t *testing.T) ([]LegacyEntry, *fakeBlobs, string) {
	t.Helper()
	plain := bytes.Repeat([]byte("plain-data!"), 900)
	gzPlain := []byte("compressed contents, exactly")
	chunkA := bytes.Repeat([]byte{0xAA}, 4096)
	chunkB := bytes.Repeat([]byte{0xBB}, 3000)
	full := append(append([]byte{}, chunkA...), chunkB...)
	shared := []byte("hardlinked bytes")

	blobs := &fakeBlobs{blobs: map[string][]byte{
		sha256Digest(plain):                 plain,
		sha256Digest(gzipBytes(t, gzPlain)): gzipBytes(t, gzPlain),
		sha256Digest(chunkA):                chunkA,
		sha256Digest(chunkB):                chunkB,
		sha256Digest(shared):                shared,
	}}

	chunksJSON, _ := json.Marshal([]chunkRef{
		{Digest: sha256Digest(chunkA), Size: int64(len(chunkA)), Offset: 0},
		{Digest: sha256Digest(chunkB), Size: int64(len(chunkB)), Offset: int64(len(chunkA))},
	})

	// Ordinals are PATH-SORTED (the database assigns them that way), so a
	// parent always precedes its children — synthesized ancestors included.
	ns := uint64(9) << 32
	entries := []LegacyEntry{
		{Ord: 0, Path: "docs", Kind: "directory", Mode: 0o755, AssignedIno: ns + 1, MtimeMs: 10, CtimeMs: 10, AtimeMs: 10},
		{Ord: 1, Path: "docs/plain.bin", Kind: "file", Mode: 0o644, Size: uint64(len(plain)),
			BlobDigest: sha256Digest(plain), BlobSize: int64(len(plain)), Compression: "none",
			AssignedIno: ns + 2, MtimeMs: 20, CtimeMs: 20, AtimeMs: 20},
		{Ord: 2, Path: "docs/zipped.txt", Kind: "file", Mode: 0o640, Size: uint64(len(gzPlain)),
			BlobDigest: sha256Digest(gzipBytes(t, gzPlain)), BlobSize: int64(len(gzipBytes(t, gzPlain))),
			Compression: "gzip", AssignedIno: ns + 3, MtimeMs: 30, CtimeMs: 30, AtimeMs: 30, UID: 5, GID: 6},
		{Ord: 3, Path: "huge", Kind: "file", Mode: 0o600, Size: uint64(len(full)),
			BlobDigest: sha256Digest(full), BlobSize: int64(len(full)), Compression: "none",
			ChunksJSON: chunksJSON, AssignedIno: ns + 4, MtimeMs: 40, CtimeMs: 40, AtimeMs: 40},
		{Ord: 4, Path: "link", Kind: "symlink", Mode: 0o777, Size: uint64(len("docs/plain.bin")),
			LinkTarget: "docs/plain.bin", AssignedIno: ns + 5, MtimeMs: 50, CtimeMs: 50, AtimeMs: 50},
		// Hardlink pair: same legacy ino 42 preserved, nlink 2.
		{Ord: 5, Path: "one", Kind: "file", Mode: 0o644, Size: uint64(len(shared)),
			BlobDigest: sha256Digest(shared), BlobSize: int64(len(shared)), Compression: "none",
			AssignedIno: 42, Nlink: 2, MtimeMs: 60, CtimeMs: 60, AtimeMs: 60},
		// The synthesized ancestor precedes its child (path order).
		{Ord: 6, Path: "synth", Kind: "directory", Mode: 0o755, AssignedIno: ns + 7, Synthetic: true},
		{Ord: 7, Path: "synth/child.txt", Kind: "file", Mode: 0o644, Size: uint64(len(plain)),
			BlobDigest: sha256Digest(plain), BlobSize: int64(len(plain)), Compression: "none",
			AssignedIno: ns + 6, MtimeMs: 70, CtimeMs: 70, AtimeMs: 70},
		{Ord: 8, Path: "two", Kind: "file", Mode: 0o644, Size: uint64(len(shared)),
			BlobDigest: sha256Digest(shared), BlobSize: int64(len(shared)), Compression: "none",
			AssignedIno: 42, Nlink: 2, MtimeMs: 60, CtimeMs: 60, AtimeMs: 60},
	}

	var hashEntries []treehash.Entry
	for i := range entries {
		if entries[i].Synthetic {
			continue
		}
		hashEntries = append(hashEntries, hashEntryOf(&entries[i]))
	}
	return entries, blobs, treehash.Compute(hashEntries)
}

func conversionFacts() CutFacts {
	return CutFacts{
		CutID: "hcut_conv", Kind: "conversion_final", SourceKind: "legacy_manifest",
		InodeNamespace: "9", NamespaceNext: "8",
	}
}

func TestLegacyConversionFullFidelity(t *testing.T) {
	entries, blobs, wantHash := legacyFixture(t)
	legacy := &fakeLegacy{entries: entries, wantHash: wantHash}
	m := &Materializer{Facts: conversionFacts(), Legacy: legacy, Blobs: blobs, Spool: NewSpool()}
	res, err := m.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if legacy.verifiedHash != wantHash {
		t.Fatalf("verified hash %s, want %s", legacy.verifiedHash, wantHash)
	}
	if res.OrphanIndex != nil {
		t.Fatal("a fresh conversion has no orphans")
	}
	// A newly materialized anchor ALWAYS carries a ControlRoot, even with no
	// control history: the canonical fresh state (empty map, first checkout
	// epoch, zero database-time floor) is anchored explicitly so epochs and
	// the floor can never silently reset across later cuts.
	if res.ControlRoot == nil {
		t.Fatal("a materialized anchor must always carry a control root")
	}
	rawControl, ok := m.Spool.(*Spool).Bytes(*res.ControlRoot)
	if !ok {
		t.Fatal("control root bytes missing from the spool")
	}
	controlNode, err := pft2.DecodeNodeKind(rawControl, pft2.KindControlRoot)
	if err != nil {
		t.Fatal(err)
	}
	cr := controlNode.ControlRoot
	if cr.MapRoot != nil || cr.NextCheckoutEpoch != 1 || cr.DbTimeFloorMs != 0 {
		t.Fatalf("fresh conversion control root = %+v, want empty map, epoch 1, floor 0", cr)
	}

	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: m.Spool}, res.Root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	lookup := func(path string) pft2.InodeView {
		t.Helper()
		view, err := reader.GetInode(ctx, pft2.RootIno)
		if err != nil {
			t.Fatal(err)
		}
		cur := view
		for _, part := range bytes.Split([]byte(path), []byte("/")) {
			entry, err := reader.Lookup(ctx, cur.Ref, string(part))
			if err != nil {
				t.Fatalf("lookup %q in %q: %v", part, path, err)
			}
			cur, err = reader.GetInode(ctx, entry.Ino)
			if err != nil {
				t.Fatal(err)
			}
		}
		return cur
	}
	readAll := func(view pft2.InodeView) []byte {
		t.Helper()
		out := make([]byte, view.Inode.Size)
		if view.Inode.ExtentRoot == nil {
			return out
		}
		extents, err := reader.ReadExtents(ctx, view.Ref, 0, view.Inode.Size)
		if err != nil {
			t.Fatal(err)
		}
		for _, ext := range extents {
			raw, err := m.Spool.Fetch(ctx, ext.Cell.Object)
			if err != nil {
				t.Fatal(err)
			}
			cell := raw[ext.Cell.ObjectOffset : ext.Cell.ObjectOffset+pft2.CellBytes]
			copy(out[ext.FileOffset:ext.FileOffset+ext.Length], cell[:ext.Length])
		}
		return out
	}

	plainView := lookup("docs/plain.bin")
	if got := readAll(plainView); !bytes.Equal(got, bytes.Repeat([]byte("plain-data!"), 900)) {
		t.Fatalf("plain content mismatch (%d bytes)", len(got))
	}
	zipped := lookup("docs/zipped.txt")
	if got := readAll(zipped); string(got) != "compressed contents, exactly" {
		t.Fatalf("gzip content = %q", got)
	}
	if zipped.Inode.UID != 5 || zipped.Inode.GID != 6 || zipped.Inode.Mode != 0o640 {
		t.Fatalf("zipped metadata: %+v", zipped.Inode)
	}
	if zipped.Inode.MtimeMs != 30 || zipped.Inode.CtimeMs != 30 || zipped.Inode.AtimeMs != 30 {
		t.Fatalf("zipped times: %+v", zipped.Inode)
	}
	huge := lookup("huge")
	wantFull := append(append([]byte{}, bytes.Repeat([]byte{0xAA}, 4096)...), bytes.Repeat([]byte{0xBB}, 3000)...)
	if got := readAll(huge); !bytes.Equal(got, wantFull) {
		t.Fatalf("chunked content mismatch (%d bytes)", len(got))
	}
	link := lookup("link")
	if link.Inode.Kind != pft2.FileKindSymlink || link.Inode.SymlinkTarget != "docs/plain.bin" {
		t.Fatalf("symlink: %+v", link.Inode)
	}
	one, two := lookup("one"), lookup("two")
	if one.Inode.Ino != 42 || two.Inode.Ino != 42 || one.Inode.Nlink != 2 {
		t.Fatalf("hardlinks: one=%+v two=%+v", one.Inode, two.Inode)
	}
	if got := readAll(one); string(got) != "hardlinked bytes" {
		t.Fatalf("hardlink content = %q", got)
	}
	synth := lookup("synth")
	if synth.Inode.Kind != pft2.FileKindDirectory || synth.Inode.Mode != 0o755 {
		t.Fatalf("synthetic parent: %+v", synth.Inode)
	}
	if res.MaxInoSeen < (uint64(9)<<32)+7 {
		t.Fatalf("MaxInoSeen = %#x", res.MaxInoSeen)
	}

	// Deterministic rerun from scratch: identical roots and closure.
	legacy2 := &fakeLegacy{entries: entries, wantHash: wantHash}
	m2 := &Materializer{Facts: conversionFacts(), Legacy: legacy2, Blobs: blobs, Spool: NewSpool()}
	res2, err := m2.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res2.Root != res.Root || res2.RecoveryRoot != res.RecoveryRoot {
		t.Fatal("conversion rerun produced different roots")
	}
	// Crash/resume: rerun with the FINAL persisted cursor over the same
	// spool replays the (already applied) tail idempotently.
	m3 := &Materializer{Facts: conversionFacts(), Legacy: legacy, Blobs: blobs, Spool: m.Spool}
	res3, err := m3.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res3.Root != res.Root {
		t.Fatal("cursor resume produced a different root")
	}
}

func TestLegacyConversionRejectsContentLies(t *testing.T) {
	base, blobs, wantHash := legacyFixture(t)

	run := func(mutate func([]LegacyEntry) []LegacyEntry, b *fakeBlobs, hash string) error {
		entries := append([]LegacyEntry(nil), base...)
		entries = mutate(entries)
		legacy := &fakeLegacy{entries: entries, wantHash: hash}
		m := &Materializer{Facts: conversionFacts(), Legacy: legacy, Blobs: b, Spool: NewSpool()}
		_, err := m.Run(context.Background())
		return err
	}

	// A size lie on a whole blob.
	if err := run(func(e []LegacyEntry) []LegacyEntry {
		e[1].Size = e[1].Size + 1
		return e
	}, blobs, ""); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("size lie: %v", err)
	}
	// Wrong stored bytes for a declared digest.
	badBlobs := &fakeBlobs{blobs: map[string][]byte{}}
	for k, v := range blobs.blobs {
		badBlobs.blobs[k] = v
	}
	badBlobs.blobs[base[1].BlobDigest] = []byte("not the declared bytes")
	if err := run(func(e []LegacyEntry) []LegacyEntry { return e }, badBlobs, ""); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("blob bytes lie: %v", err)
	}
	// Tree hash mismatch (an entry mutated after resolution).
	if err := run(func(e []LegacyEntry) []LegacyEntry {
		e[1].Mode = 0o777
		return e
	}, blobs, wantHash); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tree hash mismatch: %v", err)
	}
	// A directory hardlink alias is refused (the synth dir at index 6
	// re-uses the docs directory inode).
	if err := run(func(e []LegacyEntry) []LegacyEntry {
		e[6].Synthetic = false
		e[6].AssignedIno = e[0].AssignedIno
		return e
	}, blobs, ""); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("directory alias: %v", err)
	}
	// Missing blob content pauses with ErrNeedBlobs (not corruption).
	empty := &fakeBlobs{blobs: map[string][]byte{}}
	if err := run(func(e []LegacyEntry) []LegacyEntry { return e }, empty, ""); !errors.Is(err, ErrNeedBlobs) {
		t.Fatalf("missing blobs: %v", err)
	}
}

// ─── pfr1 conversion drain (manifest base + journal fold) ────────────────────

func TestConversionDrainManifestBasePlusPfr1(t *testing.T) {
	entries, blobs, wantHash := legacyFixture(t)
	legacy := &fakeLegacy{entries: entries, wantHash: wantHash}

	var zero [32]byte
	var payloads [][]byte
	for i, rec := range []wal.Record{
		{Op: wal.OpCreate, Path: "docs/drained.txt", Mode: 0o644, Ino: uint64(9)<<32 + 100, TsMs: 900},
		{Op: wal.OpWrite, Path: "docs/drained.txt", Data: []byte("written after the base"), TsMs: 901},
		{Op: wal.OpRemove, Path: "two", TsMs: 902},
	} {
		rec.Seq = uint64(i)
		payload, err := wal.EncodePFR1(&rec)
		if err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, payload)
	}
	records, cutDigest := buildJournal(t, zero, 0, payloads)

	facts := CutFacts{
		CutID: "hcut_drain", Kind: "conversion_final", SourceKind: "managed_journal",
		GenerationID: "gen_legacy", RecordCodec: "pfr1", ControlCodec: "pfc1",
		SourceBaseSeq: "0", SourceBaseDig: hexDigest(zero),
		CutSeqExclusive: strconv.Itoa(len(records)), CutDigest: cutDigest,
		InodeNamespace: "9", NamespaceNext: "8",
	}
	facts.BaseCommit = &BaseCommitFacts{
		CommitID: "c_base", CommitKind: "manifest_v1", BaseMode: "conversion", TreeHash: wantHash,
	}

	m := &Materializer{
		Facts:   facts,
		Journal: &fakeJournal{records: records},
		Legacy:  legacy,
		Blobs:   blobs,
		Spool:   NewSpool(),
	}
	res, err := m.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: m.Spool}, res.Root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rootView, err := reader.GetInode(ctx, pft2.RootIno)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := reader.Lookup(ctx, rootView.Ref, "docs")
	if err != nil {
		t.Fatal(err)
	}
	docsView, err := reader.GetInode(ctx, docs.Ino)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Lookup(ctx, docsView.Ref, "drained.txt"); err != nil {
		t.Fatalf("journal-drained file missing: %v", err)
	}
	if _, err := reader.Lookup(ctx, rootView.Ref, "two"); !errors.Is(err, pft2.ErrNotFound) {
		t.Fatalf("removed alias still resolves: %v", err)
	}
	// The unlinked alias dropped one name; ino 42 keeps the other.
	one, err := reader.Lookup(ctx, rootView.Ref, "one")
	if err != nil || one.Ino != 42 {
		t.Fatalf("one = %+v err=%v", one, err)
	}
	oneView, err := reader.GetInode(ctx, one.Ino)
	if err != nil {
		t.Fatal(err)
	}
	if oneView.Inode.Nlink != 1 {
		t.Fatalf("alias unlink left nlink %d, want 1", oneView.Inode.Nlink)
	}
}
