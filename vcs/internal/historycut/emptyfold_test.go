package historycut

// A cut whose record range mutates no tree at all — pure PFC2 control traffic
// over a base that has no user filesystem root — reduces to the EMPTY
// filesystem. That is a first-class reduction outcome, not a corruption: the
// fold materializes the canonical empty root and anchors the folded control
// state, checkout epoch, database-time floor, allocator watermarks, and empty
// orphan index over it exactly as a non-empty fold would.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/treehash"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

const controlBaseDbMs = int64(1_700_000_000_000)

// ─── fold fixtures ───────────────────────────────────────────────────────────

const foldTestNamespace = uint64(7) << 32

func foldIno(i int) uint64 { return foldTestNamespace + uint64(i) + 2 }

// createOnlyRecords creates `files` empty files in one directory: no content,
// no removes, nothing that would charge a traversal or staged-cell bound
// against an EMPTY base. Every record's only cost is new objects at commit.
func createOnlyRecords(files int) []wal.Record {
	out := make([]wal.Record, 0, files+1)
	out = append(out, wal.Record{
		Op: wal.OpMkdir, Path: "tree", Mode: 0o755, Excl: true, Ino: foldIno(0), TsMs: 100,
	})
	for f := 0; f < files; f++ {
		out = append(out, wal.Record{
			Op: wal.OpCreate, Path: "tree/n" + strconv.Itoa(f), Mode: 0o644,
			Ino: foldIno(f + 1), TsMs: int64(200 + f),
		})
	}
	return out
}

func foldFixture(t *testing.T, records []wal.Record) ([]PageRecord, CutFacts) {
	t.Helper()
	var zero [32]byte
	payloads := encodeEntries(t, 0, records...)
	page, cutDigest := buildJournal(t, zero, 0, payloads)
	return page, managedFacts(hexDigest(zero), cutDigest, 0, uint64(len(page)))
}

func runFold(t *testing.T, page []PageRecord, facts CutFacts, limits pft2.EditorLimits) (*Materializer, *Result) {
	t.Helper()
	m := &Materializer{
		Facts:   facts,
		Journal: &fakeJournal{records: page},
		Spool:   NewSpool(),
		Limits:  limits,
	}
	res, err := m.Run(context.Background())
	if err != nil {
		t.Fatalf("fold failed: %v", err)
	}
	return m, res
}

// dumpTree serializes the complete user-visible filesystem: every path with
// its metadata and content digest, read back through the STRICT reader.
func dumpTree(t *testing.T, m *Materializer, root pft2.Ref) []string {
	t.Helper()
	ctx := context.Background()
	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: m.Spool}, root)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func(path string, view pft2.InodeView)
	walk = func(path string, view pft2.InodeView) {
		in := view.Inode
		line := fmt.Sprintf("%s ino=%d kind=%s mode=%o uid=%d gid=%d nlink=%d size=%d mtime=%d ctime=%d target=%q",
			path, in.Ino, in.Kind, in.Mode, in.UID, in.GID, in.Nlink, in.Size,
			in.MtimeMs, in.CtimeMs, in.SymlinkTarget)
		if in.Kind == pft2.FileKindRegular && in.Size > 0 {
			content := make([]byte, in.Size)
			extents, err := reader.ReadExtents(ctx, view.Ref, 0, in.Size)
			if err != nil {
				t.Fatal(err)
			}
			for _, ext := range extents {
				raw, err := m.Spool.Fetch(ctx, ext.Cell.Object)
				if err != nil {
					t.Fatal(err)
				}
				cell := raw[ext.Cell.ObjectOffset : ext.Cell.ObjectOffset+pft2.CellBytes]
				copy(content[ext.FileOffset:ext.FileOffset+ext.Length], cell[:ext.Length])
			}
			line += fmt.Sprintf(" content=%x", sha256.Sum256(content))
		}
		out = append(out, line)
		if in.Kind != pft2.FileKindDirectory {
			return
		}
		cursor := ""
		for {
			entries, next, err := reader.ReadDir(ctx, view.Ref, cursor, 256)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				child, err := reader.GetInode(ctx, entry.Ino)
				if err != nil {
					t.Fatal(err)
				}
				walk(path+"/"+entry.Name, child)
			}
			if next == "" {
				break
			}
			cursor = next
		}
	}
	rootView, err := reader.GetInode(ctx, pft2.RootIno)
	if err != nil {
		t.Fatal(err)
	}
	walk("", rootView)
	sort.Strings(out)
	return out
}

// ─── control-only payloads ───────────────────────────────────────────────────

// controlOnlyPayloads encodes journal entries that carry ONLY control state:
// one session open each, no tree intent anywhere. Session times start at
// dbBase, which must dominate the base anchor's database-time floor.
func controlOnlyPayloads(t *testing.T, seqStart uint64, count int, tag string, dbBase int64) [][]byte {
	t.Helper()
	var token [pfc2.TokenHashBytes]byte
	token[0] = 0xAB
	var payloads [][]byte
	for i := 0; i < count; i++ {
		var factID [16]byte
		factID[0], factID[1] = byte(len(tag)), byte(i+1)
		dbMs := dbBase + int64(seqStart) + int64(i)
		record := pfc2.Record{Kind: pfc2.KindSessionOpen, SessionOpen: &pfc2.SessionOpen{
			Session:   pfc2.SessionRef{SessionID: "pfs-" + tag + strconv.Itoa(i), Generation: 1},
			Owner:     "host-a",
			TokenHash: token, Slots: 8,
			Fact:        pfc2.TimeFact{Source: pfc2.TimeSourceDB, FactID: factID, DbMs: dbMs},
			ExpiresDbMs: dbMs + 90_000,
		}}
		entry := pfj3.JournalEntry{LSN: seqStart + uint64(i), Controls: []pfc2.Record{record}}
		payload, err := pfj3.Encode(&entry)
		if err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, payload)
	}
	return payloads
}

// canonicalEmptyRoot builds the canonical empty filesystem into a scratch
// spool and returns its root reference.
func canonicalEmptyRoot(t *testing.T) pft2.Ref {
	t.Helper()
	res, err := pft2.BuildEmptyFilesystem(NewSpool())
	if err != nil {
		t.Fatal(err)
	}
	return res.Root
}

// assertEmptyFilesystem reads the materialized user tree back through the
// STRICT reader and proves it is the canonical empty filesystem.
func assertEmptyFilesystem(t *testing.T, m *Materializer, res *Result) {
	t.Helper()
	if want := canonicalEmptyRoot(t); res.Root != want {
		t.Fatalf("user root %s is not the canonical empty root %s", res.Root.Hex(), want.Hex())
	}
	if got := dumpTree(t, m, res.Root); len(got) != 1 {
		t.Fatalf("empty filesystem lists %v", got)
	}
	if res.MaxInoSeen != pft2.RootIno {
		t.Fatalf("empty filesystem anchored max ino %d, want %d", res.MaxInoSeen, pft2.RootIno)
	}
	if res.OrphanIndex != nil {
		t.Fatal("empty filesystem parked an orphan")
	}
	// Ready-able accounting: both closures are non-empty, disjoint, and each
	// root sits in its own arm (exactly what pfh.cut_mark_ready verifies).
	if res.UserObjectCount != uint64(len(res.UserClosure)) || res.UserObjectCount != 3 {
		t.Fatalf("user closure = %d objects %v", res.UserObjectCount, res.UserClosure)
	}
	if res.RecoveryObjectCount != uint64(len(res.RecoveryClosure)) || res.RecoveryObjectCount == 0 {
		t.Fatalf("recovery closure = %d objects %v", res.RecoveryObjectCount, res.RecoveryClosure)
	}
	if !containsDigest(res.UserClosure, "sha256:"+res.Root.Hex()) {
		t.Fatal("user closure misses the user root")
	}
	if !containsDigest(res.RecoveryClosure, "sha256:"+res.RecoveryRoot.Hex()) {
		t.Fatal("recovery closure misses the recovery root")
	}
	for _, d := range res.RecoveryClosure {
		if containsDigest(res.UserClosure, d) {
			t.Fatalf("closures overlap at %s", d)
		}
	}
}

// A journal of pure control records over a base with NO filesystem root — the
// fork-origin generation whose branch never wrote a byte — folds to the
// canonical empty filesystem instead of failing terminally, and the anchor
// still carries every control fact the range produced.
func TestFoldControlOnlyOverRootlessBase(t *testing.T) {
	const records = 12
	var zero [32]byte
	page, cutDigest := buildJournal(t, zero, 0, controlOnlyPayloads(t, 0, records, "a", controlBaseDbMs))
	facts := managedFacts(hexDigest(zero), cutDigest, 0, uint64(len(page)))

	m, res := runFold(t, page, facts, pft2.EditorLimits{})
	assertEmptyFilesystem(t, m, res)

	// The control plane rode the anchor: every folded session is in the map,
	// and the durable database-time floor advanced with them.
	cr := decodeAnchorControl(t, m.Spool.(*Spool), res)
	if cr.MapRoot == nil {
		t.Fatal("empty fold dropped the folded control map")
	}
	var entries uint64
	for _, c := range cr.Counts {
		entries += c.Count
	}
	if entries != records {
		t.Fatalf("anchored control map holds %d entries, want %d", entries, records)
	}
	if want := uint64(controlBaseDbMs + records - 1); cr.DbTimeFloorMs != want {
		t.Fatalf("anchored database-time floor %d, want %d", cr.DbTimeFloorMs, want)
	}
	if cr.NextCheckoutEpoch != 1 {
		t.Fatalf("anchored next checkout epoch %d, want 1", cr.NextCheckoutEpoch)
	}
	if res.NextLocal != 1 {
		t.Fatalf("empty fold anchored nextLocal %d, want 1", res.NextLocal)
	}

	// Determinism: a rerun reduces to byte-identical objects, and so does a
	// run under bounds small enough to rotate any fold that stages anything.
	// (An empty fold cannot checkpoint: a checkpoint requires staged edits.)
	_, rerunRes := runFold(t, page, facts, pft2.EditorLimits{})
	tiny, tinyRes := runFold(t, page, facts, pft2.EditorLimits{
		MaxEdits: 1, MaxStagedCellBytes: pft2.CellBytes,
		MaxFetchNodes: 2, MaxFetchBytes: 4096,
		MaxNewObjects: 2, MaxNewObjectBytes: 4096,
	})
	for _, other := range []*Result{rerunRes, tinyRes} {
		if other.Root != res.Root || other.RecoveryRoot != res.RecoveryRoot {
			t.Fatalf("empty fold roots differ: %s/%s vs %s/%s",
				other.Root.Hex(), other.RecoveryRoot.Hex(), res.Root.Hex(), res.RecoveryRoot.Hex())
		}
		if fmt.Sprint(other.UserClosure) != fmt.Sprint(res.UserClosure) ||
			fmt.Sprint(other.RecoveryClosure) != fmt.Sprint(res.RecoveryClosure) {
			t.Fatal("empty fold closures differ across runs")
		}
	}
	if roots := countRootObjects(t, tiny.Spool.(*Spool)); roots != 1 {
		t.Fatalf("empty fold committed %d roots under tiny bounds, want exactly one", roots)
	}
}

// The canonical empty root is the SAME object the shared transition engine
// commits when a record forces it to touch inode 1 and nothing else: a fold
// that reduces to nothing and a fold whose only intent no-ops agree byte for
// byte, so the empty outcome introduces no second spelling of "empty".
func TestEmptyFoldMatchesNoOpIntentFold(t *testing.T) {
	// One unlink of a name that never existed: benign, env-less, and its only
	// effect is the engine's first touch of the root inode.
	page, facts := foldFixture(t, []wal.Record{{Op: wal.OpRemove, Path: "gone", TsMs: 0}})
	m, res := runFold(t, page, facts, pft2.EditorLimits{})
	if want := canonicalEmptyRoot(t); res.Root != want {
		t.Fatalf("no-op intent fold root %s != canonical empty root %s", res.Root.Hex(), want.Hex())
	}
	if got := dumpTree(t, m, res.Root); len(got) != 1 {
		t.Fatalf("no-op intent fold tree = %v", got)
	}
}

// A control-only TAIL after real work is not an empty fold: the checkpoint
// the staged work forces leaves the final transaction anchored at the interim
// root, so it commits UNCHANGED against it and the tail's control records
// still land in the anchor. This is the chunk-boundary interaction the empty
// outcome must never touch.
//
// (main forces the boundary through the editor's MaxEdits rotation pressure;
// the OSS fold checkpoints on staged cell bytes instead, so the tree work
// here writes one cell per file under a lowered staged-cell cap.)
func TestControlOnlyTailAfterRotation(t *testing.T) {
	const tail = 5
	tree := append(createOnlyRecords(2),
		wal.Record{Op: wal.OpWrite, Path: "tree/n0", Data: fillPattern(0x11, pft2.CellBytes), TsMs: 300},
		wal.Record{Op: wal.OpWrite, Path: "tree/n1", Data: fillPattern(0x22, pft2.CellBytes), TsMs: 301},
	)
	payloads := append(encodeEntries(t, 0, tree...),
		controlOnlyPayloads(t, uint64(len(tree)), tail, "tail", controlBaseDbMs)...)
	var zero [32]byte
	page, cutDigest := buildJournal(t, zero, 0, payloads)
	facts := managedFacts(hexDigest(zero), cutDigest, 0, uint64(len(page)))

	single, singleRes := runFold(t, page, facts, pft2.EditorLimits{})
	chunked, chunkedRes := runFold(t, page, facts,
		pft2.EditorLimits{MaxStagedCellBytes: 2 * pft2.CellBytes})
	if roots := countRootObjects(t, chunked.Spool.(*Spool)); roots < 2 {
		t.Fatalf("tight bounds committed %d roots, want a checkpointed fold", roots)
	}
	if fmt.Sprint(dumpTree(t, single, singleRes.Root)) != fmt.Sprint(dumpTree(t, chunked, chunkedRes.Root)) {
		t.Fatal("the checkpointed fold reduced to a different filesystem")
	}
	if singleRes.Root == canonicalEmptyRoot(t) {
		t.Fatal("a fold with staged work must never reduce to the empty filesystem")
	}
	for _, run := range []struct {
		m   *Materializer
		res *Result
	}{{single, singleRes}, {chunked, chunkedRes}} {
		var entries uint64
		for _, c := range decodeAnchorControl(t, run.m.Spool.(*Spool), run.res).Counts {
			entries += c.Count
		}
		if entries != tail {
			t.Fatalf("anchor holds %d control entries, want the %d tail records", entries, tail)
		}
	}
}

// The empty filesystem is ADOPTABLE: the next cut on the same branch binds the
// anchor the empty fold published, folds more control records, and settles on
// the identical user root with the earlier control facts carried forward.
// (An adopted base is never rootless — its anchor pins a filesystem root and
// the claim carries that root's digest — so the reachable adopted analogue of
// the failure is adopting the empty filesystem itself.)
func TestAdoptedEmptyFilesystemFoldsAgain(t *testing.T) {
	const firstRecords = 6
	var zero [32]byte
	page, cutDigest := buildJournal(t, zero, 0, controlOnlyPayloads(t, 0, firstRecords, "a", controlBaseDbMs))
	facts := managedFacts(hexDigest(zero), cutDigest, 0, uint64(len(page)))
	m, first := runFold(t, page, facts, pft2.EditorLimits{})
	assertEmptyFilesystem(t, m, first)

	// The follow-on cut adopts the anchor exactly as the worker would.
	nextPage, nextDigest := buildJournal(t, mustHex32(t, cutDigest), uint64(firstRecords),
		controlOnlyPayloads(t, uint64(firstRecords), 4, "b", controlBaseDbMs+100))
	nextFacts := managedFacts(cutDigest, nextDigest, uint64(firstRecords), uint64(firstRecords+len(nextPage)))
	nextFacts.CutID = "hcut_adopt_empty"
	nextFacts.BaseCommit = &BaseCommitFacts{
		CommitID: "c_empty", CommitKind: "pft2", BaseMode: "adopted",
		RootDigest: first.Root.Hex(), RootSize: strconv.FormatUint(first.Root.Size, 10),
		MaxInoSeen:       strconv.FormatUint(first.MaxInoSeen, 10),
		AnchorID:         "hanchor_empty",
		RecoveryRoot:     first.RecoveryRoot.Hex(),
		RecoveryRootSize: strconv.FormatUint(first.RecoveryRoot.Size, 10),
		InodeNamespace:   "7",
		NextLocal:        strconv.FormatUint(first.NextLocal, 10),
	}

	next := &Materializer{
		Facts:   nextFacts,
		Journal: &fakeJournal{records: nextPage},
		Spool:   m.Spool, // the objects the first cut published
	}
	second, err := next.Run(context.Background())
	if err != nil {
		t.Fatalf("adopted empty-filesystem cut: %v", err)
	}
	if second.Root != first.Root {
		t.Fatalf("adopted fold moved the empty root %s -> %s", first.Root.Hex(), second.Root.Hex())
	}
	if second.RecoveryRoot == first.RecoveryRoot {
		t.Fatal("the follow-on cut must anchor its own as-of sequence")
	}
	cr := decodeAnchorControl(t, m.Spool.(*Spool), second)
	var entries uint64
	for _, c := range cr.Counts {
		entries += c.Count
	}
	if entries != firstRecords+4 {
		t.Fatalf("adopted anchor holds %d control entries, want %d", entries, firstRecords+4)
	}
	if cr.DbTimeFloorMs < uint64(controlBaseDbMs) {
		t.Fatalf("adopted anchor floor %d regressed", cr.DbTimeFloorMs)
	}
}

// An adopted or forked base that HAS a filesystem root and a record range that
// stages nothing needs no empty-root construction at all: the transaction is
// UNCHANGED and republishes the base root byte for byte.
func TestZeroEditRangeOverBaseWithRoot(t *testing.T) {
	for _, mode := range []string{"adopted", "fork"} {
		t.Run(mode, func(t *testing.T) {
			base := buildSourceBase(t)
			baseSeq := uint64(0)
			baseDigest := [32]byte{}
			namespace := forkNamespaceStr
			if mode == "adopted" {
				baseSeq = sourceAsOfSeq
				baseDigest = [32]byte{0xC1}
				namespace = strconv.FormatUint(uint64(sourceNamespace), 10)
			}
			page, cutDigest := buildJournal(t, baseDigest, baseSeq,
				controlOnlyPayloads(t, baseSeq, 3, mode, sourceFloorMs+1000))
			facts := managedFacts(hexDigest(baseDigest), cutDigest, baseSeq, baseSeq+uint64(len(page)))
			facts.InodeNamespace = namespace
			facts.BaseCommit = base.commitFacts(mode)

			m := &Materializer{Facts: facts, Journal: &fakeJournal{records: page}, Spool: base.anchorSpool}
			res, err := m.Run(context.Background())
			if err != nil {
				t.Fatalf("%s zero-edit fold: %v", mode, err)
			}
			if res.Root != base.root {
				t.Fatalf("%s zero-edit fold republished %s, want the base root %s",
					mode, res.Root.Hex(), base.root.Hex())
			}
			if got := dumpTree(t, m, res.Root); len(got) != 3 {
				t.Fatalf("%s zero-edit fold changed the tree: %v", mode, got)
			}
			cr := decodeAnchorControl(t, base.anchorSpool, res)
			if cr.MapRoot == nil {
				t.Fatalf("%s zero-edit fold dropped the folded control map", mode)
			}
		})
	}
}

// A conversion whose resolved legacy manifest is EMPTY imports the canonical
// empty filesystem: the same first-class outcome on the import path.
func TestLegacyConversionOfEmptyManifest(t *testing.T) {
	legacy := &fakeLegacy{wantHash: treehash.Compute(nil)}
	m := &Materializer{Facts: conversionFacts(), Legacy: legacy, Blobs: &fakeBlobs{}, Spool: NewSpool()}
	res, err := m.Run(context.Background())
	if err != nil {
		t.Fatalf("empty manifest conversion: %v", err)
	}
	assertEmptyFilesystem(t, m, res)
	if legacy.verifiedHash != treehash.Compute(nil) {
		t.Fatalf("verified tree hash %q", legacy.verifiedHash)
	}
}

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	out, err := parseHex32(s, "test digest")
	if err != nil {
		t.Fatal(err)
	}
	return out
}
