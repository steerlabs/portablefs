package historycut

// Recovery-root separation for materialized cuts: a FORK cut imports only
// the immutable user filesystem root — never the source branch's
// RecoveryRoot controls, orphan namespace, allocator, checkout epochs, or
// database-time floor — while an ADOPTED cut must bind the exact same-branch
// anchor and carry every recovery fact (floor and epoch included) through
// the cut. Missing, unknown, or contradictory base-mode facts fail closed
// before any journal folding.

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/fstransition"
	"github.com/trendup-ai/portablefs/vcs/internal/pfc2"
	"github.com/trendup-ai/portablefs/vcs/internal/pft2"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

const (
	sourceNamespace  = uint32(5)
	sourceFloorMs    = int64(1_701_000_000_000)
	sourceNextLocal  = uint64(50)
	sourceAsOfSeq    = uint64(7)
	sourceOrphanIno  = uint64(sourceNamespace)<<32 | 40
	forkNamespaceStr = "6"
)

func nsIno(ns uint32, local uint64) uint64 { return uint64(ns)<<32 | local }

// sourceBase is one committed pft2 base plus its hashed recovery anchor.
type sourceBase struct {
	userSpool   *Spool // exactly the user-root closure (what a fork may need)
	anchorSpool *Spool // user closure + anchor objects (what adoption needs)
	root        pft2.Ref
	rootFacts   pft2.Root
	anchor      pft2.Ref
	anchorSize  string
	rootSize    string
}

func putTestNode(t *testing.T, spools []*Spool, node *pft2.Node) pft2.Ref {
	t.Helper()
	encoded, err := pft2.EncodeNode(node)
	if err != nil {
		t.Fatalf("encode %v: %v", node.Kind, err)
	}
	ref := pft2.RefOf(encoded)
	for _, s := range spools {
		if err := s.Seed(ref, encoded); err != nil {
			t.Fatal(err)
		}
	}
	return ref
}

// buildSourceBase commits a namespaced source tree and an anchor carrying a
// LIVE session (floor-bound), a parked orphan, an advanced checkout epoch,
// and the source allocator cursor.
func buildSourceBase(t *testing.T) *sourceBase {
	t.Helper()
	ctx := context.Background()
	userSpool, anchorSpool := NewSpool(), NewSpool()

	editor, err := pft2.NewEditor(ctx, nil, nil, pft2.EditorLimits{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := fstransition.New(fstransition.Config{Tx: editor, FallbackTsMs: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []wal.Record{
		{Op: wal.OpMkdir, Path: "src", Mode: 0o755, Inos: []uint64{nsIno(sourceNamespace, 2)}, TsMs: 1000},
		{Op: wal.OpCreate, Path: "src/data", Mode: 0o644, Ino: nsIno(sourceNamespace, 3), TsMs: 1001},
		{Op: wal.OpWrite, Path: "src/data", Data: []byte("source-bytes"), TsMs: 1002},
	} {
		if _, err := engine.Apply(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	// Commit the user tree into BOTH spools (a fork legitimately reads it).
	res, err := editor.Commit(ctx, userSpool, userSpool)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range userSpool.Objects() {
		data, _ := userSpool.Bytes(ref)
		if err := anchorSpool.Seed(ref, data); err != nil {
			t.Fatal(err)
		}
	}

	// Anchor: control state with one live session (issued AT the floor), a
	// consumed+released checkout (epoch advanced to 2, map keeps only the
	// session entry), floor = sourceFloorMs.
	st := pfc2.NewState()
	sess := pfc2.SessionRef{SessionID: "src-sess", Generation: 1}
	var token [pfc2.TokenHashBytes]byte
	token[0] = 0xAB
	open, err := pfc2.NewSessionOpenRecord(sess, "src-owner", token, 8,
		pfc2.TimeFact{Source: pfc2.TimeSourceDB, FactID: [16]byte{1}, DbMs: sourceFloorMs}, 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Apply(open); err != nil {
		t.Fatal(err)
	}
	projection := st.Project()
	var entries []pft2.ControlEntry
	for i := range projection.Entries {
		value, err := pfc2.EncodeEntry(&projection.Entries[i])
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, pft2.ControlEntry{
			Key: projection.Entries[i].Key(), Kind: uint64(projection.Entries[i].Kind), Value: value,
		})
	}
	mapRoot, _, counts, err := pft2.BuildControlTree(entries, anchorSpool)
	if err != nil {
		t.Fatal(err)
	}
	controlRef := putTestNode(t, []*Spool{anchorSpool}, &pft2.Node{Kind: pft2.KindControlRoot, ControlRoot: &pft2.ControlRoot{
		Schema: pft2.ControlSchemaVersion, MapRoot: mapRoot, Counts: counts,
		NextCheckoutEpoch: 4, DbTimeFloorMs: uint64(sourceFloorMs),
	}})

	orphanInode := putTestNode(t, []*Spool{anchorSpool}, &pft2.Node{Kind: pft2.KindInode, Inode: &pft2.Inode{
		Ino: sourceOrphanIno, Kind: pft2.FileKindRegular, Mode: 0o600, Nlink: 1,
		MtimeMs: 1000, CtimeMs: 1000, AtimeMs: 1000,
	}})
	orphanIndex := putTestNode(t, []*Spool{anchorSpool}, &pft2.Node{Kind: pft2.KindInodeIndexLeaf,
		InodeIndexLeaf: &pft2.InodeIndexLeaf{Entries: []pft2.InodeIndexEntry{{Ino: sourceOrphanIno, Inode: orphanInode}}}})

	anchor := putTestNode(t, []*Spool{anchorSpool}, &pft2.Node{Kind: pft2.KindRecoveryRoot, RecoveryRoot: &pft2.RecoveryRoot{
		AsOfSeq:        sourceAsOfSeq,
		FilesystemRoot: res.Root,
		ControlRoot:    &controlRef,
		OrphanIndex:    &orphanIndex,
		InoNamespace:   sourceNamespace,
		NextLocal:      sourceNextLocal,
	}})
	anchorData, _ := anchorSpool.Bytes(anchor)
	return &sourceBase{
		userSpool: userSpool, anchorSpool: anchorSpool,
		root: res.Root, rootFacts: res.RootFacts,
		anchor:     anchor,
		anchorSize: strconv.FormatUint(uint64(len(anchorData)), 10),
		rootSize:   strconv.FormatUint(res.Root.Size, 10),
	}
}

func (b *sourceBase) commitFacts(mode string) *BaseCommitFacts {
	// The claim always projects the SOURCE anchor summary (the row exists
	// regardless of mode); a fork must ignore it without ever fetching it.
	return &BaseCommitFacts{
		CommitID: "c_src", CommitKind: "pft2", BaseMode: mode,
		RootDigest: b.root.Hex(), RootSize: b.rootSize,
		MaxInoSeen:   strconv.FormatUint(b.rootFacts.MaxInoSeen, 10),
		AnchorID:     "hanchor_src",
		RecoveryRoot: b.anchor.Hex(), RecoveryRootSize: b.anchorSize,
		InodeNamespace: strconv.FormatUint(uint64(sourceNamespace), 10),
		NextLocal:      strconv.FormatUint(sourceNextLocal, 10),
	}
}

func decodeAnchorControl(t *testing.T, spool *Spool, res *Result) *pft2.ControlRoot {
	t.Helper()
	if res.ControlRoot == nil {
		t.Fatal("materialized anchor carries no control root")
	}
	raw, ok := spool.Bytes(*res.ControlRoot)
	if !ok {
		t.Fatal("control root missing from spool")
	}
	node, err := pft2.DecodeNodeKind(raw, pft2.KindControlRoot)
	if err != nil {
		t.Fatal(err)
	}
	return node.ControlRoot
}

func TestForkCutNeverImportsSourceRecovery(t *testing.T) {
	base := buildSourceBase(t)
	var zero [32]byte

	// The fork branch's journal: two creates plus one deterministic EEXIST
	// whose burned identity must still advance the anchor allocator.
	payloads := encodeEntries(t, 0,
		wal.Record{Op: wal.OpCreate, Path: "fresh1", Mode: 0o644, Ino: nsIno(6, 1), TsMs: 2000},
		wal.Record{Op: wal.OpCreate, Path: "fresh2", Mode: 0o644, Ino: nsIno(6, 2), TsMs: 2001},
		wal.Record{Op: wal.OpCreate, Path: "fresh1", Mode: 0o644, Ino: nsIno(6, 3), TsMs: 2002},
	)
	records, cutDigest := buildJournal(t, zero, 0, payloads)
	facts := CutFacts{
		CutID: "hcut_fork", Kind: "user", SourceKind: "managed_journal",
		GenerationID: "gen_fork", RecordCodec: "pfj3", ControlCodec: "pfc2",
		SourceBaseSeq: "0", SourceBaseDig: hexDigest(zero),
		CutSeqExclusive: strconv.Itoa(len(records)), CutDigest: cutDigest,
		InodeNamespace: forkNamespaceStr,
		BaseCommit:     base.commitFacts("fork"),
	}
	// THE isolation proof: the spool holds ONLY the user-root closure. If
	// the fork path touched the source anchor, controls, orphans, or
	// allocator objects, the fetch would fail the run.
	m := &Materializer{Facts: facts, Journal: &fakeJournal{records: records}, Spool: base.userSpool}
	res, err := m.Run(context.Background())
	if err != nil {
		t.Fatalf("fork cut: %v", err)
	}

	cr := decodeAnchorControl(t, base.userSpool, res)
	if cr.MapRoot != nil || cr.NextCheckoutEpoch != 1 || cr.DbTimeFloorMs != 0 {
		t.Fatalf("fork anchor control root %+v; a fork starts with DEFAULT control state", cr)
	}
	if res.OrphanIndex != nil {
		t.Fatal("fork imported the source orphan namespace")
	}
	if res.NextLocal != 4 {
		t.Fatalf("fork anchor nextLocal %d, want 4 (locals 1..3 observed, burned EEXIST included)", res.NextLocal)
	}
	if res.MaxInoSeen < base.rootFacts.MaxInoSeen {
		t.Fatalf("fork anchor high-water %d below the reused root's %d", res.MaxInoSeen, base.rootFacts.MaxInoSeen)
	}

	// The user tree carries both the source names and the fork's creates.
	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: base.userSpool}, res.Root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rootView, err := reader.GetInode(ctx, pft2.RootIno)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Lookup(ctx, rootView.Ref, "src"); err != nil {
		t.Fatalf("fork lost the source tree: %v", err)
	}
	fresh, err := reader.Lookup(ctx, rootView.Ref, "fresh1")
	if err != nil || fresh.Ino != nsIno(6, 1) {
		t.Fatalf("fork create = %+v err=%v", fresh, err)
	}
}

func TestAdoptedCutBindsAndCarriesRecovery(t *testing.T) {
	base := buildSourceBase(t)
	baseDigest := [32]byte{0xC1}

	payloads := encodeEntries(t, sourceAsOfSeq,
		wal.Record{Op: wal.OpCreate, Path: "src/next", Mode: 0o644, Ino: nsIno(sourceNamespace, sourceNextLocal), TsMs: 3000},
	)
	records, cutDigest := buildJournal(t, baseDigest, sourceAsOfSeq, payloads)
	facts := CutFacts{
		CutID: "hcut_adopt", Kind: "user", SourceKind: "managed_journal",
		GenerationID: "gen_src", RecordCodec: "pfj3", ControlCodec: "pfc2",
		SourceBaseSeq: strconv.FormatUint(sourceAsOfSeq, 10), SourceBaseDig: hexDigest(baseDigest),
		CutSeqExclusive: strconv.FormatUint(sourceAsOfSeq+uint64(len(records)), 10), CutDigest: cutDigest,
		InodeNamespace: strconv.FormatUint(uint64(sourceNamespace), 10),
		BaseCommit:     base.commitFacts("adopted"),
	}
	m := &Materializer{Facts: facts, Journal: &fakeJournal{records: records}, Spool: base.anchorSpool}
	res, err := m.Run(context.Background())
	if err != nil {
		t.Fatalf("adopted cut: %v", err)
	}

	// The recovery plane survives the cut byte-provably: floor, epoch, the
	// live session, and the parked orphan all carry through — even though
	// the folded journal added NO control records.
	cr := decodeAnchorControl(t, base.anchorSpool, res)
	if cr.DbTimeFloorMs != uint64(sourceFloorMs) {
		t.Fatalf("adopted anchor floor %d, want %d", cr.DbTimeFloorMs, sourceFloorMs)
	}
	if cr.NextCheckoutEpoch != 4 {
		t.Fatalf("adopted anchor next epoch %d, want 4", cr.NextCheckoutEpoch)
	}
	if cr.MapRoot == nil {
		t.Fatal("adopted anchor lost the live session entry")
	}
	if res.OrphanIndex == nil {
		t.Fatal("adopted anchor lost the parked orphan")
	}
	if res.NextLocal != sourceNextLocal+1 {
		t.Fatalf("adopted anchor nextLocal %d, want %d", res.NextLocal, sourceNextLocal+1)
	}
}

func TestCutBaseModeRejectionMatrix(t *testing.T) {
	base := buildSourceBase(t)
	var zero [32]byte
	payloads := encodeEntries(t, 0,
		wal.Record{Op: wal.OpCreate, Path: "x", Mode: 0o644, Ino: nsIno(6, 1), TsMs: 2000})
	forkRecords, forkDigest := buildJournal(t, zero, 0, payloads)

	forkFacts := func() CutFacts {
		return CutFacts{
			CutID: "hcut_bad", Kind: "user", SourceKind: "managed_journal",
			GenerationID: "gen_bad", RecordCodec: "pfj3", ControlCodec: "pfc2",
			SourceBaseSeq: "0", SourceBaseDig: hexDigest(zero),
			CutSeqExclusive: strconv.Itoa(len(forkRecords)), CutDigest: forkDigest,
			InodeNamespace: forkNamespaceStr,
			BaseCommit:     base.commitFacts("fork"),
		}
	}

	cases := []struct {
		name   string
		mutate func(*CutFacts)
	}{
		{"missing mode", func(f *CutFacts) { f.BaseCommit.BaseMode = "" }},
		{"unknown mode", func(f *CutFacts) { f.BaseCommit.BaseMode = "sideways" }},
		{"conversion mode on a pft2 base", func(f *CutFacts) { f.BaseCommit.BaseMode = "conversion" }},
		{"fork with nonzero base seq", func(f *CutFacts) {
			f.SourceBaseSeq = "3"
		}},
		{"fork whose claimed anchor namespace equals the cut namespace", func(f *CutFacts) {
			f.BaseCommit.InodeNamespace = forkNamespaceStr
		}},
		{"adopted without an anchor", func(f *CutFacts) {
			f.BaseCommit.BaseMode = "adopted"
			f.BaseCommit.RecoveryRoot = ""
			f.BaseCommit.RecoveryRootSize = ""
		}},
		{"adopted with a foreign-namespace cut", func(f *CutFacts) {
			f.BaseCommit.BaseMode = "adopted"
			// The hashed anchor allocates namespace 5; the cut claims 6.
			f.SourceBaseSeq = strconv.FormatUint(sourceAsOfSeq, 10)
		}},
		{"adopted with a lying claimed nextLocal", func(f *CutFacts) {
			f.BaseCommit.BaseMode = "adopted"
			f.InodeNamespace = strconv.FormatUint(uint64(sourceNamespace), 10)
			f.SourceBaseSeq = strconv.FormatUint(sourceAsOfSeq, 10)
			f.BaseCommit.NextLocal = "999"
		}},
		{"adopted whose anchor as-of differs from the base seq", func(f *CutFacts) {
			f.BaseCommit.BaseMode = "adopted"
			f.InodeNamespace = strconv.FormatUint(uint64(sourceNamespace), 10)
			// SourceBaseSeq stays 0; the hashed anchor is as-of 7.
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := forkFacts()
			tc.mutate(&facts)
			m := &Materializer{Facts: facts, Journal: &fakeJournal{records: forkRecords}, Spool: base.anchorSpool}
			if _, err := m.Run(context.Background()); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got %v, want ErrCorrupt", err)
			}
		})
	}
}

func TestEnvlessDeterministicToleranceMatchesReplay(t *testing.T) {
	var zero [32]byte

	// Benign phantom (remove of a missing path): tolerated exactly like
	// cold replay tolerates it.
	benign := encodeEntries(t, 0,
		wal.Record{Op: wal.OpCreate, Path: "a", Mode: 0o644, Ino: nsIno(7, 1), TsMs: 1000},
		wal.Record{Op: wal.OpRemove, Path: "missing", TsMs: 1001},
	)
	records, cutDigest := buildJournal(t, zero, 0, benign)
	m := &Materializer{
		Facts:   managedFacts(hexDigest(zero), cutDigest, 0, uint64(len(records))),
		Journal: &fakeJournal{records: records},
		Spool:   NewSpool(),
	}
	if _, err := m.Run(context.Background()); err != nil {
		t.Fatalf("benign env-less phantom must fold: %v", err)
	}

	// A CURRENT (server-stamped) env-less write to a missing target could
	// discard durable bytes if skipped: replay fails closed, so the
	// materializer must too.
	fatal := encodeEntries(t, 0,
		wal.Record{Op: wal.OpWrite, Path: "missing", Data: []byte("x"), TsMs: 1000},
	)
	records, cutDigest = buildJournal(t, zero, 0, fatal)
	m = &Materializer{
		Facts:   managedFacts(hexDigest(zero), cutDigest, 0, uint64(len(records))),
		Journal: &fakeJournal{records: records},
		Spool:   NewSpool(),
	}
	if _, err := m.Run(context.Background()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("env-less deterministic write failure must fail the cut closed, got %v", err)
	}

	// The SAME record with the legacy zero timestamp keeps the migration
	// escape hatch, exactly like benignReplayErrorForRecord.
	legacy := encodeEntries(t, 0,
		wal.Record{Op: wal.OpWrite, Path: "missing", Data: []byte("x")},
	)
	records, cutDigest = buildJournal(t, zero, 0, legacy)
	m = &Materializer{
		Facts:   managedFacts(hexDigest(zero), cutDigest, 0, uint64(len(records))),
		Journal: &fakeJournal{records: records},
		Spool:   NewSpool(),
	}
	if _, err := m.Run(context.Background()); err != nil {
		t.Fatalf("legacy zero-ts write phantom must keep the migration escape: %v", err)
	}
}
