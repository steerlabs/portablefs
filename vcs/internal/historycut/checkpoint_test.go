package historycut

// Checkpointed managed folds: a journal backlog whose staged cell bytes
// would exceed one transaction's MaxStagedCellBytes cap must materialize by
// committing the tree transaction at record boundaries and rebinding the
// SAME transition engine (Engine.SetTx) over the reopened editor — never by
// raising the cap. These tests prove:
//
//   - the checkpointed fold and the single-transaction fold reduce to the
//     SAME cut semantically: identical logical filesystem (names, inode
//     facts, contents), identical orphan set (facts and content), identical
//     allocator watermarks, byte-identical ControlRoot and xattr leaves;
//   - engine state spanning chunk boundaries survives the transaction swap:
//     orphan+reap, xattr set/remove on early-chunk inodes, renames, hard
//     links, and the PFC2 control reduction (native controls AND enveloped
//     exact outcomes);
//   - a backlog that trips the staged-cell transaction limit when folded
//     through ONE transaction (the production failure) now materializes;
//   - the checkpointed reduction stays deterministic: identical inputs and
//     limits reproduce byte-identical roots and closures (crash-resume).
//
// The intermediate commits DO change content-addressed object boundaries
// (cell pack grouping and path-copy B+tree shapes are functions of each
// transaction's edit set), so the user root DIGEST legitimately differs
// between the two folds; every engine-derived artifact and every semantic
// fact must not.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fstransition"
	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// checkpointCapBytes lowers the per-transaction staged-cell cap far enough
// that the fixture backlog (~640 KiB of staged cells) forces MANY checkpoint
// commits (threshold = cap/2 = 128 KiB) while any single record (<= 24 KiB)
// stays comfortably inside one transaction.
const checkpointCapBytes = int64(256 << 10)

func fillPattern(seed byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = seed + byte(i%31) + 1 // never all-zero: holes would stage nothing
	}
	return out
}

// checkpointBacklog builds the managed journal fixture: enough staged bytes
// to force many checkpoints under checkpointCapBytes, with every kind of
// cross-record engine state deliberately spanning chunk boundaries. It
// returns the PFJ3 entries (tree and control rows) plus the bare tree
// records for driving a raw single-transaction engine fold.
func checkpointBacklog(t *testing.T) ([]pfj3.JournalEntry, []wal.Record) {
	t.Helper()
	ns := func(local uint64) uint64 { return nsIno(7, local) }
	ts := int64(1000)
	tick := func() int64 { ts++; return ts }

	var trees []wal.Record
	tree := func(r wal.Record) {
		r.TsMs = tick()
		trees = append(trees, r)
	}

	tree(wal.Record{Op: wal.OpMkdir, Path: "dir", Mode: 0o755, Inos: []uint64{ns(2)}})
	tree(wal.Record{Op: wal.OpCreate, Path: "dir/big", Mode: 0o644, Ino: ns(3), Excl: true})
	for i := 0; i < 12; i++ {
		tree(wal.Record{Op: wal.OpWrite, Path: "dir/big", Offset: int64(i) * 24576, Data: fillPattern(byte(i), 24576)})
	}
	tree(wal.Record{Op: wal.OpSetxattr, Path: "dir/big", XattrName: "user.early", Data: []byte("v-early")})

	// Victim: parked with content and an xattr, reaped MANY chunks later.
	tree(wal.Record{Op: wal.OpCreate, Path: "dir/victim", Mode: 0o600, Ino: ns(4), Excl: true})
	tree(wal.Record{Op: wal.OpWrite, Path: "dir/victim", Data: fillPattern(0x40, 8192)})
	tree(wal.Record{Op: wal.OpSetxattr, Path: "dir/victim", XattrName: "user.doomed", Data: []byte("x")})
	tree(wal.Record{Op: wal.OpRemove, Path: "dir/victim"})

	// Rename source, created chunks before the rename lands.
	tree(wal.Record{Op: wal.OpCreate, Path: "dir/from", Mode: 0o644, Ino: ns(5), Excl: true})
	tree(wal.Record{Op: wal.OpWrite, Path: "dir/from", Data: fillPattern(0x50, 12288)})

	// Parked orphan that SURVIVES to the cut, mutated by ino across chunks.
	tree(wal.Record{Op: wal.OpCreate, Path: "dir/parked", Mode: 0o640, Ino: ns(6), Excl: true})
	tree(wal.Record{Op: wal.OpWrite, Path: "dir/parked", Data: fillPattern(0x60, 8192)})
	tree(wal.Record{Op: wal.OpSetxattr, Path: "dir/parked", XattrName: "user.stay", Data: []byte("on-parked")})
	tree(wal.Record{Op: wal.OpRemove, Path: "dir/parked"})

	env := func(slotSeq uint64, hash byte) *wal.Envelope {
		return &wal.Envelope{
			SessionID: "fold-sess", Generation: 1, Slot: 1, SlotSeq: slotSeq,
			ReqHash: bytes.Repeat([]byte{hash}, 32),
		}
	}
	// Enveloped exact outcomes: a success and a deterministic ENOENT, both
	// serialized into the PFC2 control state the cut anchors.
	tree(wal.Record{Op: wal.OpWrite, Path: "dir/big", Data: fillPattern(0xEE, 4096), Env: env(1, 0xE1)})
	tree(wal.Record{Op: wal.OpWrite, Path: "missing/nope", Data: []byte("lost"), Env: env(2, 0xE2)})

	tree(wal.Record{Op: wal.OpCreate, Path: "dir/big2", Mode: 0o644, Ino: ns(7), Excl: true})
	for i := 0; i < 12; i++ {
		tree(wal.Record{Op: wal.OpWrite, Path: "dir/big2", Offset: int64(i) * 24576, Data: fillPattern(byte(0x80+i), 24576)})
	}

	// Cross-chunk engine state: xattrs on an inode created many chunks ago,
	// ino-addressed edits on the parked orphan, a rename, the victim's reap
	// (which must also drop its xattrs), and a hard link.
	tree(wal.Record{Op: wal.OpSetxattr, Path: "dir/big", XattrName: "user.late", Data: []byte("v-late")})
	tree(wal.Record{Op: wal.OpRemovexattr, Path: "dir/big", XattrName: "user.early"})
	tree(wal.Record{Op: wal.OpSetxattr, Ino: ns(6), XattrName: "user.orphan", Data: []byte("alive")})
	tree(wal.Record{Op: wal.OpWrite, Ino: ns(6), Offset: 8192, Data: fillPattern(0x66, 4096)})
	tree(wal.Record{Op: wal.OpMkdir, Path: "dir2", Mode: 0o750, Inos: []uint64{ns(8)}})
	tree(wal.Record{Op: wal.OpRename, Path: "dir/from", NewPath: "dir2/to"})
	tree(wal.Record{Op: wal.OpReap, Ino: ns(4)})
	tree(wal.Record{Op: wal.OpLink, Path: "dir/big", NewPath: "dir2/hard"})

	// One atomic batch (never split by a checkpoint) plus metadata edits.
	tree(wal.Record{Op: wal.OpBatch, Mutations: []wal.Record{
		{Op: wal.OpWrite, Path: "dir/big2", Data: fillPattern(0xBB, 4096)},
		{Op: wal.OpChmod, Path: "dir/big", Mode: 0o600},
		{Op: wal.OpTruncate, Path: "dir/big2", Size: 30000},
	}})
	tree(wal.Record{Op: wal.OpChown, Path: "dir2/to", UID: 7, GID: 8, ChownSetUID: true, ChownSetGID: true})
	tree(wal.Record{Op: wal.OpChtimes, Path: "dir/big", MtimeMs: 9_000, AtimeMs: 9_001, ChtimesSetAtime: true})
	tree(wal.Record{Op: wal.OpTruncate, Path: "dir/big", Size: 100000})
	tree(wal.Record{Op: wal.OpSymlink, Path: "dir2/ln", Target: "dir/big", Ino: ns(9), Excl: true})

	// Interleave one NATIVE control row (a session open) among the tree
	// rows: the PFC2 reduction lives beside the tree fold and must be
	// byte-identical however the tree transaction is chunked.
	var token [pfc2.TokenHashBytes]byte
	token[0] = 0xF0
	open, err := pfc2.NewSessionOpenRecord(
		pfc2.SessionRef{SessionID: "fold-sess", Generation: 1}, "fold-owner", token, 8,
		pfc2.TimeFact{Source: pfc2.TimeSourceDB, FactID: [pfc2.FactIDBytes]byte{1}, DbMs: 1_701_000_000_000},
		90*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	var entries []pfj3.JournalEntry
	for i := range trees {
		if i == 14 { // just before the enveloped outcomes reference the session
			entries = append(entries, pfj3.JournalEntry{Controls: []pfc2.Record{*open}})
		}
		rec := trees[i]
		entries = append(entries, pfj3.JournalEntry{Tree: &rec})
	}
	return entries, trees
}

// encodeJournalEntries assigns sequential LSNs, encodes each PFJ3 entry, and
// chains the payloads from baseDigest.
func encodeJournalEntries(t *testing.T, baseDigest [32]byte, baseSeq uint64, entries []pfj3.JournalEntry) ([]PageRecord, string) {
	t.Helper()
	var payloads [][]byte
	for i := range entries {
		entries[i].LSN = baseSeq + uint64(i)
		if entries[i].Tree != nil {
			entries[i].Tree.Seq = entries[i].LSN
		}
		payload, err := pfj3.Encode(&entries[i])
		if err != nil {
			t.Fatalf("encode entry %d: %v", i, err)
		}
		payloads = append(payloads, payload)
	}
	return buildJournal(t, baseDigest, baseSeq, payloads)
}

// ─── semantic snapshots (object-boundary independent) ────────────────────────

// snapInode is one inode's complete semantic view: stored facts, directory
// entries, and a digest of the logical content — everything a cut promises,
// nothing about how it chunked into objects.
type snapInode struct {
	Kind    pft2.FileKind
	Mode    uint32
	UID     uint32
	GID     uint32
	Nlink   uint64
	Size    uint64
	MtimeMs int64
	CtimeMs int64
	AtimeMs int64
	Symlink string
	Content string
	Dirents map[string]string
}

func spoolNode(t *testing.T, spool *Spool, ref pft2.Ref) *pft2.Node {
	t.Helper()
	raw, ok := spool.Bytes(ref)
	if !ok {
		t.Fatalf("object sha256:%s missing from spool", ref.Hex())
	}
	node, err := pft2.DecodeNode(raw)
	if err != nil {
		t.Fatalf("decode %s: %v", ref.Hex(), err)
	}
	return node
}

func collectIndexRefs(t *testing.T, spool *Spool, ref pft2.Ref, out map[uint64]pft2.Ref) {
	t.Helper()
	node := spoolNode(t, spool, ref)
	switch node.Kind {
	case pft2.KindInodeIndexLeaf:
		for _, e := range node.InodeIndexLeaf.Entries {
			out[e.Ino] = e.Inode
		}
	case pft2.KindInodeIndexIndex:
		for _, c := range node.InodeIndexIndex.Children {
			collectIndexRefs(t, spool, c.Child, out)
		}
	default:
		t.Fatalf("inode index contains %s", node.Kind)
	}
}

func collectDirents(t *testing.T, spool *Spool, ref pft2.Ref, out map[string]string) {
	t.Helper()
	node := spoolNode(t, spool, ref)
	switch node.Kind {
	case pft2.KindDirectoryLeaf:
		for _, e := range node.DirectoryLeaf.Entries {
			out[e.Name] = fmt.Sprintf("%d:%d", e.Ino, e.Kind)
		}
	case pft2.KindDirectoryIndex:
		for _, c := range node.DirectoryIndex.Children {
			collectDirents(t, spool, c.Child, out)
		}
	default:
		t.Fatalf("directory tree contains %s", node.Kind)
	}
}

func readLogicalContent(t *testing.T, spool *Spool, meta *pft2.Inode) []byte {
	t.Helper()
	buf := make([]byte, meta.Size)
	if meta.ExtentRoot == nil {
		return buf
	}
	var walk func(ref pft2.Ref)
	walk = func(ref pft2.Ref) {
		node := spoolNode(t, spool, ref)
		switch node.Kind {
		case pft2.KindExtentLeaf:
			for _, entry := range node.ExtentLeaf.Entries {
				page := spoolNode(t, spool, entry.Page)
				if page.Kind != pft2.KindDataPage {
					t.Fatalf("extent entry references %s", page.Kind)
				}
				for idx, cell := range page.DataPage.Cells {
					if cell == nil {
						continue
					}
					start := entry.PageOffset + uint64(idx)*pft2.CellBytes
					if start >= meta.Size {
						continue
					}
					pack, ok := spool.Bytes(cell.Object)
					if !ok {
						t.Fatalf("pack sha256:%s missing", cell.Object.Hex())
					}
					data := pack[cell.ObjectOffset : cell.ObjectOffset+pft2.CellBytes]
					n := uint64(pft2.CellBytes)
					if meta.Size-start < n {
						n = meta.Size - start
					}
					copy(buf[start:start+n], data[:n])
				}
			}
		case pft2.KindExtentIndex:
			for _, c := range node.ExtentIndex.Children {
				walk(c.Child)
			}
		default:
			t.Fatalf("extent tree contains %s", node.Kind)
		}
	}
	walk(*meta.ExtentRoot)
	return buf
}

// snapshotIndex reduces one inode index (filesystem or parked-orphan) to its
// semantic map.
func snapshotIndex(t *testing.T, spool *Spool, indexRoot *pft2.Ref) map[uint64]snapInode {
	t.Helper()
	out := map[uint64]snapInode{}
	if indexRoot == nil {
		return out
	}
	refs := map[uint64]pft2.Ref{}
	collectIndexRefs(t, spool, *indexRoot, refs)
	for ino, ref := range refs {
		node := spoolNode(t, spool, ref)
		if node.Kind != pft2.KindInode || node.Inode.Ino != ino {
			t.Fatalf("index entry %d references %s", ino, node.Kind)
		}
		meta := node.Inode
		snap := snapInode{
			Kind: meta.Kind, Mode: meta.Mode, UID: meta.UID, GID: meta.GID,
			Nlink: meta.Nlink, Size: meta.Size,
			MtimeMs: meta.MtimeMs, CtimeMs: meta.CtimeMs, AtimeMs: meta.AtimeMs,
			Symlink: meta.SymlinkTarget,
		}
		switch meta.Kind {
		case pft2.FileKindRegular:
			sum := sha256.Sum256(readLogicalContent(t, spool, meta))
			snap.Content = fmt.Sprintf("%x", sum)
		case pft2.FileKindDirectory:
			snap.Dirents = map[string]string{}
			if meta.DirectoryRoot != nil {
				collectDirents(t, spool, *meta.DirectoryRoot, snap.Dirents)
			}
		}
		out[ino] = snap
	}
	return out
}

func userSnapshot(t *testing.T, spool *Spool, res *Result) (map[uint64]snapInode, *pft2.Root) {
	t.Helper()
	node := spoolNode(t, spool, res.Root)
	if node.Kind != pft2.KindRoot {
		t.Fatalf("result root is %s", node.Kind)
	}
	index := node.Root.InodeIndex
	return snapshotIndex(t, spool, &index), node.Root
}

func decodeRecovery(t *testing.T, spool *Spool, res *Result) *pft2.RecoveryRoot {
	t.Helper()
	raw, ok := spool.Bytes(res.RecoveryRoot)
	if !ok {
		t.Fatal("recovery root missing from spool")
	}
	node, err := pft2.DecodeNodeKind(raw, pft2.KindRecoveryRoot)
	if err != nil {
		t.Fatal(err)
	}
	return node.RecoveryRoot
}

func countRootObjects(t *testing.T, spool *Spool) int {
	t.Helper()
	count := 0
	for _, ref := range spool.Objects() {
		raw, _ := spool.Bytes(ref)
		if node, err := pft2.DecodeNode(raw); err == nil && node.Kind == pft2.KindRoot {
			count++
		}
	}
	return count
}

// ─── tests ───────────────────────────────────────────────────────────────────

// TestManagedFoldCheckpointsMatchSingleTransaction folds the same backlog
// once through ONE transaction (default limits) and once with the staged
// cap lowered to force many checkpoint commits, and proves the two cuts are
// the same cut: identical semantic filesystem and orphan state, identical
// engine-derived anchors (ControlRoot, xattr leaves, watermarks), and a
// deterministic (byte-identical) rerun of the checkpointed reduction.
func TestManagedFoldCheckpointsMatchSingleTransaction(t *testing.T) {
	ctx := context.Background()
	var zero [32]byte
	entries, _ := checkpointBacklog(t)
	records, cutDigest := encodeJournalEntries(t, zero, 0, entries)
	facts := managedFacts(hexDigest(zero), cutDigest, 0, uint64(len(records)))

	single := &Materializer{Facts: facts, Journal: &fakeJournal{records: records}, Spool: NewSpool()}
	resA, err := single.Run(ctx)
	if err != nil {
		t.Fatalf("single-transaction fold: %v", err)
	}
	chunked := &Materializer{
		Facts: facts, Journal: &fakeJournal{records: records}, Spool: NewSpool(),
		Limits: pft2.EditorLimits{MaxStagedCellBytes: checkpointCapBytes},
	}
	resB, err := chunked.Run(ctx)
	if err != nil {
		t.Fatalf("checkpointed fold: %v", err)
	}

	// The single-transaction run commits exactly one user root; the
	// checkpointed run provably committed intermediate roots (many chunks).
	spoolA, spoolB := single.Spool.(*Spool), chunked.Spool.(*Spool)
	if n := countRootObjects(t, spoolA); n != 1 {
		t.Fatalf("single-transaction fold emitted %d root objects, want 1", n)
	}
	if n := countRootObjects(t, spoolB); n < 4 {
		t.Fatalf("checkpointed fold emitted %d root objects; the backlog must force many checkpoints", n)
	}

	t.Logf("user roots: single=%s chunked=%s (content-addressed boundaries are transaction-dependent; equality is not required, semantics are)",
		resA.Root.Hex()[:12], resB.Root.Hex()[:12])

	// Semantic equality: the logical filesystem and the parked-orphan set
	// (facts AND content) are identical however the fold chunked.
	userA, rootFactsA := userSnapshot(t, spoolA, resA)
	userB, rootFactsB := userSnapshot(t, spoolB, resB)
	if !reflect.DeepEqual(userA, userB) {
		t.Fatalf("user filesystems diverge:\nA=%+v\nB=%+v", userA, userB)
	}
	if resA.OrphanIndex == nil || resB.OrphanIndex == nil {
		t.Fatalf("parked orphan lost: A=%v B=%v", resA.OrphanIndex, resB.OrphanIndex)
	}
	orphA := snapshotIndex(t, spoolA, resA.OrphanIndex)
	orphB := snapshotIndex(t, spoolB, resB.OrphanIndex)
	if !reflect.DeepEqual(orphA, orphB) {
		t.Fatalf("orphan sets diverge:\nA=%+v\nB=%+v", orphA, orphB)
	}
	if len(orphA) != 1 {
		t.Fatalf("orphan set = %v, want exactly the surviving parked inode", orphA)
	}
	if _, ok := orphA[nsIno(7, 6)]; !ok {
		t.Fatalf("parked inode %d missing from %v", nsIno(7, 6), orphA)
	}

	// Verified root counters are pure functions of the final state.
	if rootFactsA.InodeCount != rootFactsB.InodeCount ||
		rootFactsA.DirentCount != rootFactsB.DirentCount ||
		rootFactsA.LogicalBytes != rootFactsB.LogicalBytes ||
		rootFactsA.MaxInoSeen != rootFactsB.MaxInoSeen {
		t.Fatalf("root facts diverge:\nA=%+v\nB=%+v", rootFactsA, rootFactsB)
	}

	// Engine-derived anchors are byte-identical: the control reduction
	// (native session open + both enveloped exact outcomes) and the xattr
	// leaves never touch the tree transaction.
	if resA.ControlRoot == nil || resB.ControlRoot == nil || *resA.ControlRoot != *resB.ControlRoot {
		t.Fatalf("control roots diverge: A=%v B=%v", resA.ControlRoot, resB.ControlRoot)
	}
	rowsA, leavesA := decodeAnchorXattrs(t, spoolA, resA)
	rowsB, leavesB := decodeAnchorXattrs(t, spoolB, resB)
	if !reflect.DeepEqual(rowsA, rowsB) || !reflect.DeepEqual(leavesA, leavesB) {
		t.Fatalf("xattr anchors diverge:\nA=%v %v\nB=%v %v", rowsA, leavesA, rowsB, leavesB)
	}
	wantBig, wantParked := fmt.Sprint(nsIno(7, 3)), fmt.Sprint(nsIno(7, 6))
	wantRows := []string{wantBig + "/user.late=v-late", wantParked + "/user.orphan=alive", wantParked + "/user.stay=on-parked"}
	if !reflect.DeepEqual(rowsA, wantRows) {
		t.Fatalf("xattr rows = %v, want %v (early attr removed, victim's reaped)", rowsA, wantRows)
	}

	// Allocator watermarks and recovery facts.
	if resA.NextLocal != resB.NextLocal || resA.MaxInoSeen != resB.MaxInoSeen {
		t.Fatalf("watermarks diverge: A={next %d max %#x} B={next %d max %#x}",
			resA.NextLocal, resA.MaxInoSeen, resB.NextLocal, resB.MaxInoSeen)
	}
	if resA.RootMaxInoSeen != resB.RootMaxInoSeen {
		// Root MaxInoSeen is an upper bound the format only proves as <=;
		// in this fixture the highest allocated inode survives, so the
		// bound is exact on both folds.
		t.Fatalf("root high-water diverges: A=%#x B=%#x", resA.RootMaxInoSeen, resB.RootMaxInoSeen)
	}
	recA, recB := decodeRecovery(t, spoolA, resA), decodeRecovery(t, spoolB, resB)
	if recA.AsOfSeq != recB.AsOfSeq || recA.InoNamespace != recB.InoNamespace || recA.NextLocal != recB.NextLocal {
		t.Fatalf("recovery facts diverge:\nA=%+v\nB=%+v", recA, recB)
	}

	// Spot-check the folded semantics landed (guards fixture rot).
	dir2 := userA[nsIno(7, 8)]
	if dir2.Dirents["to"] == "" || dir2.Dirents["hard"] == "" || dir2.Dirents["ln"] == "" {
		t.Fatalf("dir2 entries = %v", dir2.Dirents)
	}
	big := userA[nsIno(7, 3)]
	// AtimeMs proves the chtimes landed; the later truncate legitimately
	// re-stamps MtimeMs with its own record timestamp.
	if big.Nlink != 2 || big.Mode != 0o600 || big.Size != 100000 || big.AtimeMs != 9_001 {
		t.Fatalf("dir/big facts = %+v", big)
	}
	moved := userA[nsIno(7, 5)]
	if moved.UID != 7 || moved.GID != 8 {
		t.Fatalf("renamed file chown lost: %+v", moved)
	}
	if _, gone := userA[nsIno(7, 4)]; gone {
		t.Fatal("reaped victim still live in the filesystem index")
	}

	// Determinism: the checkpointed reduction reruns byte-identically
	// (the property crash-resume and idempotent upload rely on).
	rerun := &Materializer{
		Facts: facts, Journal: &fakeJournal{records: records}, Spool: NewSpool(),
		Limits: pft2.EditorLimits{MaxStagedCellBytes: checkpointCapBytes},
	}
	resC, err := rerun.Run(ctx)
	if err != nil {
		t.Fatalf("checkpointed rerun: %v", err)
	}
	if resC.Root != resB.Root || resC.RecoveryRoot != resB.RecoveryRoot {
		t.Fatal("checkpointed rerun produced different roots")
	}
	if !reflect.DeepEqual(resC.UserClosure, resB.UserClosure) ||
		!reflect.DeepEqual(resC.RecoveryClosure, resB.RecoveryClosure) {
		t.Fatal("checkpointed rerun produced different closures")
	}
}

// TestManagedFoldMaterializesBacklogBeyondStagedCap reproduces the
// production failure — the SAME backlog folded through one transaction
// trips ErrTransactionLimit on staged cell bytes — and proves the
// checkpointed materializer reduces it under the identical cap.
func TestManagedFoldMaterializesBacklogBeyondStagedCap(t *testing.T) {
	ctx := context.Background()
	var zero [32]byte
	entries, trees := checkpointBacklog(t)

	// Premise: one transaction cannot hold the backlog's staged cells.
	editor, err := pft2.NewEditor(ctx, nil, nil, pft2.EditorLimits{MaxStagedCellBytes: checkpointCapBytes})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := fstransition.New(fstransition.Config{Tx: editor})
	if err != nil {
		t.Fatal(err)
	}
	var foldErr error
	for i := range trees {
		if _, foldErr = engine.Apply(ctx, trees[i]); foldErr != nil {
			break
		}
	}
	if !errors.Is(foldErr, pft2.ErrTransactionLimit) {
		t.Fatalf("single-transaction fold under the cap returned %v, want ErrTransactionLimit", foldErr)
	}

	// The fix: the materializer checkpoints and the cut lands.
	records, cutDigest := encodeJournalEntries(t, zero, 0, entries)
	m := &Materializer{
		Facts:   managedFacts(hexDigest(zero), cutDigest, 0, uint64(len(records))),
		Journal: &fakeJournal{records: records},
		Spool:   NewSpool(),
		Limits:  pft2.EditorLimits{MaxStagedCellBytes: checkpointCapBytes},
	}
	res, err := m.Run(ctx)
	if err != nil {
		t.Fatalf("checkpointed materialization failed under the cap: %v", err)
	}
	user, _ := userSnapshot(t, m.Spool.(*Spool), res)
	big, big2 := user[nsIno(7, 3)], user[nsIno(7, 7)]
	if big.Size != 100000 || big.Nlink != 2 || big2.Size != 30000 {
		t.Fatalf("materialized facts: big=%+v big2=%+v", big, big2)
	}
	if res.OrphanIndex == nil {
		t.Fatal("surviving parked orphan missing")
	}
}
