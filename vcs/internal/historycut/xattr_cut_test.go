package historycut

// The managed persistence contract for extended attributes: live state
// folds through the shared transition engine and anchors both on the user
// Root (filesystem-homed rows) and RecoveryRoot (complete rows), so trimming,
// adoption, snapshots, and forks preserve the appropriate metadata without
// exposing orphan-only state.

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// decodeAnchorXattrs decodes the materialized RecoveryRoot and flattens its
// xattr leaves into "ino/name=value" rows.
func decodeAnchorXattrs(t *testing.T, spool *Spool, res *Result) ([]string, []pft2.Ref) {
	t.Helper()
	raw, ok := spool.Bytes(res.RecoveryRoot)
	if !ok {
		t.Fatal("recovery root missing from spool")
	}
	node, err := pft2.DecodeNodeKind(raw, pft2.KindRecoveryRoot)
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, leafRef := range node.RecoveryRoot.XattrLeaves {
		leafRaw, ok := spool.Bytes(leafRef)
		if !ok {
			t.Fatalf("xattr leaf %s missing from spool", leafRef)
		}
		leaf, err := pft2.DecodeNodeKind(leafRaw, pft2.KindXattrLeaf)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range leaf.XattrLeaf.Entries {
			rows = append(rows, strconv.FormatUint(e.Ino, 10)+"/"+e.Name+"="+string(e.Value))
		}
	}
	return rows, node.RecoveryRoot.XattrLeaves
}

func decodeUserXattrs(t *testing.T, spool *Spool, res *Result) ([]string, []pft2.Ref) {
	t.Helper()
	raw, ok := spool.Bytes(res.Root)
	if !ok {
		t.Fatal("filesystem root missing from spool")
	}
	node, err := pft2.DecodeNodeKind(raw, pft2.KindRoot)
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	for _, leafRef := range node.Root.XattrLeaves {
		leafRaw, ok := spool.Bytes(leafRef)
		if !ok {
			t.Fatalf("user xattr leaf %s missing from spool", leafRef)
		}
		leaf, err := pft2.DecodeNodeKind(leafRaw, pft2.KindXattrLeaf)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range leaf.XattrLeaf.Entries {
			rows = append(rows, strconv.FormatUint(e.Ino, 10)+"/"+e.Name+"="+string(e.Value))
		}
	}
	return rows, node.Root.XattrLeaves
}

// TestManagedCutAnchorsXattrsForRecoveryAndSnapshots: a cut whose journal
// carries xattrs places named-inode rows in both closures and drops a reaped
// inode's rows. Deterministic across reruns.
func TestManagedCutAnchorsXattrsForRecoveryAndSnapshots(t *testing.T) {
	var zero [32]byte
	keptIno, victimIno := nsIno(7, 2), nsIno(7, 3)
	payloads := encodeEntries(t, 0,
		wal.Record{Op: wal.OpCreate, Path: "kept", Mode: 0o644, Ino: keptIno, TsMs: 100},
		wal.Record{Op: wal.OpCreate, Path: "victim", Mode: 0o644, Ino: victimIno, TsMs: 101},
		wal.Record{Op: wal.OpSetxattr, Path: "kept", XattrName: "user.b", Data: []byte("vb"), TsMs: 102},
		wal.Record{Op: wal.OpSetxattr, Path: "kept", XattrName: "user.a", Data: []byte("v1"), TsMs: 103},
		wal.Record{Op: wal.OpSetxattr, Path: "kept", XattrName: "user.a", Data: []byte("v2"), TsMs: 104}, // overwrite
		wal.Record{Op: wal.OpSetxattr, Path: "victim", XattrName: "user.dies", Data: []byte("x"), TsMs: 105},
		wal.Record{Op: wal.OpSetxattr, Path: "kept", XattrName: "user.gone", Data: []byte("g"), TsMs: 106},
		wal.Record{Op: wal.OpRemovexattr, Path: "kept", XattrName: "user.gone", TsMs: 107},
		wal.Record{Op: wal.OpRemove, Path: "victim", TsMs: 108},
		wal.Record{Op: wal.OpReap, Ino: victimIno, TsMs: 109},
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

	rows, leafRefs := decodeAnchorXattrs(t, m.Spool.(*Spool), res)
	wantKept := strconv.FormatUint(keptIno, 10)
	if strings.Join(rows, ",") != wantKept+"/user.a=v2,"+wantKept+"/user.b=vb" {
		t.Fatalf("anchored xattr rows = %v", rows)
	}
	if len(leafRefs) == 0 {
		t.Fatal("cut with live xattrs anchored no xattr leaves")
	}
	// With no parked orphans the user and recovery projections share the
	// same content-addressed leaves.
	for _, ref := range leafRefs {
		digest := "sha256:" + ref.Hex()
		if !containsDigest(res.UserClosure, digest) {
			t.Fatalf("user closure misses xattr leaf %s", digest)
		}
		// RecoveryClosure is intentionally recovery-root reachability MINUS
		// UserClosure, so a content-addressed leaf shared by both projections
		// is accounted once on the user side.
	}

	// Determinism: identical inputs reproduce identical roots (crash-resume).
	m2 := &Materializer{Facts: m.Facts, Journal: &fakeJournal{records: records}, Spool: NewSpool()}
	res2, err := m2.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res2.Root != res.Root || res2.RecoveryRoot != res.RecoveryRoot {
		t.Fatal("rerun produced different roots")
	}
}

func TestManagedCutKeepsOrphanXattrsRecoveryOnly(t *testing.T) {
	var zero [32]byte
	namedIno, orphanIno := nsIno(7, 2), nsIno(7, 3)
	payloads := encodeEntries(t, 0,
		wal.Record{Op: wal.OpCreate, Path: "named", Mode: 0o644, Ino: namedIno, TsMs: 100},
		wal.Record{Op: wal.OpSetxattr, Path: "named", XattrName: "user.named", Data: []byte("visible"), TsMs: 101},
		wal.Record{Op: wal.OpCreate, Path: "temporary", Mode: 0o644, Ino: orphanIno, TsMs: 102},
		wal.Record{Op: wal.OpSetxattr, Path: "temporary", XattrName: "user.secret", Data: []byte("recovery"), TsMs: 103},
		wal.Record{Op: wal.OpOrphan, Path: "temporary", TsMs: 104},
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
	spool := m.Spool.(*Spool)
	userRows, userLeaves := decodeUserXattrs(t, spool, res)
	recoveryRows, recoveryLeaves := decodeAnchorXattrs(t, spool, res)
	wantNamed := strconv.FormatUint(namedIno, 10) + "/user.named=visible"
	wantRecovery := wantNamed + "," + strconv.FormatUint(orphanIno, 10) + "/user.secret=recovery"
	if strings.Join(userRows, ",") != wantNamed {
		t.Fatalf("user xattrs=%v, want named row only", userRows)
	}
	if strings.Join(recoveryRows, ",") != wantRecovery {
		t.Fatalf("recovery xattrs=%v, want %s", recoveryRows, wantRecovery)
	}
	for _, ref := range recoveryLeaves {
		if containsDigest(res.UserClosure, "sha256:"+ref.Hex()) {
			t.Fatalf("complete recovery xattr leaf %s leaked into user closure", ref)
		}
	}
	if len(userLeaves) == 0 || len(recoveryLeaves) == 0 {
		t.Fatal("expected both user and recovery xattr projections")
	}
}

// TestAdoptedCutAndForkPreserveBaseXattrs chains two cuts: an ADOPTED
// continuation seeds the base anchor's xattrs and folds the suffix records
// over them (survival across journal trimming), while a FORK of the same
// user root materializes from a spool holding ONLY the user closure, proving
// it preserves xattrs without fetching the source anchor.
func TestAdoptedCutAndForkPreserveBaseXattrs(t *testing.T) {
	var zero [32]byte
	keptIno := nsIno(7, 2)
	basePayloads := encodeEntries(t, 0,
		wal.Record{Op: wal.OpCreate, Path: "kept", Mode: 0o644, Ino: keptIno, TsMs: 100},
		wal.Record{Op: wal.OpSetxattr, Path: "kept", XattrName: "user.base", Data: []byte("from-base"), TsMs: 101},
		wal.Record{Op: wal.OpSetxattr, Path: "kept", XattrName: "user.doomed", Data: []byte("x"), TsMs: 102},
	)
	baseRecords, baseCutDigest := buildJournal(t, zero, 0, basePayloads)
	baseCut := &Materializer{
		Facts:   managedFacts(hexDigest(zero), baseCutDigest, 0, uint64(len(baseRecords))),
		Journal: &fakeJournal{records: baseRecords},
		Spool:   NewSpool(),
	}
	baseRes, err := baseCut.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	baseSpool := baseCut.Spool.(*Spool)
	anchorRaw, _ := baseSpool.Bytes(baseRes.RecoveryRoot)

	// ADOPTED continuation: the journal was trimmed to the base cut; the
	// suffix mutates the xattr state on top of the anchored rows.
	baseSeq := uint64(len(baseRecords))
	suffix := encodeEntries(t, baseSeq,
		wal.Record{Op: wal.OpSetxattr, Path: "kept", XattrName: "user.live", Data: []byte("from-suffix"), TsMs: 200},
		wal.Record{Op: wal.OpRemovexattr, Path: "kept", XattrName: "user.doomed", TsMs: 201},
	)
	var baseDigest32 [32]byte
	raw, err := parseHex32(baseCutDigest, "test base digest")
	if err != nil {
		t.Fatal(err)
	}
	baseDigest32 = raw
	suffixRecords, adoptDigest := buildJournal(t, baseDigest32, baseSeq, suffix)
	adoptFacts := managedFacts(baseCutDigest, adoptDigest, baseSeq, baseSeq+uint64(len(suffixRecords)))
	adoptFacts.BaseCommit = &BaseCommitFacts{
		CommitID: "c_base", CommitKind: "pft2", BaseMode: "adopted",
		RootDigest: baseRes.Root.Hex(), RootSize: strconv.FormatUint(baseRes.Root.Size, 10),
		MaxInoSeen:   strconv.FormatUint(baseRes.RootMaxInoSeen, 10),
		AnchorID:     "hanchor_base",
		RecoveryRoot: baseRes.RecoveryRoot.Hex(), RecoveryRootSize: strconv.Itoa(len(anchorRaw)),
		InodeNamespace: "7",
		NextLocal:      strconv.FormatUint(baseRes.NextLocal, 10),
	}
	adopt := &Materializer{Facts: adoptFacts, Journal: &fakeJournal{records: suffixRecords}, Spool: baseSpool}
	adoptRes, err := adopt.Run(context.Background())
	if err != nil {
		t.Fatalf("adopted cut: %v", err)
	}
	rows, _ := decodeAnchorXattrs(t, baseSpool, adoptRes)
	wantKept := strconv.FormatUint(keptIno, 10)
	if strings.Join(rows, ",") != wantKept+"/user.base=from-base,"+wantKept+"/user.live=from-suffix" {
		t.Fatalf("adopted anchored rows = %v", rows)
	}

	// FORK: only the user closure is available — the isolation proof. The
	// fork must succeed WITHOUT touching the anchor, while its own anchor
	// carries the root's filesystem-homed xattrs.
	userOnly := NewSpool()
	for _, ref := range baseSpool.Objects() {
		digest := "sha256:" + ref.Hex()
		if !containsDigest(baseRes.UserClosure, digest) {
			continue
		}
		data, _ := baseSpool.Bytes(ref)
		if err := userOnly.Seed(ref, data); err != nil {
			t.Fatal(err)
		}
	}
	forkPayloads := encodeEntries(t, 0,
		wal.Record{Op: wal.OpCreate, Path: "fresh", Mode: 0o644, Ino: nsIno(8, 1), TsMs: 300},
	)
	forkRecords, forkDigest := buildJournal(t, zero, 0, forkPayloads)
	forkFacts := CutFacts{
		CutID: "hcut_fork_x", Kind: "user", SourceKind: "managed_journal",
		GenerationID: "gen_fork_x", RecordCodec: "pfj3", ControlCodec: "pfc2",
		SourceBaseSeq: "0", SourceBaseDig: hexDigest(zero),
		CutSeqExclusive: strconv.Itoa(len(forkRecords)), CutDigest: forkDigest,
		InodeNamespace: "8",
		BaseCommit: &BaseCommitFacts{
			CommitID: "c_base", CommitKind: "pft2", BaseMode: "fork",
			RootDigest: baseRes.Root.Hex(), RootSize: strconv.FormatUint(baseRes.Root.Size, 10),
			MaxInoSeen:     strconv.FormatUint(baseRes.RootMaxInoSeen, 10),
			InodeNamespace: "7",
		},
	}
	fork := &Materializer{Facts: forkFacts, Journal: &fakeJournal{records: forkRecords}, Spool: userOnly}
	forkRes, err := fork.Run(context.Background())
	if err != nil {
		t.Fatalf("fork cut: %v", err)
	}
	forkRows, forkLeaves := decodeAnchorXattrs(t, userOnly, forkRes)
	wantFork := wantKept + "/user.base=from-base," + wantKept + "/user.doomed=x"
	if strings.Join(forkRows, ",") != wantFork || len(forkLeaves) == 0 {
		t.Fatalf("fork xattr state: rows=%v leaves=%d, want %s", forkRows, len(forkLeaves), wantFork)
	}
}
