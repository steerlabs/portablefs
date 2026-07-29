package histworker

import (
	"context"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/historycut"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// buildChainedCut continues base's journal with two more records and
// freezes the cut tuple exactly as pfh.cut_create captures a chained cut:
// source base = the ready base cut's (result commit, boundary, digest),
// baseMode adopted with the published anchor facts.
func buildChainedCut(t *testing.T, tenant, cutID string, base *fakeCut) *fakeCut {
	t.Helper()
	in := base.readyInput
	if base.state != "ready" || in == nil {
		t.Fatal("chained cut requires a ready base cut")
	}
	baseSeq, err := strconv.ParseUint(base.facts.CutSeqExclusive, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	nextIno := uint64(7)<<32 | uint64(in.NextLocal)
	var payloads [][]byte
	for i, rec := range []wal.Record{
		{Op: wal.OpCreate, Path: "docs/c.txt", Mode: 0o644, Ino: nextIno, TsMs: 66},
		{Op: wal.OpWrite, Path: "docs/c.txt", Data: []byte("chained delta"), TsMs: 77},
	} {
		rec.Seq = baseSeq + uint64(i)
		entry := pfj3.JournalEntry{LSN: rec.Seq, Tree: &rec}
		payload, err := pfj3.Encode(&entry)
		if err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, payload)
	}
	raw, err := hex.DecodeString(base.facts.CutDigest)
	if err != nil || len(raw) != 32 {
		t.Fatalf("base cut digest %q", base.facts.CutDigest)
	}
	var chain [32]byte
	copy(chain[:], raw)
	var records []historycut.PageRecord
	for i, payload := range payloads {
		chain = historycut.ChainStep(chain, payload)
		records = append(records, historycut.PageRecord{
			Seq:         baseSeq + uint64(i),
			Payload:     payload,
			RecordHash:  hexOf(historycut.RecordHash(payload)),
			ChainDigest: hexOf(chain),
		})
	}
	return &fakeCut{
		tenant: tenant,
		facts: historycut.CutFacts{
			CutID: cutID, Kind: "recovery", SourceKind: "managed_journal",
			GenerationID: "gen_1", RecordCodec: "pfj3", ControlCodec: "pfc2",
			SourceBaseSeq: base.facts.CutSeqExclusive,
			SourceBaseDig: base.facts.CutDigest,
			CutSeqExclusive: strconv.FormatUint(baseSeq+uint64(len(records)), 10),
			CutDigest:       hexOf(chain),
			InodeNamespace:  "7",
			NamespaceNext:   strconv.FormatInt(in.NextLocal, 10),
			BaseCommit: &historycut.BaseCommitFacts{
				CommitID:         base.commitID,
				CommitKind:       "pft2",
				BaseMode:         "adopted",
				TreeHash:         "pft2:" + in.RootDigestHex,
				RootDigest:       in.RootDigestHex,
				RootSize:         strconv.FormatInt(in.RootSize, 10),
				MaxInoSeen:       strconv.FormatInt(in.RootMaxInoSeen, 10),
				RecoveryRoot:     in.RecoveryRootDigestHex,
				RecoveryRootSize: strconv.FormatInt(in.RecoveryRootSize, 10),
				InodeNamespace:   "7",
				NextLocal:        strconv.FormatInt(in.NextLocal, 10),
			},
		},
		journal: records,
	}
}

// The exact-closure refresh slice is a stable pure function of the frozen
// cut digest: retries agree, roughly one cut in sixteen refreshes, and
// digest-less (legacy) tuples conservatively publish exact.
func TestExactClosureRefreshIsDeterministicSlice(t *testing.T) {
	if !exactClosureRefresh("") || !exactClosureRefresh("zz") {
		t.Fatal("absent/undecodable digests must select the exact form")
	}
	if !exactClosureRefresh("0f" + strings.Repeat("00", 31)) {
		t.Fatal("a zero first nibble selects the exact refresh")
	}
	if exactClosureRefresh("10" + strings.Repeat("00", 31)) {
		t.Fatal("a nonzero first nibble keeps the delta form")
	}
	exact := 0
	for b := 0; b < 256; b++ {
		if exactClosureRefresh(hex.EncodeToString([]byte{byte(b)})) {
			exact++
		}
	}
	if exact != 16 {
		t.Fatalf("%d of 256 first bytes select exact; want the 1-in-16 slice", exact)
	}
}

// A chained cut folds only the tail since the base cut and publishes
// O(delta): the run uploads/registers only the objects it produced, the
// base cut's closure rows are copied server-side, and the published tree
// serves both the reused and the new content.
func TestChainedCutMaterializesAndPublishesDelta(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	base := buildManagedCut(t, "tenant-chain", "hcut_chain_base")
	r.repo.addCut(base)
	if n := r.repo.mustRunCuts(t, ctx, r.worker); n != 1 {
		t.Fatalf("claimed %d cuts", n)
	}
	if base.state != "ready" {
		t.Fatalf("base cut state %s (err %s)", base.state, base.lastError)
	}

	chained := buildChainedCut(t, "tenant-chain", "hcut_chain_next", base)
	r.repo.addCut(chained)
	r.repo.mu.Lock()
	copiesBefore := len(r.repo.copies)
	locateSinglesBefore := r.repo.callsLocate
	r.repo.mu.Unlock()
	if n := r.repo.mustRunCuts(t, ctx, r.worker); n != 1 {
		t.Fatalf("claimed %d cuts", n)
	}
	if chained.state != "ready" || chained.opSettled != "succeeded" {
		t.Fatalf("chained cut state %s / op %s (err %s)", chained.state, chained.opSettled, chained.lastError)
	}

	// The registered closure is a superset of the base cut's rows (copied
	// server-side), and the published counts equal the registered rows.
	for _, closure := range []string{"user", "recovery"} {
		for digest := range base.closures[closure] {
			if !chained.closures[closure][digest] {
				t.Fatalf("%s closure lost base row %s", closure, digest)
			}
		}
	}
	in := chained.readyInput
	if int(in.UserObjectCount) != len(chained.closures["user"]) ||
		int(in.RecoveryObjectCount) != len(chained.closures["recovery"]) {
		t.Fatalf("published counts %d/%d vs rows %d/%d",
			in.UserObjectCount, in.RecoveryObjectCount,
			len(chained.closures["user"]), len(chained.closures["recovery"]))
	}

	// O(delta): the run wrote copies only for objects it produced — far
	// fewer than the registered closure — and its publish walked no
	// per-object locate storm (batch locates only).
	r.repo.mu.Lock()
	newObjects := (len(r.repo.copies) - copiesBefore) / 2 // two domains
	locateSingles := r.repo.callsLocate - locateSinglesBefore
	r.repo.mu.Unlock()
	full := len(chained.closures["user"]) + len(chained.closures["recovery"])
	if newObjects >= full/2 {
		t.Fatalf("chained run uploaded %d objects against a %d-object closure; publish is not O(delta)", newObjects, full)
	}
	if int(locateSingles) >= full {
		t.Fatalf("publish issued %d single locates against a %d-object closure", locateSingles, full)
	}

	// The published root serves the reused and the new content through
	// located exact-key reads.
	rootRef := refOf(t, in.RootDigestHex, uint64(in.RootSize))
	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{
		Fetcher: &locateFetcher{t: t, ctx: ctx, repo: r.repo, stores: r.stores, tenant: "tenant-chain"},
	}, rootRef)
	if err != nil {
		t.Fatal(err)
	}
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
	if _, err := reader.Lookup(ctx, docsView.Ref, "a.txt"); err != nil {
		t.Fatalf("reused a.txt: %v", err)
	}
	if _, err := reader.Lookup(ctx, docsView.Ref, "c.txt"); err != nil {
		t.Fatalf("chained c.txt: %v", err)
	}
}
