package remotejournal

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/ctlrec"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

func exactU(value uint64) *decimalUint64 {
	exact := decimalUint64(value)
	return &exact
}

func exactI(value int64) *decimalInt64 {
	exact := decimalInt64(value)
	return &exact
}

func boolPointer(value bool) *bool { return &value }

func validationLog() *Log {
	return &Log{
		cfg: Config{
			TenantID: "tenant-1", VolumeID: "volume-1", Branch: "main",
			AttachSessionID: "session-1", LeaseID: "lease-1", FencingToken: 9,
			HolderID: "holder-1", AuthorityInstanceID: "authority-1",
			AuthorityRuntimeID: "runtime-1",
		},
		managerEpoch: 3,
		runtimeSeq:   5,
		poisonedCh:   make(chan struct{}),
	}
}

func validWriterHead(nextSeq uint64) generationJSON {
	zero := strings.Repeat("0", 64)
	tip := zero
	if nextSeq > 0 {
		tip = strings.Repeat("1", 64)
	}
	return generationJSON{
		GenerationID: "jgen-1", TenantID: "tenant-1", VolumeID: "volume-1",
		BranchID: "branch-1", BranchName: "main", Epoch: exactU(1),
		RecordCodec: wal.PFR1Codec, ControlCodec: ctlrec.PFC1Codec,
		BaseCommitID: "commit-before", BaseSeq: exactU(0), BaseDigest: zero,
		NextSeq: exactU(nextSeq), TipDigest: tip, PhysicalTrimmedSeq: exactU(0),
		Status: "active", BacklogBytes: exactI(int64(nextSeq * 10)),
		BacklogRecords: exactI(int64(nextSeq)), QuotaBacklogBytes: exactI(1000),
		QuotaBacklogRecords: exactI(100), WriterFence: exactI(9),
		AttachSessionID: "session-1", LeaseID: "lease-1", HolderID: "holder-1",
		AuthorityInstanceID: "authority-1", ManagerEpoch: exactI(3),
		AuthorityRuntimeSeq: exactI(5), AuthorityRuntimeID: "runtime-1",
		ClaimedAt: exactI(10), UpdatedAt: exactI(11), Current: boolPointer(true),
	}
}

func TestAdoptHeadRejectsMalformedOrCrossScopeSnapshots(t *testing.T) {
	canonical := "sha256:" + strings.Repeat("a", 64)
	tests := []struct {
		name   string
		mutate func(*generationJSON)
	}{
		{"tenant", func(h *generationJSON) { h.TenantID = "tenant-2" }},
		{"branch-name", func(h *generationJSON) { h.BranchName = "other" }},
		{"branch-id", func(h *generationJSON) { h.BranchID = "" }},
		{"missing-base-seq", func(h *generationJSON) { h.BaseSeq = nil }},
		{"trim-ahead-of-base", func(h *generationJSON) { h.PhysicalTrimmedSeq = exactU(1) }},
		{"record-accounting", func(h *generationJSON) { h.BacklogRecords = exactI(1) }},
		{"zero-quota", func(h *generationJSON) { h.QuotaBacklogBytes = exactI(0) }},
		{"holder", func(h *generationJSON) { h.HolderID = "other" }},
		{"runtime", func(h *generationJSON) { h.AuthorityRuntimeID = "other" }},
		{"manager-epoch-missing", func(h *generationJSON) { h.ManagerEpoch = nil }},
		{"digest", func(h *generationJSON) { h.BaseDigest = "AA" + strings.Repeat("0", 62) }},
		{"retired", func(h *generationJSON) { h.Status = "retired" }},
		{"cut-digest", func(h *generationJSON) {
			h.Cut = &cutJSON{
				OperationID: "cut-1", Epoch: exactU(1), Status: "prepared", Watermark: exactU(0),
				ExpectedHeadCommitID: "commit-before", TreeHash: "sha256:bad",
				CanonicalRequestHash: canonical,
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l := validationLog()
			head := validWriterHead(0)
			test.mutate(&head)
			if err := l.adoptHead(&head, true); err == nil {
				t.Fatal("accepted malformed generation snapshot")
			}
			if l.generationID != "" || l.nextSeq != 0 || l.baseCommitID != "" {
				t.Fatalf("rejected snapshot mutated mirrors: %+v", l)
			}
		})
	}
}

func TestAdoptHeadRequiresExpectedBaseCommit(t *testing.T) {
	l := validationLog()
	l.cfg.ExpectedBaseCommitID = "commit-expected"
	head := validWriterHead(0)
	if err := l.adoptHead(&head, true); err == nil {
		t.Fatal("accepted claim snapshot with unexpected base commit")
	}
}

func TestApplyGenerationRejectsMalformedTransitionsWithoutMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*generationJSON)
	}{
		{"generation", func(h *generationJSON) { h.GenerationID = "jgen-other" }},
		{"head", func(h *generationJSON) { h.NextSeq = exactU(3) }},
		{"quota", func(h *generationJSON) { h.QuotaBacklogBytes = exactI(2000) }},
		{"base-accounting", func(h *generationJSON) { h.BaseSeq = exactU(1) }},
		{"writer", func(h *generationJSON) { h.AuthorityInstanceID = "authority-other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			l := validationLog()
			initial := validWriterHead(2)
			if err := l.adoptHead(&initial, true); err != nil {
				t.Fatalf("adopt initial: %v", err)
			}
			next := validWriterHead(2)
			test.mutate(&next)
			raw, err := json.Marshal(next)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := l.applyGeneration(raw); err == nil {
				t.Fatal("accepted malformed generation transition")
			}
			if l.baseSeq != 0 || l.baseCommitID != "commit-before" || l.backlogRecords != 2 {
				t.Fatalf("rejected transition mutated mirrors: base=%d commit=%s records=%d",
					l.baseSeq, l.baseCommitID, l.backlogRecords)
			}
		})
	}
}

func TestApplyGenerationAcceptsProofCarryingBaseAdvance(t *testing.T) {
	l := validationLog()
	initial := validWriterHead(2)
	if err := l.adoptHead(&initial, true); err != nil {
		t.Fatalf("adopt initial: %v", err)
	}
	next := validWriterHead(2)
	next.BaseSeq = exactU(1)
	next.BaseDigest = strings.Repeat("2", 64)
	next.BaseCommitID = "commit-after"
	next.BacklogBytes = exactI(10)
	next.BacklogRecords = exactI(1)
	digest := "sha256:" + strings.Repeat("d", 64)
	next.Cut = &cutJSON{
		OperationID: "cut-1", Epoch: exactU(1), Status: "finalized", Watermark: exactU(1),
		ExpectedHeadCommitID: "commit-before", TreeHash: digest,
		CanonicalRequestHash: digest, CommitID: "commit-after",
	}
	raw, err := json.Marshal(next)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := l.applyGeneration(raw); err != nil {
		t.Fatalf("apply proof-carrying trim: %v", err)
	}
	if l.baseSeq != 1 || l.baseCommitID != "commit-after" || l.backlogRecords != 1 ||
		!l.hasCut || l.cut.Status != wal.CheckpointFinalized {
		t.Fatalf("base advance not installed: base=%d commit=%s records=%d cut=%+v",
			l.baseSeq, l.baseCommitID, l.backlogRecords, l.cut)
	}
}

func adoptionProofJSON(oldBaseSeq, newBaseSeq uint64, oldDigest, newDigest, newCommit string) *adoptionJSON {
	return &adoptionJSON{
		AdoptionID: "hadopt_1", GenerationID: "jgen-1", CutID: "hcut_1",
		AnchorID: "hanchor_1", OperationID: "hadopt-hcut_1", State: "applied",
		OldBaseSeq: exactU(oldBaseSeq), OldBaseDigest: oldDigest,
		NewBaseSeq: exactU(newBaseSeq), NewBaseDigest: newDigest, NewBaseCommitID: newCommit,
		SubtractBacklogBytes: exactI(10), SubtractBacklogRecords: exactI(1),
		CutState: "ready", CutKind: "recovery",
		CutSeqExclusive: exactU(newBaseSeq), CutDigest: newDigest, CutResultCommitID: newCommit,
	}
}

// TestApplyGenerationAcceptsAdoptionProofCarryingBaseAdvance covers the OTHER
// lane that validates the same transition: the generation snapshot returned by
// trim/rotate/suspend. It read the same legacy-cut-only proof and would fence a
// detaching writer whose branch had adopted since its last append.
func TestApplyGenerationAcceptsAdoptionProofCarryingBaseAdvance(t *testing.T) {
	l := validationLog()
	initial := validWriterHead(2)
	if err := l.adoptHead(&initial, true); err != nil {
		t.Fatalf("adopt initial: %v", err)
	}
	next := validWriterHead(2)
	next.BaseSeq = exactU(1)
	next.BaseDigest = strings.Repeat("2", 64)
	next.BaseCommitID = "cpft2-after-adoption"
	next.BacklogBytes = exactI(10)
	next.BacklogRecords = exactI(1)
	next.Adoption = adoptionProofJSON(
		0, 1, strings.Repeat("0", 64), strings.Repeat("2", 64), "cpft2-after-adoption")
	raw, err := json.Marshal(next)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := l.applyGeneration(raw); err != nil {
		t.Fatalf("apply adoption-proof-carrying base advance: %v", err)
	}
	if l.baseSeq != 1 || l.baseCommitID != "cpft2-after-adoption" || l.backlogRecords != 1 || l.hasCut {
		t.Fatalf("adoption base advance not installed: base=%d commit=%s records=%d hasCut=%v",
			l.baseSeq, l.baseCommitID, l.backlogRecords, l.hasCut)
	}
}

// TestAdoptionProofNeverReachesBehindTheLocalBase pins the one clause that
// keeps a real, correctly-formed adoption row from being replayed to authorize
// an advance the child has already moved past. A proof may skip links (several
// adoptions can land between two calls, each independently row-authorized), but
// it may never start from a base older than the one the child already holds.
func TestAdoptionProofNeverReachesBehindTheLocalBase(t *testing.T) {
	digest := [32]byte{2}
	proof := adoptionProof{
		newBaseSeq: 9, newBaseDigest: digest, newBaseCommitID: "cpft2-9",
		oldBaseSeq: 4,
	}
	if !proof.provesBaseAdvance(4, 9, digest, "cpft2-9") {
		t.Fatal("an exact-chain proof was rejected")
	}
	if !proof.provesBaseAdvance(2, 9, digest, "cpft2-9") {
		t.Fatal("a proof that skipped an intermediate adoption was rejected")
	}
	if proof.provesBaseAdvance(5, 9, digest, "cpft2-9") {
		t.Fatal("a proof reaching back behind the local base was accepted")
	}
	if proof.provesBaseAdvance(4, 9, [32]byte{3}, "cpft2-9") {
		t.Fatal("a proof for another base digest was accepted")
	}
	if proof.provesBaseAdvance(4, 10, digest, "cpft2-9") {
		t.Fatal("a proof for another base seq was accepted")
	}
}
