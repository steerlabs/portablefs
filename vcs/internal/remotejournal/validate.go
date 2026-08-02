package remotejournal

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// validatedGeneration is the checked, exactly decoded form of a database
// generation snapshot. Raw JSON is never allowed to mutate Log mirrors.
type validatedGeneration struct {
	epoch              uint64
	baseSeq            uint64
	baseDigest         [32]byte
	nextSeq            uint64
	tipDigest          [32]byte
	physicalTrimmedSeq uint64
	backlogBytes       int64
	backlogRecords     int64
	quotaBytes         int64
	quotaRecords       int64
	cut                wal.CheckpointCut
	hasCut             bool
	adoption           adoptionProof
	hasAdoption        bool
}

// adoptionProof is the checked, exactly decoded form of pfj.adoption_proof_json
// — the modern (PFJ3) authorization for a destructive base advance.
type adoptionProof struct {
	adoptionID      string
	generationID    string
	cutID           string
	state           string
	oldBaseSeq      uint64
	oldBaseDigest   [32]byte
	newBaseSeq      uint64
	newBaseDigest   [32]byte
	newBaseCommitID string
	cutState        string
	cutSeqExclusive uint64
	cutDigest       [32]byte
	cutCommitID     string
}

func canonicalHexDigest(value string) ([32]byte, bool) {
	digest, err := decodeDigest(value)
	return digest, err == nil && hex.EncodeToString(digest[:]) == value
}

func canonicalSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, ok := canonicalHexDigest(strings.TrimPrefix(value, "sha256:"))
	return ok
}

func validateCutJSON(raw *cutJSON, epoch, nextSeq uint64) (wal.CheckpointCut, error) {
	if raw == nil {
		return wal.CheckpointCut{}, fmt.Errorf("remotejournal: nil checkpoint cut")
	}
	if raw.Epoch == nil || raw.Watermark == nil || raw.OperationID == "" || len(raw.OperationID) > 256 ||
		raw.ExpectedHeadCommitID == "" || len(raw.ExpectedHeadCommitID) > 512 {
		return wal.CheckpointCut{}, fmt.Errorf("remotejournal: checkpoint cut is missing bounded identity/revision fields")
	}
	cut := wal.CheckpointCut{
		OperationID:              raw.OperationID,
		Epoch:                    uint64(*raw.Epoch),
		Watermark:                uint64(*raw.Watermark),
		ExpectedHeadCommitID:     raw.ExpectedHeadCommitID,
		TreeHash:                 raw.TreeHash,
		CanonicalRequestHash:     raw.CanonicalRequestHash,
		AuxiliaryBlobDigestsHash: raw.AuxiliaryBlobDigestsHash,
		Status:                   wal.CheckpointCutStatus(raw.Status),
		CommitID:                 raw.CommitID,
	}
	if cut.Epoch != epoch || cut.Watermark > nextSeq {
		return wal.CheckpointCut{}, fmt.Errorf("remotejournal: checkpoint cut revision is outside generation epoch/head")
	}
	if _, err := checkedSQLBigint("checkpoint watermark", cut.Watermark); err != nil {
		return wal.CheckpointCut{}, err
	}
	if !canonicalSHA256Digest(cut.TreeHash) || !canonicalSHA256Digest(cut.CanonicalRequestHash) ||
		(cut.AuxiliaryBlobDigestsHash != "" && !canonicalSHA256Digest(cut.AuxiliaryBlobDigestsHash)) {
		return wal.CheckpointCut{}, fmt.Errorf("remotejournal: checkpoint cut contains a non-canonical sha256 digest")
	}
	switch cut.Status {
	case wal.CheckpointPrepared:
		if cut.CommitID != "" {
			return wal.CheckpointCut{}, fmt.Errorf("remotejournal: prepared checkpoint cut carries a commit id")
		}
	case wal.CheckpointLanded, wal.CheckpointFinalized:
		if cut.CommitID == "" || len(cut.CommitID) > 512 {
			return wal.CheckpointCut{}, fmt.Errorf("remotejournal: landed checkpoint cut is missing a bounded commit id")
		}
	case wal.CheckpointAborted:
		if cut.CommitID != "" {
			return wal.CheckpointCut{}, fmt.Errorf("remotejournal: aborted checkpoint cut carries a commit id")
		}
	default:
		return wal.CheckpointCut{}, fmt.Errorf("remotejournal: checkpoint cut has invalid status %q", cut.Status)
	}
	return cut, nil
}

// adoptionStateIsLanded reports the two states in which the database has
// ALREADY durably advanced the base behind this row. 'applying' is what the
// freeze trigger itself matches on (the row is inserted, the base moves, and
// the row flips to 'applied' in ONE transaction), so both are equally landed
// from any reader's perspective; 'applying' is simply the state the trigger
// sees. Anything else — 'failed', or a shape this client does not know — is
// not a landing and authorizes nothing.
func adoptionStateIsLanded(state string) bool {
	return state == "applied" || state == "applying"
}

// validateAdoptionJSON decodes and self-checks a base-advance proof. It never
// consults the local mirror — that comparison belongs to the transition
// checks, which know what the child already holds.
func validateAdoptionJSON(raw *adoptionJSON, generationID string) (adoptionProof, error) {
	if raw == nil {
		return adoptionProof{}, fmt.Errorf("remotejournal: nil adoption proof")
	}
	if raw.OldBaseSeq == nil || raw.NewBaseSeq == nil || raw.CutSeqExclusive == nil ||
		raw.SubtractBacklogBytes == nil || raw.SubtractBacklogRecords == nil {
		return adoptionProof{}, fmt.Errorf("remotejournal: adoption proof is missing exact integer fields")
	}
	if raw.AdoptionID == "" || len(raw.AdoptionID) > 512 ||
		raw.CutID == "" || len(raw.CutID) > 512 ||
		raw.NewBaseCommitID == "" || len(raw.NewBaseCommitID) > 512 ||
		raw.CutResultCommitID == "" || len(raw.CutResultCommitID) > 512 {
		return adoptionProof{}, fmt.Errorf("remotejournal: adoption proof is missing bounded identity fields")
	}
	if raw.GenerationID != generationID {
		return adoptionProof{}, fmt.Errorf("%w: adoption proof belongs to generation %q, not %q",
			ErrConflict, raw.GenerationID, generationID)
	}
	if !adoptionStateIsLanded(raw.State) {
		return adoptionProof{}, fmt.Errorf("remotejournal: adoption proof has non-landed state %q", raw.State)
	}
	// A base advance may only be adopted from a MATERIALIZED cut. 'ready' is
	// the one terminal success state of pfh.history_cuts; every other state is
	// either still running or terminal-failed, and neither covers the prefix
	// the advance is about to make deletable.
	if raw.CutState != "ready" {
		return adoptionProof{}, fmt.Errorf("remotejournal: adoption proof cites a %q cut, not a ready one", raw.CutState)
	}
	oldDigest, oldOK := canonicalHexDigest(raw.OldBaseDigest)
	newDigest, newOK := canonicalHexDigest(raw.NewBaseDigest)
	cutDigest, cutOK := canonicalHexDigest(raw.CutDigest)
	if !oldOK || !newOK || !cutOK {
		return adoptionProof{}, fmt.Errorf("remotejournal: adoption proof carries a non-canonical digest")
	}
	proof := adoptionProof{
		adoptionID:      raw.AdoptionID,
		generationID:    raw.GenerationID,
		cutID:           raw.CutID,
		state:           raw.State,
		oldBaseSeq:      uint64(*raw.OldBaseSeq),
		oldBaseDigest:   oldDigest,
		newBaseSeq:      uint64(*raw.NewBaseSeq),
		newBaseDigest:   newDigest,
		newBaseCommitID: raw.NewBaseCommitID,
		cutState:        raw.CutState,
		cutSeqExclusive: uint64(*raw.CutSeqExclusive),
		cutDigest:       cutDigest,
		cutCommitID:     raw.CutResultCommitID,
	}
	if proof.newBaseSeq < proof.oldBaseSeq {
		return adoptionProof{}, fmt.Errorf("remotejournal: adoption proof regresses the base (%d -> %d)",
			proof.oldBaseSeq, proof.newBaseSeq)
	}
	if _, err := checkedSQLBigint("adoption new base sequence", proof.newBaseSeq); err != nil {
		return adoptionProof{}, err
	}
	// THE PROOF'S OWN INTERNAL BINDING. The adoption row says "the base is now
	// X"; the cut row says "the prefix ending at X was materialized into commit
	// C with chain digest D". If those two disagree the row pair proves nothing
	// at all, whatever the server asserts separately.
	if proof.cutSeqExclusive != proof.newBaseSeq || proof.cutDigest != proof.newBaseDigest ||
		proof.cutCommitID != proof.newBaseCommitID {
		return adoptionProof{}, fmt.Errorf(
			"%w: adoption proof and its cut disagree (cut %d/%s vs base %d/%s)",
			ErrProofMissing, proof.cutSeqExclusive, proof.cutCommitID, proof.newBaseSeq, proof.newBaseCommitID)
	}
	if int64(*raw.SubtractBacklogBytes) < 0 || int64(*raw.SubtractBacklogRecords) < 0 {
		return adoptionProof{}, fmt.Errorf("remotejournal: adoption proof carries a negative backlog subtraction")
	}
	return proof, nil
}

// provesBaseAdvance reports whether this proof authorizes moving a local base
// at haveSeq to the reported (wantSeq, wantDigest, wantCommitID).
//
// It deliberately does NOT require the proof to chain to the child's exact old
// base: several adoptions may land between two of this writer's calls, and each
// link was independently authorized by its own row under the freeze trigger.
// What it does require is that the proof attests EXACTLY the tuple being
// installed and that it never reaches back behind what the child already holds.
func (p adoptionProof) provesBaseAdvance(
	haveSeq uint64, wantSeq uint64, wantDigest [32]byte, wantCommitID string,
) bool {
	return p.newBaseSeq == wantSeq && p.newBaseDigest == wantDigest &&
		p.newBaseCommitID == wantCommitID && p.oldBaseSeq >= haveSeq
}

func (l *Log) validateGenerationSnapshot(head *generationJSON, asWriter bool) (validatedGeneration, error) {
	if head == nil {
		return validatedGeneration{}, fmt.Errorf("remotejournal: nil generation snapshot")
	}
	if head.Epoch == nil || head.BaseSeq == nil || head.NextSeq == nil || head.PhysicalTrimmedSeq == nil ||
		head.BacklogBytes == nil || head.BacklogRecords == nil || head.QuotaBacklogBytes == nil ||
		head.QuotaBacklogRecords == nil || head.ClaimedAt == nil || head.UpdatedAt == nil {
		return validatedGeneration{}, fmt.Errorf("remotejournal: generation snapshot is missing exact integer fields")
	}
	if head.GenerationID == "" || len(head.GenerationID) > 512 || head.BranchID == "" || len(head.BranchID) > 512 ||
		head.BaseCommitID == "" || len(head.BaseCommitID) > 512 || head.Status == "" {
		return validatedGeneration{}, fmt.Errorf("remotejournal: generation snapshot is missing bounded identity/status fields")
	}
	if head.TenantID != l.cfg.TenantID || head.VolumeID != l.cfg.VolumeID || head.BranchName != l.cfg.Branch {
		return validatedGeneration{}, fmt.Errorf("%w: generation snapshot belongs to another tenant/volume/branch", ErrConflict)
	}
	if l.generationID != "" && head.GenerationID != l.generationID {
		return validatedGeneration{}, fmt.Errorf("%w: generation identity changed", ErrConflict)
	}
	if l.branchID != "" && head.BranchID != l.branchID {
		return validatedGeneration{}, fmt.Errorf("%w: branch identity changed", ErrConflict)
	}
	wantRecord, wantControl := l.codecPair()
	if head.RecordCodec != wantRecord || head.ControlCodec != wantControl {
		return validatedGeneration{}, fmt.Errorf("%w: generation declares %s/%s; authority speaks %s/%s",
			ErrCodec, head.RecordCodec, head.ControlCodec, wantRecord, wantControl)
	}
	epoch := uint64(*head.Epoch)
	baseSeq := uint64(*head.BaseSeq)
	nextSeq := uint64(*head.NextSeq)
	physicalTrimmedSeq := uint64(*head.PhysicalTrimmedSeq)
	if epoch == 0 {
		return validatedGeneration{}, fmt.Errorf("remotejournal: generation epoch must be positive")
	}
	for name, value := range map[string]uint64{
		"journal epoch": epoch, "base sequence": baseSeq, "next sequence": nextSeq,
		"physical trimmed sequence": physicalTrimmedSeq,
	} {
		if _, err := checkedSQLBigint(name, value); err != nil {
			return validatedGeneration{}, err
		}
	}
	if physicalTrimmedSeq > baseSeq || baseSeq > nextSeq {
		return validatedGeneration{}, fmt.Errorf("remotejournal: malformed generation trim/base/head %d/%d/%d",
			physicalTrimmedSeq, baseSeq, nextSeq)
	}
	baseDigest, baseOK := canonicalHexDigest(head.BaseDigest)
	tipDigest, tipOK := canonicalHexDigest(head.TipDigest)
	if !baseOK || !tipOK || (baseSeq == nextSeq && baseDigest != tipDigest) {
		return validatedGeneration{}, fmt.Errorf("remotejournal: generation carries a malformed or inconsistent digest anchor")
	}
	backlogBytes := int64(*head.BacklogBytes)
	backlogRecords := int64(*head.BacklogRecords)
	quotaBytes := int64(*head.QuotaBacklogBytes)
	quotaRecords := int64(*head.QuotaBacklogRecords)
	span := nextSeq - baseSeq
	if span > math.MaxInt64 || backlogRecords != int64(span) || quotaBytes <= 0 || quotaRecords <= 0 ||
		backlogBytes > quotaBytes+ControlReserveBytes || backlogRecords > quotaRecords+ControlReserveRecords {
		return validatedGeneration{}, fmt.Errorf("%w: generation backlog/quota accounting is inconsistent", ErrAccounting)
	}
	if int64(*head.ClaimedAt) <= 0 || int64(*head.UpdatedAt) <= 0 {
		return validatedGeneration{}, fmt.Errorf("remotejournal: generation timestamps must be positive")
	}
	switch head.Status {
	case "active", "suspended", "retiring":
	default:
		return validatedGeneration{}, fmt.Errorf("remotejournal: generation snapshot has non-live status %q", head.Status)
	}
	if asWriter {
		if head.Status != "active" || head.WriterFence == nil || int64(*head.WriterFence) != l.cfg.FencingToken ||
			head.AttachSessionID != l.cfg.AttachSessionID || head.LeaseID != l.cfg.LeaseID ||
			head.HolderID != l.cfg.HolderID || head.AuthorityInstanceID != l.cfg.AuthorityInstanceID ||
			head.ManagerEpoch == nil || int64(*head.ManagerEpoch) != l.managerEpoch ||
			head.AuthorityRuntimeSeq == nil || int64(*head.AuthorityRuntimeSeq) != l.runtimeSeq ||
			head.AuthorityRuntimeID != l.cfg.AuthorityRuntimeID {
			return validatedGeneration{}, fmt.Errorf("%w: generation snapshot is bound to another writer/runtime", ErrFenced)
		}
		if head.WriterLeaseLive != nil && !*head.WriterLeaseLive {
			return validatedGeneration{}, fmt.Errorf("%w: writer lease is not live at database time", ErrFenced)
		}
	}
	validated := validatedGeneration{
		epoch: epoch, baseSeq: baseSeq, baseDigest: baseDigest, nextSeq: nextSeq, tipDigest: tipDigest,
		physicalTrimmedSeq: physicalTrimmedSeq, backlogBytes: backlogBytes, backlogRecords: backlogRecords,
		quotaBytes: quotaBytes, quotaRecords: quotaRecords,
	}
	if head.Cut != nil {
		cut, err := validateCutJSON(head.Cut, epoch, nextSeq)
		if err != nil {
			return validatedGeneration{}, err
		}
		validated.cut, validated.hasCut = cut, true
	}
	if head.Adoption != nil {
		proof, err := validateAdoptionJSON(head.Adoption, head.GenerationID)
		if err != nil {
			return validatedGeneration{}, err
		}
		validated.adoption, validated.hasAdoption = proof, true
	}
	return validated, nil
}

func checkpointStatusRank(status wal.CheckpointCutStatus) int {
	switch status {
	case wal.CheckpointPrepared:
		return 1
	case wal.CheckpointLanded, wal.CheckpointAborted:
		return 2
	case wal.CheckpointFinalized:
		return 3
	default:
		return 0
	}
}

func sameCutCore(left, right wal.CheckpointCut) bool {
	return left.OperationID == right.OperationID && left.Epoch == right.Epoch &&
		left.Watermark == right.Watermark && left.ExpectedHeadCommitID == right.ExpectedHeadCommitID &&
		left.TreeHash == right.TreeHash && left.CanonicalRequestHash == right.CanonicalRequestHash &&
		left.AuxiliaryBlobDigestsHash == right.AuxiliaryBlobDigestsHash
}

func (l *Log) validateCutTransition(next wal.CheckpointCut, hasNext bool) error {
	if !l.hasCut {
		return nil
	}
	if !hasNext {
		return fmt.Errorf("%w: generation snapshot forgot an existing checkpoint cut", ErrAccounting)
	}
	current := l.cut
	if current.OperationID != next.OperationID {
		if current.Status != wal.CheckpointAborted && current.Status != wal.CheckpointFinalized {
			return fmt.Errorf("%w: active checkpoint cut changed identity", ErrConflict)
		}
		return nil // a terminal cut may be replaced and advance between snapshots
	}
	if !sameCutCore(current, next) || checkpointStatusRank(next.Status) < checkpointStatusRank(current.Status) ||
		(current.CommitID != "" && current.CommitID != next.CommitID) ||
		(current.Status == wal.CheckpointAborted && next.Status != wal.CheckpointAborted) ||
		(current.Status == wal.CheckpointLanded && next.Status == wal.CheckpointAborted) ||
		(current.Status == wal.CheckpointFinalized && next.Status != wal.CheckpointFinalized) {
		return fmt.Errorf("%w: checkpoint cut content/status regressed", ErrConflict)
	}
	return nil
}

// baseAdvance is the exact tuple a response asks the child to install, plus
// whichever proof it carried for it.
type baseAdvance struct {
	baseSeq      uint64
	baseDigest   [32]byte
	baseCommitID string
	cut          wal.CheckpointCut
	hasCut       bool
	adoption     adoptionProof
	hasAdoption  bool
}

// checkDestructiveBaseAdvanceLocked is the ONE place that decides whether a
// reported base-commit change may be installed. Records below the new base
// become deletable the moment it is, so this refuses anything it cannot prove
// — but it demands the proof the system ACTUALLY ISSUES for the generation's
// codec, which is the whole of the fix here.
//
// Two proof shapes are legitimate, and exactly one of them exists per codec:
//
//   - LEGACY (PFR1/PFC1): a landed or finalized checkpoint cut in
//     journal_generations.cut_*, at exactly the new watermark and commit.
//   - MODERN (PFJ3/PFC2): a landed pfh.adoptions row, bound to a 'ready'
//     pfh.history_cuts row at exactly the new base seq/digest/commit.
//
// The modern one used to be unrepresentable in this response, so this check
// demanded the legacy shape from a generation whose schema RAISES PF005 on any
// write to the legacy cut columns (migrations 013 and 031). It was therefore
// unsatisfiable, not protective: every real adoption that landed under an
// attached writer poisoned that writer and fenced the mount, and — because
// l.baseSeq is only assigned after this returns — CompactedThrough could never
// advance either.
func (l *Log) checkDestructiveBaseAdvanceLocked(next baseAdvance) error {
	if next.hasAdoption &&
		next.adoption.provesBaseAdvance(l.baseSeq, next.baseSeq, next.baseDigest, next.baseCommitID) {
		return nil
	}
	if next.hasCut &&
		(next.cut.Status == wal.CheckpointLanded || next.cut.Status == wal.CheckpointFinalized) &&
		next.cut.Watermark == next.baseSeq && next.cut.CommitID == next.baseCommitID {
		return nil
	}
	return fmt.Errorf(
		"%w: base commit advanced to %q at seq %d without an exact proof (adoption=%v cut=%v)",
		ErrProofMissing, next.baseCommitID, next.baseSeq, next.hasAdoption, next.hasCut)
}

// validateGenerationTransition checks facts that require the current local
// mirror. It accepts the two legitimate base advances: a proof-carrying
// base adoption/checkpoint trim (base commit moves to the materialized commit)
// and a control-only rotation (base commit stays fixed).
func (l *Log) validateGenerationTransition(head *generationJSON, next validatedGeneration) error {
	if next.epoch != l.epoch || next.nextSeq != l.durableSeq || next.tipDigest != l.durableTip ||
		next.baseSeq < l.baseSeq || next.physicalTrimmedSeq < l.physicalTrimmedSeq ||
		next.quotaBytes != l.quotaBytes || next.quotaRecords != l.quotaRecords {
		return fmt.Errorf("%w: generation immutable/head/monotonic facts changed unexpectedly", ErrConflict)
	}
	if err := l.validateCutTransition(next.cut, next.hasCut); err != nil {
		return err
	}
	if next.baseSeq == l.baseSeq {
		if next.baseDigest != l.baseDigest || head.BaseCommitID != l.baseCommitID ||
			next.backlogBytes != l.backlogBytes || next.backlogRecords != l.backlogRecords {
			return fmt.Errorf("%w: unchanged base returned different anchor/accounting", ErrAccounting)
		}
		return nil
	}
	if next.backlogBytes > l.backlogBytes || next.backlogRecords >= l.backlogRecords {
		return fmt.Errorf("%w: base advance did not reduce backlog", ErrAccounting)
	}
	if head.BaseCommitID != l.baseCommitID {
		if err := l.checkDestructiveBaseAdvanceLocked(baseAdvance{
			baseSeq: next.baseSeq, baseDigest: next.baseDigest, baseCommitID: head.BaseCommitID,
			cut: next.cut, hasCut: next.hasCut,
			adoption: next.adoption, hasAdoption: next.hasAdoption,
		}); err != nil {
			return err
		}
	} else if next.hasCut && next.cut.Status == wal.CheckpointPrepared && next.cut.Watermark < next.baseSeq {
		return fmt.Errorf("%w: control rotation crossed a prepared checkpoint cut", ErrProofMissing)
	}
	return nil
}
