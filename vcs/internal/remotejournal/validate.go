package remotejournal

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/trendup-ai/portablefs/vcs/internal/wal"
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

// validateGenerationTransition checks facts that require the current local
// mirror. It accepts the two legitimate base advances: a proof-carrying
// checkpoint trim (base commit moves to the landed cut commit) and a
// control-only rotation (base commit stays fixed).
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
		if !next.hasCut || (next.cut.Status != wal.CheckpointLanded && next.cut.Status != wal.CheckpointFinalized) ||
			next.cut.Watermark != next.baseSeq || next.cut.CommitID != head.BaseCommitID {
			return fmt.Errorf("%w: base commit advanced without exact landed checkpoint proof", ErrProofMissing)
		}
	} else if next.hasCut && next.cut.Status == wal.CheckpointPrepared && next.cut.Watermark < next.baseSeq {
		return fmt.Errorf("%w: control rotation crossed a prepared checkpoint cut", ErrProofMissing)
	}
	return nil
}
