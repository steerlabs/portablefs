package wal

import (
	"errors"
	"fmt"
)

type CheckpointCutStatus string

const (
	CheckpointPrepared  CheckpointCutStatus = "prepared"
	CheckpointLanded    CheckpointCutStatus = "landed"
	CheckpointAborted   CheckpointCutStatus = "aborted"
	CheckpointFinalized CheckpointCutStatus = "finalized"
)

// CheckpointCut is the replicated, epoch-fenced proof connecting a backend
// commit operation to the exact exclusive WAL watermark it covers. It is
// deliberately backend-neutral so checkpoint recovery can reconcile a receipt
// before loading a new manifest or replaying the retained WAL.
type CheckpointCut struct {
	OperationID              string              `json:"operationId"`
	Epoch                    uint64              `json:"epoch"`
	Watermark                uint64              `json:"watermark"`
	ExpectedHeadCommitID     string              `json:"expectedHeadCommitId"`
	TreeHash                 string              `json:"treeHash"`
	CanonicalRequestHash     string              `json:"canonicalRequestHash"`
	AuxiliaryBlobDigestsHash string              `json:"auxiliaryBlobDigestsHash,omitempty"`
	Status                   CheckpointCutStatus `json:"status"`
	CommitID                 string              `json:"commitId,omitempty"`
}

func checkpointRank(s CheckpointCutStatus) int {
	switch s {
	case CheckpointPrepared:
		return 1
	case CheckpointLanded, CheckpointAborted:
		return 2
	case CheckpointFinalized:
		return 3
	default:
		return 0
	}
}

func checkpointTerminal(s CheckpointCutStatus) bool {
	return s == CheckpointAborted || s == CheckpointFinalized
}

func sameCheckpointCore(a, b CheckpointCut) bool {
	return a.OperationID == b.OperationID && a.Epoch == b.Epoch && a.Watermark == b.Watermark &&
		a.ExpectedHeadCommitID == b.ExpectedHeadCommitID && a.TreeHash == b.TreeHash &&
		a.CanonicalRequestHash == b.CanonicalRequestHash && a.AuxiliaryBlobDigestsHash == b.AuxiliaryBlobDigestsHash
}

func (w *WAL) setCheckpointCutLocked(next CheckpointCut) error {
	if next.OperationID == "" || next.Epoch == 0 || checkpointRank(next.Status) == 0 {
		return errors.New("wal: invalid checkpoint cut")
	}
	if next.Epoch != w.epoch {
		return fmt.Errorf("%w: checkpoint cut epoch %d, WAL epoch %d", ErrEpochMismatch, next.Epoch, w.epoch)
	}
	if next.Watermark > w.nextSeq || (next.Watermark < w.compactedThrough && next.Status == CheckpointPrepared) {
		return fmt.Errorf("wal: checkpoint watermark %d outside [%d,%d]", next.Watermark, w.compactedThrough, w.nextSeq)
	}
	if next.Status == CheckpointLanded || next.Status == CheckpointFinalized {
		if next.CommitID == "" {
			return errors.New("wal: landed checkpoint cut requires commit ID")
		}
	}
	if w.hasCheckpoint {
		cur := w.checkpoint
		if cur.OperationID != next.OperationID {
			if !checkpointTerminal(cur.Status) || next.Status != CheckpointPrepared {
				return fmt.Errorf("wal: checkpoint cut %q conflicts with active %q", next.OperationID, cur.OperationID)
			}
		} else {
			if !sameCheckpointCore(cur, next) {
				return fmt.Errorf("wal: checkpoint cut %q content changed", next.OperationID)
			}
			if checkpointRank(next.Status) < checkpointRank(cur.Status) {
				return fmt.Errorf("wal: checkpoint cut %q phase regressed", next.OperationID)
			}
			if cur.CommitID != "" && next.CommitID != cur.CommitID {
				return fmt.Errorf("wal: checkpoint cut %q commit changed", next.OperationID)
			}
			if cur.Status == CheckpointAborted && next.Status != CheckpointAborted {
				return fmt.Errorf("wal: aborted checkpoint cut %q cannot advance", next.OperationID)
			}
		}
	}
	w.hasCheckpoint = true
	w.checkpoint = next
	if err := w.persistMetadataLocked(); err != nil {
		w.poisonLocked()
		return err
	}
	return nil
}

func (w *WAL) CheckpointCutState() (CheckpointCut, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.checkpoint, w.hasCheckpoint
}

func (w *WAL) validateCheckpointCompactionLocked(through uint64) error {
	if !w.hasCheckpoint {
		return nil
	}
	if w.checkpoint.Status != CheckpointLanded && w.checkpoint.Status != CheckpointFinalized {
		return errors.New("wal: compaction requires a landed checkpoint cut")
	}
	if through != w.checkpoint.Watermark {
		return fmt.Errorf("wal: compaction %d must equal landed checkpoint cut %d; partial base adoption is unsafe", through, w.checkpoint.Watermark)
	}
	return nil
}

// PrepareCheckpointCut is the mandatory pre-dispatch barrier: the cut fact is
// durable in the log's metadata before the caller may dispatch the backend
// commit.
func (w *WAL) PrepareCheckpointCut(cut CheckpointCut) (CheckpointCut, error) {
	w.commitMu.Lock()
	defer w.commitMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.poisoned {
		return CheckpointCut{}, ErrPoisoned
	}
	if err := w.ensureEpochLocked(); err != nil {
		return CheckpointCut{}, err
	}
	cut.Epoch, cut.Status, cut.CommitID = w.epoch, CheckpointPrepared, ""
	if err := w.setCheckpointCutLocked(cut); err != nil {
		return CheckpointCut{}, err
	}
	return cut, nil
}

// ResolveCheckpointCut records definitive backend receipt evidence.
func (w *WAL) ResolveCheckpointCut(operationID, commitID string, landed bool) error {
	w.commitMu.Lock()
	defer w.commitMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.hasCheckpoint || w.checkpoint.OperationID != operationID {
		return fmt.Errorf("wal: checkpoint cut %q not found", operationID)
	}
	next := w.checkpoint
	if landed {
		next.Status, next.CommitID = CheckpointLanded, commitID
	} else {
		next.Status, next.CommitID = CheckpointAborted, ""
	}
	return w.setCheckpointCutLocked(next)
}

// FinalizeCheckpointCut marks a landed cut fully compacted.
func (w *WAL) FinalizeCheckpointCut(operationID string) error {
	w.commitMu.Lock()
	defer w.commitMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.hasCheckpoint || w.checkpoint.OperationID != operationID {
		return fmt.Errorf("wal: checkpoint cut %q not found", operationID)
	}
	if w.checkpoint.Status != CheckpointLanded {
		return fmt.Errorf("wal: checkpoint cut %q is not landed", operationID)
	}
	if w.compactedThrough < w.checkpoint.Watermark {
		return fmt.Errorf("wal: checkpoint cut %q not compacted", operationID)
	}
	next := w.checkpoint
	next.Status = CheckpointFinalized
	return w.setCheckpointCutLocked(next)
}

// CompactRecoveredCheckpoint locally compacts only the watermark named by a
// persisted Landed cut — the startup path when the compaction itself did not
// survive the crash. It cannot be invoked without exact commit proof.
func (w *WAL) CompactRecoveredCheckpoint(operationID string) error {
	w.commitMu.Lock()
	defer w.commitMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.poisoned {
		return ErrPoisoned
	}
	if !w.hasCheckpoint || w.checkpoint.OperationID != operationID {
		return fmt.Errorf("wal: recovered checkpoint cut %q not found", operationID)
	}
	cut := w.checkpoint
	if cut.Status != CheckpointLanded && cut.Status != CheckpointFinalized {
		return fmt.Errorf("wal: recovered checkpoint cut %q has no landed proof", operationID)
	}
	if cut.Watermark < w.compactedThrough || cut.Watermark > w.nextSeq {
		return fmt.Errorf("wal: recovered checkpoint watermark %d outside [%d,%d]", cut.Watermark, w.compactedThrough, w.nextSeq)
	}
	if cut.Watermark > w.compactedThrough {
		digest, err := w.digestAtLocked(cut.Watermark)
		if err != nil {
			return err
		}
		if err := w.compactLocalLocked(cut.Watermark, digest); err != nil {
			return err
		}
	}
	kept := w.unflushed[:0]
	for _, record := range w.unflushed {
		if record.Seq >= cut.Watermark {
			kept = append(kept, record)
		}
	}
	w.unflushed = kept
	w.durableSeq = w.nextSeq // compactLocalLocked rewrote+fsynced the retained suffix.
	return nil
}

// SetCheckpointCutExact applies an epoch-fenced checkpoint fact on a standby.
func (w *WAL) SetCheckpointCutExact(cut CheckpointCut) error {
	w.commitMu.Lock()
	defer w.commitMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.poisoned {
		return ErrPoisoned
	}
	return w.setCheckpointCutLocked(cut)
}
