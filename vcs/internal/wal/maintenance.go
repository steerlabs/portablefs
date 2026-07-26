package wal

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/trendup-ai/portablefs/vcs/internal/ctlrec"
)

type MaintenanceStatus string

const (
	MaintenancePrepared  MaintenanceStatus = "prepared"
	MaintenanceFinalized MaintenanceStatus = "finalized"
)

// MaintenanceCut proves a backend-neutral compaction is safe: every removed
// record is control-only and a complete control snapshot at SidecarSeq remains.
type MaintenanceCut struct {
	OperationID string            `json:"operationId"`
	Epoch       uint64            `json:"epoch"`
	Watermark   uint64            `json:"watermark"`
	SidecarSeq  uint64            `json:"sidecarSeq"`
	SidecarHash [32]byte          `json:"sidecarHash"`
	Status      MaintenanceStatus `json:"status"`
}

func maintenanceID(epoch, watermark, sidecar uint64, hash [32]byte) string {
	s := sha256.Sum256([]byte(fmt.Sprintf("portablefs-control-rotation\x00%d\x00%d\x00%d\x00%x", epoch, watermark, sidecar, hash)))
	return "pfmr_" + hex.EncodeToString(s[:12])
}

func maintenanceRank(s MaintenanceStatus) int {
	switch s {
	case MaintenancePrepared:
		return 1
	case MaintenanceFinalized:
		return 2
	default:
		return 0
	}
}

func sameMaintenanceCore(a, b MaintenanceCut) bool {
	return a.OperationID == b.OperationID && a.Epoch == b.Epoch && a.Watermark == b.Watermark &&
		a.SidecarSeq == b.SidecarSeq && a.SidecarHash == b.SidecarHash
}

func controlOnlyRecord(r Record) bool {
	if r.Op == OpControl {
		return true
	}
	if r.Op != OpBatch || len(r.Mutations) == 0 {
		return false
	}
	for _, leaf := range r.Mutations {
		if leaf.Op != OpControl || len(leaf.Mutations) != 0 {
			return false
		}
	}
	return true
}

func (w *WAL) validateMaintenanceLocked(cut MaintenanceCut) error {
	if cut.Epoch != w.epoch {
		return fmt.Errorf("%w: maintenance epoch %d, WAL epoch %d", ErrEpochMismatch, cut.Epoch, w.epoch)
	}
	if cut.Watermark < w.compactedThrough || cut.Watermark > w.nextSeq {
		return fmt.Errorf("wal: maintenance watermark %d outside [%d,%d]", cut.Watermark, w.compactedThrough, w.nextSeq)
	}
	if cut.SidecarSeq < cut.Watermark || cut.SidecarSeq >= w.nextSeq {
		return fmt.Errorf("wal: maintenance sidecar LSN %d is not retained after cut %d", cut.SidecarSeq, cut.Watermark)
	}
	records, err := w.recordsLocked()
	if err != nil {
		return err
	}
	var sidecar *Record
	for i := range records {
		r := &records[i]
		if r.Seq < cut.Watermark && !controlOnlyRecord(*r) {
			return fmt.Errorf("wal: control rotation refuses user op %d at LSN %d", r.Op, r.Seq)
		}
		if r.Seq == cut.SidecarSeq {
			sidecar = r
		}
	}
	if sidecar == nil || sidecar.Op != OpControl {
		return errors.New("wal: control rotation sidecar is missing or not OpControl")
	}
	h, ok := w.recordHashes[cut.SidecarSeq]
	if !ok || h != cut.SidecarHash {
		return fmt.Errorf("%w: maintenance sidecar hash differs", ErrReplicationConflict)
	}
	payload, err := ctlrec.Decode(sidecar.Data)
	if err != nil {
		return fmt.Errorf("wal: decode maintenance sidecar: %w", err)
	}
	if payload.Kind != ctlrec.KindSnapshot || payload.Snapshot == nil || payload.Snapshot.AsOfLSN != cut.Watermark {
		return fmt.Errorf("wal: maintenance sidecar is not a complete snapshot as of LSN %d", cut.Watermark)
	}
	return nil
}

func (w *WAL) setMaintenanceLocked(cut MaintenanceCut) error {
	if cut.OperationID == "" || maintenanceRank(cut.Status) == 0 {
		return errors.New("wal: invalid maintenance cut")
	}
	if err := w.validateMaintenanceLocked(cut); err != nil {
		return err
	}
	if w.hasMaintenance {
		cur := w.maintenance
		if cur.OperationID != cut.OperationID {
			if cur.Status != MaintenanceFinalized || cut.Status != MaintenancePrepared {
				return fmt.Errorf("wal: maintenance %q conflicts with %q", cut.OperationID, cur.OperationID)
			}
		} else {
			if !sameMaintenanceCore(cur, cut) {
				return fmt.Errorf("wal: maintenance %q content changed", cut.OperationID)
			}
			if maintenanceRank(cut.Status) < maintenanceRank(cur.Status) {
				return fmt.Errorf("wal: maintenance %q phase regressed", cut.OperationID)
			}
		}
	}
	w.hasMaintenance, w.maintenance = true, cut
	if err := w.persistMetadataLocked(); err != nil {
		w.poisonLocked()
		return err
	}
	return nil
}

func (w *WAL) SetMaintenanceCutExact(cut MaintenanceCut) error {
	w.commitMu.Lock()
	defer w.commitMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.poisoned {
		return ErrPoisoned
	}
	return w.setMaintenanceLocked(cut)
}

func (w *WAL) CompactMaintenanceExact(cut MaintenanceCut) error {
	w.commitMu.Lock()
	defer w.commitMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.hasMaintenance || w.maintenance.OperationID != cut.OperationID {
		return errors.New("wal: maintenance cut was not prepared")
	}
	if w.maintenance.Status == MaintenanceFinalized && w.compactedThrough >= cut.Watermark {
		return nil
	}
	if w.maintenance.Status != MaintenancePrepared {
		return errors.New("wal: maintenance cut was not prepared")
	}
	if err := w.validateMaintenanceLocked(cut); err != nil {
		return err
	}
	digest, err := w.digestAtLocked(cut.Watermark)
	if err != nil {
		return err
	}
	if err := w.compactLocalLocked(cut.Watermark, digest); err != nil {
		return err
	}
	kept := w.unflushed[:0]
	for _, record := range w.unflushed {
		if record.Seq >= cut.Watermark {
			kept = append(kept, record)
		}
	}
	w.unflushed, w.durableSeq = kept, w.nextSeq
	return nil
}

func remoteMaintenanceState(exact ExactReplica, cut MaintenanceCut) (ReplicaState, bool) {
	state, err := exact.StateExact()
	if err != nil || !state.HasMaintenance || !sameMaintenanceCore(state.Maintenance, cut) {
		return state, false
	}
	return state, true
}

// finishMaintenanceLocked idempotently resolves every response-loss boundary.
// Caller holds commitMu and w.mu.
func (w *WAL) finishMaintenanceLocked(cut MaintenanceCut, exact ExactReplica) error {
	if exact != nil {
		remote, same := remoteMaintenanceState(exact, cut)
		if !same {
			prepared := cut
			prepared.Status = MaintenancePrepared
			if err := exact.SetMaintenanceCutExact(prepared); err != nil {
				if _, applied := remoteMaintenanceState(exact, prepared); !applied {
					return err
				}
			}
			remote, _ = exact.StateExact()
		}
		if remote.BaseSeq < cut.Watermark {
			prepared := cut
			prepared.Status = MaintenancePrepared
			if err := exact.CompactMaintenanceExact(prepared); err != nil {
				state, applied := remoteMaintenanceState(exact, prepared)
				if !applied || state.BaseSeq < cut.Watermark {
					return err
				}
			}
		}
	}
	if w.compactedThrough < cut.Watermark {
		if err := w.validateMaintenanceLocked(cut); err != nil {
			return err
		}
		digest, err := w.digestAtLocked(cut.Watermark)
		if err != nil {
			return err
		}
		if err := w.compactLocalLocked(cut.Watermark, digest); err != nil {
			if exact != nil {
				w.poisonLocked()
			}
			return err
		}
	}
	cut.Status = MaintenanceFinalized
	if exact != nil {
		if err := exact.SetMaintenanceCutExact(cut); err != nil {
			state, applied := remoteMaintenanceState(exact, cut)
			if !applied || state.Maintenance.Status != MaintenanceFinalized {
				return err
			}
		}
	}
	if err := w.setMaintenanceLocked(cut); err != nil {
		return err
	}
	kept := w.unflushed[:0]
	for _, record := range w.unflushed {
		if record.Seq >= cut.Watermark {
			kept = append(kept, record)
		}
	}
	w.unflushed = kept
	w.durableSeq = w.nextSeq // local rewrite fsynced every retained record.
	return nil
}

// RecoverControlRotation finishes a durable prepared rotation after restart or
// promotion. A promoted member may recover locally while user writes remain
// fenced until a replacement replica is attached.
func (w *WAL) RecoverControlRotation() error {
	w.commitMu.Lock()
	defer w.commitMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.hasMaintenance || (w.maintenance.Status == MaintenanceFinalized && w.compactedThrough >= w.maintenance.Watermark) {
		return nil
	}
	var exact ExactReplica
	if w.replica != nil {
		var ok bool
		exact, ok = w.replica.(ExactReplica)
		if !ok || !w.replicaExact {
			return ErrLegacyReplica
		}
	}
	return w.finishMaintenanceLocked(w.maintenance, exact)
}

// RotateControlOnlyThrough performs bounded control-WAL maintenance without a
// backend branch commit. Both members independently prove the prefix contains no
// user mutation and the retained record is a complete exact sidecar.
func (w *WAL) RotateControlOnlyThrough(watermark, sidecarSeq uint64) error {
	w.commitMu.Lock()
	defer w.commitMu.Unlock()
	if err := w.flushLocked(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.poisoned {
		return ErrPoisoned
	}
	hash, ok := w.recordHashes[sidecarSeq]
	if !ok {
		return errors.New("wal: maintenance sidecar LSN is not retained")
	}
	cut := MaintenanceCut{Epoch: w.epoch, Watermark: watermark, SidecarSeq: sidecarSeq, SidecarHash: hash, Status: MaintenancePrepared}
	cut.OperationID = maintenanceID(cut.Epoch, watermark, sidecarSeq, hash)
	var exact ExactReplica
	if w.haRequired {
		var ok bool
		exact, ok = w.replica.(ExactReplica)
		if !ok || !w.replicaExact {
			return ErrReplicaRequired
		}
	}
	if err := w.setMaintenanceLocked(cut); err != nil {
		return err
	}
	return w.finishMaintenanceLocked(cut, exact)
}
