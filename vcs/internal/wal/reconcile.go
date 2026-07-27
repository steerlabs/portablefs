package wal

import (
	"errors"
	"fmt"
)

// ReplicaState is the exact, crash-persistent identity of a replica prefix.
// BaseDigest commits to compacted history; TipDigest commits to that history plus
// the current live WAL suffix.
type ReplicaState struct {
	Epoch          uint64
	BaseSeq        uint64
	NextSeq        uint64
	BaseDigest     [32]byte
	TipDigest      [32]byte
	Pristine       bool
	Legacy         bool
	HA             bool
	Poisoned       bool
	HasCheckpoint  bool
	Checkpoint     CheckpointCut
	HasMaintenance bool
	Maintenance    MaintenanceCut
}

// ExactReplica is the production replication contract. Unlike the legacy
// Replica methods, every mutation is scoped to a persistent epoch and attach can
// prove the common prefix before either side changes state.
type ExactReplica interface {
	Replica
	StateExact() (ReplicaState, error)
	DigestAtExact(epoch, seq uint64) ([32]byte, error)
	RecordsExact(epoch, from, to uint64) ([]Record, error)
	AdoptExact(epoch, baseSeq uint64, baseDigest [32]byte) error
	AppendBatchExact(epoch uint64, records []Record) error
	CompactExact(epoch, throughSeq uint64, digest [32]byte) error
	SetCheckpointCutExact(cut CheckpointCut) error
	SetMaintenanceCutExact(cut MaintenanceCut) error
	CompactMaintenanceExact(cut MaintenanceCut) error
}

// The direct wrappers make *WAL useful as an in-process exact replica in tests
// and embedders; the network client implements the same contract.
func (w *WAL) AppendBatch(records []Record) error { return w.AppendReplicatedBatch(records) }
func (w *WAL) Compact(seq uint64) error           { return w.CompactThrough(seq) }
func (w *WAL) StateExact() (ReplicaState, error)  { return w.State(), nil }
func (w *WAL) DigestAtExact(epoch, seq uint64) ([32]byte, error) {
	return w.DigestAt(epoch, seq)
}
func (w *WAL) RecordsExact(epoch, from, to uint64) ([]Record, error) {
	return w.RecordsRange(epoch, from, to)
}
func (w *WAL) AdoptExact(epoch, baseSeq uint64, baseDigest [32]byte) error {
	return w.AdoptReplicaIdentity(epoch, baseSeq, baseDigest)
}
func (w *WAL) AppendBatchExact(epoch uint64, records []Record) error {
	return w.AppendReplicatedExact(epoch, records)
}
func (w *WAL) CompactExact(epoch, throughSeq uint64, digest [32]byte) error {
	return w.CompactReplicatedExact(epoch, throughSeq, digest)
}

// State returns the local prefix identity.
func (w *WAL) State() ReplicaState {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stateLocked()
}

func (w *WAL) stateLocked() ReplicaState {
	return ReplicaState{
		Epoch: w.epoch, BaseSeq: w.compactedThrough, NextSeq: w.nextSeq,
		BaseDigest: w.baseDigest, TipDigest: w.tipDigest,
		Pristine: w.epoch == 0 && w.nextSeq == 0 && w.compactedThrough == 0 && w.count == 0,
		Legacy:   w.legacy, HA: w.haRequired, Poisoned: w.poisoned,
		HasCheckpoint: w.hasCheckpoint, Checkpoint: w.checkpoint,
		HasMaintenance: w.hasMaintenance, Maintenance: w.maintenance,
	}
}

// RequiresReplica reports whether this WAL is a member of a fixed two-member HA
// set. The bit survives restart and promotion.
func (w *WAL) RequiresReplica() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.haRequired
}

func (w *WAL) ensureEpochLocked() error {
	if w.legacy {
		return ErrLegacyReplica
	}
	if w.epoch != 0 {
		return nil
	}
	e, err := randomEpoch()
	if err != nil {
		return err
	}
	w.epoch = e
	if err := w.persistMetadataLocked(); err != nil {
		w.epoch = 0
		return err
	}
	return nil
}

func (w *WAL) recordsLocked() ([]Record, error) {
	records, _, err := readRecords(w.path, w.enc)
	return records, err
}

func (w *WAL) digestAtLocked(seq uint64) ([32]byte, error) {
	if seq < w.compactedThrough || seq > w.nextSeq {
		return [32]byte{}, fmt.Errorf("wal: digest boundary %d outside retained range [%d,%d]", seq, w.compactedThrough, w.nextSeq)
	}
	if seq == w.compactedThrough {
		return w.baseDigest, nil
	}
	records, err := w.recordsLocked()
	if err != nil {
		return [32]byte{}, err
	}
	d := w.baseDigest
	for _, r := range records {
		if r.Seq >= seq {
			break
		}
		d, err = recordDigest(d, r)
		if err != nil {
			return [32]byte{}, err
		}
	}
	return d, nil
}

// DigestAt returns the digest at an exclusive LSN boundary retained by this WAL.
func (w *WAL) DigestAt(epoch, seq uint64) ([32]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.epoch != epoch {
		return [32]byte{}, fmt.Errorf("%w: have %d, request %d", ErrEpochMismatch, w.epoch, epoch)
	}
	return w.digestAtLocked(seq)
}

// RecordsRange returns an exact retained half-open LSN range.
func (w *WAL) RecordsRange(epoch, from, to uint64) ([]Record, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.epoch != epoch {
		return nil, fmt.Errorf("%w: have %d, request %d", ErrEpochMismatch, w.epoch, epoch)
	}
	if from < w.compactedThrough || to < from || to > w.nextSeq {
		return nil, fmt.Errorf("wal: record range [%d,%d) outside retained range [%d,%d)", from, to, w.compactedThrough, w.nextSeq)
	}
	records, err := w.recordsLocked()
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, to-from)
	for _, r := range records {
		if r.Seq >= from && r.Seq < to {
			out = append(out, r)
		}
	}
	if uint64(len(out)) != to-from {
		return nil, fmt.Errorf("wal: retained range [%d,%d) is incomplete", from, to)
	}
	return out, nil
}

// AdoptReplicaIdentity initializes only a genuinely pristine standby. It never
// truncates or overwrites existing records.
func (w *WAL) AdoptReplicaIdentity(epoch, baseSeq uint64, baseDigest [32]byte) error {
	w.commitMu.Lock()
	defer w.commitMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.poisoned {
		return ErrPoisoned
	}
	if epoch == 0 {
		return fmt.Errorf("wal: zero replication epoch")
	}
	if !w.stateLocked().Pristine || w.legacy {
		return fmt.Errorf("wal: refusing identity adoption by non-pristine replica")
	}
	w.epoch = epoch
	w.compactedThrough = baseSeq
	w.nextSeq = baseSeq
	w.durableSeq = baseSeq
	w.baseDigest = baseDigest
	w.tipDigest = baseDigest
	w.haRequired = true
	if err := w.persistMetadataLocked(); err != nil {
		w.poisonLocked()
		return err
	}
	return nil
}

func (w *WAL) verifyDuplicateLocked(in Record) error {
	if in.Seq < w.compactedThrough {
		return fmt.Errorf("%w: LSN %d was already compacted below %d", ErrReplicationConflict, in.Seq, w.compactedThrough)
	}
	want, ok := w.recordHashes[in.Seq]
	got, err := recordDigest([32]byte{}, in)
	if err != nil {
		return err
	}
	if !ok || want != got {
		return fmt.Errorf("%w: LSN %d payload differs", ErrReplicationConflict, in.Seq)
	}
	return nil
}

// AppendReplicatedExact is the epoch-fenced, gap-free standby append path.
func (w *WAL) AppendReplicatedExact(epoch uint64, records []Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.poisoned {
		return ErrPoisoned
	}
	if w.legacy || w.epoch == 0 || w.epoch != epoch {
		return fmt.Errorf("%w: have %d, request %d", ErrEpochMismatch, w.epoch, epoch)
	}
	if !w.haRequired {
		w.haRequired = true
		if err := w.persistMetadataLocked(); err != nil {
			w.poisonLocked()
			return err
		}
	}
	return w.appendReplicatedBatchLocked(records)
}

func (w *WAL) appendReplicatedBatchLocked(records []Record) error {
	if len(records) == 0 {
		return nil
	}
	// First validate the complete overlap and suffix before writing one byte.
	next := w.nextSeq
	firstNew := len(records)
	for i, r := range records {
		if i > 0 && r.Seq != records[i-1].Seq+1 {
			return fmt.Errorf("%w inside batch: %d follows %d", ErrReplicationGap, r.Seq, records[i-1].Seq)
		}
		switch {
		case r.Seq < next:
			if err := w.verifyDuplicateLocked(r); err != nil {
				return err
			}
		case r.Seq == next:
			if firstNew == len(records) {
				firstNew = i
			}
			next++
		default:
			return fmt.Errorf("%w: got %d, want %d", ErrReplicationGap, r.Seq, next)
		}
	}
	newRecords := records[firstNew:]
	if len(newRecords) == 0 {
		return nil
	}
	framed := make([][]byte, len(newRecords))
	hashes := make([][32]byte, len(newRecords))
	var total int64
	d := w.tipDigest
	for i, r := range newRecords {
		f, err := frame(r, w.enc)
		if err != nil {
			return err
		}
		framed[i] = f
		total += int64(len(f))
		d, err = recordDigest(d, r)
		if err != nil {
			return err
		}
		hashes[i], err = recordDigest([32]byte{}, r)
		if err != nil {
			return err
		}
	}
	prevOffset := w.offset
	for _, f := range framed {
		if err := writeFull(w.f, f); err != nil {
			return w.rollbackToLocked(prevOffset, err)
		}
	}
	if err := w.f.Sync(); err != nil {
		return w.rollbackToLocked(prevOffset, err)
	}
	w.offset += total
	w.nextSeq += uint64(len(newRecords))
	w.durableSeq = w.nextSeq
	w.count += len(newRecords)
	w.tipDigest = d
	if w.recordHashes == nil {
		w.recordHashes = make(map[uint64][32]byte)
	}
	for i, r := range newRecords {
		w.recordHashes[r.Seq] = hashes[i]
	}
	return nil
}

// CompactReplicatedExact rejects a stale epoch or a primary whose claimed
// boundary digest does not match the standby's exact prefix.
func (w *WAL) CompactReplicatedExact(epoch, throughSeq uint64, digest [32]byte) error {
	w.commitMu.Lock()
	defer w.commitMu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.epoch != epoch {
		return fmt.Errorf("%w: have %d, request %d", ErrEpochMismatch, w.epoch, epoch)
	}
	effective := throughSeq
	if effective > w.nextSeq {
		effective = w.nextSeq
	}
	if err := w.validateCheckpointCompactionLocked(effective); err != nil {
		return err
	}
	got, err := w.digestAtLocked(effective)
	if err != nil {
		return err
	}
	if got != digest {
		return fmt.Errorf("%w: compact boundary %d digest differs", ErrReplicationConflict, effective)
	}
	if err := w.compactLocalLocked(effective, digest); err != nil {
		return err
	}
	kept := w.unflushed[:0]
	for _, record := range w.unflushed {
		if record.Seq >= effective {
			kept = append(kept, record)
		}
	}
	w.unflushed, w.durableSeq = kept, w.nextSeq
	return nil
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func mergeCheckpointState(a ReplicaState, b ReplicaState) (CheckpointCut, bool, error) {
	if !a.HasCheckpoint {
		return b.Checkpoint, b.HasCheckpoint, nil
	}
	if !b.HasCheckpoint {
		return a.Checkpoint, true, nil
	}
	ac, bc := a.Checkpoint, b.Checkpoint
	if ac.OperationID == bc.OperationID {
		if !sameCheckpointCore(ac, bc) {
			return CheckpointCut{}, false, fmt.Errorf("%w: checkpoint cut %q differs", ErrReplicationConflict, ac.OperationID)
		}
		if checkpointRank(bc.Status) > checkpointRank(ac.Status) {
			return bc, true, nil
		}
		if checkpointRank(ac.Status) > checkpointRank(bc.Status) {
			return ac, true, nil
		}
		if ac != bc {
			return CheckpointCut{}, false, fmt.Errorf("%w: checkpoint resolution %q differs", ErrReplicationConflict, ac.OperationID)
		}
		return ac, true, nil
	}
	// A completed prior operation may be replaced by the next prepared cut. This
	// is the only safe cross-operation ordering inferable without a coordinator.
	if checkpointTerminal(ac.Status) && bc.Status == CheckpointPrepared {
		return bc, true, nil
	}
	if checkpointTerminal(bc.Status) && ac.Status == CheckpointPrepared {
		return ac, true, nil
	}
	return CheckpointCut{}, false, fmt.Errorf("%w: active checkpoint operations %q and %q differ", ErrReplicationConflict, ac.OperationID, bc.OperationID)
}

func mergeMaintenanceState(a ReplicaState, b ReplicaState) (MaintenanceCut, bool, error) {
	if !a.HasMaintenance {
		return b.Maintenance, b.HasMaintenance, nil
	}
	if !b.HasMaintenance {
		return a.Maintenance, true, nil
	}
	am, bm := a.Maintenance, b.Maintenance
	if am.OperationID == bm.OperationID {
		if !sameMaintenanceCore(am, bm) {
			return MaintenanceCut{}, false, fmt.Errorf("%w: maintenance %q differs", ErrReplicationConflict, am.OperationID)
		}
		if maintenanceRank(bm.Status) > maintenanceRank(am.Status) {
			return bm, true, nil
		}
		return am, true, nil
	}
	if am.Status == MaintenanceFinalized && bm.Status == MaintenancePrepared {
		return bm, true, nil
	}
	if bm.Status == MaintenanceFinalized && am.Status == MaintenancePrepared {
		return am, true, nil
	}
	return MaintenanceCut{}, false, fmt.Errorf("%w: active maintenance operations differ", ErrReplicationConflict)
}

// AttachReplica proves a common digest prefix, repairs only a missing exact
// suffix in either direction, verifies equality, and only then publishes the
// standby to the write path. It never calls Reset.
func (w *WAL) AttachReplica(r Replica) error {
	exact, ok := r.(ExactReplica)
	if !ok {
		return ErrLegacyReplica
	}
	w.commitMu.Lock()
	defer w.commitMu.Unlock()

	w.mu.Lock()
	if w.poisoned {
		w.mu.Unlock()
		return ErrPoisoned
	}
	if w.legacy {
		w.mu.Unlock()
		return ErrLegacyReplica
	}
	if err := w.ensureEpochLocked(); err != nil {
		w.mu.Unlock()
		return err
	}
	if err := w.f.Sync(); err != nil {
		w.poisonLocked()
		w.mu.Unlock()
		return err
	}
	local := w.stateLocked()
	w.mu.Unlock()

	remote, err := exact.StateExact()
	if err != nil {
		return err
	}
	if remote.Poisoned {
		return ErrPoisoned
	}
	if remote.Legacy {
		return ErrLegacyReplica
	}
	if remote.Pristine {
		if err := exact.AdoptExact(local.Epoch, local.BaseSeq, local.BaseDigest); err != nil {
			return err
		}
		remote, err = exact.StateExact()
		if err != nil {
			return err
		}
	}
	if remote.Epoch != local.Epoch {
		return fmt.Errorf("%w: primary %d, standby %d", ErrEpochMismatch, local.Epoch, remote.Epoch)
	}
	commonStart := max64(local.BaseSeq, remote.BaseSeq)
	commonEnd := min64(local.NextSeq, remote.NextSeq)
	if commonStart > commonEnd {
		return fmt.Errorf("wal: replicas have no retained common boundary (primary [%d,%d], standby [%d,%d])", local.BaseSeq, local.NextSeq, remote.BaseSeq, remote.NextSeq)
	}
	w.mu.Lock()
	localStartDigest, err := w.digestAtLocked(commonStart)
	w.mu.Unlock()
	if err != nil {
		return err
	}
	remoteStartDigest, err := exact.DigestAtExact(local.Epoch, commonStart)
	if err != nil || remoteStartDigest != localStartDigest {
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: compacted prefixes differ at LSN %d", ErrReplicationConflict, commonStart)
	}
	w.mu.Lock()
	localCommonDigest, err := w.digestAtLocked(commonEnd)
	w.mu.Unlock()
	if err != nil {
		return err
	}
	remoteCommonDigest, err := exact.DigestAtExact(local.Epoch, commonEnd)
	if err != nil || remoteCommonDigest != localCommonDigest {
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: live prefixes differ at LSN %d", ErrReplicationConflict, commonEnd)
	}

	const chunk = uint64(1024)
	if remote.NextSeq < local.NextSeq {
		if remote.NextSeq < local.BaseSeq {
			return fmt.Errorf("wal: standby is behind compacted primary prefix")
		}
		for from := remote.NextSeq; from < local.NextSeq; {
			to := min64(from+chunk, local.NextSeq)
			w.mu.Lock()
			records, rerr := w.recordsLocked()
			base := w.compactedThrough
			w.mu.Unlock()
			if rerr != nil {
				return rerr
			}
			slice := append([]Record(nil), records[from-base:to-base]...)
			if err := exact.AppendBatchExact(local.Epoch, slice); err != nil {
				return err
			}
			from = to
		}
	} else if remote.NextSeq > local.NextSeq {
		if local.NextSeq < remote.BaseSeq {
			return fmt.Errorf("wal: primary is behind compacted standby prefix")
		}
		for from := local.NextSeq; from < remote.NextSeq; {
			to := min64(from+chunk, remote.NextSeq)
			records, err := exact.RecordsExact(local.Epoch, from, to)
			if err != nil {
				return err
			}
			w.mu.Lock()
			err = w.appendReplicatedBatchLocked(records)
			w.mu.Unlock()
			if err != nil {
				return err
			}
			from = to
		}
	}

	// Reconcile compaction asymmetry (for example, a lost ACK after the standby
	// compacted first). The older side advances only after the digest proof above;
	// no record reset/truncation is used to hide divergence.
	remote, err = exact.StateExact()
	if err != nil {
		return err
	}
	w.mu.Lock()
	local = w.stateLocked()
	w.mu.Unlock()
	mergedCut, hasCut, err := mergeCheckpointState(local, remote)
	if err != nil {
		return err
	}
	if hasCut {
		if !remote.HasCheckpoint || remote.Checkpoint != mergedCut {
			if err := exact.SetCheckpointCutExact(mergedCut); err != nil {
				return err
			}
			remote.HasCheckpoint, remote.Checkpoint = true, mergedCut
		}
		if !local.HasCheckpoint || local.Checkpoint != mergedCut {
			w.mu.Lock()
			err = w.setCheckpointCutLocked(mergedCut)
			w.mu.Unlock()
			if err != nil {
				return err
			}
			local.HasCheckpoint, local.Checkpoint = true, mergedCut
		}
	}
	mergedMaintenance, hasMaintenance, err := mergeMaintenanceState(local, remote)
	if err != nil {
		return err
	}
	if hasMaintenance && mergedMaintenance.Status == MaintenancePrepared {
		if !local.HasMaintenance || local.Maintenance != mergedMaintenance {
			w.mu.Lock()
			err = w.setMaintenanceLocked(mergedMaintenance)
			w.mu.Unlock()
			if err != nil {
				return err
			}
		}
		w.mu.Lock()
		err = w.finishMaintenanceLocked(mergedMaintenance, exact)
		w.mu.Unlock()
		if err != nil {
			return err
		}
		remote, err = exact.StateExact()
		if err != nil {
			return err
		}
		w.mu.Lock()
		local = w.stateLocked()
		w.mu.Unlock()
		mergedMaintenance = local.Maintenance
	}
	targetBase := max64(local.BaseSeq, remote.BaseSeq)
	if targetBase > local.BaseSeq || targetBase > remote.BaseSeq {
		w.mu.Lock()
		boundary, derr := w.digestAtLocked(targetBase)
		w.mu.Unlock()
		if derr != nil {
			return derr
		}
		remoteBoundary, derr := exact.DigestAtExact(local.Epoch, targetBase)
		if derr != nil {
			return derr
		}
		if boundary != remoteBoundary {
			return fmt.Errorf("%w: compaction boundary %d differs", ErrReplicationConflict, targetBase)
		}
		if remote.BaseSeq < targetBase {
			if hasMaintenance && mergedMaintenance.Watermark == targetBase {
				prepared := mergedMaintenance
				prepared.Status = MaintenancePrepared
				if !remote.HasMaintenance || !sameMaintenanceCore(remote.Maintenance, prepared) {
					if err := exact.SetMaintenanceCutExact(prepared); err != nil {
						return err
					}
				}
				if err := exact.CompactMaintenanceExact(prepared); err != nil {
					return err
				}
			} else if err := exact.CompactExact(local.Epoch, targetBase, boundary); err != nil {
				return err
			}
		}
		if local.BaseSeq < targetBase {
			w.mu.Lock()
			err = w.compactLocalLocked(targetBase, boundary)
			w.mu.Unlock()
			if err != nil {
				return err
			}
		}
	}
	if hasMaintenance {
		remote, err = exact.StateExact()
		if err != nil {
			return err
		}
		if !remote.HasMaintenance || remote.Maintenance != mergedMaintenance {
			if err := exact.SetMaintenanceCutExact(mergedMaintenance); err != nil {
				return err
			}
		}
		w.mu.Lock()
		local = w.stateLocked()
		w.mu.Unlock()
		if !local.HasMaintenance || local.Maintenance != mergedMaintenance {
			w.mu.Lock()
			err = w.setMaintenanceLocked(mergedMaintenance)
			w.mu.Unlock()
			if err != nil {
				return err
			}
		}
	}

	remote, err = exact.StateExact()
	if err != nil {
		return err
	}
	w.mu.Lock()
	local = w.stateLocked()
	if remote.Epoch != local.Epoch || remote.BaseSeq != local.BaseSeq || remote.NextSeq != local.NextSeq ||
		remote.BaseDigest != local.BaseDigest || remote.TipDigest != local.TipDigest ||
		remote.HasCheckpoint != local.HasCheckpoint || (local.HasCheckpoint && remote.Checkpoint != local.Checkpoint) {
		// maintenance comparison follows below
		w.mu.Unlock()
		return errors.New("wal: replica reconciliation did not converge")
	}
	if remote.HasMaintenance != local.HasMaintenance || (local.HasMaintenance && remote.Maintenance != local.Maintenance) {
		w.mu.Unlock()
		return errors.New("wal: replica maintenance reconciliation did not converge")
	}
	w.replica = r
	w.replicaExact = true
	w.haRequired = true
	w.unflushed = nil
	w.mu.Unlock()
	w.durableSeq = local.NextSeq
	w.mu.Lock()
	err = w.persistMetadataLocked()
	if err != nil {
		w.poisonLocked()
	}
	w.mu.Unlock()
	return err
}
