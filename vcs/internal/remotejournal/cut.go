package remotejournal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// writerArgs are the fenced-writer facts every mutating pfj call presents.
func (l *Log) writerArgs() []any {
	record, control := l.codecPair()
	return []any{l.generationID, int64(l.epoch), l.capability, l.cfg.LeaseID, l.cfg.FencingToken,
		record, control}
}

// callWriter runs one fenced idempotent call. A proven stale-writer outcome
// (PF001) poisons the log before returning ErrFenced; other typed outcomes
// are returned to the caller un-poisoned (they reject one operation, they do
// not prove this writer lost its fence).
func (l *Log) callWriter(sql string, extra ...any) ([]byte, error) {
	if l.readOnly {
		return nil, errReadOnly
	}
	// Legacy owner-only checkpoint methods remain part of DurableLog for
	// non-managed callers. Serialize them with append commit and exact suspend
	// so no exported mutation can cross the suspension linearization point.
	l.commitMu.Lock()
	defer l.commitMu.Unlock()
	if l.IsPoisoned() {
		return nil, wal.ErrPoisoned
	}
	l.mu.Lock()
	suspended := l.suspending || l.suspended
	l.mu.Unlock()
	if suspended {
		return nil, ErrFenced
	}
	raw, err := l.callIdempotent(sql, append(l.writerArgs(), extra...)...)
	if err != nil && errors.Is(err, ErrFenced) {
		l.poison(err)
	}
	return raw, err
}

// setCut installs a cut JSON response as the local mirror.
func (l *Log) setCut(raw []byte) (wal.CheckpointCut, error) {
	var c cutJSON
	if err := json.Unmarshal(raw, &c); err != nil {
		return wal.CheckpointCut{}, fmt.Errorf("remotejournal: decode cut response: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cut, err := validateCutJSON(&c, l.epoch, l.durableSeq)
	if err != nil {
		return wal.CheckpointCut{}, err
	}
	if err := l.validateCutTransition(cut, true); err != nil {
		return wal.CheckpointCut{}, err
	}
	l.cut, l.hasCut = cut, true
	return cut, nil
}

// ensureDurableThrough makes [ , seq) durable before an operation that the
// database validates against its durable head.
func (l *Log) ensureDurableThrough(seq uint64) error {
	l.mu.Lock()
	durable := l.durableSeq
	l.mu.Unlock()
	if seq == 0 || durable >= seq {
		return nil
	}
	return l.CommitThrough(seq - 1)
}

// PrepareCheckpointCut is the pre-dispatch barrier: the cut fact is durable in
// the database (validated against the fenced writer at database time) before
// the caller may dispatch the backend commit. The watermark prefix is
// committed first so the durable journal actually covers the cut.
func (l *Log) PrepareCheckpointCut(cut wal.CheckpointCut) (wal.CheckpointCut, error) {
	watermark, err := checkedSQLBigint("checkpoint watermark", cut.Watermark)
	if err != nil {
		return wal.CheckpointCut{}, err
	}
	if err := l.ensureDurableThrough(cut.Watermark); err != nil {
		return wal.CheckpointCut{}, err
	}
	var aux any
	if cut.AuxiliaryBlobDigestsHash != "" {
		aux = cut.AuxiliaryBlobDigestsHash
	}
	raw, err := l.callWriter(
		`SELECT pfj.journal_prepare_cut($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		cut.OperationID, watermark, cut.ExpectedHeadCommitID,
		cut.TreeHash, cut.CanonicalRequestHash, aux,
	)
	if err != nil {
		return wal.CheckpointCut{}, err
	}
	return l.setCut(raw)
}

// ResolveCheckpointCut records the definitive backend receipt (landed with its
// commit id, or aborted) in the database.
func (l *Log) ResolveCheckpointCut(operationID, commitID string, landed bool) error {
	var commit any
	if commitID != "" {
		commit = commitID
	}
	raw, err := l.callWriter(
		`SELECT pfj.journal_resolve_cut($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		operationID, commit, landed,
	)
	if err != nil {
		return err
	}
	_, err = l.setCut(raw)
	return err
}

// FinalizeCheckpointCut marks a landed cut fully compacted (the database
// verifies base has reached the cut watermark).
func (l *Log) FinalizeCheckpointCut(operationID string) error {
	raw, err := l.callWriter(
		`SELECT pfj.journal_finalize_cut($1,$2,$3,$4,$5,$6,$7,$8)`,
		operationID,
	)
	if err != nil {
		return err
	}
	_, err = l.setCut(raw)
	return err
}

// CheckpointCutState returns the mirrored durable cut fact.
func (l *Log) CheckpointCutState() (wal.CheckpointCut, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cut, l.hasCut
}

// CompactThrough advances the verified logical base. The database fails
// closed (PF011) unless the generation's OWN landed/finalized checkpoint cut
// proves the prefix, and the new base commit is exactly that cut's landed
// commit — a same-volume commit from anywhere else is not proof. No physical
// deletion happens here; the physical trimmer is a separate bounded job that
// never holds the append head lock.
func (l *Log) CompactThrough(seq uint64) error {
	through, err := checkedSQLBigint("logical trim sequence", seq)
	if err != nil {
		return err
	}
	raw, err := l.callWriter(
		`SELECT pfj.journal_logical_trim($1,$2,$3,$4,$5,$6,$7,$8)`,
		through,
	)
	if err != nil {
		return err
	}
	return l.applyGeneration(raw)
}

// CompactRecoveredCheckpoint advances the base for a cut recovered from the
// database itself (cold start found a landed/finalized cut whose compaction
// had not finished). The proof requirements are identical to CompactThrough.
func (l *Log) CompactRecoveredCheckpoint(operationID string) error {
	l.mu.Lock()
	cut, has := l.cut, l.hasCut
	l.mu.Unlock()
	if !has || cut.OperationID != operationID {
		return fmt.Errorf("%w: recovered checkpoint cut %q not found", ErrNotFound, operationID)
	}
	if cut.Status != wal.CheckpointLanded && cut.Status != wal.CheckpointFinalized {
		return fmt.Errorf("%w: recovered checkpoint cut %q has no landed proof", ErrProofMissing, operationID)
	}
	return l.CompactThrough(cut.Watermark)
}

// RotateControlOnlyThrough performs the control-only maintenance rotation:
// the caller has proven (from decoded durable records) that the prefix below
// watermark carries no user mutation and that the record at sidecarSeq is a
// complete exact snapshot sidecar. The database re-verifies the sidecar's
// stored hash and refuses to cross a prepared checkpoint cut. Rotation is one
// atomic transaction, so there is no prepared maintenance state to recover.
func (l *Log) RotateControlOnlyThrough(watermark, sidecarSeq uint64) error {
	watermarkSQL, err := checkedSQLBigint("control rotation watermark", watermark)
	if err != nil {
		return err
	}
	sidecarSQL, err := checkedSQLBigint("control rotation sidecar sequence", sidecarSeq)
	if err != nil {
		return err
	}
	if sidecarSeq == ^uint64(0) {
		return fmt.Errorf("%w: control rotation sidecar has no exclusive end", ErrBounds)
	}
	if _, err := checkedSQLBigint("control rotation exclusive end", sidecarSeq+1); err != nil {
		return err
	}
	if err := l.ensureDurableThrough(sidecarSeq + 1); err != nil {
		return err
	}
	sidecarHash, err := l.recordHashAt(sidecarSeq)
	if err != nil {
		return err
	}
	raw, err := l.callWriter(
		`SELECT pfj.journal_rotate_control($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		watermarkSQL, sidecarSQL, sidecarHash,
	)
	if err != nil {
		return err
	}
	return l.applyGeneration(raw)
}

// RecoverControlRotation is a no-op: remote rotation is atomic in one
// database transaction, so a prepared-but-unfinished maintenance state
// cannot exist.
func (l *Log) RecoverControlRotation() error { return nil }

// recordHashAt reads the stored record hash of one durable LSN.
func (l *Log) recordHashAt(seq uint64) (string, error) {
	backoff := retryBackoffFloor
	for {
		hash, err := l.queryRecordHash(seq)
		if err == nil {
			return hash, nil
		}
		if typed := typedError(err); typed != nil {
			return "", typed
		}
		if !retryableSQLFailure(err) {
			return "", fmt.Errorf("remotejournal: record hash at %d: %w", seq, err)
		}
		select {
		case <-l.life.Done():
			return "", fmt.Errorf("%w: record hash at %d: %v (last attempt: %v)", ErrUnknownOutcome, seq, l.life.Err(), err)
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > retryBackoffCeil {
			backoff = retryBackoffCeil
		}
	}
}

func (l *Log) queryRecordHash(seq uint64) (string, error) {
	fromSQL, err := checkedSQLBigint("record hash sequence", seq)
	if err != nil {
		return "", err
	}
	toSQL, err := checkedSQLBigint("record hash end sequence", seq+1)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(l.life, l.cfg.CallTimeout)
	defer cancel()
	rows, err := l.pool.Query(ctx,
		`SELECT seq, record_hash FROM pfj.journal_record_hashes($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		l.generationID, int64(l.epoch), l.capability, l.cfg.LeaseID, l.cfg.FencingToken,
		l.managerEpoch, l.runtimeSeq, l.cfg.AuthorityRuntimeID,
		fromSQL, toSQL,
	)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var rowSeq int64
		var hash string
		if err := rows.Scan(&rowSeq, &hash); err != nil {
			return "", err
		}
		if uint64(rowSeq) == seq {
			return hash, nil
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("%w: LSN %d is not retained", wal.ErrJournalDiverged, seq)
}
