package remotejournal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// SuspendReceipt is the immutable, exact result of ordinary live-journal
// suspension. A retry with the same operation and expected revision returns
// these same facts even though the writer binding was cleared by the first
// committed attempt.
type SuspendReceipt struct {
	OperationID         string
	GenerationID        string
	Epoch               uint64
	NextSeq             uint64
	TipDigest           string
	WriterFence         int64
	ManagerEpoch        int64
	AuthorityRuntimeSeq int64
	AuthorityRuntimeID  string
	SuspendedAtDBMs     int64
	Replayed            bool
}

type suspendReceiptJSON struct {
	OperationID         string         `json:"operationId"`
	Status              string         `json:"status"`
	TenantID            string         `json:"tenantId"`
	VolumeID            string         `json:"volumeId"`
	BranchID            string         `json:"branchId"`
	GenerationID        string         `json:"generationId"`
	Epoch               *decimalUint64 `json:"epoch"`
	NextSeq             *decimalUint64 `json:"nextSeq"`
	TipDigest           string         `json:"tipDigest"`
	WriterFence         *decimalInt64  `json:"writerFence"`
	ManagerEpoch        *decimalInt64  `json:"managerEpoch"`
	AuthorityRuntimeSeq *decimalInt64  `json:"authorityRuntimeSeq"`
	AuthorityRuntimeID  string         `json:"authorityRuntimeId"`
	SuspendedAtDBMs     *decimalInt64  `json:"suspendedAtDbMs"`
	Replayed            *bool          `json:"replayed"`
}

// SuspendExact atomically verifies the expected durable head, changes the
// generation to suspended, clears its writer capability, and stores the exact
// receipt in the same transaction. The SQL receipt is checked before the live
// writer binding so a lost successful response remains replayable.
//
// The CALLER'S BOUNDED CONTEXT governs how long this waits: retries stop at
// ctx expiry with ErrUnknownOutcome — stopping the WAIT never invents a
// failure, and the immutable (operationID, expectedNextSeq, expectedTipDigest)
// request replays the exact receipt on the next attempt or after a restart.
// After an unknown outcome the local suspend gate STAYS CLOSED: the SQL may
// have committed the suspension, so no later append may race it.
func (l *Log) SuspendExact(
	ctx context.Context,
	operationID string,
	expectedNextSeq uint64,
	expectedTipDigest string,
) (SuspendReceipt, error) {
	if l.readOnly {
		return SuspendReceipt{}, errReadOnly
	}
	if operationID == "" || len(operationID) > 256 {
		return SuspendReceipt{}, fmt.Errorf("%w: suspend operation id is required and bounded to 256 bytes", ErrInvalid)
	}
	decodedTip, err := decodeDigest(expectedTipDigest)
	if err != nil {
		return SuspendReceipt{}, fmt.Errorf("%w: expected suspend tip: %v", ErrInvalid, err)
	}
	if fmt.Sprintf("%x", decodedTip) != expectedTipDigest {
		return SuspendReceipt{}, fmt.Errorf("%w: expected suspend tip must be canonical lowercase hex", ErrInvalid)
	}
	expectedNextSQL, err := checkedSQLBigint("suspend expected next sequence", expectedNextSeq)
	if err != nil {
		return SuspendReceipt{}, err
	}

	// CommitThrough and suspend are mutually exclusive. The suspending flag is
	// published under l.mu before checking the local revision, closing the
	// remaining AppendBatchBuffered race without relying on lifecycle callers.
	l.commitMu.Lock()
	defer l.commitMu.Unlock()
	l.mu.Lock()
	l.suspending = true
	if len(l.staged) != 0 || l.durableSeq != expectedNextSeq ||
		fmt.Sprintf("%x", l.durableTip) != expectedTipDigest {
		l.suspending = false
		l.mu.Unlock()
		return SuspendReceipt{}, fmt.Errorf("%w: local durable revision does not match expected suspend revision", ErrConflict)
	}
	l.mu.Unlock()
	finished := false
	outcomeUnknown := false
	defer func() {
		if finished || outcomeUnknown {
			// Success, or an attempt whose outcome is unknown: either way a
			// suspension may exist server-side, so the gate stays closed and
			// only the exact replay (same immutable request) can resolve it.
			return
		}
		l.mu.Lock()
		l.suspending = false
		l.mu.Unlock()
	}()

	fingerprint := canonicalFingerprint(
		"portablefs-journal-suspend-v2",
		operationID,
		l.generationID,
		strconv.FormatUint(l.epoch, 10),
		strconv.FormatUint(expectedNextSeq, 10),
		expectedTipDigest,
		l.cfg.LeaseID,
		strconv.FormatInt(l.cfg.FencingToken, 10),
		strconv.FormatInt(l.managerEpoch, 10),
		strconv.FormatInt(l.runtimeSeq, 10),
		l.cfg.AuthorityRuntimeID,
		capabilityHashHex(l.capability),
	)
	suspendRecordCodec, suspendControlCodec := l.codecPair()
	query := `SELECT pfj.journal_suspend_exact($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`
	args := []any{
		l.generationID, int64(l.epoch), l.capability, l.cfg.LeaseID, l.cfg.FencingToken,
		suspendRecordCodec, suspendControlCodec,
		l.managerEpoch, l.runtimeSeq, l.cfg.AuthorityRuntimeID,
		operationID, fingerprint, expectedNextSQL, expectedTipDigest,
	}
	backoff := retryBackoffFloor
	invalidSuccesses := 0
	attempted := false
	for {
		if err := ctx.Err(); err != nil && !attempted {
			// The caller's bound expired before ANY attempt: provably nothing
			// executed. A plain context error — the same immutable request
			// may simply be retried.
			return SuspendReceipt{}, fmt.Errorf("suspend %s: %w", operationID, err)
		}
		mustRetry := false
		attempted = true
		raw, callErr := l.callJSONB(ctx, query, args...)
		if callErr == nil {
			var wire suspendReceiptJSON
			if decodeErr := json.Unmarshal(raw, &wire); decodeErr != nil {
				callErr = fmt.Errorf("decode exact suspend receipt: %w", decodeErr)
				mustRetry = true
			} else if validationErr := l.validateSuspendReceipt(
				wire, operationID, expectedNextSeq, expectedTipDigest,
			); validationErr != nil {
				callErr = validationErr
				mustRetry = true
			} else {
				l.mu.Lock()
				l.suspending = false
				l.suspended = true
				l.mu.Unlock()
				finished = true
				return suspendReceiptFromWire(wire), nil
			}
			invalidSuccesses++
			if invalidSuccesses >= maxInvalidSuccessBodies {
				cause := fmt.Errorf("%w: suspend %s returned %d invalid success bodies (last: %v)",
					ErrProtocolIntegrity, operationID, invalidSuccesses, callErr)
				l.poison(cause)
				return SuspendReceipt{}, cause
			}
		}
		if typed := typedError(callErr); typed != nil {
			if errors.Is(typed, ErrDurabilityUnavailable) {
				// The durability guard failed before mutation. Keep the local
				// suspend gate closed and retry the exact immutable operation.
				callErr = typed
				mustRetry = true
			} else {
				if errors.Is(typed, ErrFenced) {
					l.poison(typed)
				}
				return SuspendReceipt{}, typed
			}
		}
		if callErr != nil && ctx.Err() != nil {
			// The call itself died with the caller's context: the statement
			// may or may not have committed. Unknown, never invented failure.
			outcomeUnknown = true
			return SuspendReceipt{}, fmt.Errorf("%w: suspend %s: caller deadline during the attempt: %v",
				ErrUnknownOutcome, operationID, callErr)
		}
		if !mustRetry && !retryableSQLFailure(callErr) {
			return SuspendReceipt{}, callErr
		}
		select {
		case <-ctx.Done():
			// The caller stopped waiting after at least one ambiguous
			// attempt: the outcome is UNKNOWN (never fabricated failure).
			// The suspend gate stays closed; the identical request replays
			// the receipt on retry or after restart.
			outcomeUnknown = true
			return SuspendReceipt{}, fmt.Errorf("%w: suspend %s: caller deadline: %v (last attempt: %v)",
				ErrUnknownOutcome, operationID, ctx.Err(), callErr)
		case <-l.life.Done():
			outcomeUnknown = true
			if errors.Is(callErr, ErrDurabilityUnavailable) {
				return SuspendReceipt{}, fmt.Errorf("%w: suspend %s reached its lifecycle deadline: %v: %w",
					ErrUnknownOutcome, operationID, l.life.Err(), callErr)
			}
			return SuspendReceipt{}, fmt.Errorf("%w: suspend %s: %v (last attempt: %v)",
				ErrUnknownOutcome, operationID, l.life.Err(), callErr)
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > retryBackoffCeil {
			backoff = retryBackoffCeil
		}
	}
}

func (l *Log) validateSuspendReceipt(
	wire suspendReceiptJSON,
	operationID string,
	expectedNextSeq uint64,
	expectedTipDigest string,
) error {
	if wire.Replayed == nil || wire.Epoch == nil || wire.NextSeq == nil || wire.WriterFence == nil ||
		wire.ManagerEpoch == nil || wire.AuthorityRuntimeSeq == nil || wire.SuspendedAtDBMs == nil ||
		int64(*wire.SuspendedAtDBMs) <= 0 || wire.Status != "suspended" || wire.OperationID != operationID ||
		wire.TenantID != l.cfg.TenantID || wire.VolumeID != l.cfg.VolumeID || wire.BranchID == "" ||
		(l.branchID != "" && wire.BranchID != l.branchID) ||
		wire.GenerationID != l.generationID || uint64(*wire.Epoch) != l.epoch ||
		uint64(*wire.NextSeq) != expectedNextSeq || wire.TipDigest != expectedTipDigest ||
		int64(*wire.WriterFence) != l.cfg.FencingToken ||
		int64(*wire.ManagerEpoch) != l.managerEpoch ||
		int64(*wire.AuthorityRuntimeSeq) != l.runtimeSeq ||
		wire.AuthorityRuntimeID != l.cfg.AuthorityRuntimeID {
		return fmt.Errorf("%w: suspend receipt does not match the exact requested binding/revision", ErrConflict)
	}
	return nil
}

func suspendReceiptFromWire(wire suspendReceiptJSON) SuspendReceipt {
	return SuspendReceipt{
		OperationID:         wire.OperationID,
		GenerationID:        wire.GenerationID,
		Epoch:               uint64(*wire.Epoch),
		NextSeq:             uint64(*wire.NextSeq),
		TipDigest:           wire.TipDigest,
		WriterFence:         int64(*wire.WriterFence),
		ManagerEpoch:        int64(*wire.ManagerEpoch),
		AuthorityRuntimeSeq: int64(*wire.AuthorityRuntimeSeq),
		AuthorityRuntimeID:  wire.AuthorityRuntimeID,
		SuspendedAtDBMs:     int64(*wire.SuspendedAtDBMs),
		Replayed:            *wire.Replayed,
	}
}
