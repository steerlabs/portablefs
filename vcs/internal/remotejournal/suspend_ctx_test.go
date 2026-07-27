package remotejournal

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func suspendCtxLog(db *fakeJournalDB) (*Log, string) {
	tip := [32]byte{9, 9, 9}
	tipHex := hex.EncodeToString(tip[:])
	return &Log{
		pool: db, life: context.Background(),
		cfg: Config{
			TenantID: "tenant-1", VolumeID: "volume-1",
			LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: time.Second,
		},
		generationID: "jgen-ctx", epoch: 1,
		branchID:   "branch-1",
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		durableTip: tip,
		poisonedCh: make(chan struct{}),
	}, tipHex
}

func suspendReceiptJSONFor(operationID, tipHex string, replayed bool) []byte {
	return []byte(fmt.Sprintf(`{
		"operationId":%q,"status":"suspended","tenantId":"tenant-1",
		"volumeId":"volume-1","branchId":"branch-1","generationId":"jgen-ctx",
		"epoch":"1","nextSeq":"0","tipDigest":"%s","writerFence":"3",
		"managerEpoch":"2","authorityRuntimeSeq":"4","authorityRuntimeId":"runtime-1",
		"suspendedAtDbMs":"5","replayed":%v
	}`, operationID, tipHex, replayed))
}

// TestSuspendCallerDeadlineStopsWaitingWithoutInventingFailure is the
// response-lost + caller-timeout shape: attempt 1 dies on a retryable
// transport failure AFTER the statement may have committed; the caller's
// bounded context expires during the backoff. The result is ErrUnknownOutcome
// (never a fabricated failure), the ONE attempt used the immutable request,
// and the local suspend gate stays closed.
func TestSuspendCallerDeadlineStopsWaitingWithoutInventingFailure(t *testing.T) {
	db := &fakeJournalDB{err: &pgconn.PgError{Code: "08006", Message: "connection failure"}}
	l, tipHex := suspendCtxLog(db)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := l.SuspendExact(ctx, "pfjsd-ctx", 0, tipHex)
	if !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("caller deadline after an ambiguous attempt must be UNKNOWN, got %v", err)
	}
	if errors.Is(err, ErrConflict) || errors.Is(err, ErrFenced) {
		t.Fatalf("an unknown outcome must never be dressed as a definitive failure: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the caller bound was not honored (took %s)", elapsed)
	}
	if db.callCount() < 1 {
		t.Fatal("the immutable request was never attempted")
	}
	l.mu.Lock()
	gateClosed := l.suspending && !l.suspended
	l.mu.Unlock()
	if !gateClosed {
		t.Fatal("after an unknown outcome the suspend gate must stay closed (a suspension may exist server-side)")
	}
}

// TestSuspendRetryAfterUnknownOutcomeReplaysExactReceipt: the restart/retry
// half of the lost-response story. The SAME immutable operation id replays
// the receipt the first (response-lost) attempt committed — replayed=true,
// identical facts, no second suspension.
func TestSuspendRetryAfterUnknownOutcomeReplaysExactReceipt(t *testing.T) {
	db := &fakeJournalDB{
		errors: []error{&pgconn.PgError{Code: "08006", Message: "connection failure"}},
	}
	l, tipHex := suspendCtxLog(db)
	db.responses = [][]byte{nil, suspendReceiptJSONFor("pfjsd-ctx", tipHex, true)}

	// Attempt 1: ambiguous loss under a caller bound → unknown outcome.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, err := l.SuspendExact(ctx, "pfjsd-ctx", 0, tipHex)
	cancel()
	if !errors.Is(err, ErrUnknownOutcome) {
		t.Fatalf("first attempt: %v, want unknown outcome", err)
	}

	// Attempt 2 (retry or restarted process): SAME id, fresh bound. The SQL
	// receipt answers replayed=true with the exact original facts.
	receipt, err := l.SuspendExact(context.Background(), "pfjsd-ctx", 0, tipHex)
	if err != nil {
		t.Fatalf("exact retry after unknown outcome: %v", err)
	}
	if !receipt.Replayed || receipt.OperationID != "pfjsd-ctx" || receipt.TipDigest != tipHex {
		t.Fatalf("retry must replay the exact receipt, got %+v", receipt)
	}
	l.mu.Lock()
	resolved := l.suspended && !l.suspending
	l.mu.Unlock()
	if !resolved {
		t.Fatal("the replayed receipt must resolve the suspend gate")
	}
}

// TestSuspendPreCanceledCallerNeverExecutes: a context already dead before
// the FIRST attempt provably executed nothing — a plain context error (not
// unknown outcome), and the gate reopens because no statement was sent.
func TestSuspendPreCanceledCallerNeverExecutes(t *testing.T) {
	db := &fakeJournalDB{}
	l, tipHex := suspendCtxLog(db)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := l.SuspendExact(ctx, "pfjsd-pre", 0, tipHex)
	if err == nil || errors.Is(err, ErrUnknownOutcome) || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled caller: %v, want a plain context error", err)
	}
	if db.callCount() != 0 {
		t.Fatalf("pre-canceled caller executed %d statements, want 0", db.callCount())
	}
	l.mu.Lock()
	reopened := !l.suspending
	l.mu.Unlock()
	if !reopened {
		t.Fatal("nothing executed: the gate must reopen for a later exact attempt")
	}
}
