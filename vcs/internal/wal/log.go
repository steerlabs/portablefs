package wal

import (
	"errors"

	"github.com/steerlabs/portablefs/vcs/internal/ctlrec"
)

// ErrJournalQuota classifies a DEFINITE pre-reservation admission rejection:
// the durable log's database-owned backlog quota is exhausted, nothing was
// staged or reserved, and nothing about the rejected intent will ever become
// durable. Implementations wrap it (remotejournal.ErrQuota chains to it) so
// the authority filesystem and protocol layer can map quota exhaustion to the
// canonical EDQUOT wire status WITHOUT consuming an exact-once identity: a
// rejection that cannot be durably recorded must never advance a session's
// slot sequence.
var ErrJournalQuota = errors.New("wal: durable journal backlog quota exceeded (definite pre-reservation rejection)")

// This file defines the DurableLog boundary: the narrow contract WorkFS and
// the checkpointer program against, implemented by
//
//   - *WAL (this package): the local file write-ahead log, optionally paired
//     with a synchronous standby replica. This is the explicit development /
//     self-host / offline-mount / fault-test implementation. It is NOT the
//     managed-production log.
//   - remotejournal.Log: the managed-production implementation backed by a
//     fenced PostgreSQL journal reached through SECURITY DEFINER functions.
//     Managed production has no persistent local WAL/cache/opstate files; the
//     remote journal is the only acknowledged durability authority.
//
// The contract preserves the durable-before-visible write path: records are
// staged with AppendBatchBuffered (LSN reservation, no durability, no visible
// mutation), made durable with CommitThrough (fsync+replicate for the file
// WAL; a committed database transaction for the remote journal), and only
// then applied to the visible tree.

// LogBounds are the admission bounds a DurableLog enforces BEFORE staging or
// allocation. Callers (WorkFS) consult them to split or reject oversized
// intents with typed errors instead of discovering limits at commit time.
type LogBounds struct {
	// MaxWriteDataBytes bounds one user write payload (OpWrite Data).
	MaxWriteDataBytes int
	// MaxIntentBytes bounds one whole encoded logical intent (one record,
	// including a whole OpBatch).
	MaxIntentBytes int
	// MaxGroupRecords / MaxGroupBytes bound one journal commit group.
	MaxGroupRecords int
	MaxGroupBytes   int64
	// MaxReplayPageRecords / MaxReplayPageBytes bound one replay page.
	MaxReplayPageRecords int
	MaxReplayPageBytes   int64
}

// DurableLog is the durability boundary between the working filesystem and
// its acknowledged log. Semantics every implementation must uphold:
//
//   - AppendBatchBuffered reserves ONE contiguous LSN range under an internal
//     serializer and stages the records without making them durable or
//     visible. All-or-nothing: a failure consumes no LSN.
//   - CommitThrough(seq) returns nil only when every record with LSN ≤ seq is
//     durable per the implementation's acknowledged durability definition.
//     An UNKNOWN outcome (lost response) must be resolved internally (exact
//     lookup / retry with identical bytes) or surfaced as an error after
//     poisoning — never fabricated success.
//   - Poison permanently fences the log; PoisonedCh is closed at that moment.
//   - ReplayInto streams the retained suffix in LSN order with bounded memory.
//   - CompactThrough only advances a verified logical cut; it never discards
//     unproven records.
//   - RecordCodec/ControlCodec identify the single canonical encoding of this
//     log's current epoch. No epoch mixes codecs.
type DurableLog interface {
	// Write path.
	AppendBatchBuffered(records []Record) (firstSeq, endSeq uint64, err error)
	CommitThrough(seq uint64) error

	// Capacity and observability.
	OverCapacity() bool
	SetCapacity(bytes int64)
	BacklogBytes() int64
	CompactedThrough() uint64
	Watermark() uint64
	Epoch() uint64
	BaseCommitID() string
	Bounds() LogBounds

	// Fencing.
	Poison()
	IsPoisoned() bool
	PoisonedCh() <-chan struct{}

	// Bounded replay.
	ReplayInto(fn func(Record) error) error
	RecordsBelowInto(seq uint64, fn func(Record) error) error

	// Logical compaction (verified cut advance; not physical deletion).
	CompactThrough(seq uint64) error

	// Checkpoint cut lifecycle (see CheckpointCut).
	PrepareCheckpointCut(cut CheckpointCut) (CheckpointCut, error)
	ResolveCheckpointCut(operationID, commitID string, landed bool) error
	FinalizeCheckpointCut(operationID string) error
	CheckpointCutState() (CheckpointCut, bool)
	CompactRecoveredCheckpoint(operationID string) error

	// Codec identity for this epoch.
	RecordCodec() string
	ControlCodec() string
}

// FileLogBounds are the legacy local file WAL bounds. The file WAL frames gob
// records with a 256 MiB frame ceiling and has no group/page limits beyond
// available memory; these values keep existing dev/self-host behavior.
func FileLogBounds() LogBounds {
	return LogBounds{
		MaxWriteDataBytes:    maxRecordBytes - (4 << 20),
		MaxIntentBytes:       maxRecordBytes,
		MaxGroupRecords:      0, // 0 = unbounded (file WAL group commit is one fsync)
		MaxGroupBytes:        0,
		MaxReplayPageRecords: 0,
		MaxReplayPageBytes:   0,
	}
}

// ProductionLogBounds are the FINAL managed-production bounds: 1 MiB one
// write, 8 MiB one logical intent, 128 records / 16 MiB one journal commit
// group, 256 records / 16 MiB one replay page.
//
// MaxGroupRecords is NOT client-tunable: the released migrations enforce the
// same 128 as a server-side backstop (journal_append and journal_append_v3
// reject larger groups with PF004, and journal_append_receipts pins
// record_count to 1..128), and a typed PF004 poisons the log. A 512-record
// write-back flush therefore intentionally spans four sequential commit
// groups (one durable transaction each); collapsing them into one commit
// requires a new append-only migration relaxing all three server bounds
// first, then this constant. The 256-record replay page bound is a separate
// constant with its own server mirror — never couple the two.
func ProductionLogBounds() LogBounds {
	return LogBounds{
		MaxWriteDataBytes:    MaxPFR1WriteDataBytes,
		MaxIntentBytes:       MaxPFR1RecordBytes,
		MaxGroupRecords:      128,
		MaxGroupBytes:        16 << 20,
		MaxReplayPageRecords: 256,
		MaxReplayPageBytes:   16 << 20,
	}
}

// ─── *WAL conformance ────────────────────────────────────────────────────────

var _ DurableLog = (*WAL)(nil)

// Bounds reports the file WAL's legacy admission bounds.
func (w *WAL) Bounds() LogBounds { return FileLogBounds() }

// RecordCodec identifies the file WAL's record encoding (gob framing).
func (w *WAL) RecordCodec() string { return GobRecordCodec }

// ControlCodec identifies the file WAL's control payload encoding.
func (w *WAL) ControlCodec() string { return ctlrec.GobControlCodec }

// ReplayInto streams every retained record in LSN order. The file WAL loads
// its records eagerly (the local file is the bounded dev-scale cache); the
// remote journal streams true pages.
func (w *WAL) ReplayInto(fn func(Record) error) error {
	records, err := w.Replay()
	if err != nil {
		return err
	}
	for _, r := range records {
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}

// RecordsBelowInto streams every live record with Seq < seq in LSN order.
func (w *WAL) RecordsBelowInto(seq uint64, fn func(Record) error) error {
	records, err := w.RecordsBelow(seq)
	if err != nil {
		return err
	}
	for _, r := range records {
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}
