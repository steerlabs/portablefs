package pfj3

import (
	"errors"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// EntryLog is the uniform journal surface the authority filesystem consumes:
// every log speaks JournalEntry{Tree, Controls}. A native PFJ3 log journals
// both arms in one row; the legacy adapter below exposes a PFR1/file log as
// one-tree/no-controls entries. Consumers hold ONE interface — there are
// deliberately no optional "v3" type assertions anywhere downstream: the
// construction site chooses the implementation exactly once.
type EntryLog interface {
	wal.DurableLog

	// AppendEntriesBuffered reserves contiguous LSNs for the given entries
	// (tree/controls arms; the LSN fields are assigned by the log) and stages
	// their canonical bytes. Durability still flows through CommitThrough.
	AppendEntriesBuffered(entries []JournalEntry) (firstSeq, endSeq uint64, err error)

	// ReplayEntriesInto streams the retained suffix as uniform entries in LSN
	// order, after byte/chain verification.
	ReplayEntriesInto(fn func(JournalEntry) error) error

	// IssueAdmissionFact mints one capability-bound short-lived database time
	// fact for a PFC2 control transition, in the same fenced database that
	// will validate and consume it at append. Legacy logs fail closed with
	// ErrControlsUnsupported: their control payloads carry no database-minted
	// facts, and host clocks are never a substitute.
	IssueAdmissionFact(scope pfc2.FactScope) (pfc2.IssuedFact, error)
}

// ErrControlsUnsupported reports an attempt to journal PFC2 controls through
// a legacy PFR1/file log. Managed PFC2 state-changing operations require a
// PFJ3 generation; the caller maps this to its migration-required result.
var ErrControlsUnsupported = errors.New("pfj3: this journal generation cannot carry PFC2 controls (PFJ3 generation required)")

// LegacyRecordLog adapts a PFR1/file wal.DurableLog to the uniform EntryLog
// shape: every entry is exactly one tree record and no controls. Legacy
// control state keeps riding wal.OpControl tree records with the legacy
// control codec, exactly as before — this adapter changes shape, never
// semantics.
type LegacyRecordLog struct {
	wal.DurableLog
}

// WrapLegacy wraps a record-oriented log in the uniform entry shape.
func WrapLegacy(log wal.DurableLog) LegacyRecordLog { return LegacyRecordLog{DurableLog: log} }

// AppendEntriesBuffered forwards one tree record per entry; any PFC2 control
// arm fails closed with ErrControlsUnsupported before reserving anything.
func (l LegacyRecordLog) AppendEntriesBuffered(entries []JournalEntry) (uint64, uint64, error) {
	records := make([]wal.Record, 0, len(entries))
	for i := range entries {
		if len(entries[i].Controls) != 0 {
			return 0, 0, fmt.Errorf("%w (entry %d carries %d controls)", ErrControlsUnsupported, i, len(entries[i].Controls))
		}
		if entries[i].Tree == nil {
			return 0, 0, malformedf("entry %d has no arms", i)
		}
		records = append(records, *entries[i].Tree)
	}
	return l.DurableLog.AppendBatchBuffered(records)
}

// ReplayEntriesInto streams every retained record as a one-tree entry.
func (l LegacyRecordLog) ReplayEntriesInto(fn func(JournalEntry) error) error {
	return l.DurableLog.ReplayInto(func(r wal.Record) error {
		rec := r
		return fn(JournalEntry{LSN: r.Seq, Tree: &rec})
	})
}

// IssueAdmissionFact fails closed: legacy generations mint no database time
// facts, so PFC2 control transitions cannot be journaled through them.
func (l LegacyRecordLog) IssueAdmissionFact(pfc2.FactScope) (pfc2.IssuedFact, error) {
	return pfc2.IssuedFact{}, fmt.Errorf("%w: admission facts require a PFJ3/PFC2 generation", ErrControlsUnsupported)
}

// ControlsOf returns the decoded control records of an entry (convenience for
// apply loops that treat the two arms uniformly).
func ControlsOf(e *JournalEntry) []pfc2.Record { return e.Controls }
