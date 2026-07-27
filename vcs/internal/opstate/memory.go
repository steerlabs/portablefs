package opstate

import (
	"fmt"
	"sync"
)

// Memory is the process-local OperationStore for MANAGED disposable children.
//
// A managed authority is one fenced process per runtime: it cold-replays the
// remote journal on start, never restarts over local state, and is replaced
// (never repaired) when it exits. Lifecycle idempotency across a child's
// death is owned by the DURABLE receipt layers around it — the manager's pfm
// lifecycle receipts and the journal's pfj suspend receipt — so the child
// itself only needs exact in-process receipts to answer lost-response retries
// while it is alive. Checkpoint intents and quiesce markers are checkpoint /
// history-materialization state; a managed child has neither (HistoryCut is
// an external service), so those methods fail loudly instead of pretending a
// durability domain exists.
type Memory struct {
	mu         sync.Mutex
	operations map[string]Operation
}

var _ OperationStore = (*Memory)(nil)

// NewMemory builds an empty in-process operation store.
func NewMemory() *Memory {
	return &Memory{operations: map[string]Operation{}}
}

func (m *Memory) Healthy() error { return nil }

func (m *Memory) Operation(id string) (Operation, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	op, ok := m.operations[id]
	return op, ok
}

func (m *Memory) Tombstone(string) (Tombstone, bool) { return Tombstone{}, false }

func (m *Memory) RecordOperation(op Operation) error {
	if err := op.validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.operations[op.ID]; ok && existing.Fingerprint != op.Fingerprint {
		return fmt.Errorf("opstate: operation %q already recorded with a different fingerprint", op.ID)
	}
	m.operations[op.ID] = op
	return nil
}

// UnknownExpired: a managed child's receipts live for its whole life (one
// process, bounded operation count); nothing is ever pruned, so unknown means
// genuinely new.
func (m *Memory) UnknownExpired(string, string, string) (bool, error) { return false, nil }

func (m *Memory) Quiesced() *QuiesceMarker { return nil }

func (m *Memory) SetQuiesced(QuiesceMarker, Operation) error {
	return fmt.Errorf("opstate: managed authorities have no quiesce marker (history materialization is the external HistoryCut service)")
}

func (m *Memory) LeaseRelease() *LeaseReleaseFact { return nil }

func (m *Memory) SetLeaseReleased(LeaseReleaseFact, Operation) error {
	return fmt.Errorf("opstate: managed authorities have no local lease-release fact (terminal retirement is manager-side)")
}

func (m *Memory) ClearQuiescedForForeignInstance(string) error { return nil }

func (m *Memory) CheckpointIntent() *CheckpointIntent { return nil }

func (m *Memory) PutCheckpointIntent(CheckpointIntent) error {
	return fmt.Errorf("opstate: managed authorities never run checkpoints (no checkpoint intent exists)")
}

func (m *Memory) ResolveCheckpointIntent(string, string, int64) error {
	return fmt.Errorf("opstate: managed authorities never run checkpoints (no checkpoint intent exists)")
}

func (m *Memory) FinalizeCheckpointIntent(string, int64) error {
	return fmt.Errorf("opstate: managed authorities never run checkpoints (no checkpoint intent exists)")
}
