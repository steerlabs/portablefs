//go:build linux

package fusev3

import "github.com/steerlabs/portablefs/vcs/internal/mountlog"

// WritebackStats is a bounded aggregate diagnostic snapshot. Dirty entries
// await Authority application; retained entries also include applied data still
// awaiting visibility or durability. Individual identities are never exposed.
type WritebackStats struct {
	Metadata            *mountlog.MetadataStats
	DirtyBytes          int64
	DirtyEntries        int
	RetainedBytes       int64
	RetainedEntries     int
	PendingAdmissions   int
	FlushingIdentities  int
	ScheduledIdentities int
	TrackedIdentities   int
	BufferIdentities    int
	PendingCloses       int
	AppliedSequence     uint64
	DurableSequence     uint64
	DurabilityLag       uint64
	LossSequence        uint64
}

// WritebackStats stays within one epoch. Activity can advance between the
// aggregate buffer, durability and cleanup samples; it is not a completion cut.
func (m *Mount) WritebackStats() WritebackStats {
	if m == nil || m.delegations == nil {
		return WritebackStats{}
	}
	d := m.delegations
	metadata := m.MetadataStats()
	d.epoch.RLock()
	defer d.epoch.RUnlock()
	d.mu.RLock()
	buffer, tracked := d.buf, len(d.byID)
	d.mu.RUnlock()
	stats := buffer.Stats()
	d.durabilityMu.Lock()
	applied, durable := d.appliedHigh, d.durableHigh
	d.durabilityMu.Unlock()
	d.closeMu.Lock()
	closes := d.closePending
	d.closeMu.Unlock()
	return WritebackStats{
		Metadata:   metadata,
		DirtyBytes: stats.AcceptedBytes, DirtyEntries: stats.Accepted,
		RetainedBytes: stats.Bytes, RetainedEntries: stats.Entries,
		PendingAdmissions: stats.WaitingAdmissions, FlushingIdentities: stats.Flushing,
		ScheduledIdentities: stats.Scheduled, TrackedIdentities: tracked,
		BufferIdentities: stats.Identities, PendingCloses: closes,
		AppliedSequence: applied, DurableSequence: durable,
		DurabilityLag: max(applied, durable) - durable, LossSequence: stats.LossSequence,
	}
}
