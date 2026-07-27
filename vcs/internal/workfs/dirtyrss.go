package workfs

import (
	"math"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/metrics"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// Dirty-block memory accounting and its admission bound.
//
// Every uncommitted (dirty) file block lives in RAM, and a partial write into
// a backed block materialises the WHOLE blockSize buffer: one byte written
// into each 4 MiB region of a large backed file costs 4 MiB of resident
// memory per ~40 journal bytes — a ~100,000x RAM-vs-journal-quota
// amplification. The managed child never folds dirty blocks out in-process
// (checkpoints belong to the external HistoryCut service), so without a bound
// one tenant's write pattern can OOM the shared manager host while consuming
// kilobytes of its journal quota. fs.dirtyBytes keeps the exact resident
// total; SetDirtyRSSMax (VCS_DIRTY_RSS_MAX_MB) bounds it at write admission.
//
// The bound follows the journal control-reserve philosophy: only tree WRITES
// (the sole dirty-block allocators) are refused at the bound. Reads, deletes,
// truncates, metadata ops, control rows (exactness outcomes, session
// lifecycle, lock releases), and anything that RELEASES memory keep working,
// so a volume at the bound stays recoverable — never wedged.
//
// The counter is the sum of len() over every dirty block buffer. A truncate
// that trims a boundary block keeps the buffer's backing capacity for the
// amortised-append optimisation, so true RSS can exceed the counter by at
// most one block's slack per truncated file — the same order as the inode
// and map overheads deliberately left unaccounted.

var (
	dirtyBlockBytesGauge    = metrics.Default.Gauge("vcs_dirty_block_bytes")
	dirtyBlockBytesMaxGauge = metrics.Default.Gauge("vcs_dirty_block_bytes_max")
)

// ErrDirtyRSSCapacity reports a write refused because it would push resident
// dirty-block bytes past the configured bound. It is a DEFINITE
// pre-reservation rejection: nothing was journaled or applied, and the next
// truncate/remove (or an external checkpoint fold) reopens admission.
var ErrDirtyRSSCapacity error = dirtyRSSCapacityError{}

type dirtyRSSCapacityError struct{}

func (dirtyRSSCapacityError) Error() string {
	return "vcs: resident dirty-block bytes exceed VCS_DIRTY_RSS_MAX_MB: writes rejected until truncate/remove releases blocks or a checkpoint folds them"
}

// Unwrap chains the refusal into the existing capacity vocabulary instead of
// minting a new wire mapping: ErrWALCapacity is what the protocol layer's
// quota classifier already records as a definite, durable ENOSPC exact
// outcome (through the journal control reserve), and syscall.ENOSPC is what
// every generic errno mapper translates for legacy surfaces.
func (dirtyRSSCapacityError) Unwrap() []error { return []error{ErrWALCapacity, syscall.ENOSPC} }

// SetDirtyRSSMax bounds resident dirty-block bytes (0 or negative =
// unbounded). It is set once after construction, before serving: cold replay
// must always load the durable history — even one that already exceeds a
// lowered bound — so the bound gates only NEW write admissions; an over-bound
// volume serves reads and releases until writes fit again.
func (fs *FS) SetDirtyRSSMax(maxBytes int64) {
	if maxBytes < 0 {
		maxBytes = 0
	}
	fs.mu.Lock()
	fs.dirtyMax = maxBytes
	fs.mu.Unlock()
	dirtyBlockBytesMaxGauge.Set(maxBytes)
}

// DirtyRSSMax reports the configured dirty-block byte bound (0 = unbounded).
func (fs *FS) DirtyRSSMax() int64 {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.dirtyMax
}

// DirtyBlockBytes reports the exact resident dirty-block byte total
// (telemetry and tests).
func (fs *FS) DirtyBlockBytes() int64 {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.dirtyBytes
}

// dirtyBlockBytesOf sums one inode's resident dirty-block bytes.
func dirtyBlockBytesOf(n *inode) int64 {
	var total int64
	for _, blk := range n.blocks {
		total += int64(len(blk))
	}
	return total
}

// addDirtyBlockBytesLocked moves the exact resident total. Caller holds fs.mu.
func (fs *FS) addDirtyBlockBytesLocked(delta int64) {
	if delta == 0 {
		return
	}
	fs.dirtyBytes += delta
	dirtyBlockBytesGauge.Set(fs.dirtyBytes)
}

// restoreDirtyBlockBytesLocked resets the total to a snapshot (transaction
// rollback restores block state byte-for-byte, so the counter snapshot is
// exact). Caller holds fs.mu.
func (fs *FS) restoreDirtyBlockBytesLocked(v int64) {
	fs.dirtyBytes = v
	dirtyBlockBytesGauge.Set(fs.dirtyBytes)
}

// dirtyWriteReserve is the worst-case dirty-block growth one OpWrite leaf can
// materialise at apply: every touched block filled to blockSize. It
// deliberately subtracts NOTHING for blocks that are already dirty at
// admission time — on the managed store other rows apply between this
// record's reservation and its own apply turn (a truncate can free the very
// blocks the write re-materialises), so only the state-independent ceiling
// provably dominates the apply-time growth. Over-reservation can refuse a
// write slightly early near the bound; it can never overshoot the bound.
func dirtyWriteReserve(r *wal.Record) int64 {
	if r.Op != wal.OpWrite || len(r.Data) == 0 {
		return 0
	}
	length := int64(len(r.Data))
	spanned := (length + blockSize - 1) / blockSize
	if r.Append || r.Offset < 0 || r.Offset > math.MaxInt64-length {
		// The offset resolves at apply (O_APPEND), or is malformed and will
		// be rejected there: an unaligned start can span one extra block.
		return (spanned + 1) * blockSize
	}
	first := r.Offset / blockSize
	last := (r.Offset + length - 1) / blockSize
	return (last - first + 1) * blockSize
}

// dirtyWriteReserveTotal sums the worst-case growth of an intent's leaves.
func dirtyWriteReserveTotal(leaves []wal.Record) int64 {
	var total int64
	for i := range leaves {
		total += dirtyWriteReserve(&leaves[i])
	}
	return total
}

// admitDirtyWriteLocked is the WAL store's bound check: check and apply run
// under one uninterrupted fs.mu hold there, so no reservation is needed —
// the counter cannot move between this check and the write landing. Caller
// holds fs.mu.
func (fs *FS) admitDirtyWriteLocked(r *wal.Record) error {
	need := dirtyWriteReserve(r)
	if need == 0 {
		return nil
	}
	if fs.dirtyMax > 0 && fs.dirtyBytes+fs.dirtyReserved+need > fs.dirtyMax {
		return ErrDirtyRSSCapacity
	}
	return nil
}

// reserveDirtyGrowthLocked is the managed store's check-and-reserve: the
// journal row is admitted (LSN reserved) long before its ordered apply turn,
// so the worst-case growth is held in dirtyReserved across that window.
// Racing writers each reserve under the same fs.mu hold that admits their
// row — N writers passing one stale check (TOCTOU) is impossible, and the
// invariant dirtyBytes+dirtyReserved <= dirtyMax survives every interleaving
// because an apply adds at most its own reservation. Caller holds fs.mu.
func (fs *FS) reserveDirtyGrowthLocked(reserve int64) error {
	if reserve == 0 {
		return nil
	}
	if fs.dirtyMax > 0 && fs.dirtyBytes+fs.dirtyReserved+reserve > fs.dirtyMax {
		return ErrDirtyRSSCapacity
	}
	fs.dirtyReserved += reserve
	return nil
}

// releaseDirtyReserve returns a reservation once its row applied (the exact
// growth is in dirtyBytes now) or failed before becoming durable.
func (fs *FS) releaseDirtyReserve(reserve int64) {
	if reserve == 0 {
		return
	}
	fs.mu.Lock()
	fs.dirtyReserved -= reserve
	fs.mu.Unlock()
}
