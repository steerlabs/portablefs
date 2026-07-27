package workfs

import (
	"fmt"
	"sort"
)

// This file is the typed seam between the live WorkFS and a LATER
// RecoveryRoot integration. It captures and imports recovery-plane state —
// the inode-identity allocator plus stable-identity references to
// recovery-controlled inodes (parked orphans, open pins) — as plain values.
// It deliberately carries NO user names (recovery controls never mix into
// the user namespace) and never touches a local durable file: durability of
// this state belongs to the caller (PFT2 RecoveryRoot / the database).

// AllocatorState is the explicit inode-identity allocator state:
//
//	Namespace    — branch allocation namespace (0 = legacy flat space);
//	NextLocal    — next unassigned local counter within Namespace;
//	MaxInoSeen   — monotonic high-water over every id ever observed;
//	DurableFloor — durable recovery floor (PFT2 MaxInoSeen); fresh flat
//	               allocation is strictly above max(MaxInoSeen, DurableFloor).
type AllocatorState struct {
	Namespace    uint32
	NextLocal    uint64
	MaxInoSeen   uint64
	DurableFloor uint64
}

// validate rejects torn or non-canonical allocator state on import.
func (s AllocatorState) validate() error {
	if s.Namespace > maxInodeNamespace {
		return fmt.Errorf("vcs: allocator namespace %d outside 0..%d", s.Namespace, maxInodeNamespace)
	}
	if s.NextLocal < 1 || s.NextLocal > maxInodeLocalCounter+1 {
		return fmt.Errorf("vcs: allocator next local %d outside 1..%d", s.NextLocal, maxInodeLocalCounter+1)
	}
	if s.MaxInoSeen > maxIno {
		return fmt.Errorf("vcs: allocator high-water %d exceeds max inode id %d", s.MaxInoSeen, maxIno)
	}
	if s.DurableFloor > maxIno {
		return fmt.Errorf("vcs: allocator durable floor %d exceeds max inode id %d", s.DurableFloor, maxIno)
	}
	// Internal consistency: the last id this state claims to have handed out
	// must be covered by its own high-water (a torn capture is refused).
	if s.NextLocal > 1 {
		last := s.NextLocal - 1
		if s.Namespace != 0 {
			last = uint64(s.Namespace)<<inoNamespaceShift | last
		}
		if last > s.MaxInoSeen {
			return fmt.Errorf("vcs: torn allocator state: last allocated id %d above high-water %d", last, s.MaxInoSeen)
		}
	}
	return nil
}

// RecoveryState is the typed export a later RecoveryRoot integration
// persists: the allocator plus the stable identities of recovery-controlled
// inodes. Orphan/pin references are identities only — the inodes themselves
// stay in the inode table and the user tree remains name-free here.
type RecoveryState struct {
	Allocator AllocatorState
	// OrphanInos are the parked (open-after-unlink) inode identities.
	OrphanInos []uint64
	// PinnedInos are inode identities held open by live mounts (legacy
	// open-handle leases or managed PFC2 open pins).
	PinnedInos []uint64
}

// CaptureRecoveryState snapshots the allocator and the recovery-controlled
// inode references under one lock hold, sorted and deduplicated for
// deterministic downstream encoding.
func (fs *FS) CaptureRecoveryState() RecoveryState {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	out := RecoveryState{
		Allocator: AllocatorState{
			Namespace:    fs.alloc.namespace,
			NextLocal:    fs.alloc.nextLocal,
			MaxInoSeen:   fs.alloc.maxInoSeen,
			DurableFloor: fs.alloc.durableFloor,
		},
	}
	for ino := range fs.orphans {
		out.OrphanInos = append(out.OrphanInos, ino)
	}
	pinned := map[uint64]struct{}{}
	for ino := range fs.openInodes {
		pinned[ino] = struct{}{}
	}
	if fs.managed != nil {
		for _, ino := range fs.managed.applied.PinnedInodes() {
			pinned[ino] = struct{}{}
		}
	}
	for ino := range pinned {
		out.PinnedInos = append(out.PinnedInos, ino)
	}
	sort.Slice(out.OrphanInos, func(i, j int) bool { return out.OrphanInos[i] < out.OrphanInos[j] })
	sort.Slice(out.PinnedInos, func(i, j int) bool { return out.PinnedInos[i] < out.PinnedInos[j] })
	return out
}

// ImportAllocatorState folds a durably restored allocator into the live one.
// Import is validating and monotonic: canonical bounds are enforced, the
// namespace must match (a cross-namespace restore is a different branch and
// fails closed), and no field ever moves backwards — the live allocator only
// rises, so an import can never re-expose a deleted inode id. Nothing is
// mutated on any error.
func (fs *FS) ImportAllocatorState(s AllocatorState) error {
	if err := s.validate(); err != nil {
		return err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if s.Namespace != fs.alloc.namespace {
		return fmt.Errorf("vcs: allocator namespace mismatch: imported %d, live %d", s.Namespace, fs.alloc.namespace)
	}
	if s.NextLocal > fs.alloc.nextLocal {
		fs.alloc.nextLocal = s.NextLocal
	}
	if s.MaxInoSeen > fs.alloc.maxInoSeen {
		fs.alloc.maxInoSeen = s.MaxInoSeen
	}
	if s.DurableFloor > fs.alloc.durableFloor {
		fs.alloc.durableFloor = s.DurableFloor
	}
	return nil
}

// ImportRecoveryState validates and folds a restored recovery snapshot into
// the live FS: allocator (as ImportAllocatorState) plus reference checks that
// every restored orphan is a parked inode-table record and every restored pin
// resolves in the inode table. It creates nothing: reconstruction of the
// records themselves stays with the existing control/replay code, so a torn
// or foreign reference fails closed here instead of minting phantom inodes.
func (fs *FS) ImportRecoveryState(s RecoveryState) error {
	if err := s.Allocator.validate(); err != nil {
		return err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if s.Allocator.Namespace != fs.alloc.namespace {
		return fmt.Errorf("vcs: allocator namespace mismatch: imported %d, live %d", s.Allocator.Namespace, fs.alloc.namespace)
	}
	if err := validateInoRefs("orphan", s.OrphanInos, s.Allocator.MaxInoSeen, func(ino uint64) bool {
		return fs.orphans[ino] != nil
	}); err != nil {
		return err
	}
	if err := validateInoRefs("pinned", s.PinnedInos, s.Allocator.MaxInoSeen, func(ino uint64) bool {
		return fs.byIno[ino] != nil
	}); err != nil {
		return err
	}
	if s.Allocator.NextLocal > fs.alloc.nextLocal {
		fs.alloc.nextLocal = s.Allocator.NextLocal
	}
	if s.Allocator.MaxInoSeen > fs.alloc.maxInoSeen {
		fs.alloc.maxInoSeen = s.Allocator.MaxInoSeen
	}
	if s.Allocator.DurableFloor > fs.alloc.durableFloor {
		fs.alloc.durableFloor = s.Allocator.DurableFloor
	}
	return nil
}

// validateInoRefs enforces canonical reference invariants for one identity
// list: ids in 1..maxIno, covered by the snapshot's own high-water, strictly
// ascending (sorted, duplicate-free), and resolvable in the live table.
func validateInoRefs(kind string, inos []uint64, highWater uint64, present func(uint64) bool) error {
	var prev uint64
	for _, ino := range inos {
		if ino < 1 || ino > maxIno {
			return fmt.Errorf("vcs: recovery %s inode %d outside 1..%d", kind, ino, maxIno)
		}
		if ino > highWater {
			return fmt.Errorf("vcs: recovery %s inode %d above the snapshot's allocator high-water %d", kind, ino, highWater)
		}
		if ino <= prev {
			return fmt.Errorf("vcs: recovery %s inode list not strictly ascending at %d", kind, ino)
		}
		prev = ino
		if !present(ino) {
			return fmt.Errorf("vcs: recovery %s inode %d is not in the inode table", kind, ino)
		}
	}
	return nil
}
