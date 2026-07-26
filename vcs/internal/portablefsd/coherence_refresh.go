package portablefsd

// Remote-change coherence for live kernel vnodes (macOS FSKit).
//
// macOS UserFS models single-writer media: a live vnode's SIZE is set when
// the kernel first materializes it and is updated only by local write and
// setattr paths — never by getattr (stat refreshes, reads stay capped at the
// stale EOF, mmap zero-fills past it), and FSKit gives the extension no
// invalidation API. The kernel also pins name->item bindings: answering
// ENOENT or ESTALE for a retired item wedges the path until remount, so
// identity rebinding is not an option either (both proven empirically).
//
// The two levers that DO work, both kernel-sanctioned and driveable by the
// unsandboxed daemon through its own mount:
//
//   - ftruncate(2) on a descriptor securely resolved beneath the mount is a
//     VNOP_SETATTR: on success the kernel adopts the new size for the vnode.
//     The daemon truncates to the AUTHORITATIVE size and its own setattr
//     handler consumes the marked request without touching the authority — a
//     pure kernel-state refresh.
//   - msync(MS_INVALIDATE) over a shared mapping is the POSIX contract for
//     "discard cached copies": it drops the stale pages so the next read
//     faults through the extension to the daemon.

import (
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/clientcore"
	"github.com/trendup-ai/portablefs/vcs/internal/fsproto"
	"github.com/trendup-ai/portablefs/vcs/internal/pfslocal"
)

type expectedTruncate struct {
	itemID   uint64
	size     int64
	deadline time.Time
}

const (
	// refreshCoalesce absorbs a burst of remote-write invalidations for one
	// file into a single kernel refresh.
	refreshCoalesce = 25 * time.Millisecond
	// truncateNoteTTL bounds how long a marked refresh may stay pending. An
	// application truncate to the exact same (already current) size inside
	// this window is also consumed — its only observable loss is an mtime
	// bump the remote edit has already superseded.
	truncateNoteTTL = 5 * time.Second
	// staleSampleRetries bounds how long a refresh waits for the authority
	// sample to catch up with state the daemon has already seen (see
	// refreshSample). 40 × refreshCoalesce ≈ 1s, comfortably past a flush.
	staleSampleRetries = 40
)

// scheduleCoherenceRefresh coalesces kernel refreshes for a remotely-changed
// path. The refresh drives syscalls THROUGH the mount, so it runs off the
// event loop holding no daemon locks (the kernel's upcalls are served by
// other goroutines). An invalidation arriving while a worker is in flight
// marks the path dirty and the worker runs ANOTHER full pass: a burst like
// shell truncate-then-write must never end on a mid-flight size, or the
// kernel wedges at it until the next remote edit.
func (a *attach) scheduleCoherenceRefresh(p string) {
	a.mu.Lock()
	rec := a.paths[p]
	if a.detached || rec == nil || rec.attr.Kind == "directory" {
		// The kernel never resolved this path (nothing cached), or it is a
		// directory (no content pages, and listings already revalidate).
		a.mu.Unlock()
		return
	}
	if a.purging == nil {
		a.purging = map[string]bool{}
		a.refreshAgain = map[string]bool{}
	}
	if a.purging[p] {
		a.refreshAgain[p] = true
		a.mu.Unlock()
		return
	}
	a.purging[p] = true
	mount := a.mountPath
	a.mu.Unlock()
	go func() {
		for {
			time.Sleep(refreshCoalesce)
			settled := a.refreshKernelState(mount, p)
			a.mu.Lock()
			if a.refreshAgain[p] || !settled {
				delete(a.refreshAgain, p)
				a.mu.Unlock()
				continue // settled state moved during this pass: run again
			}
			delete(a.purging, p)
			a.mu.Unlock()
			return
		}
	}()
}

// refreshKernelState pushes the authoritative size into the kernel vnode via
// a marked no-op truncate, then drops the vnode's cached pages. The size is
// read RAW from the authority — the daemon-side attr cache races its own
// invalidation-driven eviction on a separate connection, and a stale size
// here would wedge the kernel exactly like the bug this fixes.
// refreshKernelState reports whether the pass left the kernel on the settled
// authoritative state; false means the worker must run another pass. The
// refresh truncate races application writes traveling through the same
// kernel: a local write can land between the sample and the truncate — its
// own echo is invalidation-suppressed, so without the post-apply verify the
// clamp would wedge the kernel on the superseded sample forever. Verifying
// that the authority version did not move past the applied sample makes the
// worker converge on the final state instead (each pass re-samples newer
// state, and versions are monotonic).
func (a *attach) refreshKernelState(mount, p string) bool {
	vol, eno := a.volOrErr()
	if eno != 0 {
		return true
	}
	rec := a.itemByPath(p)
	if rec == nil {
		return true
	}
	size, version, ok := refreshSample(vol, p)
	if !ok {
		return true // unfetchable (gone, or a directory): nothing to converge
	}
	a.mu.Lock()
	if a.expectedTruncates == nil {
		a.expectedTruncates = map[string]expectedTruncate{}
	}
	note := expectedTruncate{
		itemID: rec.item.ItemID, size: size,
		deadline: time.Now().Add(truncateNoteTTL),
	}
	a.expectedTruncates[p] = note
	a.mu.Unlock()
	if !refreshKernelFile(mount, p, rec.item.ItemID, size) {
		// No setattr upcall occurred to consume the note. Remove only the
		// exact note installed by this pass so a future pass can never lose
		// its independently-installed marker.
		a.mu.Lock()
		if current, exists := a.expectedTruncates[p]; exists && current == note {
			delete(a.expectedTruncates, p)
		}
		a.mu.Unlock()
		// A failed safe-open means the name disappeared, changed identity,
		// became a symlink, or is inaccessible. Do not spin on that stale
		// binding: namespace changes publish their own invalidations and the
		// next path resolution or content invalidation schedules the current
		// FSItem. Retrying this obsolete item would be both wasteful and
		// incorrect for a permanent rename-over.
		return true
	}
	if version == 0 {
		return true // versionless authority: nothing to verify against
	}
	_, after, _, _, st, err := vol.Client().GetattrV(p)
	return err != nil || st != fsproto.OK || after <= version
}

// refreshSample reads the authoritative size for p, raw. The sample must be
// at least as new as anything the daemon has already seen for the path (the
// VersionCache floor: self-writes via noteSelfMutation, remote edits via
// invalidation Apply). With two machines writing the same file in the same
// instant, a raw getattr can land BETWEEN the interleaved remote truncate
// and a local, already-acknowledged write whose own echo is suppressed —
// clamping the kernel to that mid-race size would wedge it on a state the
// daemon itself has superseded, with no further event to correct it. A stale
// sample is re-fetched; if the authority still hasn't caught up, the refresh
// bails and leaves the kernel untouched (the next invalidation or local
// write re-runs it) rather than install a size known to be wrong.
func refreshSample(vol *clientcore.Volume, p string) (size int64, version uint64, ok bool) {
	for attempt := 0; ; attempt++ {
		attr, ver, gen, _, st, err := vol.Client().GetattrV(p)
		// Only regular files have kernel content pages and a size that may
		// safely be refreshed. In particular, never drive truncate through a
		// symlink: its target is authority-controlled and may name a host path.
		if err != nil || st != fsproto.OK || attr.Kind != "file" {
			return 0, 0, false
		}
		knownGen, knownVer := vol.VersionCache.GenAndVersion(p)
		if ver == 0 || gen != knownGen || ver >= knownVer {
			return attr.Size, ver, true
		}
		if attempt >= staleSampleRetries {
			return 0, 0, false
		}
		time.Sleep(refreshCoalesce)
	}
}

// consumeExpectedTruncate reports whether req is the daemon's own pending
// kernel-size refresh for path, consuming the note on a match. Only a pure
// size set (optionally with the times the kernel attaches to truncates) can
// match; anything touching mode or ownership is a real application setattr.
// A size mismatch retires the note: the kernel is performing a REAL truncate
// that must reach the authority, and the stale note must not linger.
func (a *attach) consumeExpectedTruncate(p string, req *pfslocal.SetAttrRequest) bool {
	if req.Size == nil || req.Mode != nil || req.UID != nil || req.GID != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if note, ok := a.expectedTruncates[p]; ok {
		delete(a.expectedTruncates, p)
		return now.Before(note.deadline) &&
			note.itemID == req.Item.ItemID &&
			int64(*req.Size) == note.size
	}
	// ftruncate addresses an already-open FSItem, not a pathname. A rename
	// can therefore move that item after the secure open/fstat but before its
	// setattr upcall reaches us. Find the exact item marker so the daemon's
	// refresh remains a no-op at the authority rather than becoming a real
	// truncate of the item's new name. Multiple hard-link aliases retain
	// separate path markers and are consumed one at a time.
	for notedPath, note := range a.expectedTruncates {
		if !now.Before(note.deadline) {
			delete(a.expectedTruncates, notedPath)
			continue
		}
		if note.itemID == req.Item.ItemID && int64(*req.Size) == note.size {
			delete(a.expectedTruncates, notedPath)
			return true
		}
	}
	return false
}
