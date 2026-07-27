package workfs

import (
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/coherence"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// Invalidation fan-out: because the VCS is the single authority, every mutation passes
// through the commit path, so this is the one place that can tell every connected client
// which paths just changed, at which version, and who changed them. Clients apply an
// invalidation iff its version is newer than the one they have cached (so a stale or
// duplicate echo is ignored) and identify their own write-back writes by the owner.
//
// One publish delivers ONE batch (the changes of a single mutation, or of a whole flushed
// write-back ApplyBatch) as a single channel item, so a subscriber observes a batch's
// invalidations together — never torn across the batch boundary.

// Subscribe returns a channel of coherence-invalidation batches plus an unsubscribe func.
// A batch consisting of a single FlushAll invalidation (sent when a subscriber's buffer
// overflows) tells the client to drop ALL cached versions and re-read, so a slow client
// degrades to a full refresh rather than going stale.
func (fs *FS) Subscribe() (<-chan []coherence.Invalidation, func()) {
	fs.subsMu.Lock()
	defer fs.subsMu.Unlock()
	if fs.subs == nil {
		fs.subs = map[int]chan []coherence.Invalidation{}
	}
	id := fs.nextSub
	fs.nextSub++
	ch := make(chan []coherence.Invalidation, 1024)
	fs.subs[id] = ch
	return ch, func() {
		fs.subsMu.Lock()
		if c, ok := fs.subs[id]; ok {
			delete(fs.subs, id)
			close(c)
		}
		fs.subsMu.Unlock()
	}
}

// publish delivers one batch to every subscriber without blocking (it holds only subsMu,
// never fs.mu, and never blocks on a full channel).
func (fs *FS) publish(invs []coherence.Invalidation) {
	if len(invs) == 0 {
		return
	}
	fs.subsMu.Lock()
	for _, ch := range fs.subs {
		select {
		case ch <- invs:
		default:
			// Buffer full: the subscriber is behind. Drain the now-superseded batches and
			// collapse to a single FlushAll (a full re-read). Draining first GUARANTEES the
			// FlushAll lands — a plain non-blocking send into a still-full buffer can be
			// dropped, leaving the client silently and permanently stale.
			drainAndFlush(ch, fs.generation)
		}
	}
	fs.subsMu.Unlock()
}

// PublishRecall broadcasts a handoff recall for subtree p to every subscriber: whichever client
// holds a write-back checkout covering p should flush + check in so a contender can acquire it. A
// client with no covering session ignores it. This is not a cache eviction — it carries Recall=true.
func (fs *FS) PublishRecall(p string) {
	fs.publish([]coherence.Invalidation{{Recall: true, Path: p, Gen: fs.generation}})
}

// drainAndFlush empties ch (whose batches are about to be superseded) and enqueues a single
// FlushAll batch. publish is the only producer and holds subsMu, so after the drain the
// buffer has room and the FlushAll is delivered.
func drainAndFlush(ch chan []coherence.Invalidation, gen uint64) {
	for {
		select {
		case <-ch:
		default:
			select {
			case ch <- []coherence.Invalidation{{FlushAll: true, Gen: gen}}:
			default:
			}
			return
		}
	}
}

// changesFor builds the coherence invalidations for one applied mutation: one per affected
// path (rename touches two), each tagged with the assigned version, the originating owner
// (empty for direct write-through mutations — there the version predicate suppresses the
// self-echo), and the FS generation. Reserved .portablefs- watermark paths are excluded: they are
// authority-internal and never user-visible.
func (fs *FS) changesFor(r wal.Record, owner string, version, orphanIno uint64, relatedInos ...uint64) []coherence.Invalidation {
	paths := affectedPaths(r)
	out := make([]coherence.Invalidation, 0, len(paths))

	// When this mutation parked a node, find which vanished name it parked so a peer mount with that
	// path open can redirect to ino-addressed orphan I/O (the others are plain evictions).
	orphanPath := ""
	if orphanIno != 0 {
		switch r.Op {
		case wal.OpOrphan:
			orphanPath = r.Path
		case wal.OpRemove:
			orphanPath = r.Path // a remove that PARKED (Stage 2: a peer holds the inode open)
		case wal.OpRename:
			orphanPath = r.NewPath // rename-over: the replaced destination is the parked node
		}
	}

	for _, p := range paths {
		if strings.HasPrefix(p, ".portablefs-") {
			continue
		}
		inv := coherence.Invalidation{
			Path: p, Version: version, Owner: owner, Gen: fs.generation,
			InPlace:     isInPlaceOp(r.Op),
			RelatedInos: append([]uint64(nil), relatedInos...),
		}
		if orphanPath != "" && p == orphanPath {
			inv.Orphaned = true
			inv.OrphanIno = orphanIno
		}
		out = append(out, inv)
	}
	return out
}

// relatedInodesLocked captures inode identities before a mutation changes the
// namespace. It lets cache invalidations for a write through one hard-link
// name, an unlink, or rename-over reach every cached alias without scanning
// the authority tree. Caller holds fs.mu.
func (fs *FS) relatedInodesLocked(r wal.Record) []uint64 {
	seen := map[uint64]struct{}{}
	add := func(n *inode) {
		if n != nil && n.ino != 0 {
			seen[n.ino] = struct{}{}
		}
	}
	if r.Ino != 0 {
		add(fs.byIno[r.Ino])
	}
	if r.Path != "" {
		add(fs.resolve(r.Path))
	}
	if r.Op == wal.OpRename && r.NewPath != "" {
		// The source inode changes names, while a replaced destination loses
		// one link (or becomes an orphan). Both alias sets need fresh attrs.
		add(fs.resolve(r.NewPath))
	}
	out := make([]uint64, 0, len(seen))
	for ino := range seen {
		out = append(out, ino)
	}
	return out
}

// affectedPaths is the set of paths a record changes (rename touches two).
func affectedPaths(r wal.Record) []string {
	if r.Ino != 0 && r.Path == "" {
		// Pure orphan-addressed op (OpReap, or OpWrite/OpTruncate to a parked inode with no name):
		// there is no tree name for other mounts to invalidate. A live handle-addressed op carries
		// Path as the mount's current name and still invalidates that path. If the inode was renamed
		// and Path is stale, the write still lands by ino; publishing the stale-name invalidation is
		// acceptable because it only forces a harmless cache drop for that old dentry.
		return nil
	}
	if r.Op == wal.OpRename || r.Op == wal.OpLink {
		return []string{r.Path, r.NewPath}
	}
	if r.Path == "" {
		return nil
	}
	return []string{r.Path}
}

// isInPlaceOp reports whether op changes a path's CONTENT or METADATA without changing its
// name→inode binding (so a peer need not drop the parent dentry — see Invalidation.InPlace).
// Conservative: anything that could create/remove/rename a name returns false (=> NotifyEntry).
// Xattr mutations are attr-level in-place changes exactly like chmod: peers get a
// content/attr invalidation for the path, never a namespace drop.
func isInPlaceOp(op wal.Op) bool {
	switch op {
	case wal.OpWrite, wal.OpTruncate, wal.OpChmod, wal.OpChtimes, wal.OpChown,
		wal.OpSetxattr, wal.OpRemovexattr:
		return true
	default:
		return false
	}
}
