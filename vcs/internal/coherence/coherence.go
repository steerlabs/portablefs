// Package coherence holds the wire-neutral types shared between the authority
// filesystem (workfs) and the protocol (fsproto) for cache-coherence invalidations.
// It lives in its own leaf package so neither workfs nor fsproto has to import the
// other just to name the invalidation type.
package coherence

// Invalidation is one cache-coherence event the authority pushes to a subscribed client.
//
//   - A normal invalidation (FlushAll=false) says: path Path changed to coherence
//     version Version, under authority generation Gen, originated by delegation Owner.
//     A client applies it (evicting its cached copy of Path) iff Version is newer than
//     the version it has cached for Path; it recognises its own write-back writes by
//     Owner and does not evict them.
//   - A FlushAll invalidation (empty Path) tells the client to drop ALL cached versions
//     and re-read on demand — sent when a subscriber's buffer overflows.
//   - A Recall event (Recall=true, Path = the contended subtree) asks whichever client
//     holds a write-back checkout covering Path to flush its buffered writes and check in
//     NOW, so a different client that is contending for Path can acquire it. This is the
//     delegation handoff: a holder keeps its delegation until recalled, never on a timer. A
//     client with no session covering Path ignores it.
//
// Gen is carried on every event (including liveness-only ones with an empty Path) so a
// client can detect an authority restart/promotion — a new Gen — and refresh before
// comparing any version assigned under the new generation.
type Invalidation struct {
	Path     string
	Version  uint64
	Owner    string
	Gen      uint64
	FlushAll bool
	Recall   bool // a handoff recall for subtree Path (not a cache eviction): holder flush + check in

	// RelatedInos names every existing inode whose aliases may have changed
	// attributes or content as part of this mutation. Hard-link-aware clients
	// use it to fan one path event out to any other aliases they have cached.
	// It is additive on the gob wire; older clients safely ignore it.
	RelatedInos []uint64

	// An orphan invalidation is a normal path invalidation PLUS Orphaned=true and OrphanIno: the
	// name at Path was detached (unlink-while-open or rename-over-open) and parked under OrphanIno.
	// A peer mount that still has Path open redirects that live node to ino-addressed orphan I/O so
	// its open fd survives the cross-mount unlink (POSIX delete-on-last-close). Mounts without an
	// open node at Path just evict it like any other invalidation.
	Orphaned  bool
	OrphanIno uint64 // valid only when Orphaned is true

	// InPlace marks an invalidation whose Path keeps the SAME name→inode binding — a content or
	// metadata change (write/truncate/chmod/chtimes/chown), not a create/remove/rename. The mount
	// uses it to skip dropping the parent dentry (NotifyEntry) for that path: dropping the dentry of
	// a directory a process holds as its CWD disconnects it, so a concurrent getcwd() ENOENTs ->
	// SQLITE_CANTOPEN. Content/attr coherence still flows via NotifyContent + the attr cache. The
	// zero value (false) means "name may have changed" => NotifyEntry, so an older authority that
	// never sets this stays existence-coherent (it just keeps the CWD hazard, the prior behaviour).
	InPlace bool
}
