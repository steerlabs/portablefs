// Package session is the mount-side write-back layer. While a mount holds an exclusive
// checkout on a subtree, mutations are applied LOCALLY (an in-memory overlay) and recorded
// in a durable flush log, then shipped to the authority asynchronously — so writes and
// fsync run at local-disk latency instead of a per-op round-trip. Reads of unmodified
// paths fall through to the authority; reads of locally-edited paths are served from the
// overlay. This is the AFS-style checkout that makes SQLite and interactive workloads fast.
//
// Durability is local-first: a write returns after it is in the overlay and its
// WAL frame has been written to the log fd, so daemon/process crashes replay it.
// Fsync forces the log to local media; the async flusher closes the authority /
// machine-loss window. The authority dedups resent records on their local Seq via
// a durable per-session watermark, so a flush is exactly-once.
package session

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// ErrClosing is returned by a drain cut short because CloseLocalDurable ran
// (journal-first unmount): the drain stops at its batch boundary and closes
// the log on its way out. The un-drained tail stays in pending + the WAL for
// the next clean start's recovery replay; nothing already acked by the
// authority is left behind (the drain compacts each batch before checking).
var ErrClosing = errors.New("session: closing (journal-first unmount); flush drain stopped")

// ErrReleased is returned by a session whose subtree has been idle-released (handed off to
// another mount). The caller re-acquires (Ensure) a fresh session and retries.
var ErrReleased = errors.New("session: released (idle handoff)")

// ErrOrphaned is returned when a write targets a path that Materialize has SEALED — the path was
// detached as an orphan (write-back delete-on-last-close) and any later path-addressed write would
// resurrect the deleted name. The caller re-routes the write to the parked inode by ino.
var ErrOrphaned = errors.New("session: path orphaned, address by ino")

// lastEpoch backs nextEpoch — a STRICTLY MONOTONIC, process-global generation counter.
var lastEpoch uint64

// epochFloorPath, when set, is the file where nextEpoch persists the high-water generation.
// lastEpoch is a process var that resets to 0 on restart and is otherwise floored by the wall
// clock — so a BACKWARD clock step across a restart (NTP step, VM restore/migration) would issue
// a generation BELOW one a prior session already used. With a stable per-(owner,root) SessionID,
// that makes the live owner's flush look stale (epoch < watermark) → ESTALE → its writes strand
// forever. Persisting the floor and seeding from it on startup makes the generation monotonic
// across restarts regardless of the clock.
var (
	epochFloorPath atomic.Pointer[string]
	epochPersistMu sync.Mutex // serializes the read-max-write so the floor file never regresses
)

// nextEpoch returns a strictly-increasing session generation, time-based but guaranteed to
// never repeat or go backward within a process — even across a fast re-acquire (sub-ns) or a
// wall-clock step-back (NTP). Re-acquiring a subtree restarts the local Seq space at 0, so a
// NON-increasing epoch would make the authority treat the new generation as a stale resend
// and silently drop its writes; this guarantees that never happens. The issued value is
// persisted (when a floor is configured) so it also can't regress across a process restart.
func nextEpoch() uint64 {
	for {
		now := uint64(time.Now().UnixNano())
		last := atomic.LoadUint64(&lastEpoch)
		next := now
		if next <= last {
			next = last + 1
		}
		if atomic.CompareAndSwapUint64(&lastEpoch, last, next) {
			persistEpochFloor(next) // durable before the caller flushes under this generation
			return next
		}
	}
}

// ConfigureEpochFloor points epoch persistence at path and seeds the in-process generation
// counter from any previously persisted value, so generations stay monotonic across restarts.
// Call once at startup. A missing/unreadable file just leaves the clock-based floor in place.
func ConfigureEpochFloor(path string) {
	if b, err := os.ReadFile(path); err == nil {
		if v, perr := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); perr == nil {
			for {
				last := atomic.LoadUint64(&lastEpoch)
				if v <= last {
					break
				}
				if atomic.CompareAndSwapUint64(&lastEpoch, last, v) {
					break
				}
			}
		}
	}
	epochFloorPath.Store(&path)
}

// persistEpochFloor durably records v as the high-water generation (monotonic: never lowers the
// file). Best-effort — a write failure only forfeits restart protection, never correctness.
func persistEpochFloor(v uint64) {
	p := epochFloorPath.Load()
	if p == nil {
		return
	}
	epochPersistMu.Lock()
	defer epochPersistMu.Unlock()
	if b, err := os.ReadFile(*p); err == nil {
		if cur, perr := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); perr == nil && cur >= v {
			return // already at/above v: keep the file monotonic
		}
	}
	tmp := *p + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatUint(v, 10)), 0o600); err == nil {
		_ = os.Rename(tmp, *p) // atomic replace: a reader never sees a torn value
	}
}

// CheckoutGrant names a durable managed checkout grant: the checked-out path
// plus the server-controlled monotonic epoch OpCheckout returned. The zero
// value is a legacy (owner-keyed) grant against a non-managed authority, so
// the whole managed path is inert until an authority actually returns an
// epoch — legacy self-host servers keep their exact prior behavior.
type CheckoutGrant struct {
	Path  string
	Epoch string
}

// Authority is the mount's view of the VCS (satisfied by *fsproto.Client). It is used to
// read base content for files not yet edited locally, and to flush the session's mutations.
//
// Checkout returns the grant the session must carry back on Checkin and every
// FlushBatch: a managed (journal-native) authority pins the flush watermark to
// (grant.Path, grant.Epoch), while a legacy authority ignores the zero grant.
type Authority interface {
	Checkout(path, owner string) (granted bool, heldBy string, grant CheckoutGrant, err error)
	Checkin(path, owner string, grant CheckoutGrant) error
	Read(path string, off, length int64) (data []byte, status int32, err error)
	Stat(path string) (kind string, mode uint32, status int32, err error)
	Readlink(path string) (target string, status int32, err error)
	FlushBatch(sessionID string, epoch uint64, owner string, grant CheckoutGrant, records []wal.Record) (appliedThrough uint64, status int32, err error)
}

// statusOK mirrors fsproto.OK without importing fsproto (avoids a cycle: fsproto's client
// will construct sessions). The protocol pins OK == 0.
const statusOK int32 = 0

// statusSuperseded mirrors fsproto.ESTALE: a flush rejected because a NEWER generation of this
// SessionID owns the watermark (e.g. a recovered session whose wall-clock epoch fell behind a
// pre-crash one). The session keeps its records (no compaction = no loss) and stops flushing.
const statusSuperseded int32 = 116

// entry is a path's local state in the overlay: a change relative to the authority.
type entry struct {
	kind    string // "file" | "directory" | "symlink"
	mode    uint32
	content []byte // full current bytes (files); base+edits merged
	based   bool   // base content materialized (files): reads of un-written regions are correct
	target  string // symlink target
	deleted bool   // tombstone: locally removed (read-through must report absent)
	mtimeMs int64  // locally-set mtime (0 = not set; surfaced after Chtimes)
	uid     uint32 // locally-set owner (after Chown)
	gid     uint32 // locally-set group (after Chown)
}

// LocalDirEntry is one locally-overlaid direct child reported by LocalReaddir.
type LocalDirEntry struct {
	Name    string
	Kind    string
	Mode    uint32
	Size    int64
	MtimeMs int64
	UID     uint32
	GID     uint32
}

// Session is a single exclusive checkout's write-back store.
type Session struct {
	id    string // stable per (owner, root); the authority keys the dedup watermark on it
	epoch uint64 // session GENERATION (monotonic per instance); a fresh epoch resets dedup
	owner string // this mount's checkout-owner id
	root  string // checked-out subtree root (volume-relative)
	auth  Authority
	grant CheckoutGrant // managed checkout grant (zero against a legacy authority)

	flushMu      sync.Mutex   // serializes Flush calls (ticker vs final Close) on this session
	closeMu      sync.RWMutex // Fsync RLocks; release()'s log.Close write-Locks (no sync-vs-close race)
	mu           sync.Mutex
	walPath      string              // path of the durable log (removed on a clean release)
	overlay      map[string]*entry   // volume-relative path -> local change
	sealed       map[string]struct{} // paths orphaned-while-open: reject path-addressed OpWrite (it would resurrect the deleted name)
	log          *wal.WAL            // durable flush log (the local Seq space)
	pending      []wal.Record        // un-flushed mutations (working copy of the log tail)
	lastSeq      uint64              // highest local Seq appended (for CommitThrough)
	hasSeq       bool
	lastActivity time.Time   // last mutation time (drives idle-release)
	released     bool        // idle-released: no new mutations; subtree handed off
	closing      bool        // CloseLocalDurable ran: an in-flight drain stops at its next batch boundary
	closeHandoff bool        // armed AFTER CloseLocalDurable's CommitThrough: exiting flushMu holders close the log
	logClosed    bool        // the log close happened (closeLogOnce): set by journal-first closes AND release()'s clean close — set means drained-or-fsynced, nothing local left at risk
	superseded   bool        // a newer generation owns the watermark; stop flushing (no loss)
	mx           *mgrMetrics // write-back instruments (nil for a manager-less session, e.g. tests)
	limits       FlushLimits // per-batch flush bounds (zero value = defaults)
	recovery     RecoveryResult
}

// RecoveryResult describes a crash tail recovered while opening a session WAL.
type RecoveryResult struct {
	WALPath        string
	Root           string
	Records        int
	PayloadBytes   int64
	AppliedThrough uint64
	Flushed        bool
}

// New checks out root for owner and opens the durable flush log at walPath. The caller
// owns the WAL's lifetime via Close.
func New(auth Authority, owner, id, root, walPath string) (*Session, error) {
	granted, heldBy, grant, err := auth.Checkout(root, owner)
	if err != nil {
		return nil, err
	}
	if !granted {
		return nil, &BusyError{Path: root, HeldBy: heldBy}
	}
	log, err := wal.Open(walPath)
	if err != nil {
		_ = auth.Checkin(root, owner, grant)
		return nil, err
	}
	s := &Session{
		id: id, owner: owner, root: root, auth: auth, grant: grant,
		epoch:        nextEpoch(), // strictly-monotonic generation: re-acquire always > prior
		walPath:      walPath,
		overlay:      map[string]*entry{},
		log:          log,
		lastActivity: time.Now(), // so a checked-out-but-unused session still idle-releases
	}
	// CRASH RECOVERY: a pre-existing WAL holds the un-flushed tail from a prior (crashed)
	// session for this (owner, root) — only possible with a persistent walDir + stable owner;
	// the default ephemeral walDir is always fresh. Re-flush that tail SYNCHRONOUSLY under
	// this session's fresh epoch (the authority resets dedup to 0), so the authority holds
	// everything before any read — reads (which fall through to the authority) are then
	// consistent without rebuilding the overlay.
	recovered, rerr := log.Replay()
	// Salvage the un-flushed crash tail even when Replay reports an error: on a torn or
	// corrupt log `recovered` is the valid PREFIX before the unreadable region, and
	// re-flushing what we can read beats abandoning the whole tail (silent loss). An empty
	// result (a clean or unreadable-from-byte-0 log) simply skips recovery.
	salvaged := false
	if len(recovered) > 0 {
		// Re-number the surviving tail to start at Seq 0: the prior generation's acked prefix
		// was compacted away, so these records begin mid-stream, but the authority's gap check
		// requires each generation's first flush to begin at 0. Renumber rewrites the log
		// ATOMICALLY (temp+rename) and durably — a failure can never leave a truncated tail,
		// unlike a Reset + per-record append loop that drops everything past a mid-loop error.
		if renum, nerr := log.Renumber(recovered); nerr == nil && len(renum) > 0 {
			salvaged = true
			s.pending = renum
			s.lastSeq = renum[len(renum)-1].Seq
			s.hasSeq = true
			s.recovery = RecoveryResult{
				WALPath:      walPath,
				Root:         root,
				Records:      len(renum),
				PayloadBytes: recoveryPayloadBytes(renum),
			}
			if err := s.drainRecovered(renum); err != nil {
				_ = log.Close()
				_ = auth.Checkin(root, owner, grant)
				return nil, err
			}
		}
	}
	if rerr != nil && !salvaged {
		// Mid-log corruption we could NOT rewrite to a clean prefix (no salvageable records, or
		// Renumber's rewrite itself failed). The corrupt region remains and the handle stays
		// writable, so a later acked append would land PAST it and vanish on the next replay.
		// Poison so further appends are refused and the mount fails loud instead of losing them.
		log.Poison()
	}
	if !salvaged && rerr == nil && log.CompactedThrough() > 0 {
		// A cleanly-compacted, fully-drained log left behind by a prior instance (its
		// release() raced this open before removing the file). The WAL's durable numbering
		// would resume PAST the compaction boundary, but this instance is a fresh epoch whose
		// local Seq space must start at 0 — the authority resets its flush-dedup watermark per
		// epoch and requires the first flush to begin at Seq 0; inheriting the old numbering
		// livelocks every flush on the gap check. Nothing live is discarded (fully compacted),
		// so restart the numbering. A reset failure must fail the open (loud) — proceeding
		// would guarantee the livelock.
		if err := log.Reset(); err != nil {
			_ = log.Close()
			_ = auth.Checkin(root, owner, grant)
			return nil, err
		}
	}
	return s, nil
}

// RecoveryResult returns the crash-recovery outcome from session open, if any.
func (s *Session) RecoveryResult() RecoveryResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recovery
}

// BusyError reports a checkout conflict (the subtree is held by another mount).
type BusyError struct {
	Path   string
	HeldBy string
}

func (e *BusyError) Error() string { return "session: " + e.Path + " checked out by " + e.HeldBy }

// record appends a mutation to the durable flush log + the in-memory pending set, under mu.
// A released session refuses new records (ErrReleased) so a write that races the handoff is
// re-routed to a fresh session rather than appended to a log about to be closed.
func (s *Session) record(r wal.Record) error {
	if s.released {
		return ErrReleased
	}
	if r.Op == wal.OpWrite || r.Op == wal.OpTruncate {
		if _, sealed := s.sealed[r.Path]; sealed {
			// Backstop for the early Write/Truncate guards: the path was orphaned (unlink-while-open)
			// and its overlay forgotten; a path-addressed content op here would re-create the deleted
			// name. Reject so the mount re-routes it to the parked inode by ino. Create/Mkdir/Symlink/
			// Rmove-then-recreate clear the seal (a genuine re-create), so only a stale op lands here.
			return ErrOrphaned
		}
	}
	seq, err := s.log.AppendBuffered(r)
	if err != nil {
		return err
	}
	r.Seq = seq
	s.pending = append(s.pending, r)
	s.lastSeq = seq
	s.hasSeq = true
	s.lastActivity = time.Now()
	return nil
}

// Create makes (or truncates) a local file. Born local: no authority base.
func (s *Session) Create(path string, mode uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sealed, path) // a genuine re-create of the name clears any orphan seal so its writes land
	if e := s.overlay[path]; e != nil {
		if !e.deleted {
			return nil // already present locally — idempotent O_CREAT (no truncate)
		}
		// A LOCALLY-DELETED file (tombstone) being re-created — e.g. SQLite's -journal, which it
		// deletes + re-makes every transaction. It must come back FRESH; we must NOT adopt the
		// authority's pre-deletion content (a stale journal would corrupt the DB). Fall through.
	} else {
		// Not in this session's overlay: O_CREAT WITHOUT O_TRUNC may be re-opening a file that
		// ALREADY EXISTS on the authority — a handed-off workspace file this mount's cache hadn't
		// observed (so the kernel issued CREATE not OPEN). Adopt its content instead of shadowing
		// it with an empty file (which would make reads see 0 bytes — SQLite: "no such table" —
		// and a flush of the empty create would, but for the authority's idempotent applyCreate,
		// clobber it). No OpCreate is recorded; the file is already there.
		base, exists, err := s.fetchBaseExists(path)
		if err != nil {
			return err
		}
		if exists {
			s.overlay[path] = &entry{kind: "file", mode: mode, content: base, based: true}
			return nil
		}
	}
	s.overlay[path] = &entry{kind: "file", mode: mode, content: nil, based: true}
	return s.record(wal.Record{Op: wal.OpCreate, Path: path, Mode: mode})
}

// ensureFileLocked makes path a locally-materialized file entry, fetching the authority
// base on first edit so reads of un-written regions stay correct. Caller holds s.mu.
func (s *Session) ensureFileLocked(path string) (*entry, error) {
	e := s.overlay[path]
	if e != nil && e.kind == "file" {
		if !e.based {
			base, err := s.fetchBase(path)
			if err != nil {
				return nil, err
			}
			e.content = base
			e.based = true
		}
		return e, nil
	}
	// Not in the overlay: it exists on the authority (or is a fresh write-create). Pull the
	// current base so subsequent partial reads are correct.
	base, err := s.fetchBase(path)
	if err != nil {
		return nil, err
	}
	e = &entry{kind: "file", mode: 0o644, content: base, based: true}
	s.overlay[path] = e
	return e, nil
}

// fetchBase reads a file's full current content from the authority (the overlay base).
// Returns nil for a not-yet-existing file. Caller holds s.mu.
func (s *Session) fetchBase(path string) ([]byte, error) {
	var out []byte
	const chunk = 1 << 20
	for off := int64(0); ; off += chunk {
		data, st, err := s.auth.Read(path, off, chunk)
		if err != nil {
			return nil, err
		}
		if st != statusOK { // not-exist / not-a-file: treat as empty base
			return out, nil
		}
		out = append(out, data...)
		if len(data) < chunk {
			break
		}
	}
	return out, nil
}

// fetchBaseExists is fetchBase that also reports whether the path EXISTS on the authority
// (Create uses it to distinguish "adopt an existing file" from "make a new empty one" — fetchBase
// alone returns empty for both not-exist and exists-but-empty).
func (s *Session) fetchBaseExists(path string) (content []byte, exists bool, err error) {
	const chunk = 1 << 20
	data, st, err := s.auth.Read(path, 0, chunk)
	if err != nil {
		return nil, false, err
	}
	if st != statusOK {
		return nil, false, nil // not-exist / not-a-file
	}
	out := append([]byte(nil), data...)
	for len(data) == chunk {
		data, st, err = s.auth.Read(path, int64(len(out)), chunk)
		if err != nil {
			return nil, false, err
		}
		if st != statusOK {
			break
		}
		out = append(out, data...)
	}
	return out, true, nil
}

// Write applies a write locally (read-modify-write the overlay content) and records it for
// flush. Returns the bytes written. Local-latency: no authority round-trip on the hot path
// (the base fetch happens at most once per file, on its first edit).
func (s *Session) Write(path string, off int64, data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, sealed := s.sealed[path]; sealed {
		// Reject BEFORE ensureFileLocked mutates the overlay — otherwise a stale write to an
		// orphaned name leaves a phantom overlay entry even though the write is rerouted to the ino.
		return 0, ErrOrphaned
	}
	e, err := s.ensureFileLocked(path)
	if err != nil {
		return 0, err
	}
	end := off + int64(len(data))
	if int64(len(e.content)) < end {
		// Amortized growth: a write-back file appended in small chunks must not recopy its whole
		// content on every write (O(total^2)). Extend in place when capacity allows (zeroing any
		// bytes a prior truncate-shrink left stale), else reallocate with doubled capacity.
		if int64(cap(e.content)) >= end {
			old := len(e.content)
			e.content = e.content[:end]
			clear(e.content[old:])
		} else {
			nc := int64(cap(e.content)) * 2
			if nc < end {
				nc = end
			}
			grown := make([]byte, end, nc)
			copy(grown, e.content)
			e.content = grown
		}
	}
	copy(e.content[off:end], data)
	if err := s.record(wal.Record{Op: wal.OpWrite, Path: path, Offset: off, Data: append([]byte(nil), data...)}); err != nil {
		return 0, err
	}
	return len(data), nil
}

// WriteAppend applies O_APPEND to the checkout owner's local overlay and
// records append INTENT rather than the locally observed absolute offset.
// The checkout excludes peer mutations under this subtree while the session
// is active, so the local EOF view is coherent; at flush the authority still
// resolves EOF in its ordered WAL/journal transaction. Small appends retain
// the same amortized-growth and batched-RPC performance as ordinary writes.
func (s *Session) WriteAppend(path string, data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, sealed := s.sealed[path]; sealed {
		return 0, ErrOrphaned
	}
	e, err := s.ensureFileLocked(path)
	if err != nil {
		return 0, err
	}
	off := int64(len(e.content))
	end := off + int64(len(data))
	if int64(cap(e.content)) >= end {
		e.content = e.content[:end]
	} else {
		nc := int64(cap(e.content)) * 2
		if nc < end {
			nc = end
		}
		grown := make([]byte, end, nc)
		copy(grown, e.content)
		e.content = grown
	}
	copy(e.content[off:end], data)
	if err := s.record(wal.Record{
		Op: wal.OpWrite, Path: path, Append: true,
		Data: append([]byte(nil), data...),
	}); err != nil {
		return 0, err
	}
	return len(data), nil
}

// Truncate resizes a file locally (extends with zeros / clips) and records it. SQLite's WAL
// checkpoint truncates the -wal file, so a checked-out file's truncate must stay local.
func (s *Session) Truncate(path string, size int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, sealed := s.sealed[path]; sealed {
		// Same guard as Write: an ftruncate racing the unlink must not re-fabricate the orphaned
		// name's overlay entry. Reject so the mount reroutes it to the parked inode by ino.
		return ErrOrphaned
	}
	e, err := s.ensureFileLocked(path)
	if err != nil {
		return err
	}
	if int64(len(e.content)) > size {
		e.content = e.content[:size]
	} else if int64(len(e.content)) < size {
		grown := make([]byte, size)
		copy(grown, e.content)
		e.content = grown
	}
	return s.record(wal.Record{Op: wal.OpTruncate, Path: path, Size: size})
}

// Remove tombstones a path locally (read-through then reports absent) and records it.
func (s *Session) Remove(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.overlay[path] = &entry{deleted: true}
	return s.record(wal.Record{Op: wal.OpRemove, Path: path})
}

// Materialize synchronously flushes this session's buffered writes before a still-open file is
// detached as an orphan (write-back delete-on-last-close). It drains the WHOLE session, not just
// path: FlushBatch dedups on a CONTIGUOUS local Seq watermark, so a filtered single-path flush would
// leave Seq gaps the authority cannot reconcile. It holds flushMu AND s.mu for the whole drain so no
// concurrent mutation (or ticker/release flush) can interleave — the backlog is fixed at entry and
// drains deterministically — making the subsequent Orphan + Forget atomic with respect to writes.
func (s *Session) Materialize(path string) error {
	defer s.closeLogIfHandedOff() // runs after flushMu releases: complete a close handed off mid-drain
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.released {
		return ErrReleased
	}
	if s.superseded {
		return &FlushRejectedError{Status: statusSuperseded}
	}
	if err := s.drainPendingExclusiveLocked(); err != nil {
		return err
	}
	// Seal path while STILL holding s.mu from the drain: there is no window between "backlog drained"
	// and "path sealed" in which a racing write could append a stale path-addressed record. From here
	// any OpWrite to path is rejected (ErrOrphaned) so the unlink's later Forget can't be undone.
	if s.sealed == nil {
		s.sealed = map[string]struct{}{}
	}
	s.sealed[path] = struct{}{}
	return nil
}

// Unseal lifts a Materialize seal when the orphan it was preparing for did NOT happen (e.g. the
// Orphan RPC failed): the path stays a normal session file, so writes to it must resume.
func (s *Session) Unseal(path string) {
	s.mu.Lock()
	delete(s.sealed, path)
	s.mu.Unlock()
}

// Forget drops path from the in-memory overlay after the authority has orphaned it. It appends NO
// WAL record, so a later flush can never re-delete (or re-create) the now-parked path. Caller has
// already Materialized, so there is no un-flushed record left for path to strand.
func (s *Session) Forget(path string) {
	s.mu.Lock()
	delete(s.overlay, path)
	s.mu.Unlock()
}

// Mkdir creates a directory locally and records it.
func (s *Session) Mkdir(path string, mode uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sealed, path) // a genuine re-creation of the name clears any stale orphan seal
	s.overlay[path] = &entry{kind: "directory", mode: mode, based: true}
	return s.record(wal.Record{Op: wal.OpMkdir, Path: path, Mode: mode})
}

// Symlink creates a symlink locally and records it.
func (s *Session) Symlink(path, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sealed, path) // a genuine re-creation of the name clears any stale orphan seal
	s.overlay[path] = &entry{kind: "symlink", mode: 0o777, target: target, based: true}
	return s.record(wal.Record{Op: wal.OpSymlink, Path: path, Target: target})
}

// Chmod updates a path's mode locally and records it. A metadata op must only TOUCH an existing
// overlay entry — never fabricate one for a read-through path. Fabricating a kind:"file" entry
// for, say, a directory whose mtime/mode the OS updates would shadow that directory as an empty
// file locally (readdir then finds nothing) — silent corruption of the local view. For a
// read-through path the op is still recorded and applies on the authority at flush.
func (s *Session) Chmod(path string, mode uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.overlay[path]; e != nil && !e.deleted {
		e.mode = mode
	}
	return s.record(wal.Record{Op: wal.OpChmod, Path: path, Mode: mode})
}

// Chtimes records a locally-set modification time. Without this, utimes/touch -d on a
// session-covered file (the path is checked out, so it takes no authority round-trip) was
// silently dropped — the durable mtime never moved. Like Chmod, it only updates an existing
// overlay entry; it never fabricates one (which would shadow a read-through directory as a file).
func (s *Session) Chtimes(path string, mtimeMs int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.overlay[path]; e != nil && !e.deleted {
		e.mtimeMs = mtimeMs
	}
	return s.record(wal.Record{Op: wal.OpChtimes, Path: path, MtimeMs: mtimeMs})
}

// Chown records a locally-set owner/group. Same rationale as Chtimes: a chown on a checked-out
// path took no authority round-trip and was dropped. Updates an existing entry only; never
// fabricates one for a read-through path.
func (s *Session) Chown(path string, uid, gid uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.overlay[path]; e != nil && !e.deleted {
		e.uid, e.gid = uid, gid
	}
	return s.record(wal.Record{Op: wal.OpChown, Path: path, UID: uid, GID: gid})
}

// Rename moves a path within the session (both ends covered by the same checkout). The
// source's overlay entry (materialized if a file) moves to the destination; the source is
// tombstoned. SQLite uses this for journal commits.
func (s *Session) Rename(oldPath, newPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sealed, newPath) // newPath is (re-)created by the rename: clear any stale orphan seal on it
	if src := s.overlay[oldPath]; src != nil && !src.deleted {
		// Source is local: move its overlay entry as-is (preserves kind + content/target).
		moved := *src
		s.overlay[newPath] = &moved
	} else {
		// Source not in the overlay: stat the authority so the moved entry carries the right
		// KIND. Blindly creating a "file" here fabricated an empty file for a directory or
		// symlink (losing the type, and for a symlink its target) — and an empty file for a
		// NON-EXISTENT source, making a doomed rename look like it succeeded.
		kind, mode, st, err := s.auth.Stat(oldPath)
		if err != nil {
			return err
		}
		if st != statusOK {
			return os.ErrNotExist // renaming a path that doesn't exist must fail, not fabricate
		}
		switch kind {
		case "symlink":
			target, _, _ := s.auth.Readlink(oldPath)
			s.overlay[newPath] = &entry{kind: "symlink", mode: mode, target: target, based: true}
		case "directory":
			// Dir body lives in descendants, not content; carry the kind so newPath stats as a
			// directory. Overlaid children are re-keyed below; un-overlaid children move with the
			// flushed OpRename on the authority.
			s.overlay[newPath] = &entry{kind: "directory", mode: mode, based: true}
		default:
			base, ferr := s.fetchBase(oldPath)
			if ferr != nil {
				return ferr
			}
			s.overlay[newPath] = &entry{kind: "file", mode: mode, content: base, based: true}
		}
	}
	s.overlay[oldPath] = &entry{deleted: true}
	// Re-key any overlaid descendants (a directory's locally-edited children) so their edits
	// travel with the directory instead of stranding under the now-tombstoned old path.
	s.rekeyDescendants(oldPath, newPath)
	return s.record(wal.Record{Op: wal.OpRename, Path: oldPath, NewPath: newPath})
}

// rekeyDescendants moves every overlay entry under oldPath/ to the matching path under
// newPath/, tombstoning the old keys. Called by Rename so a directory move carries its
// locally-buffered children. Caller holds s.mu.
func (s *Session) rekeyDescendants(oldPath, newPath string) {
	prefix := oldPath + "/"
	type mv struct{ from, to string }
	var moves []mv
	for k := range s.overlay {
		if strings.HasPrefix(k, prefix) {
			moves = append(moves, mv{from: k, to: newPath + "/" + k[len(prefix):]})
		}
	}
	for _, m := range moves {
		s.overlay[m.to] = s.overlay[m.from]
		s.overlay[m.from] = &entry{deleted: true}
	}
}

// Read serves a read: from the overlay if the path is locally edited, else read-through to
// the authority. ok=false means "not handled locally — caller should read-through".
func (s *Session) Read(path string, off, length int64) (data []byte, ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.overlay[path]
	if e == nil {
		return nil, false, nil // read-through
	}
	if e.deleted || e.kind != "file" {
		return nil, true, nil // locally removed / not a file: empty
	}
	if !e.based { // edited metadata only; fetch base lazily for content reads
		base, ferr := s.fetchBase(path)
		if ferr != nil {
			return nil, true, ferr
		}
		e.content = base
		e.based = true
	}
	if off >= int64(len(e.content)) {
		return nil, true, nil
	}
	endp := off + length
	if endp > int64(len(e.content)) {
		endp = int64(len(e.content))
	}
	return append([]byte(nil), e.content[off:endp]...), true, nil
}

// LocalStat reports a locally-overlaid path's kind/mode/size plus any locally-set
// mtime/uid/gid, and whether the path is handled locally at all (ok=false → the caller
// stats the authority). A locally-deleted path reports ok=true with kind "" (absent).
// mtimeMs/uid/gid are zero when never locally set; the caller substitutes sane defaults.
func (s *Session) LocalStat(path string) (kind string, mode uint32, size, mtimeMs int64, uid, gid uint32, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.overlay[path]
	if e == nil {
		return "", 0, 0, 0, 0, 0, false
	}
	if e.deleted {
		return "", 0, 0, 0, 0, 0, true
	}
	// POSIX: a symlink's st_size is its target length (workfs curSize applies the same
	// rule); an overlay symlink keeps its target in e.target, not e.content, so the
	// generic len(content) would report 0 and FSKit's kernel readlink (which reads
	// exactly st_size bytes) would truncate every session-created symlink.
	if e.kind == "symlink" {
		return e.kind, e.mode, int64(len(e.target)), e.mtimeMs, e.uid, e.gid, true
	}
	return e.kind, e.mode, int64(len(e.content)), e.mtimeMs, e.uid, e.gid, true
}

// LocalReaddir reports this session's overlaid direct children of dir. The caller has already
// established that the session covers dir. Present entries are authoritative for the local view
// and should replace any same-name authority entry; deleted names are tombstones that should hide
// authority children. Only direct children of dir are returned: descendants below a child directory
// are intentionally omitted. Results are sorted by name so a merge can be deterministic.
func (s *Session) LocalReaddir(dir string) (present []LocalDirEntry, deleted []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for p, e := range s.overlay {
		name, ok := directChildName(dir, p)
		if !ok {
			continue
		}
		if e.deleted {
			deleted = append(deleted, name)
			continue
		}
		size := int64(len(e.content))
		if e.kind == "symlink" {
			size = int64(len(e.target))
		}
		present = append(present, LocalDirEntry{
			Name: name, Kind: e.kind, Mode: e.mode, Size: size,
			MtimeMs: e.mtimeMs, UID: e.uid, GID: e.gid,
		})
	}
	sort.Slice(present, func(i, j int) bool { return present[i].Name < present[j].Name })
	sort.Strings(deleted)
	return present, deleted
}

func directChildName(dir, p string) (string, bool) {
	if dir == "" {
		if p == "" || strings.Contains(p, "/") {
			return "", false
		}
		return p, true
	}
	prefix := dir + "/"
	if !strings.HasPrefix(p, prefix) {
		return "", false
	}
	name := strings.TrimPrefix(p, prefix)
	if name == "" || strings.Contains(name, "/") {
		return "", false
	}
	return name, true
}

// LocalReadlink serves readlink for a locally-overlaid path, mirroring LocalStat's contract:
// ok=false → the path is not handled locally and the caller resolves at the authority. When
// ok=true the answer is authoritative for the session's view: kind "symlink" carries the
// overlay target (which may not have flushed yet — resolving at the authority instead would
// race the flusher and yield ENOENT for a just-created link), kind "" means locally deleted,
// and any other kind is a local non-symlink.
func (s *Session) LocalReadlink(path string) (target string, kind string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.overlay[path]
	if e == nil {
		return "", "", false
	}
	if e.deleted {
		return "", "", true
	}
	return e.target, e.kind, true
}

// Fsync makes every write so far durable on LOCAL media. Process-crash replay is
// already guaranteed once record()'s WAL write returns; Fsync closes the stronger
// machine-loss window for callers that ask for it. It does NOT wait for the
// authority — durability to the backend is the async flusher's job (or
// fsync=authority at the clientcore layer).
func (s *Session) Fsync() error {
	s.closeMu.RLock() // hold off release()'s log.Close while this CommitThrough is in flight
	defer s.closeMu.RUnlock()
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		return ErrReleased
	}
	last, has := s.lastSeq, s.hasSeq
	s.mu.Unlock()
	if !has {
		return nil
	}
	return s.log.CommitThrough(last)
}

// Idle reports whether the session is safe to idle-release: not already released, fully
// flushed (no pending), and no mutation for at least d. Requiring pending==0 means
// idle-release never races ahead of durability — the async flusher drains first.
func (s *Session) Idle(d time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.released && len(s.pending) == 0 && time.Since(s.lastActivity) >= d
}

// isReleased reports whether the session has been idle-released (so the manager skips it in
// path resolution — a released subtree reads through to the authority / re-acquires fresh).
func (s *Session) isReleased() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.released
}

// maxFlushBatch bounds the records shipped in one OpFlushBatch round-trip, so a large
// backlog flushes as several bounded batches rather than one giant payload (bounded memory
// + per-round-trip latency). The authority dedups each batch on local Seq.
const maxFlushBatch = 512

// FlushLimits bounds one OpFlushBatch RPC. Zero values keep today's behavior
// (maxFlushBatch records, no byte bound), so existing callers are unchanged.
// These are pure batching knobs: they change round-trip count and payload size,
// never which records are applied or their order.
type FlushLimits struct {
	MaxRecords int   // records per batch; <=0 means the 512 default
	MaxBytes   int64 // payload bytes (Data+Target) per batch; <=0 means unbounded
}

// batchCut returns how many leading records of pending fit in one flush batch
// under limits. Always at least 1 when pending is non-empty, so a single record
// larger than MaxBytes still ships (bounded progress, never a stall).
func batchCut(pending []wal.Record, limits FlushLimits) int {
	maxRecs := limits.MaxRecords
	if maxRecs <= 0 {
		maxRecs = maxFlushBatch
	}
	n := len(pending)
	if n > maxRecs {
		n = maxRecs
	}
	if limits.MaxBytes > 0 {
		var b int64
		for i := 0; i < n; i++ {
			b += int64(len(pending[i].Data) + len(pending[i].Target))
			if b > limits.MaxBytes && i > 0 {
				return i
			}
		}
	}
	return n
}

// SetFlushLimits overrides this session's per-batch flush bounds. Call before the
// session starts flushing (the manager sets it right after New). The startup
// crash-recovery drain inside New runs with the package defaults.
func (s *Session) SetFlushLimits(l FlushLimits) {
	s.mu.Lock()
	s.limits = l
	s.mu.Unlock()
}

// Flush ships pending mutations to the authority unless the session has been released (a
// released session is drained by its releaser; the ticker must not double-drain it).
func (s *Session) Flush() error {
	s.mu.Lock()
	skip := s.released || s.superseded
	s.mu.Unlock()
	if skip {
		return nil
	}
	return s.drainPending()
}

// isSuperseded reports whether a newer generation owns this session's watermark (so it can't
// flush — its records wait in the WAL for recovery on a clean restart).
func (s *Session) isSuperseded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.superseded
}

// IsSuperseded is the exported form of isSuperseded: a caller applying fsync=authority must treat a
// superseded session's flush as NON-durable (its records did not reach the authority) rather than a
// success, since a fenced/force-revoked generation's Flush short-circuits to a no-op.
func (s *Session) IsSuperseded() bool { return s.isSuperseded() }

// ID returns the durable SessionID (owner-hashHex(root)); exposed for coordination/tests.
func (s *Session) ID() string { return s.id }

// PendingStats reports the count and byte size of un-flushed records — the box-loss / durability
// window (data written locally but not yet durable on the authority).
func (s *Session) PendingStats() (records int, bytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records = len(s.pending)
	for i := range s.pending {
		bytes += int64(len(s.pending[i].Data))
	}
	return records, bytes
}

func recoveryPayloadBytes(records []wal.Record) int64 {
	var n int64
	for i := range records {
		n += int64(len(records[i].Data) + len(records[i].Target))
	}
	return n
}

// drainRecovered is the startup crash-recovery drain. Unlike drainPending, it does not compact the
// source WAL as each batch is acknowledged. Recovery first replays the whole tail to the authority,
// then verifies that the authority's visible state reflects the recovered records, and only then
// drops the local WAL. If the authority returns a misleading OK/resend or applies a deterministic
// no-op for a required write target, the WAL stays intact so the next start can retry instead of
// converting an acknowledged write into permanent loss.
func (s *Session) drainRecovered(records []wal.Record) error {
	if len(records) == 0 {
		return nil
	}
	defer s.closeLogIfHandedOff() // runs after flushMu releases: complete a close handed off mid-drain
	s.flushMu.Lock()
	defer s.flushMu.Unlock()

	target := records[len(records)-1].Seq
	var lastErr error
	var appliedThrough uint64
	for attempt := 0; attempt < 2; attempt++ {
		through, err := s.flushRecoveredOnce(records, target)
		if err == nil {
			appliedThrough = through
			lastErr = nil
			break
		}
		lastErr = err
		if s.mx != nil {
			s.mx.flushErrs.Inc()
		}
		if attempt == 0 {
			// A stale/equal generation can make the authority report OK/resend for records it did
			// not actually materialize. Retry once under a fresh epoch, which resets the authority's
			// Seq watermark while the recovered WAL is still intact.
			s.mu.Lock()
			s.epoch = nextEpoch()
			s.superseded = false
			s.mu.Unlock()
		}
	}
	if lastErr != nil {
		return lastErr
	}
	if err := s.log.CompactThrough(target + 1); err != nil {
		return err
	}
	s.mu.Lock()
	s.pending = nil
	s.recovery.AppliedThrough = appliedThrough
	s.recovery.Flushed = true
	s.mu.Unlock()
	return nil
}

func (s *Session) flushRecoveredOnce(records []wal.Record, target uint64) (uint64, error) {
	var appliedThrough uint64
	for start := 0; start < len(records); {
		end := start + batchCut(records[start:], s.limits)
		batch := append([]wal.Record(nil), records[start:end]...)
		through, status, err := s.auth.FlushBatch(s.id, s.epoch, s.owner, s.grant, batch)
		if err != nil {
			return 0, err
		}
		if status != statusOK {
			if status == statusSuperseded {
				s.mu.Lock()
				s.superseded = true
				s.mu.Unlock()
			}
			return 0, &FlushRejectedError{Status: status}
		}
		if s.mx != nil {
			s.mx.flushes.Inc()
			s.mx.flushRecs.Add(int64(len(batch)))
		}
		appliedThrough = through
		start = end
	}
	if appliedThrough < target {
		return appliedThrough, fmt.Errorf("session: recovery flush stopped at seq %d before recovered tail %d", appliedThrough, target)
	}
	if err := s.verifyRecovered(records); err != nil {
		return appliedThrough, err
	}
	return appliedThrough, nil
}

type recoveryExpectation struct {
	known      bool
	absent     bool
	kind       string
	target     string
	writes     []recoveryWriteExpectation
	mode       *uint32
	verifyStat bool
}

type recoveryWriteExpectation struct {
	off  int64
	data []byte
}

// verifyRecovered checks the final visible effects of a recovered WAL tail. It intentionally
// verifies the final state, not every intermediate record: a create+write+remove tail should recover
// to "absent", while a create+write tail must recover to a readable file with the written bytes.
func (s *Session) verifyRecovered(records []wal.Record) error {
	expect := map[string]*recoveryExpectation{}
	get := func(p string) *recoveryExpectation {
		e := expect[p]
		if e == nil {
			e = &recoveryExpectation{}
			expect[p] = e
		}
		return e
	}
	setPresent := func(p, kind string) *recoveryExpectation {
		e := get(p)
		e.known = true
		e.absent = false
		if kind != "" {
			e.kind = kind
		}
		e.verifyStat = true
		return e
	}
	for _, r := range records {
		switch r.Op {
		case wal.OpCreate:
			e := setPresent(r.Path, "file")
			e.mode = u32ptr(r.Mode)
			e.target = ""
			e.writes = nil
		case wal.OpMkdir:
			e := setPresent(r.Path, "directory")
			e.mode = u32ptr(r.Mode)
			e.target = ""
			e.writes = nil
		case wal.OpSymlink:
			e := setPresent(r.Path, "symlink")
			e.mode = u32ptr(0o777)
			e.target = r.Target
			e.writes = nil
		case wal.OpWrite:
			e := setPresent(r.Path, "file")
			if r.Append {
				// The authority, not the recovered client, selected this
				// write's absolute offset. FlushBatch's durable exact
				// watermark proves application; without a returned size or
				// per-record offset, guessing an offset here would turn this
				// supplemental read-back check into a false recovery failure.
				continue
			}
			cp := append([]byte(nil), r.Data...)
			e.writes = append(e.writes, recoveryWriteExpectation{off: r.Offset, data: cp})
		case wal.OpTruncate:
			e := setPresent(r.Path, "file")
			kept := e.writes[:0]
			for _, w := range e.writes {
				if w.off+int64(len(w.data)) <= r.Size {
					kept = append(kept, w)
				}
			}
			e.writes = kept
		case wal.OpRemove, wal.OpOrphan:
			e := get(r.Path)
			*e = recoveryExpectation{known: true, absent: true, verifyStat: true}
			for p := range expect {
				if p != r.Path && strings.HasPrefix(p, r.Path+"/") {
					delete(expect, p)
				}
			}
		case wal.OpRename:
			moveExpectations(expect, r.Path, r.NewPath)
		case wal.OpChmod:
			e := setPresent(r.Path, "")
			e.mode = u32ptr(r.Mode)
		case wal.OpChtimes:
			setPresent(r.Path, "")
		case wal.OpChown:
			setPresent(r.Path, "")
		}
	}

	for p, e := range expect {
		if !e.known || !e.verifyStat {
			continue
		}
		kind, mode, st, err := s.auth.Stat(p)
		if err != nil {
			return fmt.Errorf("session: verify recovered %q: %w", p, err)
		}
		if e.absent {
			if st == statusOK {
				return fmt.Errorf("session: verify recovered %q: still present after recovered remove", p)
			}
			continue
		}
		if st != statusOK {
			return fmt.Errorf("session: verify recovered %q: status %d after recovered flush", p, st)
		}
		if e.kind != "" && kind != e.kind {
			return fmt.Errorf("session: verify recovered %q: kind %q, want %q", p, kind, e.kind)
		}
		if e.mode != nil && mode&0o7777 != *e.mode&0o7777 {
			return fmt.Errorf("session: verify recovered %q: mode %#o, want %#o", p, mode&0o7777, *e.mode&0o7777)
		}
		if e.kind == "symlink" && e.target != "" {
			target, st, err := s.auth.Readlink(p)
			if err != nil {
				return fmt.Errorf("session: verify recovered readlink %q: %w", p, err)
			}
			if st != statusOK || target != e.target {
				return fmt.Errorf("session: verify recovered readlink %q: target %q status %d, want %q", p, target, st, e.target)
			}
		}
		for _, w := range e.writes {
			data, st, err := s.auth.Read(p, w.off, int64(len(w.data)))
			if err != nil {
				return fmt.Errorf("session: verify recovered read %q: %w", p, err)
			}
			if st != statusOK || string(data) != string(w.data) {
				return fmt.Errorf("session: verify recovered write %q@%d: data %q status %d, want %q", p, w.off, data, st, w.data)
			}
		}
	}
	return nil
}

func moveExpectations(expect map[string]*recoveryExpectation, oldPath, newPath string) {
	type mv struct {
		from string
		to   string
		exp  *recoveryExpectation
	}
	var moves []mv
	for p, e := range expect {
		if p == oldPath {
			moves = append(moves, mv{from: p, to: newPath, exp: e})
			continue
		}
		prefix := oldPath + "/"
		if strings.HasPrefix(p, prefix) {
			moves = append(moves, mv{from: p, to: newPath + "/" + p[len(prefix):], exp: e})
		}
	}
	for _, m := range moves {
		delete(expect, m.from)
		expect[m.to] = m.exp
	}
	expect[oldPath] = &recoveryExpectation{known: true, absent: true, verifyStat: true}
	if _, ok := expect[newPath]; !ok {
		expect[newPath] = &recoveryExpectation{known: true, verifyStat: true}
	}
}

func u32ptr(v uint32) *uint32 { return &v }

// drainPending ships the pending backlog to the authority in bounded batches and advances
// the flush cursor on each ack. Exactly-once: the authority dedups on local Seq via the
// session watermark. It drains the backlog present at the call's start (writes that arrive
// mid-flush are left for the next call, so a steady writer can't make this loop forever).
// Ignores `released` (used by both Flush and the final release drain); flushMu serializes it.
func (s *Session) drainPending() error {
	defer s.closeLogIfHandedOff() // runs after flushMu releases: complete a close handed off mid-drain
	s.flushMu.Lock()              // one drain at a time per session (ticker vs final release)
	defer s.flushMu.Unlock()
	s.mu.Lock()
	if len(s.pending) == 0 {
		s.mu.Unlock()
		return nil
	}
	target := s.pending[len(s.pending)-1].Seq // drain up to here this call
	s.mu.Unlock()

	for {
		s.mu.Lock()
		if s.closing {
			// CloseLocalDurable ran (and handed the log close to this drain):
			// stop at a batch boundary — the mount is going away, so shipping
			// the rest of the backlog belongs to recovery, not to us. Every
			// batch ACKED so far in this drain was compacted before this
			// check, so no authority-applied record is left in the kept WAL
			// to double-apply under recovery's fresh epoch; the un-sent tail
			// stays in pending + the WAL — exactly the records the replay
			// must re-ship.
			s.mu.Unlock()
			return ErrClosing
		}
		if len(s.pending) == 0 || s.pending[0].Seq > target {
			s.mu.Unlock()
			return nil
		}
		n := batchCut(s.pending, s.limits)
		batch := make([]wal.Record, n)
		copy(batch, s.pending[:n])
		s.mu.Unlock()

		start := time.Now()
		through, status, err := s.auth.FlushBatch(s.id, s.epoch, s.owner, s.grant, batch)
		if err != nil {
			if s.mx != nil {
				s.mx.flushErrs.Inc()
			}
			return err
		}
		if status != statusOK {
			if status == statusSuperseded {
				// A newer generation owns the watermark: keep our records (do NOT compact — that
				// would lose un-applied data) and stop flushing this dead generation.
				s.mu.Lock()
				s.superseded = true
				s.mu.Unlock()
			}
			if s.mx != nil {
				s.mx.flushErrs.Inc()
			}
			return &FlushRejectedError{Status: status}
		}
		if s.mx != nil {
			s.mx.flushes.Inc()
			s.mx.flushRecs.Add(int64(len(batch)))
			s.mx.flushLat.Time(start)
		}

		s.mu.Lock()
		keep := s.pending[:0:0]
		for _, r := range s.pending {
			if r.Seq > through {
				keep = append(keep, r)
			}
		}
		s.pending = keep
		cerr := s.log.CompactThrough(through + 1) // exclusive watermark = through+1
		s.mu.Unlock()
		if cerr != nil {
			return cerr
		}
	}
}

// drainPendingExclusiveLocked is drainPending for a caller that ALREADY holds flushMu AND s.mu and
// must keep holding s.mu across the whole drain (Materialize). Because s.mu is held throughout, no
// new record can append mid-drain, so the backlog is fixed at entry and the loop terminates without a
// moving target. The trade-off vs drainPending is that s.mu is held during the FlushBatch round-trips
// — acceptable because Materialize runs only on the rare unlink-while-open of a covered path.
func (s *Session) drainPendingExclusiveLocked() error {
	for len(s.pending) > 0 {
		n := batchCut(s.pending, s.limits)
		batch := make([]wal.Record, n)
		copy(batch, s.pending[:n])

		start := time.Now()
		through, status, err := s.auth.FlushBatch(s.id, s.epoch, s.owner, s.grant, batch)
		if err != nil {
			if s.mx != nil {
				s.mx.flushErrs.Inc()
			}
			return err
		}
		if status != statusOK {
			if status == statusSuperseded {
				s.superseded = true
			}
			if s.mx != nil {
				s.mx.flushErrs.Inc()
			}
			return &FlushRejectedError{Status: status}
		}
		if s.mx != nil {
			s.mx.flushes.Inc()
			s.mx.flushRecs.Add(int64(len(batch)))
			s.mx.flushLat.Time(start)
		}

		keep := s.pending[:0:0]
		for _, r := range s.pending {
			if r.Seq > through {
				keep = append(keep, r)
			}
		}
		s.pending = keep
		if cerr := s.log.CompactThrough(through + 1); cerr != nil {
			return cerr
		}
	}
	return nil
}

// FlushRejectedError reports a non-OK flush status (e.g. EBUSY on a lost checkout, or a gap
// the mount must re-derive).
type FlushRejectedError struct{ Status int32 }

func (e *FlushRejectedError) Error() string {
	return "session: flush rejected, status " + itoa(e.Status)
}

// CloseLocalDurable closes the session for a JOURNAL-FIRST unmount: it makes
// every recorded mutation durable on LOCAL media (WAL fsync) and closes the
// log WITHOUT the final authority drain and WITHOUT checking in. Used when
// the authority is unreachable or the mount session is fenced — awaiting the
// network there is exactly the unmount wedge this path exists to avoid.
//
// Invariants preserved:
//   - The WAL (and its sidecar) stay on disk, so the next clean start of this
//     (owner, root) replays the un-flushed tail — the same designed recovery
//     path a crash uses (Manager.RecoverAll / New's recovery drain).
//   - The checkout is deliberately NOT checked in: checking in an un-flushed
//     subtree would hand the next holder a stale base to overwrite (silent
//     loss). The authority reclaims the checkout via session liveness/lease
//     expiry, exactly as it would after a crash.
//
// Idempotent with release() — but only a COMPLETED release (log closed,
// logClosed set) short-circuits it. A release whose drain is still in flight
// does not: released alone proves nothing about local durability, so the
// journal-first fsync and the handed-off log close still happen (see the
// in-flight branch below).
//
// Serialization with an in-flight flusher (the ticker, or a SyncVolumeBounded
// drain abandoned past its deadline): drainPending's FlushBatch →
// CompactThrough pair must complete — or never start — before the log closes.
// Without that, a batch the authority ACKED lands after log.Close, its
// compaction fails, and the applied records stay in the kept WAL to replay
// under a fresh epoch: double-apply, re-widening the very write-resurrection
// window the journal-first unmount exists to bound. But CloseLocalDurable must
// also never WAIT out that drain's round-trip (a black-holed FlushBatch burns
// a full opTimeout — exactly the network wait this path exists to avoid). So:
// local durability (CommitThrough) happens here unconditionally, and the log
// CLOSE either happens immediately (no drain in flight) or is HANDED OFF to
// the drain, which closes at its batch boundary — after compacting anything
// the authority acked, never under it.
func (s *Session) CloseLocalDurable() error {
	s.mu.Lock()
	if s.released {
		if s.logClosed {
			// A completed closer won: a clean release() drained everything,
			// checked in, and closed the log (removing the WAL), or an
			// earlier CloseLocalDurable already ran. Nothing is left to make
			// durable.
			s.mu.Unlock()
			return nil
		}
		// released with the log still open means a release() drain is IN
		// FLIGHT (release sets the flag before its drain and re-opens the
		// session only if that drain fails). Its network outcome is
		// unknowable without waiting — the exact wait this path forbids —
		// and "released" does NOT mean "nothing at risk": a record can land
		// between the recall/idle sweep's pending==0 check and release()
		// taking the flag, and that tail is exactly what the journal-first
		// contract must make durable. Stop the drain at its next batch
		// boundary, fsync the WAL NOW, and hand the log close to whichever
		// of {drain exit, our TryLock} runs while the close is armed.
		s.closing = true
		last, has := s.lastSeq, s.hasSeq
		s.mu.Unlock()
		var serr error
		if has {
			// Unlike the un-released path below, the log's lifetime is not
			// exclusively ours here: a drain that already shipped everything
			// lets release() proceed to its own closeLogOnce after checkin.
			// closeMu serializes this fsync against that close; and once
			// logClosed is set the close belongs to a CLEAN release (drained
			// + acked), which needs no local fsync — its WAL is removed.
			s.closeMu.RLock()
			s.mu.Lock()
			closed := s.logClosed
			s.mu.Unlock()
			if !closed {
				serr = s.log.CommitThrough(last)
			}
			s.closeMu.RUnlock()
		}
		s.mu.Lock()
		s.closeHandoff = true
		s.mu.Unlock()
		if s.flushMu.TryLock() {
			// The drain exited between our closing flag and here (or
			// release() already finished): close now; closeLogOnce is
			// idempotent against release()'s own close.
			lerr := s.closeLogOnce()
			s.flushMu.Unlock()
			if serr != nil {
				return serr
			}
			return lerr
		}
		// The drain still holds flushMu: it closes the log on its way out
		// (closeLogIfHandedOff). Local durability is already proven above.
		return serr
	}
	s.released = true // from here, record()/Fsync() return ErrReleased — no new records
	s.closing = true  // an in-flight drain stops at its next batch boundary (never cleared: the log is going away)
	last, has := s.lastSeq, s.hasSeq
	s.mu.Unlock()
	var serr error
	if has {
		// The log is guaranteed OPEN here: no one may close it until
		// closeHandoff arms below, so this fsync — the journal-first
		// durability promise — can never race a close.
		serr = s.log.CommitThrough(last)
	}
	s.mu.Lock()
	s.closeHandoff = true // from here, an exiting flushMu holder closes the log
	s.mu.Unlock()
	if s.flushMu.TryLock() {
		// No flusher holds the drain lock: close now. A flusher that starts
		// later sees released/closing and never touches the log.
		lerr := s.closeLogOnce()
		s.flushMu.Unlock()
		if serr != nil {
			return serr
		}
		return lerr
	}
	// A flusher is mid-drain: it closes the log on its way out (see the
	// closeLogIfHandedOff defers on every flushMu holder). Local durability is
	// already proven above, which is all the journal-first contract promises.
	return serr
}

// closeLogOnce closes the WAL exactly once across every closer that may
// legitimately reach it: CloseLocalDurable's TryLock path, a drain exit
// completing a handed-off close, and release()'s clean close.
func (s *Session) closeLogOnce() error {
	s.mu.Lock()
	if s.logClosed {
		s.mu.Unlock()
		return nil
	}
	s.logClosed = true
	s.mu.Unlock()
	s.closeMu.Lock() // wait for any in-flight Fsync CommitThrough before closing
	err := s.log.Close()
	s.closeMu.Unlock()
	return err
}

// closeLogIfHandedOff completes a log close handed off by CloseLocalDurable.
// Every flushMu holder defers it BEFORE taking flushMu, so it runs after the
// lock is released: whichever of {drain exit, CloseLocalDurable's TryLock}
// runs second finds the work done (closeLogOnce is idempotent), and neither
// ordering can strand the log open. closeHandoff (not closing) is the trigger
// because it arms only after CloseLocalDurable's CommitThrough — a drain that
// aborts early must not close the log out from under that fsync.
func (s *Session) closeLogIfHandedOff() {
	s.mu.Lock()
	pending := s.closeHandoff && !s.logClosed
	s.mu.Unlock()
	if pending {
		_ = s.closeLogOnce()
	}
}

// FsyncLocal makes every record so far durable on LOCAL media without
// marking the session released — the journal-first volume barrier. Unlike
// Fsync it tolerates a released session: it gates on logClosed, not on
// released, because released alone can mean a release() drain still in
// flight — and a record can land between the recall/idle sweep's pending==0
// check and release() taking the flag, which is exactly the tail this
// barrier must make durable. Once the log is CLOSED the winner was either a
// clean release (everything drained and acked — nothing local at risk) or a
// journal-first close (which fsynced before closing).
func (s *Session) FsyncLocal() error {
	s.closeMu.RLock()
	defer s.closeMu.RUnlock()
	s.mu.Lock()
	if s.logClosed {
		s.mu.Unlock()
		return nil
	}
	last, has := s.lastSeq, s.hasSeq
	s.mu.Unlock()
	if !has {
		return nil
	}
	// The log cannot close under this CommitThrough: every closer goes
	// through closeLogOnce, which takes closeMu exclusively.
	return s.log.CommitThrough(last)
}

// release marks the session released (no further records), drains the FINAL pending to the
// authority, checks in (handing the subtree to whoever wants it next), and closes the log.
// Flush-BEFORE-checkin is mandatory: the next holder must observe all of this session's
// writes before it can acquire and overwrite. Idempotent. Used by idle-release AND Close.
func (s *Session) release() error {
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		return nil
	}
	s.released = true // from here, record()/Fsync() return ErrReleased — no new records
	s.mu.Unlock()
	if ferr := s.drainPending(); ferr != nil {
		// Flush FAILED — do NOT check in. Checking in hands the subtree to the next mount,
		// which would fetch a stale base and overwrite our un-flushed writes (silent data
		// loss). Re-open the session so the idle sweep retries the flush; the un-flushed
		// records stay in s.pending + the WAL (and persist for crash recovery on unmount).
		//
		// UNLESS a journal-first close intervened mid-drain (closing set):
		// the WAL tail is already fsynced, the log close is armed or done,
		// and the mount is going away — re-opening would hand future records
		// to a closed log. The session stays terminally released and the
		// kept WAL replays on the next clean start.
		s.mu.Lock()
		if !s.closing {
			s.released = false
		}
		s.mu.Unlock()
		return ferr
	}
	cerr := s.auth.Checkin(s.root, s.owner, s.grant)
	// closeLogOnce (not a bare log.Close): it records logClosed — the fact
	// CloseLocalDurable/FsyncLocal use to tell a COMPLETED release from one
	// whose drain is still in flight — and it is idempotent against a close
	// handed off to this drain's own exit by a concurrent CloseLocalDurable.
	lerr := s.closeLogOnce()
	if cerr == nil && lerr == nil && s.walPath != "" {
		// Clean release (everything flushed + checked in): drop the WAL so a later startup does
		// NOT mistake it for crash debris. A crash skips this path, leaving the WAL to recover.
		_ = os.Remove(s.walPath)
	}
	if cerr != nil {
		return cerr
	}
	return lerr
}

// Close performs a final flush, releases the checkout, and closes the log (on unmount).
func (s *Session) Close() error { return s.release() }

func itoa(n int32) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
