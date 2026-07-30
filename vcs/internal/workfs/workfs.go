// Package workfs is the mutable working filesystem: a read-write
// billy.Filesystem whose base is a committed volume manifest and whose
// uncommitted mutations are journalled to a WAL. A file's bytes are served
// lazily from the backend until first written, after which they live locally
// (dirty) until a checkpoint commits them.
//
// Durability: every mutation is appended (fsync) to the WAL before it is
// acknowledged, and the WAL is replayed on construction, so an acknowledged
// write survives a crash. Concurrency: a single FS mutex serialises the tree
// (single-authority-per-volume); backed reads fetch outside the lock, while a
// backed file's one-time materialise-on-first-write happens under the lock — a
// deliberate Slice-2 choice to be refined with block-level content later.
package workfs

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-git/go-billy/v5"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
	"github.com/steerlabs/portablefs/vcs/internal/coherence"
	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/fstransition"
	"github.com/steerlabs/portablefs/vcs/internal/metrics"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// ErrSealed reports a mutation refused because write admission was closed by
// Seal (graceful eviction / quiesce). The authority is retiring: reads keep
// serving, writes are permanently rejected in this process.
var ErrSealed = errors.New("vcs: writes stopped (authority retiring): read-only")

// ErrWALCapacity is returned when the retained WAL backlog exceeds its
// retention quota: writes are rejected until verified compaction reclaims the
// applied prefix. It exists so the protocol layer can record a definite
// ENOSPC exact outcome instead of an unrecorded reply.
var ErrWALCapacity = errors.New("vcs: WAL backlog exceeds its retention quota: writes rejected until verified compaction reclaims the applied prefix")

// errReapConditionNotMet is an internal, definite pre-reservation outcome used
// when a conditional orphan reap observes its lease/pin condition no longer
// holds at the staged position. Nothing was reserved or applied.
var errReapConditionNotMet = errors.New("vcs: orphan reap condition no longer holds")

var (
	mutationsTotal   = metrics.Default.Counter("vcs_mutations")
	replaySkipsTotal = metrics.Default.Counter("vcs_wal_replay_skips")
)

// POSIX rename/dir errors. The messages match the fsproto error mapper so a
// client sees the right errno (ENOTEMPTY / EISDIR / ENOTDIR / EINVAL).
var (
	errNotEmpty      = errors.New("directory not empty")
	errIsDir         = errors.New("is a directory")
	errNotDir        = errors.New("not a directory")
	errInvalidRename = errors.New("invalid argument: rename into own subtree")
	// errNoXattr is the removexattr/getxattr missing-name outcome (Linux
	// ENODATA semantics — deliberately an error, never a silent no-op).
	// Wrapping syscall.ENODATA routes it through the shared errnos mapping.
	errNoXattr = fmt.Errorf("vcs: no such extended attribute: %w", syscall.ENODATA)
	// errXattrNoSpace is the deterministic per-inode xattr total-bytes bound
	// (wal.MaxXattrTotalBytes) outcome, decided at the record's ordered
	// apply position exactly like the shared transition engine.
	errXattrNoSpace = fmt.Errorf("vcs: extended attributes exceed the per-inode byte bound: %w", syscall.ENOSPC)
)

// OrphanLeaseTTL is the authority-side lifetime of an unlinked-but-open orphan without renewal.
// Tests shorten this var; production keeps renewals comfortably inside it.
var OrphanLeaseTTL = 60 * time.Second

// OrphanSweepInterval is how often the authority scans for expired orphan leases.
// Tests shorten this var.
var OrphanSweepInterval = 15 * time.Second

func orphanLeaseTTL() time.Duration {
	if OrphanLeaseTTL > 0 {
		return OrphanLeaseTTL
	}
	return 60 * time.Second
}

func orphanSweepInterval() time.Duration {
	if OrphanSweepInterval > 0 {
		return OrphanSweepInterval
	}
	return 15 * time.Second
}

type inode struct {
	name       string
	kind       string // "file" | "directory" | "symlink"
	mode       os.FileMode
	mtime      time.Time
	ctime      time.Time
	atime      time.Time
	uid        uint32 // POSIX owner (0 = root)
	gid        uint32 // POSIX group (0 = root)
	ino        uint64 // stable authority-assigned identity: survives rename, distinct from name/path
	nlink      uint32 // hard-link count for non-directories (0 = legacy/unset: exactly one name)
	linkTarget string
	children   map[string]*inode
	// base is the lazy immutable-base binding for a directory that may still
	// hold unmaterialized PFT2 dirents (managed lazy-base authorities only;
	// nil everywhere else and after the directory completes).
	base *dirBase

	// file content (block-addressed): an immutable committed base plus sparse
	// dirty blocks that override it. A born file has no base; reads past the base
	// that were never written are holes (zeros).
	source    content.Source   // backed base (zero value if born local)
	blocks    map[int64][]byte // dirty block index -> bytes (overrides the base)
	size      int64            // logical file size
	born      bool             // created this session (no backend base)
	truncated bool             // size changed vs the committed source without re-dirtying a block;
	//                             a checkpoint must re-commit the new size even with no dirty blocks
	dirtyEpoch int64  // fs.epoch at this file's last content mutation
	version    uint64 // coherence version: fs.version at this inode's last mutation
}

func (n *inode) curSize() int64 {
	// POSIX: a symlink's st_size is the length of its target path. FUSE clients never
	// depended on this (readlink is an explicit op), but FSKit's kernel serves readlink
	// by reading exactly st_size bytes, so a zero here truncates every macOS symlink.
	if n.kind == "symlink" {
		return int64(len(n.linkTarget))
	}
	if n.kind != "file" {
		return 0
	}
	return n.size
}

// hasLocalContent reports whether a file carries uncommitted bytes (dirty blocks,
// a born-empty file, or a pure size change), i.e. it must be uploaded at the next checkpoint.
func (n *inode) hasLocalContent() bool { return n.born || len(n.blocks) > 0 || n.truncated }

// FS is the mutable working filesystem.
type FS struct {
	// mu guards the in-memory inode tree. It is an RWMutex: read-only operations
	// (resolve/stat/readdir/read-plan/snapshot) take RLock and run in parallel — the
	// dominant pattern when many machines share one volume — while mutations take the
	// exclusive Lock. After group commit + warm-cache the exclusive section is only the
	// fast in-memory apply (the slow fsync/replication/backend-fetch are off the lock),
	// so writers serialize for microseconds, not a replication round-trip.
	mu    sync.RWMutex
	root  *inode
	blobs content.BlobReader
	cache content.Cache
	// wal is the local file WAL (development / self-host / fault-test store).
	// nil on a managed journal generation, whose only durability truth is the
	// remote PFJ3 entry log (fs.log / fs.managed.log).
	wal   *wal.WAL
	epoch int64 // monotonic mutation counter; stamps each file's dirtyEpoch

	// log/bounds are the managed generation's PFJ3 entry log and its intent
	// bounds. nil / zero for the WAL-backed store.
	log    pfj3.EntryLog
	bounds wal.LogBounds

	// admit is the one write-admission gate behind Seal: every mutating
	// operation (both stores) enters before buffering anything and exits at
	// its full acknowledgement boundary, so SealAndDrain semantics hold for
	// eviction/quiesce on either store.
	admit admissionGate
	// seq enforces durable-before-visible strict-LSN apply for the managed
	// store. The WAL-backed store (apply-before-durable under fs.mu) never
	// touches it.
	seq mutationSequencer

	// pendingReaps marks orphans with a reserved (staged or durable but not
	// yet applied) OpReap decision, so a racing lease renewal or duplicate
	// reap cannot resurrect or double-destroy the inode.
	pendingReaps map[uint64]uint32

	// managed is the PFJ3/PFC2 attachment (nil for the WAL-backed store).
	managed *managedState
	// pft2 is the lazy PFT2 base binding (nil unless cold-started from an
	// adopted immutable base).
	pft2 *pft2Lazy
	// deadBaseInos records base inode ids the journal reaped, so a later
	// stable-handle hydration can never re-materialize them from the base.
	deadBaseInos map[uint64]struct{}
	// pins holds maintenance pins (id -> LSN watermark) that hold journal
	// suffix compaction at bay while an external consumer reads it.
	pins map[uint64]uint64

	// Dirty-block memory accounting (see dirtyrss.go for the amplification
	// pathology this bounds). All three are guarded by mu.
	//
	// dirtyBytes is the EXACT resident dirty-block byte total across every
	// live inode — named tree and parked orphans alike (an orphan's blocks
	// stay resident until OpReap destroys it). dirtyReserved holds the
	// worst-case growth of managed rows between their admission and their
	// ordered apply turn, so racing writers can never collectively pass one
	// stale bound check. dirtyMax is the admission bound (0 = unbounded).
	dirtyBytes    int64
	dirtyReserved int64
	dirtyMax      int64

	// coherence versioning (independent of epoch): a per-process generation nonce plus a
	// monotonic version assigned to every mutation and stamped on the affected inode. A
	// version is only ever compared within one generation; a new generation (restart /
	// promotion) makes clients refresh, so the absolute value need not survive a restart.
	generation uint64
	version    uint64

	// alloc assigns each inode its stable identity (root = 1), allocated under
	// mu at every create/reconstruction site. Identities are never reused: the
	// allocator floor dominates every id the base, log, and control state carry.
	alloc inoAllocator

	// orphans holds inodes that were unlinked (or renamed-over) while still open: detached from the
	// name tree but kept alive so an open handle can keep reading/writing them by their stable ino
	// (delete-on-last-close / open-after-unlink). Keyed by ino. Guarded by mu like the tree. Parked by
	// OpOrphan, dropped by OpReap (last close). Excluded from the canonical tree hash — like ino, it is
	// private authority state, not a named tree entry — so checkpoints/dedup are unaffected.
	//
	// NOTE: an orphan's content is inherently EPHEMERAL across an authority crash/restart, matching
	// local-fs/POSIX semantics — an unlinked-but-open file has no name to recover by, and the only
	// handle that can address it (by ino) lives on the mount whose connection drops on restart. So
	// orphans are deliberately NOT persisted in the checkpoint manifest; the in-memory table survives a
	// live checkpoint, and a restart legitimately drops them (the fd is already broken).
	orphans map[uint64]*inode
	// orphanLeases is in-memory liveness for parked orphans. The mount holding the open fd renews
	// its orphan inos periodically; if renewal stops, the sweeper WAL-reaps the orphan. Lease updates
	// are deliberately not WAL-logged: replayed orphans get a fresh startup grace from applyOrphan.
	orphanLeases map[uint64]time.Time

	// openInodes tracks which LIVE (still-named) inodes each mount currently holds open, keyed
	// ino -> owner -> lease expiry (Stage 2: authority open-state). A mount eager-registers an inode
	// on first open and renews it; a crashed mount's entries expire. RemoveAs PARKS (orphans) instead
	// of removing any inode with a live open holder, so a cross-mount unlink of a file ANOTHER mount
	// holds open becomes delete-on-last-close — not a broken fd. Not WAL-logged (pure liveness).
	openInodes map[uint64]map[string]time.Time

	// byIno indexes EVERY live inode (named + parked-orphan) by its stable ino — the NFSv4-style
	// file-handle map. It lets an OPEN fd address its inode by ino regardless of what happens to the
	// NAME (peer unlink, rename, or recreate-of-the-same-name), so a path-addressed op can never land
	// on a different generation. Maintained alongside the tree: an inode is linked on creation and
	// unlinked only on its true destruction (remove of a not-open file, or reap of an orphan); rename
	// (ino unchanged) and orphan (inode lives, just detached from the name tree) leave it untouched.
	byIno map[uint64]*inode

	// xattrs is the LIVE per-inode extended-attribute state (ino -> name ->
	// value), guarded by mu like the tree. It is keyed by stable ino so
	// rename/hard-link/orphan-parking keep an inode's attributes; unlinkIno
	// (true destruction) is the sole cleanup point. Applied by
	// OpSetxattr/OpRemovexattr on both generations; bounds are the frozen
	// wal.MaxXattr* values. They remain outside legacy manifests and tree
	// hashes. Managed PFT2 cuts carry named-tree rows in Root and complete
	// live rows in RecoveryRoot; legacy CompactWAL/ResetWAL re-append a
	// path-addressed xattr snapshot because that backend manifest has no
	// xattr field.
	xattrs map[uint64]map[string][]byte

	subsMu  sync.Mutex
	subs    map[int]chan coherence.Batch // invalidation-batch subscribers (FUSE clients)
	nextSub int
	invPos  uint64 // monotonic invalidation-stream position (last published)

	// renewLocks serialize session lifecycle transitions per session id, so
	// concurrent establishes/renewals of one session do not append redundant
	// (though harmless) control records.
	renewLocks [sessionRenewShards]sync.Mutex
}

var _ billy.Filesystem = (*FS)(nil)

// New builds the working FS from manifest entries (the committed base), then
// replays the WAL on top to recover any uncommitted mutations. It uses a default
// in-memory cache; NewWithCache injects one (e.g. a disk-backed tier).
func New(entries []backend.Entry, blobs content.BlobReader, w *wal.WAL) (*FS, error) {
	return NewWithCache(entries, blobs, w, content.NewCache(defaultCacheBytes))
}

// NewWithCache is New with a caller-provided content cache.
func NewWithCache(entries []backend.Entry, blobs content.BlobReader, w *wal.WAL, cache content.Cache) (*FS, error) {
	now := time.Now()
	fs := &FS{
		root:         &inode{ino: 1, kind: "directory", mode: os.ModeDir | 0o755, mtime: now, ctime: now, atime: now, children: map[string]*inode{}},
		blobs:        blobs,
		cache:        cache,
		wal:          w,
		generation:   randomNonce(),
		alloc:        newInoAllocator(), // root is 1; allocation is strictly above every observed id
		orphans:      map[uint64]*inode{},
		orphanLeases: map[uint64]time.Time{},
		openInodes:   map[uint64]map[string]time.Time{},
		pendingReaps: map[uint64]uint32{},
		byIno:        map[uint64]*inode{},
		xattrs:       map[uint64]map[string][]byte{},
		deadBaseInos: map[uint64]struct{}{},
	}
	fs.byIno[1] = fs.root
	sorted := append([]backend.Entry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	for _, e := range sorted {
		fs.insertBase(e)
	}
	if err := fs.assignMissingInos(); err != nil { // finalize restored identities + fill gaps deterministically BEFORE WAL replay
		return nil, err
	}
	fs.indexSubtree(fs.root) // seed the by-ino file-handle index from the loaded tree (replay maintains it)
	records, err := w.Replay()
	if err != nil {
		return nil, fmt.Errorf("wal replay: %w", err)
	}
	for _, r := range records {
		fs.epoch++
		if r.Op.IsControl() {
			// Session/slot control records are the retired legacy control
			// shadow; the raw data plane fails closed rather than guess at
			// exactly-once state.
			return nil, fmt.Errorf("wal replay: legacy control record at LSN %d (the raw WAL data plane carries no session store)", r.Seq)
		}
		if r.Env.Valid() {
			return nil, fmt.Errorf("wal replay: exact envelope at LSN %d (exact sessions are managed-only)", r.Seq)
		}
		_, _, applyErr := fs.applyMutationReplay(r)
		if applyErr != nil {
			if benignReplayError(applyErr) {
				// The mutation no longer applies cleanly. Two cases reach here and both
				// are safe to skip: (1) a phantom — a live op the WAL recorded just
				// before its apply guard rejected it (e.g. "mv a b" onto a non-empty b);
				// and (2) an op the committed base already reflects — a crash after a
				// checkpoint committed the manifest but before the WAL was compacted
				// leaves committed remove/rename records that re-applying would re-reject.
				// Skipping reaches the same end state; failing here would brick startup.
				replaySkipsTotal.Inc()
				continue
			}
			return nil, fmt.Errorf("wal replay record %+v: %w", r, applyErr)
		}
	}
	return fs, nil
}

// applyMutationReplay applies one replayed user record: name validation plus
// the shared apply, returning the parked orphan ino for exact-outcome
// reconstruction.
func (fs *FS) applyMutationReplay(r wal.Record) (uint64, bool, error) {
	if err := validateIntroducedName(r); err != nil {
		return 0, false, err // defensive on replay; an over-long name should never have been committed
	}
	return fs.applyMutationAs(r, "")
}

// benignReplayError reports whether an apply error during WAL replay is an expected,
// idempotent outcome (the desired end state already holds, or the op was a phantom
// guard-rejection) rather than a genuine fault. Only these are skipped on replay; any
// other error stays fatal so real corruption is never silently swallowed.
func benignReplayError(err error) bool {
	// ErrExist/ErrPermission cover guard-rejected Excl creates and hard-link
	// phantoms: this store buffers before apply, so a live guard rejection is
	// a durable phantom that replay re-rejects deterministically.
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, os.ErrExist) ||
		errors.Is(err, os.ErrPermission) ||
		errors.Is(err, syscall.ENAMETOOLONG) ||
		errors.Is(err, errNotEmpty) ||
		errors.Is(err, errIsDir) ||
		errors.Is(err, errNotDir) ||
		errors.Is(err, errInvalidRename) ||
		// Xattr guard phantoms: a removexattr that lost its name (ENODATA)
		// or a set past the per-inode bound (ENOSPC) re-rejects identically
		// at replay — the same deterministic set the transition engine's
		// BenignEnvlessOutcome tolerates. Neither errno arises from any
		// other logged apply, so this masks no real corruption.
		errors.Is(err, syscall.ENODATA) ||
		errors.Is(err, syscall.ENOSPC)
}

// benignReplayErrorForRecord keeps guard tolerance narrow on the managed
// store: a CURRENT path/handle write or truncate that cannot find its target
// must fail recovery closed — silently skipping it could discard durable
// bytes. Only pre-deterministic legacy records (TsMs==0) retain that
// historical migration escape hatch. Exact records take the separate
// exact-outcome branch and replay a recorded ENOENT deterministically.
func benignReplayErrorForRecord(r wal.Record, err error) bool {
	if errors.Is(err, os.ErrNotExist) && (r.Op == wal.OpWrite || r.Op == wal.OpTruncate) {
		return r.TsMs == 0
	}
	return benignReplayError(err)
}

// deterministicApplyError classifies an apply rejection that every replica
// and every replay reproduces identically at the record's ordered position.
func deterministicApplyError(err error) bool {
	return benignReplayError(err) ||
		errors.Is(err, os.ErrExist) ||
		errors.Is(err, os.ErrPermission) ||
		errors.Is(err, syscall.EINVAL)
}

// replayTs is the deterministic timestamp source for a durable record: the
// server-selected TsMs when present, else wall clock (legacy records only).
func replayTs(r wal.Record) time.Time {
	if r.TsMs != 0 {
		return time.UnixMilli(r.TsMs)
	}
	return time.Now()
}

// intentLeaves unwraps one intent into its leaf mutations: a sole OpBatch
// frame yields its Mutations; anything else must be batch-free.
func intentLeaves(records []wal.Record) ([]wal.Record, error) {
	if len(records) == 1 && records[0].Op.IsBatch() {
		if len(records[0].Mutations) == 0 {
			return nil, fmt.Errorf("vcs: empty WAL batch intent")
		}
		for i := range records[0].Mutations {
			if records[0].Mutations[i].Op.IsBatch() {
				return nil, fmt.Errorf("vcs: nested WAL batch intent")
			}
		}
		return records[0].Mutations, nil
	}
	for i := range records {
		if records[i].Op.IsBatch() {
			return nil, fmt.Errorf("vcs: batch intent must be the sole WAL record")
		}
	}
	return records, nil
}

// prepareIntentLocked stamps every leaf mutation with its durable replay
// inputs (identities, mkdir leg reservations, server timestamp) while
// preserving an OpBatch wrapper as one authority frame. Caller holds fs.mu.
func (fs *FS) prepareIntentLocked(records []wal.Record, nowMs int64) error {
	var prepared []*wal.Record
	prepare := func(r *wal.Record) error {
		if err := fs.preassignIno(r); err != nil {
			return err
		}
		if err := fs.reserveMkdirInos(r); err != nil {
			return err
		}
		if r.TsMs == 0 {
			r.TsMs = nowMs
		}
		prepared = append(prepared, r)
		return nil
	}
	if len(records) == 1 && records[0].Op.IsBatch() {
		if records[0].TsMs == 0 {
			records[0].TsMs = nowMs
		}
		for i := range records[0].Mutations {
			if err := prepare(&records[0].Mutations[i]); err != nil {
				return err
			}
		}
		return fs.reserveReapDecisionsLocked(prepared)
	}
	for i := range records {
		if err := prepare(&records[i]); err != nil {
			return err
		}
	}
	return fs.reserveReapDecisionsLocked(prepared)
}

// reserveReapDecisionsLocked turns an expiry observation into a deterministic
// journaled decision. For a conditional sweeper reap, the lease/open condition
// is checked at the same fs.mu-held reservation point as the buffered append.
// The pending marker makes all later renewals lose to that decision until
// OpReap's ordered apply. Replay does not re-check wall-clock liveness: the
// presence of the durable OpReap record is the replicated decision.
func (fs *FS) reserveReapDecisionsLocked(records []*wal.Record) error {
	conditional := make(map[uint64]struct{})
	for _, r := range records {
		if r.Op != wal.OpReap || r.ReapIfLeaseExpiresByMs == 0 {
			continue
		}
		if _, duplicate := conditional[r.Ino]; duplicate {
			return errReapConditionNotMet
		}
		conditional[r.Ino] = struct{}{}
		if fs.pendingReaps[r.Ino] != 0 || fs.orphans[r.Ino] == nil {
			return errReapConditionNotMet
		}
		cutoff := time.UnixMilli(r.ReapIfLeaseExpiresByMs)
		expires, leased := fs.orphanLeases[r.Ino]
		if !leased || expires.After(cutoff) || fs.inodeOpenLocked(r.Ino, cutoff) {
			return errReapConditionNotMet
		}
	}
	for _, r := range records {
		if r.Op == wal.OpReap && fs.orphans[r.Ino] != nil {
			fs.pendingReaps[r.Ino]++
		}
	}
	return nil
}

// releaseReapDecisionsLocked rolls back reservation markers when the atomic
// append itself failed. Once append succeeds, only ordered OpReap apply
// clears the marker (or the authority is poisoned and fenced).
func (fs *FS) releaseReapDecisionsLocked(records []wal.Record) {
	leaves, err := intentLeaves(records)
	if err != nil {
		return
	}
	for _, r := range leaves {
		if r.Op != wal.OpReap || fs.pendingReaps[r.Ino] == 0 {
			continue
		}
		fs.pendingReaps[r.Ino]--
		if fs.pendingReaps[r.Ino] == 0 {
			delete(fs.pendingReaps, r.Ino)
		}
	}
}

// LiveRevision names the exact live state of this authority: the log epoch,
// the applied (and durable) LSN cursor, and the coherence generation nonce.
type LiveRevision struct {
	WALEpoch            uint64
	AppliedLSN          uint64
	CoherenceGeneration uint64
}

// LiveRevision returns the current durable-applied revision cursor. On the
// managed store the applied cursor is the sequencer's watermark (every
// applied row is durable by construction); on the WAL store it is the WAL
// append watermark (apply-before-durable: the cursor bounds acknowledged
// history only after a drain, which is exactly when eviction reads it).
func (fs *FS) LiveRevision() LiveRevision {
	if fs.managed != nil {
		return LiveRevision{
			WALEpoch:            fs.managed.log.Epoch(),
			AppliedLSN:          fs.seq.appliedWatermark(),
			CoherenceGeneration: fs.generation,
		}
	}
	return LiveRevision{
		WALEpoch:            fs.wal.Epoch(),
		AppliedLSN:          fs.wal.Watermark(),
		CoherenceGeneration: fs.generation,
	}
}

// ---- explicit inode-identity allocator ----
//
// Identity layout mirrors the frozen PFT2 composition (pft2.ComposeIno):
// ino = namespace<<32 | localCounter for namespace 1..2^31-1, while namespace
// 0 is the reserved legacy flat space in which the WHOLE id is the local
// counter (root = 1, and every pre-namespace manifest/WAL id lives here).
// The bounds are wire-format constants, mirrored rather than imported so the
// live authority does not grow a production dependency on the tree codec.
const (
	inoNamespaceShift = 32
	// maxInodeNamespace bounds one branch's never-reused allocation namespace.
	maxInodeNamespace = uint32(1<<31 - 1)
	// maxInodeLocalCounter bounds the per-namespace local counter — and the
	// legacy flat space: a flat id at or above 2^32 would decompose as a
	// DIFFERENT namespace under the canonical split, so namespace-0
	// allocation is exhausted (typed, pre-mutation) at this boundary.
	maxInodeLocalCounter = uint64(1<<32 - 1)
	// maxIno keeps every inode positive in a PostgreSQL signed BIGINT.
	maxIno = uint64(1<<63 - 1)
)

// ErrInodeExhausted is the typed terminal error for inode-identity exhaustion
// (the allocation namespace has no unused id left). It is returned BEFORE any
// WAL reservation or tree mutation: the failing intent changes nothing.
var ErrInodeExhausted = errors.New("vcs: inode identity space exhausted")

// inoAllocator is the explicit allocator state for stable inode identities:
//
//	namespace    — branch allocation namespace fresh ids compose into
//	               (0 = legacy flat space);
//	nextLocal    — next unassigned local counter within namespace;
//	maxInoSeen   — monotonic high-water over EVERY id observed or allocated,
//	               deleted/orphaned/compacted included, all namespaces;
//	durableFloor — imported durable recovery floor (PFT2 MaxInoSeen /
//	               RecoveryRoot); allocation never descends to it.
//
// Deleted ids are never reused: allocation in the flat namespace is strictly
// above max(maxInoSeen, durableFloor), and composed namespaces advance a
// per-namespace monotonic counter that observation/import can only raise.
// The zero value is invalid; newInoAllocator seeds root (ino 1) as observed.
type inoAllocator struct {
	namespace    uint32
	nextLocal    uint64
	maxInoSeen   uint64
	durableFloor uint64
}

// newInoAllocator is the legacy flat-namespace allocator with root (ino 1)
// already observed — the state every eager-manifest FS construction starts
// from before base entries and replay raise it.
func newInoAllocator() inoAllocator {
	return inoAllocator{namespace: 0, nextLocal: 2, maxInoSeen: 1}
}

// floor is the id every fresh flat allocation must stay strictly above:
// max(observed high-water, imported durable floor). Deliberately strict — a
// floor at or beyond the flat cap exhausts the flat namespace (typed,
// pre-mutation) rather than ever allocating at or below a floor.
func (a *inoAllocator) floor() uint64 {
	if a.durableFloor > a.maxInoSeen {
		return a.durableFloor
	}
	return a.maxInoSeen
}

// observe records an id that entered the inode table from ANY source (base
// manifest, logged record identity, control state, restored orphan). It only
// ever raises state: the high-water dominates all observed history, and an id
// inside the allocator's own namespace advances the local counter past it.
func (a *inoAllocator) observe(ino uint64) {
	if ino == 0 {
		return
	}
	if ino > a.maxInoSeen {
		a.maxInoSeen = ino
	}
	if a.namespace == 0 {
		// Flat space: nextLocal tracks the whole id. Ids at/above 2^32 belong
		// to composed namespaces and gate allocation through maxInoSeen only.
		if ino <= maxInodeLocalCounter && ino >= a.nextLocal {
			a.nextLocal = ino + 1
		}
		return
	}
	if uint32(ino>>inoNamespaceShift) == a.namespace {
		if local := ino & maxInodeLocalCounter; local >= a.nextLocal {
			a.nextLocal = local + 1
		}
	}
}

// allocate returns the next never-used identity, or typed exhaustion BEFORE
// any state changes. Never-reuse: flat ids are strictly above floor();
// composed ids advance the monotonic per-namespace counter.
func (a *inoAllocator) allocate() (uint64, error) {
	if a.namespace == 0 {
		candidate := a.nextLocal
		if f := a.floor(); candidate <= f {
			candidate = f + 1
		}
		if candidate > maxInodeLocalCounter {
			return 0, fmt.Errorf("%w: legacy flat namespace consumed (next candidate %d exceeds %d)",
				ErrInodeExhausted, candidate, maxInodeLocalCounter)
		}
		a.nextLocal = candidate + 1
		a.maxInoSeen = candidate
		return candidate, nil
	}
	if a.nextLocal > maxInodeLocalCounter {
		return 0, fmt.Errorf("%w: namespace %d local counter consumed", ErrInodeExhausted, a.namespace)
	}
	ino := uint64(a.namespace)<<inoNamespaceShift | a.nextLocal
	a.nextLocal++
	if ino > a.maxInoSeen {
		a.maxInoSeen = ino
	}
	return ino, nil
}

// allocIno hands out the next stable inode identity. The caller holds fs.mu (the apply path) or
// is the single-threaded reconstruction constructor. Identities are never reused within a run —
// or across runs: the allocator floor dominates every id the base, log, and control state carry.
func (fs *FS) allocIno() (uint64, error) {
	return fs.alloc.allocate()
}

// useOrAllocIno returns the explicitly logged identity when a record carries one (replay, or a
// commit that pre-assigned it), advancing the allocator past it so a later allocIno can never
// collide; otherwise it allocates fresh. This is what lets ino-addressed ops survive a checkpoint
// that dropped the allocator high-water — the create's identity comes from the log, not re-derivation.
func (fs *FS) useOrAllocIno(ino uint64) (uint64, error) {
	if ino == 0 {
		return fs.allocIno()
	}
	fs.alloc.observe(ino)
	return ino, nil
}

// preassignIno stamps an inode-creating record with its identity BEFORE it is appended to the WAL,
// so replay reproduces the SAME ino instead of re-deriving it from the reloaded allocator state. A
// checkpoint that compacts earlier create/remove churn drops the allocator high-water; without the
// logged ino a replay would re-number the file and any ino-addressed (HandleIno) op against it would
// misroute or be lost. Must run under fs.mu (allocIno mutates the allocator). Both commit paths use
// it. Identity exhaustion fails HERE — before the WAL reservation, before any mutation.
func (fs *FS) preassignIno(r *wal.Record) error {
	if r.Ino == 0 && (r.Op == wal.OpCreate || r.Op == wal.OpSymlink || (r.Op == wal.OpMkdir && r.Excl)) {
		ino, err := fs.allocIno()
		if err != nil {
			return err
		}
		r.Ino = ino
	}
	if r.Op == wal.OpLink && r.Ino == 0 {
		// Stamp the SOURCE inode identity so replay/standby resolve the same
		// inode deterministically (the source name could be
		// unlinked/recreated between reserve and a later replay).
		if src := fs.resolve(r.Path); src != nil {
			r.Ino = src.ino
		}
	}
	return nil
}

// reserveMkdirInos pre-reserves one identity per path component of a
// non-exclusive (mkdir-all) intent, so replay of a compacted log reproduces
// the exact leg identities the live apply handed out.
func (fs *FS) reserveMkdirInos(r *wal.Record) error {
	if r.Op != wal.OpMkdir || r.Excl {
		return nil // exclusive mkdir logs its single leaf identity in r.Ino
	}
	clean := cleanPath(r.Path)
	if clean == "" {
		r.Inos = nil
		return nil
	}
	count := len(strings.Split(clean, "/"))
	if len(r.Inos) != 0 && len(r.Inos) != count {
		return fmt.Errorf("vcs: mkdir inode reservation count %d, want %d", len(r.Inos), count)
	}
	if len(r.Inos) == 0 {
		r.Inos = make([]uint64, count)
		for i := range r.Inos {
			ino, err := fs.allocIno()
			if err != nil {
				return err
			}
			r.Inos[i] = ino
		}
	}
	return nil
}

// linkIno registers an inode in the by-ino file-handle index. Caller holds fs.mu (apply path).
func (fs *FS) linkIno(n *inode) {
	if n != nil && n.ino != 0 {
		fs.byIno[n.ino] = n
	}
}

// unlinkIno drops an inode from the by-ino index on its TRUE destruction — a remove of a not-open
// file, or a reap of an orphan. It is deliberately NOT called on orphan (the inode lives, just
// detached from the name tree) or rename (the ino is unchanged). Caller holds fs.mu.
//
// Destruction is where a dirty file's resident blocks finally become garbage,
// so this is also the one dirty-accounting release hook for unlink/reap/
// rename-over — miss a destruction path and the dirty-RSS bound would wedge
// closed on memory that was actually freed. It is likewise the one xattr
// cleanup hook: an inode's extended attributes live exactly as long as the
// inode (rename and orphan-parking keep the ino, so they keep the xattrs).
func (fs *FS) unlinkIno(ino uint64) {
	if n, ok := fs.byIno[ino]; ok {
		fs.addDirtyBlockBytesLocked(-dirtyBlockBytesOf(n))
	}
	delete(fs.byIno, ino)
	delete(fs.xattrs, ino)
}

// indexSubtree seeds the by-ino index from a loaded tree (once, after the base load + identity
// assignment, before WAL replay). Single-threaded at construction.
func (fs *FS) indexSubtree(n *inode) {
	if n == nil {
		return
	}
	fs.linkIno(n)
	for _, c := range n.children {
		fs.indexSubtree(c)
	}
}

// assignMissingInos finalizes inode identity after the persisted base is loaded but BEFORE WAL
// replay: it observes every restored id (raising the allocator's high-water), then gives a fresh
// id — in a deterministic sorted depth-first order — to every inode still lacking one (an implicit
// parent dir, or any entry from a manifest predating inode identity). Determinism here is what
// makes reconstruction yield identical ids across restarts.
func (fs *FS) assignMissingInos() error {
	var scan func(n *inode)
	scan = func(n *inode) {
		fs.alloc.observe(n.ino)
		for _, c := range n.children {
			scan(c)
		}
	}
	scan(fs.root)
	var fill func(n *inode) error
	fill = func(n *inode) error {
		names := make([]string, 0, len(n.children))
		for name := range n.children {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			c := n.children[name]
			if c.ino == 0 {
				ino, err := fs.allocIno()
				if err != nil {
					return err
				}
				c.ino = ino
			}
			if err := fill(c); err != nil {
				return err
			}
		}
		return nil
	}
	return fill(fs.root)
}

func (fs *FS) insertBase(e backend.Entry) {
	clean := cleanPath(e.Path)
	if clean == "" {
		return
	}
	cur := fs.root
	parts := strings.Split(clean, "/")
	for i, part := range parts {
		if cur.children == nil {
			cur.children = map[string]*inode{}
		}
		child, ok := cur.children[part]
		if !ok {
			child = &inode{name: part, kind: "directory", mode: os.ModeDir | 0o755, children: map[string]*inode{}}
			cur.children[part] = child
		}
		if i == len(parts)-1 {
			child.ino = e.Ino // restore the persisted identity (0 for a pre-identity manifest → filled by assignMissingInos)
			child.kind = e.Kind
			child.mode = modeFromUnix(e.Mode)
			child.mtime, child.ctime, child.atime = manifestTimes(e.MtimeMs, e.CtimeMs, e.AtimeMs)
			child.uid = e.UID
			child.gid = e.GID
			child.linkTarget = e.LinkTarget
			switch e.Kind {
			case "directory":
				child.mode |= os.ModeDir
				if child.children == nil {
					child.children = map[string]*inode{}
				}
			case "symlink":
				child.mode |= os.ModeSymlink
			case "file":
				child.source = content.Source{
					BlobDigest:      e.BlobDigest,
					BlobSize:        e.BlobSize,
					BlobCompression: e.BlobCompression,
					BlobPacked:      e.BlobPacked,
					Chunks:          e.Chunks,
					Size:            e.Size,
				}
				child.size = e.Size
			}
		}
		cur = child
	}
}

func cleanPath(name string) string { return strings.Trim(path.Clean("/"+name), "/") }

func manifestTimes(mtimeMs, ctimeMs, atimeMs int64) (mtime, ctime, atime time.Time) {
	mtime = time.UnixMilli(mtimeMs)
	ctime = time.UnixMilli(ctimeMs)
	if ctimeMs == 0 {
		ctime = mtime
	}
	atime = time.UnixMilli(atimeMs)
	if atimeMs == 0 {
		atime = mtime
	}
	return
}

func inodeTimes(n *inode) (mtime, ctime, atime time.Time) {
	mtime = n.mtime
	ctime = n.ctime
	if ctime.IsZero() {
		ctime = mtime
	}
	atime = n.atime
	if atime.IsZero() {
		atime = mtime
	}
	return
}

func bumpDirTimes(n *inode, now time.Time) {
	if n == nil {
		return
	}
	n.mtime = now
	n.ctime = now
}

// nameMax is the POSIX/ext4 per-component filename limit. A create/mkdir/symlink/rename-target that
// would introduce a component longer than this is rejected with ENAMETOOLONG (matching a local fs),
// rather than silently storing an over-long name.
const nameMax = 255

func validateNameComponents(name string) error {
	for _, part := range strings.Split(name, "/") {
		if part == "" {
			continue
		}
		if len(part) > nameMax {
			return fmt.Errorf("vcs: path component exceeds %d bytes: %w", nameMax, syscall.ENAMETOOLONG)
		}
	}
	return nil
}

// validateIntroducedName rejects an op that would introduce an over-long name component. Only ops that
// INTRODUCE a name are checked (rename checks NewPath only — the source introduces no name, and this
// still allows renaming a legacy over-long name DOWN to a valid one).
func validateIntroducedName(r wal.Record) error {
	switch r.Op {
	case wal.OpCreate, wal.OpMkdir, wal.OpSymlink:
		return validateNameComponents(r.Path)
	case wal.OpRename:
		return validateNameComponents(r.NewPath)
	default:
		return nil
	}
}

// resolve walks the tree (caller holds the lock, or construction/replay).
func (fs *FS) resolve(name string) *inode {
	clean := cleanPath(name)
	if clean == "" {
		return fs.root
	}
	cur := fs.root
	for _, part := range strings.Split(clean, "/") {
		next, ok := cur.children[part]
		if !ok || cur.kind != "directory" {
			return nil
		}
		cur = next
	}
	return cur
}

func (fs *FS) resolveParent(name string) (*inode, string) {
	clean := cleanPath(name)
	if clean == "" {
		return nil, ""
	}
	dir, base := path.Split(clean)
	parent := fs.resolve(strings.TrimRight(dir, "/"))
	if parent == nil || parent.kind != "directory" {
		return nil, ""
	}
	return parent, base
}

// ---- mutation: buffer + apply under fs.mu, then group-commit outside it ----

func (fs *FS) mutate(r wal.Record) error {
	fs.mu.Lock()
	_, err := fs.commitMutationLocked(r, "")
	return err
}

// MutateAs is mutate with an originating owner stamped on the published invalidation, so
// the authority's subscribe stream source-suppresses the echo back to that owner. This is
// the write-THROUGH twin of ApplyBatch's owner: it makes self-suppression race-free (the
// echo is dropped at the source by identity, not by the client racing to record the
// version before the echo lands). The protocol server routes the simple write-through ops
// (mkdir/remove/rename/symlink/chmod/chtimes) through it; their record maps 1:1 to a billy
// mutator. Owner "" reproduces the plain billy mutate.
func (fs *FS) MutateAs(r wal.Record, owner string) error {
	fs.mu.Lock()
	_, err := fs.commitMutationLocked(r, owner)
	return err
}

// commitMutationLocked is the group-commit write path. The caller holds fs.mu on
// entry; this function buffers r into the WAL and applies it to the tree under fs.mu
// (fast, ordered), RELEASES fs.mu, then makes the batch durable (one fsync + one
// replication round-trip shared with every other writer flushing concurrently). So
// fs.mu is held only for the in-memory apply, never across the slow durability path —
// that is what lets many writers (and cross-region replication) proceed in parallel.
// It is also the shared core of read-modify-write ops (Chown) that must resolve the
// record against current state AND buffer+apply it under one uninterrupted fs.mu hold.
func (fs *FS) commitMutationLocked(r wal.Record, owner string) (version uint64, err error) {
	v, _, err := fs.commitMutationResultLocked(r, owner)
	return v, err
}

// commitMutationResultLocked is commitMutationLocked that ALSO returns the orphan ino an op parked —
// non-zero only for an OpRename with OrphanTarget that parked the replaced (still-open) destination,
// so the caller can hand that ino back to the mount for ino-addressed access.
func (fs *FS) commitMutationResultLocked(r wal.Record, owner string) (version uint64, orphanIno uint64, err error) {
	if fs.managed != nil {
		fs.mu.Unlock()
		return 0, 0, ErrManagedMode // managed generations journal through CommitEntry only
	}
	// Admission gate (Seal): enter before buffering anything, exit only after
	// the full acknowledgement boundary (apply + WAL fsync + publish below).
	if aerr := fs.admit.enter(); aerr != nil {
		fs.mu.Unlock()
		return 0, 0, aerr
	}
	defer fs.admit.exit()
	if verr := validateIntroducedName(r); verr != nil {
		fs.mu.Unlock() // reject BEFORE the WAL append, so an over-long name never lands in the log
		return 0, 0, verr
	}
	if derr := fs.admitDirtyWriteLocked(&r); derr != nil {
		fs.mu.Unlock() // definite pre-append refusal: dirty-block memory is at its bound
		return 0, 0, derr
	}
	if ierr := fs.preassignIno(&r); ierr != nil { // log the inode identity before the append so replay is deterministic
		fs.mu.Unlock()
		return 0, 0, ierr
	}
	if ierr := fs.reserveMkdirInos(&r); ierr != nil { // mkdir leg identities ride the record for replay
		fs.mu.Unlock()
		return 0, 0, ierr
	}
	seq, bufErr := fs.wal.AppendBuffered(r)
	if bufErr != nil {
		fs.mu.Unlock()
		return 0, 0, bufErr // record was not buffered; nothing to commit
	}
	fs.epoch++
	relatedInos := fs.relatedInodesLocked(r)
	orphanIno, changed, applyErr := fs.applyMutationAs(r, owner)
	var v uint64
	if changed {
		v = fs.stampVersion(r, orphanIno, true)
	}
	fs.mu.Unlock()
	// The record IS buffered. Make it durable regardless of applyErr: a guard-rejected
	// op becomes a phantom that tolerant replay skips, and committing keeps the WAL
	// buffer/durableSeq consistent for the writers batched with it.
	if cErr := fs.wal.CommitThrough(seq); cErr != nil {
		return 0, 0, cErr // durability failure → WAL poisoned → node halts → failover
	}
	if applyErr != nil {
		return v, 0, applyErr
	}
	if changed {
		mutationsTotal.Inc()
		// Publish tagged with the originating owner (empty for the plain billy path). When owner
		// is set, the authority's subscribe stream drops this echo for that mount by identity —
		// race-free self-suppression. v is THIS mutation's version identity, returned so a write
		// can also record the exact version of its OWN write (never a concurrent writer's) as the
		// version-predicate fallback layer.
		fs.publish(fs.changesFor(r, owner, v, orphanIno, relatedInos...))
	}
	return v, orphanIno, nil
}

// WriteAt writes data at off (creating the file if absent) and returns the coherence VERSION
// this write produced — the version THIS mutation stamped on the inode, captured atomically
// under fs.mu. This is the root fix for the concurrent-same-path-write hazard: re-reading "the
// path's current version" after a write can return a CONCURRENT writer's version; returning the
// version the commit itself assigned cannot.
func (fs *FS) WriteAt(name string, off int64, data []byte, perm os.FileMode) (n int, version uint64, err error) {
	return fs.WriteAtAs(name, off, data, perm, "")
}

// WriteAtAs is WriteAt with an originating owner stamped on BOTH the implicit OpCreate (for a
// brand-new file) and the OpWrite, so the authority source-suppresses both echoes back to that
// mount (race-free self-suppression). Owner "" reproduces the plain WriteAt.
func (fs *FS) WriteAtAs(name string, off int64, data []byte, perm os.FileMode, owner string) (n int, version uint64, err error) {
	fs.mu.RLock()
	exists := fs.resolve(name) != nil
	fs.mu.RUnlock()
	if !exists {
		if perm == 0 {
			perm = 0o644
		}
		if cerr := fs.MutateAs(wal.Record{Op: wal.OpCreate, Path: name, Mode: modeToUnix(perm)}, owner); cerr != nil {
			return 0, 0, cerr
		}
	}
	// Warm read-modified base blocks OUTSIDE fs.mu (a backend fetch under the lock would stall
	// every other writer), then commit the write under one fs.mu hold.
	fs.warmBaseForWrite(name, off, int64(len(data)))
	fs.mu.Lock()
	v, werr := fs.commitMutationLocked(wal.Record{Op: wal.OpWrite, Path: name, Offset: off, Data: append([]byte(nil), data...)}, owner)
	if werr != nil {
		return 0, 0, werr
	}
	return len(data), v, nil
}

// WriteAtExistingAs is WriteAtAs WITHOUT the create-if-absent prefix: a write to a name that does not
// exist returns os.ErrNotExist instead of resurrecting it. The RPC OpWrite path uses this so a write
// that RACES an unlink — the name detached and parked as an orphan between the mount's orphan-check
// and this write landing — cannot re-create the deleted name at the authority. The existence test is
// commitMutationLocked -> applyWrite's own resolve, ATOMIC under fs.mu with any concurrent OpOrphan,
// so there is no check-then-write gap: the write either lands before the orphan (and is parked with
// it) or sees the name already gone (ErrNotExist). Legitimate writes are unaffected because every
// open path (mount Create RPC, billy OpenFile) creates the file before the first write.
func (fs *FS) WriteAtExistingAs(name string, off int64, data []byte, owner string) (n int, version uint64, err error) {
	return fs.WriteAtHandleExistingAs(name, 0, off, data, owner)
}

// WriteAtHandleExistingAs is WriteAtExistingAs addressed by stable ino when ino is non-zero. Path is
// still carried for coherence invalidation of the mount's current/stale name; lookup never falls back
// to that path when an ino handle was provided, so unlink/rename/recreate cannot redirect the write
// into a different inode generation.
func (fs *FS) WriteAtHandleExistingAs(name string, ino uint64, off int64, data []byte, owner string) (n int, version uint64, err error) {
	if ino != 0 {
		fs.mu.RLock()
		target := fs.resolveForRW(name, ino)
		fs.mu.RUnlock()
		fs.warmBaseForWriteNode(target, off, int64(len(data)))
	} else {
		fs.warmBaseForWrite(name, off, int64(len(data)))
	}
	fs.mu.Lock()
	v, werr := fs.commitMutationLocked(wal.Record{Op: wal.OpWrite, Path: name, Ino: ino, Offset: off, Data: append([]byte(nil), data...)}, owner)
	if werr != nil {
		return 0, 0, werr
	}
	return len(data), v, nil
}

// AppendAtHandleExistingAs is the authority-side O_APPEND path. EOF is
// sampled under the same fs.mu hold that appends and applies the WAL record,
// so concurrent appenders across every mount serialize without a
// lookup/getattr round trip or overlapping ranges.
func (fs *FS) AppendAtHandleExistingAs(name string, ino uint64, data []byte, owner string) (n int, offset int64, version uint64, err error) {
	fs.mu.RLock()
	target := fs.resolveForRW(name, ino)
	var warmAt int64
	if target != nil {
		warmAt = target.curSize()
	}
	fs.mu.RUnlock()
	fs.warmBaseForWriteNode(target, warmAt, int64(len(data)))

	fs.mu.Lock()
	target = fs.resolveForRW(name, ino)
	if target == nil || target.kind != "file" {
		fs.mu.Unlock()
		return 0, 0, 0, os.ErrNotExist
	}
	offset = target.curSize()
	v, werr := fs.commitMutationLocked(wal.Record{
		Op: wal.OpWrite, Path: name, Ino: ino, Append: true,
		Data: append([]byte(nil), data...),
	}, owner)
	if werr != nil {
		return 0, 0, 0, werr
	}
	return len(data), offset, v, nil
}

func randomNonce() uint64 {
	var b [8]byte
	_, _ = crand.Read(b[:])
	v := binary.BigEndian.Uint64(b[:])
	if v == 0 {
		v = 1
	}
	return v
}

// Generation returns this authority process's coherence generation nonce. It changes
// every time the FS is reconstructed (restart / standby promotion); clients refresh all
// cached versions whenever they observe a new generation, so a version assigned under one
// generation is never compared against another.
func (fs *FS) Generation() uint64 { return fs.generation }

// stampVersion assigns the next monotonic coherence version to mutation r and records it
// on each affected inode that still exists. When stampCtime is true, it also stamps POSIX
// ctime. The caller holds fs.mu.
// It returns the assigned version, used to tag the published invalidation.
func (fs *FS) stampVersion(r wal.Record, orphanIno uint64, stampCtime bool) uint64 {
	return fs.stampVersionAt(r, orphanIno, stampCtime, time.Now())
}

// stampVersionAt is stampVersion with an explicit ctime source: the managed
// reducer passes the record's server-selected timestamp so replay stamps
// deterministic ctimes; the live WAL store passes wall-clock now.
func (fs *FS) stampVersionAt(r wal.Record, orphanIno uint64, stampCtime bool, now time.Time) uint64 {
	fs.version++
	v := fs.version
	stamp := func(n *inode) {
		if n == nil {
			return
		}
		n.version = v
		if stampCtime {
			n.ctime = now
		}
	}
	if r.Ino != 0 {
		stamp(fs.byIno[r.Ino])
		if !stampsParentVersion(r.Op) {
			return v
		}
	}
	for _, p := range affectedPaths(r) {
		stamp(fs.resolve(p))
		if stampsParentVersion(r.Op) {
			stamp(fs.resolve(parentPath(p)))
		}
	}
	if orphanIno != 0 {
		stamp(fs.orphans[orphanIno])
	}
	return v
}

func stampsParentVersion(op wal.Op) bool {
	switch op {
	case wal.OpCreate, wal.OpMkdir, wal.OpSymlink, wal.OpRemove, wal.OpRename, wal.OpOrphan, wal.OpLink:
		return true
	default:
		return false
	}
}

func parentPath(p string) string {
	d := path.Dir(cleanPath(p))
	if d == "." || d == "/" {
		return ""
	}
	return d
}

// Version returns the coherence version of a path's most recent mutation.
//
// Degradation contract: versions are ADVISORY coherence stamps attached to
// already-successful operations, and the serving operation itself resolves
// (and therefore hydrates) the path first — so a lazy-base fetch failure here
// cannot produce a WRONG stamp, only a conservative (0,false) "no version",
// which clients treat as an uncacheable answer.
func (fs *FS) Version(p string) (uint64, bool) {
	var version uint64
	found := false
	_ = fs.withReadPath(p, func(n *inode) error {
		if n != nil {
			version, found = n.version, true
		}
		return nil
	})
	return version, found
}

// ParentVersion returns p's parent directory coherence version for a lookup miss at p.
// It degrades conservatively exactly like Version: a lazy-base fetch failure
// yields (0,false), which only prevents negative-entry caching.
func (fs *FS) ParentVersion(p string) (uint64, bool) {
	var version uint64
	found := false
	_ = fs.withReadPath(parentPath(p), func(n *inode) error {
		if n != nil && n.kind == "directory" {
			version, found = n.version, true
		}
		return nil
	})
	return version, found
}

// VersionByHandle returns the coherence version of the inode addressed by stable ino when non-zero,
// otherwise by path. It lets the protocol return the target inode's version even when Path is a stale
// name kept only for invalidation. Same conservative degradation contract as Version.
func (fs *FS) VersionByHandle(p string, ino uint64) (uint64, bool) {
	var version uint64
	found := false
	_ = fs.withReadHandle(p, ino, func(n *inode) error {
		if n != nil {
			version, found = n.version, true
		}
		return nil
	})
	return version, found
}

// ApplyBatch applies an ordered batch of mutations as ONE atomic visibility unit: the
// whole batch is applied under a single write lock, made durable in one group commit,
// and published as a single invalidation set — so neither a concurrent reader (RLock)
// nor another mount can observe a partial batch (no torn flush). It generalizes
// commitMutationLocked: apply-before-durable, and commit regardless of a per-record
// guard rejection (a deterministic phantom that tolerant replay skips identically on
// every node). Used by the authority to apply a mount's flushed write-back session.
func (fs *FS) ApplyBatch(records []wal.Record, owner string) error {
	if len(records) == 0 {
		return nil
	}
	if fs.managed != nil {
		return ErrManagedMode // managed flushes ride ManagedFlushApply's per-row journal entries
	}
	if aerr := fs.admit.enter(); aerr != nil {
		return aerr
	}
	defer fs.admit.exit()
	for i := range records {
		if err := validateIntroducedName(records[i]); err != nil {
			return err // reject the whole batch up front, before any partial apply / watermark advance
		}
	}
	fs.mu.Lock()
	var lastSeq uint64
	var invs []coherence.Invalidation
	for i := range records {
		if derr := fs.admitDirtyWriteLocked(&records[i]); derr != nil {
			// Definite refusal at the dirty-block bound, before this record
			// buffers — like a bufErr, the already-buffered prefix stays
			// durable and the mount retries the remainder after memory frees.
			fs.mu.Unlock()
			return derr
		}
		if ierr := fs.preassignIno(&records[i]); ierr != nil { // log the inode identity before the append so replay is deterministic
			fs.mu.Unlock()
			return ierr
		}
		if ierr := fs.reserveMkdirInos(&records[i]); ierr != nil {
			fs.mu.Unlock()
			return ierr
		}
		seq, bufErr := fs.wal.AppendBuffered(records[i])
		if bufErr != nil {
			fs.mu.Unlock()
			return bufErr // nothing from here on was buffered
		}
		fs.epoch++
		relatedInos := fs.relatedInodesLocked(records[i])
		orphanIno, changed, _ := fs.applyMutationAs(records[i], owner) // tolerant: guard-rejected ops are deterministic phantoms
		if changed {
			// Only a record that ACTUALLY mutated the tree stamps a version and publishes an
			// invalidation — matching the single-commit path (commitMutationResultLocked). A no-op
			// (idempotent mkdir/create, a self-rename, a rejected/guard-rejected record) must do
			// NEITHER: stampVersion bumps fs.version unconditionally, so stamping a no-op both inflates
			// the clock and version-bumps an inode that didn't change; and a phantom name-change
			// invalidation makes peers drop a dentry they didn't need to — re-opening the
			// getcwd→ENOENT→SQLITE_CANTOPEN hazard that InPlace closes, if that name is a peer's CWD.
			v := fs.stampVersion(records[i], orphanIno, true)
			invs = append(invs, fs.changesFor(records[i], owner, v, orphanIno, relatedInos...)...)
		}
		lastSeq = seq
	}
	fs.mu.Unlock()
	// One durability point for the whole batch (fsync + synchronous replication).
	if err := fs.wal.CommitThrough(lastSeq); err != nil {
		return err // durability failure → WAL poisoned → node halts → failover
	}
	mutationsTotal.Add(int64(len(records)))
	fs.publish(invs) // single invalidation set, only AFTER the whole batch is durable
	return nil
}

// applyMutationAs applies r and threads the originating owner to ops that record it (OpRename with
// OrphanTarget tags the parked destination's owner). It returns the orphan ino parked, if any.
//
// This is the WAL-backed (development / self-host / fault-test) store's
// reducer: a remove destroys unless a live open holds the inode, and a rename
// parks its replaced destination only under OrphanTarget/open observation.
// The managed store's reducer (applyManagedMutation) parks deterministically
// on EVERY detach, matching the shared fstransition engine byte-for-byte.
func (fs *FS) applyMutationAs(r wal.Record, owner string) (uint64, bool, error) {
	fs.alloc.observe(r.Ino)
	for _, ino := range r.Inos {
		fs.alloc.observe(ino)
	}
	now := time.Now()
	switch r.Op {
	case wal.OpControl:
		return 0, false, fmt.Errorf("vcs: legacy control record (the raw WAL data plane carries no session store)")
	case wal.OpCreate:
		changed, err := fs.applyCreate(r.Path, "file", modeFromUnix(r.Mode), "", r.Ino, r.Excl, now)
		return 0, changed, err
	case wal.OpMkdir:
		if r.Excl {
			changed, err := fs.applyMkdirExact(r.Path, modeFromUnix(r.Mode), r.Ino, now)
			return 0, changed, err
		}
		changed, err := fs.applyMkdirAll(r.Path, modeFromUnix(r.Mode), r.Inos, now)
		return 0, changed, err
	case wal.OpSymlink:
		changed, err := fs.applyCreate(r.Path, "symlink", modeFromUnix(0o777)|os.ModeSymlink, r.Target, r.Ino, r.Excl, now)
		return 0, changed, err
	case wal.OpLink:
		changed, err := fs.applyLink(r.Path, r.NewPath, r.Ino, now)
		return 0, changed, err
	case wal.OpWrite:
		n := fs.resolveForRW(r.Path, r.Ino)
		if n == nil || n.kind != "file" {
			return 0, false, os.ErrNotExist
		}
		off := r.Offset
		if r.Append {
			// O_APPEND: EOF is resolved HERE, at this record's ordered
			// position, so every replay chooses the same offset.
			off = n.curSize()
		}
		return 0, true, fs.applyWrite(n, off, r.Data)
	case wal.OpTruncate:
		n := fs.resolveForRW(r.Path, r.Ino)
		if n == nil || n.kind != "file" {
			return 0, false, os.ErrNotExist
		}
		return 0, true, fs.applyTruncate(n, r.Size)
	case wal.OpRemove:
		// Stage 2: if ANY mount holds this inode open, PARK it as an orphan (delete-on-last-close)
		// instead of removing. Done at the APPLY layer so it covers BOTH write-through (direct
		// OpRemove) and write-back (OpRemove flushed via ApplyBatch). openInodes is in-memory and
		// empty after a restart, so a recovered OpRemove still plainly removes (the fd is already
		// broken across the restart). The parked ino is returned so changesFor tags the invalidation.
		if n := fs.resolve(r.Path); n != nil && n.kind == "file" && fs.inodeOpenLocked(n.ino, time.Now()) {
			return fs.applyOrphan(r.Path, now)
		}
		// changed (=> version bump + invalidation publish) ONLY if the remove actually happened. A
		// REJECTED remove — missing path (ErrNotExist) or non-empty directory (errNotEmpty) — changed
		// nothing, so it must NOT publish a name-change invalidation: that would make a peer drop a
		// dentry it didn't need to, and if that name is an in-use CWD directory it re-opens the
		// getcwd→ENOENT→SQLITE_CANTOPEN hazard. (Every other op already returns changed=false on a
		// no-op/reject; plain remove was the lone exception.)
		err := fs.applyRemove(r.Path)
		return 0, err == nil, err
	case wal.OpRename:
		return fs.applyRename(r.Path, r.NewPath, r.OrphanTarget, owner)
	case wal.OpOrphan:
		return fs.applyOrphan(r.Path, now)
	case wal.OpReap:
		fs.applyReap(r.Ino)
		return 0, true, nil
	case wal.OpChmod:
		n := fs.resolveForRW(r.Path, r.Ino)
		if n == nil {
			return 0, false, os.ErrNotExist
		}
		n.mode = (n.mode &^ modeUnixFileModeBits) | modeFromUnix(r.Mode)
		return 0, true, nil
	case wal.OpChtimes:
		n := fs.resolveForRW(r.Path, r.Ino)
		if n == nil {
			return 0, false, os.ErrNotExist
		}
		if r.ChtimesSetAtime {
			n.atime = time.UnixMilli(r.AtimeMs)
		}
		if !r.ChtimesKeepMtime {
			n.mtime = time.UnixMilli(r.MtimeMs)
		}
		return 0, true, nil
	case wal.OpChown:
		n := fs.resolveForRW(r.Path, r.Ino)
		if n == nil {
			return 0, false, os.ErrNotExist
		}
		if r.ChownSetUID || r.ChownSetGID {
			// Intent-carrying record (exact mutations): only the flagged field
			// changes; the other resolves against the tree at this record's
			// ordered apply position — deterministic on replay, where a
			// request-time resolution would re-read a moved tree.
			if r.ChownSetUID {
				n.uid = r.UID
			}
			if r.ChownSetGID {
				n.gid = r.GID
			}
		} else {
			// Legacy absolute record (v1 chown path): both fields were
			// resolved by the caller; apply verbatim.
			n.uid = r.UID
			n.gid = r.GID
		}
		return 0, true, nil
	case wal.OpSetxattr:
		changed, err := fs.applySetxattr(r)
		return 0, changed, err
	case wal.OpRemovexattr:
		changed, err := fs.applyRemovexattr(r)
		return 0, changed, err
	default:
		return 0, false, fmt.Errorf("unknown wal op %d", r.Op)
	}
}

// applySetxattr applies one OpSetxattr to the inode resolved by Ino-else-Path
// — named or parked orphan. With no flag it creates or overwrites;
// XattrCreate/XattrReplace evaluate their existence precondition atomically
// at this ordered position. Timestamps are untouched (the chmod discipline).
// Bounds are the frozen wal.MaxXattr* values; the per-inode total is a
// deterministic ENOSPC byte-identical to the shared transition engine
// (fstransition.XattrSetTotal). Caller holds fs.mu.
func (fs *FS) applySetxattr(r wal.Record) (bool, error) {
	if len(r.XattrName) == 0 || len(r.XattrName) > wal.MaxXattrNameBytes || len(r.Data) > wal.MaxXattrValueBytes {
		return false, invalidMutation("xattr name/value out of bounds")
	}
	n := fs.resolveForRW(r.Path, r.Ino)
	if n == nil {
		return false, os.ErrNotExist
	}
	_, exists := fs.xattrs[n.ino][r.XattrName]
	if r.XattrFlags&wal.XattrCreate != 0 && exists {
		return false, os.ErrExist
	}
	if r.XattrFlags&wal.XattrReplace != 0 && !exists {
		return false, errNoXattr
	}
	if fstransition.XattrSetTotal(fs.xattrs[n.ino], r.XattrName, r.Data) > wal.MaxXattrTotalBytes {
		return false, errXattrNoSpace
	}
	m := fs.xattrs[n.ino]
	if m == nil {
		m = map[string][]byte{}
		fs.xattrs[n.ino] = m
	}
	m[r.XattrName] = append([]byte(nil), r.Data...)
	return true, nil
}

// applyRemovexattr applies one OpRemovexattr: a missing name is a
// deterministic ENODATA outcome (Linux removexattr semantics — never a
// silent no-op). Caller holds fs.mu.
func (fs *FS) applyRemovexattr(r wal.Record) (bool, error) {
	if len(r.XattrName) == 0 || len(r.XattrName) > wal.MaxXattrNameBytes {
		return false, invalidMutation("xattr name out of bounds")
	}
	n := fs.resolveForRW(r.Path, r.Ino)
	if n == nil {
		return false, os.ErrNotExist
	}
	m := fs.xattrs[n.ino]
	if _, present := m[r.XattrName]; !present {
		return false, errNoXattr
	}
	delete(m, r.XattrName)
	if len(m) == 0 {
		delete(fs.xattrs, n.ino)
	}
	return true, nil
}

// applyManagedMutation is the MANAGED store's reducer: every state it derives
// comes from the record (timestamps, identities, chown intent) or from the
// tree at this exact LSN position, so live apply, cold replay, and the
// HistoryCut materializer (through the shared fstransition engine) reproduce
// it byte-identically. Unlike the WAL store's applyMutationAs it parks the
// detached inode on EVERY successful unlink/replace — OpReap is the sole
// destruction transition — so non-replicated open-handle observations can
// never make replicas disagree.
func (fs *FS) applyManagedMutation(r wal.Record, owner string) (uint64, bool, error) {
	_ = owner // coherence tagging happens in the caller (changesFor); the reducer is owner-free
	// Burn every logged identity BEFORE semantic application — the single
	// preassigned r.Ino and every member of the mkdir reservation r.Inos —
	// regardless of the outcome. The live authority burned them at
	// reservation even when the apply then failed deterministically (EEXIST
	// guard, unused mkdirAll members), so replay must observe them too or
	// its allocator would sit BELOW the live watermark and a later fresh
	// allocation could re-issue a logged identity. Observation is monotone
	// and idempotent, so the live path (already burned at preassign) is
	// unaffected.
	fs.alloc.observe(r.Ino)
	for _, ino := range r.Inos {
		fs.alloc.observe(ino)
	}
	now := replayTs(r)
	switch r.Op {
	case wal.OpControl:
		return 0, false, fmt.Errorf("vcs: managed reducer received an OpControl record (controls ride PFC2 rows)")
	case wal.OpCreate:
		changed, err := fs.applyCreate(r.Path, "file", modeFromUnix(r.Mode), "", r.Ino, r.Excl, now)
		return 0, changed, err
	case wal.OpMkdir:
		if r.Excl {
			// POSIX mkdir: exactly ONE component under an existing parent;
			// an existing name is a deterministic EEXIST at this LSN.
			changed, err := fs.applyMkdirExact(r.Path, modeFromUnix(r.Mode), r.Ino, now)
			return 0, changed, err
		}
		changed, err := fs.applyMkdirAll(r.Path, modeFromUnix(r.Mode), r.Inos, now)
		return 0, changed, err
	case wal.OpSymlink:
		changed, err := fs.applyCreate(r.Path, "symlink", modeFromUnix(0o777)|os.ModeSymlink, r.Target, r.Ino, r.Excl, now)
		return 0, changed, err
	case wal.OpLink:
		changed, err := fs.applyLink(r.Path, r.NewPath, r.Ino, now)
		return 0, changed, err
	case wal.OpWrite:
		n := fs.resolveForRW(r.Path, r.Ino)
		if n == nil || n.kind != "file" {
			return 0, false, os.ErrNotExist
		}
		off := r.Offset
		if r.Append {
			// O_APPEND: EOF is resolved HERE, at this record's LSN position,
			// so every replay chooses the same offset.
			off = n.curSize()
		}
		if err := fs.applyWrite(n, off, r.Data); err != nil {
			return 0, false, err
		}
		n.mtime = now
		return 0, true, nil
	case wal.OpTruncate:
		n := fs.resolveForRW(r.Path, r.Ino)
		if n == nil || n.kind != "file" {
			return 0, false, os.ErrNotExist
		}
		if err := fs.applyTruncate(n, r.Size); err != nil {
			return 0, false, err
		}
		n.mtime = now
		return 0, true, nil
	case wal.OpRemove:
		// Every successful unlink parks the detached inode first, regardless of
		// non-replicated open-handle observations. OpReap is the sole destruction
		// transition. Therefore live apply and cold replay cannot disagree
		// because one authority happened to observe a live lease.
		return fs.applyOrphan(r.Path, now)
	case wal.OpRename:
		return fs.applyRenameManaged(r.Path, r.NewPath, r.RenameNoReplace, now)
	case wal.OpOrphan:
		return fs.applyOrphan(r.Path, now)
	case wal.OpReap:
		return 0, fs.applyReap(r.Ino), nil
	case wal.OpChmod:
		n := fs.resolveForRW(r.Path, r.Ino)
		if n == nil {
			return 0, false, os.ErrNotExist
		}
		n.mode = (n.mode &^ modeUnixFileModeBits) | modeFromUnix(r.Mode)
		return 0, true, nil
	case wal.OpChtimes:
		n := fs.resolveForRW(r.Path, r.Ino)
		if n == nil {
			return 0, false, os.ErrNotExist
		}
		if r.ChtimesSetAtime {
			n.atime = time.UnixMilli(r.AtimeMs)
		}
		if !r.ChtimesKeepMtime {
			n.mtime = time.UnixMilli(r.MtimeMs)
		}
		return 0, true, nil
	case wal.OpChown:
		n := fs.resolveForRW(r.Path, r.Ino)
		if n == nil {
			return 0, false, os.ErrNotExist
		}
		// Intent-carrying chown (SetUID/SetGID): the unchanged field is resolved
		// against the tree AT THIS LSN, so concurrent chown+chgrp can never
		// clobber each other regardless of reservation interleaving, and replay
		// reproduces the same outcome. A legacy record (neither flag) carries
		// absolute values for both fields.
		if r.ChownSetUID || r.ChownSetGID {
			if r.ChownSetUID {
				n.uid = r.UID
			}
			if r.ChownSetGID {
				n.gid = r.GID
			}
			return 0, true, nil
		}
		n.uid = r.UID
		n.gid = r.GID
		return 0, true, nil
	case wal.OpSetxattr:
		// Xattr transitions derive from the record and the tree at this LSN
		// only — the same applySetxattr/applyRemovexattr the WAL store runs,
		// mirrored byte-for-byte by the shared transition engine.
		changed, err := fs.applySetxattr(r)
		return 0, changed, err
	case wal.OpRemovexattr:
		changed, err := fs.applyRemovexattr(r)
		return 0, changed, err
	default:
		return 0, false, fmt.Errorf("unknown wal op %d", r.Op)
	}
}

func (fs *FS) applyCreate(name, kind string, mode os.FileMode, target string, ino uint64, excl bool, now time.Time) (bool, error) {
	parent, base := fs.resolveParent(name)
	if parent == nil {
		return false, os.ErrNotExist
	}
	if _, ok := parent.children[base]; ok {
		if excl {
			// requireAbsent (O_EXCL create / POSIX symlink): the name existing
			// at this record's ordered position is a deterministic EEXIST —
			// live apply and replay decide identically, and the exact-once
			// outcome stores this status for lost-response retries.
			return false, os.ErrExist
		}
		// Idempotent create: O_CREAT WITHOUT O_TRUNC must not clobber an EXISTING entry — of ANY
		// kind. Same-kind: a second mount re-opening a handed-off file with O_CREAT (its cache
		// momentarily showed it absent, so the kernel issued CREATE not OPEN) would otherwise zero
		// the first mount's data. Different-kind (file-over-dir / dir-over-file / symlink-over-*):
		// a bare create would silently DESTROY an existing directory subtree. A real kind change
		// is an explicit OpRemove + OpCreate; a lone create keeps whatever is already there.
		return false, nil
	}
	assigned, ierr := fs.useOrAllocIno(ino)
	if ierr != nil {
		return false, ierr
	}
	n := &inode{ino: assigned, name: base, kind: kind, mode: mode, mtime: now, ctime: now, atime: now, linkTarget: target, nlink: 1}
	if kind == "file" {
		n.born = true // a freshly created file is local + empty (no backend base)
		n.blocks = map[int64][]byte{}
		n.dirtyEpoch = fs.epoch
	}
	parent.children[base] = n
	fs.linkIno(n)
	bumpDirTimes(parent, now)
	return true, nil
}

// applyLink adds a hard link newName -> the inode currently at (ino, or
// srcPath). POSIX link(2): the source must exist and not be a directory, the
// destination parent must exist, and the destination name must be absent
// (EEXIST). The new dirent references the SAME inode-table record — no copy —
// so the inode is reachable under both names with one stable ino and a shared
// link count. Deterministic on replay: the source is resolved by its logged
// ino when present.
func (fs *FS) applyLink(srcPath, newName string, ino uint64, now time.Time) (bool, error) {
	src := fs.resolveForRW(srcPath, ino)
	if src == nil {
		return false, os.ErrNotExist
	}
	if src.kind == "directory" {
		return false, os.ErrPermission // no hard links to directories (POSIX EPERM)
	}
	if _, parked := fs.orphans[src.ino]; parked {
		// A parked orphan has no names left (unlinked while open). Linux
		// link(2) refuses to resurrect an inode whose last link is gone:
		// ENOENT. Deterministic: the parked set is replicated state.
		return false, os.ErrNotExist
	}
	parent, base := fs.resolveParent(newName)
	if parent == nil {
		return false, os.ErrNotExist
	}
	if _, ok := parent.children[base]; ok {
		return false, os.ErrExist
	}
	parent.children[base] = src
	if src.nlink == 0 {
		src.nlink = 1 // legacy/unset NAMED source: it had exactly one name
	}
	src.nlink++
	src.ctime = now // link changes the inode's ctime (link count changed)
	bumpDirTimes(parent, now)
	return true, nil
}

// applyMkdirExact is the conditional single-component mkdir (wal.Record.Excl):
// the parent chain must already exist (ENOENT; a non-directory prefix is
// ENOTDIR) and the final component must be absent (EEXIST) — POSIX mkdir(2),
// never mkdir -p. The leaf identity rides r.Ino like create/symlink, so replay
// reproduces the same inode.
func (fs *FS) applyMkdirExact(name string, mode os.FileMode, ino uint64, now time.Time) (bool, error) {
	clean := cleanPath(name)
	if clean == "" {
		return false, os.ErrExist // mkdir of the root: it exists by definition
	}
	parent, base := fs.resolveParent(name)
	if parent == nil {
		// resolveParent already rejects a non-directory intermediate with nil;
		// distinguishing ENOTDIR from ENOENT requires re-walking, and POSIX
		// permits ENOENT for a dangling prefix — resolve the common case.
		if p, _ := fs.resolveParentKind(name); p == "notdir" {
			return false, errNotDir
		}
		return false, os.ErrNotExist
	}
	if _, ok := parent.children[base]; ok {
		return false, os.ErrExist
	}
	assigned, ierr := fs.useOrAllocIno(ino)
	if ierr != nil {
		return false, ierr
	}
	child := &inode{
		ino: assigned, name: base, kind: "directory",
		mode: os.ModeDir | mode, mtime: now, ctime: now, atime: now,
		children: map[string]*inode{},
	}
	parent.children[base] = child
	fs.linkIno(child)
	bumpDirTimes(parent, now)
	return true, nil
}

// resolveParentKind reports whether the parent chain of name is fully present
// ("dir"), interrupted by a non-directory ("notdir"), or missing ("missing").
func (fs *FS) resolveParentKind(name string) (string, *inode) {
	clean := cleanPath(name)
	if clean == "" {
		return "dir", fs.root
	}
	parts := strings.Split(clean, "/")
	cur := fs.root
	for _, part := range parts[:len(parts)-1] {
		next, ok := cur.children[part]
		if !ok {
			return "missing", nil
		}
		if next.kind != "directory" {
			return "notdir", nil
		}
		cur = next
	}
	return "dir", cur
}

func (fs *FS) applyMkdirAll(name string, mode os.FileMode, inos []uint64, now time.Time) (bool, error) {
	clean := cleanPath(name)
	if clean == "" {
		return false, nil
	}
	parts := strings.Split(clean, "/")
	if len(inos) != 0 && len(inos) != len(parts) {
		return false, fmt.Errorf("vcs: mkdir inode reservation count %d, want %d", len(inos), len(parts))
	}
	// Preflight every existing prefix before mutating so a non-directory cannot
	// leave a partially-created MkdirAll intent.
	cur := fs.root
	firstMissing := len(parts)
	for i, part := range parts {
		child := cur.children[part]
		if child == nil {
			firstMissing = i
			break
		}
		if child.kind != "directory" {
			return false, fmt.Errorf("vcs: %s: %w", part, errNotDir)
		}
		cur = child
	}
	if firstMissing == len(parts) {
		return false, nil
	}
	for i := firstMissing; i < len(parts); i++ {
		ino := uint64(0)
		if len(inos) != 0 {
			ino = inos[i]
		}
		assigned, ierr := fs.useOrAllocIno(ino)
		if ierr != nil {
			return false, ierr
		}
		child := &inode{
			ino: assigned, name: parts[i], kind: "directory",
			mode: os.ModeDir | mode, mtime: now, ctime: now, atime: now,
			children: map[string]*inode{},
		}
		cur.children[parts[i]] = child
		fs.linkIno(child)
		bumpDirTimes(cur, now)
		cur = child
	}
	return true, nil
}

func (fs *FS) applyWrite(n *inode, off int64, data []byte) error {
	if err := validateWriteRange(off, len(data), false); err != nil {
		return err
	}
	// writeBlocks can read immutable base content. Stage ONLY the blocks touched
	// by this write, then publish all of them after every base fetch succeeded.
	// This provides failure atomicity without cloning an inode's entire dirty map.
	if len(data) == 0 {
		n.dirtyEpoch = fs.epoch
		return nil
	}
	first := off / blockSize
	last := (off + int64(len(data)) - 1) / blockSize
	staged := *n
	staged.blocks = make(map[int64][]byte, last-first+1)
	for bi := first; bi <= last; bi++ {
		if block, ok := n.blocks[bi]; ok {
			staged.blocks[bi] = append([]byte(nil), block...)
		}
	}
	if err := fs.writeBlocks(&staged, off, data); err != nil {
		return err
	}
	if n.blocks == nil {
		n.blocks = make(map[int64][]byte, last-first+1)
	}
	// Exact dirty accounting at the publish boundary (never on the staged
	// copies, so a failed base fetch above accounts nothing): the touched
	// range swaps its old resident buffers for the staged ones.
	var replaced, published int64
	for bi := first; bi <= last; bi++ {
		replaced += int64(len(n.blocks[bi]))
		published += int64(len(staged.blocks[bi]))
	}
	fs.addDirtyBlockBytesLocked(published - replaced)
	for bi := first; bi <= last; bi++ {
		n.blocks[bi] = staged.blocks[bi]
	}
	n.size = staged.size
	n.mtime = staged.mtime
	n.dirtyEpoch = fs.epoch
	return nil
}

func (fs *FS) applyTruncate(n *inode, size int64) error {
	if size < 0 {
		return invalidMutation("negative replay/apply truncate size %d", size)
	}
	fs.truncateBlocks(n, size)
	n.dirtyEpoch = fs.epoch
	return nil
}

func (fs *FS) applyRemove(name string) error {
	parent, base := fs.resolveParent(name)
	if parent == nil {
		return os.ErrNotExist
	}
	child, ok := parent.children[base]
	if !ok {
		return os.ErrNotExist
	}
	if child.kind == "directory" && len(child.children) > 0 {
		return fmt.Errorf("vcs: %s: %w", name, errNotEmpty)
	}
	now := time.Now()
	// Hard links: removing ONE alias only drops its dirent; the inode stays
	// live (and byIno-indexed) through its other names.
	if child.kind != "directory" && child.nlink > 1 {
		child.nlink--
		child.ctime = now
		delete(parent.children, base)
		bumpDirTimes(parent, now)
		return nil
	}
	fs.unlinkIno(child.ino) // a plain remove truly destroys the inode (it is NOT open — else it parked)
	delete(parent.children, base)
	bumpDirTimes(parent, now)
	return nil
}

// resolveForRW resolves the inode an ino-addressed operation targets: when ino != 0 the stable
// file-handle index wins (named or parked-orphan), otherwise it falls back to the path. Caller holds mu.
func (fs *FS) resolveForRW(name string, ino uint64) *inode {
	if ino != 0 {
		// Strict by-ino resolution with NO name fallback, in live serving AND replay. A missing
		// handle ino means the inode is genuinely gone (reaped, or — for a legacy pre-identity WAL
		// whose OpCreate logged no ino — replay re-numbered it): the op simply fails (ENOENT/skip).
		// Falling back to resolve(name) would be actively dangerous, converting the miss into a
		// WRONG-GENERATION durable write if a same-name file was unlinked + recreated — which is the
		// exact corruption ino-addressing exists to prevent. Deterministic create-ino logging
		// (preassignIno + useOrAllocIno) makes post-fix replay hit byIno directly, so no fallback is
		// ever needed for correctly-logged handles.
		return fs.byIno[ino]
	}
	return fs.resolve(name)
}

// applyOrphan detaches the inode at name from its parent and PARKS it in the orphan table, keyed by
// its stable ino — the apply side of open-after-unlink. Unlike applyRemove it keeps the inode alive
// (with its blocks/source), so an open handle keeps reading and writing it by ino until OpReap (last
// close). Deterministic on replay: the parked inode is the one reconstructed at name, and its ino was
// assigned deterministically, so a restarted node parks the same ino.
func (fs *FS) applyOrphan(name string, now time.Time) (uint64, bool, error) {
	parent, base := fs.resolveParent(name)
	if parent == nil {
		return 0, false, os.ErrNotExist
	}
	child, ok := parent.children[base]
	if !ok {
		return 0, false, os.ErrNotExist
	}
	if child.kind == "directory" && len(child.children) > 0 {
		return 0, false, fmt.Errorf("vcs: %s: %w", name, errNotEmpty)
	}
	// A lazily hydrated base directory being removed was proven empty by
	// its pre-apply emptiness probe: an empty enumeration completes the
	// directory, so a pending binding here means live entries exist.
	if child.base != nil {
		return 0, false, fmt.Errorf("vcs: %s: %w", name, errNotEmpty)
	}
	delete(parent.children, base)
	tombstoneBaseName(parent, base)
	bumpDirTimes(parent, now)
	// Hard links: this unlink removes ONE name. If other names still
	// reference the inode (nlink stays > 0 after decrement), the inode is
	// still live and reachable — remove only the dirent, do NOT park. Only
	// the last-link unlink parks the inode for open-after-unlink. Directories
	// (and legacy/unset nlink) fall through to the classic single-name park.
	if child.kind != "directory" && child.nlink > 1 {
		child.nlink--
		child.ctime = now
		return 0, true, nil // the name is gone (a namespace change), but nothing is parked
	}
	if child.kind != "directory" && child.nlink == 1 {
		child.nlink = 0 // last link gone; the parked inode has no names
	}
	fs.orphans[child.ino] = child
	// Lease liveness is wall-clock (not record time): a replayed orphan gets a
	// fresh startup grace instead of an instantly-expired lease.
	fs.orphanLeases[child.ino] = time.Now().Add(orphanLeaseTTL())
	return child.ino, true, nil
}

// applyReap drops a parked orphan after an explicit durable decision. Idempotent:
// a reap of an already-gone ino is a no-op, so a resend or replay is harmless.
func (fs *FS) applyReap(ino uint64) bool {
	_, existed := fs.orphans[ino]
	if !existed {
		// A stale/duplicate/malicious reap must never remove a still-named inode
		// from the stable-handle index merely because it reused that ino.
		if fs.pendingReaps[ino] > 1 {
			fs.pendingReaps[ino]--
		} else {
			delete(fs.pendingReaps, ino)
		}
		return false
	}
	delete(fs.orphans, ino)
	delete(fs.orphanLeases, ino)
	delete(fs.openInodes, ino)
	fs.unlinkIno(ino) // last close of a parked orphan: now truly destroyed, drop the file handle
	if fs.pft2 != nil && ino <= fs.alloc.durableFloor {
		// The immutable base can still resolve this id; the reap decision
		// must dominate every later stable-handle hydration.
		fs.deadBaseInos[ino] = struct{}{}
	}
	if fs.pendingReaps[ino] > 1 {
		fs.pendingReaps[ino]--
	} else {
		delete(fs.pendingReaps, ino)
	}
	return true
}

// applyRename moves a node, enforcing POSIX rename rules so it never silently
// clobbers: the destination, if it exists, must be type-compatible (dir↔dir,
// non-dir↔non-dir) and an existing directory destination must be empty; a directory
// cannot be renamed into its own subtree. Without these guards "mv newdir olddir"
// would discard olddir's contents — a data-loss bug.
func (fs *FS) applyRename(oldName, newName string, orphanTarget bool, owner string) (uint64, bool, error) {
	oldParent, oldBase := fs.resolveParent(oldName)
	if oldParent == nil {
		return 0, false, os.ErrNotExist
	}
	node, ok := oldParent.children[oldBase]
	if !ok {
		return 0, false, os.ErrNotExist
	}
	newParent, newBase := fs.resolveParent(newName)
	if newParent == nil {
		return 0, false, os.ErrNotExist
	}
	var existing *inode
	if e, ok := newParent.children[newBase]; ok {
		existing = e
		if existing == node {
			return 0, false, nil // renaming a path onto itself is a no-op
		}
		switch {
		case node.kind == "directory" && existing.kind != "directory":
			return 0, false, errNotDir // can't replace a non-directory with a directory
		case node.kind != "directory" && existing.kind == "directory":
			return 0, false, errIsDir // can't replace a directory with a non-directory
		case existing.kind == "directory" && len(existing.children) > 0:
			return 0, false, errNotEmpty // an existing directory destination must be empty
		}
	}
	if node.kind == "directory" && isInSubtree(oldName, newName) {
		return 0, false, errInvalidRename // can't move a directory into its own subtree
	}
	now := time.Now()
	// Rename-over-an-open-file: park the replaced destination by its ino (instead of dropping it) so
	// its open handles keep reading/writing it until the last close. The dest is parked when EITHER
	// the renaming mount flagged it open locally (OrphanTarget) OR any mount holds the inode open per
	// the authority's Stage-2 open-state (inodeOpenLocked) — the latter covers a CROSS-mount rename
	// over a file only a peer holds open. openInodes is empty on replay, so a recovered rename parks
	// only on OrphanTarget; the live-only orphan that the open-state adds is moot once fds are broken.
	var orphanIno uint64
	switch {
	case existing != nil && existing.kind != "directory" && existing.nlink > 1:
		// Hard links: the replaced destination loses ONE name; the inode
		// stays live (and byIno-indexed) through its other aliases.
		existing.nlink--
		existing.ctime = now
	case existing != nil && existing.kind == "file" && (orphanTarget || fs.inodeOpenLocked(existing.ino, now)):
		orphanIno = existing.ino
		if existing.nlink == 1 {
			existing.nlink = 0 // last link gone; the parked inode has no names
		}
		fs.orphans[orphanIno] = existing
		fs.orphanLeases[orphanIno] = now.Add(orphanLeaseTTL())
	case existing != nil:
		// rename-over of a NOT-open destination: the replaced inode is truly destroyed (not parked),
		// so drop its handle from the by-ino index — otherwise it leaks a detached inode pointer that
		// a stray handle could still mutate (an inode neither named nor parked, lost at checkpoint).
		fs.unlinkIno(existing.ino)
	}
	delete(oldParent.children, oldBase)
	node.name = newBase
	newParent.children[newBase] = node
	bumpDirTimes(oldParent, now)
	if newParent != oldParent {
		bumpDirTimes(newParent, now)
	}
	return orphanIno, true, nil
}

// applyRenameManaged is the MANAGED reducer's rename: POSIX type/emptiness
// guards like applyRename, plus the durable RENAME_NOREPLACE intent (an
// existing destination at this LSN is EEXIST, decided atomically in apply
// order), and a deterministic detach policy — a replaced destination that
// loses its last name is ALWAYS parked before the source is linked, never
// destroyed on the spot (liveness only controls when a later explicit reap
// may be reserved, never the replicated transition).
func (fs *FS) applyRenameManaged(oldName, newName string, noReplace bool, now time.Time) (uint64, bool, error) {
	oldParent, oldBase := fs.resolveParent(oldName)
	if oldParent == nil {
		return 0, false, os.ErrNotExist
	}
	node, ok := oldParent.children[oldBase]
	if !ok {
		return 0, false, os.ErrNotExist
	}
	newParent, newBase := fs.resolveParent(newName)
	if newParent == nil {
		return 0, false, os.ErrNotExist
	}
	var existing *inode
	if e, ok := newParent.children[newBase]; ok {
		existing = e
		if noReplace {
			// RENAME_NOREPLACE: even a rename onto itself is EEXIST (Linux
			// renameat2 semantics — the destination exists, full stop).
			return 0, false, os.ErrExist
		}
		if existing == node {
			return 0, false, nil // renaming a path onto itself is a no-op
		}
		switch {
		case node.kind == "directory" && existing.kind != "directory":
			return 0, false, errNotDir // can't replace a non-directory with a directory
		case node.kind != "directory" && existing.kind == "directory":
			return 0, false, errIsDir // can't replace a directory with a non-directory
		case existing.kind == "directory" && len(existing.children) > 0:
			return 0, false, errNotEmpty // an existing directory destination must be empty
		case existing.kind == "directory" && existing.base != nil:
			// Lazily hydrated destination: an empty base enumeration would
			// have completed it (base == nil), so a pending binding proves
			// unmaterialized base entries — the directory is not empty.
			return 0, false, errNotEmpty
		}
	}
	if node.kind == "directory" && isInSubtree(oldName, newName) {
		return 0, false, errInvalidRename // can't move a directory into its own subtree
	}
	// A replaced destination loses ONE name. If it still has other hard links
	// (nlink > 1), it stays live and is not parked — only its dirent goes.
	// Otherwise it is parked before the source is linked.
	var orphanIno uint64
	if existing != nil {
		if existing.kind != "directory" && existing.nlink > 1 {
			existing.nlink--
			existing.ctime = now
		} else {
			if existing.kind != "directory" && existing.nlink == 1 {
				existing.nlink = 0
			}
			orphanIno = existing.ino
			fs.orphans[orphanIno] = existing
			fs.orphanLeases[orphanIno] = time.Now().Add(orphanLeaseTTL()) // liveness: wall clock, fresh grace on replay
		}
	}
	delete(oldParent.children, oldBase)
	tombstoneBaseName(oldParent, oldBase)
	// Only dirents move: the inode record carries no name, so renaming ONE
	// alias of a hard-linked inode can never corrupt how its other aliases
	// resolve or report themselves.
	newParent.children[newBase] = node
	bumpDirTimes(oldParent, now)
	if newParent != oldParent {
		bumpDirTimes(newParent, now)
	}
	return orphanIno, true, nil
}

// isInSubtree reports whether descendant is ancestor itself or lies beneath it.
func isInSubtree(ancestor, descendant string) bool {
	a := cleanPath(ancestor)
	d := cleanPath(descendant)
	return d == a || strings.HasPrefix(d, a+"/")
}

// ---- reads ----

func (fs *FS) readAt(n *inode, p []byte, off int64) (int, error) {
	return fs.readBlocks(n, p, off)
}

// ---- orphan (open-after-unlink) public API ----
//
// An open handle whose name was unlinked (or renamed-over) keeps operating on the inode by its stable
// ino: the authority parks it (Orphan), serves reads/writes/truncates against it by ino, and frees it
// on the last close (Reap). All mutations go through the WAL like any other, so a restart or standby
// promotion mid-session converges to the same orphan state.

// Orphan detaches name from the tree and parks its inode, returning the parked ino for the caller to
// address on subsequent reads/writes (0 when the unlink dropped one alias of a still-named
// hard-linked inode: nothing parked, the surviving names keep serving it). The caller (mount) issues
// this instead of Remove when it still holds the file open, so the bytes survive the unlink until
// the last handle closes.
func (fs *FS) Orphan(name, owner string) (uint64, error) {
	fs.mu.Lock()
	if fs.resolve(name) == nil {
		fs.mu.Unlock()
		return 0, os.ErrNotExist
	}
	_, orphanIno, err := fs.commitMutationResultLocked(wal.Record{Op: wal.OpOrphan, Path: name}, owner)
	if err != nil {
		return 0, err
	}
	return orphanIno, nil
}

// Reap frees a parked orphan on the last close of its final handle. Idempotent at apply, so a resend
// is harmless.
func (fs *FS) Reap(ino uint64, owner string) error {
	fs.mu.Lock()
	_, err := fs.commitMutationLocked(wal.Record{Op: wal.OpReap, Ino: ino}, owner)
	return err
}

// RenewOrphanLeases extends the in-memory leases for parked orphan inos still known to this
// authority. Unknown/reaped inos are ignored, making renewal idempotent across reconnects.
func (fs *FS) RenewOrphanLeases(inos []uint64) int {
	if len(inos) == 0 {
		return 0
	}
	expiry := time.Now().Add(orphanLeaseTTL())
	fs.mu.Lock()
	defer fs.mu.Unlock()
	renewed := 0
	for _, ino := range inos {
		if fs.orphans[ino] == nil {
			continue
		}
		fs.orphanLeases[ino] = expiry
		renewed++
	}
	return renewed
}

// MarkOpenInode registers (or refreshes) that owner holds ino open, with a fresh lease. Stage 2:
// the authority parks instead of removing an inode some mount holds open, so a cross-mount unlink of
// a peer's open file becomes delete-on-last-close. A mount registers on first open and renews; a
// crashed mount's leases expire and are ignored. Not WAL-logged (pure liveness, dropped on restart).
// MarkOpenInode records owner's open hold on ino and reports whether the inode still EXISTS. The
// existence check + the mark happen under one fs.mu hold, atomic with any concurrent unlink's
// park-check (inodeOpenLocked), so the open-registration race is closed: either this open marks the
// inode before a peer's unlink (which then parks it — the fd survives, delete-on-last-close) or the
// unlink already destroyed it and this returns false (the mount fails the open with ENOENT instead
// of handing back a handle to a dead inode). A dead ino is never recorded — that would be a leak the
// sweeper can't clear (no inode to ever UnmarkOpen).
func (fs *FS) MarkOpenInode(ino uint64, owner string) bool {
	if ino == 0 {
		return false
	}
	exp := time.Now().Add(orphanLeaseTTL())
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.byIno[ino] == nil {
		return false // raced a peer unlink: the inode is already gone
	}
	m := fs.openInodes[ino]
	if m == nil {
		m = map[string]time.Time{}
		fs.openInodes[ino] = m
	}
	m[owner] = exp
	return true
}

// UnmarkOpenInode clears owner's open hold on ino (its last local close of the inode).
func (fs *FS) UnmarkOpenInode(ino uint64, owner string) {
	fs.mu.Lock()
	if m := fs.openInodes[ino]; m != nil {
		delete(m, owner)
		if len(m) == 0 {
			delete(fs.openInodes, ino)
		}
	}
	fs.mu.Unlock()
}

// RenewOpenInodes refreshes owner's open leases for a batch of inos (periodic liveness). Idempotent.
func (fs *FS) RenewOpenInodes(inos []uint64, owner string) {
	if len(inos) == 0 {
		return
	}
	exp := time.Now().Add(orphanLeaseTTL())
	fs.mu.Lock()
	for _, ino := range inos {
		m := fs.openInodes[ino]
		if m == nil {
			m = map[string]time.Time{}
			fs.openInodes[ino] = m
		}
		m[owner] = exp
	}
	fs.mu.Unlock()
}

// inodeOpenLocked reports whether ANY mount holds ino open with a non-expired lease. Caller holds fs.mu.
func (fs *FS) inodeOpenLocked(ino uint64, now time.Time) bool {
	for _, exp := range fs.openInodes[ino] {
		if exp.After(now) {
			return true
		}
	}
	return false
}

// pruneExpiredOpenInodes drops open-lease entries whose lease has lapsed (a crashed/gone holder), so
// the table does not accumulate dead owners. Correctness does not depend on it — inodeOpenLocked
// already ignores expired entries — but it bounds memory. Called from the sweeper.
func (fs *FS) pruneExpiredOpenInodes(now time.Time) {
	fs.mu.Lock()
	for ino, m := range fs.openInodes {
		for owner, exp := range m {
			if !exp.After(now) {
				delete(m, owner)
			}
		}
		if len(m) == 0 {
			delete(fs.openInodes, ino)
		}
	}
	fs.mu.Unlock()
}

// StartOrphanSweeper runs the lease-expiry GC until ctx is cancelled.
func (fs *FS) StartOrphanSweeper(ctx context.Context) {
	interval := orphanSweepInterval()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				fs.SweepExpiredOrphans(now)
				fs.pruneExpiredOpenInodes(now)
			}
		}
	}()
}

// SweepExpiredOrphans WAL-reaps orphan leases expired at now. It re-checks each lease under the
// write lock immediately before committing OpReap, so a renewal that landed after the scan wins.
func (fs *FS) SweepExpiredOrphans(now time.Time) int {
	fs.mu.RLock()
	var expired []uint64
	for ino, exp := range fs.orphanLeases {
		if !exp.After(now) {
			expired = append(expired, ino)
		}
	}
	fs.mu.RUnlock()
	reaped := 0
	for _, ino := range expired {
		if fs.reapExpiredOrphan(ino, now) {
			reaped++
		}
	}
	return reaped
}

func (fs *FS) reapExpiredOrphan(ino uint64, now time.Time) bool {
	fs.mu.Lock()
	exp, ok := fs.orphanLeases[ino]
	if !ok || exp.After(now) || fs.orphans[ino] == nil {
		fs.mu.Unlock()
		return false
	}
	if fs.inodeOpenLocked(ino, now) {
		// A mount still holds this inode open per the authority's open-state (Stage 2), even though it
		// has not renewed the ORPHAN lease — it may have missed the Orphaned invalidation and never
		// marked its node, so it renews openInodes but not openOrphans. Re-arm the orphan lease so it
		// is NOT reaped out from under that live holder; it can still re-derive the redirect by ino.
		fs.orphanLeases[ino] = now.Add(orphanLeaseTTL())
		fs.mu.Unlock()
		return false
	}
	_, err := fs.commitMutationLocked(wal.Record{Op: wal.OpReap, Ino: ino}, "")
	return err == nil
}

// ReadOrphanAt reads from a parked orphan by ino (the read side of open-after-unlink). ErrNotExist if
// it was already reaped. readBlocks takes mu itself, so we only need to fetch the inode safely.
func (fs *FS) ReadOrphanAt(ino uint64, p []byte, off int64) (int, error) {
	fs.mu.RLock()
	n := fs.orphans[ino]
	fs.mu.RUnlock()
	if n == nil {
		return 0, os.ErrNotExist
	}
	return fs.readAt(n, p, off)
}

// ReadHandleAt reads by stable ino when ino is non-zero (named or parked-orphan), otherwise by path.
// It is the read side of an open-fd handle: path is only a fallback for old path-addressed callers.
func (fs *FS) ReadHandleAt(name string, ino uint64, p []byte, off int64) (int, error) {
	var n *inode
	if err := fs.withReadHandle(name, ino, func(resolved *inode) error {
		n = resolved
		return nil
	}); err != nil {
		return 0, err
	}
	if n == nil || n.kind != "file" {
		return 0, os.ErrNotExist
	}
	return fs.readAt(n, p, off)
}

// WriteOrphanAt writes to a parked orphan by ino, WAL-durable like any write (so replay and the
// standby converge). Warms base blocks for a partial overwrite the same way the named write path does.
func (fs *FS) WriteOrphanAt(ino uint64, off int64, data []byte, owner string) (int, uint64, error) {
	fs.mu.RLock()
	n := fs.orphans[ino]
	fs.mu.RUnlock()
	if n == nil {
		return 0, 0, os.ErrNotExist
	}
	fs.warmBaseForWriteNode(n, off, int64(len(data))) // outside mu: a base fetch must not stall writers
	fs.mu.Lock()
	v, err := fs.commitMutationLocked(wal.Record{Op: wal.OpWrite, Ino: ino, Offset: off, Data: append([]byte(nil), data...)}, owner)
	if err != nil {
		return 0, 0, err
	}
	return len(data), v, nil
}

// AppendOrphanAs is O_APPEND for an unlinked-but-open inode. It uses the same
// ordered WAL reducer as named appends; only stable-inode addressing differs.
func (fs *FS) AppendOrphanAs(ino uint64, data []byte, owner string) (n int, offset int64, version uint64, err error) {
	fs.mu.RLock()
	target := fs.orphans[ino]
	var warmAt int64
	if target != nil {
		warmAt = target.curSize()
	}
	fs.mu.RUnlock()
	fs.warmBaseForWriteNode(target, warmAt, int64(len(data)))

	fs.mu.Lock()
	target = fs.orphans[ino]
	if target == nil || target.kind != "file" {
		fs.mu.Unlock()
		return 0, 0, 0, os.ErrNotExist
	}
	offset = target.curSize()
	v, werr := fs.commitMutationLocked(wal.Record{
		Op: wal.OpWrite, Ino: ino, Append: true,
		Data: append([]byte(nil), data...),
	}, owner)
	if werr != nil {
		return 0, 0, 0, werr
	}
	return len(data), offset, v, nil
}

// OrphanInfo returns a parked orphan's attributes by ino (for fstat on an unlinked-but-open fd). The
// returned FileInfo exposes the stable ino, ownership, and link count via its Sys(), like a named
// stat does. A parked orphan has no dirent, so its reported name is empty and st_nlink is 0 — the
// POSIX truth for an unlinked-while-open inode. Not found ⇒ ok=false (reaped).
func (fs *FS) OrphanInfo(ino uint64) (os.FileInfo, bool) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	n := fs.orphans[ino]
	if n == nil {
		return nil, false
	}
	return fs.infoOfNamed(n, ""), true
}

// HandleInfo stats by stable ino when ino is non-zero (named or parked-orphan), otherwise by path.
//
// It distinguishes VERIFIED absence (os.ErrNotExist → ENOENT) from a
// lazy-base hydration/integrity/transport failure (any other error → its
// errno, EIO by default). The distinction is load-bearing: a mount that
// receives ENOENT drops the handle permanently, while an EIO retry of the
// same inode succeeds once the authority's base store recovers.
func (fs *FS) HandleInfo(name string, ino uint64) (os.FileInfo, error) {
	var fi os.FileInfo
	err := fs.withReadHandle(name, ino, func(n *inode) error {
		if n == nil {
			return os.ErrNotExist
		}
		fi = fs.infoOfNamed(n, direntName(name))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return fi, nil
}

// LiveOrphanSources returns immutable copies of every committed content source
// still reachable through a live parked inode. Checkpoint/object GC must treat
// each BlobDigest and each Chunks[i].Digest in this result as pinned until a
// later call no longer returns it (normally after ordered OpReap apply).
//
// Born-only orphans have no backend source and are omitted: their bytes reside
// in log-backed dirty blocks, not content-addressed objects. Dirty orphans that
// retain a committed base are included because untouched ranges may still be
// fetched lazily from that base. Results are ordered by stable inode identity;
// duplicate sources are intentionally retained so consumers can choose set or
// reference-count semantics. The returned chunk slices never alias live state.
func (fs *FS) LiveOrphanSources() []content.Source {
	type sourceAtIno struct {
		ino    uint64
		source content.Source
	}
	fs.mu.RLock()
	sources := make([]sourceAtIno, 0, len(fs.orphans))
	for ino, n := range fs.orphans {
		if n == nil || n.kind != "file" || (n.source.BlobDigest == "" && len(n.source.Chunks) == 0) {
			continue
		}
		source := n.source
		source.Chunks = append([]backend.Chunk(nil), n.source.Chunks...)
		sources = append(sources, sourceAtIno{ino: ino, source: source})
	}
	fs.mu.RUnlock()
	sort.Slice(sources, func(i, j int) bool { return sources[i].ino < sources[j].ino })
	out := make([]content.Source, len(sources))
	for i := range sources {
		out[i] = sources[i].source
	}
	return out
}

// TruncateOrphanAt truncates a parked orphan by ino (ftruncate on an unlinked-but-open fd is valid).
func (fs *FS) TruncateOrphanAt(ino uint64, size int64, owner string) error {
	fs.mu.RLock()
	_, ok := fs.orphans[ino]
	fs.mu.RUnlock()
	if !ok {
		return os.ErrNotExist
	}
	fs.mu.Lock()
	_, err := fs.commitMutationLocked(wal.Record{Op: wal.OpTruncate, Ino: ino, Size: size}, owner)
	return err
}

// RenameWithOrphanTarget renames oldName->newName; when orphanTarget is set and newName exists, the
// replaced destination is PARKED by its ino (rename-over-an-open-file) instead of dropped, and its
// parked ino is returned so the mount can address it by ino. orphanTarget=false is an ordinary rename.
func (fs *FS) RenameWithOrphanTarget(oldName, newName string, orphanTarget bool, owner string) (uint64, error) {
	fs.mu.Lock()
	_, orphanIno, err := fs.commitMutationResultLocked(wal.Record{
		Op:           wal.OpRename,
		Path:         oldName,
		NewPath:      newName,
		OrphanTarget: orphanTarget,
	}, owner)
	if err != nil {
		return 0, err
	}
	return orphanIno, nil
}

// Snapshot is a manifest-shaped view of the current working tree, used by the
// checkpointer. A dirty file carries its base source + a copy of its dirty
// blocks + size (the checkpointer calls MaterializeFull to get its full bytes
// without holding the FS lock); a clean file carries only its backed source.
type SnapshotEntry struct {
	Path       string
	Kind       string
	Mode       uint32
	MtimeMs    int64
	CtimeMs    int64
	AtimeMs    int64
	UID        uint32
	GID        uint32
	Ino        uint64
	LinkTarget string
	Dirty      bool
	Size       int64
	Source     content.Source
	Blocks     map[int64][]byte
}

// Snapshot is a consistent capture of the working tree for the checkpointer: the
// path-sorted entries, the mutation epoch at capture time (so MarkClean leaves
// files re-written afterwards dirty), and the WAL LSN watermark to compact away
// once committed (every record below it is part of this snapshot).
type Snapshot struct {
	Entries      []SnapshotEntry
	epoch        int64
	walWatermark uint64
	walRecords   int
}

// HasUncommittedRecords reports whether the snapshot covers any WAL record
// that no prior checkpoint has compacted away. It is the checkpoint commit
// trigger: EVERY acknowledged mutation — including metadata-only ones that
// dirty no file content — appended a WAL record, so a checkpoint pass commits
// exactly when this is true even though no file is content-dirty.
func (s *Snapshot) HasUncommittedRecords() bool { return s.walRecords > 0 }

// WALWatermark is the exclusive upper LSN bound this snapshot covers: every
// record with Seq < WALWatermark is part of the snapshot.
func (s *Snapshot) WALWatermark() uint64 { return s.walWatermark }

// Snapshot returns a consistent capture of the working tree. Dirty blocks are
// copied so the snapshot is safe to read while writes continue. On a lazily
// hydrated base the whole namespace is materialized first (a snapshot that
// silently omitted unhydrated names would commit namespace loss).
func (fs *FS) Snapshot() *Snapshot {
	fs.mustMaterializeForSnapshot()
	// RLock gives a consistent cut: it excludes all writers (which take the exclusive
	// Lock) for the duration of the walk, while admitting concurrent reads. The walk
	// copies every dirty block, so the snapshot is safe to use after the lock drops.
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.snapshotLocked(true)
}

// CheckpointProbeContext captures manifest metadata and the exact applied
// cursor, but no dirty block bytes: it checks cancellation, completes any
// lazily hydrated base namespace OUTSIDE fs.mu (a no-op for an eagerly loaded
// FS), then takes the probe under one read-lock hold. A temporarily
// unreachable immutable base (object-store outage) or a canceled pass
// surfaces as a wrapped error: the caller fails and retries later, ordinary
// live serving keeps flowing, and the authority never crashes on account of
// the probe.
func (fs *FS) CheckpointProbeContext(ctx context.Context) (*Snapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := fs.MaterializeBaseNamespace(ctx); err != nil {
		return nil, fmt.Errorf("workfs: checkpoint probe: complete lazy base namespace: %w", err)
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.snapshotLocked(false), nil
}

// snapshotLocked builds a tree snapshot while the caller holds fs.mu (read or
// write). withBlocks copies dirty block bytes; the probe variant skips them.
func (fs *FS) snapshotLocked(withBlocks bool) *Snapshot {
	var out []SnapshotEntry
	var walk func(prefix string, n *inode)
	walk = func(prefix string, n *inode) {
		names := make([]string, 0, len(n.children))
		for name := range n.children {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			c := n.children[name]
			p := name
			if prefix != "" {
				p = prefix + "/" + name
			}
			mtime, ctime, atime := inodeTimes(c)
			e := SnapshotEntry{
				Path: p, Kind: c.kind, Mode: modeToUnix(c.mode), Ino: c.ino,
				MtimeMs: mtime.UnixMilli(), CtimeMs: ctime.UnixMilli(), AtimeMs: atime.UnixMilli(),
				UID: c.uid, GID: c.gid, LinkTarget: c.linkTarget,
			}
			if c.kind == "file" {
				e.Dirty = c.hasLocalContent()
				e.Source = c.source
				e.Size = c.size
				if e.Dirty && withBlocks {
					e.Blocks = make(map[int64][]byte, len(c.blocks))
					for bi, blk := range c.blocks {
						e.Blocks[bi] = append([]byte(nil), blk...)
					}
				}
			}
			out = append(out, e)
			if c.kind == "directory" {
				walk(p, c)
			}
		}
	}
	walk("", fs.root)
	var watermark, compacted uint64
	if fs.managed != nil {
		watermark = fs.seq.appliedWatermark()
		compacted = fs.managed.log.CompactedThrough()
	} else {
		watermark = fs.wal.Watermark()
		compacted = fs.wal.CompactedThrough()
	}
	records := 0
	if watermark > compacted {
		records = int(watermark - compacted)
	}
	return &Snapshot{Entries: out, epoch: fs.epoch, walWatermark: watermark, walRecords: records}
}

// MaterializeFull reconstructs a dirty snapshot entry's full bytes (base + dirty
// blocks), fetching base blocks lazily. It takes no FS lock — it reads only the
// immutable snapshot copy — so the checkpointer can serialise large files
// without stalling live writes.
func (fs *FS) MaterializeFull(e SnapshotEntry) ([]byte, error) {
	return mergeFull(fs.blobs, fs.cache, e.Source, e.Blocks, e.Size)
}

// MarkClean rebinds a committed file to its backed source and drops its dirty
// blocks — UNLESS it was written again after the snapshot (dirtyEpoch > snap
// epoch), in which case it stays dirty so the next checkpoint commits the newer
// content. Without this guard a write racing the checkpoint would be dropped.
func (fs *FS) MarkClean(snap *Snapshot, pathName string, src content.Source) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n := fs.resolve(pathName)
	if n == nil || n.kind != "file" || n.dirtyEpoch > snap.epoch {
		return
	}
	fs.addDirtyBlockBytesLocked(-dirtyBlockBytesOf(n)) // folded into the committed base: resident copies released
	n.source = src
	n.blocks = map[int64][]byte{}
	n.born = false
	n.truncated = false // committed: source.Size now matches the live size
	n.size = src.Size
}

// EnsureSnapshotDurable flushes the WAL so EVERY record the snapshot reflects (LSN <
// walWatermark) is fsync'd AND replicated before a checkpoint commits the snapshot to
// the durable backend. Without it, the apply-before-durable hot path could let a
// checkpoint snapshot a write, commit it to the backend manifest (so it surfaces on a
// promoted standby), and only then have that write's own replication fail — a phantom
// the client was told FAILED yet which persists. On a durability failure this returns
// an error and the caller MUST abort the checkpoint (commit nothing).
func (fs *FS) EnsureSnapshotDurable(snap *Snapshot) error {
	if snap.walWatermark == 0 {
		return nil
	}
	return fs.wal.CommitThrough(snap.walWatermark - 1)
}

// PoisonedCh exposes the durable store's poison signal so the serving node can
// fence its data plane (stop reads/writes/checkpoints, step down) when
// durability can no longer be upheld — rather than keep serving
// applied-but-unacked state a successor would lack. Managed generations answer
// the PFJ3 entry log's signal; the WAL-backed store answers the file WAL's.
func (fs *FS) PoisonedCh() <-chan struct{} {
	if fs.wal != nil {
		return fs.wal.PoisonedCh()
	}
	return fs.log.PoisonedCh()
}
