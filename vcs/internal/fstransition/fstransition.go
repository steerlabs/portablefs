// Package fstransition is the ONE pure deterministic filesystem transition
// engine shared by every consumer that folds ordered wal.Record mutations
// into a tree: the live WorkFS authority semantics are the reference
// behaviour (internal/workfs applyMutationAs), and the HistoryCut
// materializer drives the identical engine over a PFT2 editor transaction.
// The engine has NO materializer-specific namespace semantics: given the same
// base state and the same ordered records it produces the same tree, inode
// identities, nlink counts, and parked-orphan set as the live authority —
// differential goldens in this package prove that record-for-record.
//
// The engine is pure state transition: it performs no IO of its own, no
// clocks (record timestamps only, with one fixed caller-supplied fallback for
// legacy zero-timestamp records), no environment reads, and no randomness.
// Deterministic semantic failures (ENOENT, EEXIST, ENOTDIR, EISDIR,
// ENOTEMPTY) are OUTCOMES: they leave the transaction untouched for that
// record and replay identically everywhere, exactly like the live authority.
// Infrastructure failures (budget, fetch, corrupt base) abort the whole apply
// with a typed error.
package fstransition

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// Tx is the transactional tree state the engine drives. *pft2.Editor
// implements it directly; the in-memory reference transaction (MemTx) mirrors
// the live WorkFS inode model for tests and differential goldens.
type Tx interface {
	GetInode(ctx context.Context, ino uint64) (pft2.Inode, bool, error)
	PutInode(ctx context.Context, inode pft2.Inode) error
	GetOrphanInode(ctx context.Context, ino uint64) (pft2.Inode, bool, error)
	PutOrphanInode(ctx context.Context, inode pft2.Inode) error
	DeleteOrphanInode(ctx context.Context, ino uint64) error

	GetDirEntry(ctx context.Context, parent uint64, name string) (pft2.DirEntry, bool, error)
	PutDirEntry(ctx context.Context, parent uint64, entry pft2.DirEntry) error
	DeleteDirEntry(ctx context.Context, parent uint64, name string) error
	// DirEntryCount is the MERGED live entry count (base + staged edits) —
	// the engine's rmdir/rename-emptiness decisions depend on it.
	DirEntryCount(ctx context.Context, parent uint64) (uint64, error)

	ReadCell(ctx context.Context, ino uint64, cellOffset uint64) ([]byte, error)
	WriteCell(ctx context.Context, ino uint64, cellOffset uint64, cell []byte) error
	SetFileSize(ctx context.Context, ino uint64, size uint64) error
}

// Sentinel outcomes (deterministic per-record semantic failures). They match
// the live authority's os.* errors — and, for the engine-local sentinels,
// the exact errnos.Of wire statuses the live authority stores — so a
// materialized exact outcome is byte-identical to the live/replayed one.
var (
	ErrNotExist = os.ErrNotExist
	ErrExist    = os.ErrExist
	errNotDir   = errors.New("fstransition: not a directory")
	errIsDir    = errors.New("fstransition: is a directory")
	errNotEmpty = errors.New("fstransition: directory not empty")
	// errInvalid covers structurally invalid mutations (write-range
	// overflow, negative truncate). The live authority validates these
	// pre-append, so a DURABLE record producing it is corruption — it is
	// deterministic but never a benign env-less replay outcome.
	errInvalid = errors.New("fstransition: invalid argument: invalid mutation")
	// errInvalidRename is the rename-into-own-subtree guard: deterministic
	// AND benign on env-less replay (exactly like the live authority's
	// errInvalidRename), unlike the other errInvalid cases.
	errInvalidRename = errors.New("fstransition: invalid argument: rename into own subtree")
	// errNoXattr is the removexattr-of-a-missing-name outcome (Linux
	// removexattr semantics: ENODATA, never a silent no-op). Deterministic
	// at the record's ordered position and benign on env-less replay (an
	// idempotent-retry phantom re-rejects identically).
	errNoXattr = fmt.Errorf("fstransition: no such extended attribute: %w", syscall.ENODATA)
	// errXattrNoSpace is the per-inode xattr total-bytes bound outcome
	// (wal.MaxXattrTotalBytes): a deterministic ENOSPC at the record's
	// ordered position, benign on env-less replay.
	errXattrNoSpace = fmt.Errorf("fstransition: extended attributes exceed the per-inode byte bound: %w", syscall.ENOSPC)
)

// IsDeterministicOutcome reports whether err is a semantic per-record outcome
// (replay-identical everywhere) rather than an infrastructure failure that
// must abort the apply.
func IsDeterministicOutcome(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrExist) ||
		errors.Is(err, os.ErrPermission) ||
		errors.Is(err, errNotDir) || errors.Is(err, errIsDir) ||
		errors.Is(err, errNotEmpty) || errors.Is(err, errInvalid) ||
		errors.Is(err, errInvalidRename) ||
		errors.Is(err, syscall.ENODATA) || errors.Is(err, syscall.ENOSPC)
}

// BenignEnvlessOutcome reports whether a deterministic outcome of one
// ENVELOPE-LESS record is a benign idempotent-retry case that environment-
// free replay (cold replay AND HistoryCut materialization) may tolerate.
// It is the engine-side twin of the live authority's
// benignReplayErrorForRecord: everything else must fail replay closed,
// because correctness of the outcome would require environment facts the
// replayer does not have. In particular a CURRENT (server-stamped) write or
// truncate that cannot find its target could discard durable bytes; only
// pre-deterministic legacy records (TsMs == 0) keep that migration escape.
func BenignEnvlessOutcome(op wal.Op, tsMs int64, err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrNotExist) && (op == wal.OpWrite || op == wal.OpTruncate) {
		return tsMs == 0
	}
	if errors.Is(err, os.ErrExist) {
		// XATTR_CREATE is an idempotent ordered guard. EEXIST from create,
		// mkdir, or link is not: replay needs the original environment to
		// prove which object won.
		return op == wal.OpSetxattr
	}
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, syscall.ENAMETOOLONG) ||
		errors.Is(err, errNotEmpty) ||
		errors.Is(err, errIsDir) ||
		errors.Is(err, errNotDir) ||
		errors.Is(err, errInvalidRename) ||
		errors.Is(err, syscall.ENODATA) ||
		errors.Is(err, syscall.ENOSPC)
}

// InoAllocator issues inode ids for legacy records that carry none
// (Record.Ino/Inos zero). Live-captured PFJ3 records always carry preassigned
// identities, so the allocator only runs for legacy WAL/PFR1 replays; it must
// be deterministic for the stream (e.g. the branch namespace counter).
type InoAllocator func() (uint64, error)

// Engine folds ordered wal.Records into a Tx.
type Engine struct {
	tx    Tx
	alloc InoAllocator

	// fallbackTsMs stamps mutations whose record carries TsMs == 0 (legacy
	// records logged before server-side stamping). One fixed value keeps
	// reruns byte-identical.
	fallbackTsMs int64

	// maxInoSeen is the monotonic high-water over every inode id the engine
	// observed or allocated (deleted and orphaned included).
	maxInoSeen uint64

	// localSeen tracks, per composed inode namespace, the highest LOCAL
	// counter value observed in any logged identity — success, deterministic
	// failure, and unused reservation members included. The caller derives
	// the anchor's NextLocal from it, so a replayed/materialized allocator
	// can never re-issue a local the live authority already burned.
	localSeen map[uint32]uint64

	// orphans tracks the parked set (ino -> true) as the engine transitions
	// it. Seeded from the base orphan index by the caller via SeedOrphan.
	orphans map[uint64]bool

	// xattrs is the LIVE per-inode extended-attribute state (ino -> name ->
	// value). It rides the engine, not the Tx: xattrs are recovery-side live
	// state (persisted on the cut's RecoveryRoot, never in the user tree),
	// seeded from the base anchor via SeedXattr and folded by
	// OpSetxattr/OpRemovexattr. Values are private copies.
	xattrs map[uint64]map[string][]byte
}

// Config configures one engine over one transaction.
type Config struct {
	Tx           Tx
	Alloc        InoAllocator
	FallbackTsMs int64
	// BaseMaxInoSeen seeds the monotonic inode high-water (from the base
	// root's MaxInoSeen; 0 for an empty base).
	BaseMaxInoSeen uint64
}

// New creates an engine. The transaction must already contain the base state
// (including inode 1 for a non-empty base; the engine creates inode 1 on
// first use for an empty base).
func New(cfg Config) (*Engine, error) {
	if cfg.Tx == nil {
		return nil, fmt.Errorf("fstransition: config requires a transaction")
	}
	alloc := cfg.Alloc
	if alloc == nil {
		alloc = func() (uint64, error) {
			return 0, fmt.Errorf("fstransition: record carries no inode identity and no allocator is configured")
		}
	}
	return &Engine{
		tx:           cfg.Tx,
		alloc:        alloc,
		fallbackTsMs: cfg.FallbackTsMs,
		maxInoSeen:   cfg.BaseMaxInoSeen,
		localSeen:    map[uint32]uint64{},
		orphans:      map[uint64]bool{},
		xattrs:       map[uint64]map[string][]byte{},
	}, nil
}

// SetTx rebinds the engine to a new transaction. It exists for checkpointed
// folds: a long journal fold commits its pft2.Editor mid-stream (bounding
// per-transaction staged bytes), reopens a fresh editor on the JUST-committed
// root and orphan index, and swaps it in beneath the same engine.
//
// The swap is safe because the engine holds NO transaction-derived tree
// state: every inode, dirent, cell, and size read or write goes through e.tx
// at the operation that needs it (resolve/resolveParent/resolveForRW and the
// per-op mutations), and nothing fetched from a transaction is cached across
// operations. The engine's own maps — orphans, xattrs, localSeen, and the
// maxInoSeen watermark — are deliberately transaction-INDEPENDENT recovery-
// side state (xattrs live only here and anchor onto the cut's RecoveryRoot,
// never in the user tree), so they must survive the swap untouched; dropping
// or rebuilding the engine at a checkpoint would silently lose them. The
// caller must hand in a transaction whose base equals the committed final
// state of the previous one (root AND orphan index), or per-op reads would
// observe a different tree than the fold has built.
func (e *Engine) SetTx(tx Tx) {
	e.tx = tx
}

// SeedOrphan registers one parked orphan from the base recovery state so
// ino-addressed operations and reaps resolve it.
func (e *Engine) SeedOrphan(ino uint64) {
	e.orphans[ino] = true
	e.noteIno(ino)
}

// SeedXattr restores one extended attribute from the base recovery anchor
// (value copied). Single-threaded seeding before the fold, like SeedOrphan.
func (e *Engine) SeedXattr(ino uint64, name string, value []byte) {
	m := e.xattrs[ino]
	if m == nil {
		m = map[string][]byte{}
		e.xattrs[ino] = m
	}
	m[name] = append([]byte(nil), value...)
	e.noteIno(ino)
}

// Xattrs returns the live per-inode extended-attribute state after the
// applied prefix, sorted by (ino, name) — the exact rows the cut's
// RecoveryRoot anchors. Values are the engine's private copies.
func (e *Engine) Xattrs() []XattrRow {
	return e.sortedXattrs(false)
}

// UserXattrs returns the xattrs belonging to filesystem-homed inodes. Parked
// open-after-unlink orphans are intentionally excluded: their attributes are
// recovery state, not user-snapshot state. This is an O(number of xattrs)
// projection over transition-engine state and performs no tree or object
// store reads.
func (e *Engine) UserXattrs() []XattrRow {
	return e.sortedXattrs(true)
}

func (e *Engine) sortedXattrs(userOnly bool) []XattrRow {
	var out []XattrRow
	for ino, m := range e.xattrs {
		if userOnly && e.orphans[ino] {
			continue
		}
		for name, value := range m {
			out = append(out, XattrRow{Ino: ino, Name: name, Value: value})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ino != out[j].Ino {
			return out[i].Ino < out[j].Ino
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// XattrRow is one live (ino, name, value) extended-attribute fact.
type XattrRow struct {
	Ino   uint64
	Name  string
	Value []byte
}

// MaxInoSeen returns the monotonic inode high-water after the applied prefix.
func (e *Engine) MaxInoSeen() uint64 { return e.maxInoSeen }

// MaxLocalSeen returns the highest LOCAL counter observed inside one composed
// inode namespace (0 = none). Namespace 0 is the legacy flat space: the whole
// id is the local counter there.
func (e *Engine) MaxLocalSeen(namespace uint32) uint64 { return e.localSeen[namespace] }

// Orphans returns the sorted parked-orphan inode set.
func (e *Engine) Orphans() []uint64 {
	out := make([]uint64, 0, len(e.orphans))
	for ino := range e.orphans {
		out = append(out, ino)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (e *Engine) noteIno(ino uint64) {
	if ino == 0 {
		return
	}
	if ino > e.maxInoSeen {
		e.maxInoSeen = ino
	}
	namespace := uint32(ino >> 32)
	local := ino
	if namespace != 0 {
		local = ino & (1<<32 - 1)
	}
	if local > e.localSeen[namespace] {
		e.localSeen[namespace] = local
	}
}

// observeRecordIdentities notes EVERY identity the record logs — the single
// preassigned Ino and every member of the mkdir reservation Inos — BEFORE
// semantic application. The live authority burned these ids at reservation
// regardless of the apply outcome, so replay and materialization must
// observe them on success, deterministic failure, and unused-allocation
// alike; otherwise a later fresh allocation could reuse a logged identity.
func (e *Engine) observeRecordIdentities(r *wal.Record) {
	e.noteIno(r.Ino)
	for _, ino := range r.Inos {
		e.noteIno(ino)
	}
}

// Outcome is the applied result of one record.
type Outcome struct {
	Seq uint64
	// Err is nil or a deterministic semantic outcome (IsDeterministicOutcome).
	Err error
	// OrphanIno is the inode parked by a remove/orphan/rename-replace.
	OrphanIno uint64
	// Changed reports whether the tree changed.
	Changed bool
	// ResolvedOffset is the EOF chosen for an O_APPEND write.
	ResolvedOffset int64
}

// Apply folds one record (OpBatch folds its Mutations in order; nested
// batches are rejected). Control records are SKIPPED here — the caller owns
// control reduction (pfc2.State) exactly like the live pipeline.
func (e *Engine) Apply(ctx context.Context, r wal.Record) ([]Outcome, error) {
	if r.Op == wal.OpBatch {
		outcomes := make([]Outcome, 0, len(r.Mutations))
		for _, m := range r.Mutations {
			if m.Op == wal.OpBatch {
				return nil, fmt.Errorf("fstransition: nested batch at seq %d", r.Seq)
			}
			out, err := e.applyOne(ctx, m)
			if err != nil {
				return nil, err
			}
			outcomes = append(outcomes, out)
		}
		return outcomes, nil
	}
	out, err := e.applyOne(ctx, r)
	if err != nil {
		return nil, err
	}
	return []Outcome{out}, nil
}

func (e *Engine) applyOne(ctx context.Context, r wal.Record) (Outcome, error) {
	out := Outcome{Seq: r.Seq}
	if r.Op == wal.OpControl {
		return out, nil
	}
	e.observeRecordIdentities(&r)
	ts := r.TsMs
	if ts == 0 {
		ts = e.fallbackTsMs
	}
	var err error
	switch r.Op {
	case wal.OpCreate:
		out.Changed, err = e.create(ctx, r.Path, pft2.FileKindRegular, r.Mode&0o7777, "", r.Ino, r.Excl, ts)
	case wal.OpMkdir:
		if r.Excl {
			out.Changed, err = e.mkdirExact(ctx, r.Path, r.Mode&0o7777, r.Ino, ts)
		} else {
			out.Changed, err = e.mkdirAll(ctx, r.Path, r.Mode&0o7777, r.Inos, ts)
		}
	case wal.OpSymlink:
		out.Changed, err = e.create(ctx, r.Path, pft2.FileKindSymlink, 0o777, r.Target, r.Ino, r.Excl, ts)
	case wal.OpWrite:
		out.ResolvedOffset, out.Changed, err = e.write(ctx, r, ts)
	case wal.OpTruncate:
		out.Changed, err = e.truncate(ctx, r, ts)
	case wal.OpRemove, wal.OpOrphan:
		out.OrphanIno, out.Changed, err = e.orphan(ctx, r.Path, ts)
	case wal.OpRename:
		out.OrphanIno, out.Changed, err = e.rename(ctx, r.Path, r.NewPath, r.RenameNoReplace, ts)
	case wal.OpLink:
		out.Changed, err = e.link(ctx, r.Path, r.NewPath, r.Ino, ts)
	case wal.OpReap:
		out.Changed, err = e.reap(ctx, r.Ino)
	case wal.OpChmod:
		out.Changed, err = e.chmod(ctx, r, ts)
	case wal.OpChtimes:
		out.Changed, err = e.chtimes(ctx, r)
	case wal.OpChown:
		out.Changed, err = e.chown(ctx, r, ts)
	case wal.OpSetxattr:
		out.Changed, err = e.setxattr(ctx, r)
	case wal.OpRemovexattr:
		out.Changed, err = e.removexattr(ctx, r)
	default:
		return out, fmt.Errorf("fstransition: unknown wal op %d at seq %d", r.Op, r.Seq)
	}
	if err != nil {
		if IsDeterministicOutcome(err) {
			out.Err = err
			return out, nil
		}
		return out, err
	}
	return out, nil
}

// ─── path resolution ─────────────────────────────────────────────────────────

func cleanPath(p string) string {
	p = strings.Trim(p, "/")
	if p == "" || p == "." {
		return ""
	}
	parts := strings.Split(p, "/")
	kept := parts[:0]
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, "/")
}

func isInSubtree(ancestor, descendant string) bool {
	a, d := cleanPath(ancestor), cleanPath(descendant)
	return d == a || strings.HasPrefix(d, a+"/")
}

// EnsureRoot materializes inode 1 (the 0755 directory every fresh branch
// starts with) when the transaction would otherwise be empty — the shape of
// converting an EMPTY authored manifest, whose valid PFT2 image is the root
// directory alone. Deterministic: the caller supplies the timestamp
// (conversions pass 0 so identical inputs produce identical roots).
func (e *Engine) EnsureRoot(ctx context.Context, tsMs int64) error {
	_, err := e.ensureRoot(ctx, tsMs)
	return err
}

// ensureRoot creates inode 1 (mode 0755 directory) on first touch of an
// empty base, mirroring the fresh-branch root every live WorkFS starts with.
func (e *Engine) ensureRoot(ctx context.Context, tsMs int64) (pft2.Inode, error) {
	root, ok, err := e.tx.GetInode(ctx, pft2.RootIno)
	if err != nil {
		return pft2.Inode{}, err
	}
	if ok {
		e.noteIno(pft2.RootIno)
		return root, nil
	}
	root = pft2.Inode{
		Ino: pft2.RootIno, Kind: pft2.FileKindDirectory, Mode: 0o755, Nlink: 1,
		MtimeMs: tsMs, CtimeMs: tsMs, AtimeMs: tsMs,
	}
	if err := e.tx.PutInode(ctx, root); err != nil {
		return pft2.Inode{}, err
	}
	e.noteIno(pft2.RootIno)
	return root, nil
}

// resolve walks the named path from the root. Missing → ("", false).
func (e *Engine) resolve(ctx context.Context, path string, tsMs int64) (pft2.Inode, bool, error) {
	clean := cleanPath(path)
	cur, err := e.ensureRoot(ctx, tsMs)
	if err != nil {
		return pft2.Inode{}, false, err
	}
	if clean == "" {
		return cur, true, nil
	}
	for _, part := range strings.Split(clean, "/") {
		if cur.Kind != pft2.FileKindDirectory {
			return pft2.Inode{}, false, nil
		}
		entry, ok, err := e.tx.GetDirEntry(ctx, cur.Ino, part)
		if err != nil {
			return pft2.Inode{}, false, err
		}
		if !ok {
			return pft2.Inode{}, false, nil
		}
		child, ok, err := e.tx.GetInode(ctx, entry.Ino)
		if err != nil {
			return pft2.Inode{}, false, err
		}
		if !ok {
			return pft2.Inode{}, false, fmt.Errorf("fstransition: dirent %q names missing inode %d", part, entry.Ino)
		}
		cur = child
	}
	return cur, true, nil
}

type parentKind int

const (
	parentDir parentKind = iota
	parentMissing
	parentNotDir
)

// resolveParent resolves the parent directory of path and the leaf name.
func (e *Engine) resolveParent(ctx context.Context, path string, tsMs int64) (pft2.Inode, string, parentKind, error) {
	clean := cleanPath(path)
	if clean == "" {
		root, err := e.ensureRoot(ctx, tsMs)
		return root, "", parentDir, err
	}
	parts := strings.Split(clean, "/")
	cur, err := e.ensureRoot(ctx, tsMs)
	if err != nil {
		return pft2.Inode{}, "", parentMissing, err
	}
	for _, part := range parts[:len(parts)-1] {
		entry, ok, err := e.tx.GetDirEntry(ctx, cur.Ino, part)
		if err != nil {
			return pft2.Inode{}, "", parentMissing, err
		}
		if !ok {
			return pft2.Inode{}, "", parentMissing, nil
		}
		child, ok, err := e.tx.GetInode(ctx, entry.Ino)
		if err != nil {
			return pft2.Inode{}, "", parentMissing, err
		}
		if !ok {
			return pft2.Inode{}, "", parentMissing, fmt.Errorf("fstransition: dirent %q names missing inode %d", part, entry.Ino)
		}
		if child.Kind != pft2.FileKindDirectory {
			return pft2.Inode{}, "", parentNotDir, nil
		}
		cur = child
	}
	return cur, parts[len(parts)-1], parentDir, nil
}

// resolveForRW mirrors the live authority: a nonzero ino resolves STRICTLY by
// ino (named or parked orphan, never a name fallback); zero resolves by path.
// Returns the inode, whether it is a parked orphan, and presence.
func (e *Engine) resolveForRW(ctx context.Context, path string, ino uint64, tsMs int64) (pft2.Inode, bool, bool, error) {
	if ino != 0 {
		inode, ok, err := e.tx.GetInode(ctx, ino)
		if err != nil {
			return pft2.Inode{}, false, false, err
		}
		if ok {
			return inode, false, true, nil
		}
		inode, ok, err = e.tx.GetOrphanInode(ctx, ino)
		if err != nil {
			return pft2.Inode{}, false, false, err
		}
		if ok {
			return inode, true, true, nil
		}
		return pft2.Inode{}, false, false, nil
	}
	inode, ok, err := e.resolve(ctx, path, tsMs)
	return inode, false, ok, err
}

func (e *Engine) putResolved(ctx context.Context, inode pft2.Inode, orphaned bool) error {
	if orphaned {
		return e.tx.PutOrphanInode(ctx, inode)
	}
	return e.tx.PutInode(ctx, inode)
}

// ResolveIno reports the inode identity a record's target resolves to AFTER
// its apply, with exactly the live authority's resolveForRW semantics: a
// nonzero logged ino resolves strictly by ino (named or parked, NEVER a path
// fallback; a miss is 0), a zero ino resolves by path. The exact-outcome
// serialization stores this identity, so a materialized outcome carries the
// same Ino byte the live reply and cold replay stored.
func (e *Engine) ResolveIno(ctx context.Context, path string, ino uint64) (uint64, error) {
	inode, _, ok, err := e.resolveForRW(ctx, path, ino, e.fallbackTsMs)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, nil
	}
	return inode.Ino, nil
}

func (e *Engine) bumpDirTimes(ctx context.Context, dir pft2.Inode, tsMs int64) error {
	dir.MtimeMs = tsMs
	dir.CtimeMs = tsMs
	return e.tx.PutInode(ctx, dir)
}

func (e *Engine) useOrAllocIno(ino uint64) (uint64, error) {
	if ino == 0 {
		allocated, err := e.alloc()
		if err != nil {
			return 0, err
		}
		if allocated == 0 {
			return 0, fmt.Errorf("fstransition: allocator returned inode 0")
		}
		ino = allocated
	}
	e.noteIno(ino)
	return ino, nil
}

// ─── mutations ───────────────────────────────────────────────────────────────

func (e *Engine) create(ctx context.Context, path string, kind pft2.FileKind, mode uint32, target string, ino uint64, excl bool, tsMs int64) (bool, error) {
	parent, base, pk, err := e.resolveParent(ctx, path, tsMs)
	if err != nil {
		return false, err
	}
	if pk != parentDir || base == "" {
		return false, ErrNotExist
	}
	if _, ok, err := e.tx.GetDirEntry(ctx, parent.Ino, base); err != nil {
		return false, err
	} else if ok {
		if excl {
			// requireAbsent (O_EXCL create / POSIX symlink): deterministic
			// EEXIST at this record's ordered position.
			return false, ErrExist
		}
		// Idempotent create never clobbers an existing entry of ANY kind.
		return false, nil
	}
	newIno, err := e.useOrAllocIno(ino)
	if err != nil {
		return false, err
	}
	inode := pft2.Inode{
		Ino: newIno, Kind: kind, Mode: mode, Nlink: 1,
		MtimeMs: tsMs, CtimeMs: tsMs, AtimeMs: tsMs,
	}
	if kind == pft2.FileKindSymlink {
		inode.SymlinkTarget = target
		inode.Size = uint64(len(target))
	}
	if err := e.tx.PutInode(ctx, inode); err != nil {
		return false, err
	}
	if err := e.tx.PutDirEntry(ctx, parent.Ino, pft2.DirEntry{Name: base, Ino: newIno, Kind: kind}); err != nil {
		return false, err
	}
	return true, e.bumpDirTimes(ctx, parent, tsMs)
}

func (e *Engine) mkdirExact(ctx context.Context, path string, mode uint32, ino uint64, tsMs int64) (bool, error) {
	clean := cleanPath(path)
	if clean == "" {
		return false, ErrExist // mkdir of the root: it exists by definition
	}
	parent, base, pk, err := e.resolveParent(ctx, path, tsMs)
	if err != nil {
		return false, err
	}
	if pk == parentNotDir {
		return false, errNotDir
	}
	if pk == parentMissing {
		return false, ErrNotExist
	}
	if _, ok, err := e.tx.GetDirEntry(ctx, parent.Ino, base); err != nil {
		return false, err
	} else if ok {
		return false, ErrExist
	}
	newIno, err := e.useOrAllocIno(ino)
	if err != nil {
		return false, err
	}
	child := pft2.Inode{
		Ino: newIno, Kind: pft2.FileKindDirectory, Mode: mode, Nlink: 1,
		MtimeMs: tsMs, CtimeMs: tsMs, AtimeMs: tsMs,
	}
	if err := e.tx.PutInode(ctx, child); err != nil {
		return false, err
	}
	if err := e.tx.PutDirEntry(ctx, parent.Ino, pft2.DirEntry{Name: base, Ino: newIno, Kind: pft2.FileKindDirectory}); err != nil {
		return false, err
	}
	return true, e.bumpDirTimes(ctx, parent, tsMs)
}

func (e *Engine) mkdirAll(ctx context.Context, path string, mode uint32, inos []uint64, tsMs int64) (bool, error) {
	clean := cleanPath(path)
	if clean == "" {
		return false, nil
	}
	parts := strings.Split(clean, "/")
	if len(inos) != 0 && len(inos) != len(parts) {
		return false, fmt.Errorf("fstransition: mkdir inode reservation count %d, want %d", len(inos), len(parts))
	}
	// Preflight every existing prefix before mutating so a non-directory
	// cannot leave a partially-created intent.
	cur, err := e.ensureRoot(ctx, tsMs)
	if err != nil {
		return false, err
	}
	firstMissing := len(parts)
	walk := cur
	for i, part := range parts {
		entry, ok, err := e.tx.GetDirEntry(ctx, walk.Ino, part)
		if err != nil {
			return false, err
		}
		if !ok {
			firstMissing = i
			break
		}
		child, ok, err := e.tx.GetInode(ctx, entry.Ino)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, fmt.Errorf("fstransition: dirent %q names missing inode %d", part, entry.Ino)
		}
		if child.Kind != pft2.FileKindDirectory {
			return false, errNotDir
		}
		walk = child
	}
	if firstMissing == len(parts) {
		return false, nil
	}
	for i := firstMissing; i < len(parts); i++ {
		var reserved uint64
		if len(inos) != 0 {
			reserved = inos[i]
		}
		newIno, err := e.useOrAllocIno(reserved)
		if err != nil {
			return false, err
		}
		child := pft2.Inode{
			Ino: newIno, Kind: pft2.FileKindDirectory, Mode: mode, Nlink: 1,
			MtimeMs: tsMs, CtimeMs: tsMs, AtimeMs: tsMs,
		}
		if err := e.tx.PutInode(ctx, child); err != nil {
			return false, err
		}
		if err := e.tx.PutDirEntry(ctx, walk.Ino, pft2.DirEntry{Name: parts[i], Ino: newIno, Kind: pft2.FileKindDirectory}); err != nil {
			return false, err
		}
		if err := e.bumpDirTimes(ctx, walk, tsMs); err != nil {
			return false, err
		}
		walk = child
	}
	return true, nil
}

// Link adds one additional name for an existing non-directory inode (hardlink
// semantics: nlink increments; content and metadata are shared). No wal op
// carries links yet — the legacy conversion importer and the v3 hardlink lane
// drive this transition directly.
func (e *Engine) Link(ctx context.Context, parentPath, name string, ino uint64, tsMs int64) error {
	target, ok, err := e.tx.GetInode(ctx, ino)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotExist
	}
	if target.Kind == pft2.FileKindDirectory {
		return errIsDir
	}
	dir, ok, err := e.resolve(ctx, parentPath, tsMs)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotExist
	}
	if dir.Kind != pft2.FileKindDirectory {
		return errNotDir
	}
	if _, exists, err := e.tx.GetDirEntry(ctx, dir.Ino, name); err != nil {
		return err
	} else if exists {
		return ErrExist
	}
	target.Nlink++
	target.CtimeMs = tsMs
	if err := e.tx.PutInode(ctx, target); err != nil {
		return err
	}
	if err := e.tx.PutDirEntry(ctx, dir.Ino, pft2.DirEntry{Name: name, Ino: ino, Kind: target.Kind}); err != nil {
		return err
	}
	return e.bumpDirTimes(ctx, dir, tsMs)
}

// orphan detaches the named entry. A last-name non-directory (nlink reaching
// 0) or an empty directory PARKS in the orphan index (open-after-unlink);
// an aliased inode just loses one name.
func (e *Engine) orphan(ctx context.Context, path string, tsMs int64) (uint64, bool, error) {
	parent, base, pk, err := e.resolveParent(ctx, path, tsMs)
	if err != nil {
		return 0, false, err
	}
	if pk != parentDir || base == "" {
		return 0, false, ErrNotExist
	}
	entry, ok, err := e.tx.GetDirEntry(ctx, parent.Ino, base)
	if err != nil {
		return 0, false, err
	}
	if !ok {
		return 0, false, ErrNotExist
	}
	child, ok, err := e.tx.GetInode(ctx, entry.Ino)
	if err != nil {
		return 0, false, err
	}
	if !ok {
		return 0, false, fmt.Errorf("fstransition: dirent %q names missing inode %d", base, entry.Ino)
	}
	if child.Kind == pft2.FileKindDirectory {
		empty, err := e.directoryEmpty(ctx, child)
		if err != nil {
			return 0, false, err
		}
		if !empty {
			return 0, false, errNotEmpty
		}
	}
	if err := e.tx.DeleteDirEntry(ctx, parent.Ino, base); err != nil {
		return 0, false, err
	}
	if err := e.bumpDirTimes(ctx, parent, tsMs); err != nil {
		return 0, false, err
	}
	if child.Nlink > 1 {
		// An aliased inode just loses one name (times untouched: the live
		// authority's remove path is the semantic reference).
		child.Nlink--
		return 0, true, e.tx.PutInode(ctx, child)
	}
	// Every successful last-name unlink parks the detached inode; OpReap is
	// the sole destruction transition (deterministic on every replica). A
	// parked inode keeps nlink 1 in the PFT2 representation: the orphan-index
	// membership is its one remaining reference (the format requires >= 1).
	child.Nlink = 1
	if err := e.tx.PutOrphanInode(ctx, child); err != nil {
		return 0, false, err
	}
	e.orphans[child.Ino] = true
	return child.Ino, true, nil
}

// link adds a hard link newPath referencing the same inode as the existing
// non-directory source (resolved by its logged ino when present, else by
// srcPath). Mirrors the live authority's applyLink: EEXIST if the
// destination exists, EPERM for a directory source, ENOENT for a missing
// source or destination parent. Increments the shared nlink.
func (e *Engine) link(ctx context.Context, srcPath, newPath string, srcIno uint64, tsMs int64) (bool, error) {
	var src pft2.Inode
	var ok bool
	var err error
	if srcIno != 0 {
		src, ok, err = e.tx.GetInode(ctx, srcIno)
	} else {
		src, ok, err = e.resolve(ctx, srcPath, tsMs)
	}
	if err != nil {
		return false, err
	}
	if !ok {
		return false, ErrNotExist
	}
	if src.Kind == pft2.FileKindDirectory {
		return false, os.ErrPermission // no hard links to directories
	}
	parent, base, pk, err := e.resolveParent(ctx, newPath, tsMs)
	if err != nil {
		return false, err
	}
	if pk == parentNotDir {
		return false, errNotDir
	}
	if pk != parentDir || base == "" {
		return false, ErrNotExist
	}
	if _, exists, err := e.tx.GetDirEntry(ctx, parent.Ino, base); err != nil {
		return false, err
	} else if exists {
		return false, ErrExist
	}
	if src.Nlink == 0 {
		src.Nlink = 1
	}
	src.Nlink++
	src.CtimeMs = tsMs
	if err := e.tx.PutInode(ctx, src); err != nil {
		return false, err
	}
	if err := e.tx.PutDirEntry(ctx, parent.Ino, pft2.DirEntry{Name: base, Ino: src.Ino, Kind: src.Kind}); err != nil {
		return false, err
	}
	e.noteIno(src.Ino)
	return true, e.bumpDirTimes(ctx, parent, tsMs)
}

func (e *Engine) directoryEmpty(ctx context.Context, dir pft2.Inode) (bool, error) {
	count, err := e.tx.DirEntryCount(ctx, dir.Ino)
	if err != nil {
		return false, err
	}
	return count == 0, nil
}

func (e *Engine) rename(ctx context.Context, oldPath, newPath string, noReplace bool, tsMs int64) (uint64, bool, error) {
	oldParent, oldBase, opk, err := e.resolveParent(ctx, oldPath, tsMs)
	if err != nil {
		return 0, false, err
	}
	if opk != parentDir || oldBase == "" {
		return 0, false, ErrNotExist
	}
	oldEntry, ok, err := e.tx.GetDirEntry(ctx, oldParent.Ino, oldBase)
	if err != nil {
		return 0, false, err
	}
	if !ok {
		return 0, false, ErrNotExist
	}
	node, ok, err := e.tx.GetInode(ctx, oldEntry.Ino)
	if err != nil {
		return 0, false, err
	}
	if !ok {
		return 0, false, fmt.Errorf("fstransition: dirent %q names missing inode %d", oldBase, oldEntry.Ino)
	}
	newParent, newBase, npk, err := e.resolveParent(ctx, newPath, tsMs)
	if err != nil {
		return 0, false, err
	}
	if npk != parentDir || newBase == "" {
		return 0, false, ErrNotExist
	}
	existingEntry, existingOk, err := e.tx.GetDirEntry(ctx, newParent.Ino, newBase)
	if err != nil {
		return 0, false, err
	}
	var existing *pft2.Inode
	if existingOk {
		if noReplace {
			// RENAME_NOREPLACE: even a rename onto itself is EEXIST.
			return 0, false, ErrExist
		}
		if existingEntry.Ino == oldEntry.Ino {
			return 0, false, nil // renaming a path onto itself is a no-op
		}
		found := pft2.Inode{}
		ok := false
		found, ok, err = e.tx.GetInode(ctx, existingEntry.Ino)
		if err != nil {
			return 0, false, err
		}
		if !ok {
			return 0, false, fmt.Errorf("fstransition: dirent %q names missing inode %d", newBase, existingEntry.Ino)
		}
		switch {
		case node.Kind == pft2.FileKindDirectory && found.Kind != pft2.FileKindDirectory:
			return 0, false, errNotDir
		case node.Kind != pft2.FileKindDirectory && found.Kind == pft2.FileKindDirectory:
			return 0, false, errIsDir
		case found.Kind == pft2.FileKindDirectory:
			empty, err := e.directoryEmpty(ctx, found)
			if err != nil {
				return 0, false, err
			}
			if !empty {
				return 0, false, errNotEmpty
			}
		}
		existing = &found
	}
	if node.Kind == pft2.FileKindDirectory && isInSubtree(oldPath, newPath) {
		return 0, false, errInvalidRename
	}
	// A replaced destination is always parked before the source is linked —
	// the same deterministic detach policy as remove. Aliased destinations
	// lose one name instead.
	var orphanIno uint64
	if existing != nil {
		if err := e.tx.DeleteDirEntry(ctx, newParent.Ino, newBase); err != nil {
			return 0, false, err
		}
		if existing.Nlink > 1 {
			existing.Nlink--
			if err := e.tx.PutInode(ctx, *existing); err != nil {
				return 0, false, err
			}
		} else {
			existing.Nlink = 1 // orphan-index membership is the one reference
			if err := e.tx.PutOrphanInode(ctx, *existing); err != nil {
				return 0, false, err
			}
			e.orphans[existing.Ino] = true
			orphanIno = existing.Ino
		}
	}
	if err := e.tx.DeleteDirEntry(ctx, oldParent.Ino, oldBase); err != nil {
		return 0, false, err
	}
	if err := e.tx.PutDirEntry(ctx, newParent.Ino, pft2.DirEntry{Name: newBase, Ino: oldEntry.Ino, Kind: oldEntry.Kind}); err != nil {
		return 0, false, err
	}
	if err := e.bumpDirTimes(ctx, oldParent, tsMs); err != nil {
		return 0, false, err
	}
	if newParent.Ino != oldParent.Ino {
		// Re-read: the old-parent bump may have staged newer metadata for an
		// ancestor chain; the new parent is a distinct inode so this is safe.
		refreshed, ok, err := e.tx.GetInode(ctx, newParent.Ino)
		if err != nil {
			return 0, false, err
		}
		if !ok {
			return 0, false, fmt.Errorf("fstransition: rename new parent %d vanished", newParent.Ino)
		}
		if err := e.bumpDirTimes(ctx, refreshed, tsMs); err != nil {
			return 0, false, err
		}
	}
	return orphanIno, true, nil
}

// reap drops a parked orphan after an explicit durable decision. Idempotent:
// reaping an already-gone ino is a no-op. Reap is the sole inode destruction
// transition, so it is also the sole xattr cleanup point.
func (e *Engine) reap(ctx context.Context, ino uint64) (bool, error) {
	_, ok, err := e.tx.GetOrphanInode(ctx, ino)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	if err := e.tx.DeleteOrphanInode(ctx, ino); err != nil {
		return false, err
	}
	delete(e.orphans, ino)
	delete(e.xattrs, ino)
	return true, nil
}

// ─── extended attributes ─────────────────────────────────────────────────────

// XattrSetTotal is the deterministic per-inode total after setting (name ->
// value) into existing: the sum of every name+value byte, with an existing
// same-name entry replaced. Shared with the live authority so the ENOSPC
// bound decision is byte-identical everywhere.
func XattrSetTotal(existing map[string][]byte, name string, value []byte) int {
	total := len(name) + len(value)
	for n, v := range existing {
		if n == name {
			continue
		}
		total += len(n) + len(v)
	}
	return total
}

// setxattr applies one OpSetxattr on the inode resolved by Ino-else-Path
// (named or parked orphan). With no flag it creates or overwrites; XattrCreate
// and XattrReplace evaluate their existence precondition atomically at this
// ordered transition. Timestamps are untouched (matching the live authority's
// chmod discipline). A durable record with out-of-bound name/value is
// corruption (admission and the PFR1 codec both refuse it), reported as the
// deterministic errInvalid.
func (e *Engine) setxattr(ctx context.Context, r wal.Record) (bool, error) {
	if len(r.XattrName) == 0 || len(r.XattrName) > wal.MaxXattrNameBytes || len(r.Data) > wal.MaxXattrValueBytes {
		return false, errInvalid
	}
	n, _, ok, err := e.resolveForRW(ctx, r.Path, r.Ino, e.fallbackTsMs)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, ErrNotExist
	}
	_, exists := e.xattrs[n.Ino][r.XattrName]
	if r.XattrFlags&wal.XattrCreate != 0 && exists {
		return false, ErrExist
	}
	if r.XattrFlags&wal.XattrReplace != 0 && !exists {
		return false, errNoXattr
	}
	if XattrSetTotal(e.xattrs[n.Ino], r.XattrName, r.Data) > wal.MaxXattrTotalBytes {
		return false, errXattrNoSpace
	}
	m := e.xattrs[n.Ino]
	if m == nil {
		m = map[string][]byte{}
		e.xattrs[n.Ino] = m
	}
	m[r.XattrName] = append([]byte(nil), r.Data...)
	return true, nil
}

// removexattr applies one OpRemovexattr: a missing name is a deterministic
// ENODATA outcome at the record's ordered position (Linux removexattr
// semantics — never a silent no-op).
func (e *Engine) removexattr(ctx context.Context, r wal.Record) (bool, error) {
	if len(r.XattrName) == 0 || len(r.XattrName) > wal.MaxXattrNameBytes {
		return false, errInvalid
	}
	n, _, ok, err := e.resolveForRW(ctx, r.Path, r.Ino, e.fallbackTsMs)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, ErrNotExist
	}
	m := e.xattrs[n.Ino]
	if _, present := m[r.XattrName]; !present {
		return false, errNoXattr
	}
	delete(m, r.XattrName)
	if len(m) == 0 {
		delete(e.xattrs, n.Ino)
	}
	return true, nil
}

func (e *Engine) write(ctx context.Context, r wal.Record, tsMs int64) (int64, bool, error) {
	n, orphaned, ok, err := e.resolveForRW(ctx, r.Path, r.Ino, tsMs)
	if err != nil {
		return 0, false, err
	}
	if !ok || n.Kind != pft2.FileKindRegular {
		return 0, false, ErrNotExist
	}
	off := r.Offset
	if r.Append {
		// O_APPEND: EOF is resolved HERE, at this record's ordered position.
		off = int64(n.Size)
	}
	if off < 0 || off > int64(pft2.MaxLogicalFileBytes) ||
		int64(len(r.Data)) > int64(pft2.MaxLogicalFileBytes)-off {
		// The target RESOLVED: report the resolved offset with the
		// deterministic failure, exactly like the live authority's stored
		// outcome (it resolves the offset before the bounds check).
		return off, false, errInvalid
	}
	if len(r.Data) == 0 {
		n.MtimeMs = tsMs
		return off, true, e.putResolved(ctx, n, orphaned)
	}
	if err := e.writeRange(ctx, n.Ino, uint64(off), r.Data); err != nil {
		return 0, false, err
	}
	end := uint64(off) + uint64(len(r.Data))
	if end > n.Size {
		if err := e.tx.SetFileSize(ctx, n.Ino, end); err != nil {
			return 0, false, err
		}
		n.Size = end
	}
	n.MtimeMs = tsMs
	return off, true, e.putResolved(ctx, n, orphaned)
}

// writeRange folds an arbitrary byte range into CellBytes-aligned cell
// writes, read-modify-writing the partial edge cells.
func (e *Engine) writeRange(ctx context.Context, ino uint64, off uint64, data []byte) error {
	remaining := data
	pos := off
	for len(remaining) > 0 {
		cellStart := pos - (pos % pft2.CellBytes)
		inCell := int(pos - cellStart)
		n := pft2.CellBytes - inCell
		if n > len(remaining) {
			n = len(remaining)
		}
		var cell []byte
		if inCell == 0 && n == pft2.CellBytes {
			cell = remaining[:pft2.CellBytes]
		} else {
			merged, err := e.tx.ReadCell(ctx, ino, cellStart)
			if err != nil {
				return err
			}
			buf := make([]byte, pft2.CellBytes)
			copy(buf, merged)
			copy(buf[inCell:], remaining[:n])
			cell = buf
		}
		if err := e.tx.WriteCell(ctx, ino, cellStart, cell); err != nil {
			return err
		}
		pos += uint64(n)
		remaining = remaining[n:]
	}
	return nil
}

func (e *Engine) truncate(ctx context.Context, r wal.Record, tsMs int64) (bool, error) {
	n, orphaned, ok, err := e.resolveForRW(ctx, r.Path, r.Ino, tsMs)
	if err != nil {
		return false, err
	}
	if !ok || n.Kind != pft2.FileKindRegular {
		return false, ErrNotExist
	}
	if r.Size < 0 {
		return false, errInvalid
	}
	if err := e.tx.SetFileSize(ctx, n.Ino, uint64(r.Size)); err != nil {
		return false, err
	}
	n.Size = uint64(r.Size)
	n.MtimeMs = tsMs
	return true, e.putResolved(ctx, n, orphaned)
}

func (e *Engine) chmod(ctx context.Context, r wal.Record, tsMs int64) (bool, error) {
	n, orphaned, ok, err := e.resolveForRW(ctx, r.Path, r.Ino, tsMs)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, ErrNotExist
	}
	// Mode only — the live authority's chmod touches no timestamps.
	n.Mode = r.Mode & 0o7777
	return true, e.putResolved(ctx, n, orphaned)
}

func (e *Engine) chtimes(ctx context.Context, r wal.Record) (bool, error) {
	n, orphaned, ok, err := e.resolveForRW(ctx, r.Path, r.Ino, e.fallbackTsMs)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, ErrNotExist
	}
	if r.ChtimesSetAtime {
		n.AtimeMs = r.AtimeMs
	}
	if !r.ChtimesKeepMtime {
		n.MtimeMs = r.MtimeMs
	}
	return true, e.putResolved(ctx, n, orphaned)
}

func (e *Engine) chown(ctx context.Context, r wal.Record, tsMs int64) (bool, error) {
	n, orphaned, ok, err := e.resolveForRW(ctx, r.Path, r.Ino, tsMs)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, ErrNotExist
	}
	// Intent-carrying chown: only the flagged field changes, resolved at this
	// record's ordered position. A legacy record (neither flag) is absolute.
	if r.ChownSetUID || r.ChownSetGID {
		if r.ChownSetUID {
			n.UID = r.UID
		}
		if r.ChownSetGID {
			n.GID = r.GID
		}
	} else {
		n.UID = r.UID
		n.GID = r.GID
	}
	return true, e.putResolved(ctx, n, orphaned)
}
