package workfs

// Lazy PFT2 base namespace hydration.
//
// A managed authority cold-started from an adopted PFT2 base
// (NewManagedFromPft2) does NOT materialize the base namespace up front.
// Instead every directory inode that may still hold unmaterialized base
// dirents carries a dirBase binding, and names are hydrated on demand:
//
//   - The live tree (children maps) plus per-directory tombstones OVERRIDE
//     the immutable base: a name present in children is live truth, a
//     tombstoned name is deterministically absent (the journal deleted,
//     replaced, or renamed it away), and only a name that is NEITHER may be
//     resolved against the base. Base content can therefore never resurrect
//     a journal-deleted entry, regardless of hydration timing.
//   - All PFT2 fetches happen OUTSIDE fs.mu. A hydration installs its result
//     under a short fs.mu hold and only when the name is still undecided, so
//     a concurrent mutation always wins and concurrent hydrations of the
//     same name converge on one canonical inode.
//   - Inode identity is canonical by construction: every install consults
//     fs.byIno first, so hard-link aliases discovered in any order share ONE
//     *inode record, exactly like the eager loader.
//   - Because the base is immutable, the live tree truth at any journal
//     position is a pure function of (base, journal prefix) independent of
//     WHEN names were hydrated. The only obligation is that no apply makes a
//     decision about a name that is still undecided; hydrateIntentTargets
//     enforces that before every locked apply (and cold-start replay does
//     the same per entry), so live apply and replay decide identically.
//
// Nothing here changes durability or snapshot semantics: PFJ3 rows remain
// the sole visibility/durability boundary and the PFT2 base remains an
// immutable overlay source. Checkpoint-style whole-tree captures go through
// an explicit complete-materialization boundary (MaterializeBaseNamespace).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// pft2LoadDirPageSize bounds one ReadDir page during directory enumeration.
const pft2LoadDirPageSize = 512

// maxReadHydrateAttempts bounds one read operation's hydrate-retry loop.
// Each attempt either finishes the walk or decides at least one new path
// component, so the bound must exceed any real path depth (PATH_MAX-scale);
// re-looping beyond it requires pathological concurrent namespace churn
// (renames constantly moving pending directories into the path), in which
// case we fail the single read rather than spin.
const maxReadHydrateAttempts = 4096

// errBaseHydration classifies a lazy-base read that could not converge or
// fetch. It is returned to the failing caller only; no hydration state is
// poisoned and a retry is safe.
var errBaseHydration = errors.New("vcs: lazy pft2 base hydration failed")

// pft2Lazy is the FS-wide handle to a lazily hydrated PFT2 base. reader,
// fetcher, and the verified pack cache are safe for concurrent use; loads
// coalesces concurrent enumerations of the same directory.
type pft2Lazy struct {
	reader  *pft2.TreeReader
	fetcher pft2.Fetcher
	// packs is the shared bounded verified immutable pack cache every file
	// Ranger (and therefore the partial-write warm path) reads through.
	packs *pft2PackCache

	mu    sync.Mutex
	loads map[*inode]*dirLoadFlight
}

// dirBase is one directory inode's immutable-base binding. It exists only
// while the directory may still hold unmaterialized base dirents; a
// completed enumeration drops the whole binding (children then carry the
// full live truth and the base is never consulted again for this
// directory). All fields except ref are guarded by fs.mu; ref is immutable.
type dirBase struct {
	lz  *pft2Lazy
	ref pft2.Ref // this directory's INODE object reference

	// tombstones are base names the journal deleted, replaced, or renamed
	// away while the directory was still pending. A tombstoned name is
	// deterministically absent no matter what the base holds; entries are
	// only ever added (the map is freed with the whole binding when the
	// directory completes). Rolled-back applies never leak tombstones:
	// every mutationTransaction rollback path fences (poisons) the
	// authority, so no later operation can observe the leftover mark.
	tombstones map[string]struct{}
}

func (b *dirBase) tombstoned(name string) bool {
	if b == nil || b.tombstones == nil {
		return false
	}
	_, dead := b.tombstones[name]
	return dead
}

// tombstoneBaseName records that a live mutation removed name from parent
// while parent's base was still pending. Caller holds fs.mu (apply path).
func tombstoneBaseName(parent *inode, name string) {
	if parent == nil || parent.base == nil {
		return
	}
	if parent.base.tombstones == nil {
		parent.base.tombstones = map[string]struct{}{}
	}
	parent.base.tombstones[name] = struct{}{}
}

// dirLoadFlight coalesces concurrent enumerations of one directory.
type dirLoadFlight struct {
	mode dirLoadMode
	done chan struct{}
	err  error
}

type dirLoadMode uint8

const (
	// loadDirComplete enumerates every base page; on success the directory
	// is complete (dirBase dropped).
	loadDirComplete dirLoadMode = iota
	// loadDirEmptiness stops as soon as the directory is provably
	// non-empty; an exhausted enumeration still completes the directory
	// (it is provably empty of base entries).
	loadDirEmptiness
)

// baseVerdicts is one operation's local absent-knowledge: names and inos a
// hydration confirmed absent in the immutable base. Verdicts are keyed by
// directory identity (pointer), so a rename that substitutes a different
// directory at the same path invalidates them naturally. They are never
// shared across operations and never stored on the tree, which keeps
// negative knowledge from pure lookups unbounded-growth-free.
type baseVerdicts struct {
	names map[*inode]map[string]struct{}
	inos  map[uint64]struct{}
}

func newBaseVerdicts() *baseVerdicts {
	return &baseVerdicts{names: map[*inode]map[string]struct{}{}, inos: map[uint64]struct{}{}}
}

func (v *baseVerdicts) nameAbsent(dir *inode, name string) bool {
	_, absent := v.names[dir][name]
	return absent
}

func (v *baseVerdicts) markNameAbsent(dir *inode, name string) {
	m := v.names[dir]
	if m == nil {
		m = map[string]struct{}{}
		v.names[dir] = m
	}
	m[name] = struct{}{}
}

func (v *baseVerdicts) inoAbsent(ino uint64) bool {
	_, absent := v.inos[ino]
	return absent
}

func (v *baseVerdicts) markInoAbsent(ino uint64) { v.inos[ino] = struct{}{} }

// baseMiss reports the first undecided name a locked walk hit: dir is the
// pending directory, ref its immutable base reference (sampled under the
// lock), name the undecided component.
type baseMiss struct {
	dir  *inode
	ref  pft2.Ref
	name string
}

// resolveLazyLocked resolves name against the live tree, reporting the
// first undecided base name instead of guessing. Caller holds fs.mu (read
// or write). Returns (node, nil) on a decided hit, (nil, nil) on a decided
// miss (absent, tombstoned, verdict-absent, or a non-directory component),
// and (nil, miss) when a component is undecided and must hydrate first.
func (fs *FS) resolveLazyLocked(name string, verdicts *baseVerdicts) (*inode, *baseMiss) {
	clean := cleanPath(name)
	if clean == "" {
		return fs.root, nil
	}
	cur := fs.root
	for _, part := range strings.Split(clean, "/") {
		if cur.kind != "directory" {
			return nil, nil
		}
		if next, ok := cur.children[part]; ok {
			cur = next
			continue
		}
		b := cur.base
		if b == nil || b.tombstoned(part) {
			return nil, nil
		}
		if verdicts != nil && verdicts.nameAbsent(cur, part) {
			return nil, nil
		}
		return nil, &baseMiss{dir: cur, ref: b.ref, name: part}
	}
	return cur, nil
}

// newInodeFromView builds a live inode for one verified base inode view:
// lazy file content through the extent-walking Ranger, symlink targets
// inline, and directories bound to their own lazy dirBase.
func (lz *pft2Lazy) newInodeFromView(view pft2.InodeView) *inode {
	n := inodeFromPft2(view.Inode, lz, view.Ref)
	if view.Inode.Kind == pft2.FileKindDirectory {
		n.base = &dirBase{lz: lz, ref: view.Ref}
	}
	return n
}

// installDirentLocked installs one fetched base dirent if (and only if) the
// name is still undecided, converging with concurrent mutations and
// hydrations. Caller holds fs.mu for WRITE. Returns the live node for the
// name (nil = decided absent) — which may differ from the fetched view when
// a live decision won.
func (lz *pft2Lazy) installDirentLocked(fs *FS, dir *inode, entry pft2.DirEntry, view pft2.InodeView) (*inode, error) {
	if existing, ok := dir.children[entry.Name]; ok {
		return existing, nil // live truth (a mutation or another hydration) wins
	}
	if dir.base == nil || dir.base.tombstoned(entry.Name) {
		// Completed directory: children is the whole truth. Tombstoned: the
		// journal removed this name; never resurrect it.
		return nil, nil
	}
	if entry.Ino != view.Inode.Ino || entry.Kind != view.Inode.Kind {
		return nil, fmt.Errorf("%w: dirent %q advertises ino %d kind %v, inode object carries %d %v",
			pft2.ErrCorrupt, entry.Name, entry.Ino, entry.Kind, view.Inode.Ino, view.Inode.Kind)
	}
	node := fs.byIno[entry.Ino]
	if node == nil {
		if _, dead := fs.deadBaseInos[entry.Ino]; dead {
			// The journal reaped this base inode; a base dirent that still
			// references it can only be a base/journal mismatch.
			return nil, fmt.Errorf("%w: base dirent %q references reaped inode %d", pft2.ErrCorrupt, entry.Name, entry.Ino)
		}
		node = lz.newInodeFromView(view)
		fs.byIno[entry.Ino] = node
		fs.alloc.observe(entry.Ino)
	} else {
		// Hard-link alias (or an inode hydrated by handle first): the base
		// dirent must reference the SAME canonical record. A parked orphan
		// cannot legally still be named by an undecided base dirent — every
		// path to parking tombstones the names it consumed.
		if fs.orphans[entry.Ino] == node {
			return nil, fmt.Errorf("%w: base dirent %q references parked inode %d", pft2.ErrCorrupt, entry.Name, entry.Ino)
		}
		if node.kind != view.Inode.Kind.String() {
			return nil, fmt.Errorf("%w: base dirent %q kind %v does not match live inode %d kind %s",
				pft2.ErrCorrupt, entry.Name, view.Inode.Kind, entry.Ino, node.kind)
		}
	}
	dir.children[entry.Name] = node
	return node, nil
}

// hydrateDirent resolves one undecided name against the base (fetching
// outside fs.mu) and installs a positive result. found=false is a verified
// base-absent verdict (nothing installed); the caller records it in its
// local verdicts. Errors are fetch/corruption failures: nothing was
// installed, nothing is poisoned, and a retry is safe.
func (lz *pft2Lazy) hydrateDirent(ctx context.Context, fs *FS, miss *baseMiss) (node *inode, found bool, err error) {
	entry, err := lz.reader.Lookup(ctx, miss.ref, miss.name)
	if errors.Is(err, pft2.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	view, err := lz.reader.GetInode(ctx, entry.Ino)
	if err != nil {
		if errors.Is(err, pft2.ErrNotFound) {
			err = fmt.Errorf("%w: dirent %q references missing inode %d", pft2.ErrCorrupt, miss.name, entry.Ino)
		}
		return nil, false, err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	node, err = lz.installDirentLocked(fs, miss.dir, entry, view)
	if err != nil {
		return nil, false, err
	}
	if node == nil {
		// A live decision (tombstone/completion) landed between fetch and
		// install: absent is the truth, but it is a LIVE verdict, not a
		// base verdict — the retry walk re-derives it from the tree.
		return nil, true, nil
	}
	return node, true, nil
}

// hydrateIno ensures the stable-handle index can answer for ino: a base
// inode never touched by the journal is fetched through the verified inode
// index and installed byIno-only (its names hydrate later through their own
// dirents and adopt the same record). Reaped base inodes stay dead; fresh
// (post-base) inos are beyond the base index high-water and resolve
// not-found without deep walks.
func (lz *pft2Lazy) hydrateIno(ctx context.Context, fs *FS, ino uint64) error {
	if ino == 0 {
		return nil
	}
	fs.mu.RLock()
	_, live := fs.byIno[ino]
	_, dead := fs.deadBaseInos[ino]
	fs.mu.RUnlock()
	if live || dead {
		return nil
	}
	view, err := lz.reader.GetInode(ctx, ino)
	if errors.Is(err, pft2.ErrNotFound) {
		return nil // genuinely absent: resolveForRW misses deterministically
	}
	if err != nil {
		return err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if _, exists := fs.byIno[ino]; exists {
		return nil
	}
	if _, nowDead := fs.deadBaseInos[ino]; nowDead {
		return nil
	}
	node := lz.newInodeFromView(view)
	fs.byIno[ino] = node
	fs.alloc.observe(ino)
	return nil
}

// loadDir enumerates one pending directory's base pages (fetching outside
// fs.mu, installing page-by-page under short write holds) and, in
// loadDirComplete mode, drops the dirBase binding once every base name is
// consumed. Concurrent calls for the same directory coalesce on one flight;
// a failed flight is cleared so retries are safe.
func (lz *pft2Lazy) loadDir(ctx context.Context, fs *FS, dir *inode, mode dirLoadMode) error {
	for {
		fs.mu.RLock()
		pending := dir.base != nil
		nonEmpty := len(dir.children) > 0
		fs.mu.RUnlock()
		if !pending || (mode == loadDirEmptiness && nonEmpty) {
			return nil
		}

		lz.mu.Lock()
		if flight := lz.loads[dir]; flight != nil {
			lz.mu.Unlock()
			select {
			case <-flight.done:
			case <-ctx.Done():
				return ctx.Err()
			}
			if flight.err != nil {
				return flight.err
			}
			// The finished flight may have been an emptiness probe that
			// stopped early; re-evaluate our own goal.
			continue
		}
		flight := &dirLoadFlight{mode: mode, done: make(chan struct{})}
		lz.loads[dir] = flight
		lz.mu.Unlock()

		var err error
		if mode == loadDirEmptiness {
			err = lz.runDirEmptinessProbe(ctx, fs, dir)
		} else {
			err = lz.runDirLoad(ctx, fs, dir, mode)
		}

		lz.mu.Lock()
		delete(lz.loads, dir)
		lz.mu.Unlock()
		flight.err = err
		close(flight.done)
		return err
	}
}

// runDirEmptinessProbe decides "does this directory have ANY live entry"
// with bounded work: it stops at the FIRST proven entry instead of loading
// unbounded children. Per page it fetches names once (one leaf visit) and
// then at most ONE undecided inode view before returning — tombstoned names
// keep scanning (they can never prove non-emptiness), and an exhausted
// enumeration completes the directory (provably empty of base entries).
func (lz *pft2Lazy) runDirEmptinessProbe(ctx context.Context, fs *FS, dir *inode) error {
	cursor := ""
	for {
		fs.mu.RLock()
		b := dir.base
		var ref pft2.Ref
		if b != nil {
			ref = b.ref
		}
		nonEmpty := len(dir.children) > 0
		fs.mu.RUnlock()
		if b == nil || nonEmpty {
			return nil
		}

		entries, next, err := lz.reader.ReadDir(ctx, ref, cursor, pft2LoadDirPageSize)
		if err != nil {
			return err
		}
		for i := range entries {
			entry := entries[i]
			fs.mu.RLock()
			if dir.base == nil || len(dir.children) > 0 {
				fs.mu.RUnlock()
				return nil // decided concurrently
			}
			if _, present := dir.children[entry.Name]; present {
				fs.mu.RUnlock()
				return nil
			}
			dead := dir.base.tombstoned(entry.Name)
			known := fs.byIno[entry.Ino] != nil
			fs.mu.RUnlock()
			if dead {
				continue
			}
			var view pft2.InodeView
			if !known {
				view, err = lz.reader.GetInode(ctx, entry.Ino)
				if err != nil {
					if errors.Is(err, pft2.ErrNotFound) {
						err = fmt.Errorf("%w: dirent %q references missing inode %d",
							pft2.ErrCorrupt, entry.Name, entry.Ino)
					}
					return err
				}
			}
			fs.mu.Lock()
			var node *inode
			if existing := fs.byIno[entry.Ino]; existing != nil {
				node, err = lz.installAliasLocked(fs, dir, entry, existing)
			} else if known {
				// The canonical record was reaped between the scan and this
				// install; the name must have been tombstoned by the same
				// journal history. Skip: install-if-undecided.
				fs.mu.Unlock()
				continue
			} else {
				node, err = lz.installDirentLocked(fs, dir, entry, view)
			}
			nonEmpty = len(dir.children) > 0
			fs.mu.Unlock()
			if err != nil {
				return err
			}
			if node != nil || nonEmpty {
				return nil // first proven entry: the directory is non-empty
			}
		}
		if next == "" {
			// Every base name is tombstoned or decided-absent: the directory
			// is provably empty of base entries and therefore complete.
			fs.mu.Lock()
			if dir.base != nil {
				dir.base = nil
			}
			fs.mu.Unlock()
			return nil
		}
		cursor = next
	}
}

// runDirLoad is one flight's enumeration. Base pages are stable under
// concurrent mutation (the base is immutable); installs skip names the live
// tree already decided, so entries removed or created mid-load stay exactly
// as the journal decided them.
func (lz *pft2Lazy) runDirLoad(ctx context.Context, fs *FS, dir *inode, mode dirLoadMode) error {
	cursor := ""
	for {
		fs.mu.RLock()
		b := dir.base
		var ref pft2.Ref
		if b != nil {
			ref = b.ref
		}
		nonEmpty := len(dir.children) > 0
		fs.mu.RUnlock()
		if b == nil || (mode == loadDirEmptiness && nonEmpty) {
			return nil
		}

		entries, next, err := lz.reader.ReadDir(ctx, ref, cursor, pft2LoadDirPageSize)
		if err != nil {
			return err
		}

		// Fetch the page's inode views outside fs.mu, skipping names the
		// live tree has already decided and inos already canonical.
		type staged struct {
			entry pft2.DirEntry
			view  pft2.InodeView
			byIno bool
		}
		page := make([]staged, 0, len(entries))
		fs.mu.RLock()
		for _, entry := range entries {
			if dir.base == nil {
				break
			}
			if _, present := dir.children[entry.Name]; present {
				continue
			}
			if dir.base.tombstoned(entry.Name) {
				continue
			}
			_, known := fs.byIno[entry.Ino]
			page = append(page, staged{entry: entry, byIno: known})
		}
		fs.mu.RUnlock()
		for i := range page {
			if page[i].byIno {
				continue // alias of an already-canonical inode: no fetch needed
			}
			view, err := lz.reader.GetInode(ctx, page[i].entry.Ino)
			if err != nil {
				if errors.Is(err, pft2.ErrNotFound) {
					err = fmt.Errorf("%w: dirent %q references missing inode %d",
						pft2.ErrCorrupt, page[i].entry.Name, page[i].entry.Ino)
				}
				return err
			}
			page[i].view = view
		}

		fs.mu.Lock()
		for i := range page {
			if dir.base == nil {
				break
			}
			entry := page[i].entry
			if page[i].byIno {
				existing := fs.byIno[entry.Ino]
				if existing == nil {
					// The canonical record was reaped between the scan and
					// this install; the name must have been tombstoned by
					// the same journal history. Skip: install-if-undecided.
					continue
				}
				if _, err := lz.installAliasLocked(fs, dir, entry, existing); err != nil {
					fs.mu.Unlock()
					return err
				}
				continue
			}
			if _, err := lz.installDirentLocked(fs, dir, entry, page[i].view); err != nil {
				fs.mu.Unlock()
				return err
			}
		}
		complete := next == ""
		if complete && dir.base != nil {
			// Every base name is now materialized or deliberately dead:
			// the directory is complete and the base (with its tombstones)
			// is never consulted again.
			dir.base = nil
		}
		nonEmpty = len(dir.children) > 0
		fs.mu.Unlock()

		if complete || (mode == loadDirEmptiness && nonEmpty) {
			return nil
		}
		cursor = next
	}
}

// installAliasLocked installs a base dirent whose inode is already
// canonical in byIno (hard-link alias or handle-hydrated inode) without a
// redundant inode-index fetch. Caller holds fs.mu for write.
func (lz *pft2Lazy) installAliasLocked(fs *FS, dir *inode, entry pft2.DirEntry, node *inode) (*inode, error) {
	if existing, ok := dir.children[entry.Name]; ok {
		return existing, nil
	}
	if dir.base == nil || dir.base.tombstoned(entry.Name) {
		return nil, nil
	}
	if fs.orphans[entry.Ino] == node {
		return nil, fmt.Errorf("%w: base dirent %q references parked inode %d", pft2.ErrCorrupt, entry.Name, entry.Ino)
	}
	if node.kind != entry.Kind.String() {
		return nil, fmt.Errorf("%w: base dirent %q kind %v does not match live inode %d kind %s",
			pft2.ErrCorrupt, entry.Name, entry.Kind, entry.Ino, node.kind)
	}
	dir.children[entry.Name] = node
	return node, nil
}

// ─── read-path hydration ────────────────────────────────────────────────────

// withReadPath resolves name for a read-only operation and runs fn under
// fs.mu.RLock with the result (nil = definitively absent). On a lazy-base
// FS, undecided components hydrate OUTSIDE the lock between attempts; a
// concurrent mutation always wins because installs are install-if-undecided
// and the walk re-runs from the root each attempt.
func (fs *FS) withReadPath(name string, fn func(n *inode) error) error {
	if fs.pft2 == nil {
		fs.mu.RLock()
		defer fs.mu.RUnlock()
		return fn(fs.resolve(name))
	}
	ctx := context.Background()
	verdicts := newBaseVerdicts()
	for attempt := 0; attempt < maxReadHydrateAttempts; attempt++ {
		fs.mu.RLock()
		n, miss := fs.resolveLazyLocked(name, verdicts)
		if miss == nil {
			defer fs.mu.RUnlock()
			return fn(n)
		}
		fs.mu.RUnlock()
		_, found, err := fs.pft2.hydrateDirent(ctx, fs, miss)
		if err != nil {
			return fmt.Errorf("%w: %s: %v", errBaseHydration, name, err)
		}
		if !found {
			verdicts.markNameAbsent(miss.dir, miss.name)
		}
	}
	return fmt.Errorf("%w: %s: did not converge under concurrent namespace churn", errBaseHydration, name)
}

// withReadHandle is withReadPath for handle-addressed reads: when ino is
// non-zero the stable index is hydrated (never a path fallback), otherwise
// the path resolves as usual.
func (fs *FS) withReadHandle(name string, ino uint64, fn func(n *inode) error) error {
	if ino == 0 {
		return fs.withReadPath(name, fn)
	}
	if err := fs.hydrateHandleIno(ino); err != nil {
		return err
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fn(fs.byIno[ino])
}

// hydrateHandleIno makes the byIno index answerable for one caller-supplied
// stable handle on a lazy-base FS. No-op otherwise.
func (fs *FS) hydrateHandleIno(ino uint64) error {
	if fs.pft2 == nil || ino == 0 {
		return nil
	}
	if err := fs.pft2.hydrateIno(context.Background(), fs, ino); err != nil {
		return fmt.Errorf("%w: ino %d: %v", errBaseHydration, ino, err)
	}
	return nil
}

// completeDirForRead fully enumerates a pending directory before a listing.
// It leaves complete directories untouched and is safe to race with
// mutations and other loads.
func (fs *FS) completeDirForRead(dir *inode) error {
	if fs.pft2 == nil || dir == nil {
		return nil
	}
	fs.mu.RLock()
	pending := dir.base != nil
	fs.mu.RUnlock()
	if !pending {
		return nil
	}
	if err := fs.pft2.loadDir(context.Background(), fs, dir, loadDirComplete); err != nil {
		return fmt.Errorf("%w: readdir: %v", errBaseHydration, err)
	}
	return nil
}

// ─── mutation-intent hydration ──────────────────────────────────────────────

type hydrateMode uint8

const (
	// hydrateOptimistic runs before reservation, outside all locks. It is
	// an optimization: it bounds how much fetching the exact pass has to do
	// under the apply turn. Convergence races are tolerated (bounded
	// iterations, no retries) because the exact pass settles everything.
	hydrateOptimistic hydrateMode = iota
	// hydrateExact runs under the mutation's apply turn (or single-threaded
	// cold-start replay): nothing else can apply concurrently, so the
	// fixpoint is guaranteed to terminate with every name the apply will
	// consult decided. Transient fetch failures are retried briefly; a
	// persistent failure is returned and the caller fails the authority
	// closed (the row is durable and MUST apply exactly).
	hydrateExact
)

const (
	// hydrateOptimisticMaxRounds bounds the pre-reservation fixpoint. Each
	// round decides at least one more path component (the walk stops at the
	// FIRST undecided name), so the bound must comfortably exceed realistic
	// path depths; beyond it the exact pass under the apply turn settles
	// the remainder.
	hydrateOptimisticMaxRounds = 64
	hydrateExactFetchAttempts  = 5
)

// baseNeedKind classifies one hydration dependency of a mutation intent.
type baseNeedKind uint8

const (
	needDirent baseNeedKind = iota
	needIno
	needEmptiness
)

type baseNeed struct {
	kind baseNeedKind
	miss baseMiss // needDirent
	ino  uint64   // needIno
	dir  *inode   // needEmptiness
}

// hydrateIntentTargets brings every name/ino/emptiness fact the given tree
// leaves' apply will consult into decided state, fetching outside fs.mu.
// After the exact pass, the ordinary locked apply resolves entirely
// in-memory and decides exactly as the eager-loaded tree would — live apply
// and cold replay converge because the base is immutable.
func (fs *FS) hydrateIntentTargets(ctx context.Context, leaves []wal.Record, mode hydrateMode) error {
	if fs.pft2 == nil || len(leaves) == 0 {
		return nil
	}
	verdicts := newBaseVerdicts()
	maxRounds := hydrateOptimisticMaxRounds
	if mode == hydrateExact {
		// Under the apply turn (or construction replay) nothing else
		// mutates, so each round strictly decides at least one new fact;
		// the bound is a defensive ceiling, not a convergence knob.
		maxRounds = maxIntentMutations * 4
	}
	for round := 0; round < maxRounds; round++ {
		fs.mu.RLock()
		needs := fs.collectIntentNeedsLocked(leaves, verdicts)
		fs.mu.RUnlock()
		if len(needs) == 0 {
			return nil
		}
		for i := range needs {
			// A fetch failure is definite for the optimistic pass (nothing
			// was buffered) and, after bounded retries, fatal for the exact
			// pass (the caller fences: a durable row must apply exactly).
			if err := fs.hydrateOneNeed(ctx, &needs[i], verdicts, mode); err != nil {
				return err
			}
		}
	}
	if mode == hydrateExact {
		return fmt.Errorf("%w: intent hydration exceeded its round ceiling", errBaseHydration)
	}
	return nil // optimistic pass gives up; the exact pass settles the rest
}

func (fs *FS) hydrateOneNeed(ctx context.Context, need *baseNeed, verdicts *baseVerdicts, mode hydrateMode) error {
	attempts := 1
	if mode == hydrateExact {
		attempts = hydrateExactFetchAttempts
	}
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(50<<(attempt-1)) * time.Millisecond):
			}
		}
		switch need.kind {
		case needDirent:
			var found bool
			_, found, err = fs.pft2.hydrateDirent(ctx, fs, &need.miss)
			if err == nil {
				if !found {
					verdicts.markNameAbsent(need.miss.dir, need.miss.name)
				}
				return nil
			}
		case needIno:
			err = fs.pft2.hydrateIno(ctx, fs, need.ino)
			if err == nil {
				fs.mu.RLock()
				_, live := fs.byIno[need.ino]
				fs.mu.RUnlock()
				if !live {
					verdicts.markInoAbsent(need.ino)
				}
				return nil
			}
		case needEmptiness:
			err = fs.pft2.loadDir(ctx, fs, need.dir, loadDirEmptiness)
			if err == nil {
				return nil
			}
		}
		if errors.Is(err, pft2.ErrCorrupt) || errors.Is(err, pft2.ErrInvalidNode) {
			return err // fail closed immediately: retrying corruption is pointless
		}
	}
	return err
}

// collectIntentNeedsLocked scans the leaves' apply dependencies against the
// current tree and reports every fact still undecided. Caller holds fs.mu
// (read). The scan mirrors exactly what applyMutationAs resolves: full path
// component chains (parents and final names), stable-handle targets, and
// directory emptiness for remove/rename-over decisions.
func (fs *FS) collectIntentNeedsLocked(leaves []wal.Record, verdicts *baseVerdicts) []baseNeed {
	var needs []baseNeed
	seenMiss := map[*inode]map[string]struct{}{}
	seenIno := map[uint64]struct{}{}
	seenDir := map[*inode]struct{}{}

	addPath := func(p string) *inode {
		n, miss := fs.resolveLazyLocked(p, verdicts)
		if miss != nil {
			if seenMiss[miss.dir] == nil {
				seenMiss[miss.dir] = map[string]struct{}{}
			}
			if _, dup := seenMiss[miss.dir][miss.name]; !dup {
				seenMiss[miss.dir][miss.name] = struct{}{}
				needs = append(needs, baseNeed{kind: needDirent, miss: *miss})
			}
		}
		return n
	}
	addIno := func(ino uint64) {
		if ino == 0 || verdicts.inoAbsent(ino) {
			return
		}
		if _, live := fs.byIno[ino]; live {
			return
		}
		if _, dead := fs.deadBaseInos[ino]; dead {
			return
		}
		if _, dup := seenIno[ino]; dup {
			return
		}
		seenIno[ino] = struct{}{}
		needs = append(needs, baseNeed{kind: needIno, ino: ino})
	}
	addEmptiness := func(n *inode) {
		// The emptiness decision (rmdir ENOTEMPTY, rename-over-directory)
		// must reflect base entries too. A live entry already proves
		// non-empty; otherwise the probe either proves the first base entry
		// or completes the directory as empty.
		if n == nil || n.kind != "directory" || n.base == nil || len(n.children) > 0 {
			return
		}
		if _, dup := seenDir[n]; dup {
			return
		}
		seenDir[n] = struct{}{}
		needs = append(needs, baseNeed{kind: needEmptiness, dir: n})
	}

	for i := range leaves {
		r := &leaves[i]
		switch r.Op {
		case wal.OpControl, wal.OpReap:
			// Controls touch no tree names; reap targets the orphan table,
			// which is eagerly restored from the recovery anchor.
		case wal.OpWrite, wal.OpTruncate, wal.OpChmod, wal.OpChtimes, wal.OpChown:
			if r.Ino != 0 {
				addIno(r.Ino)
			} else {
				addPath(r.Path)
			}
		case wal.OpCreate, wal.OpSymlink, wal.OpMkdir:
			addPath(r.Path)
		case wal.OpLink:
			if r.Ino != 0 {
				addIno(r.Ino)
			}
			addPath(r.Path)
			addPath(r.NewPath)
		case wal.OpRemove, wal.OpOrphan:
			addEmptiness(addPath(r.Path))
		case wal.OpRename:
			addPath(r.Path)
			addEmptiness(addPath(r.NewPath))
		}
	}
	return needs
}

// ─── complete materialization boundary ──────────────────────────────────────

// MaterializeBaseNamespace hydrates EVERY remaining base directory so the
// in-memory tree carries the complete live namespace. It fetches strictly
// outside fs.mu (page-by-page directory loads) and converges even against
// concurrent mutations, because mutations never create pending directories
// — only hydration does, and only beneath the finite immutable base. It is
// the explicit boundary checkpoint-style whole-tree captures use; ordinary
// access never needs it.
func (fs *FS) MaterializeBaseNamespace(ctx context.Context) error {
	if fs.pft2 == nil {
		return nil
	}
	for {
		// One pass collects EVERY currently pending directory (memory is one
		// pointer per pending dir), then loads them outside the lock. Fresh
		// pending directories can appear only underneath the ones just
		// loaded, so the pass count is bounded by the base tree depth.
		fs.mu.RLock()
		var pending []*inode
		var walk func(n *inode)
		walk = func(n *inode) {
			if n.base != nil {
				pending = append(pending, n)
			}
			for _, c := range n.children {
				if c.kind == "directory" {
					walk(c)
				}
			}
		}
		walk(fs.root)
		fs.mu.RUnlock()
		if len(pending) == 0 {
			return nil
		}
		for _, dir := range pending {
			if err := fs.pft2.loadDir(ctx, fs, dir, loadDirComplete); err != nil {
				return err
			}
		}
	}
}

// mustMaterializeForSnapshot is the non-erroring snapshot boundary used by
// the legacy no-error capture APIs. A snapshot that silently omitted
// unhydrated base names would commit namespace loss, so an unreachable base
// fails CLOSED here. The context-aware checkpoint captures propagate the
// error instead; production managed authorities cut history through the
// journal (HistoryCut), not through these captures.
func (fs *FS) mustMaterializeForSnapshot() {
	if err := fs.MaterializeBaseNamespace(context.Background()); err != nil {
		panic(fmt.Sprintf("workfs: snapshot capture requires the complete namespace, and the lazy PFT2 base is unreachable: %v", err))
	}
}
