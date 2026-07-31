package workfs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// Pft2Base is an adopted content-addressed PFT2 base: the USER filesystem
// root plus the separate internal RecoveryRoot (PFC2 control map,
// parked-orphan index, inode allocator watermarks). Fetcher must verify
// every object against its content address before returning bytes (the
// backend history-object fetcher does).
//
// Every field besides Fetcher/Root/RecoveryRoot is a PROOF-SIDE fact from
// the tenant-scoped serving proof (pfh.serving_base_prove). None of them is
// trusted alone: NewManagedFromPft2 binds each one against the hashed
// objects (ROOT facts, RecoveryRoot fields) and fails closed on any
// disagreement before readiness.
type Pft2Base struct {
	Fetcher pft2.Fetcher
	Root    pft2.Ref
	// BaseSeq is the exact claimed journal base sequence of the generation
	// adopting this base (0 for a fresh fork/conversion origin).
	BaseSeq uint64
	// RootMaxInoSeen is the proven user-root allocation high-water; it must
	// equal the hashed ROOT object's MaxInoSeen exactly. A too-low proof
	// could otherwise let a fresh allocation collide with an unhydrated
	// base inode.
	RootMaxInoSeen uint64
	// RecoveryRoot is the internal anchor: nil exactly for a FORK, which
	// reuses the immutable filesystem arm and starts controls/orphans
	// empty under a FRESH allocator namespace. Missing anchor data must
	// never be mapped onto this shape — only a positive fork proof is.
	RecoveryRoot *pft2.Ref
	// AnchorAsOfSeq is the proven anchor as-of sequence (the exact cut
	// sequence the anchor was materialized at). It must equal the hashed
	// RecoveryRoot.AsOfSeq; for an adopted base (BaseSeq != 0) it must also
	// equal BaseSeq. Zero (and ignored) for a fork.
	AnchorAsOfSeq uint64
	// InodeNamespace/NextLocal seed the branch's namespaced allocator for
	// fresh inodes. For a FORK they are the NEW branch's DB-issued
	// never-reused namespace row (a fork of a namespaced source root would
	// otherwise exhaust the flat allocator on its first create); for
	// conversion/adopted bases they must equal the hashed RecoveryRoot's
	// InoNamespace/NextLocal exactly.
	InodeNamespace uint32
	NextLocal      uint64
	// AllocatorMaxInoSeen is the proven branch allocator high-water: the
	// anchor's for conversion/adopted (must dominate RootMaxInoSeen), the
	// new branch namespace row's for a fork (fresh, so usually 1). The
	// runtime durable floor is max(hashed root high-water, this value).
	AllocatorMaxInoSeen uint64
}

// NewManagedFromPft2 cold-starts a managed authority from an adopted PFT2
// base with BOUNDED work independent of the namespace size: it opens the
// lazy BaseTree, fetches only the root directory inode (verified through
// the inode index), restores the separate RecoveryRoot facts — PFC2 control
// state (sessions, locks, checkouts, pins, exact outcome floors), parked
// orphans, allocator watermarks — and replays the journal suffix
// [base, head) through the ordinary managed replay, synchronously hydrating
// only the base paths each replayed record actually resolves (bounded by
// the journal suffix, never the tree). Everything else stays behind lazy
// per-directory bindings: namespace lookups hydrate exactly their path
// components, directory listings enumerate page by page, and file bytes
// fetch per-extent on first read — all outside FS.mu (see pft2lazy.go).
// Callers bind listeners and publish readiness only after this returns.
//
// The bounded anchor reads are justified as follows: the root inode is the
// tree entry point every walk needs; the RecoveryRoot's control map is the
// admission/fencing/exact-outcome authority and must be complete before the
// first request; the parked-orphan index must be complete because orphans
// are addressable only by stable ino (never through a hydratable name) and
// reap correctness derives from it.
//
// Exact base binding (fail closed BEFORE readiness, every mismatch):
//   - the hashed ROOT object's MaxInoSeen must equal the proven
//     RootMaxInoSeen, and the root inode must be the ROOT's exact RootInode;
//   - a non-fork RecoveryRoot must reference EXACTLY base.Root
//     (FilesystemRoot), carry AsOfSeq == AnchorAsOfSeq (== BaseSeq for an
//     adopted base), and its hashed InoNamespace/NextLocal must equal the
//     proven allocator facts — runtime allocator state derives from that
//     object/proof agreement, never one side alone;
//   - every parked-orphan id must sit at or below the authenticated root
//     high-water (the format's monotone bound covers parked orphans), and
//     named ids are structurally bounded by the same fact inside every
//     verified inode-index walk.
func NewManagedFromPft2(ctx context.Context, base Pft2Base, blobs content.BlobReader, log pfj3.EntryLog, cache content.Cache) (*FS, error) {
	if log.RecordCodec() != pfj3.RecordCodec || log.ControlCodec() != pfj3.ControlCodec {
		return nil, fmt.Errorf("%w: log speaks %s/%s", ErrNotManaged, log.RecordCodec(), log.ControlCodec())
	}
	if base.Fetcher == nil {
		return nil, fmt.Errorf("workfs: pft2 base requires a fetcher")
	}
	if base.InodeNamespace < 1 || base.InodeNamespace > pft2.MaxInodeNamespace {
		return nil, fmt.Errorf("workfs: pft2 base requires a proven inode namespace in 1..%d (got %d)",
			pft2.MaxInodeNamespace, base.InodeNamespace)
	}
	if base.NextLocal < 1 || base.NextLocal > pft2.MaxInodeLocalCounter+1 {
		return nil, fmt.Errorf("workfs: pft2 base next-local %d outside 1..%d", base.NextLocal, pft2.MaxInodeLocalCounter+1)
	}
	if base.RootMaxInoSeen < 1 || base.RootMaxInoSeen > pft2.MaxIno {
		return nil, fmt.Errorf("workfs: pft2 base root high-water %d outside 1..%d", base.RootMaxInoSeen, pft2.MaxIno)
	}
	if base.AllocatorMaxInoSeen < 1 || base.AllocatorMaxInoSeen > pft2.MaxIno {
		return nil, fmt.Errorf("workfs: pft2 base allocator high-water %d outside 1..%d", base.AllocatorMaxInoSeen, pft2.MaxIno)
	}
	if base.RecoveryRoot == nil {
		// A fork is a fresh seq-0 generation origin by construction; any
		// other claimed base sequence contradicts the fork shape.
		if base.BaseSeq != 0 {
			return nil, fmt.Errorf("workfs: fork pft2 base claims nonzero base sequence %d", base.BaseSeq)
		}
		if base.AnchorAsOfSeq != 0 {
			return nil, fmt.Errorf("workfs: fork pft2 base carries an anchor as-of sequence")
		}
	} else {
		// Adopted binding: a nonzero base sequence must be exactly the
		// anchor's as-of cut. A seq-0 conversion origin may carry the final
		// source-cut sequence instead; the hashed-object equality below
		// still binds it exactly.
		if base.BaseSeq != 0 && base.AnchorAsOfSeq != base.BaseSeq {
			return nil, fmt.Errorf("workfs: adopted pft2 anchor as-of %d does not equal base sequence %d",
				base.AnchorAsOfSeq, base.BaseSeq)
		}
		if base.AllocatorMaxInoSeen < base.RootMaxInoSeen {
			return nil, fmt.Errorf("workfs: pft2 anchor allocator high-water %d is below the root high-water %d",
				base.AllocatorMaxInoSeen, base.RootMaxInoSeen)
		}
	}
	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: base.Fetcher}, base.Root)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	fs := &FS{
		root:         &inode{ino: 1, kind: "directory", mode: os.ModeDir | 0o755, mtime: now, ctime: now, atime: now, birthtime: now, children: map[string]*inode{}},
		blobs:        blobs,
		cache:        cache,
		log:          log,
		bounds:       log.Bounds(),
		generation:   randomNonce(),
		alloc:        newInoAllocator(),
		orphans:      map[uint64]*inode{},
		orphanLeases: map[uint64]time.Time{},
		openInodes:   map[uint64]map[string]time.Time{},
		pendingReaps: map[uint64]uint32{},
		byIno:        map[uint64]*inode{},
		xattrs:       map[uint64]map[string][]byte{},
		deadBaseInos: map[uint64]struct{}{},
		managed: &managedState{
			log:      log,
			reserved: pfc2.NewState(),
			applied:  pfc2.NewState(),
		},
	}
	fs.pft2 = &pft2Lazy{
		reader:  reader,
		fetcher: base.Fetcher,
		packs:   newPft2PackCache(base.Fetcher, pft2PackCacheBytes),
		loads:   map[*inode]*dirLoadFlight{},
	}
	fs.byIno[1] = fs.root

	// Every PFT2 base — fork included — allocates fresh identities in its
	// branch's proven never-reused namespace. A fork of a namespaced source
	// root MUST NOT fall back to the legacy flat allocator: the source
	// root's high-water sits far beyond the flat 2^32 cap, so the first
	// flat allocation would report identity exhaustion.
	fs.alloc = inoAllocator{
		namespace:  base.InodeNamespace,
		nextLocal:  base.NextLocal,
		maxInoSeen: 1,
	}

	// Bind the externally proven root facts against the actual hashed ROOT
	// object before anything trusts them: a too-low proven high-water could
	// let a fresh identity collide with a real, merely unhydrated inode.
	// The proof may sit ABOVE the hashed value — pre-020 provenance rows
	// recorded the branch ALLOCATOR watermark (which dominates the root's
	// whenever the cut burned identities that did not survive into the
	// tree) — and a higher proof is only conservative: the durable floor
	// below derives from the authenticated rootFacts and the allocator
	// fact, never from this field.
	rootFacts, err := reader.RootFacts(ctx)
	if err != nil {
		return nil, fmt.Errorf("workfs: pft2 base root facts: %w", err)
	}
	if base.RootMaxInoSeen < rootFacts.MaxInoSeen {
		return nil, fmt.Errorf("workfs: proven root high-water %d is below the hashed ROOT's %d",
			base.RootMaxInoSeen, rootFacts.MaxInoSeen)
	}
	// User-root xattrs are loaded as a compact ordered side tree without
	// hydrating their inodes or directories. This preserves the PFT2 lazy
	// cold-start bound while making snapshot/fork metadata immediately
	// available by stable ino.
	rootXattrs, err := collectPft2Xattrs(ctx, base.Fetcher, rootFacts.XattrLeaves)
	if err != nil {
		return nil, fmt.Errorf("workfs: pft2 root xattrs: %w", err)
	}
	for _, e := range rootXattrs {
		if e.Ino > rootFacts.MaxInoSeen {
			return nil, fmt.Errorf("workfs: root xattr inode %d exceeds the authenticated high-water %d",
				e.Ino, rootFacts.MaxInoSeen)
		}
		m := fs.xattrs[e.Ino]
		if m == nil {
			m = map[string][]byte{}
			fs.xattrs[e.Ino] = m
		}
		m[e.Name] = append([]byte(nil), e.Value...)
		fs.alloc.observe(e.Ino)
	}

	// The ONLY user-namespace object fetched eagerly: the root directory
	// inode. Its dirents stay behind the lazy binding. The index walk is
	// verified against the ROOT facts, and the resolved object must be the
	// ROOT's exact RootInode (the format pins index entry 1 to it).
	rootView, err := reader.GetInode(ctx, pft2.RootIno)
	if err != nil {
		return nil, fmt.Errorf("workfs: pft2 base root: %w", err)
	}
	if rootView.Ref != rootFacts.RootInode {
		return nil, fmt.Errorf("workfs: inode index maps the root to %s, ROOT advertises %s",
			rootView.Ref, rootFacts.RootInode)
	}
	fs.root.ino = rootView.Inode.Ino
	applyPft2Meta(fs.root, rootView.Inode)
	fs.root.base = &dirBase{lz: fs.pft2, ref: rootView.Ref}
	fs.byIno[fs.root.ino] = fs.root
	fs.alloc.observe(fs.root.ino)

	// Restore the separate internal anchor: PFC2 controls, parked orphans,
	// allocator watermarks. Every anchor fact must agree with its hashed
	// counterpart; a fork restores nothing (fresh controls, no orphans).
	if base.RecoveryRoot != nil {
		facts, err := loadPft2Recovery(ctx, base.Fetcher, *base.RecoveryRoot)
		if err != nil {
			return nil, err
		}
		if facts.filesystemRoot != base.Root {
			return nil, fmt.Errorf("workfs: recovery anchor binds filesystem root %s, base adopts %s",
				facts.filesystemRoot, base.Root)
		}
		if facts.asOfSeq != base.AnchorAsOfSeq {
			return nil, fmt.Errorf("workfs: hashed recovery anchor as-of %d does not equal the proven %d",
				facts.asOfSeq, base.AnchorAsOfSeq)
		}
		if facts.namespace != base.InodeNamespace || facts.nextLocal != base.NextLocal {
			return nil, fmt.Errorf("workfs: hashed recovery allocator %d/%d does not equal the proven %d/%d",
				facts.namespace, facts.nextLocal, base.InodeNamespace, base.NextLocal)
		}
		if facts.state != nil {
			fs.managed.applied = facts.state
		}
		for _, view := range facts.orphans {
			// Parked orphans are nameless by definition; a parked directory
			// was empty when it parked, so none of them carries a lazy
			// binding — the record itself is the complete restored state.
			// Every parked id must sit inside the authenticated allocation
			// high-water (the ROOT's monotone bound covers parked orphans).
			if view.Inode.Ino > rootFacts.MaxInoSeen {
				return nil, fmt.Errorf("workfs: parked orphan inode %d exceeds the authenticated high-water %d",
					view.Inode.Ino, rootFacts.MaxInoSeen)
			}
			orphan := inodeFromPft2(view.Inode, fs.pft2, view.Ref)
			fs.orphans[view.Inode.Ino] = orphan
			fs.byIno[view.Inode.Ino] = orphan
			fs.alloc.observe(view.Inode.Ino)
		}
		// Restore the anchored LIVE xattr state, keyed by stable ino (the
		// inode itself may still be behind the lazy binding — xattr reads
		// resolve the ino first, so the central map needs no hydration).
		for _, e := range facts.xattrs {
			if e.Ino > rootFacts.MaxInoSeen {
				return nil, fmt.Errorf("workfs: anchored xattr inode %d exceeds the authenticated high-water %d",
					e.Ino, rootFacts.MaxInoSeen)
			}
			m := fs.xattrs[e.Ino]
			if m == nil {
				m = map[string][]byte{}
				fs.xattrs[e.Ino] = m
			}
			if prior, ok := m[e.Name]; ok && !bytes.Equal(prior, e.Value) {
				return nil, fmt.Errorf("workfs: root xattr %d/%q disagrees with recovery anchor", e.Ino, e.Name)
			}
			m[e.Name] = append([]byte(nil), e.Value...)
			fs.alloc.observe(e.Ino)
		}
	}
	// The durable floor MUST precede replay: fresh identities never descend
	// to it, and replayed reaps of base-namespace inos are classified
	// against it (deadBaseInos) so stable-handle hydration can never
	// re-materialize a reaped inode from the immutable base. It derives
	// from the AUTHENTICATED root high-water joined with the proven branch
	// allocator high-water (for a non-fork anchor already checked to
	// dominate the root's; for a fork the fresh row usually contributes
	// nothing beyond the root fact).
	durableFloor := rootFacts.MaxInoSeen
	if base.AllocatorMaxInoSeen > durableFloor {
		durableFloor = base.AllocatorMaxInoSeen
	}
	fs.alloc.durableFloor = durableFloor
	fs.alloc.observe(durableFloor)

	// Journal suffix replay to the exact head. Each entry synchronously
	// hydrates exactly the base names/inos its own apply resolves — work
	// bounded by the suffix length and path depths, never total tree size —
	// so replay decides byte-identically to the live applies it re-executes.
	if err := log.ReplayEntriesInto(func(entry pfj3.JournalEntry) error {
		if entry.Tree != nil {
			leaves, lerr := intentLeaves([]wal.Record{*entry.Tree})
			if lerr != nil {
				return fmt.Errorf("workfs: managed replay intent %d: %w", entry.LSN, lerr)
			}
			if herr := fs.hydrateIntentTargets(ctx, leaves, hydrateExact); herr != nil {
				return fmt.Errorf("workfs: pft2 cold-start replay hydration (row %d): %w", entry.LSN, herr)
			}
		}
		return fs.replayEntry(entry)
	}); err != nil {
		return nil, err
	}
	fs.advanceInoHighWaterFromControl()
	projection := fs.managed.applied.Project()
	reserved, err := pfc2.Rebuild(projection)
	if err != nil {
		return nil, fmt.Errorf("workfs: pft2 base control projection: %w", err)
	}
	fs.managed.reserved = reserved
	fs.seq.init(log.Watermark())
	fs.pins = map[uint64]uint64{}
	return fs, nil
}

func applyPft2Meta(n *inode, meta pft2.Inode) {
	n.mode = os.FileMode(meta.Mode & 0o7777)
	switch meta.Kind {
	case pft2.FileKindDirectory:
		n.kind = "directory"
		n.mode |= os.ModeDir
	case pft2.FileKindSymlink:
		n.kind = "symlink"
		n.mode |= os.ModeSymlink
	default:
		n.kind = "file"
	}
	n.uid = meta.UID
	n.gid = meta.GID
	n.mtime = time.UnixMilli(meta.MtimeMs)
	n.ctime = time.UnixMilli(meta.CtimeMs)
	n.atime = time.UnixMilli(meta.AtimeMs)
	// Birth time 0 is the format's "absent" value (a tree written before the
	// field existed), NOT a real 1970 creation. Keep the zero time so the
	// protocol layer serves 0 and the client applies its own convention;
	// converting it to time.UnixMilli(0) would fabricate a birth time.
	if meta.BirthtimeMs != 0 {
		n.birthtime = time.UnixMilli(meta.BirthtimeMs)
	} else {
		n.birthtime = time.Time{}
	}
	n.flags = meta.Flags
}

func inodeFromPft2(meta pft2.Inode, lz *pft2Lazy, ref pft2.Ref) *inode {
	n := &inode{ino: meta.Ino, children: map[string]*inode{}}
	applyPft2Meta(n, meta)
	if meta.Nlink > 1 {
		n.nlink = uint32(meta.Nlink)
	}
	switch meta.Kind {
	case pft2.FileKindSymlink:
		n.linkTarget = meta.SymlinkTarget
	case pft2.FileKindRegular:
		n.size = int64(meta.Size)
		if meta.Size > 0 {
			n.source = content.Source{
				Size:   int64(meta.Size),
				Ranger: &pft2FileRanger{lz: lz, file: ref, size: int64(meta.Size)},
			}
		}
	}
	return n
}

// pft2RangerWindowBytes bounds one ReadExtents operation's logical window.
//
// Explicit budget contract (proven against the reader's DEFAULT per-op
// bounds, 64 nodes / 8 MiB): a window of 16 pages (16 × pft2.PageBytes =
// 1 MiB) costs at most
//
//	1 (file INODE)
//	+ pft2.MaxTreeDepth (12; root-to-cover descent, conservatively double
//	  counted against the covering subtree below)
//	+ 2×16−1 = 31 (every node of a covering extent subtree over ≤16 leaf
//	  entries at the format's minimum index fanout of 2)
//	+ 16 (one DATA_PAGE node per window page)
//	= 60 logical node visits < 64,
//
// so a maximally dense window can never fail with ErrBoundExceeded, at any
// tree depth the format permits, without raising the shared reader budget.
// Successive windows re-descend the extent tree (≤ depth nodes each): total
// work stays linear in the range — never a quadratic rescan. Only a crafted
// tree of maximum-size (256 KiB) nodes can exceed the 8 MiB per-op byte
// ceiling; that remains the intended typed fail-closed outcome.
const pft2RangerWindowBytes = int64(16 * pft2.PageBytes)

// pft2FileRanger reads one base file's bytes through lazy bounded extent
// walks; absent extents are holes (zeros). Object bytes come from the shared
// verified pack cache (each unique pack at most once per operation, once
// across warm operations), and every served cell re-verifies its logical
// cell digest and terminal-zero tail via pft2.VerifyCellBytes before a byte
// is copied out.
type pft2FileRanger struct {
	lz   *pft2Lazy
	file pft2.Ref
	size int64
}

// ReadRangeAt implements content.Ranger.
func (r *pft2FileRanger) ReadRangeAt(ctx context.Context, p []byte, off int64) (int, error) {
	if off >= r.size {
		return 0, io.EOF
	}
	want := int64(len(p))
	if off+want > r.size {
		want = r.size - off
	}
	for i := range p[:want] {
		p[i] = 0
	}
	// Operation-scoped pack map: each unique immutable pack object is
	// resolved AT MOST ONCE per ReadRangeAt — across every window — through
	// the shared verified cache (which additionally makes warm operations
	// free). A dense pack backs up to 1024 cells and must never be fetched
	// per cell; the map's residency is bounded by the packs the requested
	// range actually spans (≤ range/PackBytes + 1).
	packs := map[pft2.Ref][]byte{}
	done := int64(0)
	for done < want {
		step := min(pft2RangerWindowBytes, want-done)
		extents, err := r.lz.reader.ReadExtents(ctx, r.file, uint64(off+done), uint64(step))
		if err != nil {
			return int(done), err
		}
		for i := range extents {
			if extents[i].Cell == nil {
				return int(done), fmt.Errorf("workfs: pft2 base extent without a cell (legacy extents are not served live)")
			}
			ref := extents[i].Cell.Object
			if _, resolved := packs[ref]; resolved {
				continue
			}
			raw, err := r.lz.packs.fetch(ctx, ref)
			if err != nil {
				return int(done), err
			}
			packs[ref] = raw
		}
		for _, ext := range extents {
			// Fail closed BEFORE serving: exact cell digest plus the
			// terminal-zero invariant over the logically invalid tail.
			cell, err := pft2.VerifyCellBytes(ext.Cell, packs[ext.Cell.Object], ext.Length)
			if err != nil {
				return int(done), fmt.Errorf("workfs: pft2 cell verification: %w", err)
			}
			// Intersect [ext.FileOffset, +Length) with [off, off+want).
			extStart := int64(ext.FileOffset)
			extEnd := extStart + int64(ext.Length)
			from := max(extStart, off)
			to := min(extEnd, off+want)
			if from >= to {
				continue
			}
			copy(p[from-off:to-off], cell[from-extStart:to-extStart])
		}
		done += step
	}
	return int(want), nil
}

// ─── recovery anchor decoding ────────────────────────────────────────────────

type pft2RecoveryFacts struct {
	state *pfc2.State
	// filesystemRoot and asOfSeq are the hashed anchor's exact bindings:
	// the filesystem ROOT it describes and the cut sequence it was
	// materialized at. Adoption validates both against the claimed base.
	filesystemRoot pft2.Ref
	asOfSeq        uint64
	orphans        []pft2.InodeView
	// xattrs is the anchored LIVE extended-attribute state (strictly
	// ascending (ino, name) across the anchor's xattr leaves).
	xattrs     []pft2.XattrEntry
	maxInoSeen uint64
	nextLocal  uint64
	namespace  uint32
}

// loadPft2Recovery decodes the internal RecoveryRoot: control map -> exact
// PFC2 state (sessions/locks/checkouts/pins/outcome floors), orphan index ->
// parked inodes, allocator watermarks, plus the anchor's exact filesystem
// root and as-of sequence bindings.
func loadPft2Recovery(ctx context.Context, fetcher pft2.Fetcher, ref pft2.Ref) (*pft2RecoveryFacts, error) {
	raw, err := fetcher.Fetch(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("workfs: recovery root fetch: %w", err)
	}
	if pft2.RefOf(raw) != ref {
		return nil, fmt.Errorf("workfs: recovery root does not hash to its reference")
	}
	node, err := pft2.DecodeNodeKind(raw, pft2.KindRecoveryRoot)
	if err != nil {
		return nil, fmt.Errorf("workfs: recovery root decode: %w", err)
	}
	rr := node.RecoveryRoot
	facts := &pft2RecoveryFacts{
		filesystemRoot: rr.FilesystemRoot,
		asOfSeq:        rr.AsOfSeq,
		nextLocal:      rr.NextLocal,
		namespace:      rr.InoNamespace,
	}

	if rr.ControlRoot != nil {
		entries, nextEpoch, dbTimeFloorMs, err := collectPft2ControlEntries(ctx, fetcher, *rr.ControlRoot)
		if err != nil {
			return nil, err
		}
		if dbTimeFloorMs > uint64(1<<62) {
			return nil, fmt.Errorf("workfs: anchor database-time floor %d overflows", dbTimeFloorMs)
		}
		// NextCheckoutEpoch and DbTimeFloorMs ride the hashed CONTROL_ROOT
		// itself (never map entries), so they survive cuts whose reduced
		// map is empty: adoption resumes epoch issuance and database-time
		// validation exactly where the retired prefix stopped.
		projection := &pfc2.Projection{
			Schema:            pfc2.ProjectionSchema,
			NextCheckoutEpoch: pfc2.Epoch(strconv.FormatUint(nextEpoch, 10)),
			DbTimeFloorMs:     int64(dbTimeFloorMs),
			Entries:           entries,
		}
		for i := range entries {
			switch entries[i].Kind {
			case pfc2.EntrySession:
				projection.Counts.Sessions++
			case pfc2.EntryTombstone:
				projection.Counts.Tombstones++
			case pfc2.EntrySlot:
				projection.Counts.Slots++
			case pfc2.EntryLock:
				projection.Counts.Locks++
			case pfc2.EntryCheckout:
				projection.Counts.Checkouts++
			case pfc2.EntryPin:
				projection.Counts.Pins++
			case pfc2.EntryFlush:
				projection.Counts.Flushes++
			}
		}
		state, err := pfc2.Rebuild(projection)
		if err != nil {
			return nil, fmt.Errorf("workfs: anchor control rebuild: %w", err)
		}
		facts.state = state
	}

	if rr.OrphanIndex != nil {
		orphans, maxIno, err := collectPft2Orphans(ctx, fetcher, *rr.OrphanIndex)
		if err != nil {
			return nil, err
		}
		facts.orphans = orphans
		facts.maxInoSeen = maxIno
	}
	xattrs, err := collectPft2Xattrs(ctx, fetcher, rr.XattrLeaves)
	if err != nil {
		return nil, err
	}
	facts.xattrs = xattrs
	return facts, nil
}

// collectPft2Xattrs loads an ordered xattr-leaf list and re-verifies
// the cross-leaf (ino, name) ordering the format promises (in-leaf ordering
// is the codec's own validation).
func collectPft2Xattrs(ctx context.Context, fetcher pft2.Fetcher, leaves []pft2.Ref) ([]pft2.XattrEntry, error) {
	var out []pft2.XattrEntry
	for i, ref := range leaves {
		node, err := fetchVerifiedNode(ctx, fetcher, ref)
		if err != nil {
			return nil, fmt.Errorf("workfs: xattr leaf %d: %w", i, err)
		}
		if node.Kind != pft2.KindXattrLeaf {
			return nil, fmt.Errorf("workfs: xattr leaf %d is %s", i, node.Kind)
		}
		for _, e := range node.XattrLeaf.Entries {
			if n := len(out); n > 0 {
				prev := out[n-1]
				if prev.Ino > e.Ino || (prev.Ino == e.Ino && prev.Name >= e.Name) {
					return nil, fmt.Errorf("workfs: xattr leaves are not strictly ordered across leaf %d", i)
				}
			}
			out = append(out, e)
		}
	}
	return out, nil
}

func fetchVerifiedNode(ctx context.Context, fetcher pft2.Fetcher, ref pft2.Ref) (*pft2.Node, error) {
	raw, err := fetcher.Fetch(ctx, ref)
	if err != nil {
		return nil, err
	}
	if pft2.RefOf(raw) != ref {
		return nil, fmt.Errorf("workfs: anchor object does not hash to its reference")
	}
	return pft2.DecodeNode(raw)
}

func collectPft2ControlEntries(ctx context.Context, fetcher pft2.Fetcher, root pft2.Ref) ([]pfc2.Entry, uint64, uint64, error) {
	rootNode, err := fetchVerifiedNode(ctx, fetcher, root)
	if err != nil {
		return nil, 0, 0, err
	}
	if rootNode.Kind != pft2.KindControlRoot {
		return nil, 0, 0, fmt.Errorf("workfs: anchor control root is %s", rootNode.Kind)
	}
	nextEpoch := rootNode.ControlRoot.NextCheckoutEpoch
	dbTimeFloorMs := rootNode.ControlRoot.DbTimeFloorMs
	var out []pfc2.Entry
	var walk func(ref pft2.Ref) error
	walk = func(ref pft2.Ref) error {
		node, err := fetchVerifiedNode(ctx, fetcher, ref)
		if err != nil {
			return err
		}
		switch node.Kind {
		case pft2.KindControlLeaf:
			for _, e := range node.ControlLeaf.Entries {
				entry, err := pfc2.DecodeEntry(e.Value)
				if err != nil {
					return fmt.Errorf("workfs: anchor control entry: %w", err)
				}
				out = append(out, entry)
			}
			return nil
		case pft2.KindControlIndex:
			for _, child := range node.ControlIndex.Children {
				if err := walk(child.Child); err != nil {
					return err
				}
			}
			return nil
		default:
			return fmt.Errorf("workfs: anchor control tree contains %s", node.Kind)
		}
	}
	if rootNode.ControlRoot.MapRoot != nil {
		if err := walk(*rootNode.ControlRoot.MapRoot); err != nil {
			return nil, 0, 0, err
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return string(out[i].Key()) < string(out[j].Key())
	})
	return out, nextEpoch, dbTimeFloorMs, nil
}

func collectPft2Orphans(ctx context.Context, fetcher pft2.Fetcher, root pft2.Ref) ([]pft2.InodeView, uint64, error) {
	var out []pft2.InodeView
	maxIno := uint64(0)
	var walk func(ref pft2.Ref) error
	walk = func(ref pft2.Ref) error {
		node, err := fetchVerifiedNode(ctx, fetcher, ref)
		if err != nil {
			return err
		}
		switch node.Kind {
		case pft2.KindInodeIndexLeaf:
			for _, e := range node.InodeIndexLeaf.Entries {
				inodeNode, err := fetchVerifiedNode(ctx, fetcher, e.Inode)
				if err != nil {
					return err
				}
				if inodeNode.Kind != pft2.KindInode {
					return fmt.Errorf("workfs: orphan index references %s", inodeNode.Kind)
				}
				out = append(out, pft2.InodeView{Ref: e.Inode, Inode: *inodeNode.Inode})
				if e.Ino > maxIno {
					maxIno = e.Ino
				}
			}
			return nil
		case pft2.KindInodeIndexIndex:
			for _, child := range node.InodeIndexIndex.Children {
				if err := walk(child.Child); err != nil {
					return err
				}
			}
			return nil
		default:
			return fmt.Errorf("workfs: orphan index contains %s", node.Kind)
		}
	}
	if err := walk(root); err != nil {
		return nil, 0, err
	}
	return out, maxIno, nil
}
