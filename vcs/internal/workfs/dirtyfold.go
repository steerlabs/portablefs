package workfs

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/metrics"
	"github.com/steerlabs/portablefs/vcs/internal/pft2"
)

// The history-cut FOLD: the release path a managed generation never had.
//
// ── THE DEFECT THIS CLOSES ──────────────────────────────────────────────────
//
// A managed child's resident dirty-block pool (fs.dirtyBytes, bounded by
// VCS_DIRTY_RSS_MAX_MB) had exactly three shrink paths: truncate, orphan reap,
// and transaction rollback. `rm` is NOT one of them — applyManagedMutation
// parks the detached inode on every successful unlink and OpReap is its sole
// destruction transition, so a parked orphan keeps every block it had until
// the last close. MarkClean, the one function that releases resident blocks
// into a committed source, had no production caller anywhere: only tests.
//
// So the counter was MONOTONE for the life of a child, and the bound was a
// hard ceiling on CUMULATIVE lifetime writes — ~2 GiB by default, whatever the
// rate, whatever the file, however much of it was long since committed. The
// external HistoryCut service DOES materialise those bytes into a new base
// commit, and adoption advances the generation's base tuple (baseSeq /
// baseCommitID) in remotejournal — but nothing rebound THIS child's inodes to
// it, so the freshly committed blocks stayed resident forever.
//
// FoldToBase is the missing rebind. On cut adoption the child re-resolves the
// adopted base and, for every inode the base provably contains, drops the
// resident copies of the blocks that base already holds.
//
// ── WHAT PROVES A BLOCK FOLDABLE ────────────────────────────────────────────
//
// A cut at watermark W is the deterministic materialisation of exactly the
// journal records with LSN < W over the previous base. The child applied that
// identical prefix in that identical order (cut determinism is frozen and
// goldened — the materializer and the live reducer are the same transition
// engine), so:
//
//	At the instant this child's applied cursor was exactly W, its content for
//	every inode equalled the cut's content for that inode.
//
// Call that state_W. Between state_W and now, the only transitions that can
// change a file's bytes are OpWrite (which stamps inode.blockSeq[b] with the
// writing row's LSN, necessarily >= W) and OpTruncate (which stamps
// inode.truncSeq). Renames, links, chmod/chown/chtimes/chflags, xattrs, orphan
// parking and reaping change no bytes at all. Therefore, for an inode with
//
//	truncSeq < W                            (no post-cut truncate), and
//	blockSeq[b] < W for the blocks folded   (no post-cut write to b),
//
// every folded block's live content equals the base's content, and every block
// NOT folded keeps its resident (newer) copy and continues to override the
// base. Rebinding inode.source to the base's source is likewise exact: the
// base IS the file's content at W, discarded-by-truncate regions included
// (the cut materialised the bytes, so a shrink before W is already zeros in
// it), so the "monotone visible-base cap" truncateBlocks maintains is
// reproduced by the new source rather than undone by it.
//
// Truncate is the one transition the per-block proof cannot carry, because it
// drops blocks, trims a boundary buffer, and monotonically caps source.Size so
// a later regrow reads holes instead of resurrected base bytes. An inode
// truncated at or after W is therefore SKIPPED WHOLE — never partially folded.
// That costs nothing: truncate is itself a releasing operation.
//
// ── THE RACING WRITER ───────────────────────────────────────────────────────
//
// Resolving the base is a remote read, so it runs OUTSIDE fs.mu. A write may
// land at any point during it. It cannot lose a byte:
//
//   - Every write applies under fs.mu at a journal LSN strictly greater than
//     every LSN that is already durable, hence strictly greater than W (W is a
//     durable prefix boundary). It stamps blockSeq[b] >= W for each block it
//     touches, in the same lock hold that publishes the bytes.
//   - The commit phase re-reads blockSeq and truncSeq UNDER fs.mu, after the
//     resolve, and folds only blocks still stamped below W. A block the racer
//     touched is therefore never folded — in either interleaving.
//   - The reverse order is equally safe. If the fold commits first and the
//     write lands after, the write's read-modify-write reads its base bytes
//     through the NEW source, which holds exactly the same bytes the old
//     resident copy did. The fold preserves the read function pointwise; that
//     is the whole invariant, and nothing downstream can observe the swap.
//
// PARTIAL WRITES. A write that only partially covers a block materialises the
// WHOLE block (base bytes + the new bytes) and stamps the merged buffer, so a
// partly-overwritten block is never half-proved: it is one buffer with one
// provenance. An inode partly folded and partly newer is the NORMAL outcome
// here — block 0..k folded away, blocks k+1.. still resident — and it is
// exactly representable, because dirty blocks were always an override layer
// over a base. What is NOT representable, and never produced, is a single
// block whose bytes come from two different generations.
//
// ── THE INVARIANT ───────────────────────────────────────────────────────────
//
// After a fold to watermark W completes, every resident dirty block was last
// written by a record with LSN >= W (or belongs to an inode skipped for a
// post-W truncate, or to an inode the base does not contain — both bounded by
// the same window). So:
//
//	resident dirty bytes <= blockSize x (number of distinct blocks written by
//	                        journal records in [W, appliedWatermark))
//
// i.e. residency is bounded by the UNCUT SUFFIX, not by the branch's lifetime.
// The bound stops being a ceiling on cumulative writes and becomes what it was
// always documented to be: a backstop against one pathological burst.
//
// That converts the problem into one of ORDER — the cut has to land before the
// suffix outgrows the bound — which is a scheduling question this package
// cannot answer alone. Two things bound the suffix, and both live in the
// volume-api's maintenance loop: the TRIGGER POINT
// (PORTABLEFS_HISTORY_MAINTENANCE_BACKLOG_PERCENT, coordinated against this
// bound by coordinatedBacklogPercent on both sides) and the SCAN PERIOD
// (rate x interval of overshoot between looks). Neither bounds write
// AMPLIFICATION — one byte per 4 MiB region costs a whole block per ~40
// journal bytes — and for that shape the fold makes the ceiling recoverable
// rather than terminal, with the definite ENOSPC still the answer to a burst
// that outruns any cadence.
//
// Nothing here needs object-store WRITE access — the child only READS the base
// it was given, through the content.BlobReader/Ranger it already holds. That
// is why this is buildable where an in-process checkpoint is not.

var (
	dirtyFoldReleasedTotal = metrics.Default.Counter("vcs_dirty_fold_released_bytes")
	dirtyFoldBlocksTotal   = metrics.Default.Counter("vcs_dirty_fold_blocks")
	dirtyFoldPassesTotal   = metrics.Default.Counter("vcs_dirty_fold_passes")
	dirtyFoldWatermark     = metrics.Default.Gauge("vcs_dirty_fold_watermark")
)

// ErrFoldStale reports a fold offered a watermark this generation has already
// folded to (or past). It is a benign, expected outcome — adoption
// notifications are at-least-once — and never an error the caller should
// escalate.
var ErrFoldStale = errors.New("vcs: history-cut fold watermark is not ahead of the folded watermark")

// FoldBase is one adopted history cut, described to the child well enough to
// fold into. It carries no object-store credentials and no write capability:
// Resolve is a READ of the committed base the caller already proved.
type FoldBase struct {
	// Watermark is the cut's exclusive journal boundary: the base materialises
	// exactly the records with LSN < Watermark. This is the generation's
	// baseSeq after adoption.
	Watermark uint64
	// CommitID is the adopted base manifest identity, carried for telemetry
	// and for the caller's own proof chain. The fold does not interpret it.
	CommitID string
	// Resolve returns the committed content source the base holds for one
	// stable inode identity, ok=false when the base does not contain that
	// inode as a REGULAR FILE (created after the cut, unlinked before it, or a
	// directory/symlink). It is called OUTSIDE fs.mu and may perform remote
	// reads; it must be safe for sequential use and must honour ctx.
	Resolve func(ctx context.Context, ino uint64) (content.Source, bool, error)
	// MaxInodes bounds one pass's resolve fan-out (0 = unbounded). Candidates
	// are taken in descending resident-bytes order, so a bounded pass always
	// releases the most memory available to it.
	MaxInodes int
}

// FoldReport is one fold pass's accounting.
type FoldReport struct {
	Watermark     uint64
	CommitID      string
	Candidates    int   // inodes holding at least one block provably below the cut
	Inodes        int   // inodes actually rebound
	Blocks        int   // resident dirty blocks released
	BytesReleased int64 // resident bytes released
	Absent        int   // candidates the base does not contain
	Raced         int   // candidates a concurrent write/truncate/reap disqualified
	Failed        int   // candidates whose base resolve failed (retried next pass)
	Resident      int64 // fs.dirtyBytes after the pass
}

// foldCandidate is one inode selected for a pass.
type foldCandidate struct {
	ino   uint64
	bytes int64
}

// Pft2FoldCache is the verified immutable-object cache the fold's base views
// read through, created ONCE per generation and shared by every pass.
//
// Sharing is both safe and necessary. Safe, because PFT2 objects are
// content-addressed: two different cuts referencing the same pack reference
// the same bytes, so a hit across bases is a hit on identical content, and
// successive cuts of one branch overwhelmingly re-reference the same packs.
// Necessary, because a folded inode's content.Source RETAINS the view it was
// bound to for as long as that inode keeps reading through it — so a cache per
// pass would pin one cache per adopted base indefinitely, and a fold running
// every few seconds under pressure would spend more memory on caches than the
// dirty blocks it released. One cache, bounded once.
type Pft2FoldCache struct {
	fetcher pft2.Fetcher
	packs   *pft2PackCache
}

// NewPft2FoldCache creates the shared fold object cache for one generation.
func NewPft2FoldCache(fetcher pft2.Fetcher) *Pft2FoldCache {
	if fetcher == nil {
		return nil
	}
	return &Pft2FoldCache{fetcher: fetcher, packs: newPft2PackCache(fetcher, pft2PackCacheBytes)}
}

// Pft2FoldBase opens a READ-ONLY view of an adopted PFT2 base and returns the
// FoldBase that resolves committed sources out of it by stable inode identity.
//
// It deliberately builds its own tree reader and pack cache rather than
// re-pointing the live generation's lazy base binding. The child's UNHYDRATED
// directories still reference the base it cold-started on, whose objects stay
// pinned for the life of this runtime; re-pointing them would break namespace
// hydration for an adoption that only ever needed to move FILE CONTENT. So the
// two bindings coexist: folded inodes carry sources from the adopted base,
// everything else keeps reading the base it started on. content.Source is
// self-contained (each carries its own verified Ranger), which is what makes
// that mixture ordinary rather than special.
//
// Resolution is by INODE, never by path. A rename after the cut moves a name
// but not a byte, so identity is both the cheaper and the only correct key —
// and it is the key that makes a PARKED ORPHAN foldable at all, since an
// orphan has no name to look up.
//
// The numeric inode index makes each resolve a bounded verified descent (no
// namespace walk), so a fold pass costs O(inodes with foldable blocks), not
// O(namespace).
func Pft2FoldBase(cache *Pft2FoldCache, watermark uint64, commitID string, root pft2.Ref) (FoldBase, error) {
	if cache == nil || cache.fetcher == nil {
		return FoldBase{}, fmt.Errorf("workfs: pft2 fold base requires a fold cache")
	}
	reader, err := pft2.NewTreeReader(pft2.TreeReaderConfig{Fetcher: cache.fetcher}, root)
	if err != nil {
		return FoldBase{}, fmt.Errorf("workfs: open adopted pft2 base %s: %w", commitID, err)
	}
	// A content-only lazy binding: the Ranger needs a reader bound to THIS
	// base plus the shared verified pack cache, and nothing else. No
	// directory-load flight table exists because this view never hydrates a
	// namespace.
	lz := &pft2Lazy{
		reader:  reader,
		fetcher: cache.fetcher,
		packs:   cache.packs,
	}
	return FoldBase{
		Watermark: watermark,
		CommitID:  commitID,
		Resolve: func(ctx context.Context, ino uint64) (content.Source, bool, error) {
			view, err := reader.GetInode(ctx, ino)
			if err != nil {
				if errors.Is(err, pft2.ErrNotFound) {
					// Created after the cut, or destroyed before it. Not an
					// error: the inode simply is not in this base.
					return content.Source{}, false, nil
				}
				return content.Source{}, false, err
			}
			if view.Inode.Kind != pft2.FileKindRegular {
				return content.Source{}, false, nil
			}
			if view.Inode.Size == 0 {
				// An empty committed file has no extents; the zero source is
				// its exact representation.
				return content.Source{}, true, nil
			}
			return content.Source{
				Size:   int64(view.Inode.Size),
				Ranger: &pft2FileRanger{lz: lz, file: view.Ref, size: int64(view.Inode.Size)},
			}, true, nil
		},
	}, nil
}

// FoldToBase releases the resident copies of every dirty block the adopted
// base at base.Watermark provably contains, rebinding each folded inode to the
// base's committed source. It is the production caller MarkClean never had.
//
// Correctness is argued in full at the top of this file. Mechanically the pass
// is three phases: SELECT candidates under a read lock, RESOLVE the base
// outside every lock (remote reads), COMMIT under the write lock re-checking
// every proof against state that may have moved. Only the commit phase
// mutates, and it re-derives foldability from scratch — the select phase is a
// hint, never a decision.
//
// A pass is idempotent and monotone: a watermark not ahead of the last folded
// one returns ErrFoldStale having changed nothing, so at-least-once adoption
// notifications are free. Partial progress is always safe and always kept; a
// resolve failure (object-store outage, cancellation) leaves those inodes
// dirty for the next pass and is reported, never fatal.
func (fs *FS) FoldToBase(ctx context.Context, base FoldBase) (FoldReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if base.Resolve == nil {
		return FoldReport{}, fmt.Errorf("workfs: history-cut fold requires a base resolver")
	}
	if base.Watermark == 0 {
		return FoldReport{}, fmt.Errorf("workfs: history-cut fold requires a nonzero watermark")
	}
	// One fold at a time per generation: two passes interleaving their
	// select/resolve/commit phases would each re-check their own proofs
	// correctly, but the second would waste an object-store round trip per
	// inode the first already folded.
	fs.foldMu.Lock()
	defer fs.foldMu.Unlock()

	fs.mu.RLock()
	if base.Watermark <= fs.foldWatermark {
		folded := fs.foldWatermark
		fs.mu.RUnlock()
		return FoldReport{Watermark: folded}, fmt.Errorf("%w: offered %d, already folded to %d",
			ErrFoldStale, base.Watermark, folded)
	}
	// A cut can only cover records this authority has already applied; folding
	// against a watermark ahead of the applied cursor would rebind inodes to
	// content this process has not yet reproduced.
	if applied := fs.seq.appliedWatermark(); fs.managed != nil && base.Watermark > applied {
		fs.mu.RUnlock()
		return FoldReport{}, fmt.Errorf("workfs: history-cut fold watermark %d is ahead of the applied cursor %d",
			base.Watermark, applied)
	}
	candidates := fs.foldCandidatesLocked(base.Watermark)
	fs.mu.RUnlock()

	report := FoldReport{Watermark: base.Watermark, CommitID: base.CommitID, Candidates: len(candidates)}
	// Biggest resident first: a bounded pass then always releases the most
	// memory it can, which is what makes a bounded pass sufficient to keep up.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].bytes != candidates[j].bytes {
			return candidates[i].bytes > candidates[j].bytes
		}
		return candidates[i].ino < candidates[j].ino
	})
	if base.MaxInodes > 0 && len(candidates) > base.MaxInodes {
		candidates = candidates[:base.MaxInodes]
	}

	var firstErr error
	for _, c := range candidates {
		if err := ctx.Err(); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			report.Failed += len(candidates) - report.Inodes - report.Absent - report.Raced - report.Failed
			break
		}
		src, ok, err := base.Resolve(ctx, c.ino)
		if err != nil {
			report.Failed++
			if firstErr == nil {
				firstErr = fmt.Errorf("workfs: history-cut fold resolve ino %d: %w", c.ino, err)
			}
			continue
		}
		if !ok {
			report.Absent++
			continue
		}
		blocks, bytes, folded := fs.foldInode(c.ino, base.Watermark, src)
		if !folded {
			report.Raced++
			continue
		}
		report.Inodes++
		report.Blocks += blocks
		report.BytesReleased += bytes
	}

	fs.mu.Lock()
	// The folded watermark advances even when individual inodes were skipped:
	// every skip is either a racing writer (whose blocks are ABOVE this
	// watermark and would be skipped by a repeat pass identically) or an
	// absent/failed inode a LATER cut will cover. Holding the watermark back
	// would only make the next adoption redo the same resolves.
	if base.Watermark > fs.foldWatermark {
		fs.foldWatermark = base.Watermark
	}
	report.Resident = fs.dirtyBytes
	fs.mu.Unlock()

	dirtyFoldPassesTotal.Inc()
	dirtyFoldBlocksTotal.Add(int64(report.Blocks))
	dirtyFoldReleasedTotal.Add(report.BytesReleased)
	dirtyFoldWatermark.Set(int64(base.Watermark))
	return report, firstErr
}

// FoldedWatermark reports the highest cut watermark this generation has folded
// to (0 = never folded).
func (fs *FS) FoldedWatermark() uint64 {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.foldWatermark
}

// foldCandidatesLocked lists every live file inode — named tree AND parked
// orphans, both indexed by byIno — holding at least one resident block whose
// last write provably precedes the cut. Caller holds fs.mu (read or write).
//
// Parked orphans are deliberately included. An inode unlinked at or after the
// cut is still IN that base under its stable identity, and unlinking changed
// none of its bytes, so its blocks are exactly as foldable as a named file's.
// That is the one relief `rm` never gave on a managed authority.
func (fs *FS) foldCandidatesLocked(watermark uint64) []foldCandidate {
	var out []foldCandidate
	for ino, n := range fs.byIno {
		if !foldEligibleLocked(n, watermark) {
			continue
		}
		var bytes int64
		for bi, blk := range n.blocks {
			if seq, ok := n.blockSeq[bi]; ok && seq < watermark {
				bytes += int64(len(blk))
			}
		}
		if bytes > 0 {
			out = append(out, foldCandidate{ino: ino, bytes: bytes})
		}
	}
	return out
}

// foldEligibleLocked is the per-inode precondition: a live regular file with
// resident blocks and no truncate at or after the cut. Caller holds fs.mu.
func foldEligibleLocked(n *inode, watermark uint64) bool {
	return n != nil && n.kind == "file" && len(n.blocks) > 0 && n.truncSeq < watermark
}

// foldInode is the COMMIT phase for one inode: it re-derives every proof under
// the exclusive lock (the select phase's answers are stale by construction —
// the base resolve happened outside every lock) and releases only the blocks
// still provably in the base. Returns the blocks and bytes released, and
// whether the inode was rebound at all.
func (fs *FS) foldInode(ino, watermark uint64, src content.Source) (int, int64, bool) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n := fs.byIno[ino]
	// Re-check, do not trust: the inode may have been reaped, truncated, or
	// re-written while the base resolve was in flight.
	if !foldEligibleLocked(n, watermark) {
		return 0, 0, false
	}
	var blocks int
	var released int64
	for bi, blk := range n.blocks {
		seq, ok := n.blockSeq[bi]
		if !ok || seq >= watermark {
			continue // written at or after the cut (or provenance unknown): keep the resident copy
		}
		released += int64(len(blk))
		blocks++
		delete(n.blocks, bi)
		delete(n.blockSeq, bi)
	}
	fs.addDirtyBlockBytesLocked(-released)
	// Rebind to the committed base. This is exact even when nothing was
	// released (every block was newer): the base is still this inode's content
	// at the cut, and the surviving dirty blocks still override it.
	n.source = src
	n.born = false
	// truncated is the "size differs from the committed source with no dirty
	// block to prove it" flag. After the rebind the committed source is the
	// cut's, so the flag is exactly the size comparison against it. A file
	// grown past the cut keeps dirty blocks covering the growth, so this stays
	// conservative in the safe direction.
	n.truncated = n.size != src.Size
	return blocks, released, true
}
