package writeback

import (
	"sort"
	"strings"
)

// Entry is one locally-known name: an authoritative child of a seeded
// directory, or a locally created/mutated object. Attribute fields mirror the
// wire attr shape so clientcore can serve getattr/readdir from it directly.
type Entry struct {
	Name    string
	Kind    string // "file" | "directory" | "symlink"
	Mode    uint32
	Size    int64
	MtimeMs int64
	CtimeMs int64
	AtimeMs int64
	UID     uint32
	GID     uint32
	Ino     uint64
	Nlink   uint32
	Target  string // symlink target
	// Flags is the inode's BSD file-flag word as the AUTHORITY last published
	// it. The engine carries it so a delegated getattr keeps reporting the
	// truth, but never MUTATES it: chflags has no local WAL lane (see
	// Engine.Setattr), so a flag change is written through to the authority
	// and re-seeded from there.
	Flags uint32
}

// dirView is one directory's locally-known children under a delegation.
// complete means the set is authoritative (grant snapshot, one seeded
// readdir, or born local): absence is then a proven ENOENT and creates need
// no probe. A partial view knows only locally created names and tombstones.
type dirView struct {
	children   map[string]*Entry
	tombstones map[string]bool // hidden authority names (partial views only)
	complete   bool
}

func newDirView(complete bool) *dirView {
	return &dirView{children: map[string]*Entry{}, tombstones: map[string]bool{}, complete: complete}
}

// xattrView is the complete extended-attribute map of an object created
// inside a delegation. Existing authority objects deliberately do not get a
// partial view: without every value's size the client cannot prove the
// per-inode total-byte limit before acknowledging a set locally.
type xattrView struct {
	values map[string][]byte
}

func newXattrView() *xattrView {
	return &xattrView{values: map[string][]byte{}}
}

func (x *xattrView) totalAfterSet(name string, value []byte) int {
	total := len(name) + len(value)
	for existingName, existingValue := range x.values {
		if existingName != name {
			total += len(existingName) + len(existingValue)
		}
	}
	return total
}

// extent is one current dirty range [start,end) of a file. zero extents fill
// holes (write-beyond-EOF, truncate-extend); WAL extents reference payload
// bytes in a stream segment.
type extent struct {
	start, end uint64
	seq        uint64
	zero       bool
	ordinal    uint64
	off        int64 // payload byte offset within the segment file
}

// extentRange is one half-open file range [start,end). It is the only thing
// the extent-cardinality projection needs: splicing depends on boundaries
// alone, never on where a range's bytes live.
type extentRange struct{ start, end uint64 }

// spliceRange projects fileView.insertExtent onto ranges: the extents cur that
// do not intersect r survive unchanged, a partial overlap leaves its
// non-overlapping fragment(s), a fully covered extent disappears, and r itself
// is added. Order is irrelevant to the result's cardinality, so the projection
// does not sort.
func spliceRange(cur []extentRange, r extentRange) []extentRange {
	if r.start >= r.end {
		return cur
	}
	out := cur[:0:0]
	for _, c := range cur {
		if c.end <= r.start || c.start >= r.end {
			out = append(out, c)
			continue
		}
		if c.start < r.start {
			out = append(out, extentRange{start: c.start, end: r.start})
		}
		if c.end > r.end {
			out = append(out, extentRange{start: r.end, end: c.end})
		}
	}
	return append(out, r)
}

// projectedWriteExtents is the EXACT overlay cardinality that inserting ranges
// (in order) into existing would leave behind — the same splice the write path
// then performs, so admission and effect can never disagree.
//
// It is tight in both directions, which is the whole point: a write whose range
// exactly covers existing extents REPLACES them (cardinality unchanged, or
// lower when it covers several), so it costs nothing and must be admitted at
// the bound; only a range that survives alongside what is already there costs a
// slot. A range strictly inside one existing extent genuinely costs two (the
// extent splits into a left fragment, the new range, and a right fragment)
// because the fragments reference distinct WAL payload bytes and cannot be
// represented as one extent — the projection charges exactly that, no more.
func projectedWriteExtents(existing []extent, ranges []extentRange) int {
	cur := make([]extentRange, 0, len(existing)+len(ranges))
	for _, e := range existing {
		cur = append(cur, extentRange{start: e.start, end: e.end})
	}
	for _, r := range ranges {
		cur = spliceRange(cur, r)
	}
	return len(cur)
}

// projectedTruncateExtents is the EXACT overlay cardinality after truncating
// from oldSize to newSize, mirroring fileView.truncateExtents. A shrink only
// drops and clips extents, so it NEVER needs a free slot (truncate to zero
// clears the set outright); only an extending truncate adds its hole extent.
func projectedTruncateExtents(existing []extent, oldSize, newSize uint64) int {
	switch {
	case newSize < oldSize:
		n := 0
		for _, e := range existing {
			if e.start < newSize {
				n++
			}
		}
		return n
	case newSize > oldSize:
		return projectedWriteExtents(existing, []extentRange{{start: oldSize, end: newSize}})
	default:
		return len(existing)
	}
}

// baseMove is one locally-acknowledged rename not yet applied at the
// authority: until the watermark covers seq, the view's clean ranges still
// live at the OLD authority path.
type baseMove struct {
	seq  uint64
	path string
}

// fileView is one file's dirty state: current extents over the authority
// base, plus its attr entry (shared with the parent dirView's children map).
// basePath is the authority path currently serving the view's clean ranges;
// pending local renames advance it only as the watermark covers them —
// folding a write must never redirect base reads to a name the authority has
// not bound yet (the fold-vs-rename race serves the PREVIOUS file's bytes).
type fileView struct {
	entry    *Entry
	basePath string
	moves    []baseMove
	extents  []extent
}

// notePathMove records a local rename of this view to newPath at seq.
func (fv *fileView) notePathMove(seq uint64, newPath string) {
	fv.moves = append(fv.moves, baseMove{seq: seq, path: newPath})
}

// baseAt reports the authority path serving clean ranges right now.
func (fv *fileView) baseAt() string {
	return fv.basePath
}

// insertExtent splices e into the sorted non-overlapping set, splitting
// partial overlaps and adjusting WAL payload offsets for retained fragments.
func (fv *fileView) insertExtent(e extent) {
	if e.start >= e.end {
		return
	}
	out := fv.extents[:0:0]
	for _, cur := range fv.extents {
		if cur.end <= e.start || cur.start >= e.end {
			out = append(out, cur)
			continue
		}
		if cur.start < e.start {
			left := cur
			left.end = e.start
			out = append(out, left)
		}
		if cur.end > e.end {
			right := cur
			if !right.zero {
				right.off += int64(e.end - right.start)
			}
			right.start = e.end
			out = append(out, right)
		}
	}
	out = append(out, e)
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	fv.extents = out
}

// truncateExtents applies a truncate to size: extents beyond it are dropped
// or clipped; extending inserts a zero extent so old base bytes can never
// leak back after a shrink-then-extend.
func (fv *fileView) truncateExtents(oldSize, newSize uint64, seq uint64) {
	if newSize < oldSize {
		out := fv.extents[:0]
		for _, cur := range fv.extents {
			if cur.start >= newSize {
				continue
			}
			if cur.end > newSize {
				cur.end = newSize
			}
			out = append(out, cur)
		}
		fv.extents = out
		return
	}
	if newSize > oldSize {
		fv.insertExtent(extent{start: oldSize, end: newSize, seq: seq, zero: true})
	}
}

// overlapping returns the current extents intersecting [start,end), in order.
func (fv *fileView) overlapping(start, end uint64) []extent {
	var out []extent
	for _, cur := range fv.extents {
		if cur.end <= start {
			continue
		}
		if cur.start >= end {
			break
		}
		out = append(out, cur)
	}
	return out
}

// segmentsPinned reports the WAL segment ordinals live extents reference.
func (fv *fileView) segmentsPinned(pin map[uint64]bool) {
	for _, e := range fv.extents {
		if !e.zero {
			pin[e.ordinal] = true
		}
	}
}

// foldApplied drops extents fully covered by the authority watermark: the
// flushed bytes are now the authority's current content, so reads fall
// through to the (version-refreshed) base path. Pending base moves (local
// renames) advance basePath as the watermark covers their sequences —
// strictly in order, so a chain of renames tracks exactly where the
// authority currently binds the content. Reports whether any extents remain.
func (fv *fileView) foldApplied(through uint64) bool {
	for len(fv.moves) > 0 && fv.moves[0].seq <= through {
		fv.basePath = fv.moves[0].path
		fv.moves = fv.moves[1:]
	}
	out := fv.extents[:0]
	for _, cur := range fv.extents {
		if cur.seq <= through && !cur.zero {
			continue
		}
		if cur.seq <= through && cur.zero {
			// A folded zero extent's range is now authoritative (the flushed
			// truncate/hole is applied), so it can drop with the rest.
			continue
		}
		out = append(out, cur)
	}
	fv.extents = out
	return len(fv.extents) > 0
}

func parentDir(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return ""
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func pathUnder(p, root string) bool {
	if root == "" {
		return true
	}
	return p == root || strings.HasPrefix(p, root+"/")
}
