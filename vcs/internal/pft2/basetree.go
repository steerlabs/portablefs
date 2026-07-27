package pft2

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"
)

// BaseTree is the lazy immutable-filesystem read interface WorkFS consumes
// instead of an eager flat entry list. Handles are object references issued
// by the same tree (InodeView.Ref); every read verifies size, digest, kind,
// sort/range/count invariants, and depth under explicit bounds, and fails
// closed on any mismatch. The entry point is GetInode(RootIno).
type BaseTree interface {
	// Lookup resolves one name in the directory whose INODE object is
	// parent. It returns ErrNotFound for a missing name and ErrCorrupt for a
	// non-directory parent.
	Lookup(ctx context.Context, parent Ref, name string) (DirEntry, error)
	// GetInode resolves an inode number through the tree's inode index.
	GetInode(ctx context.Context, ino uint64) (InodeView, error)
	// ReadExtents returns the present extents overlapping
	// [offset, offset+length) of the regular file whose INODE object is
	// file, ascending by file offset. Uncovered ranges are holes that read
	// as zero.
	ReadExtents(ctx context.Context, file Ref, offset, length uint64) ([]Extent, error)
	// ReadDir returns up to limit entries of the directory whose INODE
	// object is dir, strictly after cursor ("" starts at the beginning) in
	// name-byte order, plus the continuation cursor ("" when exhausted).
	ReadDir(ctx context.Context, dir Ref, cursor string, limit int) ([]DirEntry, string, error)
}

// InodeView pairs a decoded immutable inode with the reference handle used
// for Lookup/ReadDir/ReadExtents. Callers must not mutate the Inode.
type InodeView struct {
	Ref   Ref
	Inode Inode
}

// Extent is one present logical range of a file. Exactly one source is set.
type Extent struct {
	// FileOffset is the logical byte offset the extent covers.
	FileOffset uint64
	// Length is the covered logical byte count, clamped to the inode's
	// logical EOF. A PFT2 cell always verifies all CellBytes canonical bytes
	// (zero suffix included); Length reports how many are logically valid.
	Length uint64
	// Cell references a PFT2 packed 4 KiB cell.
	Cell *CellRef
	// Legacy references a byte range of an old whole-file/chunk object.
	Legacy *LegacyExtent
}

// LegacyExtent references bytes inside a legacy (pre-PFT2) content object,
// identified by the legacy digest string namespace (for example
// "sha256:<hex>"). Only whole-object digests verify legacy bytes.
type LegacyExtent struct {
	ObjectDigest string
	ObjectSize   uint64
	ObjectOffset uint64
}

// ReadBounds bounds one BaseTree operation. Budget is charged per logical
// node VISIT — cache hits and the lazily resolved ROOT object included — so
// an operation's cost is deterministic and independent of cache history or
// prior operations; exceeding any bound fails typed with ErrBoundExceeded
// rather than allocating further.
type ReadBounds struct {
	// MaxNodes bounds visited nodes per operation (default 64).
	MaxNodes int
	// MaxBytes bounds visited encoded bytes per operation (default 8 MiB).
	MaxBytes int64
	// MaxDepth bounds tree depth per walk (default and ceiling MaxTreeDepth).
	MaxDepth int
}

func (b ReadBounds) withDefaults() ReadBounds {
	if b.MaxNodes <= 0 {
		b.MaxNodes = 64
	}
	if b.MaxBytes <= 0 {
		b.MaxBytes = 8 << 20
	}
	if b.MaxDepth <= 0 || b.MaxDepth > MaxTreeDepth {
		b.MaxDepth = MaxTreeDepth
	}
	return b
}

// TreeReaderConfig configures a lazy PFT2 reader.
type TreeReaderConfig struct {
	// Fetcher retrieves object bytes (required).
	Fetcher Fetcher
	// CacheBytes budgets the digest-keyed immutable decoded-node cache
	// (default 32 MiB; <0 disables caching).
	CacheBytes int64
	// MaxConcurrentFetches bounds simultaneous Fetcher calls (default 8).
	// Identical in-flight references additionally coalesce (singleflight).
	MaxConcurrentFetches int
	// Bounds are the per-operation read bounds.
	Bounds ReadBounds
}

// TreeReader is the production lazy BaseTree over PFT2 objects. It never
// allocates a full manifest: every operation walks only the nodes it needs,
// under explicit node/byte/depth bounds, through a digest-keyed immutable
// cache with singleflight fetch coalescing.
type TreeReader struct {
	fetcher Fetcher
	bounds  ReadBounds
	sem     chan struct{}

	cache *nodeCache

	flightMu sync.Mutex
	flight   map[Ref]*flightCall

	rootRef Ref
	rootMu  sync.Mutex
	root    *Root // verified filesystem root, resolved lazily once
}

type flightCall struct {
	done chan struct{}
	node *Node
	size int64
	err  error
}

// NewTreeReader creates a lazy reader anchored at the filesystem ROOT
// reference. The root object is fetched and verified lazily on first use
// (lazy cold start).
func NewTreeReader(cfg TreeReaderConfig, root Ref) (*TreeReader, error) {
	if cfg.Fetcher == nil {
		return nil, invalidf("tree reader requires a fetcher")
	}
	if err := checkNodeRefBounds("tree root", root); err != nil {
		return nil, err
	}
	cacheBytes := cfg.CacheBytes
	if cacheBytes == 0 {
		cacheBytes = 32 << 20
	}
	maxFetches := cfg.MaxConcurrentFetches
	if maxFetches <= 0 {
		maxFetches = 8
	}
	return &TreeReader{
		fetcher: cfg.Fetcher,
		bounds:  cfg.Bounds.withDefaults(),
		sem:     make(chan struct{}, maxFetches),
		cache:   newNodeCache(cacheBytes),
		flight:  map[Ref]*flightCall{},
		rootRef: root,
	}, nil
}

// op tracks one operation's remaining budget.
type op struct {
	nodesLeft int
	bytesLeft int64
	maxDepth  int
}

func (r *TreeReader) newOp() *op {
	return &op{nodesLeft: r.bounds.MaxNodes, bytesLeft: r.bounds.MaxBytes, maxDepth: r.bounds.MaxDepth}
}

func (o *op) charge(size uint64) error {
	if o.nodesLeft <= 0 || o.bytesLeft < int64(size) {
		return boundExceededf("node/byte budget exhausted")
	}
	o.nodesLeft--
	o.bytesLeft -= int64(size)
	return nil
}

func boundExceededf(format string, args ...any) error {
	return &boundError{fmt.Sprintf(format, args...)}
}

type boundError struct{ msg string }

func (e *boundError) Error() string { return "pft2: read bound exceeded: " + e.msg }
func (e *boundError) Is(target error) bool {
	return target == ErrBoundExceeded
}

func notFoundf(format string, args ...any) error {
	return &notFoundError{fmt.Sprintf(format, args...)}
}

type notFoundError struct{ msg string }

func (e *notFoundError) Error() string        { return "pft2: not found: " + e.msg }
func (e *notFoundError) Is(target error) bool { return target == ErrNotFound }

// fetchNode returns the verified decoded node for ref, requiring one of the
// allowed kinds for the edge it was reached through. Size bounds check first,
// then the (possibly coalesced) fetch verifies exact size and digest before
// decode; decoded nodes are immutable and shared through the cache.
func (r *TreeReader) fetchNode(ctx context.Context, o *op, ref Ref, allowed ...Kind) (*Node, error) {
	if err := checkNodeRefBounds("fetch", ref); err != nil {
		return nil, err
	}
	if err := o.charge(ref.Size); err != nil {
		return nil, err
	}
	node, err := r.loadNode(ctx, ref)
	if err != nil {
		return nil, err
	}
	for _, kind := range allowed {
		if node.Kind == kind {
			return node, nil
		}
	}
	return nil, corruptf("object %s: kind %s not valid for this edge", ref.Hex(), node.Kind)
}

func (r *TreeReader) loadNode(ctx context.Context, ref Ref) (*Node, error) {
	for {
		if node, ok := r.cache.get(ref); ok {
			return node, nil
		}
		r.flightMu.Lock()
		if call, inflight := r.flight[ref]; inflight {
			r.flightMu.Unlock()
			select {
			case <-call.done:
				if call.err != nil {
					// A CANCELED leader's context error is not evidence about
					// the object or the store; a still-live waiter retries as
					// the next leader (the flight was already cleared).
					// Integrity/store failures are shared by every waiter.
					if (errors.Is(call.err, context.Canceled) ||
						errors.Is(call.err, context.DeadlineExceeded)) && ctx.Err() == nil {
						continue
					}
					return nil, call.err
				}
				return call.node, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		call := &flightCall{done: make(chan struct{})}
		r.flight[ref] = call
		r.flightMu.Unlock()

		call.node, call.size, call.err = r.fetchVerifyDecode(ctx, ref)
		r.flightMu.Lock()
		delete(r.flight, ref)
		r.flightMu.Unlock()
		if call.err == nil {
			r.cache.add(ref, call.node, call.size)
		}
		close(call.done)
		if call.err != nil {
			return nil, call.err
		}
		return call.node, nil
	}
}

func (r *TreeReader) fetchVerifyDecode(ctx context.Context, ref Ref) (*Node, int64, error) {
	select {
	case r.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
	defer func() { <-r.sem }()
	data, err := r.fetcher.Fetch(ctx, ref)
	if err != nil {
		return nil, 0, err
	}
	if err := VerifyObjectBytes(ref, data); err != nil {
		return nil, 0, err
	}
	node, err := DecodeNode(data)
	if err != nil {
		return nil, 0, err
	}
	return node, int64(len(data)), nil
}

// loadRoot resolves and verifies the filesystem ROOT lazily once. The
// logical ROOT visit is charged on every operation — cached or not — so
// budget accounting is deterministic and independent of which operation
// happened to resolve the root first (and identical to the TypeScript
// reader); only the I/O is amortized.
func (r *TreeReader) loadRoot(ctx context.Context, o *op) (*Root, error) {
	if err := o.charge(r.rootRef.Size); err != nil {
		return nil, err
	}
	r.rootMu.Lock()
	defer r.rootMu.Unlock()
	if r.root != nil {
		return r.root, nil
	}
	node, err := r.loadNode(ctx, r.rootRef)
	if err != nil {
		return nil, err
	}
	if node.Kind != KindRoot {
		return nil, corruptf("object %s: kind %s not valid for the tree root", r.rootRef.Hex(), node.Kind)
	}
	r.root = node.Root
	return r.root, nil
}

// RootFacts returns a verified copy of the filesystem ROOT object's facts
// (allocation high-water, counts, index references) as one bounded
// operation: the root resolves through the same lazily cached, digest- and
// kind-verified load every walk uses, so a caller can bind externally
// proven facts (for example a database-proven MaxInoSeen) against the
// actual hashed object before serving anything.
func (r *TreeReader) RootFacts(ctx context.Context) (Root, error) {
	o := r.newOp()
	root, err := r.loadRoot(ctx, o)
	if err != nil {
		return Root{}, err
	}
	return *root, nil
}

// GetInode implements BaseTree via the numeric inode index. Every fetched
// descent verifies the child against its parent-advertised summary, and the
// index root verifies against the ROOT object's inode facts.
func (r *TreeReader) GetInode(ctx context.Context, ino uint64) (InodeView, error) {
	if ino < 1 || ino > MaxIno {
		return InodeView{}, invalidf("ino %d outside 1..%d", ino, MaxIno)
	}
	o := r.newOp()
	root, err := r.loadRoot(ctx, o)
	if err != nil {
		return InodeView{}, err
	}
	if ino > root.MaxInoSeen {
		return InodeView{}, notFoundf("ino beyond the allocation high-water")
	}
	ref := root.InodeIndex
	var edge *edgeSummary
	for depth := 1; ; depth++ {
		if depth > o.maxDepth {
			return InodeView{}, boundExceededf("inode index depth")
		}
		node, err := r.fetchNode(ctx, o, ref, KindInodeIndexLeaf, KindInodeIndexIndex)
		if err != nil {
			return InodeView{}, err
		}
		if edge == nil {
			err = verifyFSIndexRootFacts(root, ref, node)
		} else {
			err = verifyEdgeSummary("inode index child", ref, node, *edge)
		}
		if err != nil {
			return InodeView{}, err
		}
		if node.Kind == KindInodeIndexLeaf {
			for i := range node.InodeIndexLeaf.Entries {
				e := &node.InodeIndexLeaf.Entries[i]
				if e.Ino == ino {
					return r.resolveInode(ctx, o, e.Inode, ino)
				}
			}
			return InodeView{}, notFoundf("ino not in leaf")
		}
		child, ok := findInodeIndexChild(node.InodeIndexIndex, ino)
		if !ok {
			return InodeView{}, notFoundf("ino not covered by index")
		}
		summary := inodeChildSummary(child)
		edge = &summary
		ref = child.Child
	}
}

func findInodeIndexChild(x *InodeIndexIndex, ino uint64) (*InodeIndexChild, bool) {
	for i := range x.Children {
		c := &x.Children[i]
		if ino >= c.FirstIno && ino <= c.LastIno {
			return c, true
		}
	}
	return nil, false
}

func (r *TreeReader) resolveInode(ctx context.Context, o *op, ref Ref, wantIno uint64) (InodeView, error) {
	node, err := r.fetchNode(ctx, o, ref, KindInode)
	if err != nil {
		return InodeView{}, err
	}
	if node.Inode.Ino != wantIno {
		return InodeView{}, corruptf("inode object %s carries ino %d, index advertised %d",
			ref.Hex(), node.Inode.Ino, wantIno)
	}
	return InodeView{Ref: ref, Inode: *node.Inode}, nil
}

// directoryInode fetches an INODE handle and requires directory kind.
func (r *TreeReader) directoryInode(ctx context.Context, o *op, ref Ref) (*Inode, error) {
	node, err := r.fetchNode(ctx, o, ref, KindInode)
	if err != nil {
		return nil, err
	}
	if node.Inode.Kind != FileKindDirectory {
		return nil, corruptf("inode %d is %s, not a directory", node.Inode.Ino, node.Inode.Kind)
	}
	return node.Inode, nil
}

// Lookup implements BaseTree. Every fetched descent verifies the child
// against its parent-advertised summary; the directory root edge (from the
// inode) carries no advertisement, so only its kind is checkable there.
func (r *TreeReader) Lookup(ctx context.Context, parent Ref, name string) (DirEntry, error) {
	if err := ValidateEntryName(name); err != nil {
		return DirEntry{}, err
	}
	o := r.newOp()
	dir, err := r.directoryInode(ctx, o, parent)
	if err != nil {
		return DirEntry{}, err
	}
	if dir.DirectoryRoot == nil {
		return DirEntry{}, notFoundf("empty directory")
	}
	ref := *dir.DirectoryRoot
	var edge *edgeSummary
	for depth := 1; ; depth++ {
		if depth > o.maxDepth {
			return DirEntry{}, boundExceededf("directory depth")
		}
		node, err := r.fetchNode(ctx, o, ref, KindDirectoryLeaf, KindDirectoryIndex)
		if err != nil {
			return DirEntry{}, err
		}
		if edge != nil {
			if err := verifyEdgeSummary("directory child", ref, node, *edge); err != nil {
				return DirEntry{}, err
			}
		}
		if node.Kind == KindDirectoryLeaf {
			for i := range node.DirectoryLeaf.Entries {
				e := &node.DirectoryLeaf.Entries[i]
				if e.Name == name {
					return *e, nil
				}
			}
			return DirEntry{}, notFoundf("name not in leaf")
		}
		child, ok := findDirectoryChild(node.DirectoryIndex, name)
		if !ok {
			return DirEntry{}, notFoundf("name not covered by index")
		}
		summary := directoryChildSummary(child)
		edge = &summary
		ref = child.Child
	}
}

func findDirectoryChild(x *DirectoryIndex, name string) (*DirectoryIndexChild, bool) {
	for i := range x.Children {
		c := &x.Children[i]
		if name >= c.FirstName && name <= c.LastName {
			return c, true
		}
	}
	return nil, false
}

// ReadDir implements BaseTree. Paging never re-walks returned entries: index
// subtrees whose verified LastName is not above the cursor are skipped
// without fetching.
func (r *TreeReader) ReadDir(ctx context.Context, dir Ref, cursor string, limit int) ([]DirEntry, string, error) {
	if limit <= 0 {
		return nil, "", invalidf("readdir limit %d must be positive", limit)
	}
	o := r.newOp()
	inode, err := r.directoryInode(ctx, o, dir)
	if err != nil {
		return nil, "", err
	}
	if inode.DirectoryRoot == nil {
		return nil, "", nil
	}
	var out []DirEntry
	more, err := r.readDirWalk(ctx, o, *inode.DirectoryRoot, nil, 1, cursor, limit, &out)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if more && len(out) > 0 {
		next = out[len(out)-1].Name
	}
	return out, next, nil
}

// readDirWalk appends entries strictly above cursor until limit; the bool
// result reports whether more entries may remain. Every fetched child
// verifies against its parent-advertised summary (edge is nil only for the
// unadvertised directory root); subtrees skipped by the cursor are never
// fetched.
func (r *TreeReader) readDirWalk(
	ctx context.Context, o *op, ref Ref, edge *edgeSummary, depth int, cursor string, limit int, out *[]DirEntry,
) (bool, error) {
	if depth > o.maxDepth {
		return false, boundExceededf("directory depth")
	}
	node, err := r.fetchNode(ctx, o, ref, KindDirectoryLeaf, KindDirectoryIndex)
	if err != nil {
		return false, err
	}
	if edge != nil {
		if err := verifyEdgeSummary("directory child", ref, node, *edge); err != nil {
			return false, err
		}
	}
	if node.Kind == KindDirectoryLeaf {
		for i := range node.DirectoryLeaf.Entries {
			e := &node.DirectoryLeaf.Entries[i]
			if e.Name <= cursor {
				continue
			}
			if len(*out) >= limit {
				return true, nil
			}
			*out = append(*out, *e)
		}
		return false, nil
	}
	for i := range node.DirectoryIndex.Children {
		c := &node.DirectoryIndex.Children[i]
		if c.LastName <= cursor {
			continue
		}
		childEdge := directoryChildSummary(c)
		more, err := r.readDirWalk(ctx, o, c.Child, &childEdge, depth+1, cursor, limit, out)
		if err != nil {
			return false, err
		}
		if more {
			return true, nil
		}
		if len(*out) >= limit && i < len(node.DirectoryIndex.Children)-1 {
			return true, nil
		}
	}
	return false, nil
}

// ReadExtents implements BaseTree for PFT2 extent trees.
func (r *TreeReader) ReadExtents(ctx context.Context, file Ref, offset, length uint64) ([]Extent, error) {
	o := r.newOp()
	node, err := r.fetchNode(ctx, o, file, KindInode)
	if err != nil {
		return nil, err
	}
	inode := node.Inode
	if inode.Kind != FileKindRegular {
		return nil, corruptf("inode %d is %s, not a regular file", inode.Ino, inode.Kind)
	}
	window, ok := clampExtentWindow(inode.Size, offset, length)
	if !ok || inode.ExtentRoot == nil {
		return nil, nil
	}
	var out []Extent
	if err := r.extentWalk(ctx, o, *inode.ExtentRoot, nil, 1, inode.Size, window, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// byteWindow is a clamped half-open byte range plus its inclusive page span.
type byteWindow struct {
	start, end          uint64 // [start, end), end <= logical size
	firstPage, lastPage uint64 // inclusive PageBytes-aligned span
}

// clampExtentWindow clamps the requested byte range to logical EOF and
// derives the page span. All arithmetic rejects overflow before use.
func clampExtentWindow(size, offset, length uint64) (byteWindow, bool) {
	if length == 0 || offset >= size {
		return byteWindow{}, false
	}
	end := offset + length
	if end < offset || end > size {
		end = size
	}
	return byteWindow{
		start:     offset,
		end:       end,
		firstPage: offset / PageBytes * PageBytes,
		lastPage:  (end - 1) / PageBytes * PageBytes,
	}, true
}

// extentWalk collects window-overlapping extents. Every fetched child
// verifies against its parent-advertised summary (edge is nil only for the
// unadvertised extent root); subtrees outside the window are never fetched.
func (r *TreeReader) extentWalk(
	ctx context.Context, o *op, ref Ref, edge *edgeSummary, depth int, size uint64, window byteWindow, out *[]Extent,
) error {
	if depth > o.maxDepth {
		return boundExceededf("extent depth")
	}
	node, err := r.fetchNode(ctx, o, ref, KindExtentLeaf, KindExtentIndex)
	if err != nil {
		return err
	}
	if edge != nil {
		if err := verifyEdgeSummary("extent child", ref, node, *edge); err != nil {
			return err
		}
	}
	if node.Kind == KindExtentLeaf {
		for i := range node.ExtentLeaf.Entries {
			e := &node.ExtentLeaf.Entries[i]
			if e.PageOffset < window.firstPage || e.PageOffset > window.lastPage {
				continue
			}
			if e.PageOffset >= size {
				return corruptf("extent page %d at or beyond logical EOF %d", e.PageOffset, size)
			}
			if err := r.appendPageExtents(ctx, o, e, size, window, out); err != nil {
				return err
			}
		}
		return nil
	}
	for i := range node.ExtentIndex.Children {
		c := &node.ExtentIndex.Children[i]
		if c.LastPage < window.firstPage || c.FirstPage > window.lastPage {
			continue
		}
		childEdge := extentChildSummary(c)
		if err := r.extentWalk(ctx, o, c.Child, &childEdge, depth+1, size, window, out); err != nil {
			return err
		}
	}
	return nil
}

func (r *TreeReader) appendPageExtents(
	ctx context.Context, o *op, entry *ExtentEntry, size uint64, window byteWindow, out *[]Extent,
) error {
	node, err := r.fetchNode(ctx, o, entry.Page, KindDataPage)
	if err != nil {
		return err
	}
	for cellIndex, cell := range node.DataPage.Cells {
		if cell == nil {
			continue
		}
		cellStart := entry.PageOffset + uint64(cellIndex)*CellBytes
		if cellStart >= size {
			return corruptf("data page %s cell %d at or beyond logical EOF %d",
				entry.Page.Hex(), cellIndex, size)
		}
		// Only cells overlapping the requested byte window are returned.
		if cellStart+CellBytes <= window.start || cellStart >= window.end {
			continue
		}
		logical := uint64(CellBytes)
		if cellStart+logical > size {
			logical = size - cellStart
		}
		cellCopy := *cell
		*out = append(*out, Extent{FileOffset: cellStart, Length: logical, Cell: &cellCopy})
	}
	return nil
}

// VerifyCellBytes extracts and verifies one cell's canonical CellBytes
// logical bytes from its fetched (and already object-digest-verified) pack
// bytes. logicalEOFOffset is the count of logically valid bytes in this cell
// (CellBytes for interior cells); the suffix beyond it must be canonically
// zero, enforcing the terminal-zeroing invariant before bytes publish.
func VerifyCellBytes(cell *CellRef, packBytes []byte, logicalValid uint64) ([]byte, error) {
	if err := cell.validate(); err != nil {
		return nil, err
	}
	if uint64(len(packBytes)) != cell.Object.Size {
		return nil, corruptf("pack %s: fetched %d bytes, advertised %d",
			cell.Object.Hex(), len(packBytes), cell.Object.Size)
	}
	slice := packBytes[cell.ObjectOffset : cell.ObjectOffset+CellBytes]
	if RefOf(slice).Digest != cell.CellDigest {
		return nil, corruptf("pack %s: cell slice at %d fails its logical digest",
			cell.Object.Hex(), cell.ObjectOffset)
	}
	if logicalValid > CellBytes {
		return nil, invalidf("logical valid %d exceeds cell size %d", logicalValid, CellBytes)
	}
	if !IsZeroCell(slice[logicalValid:]) {
		return nil, corruptf("pack %s: cell slice at %d has nonzero bytes beyond logical EOF",
			cell.Object.Hex(), cell.ObjectOffset)
	}
	return slice, nil
}

// ─── digest-keyed immutable decoded-node cache ──────────────────────────────

type nodeCache struct {
	mu       sync.Mutex
	maxBytes int64
	curBytes int64
	ll       *list.List
	items    map[Ref]*list.Element
}

type nodeCacheEntry struct {
	ref  Ref
	node *Node
	size int64
}

func newNodeCache(maxBytes int64) *nodeCache {
	return &nodeCache{maxBytes: maxBytes, ll: list.New(), items: map[Ref]*list.Element{}}
}

func (c *nodeCache) get(ref Ref) (*Node, bool) {
	if c.maxBytes <= 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[ref]
	if !ok {
		return nil, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*nodeCacheEntry).node, true
}

func (c *nodeCache) add(ref Ref, node *Node, size int64) {
	if c.maxBytes <= 0 || size > c.maxBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.items[ref]; exists {
		return
	}
	el := c.ll.PushFront(&nodeCacheEntry{ref: ref, node: node, size: size})
	c.items[ref] = el
	c.curBytes += size
	for c.curBytes > c.maxBytes {
		back := c.ll.Back()
		if back == nil {
			break
		}
		entry := back.Value.(*nodeCacheEntry)
		c.ll.Remove(back)
		delete(c.items, entry.ref)
		c.curBytes -= entry.size
	}
}
