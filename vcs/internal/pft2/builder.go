package pft2

import (
	"bytes"
	"crypto/sha256"

	"github.com/trendup-ai/portablefs/vcs/internal/pfwire"
)

// NodeSink persists one encoded metadata node. Builders compute the reference
// themselves (RefOf over the exact bytes); the sink only stores. Sinks are
// invoked synchronously in deterministic build order. Nothing here touches an
// object store on a mutation path: builders run in HistoryCut/materializer
// context and the caller decides where bytes go.
type NodeSink interface {
	PutNode(ref Ref, encoded []byte) error
}

// PackSink persists one packed immutable data object.
type PackSink interface {
	PutPack(ref Ref, data []byte) error
}

// ─── deterministic B+tree construction ──────────────────────────────────────
//
// FROZEN CONSTRUCTION RULE (canonical-root determinism): elements are packed
// left to right; a node closes when it already holds the level's maximum
// element count or when appending the next element would push its element
// region (the sum of every element's length-delimited encoded size at
// field 1) beyond TargetNodeBytes. On index levels, if the final run holds
// fewer than MinIndexChildren children, children move from the end of the
// previous run until it holds exactly MinIndexChildren (a size-closed run
// always holds far more than MinIndexChildren, so the donor stays valid). A
// level of one node is the root; an index node never has one child. The same
// ordered element sequence therefore always produces the same tree,
// independent of worker count or scheduling.

type levelChild struct {
	summary []byte // encoded child-summary message for the parent level
	ref     Ref
}

func shouldClose(currentBytes, elemBytes, count, maxCount int) bool {
	return count > 0 && (count >= maxCount || currentBytes+elemBytes > TargetNodeBytes)
}

// chunkRun splits ordered elements into [start, end) runs under the frozen
// rule. elemBytes reports each element's encoded field-1 size.
func chunkRun(elementCount, maxCount int, elemBytes func(i int) int) [][2]int {
	var runs [][2]int
	start := 0
	currentBytes := 0
	for i := 0; i < elementCount; i++ {
		size := elemBytes(i)
		if shouldClose(currentBytes, size, i-start, maxCount) {
			runs = append(runs, [2]int{start, i})
			start = i
			currentBytes = 0
		}
		currentBytes += size
	}
	if elementCount > start {
		runs = append(runs, [2]int{start, elementCount})
	}
	return runs
}

// chunkLeaves is the leaf-level rule (minimum one element per leaf).
func chunkLeaves(elementCount int, elemBytes func(i int) int) [][2]int {
	return chunkRun(elementCount, MaxLeafEntries, elemBytes)
}

// chunkIndex is the index-level rule, with the frozen tail rebalance.
func chunkIndex(elementCount int, elemBytes func(i int) int) [][2]int {
	runs := chunkRun(elementCount, MaxIndexChildren, elemBytes)
	if len(runs) >= 2 {
		last := &runs[len(runs)-1]
		if last[1]-last[0] < MinIndexChildren {
			shift := MinIndexChildren - (last[1] - last[0])
			runs[len(runs)-2][1] -= shift
			last[0] -= shift
		}
	}
	return runs
}

// buildLevels stacks index levels over the given leaf level until one root
// remains. makeIndex encodes one index node from a contiguous child run.
// The depth counter is absolute: bulk builds start from real leaves, so
// level one is leaf height one.
func buildLevels(
	leaves []levelChild,
	sink NodeSink,
	makeIndex func(children []levelChild) (*Node, error),
	summarize func(node *Node, ref Ref) (levelChild, error),
) (Ref, error) {
	level := leaves
	depth := 1
	for len(level) > 1 {
		depth++
		if depth > MaxTreeDepth {
			return Ref{}, invalidf("tree exceeds max depth %d", MaxTreeDepth)
		}
		runs := chunkIndex(len(level), func(i int) int {
			return pfwire.SizeTagged(1, len(level[i].summary))
		})
		next := make([]levelChild, 0, len(runs))
		for _, run := range runs {
			node, err := makeIndex(level[run[0]:run[1]])
			if err != nil {
				return Ref{}, err
			}
			encoded, err := EncodeNode(node)
			if err != nil {
				return Ref{}, err
			}
			ref := RefOf(encoded)
			if err := sink.PutNode(ref, encoded); err != nil {
				return Ref{}, err
			}
			child, err := summarize(node, ref)
			if err != nil {
				return Ref{}, err
			}
			next = append(next, child)
		}
		level = next
	}
	return level[0].ref, nil
}

// BuildDirectoryTree deterministically builds a directory B+tree from entries
// sorted strictly ascending by raw name bytes. It returns the root reference
// (nil for an empty directory) and the total entry count.
func BuildDirectoryTree(entries []DirEntry, sink NodeSink) (*Ref, uint64, error) {
	if len(entries) == 0 {
		return nil, 0, nil
	}
	for i := range entries {
		if i > 0 && entries[i-1].Name >= entries[i].Name {
			return nil, 0, invalidf("directory build: entry %d name %q not strictly above %q",
				i, entries[i].Name, entries[i-1].Name)
		}
	}
	runs := chunkLeaves(len(entries), func(i int) int {
		return pfwire.SizeTagged(1, len(appendDirEntry(nil, &entries[i])))
	})
	var leaves []levelChild
	for _, run := range runs {
		leaf := &DirectoryLeaf{Entries: entries[run[0]:run[1]]}
		node := &Node{Kind: KindDirectoryLeaf, DirectoryLeaf: leaf}
		encoded, err := EncodeNode(node)
		if err != nil {
			return nil, 0, err
		}
		ref := RefOf(encoded)
		if err := sink.PutNode(ref, encoded); err != nil {
			return nil, 0, err
		}
		child := DirectoryIndexChild{
			FirstName:  leaf.Entries[0].Name,
			LastName:   leaf.Entries[len(leaf.Entries)-1].Name,
			Child:      ref,
			EntryCount: uint64(len(leaf.Entries)),
		}
		leaves = append(leaves, levelChild{summary: encodeDirectoryIndexChild(&child), ref: ref})
	}
	root, err := buildLevels(leaves, sink,
		func(children []levelChild) (*Node, error) {
			x := &DirectoryIndex{}
			for i := range children {
				c, err := decodeDirectoryIndexChild(children[i].summary)
				if err != nil {
					return nil, err
				}
				x.Children = append(x.Children, c)
			}
			return &Node{Kind: KindDirectoryIndex, DirectoryIndex: x}, nil
		},
		func(node *Node, ref Ref) (levelChild, error) {
			x := node.DirectoryIndex
			summary, err := nodeSummary(node)
			if err != nil {
				return levelChild{}, err
			}
			child := DirectoryIndexChild{
				FirstName:  x.Children[0].FirstName,
				LastName:   x.Children[len(x.Children)-1].LastName,
				Child:      ref,
				EntryCount: summary.count,
			}
			return levelChild{summary: encodeDirectoryIndexChild(&child), ref: ref}, nil
		})
	if err != nil {
		return nil, 0, err
	}
	return &root, uint64(len(entries)), nil
}

func encodeDirectoryIndexChild(c *DirectoryIndexChild) []byte {
	child := pfwire.AppendString(nil, 1, c.FirstName)
	child = pfwire.AppendString(child, 2, c.LastName)
	child = appendRef(child, 3, c.Child)
	child = pfwire.AppendUint(child, 4, c.EntryCount)
	return child
}

// BuildExtentTree deterministically builds an extent B+tree from entries
// sorted strictly ascending by page offset. It returns the root reference
// (nil when there are no present pages) and the present-page count.
func BuildExtentTree(entries []ExtentEntry, sink NodeSink) (*Ref, uint64, error) {
	if len(entries) == 0 {
		return nil, 0, nil
	}
	for i := range entries {
		if i > 0 && entries[i-1].PageOffset >= entries[i].PageOffset {
			return nil, 0, invalidf("extent build: entry %d offset %d not strictly above %d",
				i, entries[i].PageOffset, entries[i-1].PageOffset)
		}
	}
	encodeEntry := func(e *ExtentEntry) []byte {
		entry := pfwire.AppendUint(nil, 1, e.PageOffset)
		return appendRef(entry, 2, e.Page)
	}
	runs := chunkLeaves(len(entries), func(i int) int {
		return pfwire.SizeTagged(1, len(encodeEntry(&entries[i])))
	})
	var leaves []levelChild
	for _, run := range runs {
		leaf := &ExtentLeaf{Entries: entries[run[0]:run[1]]}
		node := &Node{Kind: KindExtentLeaf, ExtentLeaf: leaf}
		encoded, err := EncodeNode(node)
		if err != nil {
			return nil, 0, err
		}
		ref := RefOf(encoded)
		if err := sink.PutNode(ref, encoded); err != nil {
			return nil, 0, err
		}
		child := ExtentIndexChild{
			FirstPage:  leaf.Entries[0].PageOffset,
			LastPage:   leaf.Entries[len(leaf.Entries)-1].PageOffset,
			Child:      ref,
			EntryCount: uint64(len(leaf.Entries)),
		}
		leaves = append(leaves, levelChild{summary: encodeExtentIndexChild(&child), ref: ref})
	}
	root, err := buildLevels(leaves, sink,
		func(children []levelChild) (*Node, error) {
			x := &ExtentIndex{}
			for i := range children {
				c, err := decodeExtentIndexChild(children[i].summary)
				if err != nil {
					return nil, err
				}
				x.Children = append(x.Children, c)
			}
			return &Node{Kind: KindExtentIndex, ExtentIndex: x}, nil
		},
		func(node *Node, ref Ref) (levelChild, error) {
			x := node.ExtentIndex
			summary, err := nodeSummary(node)
			if err != nil {
				return levelChild{}, err
			}
			child := ExtentIndexChild{
				FirstPage:  x.Children[0].FirstPage,
				LastPage:   x.Children[len(x.Children)-1].LastPage,
				Child:      ref,
				EntryCount: summary.count,
			}
			return levelChild{summary: encodeExtentIndexChild(&child), ref: ref}, nil
		})
	if err != nil {
		return nil, 0, err
	}
	return &root, uint64(len(entries)), nil
}

func encodeExtentIndexChild(c *ExtentIndexChild) []byte {
	child := pfwire.AppendUint(nil, 1, c.FirstPage)
	child = pfwire.AppendUint(child, 2, c.LastPage)
	child = appendRef(child, 3, c.Child)
	return pfwire.AppendUint(child, 4, c.EntryCount)
}

// BuildInodeIndexTree deterministically builds an inode-index B+tree from
// entries sorted strictly ascending by ino. It returns the root reference
// (nil when empty) and the entry count.
func BuildInodeIndexTree(entries []InodeIndexEntry, sink NodeSink) (*Ref, uint64, error) {
	if len(entries) == 0 {
		return nil, 0, nil
	}
	for i := range entries {
		if i > 0 && entries[i-1].Ino >= entries[i].Ino {
			return nil, 0, invalidf("inode index build: entry %d ino %d not strictly above %d",
				i, entries[i].Ino, entries[i-1].Ino)
		}
	}
	encodeEntry := func(e *InodeIndexEntry) []byte {
		entry := pfwire.AppendUint(nil, 1, e.Ino)
		return appendRef(entry, 2, e.Inode)
	}
	runs := chunkLeaves(len(entries), func(i int) int {
		return pfwire.SizeTagged(1, len(encodeEntry(&entries[i])))
	})
	var leaves []levelChild
	for _, run := range runs {
		leaf := &InodeIndexLeaf{Entries: entries[run[0]:run[1]]}
		node := &Node{Kind: KindInodeIndexLeaf, InodeIndexLeaf: leaf}
		encoded, err := EncodeNode(node)
		if err != nil {
			return nil, 0, err
		}
		ref := RefOf(encoded)
		if err := sink.PutNode(ref, encoded); err != nil {
			return nil, 0, err
		}
		child := InodeIndexChild{
			FirstIno:   leaf.Entries[0].Ino,
			LastIno:    leaf.Entries[len(leaf.Entries)-1].Ino,
			Child:      ref,
			EntryCount: uint64(len(leaf.Entries)),
		}
		leaves = append(leaves, levelChild{summary: encodeInodeIndexChild(&child), ref: ref})
	}
	root, err := buildLevels(leaves, sink,
		func(children []levelChild) (*Node, error) {
			x := &InodeIndexIndex{}
			for i := range children {
				c, err := decodeInodeIndexChild(children[i].summary)
				if err != nil {
					return nil, err
				}
				x.Children = append(x.Children, c)
			}
			return &Node{Kind: KindInodeIndexIndex, InodeIndexIndex: x}, nil
		},
		func(node *Node, ref Ref) (levelChild, error) {
			x := node.InodeIndexIndex
			summary, err := nodeSummary(node)
			if err != nil {
				return levelChild{}, err
			}
			child := InodeIndexChild{
				FirstIno:   x.Children[0].FirstIno,
				LastIno:    x.Children[len(x.Children)-1].LastIno,
				Child:      ref,
				EntryCount: summary.count,
			}
			return levelChild{summary: encodeInodeIndexChild(&child), ref: ref}, nil
		})
	if err != nil {
		return nil, 0, err
	}
	return &root, uint64(len(entries)), nil
}

func encodeInodeIndexChild(c *InodeIndexChild) []byte {
	child := pfwire.AppendUint(nil, 1, c.FirstIno)
	child = pfwire.AppendUint(child, 2, c.LastIno)
	child = appendRef(child, 3, c.Child)
	return pfwire.AppendUint(child, 4, c.EntryCount)
}

// BuildControlTree deterministically builds a control-map B+tree from entries
// sorted strictly ascending by raw key bytes. It returns the root reference
// (nil when empty), the entry count, and the ascending per-kind counts for
// the ControlRoot.
func BuildControlTree(entries []ControlEntry, sink NodeSink) (*Ref, uint64, []ControlKindCount, error) {
	if len(entries) == 0 {
		return nil, 0, nil, nil
	}
	for i := range entries {
		if i > 0 && bytes.Compare(entries[i-1].Key, entries[i].Key) >= 0 {
			return nil, 0, nil, invalidf("control build: entry %d key not strictly above previous", i)
		}
	}
	encodeEntry := func(e *ControlEntry) []byte {
		entry := pfwire.AppendBytes(nil, 1, e.Key)
		entry = pfwire.AppendUint(entry, 2, e.Kind)
		return pfwire.AppendBytes(entry, 3, e.Value)
	}
	runs := chunkLeaves(len(entries), func(i int) int {
		return pfwire.SizeTagged(1, len(encodeEntry(&entries[i])))
	})
	var leaves []levelChild
	for _, run := range runs {
		leaf := &ControlLeaf{Entries: entries[run[0]:run[1]]}
		node := &Node{Kind: KindControlLeaf, ControlLeaf: leaf}
		encoded, err := EncodeNode(node)
		if err != nil {
			return nil, 0, nil, err
		}
		ref := RefOf(encoded)
		if err := sink.PutNode(ref, encoded); err != nil {
			return nil, 0, nil, err
		}
		child := ControlIndexChild{
			FirstKey:   leaf.Entries[0].Key,
			LastKey:    leaf.Entries[len(leaf.Entries)-1].Key,
			Child:      ref,
			EntryCount: uint64(len(leaf.Entries)),
		}
		leaves = append(leaves, levelChild{summary: encodeControlIndexChild(&child), ref: ref})
	}
	root, err := buildLevels(leaves, sink,
		func(children []levelChild) (*Node, error) {
			x := &ControlIndex{}
			for i := range children {
				c, err := decodeControlIndexChild(children[i].summary)
				if err != nil {
					return nil, err
				}
				x.Children = append(x.Children, c)
			}
			return &Node{Kind: KindControlIndex, ControlIndex: x}, nil
		},
		func(node *Node, ref Ref) (levelChild, error) {
			x := node.ControlIndex
			summary, err := nodeSummary(node)
			if err != nil {
				return levelChild{}, err
			}
			child := ControlIndexChild{
				FirstKey:   x.Children[0].FirstKey,
				LastKey:    x.Children[len(x.Children)-1].LastKey,
				Child:      ref,
				EntryCount: summary.count,
			}
			return levelChild{summary: encodeControlIndexChild(&child), ref: ref}, nil
		})
	if err != nil {
		return nil, 0, nil, err
	}
	counts := controlKindCounts(entries)
	return &root, uint64(len(entries)), counts, nil
}

func encodeControlIndexChild(c *ControlIndexChild) []byte {
	child := pfwire.AppendBytes(nil, 1, c.FirstKey)
	child = pfwire.AppendBytes(child, 2, c.LastKey)
	child = appendRef(child, 3, c.Child)
	return pfwire.AppendUint(child, 4, c.EntryCount)
}

func controlKindCounts(entries []ControlEntry) []ControlKindCount {
	byKind := map[uint64]uint64{}
	for i := range entries {
		byKind[entries[i].Kind]++
	}
	var counts []ControlKindCount
	for kind := uint64(1); kind <= MaxControlEntryKind; kind++ {
		if n := byKind[kind]; n > 0 {
			counts = append(counts, ControlKindCount{Kind: kind, Count: n})
		}
	}
	return counts
}

// ─── deterministic cell packing ──────────────────────────────────────────────

// IsZeroCell reports whether every byte is zero (the cell is canonically a
// hole).
func IsZeroCell(cell []byte) bool {
	for _, b := range cell {
		if b != 0 {
			return false
		}
	}
	return true
}

// CellPacker packs changed nonzero cells into immutable data objects under
// the frozen deterministic policy: cells are appended in ascending
// (inode, pageOffset, cellIndex) order (the caller owns that ordering); every
// pack except the last closes at exactly MaxPackBytes; the terminal pack may
// be underfilled in exact CellBytes increments (>= MinPackBytes). Boundaries
// are therefore a pure function of the ordered cell sequence, independent of
// worker count and scheduling.
type CellPacker struct {
	packs    [][]byte // sealed full packs
	current  []byte
	perPack  []int // pack index per added cell
	perOff   []uint64
	digests  [][DigestBytes]byte
	finished bool
}

// NewCellPacker creates an empty packer.
func NewCellPacker() *CellPacker { return &CellPacker{} }

// Add appends the canonical CellBytes logical bytes of one changed nonzero
// cell and returns its index for resolving the CellRef after Finish. All-zero
// cells are holes and must not be added.
func (p *CellPacker) Add(cell []byte) (int, error) {
	if p.finished {
		return 0, invalidf("cell packer: add after finish")
	}
	if len(cell) != CellBytes {
		return 0, invalidf("cell packer: cell is %d bytes (want %d)", len(cell), CellBytes)
	}
	if IsZeroCell(cell) {
		return 0, invalidf("cell packer: all-zero cell must be a hole")
	}
	if len(p.current)+CellBytes > MaxPackBytes {
		p.packs = append(p.packs, p.current)
		p.current = nil
	}
	index := len(p.perPack)
	p.perPack = append(p.perPack, len(p.packs))
	p.perOff = append(p.perOff, uint64(len(p.current)))
	p.digests = append(p.digests, sha256.Sum256(cell))
	p.current = append(p.current, cell...)
	return index, nil
}

// Finish seals the terminal pack, persists every pack through sink in
// deterministic order, and returns one CellRef per added cell (in add order).
func (p *CellPacker) Finish(sink PackSink) ([]CellRef, error) {
	if p.finished {
		return nil, invalidf("cell packer: double finish")
	}
	p.finished = true
	packs := p.packs
	if len(p.current) > 0 {
		packs = append(packs, p.current)
	}
	refs := make([]Ref, len(packs))
	for i, pack := range packs {
		ref := RefOf(pack)
		if err := checkPackRefBounds("cell packer pack", ref); err != nil {
			return nil, err
		}
		if err := sink.PutPack(ref, pack); err != nil {
			return nil, err
		}
		refs[i] = ref
	}
	cells := make([]CellRef, len(p.perPack))
	for i := range p.perPack {
		cells[i] = CellRef{
			CellDigest:   p.digests[i],
			Object:       refs[p.perPack[i]],
			ObjectOffset: p.perOff[i],
		}
	}
	return cells, nil
}

// BuildFileExtents materializes one file's complete logical bytes into
// canonical PFT2 form: content splits into PageBytes pages of CellsPerPage
// cells; the terminal cell is zero-padded to CellBytes (bytes beyond EOF are
// canonically zero); all-zero cells become holes; all-hole pages are omitted;
// remaining cells pack in ascending (pageOffset, cellIndex) order through one
// CellPacker; DATA_PAGE nodes and the extent tree build deterministically. It
// returns the extent root (nil when every byte is zero or content is empty).
//
// Cross-file packing for a whole cut orders cells by (inode, pageOffset,
// cellIndex); this single-file helper is that policy's inode-local slice.
func BuildFileExtents(content []byte, nodes NodeSink, packs PackSink) (*Ref, error) {
	if uint64(len(content)) > MaxLogicalFileBytes {
		return nil, invalidf("file content %d bytes exceeds %d", len(content), MaxLogicalFileBytes)
	}
	type pendingCell struct {
		pageOffset uint64
		cellIndex  int
		packIndex  int
	}
	packer := NewCellPacker()
	var pending []pendingCell
	for pageOffset := uint64(0); pageOffset < uint64(len(content)); pageOffset += PageBytes {
		for cellIndex := 0; cellIndex < CellsPerPage; cellIndex++ {
			cellStart := pageOffset + uint64(cellIndex)*CellBytes
			if cellStart >= uint64(len(content)) {
				break
			}
			cellEnd := cellStart + CellBytes
			var cell []byte
			if cellEnd <= uint64(len(content)) {
				cell = content[cellStart:cellEnd]
			} else {
				padded := make([]byte, CellBytes)
				copy(padded, content[cellStart:])
				cell = padded
			}
			if IsZeroCell(cell) {
				continue
			}
			packIndex, err := packer.Add(cell)
			if err != nil {
				return nil, err
			}
			pending = append(pending, pendingCell{pageOffset, cellIndex, packIndex})
		}
	}
	if len(pending) == 0 {
		return nil, nil
	}
	cellRefs, err := packer.Finish(packs)
	if err != nil {
		return nil, err
	}
	var entries []ExtentEntry
	for start := 0; start < len(pending); {
		pageOffset := pending[start].pageOffset
		end := start
		page := &DataPage{}
		for end < len(pending) && pending[end].pageOffset == pageOffset {
			cell := cellRefs[pending[end].packIndex]
			page.Cells[pending[end].cellIndex] = &cell
			end++
		}
		node := &Node{Kind: KindDataPage, DataPage: page}
		encoded, err := EncodeNode(node)
		if err != nil {
			return nil, err
		}
		ref := RefOf(encoded)
		if err := nodes.PutNode(ref, encoded); err != nil {
			return nil, err
		}
		entries = append(entries, ExtentEntry{PageOffset: pageOffset, Page: ref})
		start = end
	}
	root, _, err := BuildExtentTree(entries, nodes)
	if err != nil {
		return nil, err
	}
	return root, nil
}
