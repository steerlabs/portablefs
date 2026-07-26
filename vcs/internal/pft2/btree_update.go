package pft2

import (
	"bytes"
	"context"

	"github.com/trendup-ai/portablefs/vcs/internal/pfwire"
)

// Incremental (path-copy) B+tree maintenance shared by directory, extent,
// and inode-index trees.
//
// FROZEN INCREMENTAL UPDATE RULE (canonical across implementations, given
// one base tree plus one final coalesced edit set):
//
//  1. Edits are applied in ascending key order. At an index node, edit key k
//     routes to the first child whose verified last key is >= k; keys above
//     every child's last key route to the last child. Children without edits
//     are never fetched and their references are reused byte for byte.
//  2. A run of CONTIGUOUS edited leaf children of one index node (or a lone
//     routed leaf) rewrites jointly: the run's final entries re-chunk as one
//     sequence under the bulk builder's frozen greedy rule. Splits and
//     merges therefore both fall out of one rule, and an empty result
//     removes the run. A single-leaf run that reproduces its input keeps
//     the base reference.
//  3. An index node splices the replacement summaries of its edited children
//     in place. If the spliced child list is empty the node is removed; a
//     single surviving child replaces the node (collapse); a list within
//     bounds rewrites one node; an oversized list re-chunks under the frozen
//     greedy index rule with its tail rebalance.
//  4. If the root's replacement list holds more than one summary, greedy
//     index levels stack on top until one root remains (exactly the bulk
//     builder's level rule). Merging never reaches across different parent
//     index nodes; underfilled but valid nodes persist until their entries
//     change again.
//
// The output is therefore a pure function of (base bytes, final edit set) —
// independent of edit order, worker count, retry, or resume — while touching
// only routed paths.

// btreeItem is one leaf element with its opaque ordering key.
type btreeItem struct {
	key   []byte
	value any
}

// btreeChild is one index-child summary with opaque ordering keys. A child
// with entryCount 0 is the unadvertised root-edge sentinel (real edges
// always advertise >= 1): it carries no summary to verify against.
type btreeChild struct {
	firstKey   []byte
	lastKey    []byte
	ref        Ref
	entryCount uint64
	// height is a conservative upper bound on the referenced subtree's
	// height (a leaf is height 1). heightExact marks heights proven exact:
	// newly built subtrees and fetched leaves. Unfetched base children carry
	// the readable-tree bound MaxTreeDepth-depth derived from their base
	// depth, because the frozen wire format carries no height information.
	height      int
	heightExact bool
	// resolvable marks a raw base reference whose height may be tightened
	// by one verifying fetch. Replacement summaries are never resolvable:
	// they are either exact already or reference staged nodes that no
	// fetcher can serve.
	resolvable bool
}

// summary returns the advertised edge summary of a non-sentinel child.
func (c *btreeChild) summary() edgeSummary {
	return edgeSummary{first: c.firstKey, last: c.lastKey, count: c.entryCount}
}

// btreeEdit is one final coalesced mutation. A nil value deletes the key.
type btreeEdit struct {
	key   []byte
	value any // leaf item value; nil = delete
}

// btreeShape adapts one concrete node family to the generic updater.
type btreeShape interface {
	leafKind() Kind
	indexKind() Kind
	decodeLeaf(n *Node) []btreeItem
	decodeIndex(n *Node) []btreeChild
	buildLeaf(items []btreeItem) *Node
	buildIndex(children []btreeChild) *Node
	itemBody(item btreeItem) []byte
	childBody(c btreeChild) []byte
}

// nodeStager finalizes and stages new objects. Encoding is separated from
// staging so an update that reproduces a base object byte-for-byte can reuse
// the base reference without staging (and later emitting) a duplicate.
type nodeStager interface {
	// encodeNode finalizes one node's canonical bytes and reference.
	encodeNode(n *Node) (Ref, []byte, error)
	// stage records one finalized object for emission (idempotent per ref).
	stage(ref Ref, data []byte) error
}

type btreeUpdater struct {
	editor *Editor
	shape  btreeShape
	stager nodeStager
}

// stageNew encodes and stages a node known to be new.
func (u *btreeUpdater) stageNew(n *Node) (Ref, error) {
	ref, data, err := u.stager.encodeNode(n)
	if err != nil {
		return Ref{}, err
	}
	if err := u.stager.stage(ref, data); err != nil {
		return Ref{}, err
	}
	return ref, nil
}

// stageUnlessBase encodes a node and stages it only when it differs from the
// base object it replaces.
func (u *btreeUpdater) stageUnlessBase(n *Node, base Ref) (Ref, error) {
	ref, data, err := u.stager.encodeNode(n)
	if err != nil {
		return Ref{}, err
	}
	if ref == base {
		return ref, nil
	}
	if err := u.stager.stage(ref, data); err != nil {
		return Ref{}, err
	}
	return ref, nil
}

func u64Key(v uint64) []byte {
	return []byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
}

func keyToU64(key []byte) uint64 {
	var v uint64
	for _, b := range key {
		v = v<<8 | uint64(b)
	}
	return v
}

func sortEditsUniqueAscending(edits []btreeEdit) error {
	for i := 1; i < len(edits); i++ {
		if bytes.Compare(edits[i-1].key, edits[i].key) >= 0 {
			return invalidf("btree edits are not strictly ascending")
		}
	}
	return nil
}

// updateBTreeRoot applies the final edit set to the tree rooted at baseRoot
// (nil = empty tree) and returns the new root (nil = empty result). An empty
// base starts at leaf height one; a base subtree's height never grows below
// the root, so the only place the absolute depth bound can be exceeded is
// root stacking, which fails typed before staging the offending level.
func (u *btreeUpdater) updateBTreeRoot(ctx context.Context, baseRoot *Ref, edits []btreeEdit) (*Ref, error) {
	if err := sortEditsUniqueAscending(edits); err != nil {
		return nil, err
	}
	if len(edits) == 0 {
		return baseRoot, nil
	}
	var children []btreeChild
	if baseRoot == nil {
		items := make([]btreeItem, 0, len(edits))
		for _, edit := range edits {
			if edit.value == nil {
				return nil, notFoundf("delete from an empty tree")
			}
			items = append(items, btreeItem{key: edit.key, value: edit.value})
		}
		built, err := u.buildLeafRuns(items, u.chunkLeafItems(items))
		if err != nil {
			return nil, err
		}
		children = built
	} else {
		updated, err := u.update(ctx, btreeChild{ref: *baseRoot}, edits, 1)
		if err != nil {
			return nil, err
		}
		children = updated
	}
	switch len(children) {
	case 0:
		return nil, nil
	case 1:
		root := children[0].ref
		return &root, nil
	default:
		root, err := u.stackIndexLevels(children)
		if err != nil {
			return nil, err
		}
		return &root, nil
	}
}

// update rewrites the subtree at child.ref under the routed edits and
// returns its replacement summaries (possibly empty, one, or several). A
// non-sentinel child is verified against its advertised summary.
func (u *btreeUpdater) update(ctx context.Context, child btreeChild, edits []btreeEdit, depth int) ([]btreeChild, error) {
	if depth > MaxTreeDepth {
		return nil, boundExceededf("btree update depth")
	}
	node, err := u.editor.fetchNode(ctx, child.ref, u.shape.leafKind(), u.shape.indexKind())
	if err != nil {
		return nil, err
	}
	if child.entryCount > 0 {
		if err := verifyEdgeSummary("btree child", child.ref, node, child.summary()); err != nil {
			return nil, err
		}
	}
	if node.Kind == u.shape.leafKind() {
		return u.rewriteLeafRun(ctx, []btreeChild{child}, edits, depth)
	}
	return u.updateIndex(ctx, node, child.ref, edits, depth)
}

// mergeItems merges sorted base items with sorted final edits.
func mergeItems(items []btreeItem, edits []btreeEdit) ([]btreeItem, error) {
	merged := make([]btreeItem, 0, len(items)+len(edits))
	i, j := 0, 0
	for i < len(items) || j < len(edits) {
		var cmp int
		switch {
		case i >= len(items):
			cmp = 1
		case j >= len(edits):
			cmp = -1
		default:
			cmp = bytes.Compare(items[i].key, edits[j].key)
		}
		switch {
		case cmp < 0:
			merged = append(merged, items[i])
			i++
		case cmp > 0:
			if edits[j].value == nil {
				return nil, notFoundf("btree delete of an absent key")
			}
			merged = append(merged, btreeItem{key: edits[j].key, value: edits[j].value})
			j++
		default:
			if edits[j].value != nil {
				merged = append(merged, btreeItem{key: edits[j].key, value: edits[j].value})
			}
			i++
			j++
		}
	}
	return merged, nil
}

// rewriteLeafRun jointly rewrites one contiguous run of edited leaves: the
// run's final entries re-chunk as one sequence under the frozen greedy rule,
// so splits and merges fall out of one rule. A single-leaf run reproducing
// its input keeps the base reference. Every fetched leaf verifies against
// its advertised summary (sentinel root edges carry none).
func (u *btreeUpdater) rewriteLeafRun(
	ctx context.Context, leaves []btreeChild, edits []btreeEdit, depth int,
) ([]btreeChild, error) {
	if depth > MaxTreeDepth {
		return nil, boundExceededf("btree update depth")
	}
	var items []btreeItem
	for _, leaf := range leaves {
		node, err := u.editor.fetchNode(ctx, leaf.ref, u.shape.leafKind())
		if err != nil {
			return nil, err
		}
		if leaf.entryCount > 0 {
			if err := verifyEdgeSummary("btree leaf", leaf.ref, node, leaf.summary()); err != nil {
				return nil, err
			}
		}
		items = append(items, u.shape.decodeLeaf(node)...)
	}
	merged, err := mergeItems(items, edits)
	if err != nil {
		return nil, err
	}
	if len(merged) == 0 {
		return nil, nil
	}
	runs := u.chunkLeafItems(merged)
	if len(runs) == 1 && len(leaves) == 1 {
		newRef, err := u.stageUnlessBase(u.shape.buildLeaf(merged), leaves[0].ref)
		if err != nil {
			return nil, err
		}
		return []btreeChild{summaryOfLeaf(merged, newRef)}, nil
	}
	return u.buildLeafRuns(merged, runs)
}

func (u *btreeUpdater) chunkLeafItems(items []btreeItem) [][2]int {
	return chunkLeaves(len(items), func(i int) int {
		return pfwire.SizeTagged(1, len(u.shape.itemBody(items[i])))
	})
}

// buildLeafRuns stages one new leaf node per run.
func (u *btreeUpdater) buildLeafRuns(items []btreeItem, runs [][2]int) ([]btreeChild, error) {
	children := make([]btreeChild, 0, len(runs))
	for _, run := range runs {
		slice := items[run[0]:run[1]]
		ref, err := u.stageNew(u.shape.buildLeaf(slice))
		if err != nil {
			return nil, err
		}
		children = append(children, summaryOfLeaf(slice, ref))
	}
	return children, nil
}

func summaryOfLeaf(items []btreeItem, ref Ref) btreeChild {
	return btreeChild{
		firstKey:    items[0].key,
		lastKey:     items[len(items)-1].key,
		ref:         ref,
		entryCount:  uint64(len(items)),
		height:      1,
		heightExact: true,
	}
}

func (u *btreeUpdater) updateIndex(
	ctx context.Context, node *Node, ref Ref, edits []btreeEdit, depth int,
) ([]btreeChild, error) {
	children := u.shape.decodeIndex(node)
	// Unfetched children carry the conservative readable-tree height bound
	// for their base depth (children of a depth-d node sit at depth d+1, so
	// a readable subtree there has height <= MaxTreeDepth-d). Descending
	// through an index at depth MaxTreeDepth fails the depth bound before
	// this node can return, so the bound is always >= 1 here.
	for i := range children {
		children[i].height = MaxTreeDepth - depth
		children[i].heightExact = false
		children[i].resolvable = true
	}
	// Route each edit to the first child whose lastKey >= key (last child
	// for keys above every range). Edits are ascending, so routing is one
	// forward sweep producing contiguous per-child ranges.
	ranges := make([][2]int, len(children))
	editIndex := 0
	for childIndex, child := range children {
		start := editIndex
		for editIndex < len(edits) {
			key := edits[editIndex].key
			if childIndex < len(children)-1 && bytes.Compare(key, child.lastKey) > 0 {
				break
			}
			editIndex++
		}
		ranges[childIndex] = [2]int{start, editIndex}
	}

	spliced := make([]btreeChild, 0, len(children))
	for childIndex := 0; childIndex < len(children); {
		if ranges[childIndex][0] == ranges[childIndex][1] {
			spliced = append(spliced, children[childIndex])
			childIndex++
			continue
		}
		// Extend the contiguous edited run.
		runEnd := childIndex + 1
		for runEnd < len(children) && ranges[runEnd][0] != ranges[runEnd][1] {
			runEnd++
		}
		replacement, err := u.updateChildRun(
			ctx, children[childIndex:runEnd],
			edits[ranges[childIndex][0]:ranges[runEnd-1][1]],
			ranges[childIndex:runEnd], depth,
		)
		if err != nil {
			return nil, err
		}
		spliced = append(spliced, replacement...)
		childIndex = runEnd
	}
	if len(spliced) == 0 {
		return nil, nil
	}
	if len(spliced) == 1 {
		return spliced, nil // collapse: the child replaces this node
	}
	if depth == 1 && (len(spliced) > MaxIndexChildren || u.childRegionBytes(spliced) > TargetNodeBytes) {
		// The root splice overflows, so at least one index level will stack
		// above it and every spliced child sinks below its base depth. This
		// is the only point where subtree heights matter AND unproven
		// children are still raw base references, so resolve them here (one
		// fetch each; a leaf proves height 1, an index keeps its
		// conservative bound). stackIndexLevels then refuses typed if the
		// resolved heights still cannot prove the depth bound.
		if err := u.resolveChildHeights(ctx, spliced); err != nil {
			return nil, err
		}
	}
	return u.rebuildIndex(spliced, ref)
}

// childRegionBytes sums the encoded field-1 sizes of a child list (the
// frozen index chunking measure).
func (u *btreeUpdater) childRegionBytes(children []btreeChild) int {
	region := 0
	for _, child := range children {
		region += pfwire.SizeTagged(1, len(u.shape.childBody(child)))
	}
	return region
}

// updateChildRun rewrites one contiguous run of edited children. Leaf runs
// rewrite jointly (one merged entry sequence); index runs recurse per child.
func (u *btreeUpdater) updateChildRun(
	ctx context.Context, children []btreeChild, unionEdits []btreeEdit, ranges [][2]int, depth int,
) ([]btreeChild, error) {
	if depth+1 > MaxTreeDepth {
		return nil, boundExceededf("btree update depth")
	}
	first, err := u.editor.fetchNode(ctx, children[0].ref, u.shape.leafKind(), u.shape.indexKind())
	if err != nil {
		return nil, err
	}
	if err := verifyEdgeSummary("btree child", children[0].ref, first, children[0].summary()); err != nil {
		return nil, err
	}
	if first.Kind == u.shape.leafKind() {
		return u.rewriteLeafRun(ctx, children, unionEdits, depth+1)
	}
	base := ranges[0][0]
	var out []btreeChild
	for i, child := range children {
		slice := unionEdits[ranges[i][0]-base : ranges[i][1]-base]
		replacement, err := u.update(ctx, child, slice, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, replacement...)
	}
	return out, nil
}

// rebuildIndex encodes the spliced child list under the frozen index rule.
func (u *btreeUpdater) rebuildIndex(spliced []btreeChild, ref Ref) ([]btreeChild, error) {
	region := 0
	for _, child := range spliced {
		region += pfwire.SizeTagged(1, len(u.shape.childBody(child)))
	}
	if len(spliced) <= MaxIndexChildren && region <= TargetNodeBytes {
		// An identical rebuild (all children unchanged) keeps the base ref.
		newRef, err := u.stageUnlessBase(u.shape.buildIndex(spliced), ref)
		if err != nil {
			return nil, err
		}
		summary, err := summaryOfIndex(spliced, newRef)
		if err != nil {
			return nil, err
		}
		return []btreeChild{summary}, nil
	}
	return u.buildIndexRun(spliced)
}

// buildIndexRun chunks oversized child lists under the frozen index rule.
func (u *btreeUpdater) buildIndexRun(children []btreeChild) ([]btreeChild, error) {
	runs := chunkIndex(len(children), func(i int) int {
		return pfwire.SizeTagged(1, len(u.shape.childBody(children[i])))
	})
	out := make([]btreeChild, 0, len(runs))
	for _, run := range runs {
		slice := children[run[0]:run[1]]
		ref, err := u.stageNew(u.shape.buildIndex(slice))
		if err != nil {
			return nil, err
		}
		summary, err := summaryOfIndex(slice, ref)
		if err != nil {
			return nil, err
		}
		out = append(out, summary)
	}
	return out, nil
}

func summaryOfIndex(children []btreeChild, ref Ref) (btreeChild, error) {
	var total uint64
	height := 0
	exact := true
	for _, child := range children {
		var err error
		if total, err = addCount("btree index summary", total, child.entryCount); err != nil {
			return btreeChild{}, err
		}
		if child.height > height {
			height = child.height
		}
		exact = exact && child.heightExact
	}
	return btreeChild{
		firstKey:    children[0].firstKey,
		lastKey:     children[len(children)-1].lastKey,
		ref:         ref,
		entryCount:  total,
		height:      height + 1,
		heightExact: exact,
	}, nil
}

func maxChildHeight(children []btreeChild) int {
	height := 0
	for _, child := range children {
		if child.height > height {
			height = child.height
		}
	}
	return height
}

// stackIndexLevels stacks greedy index levels until one root remains,
// tracking the absolute height of the replacement subtrees below (not just
// the newly stacked levels). A level whose (possibly conservative) height
// would exceed MaxTreeDepth fails typed BEFORE that level is staged, so a
// legal maximum-depth base whose root splits can never produce an unreadable
// depth-13 tree. Unproven base children were already resolved at the root
// splice (updateIndex), where they are still fetchable references; anything
// still unproven here is conservatively refused rather than emitted.
func (u *btreeUpdater) stackIndexLevels(children []btreeChild) (Ref, error) {
	level := children
	for len(level) > 1 {
		if maxChildHeight(level)+1 > MaxTreeDepth {
			return Ref{}, invalidf(
				"btree root split exceeds max depth %d (subtree heights the wire format cannot prove are conservatively refused)",
				MaxTreeDepth)
		}
		next, err := u.buildIndexRun(level)
		if err != nil {
			return Ref{}, err
		}
		level = next
	}
	return level[0].ref, nil
}

// resolveChildHeights tightens conservative child heights with exactly one
// fetch per unproven child: a fetched leaf has exact height 1; a fetched
// index keeps its bound, because proving anything tighter would require
// walking its whole subtree (the wire format carries no heights). Each fetch
// verifies the child against its advertised summary. Only raw base
// references may be resolved: replacement summaries are already exact or
// contain staged nodes no fetcher can serve.
func (u *btreeUpdater) resolveChildHeights(ctx context.Context, children []btreeChild) error {
	for i := range children {
		child := &children[i]
		if child.heightExact || !child.resolvable {
			continue
		}
		node, err := u.editor.fetchNode(ctx, child.ref, u.shape.leafKind(), u.shape.indexKind())
		if err != nil {
			return err
		}
		if child.entryCount > 0 {
			if err := verifyEdgeSummary("btree child", child.ref, node, child.summary()); err != nil {
				return err
			}
		}
		if node.Kind == u.shape.leafKind() {
			child.height = 1
			child.heightExact = true
		}
	}
	return nil
}

// ─── concrete shapes ─────────────────────────────────────────────────────────

type directoryShape struct{}

func (directoryShape) leafKind() Kind  { return KindDirectoryLeaf }
func (directoryShape) indexKind() Kind { return KindDirectoryIndex }

func (directoryShape) decodeLeaf(n *Node) []btreeItem {
	items := make([]btreeItem, len(n.DirectoryLeaf.Entries))
	for i, entry := range n.DirectoryLeaf.Entries {
		items[i] = btreeItem{key: []byte(entry.Name), value: entry}
	}
	return items
}

func (directoryShape) decodeIndex(n *Node) []btreeChild {
	children := make([]btreeChild, len(n.DirectoryIndex.Children))
	for i, child := range n.DirectoryIndex.Children {
		children[i] = btreeChild{
			firstKey:   []byte(child.FirstName),
			lastKey:    []byte(child.LastName),
			ref:        child.Child,
			entryCount: child.EntryCount,
		}
	}
	return children
}

func (directoryShape) buildLeaf(items []btreeItem) *Node {
	entries := make([]DirEntry, len(items))
	for i, item := range items {
		entries[i] = item.value.(DirEntry)
	}
	return &Node{Kind: KindDirectoryLeaf, DirectoryLeaf: &DirectoryLeaf{Entries: entries}}
}

func (directoryShape) buildIndex(children []btreeChild) *Node {
	typed := make([]DirectoryIndexChild, len(children))
	for i, child := range children {
		typed[i] = DirectoryIndexChild{
			FirstName:  string(child.firstKey),
			LastName:   string(child.lastKey),
			Child:      child.ref,
			EntryCount: child.entryCount,
		}
	}
	return &Node{Kind: KindDirectoryIndex, DirectoryIndex: &DirectoryIndex{Children: typed}}
}

func (directoryShape) itemBody(item btreeItem) []byte {
	entry := item.value.(DirEntry)
	return appendDirEntry(nil, &entry)
}

func (directoryShape) childBody(c btreeChild) []byte {
	child := DirectoryIndexChild{
		FirstName:  string(c.firstKey),
		LastName:   string(c.lastKey),
		Child:      c.ref,
		EntryCount: c.entryCount,
	}
	return encodeDirectoryIndexChild(&child)
}

type extentShape struct{}

func (extentShape) leafKind() Kind  { return KindExtentLeaf }
func (extentShape) indexKind() Kind { return KindExtentIndex }

func (extentShape) decodeLeaf(n *Node) []btreeItem {
	items := make([]btreeItem, len(n.ExtentLeaf.Entries))
	for i, entry := range n.ExtentLeaf.Entries {
		items[i] = btreeItem{key: u64Key(entry.PageOffset), value: entry}
	}
	return items
}

func (extentShape) decodeIndex(n *Node) []btreeChild {
	children := make([]btreeChild, len(n.ExtentIndex.Children))
	for i, child := range n.ExtentIndex.Children {
		children[i] = btreeChild{
			firstKey:   u64Key(child.FirstPage),
			lastKey:    u64Key(child.LastPage),
			ref:        child.Child,
			entryCount: child.EntryCount,
		}
	}
	return children
}

func (extentShape) buildLeaf(items []btreeItem) *Node {
	entries := make([]ExtentEntry, len(items))
	for i, item := range items {
		entries[i] = item.value.(ExtentEntry)
	}
	return &Node{Kind: KindExtentLeaf, ExtentLeaf: &ExtentLeaf{Entries: entries}}
}

func (extentShape) buildIndex(children []btreeChild) *Node {
	typed := make([]ExtentIndexChild, len(children))
	for i, child := range children {
		typed[i] = ExtentIndexChild{
			FirstPage:  keyToU64(child.firstKey),
			LastPage:   keyToU64(child.lastKey),
			Child:      child.ref,
			EntryCount: child.entryCount,
		}
	}
	return &Node{Kind: KindExtentIndex, ExtentIndex: &ExtentIndex{Children: typed}}
}

func (extentShape) itemBody(item btreeItem) []byte {
	entry := item.value.(ExtentEntry)
	body := pfwire.AppendUint(nil, 1, entry.PageOffset)
	return appendRef(body, 2, entry.Page)
}

func (extentShape) childBody(c btreeChild) []byte {
	child := ExtentIndexChild{
		FirstPage:  keyToU64(c.firstKey),
		LastPage:   keyToU64(c.lastKey),
		Child:      c.ref,
		EntryCount: c.entryCount,
	}
	return encodeExtentIndexChild(&child)
}

type inodeIndexShape struct{}

func (inodeIndexShape) leafKind() Kind  { return KindInodeIndexLeaf }
func (inodeIndexShape) indexKind() Kind { return KindInodeIndexIndex }

func (inodeIndexShape) decodeLeaf(n *Node) []btreeItem {
	items := make([]btreeItem, len(n.InodeIndexLeaf.Entries))
	for i, entry := range n.InodeIndexLeaf.Entries {
		items[i] = btreeItem{key: u64Key(entry.Ino), value: entry}
	}
	return items
}

func (inodeIndexShape) decodeIndex(n *Node) []btreeChild {
	children := make([]btreeChild, len(n.InodeIndexIndex.Children))
	for i, child := range n.InodeIndexIndex.Children {
		children[i] = btreeChild{
			firstKey:   u64Key(child.FirstIno),
			lastKey:    u64Key(child.LastIno),
			ref:        child.Child,
			entryCount: child.EntryCount,
		}
	}
	return children
}

func (inodeIndexShape) buildLeaf(items []btreeItem) *Node {
	entries := make([]InodeIndexEntry, len(items))
	for i, item := range items {
		entries[i] = item.value.(InodeIndexEntry)
	}
	return &Node{Kind: KindInodeIndexLeaf, InodeIndexLeaf: &InodeIndexLeaf{Entries: entries}}
}

func (inodeIndexShape) buildIndex(children []btreeChild) *Node {
	typed := make([]InodeIndexChild, len(children))
	for i, child := range children {
		typed[i] = InodeIndexChild{
			FirstIno:   keyToU64(child.firstKey),
			LastIno:    keyToU64(child.lastKey),
			Child:      child.ref,
			EntryCount: child.entryCount,
		}
	}
	return &Node{Kind: KindInodeIndexIndex, InodeIndexIndex: &InodeIndexIndex{Children: typed}}
}

func (inodeIndexShape) itemBody(item btreeItem) []byte {
	entry := item.value.(InodeIndexEntry)
	body := pfwire.AppendUint(nil, 1, entry.Ino)
	return appendRef(body, 2, entry.Inode)
}

func (inodeIndexShape) childBody(c btreeChild) []byte {
	child := InodeIndexChild{
		FirstIno:   keyToU64(c.firstKey),
		LastIno:    keyToU64(c.lastKey),
		Child:      c.ref,
		EntryCount: c.entryCount,
	}
	return encodeInodeIndexChild(&child)
}
