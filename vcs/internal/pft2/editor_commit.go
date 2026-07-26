package pft2

import (
	"bytes"
	"context"
	"sort"
)

// CommitResult reports one successfully planned/emitted transaction.
type CommitResult struct {
	// Root references the new (or unchanged) filesystem ROOT object.
	Root Ref
	// RootFacts is the decoded new root (verified counters included).
	RootFacts Root
	// OrphanIndex references the new parked-orphan index root (nil = none).
	// It is never reachable from Root; the recovery anchor references it.
	OrphanIndex *Ref
	// Unchanged reports a no-effect transaction: Root equals the base root
	// and nothing was emitted.
	Unchanged bool

	NewNodes     int
	NewNodeBytes int64
	NewPacks     int
	NewPackBytes int64
}

type stagedObject struct {
	ref  Ref
	data []byte
}

type commitPlan struct {
	result CommitResult
	packs  []stagedObject
	nodes  []stagedObject
}

// Commit computes the deterministic path-copy plan (first call only; a
// retained plan is reused verbatim on retry) and then emits every new object
// through the sinks: packs first, then metadata nodes, in deterministic
// build order. Duplicate puts must be idempotent in the sink. Any error —
// validation, fetch, bound, or sink — publishes no root and leaves the
// editor usable; after a successful commit the editor is sealed.
func (e *Editor) Commit(ctx context.Context, nodes NodeSink, packs PackSink) (*CommitResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sealed {
		return nil, ErrEditorSealed
	}
	if nodes == nil || packs == nil {
		return nil, invalidf("commit requires node and pack sinks")
	}
	if e.plan == nil {
		// Retry-safe budget semantics: a failed plan build restores the
		// pre-attempt traversal budget, so an exact retry sees the identical
		// budget (each attempt stays bounded by it) and rebuilds the same
		// deterministic plan byte for byte. A successful build retains the
		// plan, so sink-failure retries re-emit without re-walking.
		restore := e.budgetSnapshot()
		plan, err := e.buildPlan(ctx)
		restore(&err)
		if err != nil {
			return nil, err
		}
		e.plan = plan
	}
	for _, obj := range e.plan.packs {
		if err := packs.PutPack(obj.ref, obj.data); err != nil {
			return nil, err
		}
	}
	for _, obj := range e.plan.nodes {
		if err := nodes.PutNode(obj.ref, obj.data); err != nil {
			return nil, err
		}
	}
	e.sealed = true
	result := e.plan.result
	return &result, nil
}

// planBuilder stages finalized objects under the new-object budgets.
type planBuilder struct {
	e         *Editor
	pending   map[Ref]bool
	nodes     []stagedObject
	packs     []stagedObject
	nodeBytes int64
	packBytes int64
}

func (p *planBuilder) chargeObject(size int) error {
	total := len(p.nodes) + len(p.packs)
	if total >= p.e.limits.MaxNewObjects {
		return transactionLimitf("new object count exceeds %d", p.e.limits.MaxNewObjects)
	}
	if p.nodeBytes+p.packBytes+int64(size) > p.e.limits.MaxNewObjectBytes {
		return transactionLimitf("new object bytes exceed %d", p.e.limits.MaxNewObjectBytes)
	}
	return nil
}

// encodeNode finalizes one node's canonical bytes and reference
// (nodeStager).
func (p *planBuilder) encodeNode(n *Node) (Ref, []byte, error) {
	encoded, err := EncodeNode(n)
	if err != nil {
		return Ref{}, nil, err
	}
	return RefOf(encoded), encoded, nil
}

// stage records one finalized node for emission; bytes/digest/size are final
// before the object is ever exposed. Duplicate stages coalesce (nodeStager).
func (p *planBuilder) stage(ref Ref, data []byte) error {
	if p.pending[ref] {
		return nil
	}
	if err := p.chargeObject(len(data)); err != nil {
		return err
	}
	p.pending[ref] = true
	p.nodes = append(p.nodes, stagedObject{ref: ref, data: data})
	p.nodeBytes += int64(len(data))
	return nil
}

// stageNode encodes and stages one node known to be new.
func (p *planBuilder) stageNode(n *Node) (Ref, error) {
	ref, data, err := p.encodeNode(n)
	if err != nil {
		return Ref{}, err
	}
	if err := p.stage(ref, data); err != nil {
		return Ref{}, err
	}
	return ref, nil
}

// stageNodeUnless encodes a node and stages it only when it differs from the
// base object it replaces.
func (p *planBuilder) stageNodeUnless(n *Node, base Ref) (Ref, error) {
	ref, data, err := p.encodeNode(n)
	if err != nil {
		return Ref{}, err
	}
	if ref == base {
		return ref, nil
	}
	if err := p.stage(ref, data); err != nil {
		return Ref{}, err
	}
	return ref, nil
}

// PutPack implements PackSink for the cell packer, staging into the plan.
func (p *planBuilder) PutPack(ref Ref, data []byte) error {
	if p.pending[ref] {
		return nil
	}
	if err := p.chargeObject(len(data)); err != nil {
		return err
	}
	p.pending[ref] = true
	p.packs = append(p.packs, stagedObject{ref: ref, data: append([]byte(nil), data...)})
	p.packBytes += int64(len(data))
	return nil
}

func (p *planBuilder) updater(shape btreeShape) *btreeUpdater {
	return &btreeUpdater{editor: p.e, shape: shape, stager: p}
}

// changedCell is one repacked cell in the frozen global order.
type changedCell struct {
	ino        uint64
	pageOffset uint64
	cellIndex  int
	data       []byte
}

// pageState is the final composition of one touched page.
type pageState struct {
	ino        uint64
	pageOffset uint64
	baseRef    *Ref            // existing page object, if any
	keep       map[int]CellRef // base cells carried over unchanged
	repack     map[int]bool    // cell indexes repacked this transaction
}

func checkedAdd(total *int64, delta int64) error {
	sum := *total + delta
	if (delta > 0 && sum < *total) || (delta < 0 && sum > *total) {
		return invalidf("counter delta overflow")
	}
	*total = sum
	return nil
}

func applyCounterDelta(what string, base uint64, delta int64) (uint64, error) {
	if delta >= 0 {
		sum := base + uint64(delta)
		if sum < base || sum > MaxCount64 {
			return 0, invalidf("%s counter overflows", what)
		}
		return sum, nil
	}
	magnitude := uint64(-delta)
	if magnitude > base {
		return 0, invalidf("%s counter underflows", what)
	}
	return base - magnitude, nil
}

// effectiveDirEdits returns the parent's staged edits that actually change
// the merged state (a coalesced delete of a never-existing name is a no-op).
func effectiveDirEdits(edits map[string]*dirEdit) map[string]*dirEdit {
	out := map[string]*dirEdit{}
	for name, edit := range edits {
		if edit.entry == nil && !edit.baseExisted {
			continue
		}
		out[name] = edit
	}
	return out
}

func (e *Editor) buildPlan(ctx context.Context) (*commitPlan, error) {
	touched := map[uint64]bool{}
	for ino, st := range e.inodes {
		if st.finalHome != homeInherit || st.metaStaged || st.contentDirty {
			touched[ino] = true
		}
	}
	dirParents := map[uint64]map[string]*dirEdit{}
	for parent, edits := range e.dirEdits {
		effective := effectiveDirEdits(edits)
		if len(effective) > 0 {
			dirParents[parent] = effective
			touched[parent] = true
		}
	}
	if len(touched) == 0 && !e.rootXattrsSet {
		if e.baseRoot == nil {
			return nil, invalidf("empty transaction cannot create a filesystem root")
		}
		return &commitPlan{result: CommitResult{
			Root: e.baseRootRef, RootFacts: *e.baseRoot, OrphanIndex: e.orphanBase, Unchanged: true,
		}}, nil
	}
	if len(touched) == 0 {
		if e.baseRoot == nil {
			return nil, invalidf("empty transaction cannot create a filesystem root")
		}
		rootFacts := *e.baseRoot
		rootFacts.XattrLeaves = append([]Ref(nil), e.rootXattrLeaves...)
		p := &planBuilder{e: e, pending: map[Ref]bool{}}
		rootRef, err := p.stageNode(&Node{Kind: KindRoot, Root: &rootFacts})
		if err != nil {
			return nil, err
		}
		if rootRef == e.baseRootRef {
			return &commitPlan{result: CommitResult{
				Root: rootRef, RootFacts: rootFacts, OrphanIndex: e.orphanBase, Unchanged: true,
			}}, nil
		}
		return &commitPlan{
			result: CommitResult{
				Root: rootRef, RootFacts: rootFacts, OrphanIndex: e.orphanBase,
				NewNodes: len(p.nodes), NewNodeBytes: p.nodeBytes,
			},
			nodes: p.nodes,
		}, nil
	}

	touchedInos := make([]uint64, 0, len(touched))
	for ino := range touched {
		touchedInos = append(touchedInos, ino)
	}
	sort.Slice(touchedInos, func(i, j int) bool { return touchedInos[i] < touchedInos[j] })

	// Every touched inode's base facts resolve before validation.
	for _, ino := range touchedInos {
		if err := e.loadBase(ctx, e.inodeState(ino)); err != nil {
			return nil, err
		}
	}
	if err := e.validatePlan(ctx, touchedInos, dirParents); err != nil {
		return nil, err
	}

	p := &planBuilder{e: e, pending: map[Ref]bool{}}

	// Content pipeline: page composition, then the frozen global cell pack.
	var cells []changedCell
	pagesByIno := map[uint64][]*pageState{}
	for _, ino := range touchedInos {
		st := e.inodes[ino]
		if !st.contentDirty || st.mergedHome() == homeDeleted {
			continue
		}
		pages, inoCells, err := e.composeFinalPages(ctx, st)
		if err != nil {
			return nil, err
		}
		for i := range inoCells {
			inoCells[i].ino = ino
		}
		cells = append(cells, inoCells...)
		pagesByIno[ino] = pages
	}
	sort.Slice(cells, func(i, j int) bool {
		if cells[i].ino != cells[j].ino {
			return cells[i].ino < cells[j].ino
		}
		if cells[i].pageOffset != cells[j].pageOffset {
			return cells[i].pageOffset < cells[j].pageOffset
		}
		return cells[i].cellIndex < cells[j].cellIndex
	})
	cellRefs, err := packCells(cells, p)
	if err != nil {
		return nil, err
	}
	cellRefByKey := map[[3]uint64]CellRef{}
	for i, cell := range cells {
		cellRefByKey[[3]uint64{cell.ino, cell.pageOffset, uint64(cell.cellIndex)}] = cellRefs[i]
	}

	// Extent trees per content-dirty inode.
	extentRoots := map[uint64]*Ref{}
	for _, ino := range touchedInos {
		pages, ok := pagesByIno[ino]
		if !ok {
			continue
		}
		st := e.inodes[ino]
		root, err := e.buildExtentRoot(ctx, p, st, pages, cellRefByKey)
		if err != nil {
			return nil, err
		}
		extentRoots[ino] = root
	}

	// Directory trees per live edited parent.
	dirRoots := map[uint64]*Ref{}
	var direntDelta int64
	for _, parent := range touchedInos {
		edits, ok := dirParents[parent]
		if !ok {
			continue
		}
		for _, edit := range edits {
			final := int64(0)
			if edit.entry != nil {
				final = 1
			}
			base := int64(0)
			if edit.baseExisted {
				base = 1
			}
			if err := checkedAdd(&direntDelta, final-base); err != nil {
				return nil, err
			}
		}
		st := e.inodes[parent]
		if st.mergedHome() != homeFS {
			continue // deleted parent: edits only feed the empty check
		}
		root, err := e.buildDirectoryRoot(ctx, p, st, edits)
		if err != nil {
			return nil, err
		}
		dirRoots[parent] = root
	}

	// Final inode objects plus index edits. MaxInoSeen is the monotonic
	// allocation/observation high-water: it rises for every touched live
	// inode — orphan-homed ones included — and never falls on delete,
	// because inode ids are never reused.
	finalRefs := map[uint64]Ref{}
	var fsEdits, orphanEdits []btreeEdit
	var inodeDelta, logicalDelta int64
	maxInoSeen := uint64(RootIno)
	if e.baseRoot != nil {
		maxInoSeen = e.baseRoot.MaxInoSeen
	}
	for _, ino := range touchedInos {
		st := e.inodes[ino]
		home := st.mergedHome()
		baseInFS := st.baseExists && st.baseHome == homeFS
		baseInOrphan := st.baseExists && st.baseHome == homeOrphan
		if home == homeDeleted {
			if baseInFS {
				fsEdits = append(fsEdits, btreeEdit{key: u64Key(ino)})
				if err := checkedAdd(&inodeDelta, -1); err != nil {
					return nil, err
				}
				if err := checkedAdd(&logicalDelta, -int64(st.baseMeta.Size)); err != nil {
					return nil, err
				}
			}
			if baseInOrphan {
				orphanEdits = append(orphanEdits, btreeEdit{key: u64Key(ino)})
			}
			continue
		}
		final, err := e.assembleFinalInode(st, extentRoots, dirRoots)
		if err != nil {
			return nil, err
		}
		var ref Ref
		if st.baseExists && inodesEqual(&final, &st.baseMeta) {
			ref = st.baseRef
		} else {
			ref, err = p.stageNode(&Node{Kind: KindInode, Inode: &final})
			if err != nil {
				return nil, err
			}
		}
		finalRefs[ino] = ref
		if ino > maxInoSeen {
			maxInoSeen = ino
		}
		entry := InodeIndexEntry{Ino: ino, Inode: ref}
		if home == homeFS {
			if !baseInFS || ref != st.baseRef {
				fsEdits = append(fsEdits, btreeEdit{key: u64Key(ino), value: entry})
			}
			if baseInOrphan {
				orphanEdits = append(orphanEdits, btreeEdit{key: u64Key(ino)})
			}
			if !baseInFS {
				if err := checkedAdd(&inodeDelta, 1); err != nil {
					return nil, err
				}
			}
			baseLogical := int64(0)
			if baseInFS {
				baseLogical = int64(st.baseMeta.Size)
			}
			if err := checkedAdd(&logicalDelta, int64(final.Size)-baseLogical); err != nil {
				return nil, err
			}
		} else { // homeOrphan
			if !baseInOrphan || ref != st.baseRef {
				orphanEdits = append(orphanEdits, btreeEdit{key: u64Key(ino), value: entry})
			}
			if baseInFS {
				fsEdits = append(fsEdits, btreeEdit{key: u64Key(ino)})
				if err := checkedAdd(&inodeDelta, -1); err != nil {
					return nil, err
				}
				if err := checkedAdd(&logicalDelta, -int64(st.baseMeta.Size)); err != nil {
					return nil, err
				}
			}
		}
	}
	sortBtreeEdits(fsEdits)
	sortBtreeEdits(orphanEdits)

	// Index roots. The base filesystem index root is pinned against the base
	// ROOT facts before the path-copy update trusts its advertisements.
	var baseFSIndex *Ref
	if e.baseRoot != nil {
		root := e.baseRoot.InodeIndex
		baseFSIndex = &root
		node, err := e.fetchNode(ctx, root, KindInodeIndexLeaf, KindInodeIndexIndex)
		if err != nil {
			return nil, err
		}
		if err := verifyFSIndexRootFacts(e.baseRoot, root, node); err != nil {
			return nil, err
		}
	}
	fsIndexRoot, err := p.updater(inodeIndexShape{}).updateBTreeRoot(ctx, baseFSIndex, fsEdits)
	if err != nil {
		return nil, err
	}
	if fsIndexRoot == nil {
		return nil, invalidf("transaction leaves the filesystem without inodes")
	}
	orphanRoot, err := p.updater(inodeIndexShape{}).updateBTreeRoot(ctx, e.orphanBase, orphanEdits)
	if err != nil {
		return nil, err
	}

	// New root facts.
	rootInodeRef, ok := finalRefs[RootIno]
	if !ok {
		if e.baseRoot == nil {
			return nil, invalidf("transaction must create root inode %d", RootIno)
		}
		rootInodeRef = e.baseRoot.RootInode
	}
	baseFacts := Root{MaxInoSeen: RootIno, InodeCount: 0, DirentCount: 0, LogicalBytes: 0}
	if e.baseRoot != nil {
		baseFacts = *e.baseRoot
	}
	inodeCount, err := applyCounterDelta("inode", baseFacts.InodeCount, inodeDelta)
	if err != nil {
		return nil, err
	}
	direntCount, err := applyCounterDelta("dirent", baseFacts.DirentCount, direntDelta)
	if err != nil {
		return nil, err
	}
	logicalBytes, err := applyCounterDelta("logical byte", baseFacts.LogicalBytes, logicalDelta)
	if err != nil {
		return nil, err
	}
	rootFacts := Root{
		RootInode:    rootInodeRef,
		InodeIndex:   *fsIndexRoot,
		MaxInoSeen:   maxInoSeen,
		InodeCount:   inodeCount,
		DirentCount:  direntCount,
		LogicalBytes: logicalBytes,
		Features:     baseFacts.Features,
		XattrLeaves:  append([]Ref(nil), baseFacts.XattrLeaves...),
	}
	if e.rootXattrsSet {
		rootFacts.XattrLeaves = append([]Ref(nil), e.rootXattrLeaves...)
	}
	rootRef, err := p.stageNode(&Node{Kind: KindRoot, Root: &rootFacts})
	if err != nil {
		return nil, err
	}

	if e.baseRoot != nil && rootRef == e.baseRootRef && refsEqual(orphanRoot, e.orphanBase) {
		// Byte-identical outcome: every staged object already exists in the
		// base; publish nothing.
		return &commitPlan{result: CommitResult{
			Root: rootRef, RootFacts: rootFacts, OrphanIndex: e.orphanBase, Unchanged: true,
		}}, nil
	}
	return &commitPlan{
		result: CommitResult{
			Root:         rootRef,
			RootFacts:    rootFacts,
			OrphanIndex:  orphanRoot,
			NewNodes:     len(p.nodes),
			NewNodeBytes: p.nodeBytes,
			NewPacks:     len(p.packs),
			NewPackBytes: p.packBytes,
		},
		packs: p.packs,
		nodes: p.nodes,
	}, nil
}

func refsEqual(a, b *Ref) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

func sortBtreeEdits(edits []btreeEdit) {
	sort.Slice(edits, func(i, j int) bool { return bytes.Compare(edits[i].key, edits[j].key) < 0 })
}

// inodesEqual compares complete stored inode values (roots included).
func inodesEqual(a, b *Inode) bool {
	if a.Ino != b.Ino || a.Kind != b.Kind || a.Mode != b.Mode || a.UID != b.UID ||
		a.GID != b.GID || a.Nlink != b.Nlink || a.Size != b.Size ||
		a.MtimeMs != b.MtimeMs || a.CtimeMs != b.CtimeMs || a.AtimeMs != b.AtimeMs ||
		a.SymlinkTarget != b.SymlinkTarget {
		return false
	}
	return refsEqual(a.DirectoryRoot, b.DirectoryRoot) && refsEqual(a.ExtentRoot, b.ExtentRoot)
}

// validatePlan enforces the structural invariants the format demands before
// anything is staged.
func (e *Editor) validatePlan(
	ctx context.Context, touchedInos []uint64, dirParents map[uint64]map[string]*dirEdit,
) error {
	// Root inode must be live filesystem directory. Transient fetch errors
	// propagate untouched (they are retryable); only a definite absence is a
	// validation failure.
	rootState, err := e.ensureLive(ctx, RootIno, homeFS)
	if err != nil {
		if errIsNotFound(err) {
			return invalidf("root inode %d must be a live filesystem directory", RootIno)
		}
		return err
	}
	if rootState.mergedMeta().Kind != FileKindDirectory {
		return invalidf("root inode %d is not a directory", RootIno)
	}

	for _, ino := range touchedInos {
		st := e.inodes[ino]
		home := st.mergedHome()
		// Kind changes against the base are rejected (stable identity).
		if st.metaStaged && st.baseExists && st.meta.Kind != st.baseMeta.Kind {
			return invalidf("inode %d: kind change is forbidden", ino)
		}
		if home == homeDeleted && st.baseExists && st.baseMeta.Kind == FileKindDirectory && st.baseHome == homeFS {
			count, err := e.baseDirEntryCount(ctx, st)
			if err != nil {
				return err
			}
			var delta int64
			for _, edit := range effectiveDirEdits(e.dirEdits[ino]) {
				final := int64(0)
				if edit.entry != nil {
					final = 1
				}
				base := int64(0)
				if edit.baseExisted {
					base = 1
				}
				delta += final - base
			}
			if int64(count)+delta != 0 {
				return invalidf("deleted directory %d still holds %d entries", ino, int64(count)+delta)
			}
		}
		// A staged nonzero cell at or beyond the final size is an engine bug;
		// the straddled final cell must carry a canonically zero suffix.
		if st.contentDirty && home != homeDeleted {
			for cellOffset, data := range st.cells {
				if data == nil {
					continue
				}
				if cellOffset >= st.size {
					return invalidf("inode %d: nonzero staged cell at %d is at or beyond size %d",
						ino, cellOffset, st.size)
				}
				if st.size-cellOffset < CellBytes && !IsZeroCell(data[st.size-cellOffset:]) {
					return invalidf("inode %d: staged cell at %d has nonzero bytes beyond size %d",
						ino, cellOffset, st.size)
				}
			}
		}
	}

	for parent, edits := range dirParents {
		st := e.inodes[parent]
		home := st.mergedHome()
		if home == homeOrphan {
			return invalidf("directory %d is parked; parked trees are frozen", parent)
		}
		if home == homeFS && st.mergedMeta().Kind != FileKindDirectory {
			return invalidf("inode %d with entry edits is not a directory", parent)
		}
		if home == homeDeleted {
			continue // covered by the deleted-directory empty check
		}
		names := make([]string, 0, len(edits))
		for name := range edits {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			edit := edits[name]
			if edit.entry == nil {
				continue
			}
			target := e.inodeState(edit.entry.Ino)
			if err := e.loadBase(ctx, target); err != nil {
				return err
			}
			if target.mergedHome() != homeFS {
				return invalidf("dir entry %q in inode %d references ino %d, which is not live in the filesystem",
					name, parent, edit.entry.Ino)
			}
			if target.mergedMeta().Kind != edit.entry.Kind {
				return invalidf("dir entry %q kind %s does not match inode %d kind %s",
					name, edit.entry.Kind, edit.entry.Ino, target.mergedMeta().Kind)
			}
		}
	}
	return nil
}

// baseDirEntryCount reads the advertised entry count of a base directory
// from its root node alone (a lazy bound: the advertisement is only proven
// where edges are traversed).
func (e *Editor) baseDirEntryCount(ctx context.Context, st *editorInode) (uint64, error) {
	if !st.baseExists || st.baseMeta.DirectoryRoot == nil {
		return 0, nil
	}
	node, err := e.fetchNode(ctx, *st.baseMeta.DirectoryRoot, KindDirectoryLeaf, KindDirectoryIndex)
	if err != nil {
		return 0, err
	}
	summary, err := nodeSummary(node)
	if err != nil {
		return 0, err
	}
	return summary.count, nil
}

// packCells runs the frozen global (ino, pageOffset, cellIndex) pack.
func packCells(cells []changedCell, p *planBuilder) ([]CellRef, error) {
	if len(cells) == 0 {
		return nil, nil
	}
	packer := NewCellPacker()
	for i := range cells {
		if _, err := packer.Add(cells[i].data); err != nil {
			return nil, err
		}
	}
	return packer.Finish(p)
}

// composeFinalPages resolves one content-dirty file's final page set. It
// fetches only: one ordered range walk over the base extent tree at or
// beyond the visibility boundary (whose already verified page refs are
// carried into page state and never re-searched), one point lookup per
// staged page strictly before the boundary, the page nodes it must rewrite,
// and the single pack slice needed to COW a straddled visibility cell. A
// shrink over N base pages therefore costs the range-walk nodes plus the
// touched pages, never pages times tree depth.
func (e *Editor) composeFinalPages(ctx context.Context, st *editorInode) ([]*pageState, []changedCell, error) {
	finalSize := st.size
	bvs := st.baseVisible
	baseIsFile := st.baseExists && st.baseMeta.Kind == FileKindRegular && st.baseMeta.ExtentRoot != nil

	type pendingPage struct {
		state     *pageState
		baseEntry *ExtentEntry   // verified base entry carried from the range walk
		overrides map[int][]byte // cellIndex -> data (nil = hole)
	}
	pages := map[uint64]*pendingPage{}
	page := func(pageOffset uint64) *pendingPage {
		pp, ok := pages[pageOffset]
		if !ok {
			pp = &pendingPage{
				state:     &pageState{ino: st.ino, pageOffset: pageOffset, keep: map[int]CellRef{}, repack: map[int]bool{}},
				overrides: map[int][]byte{},
			}
			pages[pageOffset] = pp
		}
		return pp
	}

	// 1. Staged overrides.
	for cellOffset, data := range st.cells {
		pageOffset := cellOffset / PageBytes * PageBytes
		if data == nil && cellOffset >= finalSize {
			// Holes at or beyond EOF only matter if the base page survives;
			// base filtering below already excludes those cells.
			if !baseIsFile || cellOffset >= bvs {
				continue
			}
		}
		page(pageOffset).overrides[int((cellOffset-pageOffset)/CellBytes)] = data
	}

	// 2. Base pages at or beyond the visibility boundary must drop (unless
	// overrides repopulate them). The single ordered range walk is
	// authoritative for every page offset >= its start, so each returned
	// entry's verified ref is carried into page state and pages it did not
	// return are known absent without any further lookup.
	rangeWalkFrom := uint64(0)
	rangeWalked := false
	if baseIsFile && bvs < st.baseMeta.Size {
		rangeWalkFrom = bvs / PageBytes * PageBytes
		rangeWalked = true
		basePages, err := e.collectExtentRange(ctx, *st.baseMeta.ExtentRoot, rangeWalkFrom)
		if err != nil {
			return nil, nil, err
		}
		for i := range basePages {
			entry := basePages[i]
			page(entry.PageOffset).baseEntry = &entry
		}
	}

	// 3. Straddled base visibility cell: copy-on-write with a zero suffix.
	if baseIsFile && bvs < st.baseMeta.Size && bvs%CellBytes != 0 {
		cellOffset := bvs / CellBytes * CellBytes
		pageOffset := cellOffset / PageBytes * PageBytes
		cellIndex := int((cellOffset - pageOffset) / CellBytes)
		if _, overridden := page(pageOffset).overrides[cellIndex]; !overridden && cellOffset < finalSize {
			data, err := e.baseCell(ctx, st, cellOffset)
			if err != nil {
				return nil, nil, err
			}
			if data != nil {
				cow := make([]byte, CellBytes)
				copy(cow, data[:bvs-cellOffset])
				if IsZeroCell(cow) {
					page(pageOffset).overrides[cellIndex] = nil
				} else {
					page(pageOffset).overrides[cellIndex] = cow
				}
			}
		}
	}

	// 4. Compose each touched page: visible base cells plus overrides.
	pageOffsets := make([]uint64, 0, len(pages))
	for pageOffset := range pages {
		pageOffsets = append(pageOffsets, pageOffset)
	}
	sort.Slice(pageOffsets, func(i, j int) bool { return pageOffsets[i] < pageOffsets[j] })

	var out []*pageState
	var cells []changedCell
	for _, pageOffset := range pageOffsets {
		pp := pages[pageOffset]
		// Resolve the base page ref: reuse the range walk's verified entry;
		// only staged pages strictly before the walked range may still do
		// one point lookup, and pages the walk did not return are absent.
		var basePageRef *Ref
		if pp.baseEntry != nil {
			refCopy := pp.baseEntry.Page
			basePageRef = &refCopy
		} else if baseIsFile && !(rangeWalked && pageOffset >= rangeWalkFrom) {
			pageRef, found, err := e.findExtentPage(ctx, *st.baseMeta.ExtentRoot, pageOffset)
			if err != nil {
				return nil, nil, err
			}
			if found {
				refCopy := pageRef
				basePageRef = &refCopy
			}
		}
		pp.state.baseRef = basePageRef
		// Any surviving base cells (pages overlapping the visible prefix)
		// carry over unless overridden.
		if basePageRef != nil && pageOffset < bvs {
			node, err := e.fetchNode(ctx, *basePageRef, KindDataPage)
			if err != nil {
				return nil, nil, err
			}
			for cellIndex, cell := range node.DataPage.Cells {
				if cell == nil {
					continue
				}
				cellStart := pageOffset + uint64(cellIndex)*CellBytes
				if cellStart >= bvs || cellStart >= finalSize {
					continue // hidden by shrink (or beyond final EOF)
				}
				if data, overridden := pp.overrides[cellIndex]; overridden {
					// Unchanged-cell reuse: an override whose logical
					// digest equals the base cell's keeps the base
					// CellRef, without fetching or repacking its bytes.
					if data != nil && RefOf(data).Digest == cell.CellDigest {
						pp.state.keep[cellIndex] = *cell
						delete(pp.overrides, cellIndex)
					}
					continue
				}
				pp.state.keep[cellIndex] = *cell
			}
		}
		for cellIndex, data := range pp.overrides {
			if data == nil {
				continue // hole
			}
			cellStart := pageOffset + uint64(cellIndex)*CellBytes
			if cellStart >= finalSize {
				return nil, nil, invalidf("inode %d: staged cell at %d beyond final size %d",
					st.ino, cellStart, finalSize)
			}
			pp.state.repack[cellIndex] = true
			cells = append(cells, changedCell{
				pageOffset: pageOffset,
				cellIndex:  cellIndex,
				data:       data,
			})
		}
		out = append(out, pp.state)
	}
	return out, cells, nil
}

// collectExtentRange returns every base extent entry with pageOffset >=
// fromPage in one ordered range walk, pruning subtrees by their advertised
// ranges and verifying every fetched descent against its parent-advertised
// summary. The returned entries carry the verified page refs, so callers
// never re-search the tree for them.
func (e *Editor) collectExtentRange(ctx context.Context, root Ref, fromPage uint64) ([]ExtentEntry, error) {
	var out []ExtentEntry
	var walk func(ref Ref, edge *edgeSummary, depth int) error
	walk = func(ref Ref, edge *edgeSummary, depth int) error {
		if depth > MaxTreeDepth {
			return boundExceededf("extent depth")
		}
		node, err := e.fetchNode(ctx, ref, KindExtentLeaf, KindExtentIndex)
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
				entry := node.ExtentLeaf.Entries[i]
				if entry.PageOffset >= fromPage {
					out = append(out, entry)
				}
			}
			return nil
		}
		for i := range node.ExtentIndex.Children {
			child := &node.ExtentIndex.Children[i]
			if child.LastPage < fromPage {
				continue
			}
			childEdge := extentChildSummary(child)
			if err := walk(child.Child, &childEdge, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(root, nil, 1); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PageOffset < out[j].PageOffset })
	return out, nil
}

// buildExtentRoot stages final DataPage nodes and updates the extent tree.
func (e *Editor) buildExtentRoot(
	ctx context.Context,
	p *planBuilder,
	st *editorInode,
	pages []*pageState,
	cellRefByKey map[[3]uint64]CellRef,
) (*Ref, error) {
	var edits []btreeEdit
	for _, page := range pages {
		dataPage := &DataPage{}
		present := 0
		for cellIndex, cell := range page.keep {
			cellCopy := cell
			dataPage.Cells[cellIndex] = &cellCopy
			present++
		}
		for cellIndex := range page.repack {
			cellRef, ok := cellRefByKey[[3]uint64{page.ino, page.pageOffset, uint64(cellIndex)}]
			if !ok {
				return nil, invalidf("internal: missing packed cell for inode %d page %d cell %d",
					page.ino, page.pageOffset, cellIndex)
			}
			cellCopy := cellRef
			dataPage.Cells[cellIndex] = &cellCopy
			present++
		}
		if present == 0 {
			if page.baseRef != nil {
				edits = append(edits, btreeEdit{key: u64Key(page.pageOffset)})
			}
			continue
		}
		ref, err := p.stageNode(&Node{Kind: KindDataPage, DataPage: dataPage})
		if err != nil {
			return nil, err
		}
		if page.baseRef != nil && ref == *page.baseRef {
			continue // identical page: reuse without an edit
		}
		edits = append(edits, btreeEdit{
			key:   u64Key(page.pageOffset),
			value: ExtentEntry{PageOffset: page.pageOffset, Page: ref},
		})
	}
	sortBtreeEdits(edits)
	var baseExtentRoot *Ref
	if st.baseExists && st.baseMeta.Kind == FileKindRegular {
		baseExtentRoot = st.baseMeta.ExtentRoot
	}
	return p.updater(extentShape{}).updateBTreeRoot(ctx, baseExtentRoot, edits)
}

// buildDirectoryRoot updates one live directory tree.
func (e *Editor) buildDirectoryRoot(
	ctx context.Context, p *planBuilder, st *editorInode, edits map[string]*dirEdit,
) (*Ref, error) {
	treeEdits := make([]btreeEdit, 0, len(edits))
	for name, edit := range edits {
		if edit.entry == nil {
			treeEdits = append(treeEdits, btreeEdit{key: []byte(name)})
		} else {
			treeEdits = append(treeEdits, btreeEdit{key: []byte(name), value: *edit.entry})
		}
	}
	sortBtreeEdits(treeEdits)
	var baseDirRoot *Ref
	if st.baseExists && st.baseMeta.Kind == FileKindDirectory {
		baseDirRoot = st.baseMeta.DirectoryRoot
	}
	return p.updater(directoryShape{}).updateBTreeRoot(ctx, baseDirRoot, treeEdits)
}

// assembleFinalInode composes the complete stored inode for one live ino.
func (e *Editor) assembleFinalInode(
	st *editorInode, extentRoots map[uint64]*Ref, dirRoots map[uint64]*Ref,
) (Inode, error) {
	final := st.mergedMeta()
	final.Ino = st.ino
	switch final.Kind {
	case FileKindRegular:
		if st.contentDirty {
			final.Size = st.size
			final.ExtentRoot = extentRoots[st.ino]
		} else if st.baseExists {
			final.Size = st.baseMeta.Size
			final.ExtentRoot = st.baseMeta.ExtentRoot
		} else {
			final.Size = 0
		}
		if final.Size == 0 {
			final.ExtentRoot = nil
		}
	case FileKindDirectory:
		if root, ok := dirRoots[st.ino]; ok {
			final.DirectoryRoot = root
		} else if st.baseExists {
			final.DirectoryRoot = st.baseMeta.DirectoryRoot
		}
	case FileKindSymlink:
		final.Size = uint64(len(final.SymlinkTarget))
	}
	return final, nil
}
