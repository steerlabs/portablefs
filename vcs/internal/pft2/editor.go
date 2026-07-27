package pft2

import (
	"context"
	"sync"
)

// Editor is a private, in-memory PFT2 path-copy transaction for the
// asynchronous HistoryCut worker. It opens an existing filesystem ROOT (and
// optional parked-orphan index) through the strict bounded reader, stages
// low-level edits with full coalescing (only final values matter), and on
// Commit deterministically path-copies exactly the changed nodes.
//
// Scope: this package provides mechanical low-level operations only —
// get/put/delete inode, get/put/delete directory entry, sparse cell
// write/zero, exact truncate, metadata updates, and parked-orphan index
// membership. High-level filesystem transition semantics (rename, unlink,
// nlink maintenance, orphan parking policy) belong to the shared transition
// engine outside this package; the editor enforces only the structural
// invariants the format itself demands.
//
// Atomicity: no operation and no failure publishes anything. Commit first
// computes the complete deterministic plan in memory (every new object's
// bytes, digest, and size finalized) and only then emits through the caller's
// sinks; a validation, allocation, fetch, or sink failure returns a typed
// error and publishes no new root. A failed Commit leaves the editor usable
// and the retained plan makes retry emit byte-identical objects.
//
// The editor performs no object-store work itself and must never run on an
// ordinary write path: it exists for immutable history/base construction.
// Editors are safe for concurrent use by multiple goroutines; the final
// committed bytes depend only on the final coalesced edit set, never on
// staging order, goroutine count, retry, or resume.
type Editor struct {
	mu sync.Mutex

	reader      *TreeReader
	baseRoot    *Root // nil = empty base
	baseRootRef Ref
	orphanBase  *Ref
	limits      EditorLimits
	budget      op // per-transaction traversal budget (ops + commit)

	sealed bool
	plan   *commitPlan

	inodes   map[uint64]*editorInode
	dirEdits map[uint64]map[string]*dirEdit

	editCount       int
	stagedCellBytes int64

	rootXattrLeaves []Ref
	rootXattrsSet   bool
}

// EditorLimits bounds one transaction. Zero values select the defaults.
// Every bound is enforced before the corresponding allocation; exceeding a
// staging bound fails typed with ErrTransactionLimit, and traversal bounds
// fail with ErrBoundExceeded.
type EditorLimits struct {
	// MaxEdits bounds staged edit operations (default 1<<20).
	MaxEdits int
	// MaxStagedCellBytes bounds retained staged cell bytes (default 256 MiB).
	MaxStagedCellBytes int64
	// MaxFetchNodes bounds node VISITS across the whole transaction —
	// cache hits included, so repeated walks over hot paths consume budget
	// (default 65536).
	MaxFetchNodes int
	// MaxFetchBytes bounds visited object bytes across the transaction,
	// packs included and cache hits included (default 256 MiB). Many-edit
	// transactions walk index paths once per operation, so this scales with
	// edits × node size, not with unique objects.
	MaxFetchBytes int64
	// MaxNewObjects bounds new objects one commit may produce
	// (default 65536).
	MaxNewObjects int
	// MaxNewObjectBytes bounds new object bytes one commit may produce
	// (default 512 MiB).
	MaxNewObjectBytes int64
}

func (l EditorLimits) withDefaults() EditorLimits {
	if l.MaxEdits <= 0 {
		l.MaxEdits = 1 << 20
	}
	if l.MaxStagedCellBytes <= 0 {
		l.MaxStagedCellBytes = 256 << 20
	}
	if l.MaxFetchNodes <= 0 {
		l.MaxFetchNodes = 65536
	}
	if l.MaxFetchBytes <= 0 {
		l.MaxFetchBytes = 256 << 20
	}
	if l.MaxNewObjects <= 0 {
		l.MaxNewObjects = 65536
	}
	if l.MaxNewObjectBytes <= 0 {
		l.MaxNewObjectBytes = 512 << 20
	}
	return l
}

// inode index home of one edited inode.
const (
	homeInherit = iota // untouched membership: whatever the base says
	homeFS
	homeOrphan
	homeDeleted
)

type editorInode struct {
	ino uint64

	baseLoaded bool
	baseExists bool
	baseHome   int // homeFS or homeOrphan when baseExists
	baseMeta   Inode
	baseRef    Ref

	finalHome  int // homeInherit until an index-membership op stages one
	meta       Inode
	metaStaged bool

	contentTouched bool              // overlay initialized (reads included)
	contentDirty   bool              // content actually edited (write/zero/truncate)
	size           uint64            // merged logical size (valid when contentTouched)
	baseVisible    uint64            // base bytes still visible after shrinks
	cells          map[uint64][]byte // cellOffset -> 4096 bytes; nil = hole
}

type dirEdit struct {
	entry       *DirEntry // nil = delete
	baseExisted bool
}

// NewEditor opens a transaction over the filesystem ROOT the reader is
// anchored at, plus an optional parked-orphan inode index root (from the
// recovery anchor). A nil reader opens an empty base: the transaction must
// then create inode 1 before it can commit. The base root is fetched and
// verified eagerly so a corrupt base fails here, before any edit.
func NewEditor(ctx context.Context, reader *TreeReader, orphanIndex *Ref, limits EditorLimits) (*Editor, error) {
	e := &Editor{
		reader:   reader,
		limits:   limits.withDefaults(),
		inodes:   map[uint64]*editorInode{},
		dirEdits: map[uint64]map[string]*dirEdit{},
	}
	e.budget = op{
		nodesLeft: e.limits.MaxFetchNodes,
		bytesLeft: e.limits.MaxFetchBytes,
		maxDepth:  MaxTreeDepth,
	}
	if orphanIndex != nil {
		if reader == nil {
			return nil, invalidf("editor: orphan index requires a base reader")
		}
		if err := checkNodeRefBounds("editor orphan index", *orphanIndex); err != nil {
			return nil, err
		}
		refCopy := *orphanIndex
		e.orphanBase = &refCopy
	}
	if reader != nil {
		node, err := reader.fetchNode(ctx, &e.budget, reader.rootRef, KindRoot)
		if err != nil {
			return nil, err
		}
		e.baseRoot = node.Root
		e.baseRootRef = reader.rootRef
	}
	return e, nil
}

// SetRootXattrLeaves sets the filesystem-homed xattr projection that the
// next Commit embeds in Root. It is metadata-only, coalesces to the last
// call, and does not fetch the tree or stage object bytes. History
// materialization uses it after reducing a whole cut, avoiding a throwaway
// intermediate Root object.
func (e *Editor) SetRootXattrLeaves(refs []Ref) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sealed {
		return invalidf("editor: transaction is sealed")
	}
	for i, ref := range refs {
		if err := checkNodeRefBounds("editor root xattr leaf", ref); err != nil {
			return invalidf("editor root xattr leaf %d: %v", i, err)
		}
	}
	e.rootXattrLeaves = append([]Ref(nil), refs...)
	e.rootXattrsSet = true
	e.plan = nil
	return nil
}

// fetchNode charges the transaction budget and fetches a verified node.
func (e *Editor) fetchNode(ctx context.Context, ref Ref, allowed ...Kind) (*Node, error) {
	if e.reader == nil {
		return nil, corruptf("editor: fetch %s against an empty base", ref.Hex())
	}
	return e.reader.fetchNode(ctx, &e.budget, ref, allowed...)
}

// budgetSnapshot implements retry-safe budget semantics for one staged
// operation or plan-build attempt: `defer e.budgetSnapshot()(&err)` restores
// the traversal budget and edit count to their pre-attempt values when the
// attempt fails, so a transient fetch failure or rejected plan never
// permanently drains the transaction and an exact retry sees the identical
// budget. Each attempt stays bounded by the snapshot itself, and staged
// state is only mutated after an operation's last fallible step, so a failed
// attempt leaves no partial edit behind.
func (e *Editor) budgetSnapshot() func(*error) {
	budget, edits := e.budget, e.editCount
	return func(errp *error) {
		if *errp != nil {
			e.budget, e.editCount = budget, edits
		}
	}
}

// fetchPack charges the budget and fetches one verified packed data object.
func (e *Editor) fetchPack(ctx context.Context, ref Ref) ([]byte, error) {
	if e.reader == nil {
		return nil, corruptf("editor: pack fetch against an empty base")
	}
	if err := checkPackRefBounds("editor pack", ref); err != nil {
		return nil, err
	}
	if err := e.budget.charge(ref.Size); err != nil {
		return nil, err
	}
	data, err := e.reader.fetcher.Fetch(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err := VerifyObjectBytes(ref, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (e *Editor) chargeEdit() error {
	if e.sealed {
		return ErrEditorSealed
	}
	if e.editCount >= e.limits.MaxEdits {
		return transactionLimitf("edit count exceeds %d", e.limits.MaxEdits)
	}
	e.editCount++
	e.plan = nil // staged state changed: any retained plan is stale
	return nil
}

// ─── base loading ────────────────────────────────────────────────────────────

func (e *Editor) inodeState(ino uint64) *editorInode {
	st, ok := e.inodes[ino]
	if !ok {
		st = &editorInode{ino: ino, finalHome: homeInherit}
		e.inodes[ino] = st
	}
	return st
}

// loadBase resolves the inode's base facts exactly once: which index holds
// it (filesystem first, then the orphan index) and its stored inode object.
// A fetch failure leaves the facts unresolved so a retried operation walks
// again instead of adopting a poisoned "not found".
func (e *Editor) loadBase(ctx context.Context, st *editorInode) error {
	if st.baseLoaded {
		return nil
	}
	if e.baseRoot != nil {
		ref, found, err := e.findInodeRef(ctx, e.baseRoot.InodeIndex, e.baseRoot, st.ino)
		if err != nil {
			return err
		}
		if found {
			return e.loadBaseObject(ctx, st, ref, homeFS)
		}
	}
	if e.orphanBase != nil {
		// The orphan index root carries no advertised facts (the recovery
		// anchor references it bare), so only the edges below it verify.
		ref, found, err := e.findInodeRef(ctx, *e.orphanBase, nil, st.ino)
		if err != nil {
			return err
		}
		if found {
			return e.loadBaseObject(ctx, st, ref, homeOrphan)
		}
	}
	st.baseLoaded = true
	return nil
}

func (e *Editor) loadBaseObject(ctx context.Context, st *editorInode, ref Ref, home int) error {
	node, err := e.fetchNode(ctx, ref, KindInode)
	if err != nil {
		return err
	}
	if node.Inode.Ino != st.ino {
		return corruptf("inode object %s carries ino %d, index advertised %d",
			ref.Hex(), node.Inode.Ino, st.ino)
	}
	st.baseLoaded = true
	st.baseExists = true
	st.baseHome = home
	st.baseMeta = *node.Inode
	st.baseRef = ref
	return nil
}

// findInodeRef walks one inode index by number, returning the INODE ref.
// Every fetched descent verifies the child against its parent-advertised
// summary; when facts is non-nil (the filesystem index) the root node
// additionally verifies against the ROOT object's inode facts.
func (e *Editor) findInodeRef(ctx context.Context, root Ref, facts *Root, ino uint64) (Ref, bool, error) {
	ref := root
	var edge *edgeSummary
	for depth := 1; ; depth++ {
		if depth > MaxTreeDepth {
			return Ref{}, false, boundExceededf("inode index depth")
		}
		node, err := e.fetchNode(ctx, ref, KindInodeIndexLeaf, KindInodeIndexIndex)
		if err != nil {
			return Ref{}, false, err
		}
		if edge != nil {
			err = verifyEdgeSummary("inode index child", ref, node, *edge)
		} else if facts != nil {
			err = verifyFSIndexRootFacts(facts, ref, node)
		}
		if err != nil {
			return Ref{}, false, err
		}
		if node.Kind == KindInodeIndexLeaf {
			for i := range node.InodeIndexLeaf.Entries {
				entry := &node.InodeIndexLeaf.Entries[i]
				if entry.Ino == ino {
					return entry.Inode, true, nil
				}
			}
			return Ref{}, false, nil
		}
		child, ok := findInodeIndexChild(node.InodeIndexIndex, ino)
		if !ok {
			return Ref{}, false, nil
		}
		summary := inodeChildSummary(child)
		edge = &summary
		ref = child.Child
	}
}

// findDirEntry walks one directory tree by name, verifying every fetched
// descent against its parent-advertised summary.
func (e *Editor) findDirEntry(ctx context.Context, root Ref, name string) (DirEntry, bool, error) {
	ref := root
	var edge *edgeSummary
	for depth := 1; ; depth++ {
		if depth > MaxTreeDepth {
			return DirEntry{}, false, boundExceededf("directory depth")
		}
		node, err := e.fetchNode(ctx, ref, KindDirectoryLeaf, KindDirectoryIndex)
		if err != nil {
			return DirEntry{}, false, err
		}
		if edge != nil {
			if err := verifyEdgeSummary("directory child", ref, node, *edge); err != nil {
				return DirEntry{}, false, err
			}
		}
		if node.Kind == KindDirectoryLeaf {
			for i := range node.DirectoryLeaf.Entries {
				entry := &node.DirectoryLeaf.Entries[i]
				if entry.Name == name {
					return *entry, true, nil
				}
			}
			return DirEntry{}, false, nil
		}
		child, ok := findDirectoryChild(node.DirectoryIndex, name)
		if !ok {
			return DirEntry{}, false, nil
		}
		summary := directoryChildSummary(child)
		edge = &summary
		ref = child.Child
	}
}

// mergedHome resolves the inode's final index membership.
func (st *editorInode) mergedHome() int {
	if st.finalHome != homeInherit {
		return st.finalHome
	}
	if st.baseExists {
		return st.baseHome
	}
	return homeDeleted // never existed
}

// mergedMeta resolves the inode's final metadata (roots stripped).
func (st *editorInode) mergedMeta() Inode {
	var meta Inode
	if st.metaStaged {
		meta = st.meta
	} else {
		meta = st.baseMeta
	}
	meta.DirectoryRoot = nil
	meta.ExtentRoot = nil
	return meta
}

// mergedSize resolves the inode's final logical size.
func (st *editorInode) mergedSize() uint64 {
	if st.contentTouched {
		return st.size
	}
	meta := st.mergedMeta()
	if st.metaStaged && meta.Kind == FileKindSymlink {
		return uint64(len(meta.SymlinkTarget))
	}
	if st.baseExists {
		return st.baseMeta.Size
	}
	return meta.Size
}

// ensureLive loads base facts and confirms the inode exists in home.
func (e *Editor) ensureLive(ctx context.Context, ino uint64, home int) (*editorInode, error) {
	if ino < 1 || ino > MaxIno {
		return nil, invalidf("ino %d outside 1..%d", ino, MaxIno)
	}
	st := e.inodeState(ino)
	if err := e.loadBase(ctx, st); err != nil {
		return nil, err
	}
	if st.mergedHome() != home {
		return nil, notFoundf("ino %d is not live in the requested index", ino)
	}
	return st, nil
}

// ─── inode operations ────────────────────────────────────────────────────────

// GetInode returns the merged view of a filesystem-homed inode. The returned
// Size is the merged logical size; DirectoryRoot/ExtentRoot are always nil
// (tree roots are resolved at commit).
func (e *Editor) GetInode(ctx context.Context, ino uint64) (meta Inode, found bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.budgetSnapshot()(&err)
	return e.getInodeLocked(ctx, ino, homeFS)
}

// GetOrphanInode is GetInode against the parked-orphan index.
func (e *Editor) GetOrphanInode(ctx context.Context, ino uint64) (meta Inode, found bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.budgetSnapshot()(&err)
	return e.getInodeLocked(ctx, ino, homeOrphan)
}

func (e *Editor) getInodeLocked(ctx context.Context, ino uint64, home int) (Inode, bool, error) {
	st, err := e.ensureLive(ctx, ino, home)
	if err != nil {
		if errIsNotFound(err) {
			return Inode{}, false, nil
		}
		return Inode{}, false, err
	}
	meta := st.mergedMeta()
	meta.Size = st.mergedSize()
	return meta, true, nil
}

func errIsNotFound(err error) bool {
	_, ok := err.(*notFoundError)
	return ok
}

// PutInode upserts an inode into the filesystem index. The value carries
// metadata only: DirectoryRoot/ExtentRoot must be nil (the editor owns tree
// roots), and for regular files the Size field is ignored (use SetFileSize).
// Changing the kind of an inode that exists in the base is rejected: stable
// inode identity is what makes hard links and rename-aware merge work.
func (e *Editor) PutInode(ctx context.Context, inode Inode) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.budgetSnapshot()(&err)
	return e.putInodeLocked(ctx, inode, homeFS)
}

// PutOrphanInode is PutInode against the parked-orphan index.
func (e *Editor) PutOrphanInode(ctx context.Context, inode Inode) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.budgetSnapshot()(&err)
	return e.putInodeLocked(ctx, inode, homeOrphan)
}

func (e *Editor) putInodeLocked(ctx context.Context, inode Inode, home int) error {
	if err := e.chargeEdit(); err != nil {
		return err
	}
	if inode.Ino < 1 || inode.Ino > MaxIno {
		return invalidf("ino %d outside 1..%d", inode.Ino, MaxIno)
	}
	if inode.DirectoryRoot != nil || inode.ExtentRoot != nil {
		return invalidf("inode %d: tree roots are editor-owned; put metadata only", inode.Ino)
	}
	st := e.inodeState(inode.Ino)
	if err := e.loadBase(ctx, st); err != nil {
		return err
	}
	if st.baseExists && st.baseMeta.Kind != inode.Kind {
		return invalidf("inode %d: kind change from %s to %s is forbidden",
			inode.Ino, st.baseMeta.Kind, inode.Kind)
	}
	if st.metaStaged && st.meta.Kind != inode.Kind {
		return invalidf("inode %d: kind change from %s to %s is forbidden",
			inode.Ino, st.meta.Kind, inode.Kind)
	}
	meta := inode
	switch meta.Kind {
	case FileKindRegular:
		meta.Size = 0 // size is owned by SetFileSize / content state
	case FileKindSymlink:
		meta.Size = uint64(len(meta.SymlinkTarget))
	case FileKindDirectory:
		if meta.Size != 0 {
			return invalidf("inode %d: directory size must be 0", meta.Ino)
		}
	default:
		return invalidf("inode %d: unknown file kind %d", meta.Ino, meta.Kind)
	}
	// Validate the metadata subset now (roots and file size settle at commit).
	probe := meta
	if err := (&probe).validate(); err != nil {
		return err
	}
	st.meta = meta
	st.metaStaged = true
	st.finalHome = home
	return nil
}

// DeleteInode removes an inode from the filesystem index. The inode must be
// live there; a deleted directory must be empty at commit.
func (e *Editor) DeleteInode(ctx context.Context, ino uint64) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.budgetSnapshot()(&err)
	return e.deleteInodeLocked(ctx, ino, homeFS)
}

// DeleteOrphanInode removes an inode from the parked-orphan index.
func (e *Editor) DeleteOrphanInode(ctx context.Context, ino uint64) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.budgetSnapshot()(&err)
	return e.deleteInodeLocked(ctx, ino, homeOrphan)
}

func (e *Editor) deleteInodeLocked(ctx context.Context, ino uint64, home int) error {
	if err := e.chargeEdit(); err != nil {
		return err
	}
	st, err := e.ensureLive(ctx, ino, home)
	if err != nil {
		return err
	}
	st.finalHome = homeDeleted
	return nil
}

// ─── directory entry operations ──────────────────────────────────────────────

// GetDirEntry resolves one name in a filesystem directory's merged view.
func (e *Editor) GetDirEntry(ctx context.Context, parent uint64, name string) (entry DirEntry, found bool, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.budgetSnapshot()(&err)
	if err := ValidateEntryName(name); err != nil {
		return DirEntry{}, false, err
	}
	st, err := e.directoryState(ctx, parent)
	if err != nil {
		return DirEntry{}, false, err
	}
	if edits, ok := e.dirEdits[parent]; ok {
		if edit, staged := edits[name]; staged {
			if edit.entry == nil {
				return DirEntry{}, false, nil
			}
			return *edit.entry, true, nil
		}
	}
	return e.baseDirLookup(ctx, st, name)
}

func (e *Editor) directoryState(ctx context.Context, parent uint64) (*editorInode, error) {
	st, err := e.ensureLive(ctx, parent, homeFS)
	if err != nil {
		return nil, err
	}
	if st.mergedMeta().Kind != FileKindDirectory {
		return nil, invalidf("inode %d is %s, not a directory", parent, st.mergedMeta().Kind)
	}
	return st, nil
}

// directoryStateForDelete additionally accepts a directory that was deleted
// in this transaction (it was filesystem-homed in the base).
func (e *Editor) directoryStateForDelete(ctx context.Context, parent uint64) (*editorInode, error) {
	if parent < 1 || parent > MaxIno {
		return nil, invalidf("ino %d outside 1..%d", parent, MaxIno)
	}
	st := e.inodeState(parent)
	if err := e.loadBase(ctx, st); err != nil {
		return nil, err
	}
	home := st.mergedHome()
	deletedFromFS := home == homeDeleted && st.baseExists && st.baseHome == homeFS
	if home != homeFS && !deletedFromFS {
		return nil, notFoundf("ino %d is not live in the filesystem index", parent)
	}
	if st.mergedMeta().Kind != FileKindDirectory {
		return nil, invalidf("inode %d is %s, not a directory", parent, st.mergedMeta().Kind)
	}
	return st, nil
}

func (e *Editor) baseDirLookup(ctx context.Context, st *editorInode, name string) (DirEntry, bool, error) {
	if !st.baseExists || st.baseMeta.DirectoryRoot == nil {
		return DirEntry{}, false, nil
	}
	return e.findDirEntry(ctx, *st.baseMeta.DirectoryRoot, name)
}

// PutDirEntry upserts one entry in a filesystem directory. The target inode
// must be live in the filesystem index at commit; the entry kind must match
// the target inode kind.
func (e *Editor) PutDirEntry(ctx context.Context, parent uint64, entry DirEntry) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.budgetSnapshot()(&err)
	if err := ValidateEntryName(entry.Name); err != nil {
		return err
	}
	if entry.Ino < 1 || entry.Ino > MaxIno {
		return invalidf("dir entry %q: ino %d outside 1..%d", entry.Name, entry.Ino, MaxIno)
	}
	if !validFileKind(entry.Kind) {
		return invalidf("dir entry %q: unknown kind %d", entry.Name, entry.Kind)
	}
	if err := e.chargeEdit(); err != nil {
		return err
	}
	st, err := e.directoryState(ctx, parent)
	if err != nil {
		return err
	}
	edit, _, err := e.dirEditState(ctx, st, entry.Name)
	if err != nil {
		return err
	}
	entryCopy := entry
	edit.entry = &entryCopy
	return nil
}

// DeleteDirEntry removes one entry; deleting an absent name is ErrNotFound.
// Deletes are also accepted on a directory deleted in this same transaction,
// because a deleted directory must commit empty and the transition engine
// may stage the operations in either order.
func (e *Editor) DeleteDirEntry(ctx context.Context, parent uint64, name string) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.budgetSnapshot()(&err)
	if err := ValidateEntryName(name); err != nil {
		return err
	}
	if err := e.chargeEdit(); err != nil {
		return err
	}
	st, err := e.directoryStateForDelete(ctx, parent)
	if err != nil {
		return err
	}
	edit, wasStaged, err := e.dirEditState(ctx, st, name)
	if err != nil {
		return err
	}
	present := edit.baseExisted
	if wasStaged {
		present = edit.entry != nil
	}
	if !present {
		return notFoundf("dir entry %q absent in inode %d", name, parent)
	}
	edit.entry = nil
	return nil
}

// DirEntryCount returns the merged live entry count of a filesystem
// directory: the base tree's verified count plus staged dirent edits. The
// transition engine's rmdir/rename-emptiness decisions read THIS count, so
// they observe staged puts and deletes exactly like committed state.
func (e *Editor) DirEntryCount(ctx context.Context, parent uint64) (count uint64, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.budgetSnapshot()(&err)
	st, err := e.directoryState(ctx, parent)
	if err != nil {
		return 0, err
	}
	count, err = e.baseDirEntryCount(ctx, st)
	if err != nil {
		return 0, err
	}
	for _, edit := range e.dirEdits[parent] {
		switch {
		case edit.entry == nil && edit.baseExisted:
			if count == 0 {
				return 0, corruptf("directory %d staged deletes underflow its base count", parent)
			}
			count--
		case edit.entry != nil && !edit.baseExisted:
			count++
		}
	}
	return count, nil
}

// dirEditState resolves (creating if needed) the staged edit slot for one
// (parent, name), resolving base existence exactly once. wasStaged reports
// whether an edit for the name already existed.
func (e *Editor) dirEditState(ctx context.Context, st *editorInode, name string) (*dirEdit, bool, error) {
	edits, ok := e.dirEdits[st.ino]
	if !ok {
		edits = map[string]*dirEdit{}
		e.dirEdits[st.ino] = edits
	}
	if edit, staged := edits[name]; staged {
		return edit, true, nil
	}
	_, existed, err := e.baseDirLookup(ctx, st, name)
	if err != nil {
		return nil, false, err
	}
	edit := &dirEdit{baseExisted: existed}
	edits[name] = edit
	return edit, false, nil
}

// ─── file content operations ─────────────────────────────────────────────────

// fileState resolves the content overlay for one live regular file,
// initializing merged size/base visibility on first touch.
func (e *Editor) fileState(ctx context.Context, ino uint64) (*editorInode, error) {
	st := e.inodeState(ino)
	if err := e.loadBase(ctx, st); err != nil {
		return nil, err
	}
	if st.mergedHome() == homeDeleted {
		return nil, notFoundf("ino %d is not live", ino)
	}
	if st.mergedMeta().Kind != FileKindRegular {
		return nil, invalidf("inode %d is %s, not a regular file", ino, st.mergedMeta().Kind)
	}
	if !st.contentTouched {
		st.contentTouched = true
		if st.baseExists && st.baseMeta.Kind == FileKindRegular {
			st.size = st.baseMeta.Size
			st.baseVisible = st.baseMeta.Size
		} else {
			st.size = 0
			st.baseVisible = 0
		}
		st.cells = map[uint64][]byte{}
	}
	return st, nil
}

func checkCellOffset(cellOffset uint64) error {
	if cellOffset%CellBytes != 0 {
		return invalidf("cell offset %d is not %d-aligned", cellOffset, CellBytes)
	}
	if cellOffset > MaxLogicalFileBytes-CellBytes {
		return invalidf("cell offset %d out of range", cellOffset)
	}
	return nil
}

// WriteCell stages the canonical CellBytes logical bytes of one aligned
// cell. An all-zero cell stages a hole. Writing does not change the logical
// size: the transition engine owns size via SetFileSize, and a staged
// nonzero cell at or beyond the final size fails the commit.
func (e *Editor) WriteCell(ctx context.Context, ino uint64, cellOffset uint64, cell []byte) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.budgetSnapshot()(&err)
	if len(cell) != CellBytes {
		return invalidf("cell is %d bytes (want %d)", len(cell), CellBytes)
	}
	if err := checkCellOffset(cellOffset); err != nil {
		return err
	}
	if err := e.chargeEdit(); err != nil {
		return err
	}
	st, err := e.fileState(ctx, ino)
	if err != nil {
		return err
	}
	st.contentDirty = true
	if IsZeroCell(cell) {
		if prior, ok := st.cells[cellOffset]; ok && prior != nil {
			e.stagedCellBytes -= CellBytes
		}
		st.cells[cellOffset] = nil
		return nil
	}
	if prior, ok := st.cells[cellOffset]; !ok || prior == nil {
		if e.stagedCellBytes+CellBytes > e.limits.MaxStagedCellBytes {
			return transactionLimitf("staged cell bytes exceed %d", e.limits.MaxStagedCellBytes)
		}
		e.stagedCellBytes += CellBytes
	}
	st.cells[cellOffset] = append([]byte(nil), cell...)
	return nil
}

// ZeroCell stages one aligned cell as an explicit hole.
func (e *Editor) ZeroCell(ctx context.Context, ino uint64, cellOffset uint64) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.budgetSnapshot()(&err)
	if err := checkCellOffset(cellOffset); err != nil {
		return err
	}
	if err := e.chargeEdit(); err != nil {
		return err
	}
	st, err := e.fileState(ctx, ino)
	if err != nil {
		return err
	}
	st.contentDirty = true
	if prior, ok := st.cells[cellOffset]; ok && prior != nil {
		e.stagedCellBytes -= CellBytes
	}
	st.cells[cellOffset] = nil
	return nil
}

// ReadCell returns the merged canonical CellBytes bytes of one aligned cell
// (zeros for holes and beyond the merged EOF), fetching at most the base
// extent path, one page node, and one pack.
func (e *Editor) ReadCell(ctx context.Context, ino uint64, cellOffset uint64) (merged []byte, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.budgetSnapshot()(&err)
	if err := checkCellOffset(cellOffset); err != nil {
		return nil, err
	}
	st, err := e.fileState(ctx, ino)
	if err != nil {
		return nil, err
	}
	if staged, ok := st.cells[cellOffset]; ok {
		out := make([]byte, CellBytes)
		copy(out, staged) // nil staged = hole = zeros
		return out, nil
	}
	if cellOffset >= st.size || cellOffset >= st.baseVisible {
		return make([]byte, CellBytes), nil
	}
	cell, err := e.baseCell(ctx, st, cellOffset)
	if err != nil {
		return nil, err
	}
	out := make([]byte, CellBytes)
	if cell != nil {
		copy(out, cell)
	}
	// Base bytes at or beyond the visible boundary read as zero.
	if st.baseVisible-cellOffset < CellBytes {
		zeroFrom := st.baseVisible - cellOffset
		for i := zeroFrom; i < CellBytes; i++ {
			out[i] = 0
		}
	}
	return out, nil
}

// baseCell fetches one base cell's verified canonical bytes (nil = hole).
func (e *Editor) baseCell(ctx context.Context, st *editorInode, cellOffset uint64) ([]byte, error) {
	if !st.baseExists || st.baseMeta.ExtentRoot == nil {
		return nil, nil
	}
	pageOffset := cellOffset / PageBytes * PageBytes
	pageRef, found, err := e.findExtentPage(ctx, *st.baseMeta.ExtentRoot, pageOffset)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	node, err := e.fetchNode(ctx, pageRef, KindDataPage)
	if err != nil {
		return nil, err
	}
	cell := node.DataPage.Cells[(cellOffset-pageOffset)/CellBytes]
	if cell == nil {
		return nil, nil
	}
	pack, err := e.fetchPack(ctx, cell.Object)
	if err != nil {
		return nil, err
	}
	logicalValid := uint64(CellBytes)
	if remaining := st.baseMeta.Size - cellOffset; remaining < logicalValid {
		logicalValid = remaining
	}
	return VerifyCellBytes(cell, pack, logicalValid)
}

// findExtentPage walks one base extent tree to the page at pageOffset,
// verifying every fetched descent against its parent-advertised summary.
func (e *Editor) findExtentPage(ctx context.Context, root Ref, pageOffset uint64) (Ref, bool, error) {
	ref := root
	var edge *edgeSummary
	for depth := 1; ; depth++ {
		if depth > MaxTreeDepth {
			return Ref{}, false, boundExceededf("extent depth")
		}
		node, err := e.fetchNode(ctx, ref, KindExtentLeaf, KindExtentIndex)
		if err != nil {
			return Ref{}, false, err
		}
		if edge != nil {
			if err := verifyEdgeSummary("extent child", ref, node, *edge); err != nil {
				return Ref{}, false, err
			}
		}
		if node.Kind == KindExtentLeaf {
			for i := range node.ExtentLeaf.Entries {
				entry := &node.ExtentLeaf.Entries[i]
				if entry.PageOffset == pageOffset {
					return entry.Page, true, nil
				}
			}
			return Ref{}, false, nil
		}
		found := false
		for i := range node.ExtentIndex.Children {
			child := &node.ExtentIndex.Children[i]
			if pageOffset >= child.FirstPage && pageOffset <= child.LastPage {
				summary := extentChildSummary(child)
				edge = &summary
				ref = child.Child
				found = true
				break
			}
		}
		if !found {
			return Ref{}, false, nil
		}
	}
}

// StagedCellBytes reports the cell bytes currently retained by staged
// nonzero cell writes — the exact quantity MaxStagedCellBytes bounds
// (holes and shrink-scrubbed cells release their bytes). Long folds read it
// to place checkpoint commits BEFORE the transaction limit can trip, which
// is more precise than estimating retained bytes from record payload sizes:
// coalesced overwrites and truncates never double-count.
func (e *Editor) StagedCellBytes() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stagedCellBytes
}

// SetFileSize stages an exact truncate. Shrinking hides base bytes past the
// new size and zeroes the staged suffix of a straddled cell, so a later grow
// reads zeros (shrink-then-grow can never reveal old base or dirty bytes);
// growing changes only the logical size.
func (e *Editor) SetFileSize(ctx context.Context, ino uint64, size uint64) (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.budgetSnapshot()(&err)
	if size > MaxLogicalFileBytes {
		return invalidf("size %d exceeds %d", size, MaxLogicalFileBytes)
	}
	if err := e.chargeEdit(); err != nil {
		return err
	}
	st, err := e.fileState(ctx, ino)
	if err != nil {
		return err
	}
	st.contentDirty = true
	if size >= st.size {
		st.size = size
		return nil
	}
	// Shrink: hide base bytes past the new size and scrub staged overlays.
	if st.baseVisible > size {
		st.baseVisible = size
	}
	for cellOffset, staged := range st.cells {
		if cellOffset >= size {
			// The whole staged cell is beyond the new EOF: it becomes a hole.
			if staged != nil {
				e.stagedCellBytes -= CellBytes
			}
			st.cells[cellOffset] = nil
			continue
		}
		if staged != nil && size-cellOffset < CellBytes {
			// Straddled staged cell: zero its suffix in place.
			zeroFrom := size - cellOffset
			for i := zeroFrom; i < CellBytes; i++ {
				staged[i] = 0
			}
			if IsZeroCell(staged) {
				e.stagedCellBytes -= CellBytes
				st.cells[cellOffset] = nil
			}
		}
	}
	st.size = size
	return nil
}
