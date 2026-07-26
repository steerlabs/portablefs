package workfs

import (
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// mutationTransaction is a touched-state undo log for one multi-mutation
// intent. It never clones the whole tree or every dirty block. Namespace undo
// copies only the child map of a directory the batch changes; content undo
// retains only block entries the batch overwrites/removes. Its cost is thus
// proportional to the batch's write set (and to an affected directory's
// dentry map), not to total live filesystem size.
type mutationTransaction struct {
	fs *FS

	clocks int64AndUint64
	alloc  inoAllocator
	// dirtyBytes snapshots the resident dirty-block counter at Begin: rollback
	// restores every captured block map byte-for-byte, so restoring the
	// counter to this snapshot is exact (Begin and rollback happen inside one
	// fs.mu hold — nothing else can move the counter in between).
	dirtyBytes int64

	inodes map[*inode]inode
	blocks []blockUndo

	orphans      map[uint64]inodeEntryUndo
	orphanLeases map[uint64]timeEntryUndo
	openInodes   map[uint64]openEntryUndo
	byIno        map[uint64]inodeEntryUndo
	pendingReaps map[uint64]uint32EntryUndo

	ctlSessionsNil   bool
	ctlWatermarksNil bool
	ctlSlotStates    int
	ctlSessions      map[string]sessionEntryUndo
	ctlWatermarks    map[string]watermarkEntryUndo
	ctlSlots         map[slotUndoKey]slotEntryUndo
}

// int64AndUint64 keeps the two apply clocks together without introducing a
// full-FS snapshot type.
type int64AndUint64 struct {
	i int64
	u uint64
}

type blockUndo struct {
	blocks map[int64][]byte
	index  int64
	value  []byte
	ok     bool
}

type inodeEntryUndo struct {
	value *inode
	ok    bool
}

type timeEntryUndo struct {
	value time.Time
	ok    bool
}

type openEntryUndo struct {
	value map[string]time.Time
	ok    bool
}

type uint32EntryUndo struct {
	value uint32
	ok    bool
}

type sessionEntryUndo struct {
	value *ctlSession
	ok    bool
}

type watermarkEntryUndo struct {
	value ctlWatermark
	ok    bool
}

type slotUndoKey struct {
	session string
	slot    uint32
}

type slotEntryUndo struct {
	value       *slotOutcome
	ok          bool
	outcomesNil bool
}

func newMutationTransaction(fs *FS) *mutationTransaction {
	return &mutationTransaction{
		fs:     fs,
		clocks: int64AndUint64{i: fs.epoch, u: fs.version}, alloc: fs.alloc,
		dirtyBytes: fs.dirtyBytes,
		inodes:     make(map[*inode]inode),
		orphans:    make(map[uint64]inodeEntryUndo), orphanLeases: make(map[uint64]timeEntryUndo),
		openInodes: make(map[uint64]openEntryUndo), byIno: make(map[uint64]inodeEntryUndo),
		pendingReaps:   make(map[uint64]uint32EntryUndo),
		ctlSessionsNil: fs.ctl.sessions == nil, ctlWatermarksNil: fs.ctl.watermarks == nil,
		ctlSlotStates: fs.ctl.slotStates,
		ctlSessions:   make(map[string]sessionEntryUndo), ctlWatermarks: make(map[string]watermarkEntryUndo),
		ctlSlots: make(map[slotUndoKey]slotEntryUndo),
	}
}

func cloneChildren(children map[string]*inode) map[string]*inode {
	if children == nil {
		return nil
	}
	cloned := make(map[string]*inode, len(children))
	for name, child := range children {
		cloned[name] = child
	}
	return cloned
}

func (tx *mutationTransaction) captureInode(n *inode) {
	if n == nil {
		return
	}
	if _, captured := tx.inodes[n]; captured {
		return
	}
	state := *n
	if n.kind == "directory" {
		state.children = cloneChildren(n.children)
	}
	// File blocks intentionally remain a shallow map reference. Individual
	// entries a mutation can replace/delete are retained by captureBlock.
	tx.inodes[n] = state
}

func (tx *mutationTransaction) captureBlock(n *inode, index int64) {
	if n == nil {
		return
	}
	block, ok := n.blocks[index]
	// applyWrite publishes a new slice and truncate only changes map entries or
	// slice headers, so retaining this immutable pre-apply slice is sufficient.
	// Retain the map itself as well: truncate-to-zero can replace n.blocks, and
	// reverse undo must repair the exact historical map before inode restoration.
	tx.blocks = append(tx.blocks, blockUndo{blocks: n.blocks, index: index, value: block, ok: ok})
}

func (tx *mutationTransaction) captureWriteBlocks(n *inode, off int64, length int) {
	if n == nil || length == 0 {
		return
	}
	last := (off + int64(length) - 1) / blockSize
	for bi := off / blockSize; bi <= last; bi++ {
		tx.captureBlock(n, bi)
	}
}

func (tx *mutationTransaction) captureTruncateBlocks(n *inode, size int64) {
	if n == nil || size <= 0 || size >= n.size {
		return
	}
	boundary := (size - 1) / blockSize
	for bi := range n.blocks {
		if bi >= boundary {
			tx.captureBlock(n, bi)
		}
	}
}

func (tx *mutationTransaction) captureOrphan(ino uint64) {
	if _, ok := tx.orphans[ino]; !ok {
		v, present := tx.fs.orphans[ino]
		tx.orphans[ino] = inodeEntryUndo{value: v, ok: present}
	}
	if _, ok := tx.orphanLeases[ino]; !ok {
		v, present := tx.fs.orphanLeases[ino]
		tx.orphanLeases[ino] = timeEntryUndo{value: v, ok: present}
	}
}

func (tx *mutationTransaction) captureOpen(ino uint64) {
	if _, ok := tx.openInodes[ino]; ok {
		return
	}
	v, present := tx.fs.openInodes[ino]
	tx.openInodes[ino] = openEntryUndo{value: v, ok: present}
}

func (tx *mutationTransaction) captureByIno(ino uint64) {
	if ino == 0 {
		return
	}
	if _, ok := tx.byIno[ino]; ok {
		return
	}
	v, present := tx.fs.byIno[ino]
	tx.byIno[ino] = inodeEntryUndo{value: v, ok: present}
}

func (tx *mutationTransaction) capturePendingReap(ino uint64) {
	if _, ok := tx.pendingReaps[ino]; ok {
		return
	}
	v, present := tx.fs.pendingReaps[ino]
	tx.pendingReaps[ino] = uint32EntryUndo{value: v, ok: present}
}

func cloneSlotOutcome(o *slotOutcome) *slotOutcome {
	if o == nil {
		return nil
	}
	cloned := *o
	cloned.reqHash = append([]byte(nil), o.reqHash...)
	return &cloned
}

func cloneCtlSession(s *ctlSession) *ctlSession {
	if s == nil {
		return nil
	}
	cloned := *s
	cloned.tokenHash = append([]byte(nil), s.tokenHash...)
	cloned.outcomes = make(map[uint32]*slotOutcome, len(s.outcomes))
	for slot, outcome := range s.outcomes {
		cloned.outcomes[slot] = cloneSlotOutcome(outcome)
	}
	return &cloned
}

func (tx *mutationTransaction) captureSession(id string) {
	if _, ok := tx.ctlSessions[id]; ok {
		return
	}
	v, present := tx.fs.ctl.sessions[id]
	tx.ctlSessions[id] = sessionEntryUndo{value: cloneCtlSession(v), ok: present}
}

func (tx *mutationTransaction) captureWatermark(id string) {
	if _, ok := tx.ctlWatermarks[id]; ok {
		return
	}
	v, present := tx.fs.ctl.watermarks[id]
	tx.ctlWatermarks[id] = watermarkEntryUndo{value: v, ok: present}
}

func (tx *mutationTransaction) captureSlot(env *wal.Envelope) {
	if !env.Valid() {
		return
	}
	key := slotUndoKey{session: env.SessionID, slot: env.Slot}
	if _, ok := tx.ctlSlots[key]; ok {
		return
	}
	s := tx.fs.ctl.sessions[env.SessionID]
	if s == nil {
		tx.ctlSlots[key] = slotEntryUndo{}
		return
	}
	v, present := s.outcomes[env.Slot]
	tx.ctlSlots[key] = slotEntryUndo{value: cloneSlotOutcome(v), ok: present, outcomesNil: s.outcomes == nil}
}

func (tx *mutationTransaction) captureControl(r wal.Record) error {
	p, err := decodeCtlPayload(r.Data)
	if err != nil {
		return err
	}
	switch p.Kind {
	case ctlKindSession:
		tx.captureSession(p.Session.SessionID)
	case ctlKindExpire:
		tx.captureSession(p.Expire.SessionID)
	case ctlKindRenew:
		tx.captureSession(p.Renew.SessionID)
	case ctlKindWatermark:
		tx.captureWatermark(p.Watermark.SessionID)
	case ctlKindOutcome:
		tx.captureSession(p.Outcome.SessionID)
	case ctlKindSnapshot:
		for i := range p.Snapshot.Sessions {
			tx.captureSession(p.Snapshot.Sessions[i].SessionID)
		}
		for i := range p.Snapshot.Watermarks {
			tx.captureWatermark(p.Snapshot.Watermarks[i].SessionID)
		}
	}
	return nil
}

// captureMutation records precisely the state that r may change at its current
// ordered apply position. Caller holds fs.mu.
func (tx *mutationTransaction) captureMutation(r wal.Record) error {
	fs := tx.fs
	switch r.Op {
	case wal.OpControl:
		return tx.captureControl(r)
	case wal.OpCreate, wal.OpSymlink:
		parent, _ := fs.resolveParent(r.Path)
		tx.captureInode(parent)
		tx.captureByIno(r.Ino)
	case wal.OpMkdir:
		cur := fs.root
		tx.captureInode(cur)
		for _, part := range splitCleanPath(r.Path) {
			next := cur.children[part]
			if next == nil || next.kind != "directory" {
				break
			}
			cur = next
			tx.captureInode(cur)
		}
		for _, ino := range r.Inos {
			tx.captureByIno(ino)
		}
		tx.captureByIno(r.Ino) // exclusive mkdir: single leaf identity
	case wal.OpWrite:
		n := fs.resolveForRW(r.Path, r.Ino)
		tx.captureInode(n)
		off := r.Offset
		if r.Append && n != nil {
			off = n.curSize()
		}
		if validateWriteRange(off, len(r.Data), false) == nil {
			tx.captureWriteBlocks(n, off, len(r.Data))
		}
	case wal.OpTruncate:
		n := fs.resolveForRW(r.Path, r.Ino)
		tx.captureInode(n)
		tx.captureTruncateBlocks(n, r.Size)
	case wal.OpChmod, wal.OpChtimes, wal.OpChown:
		tx.captureInode(fs.resolveForRW(r.Path, r.Ino))
	case wal.OpRemove, wal.OpOrphan:
		parent, base := fs.resolveParent(r.Path)
		tx.captureInode(parent)
		if parent != nil {
			if child := parent.children[base]; child != nil {
				tx.captureInode(child)
				tx.captureOrphan(child.ino)
			}
		}
	case wal.OpRename:
		oldParent, oldBase := fs.resolveParent(r.Path)
		newParent, newBase := fs.resolveParent(r.NewPath)
		tx.captureInode(oldParent)
		tx.captureInode(newParent)
		if oldParent != nil {
			tx.captureInode(oldParent.children[oldBase])
		}
		if newParent != nil {
			if replaced := newParent.children[newBase]; replaced != nil {
				tx.captureInode(replaced)
				tx.captureOrphan(replaced.ino)
			}
		}
	case wal.OpLink:
		newParent, _ := fs.resolveParent(r.NewPath)
		tx.captureInode(newParent)
		tx.captureInode(fs.resolveForRW(r.Path, r.Ino)) // source inode: nlink++ / ctime
	case wal.OpReap:
		tx.captureInode(fs.orphans[r.Ino])
		tx.captureOrphan(r.Ino)
		tx.captureOpen(r.Ino)
		tx.captureByIno(r.Ino)
		tx.capturePendingReap(r.Ino)
	}
	tx.captureSlot(r.Env)
	return nil
}

func splitCleanPath(p string) []string {
	clean := cleanPath(p)
	if clean == "" {
		return nil
	}
	// Avoid importing path/string parsing throughout the undo logic.
	var parts []string
	start := 0
	for i := 0; i <= len(clean); i++ {
		if i == len(clean) || clean[i] == '/' {
			parts = append(parts, clean[start:i])
			start = i + 1
		}
	}
	return parts
}

func (tx *mutationTransaction) captureOrphanVersion(ino uint64) {
	if ino != 0 {
		tx.captureInode(tx.fs.orphans[ino])
	}
}

func (tx *mutationTransaction) rollback() {
	fs := tx.fs
	for n, state := range tx.inodes {
		*n = state
	}
	for i := len(tx.blocks) - 1; i >= 0; i-- {
		undo := tx.blocks[i]
		if undo.blocks == nil {
			continue
		}
		if undo.ok {
			undo.blocks[undo.index] = undo.value
		} else {
			delete(undo.blocks, undo.index)
		}
	}
	for ino, undo := range tx.orphans {
		restoreInodeEntry(fs.orphans, ino, undo)
	}
	for ino, undo := range tx.orphanLeases {
		if undo.ok {
			fs.orphanLeases[ino] = undo.value
		} else {
			delete(fs.orphanLeases, ino)
		}
	}
	for ino, undo := range tx.openInodes {
		if undo.ok {
			fs.openInodes[ino] = undo.value
		} else {
			delete(fs.openInodes, ino)
		}
	}
	for ino, undo := range tx.byIno {
		restoreInodeEntry(fs.byIno, ino, undo)
	}
	for ino, undo := range tx.pendingReaps {
		if undo.ok {
			fs.pendingReaps[ino] = undo.value
		} else {
			delete(fs.pendingReaps, ino)
		}
	}
	for id, undo := range tx.ctlSessions {
		if undo.ok {
			fs.ctl.sessions[id] = undo.value
		} else {
			delete(fs.ctl.sessions, id)
		}
	}
	for id, undo := range tx.ctlWatermarks {
		if undo.ok {
			fs.ctl.watermarks[id] = undo.value
		} else {
			delete(fs.ctl.watermarks, id)
		}
	}
	for key, undo := range tx.ctlSlots {
		s := fs.ctl.sessions[key.session]
		if s == nil {
			continue
		}
		if undo.outcomesNil {
			s.outcomes = nil
			continue
		}
		if undo.ok {
			s.outcomes[key.slot] = undo.value
		} else {
			delete(s.outcomes, key.slot)
		}
	}
	if tx.ctlSessionsNil {
		fs.ctl.sessions = nil
	}
	if tx.ctlWatermarksNil {
		fs.ctl.watermarks = nil
	}
	fs.ctl.slotStates = tx.ctlSlotStates
	fs.epoch = tx.clocks.i
	fs.version = tx.clocks.u
	fs.alloc = tx.alloc
	fs.restoreDirtyBlockBytesLocked(tx.dirtyBytes)
}

func restoreInodeEntry(m map[uint64]*inode, ino uint64, undo inodeEntryUndo) {
	if undo.ok {
		m[ino] = undo.value
	} else {
		delete(m, ino)
	}
}
