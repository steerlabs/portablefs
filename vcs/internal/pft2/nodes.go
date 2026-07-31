package pft2

import (
	"bytes"
	"unicode/utf8"
)

// Node is one decoded PFT2 object: a kind plus exactly the matching arm.
type Node struct {
	Kind Kind

	Root            *Root
	Inode           *Inode
	DirectoryLeaf   *DirectoryLeaf
	DirectoryIndex  *DirectoryIndex
	ExtentLeaf      *ExtentLeaf
	ExtentIndex     *ExtentIndex
	InodeIndexLeaf  *InodeIndexLeaf
	InodeIndexIndex *InodeIndexIndex
	RecoveryRoot    *RecoveryRoot
	DataPage        *DataPage
	ControlRoot     *ControlRoot
	ControlLeaf     *ControlLeaf
	ControlIndex    *ControlIndex
	XattrLeaf       *XattrLeaf
}

// Root is the filesystem root. It carries filesystem facts and the live
// extended attributes of filesystem-homed inodes: no session, lock,
// checkout, access, manager, orphan-only metadata, or future-allocation
// state (those are structurally confined to RecoveryRoot / the control
// tree).
type Root struct {
	// RootInode references the INODE object for inode 1 (the root directory).
	RootInode Ref
	// InodeIndex references the named-inode index root (INODE_INDEX_LEAF or
	// INODE_INDEX_INDEX). It enumerates every live inode, including inode 1,
	// which must map to exactly RootInode.
	InodeIndex Ref
	// MaxInoSeen is the monotonic allocation/observation high-water: every
	// inode id ever live in this filesystem's history — parked-orphan ids
	// included — is <= MaxInoSeen. Inode ids are never reused, so the value
	// never decreases; deleting the highest inode does not lower it. It is
	// an upper bound on the ids present in InodeIndex, NOT the exact maximum
	// currently present. Wire field 3 (formerly documented as max_ino; the
	// tag and encoding are unchanged).
	MaxInoSeen uint64
	// InodeCount is the verified total number of live inodes.
	InodeCount uint64
	// DirentCount is the verified total number of directory entries.
	DirentCount uint64
	// LogicalBytes is the verified sum of all file logical sizes.
	LogicalBytes uint64
	// Features must have no bits outside the defined mask (currently empty),
	// so an old reader fails closed on a future incompatible root.
	Features uint64
	// XattrLeaves is the ordered XATTR_LEAF list carrying attributes of live
	// filesystem-homed inodes. It is part of the user closure so snapshots
	// and forks preserve file metadata. RecoveryRoot carries the complete
	// set as well, including attributes of parked open-after-unlink orphans.
	XattrLeaves []Ref
}

// Inode is one file, directory, or symlink.
type Inode struct {
	Ino     uint64
	Kind    FileKind
	Mode    uint32 // permission + setuid/setgid/sticky bits only (<= 0o7777)
	UID     uint32
	GID     uint32
	Nlink   uint64
	Size    uint64 // logical size; 0 for directories; len(SymlinkTarget) for symlinks
	MtimeMs int64
	CtimeMs int64
	AtimeMs int64
	// BirthtimeMs is the durable creation time (APPENDED wire field 14). It is
	// stamped once, at inode creation, from the journaled record's op time and
	// never moves again: no write, truncate, chmod, rename, or hard link may
	// change it. Zero is the canonical "absent" value — every inode written by
	// a pre-birthtime authority decodes with zero, and consumers treat zero as
	// "unknown" rather than "1970" (the FSKit client already derives mtime in
	// that case).
	BirthtimeMs int64
	// Flags carries the BSD file flags (Darwin st_flags / chflags(2)) as the
	// full opaque uint32 the client sent (APPENDED wire field 15). The tree
	// format deliberately defines NO bit policy: masking which flags a mount
	// may set (UF_HIDDEN, UF_IMMUTABLE, SF_* …) is a client-side decision, and
	// pinning a mask here would make the durable format lie about what an
	// older/newer client meant. Zero is the canonical "no flags" value and the
	// value every pre-flags inode decodes to.
	Flags uint32
	// DirectoryRoot references the directory tree root (directories only).
	// Nil means an empty directory.
	DirectoryRoot *Ref
	// ExtentRoot references the extent tree root (regular files only). Nil
	// means a file with no present pages (entirely holes / zero bytes).
	ExtentRoot *Ref
	// SymlinkTarget is the inline target (symlinks only): 1..4096 bytes of
	// NUL-free UTF-8.
	SymlinkTarget string
}

// DirEntry is one directory entry.
type DirEntry struct {
	// Name is 1..255 bytes of NUL- and slash-free UTF-8, not "." or "..".
	// Ordering is by raw bytes; PortableFS performs no Unicode normalization.
	Name string
	Ino  uint64
	Kind FileKind
}

// DirectoryLeaf holds directory entries sorted strictly ascending by raw
// name bytes.
type DirectoryLeaf struct {
	Entries []DirEntry
}

// DirectoryIndexChild advertises one child subtree of a directory index.
type DirectoryIndexChild struct {
	FirstName  string
	LastName   string
	Child      Ref
	EntryCount uint64
}

// DirectoryIndex is an internal directory B+tree node.
type DirectoryIndex struct {
	Children []DirectoryIndexChild
}

// ExtentEntry maps one PageBytes-aligned logical page offset to a DATA_PAGE.
type ExtentEntry struct {
	PageOffset uint64
	Page       Ref
}

// ExtentLeaf holds extent entries sorted strictly ascending by page offset.
// Absent offsets are holes that read as zero.
type ExtentLeaf struct {
	Entries []ExtentEntry
}

// ExtentIndexChild advertises one child subtree of an extent index.
type ExtentIndexChild struct {
	FirstPage  uint64
	LastPage   uint64
	Child      Ref
	EntryCount uint64
}

// ExtentIndex is an internal extent B+tree node.
type ExtentIndex struct {
	Children []ExtentIndexChild
}

// InodeIndexEntry maps one inode number to its INODE object.
type InodeIndexEntry struct {
	Ino   uint64
	Inode Ref
}

// InodeIndexLeaf holds inode index entries sorted strictly ascending by ino.
type InodeIndexLeaf struct {
	Entries []InodeIndexEntry
}

// InodeIndexChild advertises one child subtree of an inode index.
type InodeIndexChild struct {
	FirstIno   uint64
	LastIno    uint64
	Child      Ref
	EntryCount uint64
}

// InodeIndexIndex is an internal inode-index B+tree node.
type InodeIndexIndex struct {
	Children []InodeIndexChild
}

// RecoveryRoot anchors one exact journal cut's internal recovery state. It is
// never reachable from a filesystem Root; only the active journal
// generation's internal control anchor references it.
type RecoveryRoot struct {
	// AsOfSeq is the exact as-of journal sequence (0 for a fresh branch).
	AsOfSeq uint64
	// FilesystemRoot references the matching filesystem ROOT object.
	FilesystemRoot Ref
	// ControlRoot references the bounded PFC2 CONTROL_ROOT object. Nil means
	// an empty control state (fresh branch).
	ControlRoot *Ref
	// OrphanIndex references the parked-orphan inode index root. Nil means no
	// parked orphans.
	OrphanIndex *Ref
	// InoNamespace is the branch's immutable inode-allocation namespace
	// (1..MaxInodeNamespace; namespace 0 never appears here — it is reserved
	// for inode 1 and verified legacy ids).
	InoNamespace uint32
	// NextLocal is the next unassigned local counter value
	// (1..MaxInodeLocalCounter+1; MaxInodeLocalCounter+1 marks exhaustion).
	NextLocal uint64
	// Features must have no bits outside the defined mask (currently empty).
	Features uint64
	// XattrLeaves is the ordered XATTR_LEAF list carrying the LIVE per-inode
	// extended attributes at the cut ((ino, name) keys strictly ascending
	// across leaves — the loader re-verifies the cross-leaf ordering). Empty
	// when no inode carries xattrs. Root carries the filesystem-homed subset
	// for snapshots/forks; this recovery projection additionally retains
	// attributes of parked open-after-unlink orphans.
	XattrLeaves []Ref
}

// XattrEntry is one live extended attribute of one inode.
type XattrEntry struct {
	Ino   uint64
	Name  string // 1..MaxXattrNameBytes bytes of NUL-free UTF-8
	Value []byte // 0..MaxXattrValueBytes raw bytes
}

// XattrLeaf holds extended-attribute entries sorted strictly ascending by
// (ino, raw name bytes).
type XattrLeaf struct {
	Entries []XattrEntry
}

// CellRef references the canonical CellBytes logical bytes of one cell inside
// one immutable packed data object. The slice length is structurally exact:
// always CellBytes.
type CellRef struct {
	// CellDigest is sha256 of the canonical CellBytes logical bytes. It must
	// not equal ZeroCellDigest: an all-zero cell is canonically a hole.
	CellDigest [DigestBytes]byte
	// Object references the packed immutable data object (exact size).
	Object Ref
	// ObjectOffset is the CellBytes-aligned offset of the slice inside Object.
	ObjectOffset uint64
}

// DataPage holds exactly CellsPerPage optional cell slots. A nil slot is a
// hole. An all-hole page must be omitted from its extent tree entirely.
type DataPage struct {
	Cells [CellsPerPage]*CellRef
}

// ControlKindCount is one verified per-kind entry count in a ControlRoot.
type ControlKindCount struct {
	Kind  uint64
	Count uint64
}

// ControlEntry is one granular typed record in the sorted control map. The
// value payload is owned by the control (PFC2) layer and is opaque here.
type ControlEntry struct {
	Key   []byte // 1..MaxControlKeyBytes
	Kind  uint64 // 1..MaxControlEntryKind
	Value []byte // 0..MaxControlValueBytes
}

// ControlLeaf holds control entries sorted strictly ascending by raw key
// bytes (unique keys).
type ControlLeaf struct {
	Entries []ControlEntry
}

// ControlIndexChild advertises one child subtree of a control index.
type ControlIndexChild struct {
	FirstKey   []byte
	LastKey    []byte
	Child      Ref
	EntryCount uint64
}

// ControlIndex is an internal control B+tree node.
type ControlIndex struct {
	Children []ControlIndexChild
}

// ControlRoot names the generic sorted immutable control map.
type ControlRoot struct {
	// Schema must equal ControlSchemaVersion.
	Schema uint64
	// MapRoot references the control map root (CONTROL_LEAF or
	// CONTROL_INDEX). Nil means an empty map.
	MapRoot *Ref
	// NextCheckoutEpoch is the next server-controlled checkout epoch
	// (1..MaxCheckoutEpoch).
	NextCheckoutEpoch uint64
	// Features must have no bits outside the defined mask (currently empty).
	Features uint64
	// Counts holds the verified per-kind entry counts, ascending by kind,
	// present exactly for kinds with at least one entry. Empty iff MapRoot is
	// nil.
	Counts []ControlKindCount
	// DbTimeFloorMs is the durable database-time floor at the anchor cut:
	// the latest database-minted time any applied control record carried
	// (0 = no time fact was ever journaled). It rides the root — NOT a map
	// entry — because it must survive cuts whose reduced map is empty;
	// recovery resumes time validation from it, so a replacement authority
	// can never accept a minted time older than the retired prefix.
	DbTimeFloorMs uint64
}

// ─── validation ─────────────────────────────────────────────────────────────
//
// Validate is applied on BOTH encode and decode, so the encoder can never
// emit a node the decoder would reject and vice versa. Wire-shape rules
// (ordering, minimal varints, defaults) are separately enforced by pfwire.

// Validate checks the node's structural invariants.
func (n *Node) Validate() error {
	if n == nil {
		return invalidf("nil node")
	}
	if n.Kind < minKind || n.Kind > maxKind {
		return invalidf("unknown kind %d", n.Kind)
	}
	arms := 0
	countArm := func(present bool) {
		if present {
			arms++
		}
	}
	countArm(n.Root != nil)
	countArm(n.Inode != nil)
	countArm(n.DirectoryLeaf != nil)
	countArm(n.DirectoryIndex != nil)
	countArm(n.ExtentLeaf != nil)
	countArm(n.ExtentIndex != nil)
	countArm(n.InodeIndexLeaf != nil)
	countArm(n.InodeIndexIndex != nil)
	countArm(n.RecoveryRoot != nil)
	countArm(n.DataPage != nil)
	countArm(n.ControlRoot != nil)
	countArm(n.ControlLeaf != nil)
	countArm(n.ControlIndex != nil)
	countArm(n.XattrLeaf != nil)
	if arms != 1 {
		return invalidf("node must carry exactly one arm (has %d)", arms)
	}
	switch n.Kind {
	case KindRoot:
		if n.Root == nil {
			return invalidf("kind %s without its arm", n.Kind)
		}
		return n.Root.validate()
	case KindInode:
		if n.Inode == nil {
			return invalidf("kind %s without its arm", n.Kind)
		}
		return n.Inode.validate()
	case KindDirectoryLeaf:
		if n.DirectoryLeaf == nil {
			return invalidf("kind %s without its arm", n.Kind)
		}
		return n.DirectoryLeaf.validate()
	case KindDirectoryIndex:
		if n.DirectoryIndex == nil {
			return invalidf("kind %s without its arm", n.Kind)
		}
		return n.DirectoryIndex.validate()
	case KindExtentLeaf:
		if n.ExtentLeaf == nil {
			return invalidf("kind %s without its arm", n.Kind)
		}
		return n.ExtentLeaf.validate()
	case KindExtentIndex:
		if n.ExtentIndex == nil {
			return invalidf("kind %s without its arm", n.Kind)
		}
		return n.ExtentIndex.validate()
	case KindInodeIndexLeaf:
		if n.InodeIndexLeaf == nil {
			return invalidf("kind %s without its arm", n.Kind)
		}
		return n.InodeIndexLeaf.validate()
	case KindInodeIndexIndex:
		if n.InodeIndexIndex == nil {
			return invalidf("kind %s without its arm", n.Kind)
		}
		return n.InodeIndexIndex.validate()
	case KindRecoveryRoot:
		if n.RecoveryRoot == nil {
			return invalidf("kind %s without its arm", n.Kind)
		}
		return n.RecoveryRoot.validate()
	case KindDataPage:
		if n.DataPage == nil {
			return invalidf("kind %s without its arm", n.Kind)
		}
		return n.DataPage.validate()
	case KindControlRoot:
		if n.ControlRoot == nil {
			return invalidf("kind %s without its arm", n.Kind)
		}
		return n.ControlRoot.validate()
	case KindControlLeaf:
		if n.ControlLeaf == nil {
			return invalidf("kind %s without its arm", n.Kind)
		}
		return n.ControlLeaf.validate()
	case KindControlIndex:
		if n.ControlIndex == nil {
			return invalidf("kind %s without its arm", n.Kind)
		}
		return n.ControlIndex.validate()
	case KindXattrLeaf:
		if n.XattrLeaf == nil {
			return invalidf("kind %s without its arm", n.Kind)
		}
		return n.XattrLeaf.validate()
	default:
		return invalidf("unknown kind %d", n.Kind)
	}
}

func (r *Root) validate() error {
	if err := checkNodeRefBounds("root.root_inode", r.RootInode); err != nil {
		return err
	}
	if err := checkNodeRefBounds("root.inode_index", r.InodeIndex); err != nil {
		return err
	}
	if r.MaxInoSeen < RootIno || r.MaxInoSeen > MaxIno {
		return invalidf("root: max_ino_seen %d outside %d..%d", r.MaxInoSeen, RootIno, MaxIno)
	}
	if r.InodeCount < 1 || r.InodeCount > MaxCount64 {
		return invalidf("root: inode_count %d outside 1..%d", r.InodeCount, MaxCount64)
	}
	if r.InodeCount > r.MaxInoSeen {
		return invalidf("root: inode_count %d exceeds max_ino_seen %d", r.InodeCount, r.MaxInoSeen)
	}
	if r.DirentCount > MaxCount64 {
		return invalidf("root: dirent_count %d exceeds %d", r.DirentCount, MaxCount64)
	}
	if r.LogicalBytes > MaxCount64 {
		return invalidf("root: logical_bytes %d exceeds %d", r.LogicalBytes, MaxCount64)
	}
	if r.Features != 0 {
		return invalidf("root: unknown feature bits %#x", r.Features)
	}
	for i, ref := range r.XattrLeaves {
		if err := checkNodeRefBounds("root.xattr_leaves", ref); err != nil {
			return invalidf("root xattr leaf %d: %v", i, err)
		}
	}
	return nil
}

func validTimeMs(v int64) bool { return v >= -MaxAbsTimeMs && v <= MaxAbsTimeMs }

func (ino *Inode) validate() error {
	if ino.Ino < 1 || ino.Ino > MaxIno {
		return invalidf("inode: ino %d outside 1..%d", ino.Ino, MaxIno)
	}
	if ino.Mode > MaxModeBits {
		return invalidf("inode %d: mode %#o exceeds %#o", ino.Ino, ino.Mode, MaxModeBits)
	}
	if ino.Nlink < 1 || ino.Nlink > MaxNlink {
		return invalidf("inode %d: nlink %d outside 1..%d", ino.Ino, ino.Nlink, MaxNlink)
	}
	if !validTimeMs(ino.MtimeMs) || !validTimeMs(ino.CtimeMs) || !validTimeMs(ino.AtimeMs) {
		return invalidf("inode %d: timestamp outside ±%d ms", ino.Ino, MaxAbsTimeMs)
	}
	if !validTimeMs(ino.BirthtimeMs) {
		return invalidf("inode %d: birth time outside ±%d ms", ino.Ino, MaxAbsTimeMs)
	}
	// Flags is the full uint32 the client sent: no bit is reserved or
	// rejected here (see the Inode.Flags contract).
	switch ino.Kind {
	case FileKindRegular:
		if ino.DirectoryRoot != nil || ino.SymlinkTarget != "" {
			return invalidf("inode %d: file carries directory or symlink state", ino.Ino)
		}
		if ino.Size > MaxLogicalFileBytes {
			return invalidf("inode %d: size %d exceeds %d", ino.Ino, ino.Size, MaxLogicalFileBytes)
		}
		if ino.ExtentRoot != nil {
			if ino.Size == 0 {
				return invalidf("inode %d: zero-size file carries an extent root", ino.Ino)
			}
			if err := checkNodeRefBounds("inode.extent_root", *ino.ExtentRoot); err != nil {
				return err
			}
		}
	case FileKindDirectory:
		if ino.ExtentRoot != nil || ino.SymlinkTarget != "" {
			return invalidf("inode %d: directory carries extent or symlink state", ino.Ino)
		}
		if ino.Size != 0 {
			return invalidf("inode %d: directory size must be 0 (got %d)", ino.Ino, ino.Size)
		}
		if ino.DirectoryRoot != nil {
			if err := checkNodeRefBounds("inode.directory_root", *ino.DirectoryRoot); err != nil {
				return err
			}
		}
	case FileKindSymlink:
		if ino.DirectoryRoot != nil || ino.ExtentRoot != nil {
			return invalidf("inode %d: symlink carries directory or extent state", ino.Ino)
		}
		if err := validateSymlinkTarget(ino.SymlinkTarget); err != nil {
			return invalidf("inode %d: %v", ino.Ino, err)
		}
		if ino.Size != uint64(len(ino.SymlinkTarget)) {
			return invalidf("inode %d: symlink size %d != target byte length %d",
				ino.Ino, ino.Size, len(ino.SymlinkTarget))
		}
	default:
		return invalidf("inode %d: unknown file kind %d", ino.Ino, ino.Kind)
	}
	return nil
}

func validateSymlinkTarget(target string) error {
	if len(target) < 1 || len(target) > MaxSymlinkTargetBytes {
		return invalidf("symlink target length %d outside 1..%d", len(target), MaxSymlinkTargetBytes)
	}
	if !utf8.ValidString(target) {
		return invalidf("symlink target is not valid UTF-8")
	}
	for i := 0; i < len(target); i++ {
		if target[i] == 0 {
			return invalidf("symlink target contains NUL")
		}
	}
	return nil
}

// ValidateEntryName checks one directory entry name: 1..MaxNameBytes bytes of
// NUL- and slash-free UTF-8, not "." or "..".
func ValidateEntryName(name string) error {
	if len(name) < 1 || len(name) > MaxNameBytes {
		return invalidf("name length %d outside 1..%d", len(name), MaxNameBytes)
	}
	if name == "." || name == ".." {
		return invalidf("name %q is reserved", name)
	}
	if !utf8.ValidString(name) {
		return invalidf("name is not valid UTF-8")
	}
	for i := 0; i < len(name); i++ {
		if name[i] == 0 || name[i] == '/' {
			return invalidf("name contains NUL or '/'")
		}
	}
	return nil
}

func validFileKind(k FileKind) bool {
	return k == FileKindRegular || k == FileKindDirectory || k == FileKindSymlink
}

func (l *DirectoryLeaf) validate() error {
	if len(l.Entries) < 1 || len(l.Entries) > MaxLeafEntries {
		return invalidf("directory leaf: %d entries outside 1..%d", len(l.Entries), MaxLeafEntries)
	}
	for i := range l.Entries {
		e := &l.Entries[i]
		if err := ValidateEntryName(e.Name); err != nil {
			return invalidf("directory leaf entry %d: %v", i, err)
		}
		if e.Ino < 1 || e.Ino > MaxIno {
			return invalidf("directory leaf entry %q: ino %d outside 1..%d", e.Name, e.Ino, MaxIno)
		}
		if !validFileKind(e.Kind) {
			return invalidf("directory leaf entry %q: unknown kind %d", e.Name, e.Kind)
		}
		if i > 0 && l.Entries[i-1].Name >= e.Name {
			return invalidf("directory leaf: entry %d name %q not strictly above %q",
				i, e.Name, l.Entries[i-1].Name)
		}
	}
	return nil
}

// addCount adds subtree entry counts, rejecting uint64 overflow and the
// MaxCount64 bound.
func addCount(what string, total, add uint64) (uint64, error) {
	sum := total + add
	if sum < total || sum > MaxCount64 {
		return 0, invalidf("%s: entry count overflows %d", what, MaxCount64)
	}
	return sum, nil
}

func (x *DirectoryIndex) validate() error {
	if len(x.Children) < MinIndexChildren || len(x.Children) > MaxIndexChildren {
		return invalidf("directory index: %d children outside %d..%d",
			len(x.Children), MinIndexChildren, MaxIndexChildren)
	}
	var total uint64
	for i := range x.Children {
		c := &x.Children[i]
		if err := ValidateEntryName(c.FirstName); err != nil {
			return invalidf("directory index child %d first: %v", i, err)
		}
		if err := ValidateEntryName(c.LastName); err != nil {
			return invalidf("directory index child %d last: %v", i, err)
		}
		if c.FirstName > c.LastName {
			return invalidf("directory index child %d: first %q above last %q", i, c.FirstName, c.LastName)
		}
		if err := checkNodeRefBounds("directory index child", c.Child); err != nil {
			return err
		}
		if c.EntryCount < 1 {
			return invalidf("directory index child %d: zero entry count", i)
		}
		var err error
		if total, err = addCount("directory index", total, c.EntryCount); err != nil {
			return err
		}
		if i > 0 && x.Children[i-1].LastName >= c.FirstName {
			return invalidf("directory index child %d: first %q not strictly above previous last %q",
				i, c.FirstName, x.Children[i-1].LastName)
		}
	}
	return nil
}

func validPageOffset(off uint64) bool {
	return off%PageBytes == 0 && off <= MaxLogicalFileBytes-PageBytes
}

func (l *ExtentLeaf) validate() error {
	if len(l.Entries) < 1 || len(l.Entries) > MaxLeafEntries {
		return invalidf("extent leaf: %d entries outside 1..%d", len(l.Entries), MaxLeafEntries)
	}
	for i := range l.Entries {
		e := &l.Entries[i]
		if !validPageOffset(e.PageOffset) {
			return invalidf("extent leaf entry %d: page offset %d unaligned or out of range", i, e.PageOffset)
		}
		if err := checkNodeRefBounds("extent leaf page", e.Page); err != nil {
			return err
		}
		if i > 0 && l.Entries[i-1].PageOffset >= e.PageOffset {
			return invalidf("extent leaf: entry %d offset %d not strictly above %d",
				i, e.PageOffset, l.Entries[i-1].PageOffset)
		}
	}
	return nil
}

func (x *ExtentIndex) validate() error {
	if len(x.Children) < MinIndexChildren || len(x.Children) > MaxIndexChildren {
		return invalidf("extent index: %d children outside %d..%d",
			len(x.Children), MinIndexChildren, MaxIndexChildren)
	}
	var total uint64
	for i := range x.Children {
		c := &x.Children[i]
		if !validPageOffset(c.FirstPage) || !validPageOffset(c.LastPage) {
			return invalidf("extent index child %d: unaligned or out-of-range page bound", i)
		}
		if c.FirstPage > c.LastPage {
			return invalidf("extent index child %d: first page %d above last %d", i, c.FirstPage, c.LastPage)
		}
		if err := checkNodeRefBounds("extent index child", c.Child); err != nil {
			return err
		}
		if c.EntryCount < 1 {
			return invalidf("extent index child %d: zero entry count", i)
		}
		// Pages are PageBytes-aligned and strictly ascending, so the range
		// can hold at most (LastPage-FirstPage)/PageBytes + 1 entries. Both
		// operands are validated above, so the arithmetic cannot overflow.
		if c.EntryCount-1 > (c.LastPage-c.FirstPage)/PageBytes {
			return invalidf("extent index child %d: entry count %d exceeds possible pages in %d..%d",
				i, c.EntryCount, c.FirstPage, c.LastPage)
		}
		var err error
		if total, err = addCount("extent index", total, c.EntryCount); err != nil {
			return err
		}
		if i > 0 && x.Children[i-1].LastPage >= c.FirstPage {
			return invalidf("extent index child %d: first page %d not strictly above previous last %d",
				i, c.FirstPage, x.Children[i-1].LastPage)
		}
	}
	return nil
}

func (l *InodeIndexLeaf) validate() error {
	if len(l.Entries) < 1 || len(l.Entries) > MaxLeafEntries {
		return invalidf("inode index leaf: %d entries outside 1..%d", len(l.Entries), MaxLeafEntries)
	}
	for i := range l.Entries {
		e := &l.Entries[i]
		if e.Ino < 1 || e.Ino > MaxIno {
			return invalidf("inode index leaf entry %d: ino %d outside 1..%d", i, e.Ino, MaxIno)
		}
		if err := checkNodeRefBounds("inode index leaf entry", e.Inode); err != nil {
			return err
		}
		if i > 0 && l.Entries[i-1].Ino >= e.Ino {
			return invalidf("inode index leaf: entry %d ino %d not strictly above %d",
				i, e.Ino, l.Entries[i-1].Ino)
		}
	}
	return nil
}

func (x *InodeIndexIndex) validate() error {
	if len(x.Children) < MinIndexChildren || len(x.Children) > MaxIndexChildren {
		return invalidf("inode index index: %d children outside %d..%d",
			len(x.Children), MinIndexChildren, MaxIndexChildren)
	}
	var total uint64
	for i := range x.Children {
		c := &x.Children[i]
		if c.FirstIno < 1 || c.FirstIno > MaxIno || c.LastIno < 1 || c.LastIno > MaxIno {
			return invalidf("inode index child %d: ino bound outside 1..%d", i, MaxIno)
		}
		if c.FirstIno > c.LastIno {
			return invalidf("inode index child %d: first ino %d above last %d", i, c.FirstIno, c.LastIno)
		}
		if err := checkNodeRefBounds("inode index child", c.Child); err != nil {
			return err
		}
		if c.EntryCount < 1 {
			return invalidf("inode index child %d: zero entry count", i)
		}
		if c.EntryCount-1 > c.LastIno-c.FirstIno {
			return invalidf("inode index child %d: entry count %d exceeds ino range %d..%d",
				i, c.EntryCount, c.FirstIno, c.LastIno)
		}
		var err error
		if total, err = addCount("inode index", total, c.EntryCount); err != nil {
			return err
		}
		if i > 0 && x.Children[i-1].LastIno >= c.FirstIno {
			return invalidf("inode index child %d: first ino %d not strictly above previous last %d",
				i, c.FirstIno, x.Children[i-1].LastIno)
		}
	}
	return nil
}

func (r *RecoveryRoot) validate() error {
	// AsOfSeq 0 is legal: a fresh branch starts at sequence zero.
	if err := checkNodeRefBounds("recovery.filesystem_root", r.FilesystemRoot); err != nil {
		return err
	}
	if r.ControlRoot != nil {
		if err := checkNodeRefBounds("recovery.control_root", *r.ControlRoot); err != nil {
			return err
		}
	}
	if r.OrphanIndex != nil {
		if err := checkNodeRefBounds("recovery.orphan_index", *r.OrphanIndex); err != nil {
			return err
		}
	}
	if r.InoNamespace < 1 || r.InoNamespace > MaxInodeNamespace {
		return invalidf("recovery: inode namespace %d outside 1..%d", r.InoNamespace, MaxInodeNamespace)
	}
	if r.NextLocal < 1 || r.NextLocal > MaxInodeLocalCounter+1 {
		return invalidf("recovery: next local counter %d outside 1..%d", r.NextLocal, MaxInodeLocalCounter+1)
	}
	if r.Features != 0 {
		return invalidf("recovery: unknown feature bits %#x", r.Features)
	}
	for i, ref := range r.XattrLeaves {
		if err := checkNodeRefBounds("recovery.xattr_leaves", ref); err != nil {
			return invalidf("recovery xattr leaf %d: %v", i, err)
		}
	}
	return nil
}

// ValidateXattrName checks one extended-attribute name: 1..MaxXattrNameBytes
// bytes of NUL-free UTF-8 (raw case-sensitive bytes; no namespace rules).
func ValidateXattrName(name string) error {
	if len(name) < 1 || len(name) > MaxXattrNameBytes {
		return invalidf("xattr name length %d outside 1..%d", len(name), MaxXattrNameBytes)
	}
	if !utf8.ValidString(name) {
		return invalidf("xattr name is not valid UTF-8")
	}
	for i := 0; i < len(name); i++ {
		if name[i] == 0 {
			return invalidf("xattr name contains NUL")
		}
	}
	return nil
}

func (l *XattrLeaf) validate() error {
	if len(l.Entries) < 1 || len(l.Entries) > MaxLeafEntries {
		return invalidf("xattr leaf: %d entries outside 1..%d", len(l.Entries), MaxLeafEntries)
	}
	for i := range l.Entries {
		e := &l.Entries[i]
		if e.Ino < 1 || e.Ino > MaxIno {
			return invalidf("xattr leaf entry %d: ino %d outside 1..%d", i, e.Ino, MaxIno)
		}
		if err := ValidateXattrName(e.Name); err != nil {
			return invalidf("xattr leaf entry %d: %v", i, err)
		}
		if len(e.Value) > MaxXattrValueBytes {
			return invalidf("xattr leaf entry %d: value length %d exceeds %d", i, len(e.Value), MaxXattrValueBytes)
		}
		if i > 0 {
			prev := &l.Entries[i-1]
			if prev.Ino > e.Ino || (prev.Ino == e.Ino && prev.Name >= e.Name) {
				return invalidf("xattr leaf: entry %d (ino %d, %q) not strictly above (ino %d, %q)",
					i, e.Ino, e.Name, prev.Ino, prev.Name)
			}
		}
	}
	return nil
}

func (c *CellRef) validate() error {
	if c.CellDigest == ZeroCellDigest {
		return invalidf("cell ref: all-zero cell must be a hole, not a reference")
	}
	if err := checkPackRefBounds("cell ref object", c.Object); err != nil {
		return err
	}
	if c.ObjectOffset%CellBytes != 0 {
		return invalidf("cell ref: object offset %d is not %d-aligned", c.ObjectOffset, CellBytes)
	}
	if c.ObjectOffset > c.Object.Size-CellBytes {
		return invalidf("cell ref: slice %d..%d exceeds object size %d",
			c.ObjectOffset, c.ObjectOffset+CellBytes, c.Object.Size)
	}
	return nil
}

func (p *DataPage) validate() error {
	present := 0
	for i, c := range p.Cells {
		if c == nil {
			continue
		}
		present++
		if err := c.validate(); err != nil {
			return invalidf("data page cell %d: %v", i, err)
		}
	}
	if present == 0 {
		return invalidf("data page: all-hole page must be omitted, not encoded")
	}
	return nil
}

func validateControlKey(what string, key []byte) error {
	if len(key) < 1 || len(key) > MaxControlKeyBytes {
		return invalidf("%s: key length %d outside 1..%d", what, len(key), MaxControlKeyBytes)
	}
	return nil
}

func (l *ControlLeaf) validate() error {
	if len(l.Entries) < 1 || len(l.Entries) > MaxLeafEntries {
		return invalidf("control leaf: %d entries outside 1..%d", len(l.Entries), MaxLeafEntries)
	}
	for i := range l.Entries {
		e := &l.Entries[i]
		if err := validateControlKey("control leaf entry", e.Key); err != nil {
			return err
		}
		if e.Kind < 1 || e.Kind > MaxControlEntryKind {
			return invalidf("control leaf entry %d: kind %d outside 1..%d", i, e.Kind, MaxControlEntryKind)
		}
		if len(e.Value) > MaxControlValueBytes {
			return invalidf("control leaf entry %d: value length %d exceeds %d", i, len(e.Value), MaxControlValueBytes)
		}
		if i > 0 && bytes.Compare(l.Entries[i-1].Key, e.Key) >= 0 {
			return invalidf("control leaf: entry %d key not strictly above previous", i)
		}
	}
	return nil
}

func (x *ControlIndex) validate() error {
	if len(x.Children) < MinIndexChildren || len(x.Children) > MaxIndexChildren {
		return invalidf("control index: %d children outside %d..%d",
			len(x.Children), MinIndexChildren, MaxIndexChildren)
	}
	var total uint64
	for i := range x.Children {
		c := &x.Children[i]
		if err := validateControlKey("control index child first", c.FirstKey); err != nil {
			return err
		}
		if err := validateControlKey("control index child last", c.LastKey); err != nil {
			return err
		}
		if bytes.Compare(c.FirstKey, c.LastKey) > 0 {
			return invalidf("control index child %d: first key above last key", i)
		}
		if err := checkNodeRefBounds("control index child", c.Child); err != nil {
			return err
		}
		if c.EntryCount < 1 {
			return invalidf("control index child %d: zero entry count", i)
		}
		var err error
		if total, err = addCount("control index", total, c.EntryCount); err != nil {
			return err
		}
		if i > 0 && bytes.Compare(x.Children[i-1].LastKey, c.FirstKey) >= 0 {
			return invalidf("control index child %d: first key not strictly above previous last", i)
		}
	}
	return nil
}

func (r *ControlRoot) validate() error {
	if r.Schema != ControlSchemaVersion {
		return invalidf("control root: schema %d is not %d", r.Schema, ControlSchemaVersion)
	}
	if r.MapRoot != nil {
		if err := checkNodeRefBounds("control root map", *r.MapRoot); err != nil {
			return err
		}
	}
	if r.NextCheckoutEpoch < 1 || r.NextCheckoutEpoch > MaxCheckoutEpoch {
		return invalidf("control root: next checkout epoch %d outside 1..%d", r.NextCheckoutEpoch, MaxCheckoutEpoch)
	}
	if r.Features != 0 {
		return invalidf("control root: unknown feature bits %#x", r.Features)
	}
	if (r.MapRoot == nil) != (len(r.Counts) == 0) {
		return invalidf("control root: counts must be present exactly when the map is non-empty")
	}
	var total uint64
	for i := range r.Counts {
		c := &r.Counts[i]
		if c.Kind < 1 || c.Kind > MaxControlEntryKind {
			return invalidf("control root count %d: kind %d outside 1..%d", i, c.Kind, MaxControlEntryKind)
		}
		if c.Count < 1 {
			return invalidf("control root count %d: zero count", i)
		}
		var err error
		if total, err = addCount("control root", total, c.Count); err != nil {
			return err
		}
		if i > 0 && r.Counts[i-1].Kind >= c.Kind {
			return invalidf("control root count %d: kind %d not strictly above previous", i, c.Kind)
		}
	}
	if r.DbTimeFloorMs > uint64(MaxAbsTimeMs) {
		return invalidf("control root: database-time floor %d exceeds %d ms", r.DbTimeFloorMs, MaxAbsTimeMs)
	}
	return nil
}
