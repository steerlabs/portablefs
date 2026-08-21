package archive

import (
	"fmt"
	"io"
)

// This package never walks a filesystem. The archiver that does runs on a
// read-only bind of one volume tree in its own hardened unit; the format
// library takes what that walk produced and is testable, portable, and
// deterministic because it does. Source is that boundary.

// SourceFile is one regular file's content as the builder needs it: logical
// bytes on demand, and the map of which of those bytes are actually allocated.
//
// ReadAt is only ever called for ranges the extent map reports as data, so an
// implementation is free to fail rather than synthesize zeros for a hole; an
// implementation that reads holes as zeros anyway is also correct.
//
// Extents reports the file's data extents over logical offsets, strictly
// increasing, non-empty, non-adjacent, and inside [0, size). A fully allocated
// file reports one extent covering the whole file; a fully sparse file reports
// none. Adjacent extents must be merged before they are reported: the format
// gives one byte range exactly one representation, and a source that split a
// run would produce a manifest whose extent map is not canonical.
type SourceFile interface {
	io.ReaderAt
	Extents() ([]Extent, error)
	io.Closer
}

// SourceEntry is one node the walk produced, in depth-first order.
//
// ParentIndex refers to the position of an entry already returned; the first
// entry is the volume root and is its own parent with an empty name. InodeKey
// is the source's inode identity — st_ino on Linux — and is what forms hardlink
// groups: two entries with the same non-zero key are two links to one inode. A
// zero key means the source is asserting this entry shares its inode with
// nothing.
//
// Nlink is the source's link count, and it is checked, not trusted: a group's
// membership must equal it exactly. A file with three links of which only two
// are inside the volume fails the seal rather than restoring as two independent
// files, because silently converting a hardlink into a copy changes what the
// volume means.
//
// Open is called exactly once per distinct inode, and only for a regular file
// with a non-zero size. Hardlink group members after the first are never
// opened; deduplicated content is never read twice.
type SourceEntry struct {
	ParentIndex uint32
	Name        []byte
	Type        EntryType
	Size        uint64
	Mode        uint32
	MTimeNanos  int64
	CTimeNanos  int64
	LinkName    []byte
	Nlink       uint32
	InodeKey    uint64
	Xattrs      []Xattr
	Open        func() (SourceFile, error)
}

// Source enumerates one volume tree. Next returns entries in depth-first order
// and reports io.EOF when the walk is complete. A Source that returns any other
// error aborts the archive: an export that could not read part of the tree must
// not produce a manifest that quietly omits it.
type Source interface {
	Next() (SourceEntry, error)
}

// SliceSource is a Source over an in-memory slice of entries, for callers that
// have already materialized a walk — the test suites and the seal-verification
// paths that rebuild a tree model to compare against a manifest.
type SliceSource struct {
	entries []SourceEntry
	at      int
}

func NewSliceSource(entries []SourceEntry) *SliceSource {
	return &SliceSource{entries: entries}
}

func (s *SliceSource) Next() (SourceEntry, error) {
	if s.at >= len(s.entries) {
		return SourceEntry{}, io.EOF
	}
	entry := s.entries[s.at]
	s.at++
	return entry, nil
}

// MemoryFile is a SourceFile over a logical byte image plus an explicit extent
// map, so a caller can describe a sparse file exactly without a filesystem that
// supports holes. It is the shape the property tests generate and a legitimate
// production shape for content that is synthesized rather than read.
type MemoryFile struct {
	Logical []byte
	Data    []Extent
}

func (f *MemoryFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > int64(len(f.Logical)) {
		return 0, fmt.Errorf("archive: read at %d outside a %d byte image", off, len(f.Logical))
	}
	n := copy(p, f.Logical[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (f *MemoryFile) Extents() ([]Extent, error) { return f.Data, nil }

func (f *MemoryFile) Close() error { return nil }
