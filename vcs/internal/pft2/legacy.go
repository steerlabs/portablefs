package pft2

import (
	"context"
	"crypto/sha256"
	"sort"
	"strconv"
	"strings"
)

// This file adapts legacy flat tree manifests (the portablefs-v1 JSON entry
// list) to the lazy BaseTree interface, so WorkFS-side consumers can switch
// to BaseTree before any blob is rewritten into PFT2 form. Existing
// whole-file/chunk objects are exposed as LegacyExtent ranges; nothing is
// converted or fetched here.
//
// Legacy handles are synthetic references (sha256 over a private label and
// the inode's decimal id, size 0). A size-0 reference can never satisfy
// checkNodeRefBounds, so a legacy handle presented to a real PFT2 TreeReader
// or fetched from an object store fails closed instead of resolving to the
// wrong object.

// LegacyEntry mirrors one legacy manifest entry (backend.ManifestEntry /
// @portablefs/protocol TreeEntry). Paths are relative volume paths with '/'
// separators.
type LegacyEntry struct {
	Path       string
	Kind       string // "file", "directory", or "symlink"
	Mode       uint32
	Size       int64
	MtimeMs    int64
	CtimeMs    int64
	AtimeMs    int64
	UID        uint32
	GID        uint32
	Ino        uint64 // 0 = unassigned; the adapter synthesizes stable ids
	BlobDigest string // legacy digest string ("sha256:<hex>"), files only
	BlobSize   int64
	Chunks     []LegacyChunk
	LinkTarget string
}

// LegacyChunk mirrors one legacy chunk reference.
type LegacyChunk struct {
	Digest string
	Size   int64
	Offset int64
}

type legacyFile struct {
	inode    Inode
	ref      Ref
	blob     *LegacyExtent // whole-file object (chunkless files)
	chunks   []LegacyChunk // contiguous chunk objects
	children map[string]DirEntry
	names    []string // sorted child names (directories)
}

// LegacyBaseTree exposes a legacy manifest through the BaseTree interface.
// The manifest is already an eager in-memory entry list; the adapter's maps
// are proportional to it and no PFT2 objects are allocated or fetched.
type LegacyBaseTree struct {
	byIno map[uint64]*legacyFile
	byRef map[Ref]*legacyFile
}

var _ BaseTree = (*LegacyBaseTree)(nil)

func legacyRef(ino uint64) Ref {
	digest := sha256.Sum256([]byte("pft2-legacy-inode\x00" + strconv.FormatUint(ino, 10)))
	return Ref{Digest: digest, Size: 0}
}

// NewLegacyBaseTree builds the adapter from a legacy manifest entry list
// (any order). Explicit nonzero inode ids are preserved exactly (they live in
// the reserved namespace-0 legacy domain or are verified composed ids);
// entries without one receive deterministic ids above the maximum explicit
// id, in ascending path-byte order. Missing intermediate directories are
// synthesized. The root directory is always inode 1.
func NewLegacyBaseTree(entries []LegacyEntry) (*LegacyBaseTree, error) {
	sorted := make([]LegacyEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	byPath := map[string]*LegacyEntry{}
	maxExplicit := RootIno
	for i := range sorted {
		e := &sorted[i]
		if e.Path == "" || strings.HasPrefix(e.Path, "/") || strings.Contains(e.Path, "//") ||
			strings.HasSuffix(e.Path, "/") {
			return nil, invalidf("legacy entry has invalid path %q", e.Path)
		}
		for _, segment := range strings.Split(e.Path, "/") {
			if err := ValidateEntryName(segment); err != nil {
				return nil, invalidf("legacy path %q: %v", e.Path, err)
			}
		}
		if _, dup := byPath[e.Path]; dup {
			return nil, invalidf("legacy manifest repeats path %q", e.Path)
		}
		byPath[e.Path] = e
		if e.Ino != 0 {
			if e.Ino > MaxIno {
				return nil, invalidf("legacy entry %q ino %d exceeds %d", e.Path, e.Ino, MaxIno)
			}
			if e.Ino == RootIno {
				return nil, invalidf("legacy entry %q claims reserved root ino %d", e.Path, RootIno)
			}
			if e.Ino > maxExplicit {
				maxExplicit = e.Ino
			}
		}
	}

	tree := &LegacyBaseTree{byIno: map[uint64]*legacyFile{}, byRef: map[Ref]*legacyFile{}}
	inoByPath := map[string]uint64{"": RootIno}
	seenInos := map[uint64]string{RootIno: ""}
	nextSynthetic := maxExplicit + 1

	root := &legacyFile{
		inode: Inode{
			Ino:   RootIno,
			Kind:  FileKindDirectory,
			Mode:  0o755,
			Nlink: 1,
		},
		ref:      legacyRef(RootIno),
		children: map[string]DirEntry{},
	}
	tree.register(root)

	// Ensure every ancestor directory exists (synthesizing absent ones and
	// linking them into their parent), in ascending path order so parents
	// always precede children.
	ensureDir := func(path string) error {
		if _, ok := inoByPath[path]; ok {
			file := tree.fileByPath(inoByPath, path)
			if file.inode.Kind != FileKindDirectory {
				return invalidf("legacy path %q is used as a directory but is %s", path, file.inode.Kind)
			}
			return nil
		}
		ino := nextSynthetic
		nextSynthetic++
		if ino > MaxIno {
			return invalidf("legacy manifest exhausts synthetic inode space")
		}
		inoByPath[path] = ino
		seenInos[ino] = path
		tree.register(&legacyFile{
			inode: Inode{
				Ino:   ino,
				Kind:  FileKindDirectory,
				Mode:  0o755,
				Nlink: 1,
			},
			ref:      legacyRef(ino),
			children: map[string]DirEntry{},
		})
		parentPath := ""
		if idx := strings.LastIndexByte(path, '/'); idx >= 0 {
			parentPath = path[:idx]
		}
		parent := tree.fileByPath(inoByPath, parentPath)
		if parent == nil || parent.inode.Kind != FileKindDirectory {
			return invalidf("legacy path %q has non-directory parent", path)
		}
		name := path[strings.LastIndexByte(path, '/')+1:]
		parent.children[name] = DirEntry{Name: name, Ino: ino, Kind: FileKindDirectory}
		return nil
	}

	for i := range sorted {
		e := &sorted[i]
		parentPath := ""
		if idx := strings.LastIndexByte(e.Path, '/'); idx >= 0 {
			parentPath = e.Path[:idx]
		}
		// Ascending path order guarantees ancestors sort before descendants,
		// but only for ancestors missing from the manifest do we synthesize.
		for _, ancestor := range ancestorPaths(e.Path) {
			if err := ensureDir(ancestor); err != nil {
				return nil, err
			}
		}

		ino := e.Ino
		if existing, ok := inoByPath[e.Path]; ok {
			// The path was synthesized as an ancestor before its explicit
			// entry arrived — impossible in ascending order.
			return nil, invalidf("legacy path %q registered twice (ino %d)", e.Path, existing)
		}
		if ino == 0 {
			ino = nextSynthetic
			nextSynthetic++
			if ino > MaxIno {
				return nil, invalidf("legacy manifest exhausts synthetic inode space")
			}
		} else if prior, taken := seenInos[ino]; taken {
			return nil, invalidf("legacy entries %q and %q share ino %d", prior, e.Path, ino)
		}
		inoByPath[e.Path] = ino
		seenInos[ino] = e.Path

		file, err := legacyFileOf(e, ino)
		if err != nil {
			return nil, err
		}
		tree.register(file)

		parent := tree.fileByPath(inoByPath, parentPath)
		if parent == nil || parent.inode.Kind != FileKindDirectory {
			return nil, invalidf("legacy entry %q has non-directory parent", e.Path)
		}
		name := e.Path[strings.LastIndexByte(e.Path, '/')+1:]
		parent.children[name] = DirEntry{Name: name, Ino: ino, Kind: file.inode.Kind}
	}

	for _, file := range tree.byIno {
		if file.inode.Kind != FileKindDirectory {
			continue
		}
		file.names = make([]string, 0, len(file.children))
		for name := range file.children {
			file.names = append(file.names, name)
		}
		sort.Strings(file.names)
		if err := (&file.inode).validate(); err != nil {
			return nil, err
		}
	}
	return tree, nil
}

func ancestorPaths(path string) []string {
	var out []string
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			out = append(out, path[:i])
		}
	}
	return out
}

func (t *LegacyBaseTree) register(file *legacyFile) {
	t.byIno[file.inode.Ino] = file
	t.byRef[file.ref] = file
}

func (t *LegacyBaseTree) fileByPath(inoByPath map[string]uint64, path string) *legacyFile {
	ino, ok := inoByPath[path]
	if !ok {
		return nil
	}
	return t.byIno[ino]
}

func legacyFileOf(e *LegacyEntry, ino uint64) (*legacyFile, error) {
	if e.Size < 0 || e.BlobSize < 0 {
		return nil, invalidf("legacy entry %q has negative size", e.Path)
	}
	mode := e.Mode & MaxModeBits
	inode := Inode{
		Ino:     ino,
		Mode:    mode,
		UID:     e.UID,
		GID:     e.GID,
		Nlink:   1,
		MtimeMs: e.MtimeMs,
		CtimeMs: e.CtimeMs,
		AtimeMs: e.AtimeMs,
	}
	file := &legacyFile{ref: legacyRef(ino)}
	switch e.Kind {
	case "directory":
		inode.Kind = FileKindDirectory
		file.children = map[string]DirEntry{}
	case "symlink":
		inode.Kind = FileKindSymlink
		inode.SymlinkTarget = e.LinkTarget
		// Legacy manifests occasionally disagree with the target's byte
		// length; the target is authoritative.
		inode.Size = uint64(len(e.LinkTarget))
	case "file":
		inode.Kind = FileKindRegular
		inode.Size = uint64(e.Size)
		if inode.Size > MaxLogicalFileBytes {
			return nil, invalidf("legacy entry %q size %d exceeds %d", e.Path, e.Size, MaxLogicalFileBytes)
		}
		if len(e.Chunks) > 0 {
			chunks := make([]LegacyChunk, len(e.Chunks))
			copy(chunks, e.Chunks)
			sort.Slice(chunks, func(i, j int) bool { return chunks[i].Offset < chunks[j].Offset })
			var expected int64
			for i := range chunks {
				c := &chunks[i]
				if c.Digest == "" || c.Size <= 0 || c.Offset != expected {
					return nil, invalidf("legacy entry %q has non-contiguous or invalid chunks", e.Path)
				}
				expected += c.Size
			}
			if uint64(expected) != inode.Size {
				return nil, invalidf("legacy entry %q chunk sizes sum %d, size %d", e.Path, expected, e.Size)
			}
			file.chunks = chunks
		} else if inode.Size > 0 {
			if e.BlobDigest == "" {
				return nil, invalidf("legacy entry %q has size %d but no blob", e.Path, e.Size)
			}
			if uint64(e.BlobSize) != inode.Size {
				return nil, invalidf("legacy entry %q blob size %d, size %d", e.Path, e.BlobSize, e.Size)
			}
			file.blob = &LegacyExtent{
				ObjectDigest: e.BlobDigest,
				ObjectSize:   uint64(e.BlobSize),
				ObjectOffset: 0,
			}
		}
	default:
		return nil, invalidf("legacy entry %q has unknown kind %q", e.Path, e.Kind)
	}
	file.inode = inode
	if err := (&file.inode).validate(); err != nil {
		return nil, invalidf("legacy entry %q: %v", e.Path, err)
	}
	return file, nil
}

func (t *LegacyBaseTree) fileFor(ref Ref) (*legacyFile, error) {
	file, ok := t.byRef[ref]
	if !ok {
		return nil, corruptf("unknown legacy handle %s", ref.Hex())
	}
	return file, nil
}

// GetInode implements BaseTree.
func (t *LegacyBaseTree) GetInode(_ context.Context, ino uint64) (InodeView, error) {
	file, ok := t.byIno[ino]
	if !ok {
		return InodeView{}, notFoundf("legacy ino")
	}
	return InodeView{Ref: file.ref, Inode: file.inode}, nil
}

// Lookup implements BaseTree.
func (t *LegacyBaseTree) Lookup(_ context.Context, parent Ref, name string) (DirEntry, error) {
	if err := ValidateEntryName(name); err != nil {
		return DirEntry{}, err
	}
	file, err := t.fileFor(parent)
	if err != nil {
		return DirEntry{}, err
	}
	if file.inode.Kind != FileKindDirectory {
		return DirEntry{}, corruptf("legacy inode %d is %s, not a directory", file.inode.Ino, file.inode.Kind)
	}
	entry, ok := file.children[name]
	if !ok {
		return DirEntry{}, notFoundf("legacy name")
	}
	return entry, nil
}

// ReadDir implements BaseTree.
func (t *LegacyBaseTree) ReadDir(_ context.Context, dir Ref, cursor string, limit int) ([]DirEntry, string, error) {
	if limit <= 0 {
		return nil, "", invalidf("readdir limit %d must be positive", limit)
	}
	file, err := t.fileFor(dir)
	if err != nil {
		return nil, "", err
	}
	if file.inode.Kind != FileKindDirectory {
		return nil, "", corruptf("legacy inode %d is %s, not a directory", file.inode.Ino, file.inode.Kind)
	}
	start := sort.SearchStrings(file.names, cursor)
	if start < len(file.names) && file.names[start] == cursor {
		start++
	}
	var out []DirEntry
	for _, name := range file.names[start:] {
		if len(out) >= limit {
			return out, out[len(out)-1].Name, nil
		}
		out = append(out, file.children[name])
	}
	return out, "", nil
}

// ReadExtents implements BaseTree over legacy whole-file/chunk objects.
func (t *LegacyBaseTree) ReadExtents(_ context.Context, ref Ref, offset, length uint64) ([]Extent, error) {
	file, err := t.fileFor(ref)
	if err != nil {
		return nil, err
	}
	if file.inode.Kind != FileKindRegular {
		return nil, corruptf("legacy inode %d is %s, not a regular file", file.inode.Ino, file.inode.Kind)
	}
	size := file.inode.Size
	if length == 0 || offset >= size {
		return nil, nil
	}
	end := offset + length
	if end < offset || end > size {
		end = size
	}
	var out []Extent
	appendRange := func(objDigest string, objSize, objStart, fileStart, fileEnd uint64) {
		if fileEnd <= offset || fileStart >= end {
			return
		}
		from := max64(fileStart, offset)
		to := min64(fileEnd, end)
		out = append(out, Extent{
			FileOffset: from,
			Length:     to - from,
			Legacy: &LegacyExtent{
				ObjectDigest: objDigest,
				ObjectSize:   objSize,
				ObjectOffset: objStart + (from - fileStart),
			},
		})
	}
	if len(file.chunks) > 0 {
		for i := range file.chunks {
			c := &file.chunks[i]
			appendRange(c.Digest, uint64(c.Size), 0, uint64(c.Offset), uint64(c.Offset+c.Size))
		}
		return out, nil
	}
	if file.blob != nil {
		appendRange(file.blob.ObjectDigest, file.blob.ObjectSize, 0, 0, size)
	}
	return out, nil
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
