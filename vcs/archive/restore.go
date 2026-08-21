package archive

import (
	"fmt"
	"sort"
)

// The restore side of the format: the namespace plan the restorer materializes
// before the first mount is admitted, and the chunk lookup the hydrator uses to
// turn a read of a cold offset into a byte range in a pack object.

// PlanStep is one node of the namespace, in the order a restorer creates it.
// Because the entry table is depth-first, following the steps in order means a
// parent directory always exists before anything is created inside it, and one
// forward pass with a stack of open directory handles is enough.
//
// LinkFrom is the index of the entry that already materialized this inode, or
// -1 when this step creates it. A hardlink group is materialized once and
// linked thereafter, which is what makes the restored tree have one inode per
// group rather than one per name.
//
// Xattrs are the pre-existing user.* attributes to set on the created node.
// They are part of the namespace pass, not the hydration pass: they are visible
// through PortableFS the moment the node exists, so they must be in place
// before the first mount is admitted.
type PlanStep struct {
	Index       uint32
	ParentIndex uint32
	Name        []byte
	Type        EntryType
	Size        uint64
	Mode        uint32
	MTimeNanos  int64
	LinkName    []byte
	Xattrs      []Xattr
	Group       uint32
	LinkFrom    int32
}

// Creates reports whether this step materializes the inode, as opposed to
// adding another link to one an earlier step already created.
func (s PlanStep) Creates() bool { return s.LinkFrom < 0 }

// PlanIterator walks the namespace plan. It is an iterator rather than a slice
// because a restorer streams a tree of any size through it and never needs two
// steps at once.
type PlanIterator struct {
	manifest *Manifest
	at       int
	// created maps a hardlink group to the entry that materialized it.
	created map[uint32]uint32
}

// NamespacePlan returns the restorer's plan for this manifest. The manifest
// must already be validated; the plan trusts the graph rather than re-deriving
// it per step.
func (m *Manifest) NamespacePlan() *PlanIterator {
	return &PlanIterator{manifest: m, created: make(map[uint32]uint32)}
}

// Next returns the next step, reporting false when the plan is complete. The
// root is step zero: a restorer applies its mode, mtime, and attributes to the
// volume directory it has already provisioned rather than creating it.
func (p *PlanIterator) Next() (PlanStep, bool) {
	if p.at >= len(p.manifest.Entries) {
		return PlanStep{}, false
	}
	index := p.at
	p.at++
	entry := &p.manifest.Entries[index]
	step := PlanStep{
		Index:       uint32(index),
		ParentIndex: entry.ParentIndex,
		Name:        entry.Name,
		Type:        entry.Type,
		Size:        entry.Size,
		Mode:        entry.Mode,
		MTimeNanos:  entry.MTimeNanos,
		LinkName:    entry.LinkName,
		Xattrs:      entry.Xattrs,
		Group:       entry.HardlinkGroup,
		LinkFrom:    -1,
	}
	if entry.HardlinkGroup != 0 {
		if first, ok := p.created[entry.HardlinkGroup]; ok {
			step.LinkFrom = int32(first)
		} else {
			p.created[entry.HardlinkGroup] = uint32(index)
		}
	}
	return step, true
}

// Path returns one entry's path as raw name components from the volume root,
// which is the empty slice. Components are raw bytes because a Linux path is
// not required to be UTF-8, and they are never joined with a separator here:
// joining is the caller's decision and a name may contain anything but NUL and
// the separator itself.
func (m *Manifest) Path(index uint32) ([][]byte, error) {
	if index >= uint32(len(m.Entries)) {
		return nil, fmt.Errorf("%w: entry %d does not exist", ErrInvalid, index)
	}
	depth := 0
	for at := index; at != 0; at = m.Entries[at].ParentIndex {
		depth++
		if depth > len(m.Entries) {
			return nil, fmt.Errorf("%w: entry %d has no path to the root", ErrInvalid, index)
		}
	}
	components := make([][]byte, depth)
	at := index
	for position := depth - 1; position >= 0; position-- {
		components[position] = m.Entries[at].Name
		at = m.Entries[at].ParentIndex
	}
	return components, nil
}

// ChunkAt is the hydrator's lookup: which chunk of an entry covers a logical
// offset, and where its bytes are. A chunk that is not stored is a hole, born
// hydrated; the caller writes nothing and marks it.
func (m *Manifest) ChunkAt(index uint32, offset uint64) (chunkIndex int, chunk ChunkRef, err error) {
	if index >= uint32(len(m.Entries)) {
		return 0, ChunkRef{}, fmt.Errorf("%w: entry %d does not exist", ErrInvalid, index)
	}
	entry := &m.Entries[index]
	if entry.Type != TypeRegular {
		return 0, ChunkRef{}, fmt.Errorf("%w: entry %d is a %s, not a regular file", ErrInvalid, index, entry.Type)
	}
	if offset >= entry.Size {
		return 0, ChunkRef{}, fmt.Errorf("%w: offset %d is past entry %d's size %d",
			ErrInvalid, offset, index, entry.Size)
	}
	position := int(offset / uint64(m.Header.ChunkSizeBytes))
	return position, entry.Chunks[position], nil
}

// FramesForEntry is every frame one entry's content lives in, in ascending
// frame order with duplicates removed. It is what a hydrator hands to
// CoalesceFrames to fetch a whole file in as few requests as the layout allows.
func (m *Manifest) FramesForEntry(index uint32) ([]uint32, error) {
	if index >= uint32(len(m.Entries)) {
		return nil, fmt.Errorf("%w: entry %d does not exist", ErrInvalid, index)
	}
	entry := &m.Entries[index]
	seen := make(map[uint32]struct{}, len(entry.Chunks))
	frames := make([]uint32, 0, len(entry.Chunks))
	for _, chunk := range entry.Chunks {
		if !chunk.Stored() {
			continue
		}
		if _, ok := seen[chunk.FrameIndex]; ok {
			continue
		}
		seen[chunk.FrameIndex] = struct{}{}
		frames = append(frames, chunk.FrameIndex)
	}
	sort.Slice(frames, func(i, j int) bool { return frames[i] < frames[j] })
	return frames, nil
}
