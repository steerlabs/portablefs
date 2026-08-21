package archive

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"
)

// rng is SplitMix64. It is used instead of math/rand for the same reason the
// direct-store harness uses it: a failing seed must reproduce the identical
// tree on any toolchain, and math/rand's stream is not a stable contract.
type rng struct{ state uint64 }

func newRNG(seed uint64) *rng { return &rng{state: seed} }

func (r *rng) uint64() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (r *rng) bounded(n uint64) uint64 {
	if n == 0 {
		panic("archive test: zero bound")
	}
	threshold := (0 - n) % n
	for {
		value := r.uint64()
		if value >= threshold {
			return value % n
		}
	}
}

func (r *rng) intn(n int) int { return int(r.bounded(uint64(n))) }

func (r *rng) bytes(n int) []byte {
	out := make([]byte, n)
	for index := range out {
		out[index] = byte(r.uint64())
	}
	return out
}

// memoryPacks is both the builder's sink and the reader's source, so a test
// round-trips through exactly the interfaces a real uploader and hydrator use.
type memoryPacks struct {
	packs [][]byte
}

type packBuffer struct {
	owner *memoryPacks
	index uint32
	buf   bytes.Buffer
}

func (p *packBuffer) Write(b []byte) (int, error) { return p.buf.Write(b) }

func (p *packBuffer) Close() error {
	p.owner.packs[p.index] = append([]byte(nil), p.buf.Bytes()...)
	return nil
}

func (m *memoryPacks) OpenPack(index uint32) (io.WriteCloser, error) {
	if int(index) != len(m.packs) {
		return nil, fmt.Errorf("packs opened out of order: got %d, have %d", index, len(m.packs))
	}
	m.packs = append(m.packs, nil)
	return &packBuffer{owner: m, index: index}, nil
}

func (m *memoryPacks) ReadPackRange(index uint32, offset, length uint64) ([]byte, error) {
	if int(index) >= len(m.packs) {
		return nil, fmt.Errorf("pack %d does not exist", index)
	}
	pack := m.packs[index]
	if offset+length > uint64(len(pack)) {
		return nil, fmt.Errorf("range [%d,%d) past pack %d of %d bytes", offset, offset+length, index, len(pack))
	}
	return append([]byte(nil), pack[offset:offset+length]...), nil
}

// modelEntry is the ground truth one generated entry is compared against after
// a full archive and read-back.
type modelEntry struct {
	source  SourceEntry
	logical []byte
	extents []Extent
	// group is the set of entry indices sharing this entry's inode, or nil.
	group []int
}

type model struct {
	entries []modelEntry
}

func (m *model) source() *SliceSource {
	entries := make([]SourceEntry, len(m.entries))
	for index := range m.entries {
		entry := m.entries[index]
		source := entry.source
		if source.Type == TypeRegular && source.Size > 0 {
			file := &MemoryFile{Logical: entry.logical, Data: entry.extents}
			source.Open = func() (SourceFile, error) { return file, nil }
		}
		entries[index] = source
	}
	return NewSliceSource(entries)
}

// namePool covers everything a Linux name is allowed to be and a naive
// implementation gets wrong: non-UTF-8 byte sequences, multi-byte unicode,
// names that look like directory aliases without being them, leading and
// trailing whitespace, and NAME_MAX exactly.
var namePool = [][]byte{
	[]byte("file"),
	[]byte("a.txt"),
	[]byte("b.txt"),
	[]byte("notes.txt"),
	[]byte("data.bin"),
	[]byte("data.log"),
	[]byte("ünïcödé"),
	[]byte("日本語のファイル"),
	[]byte("emoji\U0001F4C1"),
	{0xff, 0xfe, 0x41},
	{0x80, 0x81, 0x82},
	{0xc3, 0x28},
	{0xed, 0xa0, 0x80},
	[]byte("...hidden"),
	[]byte(".hidden"),
	[]byte(" leading"),
	[]byte("trailing "),
	[]byte("with\tspace"),
	[]byte(strings.Repeat("n", MaxNameBytes)),
	[]byte("-"),
	[]byte("sub"),
	[]byte("deep"),
}

var xattrNamePool = [][]byte{
	[]byte("user.comment"),
	[]byte("user.mime_type"),
	[]byte("user.ünïcödé"),
	append([]byte("user."), 0xff, 0xfe),
	[]byte("user." + strings.Repeat("x", MaxXattrNameBytes-len("user."))),
}

type generator struct {
	rng       *rng
	chunkSize uint64
	model     *model
	budget    int
	nextInode uint64
}

// generateTree builds a random depth-first tree. The shape is deliberately
// hostile: deep paths, sibling names reused across directories, every content
// class the format distinguishes, and hardlink groups layered on afterwards.
func generateTree(seed uint64, chunkSize uint64, budget int) *model {
	g := &generator{
		rng:       newRNG(seed),
		chunkSize: chunkSize,
		model:     &model{},
		budget:    budget,
		nextInode: 1,
	}
	g.model.entries = append(g.model.entries, modelEntry{source: SourceEntry{
		Type:       TypeDirectory,
		Mode:       0o755,
		Nlink:      1,
		MTimeNanos: int64(g.rng.bounded(1 << 40)),
		CTimeNanos: int64(g.rng.bounded(1 << 40)),
		Xattrs:     g.xattrs(),
	}})
	g.fill(0, 0)
	g.addHardlinkGroups()
	return g.model
}

func (g *generator) fill(parent int, depth int) {
	used := map[string]struct{}{}
	children := g.rng.intn(5)
	for count := 0; count < children && g.budget > 0; count++ {
		name := namePool[g.rng.intn(len(namePool))]
		if _, taken := used[string(name)]; taken {
			continue
		}
		used[string(name)] = struct{}{}
		g.budget--
		kind := g.rng.intn(10)
		switch {
		case kind < 3 && depth < 6:
			index := g.appendEntry(SourceEntry{
				ParentIndex: uint32(parent),
				Name:        name,
				Type:        TypeDirectory,
				Mode:        g.dirMode(),
				Nlink:       1,
				MTimeNanos:  int64(g.rng.bounded(1 << 40)),
				CTimeNanos:  int64(g.rng.bounded(1 << 40)),
				Xattrs:      g.xattrs(),
			}, nil, nil)
			g.fill(index, depth+1)
		case kind < 4:
			target := namePool[g.rng.intn(len(namePool))]
			if g.rng.intn(2) == 0 {
				target = append([]byte("../"), target...)
			}
			g.appendEntry(SourceEntry{
				ParentIndex: uint32(parent),
				Name:        name,
				Type:        TypeSymlink,
				Size:        uint64(len(target)),
				Mode:        0o777,
				Nlink:       1,
				LinkName:    target,
				MTimeNanos:  int64(g.rng.bounded(1 << 40)),
				CTimeNanos:  int64(g.rng.bounded(1 << 40)),
				Xattrs:      g.xattrs(),
			}, nil, nil)
		default:
			logical, extents := g.content()
			g.appendEntry(SourceEntry{
				ParentIndex: uint32(parent),
				Name:        name,
				Type:        TypeRegular,
				Size:        uint64(len(logical)),
				Mode:        g.fileMode(),
				Nlink:       1,
				MTimeNanos:  int64(g.rng.bounded(1 << 40)),
				CTimeNanos:  int64(g.rng.bounded(1 << 40)),
				Xattrs:      g.xattrs(),
			}, logical, extents)
		}
	}
}

func (g *generator) appendEntry(source SourceEntry, logical []byte, extents []Extent) int {
	index := len(g.model.entries)
	g.model.entries = append(g.model.entries, modelEntry{source: source, logical: logical, extents: extents})
	return index
}

// dirMode and fileMode exercise the set-ID and sticky bits the format promises
// round-trip, not just ordinary permissions.
func (g *generator) dirMode() uint32 {
	modes := []uint32{0o755, 0o700, 0o1777, 0o2755, 0o750}
	return modes[g.rng.intn(len(modes))]
}

func (g *generator) fileMode() uint32 {
	modes := []uint32{0o644, 0o600, 0o755, 0o4755, 0o2644, 0o000}
	return modes[g.rng.intn(len(modes))]
}

func (g *generator) xattrs() []Xattr {
	count := g.rng.intn(4)
	if count == 0 {
		return nil
	}
	used := map[string]struct{}{}
	out := make([]Xattr, 0, count)
	for i := 0; i < count; i++ {
		name := xattrNamePool[g.rng.intn(len(xattrNamePool))]
		if _, taken := used[string(name)]; taken {
			continue
		}
		used[string(name)] = struct{}{}
		var value []byte
		switch g.rng.intn(4) {
		case 0:
			value = nil
		case 1:
			value = []byte("plain")
		case 2:
			value = g.rng.bytes(1 + g.rng.intn(64))
		default:
			value = []byte{0xff, 0x00 ^ 0x01, 0xfe, 0x80}
		}
		out = append(out, Xattr{Name: name, Value: value})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// content produces one file image plus its extent map, covering every class the
// format treats differently: empty, compressible, incompressible, multi-chunk,
// partially sparse with holes that span chunk boundaries, fully sparse, and the
// allocated-zeros twin of a fully sparse file.
func (g *generator) content() ([]byte, []Extent) {
	switch g.rng.intn(8) {
	case 0:
		return nil, nil
	case 1:
		size := 1 + g.rng.intn(int(g.chunkSize))
		return bytes.Repeat([]byte("compressible-"), size/13+1)[:size], []Extent{{Offset: 0, Length: uint64(size)}}
	case 2:
		size := 1 + g.rng.intn(int(g.chunkSize))
		return g.rng.bytes(size), []Extent{{Offset: 0, Length: uint64(size)}}
	case 3:
		size := int(g.chunkSize)*(2+g.rng.intn(4)) + g.rng.intn(int(g.chunkSize))
		return g.rng.bytes(size), []Extent{{Offset: 0, Length: uint64(size)}}
	case 4, 5:
		return g.sparse()
	case 6:
		size := int(g.chunkSize)*(1+g.rng.intn(3)) + g.rng.intn(97)
		return make([]byte, size), nil
	default:
		size := int(g.chunkSize)*(1+g.rng.intn(3)) + g.rng.intn(97)
		return make([]byte, size), []Extent{{Offset: 0, Length: uint64(size)}}
	}
}

// sparse builds a file whose data extents are separated by real holes, sized so
// that extents routinely straddle chunk boundaries.
func (g *generator) sparse() ([]byte, []Extent) {
	size := int(g.chunkSize)*(1+g.rng.intn(4)) + g.rng.intn(int(g.chunkSize))
	logical := make([]byte, size)
	var extents []Extent
	offset := 0
	for offset < size {
		hole := 1 + g.rng.intn(int(g.chunkSize)/2+1)
		offset += hole
		if offset >= size {
			break
		}
		data := 1 + g.rng.intn(int(g.chunkSize)+1)
		if offset+data > size {
			data = size - offset
		}
		filler := g.rng.bytes(data)
		for i := range filler {
			if filler[i] == 0 {
				filler[i] = 1
			}
		}
		copy(logical[offset:offset+data], filler)
		extents = append(extents, Extent{Offset: uint64(offset), Length: uint64(data)})
		offset += data
	}
	return logical, extents
}

// addHardlinkGroups turns some existing regular files into links to one inode.
// Group members must be byte-identical because they are one inode, so the whole
// image and extent map are copied from the group's first member.
func (g *generator) addHardlinkGroups() {
	var regular []int
	for index := range g.model.entries {
		if g.model.entries[index].source.Type == TypeRegular {
			regular = append(regular, index)
		}
	}
	if len(regular) < 2 {
		return
	}
	groups := g.rng.intn(3)
	assigned := map[int]bool{}
	for i := 0; i < groups; i++ {
		size := 2 + g.rng.intn(2)
		var members []int
		for len(members) < size {
			candidate := regular[g.rng.intn(len(regular))]
			if assigned[candidate] {
				break
			}
			duplicate := false
			for _, existing := range members {
				if existing == candidate {
					duplicate = true
				}
			}
			if duplicate {
				break
			}
			members = append(members, candidate)
		}
		if len(members) < 2 {
			continue
		}
		owner := members[0]
		key := g.nextInode
		g.nextInode++
		for _, index := range members {
			assigned[index] = true
			entry := &g.model.entries[index]
			entry.logical = g.model.entries[owner].logical
			entry.extents = g.model.entries[owner].extents
			entry.source.Size = g.model.entries[owner].source.Size
			entry.source.Mode = g.model.entries[owner].source.Mode
			entry.source.MTimeNanos = g.model.entries[owner].source.MTimeNanos
			entry.source.InodeKey = key
			entry.source.Nlink = uint32(len(members))
			entry.group = members
		}
	}
}

func testConfig(chunkSize uint32) BuilderConfig {
	config := DefaultBuilderConfig()
	config.ChunkSizeBytes = chunkSize
	config.PackTargetBytes = uint64(chunkSize) * 8
	config.PriorityLogicalBytes = uint64(chunkSize) * 3
	config.VolumeID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	config.Attempt = [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	config.SealedEpoch = 7
	return config
}

// absoluteExtents recovers a file's whole-file extent map from its per-chunk
// maps, merging the pieces chunking split at chunk boundaries. Comparing this
// against the model's map is what proves sparseness round-trips exactly rather
// than approximately.
func absoluteExtents(manifest *Manifest, entry *Entry) []Extent {
	chunkSize := uint64(manifest.Header.ChunkSizeBytes)
	var out []Extent
	for chunkIndex, chunk := range entry.Chunks {
		base := uint64(chunkIndex) * chunkSize
		for _, extent := range chunk.Extents {
			absolute := Extent{Offset: base + extent.Offset, Length: extent.Length}
			if last := len(out) - 1; last >= 0 && out[last].Offset+out[last].Length == absolute.Offset {
				out[last].Length += absolute.Length
				continue
			}
			out = append(out, absolute)
		}
	}
	return out
}

// verifyModel is the full-tree comparison: bytes reconstructed from packs,
// modes, ns-mtimes, symlink targets, extent maps, hardlink relations, xattrs,
// and content digests, for every entry.
func verifyModel(t *testing.T, m *model, manifest *Manifest, packs *memoryPacks) {
	t.Helper()
	if len(manifest.Entries) != len(m.entries) {
		t.Fatalf("manifest has %d entries, model has %d", len(manifest.Entries), len(m.entries))
	}
	reader, err := NewPackReader(manifest, packs)
	if err != nil {
		t.Fatalf("new pack reader: %v", err)
	}
	groupOf := map[int]uint32{}
	for index := range manifest.Entries {
		entry := &manifest.Entries[index]
		want := &m.entries[index]
		if !bytes.Equal(entry.Name, want.source.Name) {
			t.Fatalf("entry %d name %q, want %q", index, entry.Name, want.source.Name)
		}
		if entry.Type != want.source.Type {
			t.Fatalf("entry %d type %v, want %v", index, entry.Type, want.source.Type)
		}
		if entry.Mode != want.source.Mode&ModeMask {
			t.Fatalf("entry %d mode %o, want %o", index, entry.Mode, want.source.Mode&ModeMask)
		}
		if entry.MTimeNanos != want.source.MTimeNanos {
			t.Fatalf("entry %d mtime %d, want %d", index, entry.MTimeNanos, want.source.MTimeNanos)
		}
		if entry.CTimeNanos != want.source.CTimeNanos {
			t.Fatalf("entry %d ctime %d, want %d", index, entry.CTimeNanos, want.source.CTimeNanos)
		}
		if !bytes.Equal(entry.LinkName, want.source.LinkName) {
			t.Fatalf("entry %d link target %q, want %q", index, entry.LinkName, want.source.LinkName)
		}
		verifyXattrs(t, index, entry.Xattrs, want.source.Xattrs)
		if entry.ParentIndex != want.source.ParentIndex {
			t.Fatalf("entry %d parent %d, want %d", index, entry.ParentIndex, want.source.ParentIndex)
		}
		if len(want.group) > 1 {
			if entry.HardlinkGroup == 0 {
				t.Fatalf("entry %d is one of %d links but carries no group", index, len(want.group))
			}
			if entry.Nlink != uint32(len(want.group)) {
				t.Fatalf("entry %d link count %d, want %d", index, entry.Nlink, len(want.group))
			}
			groupOf[index] = entry.HardlinkGroup
		} else if entry.HardlinkGroup != 0 {
			t.Fatalf("entry %d carries group %d but is a single link", index, entry.HardlinkGroup)
		}
		if entry.Type != TypeRegular {
			continue
		}
		if entry.Size != uint64(len(want.logical)) {
			t.Fatalf("entry %d size %d, want %d", index, entry.Size, len(want.logical))
		}
		if entry.ContentDigest != sha256.Sum256(want.logical) {
			t.Fatalf("entry %d content digest does not cover its bytes", index)
		}
		got, err := reader.ReadFile(uint32(index))
		if err != nil {
			t.Fatalf("entry %d read back: %v", index, err)
		}
		if !bytes.Equal(got, want.logical) {
			t.Fatalf("entry %d reconstructed %d bytes that differ from the source", index, len(got))
		}
		gotExtents := absoluteExtents(manifest, entry)
		if !equalExtents(gotExtents, want.extents) {
			t.Fatalf("entry %d extent map %v, want %v", index, gotExtents, want.extents)
		}
	}
	// Every member of a source hardlink group must have landed in one manifest
	// group, and members of different source groups must not share one.
	for index, group := range groupOf {
		for _, member := range m.entries[index].group {
			if groupOf[member] != group {
				t.Fatalf("entries %d and %d share an inode but are in groups %d and %d",
					index, member, group, groupOf[member])
			}
		}
	}
}

func verifyXattrs(t *testing.T, index int, got, want []Xattr) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("entry %d has %d xattrs, want %d", index, len(got), len(want))
	}
	for _, expected := range want {
		found := false
		for _, actual := range got {
			if bytes.Equal(actual.Name, expected.Name) {
				found = true
				if !bytes.Equal(actual.Value, expected.Value) {
					t.Fatalf("entry %d xattr %q value %q, want %q", index, expected.Name, actual.Value, expected.Value)
				}
			}
		}
		if !found {
			t.Fatalf("entry %d is missing xattr %q", index, expected.Name)
		}
	}
	for position := 1; position < len(got); position++ {
		if bytes.Compare(got[position-1].Name, got[position].Name) >= 0 {
			t.Fatalf("entry %d xattrs are not in canonical order", index)
		}
	}
}

func equalExtents(a, b []Extent) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}
