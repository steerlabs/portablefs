package pft2

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pfwire"
)

func labelDigest(label string) [DigestBytes]byte {
	return sha256.Sum256([]byte(label))
}

func labelRef(label string, size uint64) Ref {
	return Ref{Digest: labelDigest(label), Size: size}
}

func refPtr(r Ref) *Ref { return &r }

// sampleNodes returns one valid instance of every node kind (the same
// definitions feed the golden vectors).
func sampleNodes() map[string]*Node {
	symlinkTarget := "π/→/target"
	return map[string]*Node{
		"root": {Kind: KindRoot, Root: &Root{
			RootInode:    labelRef("root-inode", 120),
			InodeIndex:   labelRef("inode-index", 321),
			MaxInoSeen:   4294967298,
			InodeCount:   3,
			DirentCount:  2,
			LogicalBytes: 70000,
		}},
		"root-xattrs": {Kind: KindRoot, Root: &Root{
			RootInode:    labelRef("root-inode", 120),
			InodeIndex:   labelRef("inode-index", 321),
			MaxInoSeen:   4294967298,
			InodeCount:   3,
			DirentCount:  2,
			LogicalBytes: 70000,
			XattrLeaves:  []Ref{labelRef("xattr-leaf-0", 300), labelRef("xattr-leaf-1", 301)},
		}},
		"inode-file": {Kind: KindInode, Inode: &Inode{
			Ino: 21474836487, Kind: FileKindRegular, Mode: 0o644, UID: 1000, GID: 1000,
			Nlink: 1, Size: 70000, MtimeMs: 1700000000123, CtimeMs: 1700000000456,
			AtimeMs: -777, ExtentRoot: refPtr(labelRef("extent-root", 555)),
		}},
		"inode-dir": {Kind: KindInode, Inode: &Inode{
			Ino: 1, Kind: FileKindDirectory, Mode: 0o755, Nlink: 1,
			DirectoryRoot: refPtr(labelRef("dir-root", 200)),
		}},
		"inode-symlink": {Kind: KindInode, Inode: &Inode{
			Ino: 42, Kind: FileKindSymlink, Mode: 0o777, Nlink: 1,
			Size: uint64(len(symlinkTarget)), SymlinkTarget: symlinkTarget,
		}},
		"inode-empty-file": {Kind: KindInode, Inode: &Inode{
			Ino: 99, Kind: FileKindRegular, Nlink: 1,
		}},
		// Fields 14/15 (APPENDED). These vectors pin the exact appended bytes
		// in BOTH languages; the pre-existing inode vectors above deliberately
		// keep both fields at their omitted zero default, so their bytes are
		// unchanged by the format revision (the forward-only compat contract).
		"inode-birthtime-flags": {Kind: KindInode, Inode: &Inode{
			Ino: 21474836488, Kind: FileKindRegular, Mode: 0o600, UID: 501, GID: 20,
			Nlink: 2, Size: 4096, MtimeMs: 1700000009999, CtimeMs: 1700000008888,
			AtimeMs: 1700000007777, BirthtimeMs: 1700000000001,
			Flags:      0x00008000, // UF_HIDDEN
			ExtentRoot: refPtr(labelRef("extent-root", 555)),
		}},
		// A birth time BEFORE the epoch (zigzag-negative) and the full uint32
		// flag space: the two encodings a Go/TS varint disagreement would show
		// up in first.
		"inode-birthtime-negative-flags-max": {Kind: KindInode, Inode: &Inode{
			Ino: 7, Kind: FileKindDirectory, Mode: 0o755, Nlink: 1,
			MtimeMs: 12, CtimeMs: 13, AtimeMs: 14, BirthtimeMs: -1700000000001,
			Flags:         0xFFFFFFFF,
			DirectoryRoot: refPtr(labelRef("dir-root", 200)),
		}},
		// Flags without a birth time: field 14 omitted, field 15 present —
		// proves the two appended fields are independently optional.
		"inode-flags-only": {Kind: KindInode, Inode: &Inode{
			Ino: 8, Kind: FileKindSymlink, Mode: 0o777, Nlink: 1,
			Size: uint64(len(symlinkTarget)), SymlinkTarget: symlinkTarget,
			Flags: 0x00000002, // UF_IMMUTABLE
		}},
		"directory-leaf": {Kind: KindDirectoryLeaf, DirectoryLeaf: &DirectoryLeaf{
			Entries: []DirEntry{
				{Name: ".hidden", Ino: 12, Kind: FileKindRegular},
				{Name: "a", Ino: 10, Kind: FileKindDirectory},
				{Name: "ab", Ino: 11, Kind: FileKindSymlink},
				{Name: "béta", Ino: 13, Kind: FileKindRegular},
			},
		}},
		"directory-index": {Kind: KindDirectoryIndex, DirectoryIndex: &DirectoryIndex{
			Children: []DirectoryIndexChild{
				{FirstName: ".hidden", LastName: "ab", Child: labelRef("dir-leaf-0", 5000), EntryCount: 3},
				{FirstName: "béta", LastName: "zz", Child: labelRef("dir-leaf-1", 6000), EntryCount: 2},
			},
		}},
		"extent-leaf": {Kind: KindExtentLeaf, ExtentLeaf: &ExtentLeaf{
			Entries: []ExtentEntry{
				{PageOffset: 0, Page: labelRef("page-0", 900)},
				{PageOffset: 65536, Page: labelRef("page-1", 901)},
				{PageOffset: 6553600, Page: labelRef("page-100", 902)},
			},
		}},
		"extent-index": {Kind: KindExtentIndex, ExtentIndex: &ExtentIndex{
			Children: []ExtentIndexChild{
				{FirstPage: 0, LastPage: 65536, Child: labelRef("extent-leaf-0", 1000), EntryCount: 2},
				{FirstPage: 131072, LastPage: 6553600, Child: labelRef("extent-leaf-1", 1001), EntryCount: 7},
			},
		}},
		"inode-index-leaf": {Kind: KindInodeIndexLeaf, InodeIndexLeaf: &InodeIndexLeaf{
			Entries: []InodeIndexEntry{
				{Ino: 1, Inode: labelRef("ino-1", 150)},
				{Ino: 21474836487, Inode: labelRef("ino-file", 151)},
			},
		}},
		"inode-index-index": {Kind: KindInodeIndexIndex, InodeIndexIndex: &InodeIndexIndex{
			Children: []InodeIndexChild{
				{FirstIno: 1, LastIno: 100, Child: labelRef("ino-leaf-0", 400), EntryCount: 5},
				{FirstIno: 101, LastIno: 21474836487, Child: labelRef("ino-leaf-1", 401), EntryCount: 6},
			},
		}},
		"recovery-root": {Kind: KindRecoveryRoot, RecoveryRoot: &RecoveryRoot{
			AsOfSeq:        123456789012345,
			FilesystemRoot: labelRef("fs-root", 180),
			ControlRoot:    refPtr(labelRef("control-root", 90)),
			OrphanIndex:    refPtr(labelRef("orphan-index", 91)),
			InoNamespace:   2147483647,
			NextLocal:      4294967296,
		}},
		"recovery-root-fresh": {Kind: KindRecoveryRoot, RecoveryRoot: &RecoveryRoot{
			FilesystemRoot: labelRef("fs-root", 180),
			InoNamespace:   7,
			NextLocal:      1,
		}},
		"data-page": {Kind: KindDataPage, DataPage: func() *DataPage {
			p := &DataPage{}
			p.Cells[0] = &CellRef{
				CellDigest: labelDigest("cell-0"), Object: labelRef("pack-0", 16384), ObjectOffset: 0,
			}
			p.Cells[15] = &CellRef{
				CellDigest: labelDigest("cell-15"), Object: labelRef("pack-0", 16384), ObjectOffset: 12288,
			}
			return p
		}()},
		"control-root-empty": {Kind: KindControlRoot, ControlRoot: &ControlRoot{
			Schema: 1, NextCheckoutEpoch: 1,
		}},
		"control-root": {Kind: KindControlRoot, ControlRoot: &ControlRoot{
			Schema: 1, MapRoot: refPtr(labelRef("control-map", 777)),
			NextCheckoutEpoch: 922337203685477580,
			Counts:            []ControlKindCount{{Kind: 1, Count: 3}, {Kind: 7, Count: 1}},
		}},
		"control-root-floor": {Kind: KindControlRoot, ControlRoot: &ControlRoot{
			Schema: 1, NextCheckoutEpoch: 42, DbTimeFloorMs: 1_752_222_333_444,
		}},
		"control-leaf": {Kind: KindControlLeaf, ControlLeaf: &ControlLeaf{
			Entries: []ControlEntry{
				{Key: []byte("a-key"), Kind: 1, Value: []byte("value-bytes")},
				{Key: []byte("b-key"), Kind: 7},
			},
		}},
		"control-index": {Kind: KindControlIndex, ControlIndex: &ControlIndex{
			Children: []ControlIndexChild{
				{FirstKey: []byte("a"), LastKey: []byte("m"), Child: labelRef("control-leaf-0", 800), EntryCount: 12},
				{FirstKey: []byte("n"), LastKey: []byte("z"), Child: labelRef("control-leaf-1", 801), EntryCount: 9},
			},
		}},
		"recovery-root-xattrs": {Kind: KindRecoveryRoot, RecoveryRoot: &RecoveryRoot{
			AsOfSeq:        99,
			FilesystemRoot: labelRef("fs-root", 180),
			ControlRoot:    refPtr(labelRef("control-root", 90)),
			InoNamespace:   7,
			NextLocal:      12,
			XattrLeaves:    []Ref{labelRef("xattr-leaf-0", 300), labelRef("xattr-leaf-1", 301)},
		}},
		"xattr-leaf": {Kind: KindXattrLeaf, XattrLeaf: &XattrLeaf{
			Entries: []XattrEntry{
				{Ino: 2, Name: "com.apple.FinderInfo", Value: bytes.Repeat([]byte{0xAB}, 32)},
				{Ino: 2, Name: "user.empty"},
				{Ino: 21474836487, Name: "user.π", Value: []byte("v")},
			},
		}},
	}
}

func TestEncodeDecodeRoundTripAllKinds(t *testing.T) {
	seenKinds := map[Kind]bool{}
	for name, node := range sampleNodes() {
		encoded, err := EncodeNode(node)
		if err != nil {
			t.Fatalf("%s: encode: %v", name, err)
		}
		if !bytes.Equal(encoded[:4], Magic[:]) {
			t.Fatalf("%s: missing magic", name)
		}
		decoded, err := DecodeNode(encoded)
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		reencoded, err := EncodeNode(decoded)
		if err != nil {
			t.Fatalf("%s: re-encode: %v", name, err)
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Fatalf("%s: re-encode differs\n  first:  %x\n  second: %x", name, encoded, reencoded)
		}
		if _, err := DecodeNodeKind(encoded, node.Kind); err != nil {
			t.Fatalf("%s: kind-checked decode: %v", name, err)
		}
		wrongKind := node.Kind%maxKind + 1
		if _, err := DecodeNodeKind(encoded, wrongKind); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("%s: wrong-kind decode returned %v", name, err)
		}
		seenKinds[node.Kind] = true
	}
	for kind := minKind; kind <= maxKind; kind++ {
		if !seenKinds[kind] {
			t.Fatalf("no sample for kind %s", kind)
		}
	}
}

func TestRootXattrLeavesRoundTripAndOrderingFence(t *testing.T) {
	legacy := sampleNodes()["root"]
	legacyEncoded, err := EncodeNode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacyDecoded, err := DecodeNodeKind(legacyEncoded, KindRoot)
	if err != nil {
		t.Fatalf("decode legacy root without field 8: %v", err)
	}
	if len(legacyDecoded.Root.XattrLeaves) != 0 {
		t.Fatalf("legacy root unexpectedly decoded xattr leaves: %v", legacyDecoded.Root.XattrLeaves)
	}
	legacyReencoded, err := EncodeNode(legacyDecoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legacyEncoded, legacyReencoded) {
		t.Fatal("legacy root without field 8 did not re-encode byte-identically")
	}

	root := *legacy.Root
	root.XattrLeaves = []Ref{
		labelRef("root-xattr-leaf-0", 300),
		labelRef("root-xattr-leaf-1", 301),
	}
	encoded, err := EncodeNode(&Node{Kind: KindRoot, Root: &root})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeNodeKind(encoded, KindRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Root.XattrLeaves, root.XattrLeaves) {
		t.Fatalf("xattr leaves = %v, want %v", decoded.Root.XattrLeaves, root.XattrLeaves)
	}

	// Repeated field 8 must remain contiguous and ordered after fields 1..7;
	// a duplicate earlier field after it is non-canonical and fails closed.
	body := appendRoot(nil, &root)
	body = append(body, 0x18, 0x01) // root field 3 after appended field 8
	if _, err := decodeRoot(body); err == nil {
		t.Fatal("decoder accepted a field after repeated root xattr leaves")
	}
}

// TestInodeBirthtimeFlagsCompatContract pins the format revision's compat
// contract for the APPENDED inode fields 14 (birthtime_ms) and 15 (flags):
//
//   - an inode written WITHOUT them (every pre-revision tree) decodes with both
//     at zero and re-encodes byte-identically, so old trees are readable and
//     their digests never move;
//   - an inode carrying them round-trips exactly;
//   - a new writer that stamps neither emits bytes an OLD reader still accepts
//     (nothing appended at all), while an inode that DOES carry them appends
//     only fields an old reader rejects as unknown — fail-closed, never a
//     silent read that loses the metadata. That is the schema's standing
//     forward-only promise, the same one xattr_leaves took.
func TestInodeBirthtimeFlagsCompatContract(t *testing.T) {
	legacy := &Inode{
		Ino: 4242, Kind: FileKindRegular, Mode: 0o644, Nlink: 1, Size: 9,
		MtimeMs: 1700000000000, CtimeMs: 1700000000000, AtimeMs: 1700000000000,
	}
	legacyEncoded, err := EncodeNode(&Node{Kind: KindInode, Inode: legacy})
	if err != nil {
		t.Fatal(err)
	}
	legacyDecoded, err := DecodeNodeKind(legacyEncoded, KindInode)
	if err != nil {
		t.Fatalf("decode inode without fields 14/15: %v", err)
	}
	if legacyDecoded.Inode.BirthtimeMs != 0 || legacyDecoded.Inode.Flags != 0 {
		t.Fatalf("old-format inode decoded birthtime=%d flags=%#x, want zeros",
			legacyDecoded.Inode.BirthtimeMs, legacyDecoded.Inode.Flags)
	}
	legacyReencoded, err := EncodeNode(legacyDecoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legacyEncoded, legacyReencoded) {
		t.Fatal("old-format inode did not re-encode byte-identically")
	}

	// A new writer that stamps neither field emits exactly the old bytes: the
	// revision costs nothing on a tree that never uses it.
	unstamped := *legacy
	unstampedEncoded, err := EncodeNode(&Node{Kind: KindInode, Inode: &unstamped})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(legacyEncoded, unstampedEncoded) {
		t.Fatal("an unstamped inode must encode to the pre-revision bytes")
	}

	for _, tc := range []struct {
		name        string
		birthtimeMs int64
		flags       uint32
	}{
		{"both", 1700000000001, 0x00008000},
		{"birthtime only", 1699999999999, 0},
		{"flags only", 0, 0xFFFFFFFF},
		{"pre-epoch birthtime", -1700000000001, 0x00000002},
		{"bound birthtime", MaxAbsTimeMs, 1},
		{"negative bound birthtime", -MaxAbsTimeMs, 1},
	} {
		stamped := *legacy
		stamped.BirthtimeMs = tc.birthtimeMs
		stamped.Flags = tc.flags
		encoded, err := EncodeNode(&Node{Kind: KindInode, Inode: &stamped})
		if err != nil {
			t.Fatalf("%s: encode: %v", tc.name, err)
		}
		decoded, err := DecodeNodeKind(encoded, KindInode)
		if err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		if decoded.Inode.BirthtimeMs != tc.birthtimeMs || decoded.Inode.Flags != tc.flags {
			t.Fatalf("%s: round-trip gave birthtime=%d flags=%#x, want %d/%#x",
				tc.name, decoded.Inode.BirthtimeMs, decoded.Inode.Flags, tc.birthtimeMs, tc.flags)
		}
		reencoded, err := EncodeNode(decoded)
		if err != nil {
			t.Fatalf("%s: re-encode: %v", tc.name, err)
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Fatalf("%s: re-encode differs", tc.name)
		}
		// The stamped inode body is the old body plus APPENDED trailing
		// fields: an old reader consumes fields 1..13 unchanged and then hits
		// an unknown field number, so it fails closed on the new metadata
		// instead of silently dropping it.
		if !bytes.HasPrefix(appendInode(nil, &stamped), appendInode(nil, legacy)) {
			t.Fatalf("%s: fields 14/15 are not a pure append onto the old body", tc.name)
		}
		if _, err := decodeInode(appendInode(nil, &stamped)); err != nil {
			t.Fatalf("%s: new reader must accept the stamped body: %v", tc.name, err)
		}
	}

	// Out-of-range birth times fail validation on BOTH directions, exactly
	// like the other timestamps.
	bad := *legacy
	bad.BirthtimeMs = MaxAbsTimeMs + 1
	if _, err := EncodeNode(&Node{Kind: KindInode, Inode: &bad}); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("encoding an out-of-range birth time returned %v", err)
	}
}

// mutateByte returns a copy with one byte changed.
func mutateByte(data []byte, index int, value byte) []byte {
	out := append([]byte(nil), data...)
	out[index] = value
	return out
}

func TestDecodeRejectsNonCanonicalBytes(t *testing.T) {
	leaf := sampleNodes()["directory-leaf"]
	encoded, err := EncodeNode(leaf)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong magic", func(t *testing.T) {
		if _, err := DecodeNode(mutateByte(encoded, 0, 'Q')); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("trailing byte", func(t *testing.T) {
		if _, err := DecodeNode(append(append([]byte(nil), encoded...), 0x00)); err == nil {
			t.Fatal("accepted trailing byte")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		for cut := MinNodeBytes; cut < len(encoded); cut++ {
			if _, err := DecodeNode(encoded[:cut]); err == nil {
				t.Fatalf("accepted truncation at %d", cut)
			}
		}
	})
	t.Run("below min size", func(t *testing.T) {
		if _, err := DecodeNode(encoded[:MinNodeBytes-1]); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("above max size", func(t *testing.T) {
		big := make([]byte, MaxNodeBytes+1)
		copy(big, encoded)
		if _, err := DecodeNode(big); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})

	body := func(fields []byte) []byte {
		return append(append([]byte(nil), Magic[:]...), fields...)
	}
	armBytes := func(node *Node) []byte {
		full, err := EncodeNode(node)
		if err != nil {
			t.Fatal(err)
		}
		return full[4:]
	}
	_ = armBytes

	t.Run("missing kind", func(t *testing.T) {
		fields := pfwire.AppendBytes(nil, 4, []byte{0x08, 0x01})
		if _, err := DecodeNode(body(append(fields, make([]byte, 16)...))); err == nil {
			t.Fatal("accepted arm before kind")
		}
	})
	t.Run("kind without arm", func(t *testing.T) {
		fields := pfwire.AppendUint(nil, 1, uint64(KindDirectoryLeaf))
		padded := body(fields)
		for len(padded) < MinNodeBytes {
			padded = append(padded, 0)
		}
		if _, err := DecodeNode(padded); err == nil {
			t.Fatal("accepted node without arm")
		}
	})
	t.Run("arm not matching kind", func(t *testing.T) {
		// Kind ROOT (1) with the directory-leaf arm at field 4.
		inner := encoded[4:]
		rd := pfwire.NewReader("probe", inner)
		if _, _, _, err := rd.Next(); err != nil {
			t.Fatal(err)
		}
		fields := pfwire.AppendUint(nil, 1, uint64(KindRoot))
		fields = append(fields, inner[2:]...) // reuse the leaf's arm bytes (field 4)
		if _, err := DecodeNode(body(fields)); err == nil {
			t.Fatal("accepted mismatched arm")
		}
	})
	t.Run("unknown kind", func(t *testing.T) {
		fields := pfwire.AppendUint(nil, 1, 14)
		fields = pfwire.AppendBytes(fields, 15, []byte{0x08, 0x01})
		padded := body(fields)
		for len(padded) < MinNodeBytes {
			padded = append(padded, 0)
		}
		if _, err := DecodeNode(padded); err == nil {
			t.Fatal("accepted unknown kind")
		}
	})
	t.Run("explicit default rejected", func(t *testing.T) {
		// Inode with explicit mode=0 (field 3 varint 0).
		inner := pfwire.AppendUint(nil, 1, 99)
		inner = pfwire.AppendUint(inner, 2, uint64(FileKindRegular))
		inner = pfwire.AppendTag(inner, 3, pfwire.TypeVarint)
		inner = append(inner, 0x00)
		inner = pfwire.AppendUint(inner, 6, 1)
		fields := pfwire.AppendUint(nil, 1, uint64(KindInode))
		fields = pfwire.AppendBytes(fields, 3, inner)
		if _, err := DecodeNode(body(fields)); err == nil {
			t.Fatal("accepted explicit default")
		}
	})
	t.Run("non-minimal varint rejected", func(t *testing.T) {
		// ino = 1 encoded as two bytes (0x81 0x00).
		inner := pfwire.AppendTag(nil, 1, pfwire.TypeVarint)
		inner = append(inner, 0x81, 0x00)
		inner = pfwire.AppendUint(inner, 2, uint64(FileKindRegular))
		inner = pfwire.AppendUint(inner, 6, 1)
		fields := pfwire.AppendUint(nil, 1, uint64(KindInode))
		fields = pfwire.AppendBytes(fields, 3, inner)
		if _, err := DecodeNode(body(fields)); err == nil {
			t.Fatal("accepted non-minimal varint")
		}
	})
	t.Run("varint overflow rejected", func(t *testing.T) {
		inner := pfwire.AppendTag(nil, 1, pfwire.TypeVarint)
		inner = append(inner, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02)
		inner = pfwire.AppendUint(inner, 2, uint64(FileKindRegular))
		inner = pfwire.AppendUint(inner, 6, 1)
		fields := pfwire.AppendUint(nil, 1, uint64(KindInode))
		fields = pfwire.AppendBytes(fields, 3, inner)
		if _, err := DecodeNode(body(fields)); err == nil {
			t.Fatal("accepted 64-bit varint overflow")
		}
	})
	t.Run("duplicate field rejected", func(t *testing.T) {
		inner := pfwire.AppendUint(nil, 1, 99)
		inner = pfwire.AppendUint(inner, 1, 99)
		inner = pfwire.AppendUint(inner, 2, uint64(FileKindRegular))
		inner = pfwire.AppendUint(inner, 6, 1)
		fields := pfwire.AppendUint(nil, 1, uint64(KindInode))
		fields = pfwire.AppendBytes(fields, 3, inner)
		if _, err := DecodeNode(body(fields)); err == nil {
			t.Fatal("accepted duplicate field")
		}
	})
	t.Run("out of order field rejected", func(t *testing.T) {
		inner := pfwire.AppendUint(nil, 2, uint64(FileKindRegular))
		inner = pfwire.AppendUint(inner, 1, 99)
		inner = pfwire.AppendUint(inner, 6, 1)
		fields := pfwire.AppendUint(nil, 1, uint64(KindInode))
		fields = pfwire.AppendBytes(fields, 3, inner)
		if _, err := DecodeNode(body(fields)); err == nil {
			t.Fatal("accepted out-of-order field")
		}
	})
	t.Run("unknown field rejected", func(t *testing.T) {
		inner := pfwire.AppendUint(nil, 1, 99)
		inner = pfwire.AppendUint(inner, 2, uint64(FileKindRegular))
		inner = pfwire.AppendUint(inner, 6, 1)
		inner = pfwire.AppendUint(inner, 99, 1)
		fields := pfwire.AppendUint(nil, 1, uint64(KindInode))
		fields = pfwire.AppendBytes(fields, 3, inner)
		if _, err := DecodeNode(body(fields)); err == nil {
			t.Fatal("accepted unknown field")
		}
	})
	t.Run("unsorted directory leaf rejected", func(t *testing.T) {
		bad := &Node{Kind: KindDirectoryLeaf, DirectoryLeaf: &DirectoryLeaf{
			Entries: []DirEntry{
				{Name: "b", Ino: 1, Kind: FileKindRegular},
				{Name: "a", Ino: 2, Kind: FileKindRegular},
			},
		}}
		if _, err := EncodeNode(bad); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("encode accepted unsorted leaf: %v", err)
		}
		// Hand-build the same bytes and confirm the decoder also rejects.
		entryA := appendDirEntry(nil, &DirEntry{Name: "a", Ino: 2, Kind: FileKindRegular})
		entryB := appendDirEntry(nil, &DirEntry{Name: "b", Ino: 1, Kind: FileKindRegular})
		arm := pfwire.AppendBytes(nil, 1, entryB)
		arm = pfwire.AppendBytes(arm, 1, entryA)
		fields := pfwire.AppendUint(nil, 1, uint64(KindDirectoryLeaf))
		fields = pfwire.AppendBytes(fields, 4, arm)
		if _, err := DecodeNode(body(fields)); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("decode accepted unsorted leaf: %v", err)
		}
	})
	t.Run("invalid utf8 name rejected", func(t *testing.T) {
		entry := pfwire.AppendBytes(nil, 1, []byte{0xff, 0xfe})
		entry = pfwire.AppendUint(entry, 2, 5)
		entry = pfwire.AppendUint(entry, 3, 1)
		arm := pfwire.AppendBytes(nil, 1, entry)
		fields := pfwire.AppendUint(nil, 1, uint64(KindDirectoryLeaf))
		fields = pfwire.AppendBytes(fields, 4, arm)
		if _, err := DecodeNode(body(fields)); err == nil {
			t.Fatal("accepted invalid UTF-8 name")
		}
	})
	t.Run("zero cell digest rejected", func(t *testing.T) {
		p := &DataPage{}
		p.Cells[0] = &CellRef{CellDigest: ZeroCellDigest, Object: labelRef("pack", 4096)}
		if _, err := EncodeNode(&Node{Kind: KindDataPage, DataPage: p}); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cell slice beyond object rejected", func(t *testing.T) {
		p := &DataPage{}
		p.Cells[0] = &CellRef{CellDigest: labelDigest("c"), Object: labelRef("pack", 4096), ObjectOffset: 4096}
		if _, err := EncodeNode(&Node{Kind: KindDataPage, DataPage: p}); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("misaligned page offset rejected", func(t *testing.T) {
		bad := &Node{Kind: KindExtentLeaf, ExtentLeaf: &ExtentLeaf{
			Entries: []ExtentEntry{{PageOffset: 4096, Page: labelRef("p", 900)}},
		}}
		if _, err := EncodeNode(bad); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("index below fanout rejected", func(t *testing.T) {
		bad := &Node{Kind: KindDirectoryIndex, DirectoryIndex: &DirectoryIndex{
			Children: []DirectoryIndexChild{
				{FirstName: "a", LastName: "b", Child: labelRef("c", 100), EntryCount: 2},
			},
		}}
		if _, err := EncodeNode(bad); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("extent index possible-count bound", func(t *testing.T) {
		// A PageBytes-aligned range of two pages holds at most two entries:
		// exactly-possible passes, one more is rejected on encode AND on a
		// hand-built decode.
		possible := &Node{Kind: KindExtentIndex, ExtentIndex: &ExtentIndex{
			Children: []ExtentIndexChild{
				{FirstPage: 0, LastPage: PageBytes, Child: labelRef("a", 100), EntryCount: 2},
				{FirstPage: 4 * PageBytes, LastPage: 4 * PageBytes, Child: labelRef("b", 100), EntryCount: 1},
			},
		}}
		encoded, err := EncodeNode(possible)
		if err != nil {
			t.Fatalf("exactly-possible count rejected: %v", err)
		}
		if _, err := DecodeNode(encoded); err != nil {
			t.Fatalf("exactly-possible count failed decode: %v", err)
		}
		impossible := &Node{Kind: KindExtentIndex, ExtentIndex: &ExtentIndex{
			Children: []ExtentIndexChild{
				{FirstPage: 0, LastPage: PageBytes, Child: labelRef("a", 100), EntryCount: 3},
				{FirstPage: 4 * PageBytes, LastPage: 4 * PageBytes, Child: labelRef("b", 100), EntryCount: 1},
			},
		}}
		if _, err := EncodeNode(impossible); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("impossible count encoded: %v", err)
		}
		arm := appendExtentIndex(nil, impossible.ExtentIndex)
		fields := pfwire.AppendUint(nil, 1, uint64(KindExtentIndex))
		fields = pfwire.AppendBytes(fields, uint32(KindExtentIndex)+1, arm)
		if _, err := DecodeNode(body(fields)); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("impossible count decoded: %v", err)
		}
		// Full-range child at the offset ceiling: overflow-safe arithmetic
		// with the exactly-possible count for the widest legal range.
		widest := (MaxLogicalFileBytes-PageBytes-PageBytes)/PageBytes + 1
		extreme := &Node{Kind: KindExtentIndex, ExtentIndex: &ExtentIndex{
			Children: []ExtentIndexChild{
				{FirstPage: 0, LastPage: 0, Child: labelRef("a", 100), EntryCount: 1},
				{
					FirstPage:  PageBytes,
					LastPage:   MaxLogicalFileBytes - PageBytes,
					Child:      labelRef("b", 100),
					EntryCount: widest,
				},
			},
		}}
		if _, err := EncodeNode(extreme); err != nil {
			t.Fatalf("extreme-range count rejected: %v", err)
		}
		extreme.ExtentIndex.Children[1].EntryCount = widest + 1
		if _, err := EncodeNode(extreme); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("beyond-extreme count encoded: %v", err)
		}
	})

	t.Run("index count overflow rejected", func(t *testing.T) {
		bad := &Node{Kind: KindDirectoryIndex, DirectoryIndex: &DirectoryIndex{
			Children: []DirectoryIndexChild{
				{FirstName: "a", LastName: "b", Child: labelRef("c", 100), EntryCount: 1 << 63},
				{FirstName: "c", LastName: "d", Child: labelRef("d", 100), EntryCount: 1 << 63},
			},
		}}
		if _, err := EncodeNode(bad); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("symlink size mismatch rejected", func(t *testing.T) {
		bad := &Node{Kind: KindInode, Inode: &Inode{
			Ino: 5, Kind: FileKindSymlink, Nlink: 1, Size: 3, SymlinkTarget: "abcd",
		}}
		if _, err := EncodeNode(bad); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("reserved names rejected", func(t *testing.T) {
		for _, name := range []string{".", "..", "a/b", "a\x00b", "", strings.Repeat("x", 256)} {
			if err := ValidateEntryName(name); err == nil {
				t.Fatalf("accepted name %q", name)
			}
		}
	})
	t.Run("directory with size rejected", func(t *testing.T) {
		bad := &Node{Kind: KindInode, Inode: &Inode{Ino: 2, Kind: FileKindDirectory, Nlink: 1, Size: 7}}
		if _, err := EncodeNode(bad); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("root feature bits rejected", func(t *testing.T) {
		bad := &Node{Kind: KindRoot, Root: &Root{
			RootInode:  labelRef("a", 100),
			InodeIndex: labelRef("b", 100),
			MaxInoSeen: 1, InodeCount: 1, Features: 1,
		}}
		if _, err := EncodeNode(bad); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("control counts without map rejected", func(t *testing.T) {
		bad := &Node{Kind: KindControlRoot, ControlRoot: &ControlRoot{
			Schema: 1, NextCheckoutEpoch: 1, Counts: []ControlKindCount{{Kind: 1, Count: 1}},
		}}
		if _, err := EncodeNode(bad); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("control db-time floor beyond the timestamp bound rejected", func(t *testing.T) {
		bad := &Node{Kind: KindControlRoot, ControlRoot: &ControlRoot{
			Schema: 1, NextCheckoutEpoch: 1, DbTimeFloorMs: uint64(MaxAbsTimeMs) + 1,
		}}
		if _, err := EncodeNode(bad); !errors.Is(err, ErrInvalidNode) {
			t.Fatalf("got %v", err)
		}
	})
}

// TestByteFlipNeverChangesCanonicalBytes is the corruption sweep: every
// single-byte mutation of a canonical object either fails to decode or
// re-encodes to exactly the mutated bytes (a different but self-canonical
// value). No mutation may decode into a value whose canonical form differs
// from the input bytes.
func TestByteFlipNeverChangesCanonicalBytes(t *testing.T) {
	for name, node := range sampleNodes() {
		encoded, err := EncodeNode(node)
		if err != nil {
			t.Fatal(err)
		}
		for i := range encoded {
			for _, delta := range []byte{0x01, 0x80, 0xff} {
				mutated := mutateByte(encoded, i, encoded[i]^delta)
				decoded, err := DecodeNode(mutated)
				if err != nil {
					continue
				}
				reencoded, err := EncodeNode(decoded)
				if err != nil {
					t.Fatalf("%s: byte %d: decode accepted but re-encode failed: %v", name, i, err)
				}
				if !bytes.Equal(reencoded, mutated) {
					t.Fatalf("%s: byte %d delta %#x: accepted bytes are not canonical", name, i, delta)
				}
			}
		}
	}
}

func TestVerifyObjectBytes(t *testing.T) {
	encoded, err := EncodeNode(sampleNodes()["root"])
	if err != nil {
		t.Fatal(err)
	}
	ref := RefOf(encoded)
	if err := VerifyObjectBytes(ref, encoded); err != nil {
		t.Fatal(err)
	}
	if err := VerifyObjectBytes(ref, encoded[:len(encoded)-1]); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("size mismatch: %v", err)
	}
	if err := VerifyObjectBytes(ref, mutateByte(encoded, 5, encoded[5]^1)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("digest mismatch: %v", err)
	}
	wrongSize := Ref{Digest: ref.Digest, Size: ref.Size + 1}
	if err := VerifyObjectBytes(wrongSize, encoded); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("advertised size mismatch: %v", err)
	}
}
