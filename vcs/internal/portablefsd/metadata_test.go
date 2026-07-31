package portablefsd

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func newMetadataTestAttach() *attach {
	return &attach{
		items:       map[uint64]*itemRecord{},
		paths:       map[string]*itemRecord{},
		itemAliases: map[uint64]map[string]struct{}{},
		handles:     map[uint64]*handleRecord{},
	}
}

func (a *attach) bindTestRecord(rec *itemRecord) *itemRecord {
	if a.items[rec.item.ItemID] == nil {
		a.items[rec.item.ItemID] = rec
	}
	a.paths[rec.path] = rec
	a.addItemAliasLocked(rec)
	return rec
}

func newTestDirRecord(p string, id uint64) *itemRecord {
	return &itemRecord{
		item:  pfslocal.Item{ItemID: id, ItemGeneration: 1},
		path:  p,
		state: clientcore.NewNodeState(id, true),
		attr:  fsproto.Attr{Kind: "directory", Nlink: 2},
	}
}

// TestObjectTargetParentIsAliasStableWithAndWithoutHandle pins that a
// hard-linked file reports one parent regardless of whether the caller holds a
// descriptor. The identity-only lane used to fall back to rec.path — the first
// alias that happened to register — while the handle lane resolved the
// canonical (lexicographically smallest) alias, so opening a file could flip
// its parent ID.
func TestObjectTargetParentIsAliasStableWithAndWithoutHandle(t *testing.T) {
	a := newMetadataTestAttach()
	a.bindTestRecord(newTestDirRecord("", 1))
	a.bindTestRecord(newTestDirRecord("zdir", 2))
	adir := a.bindTestRecord(newTestDirRecord("adir", 3))

	// Registration order is deliberately the reverse of lexicographic order.
	item := pfslocal.Item{ItemID: 7, ItemGeneration: 1}
	state := clientcore.NewNodeState(7, true)
	attr := fsproto.Attr{Kind: "file", Nlink: 2, Size: 4, AllocSize: 4, MtimeMs: 5}
	a.bindTestRecord(&itemRecord{item: item, path: "zdir/z", state: state, attr: attr})
	a.bindTestRecord(&itemRecord{item: item, path: "adir/a", state: state, attr: attr})

	parentOf := func(handleID uint64) pfslocal.Item {
		t.Helper()
		target, eno := a.objectTarget(item, handleID)
		if eno != 0 {
			t.Fatalf("objectTarget(handle=%d) errno=%d", handleID, eno)
		}
		local := a.localAttrForRecordPath(
			target.rec.attr, target.rec, target.scope, target.detached,
		)
		if local.Parent == nil {
			t.Fatalf("objectTarget(handle=%d) reported no parent", handleID)
		}
		return *local.Parent
	}

	withoutHandle := parentOf(0)
	a.handles[4] = &handleRecord{
		id: 4, itemID: item.ItemID, path: "zdir/z", openPath: "zdir/z", state: state,
	}
	withHandle := parentOf(4)

	if withoutHandle != withHandle {
		t.Fatalf("parent flipped with an open handle: without=%+v with=%+v",
			withoutHandle, withHandle)
	}
	if withoutHandle != adir.item {
		t.Fatalf("parent = %+v, want the canonical alias parent %+v",
			withoutHandle, adir.item)
	}
}

// TestAuthorityAttrDefaultsFillMissingAllocSizeAndBirthtime covers the fields
// the authority's metadata model does not carry: a gob-omitted AllocSize would
// otherwise report st_blocks=0 for every cloud-backed file, and an absent
// birth time would show as 1 Jan 1970.
func TestAuthorityAttrDefaultsFillMissingAllocSizeAndBirthtime(t *testing.T) {
	const mtime = int64(1_700_000_000_000)
	// Exactly what today's production authority sends: no AllocSize field, no
	// BirthtimeMs field.
	authority := fsproto.Attr{
		Kind: "file", Size: 1 << 20, Mode: 0o644, Nlink: 1,
		MtimeMs: mtime, CtimeMs: mtime, AtimeMs: mtime,
	}

	filled := authorityAttrDefaults(authority)
	if filled.AllocSize != authority.Size {
		t.Fatalf("AllocSize = %d, want the logical size %d", filled.AllocSize, authority.Size)
	}
	if filled.BirthtimeMs != mtime {
		t.Fatalf("BirthtimeMs = %d, want mtime %d", filled.BirthtimeMs, mtime)
	}

	// A present allocation and birth time are never overwritten.
	explicit := authority
	explicit.AllocSize = 4096
	explicit.BirthtimeMs = 42
	if got := authorityAttrDefaults(explicit); got.AllocSize != 4096 || got.BirthtimeMs != 42 {
		t.Fatalf("explicit authority values overwritten: %+v", got)
	}

	// An empty file has no allocation to derive.
	if got := authorityAttrDefaults(fsproto.Attr{Kind: "file", MtimeMs: mtime}); got.AllocSize != 0 {
		t.Fatalf("empty file AllocSize = %d, want 0", got.AllocSize)
	}
}

// TestLocalAttrNormalizesAuthorityRecordsOnly checks the normalization is
// applied on the authority lane and withheld from grafts, whose zeros come
// from a real stat(2) of a backing file.
func TestLocalAttrNormalizesAuthorityRecordsOnly(t *testing.T) {
	a := newMetadataTestAttach()
	a.bindTestRecord(newTestDirRecord("", 1))

	attr := fsproto.Attr{Kind: "file", Size: 1 << 20, Nlink: 1, MtimeMs: 99}
	authorityRec := a.bindTestRecord(&itemRecord{
		item:  pfslocal.Item{ItemID: 5, ItemGeneration: 1},
		path:  "cloud.bin",
		state: clientcore.NewNodeState(5, true),
		attr:  attr,
	})
	graftRec := a.bindTestRecord(&itemRecord{
		item:  pfslocal.Item{ItemID: 6, ItemGeneration: 1},
		path:  "sparse.bin",
		graft: true,
		attr:  attr,
	})

	authorityLocal := a.localAttrForRecordPath(attr, authorityRec, "", false)
	if authorityLocal.AllocSize != uint64(attr.Size) || authorityLocal.BirthtimeMs != 99 {
		t.Fatalf("authority attr = %+v", authorityLocal)
	}
	graftLocal := a.localAttrForRecordPath(attr, graftRec, "", false)
	if graftLocal.AllocSize != 0 || graftLocal.BirthtimeMs != 0 {
		t.Fatalf("graft stat measurements were rewritten: %+v", graftLocal)
	}
}

// TestReclaimRefusesDirectoryWithBoundChildren pins that a directory Item
// cannot be retired while it is still the parent identity of live bindings;
// otherwise those children answer FSKit with an invalid parent.
func TestReclaimRefusesDirectoryWithBoundChildren(t *testing.T) {
	a := newMetadataTestAttach()
	a.bindTestRecord(newTestDirRecord("", 1))
	dir := a.bindTestRecord(newTestDirRecord("dir", 2))
	empty := a.bindTestRecord(newTestDirRecord("empty", 3))
	child := a.bindTestRecord(&itemRecord{
		item:  pfslocal.Item{ItemID: 4, ItemGeneration: 1},
		path:  "dir/child.txt",
		state: clientcore.NewNodeState(4, true),
		attr:  fsproto.Attr{Kind: "file", Nlink: 1},
	})
	// A sibling whose name merely shares a prefix is not a child.
	a.bindTestRecord(&itemRecord{
		item:  pfslocal.Item{ItemID: 5, ItemGeneration: 1},
		path:  "dirt",
		state: clientcore.NewNodeState(5, true),
		attr:  fsproto.Attr{Kind: "file", Nlink: 1},
	})

	if eno := a.reclaim(&pfslocal.ReclaimRequest{Item: dir.item}); eno != darwinEBUSY {
		t.Fatalf("reclaim of a populated directory errno=%d, want EBUSY", eno)
	}
	if a.items[dir.item.ItemID] == nil {
		t.Fatal("refused reclaim retired the directory Item anyway")
	}
	if eno := a.reclaim(&pfslocal.ReclaimRequest{Item: empty.item}); eno != 0 {
		t.Fatalf("reclaim of an empty directory errno=%d, want 0", eno)
	}

	// The host retries after retiring the subtree.
	if eno := a.reclaim(&pfslocal.ReclaimRequest{Item: child.item}); eno != 0 {
		t.Fatalf("reclaim of the child errno=%d, want 0", eno)
	}
	if eno := a.reclaim(&pfslocal.ReclaimRequest{Item: dir.item}); eno != 0 {
		t.Fatalf("reclaim after the subtree drained errno=%d, want 0", eno)
	}
	if a.items[dir.item.ItemID] != nil {
		t.Fatal("drained directory Item was not retired")
	}
}
