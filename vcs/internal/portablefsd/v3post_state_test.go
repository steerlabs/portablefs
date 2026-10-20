package portablefsd

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"google.golang.org/protobuf/proto"
)

func testV3ID(identity byte) []byte { return bytes.Repeat([]byte{identity}, 16) }

func testV3DirAttr(inode uint64, nlink uint32) *authoritypb.Attr {
	return &authoritypb.Attr{Kind: authoritypb.Attr_DIRECTORY, Inode: inode, Mode: 0o755, Nlink: nlink}
}

func testV3FileAttr(inode uint64, size int64, nlink uint32) *authoritypb.Attr {
	return &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: inode, Mode: 0o644, Nlink: nlink, Size: size}
}

// testV3PostObject is one object of a test mutation post-state.
type testV3PostObject struct {
	identity byte
	attr     *authoritypb.Attr
	version  uint64
	roles    uint32
}

// testV3MutationState builds a canonical mutation post-state at snapshot.
func testV3MutationState(snapshot uint64, objects ...testV3PostObject) *authoritypb.PostState {
	state := &authoritypb.PostState{VisibilitySequence: snapshot, SnapshotSequence: snapshot}
	sort.Slice(objects, func(i, j int) bool { return objects[i].identity < objects[j].identity })
	for _, object := range objects {
		state.Objects = append(state.Objects, &authoritypb.ObjectPostState{
			StableIdentity: testV3ID(object.identity), ObjectVersion: object.version,
			Attr: proto.Clone(object.attr).(*authoritypb.Attr), Roles: object.roles,
		})
	}
	return state
}

// testV3TargetState is a single changed TARGET at snapshot.
func testV3TargetState(identity byte, attr *authoritypb.Attr, snapshot uint64) *authoritypb.PostState {
	return testV3MutationState(snapshot, testV3PostObject{identity: identity, attr: attr, version: snapshot, roles: v3PostStateRoleTarget})
}

// testV3StampedItem is an Item whose attributes and stamps agree with the
// post-state object the authority returns for it.
func testV3StampedItem(token []byte, identity byte, attr *authoritypb.Attr, version, snapshot uint64) *authoritypb.Item {
	return &authoritypb.Item{
		Token: token, StableIdentity: testV3ID(identity), Attr: proto.Clone(attr).(*authoritypb.Attr),
		ObjectVersion: version, SnapshotSequence: snapshot,
	}
}

// testV3RootBinding stamps item as created or bound under the fake's root
// at snapshot 2 and returns the matching PARENT + role post-state.
func testV3RootBinding(item *authoritypb.Item, role uint32) *authoritypb.PostState {
	item.ObjectVersion, item.SnapshotSequence = 2, 2
	return testV3MutationState(2,
		testV3PostObject{identity: 0x20, attr: testV3DirAttr(1, 3), version: 2, roles: v3PostStateRoleParent},
		testV3PostObject{identity: item.GetStableIdentity()[0], attr: item.GetAttr(), version: 2, roles: role},
	)
}

func testV3Record(identity byte, inode uint64, kind authoritypb.Attr_Kind) *v3ItemRecord {
	return &v3ItemRecord{item: v3TestItem(identity), inode: inode, kind: kind}
}

func v3TestItem(identity byte) (item pfslocal.Item) {
	item.ItemID = uint64(identity)
	item.ItemGeneration = 9
	copy(item.StableIdentity[:], testV3ID(identity))
	return item
}

// Whole-reply validation refuses every malformed envelope or role set before
// any cache entry changes.
func TestV3PostStateValidationRejectsMalformedReplies(t *testing.T) {
	parent := testV3Record(0x20, 1, authoritypb.Attr_DIRECTORY)
	file := testV3Record(0x40, 2, authoritypb.Attr_REGULAR)
	dirAttr, fileAttr := testV3DirAttr(1, 2), testV3FileAttr(2, 4, 1)
	good := func() *authoritypb.PostState {
		return testV3MutationState(5,
			testV3PostObject{identity: 0x20, attr: dirAttr, version: 5, roles: v3PostStateRoleParent},
			testV3PostObject{identity: 0x40, attr: fileAttr, version: 3, roles: v3PostStateRoleRemoved},
		)
	}
	if _, err := v3RemoveEffect(good(), parent, []byte("f"), false); err != nil {
		t.Fatalf("well-formed removal refused: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*authoritypb.PostState)
	}{
		{name: "missing", mutate: func(s *authoritypb.PostState) { *s = authoritypb.PostState{} }},
		{name: "visibility-differs", mutate: func(s *authoritypb.PostState) { s.VisibilitySequence = 4 }},
		{name: "future-version", mutate: func(s *authoritypb.PostState) { s.Objects[1].ObjectVersion = 6 }},
		{name: "zero-version", mutate: func(s *authoritypb.PostState) { s.Objects[1].ObjectVersion = 0 }},
		{name: "noncanonical-order", mutate: func(s *authoritypb.PostState) { s.Objects[0], s.Objects[1] = s.Objects[1], s.Objects[0] }},
		{name: "duplicate-identity", mutate: func(s *authoritypb.PostState) { s.Objects[1].StableIdentity = testV3ID(0x20) }},
		{name: "unknown-role", mutate: func(s *authoritypb.PostState) { s.Objects[1].Roles = 0x8000 }},
		{name: "wrong-roles", mutate: func(s *authoritypb.PostState) { s.Objects[1].Roles = v3PostStateRoleTarget }},
		{name: "extra-object", mutate: func(s *authoritypb.PostState) {
			s.Objects = append(s.Objects, &authoritypb.ObjectPostState{StableIdentity: testV3ID(0x50), ObjectVersion: 1, Attr: fileAttr, Roles: v3PostStateRoleOverwritten})
		}},
		{name: "wrong-parent", mutate: func(s *authoritypb.PostState) { s.Objects[0].StableIdentity = testV3ID(0x10) }},
		{name: "parent-inode-changed", mutate: func(s *authoritypb.PostState) { s.Objects[0].Attr.Inode = 9 }},
		{name: "removed-kind-mismatch", mutate: func(s *authoritypb.PostState) { s.Objects[1].Attr.Kind = authoritypb.Attr_DIRECTORY }},
		{name: "missing-attr", mutate: func(s *authoritypb.PostState) { s.Objects[1].Attr = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := good()
			test.mutate(state)
			if _, err := v3RemoveEffect(state, parent, []byte("f"), false); err == nil {
				t.Fatal("malformed removal post-state was accepted")
			}
		})
	}
	if _, _, err := v3TargetEffect(testV3TargetState(0x41, fileAttr, 2), file); err == nil {
		t.Fatal("a target naming another identity was accepted")
	}
}

func TestV3BindingEffectRequiresItemAgreement(t *testing.T) {
	parent := testV3Record(0x20, 1, authoritypb.Attr_DIRECTORY)
	attr := testV3FileAttr(7, 0, 1)
	state := testV3MutationState(4,
		testV3PostObject{identity: 0x20, attr: testV3DirAttr(1, 2), version: 4, roles: v3PostStateRoleParent},
		testV3PostObject{identity: 0x70, attr: attr, version: 4, roles: v3PostStateRoleCreated},
	)
	item := testV3StampedItem(testV3ID(0xc0), 0x70, attr, 4, 4)
	effect, err := v3BindingEffect(state, parent, []byte("n"), item, authoritypb.Attr_REGULAR, v3PostStateRoleCreated)
	if err != nil || len(effect.names) != 1 || !effect.names[0].bound || effect.names[0].identity != [16]byte(testV3ID(0x70)) {
		t.Fatalf("create effect = (%+v,%v)", effect, err)
	}
	for name, mutate := range map[string]func(*authoritypb.Item){
		"stale-version":  func(i *authoritypb.Item) { i.ObjectVersion = 3 },
		"other-snapshot": func(i *authoritypb.Item) { i.SnapshotSequence = 5 },
		"attr-differs":   func(i *authoritypb.Item) { i.Attr.Size = 1 },
		"other-identity": func(i *authoritypb.Item) { i.StableIdentity = testV3ID(0x71) },
	} {
		bad := proto.Clone(item).(*authoritypb.Item)
		mutate(bad)
		if _, err := v3BindingEffect(state, parent, []byte("n"), bad, authoritypb.Attr_REGULAR, v3PostStateRoleCreated); err == nil {
			t.Fatalf("%s: a disagreeing reply item was accepted", name)
		}
	}
	if _, err := v3BindingEffect(state, parent, []byte("n"), item, authoritypb.Attr_DIRECTORY, v3PostStateRoleCreated); err == nil {
		t.Fatal("a created object of the wrong kind was accepted")
	}
}

func TestV3RenameEffectBindsExactOperandsAndPostBindings(t *testing.T) {
	from := testV3Record(0x20, 1, authoritypb.Attr_DIRECTORY)
	to := testV3Record(0x50, 5, authoritypb.Attr_DIRECTORY)
	moved := v3PublicationIdentity(testV3ID(0x70))
	cross := func(roles ...testV3PostObject) *authoritypb.PostState { return testV3MutationState(6, roles...) }
	movedObject := testV3PostObject{identity: 0x70, attr: testV3FileAttr(7, 0, 1), version: 6, roles: v3PostStateRoleMoved}
	oldParent := testV3PostObject{identity: 0x20, attr: testV3DirAttr(1, 2), version: 6, roles: v3PostStateRoleOldParent}
	newParent := testV3PostObject{identity: 0x50, attr: testV3DirAttr(5, 2), version: 6, roles: v3PostStateRoleNewParent}
	victim := testV3PostObject{identity: 0x71, attr: testV3FileAttr(8, 0, 0), version: 6, roles: v3PostStateRoleOverwritten}

	effect, err := v3RenameEffect(cross(movedObject, oldParent, newParent, victim), from, []byte("a"), to, []byte("b"), moved, v3PublicationIdentity{}, false)
	if err != nil || len(effect.names) != 2 || effect.names[0].bound || !effect.names[1].bound {
		t.Fatalf("rename-over effect = (%+v,%v)", effect, err)
	}
	// The same-inode no-op keeps the old name bound to the moved object.
	noop, err := v3RenameEffect(cross(movedObject, oldParent, newParent), from, []byte("a"), to, []byte("b"), moved, moved, true)
	if err != nil || !noop.names[0].bound || noop.names[0].identity != [16]byte(moved) {
		t.Fatalf("no-op rename effect = (%+v,%v)", noop, err)
	}
	for _, test := range []struct {
		name     string
		state    *authoritypb.PostState
		old      v3PublicationIdentity
		oldBound bool
	}{
		{name: "exchange-roles", state: cross(
			testV3PostObject{identity: 0x70, attr: movedObject.attr, version: 6, roles: v3PostStateRoleMoved | v3PostStateRoleExchanged},
			testV3PostObject{identity: 0x71, attr: victim.attr, version: 6, roles: v3PostStateRoleMoved | v3PostStateRoleExchanged},
			oldParent, newParent)},
		{name: "merged-parent-for-two-directories", state: cross(movedObject,
			testV3PostObject{identity: 0x20, attr: oldParent.attr, version: 6, roles: v3PostStateRoleOldParent | v3PostStateRoleNewParent})},
		{name: "moved-is-not-the-post-identity", state: cross(
			testV3PostObject{identity: 0x72, attr: movedObject.attr, version: 6, roles: v3PostStateRoleMoved}, oldParent, newParent)},
		{name: "parents-swapped", state: cross(movedObject,
			testV3PostObject{identity: 0x20, attr: oldParent.attr, version: 6, roles: v3PostStateRoleNewParent},
			testV3PostObject{identity: 0x50, attr: newParent.attr, version: 6, roles: v3PostStateRoleOldParent})},
		{name: "old-name-bound-to-another-object", state: cross(movedObject, oldParent, newParent),
			old: v3PublicationIdentity(testV3ID(0x71)), oldBound: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := v3RenameEffect(test.state, from, []byte("a"), to, []byte("b"), moved, test.old, test.oldBound); err == nil {
				t.Fatal("malformed rename result was accepted")
			}
		})
	}
}

func TestV3ReadStampRequiresAnActualVersionWithinItsSnapshot(t *testing.T) {
	for _, test := range []struct {
		version, snapshot uint64
		valid             bool
	}{
		{1, 1, true}, {3, 9, true}, {0, 1, false}, {1, 0, false}, {5, 4, false},
	} {
		err := v3ReadStamp(test.version, test.snapshot)
		if (err == nil) != test.valid || err != nil && !strings.Contains(err.Error(), "0 < v <= s") {
			t.Fatalf("stamp v=%d s=%d: %v", test.version, test.snapshot, err)
		}
	}
}
