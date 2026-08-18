//go:build linux

package authorityrpc

import (
	"reflect"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

func postStateTestIdentity(value byte) [16]byte {
	var identity [16]byte
	identity[15] = value
	return identity
}

func TestMutationPostStateExactObjectRoleSets(t *testing.T) {
	target, parent := postStateTestIdentity(1), postStateTestIdentity(2)
	oldParent, newParent := postStateTestIdentity(3), postStateTestIdentity(4)
	overwritten := postStateTestIdentity(5)
	attr := func(identity [16]byte) xfsstore.Attr {
		return xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: uint64(identity[15])}
	}
	snapshot := func(identity [16]byte, roles uint32) postStateSnapshot {
		return postStateSnapshot{identity: identity, attr: attr(identity), roles: roles, changed: true}
	}
	tests := []struct {
		name     string
		request  *authoritypb.Request
		input    []postStateSnapshot
		expected map[[16]byte]uint32
	}{
		{"write", &authoritypb.Request{Body: &authoritypb.Request_OneShotWrite{}}, []postStateSnapshot{snapshot(target, postStateRoleTarget)}, map[[16]byte]uint32{target: postStateRoleTarget}},
		{"setattr", &authoritypb.Request{Body: &authoritypb.Request_SetAttr{}}, []postStateSnapshot{snapshot(target, postStateRoleTarget)}, map[[16]byte]uint32{target: postStateRoleTarget}},
		{"fallocate", &authoritypb.Request{Body: &authoritypb.Request_Fallocate{}}, []postStateSnapshot{snapshot(target, postStateRoleTarget)}, map[[16]byte]uint32{target: postStateRoleTarget}},
		{"copy distinct", &authoritypb.Request{Body: &authoritypb.Request_CopyFileRange{}}, []postStateSnapshot{snapshot(target, postStateRoleSource), snapshot(parent, postStateRoleDestination)}, map[[16]byte]uint32{target: postStateRoleSource, parent: postStateRoleDestination}},
		{"copy identical", &authoritypb.Request{Body: &authoritypb.Request_CopyFileRange{}}, []postStateSnapshot{snapshot(target, postStateRoleSource), snapshot(target, postStateRoleDestination)}, map[[16]byte]uint32{target: postStateRoleSource | postStateRoleDestination}},
		{"create new", &authoritypb.Request{Body: &authoritypb.Request_Create{}}, []postStateSnapshot{snapshot(target, postStateRoleCreated), snapshot(parent, postStateRoleParent)}, map[[16]byte]uint32{target: postStateRoleCreated, parent: postStateRoleParent}},
		{"create existing", &authoritypb.Request{Body: &authoritypb.Request_Create{}}, []postStateSnapshot{snapshot(target, postStateRoleTarget), snapshot(parent, postStateRoleParent)}, map[[16]byte]uint32{target: postStateRoleTarget, parent: postStateRoleParent}},
		{"mkdir", &authoritypb.Request{Body: &authoritypb.Request_Mkdir{}}, []postStateSnapshot{snapshot(target, postStateRoleCreated), snapshot(parent, postStateRoleParent)}, map[[16]byte]uint32{target: postStateRoleCreated, parent: postStateRoleParent}},
		{"symlink", &authoritypb.Request{Body: &authoritypb.Request_Symlink{}}, []postStateSnapshot{snapshot(target, postStateRoleCreated), snapshot(parent, postStateRoleParent)}, map[[16]byte]uint32{target: postStateRoleCreated, parent: postStateRoleParent}},
		{"tmpfile", &authoritypb.Request{Body: &authoritypb.Request_Tmpfile{}}, []postStateSnapshot{snapshot(target, postStateRoleCreated), snapshot(parent, postStateRoleParent)}, map[[16]byte]uint32{target: postStateRoleCreated, parent: postStateRoleParent}},
		{"link", &authoritypb.Request{Body: &authoritypb.Request_Link{}}, []postStateSnapshot{snapshot(target, postStateRoleTarget), snapshot(parent, postStateRoleParent)}, map[[16]byte]uint32{target: postStateRoleTarget, parent: postStateRoleParent}},
		{"unlink", &authoritypb.Request{Body: &authoritypb.Request_Unlink{}}, []postStateSnapshot{snapshot(target, postStateRoleRemoved), snapshot(parent, postStateRoleParent)}, map[[16]byte]uint32{target: postStateRoleRemoved, parent: postStateRoleParent}},
		{"rename same parent overwrite", &authoritypb.Request{Body: &authoritypb.Request_Rename{}}, []postStateSnapshot{snapshot(target, postStateRoleSource|postStateRoleDestination), snapshot(parent, postStateRoleOldParent), snapshot(parent, postStateRoleNewParent), snapshot(overwritten, postStateRoleOverwritten)}, map[[16]byte]uint32{target: postStateRoleSource | postStateRoleDestination, parent: postStateRoleOldParent | postStateRoleNewParent, overwritten: postStateRoleOverwritten}},
		{"rename distinct parents", &authoritypb.Request{Body: &authoritypb.Request_Rename{}}, []postStateSnapshot{snapshot(target, postStateRoleSource|postStateRoleDestination), snapshot(oldParent, postStateRoleOldParent), snapshot(newParent, postStateRoleNewParent)}, map[[16]byte]uint32{target: postStateRoleSource | postStateRoleDestination, oldParent: postStateRoleOldParent, newParent: postStateRoleNewParent}},
		{"rename exchange", &authoritypb.Request{Body: &authoritypb.Request_Rename{}}, []postStateSnapshot{snapshot(target, postStateRoleSource|postStateRoleDestination|postStateRoleExchanged), snapshot(overwritten, postStateRoleSource|postStateRoleDestination|postStateRoleExchanged), snapshot(oldParent, postStateRoleOldParent), snapshot(newParent, postStateRoleNewParent)}, map[[16]byte]uint32{target: postStateRoleSource | postStateRoleDestination | postStateRoleExchanged, overwritten: postStateRoleSource | postStateRoleDestination | postStateRoleExchanged, oldParent: postStateRoleOldParent, newParent: postStateRoleNewParent}},
		{"xattr removal", &authoritypb.Request{Body: &authoritypb.Request_RemoveXattr{}}, []postStateSnapshot{snapshot(target, postStateRoleTarget)}, map[[16]byte]uint32{target: postStateRoleTarget}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := &VolumeHandler{}
			state := handler.mutationPostState(9, test.input...)
			if !validMutationPostStateRoles(test.request, state) {
				t.Fatalf("role set rejected: %+v", state.GetObjects())
			}
			got := make(map[[16]byte]uint32, len(state.GetObjects()))
			for _, object := range state.GetObjects() {
				var identity [16]byte
				copy(identity[:], object.GetStableIdentity())
				got[identity] = object.GetRoles()
			}
			if !reflect.DeepEqual(got, test.expected) {
				t.Fatalf("objects/roles = %#v, want %#v", got, test.expected)
			}
		})
	}
}

func TestMutationPostStateCarriesMaskedStatxFlags(t *testing.T) {
	identity := postStateTestIdentity(0x71)
	const flags = uint32(0x00300870)
	state := (&VolumeHandler{}).mutationPostState(23, postStateSnapshot{
		identity: identity,
		attr: xfsstore.Attr{
			Kind: xfsstore.KindRegular, Ino: 71, Mode: 0o600, Nlink: 1, Flags: flags,
		},
		roles:   postStateRoleTarget,
		changed: true,
	})
	if len(state.GetObjects()) != 1 || state.GetObjects()[0].GetAttr().GetFlags() != flags {
		t.Fatalf("post-state flags = %#x, want %#x", state.GetObjects()[0].GetAttr().GetFlags(), flags)
	}
}
