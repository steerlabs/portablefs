package authorityrpc

import (
	"bytes"
	"sort"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

const (
	postStateRoleTarget      uint32 = 0x0001
	postStateRoleParent      uint32 = 0x0002
	postStateRoleOldParent   uint32 = 0x0004
	postStateRoleNewParent   uint32 = 0x0008
	postStateRoleRemoved     uint32 = 0x0010
	postStateRoleOverwritten uint32 = 0x0020
	postStateRoleSource      uint32 = 0x0040
	postStateRoleDestination uint32 = 0x0080
	postStateRoleCreated     uint32 = 0x0100
	postStateRoleExchanged   uint32 = 0x0200

	postStateKnownRoles = postStateRoleTarget | postStateRoleParent |
		postStateRoleOldParent | postStateRoleNewParent | postStateRoleRemoved |
		postStateRoleOverwritten | postStateRoleSource | postStateRoleDestination |
		postStateRoleCreated | postStateRoleExchanged
)

// validPostStateShape validates invariants that do not depend on the operation
// that produced the envelope. Operation-specific role and identity validation
// is intentionally performed at the consumer boundary before cache admission.
func validPostStateShape(state *authoritypb.PostState, mutation bool) bool {
	if state == nil || state.GetSnapshotSequence() == 0 || len(state.GetObjects()) < 1 || len(state.GetObjects()) > 4 {
		return false
	}
	if mutation {
		if state.GetVisibilitySequence() == 0 || state.GetVisibilitySequence() != state.GetSnapshotSequence() {
			return false
		}
	} else if state.GetVisibilitySequence() != 0 {
		return false
	}
	var previous []byte
	for _, object := range state.GetObjects() {
		if object == nil || len(object.GetStableIdentity()) != 16 || object.GetObjectVersion() == 0 ||
			object.GetObjectVersion() > state.GetSnapshotSequence() || object.GetAttr() == nil ||
			object.GetRoles() == 0 || object.GetRoles()&^postStateKnownRoles != 0 {
			return false
		}
		if previous != nil && bytes.Compare(previous, object.GetStableIdentity()) >= 0 {
			return false
		}
		previous = object.GetStableIdentity()
	}
	return true
}

func postStateRoleMultiset(state *authoritypb.PostState) []uint32 {
	roles := make([]uint32, 0, len(state.GetObjects()))
	for _, object := range state.GetObjects() {
		roles = append(roles, object.GetRoles())
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	return roles
}

func rolesEqual(got []uint32, want ...uint32) bool {
	sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

// validMutationPostStateRoles is the operation-level half of envelope
// validation. It deliberately compares complete role multisets: accepting a
// required subset would make an extra object just as silent as a missing one.
func validMutationPostStateRoles(request *authoritypb.Request, state *authoritypb.PostState) bool {
	if request == nil || !validPostStateShape(state, true) {
		return false
	}
	got := postStateRoleMultiset(state)
	switch body := request.GetBody().(type) {
	case *authoritypb.Request_Write, *authoritypb.Request_FskitWrite,
		*authoritypb.Request_SetAttr, *authoritypb.Request_Fallocate,
		*authoritypb.Request_Open, *authoritypb.Request_SetXattr,
		*authoritypb.Request_RemoveXattr:
		return rolesEqual(got, postStateRoleTarget)
	case *authoritypb.Request_CopyFileRange:
		return rolesEqual(got, postStateRoleSource|postStateRoleDestination) ||
			rolesEqual(got, postStateRoleSource, postStateRoleDestination)
	case *authoritypb.Request_Tmpfile, *authoritypb.Request_Mkdir, *authoritypb.Request_Symlink:
		return rolesEqual(got, postStateRoleParent, postStateRoleCreated)
	case *authoritypb.Request_Create:
		_ = body
		return rolesEqual(got, postStateRoleParent, postStateRoleTarget) || rolesEqual(got, postStateRoleParent, postStateRoleCreated)
	case *authoritypb.Request_Link:
		return rolesEqual(got, postStateRoleTarget, postStateRoleParent)
	case *authoritypb.Request_Unlink:
		return rolesEqual(got, postStateRoleRemoved, postStateRoleParent)
	case *authoritypb.Request_Rename:
		return validRenamePostStateRoles(got)
	default:
		return false
	}
}

func validRenamePostStateRoles(got []uint32) bool {
	const moved = postStateRoleSource | postStateRoleDestination
	const exchanged = moved | postStateRoleExchanged
	allowed := [][]uint32{
		{moved, postStateRoleOldParent | postStateRoleNewParent},
		{moved, postStateRoleOldParent, postStateRoleNewParent},
		{moved, postStateRoleOverwritten, postStateRoleOldParent | postStateRoleNewParent},
		{moved, postStateRoleOverwritten, postStateRoleOldParent, postStateRoleNewParent},
		{exchanged, exchanged, postStateRoleOldParent | postStateRoleNewParent},
		{exchanged, exchanged, postStateRoleOldParent, postStateRoleNewParent},
	}
	for _, want := range allowed {
		if rolesEqual(got, want...) {
			return true
		}
	}
	return false
}

func postStateTargetAttr(state *authoritypb.PostState) *authoritypb.Attr {
	if state == nil {
		return nil
	}
	for _, object := range state.GetObjects() {
		if object.GetRoles()&postStateRoleTarget != 0 {
			return object.GetAttr()
		}
	}
	return nil
}
