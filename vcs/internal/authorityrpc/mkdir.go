package authorityrpc

import (
	"bytes"
	"fmt"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
)

// A successful MKDIR transfers one owning item. Its permission observation is
// meaningful only with the same created identity, attributes and committed
// snapshot; accepting an unrelated PostState would seed an unproved absence.
func validMkdirReply(response *authoritypb.Response) bool {
	item := response.GetMkdir().GetItem()
	state := response.GetPostState()
	if item == nil || !validCoherenceIdentity(item.GetToken()) ||
		!validCoherenceIdentity(item.GetStableIdentity()) || item.GetAttr() == nil ||
		item.GetAttr().GetKind() != authoritypb.Attr_DIRECTORY || item.GetAttr().GetInode() == 0 ||
		item.GetObjectVersion() == 0 || item.GetObjectVersion() > item.GetSnapshotSequence() ||
		!validPostStateShape(state, true) || item.GetSnapshotSequence() != state.GetSnapshotSequence() ||
		!rolesEqual(postStateRoleMultiset(state), postStateRoleParent, postStateRoleCreated) {
		return false
	}
	for _, object := range state.GetObjects() {
		if object.GetAttr().GetKind() != authoritypb.Attr_DIRECTORY || object.GetAttr().GetInode() == 0 {
			return false
		}
		if object.GetRoles() == postStateRoleCreated &&
			(!bytes.Equal(object.GetStableIdentity(), item.GetStableIdentity()) ||
				object.GetObjectVersion() != item.GetObjectVersion() || !proto.Equal(object.GetAttr(), item.GetAttr())) {
			return false
		}
	}
	return true
}

// The frame validator sees the result body, but only the caller can bind that
// body to MKDIR. LookupReply remains valid for lookup and symlink, never mkdir.
func validateMkdirResult(request *authoritypb.Request, response *authoritypb.Response) error {
	if response.GetErrno() != 0 || response.GetUncertain() {
		return nil
	}
	_, requested := request.GetBody().(*authoritypb.Request_Mkdir)
	_, returned := response.GetBody().(*authoritypb.Response_Mkdir)
	if requested {
		if response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_UNSPECIFIED || !validMkdirReply(response) {
			return fmt.Errorf("%w: successful mkdir omitted its exact item/post-state result", ErrTransportBinding)
		}
	} else if returned {
		return fmt.Errorf("%w: mkdir result for a different operation", ErrTransportBinding)
	}
	return nil
}
