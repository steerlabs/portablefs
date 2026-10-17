package portablefsd

import (
	"errors"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

const v3PostStateRoleTarget uint32 = 0x0001

func v3PostAttr(response *authoritypb.Response) *authoritypb.Attr {
	if response == nil || response.GetPostState() == nil {
		return nil
	}
	for _, object := range response.GetPostState().GetObjects() {
		if object.GetRoles()&v3PostStateRoleTarget != 0 {
			return object.GetAttr()
		}
	}
	return nil
}

// v3PostTarget is the post-state's single TARGET object, identity included,
// for replies whose target must be checked against the operation's item.
func v3PostTarget(response *authoritypb.Response) (*authoritypb.ObjectPostState, error) {
	var target *authoritypb.ObjectPostState
	for _, object := range response.GetPostState().GetObjects() {
		if object.GetRoles()&v3PostStateRoleTarget == 0 {
			continue
		}
		if target != nil {
			return nil, errors.New("post-state names more than one target")
		}
		target = object
	}
	if target == nil {
		return nil, errors.New("post-state omitted its target")
	}
	return target, nil
}
