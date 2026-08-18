package portablefsd

import "github.com/steerlabs/portablefs/vcs/internal/authoritypb"

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
