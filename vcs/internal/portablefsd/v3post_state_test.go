package portablefsd

import "github.com/steerlabs/portablefs/vcs/internal/authoritypb"

func testV3PostState(attr *authoritypb.Attr) *authoritypb.PostState {
	return &authoritypb.PostState{VisibilitySequence: 2, SnapshotSequence: 2, Objects: []*authoritypb.ObjectPostState{{
		StableIdentity: []byte("0123456789abcdef"), ObjectVersion: 2, Attr: attr, Roles: v3PostStateRoleTarget,
	}}}
}
