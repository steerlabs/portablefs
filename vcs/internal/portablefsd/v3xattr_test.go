package portablefsd

import (
	"context"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func TestV3StaticallyRefusedXattrsNeverReachTheAuthority(t *testing.T) {
	// The authority refuses these names with EOPNOTSUPP, which crosses the
	// wire mapping as Darwin ENOTSUP; the local answer must be identical.
	authorityAnswer := linuxToDarwin(errnos.EOPNOTSUPP)
	if authorityAnswer != darwinENOTSUP {
		t.Fatalf("authority EOPNOTSUPP maps to %d, want Darwin ENOTSUP", authorityAnswer)
	}
	for _, test := range []struct {
		name      string
		attribute string
		errno     int32
	}{
		{name: "finder-info", attribute: "com.apple.FinderInfo", errno: authorityAnswer},
		{name: "resource-fork", attribute: "com.apple.ResourceFork", errno: authorityAnswer},
		{name: "security", attribute: "security.selinux", errno: authorityAnswer},
		{name: "trusted", attribute: "trusted.overlay", errno: authorityAnswer},
		{name: "portablefs-internal", attribute: "user.portablefs.meta", errno: authorityAnswer},
		{name: "portable-user", attribute: "user.note"},
	} {
		for _, operation := range []struct {
			name    string
			request func(item pfslocal.Item, name string) any
		}{
			{name: "get", request: func(item pfslocal.Item, name string) any {
				return &pfslocal.XattrGetRequest{Item: item, Name: name}
			}},
			{name: "remove", request: func(item pfslocal.Item, name string) any {
				return &pfslocal.XattrRemoveRequest{Item: item, Name: name}
			}},
		} {
			t.Run(test.name+"/"+operation.name, func(t *testing.T) {
				client := newFakeV3DataClient()
				d := testV3DataPlane(t, client)
				file := lookupTestAttr(t, d, d.resolveReply().Root, "file")
				var reads, mutations int
				client.read = func(context.Context, *authoritypb.Request) (*authoritypb.Response, error) {
					reads++
					return &authoritypb.Response{Body: &authoritypb.Response_GetXattr{GetXattr: &authoritypb.GetXattrReply{Value: []byte("v")}}}, nil
				}
				client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, _ *authoritypb.Request) (*authoritypb.Response, error) {
					mutations++
					return exactTestMutationReply(identity), nil
				}
				_, errno := dispatchV3Test(d, context.Background(), 0, operation.request(file.Item, test.attribute))
				if errno != test.errno {
					t.Fatalf("%s %q errno=%d, want %d", operation.name, test.attribute, errno, test.errno)
				}
				forwarded := reads + mutations
				if test.errno != 0 && forwarded != 0 || test.errno == 0 && forwarded != 1 {
					t.Fatalf("%s %q reached the authority %d time(s)", operation.name, test.attribute, forwarded)
				}
			})
		}
	}
}

// Local validation keeps its order: a stale item, a foreign handle, or a
// malformed name is reported as such even when the name is also refused by
// static policy.
func TestV3XattrStaticRefusalKeepsLocalErrorPrecedence(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	file, handle := openTestV3File(t, d, false)
	stale := file
	stale.ItemID += 1000
	for _, test := range []struct {
		name    string
		request any
		errno   int32
	}{
		{name: "stale-item", request: &pfslocal.XattrGetRequest{Item: stale, Name: "com.apple.FinderInfo"}, errno: darwinESTALE},
		{name: "foreign-handle", request: &pfslocal.XattrRemoveRequest{Item: d.resolveReply().Root, Handle: handle, Name: "com.apple.FinderInfo"}, errno: darwinEBADF},
		{name: "empty-name", request: &pfslocal.XattrGetRequest{Item: file, Name: ""}, errno: darwinEINVAL},
		{name: "nul-name", request: &pfslocal.XattrRemoveRequest{Item: file, Name: "com.apple\x00x"}, errno: darwinEINVAL},
		{name: "handle-bound-refusal", request: &pfslocal.XattrGetRequest{Item: file, Handle: handle, Name: "com.apple.FinderInfo"}, errno: darwinENOTSUP},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, errno := dispatchV3Test(d, context.Background(), 0, test.request); errno != test.errno {
				t.Fatalf("errno=%d, want %d", errno, test.errno)
			}
		})
	}
	if d.terminalError() != nil {
		t.Fatalf("local xattr refusals were terminal: %v", d.terminalError())
	}
}

// Sets are refused locally with exactly the authority's answer, after the
// frozen local validation order, and never enter mutation machinery.
func TestV3XattrSetIsRefusedLocallyWithTheAuthorityErrno(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	file, handle := openTestV3File(t, d, false)
	stale := file
	stale.ItemID += 1000
	refusal := linuxToDarwin(errnos.EOPNOTSUPP)
	for index, test := range []struct {
		name    string
		request *pfslocal.XattrSetRequest
		errno   int32
	}{
		{name: "portable-user", request: &pfslocal.XattrSetRequest{Item: file, Name: "user.note", Value: []byte("v")}, errno: refusal},
		{name: "with-handle", request: &pfslocal.XattrSetRequest{Item: file, Handle: handle, Name: "user.note", Value: []byte("v"), CreateOnly: true}, errno: refusal},
		{name: "forbidden-namespace", request: &pfslocal.XattrSetRequest{Item: file, Name: "com.apple.FinderInfo"}, errno: refusal},
		{name: "stale-item", request: &pfslocal.XattrSetRequest{Item: stale, Name: "user.note"}, errno: darwinESTALE},
		{name: "foreign-handle", request: &pfslocal.XattrSetRequest{Item: d.resolveReply().Root, Handle: handle, Name: "user.note"}, errno: darwinEBADF},
		{name: "empty-name", request: &pfslocal.XattrSetRequest{Item: file, Name: ""}, errno: darwinEINVAL},
		{name: "create-and-replace", request: &pfslocal.XattrSetRequest{Item: file, Name: "user.note", CreateOnly: true, ReplaceOnly: true}, errno: darwinEINVAL},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := len(client.mutationRequests())
			operationID := uint64(700 + index)
			if _, errno := dispatchV3Test(d, context.Background(), operationID, test.request); errno != test.errno {
				t.Fatalf("setxattr errno=%d, want %d", errno, test.errno)
			}
			if sent := len(client.mutationRequests()) - before; sent != 0 {
				t.Fatalf("setxattr sent %d authority mutations", sent)
			}
		})
	}
	if refusal != darwinENOTSUP || d.terminalError() != nil {
		t.Fatalf("set refusal=%d terminal=%v", refusal, d.terminalError())
	}
}
