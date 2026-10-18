package portablefsd

import (
	"context"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// These requests deliberately send no ResourceReplyDisposition. Only the real
// handler's deferred unused-reservation retirement can return their capacity.
func TestP6WireNoResourceRetiresReservation(t *testing.T) {
	for _, kind := range []string{"invalid", "authority", "negative", "duplicate-link"} {
		t.Run(kind, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			d.pending = newV3PendingBudget(1)
			root := d.resolveReply().Root
			var body any = &pfslocal.LookupRequest{Dir: root, Name: []byte("invalid/name")}
			want := int32(darwinEINVAL)
			initialTokens := 1
			if kind == "authority" || kind == "negative" {
				body = &pfslocal.LookupRequest{Dir: root, Name: []byte("absent")}
				want = darwinENOENT
				if kind == "authority" {
					want = darwinENOMEM
				}
				client.mutation = func(_ context.Context, id authorityrpc.MutationIdentity, _ *authoritypb.Request) (*authoritypb.Response, error) {
					r := exactTestMutationReply(id)
					if kind == "authority" {
						r.Errno = errnos.ENOMEM
					} else {
						r.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{NegativeSnapshotSequence: 1}}
					}
					return r, nil
				}
			}
			if kind == "duplicate-link" {
				file := lookupTestAttr(t, d, root, "file")
				initialTokens = 2
				// Ignore the accepted fixture Lookup's already retired reservation.
				d.pending = newV3PendingBudget(1)
				body = &pfslocal.HardLinkRequest{Item: file.Item, Dir: root, Name: []byte("alias")}
				want = 0
				client.mutation = func(_ context.Context, id authorityrpc.MutationIdentity, req *authoritypb.Request) (*authoritypb.Response, error) {
					if req.GetReclaim() != nil {
						return client.reclaim(id, req), nil
					}
					if req.GetLink() == nil {
						t.Errorf("unexpected request: %T", req.GetBody())
						return exactTestMutationReply(id), nil
					}
					item := client.issueItem(2, authoritypb.Attr_REGULAR, 0x40)
					item.Attr.Nlink = 2
					r := exactTestMutationReply(id)
					r.PostState = testV3RootBinding(item, v3PostStateRoleTarget)
					r.Body = &authoritypb.Response_Link{Link: &authoritypb.LinkReply{Item: item}}
					return r, nil
				}
			}
			conn := p6Frontend(t, d)("p6.no-resource")
			p6Send(t, conn, &pfslocal.Envelope{RequestID: 3, OperationID: 7, Body: body})
			reply := readPFSReply(t, conn, 3)
			if want != 0 {
				failure, ok := reply.Body.(*pfslocal.ErrorReply)
				if !ok || failure.Errno != want {
					t.Fatalf("reply=%#v want errno=%d", reply.Body, want)
				}
			} else if _, ok := reply.Body.(*pfslocal.HardLinkReply); !ok {
				t.Fatalf("reply=%#v", reply.Body)
			}
			commit := pfslocal.PublicationSemanticCommitNotPublished
			if want == 0 {
				commit = pfslocal.PublicationSemanticCommitPublished
			}
			p6Send(t, conn, &pfslocal.Envelope{Body: &pfslocal.PublicationAck{OperationID: 7, SemanticCommit: commit}})
			p6Wait(t, d, func(m v3PendingMetrics) bool { return m.Pending == 0 })
			waitV3ReleasesIdle(t, d)
			if m := d.pending.metrics(); m.Reserved != 1 || m.Retired != 1 || m.Teardown != 0 || client.liveTokens() != initialTokens || d.terminalError() != nil {
				t.Fatalf("handler did not retire unused reservation: metrics=%+v live=%d terminal=%v", m, client.liveTokens(), d.terminalError())
			}
		})
	}
}
