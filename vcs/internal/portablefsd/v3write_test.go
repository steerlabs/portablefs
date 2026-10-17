package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"google.golang.org/protobuf/proto"
)

func v3SourceLeaseState(d *v3DataPlane, operationID uint64) (assigned uint32, committed, released bool) {
	lease := d.bridge.sourcePublication.operationLease(operationID)
	d.bridge.sourcePublication.mu.Lock()
	defer d.bridge.sourcePublication.mu.Unlock()
	if op := d.bridge.sourcePublication.operations[operationID]; op != nil {
		committed = op.committed
	}
	if lease != nil {
		assigned, released = lease.assigned, lease.released
	}
	return assigned, committed, released
}

func TestV3WriteSendsOneExactWritePerChunk(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	file, handle := openTestV3File(t, d, false)
	const operationID = uint64(77)
	expectedGate, err := v3ItemSourceGate(file, true)
	if err != nil {
		t.Fatal(err)
	}
	client.beforeAssigned = func(request *authoritypb.Request) error {
		lease := d.bridge.sourcePublication.operationLease(operationID)
		if lease == nil || !proto.Equal(request.GetFskitSourcePublication(), expectedGate) {
			return errors.New("write did not install its exact ATTR+DATA source gate before replay assignment")
		}
		return nil
	}
	before := len(client.mutationRequests())
	d.bridge.reserveFrontendPublication(operationID)
	replyAny, errno := d.dispatchFrontend(context.Background(), operationID, &pfslocal.WriteRequest{
		Handle: handle, Offset: 7, Data: []byte("abcde"),
	})
	if errno != 0 {
		t.Fatalf("write errno=%d", errno)
	}
	reply := replyAny.(*pfslocal.WriteReply)
	if reply.Written != 5 || reply.Attr.Size != 12 || reply.Attr.FileID != 2 || reply.Attr.Item != file {
		t.Fatalf("write reply = %+v", reply)
	}
	sent := client.mutationRequests()[before:]
	if len(sent) != 1 {
		t.Fatalf("write sent %d authority mutations, want exactly one", len(sent))
	}
	want := &authoritypb.WriteRequest{
		Handle: d.handles[handle].token, Position: 7, Size: 5,
		Data: []byte("abcde"), WriteFlags: v3WriteFlagKillSUIDGID,
	}
	if !proto.Equal(sent[0].GetWrite(), want) || sent[0].GetFskitFrontendOperationId() != operationID {
		t.Fatalf("write request = %v, want exactly %v for operation %d", sent[0], want, operationID)
	}
	if _, committed, _ := v3SourceLeaseState(d, operationID); !committed {
		t.Fatal("successful write did not record its commit before publication")
	}
	if !acknowledgeBridgePublished(t, d.bridge, operationID) {
		t.Fatal("write PublicationAck was refused")
	}
	d.bridge.releaseFrontendPublication(operationID)
}

func TestV3WriteReturnsAShortCommittedPrefix(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	_, handle := openTestV3File(t, d, false)
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		response := exactTestWriteReply(identity, request)
		response.GetWrite().CommittedSize = 2
		return response, nil
	}
	reply, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.WriteRequest{Handle: handle, Data: []byte("abcde")})
	if errno != 0 || reply.(*pfslocal.WriteReply).Written != 2 || d.terminalError() != nil {
		t.Fatalf("short write = (%#v,%d) terminal=%v, want the committed prefix", reply, errno, d.terminalError())
	}
}

func TestV3WriteReplyIsValidatedExactly(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*authoritypb.Response)
	}{
		{name: "zero-committed", mutate: func(r *authoritypb.Response) { r.GetWrite().CommittedSize = 0 }},
		{name: "over-committed", mutate: func(r *authoritypb.Response) { r.GetWrite().CommittedSize = 6 }},
		{name: "moved-offset", mutate: func(r *authoritypb.Response) { r.GetWrite().AssignedOffset = 1 }},
		{name: "missing-post-attr", mutate: func(r *authoritypb.Response) { r.GetWrite().PostAttr = nil }},
		{name: "missing-post-state", mutate: func(r *authoritypb.Response) { r.PostState = nil }},
		{name: "post-attr-disagrees", mutate: func(r *authoritypb.Response) { r.GetWrite().GetPostAttr().Mode = 0o777 }},
		{name: "other-kind", mutate: func(r *authoritypb.Response) {
			r.GetWrite().GetPostAttr().Kind = authoritypb.Attr_DIRECTORY
			r.PostState.Objects[0].Attr.Kind = authoritypb.Attr_DIRECTORY
		}},
		{name: "other-inode", mutate: func(r *authoritypb.Response) {
			r.GetWrite().GetPostAttr().Inode = 3
			r.PostState.Objects[0].Attr.Inode = 3
		}},
		{name: "size-short-of-end", mutate: func(r *authoritypb.Response) {
			r.GetWrite().GetPostAttr().Size = 4
			r.PostState.Objects[0].Attr.Size = 4
		}},
		{name: "positive-errno", mutate: func(r *authoritypb.Response) { r.GetWrite().Error = 5 }},
		{name: "target-other-identity", mutate: func(r *authoritypb.Response) {
			r.PostState.Objects[0].StableIdentity = bytes.Repeat([]byte{0x41}, 16)
		}},
		{name: "target-missing", mutate: func(r *authoritypb.Response) { r.PostState.Objects[0].Roles = 0 }},
		{name: "target-repeated", mutate: func(r *authoritypb.Response) {
			r.PostState.Objects = append(r.PostState.Objects, proto.Clone(r.PostState.Objects[0]).(*authoritypb.ObjectPostState))
		}},
		{name: "missing-reply", mutate: func(r *authoritypb.Response) { r.Body = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			_, handle := openTestV3File(t, d, false)
			client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
				response := exactTestWriteReply(identity, request)
				test.mutate(response)
				return response, nil
			}
			const operationID = uint64(91)
			d.bridge.reserveFrontendPublication(operationID)
			if reply, errno := d.dispatchFrontend(context.Background(), operationID, &pfslocal.WriteRequest{
				Handle: handle, Data: []byte("abcde"),
			}); errno != darwinEIO || reply != nil || d.terminalError() == nil {
				t.Fatalf("malformed write reply = (%#v,%d), want terminal EIO", reply, errno)
			}
			if _, committed, _ := v3SourceLeaseState(d, operationID); !committed {
				t.Fatal("malformed write reply after assignment was not treated as possibly applied")
			}
		})
	}
}

func TestV3WriteDefiniteRejectionIsNonTerminal(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	_, handle := openTestV3File(t, d, false)
	var consumed atomic.Int32
	client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
		return &countingV3ResponseConsumption{count: &consumed}
	}
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, _ *authoritypb.Request) (*authoritypb.Response, error) {
		response := exactTestMutationReply(identity)
		response.Body = &authoritypb.Response_Write{Write: &authoritypb.WriteReply{Error: -int32(errnos.ENOSPC)}}
		return response, nil
	}
	const operationID = uint64(92)
	d.bridge.reserveFrontendPublication(operationID)
	if reply, errno := d.dispatchFrontend(context.Background(), operationID, &pfslocal.WriteRequest{
		Handle: handle, Data: []byte("abc"),
	}); errno != darwinENOSPC || reply != nil {
		t.Fatalf("definite rejection = (%#v,%d), want ENOSPC", reply, errno)
	}
	lease := d.bridge.sourcePublication.operationLease(operationID)
	assigned, committed, released := v3SourceLeaseState(d, operationID)
	if lease == nil || assigned == 0 || committed || released || d.terminalError() != nil {
		t.Fatalf("definite rejection lease assigned=%d committed=%t released=%t terminal=%v", assigned, committed, released, d.terminalError())
	}
	if got := consumed.Load(); got != 0 {
		t.Fatalf("definite rejection consumed its receipt before publication: %d", got)
	}
	if !acknowledgeBridgePublished(t, d.bridge, operationID) {
		t.Fatal("rejected callback PublicationAck was refused")
	}
	d.bridge.releaseFrontendPublication(operationID)
	if err := d.bridge.finishFrontendPublication(operationID); err != nil {
		t.Fatal(err)
	}
	d.bridge.sourcePublication.mu.Lock()
	released = lease.released
	d.bridge.sourcePublication.mu.Unlock()
	if !released || consumed.Load() != 1 {
		t.Fatalf("definite rejection released=%t consumed=%d after publication", released, consumed.Load())
	}
}

func TestV3WriteUnadmittedReplyIsANonTerminalENOMEM(t *testing.T) {
	unadmitted := func(_ authorityrpc.MutationIdentity) *authoritypb.Response {
		return &authoritypb.Response{Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{Error: -int32(errnos.ENOMEM)}}}
	}
	for _, test := range []struct {
		name     string
		response func(authorityrpc.MutationIdentity) *authoritypb.Response
		terminal bool
	}{
		{name: "unadmitted", response: unadmitted},
		{name: "unrecorded-other-errno", terminal: true, response: func(authorityrpc.MutationIdentity) *authoritypb.Response {
			return &authoritypb.Response{Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{Error: -int32(errnos.ENOSPC)}}}
		}},
		{name: "unrecorded-with-post-attr", terminal: true, response: func(identity authorityrpc.MutationIdentity) *authoritypb.Response {
			response := unadmitted(identity)
			response.GetWrite().PostAttr = &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: 2}
			return response
		}},
		{name: "unrecorded-uncertain", terminal: true, response: func(identity authorityrpc.MutationIdentity) *authoritypb.Response {
			response := unadmitted(identity)
			response.Uncertain = true
			return response
		}},
		{name: "unrecorded-envelope-errno", terminal: true, response: func(authorityrpc.MutationIdentity) *authoritypb.Response {
			return &authoritypb.Response{Errno: errnos.ENOMEM}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			_, handle := openTestV3File(t, d, false)
			client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, _ *authoritypb.Request) (*authoritypb.Response, error) {
				return test.response(identity), nil
			}
			const operationID = uint64(93)
			d.bridge.reserveFrontendPublication(operationID)
			reply, errno := d.dispatchFrontend(context.Background(), operationID, &pfslocal.WriteRequest{Handle: handle, Data: []byte("abc")})
			if test.terminal {
				if errno != darwinEIO || d.terminalError() == nil {
					t.Fatalf("unrecognized unrecorded reply = (%#v,%d), want terminal EIO", reply, errno)
				}
				return
			}
			if errno != darwinENOMEM || reply != nil || d.terminalError() != nil {
				t.Fatalf("unadmitted write = (%#v,%d) terminal=%v, want non-terminal ENOMEM", reply, errno, d.terminalError())
			}
			if _, committed, _ := v3SourceLeaseState(d, operationID); committed {
				t.Fatal("an unadmitted write was recorded as committed")
			}
			if !acknowledgeBridgePublished(t, d.bridge, operationID) {
				t.Fatal("unadmitted callback PublicationAck was refused")
			}
			d.bridge.releaseFrontendPublication(operationID)
			client.mutation = nil
			if reply, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.WriteRequest{Handle: handle, Data: []byte("abc")}); errno != 0 || reply.(*pfslocal.WriteReply).Written != 3 {
				t.Fatalf("write after unadmitted refusal = (%#v,%d)", reply, errno)
			}
		})
	}
}

func TestV3WritePostApplyFailureIsTerminal(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*authoritypb.Response)
		// A storage failure fences the authority epoch itself, so its
		// transport ends either way; every other post-apply outcome leaves the
		// session intact for the supervisor's absence proof.
		sessionEnds bool
	}{
		{name: "committed-prefix", mutate: func(r *authoritypb.Response) { r.GetWrite().Error = -int32(errnos.EIO) }},
		{name: "zero-byte", mutate: func(r *authoritypb.Response) {
			r.GetWrite().CommittedSize = 0
			r.GetWrite().AssignedOffset = 0
			r.GetWrite().Error = -int32(errnos.EDQUOT)
		}},
		{name: "durability-storage-failure", sessionEnds: true, mutate: func(r *authoritypb.Response) {
			r.GetWrite().Error = -int32(errnos.EIO)
			r.Failure = authoritypb.FailureClass_FAILURE_CLASS_STORAGE
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			_, handle := openTestV3File(t, d, false)
			client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
				response := exactTestWriteReply(identity, request)
				test.mutate(response)
				return response, nil
			}
			const operationID = uint64(94)
			d.bridge.reserveFrontendPublication(operationID)
			if reply, errno := d.dispatchFrontend(context.Background(), operationID, &pfslocal.WriteRequest{
				Handle: handle, Data: []byte("abc"),
			}); errno != darwinEIO || reply != nil || d.terminalError() == nil {
				t.Fatalf("post-apply write = (%#v,%d), want terminal EIO", reply, errno)
			}
			client.mu.Lock()
			closed := client.closed
			client.mu.Unlock()
			if closed != test.sessionEnds {
				t.Fatalf("authority transport closed=%t, want %t: a session-safe post-apply outcome must keep it for the unmount absence proof", closed, test.sessionEnds)
			}
			_, _ = d.bridge.acknowledgePublication(operationID, pfslocal.PublicationSemanticCommitNotPublished)
			d.bridge.releaseFrontendPublication(operationID)
			if _, _, released := v3SourceLeaseState(d, operationID); released {
				t.Fatal("a possibly applied write reopened its source gate")
			}
		})
	}
}

func TestV3WriteRefusesUnrepresentableChunksBeforeTheAuthority(t *testing.T) {
	for _, test := range []struct {
		name   string
		offset uint64
		size   int
		errno  int32
	}{
		{name: "max-write", size: 4096},
		{name: "oversize", size: 4097, errno: darwinEINVAL},
		{name: "offset-at-limit", offset: math.MaxInt64, size: 1, errno: darwinEFBIG},
		{name: "end-overflows", offset: math.MaxInt64 - 2, size: 3, errno: darwinEFBIG},
		{name: "end-at-limit", offset: math.MaxInt64 - 3, size: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			_, handle := openTestV3File(t, d, false)
			before := len(client.mutationRequests())
			reply, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.WriteRequest{
				Handle: handle, Offset: test.offset, Data: bytes.Repeat([]byte{'x'}, test.size),
			})
			sent := len(client.mutationRequests()) - before
			if test.errno != 0 {
				if errno != test.errno || sent != 0 || d.terminalError() != nil {
					t.Fatalf("refused chunk = (%#v,%d) sent=%d, want %d before the authority", reply, errno, sent, test.errno)
				}
				return
			}
			if errno != 0 || sent != 1 || reply.(*pfslocal.WriteReply).Written != uint32(test.size) {
				t.Fatalf("representable chunk = (%#v,%d) sent=%d, want one WRITE", reply, errno, sent)
			}
		})
	}
}

// Writes to different files carry no mount-wide ordering: each is one replay
// mutation under its own item gate.
func TestV3WritesToDifferentFilesAreNotSerializedMountWide(t *testing.T) {
	client := newFakeV3DataClient()
	client.limit = 4
	d := testV3DataPlane(t, client)
	root := d.resolveReply().Root
	names := map[string]*authoritypb.Item{
		"one": authorityTestItem(20, authoritypb.Attr_REGULAR, 0, 0x81),
		"two": authorityTestItem(21, authoritypb.Attr_REGULAR, 0, 0x82),
	}
	lookups := lookupByName(client, names)
	blocked, release := make(chan struct{}), make(chan struct{})
	client.mutation = func(ctx context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		switch request.GetBody().(type) {
		case *authoritypb.Request_Open:
			response := exactTestMutationReply(identity)
			response.Body = &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: bytes.Repeat([]byte{0x52}, 16)}}
			return response, nil
		case *authoritypb.Request_Write:
			if string(request.GetWrite().GetData()) == "first" {
				close(blocked)
				<-release
				return exactTestWriteReplyFor(identity, request, 0x81, 20), nil
			}
			return exactTestWriteReplyFor(identity, request, 0x82, 21), nil
		default:
			return lookups(ctx, identity, request)
		}
	}
	open := func(name string) uint64 {
		attr := lookupTestAttr(t, d, root, name)
		reply, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.OpenRequest{Item: attr.Item, Mode: pfslocal.OpenModeReadWrite})
		if errno != 0 {
			t.Fatalf("open %s errno=%d", name, errno)
		}
		return reply.(*pfslocal.OpenReply).Handle
	}
	first, second := open("one"), open("two")
	firstDone := make(chan int32, 1)
	go func() {
		_, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.WriteRequest{Handle: first, Data: []byte("first")})
		firstDone <- errno
	}()
	<-blocked
	secondDone := make(chan int32, 1)
	go func() {
		_, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.WriteRequest{Handle: second, Data: []byte("second")})
		secondDone <- errno
	}()
	select {
	case errno := <-secondDone:
		if errno != 0 {
			t.Fatalf("second write errno=%d", errno)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a write to another file waited behind an in-flight write")
	}
	close(release)
	if errno := <-firstDone; errno != 0 {
		t.Fatalf("first write errno=%d", errno)
	}
}

func TestV3HandleIsBoundToItsFullItemIdentity(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	file, _ := openTestV3File(t, d, false)
	impostor := file
	impostor.StableIdentity[0] ^= 0xff
	handle, err := d.installHandle(bytes.Repeat([]byte{0x53}, 16), impostor, false)
	if err != nil {
		t.Fatal(err)
	}
	mode := uint32(0o600)
	before := len(client.mutationRequests())
	if _, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.SetAttrRequest{Item: file, Handle: handle.id, Mode: &mode}); errno != darwinEBADF {
		t.Fatalf("setattr through a handle of another identity errno=%d, want EBADF", errno)
	}
	if sent := len(client.mutationRequests()) - before; sent != 0 {
		t.Fatalf("identity mismatch reached the authority with %d mutations", sent)
	}
}
