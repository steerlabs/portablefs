package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/visibilitywire"
)

type fakeV3DataClient struct {
	*fakeV3VisibilityClient
	root      *authoritypb.Item
	lease     time.Duration
	limit     int
	mu        sync.Mutex
	sequence  uint64
	readCalls int
	keepErr   error
	mutation  func(context.Context, authorityrpc.MutationIdentity, *authoritypb.Request) (*authoritypb.Response, error)
}

func newFakeV3DataClient() *fakeV3DataClient {
	visibility := newFakeV3VisibilityClient()
	visibility.initial = nil
	return &fakeV3DataClient{
		fakeV3VisibilityClient: visibility,
		root:                   authorityTestItem(1, authoritypb.Attr_DIRECTORY, 0x10, 0x20),
		lease:                  time.Minute, limit: 2,
	}
}

func authorityTestItem(inode uint64, kind authoritypb.Attr_Kind, tokenByte, identityByte byte) *authoritypb.Item {
	return &authoritypb.Item{
		Token: bytes.Repeat([]byte{tokenByte}, 16), StableIdentity: bytes.Repeat([]byte{identityByte}, 16),
		Attr: &authoritypb.Attr{Kind: kind, Inode: inode, Mode: 0o755, Nlink: 1},
	}
}

func (f *fakeV3DataClient) Root() *authoritypb.Item      { return f.root }
func (f *fakeV3DataClient) IOLimits() (uint32, uint32)   { return 4096, 4096 }
func (f *fakeV3DataClient) SessionLease() time.Duration  { return f.lease }
func (f *fakeV3DataClient) DataPlaneOperationLimit() int { return f.limit }
func (f *fakeV3DataClient) CallRead(_ context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	f.mu.Lock()
	f.readCalls++
	f.mu.Unlock()
	switch request.GetBody().(type) {
	case *authoritypb.Request_StatFs:
		return &authoritypb.Response{Body: &authoritypb.Response_StatFs{StatFs: &authoritypb.StatFSReply{BlockSize: 4096, NameMax: 255}}}, nil
	case *authoritypb.Request_KeepAlive:
		if f.keepErr != nil {
			return nil, f.keepErr
		}
		return &authoritypb.Response{}, nil
	case *authoritypb.Request_Lookup:
		return &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: authorityTestItem(2, authoritypb.Attr_REGULAR, 0x30, 0x40)}}}, nil
	case *authoritypb.Request_Reclaim:
		return &authoritypb.Response{}, nil
	default:
		return &authoritypb.Response{}, nil
	}
}
func (f *fakeV3DataClient) CallMutationWithIdentity(ctx context.Context, request *authoritypb.Request, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	f.mu.Lock()
	f.sequence++
	identity := authorityrpc.MutationIdentity{Slot: 2, Sequence: f.sequence}
	hook := f.mutation
	f.mu.Unlock()
	if assigned != nil {
		if err := assigned(identity); err != nil {
			return nil, err
		}
	}
	if hook != nil {
		return hook(ctx, identity, request)
	}
	response := &authoritypb.Response{Mutation: &authoritypb.MutationState{Slot: identity.Slot, AcceptedSequence: identity.Sequence}}
	switch request.GetBody().(type) {
	case *authoritypb.Request_Open:
		response.Body = &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: bytes.Repeat([]byte{0x51}, 16)}}
	case *authoritypb.Request_Write:
		response.Body = &authoritypb.Response_Write{Write: &authoritypb.WriteReply{Count: uint32(len(request.GetWrite().GetData()))}}
		response.PostAttr = &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: 2, Size: int64(len(request.GetWrite().GetData())), Nlink: 1}
	case *authoritypb.Request_SyncFs:
		response.Body = &authoritypb.Response_SyncFs{SyncFs: &authoritypb.SyncFSReply{}}
	}
	return response, nil
}

func testV3DataPlane(t *testing.T, client *fakeV3DataClient) *v3DataPlane {
	t.Helper()
	d, err := newV3DataPlane(context.Background(), v3DataPlaneConfig{Client: client, VolumeID: "volume", VolumeName: "Volume", ItemGeneration: 9, PrincipalUID: 501, PrincipalGID: 20, CachePolicy: v3CachePolicyFSKit})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.bridge.bind(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.fail(errors.New("test cleanup")) })
	return d
}

func TestV3DataPlaneRootIdentityAndGenesisContract(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	resolved := d.resolveReply()
	if resolved == nil || resolved.Root.ItemID != 1 || resolved.Root.ItemGeneration != 9 || resolved.Root.StableIdentity != ([16]byte{0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20}) {
		t.Fatalf("unexpected v3 root: %#v", resolved)
	}
	if resolved.V3Coherence == nil || resolved.V3Coherence.InitialCursor != nil {
		t.Fatalf("genesis contract serialized an invalid cursor: %#v", resolved.V3Coherence)
	}
}

func TestV3DataPlaneOpenCloseOperationZeroKeepsReplayButNoPublicationTicket(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	lookupAny, errno := d.dispatch(context.Background(), 0, &pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("file")})
	if errno != 0 {
		t.Fatalf("lookup errno=%d", errno)
	}
	file := lookupAny.(*pfslocal.LookupReply).Attr.Item
	openedAny, errno := d.dispatch(context.Background(), 0, &pfslocal.OpenRequest{Item: file, Mode: pfslocal.OpenModeReadWrite})
	if errno != 0 {
		t.Fatalf("open errno=%d", errno)
	}
	handle := openedAny.(*pfslocal.OpenReply).Handle
	d.bridge.mu.Lock()
	ticketsAfterOpen := len(d.bridge.operations)
	d.bridge.mu.Unlock()
	if ticketsAfterOpen != 0 {
		t.Fatalf("non-visible open created %d publication tickets", ticketsAfterOpen)
	}
	closedAny, errno := d.dispatch(context.Background(), 0, &pfslocal.CloseRequest{Handle: handle})
	if errno != 0 || !closedAny.(*pfslocal.CloseReply).Retired {
		t.Fatalf("close=(%#v,%d)", closedAny, errno)
	}
}

func TestV3DataPlaneRegistersPublishingMutationBeforeSourcePrepare(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	lookupAny, errno := d.dispatch(context.Background(), 0, &pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("file")})
	if errno != 0 {
		t.Fatal(errno)
	}
	file := lookupAny.(*pfslocal.LookupReply).Attr.Item
	openedAny, errno := d.dispatch(context.Background(), 0, &pfslocal.OpenRequest{Item: file, Mode: pfslocal.OpenModeReadWrite})
	if errno != 0 {
		t.Fatal(errno)
	}
	handle := openedAny.(*pfslocal.OpenReply).Handle
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetWrite() == nil {
			return nil, errors.New("expected write")
		}
		client.next <- v3VisibilityResult{event: &authoritypb.VisibilityEvent{
			Cursor:             &authoritypb.VisibilityCursor{Sequence: 1, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE},
			InitiatorSessionId: client.session, MutationSlot: identity.Slot, MutationSequence: identity.Sequence,
			Targets: []*authoritypb.VisibilityTarget{visibilitywire.Data(bytes.Repeat([]byte{0x40}, 16), 2, 0x700000001, 3)},
		}}
		pending, err := d.bridge.next(context.Background())
		if err != nil {
			return nil, err
		}
		if pending.event.LocalOperationID != 77 {
			return nil, errors.New("source PREPARE arrived before exact local assignment")
		}
		return &authoritypb.Response{Mutation: &authoritypb.MutationState{Slot: identity.Slot, AcceptedSequence: identity.Sequence}, Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{Count: 3}}, PostAttr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: 2, Size: 3, Nlink: 1}}, nil
	}
	replyAny, errno := d.dispatch(context.Background(), 77, &pfslocal.WriteRequest{Handle: handle, Data: []byte("abc")})
	if errno != 0 || replyAny.(*pfslocal.WriteReply).Written != 3 {
		t.Fatalf("write=(%#v,%d)", replyAny, errno)
	}
}

func TestV3DataPlaneCreatePublishesItsExactNamespaceOperation(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		create := request.GetCreate()
		if create == nil || !bytes.Equal(create.GetName(), []byte("new")) {
			return nil, errors.New("expected create")
		}
		client.next <- v3VisibilityResult{event: &authoritypb.VisibilityEvent{
			Cursor:             &authoritypb.VisibilityCursor{Sequence: 1, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE},
			InitiatorSessionId: client.session,
			MutationSlot:       identity.Slot,
			MutationSequence:   identity.Sequence,
			Targets: []*authoritypb.VisibilityTarget{
				visibilitywire.Namespace(bytes.Repeat([]byte{0x20}, 16), []byte("new"), 1, 0x700000001),
			},
		}}
		pending, err := d.bridge.next(context.Background())
		if err != nil {
			return nil, err
		}
		if pending.event.LocalOperationID != 88 {
			return nil, errors.New("source namespace PREPARE lost its exact create operation")
		}
		return &authoritypb.Response{
			Mutation: &authoritypb.MutationState{Slot: identity.Slot, AcceptedSequence: identity.Sequence},
			Body: &authoritypb.Response_Create{Create: &authoritypb.CreateReply{
				Item:   authorityTestItem(3, authoritypb.Attr_REGULAR, 0x61, 0x62),
				Handle: bytes.Repeat([]byte{0x63}, 16),
			}},
		}, nil
	}
	replyAny, errno := d.dispatch(context.Background(), 88, &pfslocal.CreateRequest{
		Dir: d.resolveReply().Root, Name: []byte("new"), Mode: 0o644, Exclusive: true,
	})
	if errno != 0 {
		t.Fatalf("create errno=%d", errno)
	}
	reply := replyAny.(*pfslocal.CreateReply)
	if reply.Handle == 0 || reply.Attr.Item.StableIdentity != ([16]byte{0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62}) {
		t.Fatalf("unexpected create reply: %#v", reply)
	}
}

func TestV3DataPlaneSyncVolumeUsesExactAuthorityBarrier(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	var sawSync bool
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		sawSync = request.GetSyncFs() != nil
		return &authoritypb.Response{Mutation: &authoritypb.MutationState{Slot: identity.Slot, AcceptedSequence: identity.Sequence}, Body: &authoritypb.Response_SyncFs{SyncFs: &authoritypb.SyncFSReply{}}}, nil
	}
	reply, errno := d.dispatch(context.Background(), 0, &pfslocal.SyncVolumeRequest{})
	if errno != 0 || !sawSync || reply.(*pfslocal.SyncVolumeReply).Degraded {
		t.Fatalf("sync=(%#v,%d) saw=%v", reply, errno, sawSync)
	}
}

func TestV3CookieTableRetiresConsumedPositionsAndBoundsStaleSeeks(t *testing.T) {
	d := testV3DataPlane(t, newFakeV3DataClient())
	verifier := bytes.Repeat([]byte{0x71}, 16)
	first, _ := d.issueCookie(v3CookieRecord{dirID: v3RootItemID, cookie: []byte{1}, verifier: verifier})
	second, _ := d.issueCookie(v3CookieRecord{dirID: v3RootItemID, cookie: []byte{2}, verifier: verifier})
	third, _ := d.issueCookie(v3CookieRecord{dirID: v3RootItemID, cookie: []byte{3}, verifier: verifier})
	otherVerifier, _ := d.issueCookie(v3CookieRecord{dirID: v3RootItemID, cookie: []byte{4}, verifier: bytes.Repeat([]byte{0x72}, 16)})
	position, ok := d.consumeCookie(v3RootItemID, second)
	if !ok || !bytes.Equal(position.cookie, []byte{2}) {
		t.Fatalf("consume second=(%#v,%v)", position, ok)
	}
	d.mu.Lock()
	_, firstPresent := d.cookies[first]
	_, secondPresent := d.cookies[second]
	_, thirdPresent := d.cookies[third]
	_, otherPresent := d.cookies[otherVerifier]
	d.mu.Unlock()
	if firstPresent || secondPresent || !thirdPresent || !otherPresent {
		t.Fatalf("retirement first=%v second=%v third=%v other=%v", firstPresent, secondPresent, thirdPresent, otherPresent)
	}

	// Start a clean table, fill it to the hard bound, and force one eviction.
	d.mu.Lock()
	d.cookies = make(map[uint64]v3CookieRecord)
	d.mu.Unlock()
	var oldest uint64
	for i := 0; i < v3MaxCookies+1; i++ {
		cookie, err := d.issueCookie(v3CookieRecord{dirID: v3RootItemID, cookie: []byte{byte(i + 1)}, verifier: verifier})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			oldest = cookie
		}
	}
	d.mu.Lock()
	bounded := len(d.cookies)
	d.mu.Unlock()
	if bounded != v3MaxCookies {
		t.Fatalf("cookie table size=%d, want %d", bounded, v3MaxCookies)
	}
	if _, errno := d.enumerate(context.Background(), 0, &pfslocal.EnumerateRequest{Dir: d.resolveReply().Root, Cookie: oldest, MaxEntries: 1}); errno != darwinESTALE {
		t.Fatalf("evicted cookie errno=%d, want %d", errno, darwinESTALE)
	}
}

func TestV3EnumerateClosesHiddenHandleWithIndependentBoundedContext(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	callerCtx, cancelCaller := context.WithCancel(context.Background())
	closeCalled := false
	client.mutation = func(ctx context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		response := &authoritypb.Response{Mutation: &authoritypb.MutationState{Slot: identity.Slot, AcceptedSequence: identity.Sequence}}
		switch request.GetBody().(type) {
		case *authoritypb.Request_Open:
			response.Body = &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: bytes.Repeat([]byte{0x73}, 16)}}
		case *authoritypb.Request_ReadDir:
			cancelCaller()
			response.Body = &authoritypb.Response_ReadDir{ReadDir: &authoritypb.ReadDirReply{Verifier: bytes.Repeat([]byte{0x74}, 16), Eof: true}}
		case *authoritypb.Request_Close:
			closeCalled = true
			if ctx.Err() != nil {
				return nil, errors.New("hidden close inherited canceled caller context")
			}
			deadline, ok := ctx.Deadline()
			if !ok || !deadline.After(time.Now()) || time.Until(deadline) > v3KeepAliveInterval(client.lease, client.budget) {
				return nil, errors.New("hidden close did not receive its bounded cleanup deadline")
			}
		default:
			return nil, errors.New("unexpected enumeration mutation")
		}
		return response, nil
	}
	reply, errno := d.enumerate(callerCtx, 0, &pfslocal.EnumerateRequest{Dir: d.resolveReply().Root, MaxEntries: 1})
	if errno != 0 || reply == nil || !closeCalled || callerCtx.Err() != context.Canceled {
		t.Fatalf("enumerate=(%#v,%d) close=%v caller=%v", reply, errno, closeCalled, callerCtx.Err())
	}
}

func TestV3DataPlaneReadRejectsUnframeableAllocation(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	_, errno := d.read(context.Background(), &pfslocal.ReadRequest{Handle: 1, Length: v3MaxLocalRead + 1})
	if errno != darwinEOVERFLOW {
		t.Fatalf("oversized read errno=%d, want %d", errno, darwinEOVERFLOW)
	}
}

func TestV3LivenessBypassesSaturatedOperationsAndProvesExactSession(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	for range cap(d.ops) {
		d.ops <- struct{}{}
	}
	defer func() {
		for range cap(d.ops) {
			<-d.ops
		}
	}()

	request := &pfslocal.V3LivenessRequest{
		AuthorityEpoch: client.Epoch(),
		SessionID:      client.SessionID(),
	}
	replyAny, errno := d.dispatch(context.Background(), 0, request)
	if errno != 0 {
		t.Fatalf("liveness errno=%d", errno)
	}
	reply := replyAny.(*pfslocal.V3LivenessReply)
	if !bytes.Equal(reply.AuthorityEpoch, request.AuthorityEpoch) || !bytes.Equal(reply.SessionID, request.SessionID) {
		t.Fatalf("liveness reply=%#v, want exact authority identity", reply)
	}

	bad := *request
	bad.SessionID = bytes.Repeat([]byte{0xff}, 16)
	if _, errno := d.dispatch(context.Background(), 0, &bad); errno != darwinEINVAL {
		t.Fatalf("mismatched session errno=%d, want %d", errno, darwinEINVAL)
	}
}

func TestV3LivenessAuthorityFailureIsTerminal(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	client.keepErr = errors.New("authority unreachable")
	_, errno := d.dispatch(context.Background(), 0, &pfslocal.V3LivenessRequest{
		AuthorityEpoch: client.Epoch(), SessionID: client.SessionID(),
	})
	if errno != darwinEIO {
		t.Fatalf("failed liveness errno=%d, want %d", errno, darwinEIO)
	}
	select {
	case <-d.ctx.Done():
	default:
		t.Fatal("failed on-demand liveness did not terminate data plane")
	}
}

func TestV3KeepAliveIntervalAndFailureAreTerminal(t *testing.T) {
	if got := v3KeepAliveInterval(9*time.Second, time.Minute); got != 3*time.Second {
		t.Fatalf("lease interval=%s", got)
	}
	if got := v3KeepAliveInterval(time.Minute, 12*time.Second); got != 4*time.Second {
		t.Fatalf("repair interval=%s", got)
	}
	client := newFakeV3DataClient()
	client.lease = 6 * time.Millisecond
	client.budget = 6 * time.Millisecond
	client.keepErr = errors.New("fenced")
	d := testV3DataPlane(t, client)
	select {
	case <-d.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("keepalive failure did not terminate v3 data plane")
	}
}

func TestLinuxToDarwinErrnoTranslation(t *testing.T) {
	for linux, darwin := range map[int32]int32{errnos.EAGAIN: darwinEAGAIN, errnos.ENAMETOOLONG: darwinENAMETOOLONG, errnos.ENOTEMPTY: darwinENOTEMPTY, errnos.ELOOP: darwinELOOP, errnos.ENODATA: darwinENOATTR, errnos.EOVERFLOW: darwinEOVERFLOW, errnos.EOPNOTSUPP: darwinENOTSUP, errnos.ETIMEDOUT: darwinETIMEDOUT, errnos.ESTALE: darwinESTALE, errnos.EDQUOT: darwinEDQUOT} {
		if got := linuxToDarwin(linux); got != darwin {
			t.Fatalf("linux errno %d -> %d, want %d", linux, got, darwin)
		}
	}
}
