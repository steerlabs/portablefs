package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"math"
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
	case *authoritypb.Request_Lookup:
		response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: authorityTestItem(2, authoritypb.Attr_REGULAR, 0x30, 0x40)}}
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

func collectTestItem(
	t *testing.T,
	d *v3DataPlane,
	collector *v3ReplyResourceCollector,
	candidate *authoritypb.Item,
) *v3ItemRecord {
	t.Helper()
	ctx := context.WithValue(context.Background(), v3ReplyResourceContextKey{}, collector)
	root := d.resolveReply().Root
	record, errno := d.intern(ctx, candidate, &root)
	if errno != 0 {
		t.Fatalf("intern errno=%d", errno)
	}
	collectV3ReplyItem(ctx, record)
	if collector.err != nil {
		t.Fatal(collector.err)
	}
	return record
}

func exactTestMutationReply(identity authorityrpc.MutationIdentity) *authoritypb.Response {
	return &authoritypb.Response{Mutation: &authoritypb.MutationState{
		Slot: identity.Slot, AcceptedSequence: identity.Sequence,
	}}
}

func TestV3ReplyDispositionSeparatesCreateHandleFromPublishedItem(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	collector := &v3ReplyResourceCollector{d: d, visible: true}
	record := collectTestItem(t, d, collector, authorityTestItem(2, authoritypb.Attr_REGULAR, 0x31, 0x41))
	handle, err := d.installHandle(bytes.Repeat([]byte{0x51}, 16), record.item.ItemID, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), v3ReplyResourceContextKey{}, collector)
	collectV3ReplyHandle(ctx, handle)
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}

	// The item reached FSKit, but VolumeCore rejected/closed the returned open
	// handle. This is a valid split verdict and must not fence the mount.
	cleanup, err := d.applyReplyResourceDisposition(resources, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup.terminalReason != nil || len(cleanup.items) != 0 || len(cleanup.handles) != 1 {
		t.Fatalf("split cleanup=%+v", cleanup)
	}
	d.mu.Lock()
	accepted := record.accepted
	_, itemLive := d.itemsByID[record.item.ItemID]
	_, handleLive := d.handles[handle.id]
	d.mu.Unlock()
	if !accepted || !itemLive || handleLive {
		t.Fatalf("accepted=%t itemLive=%t handleLive=%t", accepted, itemLive, handleLive)
	}
}

func TestV3VisibleReplyMissingPublishedItemIsTerminal(t *testing.T) {
	d := testV3DataPlane(t, newFakeV3DataClient())
	collector := &v3ReplyResourceCollector{d: d, visible: true}
	_ = collectTestItem(t, d, collector, authorityTestItem(2, authoritypb.Attr_DIRECTORY, 0x32, 0x42))
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := d.applyReplyResourceDisposition(resources, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup.terminalReason == nil || !cleanup.required() || len(cleanup.items) != 1 {
		t.Fatalf("visible abandon cleanup=%+v", cleanup)
	}
	if d.terminalError() == nil {
		t.Fatal("visible item abandonment was not terminal before disposition returned")
	}
}

func TestV3OverlappingItemRepliesCannotReclaimEachOther(t *testing.T) {
	d := testV3DataPlane(t, newFakeV3DataClient())
	candidate := authorityTestItem(2, authoritypb.Attr_REGULAR, 0x33, 0x43)
	first := &v3ReplyResourceCollector{d: d}
	record := collectTestItem(t, d, first, candidate)
	second := &v3ReplyResourceCollector{d: d}
	if same := collectTestItem(t, d, second, candidate); same != record {
		t.Fatal("same authority identity did not intern to one local item")
	}
	firstResources, err := d.prepareReplyResources(first)
	if err != nil {
		t.Fatal(err)
	}
	secondResources, err := d.prepareReplyResources(second)
	if err != nil {
		t.Fatal(err)
	}
	firstCleanup, err := d.applyReplyResourceDisposition(firstResources, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if firstCleanup.required() {
		t.Fatalf("first abandon reclaimed overlapping item: %+v", firstCleanup)
	}
	secondCleanup, err := d.applyReplyResourceDisposition(secondResources, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	if secondCleanup.required() {
		t.Fatalf("second accept unexpectedly cleaned resources: %+v", secondCleanup)
	}
	d.mu.Lock()
	live := d.itemsByID[record.item.ItemID] == record && record.accepted && record.provisional == 0
	d.mu.Unlock()
	if !live {
		t.Fatal("accepted overlapping reply did not retain the shared item")
	}
}

func TestV3ItemPrefixCountsDuplicateHardLinkOccurrences(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	var reclaims int
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetReclaim() != nil {
			reclaims++
		}
		return exactTestMutationReply(identity), nil
	}

	acceptedCollector := &v3ReplyResourceCollector{d: d}
	record := collectTestItem(t, d, acceptedCollector, authorityTestItem(2, authoritypb.Attr_REGULAR, 0x34, 0x44))
	ctx := context.WithValue(context.Background(), v3ReplyResourceContextKey{}, acceptedCollector)
	collectV3ReplyItem(ctx, record)
	acceptedResources, err := d.prepareReplyResources(acceptedCollector)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := d.applyReplyResourceDisposition(acceptedResources, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup.required() || !record.accepted || record.provisional != 0 {
		t.Fatalf("accepted duplicate prefix cleanup=%+v record=%+v", cleanup, record)
	}

	abandonedCollector := &v3ReplyResourceCollector{d: d}
	abandoned := collectTestItem(t, d, abandonedCollector, authorityTestItem(3, authoritypb.Attr_REGULAR, 0x35, 0x45))
	ctx = context.WithValue(context.Background(), v3ReplyResourceContextKey{}, abandonedCollector)
	collectV3ReplyItem(ctx, abandoned)
	abandonedResources, err := d.prepareReplyResources(abandonedCollector)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err = d.applyReplyResourceDisposition(abandonedResources, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cleanup.items) != 1 {
		t.Fatalf("duplicate abandon queued %d reclaims, want one", len(cleanup.items))
	}
	if err := cleanup.finish(); err != nil {
		t.Fatal(err)
	}
	if reclaims != 1 {
		t.Fatalf("authority reclaims=%d, want one", reclaims)
	}
}

func TestV3ReclaimWaitsForOverlappingItemDisposition(t *testing.T) {
	d := testV3DataPlane(t, newFakeV3DataClient())
	collector := &v3ReplyResourceCollector{d: d}
	record := collectTestItem(t, d, collector, authorityTestItem(2, authoritypb.Attr_REGULAR, 0x36, 0x46))
	d.mu.Lock()
	record.accepted = true
	d.mu.Unlock()
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	if _, errno := d.reclaim(context.Background(), &pfslocal.ReclaimRequest{Item: record.item}); errno != 0 {
		t.Fatalf("reclaim errno=%d", errno)
	}
	d.mu.Lock()
	deferred := !record.accepted && record.provisional == 1 && d.itemsByID[record.item.ItemID] == record
	d.mu.Unlock()
	if !deferred {
		t.Fatal("reclaim did not defer authority retirement to the overlapping reply")
	}
	cleanup, err := d.applyReplyResourceDisposition(resources, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup.required() || !record.accepted || record.provisional != 0 {
		t.Fatal("overlapping accept did not restore item ownership")
	}
}

func TestV3FrontendDisconnectAbandonsProvisionalOpen(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	var closes int
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetClose() != nil {
			closes++
		}
		return exactTestMutationReply(identity), nil
	}
	root := d.resolveReply().Root
	record, errno := d.intern(context.Background(), authorityTestItem(2, authoritypb.Attr_REGULAR, 0x37, 0x47), &root)
	if errno != 0 {
		t.Fatalf("intern errno=%d", errno)
	}
	handle, err := d.installHandle(bytes.Repeat([]byte{0x57}, 16), record.item.ItemID, false)
	if err != nil {
		t.Fatal(err)
	}
	collector := &v3ReplyResourceCollector{d: d}
	ctx := context.WithValue(context.Background(), v3ReplyResourceContextKey{}, collector)
	collectV3ReplyHandle(ctx, handle)
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	c := &frontendConn{}
	if !c.registerProvisionalResource(91, resources) {
		t.Fatal("failed to register provisional Open reply")
	}
	cleanups := c.abandonProvisionalResources()
	if len(cleanups) != 1 || !c.resourceClosed || c.provisional != nil {
		t.Fatalf("disconnect cleanups=%d closed=%t table=%v", len(cleanups), c.resourceClosed, c.provisional)
	}
	d.mu.Lock()
	_, live := d.handles[handle.id]
	d.mu.Unlock()
	if live {
		t.Fatal("disconnect left provisional handle locally reachable")
	}
	if err := cleanups[0].finish(); err != nil {
		t.Fatal(err)
	}
	if closes != 1 {
		t.Fatalf("authority closes=%d, want one", closes)
	}
}

func TestV3PostInternReplyBuildFailureRollsBackCollectedItem(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetLookup() == nil {
			return nil, errors.New("expected lookup")
		}
		item := authorityTestItem(2, authoritypb.Attr_REGULAR, 0x38, 0x48)
		item.Attr.Blocks = math.MaxUint64/512 + 1 // accepted by intern, rejected by localAttr
		response := exactTestMutationReply(identity)
		response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: item}}
		return response, nil
	}
	collector := &v3ReplyResourceCollector{d: d}
	ctx := context.WithValue(context.Background(), v3ReplyResourceContextKey{}, collector)
	if _, errno := d.lookup(ctx, &pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("bad-attr")}); errno != darwinEIO {
		t.Fatalf("lookup errno=%d, want %d", errno, darwinEIO)
	}
	if len(collector.items) != 1 || collector.items[0].provisional != 1 {
		t.Fatalf("collector did not retain post-intern item: %+v", collector)
	}
	itemID := collector.items[0].item.ItemID
	cleanup, err := d.abandonCollectedReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup == nil || len(cleanup.items) != 1 {
		t.Fatalf("rollback cleanup=%+v", cleanup)
	}
	d.mu.Lock()
	_, live := d.itemsByID[itemID]
	d.mu.Unlock()
	if live {
		t.Fatal("post-intern reply-build failure left item locally reachable")
	}
}

func TestV3RegistrationRaceSynchronouslyAbandonsOpen(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	var closes int
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetClose() != nil {
			closes++
		}
		return exactTestMutationReply(identity), nil
	}
	root := d.resolveReply().Root
	record, errno := d.intern(context.Background(), authorityTestItem(2, authoritypb.Attr_REGULAR, 0x39, 0x49), &root)
	if errno != 0 {
		t.Fatalf("intern errno=%d", errno)
	}
	handle, err := d.installHandle(bytes.Repeat([]byte{0x59}, 16), record.item.ItemID, false)
	if err != nil {
		t.Fatal(err)
	}
	collector := &v3ReplyResourceCollector{d: d}
	ctx := context.WithValue(context.Background(), v3ReplyResourceContextKey{}, collector)
	collectV3ReplyHandle(ctx, handle)
	resources, err := d.prepareReplyResources(collector)
	if err != nil {
		t.Fatal(err)
	}
	c := &frontendConn{resourceClosed: true}
	cleanup, registered, err := c.registerProvisionalResourceOrAbandon(97, resources)
	if err != nil {
		t.Fatal(err)
	}
	if registered || cleanup == nil || len(cleanup.handles) != 1 {
		t.Fatalf("registration race registered=%t cleanup=%+v", registered, cleanup)
	}
	d.mu.Lock()
	_, live := d.handles[handle.id]
	d.mu.Unlock()
	if live {
		t.Fatal("failed registration left Open handle locally reachable")
	}
	if err := cleanup.finish(); err != nil {
		t.Fatal(err)
	}
	if closes != 1 {
		t.Fatalf("authority closes=%d, want one", closes)
	}
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
	// Xattrs advertises the operation family; XattrSetSupported separately
	// prevents the macOS frontend from entering ordered mutation machinery for
	// the production authority's deliberately unsupported write surface.
	if !resolved.Capabilities.Xattrs || resolved.Capabilities.XattrSetSupported {
		t.Fatalf("v3 resolve xattr capabilities = %+v", resolved.Capabilities)
	}
}

func TestV3DataPlaneItemIdentifiersStopAtTheRepairPartition(t *testing.T) {
	if v3RepairItemFloor != uint64(1)<<63 {
		t.Fatalf("repair item floor=%#x, want the high-half boundary", v3RepairItemFloor)
	}
	d := testV3DataPlane(t, newFakeV3DataClient())
	d.mu.Lock()
	d.nextItemID = v3RepairItemFloor - 1
	d.mu.Unlock()

	last, errno := d.intern(
		context.Background(),
		authorityTestItem(2, authoritypb.Attr_REGULAR, 0x31, 0x41),
		&d.resolveReply().Root,
	)
	if errno != 0 || last.item.ItemID != v3RepairItemFloor-1 {
		t.Fatalf("last daemon item=(%#v,%d)", last, errno)
	}
	if _, errno := d.intern(
		context.Background(),
		authorityTestItem(3, authoritypb.Attr_REGULAR, 0x32, 0x42),
		&d.resolveReply().Root,
	); errno != darwinEIO {
		t.Fatalf("first repair-partition item errno=%d, want %d", errno, darwinEIO)
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
		if request.GetFrontendOperationId() != 77 {
			return nil, errors.New("write lost its pfslocal frontend operation identity")
		}
		if !request.GetSourcePhaseQueueable() {
			return nil, errors.New("write lost its source-phase queueability proof")
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
	replyAny, errno := d.dispatchFrontend(
		context.Background(), 77, true,
		&pfslocal.WriteRequest{Handle: handle, Data: []byte("abc")},
	)
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

func TestV3CookieTableKeepsResumptionReusableAndBoundsStaleSeeks(t *testing.T) {
	d := testV3DataPlane(t, newFakeV3DataClient())
	verifier := bytes.Repeat([]byte{0x71}, 16)
	const handleID = 41
	firstWalk, err := d.issueCookieBatch([]v3CookieRecord{
		{dirID: v3RootItemID, handleID: handleID, cookie: []byte{1}, verifier: verifier},
		{dirID: v3RootItemID, handleID: handleID, cookie: []byte{2}, verifier: verifier},
		{dirID: v3RootItemID, handleID: handleID, cookie: []byte{3}, verifier: verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	concurrentWalk, err := d.issueCookieBatch([]v3CookieRecord{
		{dirID: v3RootItemID, handleID: handleID, cookie: []byte{4}, verifier: verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	otherVerifier, err := d.issueCookieBatch([]v3CookieRecord{
		{dirID: v3RootItemID, handleID: handleID, cookie: []byte{5}, verifier: bytes.Repeat([]byte{0x72}, 16)},
	})
	if err != nil {
		t.Fatal(err)
	}
	position, ok := d.resolveCookie(v3RootItemID, handleID, firstWalk[1])
	if !ok || !bytes.Equal(position.cookie, []byte{2}) {
		t.Fatalf("resolve second=(%#v,%v)", position, ok)
	}
	// A continuation is a reusable seek handle. FSKit may present it again
	// after the extension used it to prefetch a page that did not fit in the
	// current kernel buffer.
	position, ok = d.resolveCookie(v3RootItemID, handleID, firstWalk[1])
	if !ok || !bytes.Equal(position.cookie, []byte{2}) {
		t.Fatalf("repeat resolve second=(%#v,%v)", position, ok)
	}
	if _, ok := d.resolveCookie(v3RootItemID, handleID+1, firstWalk[1]); ok {
		t.Fatal("cookie crossed into another open of the same directory")
	}
	d.mu.Lock()
	_, firstPresent := d.cookies[firstWalk[0]]
	_, secondPresent := d.cookies[firstWalk[1]]
	_, thirdPresent := d.cookies[firstWalk[2]]
	_, concurrentPresent := d.cookies[concurrentWalk[0]]
	_, otherPresent := d.cookies[otherVerifier[0]]
	d.mu.Unlock()
	if !firstPresent || !secondPresent || !thirdPresent || !concurrentPresent || !otherPresent {
		t.Fatalf("reusable first=%v second=%v third=%v concurrent=%v other=%v", firstPresent, secondPresent, thirdPresent, concurrentPresent, otherPresent)
	}

	// Start a clean table, fill it to the hard bound with whole pages, then
	// prove capacity pressure evicts one complete oldest page atomically.
	d.mu.Lock()
	d.cookies = make(map[uint64]v3CookieRecord)
	d.cookieBatches = make(map[uint64]*v3CookieBatch)
	d.cookieOrder.Init()
	d.mu.Unlock()
	const pageSize = 256
	var oldest []uint64
	page := make([]v3CookieRecord, pageSize)
	for i := range page {
		page[i] = v3CookieRecord{dirID: v3RootItemID, handleID: handleID, cookie: []byte{byte(i + 1)}, verifier: verifier}
	}
	for i := 0; i < v3MaxCookies/pageSize; i++ {
		cookies, err := d.issueCookieBatch(page)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			oldest = cookies
		}
	}
	newest, err := d.issueCookieBatch([]v3CookieRecord{
		{dirID: v3RootItemID, handleID: handleID, cookie: []byte{0x81}, verifier: verifier},
		{dirID: v3RootItemID, handleID: handleID, cookie: []byte{0x82}, verifier: verifier},
		{dirID: v3RootItemID, handleID: handleID, cookie: []byte{0x83}, verifier: verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	bounded := len(d.cookies)
	batchCount := len(d.cookieBatches)
	d.mu.Unlock()
	if bounded != v3MaxCookies-pageSize+len(newest) || batchCount != v3MaxCookies/pageSize {
		t.Fatalf("cookie table size=%d batches=%d after whole-page eviction", bounded, batchCount)
	}
	for _, cookie := range oldest {
		if _, ok := d.resolveCookie(v3RootItemID, handleID, cookie); ok {
			t.Fatalf("oldest page cookie %#x survived whole-page eviction", cookie)
		}
	}
	if _, ok := d.resolveCookie(v3RootItemID, handleID, newest[1]); !ok {
		t.Fatal("newest page was damaged by oldest-page eviction")
	}
}

func TestV3EnumerateAssignsIndependentBatchesToConcurrentWalks(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	retained, err := d.installHandle(bytes.Repeat([]byte{0x76}, 16), v3RootItemID, false)
	if err != nil {
		t.Fatal(err)
	}
	verifier := bytes.Repeat([]byte{0x75}, 16)
	var authorityCookies [][]byte
	entries := make([]*authoritypb.Dirent, 3)
	for index := range entries {
		item := authorityTestItem(
			uint64(index+10),
			authoritypb.Attr_REGULAR,
			byte(0x80+index),
			byte(0x90+index),
		)
		entries[index] = &authoritypb.Dirent{
			Name: []byte{byte('a' + index)}, Attr: item.Attr, Item: item,
			NextCookie: []byte{byte(index + 1)},
		}
	}
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		response := &authoritypb.Response{Mutation: &authoritypb.MutationState{
			Slot: identity.Slot, AcceptedSequence: identity.Sequence,
		}}
		switch request.GetBody().(type) {
		case *authoritypb.Request_Open:
			response.Body = &authoritypb.Response_Open{Open: &authoritypb.OpenReply{
				Handle: bytes.Repeat([]byte{0x76}, 16),
			}}
		case *authoritypb.Request_ReadDir:
			authorityCookies = append(authorityCookies, cloneBytesV3(request.GetReadDir().GetCookie()))
			response.Body = &authoritypb.Response_ReadDir{ReadDir: &authoritypb.ReadDirReply{
				Entries: entries, Verifier: verifier, Eof: true,
			}}
		case *authoritypb.Request_Close:
		default:
			return nil, errors.New("unexpected enumeration mutation")
		}
		return response, nil
	}

	firstAny, errno := d.enumerate(context.Background(), 0, &pfslocal.EnumerateRequest{
		Dir: d.resolveReply().Root, Handle: retained.id, MaxEntries: 3,
	})
	if errno != 0 {
		t.Fatalf("first enumerate errno=%d", errno)
	}
	secondAny, errno := d.enumerate(context.Background(), 0, &pfslocal.EnumerateRequest{
		Dir: d.resolveReply().Root, Handle: retained.id, MaxEntries: 3,
	})
	if errno != 0 {
		t.Fatalf("second enumerate errno=%d", errno)
	}
	first := firstAny.(*pfslocal.EnumerateReply)
	second := secondAny.(*pfslocal.EnumerateReply)
	if len(first.Entries) != 3 || len(second.Entries) != 3 {
		t.Fatalf("enumerate entry counts=(%d,%d)", len(first.Entries), len(second.Entries))
	}
	if first.NextCookie != 0 || first.Entries[len(first.Entries)-1].Cookie != 0 ||
		second.NextCookie != 0 || second.Entries[len(second.Entries)-1].Cookie != 0 {
		t.Fatalf("EOF cookies first=%#v second=%#v", first, second)
	}
	if _, ok := d.resolveCookie(v3RootItemID, retained.id, first.Entries[1].Cookie); !ok {
		t.Fatal("first walk continuation was not resolvable")
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, errno := d.enumerate(context.Background(), 0, &pfslocal.EnumerateRequest{
			Dir: d.resolveReply().Root, Handle: retained.id,
			Cookie: first.Entries[1].Cookie, MaxEntries: 3,
		}); errno != 0 {
			t.Fatalf("repeat page-boundary continuation %d errno=%d", attempt+1, errno)
		}
	}
	if len(authorityCookies) != 4 || !bytes.Equal(authorityCookies[2], []byte{2}) ||
		!bytes.Equal(authorityCookies[3], []byte{2}) {
		t.Fatalf("authority resumptions=%x, want the same page-one position twice", authorityCookies)
	}
	if _, ok := d.resolveCookie(v3RootItemID, retained.id, second.Entries[1].Cookie); !ok {
		t.Fatal("first walk invalidated the concurrent walk's page")
	}
	otherHandle, err := d.installHandle(bytes.Repeat([]byte{0x79}, 16), v3RootItemID, false)
	if err != nil {
		t.Fatal(err)
	}
	otherCookies, err := d.issueCookieBatch([]v3CookieRecord{{
		dirID: v3RootItemID, handleID: otherHandle.id,
		cookie: []byte{0x7a}, verifier: verifier,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, errno := d.closeHandle(context.Background(), 0, &pfslocal.CloseRequest{Handle: retained.id}); errno != 0 {
		t.Fatalf("close retained enumeration handle errno=%d", errno)
	}
	if _, ok := d.resolveCookie(v3RootItemID, retained.id, first.Entries[1].Cookie); ok {
		t.Fatal("closed handle retained its cookie batches")
	}
	if _, ok := d.resolveCookie(v3RootItemID, otherHandle.id, otherCookies[0]); !ok {
		t.Fatal("closing one handle purged another handle's cookie batch")
	}
}

func TestV3EnumerateMarksLastEmittedEntryTerminalPastOpaqueEOFTail(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	retained, err := d.installHandle(bytes.Repeat([]byte{0x78}, 16), v3RootItemID, false)
	if err != nil {
		t.Fatal(err)
	}
	verifier := bytes.Repeat([]byte{0x77}, 16)
	visible := authorityTestItem(10, authoritypb.Attr_REGULAR, 0x91, 0xa1)
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		response := &authoritypb.Response{Mutation: &authoritypb.MutationState{
			Slot: identity.Slot, AcceptedSequence: identity.Sequence,
		}}
		switch request.GetBody().(type) {
		case *authoritypb.Request_Open:
			response.Body = &authoritypb.Response_Open{Open: &authoritypb.OpenReply{
				Handle: bytes.Repeat([]byte{0x78}, 16),
			}}
		case *authoritypb.Request_ReadDir:
			response.Body = &authoritypb.Response_ReadDir{ReadDir: &authoritypb.ReadDirReply{
				Entries: []*authoritypb.Dirent{
					{Name: []byte("visible"), Attr: visible.Attr, Item: visible, NextCookie: []byte{1}},
					{Name: []byte("opaque"), Attr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR}, NextCookie: []byte{2}},
				},
				Verifier: verifier, Eof: true,
			}}
		case *authoritypb.Request_Close:
		default:
			return nil, errors.New("unexpected enumeration mutation")
		}
		return response, nil
	}

	replyAny, errno := d.enumerate(context.Background(), 0, &pfslocal.EnumerateRequest{
		Dir: d.resolveReply().Root, Handle: retained.id, MaxEntries: 2,
	})
	if errno != 0 {
		t.Fatalf("enumerate errno=%d", errno)
	}
	reply := replyAny.(*pfslocal.EnumerateReply)
	if len(reply.Entries) != 1 || reply.Entries[0].Cookie != 0 || reply.NextCookie != 0 {
		t.Fatalf("opaque EOF tail reply=%#v", reply)
	}
}

func TestV3CookieIdentifiersNeverIssueTheSwiftTerminalMarkerOrWrap(t *testing.T) {
	if v3CookieFloor != uint64(1)<<63 {
		t.Fatalf("cookie floor=%#x, want the Swift daemon-cookie marker", v3CookieFloor)
	}
	position := v3CookieRecord{
		dirID: v3RootItemID, handleID: 1, cookie: []byte{1}, verifier: bytes.Repeat([]byte{2}, 16),
	}

	d := testV3DataPlane(t, newFakeV3DataClient())
	d.mu.Lock()
	d.nextCookieID = math.MaxUint64 - 1
	d.mu.Unlock()
	last, err := d.issueCookieBatch([]v3CookieRecord{position})
	if err != nil || len(last) != 1 || last[0] != math.MaxUint64-1 {
		t.Fatalf("last cookie=(%v,%v)", last, err)
	}
	if issued, err := d.issueCookieBatch([]v3CookieRecord{position}); err == nil || issued != nil {
		t.Fatalf("terminal cookie marker was issued: (%v,%v)", issued, err)
	}

	d = testV3DataPlane(t, newFakeV3DataClient())
	d.mu.Lock()
	d.nextCookieBatch = math.MaxUint64 - 1
	d.mu.Unlock()
	if _, err := d.issueCookieBatch([]v3CookieRecord{position}); err != nil {
		t.Fatalf("last batch ID was refused: %v", err)
	}
	if issued, err := d.issueCookieBatch([]v3CookieRecord{position}); err == nil || issued != nil {
		t.Fatalf("batch identifier wrapped: (%v,%v)", issued, err)
	}
}

func TestV3EnumerateUsesTheRetainedDirectoryHandleWithoutHiddenOpenOrClose(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	retainedToken := bytes.Repeat([]byte{0x73}, 16)
	retained, err := d.installHandle(retainedToken, v3RootItemID, false)
	if err != nil {
		t.Fatal(err)
	}
	readCalled := false
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		response := &authoritypb.Response{Mutation: &authoritypb.MutationState{Slot: identity.Slot, AcceptedSequence: identity.Sequence}}
		switch request.GetBody().(type) {
		case *authoritypb.Request_ReadDir:
			readCalled = true
			if !bytes.Equal(request.GetReadDir().GetHandle(), retainedToken) {
				return nil, errors.New("enumeration did not use the retained authority handle")
			}
			response.Body = &authoritypb.Response_ReadDir{ReadDir: &authoritypb.ReadDirReply{Verifier: bytes.Repeat([]byte{0x74}, 16), Eof: true}}
		default:
			return nil, errors.New("enumeration opened or closed a hidden authority handle")
		}
		return response, nil
	}
	reply, errno := d.enumerate(context.Background(), 0, &pfslocal.EnumerateRequest{
		Dir: d.resolveReply().Root, Handle: retained.id, MaxEntries: 1,
	})
	if errno != 0 || reply == nil || !readCalled {
		t.Fatalf("enumerate=(%#v,%d) read=%v", reply, errno, readCalled)
	}
	if _, errno := d.enumerate(context.Background(), 0, &pfslocal.EnumerateRequest{
		Dir: d.resolveReply().Root, MaxEntries: 1,
	}); errno != darwinEBADF {
		t.Fatalf("handle-free enumerate errno=%d, want %d", errno, darwinEBADF)
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

func TestV3DataPlaneMapsClassifiedPreApplyInterruptionToECANCELEDWithoutFencing(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	d.cfg.CachePolicy = v3CachePolicyMacOS26
	root := d.resolveReply().Root

	var calls, applies int
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		calls++
		rename := request.GetRename()
		if rename == nil || !bytes.Equal(rename.GetOldName(), []byte("old")) || !bytes.Equal(rename.GetNewName(), []byte("new")) {
			return nil, errors.New("unexpected rename request")
		}
		response := &authoritypb.Response{Mutation: &authoritypb.MutationState{Slot: identity.Slot, AcceptedSequence: identity.Sequence}}
		response.Errno = errnos.EINTR
		response.Failure = authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_INTERRUPTED
		return response, nil
	}

	if reply, errno := d.dispatch(context.Background(), 71, &pfslocal.RenameRequest{
		FromDir: root, FromName: []byte("old"), ToDir: root, ToName: []byte("new"),
	}); errno != darwinECANCELED {
		t.Fatalf("classified rename=(%#v,%d), want ECANCELED", reply, errno)
	}
	if calls != 1 || applies != 0 {
		t.Fatalf("classified rename calls=%d applies=%d, want one call and no apply", calls, applies)
	}
	if d.terminalError() != nil {
		t.Fatalf("definite-preapply refusal fenced the mount: %v", d.terminalError())
	}
}

func TestV3DataPlaneClassifiedInterruptionRemainsPreApplyWhenCallbackCancels(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	d.cfg.CachePolicy = v3CachePolicyMacOS26
	ctx, cancel := context.WithCancel(context.Background())
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, _ *authoritypb.Request) (*authoritypb.Response, error) {
		cancel()
		return &authoritypb.Response{
			Errno:    errnos.EINTR,
			Failure:  authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_INTERRUPTED,
			Mutation: &authoritypb.MutationState{Slot: identity.Slot, AcceptedSequence: identity.Sequence},
		}, nil
	}
	root := d.resolveReply().Root
	if _, errno := d.dispatch(ctx, 72, &pfslocal.RenameRequest{
		FromDir: root, FromName: []byte("old"), ToDir: root, ToName: []byte("new"),
	}); errno != darwinECANCELED {
		t.Fatalf("cancelled classified mutation errno=%d, want ECANCELED", errno)
	}
	if d.terminalError() != nil {
		t.Fatalf("definite-preapply cancelled result fenced the mount: %v", d.terminalError())
	}
}

func TestV3DataPlanePreservesV1VisibilityInterruptionBoundary(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	d.cfg.CachePolicy = v3CachePolicyMacOS26V1
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, _ *authoritypb.Request) (*authoritypb.Response, error) {
		return &authoritypb.Response{
			Errno:    errnos.EINTR,
			Failure:  authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_INTERRUPTED,
			Mutation: &authoritypb.MutationState{Slot: identity.Slot, AcceptedSequence: identity.Sequence},
		}, nil
	}
	root := d.resolveReply().Root
	if _, errno := d.dispatch(context.Background(), 73, &pfslocal.RenameRequest{
		FromDir: root, FromName: []byte("old"), ToDir: root, ToName: []byte("new"),
	}); errno != darwinEINTR {
		t.Fatalf("v1 visibility interruption errno=%d, want frozen EINTR", errno)
	}
}
