package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"google.golang.org/protobuf/proto"
)

type fakeV3DataClient struct {
	*fakeV3VisibilityClient
	root            *authoritypb.Item
	lease           time.Duration
	limit           int
	mu              sync.Mutex
	sequence        uint64
	readCalls       int
	idempotentCalls []*authoritypb.Request
	keepErr         error
	read            func(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	beforeAssigned  func(*authoritypb.Request) error
	idempotent      func(context.Context, *authoritypb.Request) (*authoritypb.Response, error)
	mutation        func(context.Context, authorityrpc.MutationIdentity, *authoritypb.Request) (*authoritypb.Response, error)
	newConsumption  func(func(error)) authorityrpc.ResponseConsumption
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

func (f *fakeV3DataClient) Root() *authoritypb.Item    { return f.root }
func (f *fakeV3DataClient) IOLimits() (uint32, uint32) { return 4096, 4096 }
func (f *fakeV3DataClient) MaxWriteTransactionBytes() uint64 {
	return authorityrpc.RequiredFskitWriteBytes
}
func (f *fakeV3DataClient) SessionLease() time.Duration  { return f.lease }
func (f *fakeV3DataClient) DataPlaneOperationLimit() int { return f.limit }
func (f *fakeV3DataClient) CallRead(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	f.mu.Lock()
	f.readCalls++
	hook := f.read
	f.mu.Unlock()
	if hook != nil {
		return hook(ctx, request)
	}
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
	case *authoritypb.Request_GetAttr:
		return &authoritypb.Response{Body: &authoritypb.Response_GetAttr{GetAttr: &authoritypb.GetAttrReply{Attr: &authoritypb.Attr{
			Kind: authoritypb.Attr_REGULAR, Inode: 2, Mode: 0o644, Nlink: 1,
		}}}}, nil
	case *authoritypb.Request_Reclaim:
		return &authoritypb.Response{}, nil
	default:
		return &authoritypb.Response{}, nil
	}
}
func (f *fakeV3DataClient) CallReadRetained(
	ctx context.Context,
	request *authoritypb.Request,
	force func(error),
) (*authoritypb.Response, authorityrpc.ResponseConsumption, error) {
	response, err := f.CallRead(ctx, request)
	if err != nil || response == nil {
		return response, nil, err
	}
	f.mu.Lock()
	newConsumption := f.newConsumption
	f.mu.Unlock()
	if newConsumption != nil {
		return response, newConsumption(force), nil
	}
	return response, &fakeV3ResponseConsumption{consume: func() {}}, nil
}
func (f *fakeV3DataClient) CallIdempotent(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	f.mu.Lock()
	f.idempotentCalls = append(f.idempotentCalls, proto.Clone(request).(*authoritypb.Request))
	hook := f.idempotent
	f.mu.Unlock()
	if hook != nil {
		return hook(ctx, request)
	}
	write := request.GetFskitWrite()
	if write == nil {
		return f.CallRead(ctx, request)
	}
	flags := uint32(0)
	switch write.GetPhase() {
	case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN:
		flags = v3WriteReplyBegun
	case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA:
		flags = v3WriteReplyStaged
	case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_ABORT:
		flags = v3WriteReplyAborted
	}
	return &authoritypb.Response{Body: &authoritypb.Response_FskitWrite{FskitWrite: &authoritypb.FskitWriteReply{
		TransactionId: write.GetTransactionId(), Flags: flags,
	}}}, nil
}
func (f *fakeV3DataClient) CallIdempotentRetained(
	ctx context.Context,
	request *authoritypb.Request,
	force func(error),
) (*authoritypb.Response, authorityrpc.ResponseConsumption, error) {
	response, err := f.CallIdempotent(ctx, request)
	if err != nil || response == nil {
		return response, nil, err
	}
	f.mu.Lock()
	newConsumption := f.newConsumption
	f.mu.Unlock()
	if newConsumption != nil {
		return response, newConsumption(force), nil
	}
	return response, &fakeV3ResponseConsumption{consume: func() {}}, nil
}
func (f *fakeV3DataClient) callMutationWithIdentity(ctx context.Context, request *authoritypb.Request, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	f.mu.Lock()
	f.sequence++
	identity := authorityrpc.MutationIdentity{Slot: 2, Sequence: f.sequence}
	beforeAssigned := f.beforeAssigned
	hook := f.mutation
	f.mu.Unlock()
	if beforeAssigned != nil {
		if err := beforeAssigned(request); err != nil {
			return nil, err
		}
	}
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
	case *authoritypb.Request_FskitWrite:
		write := request.GetFskitWrite()
		postSize := write.GetPosition() + write.GetFragmentOffset()
		response.Body = &authoritypb.Response_FskitWrite{FskitWrite: &authoritypb.FskitWriteReply{
			TransactionId: write.GetTransactionId(), CommittedSize: write.GetFragmentOffset(),
			AssignedOffset: write.GetPosition(), PostSize: postSize, VisibilitySequence: identity.Sequence,
			Flags: v3WriteReplyCommitted,
		}}
		response.PostState = testV3PostState(&authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: 2, Size: int64(postSize), Nlink: 1})
	case *authoritypb.Request_SyncFs:
		response.Body = &authoritypb.Response_SyncFs{SyncFs: &authoritypb.SyncFSReply{}}
	}
	return response, nil
}

type fakeV3ResponseConsumption struct {
	once    sync.Once
	consume func()
}

func (c *fakeV3ResponseConsumption) Consume() {
	if c != nil && c.consume != nil {
		c.once.Do(c.consume)
	}
}

func (f *fakeV3DataClient) CallMutationWithIdentity(ctx context.Context, request *authoritypb.Request, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	return f.callMutationWithIdentity(ctx, request, assigned)
}

func (f *fakeV3DataClient) CallMutationWithIdentityRetained(
	ctx context.Context,
	request *authoritypb.Request,
	assigned authorityrpc.MutationAssigned,
	force func(error),
) (*authoritypb.Response, authorityrpc.ResponseConsumption, error) {
	response, err := f.callMutationWithIdentity(ctx, request, assigned)
	if err != nil || response == nil {
		return response, nil, err
	}
	f.mu.Lock()
	newConsumption := f.newConsumption
	f.mu.Unlock()
	if newConsumption != nil {
		return response, newConsumption(force), nil
	}
	return response, &fakeV3ResponseConsumption{consume: func() {}}, nil
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

var testV3OperationID atomic.Uint64

func dispatchV3Test(d *v3DataPlane, ctx context.Context, operationID uint64, body any) (any, int32) {
	if frontendRequestPublishes(body) {
		if operationID == 0 {
			operationID = 10_000 + testV3OperationID.Add(1)
		}
		d.bridge.reserveFrontendPublication(operationID)
		defer func() { _ = d.bridge.finishFrontendPublication(operationID) }()
		defer d.bridge.releaseFrontendPublication(operationID)
		defer func() {
			_, _ = d.bridge.acknowledgePublication(
				operationID, pfslocal.PublicationSemanticCommitPublished,
			)
		}()
	}
	return d.dispatchFrontend(ctx, operationID, body)
}

func TestV3PublishingReadResponsesRemainRetainedThroughFrontendPublication(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	var consumed atomic.Int32
	client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
		return &countingV3ResponseConsumption{count: &consumed}
	}
	const operationID = uint64(7601)
	d.bridge.reserveFrontendPublication(operationID)
	request := &authoritypb.Request{Body: &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{
		Item: bytes.Repeat([]byte{0x30}, 16),
	}}}
	for index := 0; index < 2; index++ {
		if response, errno := d.callRead(context.Background(), operationID, request); errno != 0 || response.GetGetAttr() == nil {
			t.Fatalf("publishing read %d = (%#v,%d)", index, response, errno)
		}
	}
	if got := consumed.Load(); got != 0 {
		t.Fatalf("publishing reads consumed at authority return: %d", got)
	}
	known, err := d.bridge.acknowledgePublication(operationID, pfslocal.PublicationSemanticCommitPublished)
	if !known || err != nil {
		t.Fatalf("PublicationAck = (%t,%v)", known, err)
	}
	if got := consumed.Load(); got != 0 {
		t.Fatalf("publishing reads consumed before handler retirement: %d", got)
	}
	d.bridge.releaseFrontendPublication(operationID)
	if got := consumed.Load(); got != 0 {
		t.Fatalf("publishing reads consumed before logical finish: %d", got)
	}
	if err := d.bridge.finishFrontendPublication(operationID); err != nil {
		t.Fatal(err)
	}
	if got := consumed.Load(); got != 2 {
		t.Fatalf("publishing read consumptions after frontend publication = %d, want 2", got)
	}
}

func TestV3PublishingReplayResponseRemainsRetainedThroughFrontendPublication(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	var consumed atomic.Int32
	client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
		return &countingV3ResponseConsumption{count: &consumed}
	}
	const operationID = uint64(7602)
	d.bridge.reserveFrontendPublication(operationID)
	request := &authoritypb.Request{Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{
		Parent: bytes.Repeat([]byte{0x10}, 16), Name: []byte("entry"),
	}}}
	if response, errno := d.callNonVisibleMutation(context.Background(), operationID, request); errno != 0 || response.GetLookup() == nil {
		t.Fatalf("publishing replay = (%#v,%d)", response, errno)
	}
	if got := consumed.Load(); got != 0 {
		t.Fatalf("publishing replay consumed at authority return: %d", got)
	}
	known, err := d.bridge.acknowledgePublication(operationID, pfslocal.PublicationSemanticCommitPublished)
	if !known || err != nil {
		t.Fatalf("PublicationAck = (%t,%v)", known, err)
	}
	d.bridge.releaseFrontendPublication(operationID)
	if got := consumed.Load(); got != 0 {
		t.Fatalf("publishing replay consumed before logical finish: %d", got)
	}
	if err := d.bridge.finishFrontendPublication(operationID); err != nil {
		t.Fatal(err)
	}
	if got := consumed.Load(); got != 1 {
		t.Fatalf("publishing replay consumption after frontend publication = %d, want 1", got)
	}
}

func openTestV3File(t *testing.T, d *v3DataPlane, appendMode bool) (pfslocal.Item, uint64) {
	t.Helper()
	lookupAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{
		Dir: d.resolveReply().Root, Name: []byte("file"),
	})
	if errno != 0 {
		t.Fatalf("lookup errno=%d", errno)
	}
	file := lookupAny.(*pfslocal.LookupReply).Attr.Item
	openedAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.OpenRequest{
		Item: file, Mode: pfslocal.OpenModeReadWrite, Append: appendMode,
	})
	if errno != 0 {
		t.Fatalf("open errno=%d", errno)
	}
	return file, openedAny.(*pfslocal.OpenReply).Handle
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

func exactTestWritePhaseReply(request *authoritypb.Request, flags uint32) *authoritypb.Response {
	write := request.GetFskitWrite()
	return &authoritypb.Response{Body: &authoritypb.Response_FskitWrite{FskitWrite: &authoritypb.FskitWriteReply{
		TransactionId: write.GetTransactionId(), Flags: flags,
	}}}
}

func exactTestWriteCommit(identity authorityrpc.MutationIdentity, request *authoritypb.Request) *authoritypb.Response {
	write := request.GetFskitWrite()
	postSize := write.GetPosition() + write.GetFragmentOffset()
	response := exactTestMutationReply(identity)
	response.Body = &authoritypb.Response_FskitWrite{FskitWrite: &authoritypb.FskitWriteReply{
		TransactionId: write.GetTransactionId(), CommittedSize: write.GetFragmentOffset(),
		AssignedOffset: write.GetPosition(), PostSize: postSize, VisibilitySequence: identity.Sequence,
		Flags: v3WriteReplyCommitted,
	}}
	response.PostState = testV3PostState(&authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: 2, Size: int64(postSize), Nlink: 1})
	return response
}

func TestV3VisibleCreateReplyRejectedHandleIsTerminal(t *testing.T) {
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

	// A successful Create publishes both the namespace item and the open handle
	// as one callback result. Rejecting either half means FSKit did not receive
	// the authority-committed result, so PublicationAck must never reopen the
	// source gate.
	cleanup, err := d.applyReplyResourceDisposition(resources, false, 1)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup.terminalReason == nil || len(cleanup.items) != 0 || len(cleanup.handles) != 1 {
		t.Fatalf("split cleanup=%+v", cleanup)
	}
	if d.terminalError() == nil {
		t.Fatal("visible Create handle rejection did not fail closed")
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
	if _, errno := d.lookup(ctx, 0, &pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("bad-attr")}); errno != darwinEIO {
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
	lookupAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("file")})
	if errno != 0 {
		t.Fatalf("lookup errno=%d", errno)
	}
	file := lookupAny.(*pfslocal.LookupReply).Attr.Item
	openedAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.OpenRequest{Item: file, Mode: pfslocal.OpenModeReadWrite})
	if errno != 0 {
		t.Fatalf("open errno=%d", errno)
	}
	handle := openedAny.(*pfslocal.OpenReply).Handle
	d.bridge.sourcePublication.mu.Lock()
	ticketsAfterOpen := len(d.bridge.sourcePublication.operations)
	d.bridge.sourcePublication.mu.Unlock()
	if ticketsAfterOpen != 0 {
		t.Fatalf("non-visible open created %d publication tickets", ticketsAfterOpen)
	}
	closedAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.CloseRequest{Handle: handle})
	if errno != 0 || !closedAny.(*pfslocal.CloseReply).Retired {
		t.Fatalf("close=(%#v,%d)", closedAny, errno)
	}
}

func TestV3DataPlaneWriteInstallsExactSourceGateBeforeAssignment(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	lookupAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{Dir: d.resolveReply().Root, Name: []byte("file")})
	if errno != 0 {
		t.Fatal(errno)
	}
	file := lookupAny.(*pfslocal.LookupReply).Attr.Item
	openedAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.OpenRequest{Item: file, Mode: pfslocal.OpenModeReadWrite})
	if errno != 0 {
		t.Fatal(errno)
	}
	handle := openedAny.(*pfslocal.OpenReply).Handle
	d.bridge.reserveFrontendPublication(77)
	client.beforeAssigned = func(request *authoritypb.Request) error {
		if request.GetFskitSourcePublication() == nil {
			return errors.New("source gate was not carried into replay assignment")
		}
		d.bridge.sourcePublication.mu.Lock()
		lease := d.bridge.sourcePublication.operationLeaseLocked(77)
		installed := lease != nil && lease.assigned == 0
		d.bridge.sourcePublication.mu.Unlock()
		if !installed {
			return errors.New("source gate was not installed before replay assignment")
		}
		return nil
	}
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		write := request.GetFskitWrite()
		if write == nil || write.GetPhase() != authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_COMMIT ||
			write.GetTransactionId() != 1 || write.GetRequestedSize() != 3 || write.GetFragmentOffset() != 3 ||
			write.GetPosition() != 0 || write.GetRlimitFsize() != math.MaxUint64 || write.GetFileMaxSize() != math.MaxInt64 {
			return nil, errors.New("expected exact write transaction COMMIT")
		}
		if request.GetFskitFrontendOperationId() != 77 {
			return nil, errors.New("write lost its pfslocal frontend operation identity")
		}
		gate := request.GetFskitSourcePublication()
		if gate == nil || len(gate.GetTargets()) != 1 || gate.GetTargets()[0].GetItem() == nil ||
			!bytes.Equal(gate.GetTargets()[0].GetItem().GetIdentity(), bytes.Repeat([]byte{0x40}, 16)) ||
			!gate.GetTargets()[0].GetItem().GetAttributes() || !gate.GetTargets()[0].GetItem().GetData() {
			return nil, errors.New("write lost its exact item ATTR+DATA source gate")
		}
		return exactTestWriteCommit(identity, request), nil
	}
	replyAny, errno := d.dispatchFrontend(
		context.Background(), 77,
		&pfslocal.WriteRequest{Handle: handle, Data: []byte("abc")},
	)
	if errno != 0 || replyAny.(*pfslocal.WriteReply).Written != 3 {
		t.Fatalf("write=(%#v,%d)", replyAny, errno)
	}
	if !acknowledgeBridgePublished(t, d.bridge, 77) {
		t.Fatal("PublicationAck did not release the write source gate")
	}
	d.bridge.releaseFrontendPublication(77)

	client.mu.Lock()
	inert := append([]*authoritypb.Request(nil), client.idempotentCalls...)
	client.mu.Unlock()
	if len(inert) != 2 {
		t.Fatalf("write inert phase count=%d, want BEGIN+DATA", len(inert))
	}
	for index, exact := range []struct {
		phase          authoritypb.FskitWritePhase
		fragmentOffset uint64
		size           uint32
		data           []byte
	}{
		{phase: authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN},
		{phase: authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA, size: 3, data: []byte("abc")},
	} {
		request := inert[index]
		write := request.GetFskitWrite()
		if request.GetMutation() != nil || request.GetFskitSourcePublication() != nil || request.GetFskitFrontendOperationId() != 0 ||
			write == nil || write.GetPhase() != exact.phase || write.GetTransactionId() != 1 ||
			!bytes.Equal(write.GetHandle(), bytes.Repeat([]byte{0x51}, 16)) || write.GetRequestedSize() != 3 ||
			write.GetFragmentOffset() != exact.fragmentOffset || write.GetPosition() != 0 ||
			write.GetRlimitFsize() != math.MaxUint64 || write.GetFileMaxSize() != math.MaxInt64 ||
			write.GetLockOwner() != 0 || write.GetWriteFlags() != v3WriteFlagKillSUIDGID || write.GetFlags() != 0 ||
			write.GetSize() != exact.size || !bytes.Equal(write.GetData(), exact.data) {
			t.Fatalf("inert phase[%d] = %#v, want exact immutable transaction metadata", index, request)
		}
	}
}

func TestV3DataPlaneWriteFragmentsOneTransactionAndCommitsOnce(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	_, handle := openTestV3File(t, d, false)
	d.maxWrite = 2
	var consumed atomic.Int32
	client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
		return &countingV3ResponseConsumption{count: &consumed}
	}

	commits := 0
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		commits++
		write := request.GetFskitWrite()
		if write == nil || write.GetPhase() != authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_COMMIT ||
			write.GetTransactionId() != 1 || write.GetFragmentOffset() != 5 {
			return nil, errors.New("expected one exact five-byte COMMIT")
		}
		return exactTestWriteCommit(identity, request), nil
	}
	const operationID = uint64(780)
	d.bridge.reserveFrontendPublication(operationID)
	if reply, errno := d.dispatchFrontend(context.Background(), operationID, &pfslocal.WriteRequest{
		Handle: handle, Offset: 7, Data: []byte("abcde"),
	}); errno != 0 || reply.(*pfslocal.WriteReply).Written != 5 {
		t.Fatalf("fragmented write=(%#v,%d)", reply, errno)
	}
	if got := consumed.Load(); got != 0 {
		t.Fatalf("fragmented write consumed %d phase receipts before frontend publication", got)
	}
	client.mu.Lock()
	inert := append([]*authoritypb.Request(nil), client.idempotentCalls...)
	client.mu.Unlock()
	if commits != 1 || len(inert) != 4 {
		t.Fatalf("fragmented phases: inert=%d commits=%d, want BEGIN+3 DATA+COMMIT", len(inert), commits)
	}
	for index, exact := range []struct {
		phase  authoritypb.FskitWritePhase
		offset uint64
		data   string
	}{
		{phase: authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN},
		{phase: authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA, data: "ab"},
		{phase: authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA, offset: 2, data: "cd"},
		{phase: authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA, offset: 4, data: "e"},
	} {
		write := inert[index].GetFskitWrite()
		if write == nil || write.GetPhase() != exact.phase || write.GetTransactionId() != 1 ||
			write.GetFragmentOffset() != exact.offset || string(write.GetData()) != exact.data ||
			write.GetSize() != uint32(len(exact.data)) {
			t.Fatalf("fragment[%d]=%#v", index, inert[index])
		}
	}
	if !acknowledgeBridgePublished(t, d.bridge, operationID) {
		t.Fatal("fragmented write PublicationAck was refused")
	}
	d.bridge.releaseFrontendPublication(operationID)
	if got := consumed.Load(); got != 0 {
		t.Fatalf("fragmented write consumed %d receipts before logical retirement", got)
	}
	if err := d.bridge.finishFrontendPublication(operationID); err != nil {
		t.Fatal(err)
	}
	if got := consumed.Load(); got != 5 {
		t.Fatalf("fragmented write consumed %d receipts, want BEGIN+3 DATA+COMMIT=5", got)
	}
}

func TestV3DataPlaneWriteDATAFailureUsesExactAbortAndNoCommit(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	_, handle := openTestV3File(t, d, false)
	dataCalls := 0
	client.idempotent = func(_ context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
		write := request.GetFskitWrite()
		switch write.GetPhase() {
		case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN:
			return exactTestWritePhaseReply(request, v3WriteReplyBegun), nil
		case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA:
			dataCalls++
			return &authoritypb.Response{Errno: errnos.ENOSPC}, nil
		case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_ABORT:
			return exactTestWritePhaseReply(request, v3WriteReplyAborted), nil
		default:
			return nil, errors.New("unexpected idempotent phase")
		}
	}
	commits := 0
	client.mutation = func(context.Context, authorityrpc.MutationIdentity, *authoritypb.Request) (*authoritypb.Response, error) {
		commits++
		return nil, errors.New("COMMIT must not follow failed DATA")
	}
	if reply, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.WriteRequest{
		Handle: handle, Data: []byte("abc"),
	}); errno != darwinENOSPC || reply != nil {
		t.Fatalf("DATA refusal=(%#v,%d), want ENOSPC", reply, errno)
	}
	client.mu.Lock()
	inert := append([]*authoritypb.Request(nil), client.idempotentCalls...)
	client.mu.Unlock()
	if dataCalls != 1 || commits != 0 || len(inert) != 3 {
		t.Fatalf("DATA failure phases: data=%d commits=%d inert=%d", dataCalls, commits, len(inert))
	}
	abort := inert[2].GetFskitWrite()
	if abort == nil || abort.GetPhase() != authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_ABORT ||
		abort.GetTransactionId() != 1 || abort.GetFragmentOffset() != 0 || abort.GetSize() != 0 || len(abort.GetData()) != 0 {
		t.Fatalf("ABORT=%#v, want exact metadata with zero offset/payload", inert[2])
	}
}

func TestV3DataPlaneWriteStructuredRejectionAbortsWithoutPublicationCommit(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	_, handle := openTestV3File(t, d, false)
	var consumed atomic.Int32
	client.newConsumption = func(func(error)) authorityrpc.ResponseConsumption {
		return &countingV3ResponseConsumption{count: &consumed}
	}
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		write := request.GetFskitWrite()
		return &authoritypb.Response{
			Mutation: &authoritypb.MutationState{Slot: identity.Slot, AcceptedSequence: identity.Sequence},
			Body: &authoritypb.Response_FskitWrite{FskitWrite: &authoritypb.FskitWriteReply{
				TransactionId: write.GetTransactionId(), Flags: v3WriteReplyRejected, Error: -int32(errnos.ENOSPC),
			}},
		}, nil
	}
	const operationID = uint64(779)
	d.bridge.reserveFrontendPublication(operationID)
	if reply, errno := d.dispatchFrontend(context.Background(), operationID, &pfslocal.WriteRequest{
		Handle: handle, Data: []byte("abc"),
	}); errno != darwinENOSPC || reply != nil {
		t.Fatalf("structured rejection=(%#v,%d), want ENOSPC", reply, errno)
	}
	if got := consumed.Load(); got != 0 {
		t.Fatalf("definite no-publication rejection consumed receipt at authority return: %d", got)
	}
	client.mu.Lock()
	inert := append([]*authoritypb.Request(nil), client.idempotentCalls...)
	client.mu.Unlock()
	if len(inert) != 3 || inert[2].GetFskitWrite().GetPhase() != authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_ABORT {
		t.Fatalf("structured rejection phases=%#v, want BEGIN+DATA+ABORT", inert)
	}
	lease := d.bridge.sourcePublication.operationLease(operationID)
	d.bridge.sourcePublication.mu.Lock()
	op := d.bridge.sourcePublication.operations[operationID]
	committed, released := op != nil && op.committed, lease != nil && lease.released
	d.bridge.sourcePublication.mu.Unlock()
	if lease == nil || committed || released || d.terminalError() != nil {
		t.Fatalf("rejected lease=%#v committed=%t released=%t terminal=%v", lease, committed, released, d.terminalError())
	}
	if !acknowledgeBridgePublished(t, d.bridge, operationID) {
		t.Fatal("rejected callback PublicationAck was not accepted")
	}
	d.bridge.releaseFrontendPublication(operationID)
	if err := d.bridge.finishFrontendPublication(operationID); err != nil {
		t.Fatal(err)
	}
	if got := consumed.Load(); got != 4 {
		t.Fatalf("definite rejection consumed %d receipts, want BEGIN+DATA+COMMIT+ABORT=4", got)
	}
	d.bridge.sourcePublication.mu.Lock()
	released = lease.released
	d.bridge.sourcePublication.mu.Unlock()
	if !released {
		t.Fatal("definite rejection did not release its noncommitted source lease")
	}
}

func TestV3DataPlaneWriteBeginDispatchOrderIsMonotonic(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	_, handle := openTestV3File(t, d, false)
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var once sync.Once
	client.idempotent = func(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
		write := request.GetFskitWrite()
		if write.GetPhase() == authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN && write.GetTransactionId() == 1 {
			once.Do(func() { close(firstEntered) })
			select {
			case <-releaseFirst:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		var flags uint32
		switch write.GetPhase() {
		case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN:
			flags = v3WriteReplyBegun
		case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA:
			flags = v3WriteReplyStaged
		case authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_ABORT:
			flags = v3WriteReplyAborted
		}
		return exactTestWritePhaseReply(request, flags), nil
	}

	type result struct{ errno int32 }
	results := make(chan result, 2)
	go func() {
		_, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.WriteRequest{Handle: handle, Data: []byte("a")})
		results <- result{errno: errno}
	}()
	<-firstEntered
	go func() {
		_, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.WriteRequest{Handle: handle, Offset: 1, Data: []byte("b")})
		results <- result{errno: errno}
	}()
	time.Sleep(20 * time.Millisecond)
	client.mu.Lock()
	beforeRelease := append([]*authoritypb.Request(nil), client.idempotentCalls...)
	client.mu.Unlock()
	if len(beforeRelease) != 1 || beforeRelease[0].GetFskitWrite().GetTransactionId() != 1 {
		t.Fatalf("BEGIN mutex allowed later dispatch before transaction 1 reply: %#v", beforeRelease)
	}
	close(releaseFirst)
	for range 2 {
		if result := <-results; result.errno != 0 {
			t.Fatalf("concurrent write errno=%d", result.errno)
		}
	}
	client.mu.Lock()
	all := append([]*authoritypb.Request(nil), client.idempotentCalls...)
	client.mu.Unlock()
	beginIDs := make([]uint64, 0, 2)
	for _, request := range all {
		if write := request.GetFskitWrite(); write.GetPhase() == authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN {
			beginIDs = append(beginIDs, write.GetTransactionId())
		}
	}
	if !slices.Equal(beginIDs, []uint64{1, 2}) {
		t.Fatalf("BEGIN dispatch IDs=%v, want [1 2]", beginIDs)
	}
}

func TestV3DataPlaneZeroWritePublishesCurrentAttrWithoutTransaction(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	_, handle := openTestV3File(t, d, true)
	mutationsBefore := client.sequence
	if reply, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.WriteRequest{
		Handle: handle, Offset: math.MaxInt64 - 1, Append: true,
	}); errno != 0 || reply.(*pfslocal.WriteReply).Written != 0 {
		t.Fatalf("zero write=(%#v,%d)", reply, errno)
	}
	client.mu.Lock()
	inert := len(client.idempotentCalls)
	mutationsAfter := client.sequence
	client.mu.Unlock()
	if inert != 0 || mutationsAfter != mutationsBefore || d.nextWriteTransaction != 1 {
		t.Fatalf("zero write allocated work: inert=%d mutation=%d->%d nextTx=%d", inert, mutationsBefore, mutationsAfter, d.nextWriteTransaction)
	}
}

func TestV3DataPlaneAppendHasNoPositionalFallback(t *testing.T) {
	for _, test := range []struct {
		name          string
		handleAppend  bool
		requestAppend bool
	}{
		{name: "append handle", handleAppend: true},
		{name: "per-write append", requestAppend: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			lookupAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{
				Dir: d.resolveReply().Root, Name: []byte("file"),
			})
			if errno != 0 {
				t.Fatal(errno)
			}
			file := lookupAny.(*pfslocal.LookupReply).Attr.Item
			openedAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.OpenRequest{
				Item: file, Mode: pfslocal.OpenModeReadWrite, Append: test.handleAppend,
			})
			if errno != 0 {
				t.Fatal(errno)
			}
			handle := openedAny.(*pfslocal.OpenReply).Handle

			const expectedEOF = uint64(37)
			called := false
			client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
				called = true
				return exactTestWriteCommit(identity, request), nil
			}

			replyAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.WriteRequest{
				Handle: handle, Offset: expectedEOF, Data: []byte("abc"), Append: test.requestAppend,
			})
			if errno != darwinENOTSUP || replyAny != nil || called {
				t.Fatalf("append fallback = (%#v, %d, called=%t), want ENOTSUP before authority dispatch", replyAny, errno, called)
			}
		})
	}
}

func TestV3DataPlaneMixedOperationLocalFailureAfterCommittedWriteFailsClosed(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	lookupAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{
		Dir: d.resolveReply().Root, Name: []byte("file"),
	})
	if errno != 0 {
		t.Fatal(errno)
	}
	file := lookupAny.(*pfslocal.LookupReply).Attr.Item
	openedAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.OpenRequest{
		Item: file, Mode: pfslocal.OpenModeReadWrite,
	})
	if errno != 0 {
		t.Fatal(errno)
	}
	handle := openedAny.(*pfslocal.OpenReply).Handle

	calls := 0
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetFskitWrite() == nil {
			return nil, errors.New("expected write transaction")
		}
		calls++
		return exactTestWriteCommit(identity, request), nil
	}

	const operationID = 771
	d.bridge.reserveFrontendPublication(operationID)
	if reply, errno := d.dispatchFrontend(context.Background(), operationID, &pfslocal.WriteRequest{
		Handle: handle, Data: []byte("a"),
	}); errno != 0 || reply.(*pfslocal.WriteReply).Written != 1 {
		t.Fatalf("committed write = (%#v, %d)", reply, errno)
	}
	if reply, errno := d.dispatchFrontend(context.Background(), operationID, &pfslocal.WriteRequest{
		Handle: handle + 10_000, Offset: 1, Data: []byte("b"),
	}); errno != darwinEBADF || reply != nil {
		t.Fatalf("locally failing continuation = (%#v, %d), want EBADF", reply, errno)
	}
	if calls != 1 {
		t.Fatalf("local continuation failure reached authority: calls=%d", calls)
	}
	lease := d.bridge.sourcePublication.operationLease(operationID)
	d.bridge.sourcePublication.mu.Lock()
	op := d.bridge.sourcePublication.operations[operationID]
	committed := op != nil && op.committed
	d.bridge.sourcePublication.mu.Unlock()
	if lease == nil || !committed {
		t.Fatalf("mixed operation lost committed source fact: lease=%#v committed=%t", lease, committed)
	}
	known, ackErr := d.bridge.acknowledgePublication(
		operationID, pfslocal.PublicationSemanticCommitNotPublished,
	)
	if !known || !errors.Is(ackErr, errV3SourcePublicationNotPublished) {
		t.Fatalf("mixed operation ack = (%t, %v)", known, ackErr)
	}
	d.bridge.releaseFrontendPublication(operationID)
	d.bridge.sourcePublication.mu.Lock()
	released, terminal := lease.released, d.bridge.sourcePublication.terminal
	d.bridge.sourcePublication.mu.Unlock()
	if released || !errors.Is(terminal, errV3SourcePublicationNotPublished) || d.terminalError() == nil {
		t.Fatalf("mixed operation reopened: released=%t terminal=%v dataTerminal=%v", released, terminal, d.terminalError())
	}
}

func TestV3DataPlanePeerFirstRefusalAbortsStagingBeforeReplayAssignment(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	d.cfg.CachePolicy = v3CachePolicyMacOS26
	lookupAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{
		Dir: d.resolveReply().Root, Name: []byte("file"),
	})
	if errno != 0 {
		t.Fatal(errno)
	}
	file := lookupAny.(*pfslocal.LookupReply).Attr.Item
	openedAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.OpenRequest{
		Item: file, Mode: pfslocal.OpenModeReadWrite,
	})
	if errno != 0 {
		t.Fatal(errno)
	}
	handle := openedAny.(*pfslocal.OpenReply).Handle
	if err := d.bridge.sourcePublication.acquirePeer(
		context.Background(), 17, []*authoritypb.VisibilityTarget{testV3AttributeTarget(0x40)},
	); err != nil {
		t.Fatal(err)
	}
	client.mu.Lock()
	beforeSequence := client.sequence
	client.mu.Unlock()
	assigned := false
	client.beforeAssigned = func(*authoritypb.Request) error {
		assigned = true
		return nil
	}
	d.bridge.reserveFrontendPublication(78)
	reply, errno := d.dispatchFrontend(context.Background(), 78, &pfslocal.WriteRequest{
		Handle: handle, Offset: 0, Data: []byte("x"),
	})
	if errno != darwinECANCELED || reply != nil {
		t.Fatalf("peer-first write = (%#v, %d), want (nil, ECANCELED)", reply, errno)
	}
	client.mu.Lock()
	afterSequence := client.sequence
	client.mu.Unlock()
	if assigned || afterSequence != beforeSequence {
		t.Fatalf("peer-first refusal reached replay assignment/send: assigned=%t sequence=%d->%d", assigned, beforeSequence, afterSequence)
	}
	client.mu.Lock()
	inert := append([]*authoritypb.Request(nil), client.idempotentCalls...)
	client.mu.Unlock()
	if len(inert) != 3 {
		t.Fatalf("peer-first inert phase count=%d, want BEGIN+DATA+ABORT", len(inert))
	}
	for index, phase := range []authoritypb.FskitWritePhase{
		authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_BEGIN,
		authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_DATA,
		authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_ABORT,
	} {
		write := inert[index].GetFskitWrite()
		if write == nil || write.GetTransactionId() != 1 || write.GetPhase() != phase ||
			phase == authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_ABORT &&
				(write.GetFragmentOffset() != 0 || write.GetSize() != 0 || len(write.GetData()) != 0) {
			t.Fatalf("peer-first inert phase[%d] = %#v", index, inert[index])
		}
	}
	if lease := d.bridge.sourcePublication.operationLease(78); lease != nil {
		t.Fatal("peer-first refusal retained a source lease")
	}
	if !acknowledgeBridgePublished(t, d.bridge, 78) {
		t.Fatal("refused callback PublicationAck was not accepted")
	}
	d.bridge.releaseFrontendPublication(78)
	if err := d.bridge.sourcePublication.releasePeer(17); err != nil {
		t.Fatal(err)
	}
}

func TestV3DataPlaneCreateDeclaresAndResolvesItsExactSourceGate(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		create := request.GetCreate()
		if create == nil || !bytes.Equal(create.GetName(), []byte("new")) {
			return nil, errors.New("expected create")
		}
		gate := request.GetFskitSourcePublication()
		if gate == nil || len(gate.GetTargets()) != 2 || gate.GetTargets()[0].GetItem() == nil ||
			!bytes.Equal(gate.GetTargets()[0].GetItem().GetIdentity(), bytes.Repeat([]byte{0x20}, 16)) ||
			gate.GetTargets()[1].GetNamespace() == nil ||
			!bytes.Equal(gate.GetTargets()[1].GetNamespace().GetParentIdentity(), bytes.Repeat([]byte{0x20}, 16)) ||
			!bytes.Equal(gate.GetTargets()[1].GetNamespace().GetName(), []byte("new")) ||
			!gate.GetTargets()[1].GetNamespace().GetBoundAttributes() || gate.GetTargets()[1].GetNamespace().GetBoundData() {
			return nil, errors.New("create lost its canonical parent+namespace source gate")
		}
		return &authoritypb.Response{
			Mutation: &authoritypb.MutationState{Slot: identity.Slot, AcceptedSequence: identity.Sequence},
			Body: &authoritypb.Response_Create{Create: &authoritypb.CreateReply{
				Item:   authorityTestItem(3, authoritypb.Attr_REGULAR, 0x61, 0x62),
				Handle: bytes.Repeat([]byte{0x63}, 16),
			}},
		}, nil
	}
	d.bridge.reserveFrontendPublication(88)
	replyAny, errno := d.dispatchFrontend(context.Background(), 88, &pfslocal.CreateRequest{
		Dir: d.resolveReply().Root, Name: []byte("new"), Mode: 0o644, Exclusive: true,
	})
	if errno != 0 {
		t.Fatalf("create errno=%d", errno)
	}
	reply := replyAny.(*pfslocal.CreateReply)
	if reply.Handle == 0 || reply.Attr.Item.StableIdentity != ([16]byte{0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62, 0x62}) {
		t.Fatalf("unexpected create reply: %#v", reply)
	}
	lease := d.bridge.sourcePublication.operationLease(88)
	if lease == nil || lease.unresolvedAttributes != 0 {
		t.Fatal("create reply did not resolve the namespace wildcard to its returned identity")
	}
	if !acknowledgeBridgePublished(t, d.bridge, 88) {
		t.Fatal("PublicationAck did not release the create source gate")
	}
	d.bridge.releaseFrontendPublication(88)
}

func TestV3DataPlaneRenameConsumesExactAuthoritativePostBindings(t *testing.T) {
	tests := []struct {
		name           string
		fromName       string
		toName         string
		newIdentity    byte
		oldIdentity    byte
		oldBound       bool
		wantNameClaims int
	}{
		{name: "move-removes-source", fromName: "old", toName: "new", newIdentity: 0xa1},
		{name: "same-inode-hard-links-remain-bound", fromName: "old", toName: "alias", newIdentity: 0xa2, oldIdentity: 0xa2, oldBound: true},
		{name: "same-path-no-op-has-one-canonical-claim", fromName: "same", toName: "same", newIdentity: 0xa3, oldIdentity: 0xa3, oldBound: true},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
				if request.GetRename() == nil {
					return nil, errors.New("expected rename")
				}
				reply := &authoritypb.RenameReply{
					NewPostIdentity: bytes.Repeat([]byte{test.newIdentity}, 16),
				}
				if test.oldBound {
					reply.OldPostIdentity = bytes.Repeat([]byte{test.oldIdentity}, 16)
				}
				response := exactTestMutationReply(identity)
				response.Body = &authoritypb.Response_Rename{Rename: reply}
				return response, nil
			}
			operationID := uint64(890 + index)
			d.bridge.reserveFrontendPublication(operationID)
			root := d.resolveReply().Root
			replyAny, errno := d.dispatchFrontend(context.Background(), operationID, &pfslocal.RenameRequest{
				FromDir: root, FromName: []byte(test.fromName),
				ToDir: root, ToName: []byte(test.toName),
			})
			if errno != 0 {
				t.Fatalf("rename errno=%d", errno)
			}
			reply := replyAny.(*pfslocal.RenameReply)
			if !bytes.Equal(reply.NewPostIdentity, bytes.Repeat([]byte{test.newIdentity}, 16)) ||
				test.oldBound != (len(reply.OldPostIdentity) != 0) ||
				(test.oldBound && !bytes.Equal(reply.OldPostIdentity, bytes.Repeat([]byte{test.oldIdentity}, 16))) {
				t.Fatalf("rename post bindings = %#v", reply)
			}
			lease := d.bridge.sourcePublication.operationLease(operationID)
			d.bridge.sourcePublication.mu.Lock()
			op := d.bridge.sourcePublication.operations[operationID]
			committed := op != nil && op.committed
			unresolvedAttributes := lease.unresolvedAttributes
			unresolvedData := lease.unresolvedData
			remainingClaims := len(lease.names)
			_, newHeld := lease.coordinates[v3PublicationCoordinate{
				kind: v3PublicationItemAttributes,
				item: testV3PublicationIdentity(test.newIdentity),
			}]
			d.bridge.sourcePublication.mu.Unlock()
			if !committed || unresolvedAttributes != 0 || unresolvedData != 0 || remainingClaims != 0 || !newHeld {
				t.Fatalf(
					"rename lease committed=%t unresolved attr=%d data=%d claims=%d newHeld=%t",
					committed, unresolvedAttributes, unresolvedData, remainingClaims, newHeld,
				)
			}
			if !acknowledgeBridgePublished(t, d.bridge, operationID) {
				t.Fatal("rename PublicationAck was not accepted")
			}
			d.bridge.releaseFrontendPublication(operationID)
		})
	}
}

func TestV3DataPlaneEveryVisibleMutationCarriesItsFrozenExactSourceGate(t *testing.T) {
	type mutationCase struct {
		name     string
		request  func(root, file pfslocal.Item, handle uint64) any
		expected func(root, file pfslocal.Item) (*authoritypb.FskitSourcePublication, error)
	}
	mode := uint32(0o600)
	size := uint64(7)
	cases := []mutationCase{
		{
			name: "setattr-attributes-with-corroborating-handle",
			request: func(_ pfslocal.Item, file pfslocal.Item, handle uint64) any {
				return &pfslocal.SetAttrRequest{Item: file, Handle: handle, Mode: &mode}
			},
			expected: func(_ pfslocal.Item, file pfslocal.Item) (*authoritypb.FskitSourcePublication, error) {
				return v3ItemSourceGate(file, false)
			},
		},
		{
			name: "setattr-size-implies-attributes-and-data",
			request: func(_ pfslocal.Item, file pfslocal.Item, handle uint64) any {
				return &pfslocal.SetAttrRequest{Item: file, Handle: handle, Size: &size}
			},
			expected: func(_ pfslocal.Item, file pfslocal.Item) (*authoritypb.FskitSourcePublication, error) {
				return v3ItemSourceGate(file, true)
			},
		},
		{
			name: "write",
			request: func(_ pfslocal.Item, _ pfslocal.Item, handle uint64) any {
				return &pfslocal.WriteRequest{Handle: handle, Data: []byte("payload")}
			},
			expected: func(_ pfslocal.Item, file pfslocal.Item) (*authoritypb.FskitSourcePublication, error) {
				return v3ItemSourceGate(file, true)
			},
		},
		{
			name: "create",
			request: func(root pfslocal.Item, _ pfslocal.Item, _ uint64) any {
				return &pfslocal.CreateRequest{Dir: root, Name: []byte("created"), Mode: 0o644, Exclusive: true}
			},
			expected: func(root pfslocal.Item, _ pfslocal.Item) (*authoritypb.FskitSourcePublication, error) {
				return v3NamespaceSourceGate(root, []byte("created"), false)
			},
		},
		{
			name: "mkdir",
			request: func(root pfslocal.Item, _ pfslocal.Item, _ uint64) any {
				return &pfslocal.MkdirRequest{Dir: root, Name: []byte("directory"), Mode: 0o755}
			},
			expected: func(root pfslocal.Item, _ pfslocal.Item) (*authoritypb.FskitSourcePublication, error) {
				return v3NamespaceSourceGate(root, []byte("directory"), false)
			},
		},
		{
			name: "unlink",
			request: func(root pfslocal.Item, _ pfslocal.Item, _ uint64) any {
				return &pfslocal.RemoveRequest{Dir: root, Name: []byte("gone")}
			},
			expected: func(root pfslocal.Item, _ pfslocal.Item) (*authoritypb.FskitSourcePublication, error) {
				return v3NamespaceSourceGate(root, []byte("gone"), false)
			},
		},
		{
			name: "rename",
			request: func(root pfslocal.Item, _ pfslocal.Item, _ uint64) any {
				return &pfslocal.RenameRequest{FromDir: root, FromName: []byte("old"), ToDir: root, ToName: []byte("new")}
			},
			expected: func(root pfslocal.Item, _ pfslocal.Item) (*authoritypb.FskitSourcePublication, error) {
				return v3RenameSourceGate(root, []byte("old"), root, []byte("new"))
			},
		},
		{
			name: "symlink",
			request: func(root pfslocal.Item, _ pfslocal.Item, _ uint64) any {
				return &pfslocal.SymlinkRequest{Dir: root, Name: []byte("symbol"), Target: []byte("target")}
			},
			expected: func(root pfslocal.Item, _ pfslocal.Item) (*authoritypb.FskitSourcePublication, error) {
				return v3NamespaceSourceGate(root, []byte("symbol"), false)
			},
		},
		{
			name: "hard-link",
			request: func(root pfslocal.Item, file pfslocal.Item, _ uint64) any {
				return &pfslocal.HardLinkRequest{Item: file, Dir: root, Name: []byte("alias")}
			},
			expected: func(root pfslocal.Item, file pfslocal.Item) (*authoritypb.FskitSourcePublication, error) {
				return v3NamespaceSourceGate(root, []byte("alias"), false, file)
			},
		},
		{
			name: "set-xattr-with-corroborating-handle",
			request: func(_ pfslocal.Item, file pfslocal.Item, handle uint64) any {
				return &pfslocal.XattrSetRequest{Item: file, Handle: handle, Name: "user.key", Value: []byte("value")}
			},
			expected: func(_ pfslocal.Item, file pfslocal.Item) (*authoritypb.FskitSourcePublication, error) {
				return v3ItemSourceGate(file, false)
			},
		},
		{
			name: "remove-xattr-with-corroborating-handle",
			request: func(_ pfslocal.Item, file pfslocal.Item, handle uint64) any {
				return &pfslocal.XattrRemoveRequest{Item: file, Handle: handle, Name: "user.key"}
			},
			expected: func(_ pfslocal.Item, file pfslocal.Item) (*authoritypb.FskitSourcePublication, error) {
				return v3ItemSourceGate(file, false)
			},
		},
	}
	for index, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			root := d.resolveReply().Root
			lookupAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{Dir: root, Name: []byte("file")})
			if errno != 0 {
				t.Fatal(errno)
			}
			file := lookupAny.(*pfslocal.LookupReply).Attr.Item
			openedAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.OpenRequest{Item: file, Mode: pfslocal.OpenModeReadWrite})
			if errno != 0 {
				t.Fatal(errno)
			}
			handle := openedAny.(*pfslocal.OpenReply).Handle
			expected, err := test.expected(root, file)
			if err != nil {
				t.Fatal(err)
			}
			operationID := uint64(500 + index)
			client.beforeAssigned = func(request *authoritypb.Request) error {
				if request.GetFskitFrontendOperationId() != operationID {
					return errors.New("visible mutation lost its exact callback identity")
				}
				if !proto.Equal(request.GetFskitSourcePublication(), expected) {
					return errors.New("visible mutation carried a different source publication footprint")
				}
				return nil
			}
			client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
				response := &authoritypb.Response{Mutation: &authoritypb.MutationState{Slot: identity.Slot, AcceptedSequence: identity.Sequence}}
				switch request.GetBody().(type) {
				case *authoritypb.Request_SetAttr:
					response.PostState = testV3PostState(&authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Inode: 2, Mode: 0o600, Nlink: 1, Size: 7})
				case *authoritypb.Request_FskitWrite:
					response = exactTestWriteCommit(identity, request)
					v3PostAttr(response).Mode = 0o600
				case *authoritypb.Request_Rename:
					response.Body = &authoritypb.Response_Rename{Rename: &authoritypb.RenameReply{
						NewPostIdentity: bytes.Repeat([]byte{0xaf}, 16),
					}}
				case *authoritypb.Request_Create:
					response.Body = &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Item: authorityTestItem(10, authoritypb.Attr_REGULAR, 0xa0, 0xa1), Handle: bytes.Repeat([]byte{0xa2}, 16)}}
				case *authoritypb.Request_Mkdir:
					response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: authorityTestItem(11, authoritypb.Attr_DIRECTORY, 0xa3, 0xa4)}}
				case *authoritypb.Request_Symlink:
					response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: authorityTestItem(12, authoritypb.Attr_SYMLINK, 0xa5, 0xa6)}}
				case *authoritypb.Request_Link:
					linked := authorityTestItem(2, authoritypb.Attr_REGULAR, 0x30, 0x40)
					linked.Attr.Nlink = 2
					response.Body = &authoritypb.Response_Link{Link: &authoritypb.LinkReply{Item: linked}}
				}
				return response, nil
			}
			d.bridge.reserveFrontendPublication(operationID)
			if reply, errno := d.dispatchFrontend(context.Background(), operationID, test.request(root, file, handle)); errno != 0 || reply == nil {
				t.Fatalf("visible mutation reply = (%#v, %d)", reply, errno)
			}
			lease := d.bridge.sourcePublication.operationLease(operationID)
			if lease == nil {
				t.Fatal("visible mutation returned without a source lease")
			}
			if !acknowledgeBridgePublished(t, d.bridge, operationID) {
				t.Fatal("visible mutation PublicationAck was not accepted")
			}
			d.bridge.releaseFrontendPublication(operationID)
		})
	}
}

func TestV3DataPlaneRejectsItemHandleIdentityMismatchBeforeSourceAssignment(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	root := d.resolveReply().Root
	lookupAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{Dir: root, Name: []byte("file")})
	if errno != 0 {
		t.Fatal(errno)
	}
	file := lookupAny.(*pfslocal.LookupReply).Attr.Item
	openedAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.OpenRequest{Item: file, Mode: pfslocal.OpenModeReadWrite})
	if errno != 0 {
		t.Fatal(errno)
	}
	handle := openedAny.(*pfslocal.OpenReply).Handle
	other, errno := d.intern(context.Background(), authorityTestItem(3, authoritypb.Attr_REGULAR, 0x31, 0x41), &root)
	if errno != 0 {
		t.Fatal(errno)
	}
	client.mu.Lock()
	before := client.sequence
	client.mu.Unlock()
	mode := uint32(0o600)
	d.bridge.reserveFrontendPublication(520)
	if reply, errno := d.dispatchFrontend(context.Background(), 520, &pfslocal.SetAttrRequest{
		Item: other.item, Handle: handle, Mode: &mode,
	}); errno != darwinEBADF || reply != nil {
		t.Fatalf("mismatched item+handle setattr = (%#v, %d), want EBADF", reply, errno)
	}
	client.mu.Lock()
	after := client.sequence
	client.mu.Unlock()
	if after != before || d.bridge.sourcePublication.operationLease(520) != nil {
		t.Fatalf("identity mismatch reached source assignment: sequence=%d->%d", before, after)
	}
	if !acknowledgeBridgePublished(t, d.bridge, 520) {
		t.Fatal("refused mismatch PublicationAck was not accepted")
	}
	d.bridge.releaseFrontendPublication(520)
}

func TestV3DataPlaneSyncVolumeUsesExactAuthorityBarrier(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	var sawSync bool
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
		sawSync = request.GetSyncFs() != nil
		return &authoritypb.Response{Mutation: &authoritypb.MutationState{Slot: identity.Slot, AcceptedSequence: identity.Sequence}, Body: &authoritypb.Response_SyncFs{SyncFs: &authoritypb.SyncFSReply{}}}, nil
	}
	reply, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.SyncVolumeRequest{})
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
	_, errno := d.read(context.Background(), 0, &pfslocal.ReadRequest{Handle: 1, Length: v3MaxLocalRead + 1})
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
	replyAny, errno := dispatchV3Test(d, context.Background(), 0, request)
	if errno != 0 {
		t.Fatalf("liveness errno=%d", errno)
	}
	reply := replyAny.(*pfslocal.V3LivenessReply)
	if !bytes.Equal(reply.AuthorityEpoch, request.AuthorityEpoch) || !bytes.Equal(reply.SessionID, request.SessionID) {
		t.Fatalf("liveness reply=%#v, want exact authority identity", reply)
	}

	bad := *request
	bad.SessionID = bytes.Repeat([]byte{0xff}, 16)
	if _, errno := dispatchV3Test(d, context.Background(), 0, &bad); errno != darwinEINVAL {
		t.Fatalf("mismatched session errno=%d, want %d", errno, darwinEINVAL)
	}
}

func TestV3LivenessAuthorityFailureIsTerminal(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	client.keepErr = errors.New("authority unreachable")
	_, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.V3LivenessRequest{
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

	d.bridge.reserveFrontendPublication(71)
	if reply, errno := d.dispatchFrontend(context.Background(), 71, &pfslocal.RenameRequest{
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
	lease := d.bridge.sourcePublication.operationLease(71)
	d.bridge.sourcePublication.mu.Lock()
	released := lease != nil && lease.released
	unresolvedAttributes, unresolvedData, unresolvedNames := 0, 0, 0
	if lease != nil {
		unresolvedAttributes, unresolvedData = lease.unresolvedAttributes, lease.unresolvedData
		unresolvedNames = len(lease.names)
	}
	d.bridge.sourcePublication.mu.Unlock()
	if lease == nil || released {
		t.Fatal("definite visibility interruption released its source gate before PublicationAck")
	}
	if unresolvedAttributes != 0 || unresolvedData != 0 {
		t.Fatalf("definite visibility interruption did not resolve its impossible returned bindings: attrs=%d data=%d names=%d", unresolvedAttributes, unresolvedData, unresolvedNames)
	}
	if !acknowledgeBridgePublished(t, d.bridge, 71) {
		t.Fatal("exact PublicationAck was not accepted")
	}
	d.bridge.sourcePublication.mu.Lock()
	released = lease.released
	d.bridge.sourcePublication.mu.Unlock()
	if released {
		t.Fatal("PublicationAck released the source gate before its handler reservation retired")
	}
	d.bridge.releaseFrontendPublication(71)
	d.bridge.sourcePublication.mu.Lock()
	released = lease.released
	d.bridge.sourcePublication.mu.Unlock()
	if !released {
		t.Fatal("PublicationAck plus handler retirement did not release the definite-interruption source gate")
	}
}

func TestV3DataPlaneRejectsLinuxOnlyItemVisibilityRetry(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, _ *authoritypb.Request) (*authoritypb.Response, error) {
		return &authoritypb.Response{
			Errno: errnos.EINTR, Failure: authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_RETRY,
			FskitRepairRetrySequence: 1,
			Mutation:                 &authoritypb.MutationState{Slot: identity.Slot, AcceptedSequence: identity.Sequence},
		}, nil
	}
	root := d.resolveReply().Root
	if _, errno := dispatchV3Test(d, context.Background(), 74, &pfslocal.RenameRequest{
		FromDir: root, FromName: []byte("old"), ToDir: root, ToName: []byte("new"),
	}); errno != darwinEIO {
		t.Fatalf("Linux-only item retry on FSKit = %d, want fail-closed EIO", errno)
	}
	if d.terminalError() == nil {
		t.Fatal("Linux-only item retry did not terminalize callback-serialized frontend")
	}
}

func TestV3DataPlaneAssignedUncertaintyFailsClosedAcrossPublicationAck(t *testing.T) {
	client := newFakeV3DataClient()
	d := testV3DataPlane(t, client)
	lookupAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{
		Dir: d.resolveReply().Root, Name: []byte("file"),
	})
	if errno != 0 {
		t.Fatal(errno)
	}
	file := lookupAny.(*pfslocal.LookupReply).Attr.Item
	openedAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.OpenRequest{
		Item: file, Mode: pfslocal.OpenModeReadWrite,
	})
	if errno != 0 {
		t.Fatal(errno)
	}
	handle := openedAny.(*pfslocal.OpenReply).Handle
	client.mutation = func(context.Context, authorityrpc.MutationIdentity, *authoritypb.Request) (*authoritypb.Response, error) {
		return nil, authorityrpc.ErrTransportUncertain
	}
	d.bridge.reserveFrontendPublication(79)
	if reply, errno := d.dispatchFrontend(context.Background(), 79, &pfslocal.WriteRequest{
		Handle: handle, Offset: 0, Data: []byte("uncertain"),
	}); errno != darwinEIO || reply != nil {
		t.Fatalf("uncertain write = (%#v, %d), want terminal EIO", reply, errno)
	}
	lease := d.bridge.sourcePublication.operationLease(79)
	d.bridge.sourcePublication.mu.Lock()
	assigned, released, terminal := uint32(0), false, d.bridge.sourcePublication.terminal
	if lease != nil {
		assigned, released = lease.assigned, lease.released
	}
	d.bridge.sourcePublication.mu.Unlock()
	if lease == nil || assigned == 0 || released {
		t.Fatalf("assigned uncertain lease = %#v", lease)
	}
	if d.terminalError() == nil || terminal == nil {
		t.Fatal("assigned uncertainty did not terminate both data plane and source coordinator")
	}
	if !acknowledgeBridgePublished(t, d.bridge, 79) {
		t.Fatal("terminal callback PublicationAck was not recorded")
	}
	d.bridge.releaseFrontendPublication(79)
	d.bridge.sourcePublication.mu.Lock()
	released = lease.released
	d.bridge.sourcePublication.mu.Unlock()
	if released {
		t.Fatal("PublicationAck reopened an assigned-uncertain terminal source gate")
	}
}

func TestV3DataPlaneAuthoritySuccessWithUnpublishableItemResultIsTerminal(t *testing.T) {
	tests := []struct {
		name    string
		request func(file pfslocal.Item, handle uint64) any
		result  func(authorityrpc.MutationIdentity, *authoritypb.Request) *authoritypb.Response
	}{
		{
			name: "setattr-missing-post-attr",
			request: func(file pfslocal.Item, handle uint64) any {
				mode := uint32(0o600)
				return &pfslocal.SetAttrRequest{Item: file, Handle: handle, Mode: &mode}
			},
			result: func(identity authorityrpc.MutationIdentity, _ *authoritypb.Request) *authoritypb.Response {
				return &authoritypb.Response{Mutation: &authoritypb.MutationState{
					Slot: identity.Slot, AcceptedSequence: identity.Sequence,
				}}
			},
		},
		{
			name: "write-missing-post-attr",
			request: func(_ pfslocal.Item, handle uint64) any {
				return &pfslocal.WriteRequest{Handle: handle, Data: []byte("committed")}
			},
			result: func(identity authorityrpc.MutationIdentity, request *authoritypb.Request) *authoritypb.Response {
				write := request.GetFskitWrite()
				return &authoritypb.Response{
					Mutation: &authoritypb.MutationState{Slot: identity.Slot, AcceptedSequence: identity.Sequence},
					Body: &authoritypb.Response_FskitWrite{FskitWrite: &authoritypb.FskitWriteReply{
						TransactionId: write.GetTransactionId(), CommittedSize: write.GetFragmentOffset(),
						AssignedOffset: write.GetPosition(), PostSize: write.GetPosition() + write.GetFragmentOffset(),
						VisibilitySequence: identity.Sequence, Flags: v3WriteReplyCommitted,
					}},
				}
			},
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newFakeV3DataClient()
			d := testV3DataPlane(t, client)
			lookupAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.LookupRequest{
				Dir: d.resolveReply().Root, Name: []byte("file"),
			})
			if errno != 0 {
				t.Fatal(errno)
			}
			file := lookupAny.(*pfslocal.LookupReply).Attr.Item
			openedAny, errno := dispatchV3Test(d, context.Background(), 0, &pfslocal.OpenRequest{
				Item: file, Mode: pfslocal.OpenModeReadWrite,
			})
			if errno != 0 {
				t.Fatal(errno)
			}
			handle := openedAny.(*pfslocal.OpenReply).Handle
			client.mutation = func(_ context.Context, identity authorityrpc.MutationIdentity, request *authoritypb.Request) (*authoritypb.Response, error) {
				return test.result(identity, request), nil
			}
			operationID := uint64(180 + index)
			d.bridge.reserveFrontendPublication(operationID)
			if reply, errno := d.dispatchFrontend(context.Background(), operationID, test.request(file, handle)); errno != darwinEIO || reply != nil {
				t.Fatalf("unpublishable committed result = (%#v, %d), want terminal EIO", reply, errno)
			}
			lease := d.bridge.sourcePublication.operationLease(operationID)
			d.bridge.sourcePublication.mu.Lock()
			assigned, released, terminal := uint32(0), false, d.bridge.sourcePublication.terminal
			committed := false
			if lease != nil {
				assigned, released = lease.assigned, lease.released
			}
			if op := d.bridge.sourcePublication.operations[operationID]; op != nil {
				committed = op.committed
			}
			d.bridge.sourcePublication.mu.Unlock()
			if lease == nil || assigned == 0 || !committed || released || terminal == nil || d.terminalError() == nil {
				t.Fatalf("committed malformed result did not freeze publication: lease=%#v assigned=%d committed=%t released=%t terminal=%v", lease, assigned, committed, released, terminal)
			}
			known, ackErr := d.bridge.acknowledgePublication(
				operationID, pfslocal.PublicationSemanticCommitNotPublished,
			)
			if !known || !errors.Is(ackErr, errV3SourcePublicationNotPublished) {
				t.Fatalf("terminal callback PublicationAck = (%t, %v)", known, ackErr)
			}
			d.bridge.releaseFrontendPublication(operationID)
			d.bridge.sourcePublication.mu.Lock()
			released = lease.released
			d.bridge.sourcePublication.mu.Unlock()
			if released {
				t.Fatal("PublicationAck and retirement reopened an unpublishable committed result")
			}
		})
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
	if _, errno := dispatchV3Test(d, ctx, 72, &pfslocal.RenameRequest{
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
	if _, errno := dispatchV3Test(d, context.Background(), 73, &pfslocal.RenameRequest{
		FromDir: root, FromName: []byte("old"), ToDir: root, ToName: []byte("new"),
	}); errno != darwinEINTR {
		t.Fatalf("v1 visibility interruption errno=%d, want frozen EINTR", errno)
	}
}
