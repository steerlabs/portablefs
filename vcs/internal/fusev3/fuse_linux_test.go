//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

// fakeRPC is a programmable stand-in for the authority. It answers every
// request shape the frontend issues, so the real mount path -- including
// MountVolume -- is reachable without a kernel.
type fakeRPC struct {
	mu sync.Mutex

	writeTransactions []*authoritypb.WriteTransactionRequest
	oneShotWrites     []*authoritypb.OneShotWriteRequest
	oneShotRequests   []*authoritypb.Request
	setattrs          []*authoritypb.SetAttrRequest
	flushes           []*authoritypb.FlushRequest
	fsyncs            []*authoritypb.FsyncRequest
	syncFS            int
	fileCloses        []*authoritypb.CloseRequest
	readdirs          []*authoritypb.ReadDirRequest
	reclaims          [][]byte
	keepAlives        int
	reads             int
	calls             int
	assignments       int
	mutationCalls     int
	closes            int
	canceled          int

	closeFailure   syscall.Errno
	mkdirFailure   syscall.Errno
	reclaimFailure syscall.Errno
	keepAliveErr   syscall.Errno
	xattrValue     []byte
	xattrNames     [][]byte
	fileData       []byte
	renameNewPost  []byte
	renameOldPost  []byte
	replyOverride  func(*authoritypb.Request) (*authoritypb.Response, error)

	root *authoritypb.Item
	item *authoritypb.Item
	// byName, when non-nil, mints one distinct object per name so a test can
	// walk a volume path of several different directories. Without it every
	// lookup answers with the same object and a path has no shape.
	byName map[string]*authoritypb.Item
	// missingNames are the names this authority answers ENOENT for, which is
	// how a negative resolution is made reachable without a kernel. A name is
	// removed from the set by whatever creates it, so the miss/create/hit
	// sequence a probing workload performs can be replayed exactly.
	missingNames        map[string]bool
	handle              []byte
	maxRead             uint32
	maxWrite            uint32
	maxWriteTransaction uint64
	lease               time.Duration
	done                chan struct{}

	dirPages     []*authoritypb.ReadDirReply
	dirPageIndex int

	// The strict cache contract. events is the programmed visibility stream;
	// acked records every cursor the frontend acknowledged, which is what the
	// liveness assertions read.
	session        []byte
	initial        *authoritypb.VisibilityCursor
	events         chan *authoritypb.VisibilityEvent
	acked          []*authoritypb.VisibilityCursor
	blocked        []*authoritypb.VisibilityCursor
	blockedParents [][]uint64
	blockedErr     error
	// onBlocked models the authority's nonterminal cycle break: it refuses the
	// queued overlapping mutation before returning success to the report.
	onBlocked     func()
	detachProofs  []MountAbsenceProof
	detachErr     error
	visibilityErr error
	// mutationStates are attached, in order, to successful mutation responses.
	// afterMutation runs after the envelope has been attached but before the
	// response is returned to the frontend, allowing ordering tests to place a
	// raw callback precisely on either side of transport delivery.
	mutationStates       []*authoritypb.MutationState
	mutationSeq          uint64
	afterMutation        func()
	retainedConsumption  authorityrpc.ResponseConsumption
	retainedConsumptions []authorityrpc.ResponseConsumption

	// observeCancel makes every call wait briefly on its own context so a test
	// can prove whether the kernel's INTERRUPT reached the authority.
	observeCancel bool
	// block, when non-nil, holds every call except Detach until it is closed.
	block chan struct{}
	// hook runs outside the lock before a reply is produced.
	hook func(*authoritypb.Request)
}

func newFakeRPC() *fakeRPC {
	return &fakeRPC{
		root:                testItem(1, authoritypb.Attr_DIRECTORY, 1),
		item:                testItem(7, authoritypb.Attr_REGULAR, 7),
		handle:              testToken(900),
		maxRead:             64 * 1024,
		maxWrite:            64 * 1024,
		maxWriteTransaction: kernelMaxRWCount(),
		lease:               time.Minute,
		done:                make(chan struct{}),
		session:             []byte("test-mount-00001"),
	}
}

func (f *fakeRPC) Root() *authoritypb.Item            { return cloneItem(f.root) }
func (f *fakeRPC) IOLimits() (uint32, uint32)         { return f.maxRead, f.maxWrite }
func (f *fakeRPC) MaxWriteTransactionBytes() uint64   { return f.maxWriteTransaction }
func (f *fakeRPC) SessionLease() time.Duration        { return f.lease }
func (f *fakeRPC) SessionDone() <-chan struct{}       { return f.done }
func (f *fakeRPC) SessionError() error                { return nil }
func (f *fakeRPC) SessionEndPending() <-chan struct{} { return f.done }
func (f *fakeRPC) SessionEndCause() error             { return nil }
func (f *fakeRPC) FinishLocalSessionEnforcement()     {}

func (f *fakeRPC) Close() error {
	f.mu.Lock()
	f.closes++
	f.mu.Unlock()
	return nil
}

func (f *fakeRPC) CallRead(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	f.mu.Lock()
	f.reads++
	f.mu.Unlock()
	return f.dispatch(ctx, request)
}

func (f *fakeRPC) CallReadRetained(
	ctx context.Context,
	request *authoritypb.Request,
	_ func(error),
) (*authoritypb.Response, authorityrpc.ResponseConsumption, error) {
	response, err := f.CallRead(ctx, request)
	f.mu.Lock()
	consumption := f.takeRetainedConsumptionLocked()
	f.mu.Unlock()
	return response, consumption, err
}

func (f *fakeRPC) CallIdempotent(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	return f.CallRead(ctx, request)
}

func (f *fakeRPC) CallIdempotentRetained(
	ctx context.Context,
	request *authoritypb.Request,
	_ func(error),
) (*authoritypb.Response, authorityrpc.ResponseConsumption, error) {
	response, err := f.CallIdempotent(ctx, request)
	f.mu.Lock()
	consumption := f.takeRetainedConsumptionLocked()
	f.mu.Unlock()
	return response, consumption, err
}

func (f *fakeRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	return f.CallMutationWithIdentity(ctx, request, nil)
}

func (f *fakeRPC) CallMutationWithIdentity(ctx context.Context, request *authoritypb.Request, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	f.mu.Lock()
	f.mutationCalls++
	next := f.mutationSeq + 1
	f.mu.Unlock()
	if assigned != nil {
		f.mu.Lock()
		f.assignments++
		f.mu.Unlock()
		if err := assigned(authorityrpc.MutationIdentity{Slot: 0, Sequence: next}); err != nil {
			return nil, err
		}
	}
	response, err := f.dispatch(ctx, request)
	if err != nil || response == nil {
		return response, err
	}
	f.mu.Lock()
	if len(f.mutationStates) != 0 {
		response.Mutation = proto.Clone(f.mutationStates[0]).(*authoritypb.MutationState)
		f.mutationStates = f.mutationStates[1:]
	} else {
		f.mutationSeq++
		response.Mutation = &authoritypb.MutationState{Slot: 0, AcceptedSequence: f.mutationSeq}
	}
	after := f.afterMutation
	f.mu.Unlock()
	if after != nil {
		after()
	}
	return response, nil
}

func (f *fakeRPC) CallMutationWithIdentityRetained(
	ctx context.Context,
	request *authoritypb.Request,
	assigned authorityrpc.MutationAssigned,
	_ func(error),
) (*authoritypb.Response, authorityrpc.ResponseConsumption, error) {
	response, err := f.CallMutationWithIdentity(ctx, request, assigned)
	f.mu.Lock()
	consumption := f.takeRetainedConsumptionLocked()
	f.mu.Unlock()
	return response, consumption, err
}

func (f *fakeRPC) takeRetainedConsumptionLocked() authorityrpc.ResponseConsumption {
	if len(f.retainedConsumptions) == 0 {
		return f.retainedConsumption
	}
	consumption := f.retainedConsumptions[0]
	f.retainedConsumptions = f.retainedConsumptions[1:]
	return consumption
}

type recordingResponseConsumption struct{ calls atomic.Int32 }

func (r *recordingResponseConsumption) Consume() { r.calls.Add(1) }

func (f *fakeRPC) dispatch(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	f.mu.Lock()
	f.calls++
	block, observe, hook := f.block, f.observeCancel, f.hook
	f.mu.Unlock()
	// Detach is the shutdown path and is never held: closeLocked must be able
	// to end the session even when everything else is stalled.
	if request.GetDetach() == nil {
		if block != nil {
			select {
			case <-block:
			case <-ctx.Done():
				return nil, f.noteCancel(ctx)
			}
		}
		if observe {
			select {
			case <-ctx.Done():
				return nil, f.noteCancel(ctx)
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
	if hook != nil {
		hook(request)
	}
	return f.reply(request)
}

func (f *fakeRPC) noteCancel(ctx context.Context) error {
	f.mu.Lock()
	f.canceled++
	f.mu.Unlock()
	return ctx.Err()
}

func (f *fakeRPC) reply(request *authoritypb.Request) (*authoritypb.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.replyOverride != nil {
		return f.replyOverride(request)
	}
	switch {
	case request.GetKeepAlive() != nil:
		f.keepAlives++
		if f.keepAliveErr != 0 {
			return &authoritypb.Response{Errno: int32(f.keepAliveErr)}, nil
		}
	case request.GetReclaim() != nil:
		f.reclaims = append(f.reclaims, cloneBytes(request.GetReclaim().GetItem()))
		if f.reclaimFailure != 0 {
			return &authoritypb.Response{Errno: int32(f.reclaimFailure)}, nil
		}
	case request.GetClose() != nil:
		f.fileCloses = append(f.fileCloses, proto.Clone(request.GetClose()).(*authoritypb.CloseRequest))
		if f.closeFailure != 0 {
			return &authoritypb.Response{Errno: int32(f.closeFailure)}, nil
		}
	case request.GetFlush() != nil:
		f.flushes = append(f.flushes, proto.Clone(request.GetFlush()).(*authoritypb.FlushRequest))
	case request.GetFsync() != nil:
		f.fsyncs = append(f.fsyncs, proto.Clone(request.GetFsync()).(*authoritypb.FsyncRequest))
	case request.GetSyncFs() != nil:
		f.syncFS++
		return &authoritypb.Response{Body: &authoritypb.Response_SyncFs{SyncFs: &authoritypb.SyncFSReply{}}}, nil
	case request.GetGetXattr() != nil:
		return &authoritypb.Response{Body: &authoritypb.Response_GetXattr{GetXattr: &authoritypb.GetXattrReply{Value: cloneBytes(f.xattrValue)}}}, nil
	case request.GetListXattr() != nil:
		names := make([][]byte, len(f.xattrNames))
		for index, name := range f.xattrNames {
			names[index] = cloneBytes(name)
		}
		return &authoritypb.Response{Body: &authoritypb.Response_ListXattr{ListXattr: &authoritypb.ListXattrReply{Names: names}}}, nil
	case request.GetGetAttr() != nil:
		return &authoritypb.Response{Body: &authoritypb.Response_GetAttr{GetAttr: &authoritypb.GetAttrReply{Attr: cloneItem(f.item).GetAttr()}}}, nil
	case request.GetLookup() != nil:
		if f.missingNames[string(request.GetLookup().GetName())] {
			return &authoritypb.Response{Errno: int32(syscall.ENOENT)}, nil
		}
		return &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: f.namedItem(request.GetLookup().GetName())}}}, nil
	case request.GetMkdir() != nil:
		if f.mkdirFailure != 0 {
			return &authoritypb.Response{Errno: int32(f.mkdirFailure)}, nil
		}
		delete(f.missingNames, string(request.GetMkdir().GetName()))
		return &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: f.namedItem(request.GetMkdir().GetName())}}}, nil
	case request.GetSymlink() != nil:
		return &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: f.namedItem(request.GetSymlink().GetName())}}}, nil
	case request.GetOpen() != nil:
		return &authoritypb.Response{Body: &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: cloneBytes(f.handle)}}}, nil
	case request.GetCreate() != nil:
		return &authoritypb.Response{Body: &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Item: cloneItem(f.item), Handle: cloneBytes(f.handle)}}}, nil
	case request.GetRead() != nil:
		offset := int(request.GetRead().GetOffset())
		length := int(request.GetRead().GetLength())
		data := []byte(nil)
		if offset < len(f.fileData) {
			data = cloneBytes(f.fileData[offset:min(offset+length, len(f.fileData))])
		}
		return &authoritypb.Response{Body: &authoritypb.Response_Read{Read: &authoritypb.ReadReply{Data: data}}}, nil
	case request.GetReadDir() != nil:
		f.readdirs = append(f.readdirs, proto.Clone(request.GetReadDir()).(*authoritypb.ReadDirRequest))
		if f.dirPageIndex >= len(f.dirPages) {
			return &authoritypb.Response{Body: &authoritypb.Response_ReadDir{ReadDir: &authoritypb.ReadDirReply{Verifier: testToken(5), Eof: true}}}, nil
		}
		page := f.dirPages[f.dirPageIndex]
		f.dirPageIndex++
		return &authoritypb.Response{Body: &authoritypb.Response_ReadDir{ReadDir: proto.Clone(page).(*authoritypb.ReadDirReply)}}, nil
	case request.GetWriteTransaction() != nil:
		writeRequest := proto.Clone(request.GetWriteTransaction()).(*authoritypb.WriteTransactionRequest)
		f.writeTransactions = append(f.writeTransactions, writeRequest)
		reply := &authoritypb.WriteTransactionReply{TransactionId: writeRequest.GetTransactionId()}
		switch writeRequest.GetPhase() {
		case authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN:
			reply.Flags = fuse.PFS_WRITE_OUT_BEGUN
		case authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA:
			reply.Flags = fuse.PFS_WRITE_OUT_STAGED
		case authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_ABORT:
			reply.Flags = fuse.PFS_WRITE_OUT_ABORTED
		case authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT:
			reply.Flags = fuse.PFS_WRITE_OUT_COMMITTED
			reply.CommittedSize = writeRequest.GetFragmentOffset()
			reply.AssignedOffset = writeRequest.GetPosition()
			if writeRequest.GetFlags()&uint32(syscall.O_APPEND) != 0 {
				reply.AssignedOffset = 100
			}
			reply.PostSize = 100 + reply.CommittedSize
			if writeRequest.GetFlags()&uint32(syscall.O_APPEND) == 0 && reply.AssignedOffset+reply.CommittedSize > 100 {
				reply.PostSize = reply.AssignedOffset + reply.CommittedSize
			}
			reply.VisibilitySequence = 17
		default:
			return &authoritypb.Response{Errno: int32(syscall.EPROTO)}, nil
		}
		response := &authoritypb.Response{Body: &authoritypb.Response_WriteTransaction{WriteTransaction: reply}}
		if writeRequest.GetPhase() == authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT {
			response.PostAttr = &authoritypb.Attr{Inode: f.item.GetAttr().GetInode(), Kind: authoritypb.Attr_REGULAR, Mode: 0o600, Size: int64(reply.GetPostSize())}
		}
		return response, nil
	case request.GetOneShotWrite() != nil:
		f.oneShotRequests = append(f.oneShotRequests, proto.Clone(request).(*authoritypb.Request))
		writeRequest := proto.Clone(request.GetOneShotWrite()).(*authoritypb.OneShotWriteRequest)
		f.oneShotWrites = append(f.oneShotWrites, writeRequest)
		assigned := writeRequest.GetPosition()
		if writeRequest.GetFlags()&uint32(syscall.O_APPEND) != 0 {
			assigned = 100
		}
		postSize := assigned + uint64(writeRequest.GetSize())
		return &authoritypb.Response{
			PostAttr: &authoritypb.Attr{Inode: f.item.GetAttr().GetInode(), Kind: authoritypb.Attr_REGULAR, Mode: 0o600, Size: int64(postSize)},
			Body: &authoritypb.Response_OneShotWrite{OneShotWrite: &authoritypb.OneShotWriteReply{
				CommittedSize: uint64(writeRequest.GetSize()), AssignedOffset: assigned,
				PostSize: postSize, VisibilitySequence: 17, Flags: fuse.PFS_WRITE_OUT_COMMITTED,
			}},
		}, nil
	case request.GetSetAttr() != nil:
		f.setattrs = append(f.setattrs, request.GetSetAttr())
		return &authoritypb.Response{PostAttr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Mode: 0o600}}, nil
	case request.GetRename() != nil:
		rename := request.GetRename()
		newPost := cloneBytes(f.renameNewPost)
		if len(newPost) == 0 {
			moved := f.item
			if f.byName != nil && f.byName[string(rename.GetOldName())] != nil {
				moved = f.byName[string(rename.GetOldName())]
			}
			newPost = cloneBytes(moved.GetStableIdentity())
		}
		oldPost := cloneBytes(f.renameOldPost)
		if len(oldPost) == 0 && rename.GetExchange() {
			replaced := f.item
			if f.byName != nil && f.byName[string(rename.GetNewName())] != nil {
				replaced = f.byName[string(rename.GetNewName())]
			}
			oldPost = cloneBytes(replaced.GetStableIdentity())
		}
		return &authoritypb.Response{Body: &authoritypb.Response_Rename{Rename: &authoritypb.RenameReply{
			NewPostIdentity: newPost,
			OldPostIdentity: oldPost,
		}}}, nil
	}
	return &authoritypb.Response{}, nil
}

// namedItem answers with the object this fake associates with one name. The
// caller holds f.mu.
func (f *fakeRPC) namedItem(name []byte) *authoritypb.Item {
	if f.byName == nil {
		return cloneItem(f.item)
	}
	if item, known := f.byName[string(name)]; known {
		return cloneItem(item)
	}
	inode := uint64(1000 + len(f.byName))
	item := testItem(inode, authoritypb.Attr_DIRECTORY, inode)
	f.byName[string(name)] = item
	return cloneItem(item)
}

func (f *fakeRPC) snapshot(read func(*fakeRPC)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	read(f)
}

func testConfig(watermark int) Config {
	return Config{
		MountInstanceID: "mnt_AAAAAAAAAAAAAAAAAAAAAA", RequestTimeout: 2 * time.Second,
		MaxBackground: 8, MaxInFlight: 16, ReclaimQueue: watermark,
		PresentedUID: 501, PresentedGID: 20, Coherence: CoherenceStrict,
	}
}

func testMount(t *testing.T, watermark int) (*Mount, *fakeRPC) {
	t.Helper()
	rpc := newFakeRPC()
	mount := newMount(context.Background(), rpc, testConfig(watermark))
	mount.plannedFSName = "portablefs:" + testConfig(watermark).MountInstanceID
	mount.plannedMountpoint = t.TempDir()
	root := &node{mount: mount, item: testItem(1, authoritypb.Attr_DIRECTORY, 0), requestTimeout: time.Second, maxRead: 64 * 1024, maxWrite: 64 * 1024}
	newRawFileSystem(mount, root)
	t.Cleanup(mount.cancel)
	return mount, rpc
}

func testRawFileSystem(t *testing.T, watermark int) (*rawFileSystem, *Mount, *fakeRPC) {
	t.Helper()
	mount, rpc := testMount(t, watermark)
	return mount.raw, mount, rpc
}

var testReplyUnique atomic.Uint64

func init() {
	// Patched Linux allocates ordinary FUSE request identities from the positive
	// even sequence. Tests use the same disjoint space so publication identities
	// can exercise the mandatory odd sequence without artificial collisions.
	testReplyUnique.Store(2)
}

func nextTestRequestUnique() uint64 { return testReplyUnique.Add(2) }

const (
	testPublicationNodeID = uint64(fuse.FUSE_ROOT_ID)
	testPublicationOpcode = uint32(1) // FUSE_LOOKUP; only the exact echoed identity matters here.
)

// completeTestReply models the strict patched-kernel publication handshake for
// direct RawFileSystem tests. A successful original /dev/fuse write is not the
// publication boundary: the kernel first performs its VFS postprocessing, then
// sends PFS_PUBLISH, and only the physical ACK write releases frontend state.
func completeTestReply(t *testing.T, raw *rawFileSystem, unique uint64, status fuse.Status) {
	t.Helper()
	if !raw.ReplyWriteOrdered(unique) {
		return
	}
	marked := raw.ReplyPublishMarked(unique, testPublicationNodeID, testPublicationOpcode)
	raw.ReplyWritten(unique, status)
	if status.Ok() && marked {
		acknowledgeTestPublication(t, raw, unique)
	}
}

func markTestReply(t *testing.T, raw *rawFileSystem, unique uint64) {
	t.Helper()
	if !raw.ReplyPublishMarked(unique, testPublicationNodeID, testPublicationOpcode) {
		t.Fatalf("mark reply %d for publication", unique)
	}
}

func acknowledgeTestPublication(t *testing.T, raw *rawFileSystem, unique uint64) {
	t.Helper()
	serial := nextTestRequestUnique()
	publishUnique := uint64(1)<<61 | serial
	publicationID := serial - 1
	in := &fuse.PFSPublishIn{
		InHeader:      fuse.InHeader{Unique: publishUnique},
		RequestUnique: unique,
		PublicationID: publicationID,
		Nodeid:        testPublicationNodeID,
		Opcode:        testPublicationOpcode,
	}
	out := &fuse.PFSPublishOut{}
	if got := raw.PFSPublish(nil, in, out); !got.Ok() {
		t.Fatalf("PFS_PUBLISH for reply %d = %v", unique, got)
	}
	if out.RequestUnique != in.RequestUnique || out.PublicationID != in.PublicationID ||
		out.Nodeid != in.Nodeid || out.Opcode != in.Opcode || out.Flags != fuse.PFS_PUBLISH_ACK {
		t.Fatalf("PFS_PUBLISH ACK for reply %d = %+v", unique, out)
	}
	raw.ReplyWritten(publishUnique, fuse.OK)
}

// testMutationContext models the RawFS ownership which direct node unit tests
// intentionally bypass. Its completion resolves namespace post-bindings only
// for tests whose assertion is unrelated to returned cache identity; real RawFS
// callbacks attach the authoritative identity before reaching this boundary.
func testMutationContext(t *testing.T, mount *Mount) (context.Context, func(success bool)) {
	t.Helper()
	unique := nextTestRequestUnique()
	ctx, callbackDone, status := mount.raw.mutationContext(unique)
	if !status.Ok() {
		t.Fatalf("reserve test reply publication: %v", status)
	}
	return ctx, func(success bool) {
		t.Helper()
		lease := sourceLeaseFromContext(ctx)
		if success && lease != nil {
			lease.resolveAllNoBinding()
			if err := completeSourcePublication(ctx); err != nil {
				t.Fatalf("complete test source publication: %v", err)
			}
		}
		callbackDone()
		completeTestReply(t, mount.raw, unique, fuse.OK)
	}
}

func testRawCall(t *testing.T, raw *rawFileSystem, call func(unique uint64) fuse.Status) fuse.Status {
	t.Helper()
	unique := nextTestRequestUnique()
	status := call(unique)
	completeTestReply(t, raw, unique, fuse.OK)
	return status
}

func testVisibleMutation[T any](t *testing.T, mount *Mount, call func(context.Context) (T, syscall.Errno)) (T, syscall.Errno) {
	t.Helper()
	ctx, finish := testMutationContext(t, mount)
	result, errno := call(ctx)
	finish(errno == 0)
	return result, errno
}

func testNode(mount *Mount) *node {
	return &node{mount: mount, item: testItem(7, authoritypb.Attr_REGULAR, 7), requestTimeout: time.Second, maxRead: 64 * 1024, maxWrite: 64 * 1024}
}

func popReclaim(t *testing.T, mount *Mount) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	token, ok := mount.reclaim.pop(ctx)
	if !ok {
		t.Fatal("expected a queued reclaim")
	}
	return token
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func testItem(inode uint64, kind authoritypb.Attr_Kind, tokenID uint64) *authoritypb.Item {
	return &authoritypb.Item{
		Token: testToken(tokenID), StableIdentity: testIdentity(inode),
		Attr: &authoritypb.Attr{Inode: inode, Kind: kind, Mode: 0o600},
	}
}

func testToken(id uint64) []byte {
	token := make([]byte, 16)
	binary.BigEndian.PutUint64(token[8:], id)
	return token
}

// --- Defect 8: the direct-I/O decision is explicit and asserted -------------

func TestOpenAndCreateAlwaysReturnTheExactCacheablePair(t *testing.T) {
	mount, _ := testMount(t, 8)
	n := testNode(mount)
	openCtx, finishOpen := testMutationContext(t, mount)
	_, flags, errno := n.Open(openCtx, syscall.O_RDONLY)
	finishOpen(errno == 0)
	if errno != 0 {
		t.Fatalf("Open errno = %v", errno)
	}
	if flags != coherentOpenFlags {
		t.Fatalf("Open OpenFlags = %#x, want exactly %#x", flags, coherentOpenFlags)
	}
	ctx, finish := testMutationContext(t, mount)
	_, _, createFlags, errno := n.Create(ctx, "child", syscall.O_RDWR|syscall.O_CREAT, 0o644)
	finish(errno == 0)
	if errno != 0 {
		t.Fatalf("Create errno = %v", errno)
	}
	if createFlags != coherentOpenFlags {
		t.Fatalf("Create OpenFlags = %#x, want exactly %#x", createFlags, coherentOpenFlags)
	}
	// The pair is exact in both directions. FOPEN_PFS_SHARED is what routes
	// writes through the kernel transaction and what makes the kernel refuse
	// every shared mmap, so it can never be dropped. FOPEN_DIRECT_IO is now
	// refused by the kernel outright: it would route reads around the page
	// cache the DATA barrier is written against, and there is no compatibility
	// mode in which both pairs are accepted.
	for _, got := range []uint32{flags, createFlags} {
		if got&fuse.FOPEN_KEEP_CACHE == 0 || got&fuse.FOPEN_PFS_SHARED == 0 {
			t.Fatalf("authority open flags %#x must be exactly KEEP_CACHE|PFS_SHARED", got)
		}
		if got&fuse.FOPEN_DIRECT_IO != 0 {
			t.Fatalf("authority open flags %#x must never carry FOPEN_DIRECT_IO", got)
		}
	}
}

func TestEveryAuthorityAttrIsExplicitlyShared(t *testing.T) {
	for _, kind := range []authoritypb.Attr_Kind{authoritypb.Attr_REGULAR, authoritypb.Attr_DIRECTORY, authoritypb.Attr_SYMLINK} {
		var out fuse.Attr
		fillAttr(&authoritypb.Attr{Inode: 7, Kind: kind, Mode: 0o600}, &out, 1, 2)
		if out.Flags != fuse.FUSE_ATTR_PFS_SHARED {
			t.Fatalf("%s attr flags = %#x, want exactly PFS_SHARED", kind, out.Flags)
		}
	}
}

func TestMountOptionsRefuseSharedMmapAsADecision(t *testing.T) {
	options := mountOptions(testConfig(8), 128*1024, 64*1024)
	if options.DisabledCapabilities&fuse.CAP_DIRECT_IO_ALLOW_MMAP == 0 {
		t.Fatal("shared mmap over direct I/O must be disabled explicitly, not left to kernel defaults")
	}
	if options.ExtraCapabilities&fuse.CAP_DIRECT_IO_ALLOW_MMAP != 0 {
		t.Fatal("direct-I/O shared-mmap capability must never be requested")
	}
	if options.ExtraCapabilities&fuse.CAP_ATOMIC_O_TRUNC == 0 {
		t.Fatal("atomic open-truncate must be explicitly requested")
	}
	if options.ExtraCapabilities&fuse.CAP_PFS_STRICT_COHERENCE == 0 ||
		options.ExtraCapabilities&fuse.CAP_PFS_CACHED_DATA == 0 ||
		options.ExtraCapabilities&fuse.CAP_PFS_WRITE_ONESHOT == 0 {
		t.Fatal("every bit of the indivisible strict-coherence revision must be explicitly requested")
	}
	if options.DisabledCapabilities&fuse.CAP_AUTO_INVAL_DATA == 0 || !options.ExplicitDataCacheControl {
		t.Fatal("a retained page cache must be withdrawn by this mount's own repair, never by an mtime heuristic")
	}
	if options.ExtraCapabilities&fuse.CAP_HANDLE_KILLPRIV_V2 == 0 {
		t.Fatal("HANDLE_KILLPRIV_V2 must be explicitly requested")
	}
	if options.ExtraCapabilities&fuse.CAP_HAS_RESEND != 0 {
		t.Fatal("strict mounts must not negotiate HAS_RESEND")
	}
	if options.DisabledCapabilities&(fuse.CAP_PASSTHROUGH|fuse.CAP_NO_OPEN_SUPPORT|fuse.CAP_NO_OPENDIR_SUPPORT) !=
		fuse.CAP_PASSTHROUGH|fuse.CAP_NO_OPEN_SUPPORT|fuse.CAP_NO_OPENDIR_SUPPORT {
		t.Fatal("strict mount did not disable passthrough and no-open shortcuts")
	}
	// The read-ahead window is paired with the authority read bound: reads are
	// now served from the page cache, so the window is what decides how many
	// authority round trips a sequential reader pays.
	if !options.EnableLocks || !options.DisableReadDirPlus || options.MaxWrite != 64*1024 || options.MaxReadAhead != 128*1024 {
		t.Fatalf("mount options = %#v", options)
	}
	foundDefaultPermissions := false
	for _, option := range options.Options {
		foundDefaultPermissions = foundDefaultPermissions || option == "default_permissions"
	}
	if !foundDefaultPermissions {
		t.Fatal("kernel default_permissions enforcement must be enabled")
	}
	if err := verifyMountDecisions(options); err != nil {
		t.Fatalf("verifyMountDecisions rejected the shipped options: %v", err)
	}
	tampered := mountOptions(testConfig(8), 128*1024, 64*1024)
	tampered.DisabledCapabilities = 0
	if err := verifyMountDecisions(tampered); err == nil {
		t.Fatal("a mount that permits shared mmap must be refused")
	}
	tampered = mountOptions(testConfig(8), 128*1024, 64*1024)
	tampered.EnableLocks = false
	if err := verifyMountDecisions(tampered); err == nil {
		t.Fatal("a mount that does not forward locks must be refused")
	}
	tampered.ExtraCapabilities &^= fuse.CAP_ATOMIC_O_TRUNC
	if err := verifyMountDecisions(tampered); err == nil {
		t.Fatal("a mount that permits Linux to split open(O_TRUNC) into two mutations must be refused")
	}
	tampered = mountOptions(testConfig(8), 128*1024, 64*1024)
	tampered.ExtraCapabilities |= fuse.CAP_HAS_RESEND
	if err := verifyMountDecisions(tampered); err == nil {
		t.Fatal("a strict mount that requests HAS_RESEND must be refused")
	}
	tampered = mountOptions(testConfig(8), 128*1024, 64*1024)
	tampered.ExtraCapabilities &^= fuse.CAP_PFS_CACHED_DATA
	if err := verifyMountDecisions(tampered); err == nil {
		t.Fatal("a mount that requests only half the private profile must be refused")
	}
	tampered = mountOptions(testConfig(8), 128*1024, 64*1024)
	tampered.ExtraCapabilities &^= fuse.CAP_PFS_WRITE_ONESHOT
	if err := verifyMountDecisions(tampered); err == nil {
		t.Fatal("a mount that omits the one-shot write revision must be refused")
	}
	tampered = mountOptions(testConfig(8), 128*1024, 64*1024)
	tampered.ExplicitDataCacheControl = false
	if err := verifyMountDecisions(tampered); err == nil {
		t.Fatal("a mount whose retained pages could be dropped by an mtime heuristic must be refused")
	}
	tampered = mountOptions(testConfig(8), 128*1024, 64*1024)
	tampered.MaxReadAhead = 0
	if err := verifyMountDecisions(tampered); err == nil {
		t.Fatal("a mount that leaves the read-ahead window unnegotiated must be refused")
	}
}

func TestMountVolumeRejectsRetiredZeroCoherenceBeforeKernelMount(t *testing.T) {
	rpc := newFakeRPC()
	cfg := testConfig(8)
	cfg.Coherence = 0
	_, err := MountVolume(context.Background(), t.TempDir(), rpc, cfg)
	if err == nil || !strings.Contains(err.Error(), "strict coherence is required") {
		t.Fatalf("legacy zero coherence error = %v, want an explicit strict-only refusal", err)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if f.calls != 0 || f.closes != 1 {
			t.Fatalf("retired coherence reached authority/kernel setup: calls=%d closes=%d", f.calls, f.closes)
		}
	})
}

// --- Defect 7: the kernel must actually grant what the contract needs -------

func TestKernelGuaranteesRequireForwardedLocksAndRequestSize(t *testing.T) {
	settings := func(flags uint64) *fuse.InitIn {
		in := &fuse.InitIn{}
		in.Flags = uint32(flags)
		in.Flags2 = uint32(flags >> 32)
		return in
	}
	// A strict mount also needs a kernel that can receive invalidations, so
	// every case here advertises a protocol new enough for them; the notify
	// requirement has its own test.
	notifying := func(in *fuse.InitIn) *fuse.InitIn {
		in.Major, in.Minor = 7, 41
		return in
	}
	required := uint64(fuse.CAP_POSIX_LOCKS | fuse.CAP_FLOCK_LOCKS | fuse.CAP_ATOMIC_O_TRUNC | fuse.CAP_HANDLE_KILLPRIV_V2 |
		fuse.CAP_PFS_STRICT_COHERENCE | fuse.CAP_PFS_CACHED_DATA | fuse.CAP_PFS_WRITE_ONESHOT | fuse.CAP_EXPLICIT_INVAL_DATA)
	if err := verifyKernelGuarantees(notifying(settings(required)), 64*1024); err != nil {
		t.Fatalf("a lock-forwarding kernel was refused: %v", err)
	}
	for _, version := range []struct{ major, minor uint32 }{{7, 28}, {7, 36}, {7, 40}, {7, 42}, {8, 41}} {
		in := settings(required)
		in.Major, in.Minor = version.major, version.minor
		if err := verifyKernelGuarantees(in, 64*1024); err == nil {
			t.Fatalf("unpinned FUSE protocol %d.%d was accepted", version.major, version.minor)
		}
	}
	if err := verifyKernelGuarantees(notifying(settings(required&^fuse.CAP_FLOCK_LOCKS)), 64*1024); err == nil {
		t.Fatal("a kernel without CAP_FLOCK_LOCKS silently falls back to the local lock manager and must be refused")
	}
	if err := verifyKernelGuarantees(notifying(settings(required&^fuse.CAP_POSIX_LOCKS)), 64*1024); err == nil {
		t.Fatal("a kernel without CAP_POSIX_LOCKS must be refused")
	}
	if err := verifyKernelGuarantees(notifying(settings(required&^fuse.CAP_ATOMIC_O_TRUNC)), 64*1024); err == nil {
		t.Fatal("a kernel without CAP_ATOMIC_O_TRUNC must be refused")
	}
	if err := verifyKernelGuarantees(notifying(settings(required&^fuse.CAP_PFS_STRICT_COHERENCE)), 64*1024); err == nil {
		t.Fatal("a kernel without the indivisible PortableFS strict-coherence contract must be refused")
	}
	// The private bits are one profile revision. A kernel offering only the
	// older cached-data subset implements the retired direct-I/O open pair and would reject
	// this daemon's very first regular OPEN with -EPROTO, so the mismatch has
	// to be a failed mount rather than an aborted connection under load.
	if err := verifyKernelGuarantees(notifying(settings(required&^fuse.CAP_PFS_CACHED_DATA)), 64*1024); err == nil {
		t.Fatal("a kernel implementing only the pre-cached-data revision of the contract must be refused")
	}
	if err := verifyKernelGuarantees(notifying(settings(required&^fuse.CAP_PFS_WRITE_ONESHOT)), 64*1024); err == nil {
		t.Fatal("a kernel implementing only the pre-one-shot revision of the contract must be refused")
	}
	if err := verifyKernelGuarantees(notifying(settings(required&^fuse.CAP_EXPLICIT_INVAL_DATA)), 64*1024); err == nil {
		t.Fatal("a kernel that cannot grant explicit data-cache control must be refused; retained pages would be dropped by an mtime heuristic")
	}
	if err := verifyKernelGuarantees(notifying(settings(required&^fuse.CAP_HANDLE_KILLPRIV_V2)), 64*1024); err == nil {
		t.Fatal("a kernel without HANDLE_KILLPRIV_V2 must be refused")
	}
	for _, offeredOptional := range []uint64{fuse.CAP_HAS_RESEND, fuse.CAP_PASSTHROUGH, fuse.CAP_NO_OPEN_SUPPORT, fuse.CAP_NO_OPENDIR_SUPPORT, fuse.CAP_DIRECT_IO_ALLOW_MMAP} {
		if err := verifyKernelGuarantees(notifying(settings(required|offeredOptional)), 64*1024); err != nil {
			t.Fatalf("kernel-offered optional capability %#x was mistaken for a daemon-negotiated capability: %v", offeredOptional, err)
		}
	}
	if err := verifyKernelGuarantees(nil, 64*1024); err == nil {
		t.Fatal("unavailable INIT settings must be refused")
	}
	big := uint32(kernelDefaultMaxPages*syscall.Getpagesize()) + 1
	if err := verifyKernelGuarantees(notifying(settings(required)), big); err == nil {
		t.Fatal("a kernel that ignores MaxPages cannot carry the negotiated write size and must be refused")
	}
	if err := verifyKernelGuarantees(notifying(settings(required|fuse.CAP_MAX_PAGES)), big); err != nil {
		t.Fatalf("a CAP_MAX_PAGES kernel was refused: %v", err)
	}
}

// --- Defect 1: cleanup pressure throttles, it does not destroy the mount ----

func TestCleanupPressureThrottlesInterningAndNeverDestroysTheMount(t *testing.T) {
	frontend, mount, _ := testRawFileSystem(t, 2)
	// FORGET produces cleanup debt without any admission at all, so it can and
	// does push the backlog past the watermark. That must never be fatal.
	for id := uint64(1); id <= 3; id++ {
		mount.deferReclaim(testToken(id))
	}
	if mount.ctx.Err() != nil || mount.fatalError() != nil {
		t.Fatalf("cleanup pressure destroyed the mount: %v", mount.fatalError())
	}
	if got := mount.reclaim.pending(); got != 3 {
		t.Fatalf("backlog = %d, want 3 (no capability may ever be discarded)", got)
	}
	interned := make(chan syscall.Errno, 1)
	go func() {
		_, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_REGULAR, 10))
		interned <- errno
	}()
	select {
	case errno := <-interned:
		t.Fatalf("intern completed without backpressure (errno %v)", errno)
	case <-time.After(75 * time.Millisecond):
	}
	popReclaim(t, mount)
	popReclaim(t, mount)
	select {
	case errno := <-interned:
		if errno != 0 {
			t.Fatalf("throttled intern = %v, want success once the backlog drained", errno)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("intern never resumed after the backlog drained")
	}
	if mount.ctx.Err() != nil || mount.fatalError() != nil {
		t.Fatalf("mount aborted under ordinary cleanup pressure: %v", mount.fatalError())
	}
}

func TestForgetNeverBlocksUnderCleanupPressure(t *testing.T) {
	frontend, mount, _ := testRawFileSystem(t, 1)
	records := make([]*inodeRecord, 0, 64)
	for id := uint64(1); id <= 64; id++ {
		record, errno := frontend.intern(context.Background(), testItem(id, authoritypb.Attr_REGULAR, id))
		if errno != 0 {
			t.Fatalf("intern %d = %v", id, errno)
		}
		records = append(records, record)
		// Drain immediately so interning is never itself throttled here; the
		// point of this test is FORGET, which must not block even at watermark.
		if mount.reclaim.pending() > 0 {
			popReclaim(t, mount)
		}
	}
	done := make(chan struct{})
	go func() {
		for _, record := range records {
			frontend.Forget(record.id, 1)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("FORGET blocked; go-fuse spawns no replacement reader for it, so the whole request loop would stall")
	}
	if mount.ctx.Err() != nil || mount.fatalError() != nil {
		t.Fatalf("FORGET storm destroyed the mount: %v", mount.fatalError())
	}
	if got := mount.reclaim.pending(); got != len(records) {
		t.Fatalf("queued reclaims = %d, want %d", got, len(records))
	}
}

func TestReclaimDrainIsConcurrent(t *testing.T) {
	mount, rpc := testMount(t, 1024)
	width := mount.reclaimWorkers
	if width < 2 {
		t.Fatalf("reclaim lane width = %d, want at least 2", width)
	}
	reached := make(chan struct{}, width)
	release := make(chan struct{})
	rpc.hook = func(request *authoritypb.Request) {
		if request.GetReclaim() == nil {
			return
		}
		reached <- struct{}{}
		<-release
	}
	for id := uint64(1); id <= uint64(width); id++ {
		mount.deferReclaim(testToken(id))
	}
	mount.start(time.Hour)
	defer func() {
		close(release)
		_ = mount.Close()
	}()
	for count := 0; count < width; count++ {
		select {
		case <-reached:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of %d reclaims were in flight at once; a serial drain cannot keep up with ordinary path walking", count, width)
		}
	}
}

// --- Defect 3: a cancelled shutdown is not a fatal error -------------------

func TestCancelledShutdownIsNotReportedAsFailure(t *testing.T) {
	mount, rpc := testMount(t, 64)
	rpc.block = make(chan struct{})
	mount.start(time.Hour)
	for id := uint64(1); id <= 8; id++ {
		mount.deferReclaim(testToken(id))
	}
	waitFor(t, "a reclaim to be in flight", func() bool {
		blocked := false
		rpc.snapshot(func(f *fakeRPC) { blocked = f.calls > 0 })
		return blocked
	})
	if err := mount.Close(); err != nil {
		t.Fatalf("clean shutdown reported a fatal error: %v", err)
	}
	if err := mount.fatalError(); err != nil {
		t.Fatalf("shutdown recorded a fatal error: %v", err)
	}
}

func TestCancelledKeepAliveIsNotReportedAsFailure(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.block = make(chan struct{})
	mount.wg.Add(1)
	go mount.keepAlive(mount.ctx, 15*time.Millisecond)
	waitFor(t, "a keepalive to be in flight", func() bool {
		started := false
		rpc.snapshot(func(f *fakeRPC) { started = f.calls > 0 })
		return started
	})
	mount.cancel()
	mount.wg.Wait()
	if err := mount.fatalError(); err != nil {
		t.Fatalf("a keepalive cancelled by shutdown was reported as an authority failure: %v", err)
	}
}

// --- Defect 4: INTERRUPT never reaches the authority -----------------------

func TestKernelInterruptNeitherCancelsTheMutationNorTearsDownTheMount(t *testing.T) {
	frontend, mount, rpc := testRawFileSystem(t, 8)
	rpc.observeCancel = true
	interrupt := make(chan struct{})
	close(interrupt)
	if status := testRawCall(t, frontend, func(unique uint64) fuse.Status {
		input := &fuse.MkdirIn{InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID}, Mode: 0o755}
		return frontend.Mkdir(interrupt, input, "child", &fuse.EntryOut{})
	}); status != fuse.OK {
		t.Fatalf("interrupted mkdir = %v, want OK; FUSE permits ignoring INTERRUPT and this path must", status)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if f.canceled != 0 {
			t.Fatalf("the kernel INTERRUPT reached %d authority call(s); a cancelled mutation poisons the session and unmounts the volume", f.canceled)
		}
	})
	if mount.ctx.Err() != nil || mount.fatalError() != nil {
		t.Fatalf("INTERRUPT tore the mount down: %v", mount.fatalError())
	}
}

// --- Defect 6: a timeout is not an interrupt -------------------------------

func TestRequestTimeoutIsNeverReportedAsEINTR(t *testing.T) {
	if got := rpcErrno(nil, context.DeadlineExceeded); got != syscall.ETIMEDOUT {
		t.Fatalf("deadline errno = %v, want ETIMEDOUT; EINTR makes applications retry forever", got)
	}
	if got := rpcErrno(nil, fmt.Errorf("call: %w", context.DeadlineExceeded)); got != syscall.ETIMEDOUT {
		t.Fatalf("wrapped deadline errno = %v, want ETIMEDOUT", got)
	}
	if got := rpcErrno(nil, context.Canceled); got != syscall.ENOTCONN {
		t.Fatalf("cancelled errno = %v, want ENOTCONN", got)
	}
	if got := rpcErrno(nil, errors.New("transport")); got != syscall.EIO {
		t.Fatalf("transport errno = %v, want EIO", got)
	}
	mount, rpc := testMount(t, 8)
	rpc.block = make(chan struct{})
	n := testNode(mount)
	n.requestTimeout = 20 * time.Millisecond
	ctx, finish := testMutationContext(t, mount)
	_, errno := n.Lookup(ctx, "slow")
	finish(false)
	if errno != syscall.ETIMEDOUT {
		t.Fatalf("timed-out lookup = %v, want ETIMEDOUT", errno)
	}
}

func TestRouteCauseSurvivesEarlierGenericSessionTeardown(t *testing.T) {
	mount, _ := testMount(t, 8)
	// Pre-claim only teardown ownership. This makes the production interleaving
	// deterministic without starting an unmount goroutine: fatal causes must be
	// recorded independently of this one-shot.
	mount.abort.Do(func() {})
	done := make(chan struct{})
	mount.wg.Add(1)
	go mount.watchSession(mount.ctx, done)
	close(done)
	waitFor(t, "generic session terminal cause", func() bool {
		err := mount.fatalError()
		return err != nil && strings.Contains(err.Error(), "authority session ended")
	})

	previous := bytes.Repeat([]byte{0x11}, 32)
	announced := bytes.Repeat([]byte{0x22}, 32)
	mount.revoke(routesChangeCause(previous, announced))
	err := mount.fatalError()
	if err == nil || !strings.Contains(err.Error(), LocalDirsPath) || !strings.Contains(err.Error(), "unmount and mount again") {
		t.Fatalf("later route-specific cause was masked by generic teardown: %v", err)
	}
	if !strings.Contains(err.Error(), "authority session ended") {
		t.Fatalf("recording route cause discarded the original session terminal cause: %v", err)
	}
}

func TestGenericTerminalCauseCannotMaskAnExistingRouteCause(t *testing.T) {
	mount, _ := testMount(t, 8)
	mount.abort.Do(func() {})
	mount.revoke(routesChangeCause(bytes.Repeat([]byte{0x33}, 32), bytes.Repeat([]byte{0x44}, 32)))
	mount.failAsync(errors.New("generic transport failure"))
	err := mount.fatalError()
	if err == nil || !strings.Contains(err.Error(), "unmount and mount again") || !strings.Contains(err.Error(), "generic transport failure") {
		t.Fatalf("terminal diagnostic did not retain both causes: %v", err)
	}
}

// --- Defect 5: liveness and cleanup have reserved capacity -----------------

func TestLivenessAndCleanupLanesAreReserved(t *testing.T) {
	cfg := testConfig(8)
	mount, rpc := testMount(t, 8)
	if cap(mount.bulk)+mount.reclaimWorkers+livenessReserve+visibilityReserve != cfg.MaxInFlight {
		t.Fatalf("bulk %d + cleanup %d + liveness %d + visibility %d != authority in-flight budget %d", cap(mount.bulk), mount.reclaimWorkers, livenessReserve, visibilityReserve, cfg.MaxInFlight)
	}
	for range cap(mount.bulk) {
		mount.bulk <- struct{}{}
	}
	saturated, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if errno := mount.acquireBulk(saturated); errno != syscall.ETIMEDOUT {
		t.Fatalf("saturated bulk lane admitted a call (errno %v)", errno)
	}
	mount.wg.Add(1)
	go mount.keepAlive(mount.ctx, 30*time.Millisecond)
	waitFor(t, "a keepalive to complete while bulk I/O is saturated", func() bool {
		renewed := false
		rpc.snapshot(func(f *fakeRPC) { renewed = f.keepAlives > 0 })
		return renewed
	})
	mount.cancel()
	mount.wg.Wait()
	if err := mount.fatalError(); err != nil {
		t.Fatalf("keepalive starved behind bulk work: %v", err)
	}
}

// --- Defect 9: a refused release is never discarded ------------------------

func TestReleaseSurfacesARefusedClose(t *testing.T) {
	frontend, mount, rpc := testRawFileSystem(t, 8)
	rpc.closeFailure = syscall.EIO
	record, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_REGULAR, 1))
	if errno != 0 {
		t.Fatal(errno)
	}
	id, ok := frontend.addHandle(record, &handleRecord{file: &fileHandle{node: record.node, token: testToken(100)}})
	if !ok {
		t.Fatal("add handle")
	}
	unique := nextTestRequestUnique()
	frontend.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{Unique: unique}, Fh: id})
	if frontend.ReplyWriteOrdered(unique) {
		frontend.ReplyWritten(unique, fuse.OK)
	}
	err := mount.fatalError()
	if err == nil {
		t.Fatal("a refused close was discarded; the authority keeps the open file description until the session ends")
	}
	if !strings.Contains(err.Error(), "frontend-owned resource") {
		t.Fatalf("diagnostic does not name the cause: %v", err)
	}
}

func TestReleaseDirSurfacesARefusedClose(t *testing.T) {
	frontend, mount, rpc := testRawFileSystem(t, 8)
	rpc.closeFailure = syscall.EIO
	record, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_DIRECTORY, 1))
	if errno != 0 {
		t.Fatal(errno)
	}
	id, ok := frontend.addHandle(record, &handleRecord{dir: &dirHandle{node: record.node, token: testToken(100)}})
	if !ok {
		t.Fatal("add handle")
	}
	frontend.ReleaseDir(&fuse.ReleaseIn{Fh: id})
	if mount.fatalError() == nil {
		t.Fatal("a refused directory close was discarded")
	}
}

// --- Defect 10: the authority's Open reply is validated at the boundary -----

func TestOpendirRejectsMalformedOpenReply(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.handle = nil
	if _, _, errno := testNode(mount).OpendirHandle(context.Background(), syscall.O_RDONLY); errno != syscall.EIO {
		t.Fatalf("OpendirHandle on a malformed reply = %v, want EIO", errno)
	}
	rpc.handle = testToken(900)
	if _, _, errno := testNode(mount).OpendirHandle(context.Background(), syscall.O_WRONLY); errno != syscall.EISDIR {
		t.Fatalf("writable opendir = %v, want EISDIR", errno)
	}
}

// --- Defect 11: the kernel's max_write floor -------------------------------

func TestMountVolumeRejectsBoundsBelowTheKernelWriteFloor(t *testing.T) {
	rpc := newFakeRPC()
	rpc.maxRead, rpc.maxWrite = 1024, 1024
	_, err := MountVolume(context.Background(), "/nonexistent-portablefs-mountpoint", rpc, testConfig(8))
	if err == nil || !strings.Contains(err.Error(), "floor") {
		t.Fatalf("MountVolume with a 1 KiB max_write = %v, want a refusal naming the kernel floor", err)
	}
}

func TestMountVolumeRequiresACompleteConfiguration(t *testing.T) {
	cfg := testConfig(8)
	cfg.MountInstanceID = "volume-wide-source"
	rpc := newFakeRPC()
	if _, err := MountVolume(context.Background(), "/nonexistent-portablefs-mountpoint", rpc, cfg); err == nil {
		t.Fatal("a non-random mount identity must be refused")
	}
	rpc.mu.Lock()
	closes := rpc.closes
	rpc.mu.Unlock()
	if closes != 1 {
		t.Fatalf("RPC closes after invalid mount identity = %d, want 1", closes)
	}
	cfg = testConfig(8)
	cfg.MaxInFlight = 0
	if _, err := MountVolume(context.Background(), "/nonexistent-portablefs-mountpoint", newFakeRPC(), cfg); err == nil {
		t.Fatal("a mount without the authority in-flight budget cannot reserve a liveness lane and must be refused")
	}
	cfg = testConfig(8)
	cfg.MaxInFlight = minMaxInFlight - 1
	if _, err := MountVolume(context.Background(), "/nonexistent-portablefs-mountpoint", newFakeRPC(), cfg); err == nil {
		t.Fatal("an in-flight budget too small to carve lanes from must be refused")
	}
	rpc = newFakeRPC()
	rpc.root = nil
	if _, err := MountVolume(context.Background(), "/nonexistent-portablefs-mountpoint", rpc, testConfig(8)); err == nil {
		t.Fatal("a missing authority root must be refused")
	}
}

func TestFailedStartupCleanRequiresExactSessionRelease(t *testing.T) {
	for _, test := range []struct {
		name      string
		detachErr error
		wantClean bool
	}{
		{name: "released", wantClean: true},
		{name: "detach refused", detachErr: syscall.EIO, wantClean: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			rpc := newFakeRPC()
			rpc.detachErr = test.detachErr
			cfg := testConfig(8)
			cfg.Coherence = CoherenceStrict
			cfg.MaxInFlight = 0
			_, err := MountVolume(context.Background(), "/nonexistent-portablefs-mountpoint", rpc, cfg)
			if err == nil {
				t.Fatal("an incomplete mount configuration was accepted")
			}
			wrapped := fmt.Errorf("supervisor boundary: %w", err)
			if got := FailedStartupClean(wrapped); got != test.wantClean {
				t.Fatalf("FailedStartupClean(%v) = %t, want %t", err, got, test.wantClean)
			}
			rpc.snapshot(func(f *fakeRPC) {
				if len(f.detachProofs) != 1 {
					t.Fatalf("detach proofs = %d, want 1", len(f.detachProofs))
				}
				if f.closes != 1 {
					t.Fatalf("RPC closes = %d, want 1", f.closes)
				}
			})
		})
	}
}

// --- Defect 12: mknod ------------------------------------------------------

func TestMknodCreatesRegularFilesAndRefusesUnrepresentableTypes(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	item, errno := testVisibleMutation(t, mount, func(ctx context.Context) (*authoritypb.Item, syscall.Errno) {
		return n.Mknod(ctx, "plain", syscall.S_IFREG|0o644, 0)
	})
	if errno != 0 || item == nil {
		t.Fatalf("mknod regular = (%v, %v)", item, errno)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if len(f.fileCloses) != 1 {
			t.Fatalf("mknod left %d open file descriptions behind, want 0", len(f.fileCloses))
		}
	})
	_, errno = testVisibleMutation(t, mount, func(ctx context.Context) (*authoritypb.Item, syscall.Errno) {
		return n.Mknod(ctx, "untyped", 0o644, 0)
	})
	if errno != 0 {
		t.Fatalf("mknod with no type bits = %v, want a regular file", errno)
	}
	for name, mode := range map[string]uint32{"fifo": syscall.S_IFIFO, "socket": syscall.S_IFSOCK} {
		if _, errno := n.Mknod(context.Background(), name, mode|0o644, 0); errno != syscall.EOPNOTSUPP {
			t.Fatalf("mknod %s = %v, want EOPNOTSUPP (never ENOSYS)", name, errno)
		}
	}
	for name, mode := range map[string]uint32{"chr": syscall.S_IFCHR, "blk": syscall.S_IFBLK} {
		if _, errno := n.Mknod(context.Background(), name, mode|0o644, 0x100); errno != syscall.EPERM {
			t.Fatalf("mknod %s = %v, want EPERM", name, errno)
		}
	}
}

func TestMknodIsWiredIntoTheRawFileSystem(t *testing.T) {
	frontend, _, _ := testRawFileSystem(t, 8)
	status := testRawCall(t, frontend, func(unique uint64) fuse.Status {
		input := &fuse.MknodIn{InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID}, Mode: syscall.S_IFIFO | 0o644}
		return frontend.Mknod(nil, input, "fifo", &fuse.EntryOut{})
	})
	if status == fuse.ENOSYS {
		t.Fatal("MKNOD still falls through to the default ENOSYS implementation")
	}
	if status != fuse.Status(syscall.EOPNOTSUPP) {
		t.Fatalf("MKNOD status = %v, want EOPNOTSUPP", status)
	}
}

// --- Defect 13: directory paging, cookies, fsync bits, append, rename ------

func testDirPage(count int, eof bool, cookie func(int) []byte) *authoritypb.ReadDirReply {
	page := &authoritypb.ReadDirReply{Verifier: testToken(5), Eof: eof}
	for index := range count {
		page.Entries = append(page.Entries, &authoritypb.Dirent{
			Name:       []byte{byte('a' + index)},
			Attr:       &authoritypb.Attr{Inode: uint64(index + 10), Kind: authoritypb.Attr_REGULAR, Mode: 0o644},
			NextCookie: cookie(index),
		})
	}
	return page
}

func testDirHandle(t *testing.T, frontend *rawFileSystem, pages ...*authoritypb.ReadDirReply) (uint64, *fakeRPC) {
	t.Helper()
	record, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_DIRECTORY, 1))
	if errno != 0 {
		t.Fatal(errno)
	}
	rpc := frontend.mount.rpc.(*fakeRPC)
	rpc.dirPages = pages
	id, ok := frontend.addHandle(record, &handleRecord{dir: &dirHandle{node: record.node, token: testToken(100)}})
	if !ok {
		t.Fatal("add directory handle")
	}
	return id, rpc
}

// readDirOnce issues one kernel READDIR into a buffer that holds exactly
// `entries` one-byte-named entries, and returns the offset the kernel would
// resume from (the Off of the last entry that fitted).
func readDirOnce(t *testing.T, frontend *rawFileSystem, id, offset uint64, entries int) uint64 {
	t.Helper()
	const oneByteNameEntrySize = 32
	list := fuse.NewDirEntryList(make([]byte, entries*oneByteNameEntrySize), offset)
	status := testRawCall(t, frontend, func(unique uint64) fuse.Status {
		return frontend.ReadDir(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique}, Fh: id, Offset: offset}, list)
	})
	if status != fuse.OK {
		t.Fatalf("ReadDir at %d = %v", offset, status)
	}
	return list.Offset
}

func TestDirHandleBuffersOneAuthorityPageAcrossEntries(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.dirPages = []*authoritypb.ReadDirReply{testDirPage(4, true, func(index int) []byte { return encodeCookie(uint64(index + 1)) })}
	handle := &dirHandle{node: testNode(mount), token: testToken(100)}
	ctx, finish := testMutationContext(t, mount)
	defer finish(false)
	names := []string(nil)
	for range 4 {
		entry, errno := handle.peek(ctx)
		if errno != 0 || entry == nil {
			t.Fatalf("peek = (%v, %v)", entry, errno)
		}
		// Peeking twice must not advance: the entry is only consumed when the
		// kernel buffer has accepted it.
		again, _ := handle.peek(ctx)
		if again.Name != entry.Name {
			t.Fatalf("peek is not idempotent: %q then %q", entry.Name, again.Name)
		}
		names = append(names, entry.Name)
		handle.consume()
	}
	entry, errno := handle.peek(ctx)
	if errno != 0 || entry != nil {
		t.Fatalf("end of directory = (%v, %v)", entry, errno)
	}
	if len(names) != 4 || names[0] != "a" || names[3] != "d" {
		t.Fatalf("entries = %v", names)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if len(f.readdirs) != 1 {
			t.Fatalf("authority READDIR calls = %d, want 1; the buffered page was discarded", len(f.readdirs))
		}
	})
}

func TestReadDirContinuesFromTheBufferedPage(t *testing.T) {
	frontend, _, _ := testRawFileSystem(t, 8)
	page := testDirPage(4, true, func(index int) []byte { return encodeCookie(uint64(index + 1)) })
	id, rpc := testDirHandle(t, frontend, page)
	if got := readDirOnce(t, frontend, id, 0, 2); got != 2 {
		t.Fatalf("first READDIR resume offset = %d, want 2", got)
	}
	if got := readDirOnce(t, frontend, id, 2, 2); got != 4 {
		t.Fatalf("second READDIR resume offset = %d; an entry that did not fit was lost", got)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if len(f.readdirs) != 1 {
			t.Fatalf("authority READDIR calls = %d, want 1; Seekdir discarded the buffered page", len(f.readdirs))
		}
	})
}

func TestReadDirRewindDiscardsTheBufferedPage(t *testing.T) {
	frontend, _, _ := testRawFileSystem(t, 8)
	cookie := func(index int) []byte { return encodeCookie(uint64(index + 1)) }
	id, rpc := testDirHandle(t, frontend, testDirPage(4, true, cookie), testDirPage(4, true, cookie))
	if got := readDirOnce(t, frontend, id, 0, 2); got != 2 {
		t.Fatalf("first READDIR resume offset = %d", got)
	}
	if got := readDirOnce(t, frontend, id, 0, 2); got != 2 {
		t.Fatalf("rewound READDIR resume offset = %d, want the directory from the start", got)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if len(f.readdirs) != 2 {
			t.Fatalf("authority READDIR calls = %d, want 2 (rewind must refetch)", len(f.readdirs))
		}
		if len(f.readdirs[1].GetVerifier()) != 0 {
			t.Fatal("a rewind to offset 0 must drop the directory verifier")
		}
	})
}

func TestReadDirRejectsACookieItCannotResumeFrom(t *testing.T) {
	for name, cookie := range map[string]func(int) []byte{
		"short": func(int) []byte { return []byte{1, 2, 3, 4} },
		"zero":  func(int) []byte { return make([]byte, 8) },
		"empty": func(int) []byte { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			frontend, _, _ := testRawFileSystem(t, 8)
			id, _ := testDirHandle(t, frontend, testDirPage(2, true, cookie))
			list := fuse.NewDirEntryList(make([]byte, 256), 0)
			status := testRawCall(t, frontend, func(unique uint64) fuse.Status {
				return frontend.ReadDir(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique}, Fh: id}, list)
			})
			if status != fuse.EIO {
				t.Fatalf("ReadDir with a %s cookie = %v, want EIO; go-fuse would substitute an offset the authority cannot resume from and `ls` would never terminate", name, status)
			}
		})
	}
}

func TestFsyncUsesOnlyTheDataSyncBit(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	handle := &fileHandle{node: n, token: testToken(100)}
	for flags, want := range map[uint32]bool{0: false, 1: true, 2: false, 3: true} {
		if errno := n.Fsync(context.Background(), handle, flags); errno != 0 {
			t.Fatal(errno)
		}
		var got bool
		rpc.snapshot(func(f *fakeRPC) { got = f.fsyncs[len(f.fsyncs)-1].GetDataOnly() })
		if got != want {
			t.Fatalf("Fsync(%#b) DataOnly = %v, want %v", flags, got, want)
		}
	}
}

func TestSyncFSUsesOneReplayMutationAndNoPublicationGate(t *testing.T) {
	frontend, mount, rpc := testRawFileSystem(t, 8)
	consumption := &recordingResponseConsumption{}
	rpc.retainedConsumption = consumption
	unique := nextTestRequestUnique()
	status := frontend.SyncFS(nil, &fuse.SyncFSIn{InHeader: fuse.InHeader{
		Unique: unique, NodeId: fuse.FUSE_ROOT_ID,
	}})
	if !status.Ok() || mount.isRevoked() {
		t.Fatalf("SYNCFS = %v, revoked=%t fatal=%v", status, mount.isRevoked(), mount.fatalError())
	}
	rpc.snapshot(func(f *fakeRPC) {
		if f.syncFS != 1 || f.calls != 1 || f.mutationCalls != 1 || f.mutationSeq != 1 || f.reads != 0 {
			t.Fatalf("SYNCFS routing: syncfs=%d calls=%d mutation_calls=%d accepted_sequence=%d reads=%d",
				f.syncFS, f.calls, f.mutationCalls, f.mutationSeq, f.reads)
		}
	})
	if !frontend.ReplyWriteOrdered(unique) || frontend.ReplyPublishMarked(unique, fuse.FUSE_ROOT_ID, 50) {
		t.Fatal("SYNCFS omitted physical reply ordering or created a cache/source publication obligation")
	}
	if got := consumption.calls.Load(); got != 0 {
		t.Fatalf("SYNCFS consumed response %d time(s) before physical reply", got)
	}
	frontend.ReplyWritten(unique, fuse.OK)
	if got := consumption.calls.Load(); got != 1 {
		t.Fatalf("SYNCFS consumed response %d time(s), want 1 after physical reply", got)
	}
}

func TestSyncFSPropagatesDefiniteErrorAndRejectsMalformedSuccess(t *testing.T) {
	t.Run("definite authority error", func(t *testing.T) {
		frontend, mount, rpc := testRawFileSystem(t, 8)
		consumption := &recordingResponseConsumption{}
		rpc.retainedConsumption = consumption
		rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
			if request.GetSyncFs() != nil {
				return &authoritypb.Response{Errno: int32(syscall.EIO)}, nil
			}
			return &authoritypb.Response{}, nil
		}
		unique := nextTestRequestUnique()
		if status := frontend.SyncFS(nil, &fuse.SyncFSIn{InHeader: fuse.InHeader{
			Unique: unique, NodeId: fuse.FUSE_ROOT_ID,
		}}); status != fuse.EIO || mount.isRevoked() {
			t.Fatalf("definite SYNCFS error = %v, revoked=%t", status, mount.isRevoked())
		}
		if !frontend.ReplyWriteOrdered(unique) || frontend.ReplyPublishMarked(unique, fuse.FUSE_ROOT_ID, 50) {
			t.Fatal("definite SYNCFS error omitted physical reply ordering or created publication")
		}
		if got := consumption.calls.Load(); got != 0 {
			t.Fatalf("definite SYNCFS error consumed response %d time(s) before physical reply", got)
		}
		frontend.ReplyWritten(unique, fuse.EIO)
		if got := consumption.calls.Load(); got != 1 {
			t.Fatalf("definite SYNCFS error consumed response %d time(s), want 1", got)
		}
	})
	t.Run("malformed success", func(t *testing.T) {
		frontend, mount, rpc := testRawFileSystem(t, 8)
		rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
			if request.GetSyncFs() != nil {
				return &authoritypb.Response{}, nil
			}
			return &authoritypb.Response{}, nil
		}
		if status := frontend.SyncFS(nil, &fuse.SyncFSIn{InHeader: fuse.InHeader{
			Unique: nextTestRequestUnique(), NodeId: fuse.FUSE_ROOT_ID,
		}}); status != fuse.Status(syscall.ENOTCONN) || !mount.isRevoked() {
			t.Fatalf("malformed SYNCFS success = %v, revoked=%t fatal=%v", status, mount.isRevoked(), mount.fatalError())
		}
	})
}

func TestLinuxFrontendRejectsItemRetryOutsideItemMutation(t *testing.T) {
	t.Run("ungated mutation", func(t *testing.T) {
		frontend, mount, rpc := testRawFileSystem(t, 8)
		rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
			if request.GetSyncFs() == nil {
				return nil, errors.New("unexpected request in ungated item-retry test")
			}
			return &authoritypb.Response{
				Errno: int32(syscall.EINTR), Failure: authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_RETRY,
				VisibilityRetrySequence: 1,
			}, nil
		}
		if status := frontend.SyncFS(nil, &fuse.SyncFSIn{InHeader: fuse.InHeader{
			Unique: nextTestRequestUnique(), NodeId: fuse.FUSE_ROOT_ID,
		}}); status != fuse.EIO || !mount.isRevoked() {
			t.Fatalf("ungated item retry = %v, revoked=%t fatal=%v", status, mount.isRevoked(), mount.fatalError())
		}
	})

	t.Run("read-only request", func(t *testing.T) {
		f := newStrictFixture(t)
		entry := f.lookup(t, fuse.FUSE_ROOT_ID, "read-retry")
		f.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
			if request.GetGetAttr() == nil {
				return nil, errors.New("unexpected request in read item-retry test")
			}
			return &authoritypb.Response{
				Errno: int32(syscall.EINTR), Failure: authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_RETRY,
				VisibilityRetrySequence: 1,
			}, nil
		}
		status := f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{
			Unique: nextTestRequestUnique(), NodeId: entry.NodeId,
		}}, &fuse.AttrOut{})
		if status != fuse.Status(syscall.ENOTCONN) || !f.mount.isRevoked() {
			t.Fatalf("read-only item retry = %v, revoked=%t fatal=%v", status, f.mount.isRevoked(), f.mount.fatalError())
		}
	})
}

func TestReadOnlyOpenDropsOAppend(t *testing.T) {
	flags, errno := protocolOpenFlags(syscall.O_RDONLY | syscall.O_APPEND)
	if errno != 0 {
		t.Fatal(errno)
	}
	if flags.GetAppend() {
		t.Fatal("O_APPEND on a read-only open is legal and ignored on every other Linux filesystem; forwarding it makes the authority reject the open with EINVAL")
	}
	if flags, _ := protocolOpenFlags(syscall.O_WRONLY | syscall.O_APPEND); !flags.GetAppend() {
		t.Fatal("O_APPEND must survive on a writable open")
	}
	if flags, _ := protocolOpenFlags(syscall.O_RDWR | syscall.O_APPEND); !flags.GetAppend() {
		t.Fatal("O_APPEND must survive on a read-write open")
	}
}

func TestRenameValidatesFlagCombinations(t *testing.T) {
	mount, _ := testMount(t, 8)
	n := testNode(mount)
	parent := testNode(mount)
	for _, flags := range []uint32{4, renameNoReplace | renameExchange, 0xffffffff} {
		if _, errno := n.Rename(context.Background(), "a", parent, "b", flags); errno != syscall.EINVAL {
			t.Fatalf("Rename flags %#x = %v, want EINVAL", flags, errno)
		}
	}
	for _, flags := range []uint32{0, renameNoReplace, renameExchange} {
		_, errno := testVisibleMutation(t, mount, func(ctx context.Context) (bool, syscall.Errno) {
			return n.Rename(ctx, "a", parent, "b", flags)
		})
		if errno != 0 {
			t.Fatalf("Rename flags %#x = %v, want success", flags, errno)
		}
	}
	if _, errno := n.Rename(context.Background(), "a", nil, "b", 0); errno != syscall.EINVAL {
		t.Fatalf("Rename without a destination parent = %v, want EINVAL", errno)
	}
}

func TestReadChunksAtTheNegotiatedMaxRead(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.fileData = []byte("0123456789")
	n := testNode(mount)
	n.maxRead = 4
	handle := &fileHandle{node: n, token: testToken(100)}
	dest := make([]byte, 16)
	result, errno := n.Read(context.Background(), handle, dest, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	data, status := result.Bytes(make([]byte, 16))
	if status != fuse.OK || !bytes.Equal(data, rpc.fileData) {
		t.Fatalf("Read = (%q, %v), want the whole file", data, status)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if f.reads != 3 {
			t.Fatalf("authority READ calls = %d, want 3 chunks of at most maxRead", f.reads)
		}
	})
	if _, errno := n.Read(context.Background(), handle, dest, -1); errno != syscall.EBADF {
		t.Fatalf("Read at a negative offset = %v", errno)
	}
	if _, errno := n.Read(context.Background(), nil, dest, 0); errno != syscall.EBADF {
		t.Fatalf("Read without a handle = %v", errno)
	}
}

func TestGetxattrSupportsSizeProbe(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.xattrValue = []byte("value")
	n := testNode(mount)
	if size, errno := n.Getxattr(context.Background(), "user.test", nil); size != 5 || errno != 0 {
		t.Fatalf("Getxattr probe = (%d, %v), want (5, 0)", size, errno)
	}
	if size, errno := n.Getxattr(context.Background(), "user.test", make([]byte, 4)); size != 5 || errno != syscall.ERANGE {
		t.Fatalf("Getxattr short buffer = (%d, %v), want (5, ERANGE)", size, errno)
	}
	dest := make([]byte, 5)
	if size, errno := n.Getxattr(context.Background(), "user.test", dest); size != 5 || errno != 0 || !bytes.Equal(dest, []byte("value")) {
		t.Fatalf("Getxattr value = (%d, %v, %q)", size, errno, dest)
	}
}

func TestSetxattrReadonlyContractIsLocal(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	var beforeCalls, beforeSequence uint64
	rpc.snapshot(func(f *fakeRPC) {
		beforeCalls, beforeSequence = uint64(f.calls), f.mutationSeq
	})

	// VFS owns public xattr-name syntax before this callback. Once a valid set
	// mode reaches the filesystem, user-xattr-readonly is the exact result even
	// for a name a direct authority caller could not use.
	for _, name := range []string{"user.test", "", "security.capability", "user.portablefs.internal"} {
		for _, flags := range []uint32{0, unix.XATTR_CREATE, unix.XATTR_REPLACE} {
			if errno := n.Setxattr(context.Background(), name, []byte("value"), flags); errno != syscall.EOPNOTSUPP {
				t.Fatalf("Setxattr(%q, flags=%#x)=%v, want EOPNOTSUPP", name, flags, errno)
			}
		}
	}
	rpc.snapshot(func(f *fakeRPC) {
		if uint64(f.calls) != beforeCalls || f.mutationSeq != beforeSequence {
			t.Fatalf("local setxattr refusal advanced RPC calls %d->%d or mutation sequence %d->%d", beforeCalls, f.calls, beforeSequence, f.mutationSeq)
		}
	})
}

func TestSetxattrInvalidFlagsPrecedeReadonlyRefusal(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	for _, test := range []struct {
		name  string
		flags uint32
	}{
		{name: "user.test", flags: unix.XATTR_CREATE | unix.XATTR_REPLACE},
		{name: "", flags: 1 << 31},
	} {
		if errno := n.Setxattr(context.Background(), test.name, nil, test.flags); errno != syscall.EINVAL {
			t.Fatalf("Setxattr(%q, flags=%#x)=%v, want EINVAL", test.name, test.flags, errno)
		}
	}
	rpc.snapshot(func(f *fakeRPC) {
		if f.calls != 0 || f.mutationSeq != 0 {
			t.Fatalf("invalid setxattr flags reached RPC: calls=%d mutation_sequence=%d", f.calls, f.mutationSeq)
		}
	})
}

func TestRemovexattrStillForwardsToAuthority(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	removed := 0
	rpc.hook = func(request *authoritypb.Request) {
		if remove := request.GetRemoveXattr(); remove != nil && string(remove.GetName()) == "user.test" {
			removed++
		}
	}
	_, errno := testVisibleMutation(t, mount, func(ctx context.Context) (struct{}, syscall.Errno) {
		return struct{}{}, n.Removexattr(ctx, "user.test")
	})
	if errno != 0 {
		t.Fatalf("Removexattr=%v", errno)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if removed != 1 || f.calls != 1 || f.mutationSeq != 1 {
			t.Fatalf("remove forwarding: matched=%d calls=%d mutation_sequence=%d", removed, f.calls, f.mutationSeq)
		}
	})
}

func TestListxattrSupportsSizeProbe(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.xattrNames = [][]byte{[]byte("user.a"), []byte("user.bb")}
	n := testNode(mount)
	want := []byte("user.a\x00user.bb\x00")
	if size, errno := n.Listxattr(context.Background(), nil); size != uint32(len(want)) || errno != 0 {
		t.Fatalf("Listxattr probe = (%d, %v), want (%d, 0)", size, errno, len(want))
	}
	if size, errno := n.Listxattr(context.Background(), make([]byte, len(want)-1)); size != uint32(len(want)) || errno != syscall.ERANGE {
		t.Fatalf("Listxattr short buffer = (%d, %v), want (%d, ERANGE)", size, errno, len(want))
	}
	dest := make([]byte, len(want))
	if size, errno := n.Listxattr(context.Background(), dest); size != uint32(len(want)) || errno != 0 || !bytes.Equal(dest, want) {
		t.Fatalf("Listxattr value = (%d, %v, %q)", size, errno, dest)
	}
}

func TestSetattrProjectsSinglePrincipal(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	in := &fuse.SetAttrIn{}
	in.Valid = fuse.FATTR_UID | fuse.FATTR_GID | fuse.FATTR_MODE
	in.Uid, in.Gid, in.Mode = 501, 20, 0o600
	_, errno := testVisibleMutation(t, mount, func(ctx context.Context) (struct{}, syscall.Errno) {
		return struct{}{}, n.Setattr(ctx, nil, in, &fuse.AttrOut{})
	})
	if errno != 0 {
		t.Fatal(errno)
	}
	if len(rpc.setattrs) != 1 || rpc.setattrs[0].Uid != nil || rpc.setattrs[0].Gid != nil || rpc.setattrs[0].GetMode() != 0o600 {
		t.Fatalf("projected setattr = %#v", rpc.setattrs)
	}
	in.Uid = 502
	if errno := n.Setattr(context.Background(), nil, in, &fuse.AttrOut{}); errno != syscall.EPERM {
		t.Fatalf("foreign chown errno = %v, want EPERM", errno)
	}
}

func TestSetattrPreservesServerClockNowIntent(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	in := &fuse.SetAttrIn{}
	in.Valid = fuse.FATTR_ATIME_NOW | fuse.FATTR_MTIME_NOW
	_, errno := testVisibleMutation(t, mount, func(ctx context.Context) (struct{}, syscall.Errno) {
		return struct{}{}, n.Setattr(ctx, nil, in, &fuse.AttrOut{})
	})
	if errno != 0 {
		t.Fatal(errno)
	}
	if len(rpc.setattrs) != 1 {
		t.Fatalf("setattr calls = %d, want 1", len(rpc.setattrs))
	}
	request := rpc.setattrs[0]
	if !request.GetAtimeNow() || !request.GetMtimeNow() || request.AtimeNs != nil || request.MtimeNs != nil {
		t.Fatalf("server-clock setattr intent lost: %#v", request)
	}
}

func TestFlushAndReleaseCarryKernelLockOwners(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	handle := &fileHandle{node: n, token: testToken(100)}
	flushCtx, finishFlush := testMutationContext(t, mount)
	if errno := n.Flush(flushCtx, handle, 41); errno != 0 {
		t.Fatal(errno)
	}
	finishFlush(false)
	closeCtx, finishClose := testMutationContext(t, mount)
	if errno := handle.close(closeCtx, 42, true); errno != 0 {
		t.Fatal(errno)
	}
	finishClose(false)
	rpc.mu.Lock()
	defer rpc.mu.Unlock()
	if len(rpc.flushes) != 1 || rpc.flushes[0].GetLockOwner() != 41 {
		t.Fatalf("flush lock owner = %#v", rpc.flushes)
	}
	if len(rpc.fileCloses) != 1 || rpc.fileCloses[0].GetLockOwner() != 42 || !rpc.fileCloses[0].GetFlockUnlock() {
		t.Fatalf("release flock owner = %#v", rpc.fileCloses)
	}
}

func TestLockRequestPreservesFlockNamespace(t *testing.T) {
	spec := lockRequest(make([]byte, 16), 7, &fuse.FileLock{Typ: syscall.F_WRLCK, End: ^uint64(0)}, fuse.FUSE_LK_FLOCK)
	if !spec.GetFlock() || !spec.GetWrite() || spec.GetOwner() != 7 {
		t.Fatalf("flock request = %#v", spec)
	}
}

func TestUncertainResponseFailsClosed(t *testing.T) {
	if got := responseErrno(&authoritypb.Response{Uncertain: true}); got != syscall.EIO {
		t.Fatalf("uncertain errno = %v", got)
	}
}

func TestRawInodeInterningReclaimsEveryCapabilityExactlyOnce(t *testing.T) {
	frontend, mount, rpc := testRawFileSystem(t, 1024)
	const lookups = 64
	records := make([]*inodeRecord, lookups)
	var wg sync.WaitGroup
	for index := range lookups {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			item := testItem(42, authoritypb.Attr_REGULAR, uint64(index+1))
			var errno syscall.Errno
			records[index], errno = frontend.intern(context.Background(), item)
			if errno != 0 {
				t.Errorf("intern %d failed: %v", index, errno)
			}
		}(index)
	}
	wg.Wait()
	first := records[0]
	for index, record := range records {
		if record == nil || record.id != first.id {
			t.Fatalf("record %d = %#v, want NodeID %d", index, record, first.id)
		}
	}
	frontend.Forget(first.id, lookups)
	seen := make(map[string]bool, lookups)
	for range lookups {
		seen[string(popReclaim(t, mount))] = true
	}
	if len(seen) != lookups {
		t.Fatalf("unique reclaimed capabilities = %d, want %d", len(seen), lookups)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if f.calls != 0 {
			t.Fatalf("interning and FORGET performed %d authority calls", f.calls)
		}
	})
}

func TestForgetCannotReclaimCapabilityUsedByInflightOperation(t *testing.T) {
	frontend, mount, _ := testRawFileSystem(t, 8)
	oldRecord, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_REGULAR, 1))
	if errno != 0 {
		t.Fatal("intern old record")
	}
	inflight := frontend.acquire(oldRecord.id)
	if inflight == nil {
		t.Fatal("acquire old record")
	}
	frontend.Forget(oldRecord.id, 1)
	if mount.reclaim.pending() != 0 {
		t.Fatal("FORGET reclaimed a capability still used by an operation")
	}
	newRecord, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_REGULAR, 2))
	if errno != 0 || newRecord.id == oldRecord.id {
		t.Fatalf("replacement record = %#v, old NodeID %d", newRecord, oldRecord.id)
	}
	if newRecord.identity != oldRecord.identity {
		t.Fatalf("replacement stable identity = %x, want %x", newRecord.identity, oldRecord.identity)
	}
	frontend.release(inflight)
	if got := popReclaim(t, mount); !bytes.Equal(got, testToken(1)) {
		t.Fatalf("reclaimed token = %x, want old token", got)
	}
	frontend.Forget(newRecord.id, 1)
	if got := popReclaim(t, mount); !bytes.Equal(got, testToken(2)) {
		t.Fatalf("reclaimed token = %x, want replacement token", got)
	}
}

func TestLiveKernelRecordCannotChangeStableIdentity(t *testing.T) {
	frontend, _, _ := testRawFileSystem(t, 8)
	if _, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_REGULAR, 1)); errno != 0 {
		t.Fatalf("intern original record: %v", errno)
	}
	changed := testItem(42, authoritypb.Attr_REGULAR, 2)
	changed.StableIdentity = testIdentity(4200)
	if _, errno := frontend.intern(context.Background(), changed); errno != syscall.EIO {
		t.Fatalf("intern same live kernel coordinate under another stable identity = %v, want EIO", errno)
	}
}

func TestOpenHandlePinsForgottenInode(t *testing.T) {
	frontend, mount, _ := testRawFileSystem(t, 8)
	record, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_REGULAR, 1))
	if errno != 0 {
		t.Fatal("intern")
	}
	handle := &fileHandle{node: record.node, token: testToken(100)}
	id, ok := frontend.addHandle(record, &handleRecord{file: handle})
	if !ok {
		t.Fatal("add handle")
	}
	frontend.Forget(record.id, 1)
	if mount.reclaim.pending() != 0 || frontend.acquire(record.id) == nil {
		t.Fatal("forgotten inode was not retained by its open handle")
	}
	frontend.release(record)
	taken, ok := frontend.takeHandle(id, handleAuthorityFile)
	if !ok {
		t.Fatal("take handle")
	}
	frontend.unpin(taken.inode)
	if got := popReclaim(t, mount); !bytes.Equal(got, testToken(1)) {
		t.Fatalf("reclaimed token = %x", got)
	}
}

func TestReleaseWaitsForInflightHandleOperation(t *testing.T) {
	frontend, _, _ := testRawFileSystem(t, 8)
	record, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_REGULAR, 1))
	if errno != 0 {
		t.Fatal("intern")
	}
	id, ok := frontend.addHandle(record, &handleRecord{file: &fileHandle{node: record.node, token: testToken(100)}})
	if !ok {
		t.Fatal("add handle")
	}
	operation, handle := frontend.acquireFileHandle(id)
	if handle == nil {
		t.Fatal("acquire handle operation")
	}
	released := make(chan *handleRecord, 1)
	go func() {
		taken, _ := frontend.takeHandle(id, handleAuthorityFile)
		released <- taken
	}()
	select {
	case <-released:
		t.Fatal("release passed an in-flight handle operation")
	case <-time.After(20 * time.Millisecond):
	}
	frontend.releaseHandleOperation(operation)
	select {
	case taken := <-released:
		frontend.unpin(taken.inode)
	case <-time.After(time.Second):
		t.Fatal("release did not resume after operation completed")
	}
}

func TestKeepAliveFailureAbortsSession(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.keepAliveErr = syscall.EIO
	mount.wg.Add(1)
	go mount.keepAlive(mount.ctx, 15*time.Millisecond)
	select {
	case <-mount.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("keepalive failure did not abort mount session")
	}
}

func TestStrictKeepAliveIsBoundedByTheRepairBudget(t *testing.T) {
	const (
		lease  = 2 * time.Minute
		budget = 15 * time.Second
	)
	if got, want := keepAliveInterval(lease, budget), budget/3; got != want {
		t.Fatalf("strict keepalive interval = %s, want %s", got, want)
	}
	if got, want := keepAliveInterval(9*time.Second, time.Minute), 3*time.Second; got != want {
		t.Fatalf("short-lease keepalive interval = %s, want %s", got, want)
	}
}

func TestTerminalSessionSignalAbortsMount(t *testing.T) {
	mount, _ := testMount(t, 8)
	done := make(chan struct{})
	mount.wg.Add(1)
	go mount.watchSession(mount.ctx, done)
	close(done)
	select {
	case <-mount.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("terminal session signal did not abort mount")
	}
}

func TestRefusedReclaimIsTerminal(t *testing.T) {
	mount, rpc := testMount(t, 64)
	rpc.reclaimFailure = syscall.EIO
	mount.start(time.Hour)
	mount.deferReclaim(testToken(1))
	select {
	case <-mount.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("a refused reclaim left the frontend and the authority disagreeing about ownership")
	}
}

// --- the strict cache contract --------------------------------------------

func (f *fakeRPC) SessionID() []byte { return cloneBytes(f.session) }

func (f *fakeRPC) InitialVisibilityCursor() *authoritypb.VisibilityCursor {
	if f.initial == nil {
		return nil
	}
	return proto.Clone(f.initial).(*authoritypb.VisibilityCursor)
}

func (f *fakeRPC) NextVisibility(ctx context.Context, _ *authoritypb.VisibilityCursor) (*authoritypb.VisibilityEvent, error) {
	f.mu.Lock()
	failure, stream := f.visibilityErr, f.events
	f.mu.Unlock()
	if failure != nil {
		return nil, failure
	}
	if stream == nil {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	select {
	case event := <-stream:
		return event, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fakeRPC) AckVisibility(_ context.Context, cursor *authoritypb.VisibilityCursor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acked = append(f.acked, proto.Clone(cursor).(*authoritypb.VisibilityCursor))
	return nil
}

func (f *fakeRPC) NextVisibilityAfterAck(ctx context.Context, cursor *authoritypb.VisibilityCursor, _ bool) (*authoritypb.VisibilityEvent, error) {
	if err := f.AckVisibility(ctx, cursor); err != nil {
		return nil, err
	}
	return f.NextVisibility(ctx, cursor)
}

// ReportVisibilityBlocked records the exact-cycle report and lets a test model
// the authority's pre-apply interruption before the report returns.
func (f *fakeRPC) ReportVisibilityBlocked(_ context.Context, cursor *authoritypb.VisibilityCursor, parents []uint64) error {
	f.mu.Lock()
	f.blocked = append(f.blocked, proto.Clone(cursor).(*authoritypb.VisibilityCursor))
	f.blockedParents = append(f.blockedParents, append([]uint64(nil), parents...))
	err, hook := f.blockedErr, f.onBlocked
	f.mu.Unlock()
	if err == nil && hook != nil {
		hook()
	}
	return err
}

func (f *fakeRPC) DetachAfterUnmount(_ context.Context, proof MountAbsenceProof) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detachProofs = append(f.detachProofs, proof)
	return f.detachErr
}
