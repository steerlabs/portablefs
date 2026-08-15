//go:build linux

package authorityrpc

import (
	"errors"
	"fmt"
	"math"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"golang.org/x/sys/unix"
)

type rangeMutationTestStore struct {
	resourceAdmissionFaultStore
	fallocateCalls atomic.Uint32
	copyCalls      atomic.Uint32
	fallocatePost  xfsstore.Attr
	fallocateErr   error
	copyCount      uint64
	copyPost       xfsstore.Attr
	copyErr        error
}

func (s *rangeMutationTestStore) CoordinateOpen(handle xfsstore.Capability) (xfsstore.ObjectCoordinate, error) {
	return xfsstore.ObjectCoordinate{Stable: [16]byte{handle[0]}, Ino: uint64(handle[0]), DeviceMinor: 1}, nil
}

func (s *rangeMutationTestStore) Fallocate(xfsstore.Capability, xfsstore.FallocateSpec) (xfsstore.Attr, error) {
	s.fallocateCalls.Add(1)
	return s.fallocatePost, s.fallocateErr
}

func (s *rangeMutationTestStore) CopyFileRange(xfsstore.Capability, xfsstore.Capability, xfsstore.CopyFileRangeSpec) (uint64, xfsstore.Attr, error) {
	s.copyCalls.Add(1)
	return s.copyCount, s.copyPost, s.copyErr
}

func newRangeMutationHarness(t *testing.T) (*VolumeHandler, volumeserver.SessionCredential, *rangeMutationTestStore, xfsstore.Capability, xfsstore.Capability) {
	t.Helper()
	runtime, err := volumeserver.New("range-mutation", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 4, MaxSessions: 2, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := runtime.AttachActiveForTest(2, volumeserver.PeerIdentity{0x71}, volumeserver.Authorization{
		Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &rangeMutationTestStore{}
	h := testVolumeHandler()
	h.Store, h.Runtime = store, runtime
	root := xfsstore.Capability{0x11}
	input, output := xfsstore.Capability{0x21}, xfsstore.Capability{0x31}
	if err := h.startSessionResources(credential.ID, root, 4, [32]byte{}, volumeserver.CoherenceStrict); err != nil {
		t.Fatal(err)
	}
	if err := h.trackOpen(credential.ID, input, false); err != nil {
		t.Fatal(err)
	}
	if err := h.trackOpen(credential.ID, output, false); err != nil {
		t.Fatal(err)
	}
	return h, credential, store, input, output
}

func itemGate(identities ...[16]byte) *authoritypb.SourcePublicationGate {
	targets := make([]*authoritypb.SourcePublicationTarget, 0, len(identities))
	for _, identity := range identities {
		identity := identity
		targets = append(targets, &authoritypb.SourcePublicationTarget{Coordinate: &authoritypb.SourcePublicationTarget_Item{
			Item: &authoritypb.SourcePublicationItem{Identity: identity[:], Attributes: true, Data: true},
		}})
	}
	return &authoritypb.SourcePublicationGate{Targets: targets}
}

func fallocateMutationRequest(requestID uint64, handle xfsstore.Capability) *authoritypb.Request {
	request := &authoritypb.Request{
		RequestId: requestID, FrontendOperationId: 17,
		Body: &authoritypb.Request_Fallocate{Fallocate: &authoritypb.FallocateRequest{
			Handle: handle[:], Offset: 4, Length: 8, RlimitFsize: math.MaxUint64,
			FileMaxSize: math.MaxInt64, WriteFlags: writeTransactionKillSUIDGID,
		}},
		SourcePublicationGate: itemGate([16]byte{handle[0]}),
	}
	request.Mutation = &authoritypb.Mutation{Slot: 0, Sequence: 1}
	return request
}

func TestFallocateRequestModeSetIsExact(t *testing.T) {
	valid := []uint32{
		0,
		uint32(unix.FALLOC_FL_KEEP_SIZE),
		uint32(unix.FALLOC_FL_PUNCH_HOLE | unix.FALLOC_FL_KEEP_SIZE),
		uint32(unix.FALLOC_FL_ZERO_RANGE),
		uint32(unix.FALLOC_FL_ZERO_RANGE | unix.FALLOC_FL_KEEP_SIZE),
		uint32(unix.FALLOC_FL_COLLAPSE_RANGE),
		uint32(unix.FALLOC_FL_INSERT_RANGE),
		uint32(unix.FALLOC_FL_UNSHARE_RANGE),
		uint32(unix.FALLOC_FL_UNSHARE_RANGE | unix.FALLOC_FL_KEEP_SIZE),
	}
	for _, mode := range valid {
		body := &authoritypb.FallocateRequest{Handle: make([]byte, 16), Length: 1, RlimitFsize: math.MaxUint64, FileMaxSize: math.MaxInt64, Mode: mode}
		if !validFallocateRequest(body) {
			t.Fatalf("valid mode %#x was refused", mode)
		}
	}
	invalid := []uint32{
		uint32(unix.FALLOC_FL_PUNCH_HOLE),
		uint32(unix.FALLOC_FL_COLLAPSE_RANGE | unix.FALLOC_FL_KEEP_SIZE),
		uint32(unix.FALLOC_FL_INSERT_RANGE | unix.FALLOC_FL_KEEP_SIZE),
		uint32(unix.FALLOC_FL_ZERO_RANGE | unix.FALLOC_FL_UNSHARE_RANGE),
		1 << 31,
	}
	for _, mode := range invalid {
		body := &authoritypb.FallocateRequest{Handle: make([]byte, 16), Length: 1, RlimitFsize: math.MaxUint64, FileMaxSize: math.MaxInt64, Mode: mode}
		if validFallocateRequest(body) {
			t.Fatalf("invalid mode %#x was admitted", mode)
		}
	}
}

func TestFallocateAppliedResultAndReplayCarryExactPostState(t *testing.T) {
	h, credential, store, handle, _ := newRangeMutationHarness(t)
	store.fallocatePost = xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x21, Size: 12, Mode: 0o600, Nlink: 1}
	request := fallocateMutationRequest(1, handle)
	response := h.handleFallocate(t.Context(), request, credential, request.GetFallocate())
	reply := response.GetFallocate()
	if response.GetErrno() != 0 || response.GetUncertain() || response.GetPostAttr().GetSize() != 12 ||
		reply.GetFlags() != rangeReplyApplied || reply.GetResultSize() != 0 || reply.GetPostSize() != 12 || reply.GetVisibilitySequence() != 1 {
		t.Fatalf("fallocate applied = %+v", response)
	}
	replay := fallocateMutationRequest(2, handle)
	replayed := h.handleFallocate(t.Context(), replay, credential, replay.GetFallocate())
	if replayed.GetErrno() != 0 || replayed.GetFallocate().GetPostSize() != 12 || store.fallocateCalls.Load() != 1 {
		t.Fatalf("fallocate replay = %+v calls=%d", replayed, store.fallocateCalls.Load())
	}
}

func TestFallocateRLimitRejectionIsDefiniteAndHasNoPostState(t *testing.T) {
	h, credential, store, handle, _ := newRangeMutationHarness(t)
	store.fallocatePost = xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x21, Size: 6, Mode: 0o600, Nlink: 1}
	store.fallocateErr = &xfsstore.WriteLimitError{RLimit: true}
	request := fallocateMutationRequest(1, handle)
	response := h.handleFallocate(t.Context(), request, credential, request.GetFallocate())
	reply := response.GetFallocate()
	if response.GetErrno() != 0 || response.GetUncertain() || response.GetPostAttr() != nil ||
		reply.GetFlags() != rangeReplyRejectedRLimit || reply.GetError() != -int32(syscall.EFBIG) ||
		reply.GetResultSize() != 0 || reply.GetPostSize() != 6 || reply.GetVisibilitySequence() != 0 {
		t.Fatalf("fallocate RLIMIT rejection = %+v", response)
	}
}

func TestFallocatePostDispatchErrorPublishesAndReplaysExactState(t *testing.T) {
	h, credential, store, handle, _ := newRangeMutationHarness(t)
	store.fallocatePost = xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x21, Size: 12, Mode: 0o600, Nlink: 1}
	store.fallocateErr = fmt.Errorf("%w: %w", xfsstore.ErrWritePostApply, syscall.ENOSPC)
	request := fallocateMutationRequest(1, handle)
	response := h.handleFallocate(t.Context(), request, credential, request.GetFallocate())
	reply := response.GetFallocate()
	if response.GetErrno() != 0 || response.GetUncertain() || response.GetPostAttr().GetSize() != 12 ||
		reply.GetFlags() != rangeReplyApplied|rangeReplyPostApply || reply.GetResultSize() != 0 ||
		reply.GetPostSize() != 12 || reply.GetVisibilitySequence() != 1 || reply.GetError() != -int32(syscall.ENOSPC) {
		t.Fatalf("post-dispatch fallocate error = %+v", response)
	}
	replay := fallocateMutationRequest(2, handle)
	replayed := h.handleFallocate(t.Context(), replay, credential, replay.GetFallocate())
	if replayed.GetFallocate().GetFlags() != rangeReplyApplied|rangeReplyPostApply ||
		replayed.GetFallocate().GetError() != -int32(syscall.ENOSPC) || store.fallocateCalls.Load() != 1 {
		t.Fatalf("post-dispatch fallocate replay = %+v calls=%d", replayed, store.fallocateCalls.Load())
	}
}

func copyMutationRequest(requestID uint64, input, output xfsstore.Capability) *authoritypb.Request {
	request := &authoritypb.Request{
		RequestId: requestID, FrontendOperationId: 18,
		Body: &authoritypb.Request_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeRequest{
			InputHandle: input[:], InputOffset: 2, OutputHandle: output[:], OutputOffset: 7, Length: 9,
			RlimitFsize: math.MaxUint64, FileMaxSize: math.MaxInt64,
		}},
		SourcePublicationGate: itemGate([16]byte{input[0]}, [16]byte{output[0]}),
	}
	request.Mutation = &authoritypb.Mutation{Slot: 0, Sequence: 1}
	return request
}

func TestCopyFileRangeAppliedReplayAndEOFNoopShapes(t *testing.T) {
	h, credential, store, input, output := newRangeMutationHarness(t)
	store.copyCount = 5
	store.copyPost = xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x31, Size: 20, Mode: 0o600, Nlink: 1}
	request := copyMutationRequest(1, input, output)
	response := h.handleCopyFileRange(t.Context(), request, credential, request.GetCopyFileRange())
	reply := response.GetCopyFileRange()
	if response.GetErrno() != 0 || response.GetPostAttr().GetSize() != 20 || reply.GetFlags() != rangeReplyApplied ||
		reply.GetResultSize() != 5 || reply.GetPostSize() != 20 || reply.GetVisibilitySequence() != 1 {
		t.Fatalf("copy applied = %+v", response)
	}
	replay := copyMutationRequest(2, input, output)
	if got := h.handleCopyFileRange(t.Context(), replay, credential, replay.GetCopyFileRange()); got.GetCopyFileRange().GetResultSize() != 5 || store.copyCalls.Load() != 1 {
		t.Fatalf("copy replay = %+v calls=%d", got, store.copyCalls.Load())
	}

	h2, credential2, store2, input2, output2 := newRangeMutationHarness(t)
	noop := copyMutationRequest(1, input2, output2)
	response = h2.handleCopyFileRange(t.Context(), noop, credential2, noop.GetCopyFileRange())
	reply = response.GetCopyFileRange()
	if response.GetErrno() != 0 || response.GetPostAttr() != nil || reply.GetFlags() != rangeReplyNoop ||
		reply.GetResultSize() != 0 || reply.GetPostSize() != 0 || reply.GetVisibilitySequence() != 0 || reply.GetError() != 0 || store2.copyCalls.Load() != 1 {
		t.Fatalf("copy EOF no-op = %+v calls=%d", response, store2.copyCalls.Load())
	}
}

func TestCopyFileRangePublishesZeroByteMetadataOnlyPostApply(t *testing.T) {
	h, credential, store, input, output := newRangeMutationHarness(t)
	store.copyPost = xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x31, Size: 19, Mode: 0o640, Nlink: 1}
	store.copyErr = fmt.Errorf("%w: %w", xfsstore.ErrWritePostApply, syscall.ENOSPC)
	request := copyMutationRequest(1, input, output)
	response := h.handleCopyFileRange(t.Context(), request, credential, request.GetCopyFileRange())
	reply := response.GetCopyFileRange()
	if response.GetErrno() != 0 || response.GetUncertain() || response.GetPostAttr().GetSize() != 19 ||
		reply.GetFlags() != rangeReplyApplied|rangeReplyPostApply || reply.GetResultSize() != 0 ||
		reply.GetPostSize() != 19 || reply.GetVisibilitySequence() != 1 || reply.GetError() != -int32(syscall.ENOSPC) {
		t.Fatalf("zero-byte metadata-only CFR = %+v", response)
	}
	replay := copyMutationRequest(2, input, output)
	replayed := h.handleCopyFileRange(t.Context(), replay, credential, replay.GetCopyFileRange())
	if replayed.GetCopyFileRange().GetFlags() != rangeReplyApplied|rangeReplyPostApply ||
		replayed.GetCopyFileRange().GetResultSize() != 0 || store.copyCalls.Load() != 1 {
		t.Fatalf("zero-byte metadata-only CFR replay = %+v calls=%d", replayed, store.copyCalls.Load())
	}
}

func TestRangePostApplyBarrierFailureRetainsAppliedResult(t *testing.T) {
	response := &authoritypb.Response{Body: &authoritypb.Response_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeReply{
		ResultSize: 3, PostSize: 8, VisibilitySequence: 9, Flags: rangeReplyApplied,
	}}}
	if !markRangePostApplyFailure(response, syscall.EIO) {
		t.Fatal("applied copy was not retainable after peer completion failure")
	}
	if got := response.GetCopyFileRange(); got.GetFlags() != rangeReplyApplied|rangeReplyPostApply || got.GetError() != -int32(syscall.EIO) {
		t.Fatalf("postapply copy = %+v", got)
	}
	zero := &authoritypb.Response{Body: &authoritypb.Response_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeReply{
		PostSize: 8, VisibilitySequence: 9, Flags: rangeReplyApplied,
	}}}
	if !markRangePostApplyFailure(zero, syscall.EIO) {
		t.Fatal("zero-byte metadata-only copy was not retainable after peer completion failure")
	}
	rejected := copyFileRangeRejected(&VolumeHandler{}, errors.New("bad request"))
	if markRangePostApplyFailure(rejected, syscall.EIO) {
		t.Fatal("definite rejection was rewritten as applied")
	}
}
