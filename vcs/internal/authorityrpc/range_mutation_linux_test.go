//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"fmt"
	"sync"
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

	lockTableMu sync.Mutex
	lockTable   map[[16]byte]*sync.Mutex
	lockStateMu sync.Mutex
	held        map[[16]byte]int
	lockCalls   [][][16]byte

	coordinateWhileLocked bool
	copyUnderLock         bool
	postSampleUnderLock   bool
	copyEntered           chan struct{}
	copyRelease           chan struct{}
	copyEnteredOnce       sync.Once
}

func (s *rangeMutationTestStore) CoordinateOpen(handle xfsstore.Capability) (xfsstore.ObjectCoordinate, error) {
	s.lockStateMu.Lock()
	if len(s.held) != 0 {
		s.coordinateWhileLocked = true
	}
	s.lockStateMu.Unlock()
	return xfsstore.ObjectCoordinate{Stable: [16]byte{handle[0]}, Ino: uint64(handle[0]), DeviceMinor: 1}, nil
}

func (s *rangeMutationTestStore) LockMutation(identities [][16]byte) func() {
	s.lockStateMu.Lock()
	s.lockCalls = append(s.lockCalls, append([][16]byte(nil), identities...))
	s.lockStateMu.Unlock()

	seen := make(map[[16]byte]struct{}, len(identities))
	ordered := make([][16]byte, 0, len(identities))
	locks := make([]*sync.Mutex, 0, len(identities))
	s.lockTableMu.Lock()
	for _, identity := range identities {
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}
		lock := s.lockTable[identity]
		if lock == nil {
			lock = &sync.Mutex{}
			s.lockTable[identity] = lock
		}
		ordered = append(ordered, identity)
		locks = append(locks, lock)
	}
	s.lockTableMu.Unlock()
	for _, lock := range locks {
		lock.Lock()
	}
	s.lockStateMu.Lock()
	for _, identity := range ordered {
		s.held[identity]++
	}
	s.lockStateMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			s.lockStateMu.Lock()
			for _, identity := range ordered {
				if s.held[identity]--; s.held[identity] == 0 {
					delete(s.held, identity)
				}
			}
			s.lockStateMu.Unlock()
			for index := len(locks) - 1; index >= 0; index-- {
				locks[index].Unlock()
			}
		})
	}
}

func (s *rangeMutationTestStore) identitiesHeld(identities ...[16]byte) bool {
	s.lockStateMu.Lock()
	defer s.lockStateMu.Unlock()
	for _, identity := range identities {
		if s.held[identity] == 0 {
			return false
		}
	}
	return true
}

func (s *rangeMutationTestStore) Fallocate(xfsstore.Capability, xfsstore.FallocateSpec) (xfsstore.Attr, error) {
	s.fallocateCalls.Add(1)
	return s.fallocatePost, s.fallocateErr
}

func (s *rangeMutationTestStore) CopyFileRange(input, output xfsstore.Capability, _ xfsstore.CopyFileRangeSpec) (uint64, xfsstore.Attr, error) {
	s.copyCalls.Add(1)
	s.lockStateMu.Lock()
	s.copyUnderLock = s.held[[16]byte{input[0]}] != 0 && s.held[[16]byte{output[0]}] != 0
	s.lockStateMu.Unlock()
	if s.copyEntered != nil {
		s.copyEnteredOnce.Do(func() { close(s.copyEntered) })
	}
	if s.copyRelease != nil {
		<-s.copyRelease
	}
	return s.copyCount, s.copyPost, s.copyErr
}

func (s *rangeMutationTestStore) GetattrOpen(handle xfsstore.Capability) (xfsstore.Attr, error) {
	if s.copyCalls.Load() != 0 {
		s.lockStateMu.Lock()
		s.postSampleUnderLock = s.held[[16]byte{handle[0]}] != 0
		s.lockStateMu.Unlock()
	}
	return xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: uint64(handle[0]), Size: 64, Mode: 0o600, Nlink: 1}, nil
}

func rangePostStateAttr(state *authoritypb.PostState, role uint32) *authoritypb.Attr {
	for _, object := range state.GetObjects() {
		if object.GetRoles() == role {
			return object.GetAttr()
		}
	}
	return nil
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
	store := &rangeMutationTestStore{
		lockTable: make(map[[16]byte]*sync.Mutex),
		held:      make(map[[16]byte]int),
	}
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

func fallocateMutationRequest(requestID uint64, handle xfsstore.Capability) *authoritypb.Request {
	request := &authoritypb.Request{
		RequestId: requestID,
		Body: &authoritypb.Request_Fallocate{Fallocate: &authoritypb.FallocateRequest{
			Handle: handle[:], Offset: 4, Length: 8,
		}},
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
		body := &authoritypb.FallocateRequest{Handle: make([]byte, 16), Length: 1, Mode: mode}
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
		body := &authoritypb.FallocateRequest{Handle: make([]byte, 16), Length: 1, Mode: mode}
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
	if response.GetErrno() != 0 || response.GetUncertain() || postStateTargetAttr(response.GetPostState()).GetSize() != 12 ||
		reply.GetFlags() != rangeReplyApplied || reply.GetResultSize() != 0 || reply.GetPostSize() != 12 ||
		reply.GetVisibilitySequence() != response.GetPostState().GetSnapshotSequence() {
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
	if response.GetErrno() != 0 || response.GetUncertain() || response.GetPostState() != nil ||
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
	if response.GetErrno() != 0 || response.GetUncertain() || postStateTargetAttr(response.GetPostState()).GetSize() != 12 ||
		reply.GetFlags() != rangeReplyApplied|rangeReplyPostApply || reply.GetResultSize() != 0 ||
		reply.GetPostSize() != 12 || reply.GetVisibilitySequence() != response.GetPostState().GetSnapshotSequence() || reply.GetError() != -int32(syscall.ENOSPC) {
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
		RequestId: requestID,
		Body: &authoritypb.Request_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeRequest{
			InputHandle: input[:], InputOffset: 2, OutputHandle: output[:], OutputOffset: 7, Length: 9,
		}},
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
	if response.GetErrno() != 0 || len(response.GetPostState().GetObjects()) != 2 ||
		rangePostStateAttr(response.GetPostState(), postStateRoleSource).GetInode() != 0x21 ||
		rangePostStateAttr(response.GetPostState(), postStateRoleDestination).GetSize() != 20 || reply.GetFlags() != rangeReplyApplied ||
		reply.GetResultSize() != 5 || reply.GetPostSize() != 20 || reply.GetVisibilitySequence() != response.GetPostState().GetSnapshotSequence() {
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
	if response.GetErrno() != 0 || response.GetPostState() != nil || reply.GetFlags() != rangeReplyNoop ||
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
	if response.GetErrno() != 0 || response.GetUncertain() || len(response.GetPostState().GetObjects()) != 2 ||
		rangePostStateAttr(response.GetPostState(), postStateRoleDestination).GetSize() != 19 ||
		reply.GetFlags() != rangeReplyApplied|rangeReplyPostApply || reply.GetResultSize() != 0 ||
		reply.GetPostSize() != 19 || reply.GetVisibilitySequence() != response.GetPostState().GetSnapshotSequence() || reply.GetError() != -int32(syscall.ENOSPC) {
		t.Fatalf("zero-byte metadata-only CFR = %+v", response)
	}
	replay := copyMutationRequest(2, input, output)
	replayed := h.handleCopyFileRange(t.Context(), replay, credential, replay.GetCopyFileRange())
	if replayed.GetCopyFileRange().GetFlags() != rangeReplyApplied|rangeReplyPostApply ||
		replayed.GetCopyFileRange().GetResultSize() != 0 || store.copyCalls.Load() != 1 {
		t.Fatalf("zero-byte metadata-only CFR replay = %+v calls=%d", replayed, store.copyCalls.Load())
	}
}

func TestCopyFileRangeLocksResolvedIdentitiesThroughBothSnapshots(t *testing.T) {
	h, credential, store, input, output := newRangeMutationHarness(t)
	store.copyCount = 5
	store.copyPost = xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x31, Size: 20, Mode: 0o600, Nlink: 1}
	store.copyEntered = make(chan struct{})
	store.copyRelease = make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-store.copyRelease:
		default:
			close(store.copyRelease)
		}
	})

	response := make(chan *authoritypb.Response, 1)
	request := copyMutationRequest(1, input, output)
	go func() {
		response <- h.handleCopyFileRange(t.Context(), request, credential, request.GetCopyFileRange())
	}()
	select {
	case <-store.copyEntered:
	case <-time.After(time.Second):
		t.Fatal("COPY_FILE_RANGE did not reach the locked storage call")
	}

	sourceIdentity, destinationIdentity := [16]byte{input[0]}, [16]byte{output[0]}
	store.lockStateMu.Lock()
	if len(store.lockCalls) != 1 || len(store.lockCalls[0]) != 2 ||
		store.lockCalls[0][0] != sourceIdentity || store.lockCalls[0][1] != destinationIdentity {
		calls := append([][][16]byte(nil), store.lockCalls...)
		store.lockStateMu.Unlock()
		t.Fatalf("mutation lock calls = %#v, want resolved source then destination", calls)
	}
	coordinateWhileLocked, copyUnderLock := store.coordinateWhileLocked, store.copyUnderLock
	store.lockStateMu.Unlock()
	if coordinateWhileLocked || !copyUnderLock {
		t.Fatalf("coordinateWhileLocked=%v copyUnderLock=%v", coordinateWhileLocked, copyUnderLock)
	}

	competitorAcquired := make(chan struct{})
	go func() {
		unlock := store.LockMutation([][16]byte{sourceIdentity})
		close(competitorAcquired)
		unlock()
	}()
	select {
	case <-competitorAcquired:
		t.Fatal("a concurrent source mutation entered before COPY_FILE_RANGE sampled post-state")
	case <-time.After(25 * time.Millisecond):
	}
	close(store.copyRelease)
	select {
	case got := <-response:
		if got.GetErrno() != 0 || got.GetUncertain() {
			t.Fatalf("COPY_FILE_RANGE = %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("COPY_FILE_RANGE did not finish")
	}
	select {
	case <-competitorAcquired:
	case <-time.After(time.Second):
		t.Fatal("source mutation lock was not released")
	}
	store.lockStateMu.Lock()
	postSampleUnderLock := store.postSampleUnderLock
	held := len(store.held)
	store.lockStateMu.Unlock()
	if !postSampleUnderLock || held != 0 {
		t.Fatalf("postSampleUnderLock=%v retainedLocks=%d", postSampleUnderLock, held)
	}
}

func TestCopyFileRangeRecallsLeasesHeldOnlyOnSource(t *testing.T) {
	h, source, store, input, output := newRangeMutationHarness(t)
	store.copyCount = 5
	store.copyPost = xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0x31, Size: 20, Mode: 0o600, Nlink: 1}
	observer, err := h.Runtime.AttachActiveForTest(2, volumeserver.PeerIdentity{0x72}, volumeserver.Authorization{
		Access: volumeserver.AccessRead, Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := h.Runtime.SessionTerminal(observer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Leases.ActivateHolder(observer.ID, terminal); err != nil {
		t.Fatal(err)
	}
	sourceIdentity := [16]byte{input[0]}
	for _, grant := range []struct {
		coordinate volumeserver.LeaseCoordinate
		right      volumeserver.LeaseRight
	}{
		{volumeserver.LeaseCoordinate{Family: volumeserver.LeaseFamilyData, Identity: sourceIdentity}, volumeserver.LeaseRightDataRead},
		{volumeserver.LeaseCoordinate{Family: volumeserver.LeaseFamilyAttributes, Identity: sourceIdentity}, volumeserver.LeaseRightAttributesRead},
	} {
		if _, err := h.Leases.Grant(t.Context(), observer.ID, grant.coordinate, grant.right); err != nil {
			t.Fatal(err)
		}
	}

	request := copyMutationRequest(1, input, output)
	response := make(chan *authoritypb.Response, 1)
	go func() {
		response <- h.handleCopyFileRange(t.Context(), request, source, request.GetCopyFileRange())
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	revoke, err := h.Leases.Next(ctx, observer.ID, volumeserver.LeaseEventCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if revoke.Cursor.Phase != volumeserver.LeaseEventRevoke || len(revoke.Recalls) != 2 {
		t.Fatalf("source-only REVOKE = %#v", revoke)
	}
	for _, recall := range revoke.Recalls {
		if recall.Coordinate.Identity != sourceIdentity ||
			(recall.Coordinate.Family != volumeserver.LeaseFamilyData && recall.Coordinate.Family != volumeserver.LeaseFamilyAttributes) {
			t.Fatalf("source-only recall = %#v", recall)
		}
	}
	if err := h.Leases.AcknowledgeRevoke(observer.ID, revoke.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := h.Leases.Next(ctx, observer.ID, revoke.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if complete.Cursor.Phase != volumeserver.LeaseEventComplete || len(complete.PostState) != 2 {
		t.Fatalf("source-only COMPLETE = %#v", complete)
	}
	var sourceState *volumeserver.VisibilityObjectPostState
	for index := range complete.PostState {
		if complete.PostState[index].StableIdentity == sourceIdentity {
			sourceState = &complete.PostState[index]
		}
	}
	if sourceState == nil || sourceState.Roles != postStateRoleSource || sourceState.Attr.Inode != uint64(input[0]) || sourceState.ObjectVersion != 1 {
		t.Fatalf("source-only exact post-state = %#v", sourceState)
	}
	discharges := make([]volumeserver.LeaseDischarge, len(complete.Recalls))
	for index, recall := range complete.Recalls {
		discharges[index] = volumeserver.LeaseDischarge{
			Coordinate: recall.Coordinate, RevokeEpoch: recall.RevokeEpoch, Mode: volumeserver.LeaseDischargeToNone,
		}
	}
	if err := h.Leases.Discharge(observer.ID, complete.Cursor, discharges); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-response:
		if got.GetErrno() != 0 || got.GetUncertain() {
			t.Fatalf("COPY_FILE_RANGE = %+v", got)
		}
	case <-ctx.Done():
		t.Fatal("COPY_FILE_RANGE did not finish after source-only repair")
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
