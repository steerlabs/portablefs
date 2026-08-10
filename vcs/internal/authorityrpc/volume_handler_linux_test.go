//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

func testVolumeHandler() *VolumeHandler {
	return &VolumeHandler{
		MaxFrame: 1 << 20, MaxRead: 1 << 16, MaxWrite: 1 << 16, MaxInFlight: 8,
		MaxItemsPerSession: 64, MaxOpensPerSession: 64, MaxItems: 128, MaxOpens: 128,
		MaxRetainedReplyBytes: 1 << 20,
	}
}

type detachMembership struct {
	mu     sync.Mutex
	active map[volumeserver.SessionID]bool
}

func (m *detachMembership) Activate(id volumeserver.SessionID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		m.active = make(map[volumeserver.SessionID]bool)
	}
	m.active[id] = true
	return nil
}

func (m *detachMembership) Deactivate(id volumeserver.SessionID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.active, id)
	return nil
}

func (m *detachMembership) contains(id volumeserver.SessionID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active[id]
}

func TestStrictCleanDetachIsBoundToTheAuthenticatedSession(t *testing.T) {
	runtime, err := volumeserver.New("authenticated-detach", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 4, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	membership := &detachMembership{}
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: membership, Fencer: runtime,
		MaxCachedNameCapacity: 64, MaxRepairBudget: time.Minute, MaxClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := testVolumeHandler()
	h.Store = &resourceAdmissionFaultStore{}
	h.Runtime = runtime
	h.Authorizer = allowAuthorizer{access: volumeserver.AccessRead}
	h.Visibility = visibility
	h.Routes = &RoutesController{Visibility: visibility, loaded: true}

	peers := []volumeserver.PeerIdentity{{0x31}, {0x32}, {0x33}}
	credentials := make([]volumeserver.SessionCredential, len(peers))
	for index, peer := range peers {
		credential, err := runtime.Attach(2, peer, volumeserver.Authorization{Access: volumeserver.AccessRead, Deadline: time.Now().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		credentials[index] = credential
		if err := h.startSessionResources(credential.ID, xfsstore.Capability{byte(index + 1)}, 2, [32]byte{}, volumeserver.CoherenceStrict); err != nil {
			t.Fatal(err)
		}
		terminal, err := runtime.SessionTerminal(credential.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := visibility.Register(credential.ID, volumeserver.CoherenceStrict, terminal, volumeserver.VisibilityCommitment{
			CachedNameCapacity: 32, RepairBudget: time.Second, NamespaceRepair: volumeserver.NamespaceRepairParentExclusive,
		}); err != nil {
			t.Fatal(err)
		}
	}

	requestFor := func(id uint64, credential volumeserver.SessionCredential) *authoritypb.Request {
		return &authoritypb.Request{
			RequestId: id, Epoch: credential.Epoch[:],
			Session: &authoritypb.SessionProof{Id: credential.ID[:], Generation: credential.Generation, ResumeSecret: credential.Secret[:]},
			Body: &authoritypb.Request_Detach{Detach: &authoritypb.DetachRequest{MountAbsence: &authoritypb.MountAbsenceProof{
				ObservedUnixNanos: time.Now().UnixNano(), Observation: []byte("exact kernel mount absent"), Component: "official-supervisor",
			}}},
		}
	}

	// A valid secret presented from the other authenticated peer cannot detach
	// this session. The credential binds both the peer and the exact session.
	wrongPeer := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte(peers[1]))
	if response := h.Handle(wrongPeer, requestFor(1, credentials[0])); response.GetErrno() == 0 {
		t.Fatal("a different authenticated peer detached the first mount session")
	}
	if !membership.contains(credentials[0].ID) || !membership.contains(credentials[1].ID) || !membership.contains(credentials[2].ID) {
		t.Fatal("a refused cross-session detach changed durable membership")
	}

	// Peer mismatch permanently fences the attacked credential, so use the two
	// untouched sessions to prove normal clean detach removes only its caller.
	for index := 1; index < len(credentials); index++ {
		credential := credentials[index]
		ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte(peers[index]))
		if response := h.Handle(ctx, requestFor(uint64(index+2), credential)); response.GetErrno() != 0 {
			t.Fatalf("session %d clean detach = %+v", index, response)
		}
		if membership.contains(credential.ID) {
			t.Fatalf("session %d clean detach left its durable membership active", index)
		}
		if !membership.contains(credentials[0].ID) {
			t.Fatal("clean detach cleared the fenced victim's durable membership")
		}
		if index == 1 && !membership.contains(credentials[2].ID) {
			t.Fatal("detaching one healthy session cleared the other session's membership")
		}
	}
}

func TestWireErrnoPreservesLinuxSyscall(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EACCES, syscall.EXDEV, syscall.ELOOP, syscall.EBADF} {
		if got := wireErrno(errno); got != int32(errno) {
			t.Fatalf("wireErrno(%v) = %d", errno, got)
		}
	}
}

func TestPostMutationLocalFailureIsMarkedUncertain(t *testing.T) {
	h := &VolumeHandler{}
	response := h.errorResponse(7, errors.Join(xfsstore.ErrOutcomeUncertain, syscall.EMFILE), false)
	if !response.GetUncertain() || response.GetErrno() != int32(syscall.EMFILE) {
		t.Fatalf("response = %+v, want uncertain EMFILE", response)
	}
}

func TestVisibilityInterruptedMapsToDefiniteEINTR(t *testing.T) {
	h := &VolumeHandler{}
	response := h.errorResponse(7, volumeserver.ErrVisibilityInterrupted, false)
	if response.GetErrno() != errnos.EINTR {
		t.Fatalf("visibility interruption errno = %d, want EINTR", response.GetErrno())
	}
	if response.GetUncertain() {
		t.Fatal("pre-apply visibility interruption was marked uncertain")
	}
	if response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_INTERRUPTED {
		t.Fatalf("visibility interruption failure class = %v, want VISIBILITY_INTERRUPTED", response.GetFailure())
	}
}

func TestHandlerRejectsInvalidSourcePhaseQueueabilityBeforeDispatch(t *testing.T) {
	h := &VolumeHandler{}
	tests := []struct {
		name    string
		request *authoritypb.Request
	}{
		{name: "hello", request: &authoritypb.Request{Body: &authoritypb.Request_Hello{Hello: &authoritypb.HelloRequest{}}}},
		{name: "attach", request: &authoritypb.Request{Body: &authoritypb.Request_Attach{Attach: &authoritypb.AttachRequest{}}}},
		{name: "visibility control", request: &authoritypb.Request{Body: &authoritypb.Request_NextVisibility{NextVisibility: &authoritypb.NextVisibilityRequest{}}}},
		{name: "ordinary request", request: &authoritypb.Request{Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.request.RequestId = 19
			test.request.FrontendOperationId = 7
			test.request.SourcePhaseQueueable = true
			response := h.Handle(context.Background(), test.request)
			if response.GetErrno() != int32(syscall.EINVAL) || response.GetUncertain() {
				t.Fatalf("invalid queueability response = %+v, want definite EINVAL", response)
			}
		})
	}
}

// This exercises the retained-mutation path, not only errorResponse. A
// callback-serialized source with deferred COMPLETE outstanding consumes one
// mutation slot as a definite EINTR. Replaying that exact identity must return
// the retained EINTR and must never enter visibility prepare or filesystem
// apply on either delivery.
func TestMutateVisibleRetainsPreApplyVisibilityEINTRForExactReplay(t *testing.T) {
	runtime, err := volumeserver.New("visibility-eintr-replay", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 2, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := volumeserver.PeerIdentity{1}
	cred, err := runtime.Attach(2, peer, volumeserver.Authorization{
		Access:   volumeserver.AccessRead | volumeserver.AccessWrite,
		Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: noopMembership{}, Fencer: noopFencer{},
		MaxCachedNameCapacity: 1024, MaxRepairBudget: time.Minute, MaxClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal := make(chan struct{})
	t.Cleanup(func() { close(terminal) })
	if err := visibility.Register(cred.ID, volumeserver.CoherenceStrict, terminal, volumeserver.VisibilityCommitment{
		CachedNameCapacity: 1024,
		RepairBudget:       5 * time.Second,
		NamespaceRepair:    volumeserver.NamespaceRepairCallbackSerialized,
	}); err != nil {
		t.Fatal(err)
	}

	// Produce the source-deferred COMPLETE state against which the handler's
	// mutation is refused.
	parent := [16]byte{1}
	targets := []volumeserver.VisibilityTarget{{
		Scope: volumeserver.VisibilityNamespace, ParentIdentity: parent, Name: []byte("first"),
	}}
	first := make(chan error, 1)
	go func() {
		first <- visibility.Execute(
			context.Background(), cred.ID, volumeserver.MutationID{Sequence: 1},
			func() ([]volumeserver.VisibilityTarget, error) { return targets, nil },
			func() ([]volumeserver.VisibilityTarget, bool) { return targets, true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := visibility.Next(ctx, cred.ID, volumeserver.VisibilityCursor{})
	if err != nil {
		t.Fatal(err)
	}
	if err := visibility.Ack(cred.ID, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-first; err != nil {
		t.Fatalf("seed mutation: %v", err)
	}
	complete, err := visibility.Next(ctx, cred.ID, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}

	h := testVolumeHandler()
	h.Runtime = runtime
	h.Visibility = visibility
	if err := h.startSessionResources(cred.ID, xfsstore.Capability{1}, 2, [32]byte{}, volumeserver.CoherenceStrict); err != nil {
		t.Fatal(err)
	}
	request := &authoritypb.Request{
		RequestId:           7,
		FrontendOperationId: 77,
		Body: &authoritypb.Request_SetXattr{SetXattr: &authoritypb.SetXattrRequest{
			Item: []byte{1}, Name: []byte("user.replay"), Value: []byte("value"),
		}},
	}
	stampMutation(t, request, 0, 1)
	var prepareCalls, applyCalls atomic.Uint32
	handlerPrepare := func() ([]volumeserver.VisibilityTarget, error) {
		prepareCalls.Add(1)
		return []volumeserver.VisibilityTarget{{
			Scope: volumeserver.VisibilityAttributes, Identity: [16]byte{2},
		}}, nil
	}
	handlerApply := func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
		applyCalls.Add(1)
		response := h.success(0)
		return response, []volumeserver.VisibilityTarget{{
			Scope: volumeserver.VisibilityAttributes, Identity: [16]byte{2},
		}}
	}

	interrupted := h.mutateVisible(ctx, request, cred, handlerPrepare, handlerApply)
	if interrupted.GetErrno() != errnos.EINTR || interrupted.GetUncertain() {
		t.Fatalf("first interrupted mutation = %+v, want definite EINTR", interrupted)
	}
	if interrupted.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_INTERRUPTED {
		t.Fatalf("interrupted failure class = %v, want VISIBILITY_INTERRUPTED", interrupted.GetFailure())
	}
	if interrupted.GetMutation().GetSlot() != 0 || interrupted.GetMutation().GetAcceptedSequence() != 1 {
		t.Fatalf("interrupted mutation state = %v, want retained slot 0 sequence 1", interrupted.GetMutation())
	}
	if prepareCalls.Load() != 0 || applyCalls.Load() != 0 {
		t.Fatalf("first interrupted delivery reached prepare=%d apply=%d", prepareCalls.Load(), applyCalls.Load())
	}

	request.RequestId = 8
	// Queueability is scheduling metadata, not replay identity. Flipping it on
	// an exact replay must return the retained definite interruption rather than
	// execute prepare/apply again under a different scheduling decision.
	request.SourcePhaseQueueable = true
	replayed := h.mutateVisible(ctx, request, cred, handlerPrepare, handlerApply)
	if replayed.GetErrno() != errnos.EINTR || replayed.GetUncertain() {
		t.Fatalf("replayed interrupted mutation = %+v, want retained definite EINTR", replayed)
	}
	if replayed.GetMutation().GetSlot() != 0 || replayed.GetMutation().GetAcceptedSequence() != 1 {
		t.Fatalf("replayed mutation state = %v, want retained slot 0 sequence 1", replayed.GetMutation())
	}
	if prepareCalls.Load() != 0 || applyCalls.Load() != 0 {
		t.Fatalf("exact replay re-executed prepare=%d apply=%d", prepareCalls.Load(), applyCalls.Load())
	}
	if err := visibility.Ack(cred.ID, complete.Cursor); err != nil {
		t.Fatal(err)
	}
}

// EIO is not the only errno with which the kernel declares the filesystem
// gone: XFS surfaces detected corruption as EUCLEAN (EFSCORRUPTED), an
// already-failed filesystem answers ESHUTDOWN, and terminal state loss is
// ENOTRECOVERABLE. Every one of them must classify as a storage failure and
// stay uncertain — a volume that kept serving mutations after corruption was
// detected would be trusting durable state the kernel just disavowed.
func TestCorruptionAndShutdownErrnosFenceLikeEIO(t *testing.T) {
	h := &VolumeHandler{}
	for _, errno := range []syscall.Errno{syscall.EUCLEAN, syscall.ESHUTDOWN, syscall.ENOTRECOVERABLE} {
		if !fatalStorageErrno(errno) {
			t.Fatalf("%v is not treated as fatal storage state", errno)
		}
		response := h.errorResponse(1, errno, false)
		if response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_STORAGE {
			t.Fatalf("%v = %+v, want FAILURE_CLASS_STORAGE", errno, response)
		}
		if !response.GetUncertain() {
			t.Fatalf("%v must stay uncertain: the operation may have partially reached the device", errno)
		}
	}
	if fatalStorageErrno(syscall.ENOSPC) {
		t.Fatal("ENOSPC is an ordinary, retryable outcome and must not fence the volume")
	}
}

// Defect 6: a real storage EIO and an internal error the authority failed to
// recognise produced identical wire responses, so the client could not tell
// "your filesystem is gone" from "I did not recognise this error".
func TestEIOCarriesItsFailureClass(t *testing.T) {
	h := &VolumeHandler{}
	storage := h.errorResponse(1, syscall.EIO, false)
	if storage.GetErrno() != errnos.EIO || storage.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_STORAGE {
		t.Fatalf("storage EIO = %+v, want FAILURE_CLASS_STORAGE", storage)
	}
	if !storage.GetUncertain() {
		t.Fatal("a storage EIO must stay uncertain")
	}
	internal := h.errorResponse(2, errInternal, false)
	if internal.GetErrno() != errnos.EIO || internal.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_INTERNAL {
		t.Fatalf("internal error = %+v, want FAILURE_CLASS_INTERNAL", internal)
	}
	if internal.GetUncertain() {
		t.Fatal("an unrecognised internal error is not evidence that XFS changed")
	}
	unclassified := h.errorResponse(3, errors.New("something the mapping table does not cover"), false)
	if unclassified.GetErrno() != errnos.EIO || unclassified.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_INTERNAL {
		t.Fatalf("unclassified error = %+v, want FAILURE_CLASS_INTERNAL", unclassified)
	}
	fenced := h.errorResponse(4, xfsstore.ErrFenced, false)
	if fenced.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_STORAGE {
		t.Fatalf("fenced store = %+v, want FAILURE_CLASS_STORAGE", fenced)
	}
	if ok := h.errorResponse(5, syscall.ENOENT, false); ok.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_UNSPECIFIED {
		t.Fatalf("a non-EIO errno must not claim a failure class: %+v", ok)
	}
}

// Defect 2: a partially successful write reported the byte count and a nonzero
// errno at once. The application saw a failed write(2) while the file had
// already grown. Linux returns the short count.
func TestPartialWriteReportsTheShortCountAlone(t *testing.T) {
	h := testVolumeHandler()
	partial := h.writeOutcome(4096, 0, syscall.ENOSPC)
	if partial.GetErrno() != 0 {
		t.Fatalf("partial write errno = %d, want 0: %d bytes are already durable in XFS", partial.GetErrno(), partial.GetWrite().GetCount())
	}
	if partial.GetWrite().GetCount() != 4096 {
		t.Fatalf("partial write count = %d, want 4096", partial.GetWrite().GetCount())
	}
	if partial.GetUncertain() {
		t.Fatal("a short write on a live store is an exact outcome")
	}

	quota := h.writeOutcome(10, 64, syscall.EDQUOT)
	if quota.GetErrno() != 0 || quota.GetWrite().GetCount() != 10 || quota.GetWrite().GetAssignedOffset() != 64 {
		t.Fatalf("short append = %+v, want an exact short count at the assigned offset", quota)
	}

	// Only a write that made no progress reports the condition.
	none := h.writeOutcome(0, 0, syscall.ENOSPC)
	if none.GetErrno() != int32(syscall.ENOSPC) || none.GetWrite().GetCount() != 0 {
		t.Fatalf("failed write = %+v, want ENOSPC with no count", none)
	}

	// A short write whose error means the store itself is gone keeps the exact
	// count and stays explicitly uncertain, because the mount cannot continue.
	dead := h.writeOutcome(8, 0, syscall.EIO)
	if dead.GetErrno() != 0 || dead.GetWrite().GetCount() != 8 || !dead.GetUncertain() ||
		dead.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_STORAGE {
		t.Fatalf("short write on a dying store = %+v", dead)
	}

	empty := h.writeOutcome(0, 0, nil)
	if empty.GetErrno() != 0 || empty.GetWrite() == nil {
		t.Fatalf("zero-length write = %+v, want a successful no-op", empty)
	}
}

// Defect 4b: read and write payload sizes were used as a proxy for maximum
// response size, so a directory listing was covered by neither bound. The
// listing is now built to a budget derived from the frame, and every reply the
// handler can retain fits in the frame once the envelope is restored.
func TestDirectoryReplyBudgetAlwaysFitsTheFrame(t *testing.T) {
	for _, maxFrame := range []uint32{MinimumFrameBytes, 64 << 10, 1 << 20, 16 << 20} {
		h := testVolumeHandler()
		h.MaxFrame = maxFrame
		h.MaxRead, h.MaxWrite = 1024, 1024
		h.MaxRetainedReplyBytes = uint64(maxFrame) * 4
		if !h.validBounds() {
			t.Fatalf("frame %d rejected by its own bounds check", maxFrame)
		}
		for _, entries := range []uint32{1, 128, 4096} {
			budget := h.readDirEntryBudget(entries)
			if budget == 0 || budget > h.maxReplyBytes() {
				t.Fatalf("frame %d entries %d: budget %d out of range", maxFrame, entries, budget)
			}
			if budget < maxDirentBytes {
				t.Fatalf("frame %d entries %d: budget %d cannot hold one directory entry", maxFrame, entries, budget)
			}
			reply := &authoritypb.ReadDirReply{Verifier: make([]byte, 16)}
			used := uint64(0)
			for i := 0; ; i++ {
				attr := xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: ^uint64(0), Size: 1 << 40}
				var identity [16]byte
				for j := range identity {
					identity[j] = 0xff
				}
				dirent := &authoritypb.Dirent{
					Name:       bytes.Repeat([]byte{'n'}, 255),
					Attr:       attrProto(attr),
					NextCookie: encodeCookie(uint64(i)),
					Item:       itemProto(xfsstore.Capability(identity), attr, identity),
				}
				cost := direntCost(dirent)
				if used+cost > uint64(budget) {
					break
				}
				used += cost
				reply.Entries = append(reply.Entries, dirent)
			}
			if len(reply.Entries) == 0 {
				t.Fatalf("frame %d entries %d: no entry fits the budget", maxFrame, entries)
			}
			response := &authoritypb.Response{Body: &authoritypb.Response_ReadDir{ReadDir: reply}}
			encoded, err := marshalOutcome(response)
			if err != nil {
				t.Fatal(err)
			}
			if uint32(len(encoded)) > h.replyReserve(entries) {
				t.Fatalf("frame %d entries %d: retained reply %d exceeds its reservation %d", maxFrame, entries, len(encoded), h.replyReserve(entries))
			}
			response.RequestId, response.Epoch = ^uint64(0), bytes.Repeat([]byte{0xFF}, 16)
			response.Mutation = &authoritypb.MutationState{Slot: ^uint32(0), AcceptedSequence: ^uint64(0)}
			var frame bytes.Buffer
			if err := writeFrame(&frame, maxFrame, response); err != nil {
				t.Fatalf("frame %d entries %d: a budgeted listing did not fit the wire frame: %v", maxFrame, entries, err)
			}
		}
	}
}

// Defect 3: the replay cache was bounded in entries, not bytes. The admission
// decision is now taken against the retained bytes themselves.
func TestReplyCacheIsBoundedInBytes(t *testing.T) {
	h := testVolumeHandler()
	h.MaxRetainedReplyBytes = 3 * uint64(fixedMutationReplyBytes)
	session := volumeserver.SessionID{1}
	if err := h.startSessionResources(session, xfsstore.Capability{0xFF}, 4, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	for slot := uint32(0); slot < 3; slot++ {
		reserved, err := h.reserveReplyBytes(session, slot, fixedMutationReplyBytes)
		if err != nil {
			t.Fatalf("slot %d reservation refused: %v", slot, err)
		}
		h.settleReplyBytes(session, slot, fixedMutationReplyBytes, reserved)
	}
	if h.retainedReplyBytes != 3*uint64(fixedMutationReplyBytes) {
		t.Fatalf("retained = %d, want %d", h.retainedReplyBytes, 3*uint64(fixedMutationReplyBytes))
	}
	// A fourth slot would grow the total past the byte budget.
	if _, err := h.reserveReplyBytes(session, 3, fixedMutationReplyBytes); !errors.Is(err, volumeserver.ErrAdmission) {
		t.Fatalf("over-budget reservation = %v, want ErrAdmission (a retryable refusal, not an OOM)", err)
	}
	// Reusing a slot replaces its retained bytes rather than adding to them, so
	// a worker sitting exactly at the budget still makes progress.
	reserved, err := h.reserveReplyBytes(session, 0, fixedMutationReplyBytes)
	if err != nil {
		t.Fatalf("reusing a slot at the budget was refused: %v", err)
	}
	if reserved != 0 {
		t.Fatalf("reusing a slot reserved %d extra bytes, want 0", reserved)
	}
	h.settleReplyBytes(session, 0, 64, reserved)
	if want := 2*uint64(fixedMutationReplyBytes) + 64; h.retainedReplyBytes != want {
		t.Fatalf("retained after slot reuse = %d, want %d", h.retainedReplyBytes, want)
	}
	// The bytes that slot gave back are available to a new one.
	if _, err := h.reserveReplyBytes(session, 3, 64); err != nil {
		t.Fatalf("bytes released by a smaller outcome were not returned: %v", err)
	}
	h.releaseReplyReservation(64)
	h.closeSessionResources(session)
	if h.retainedReplyBytes != 0 || h.reservedReplyBytes != 0 {
		t.Fatalf("session cleanup left %d retained / %d reserved bytes", h.retainedReplyBytes, h.reservedReplyBytes)
	}
}

func TestReplyReservationIsReleasedWhenNothingIsRetained(t *testing.T) {
	h := testVolumeHandler()
	h.MaxRetainedReplyBytes = uint64(fixedMutationReplyBytes)
	session := volumeserver.SessionID{4}
	if err := h.startSessionResources(session, xfsstore.Capability{0xF3}, 2, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	reserved, err := h.reserveReplyBytes(session, 0, fixedMutationReplyBytes)
	if err != nil {
		t.Fatal(err)
	}
	h.releaseReplyReservation(reserved)
	if h.reservedReplyBytes != 0 {
		t.Fatalf("reserved = %d after release", h.reservedReplyBytes)
	}
	if _, err := h.reserveReplyBytes(session, 1, fixedMutationReplyBytes); err != nil {
		t.Fatalf("budget was not returned: %v", err)
	}
}

func TestSessionResourceAdmissionAndTerminalState(t *testing.T) {
	h := &VolumeHandler{MaxItemsPerSession: 1, MaxOpensPerSession: 1, MaxItems: 1, MaxOpens: 1, MaxFrame: 1 << 20, MaxRetainedReplyBytes: 1 << 20}
	first := volumeserver.SessionID{1}
	second := volumeserver.SessionID{2}
	if err := h.startSessionResources(first, xfsstore.Capability{0xF1}, 2, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	if err := h.startSessionResources(second, xfsstore.Capability{0xF1}, 2, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	if err := h.trackItem(first, xfsstore.Capability{1}, false); err != nil {
		t.Fatal(err)
	}
	if err := h.trackItem(second, xfsstore.Capability{2}, false); !errors.Is(err, volumeserver.ErrAdmission) {
		t.Fatalf("global item admission = %v, want ErrAdmission", err)
	}
	h.closeSessionResources(first)
	if err := h.trackItem(first, xfsstore.Capability{3}, false); !errors.Is(err, volumeserver.ErrSessionExpired) {
		t.Fatalf("track after session end = %v, want ErrSessionExpired", err)
	}
	if err := h.trackItem(second, xfsstore.Capability{4}, false); err != nil {
		t.Fatalf("admission was not released by cleanup: %v", err)
	}
}

func TestCapabilityReservationIsPreApplyAndSymmetric(t *testing.T) {
	h := &VolumeHandler{
		MaxItemsPerSession: 1, MaxOpensPerSession: 1,
		MaxItems: 1, MaxOpens: 1,
		MaxFrame: 1 << 20, MaxRetainedReplyBytes: 1 << 20,
	}
	first := volumeserver.SessionID{0x31}
	second := volumeserver.SessionID{0x32}
	for _, id := range []volumeserver.SessionID{first, second} {
		if err := h.startSessionResources(id, xfsstore.Capability{0xF1}, 2, [32]byte{}); err != nil {
			t.Fatal(err)
		}
	}

	reservation, err := h.reserveCapabilities(first, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if h.totalItems != 1 || h.totalOpens != 1 {
		t.Fatalf("reservation charged %d items / %d opens, want 1 / 1", h.totalItems, h.totalOpens)
	}
	if _, err := h.reserveCapabilities(second, 1, 0); !errors.Is(err, volumeserver.ErrAdmission) {
		t.Fatalf("item admitted past outstanding reservation: %v", err)
	}
	if _, err := h.reserveCapabilities(second, 0, 1); !errors.Is(err, volumeserver.ErrAdmission) {
		t.Fatalf("open admitted past outstanding reservation: %v", err)
	}

	item := xfsstore.Capability{0x41}
	open := xfsstore.Capability{0x42}
	if err := reservation.commit(
		[]trackedCapability{{value: item}},
		[]trackedCapability{{value: open}},
	); err != nil {
		t.Fatal(err)
	}
	reservation.release() // A committed reservation is an idempotent no-op.
	resources := h.resources[first]
	if !resources.items[item] || !resources.opens[open] {
		// The bool is the protected bit, so explicitly inspect membership below
		// when the unprotected value is false.
		_, hasItem := resources.items[item]
		_, hasOpen := resources.opens[open]
		if !hasItem || !hasOpen {
			t.Fatalf("committed capabilities missing: item=%v open=%v", hasItem, hasOpen)
		}
	}
	if resources.reservedItems != 0 || resources.reservedOpens != 0 || h.totalItems != 1 || h.totalOpens != 1 {
		t.Fatalf("commit accounting = reserved %d/%d total %d/%d", resources.reservedItems, resources.reservedOpens, h.totalItems, h.totalOpens)
	}

	h.closeSessionResources(first)
	if h.totalItems != 0 || h.totalOpens != 0 {
		t.Fatalf("cleanup left %d items / %d opens", h.totalItems, h.totalOpens)
	}
	if admitted, err := h.reserveCapabilities(second, 1, 1); err != nil {
		t.Fatalf("cleanup did not release reserved capacity: %v", err)
	} else {
		admitted.release()
	}
}

func TestCapabilityReservationReleaseReturnsCapacity(t *testing.T) {
	h := &VolumeHandler{
		MaxItemsPerSession: 1, MaxOpensPerSession: 1,
		MaxItems: 1, MaxOpens: 1,
		MaxFrame: 1 << 20, MaxRetainedReplyBytes: 1 << 20,
	}
	session := volumeserver.SessionID{0x33}
	if err := h.startSessionResources(session, xfsstore.Capability{0xF2}, 2, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	reservation, err := h.reserveCapabilities(session, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	reservation.release()
	reservation.release()
	resources := h.resources[session]
	if resources.reservedItems != 0 || resources.reservedOpens != 0 || h.totalItems != 0 || h.totalOpens != 0 {
		t.Fatalf("release accounting = reserved %d/%d total %d/%d", resources.reservedItems, resources.reservedOpens, h.totalItems, h.totalOpens)
	}
	if admitted, err := h.reserveCapabilities(session, 1, 1); err != nil {
		t.Fatalf("released capacity was not reusable: %v", err)
	} else {
		admitted.release()
	}
}

func TestCapabilityReservationReleaseAfterSessionCleanupDoesNotUnderflow(t *testing.T) {
	h := &VolumeHandler{
		MaxItemsPerSession: 1, MaxOpensPerSession: 1,
		MaxItems: 1, MaxOpens: 1,
		MaxFrame: 1 << 20, MaxRetainedReplyBytes: 1 << 20,
	}
	session := volumeserver.SessionID{0x34}
	if err := h.startSessionResources(session, xfsstore.Capability{0xF3}, 2, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	reservation, err := h.reserveCapabilities(session, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	h.closeSessionResources(session)
	reservation.release()
	if h.totalItems != 0 || h.totalOpens != 0 {
		t.Fatalf("post-cleanup release underflowed totals to %d items / %d opens", h.totalItems, h.totalOpens)
	}
}

type resourceAdmissionFaultStore struct {
	volumeStore
	failure    error
	create     atomic.Uint32
	mkdir      atomic.Uint32
	symlink    atomic.Uint32
	open       atomic.Uint32
	lookup     atomic.Uint32
	forget     atomic.Uint32
	lookupItem xfsstore.Capability
}

func (s *resourceAdmissionFaultStore) Fence(error) {}
func (s *resourceAdmissionFaultStore) Identity(item xfsstore.Capability) ([16]byte, error) {
	return [16]byte{item[0]}, nil
}
func (s *resourceAdmissionFaultStore) Getattr(xfsstore.Capability) (xfsstore.Attr, error) {
	return xfsstore.Attr{Kind: xfsstore.KindDirectory, Ino: 1}, nil
}
func (s *resourceAdmissionFaultStore) Lookup(xfsstore.Capability, string) (xfsstore.Capability, xfsstore.Attr, error) {
	s.lookup.Add(1)
	if s.lookupItem != (xfsstore.Capability{}) {
		return s.lookupItem, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 2, Mode: 0o600, Nlink: 1}, nil
	}
	return xfsstore.Capability{}, xfsstore.Attr{}, syscall.ENOENT
}
func (s *resourceAdmissionFaultStore) Forget(xfsstore.Capability) error {
	s.forget.Add(1)
	return nil
}
func (s *resourceAdmissionFaultStore) Create(xfsstore.Capability, string, os.FileMode, bool) (xfsstore.Capability, xfsstore.Attr, error) {
	s.create.Add(1)
	return xfsstore.Capability{}, xfsstore.Attr{}, s.failure
}
func (s *resourceAdmissionFaultStore) Mkdir(xfsstore.Capability, string, os.FileMode) (xfsstore.Capability, xfsstore.Attr, error) {
	s.mkdir.Add(1)
	return xfsstore.Capability{}, xfsstore.Attr{}, s.failure
}
func (s *resourceAdmissionFaultStore) Symlink(xfsstore.Capability, string, string) (xfsstore.Capability, xfsstore.Attr, error) {
	s.symlink.Add(1)
	return xfsstore.Capability{}, xfsstore.Attr{}, s.failure
}
func (s *resourceAdmissionFaultStore) OpenFile(xfsstore.Capability, xfsstore.OpenFlags) (xfsstore.Capability, error) {
	s.open.Add(1)
	return xfsstore.Capability{}, s.failure
}

func (s *resourceAdmissionFaultStore) calls(operation string) uint32 {
	switch operation {
	case "create":
		return s.create.Load()
	case "mkdir":
		return s.mkdir.Load()
	case "symlink":
		return s.symlink.Load()
	case "open":
		return s.open.Load()
	default:
		return 0
	}
}

func resourceAdmissionRequestHarness(
	t *testing.T,
	store volumeStore,
	maxItems, maxOpens uint32,
) (*VolumeHandler, context.Context, volumeserver.SessionCredential, xfsstore.Capability) {
	t.Helper()
	runtime, err := volumeserver.New("resource-admission", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 2, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := volumeserver.PeerIdentity{0x71}
	cred, err := runtime.Attach(2, peer, volumeserver.Authorization{
		Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: noopMembership{}, Fencer: noopFencer{},
		MaxCachedNameCapacity: 16, MaxRepairBudget: time.Minute, MaxClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	routes := &RoutesController{Visibility: visibility, loaded: true}
	h := &VolumeHandler{
		Store: store, Runtime: runtime, Authorizer: allowAuthorizer{volumeserver.AccessRead | volumeserver.AccessWrite}, Routes: routes,
		MaxFrame: 1 << 20, MaxRead: 1 << 16, MaxWrite: 1 << 16, MaxInFlight: 8,
		MaxItemsPerSession: maxItems, MaxOpensPerSession: maxOpens,
		MaxItems: maxItems, MaxOpens: maxOpens, MaxRetainedReplyBytes: 1 << 20,
	}
	root := xfsstore.Capability{0x72}
	if err := h.startSessionResources(cred.ID, root, 2, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.FenceSession(cred.ID) })
	ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte(peer))
	return h, ctx, cred, root
}

func resourceAcquisitionRequest(
	t *testing.T,
	operation string,
	cred volumeserver.SessionCredential,
	root xfsstore.Capability,
) *authoritypb.Request {
	t.Helper()
	request := &authoritypb.Request{
		RequestId: 1, Epoch: cred.Epoch[:],
		Session: &authoritypb.SessionProof{Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:]},
	}
	switch operation {
	case "create":
		request.Body = &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
			Parent: root[:], Name: []byte("capacity-create"), Mode: 0o600,
			Flags: &authoritypb.OpenFlags{Read: true, Write: true}, Exclusive: true,
		}}
	case "mkdir":
		request.Body = &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{
			Parent: root[:], Name: []byte("capacity-mkdir"), Mode: 0o700,
		}}
	case "symlink":
		request.Body = &authoritypb.Request_Symlink{Symlink: &authoritypb.SymlinkRequest{
			Parent: root[:], Name: []byte("capacity-symlink"), Target: []byte("target"),
		}}
	case "open":
		request.Body = &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{
			Item: root[:], Flags: &authoritypb.OpenFlags{Read: true},
		}}
	default:
		t.Fatalf("unknown operation %q", operation)
	}
	stampMutation(t, request, 0, 1)
	return request
}

func TestResourceCapacityRefusalPrecedesEveryStoreAllocation(t *testing.T) {
	for _, operation := range []string{"create", "mkdir", "symlink", "open"} {
		t.Run(operation, func(t *testing.T) {
			store := &resourceAdmissionFaultStore{failure: syscall.EACCES}
			h, ctx, cred, root := resourceAdmissionRequestHarness(t, store, 0, 0)
			response := h.Handle(ctx, resourceAcquisitionRequest(t, operation, cred, root))
			if response.GetErrno() != errnos.EAGAIN || response.GetUncertain() {
				t.Fatalf("capacity response=%+v, want definite EAGAIN", response)
			}
			if calls := store.calls(operation); calls != 0 {
				t.Fatalf("store %s calls=%d before capacity refusal", operation, calls)
			}
			if h.totalItems != 0 || h.totalOpens != 0 {
				t.Fatalf("capacity refusal left totals %d/%d", h.totalItems, h.totalOpens)
			}
		})
	}
}

func TestResourceStoreFailureReleasesExactReservation(t *testing.T) {
	for _, operation := range []string{"create", "mkdir", "symlink", "open"} {
		t.Run(operation, func(t *testing.T) {
			store := &resourceAdmissionFaultStore{failure: syscall.EACCES}
			h, ctx, cred, root := resourceAdmissionRequestHarness(t, store, 1, 1)
			response := h.Handle(ctx, resourceAcquisitionRequest(t, operation, cred, root))
			if response.GetErrno() != int32(syscall.EACCES) || response.GetUncertain() {
				t.Fatalf("store failure response=%+v, want definite EACCES", response)
			}
			if calls := store.calls(operation); calls != 1 {
				t.Fatalf("store %s calls=%d, want one", operation, calls)
			}
			resources := h.resources[cred.ID]
			if resources.reservedItems != 0 || resources.reservedOpens != 0 || h.totalItems != 0 || h.totalOpens != 0 {
				t.Fatalf("store failure left reserved %d/%d totals %d/%d", resources.reservedItems, resources.reservedOpens, h.totalItems, h.totalOpens)
			}
			items, opens := uint32(1), uint32(0)
			if operation == "open" {
				items, opens = 0, 1
			} else if operation == "create" {
				opens = 1
			}
			reservation, err := h.reserveCapabilities(cred.ID, items, opens)
			if err != nil {
				t.Fatalf("released capacity was not reusable: %v", err)
			}
			reservation.release()
		})
	}
}

func TestLookupCapabilityTransferUsesExactReplay(t *testing.T) {
	item := xfsstore.Capability{0x7a}
	store := &resourceAdmissionFaultStore{lookupItem: item}
	h, ctx, cred, root := resourceAdmissionRequestHarness(t, store, 1, 1)
	request := &authoritypb.Request{
		RequestId: 11, Epoch: cred.Epoch[:],
		Session: &authoritypb.SessionProof{Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:]},
		Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{
			Parent: root[:], Name: []byte("exact-lookup"),
		}},
	}
	stampMutation(t, request, 0, 1)
	first := h.Handle(ctx, request)
	if first.GetErrno() != 0 || first.GetLookup().GetItem() == nil ||
		!bytes.Equal(first.GetLookup().GetItem().GetToken(), item[:]) {
		t.Fatalf("first lookup=%+v", first)
	}
	request.RequestId = 12
	replayed := h.Handle(ctx, request)
	if replayed.GetErrno() != 0 || replayed.GetMutation().GetAcceptedSequence() != 1 ||
		!bytes.Equal(replayed.GetLookup().GetItem().GetToken(), item[:]) {
		t.Fatalf("replayed lookup=%+v", replayed)
	}
	if calls := store.lookup.Load(); calls != 1 {
		t.Fatalf("lookup store calls=%d, want one exact acquisition", calls)
	}
	resources := h.resources[cred.ID]
	if len(resources.items) != 1 || h.totalItems != 1 {
		t.Fatalf("lookup tracked items=%d total=%d, want one", len(resources.items), h.totalItems)
	}
}

// Defect 11: tracking a capability twice incremented the worker-wide counter
// twice while the set grew once, so cleanup subtracted less than was added and
// the drift was absorbed by clamped subtractions instead of being impossible.
func TestCapabilityAccountingIsSymmetric(t *testing.T) {
	h := testVolumeHandler()
	session := volumeserver.SessionID{3}
	if err := h.startSessionResources(session, xfsstore.Capability{0xF2}, 2, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	item, handle := xfsstore.Capability{7}, xfsstore.Capability{8}
	for range 4 {
		if err := h.trackItem(session, item, false); err != nil {
			t.Fatal(err)
		}
		if err := h.trackOpen(session, handle, false); err != nil {
			t.Fatal(err)
		}
	}
	if h.totalItems != 1 || h.totalOpens != 1 {
		t.Fatalf("repeated tracking counted %d items / %d opens for one of each", h.totalItems, h.totalOpens)
	}
	// Untracking a capability this session does not hold must not move anything.
	h.untrackItem(session, xfsstore.Capability{99})
	h.untrackOpen(session, xfsstore.Capability{99})
	if h.totalItems != 1 || h.totalOpens != 1 {
		t.Fatalf("a foreign capability changed the accounting: %d items / %d opens", h.totalItems, h.totalOpens)
	}
	h.closeSessionResources(session)
	if h.totalItems != 0 || h.totalOpens != 0 {
		t.Fatalf("cleanup left %d items / %d opens", h.totalItems, h.totalOpens)
	}
}

// Defect 11: item and handle capabilities were volume-epoch bearer tokens, so a
// session that learned another session's handle could close or reclaim it.
func TestCapabilitiesResolveOnlyInsideTheirSession(t *testing.T) {
	h := testVolumeHandler()
	root := xfsstore.Capability{0xAA}
	owner, other := volumeserver.SessionID{1}, volumeserver.SessionID{2}
	for _, id := range []volumeserver.SessionID{owner, other} {
		if err := h.startSessionResources(id, root, 2, [32]byte{}); err != nil {
			t.Fatal(err)
		}
	}
	item, handle := xfsstore.Capability{5}, xfsstore.Capability{6}
	if err := h.trackItem(owner, item, false); err != nil {
		t.Fatal(err)
	}
	if err := h.trackOpen(owner, handle, false); err != nil {
		t.Fatal(err)
	}
	if got, err := h.item(owner, item[:]); err != nil || got != item {
		t.Fatalf("owner item = %v, %v", got, err)
	}
	if got, err := h.open(owner, handle[:]); err != nil || got != handle {
		t.Fatalf("owner handle = %v, %v", got, err)
	}
	if _, err := h.item(other, item[:]); !errors.Is(err, xfsstore.ErrStaleObject) {
		t.Fatalf("foreign item = %v, want a stale-object refusal", err)
	}
	if _, err := h.open(other, handle[:]); !errors.Is(err, xfsstore.ErrStaleOpen) {
		t.Fatalf("foreign handle = %v, want a stale-open refusal", err)
	}
	// The shared volume root is reachable from every session by construction.
	if got, err := h.item(other, root[:]); err != nil || got != root {
		t.Fatalf("root from another session = %v, %v", got, err)
	}
	if _, err := h.item(volumeserver.SessionID{9}, root[:]); !errors.Is(err, volumeserver.ErrSessionExpired) {
		t.Fatalf("unknown session = %v", err)
	}
	if _, err := h.item(owner, item[:3]); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("malformed capability = %v", err)
	}
}

func TestHeldDirectoriesRejectsUnresolvedRenameParent(t *testing.T) {
	h := testVolumeHandler()
	session := volumeserver.SessionID{1}
	root := xfsstore.Capability{0xAA}
	if err := h.startSessionResources(session, root, 2, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	untracked := xfsstore.Capability{0xBB}

	for _, test := range []struct {
		name string
		old  []byte
		want error
	}{
		{name: "malformed", old: []byte{1}, want: syscall.EINVAL},
		{name: "untracked", old: untracked[:], want: xfsstore.ErrStaleObject},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{
				OldParent: test.old,
				NewParent: root[:],
			}}}
			if _, err := h.heldDirectories(session, request); !errors.Is(err, test.want) {
				t.Fatalf("heldDirectories = %v, want %v", err, test.want)
			}
		})
	}
}

// Defect 11: a cancellation acknowledgment went through the lease-renewing
// path, so a peer could keep a session alive indefinitely using only cancels.
func TestCancelAcknowledgmentDoesNotRenewTheLease(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	runtime, err := volumeserver.New("cancel-volume", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 4, MaxSessions: 2, MaxLockRecords: 8,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	h := testVolumeHandler()
	h.Runtime = runtime
	cred, err := runtime.Attach(2, volumeserver.PeerIdentity{1}, volumeserver.Authorization{Access: volumeserver.AccessRead, Deadline: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte{1})
	cancel := &authoritypb.Request{
		RequestId: 3, Epoch: cred.Epoch[:],
		Session: &authoritypb.SessionProof{Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:]},
		Body:    &authoritypb.Request_Cancel{Cancel: &authoritypb.CancelRequest{TargetRequestId: 2}},
	}
	for range 6 {
		now = now.Add(30 * time.Second)
		if response := h.cancelAcknowledgment(ctx, cancel); response.GetErrno() != 0 {
			t.Fatalf("cancel acknowledgment = errno %d", response.GetErrno())
		}
	}
	if _, err := runtime.Begin(cred); !errors.Is(err, volumeserver.ErrSessionExpired) && !errors.Is(err, volumeserver.ErrSessionFenced) {
		t.Fatalf("session survived three minutes of cancels alone with a one-minute lease: %v", err)
	}

	// A cancel for a different epoch is still refused.
	stale := proto.Clone(cancel).(*authoritypb.Request)
	stale.Epoch = bytes.Repeat([]byte{0x5A}, 16)
	if response := h.cancelAcknowledgment(ctx, stale); response.GetErrno() != errnos.ESTALE {
		t.Fatalf("cancel in a foreign epoch = errno %d, want ESTALE", response.GetErrno())
	}
}

type allowAuthorizer struct{ access volumeserver.Access }

func (a allowAuthorizer) Authorize(context.Context, string, []byte) (volumeserver.Authorization, error) {
	return volumeserver.Authorization{Access: a.access, Deadline: time.Now().Add(time.Hour)}, nil
}

type reauthorizationTestAuthorizer struct {
	session  volumeserver.SessionID
	sequence uint64
	deadline time.Time
	proof    [32]byte
}

func (authorizer reauthorizationTestAuthorizer) Authorize(context.Context, string, []byte) (volumeserver.Authorization, error) {
	return volumeserver.Authorization{}, errors.New("unexpected initial authorization")
}

func (authorizer reauthorizationTestAuthorizer) Reauthorize(_ context.Context, _ string, session volumeserver.SessionID, sequence uint64, token []byte) (volumeserver.Authorization, [32]byte, error) {
	if session != authorizer.session || sequence != authorizer.sequence || string(token) != "renewed" {
		return volumeserver.Authorization{}, [32]byte{}, errors.New("wrong reauthorization binding")
	}
	return volumeserver.Authorization{Access: volumeserver.AccessRead, Deadline: authorizer.deadline}, authorizer.proof, nil
}

func TestVolumeHandlerReauthorizesExactLiveSessionBeforeOrdinaryPeerAdmission(t *testing.T) {
	handler, ctx, credential, _ := resourceAdmissionRequestHarness(t, &resourceAdmissionFaultStore{}, 8, 8)
	deadline := time.Now().Add(2 * time.Hour).Round(0)
	proof := [32]byte{0x99}
	handler.Authorizer = reauthorizationTestAuthorizer{session: credential.ID, sequence: 1, deadline: deadline, proof: proof}
	request := &authoritypb.Request{
		RequestId: 7, Epoch: credential.Epoch[:],
		Session: &authoritypb.SessionProof{Id: credential.ID[:], Generation: credential.Generation, ResumeSecret: credential.Secret[:]},
		Body:    &authoritypb.Request_Reauthorize{Reauthorize: &authoritypb.ReauthorizeRequest{AccessToken: []byte("renewed"), Sequence: 1}},
	}
	response := handler.Handle(ctx, request)
	if response.GetErrno() != 0 || response.GetReauthorize() == nil || response.GetReauthorize().GetSequence() != 1 ||
		response.GetReauthorize().GetAuthorizationDeadlineUnixNanos() != deadline.UnixNano() {
		t.Fatalf("reauthorization response = %+v", response)
	}
	access, err := handler.Runtime.Access(credential)
	if err != nil || access != volumeserver.AccessRead {
		t.Fatalf("reauthorized access = %v, %v", access, err)
	}
}

func TestVolumeHandlerEndToEndOnXFS(t *testing.T) {
	root := os.Getenv("PORTABLEFS_XFS_TEST_ROOT")
	projectRaw := os.Getenv("PORTABLEFS_XFS_TEST_PROJECT")
	// PORTABLEFS_XFS_TEST_REQUIRED is set by the privileged CI job. It turns an
	// unconfigured gate, or a root-owned test process, into a hard failure so a
	// provisioning regression can never present as a green run with a silent
	// skip, which is how this test previously never ran at all.
	required := os.Getenv("PORTABLEFS_XFS_TEST_REQUIRED") == "1"
	if root == "" || projectRaw == "" {
		if required {
			t.Fatalf("PORTABLEFS_XFS_TEST_REQUIRED=1 but PORTABLEFS_XFS_TEST_ROOT=%q PORTABLEFS_XFS_TEST_PROJECT=%q", root, projectRaw)
		}
		t.Skip("privileged XFS gate is not configured")
	}
	if required && os.Geteuid() == 0 {
		t.Fatal("PORTABLEFS_XFS_TEST_REQUIRED=1 requires the unprivileged volume identity, not root")
	}
	resetXFSRouteDeclaration(t, root)
	project, err := strconv.ParseUint(projectRaw, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	store, err := xfsstore.Open(root, xfsstore.Config{ExpectedProjectID: uint32(project), ExpectedOwnerUID: uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid())})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runtime, err := volumeserver.New("volume-e2e", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 4, MaxSessions: 8, MaxLockRecords: 64})
	if err != nil {
		t.Fatal(err)
	}
	h := &VolumeHandler{
		Store: store, Runtime: runtime, Authorizer: allowAuthorizer{volumeserver.AccessRead | volumeserver.AccessWrite},
		Routes:   testRoutesController(t, store),
		MaxFrame: 1 << 20, MaxRead: 1 << 16, MaxWrite: 1 << 16, MaxInFlight: 8,
		MaxItemsPerSession: 1024, MaxOpensPerSession: 1024, MaxItems: 8192, MaxOpens: 8192,
		MaxRetainedReplyBytes: 8 << 20,
	}
	ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte{7})

	attach := h.Handle(ctx, &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Attach{Attach: &authoritypb.AttachRequest{VolumeId: "volume-e2e", AccessToken: []byte("test-only"), ReplaySlots: 2, RoutesRevision: emptyRoutesRevision()}}})
	if attach.GetErrno() != 0 || attach.GetAttach() == nil {
		t.Fatalf("attach = %v", attach)
	}
	proof := &authoritypb.SessionProof{Id: attach.GetAttach().GetSessionId(), Generation: attach.GetAttach().GetSessionGeneration(), ResumeSecret: attach.GetAttach().GetResumeSecret()}
	var sessionID volumeserver.SessionID
	copy(sessionID[:], proof.GetId())

	mkdir := func(requestID, sequence uint64, name string) *authoritypb.Item {
		t.Helper()
		request := &authoritypb.Request{RequestId: requestID, Epoch: attach.GetEpoch(), Session: proof, Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{
			Parent: attach.GetAttach().GetRoot().GetToken(), Name: []byte(name), Mode: 0o700,
		}}}
		stampMutation(t, request, 1, sequence)
		response := h.Handle(ctx, request)
		if response.GetErrno() != 0 || response.GetLookup().GetItem() == nil {
			t.Fatalf("mkdir %q = %v", name, response)
		}
		t.Cleanup(func() {
			if err := os.Remove(filepath.Join(root, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("remove test directory %q: %v", name, err)
			}
		})
		return response.GetLookup().GetItem()
	}
	oldParent := mkdir(100, 1, "handler-e2e-old-parent")
	newParent := mkdir(101, 2, "handler-e2e-new-parent")
	var oldCapability, newCapability xfsstore.Capability
	copy(oldCapability[:], oldParent.GetToken())
	copy(newCapability[:], newParent.GetToken())
	oldIdentity, err := store.Identity(oldCapability)
	if err != nil {
		t.Fatal(err)
	}
	newIdentity, err := store.Identity(newCapability)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name      string
		oldParent []byte
		newParent []byte
		want      [][16]byte
	}{
		{name: "old parent overlap", oldParent: oldParent.GetToken(), newParent: newParent.GetToken(), want: [][16]byte{oldIdentity, newIdentity}},
		{name: "new parent overlap", oldParent: newParent.GetToken(), newParent: oldParent.GetToken(), want: [][16]byte{newIdentity, oldIdentity}},
		{name: "same parent", oldParent: oldParent.GetToken(), newParent: oldParent.GetToken(), want: [][16]byte{oldIdentity, oldIdentity}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{
				OldParent: test.oldParent,
				NewParent: test.newParent,
			}}}
			got, err := h.heldDirectories(sessionID, request)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(test.want) {
				t.Fatalf("held directories = %x, want %x", got, test.want)
			}
			for i := range test.want {
				if got[i] != test.want[i] {
					t.Fatalf("held directory %d = %x, want %x", i, got[i], test.want[i])
				}
			}
		})
	}

	unknown := xfsstore.Capability{0xFE}
	unresolvedRename := &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{
		OldParent: oldParent.GetToken(), NewParent: unknown[:],
	}}}
	if _, err := h.heldDirectories(sessionID, unresolvedRename); !errors.Is(err, xfsstore.ErrStaleObject) {
		t.Fatalf("unresolved new rename parent = %v, want stale-object refusal", err)
	}

	create := &authoritypb.Request{RequestId: 2, Epoch: attach.GetEpoch(), Session: proof, Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: attach.GetAttach().GetRoot().GetToken(), Name: []byte("handler-e2e"), Mode: 0o600, Exclusive: true, Flags: &authoritypb.OpenFlags{Read: true, Write: true}}}}
	stampMutation(t, create, 0, 1)
	created := h.Handle(ctx, create)
	if created.GetErrno() != 0 || created.GetCreate() == nil {
		t.Fatalf("create = %v", created)
	}
	if created.GetMutation().GetSlot() != 0 || created.GetMutation().GetAcceptedSequence() != 1 {
		t.Fatalf("create did not report the recorded slot state: %v", created.GetMutation())
	}
	create.RequestId = 3
	replayed := h.Handle(ctx, create)
	if replayed.GetErrno() != 0 || string(replayed.GetCreate().GetItem().GetToken()) != string(created.GetCreate().GetItem().GetToken()) {
		t.Fatalf("create replay = %v", replayed)
	}
	if replayed.GetMutation().GetAcceptedSequence() != 1 {
		t.Fatalf("a replay must report the same recorded slot state: %v", replayed.GetMutation())
	}
	write := &authoritypb.Request{RequestId: 4, Epoch: attach.GetEpoch(), Session: proof, Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{Handle: created.GetCreate().GetHandle(), Data: []byte("hello")}}}
	stampMutation(t, write, 0, 2)
	written := h.Handle(ctx, write)
	if written.GetErrno() != 0 || written.GetWrite().GetCount() != 5 {
		t.Fatalf("write = %v", written)
	}

	unlink := &authoritypb.Request{RequestId: 5, Epoch: attach.GetEpoch(), Session: proof, Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: attach.GetAttach().GetRoot().GetToken(), Name: []byte("handler-e2e")}}}
	stampMutation(t, unlink, 0, 3)
	if got := h.Handle(ctx, unlink); got.GetErrno() != 0 {
		t.Fatalf("unlink = %v", got)
	}

	read := h.Handle(ctx, &authoritypb.Request{RequestId: 6, Epoch: attach.GetEpoch(), Session: proof, Body: &authoritypb.Request_Read{Read: &authoritypb.ReadRequest{Handle: created.GetCreate().GetHandle(), Length: 5}}})
	if read.GetErrno() != 0 || string(read.GetRead().GetData()) != "hello" {
		t.Fatalf("read after unlink = %v", read)
	}
	fsync := h.Handle(ctx, &authoritypb.Request{RequestId: 7, Epoch: attach.GetEpoch(), Session: proof, Body: &authoritypb.Request_Fsync{Fsync: &authoritypb.FsyncRequest{Handle: created.GetCreate().GetHandle()}}})
	if fsync.GetErrno() != 0 {
		t.Fatalf("fsync = %v", fsync)
	}
}

// TestBlockedLockWaitDoesNotHoldTheTopologyGuard reproduces the volume-wide
// freeze this classification exists to prevent: one session parks in a
// blocking F_SETLKW-style wait, an administrator runs ApplyRoutes, and — with
// the wait misclassified as a topology request — the queued topology writer
// stalls every guarded request on the volume for as long as the wait lasts,
// while KeepAlive (exempt from the guard) keeps the waiting session alive
// indefinitely. The lock table never reaches XFS, so the wait must be admitted
// through the ordinary session-routes check instead of holding the guard.
func TestBlockedLockWaitDoesNotHoldTheTopologyGuard(t *testing.T) {
	root := os.Getenv("PORTABLEFS_XFS_TEST_ROOT")
	projectRaw := os.Getenv("PORTABLEFS_XFS_TEST_PROJECT")
	required := os.Getenv("PORTABLEFS_XFS_TEST_REQUIRED") == "1"
	if root == "" || projectRaw == "" {
		if required {
			t.Fatalf("PORTABLEFS_XFS_TEST_REQUIRED=1 but PORTABLEFS_XFS_TEST_ROOT=%q PORTABLEFS_XFS_TEST_PROJECT=%q", root, projectRaw)
		}
		t.Skip("privileged XFS gate is not configured")
	}
	resetXFSRouteDeclaration(t, root)
	project, err := strconv.ParseUint(projectRaw, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	store, err := xfsstore.Open(root, xfsstore.Config{ExpectedProjectID: uint32(project), ExpectedOwnerUID: uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid())})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runtime, err := volumeserver.New("volume-lockwait", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 4, MaxSessions: 8, MaxLockRecords: 64})
	if err != nil {
		t.Fatal(err)
	}
	h := &VolumeHandler{
		Store: store, Runtime: runtime, Authorizer: allowAuthorizer{volumeserver.AccessRead | volumeserver.AccessWrite},
		Routes:   testRoutesController(t, store),
		MaxFrame: 1 << 20, MaxRead: 1 << 16, MaxWrite: 1 << 16, MaxInFlight: 8,
		MaxItemsPerSession: 1024, MaxOpensPerSession: 1024, MaxItems: 8192, MaxOpens: 8192,
		MaxRetainedReplyBytes: 8 << 20,
	}
	ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte{9})

	attachSession := func(id uint64) (*authoritypb.AttachReply, []byte, *authoritypb.SessionProof) {
		t.Helper()
		attach := h.Handle(ctx, &authoritypb.Request{RequestId: id, Body: &authoritypb.Request_Attach{Attach: &authoritypb.AttachRequest{VolumeId: "volume-lockwait", AccessToken: []byte("test-only"), ReplaySlots: 2, RoutesRevision: emptyRoutesRevision()}}})
		if attach.GetErrno() != 0 || attach.GetAttach() == nil {
			t.Fatalf("attach = %v", attach)
		}
		return attach.GetAttach(), attach.GetEpoch(), &authoritypb.SessionProof{Id: attach.GetAttach().GetSessionId(), Generation: attach.GetAttach().GetSessionGeneration(), ResumeSecret: attach.GetAttach().GetResumeSecret()}
	}
	holder, epoch, holderProof := attachSession(1)
	waiter, _, waiterProof := attachSession(2)

	create := &authoritypb.Request{RequestId: 3, Epoch: epoch, Session: holderProof, Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: holder.GetRoot().GetToken(), Name: []byte("lock-wait-target"), Mode: 0o600, Exclusive: true, Flags: &authoritypb.OpenFlags{Read: true, Write: true}}}}
	stampMutation(t, create, 0, 1)
	created := h.Handle(ctx, create)
	if created.GetErrno() != 0 {
		t.Fatalf("create = %v", created)
	}
	t.Cleanup(func() {
		// Removed behind the store, like resetXFSRouteDeclaration: the routing
		// revision this test installs makes the holder's session stale by
		// design, so an in-protocol unlink could not run in every exit path.
		if err := os.Remove(filepath.Join(root, "lock-wait-target")); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove shared XFS lock fixture: %v", err)
		}
	})
	itemToken := created.GetCreate().GetItem().GetToken()

	// The waiter needs its own capability for the same object.
	waiterLookupRequest := &authoritypb.Request{RequestId: 4, Epoch: epoch, Session: waiterProof, Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: waiter.GetRoot().GetToken(), Name: []byte("lock-wait-target")}}}
	stampMutation(t, waiterLookupRequest, 0, 1)
	waiterLookup := h.Handle(ctx, waiterLookupRequest)
	if waiterLookup.GetErrno() != 0 {
		t.Fatalf("waiter lookup = %v", waiterLookup)
	}
	waiterToken := waiterLookup.GetLookup().GetItem().GetToken()

	wholeFile := &authoritypb.LockRange{Start: 0, End: 0}
	hold := &authoritypb.Request{RequestId: 5, Epoch: epoch, Session: holderProof, Body: &authoritypb.Request_SetLock{SetLock: &authoritypb.SetLockRequest{Lock: &authoritypb.LockSpec{Item: itemToken, Owner: 1, Write: true, Range: wholeFile}}}}
	stampMutation(t, hold, 0, 2)
	if response := h.Handle(ctx, hold); response.GetErrno() != 0 {
		t.Fatalf("holder SetLock = %v", response)
	}

	waitCtx, cancelWait := context.WithCancel(ctx)
	defer cancelWait()
	waitDone := make(chan *authoritypb.Response, 1)
	go func() {
		wait := &authoritypb.Request{RequestId: 6, Epoch: epoch, Session: waiterProof, Body: &authoritypb.Request_SetLock{SetLock: &authoritypb.SetLockRequest{Lock: &authoritypb.LockSpec{Item: waiterToken, Owner: 2, Write: true, Range: wholeFile}, Wait: true}}}
		stampMutation(t, wait, 0, 2)
		waitDone <- h.Handle(waitCtx, wait)
	}()
	select {
	case response := <-waitDone:
		t.Fatalf("the conflicting blocking wait returned immediately: %v", response)
	case <-time.After(300 * time.Millisecond):
	}

	// The topology writer must not queue behind the parked wait. Before the
	// fix, this Apply blocked until the lock wait ended — and because a queued
	// RWMutex writer stops new readers, every guarded request on the volume
	// blocked with it.
	active, err := h.Routes.Revision()
	if err != nil {
		t.Fatal(err)
	}
	applyDone := make(chan error, 1)
	go func() {
		_, err := h.Routes.Apply(ctx, []byte("node_modules\n"), active)
		applyDone <- err
	}()
	select {
	case err := <-applyDone:
		if err != nil {
			t.Fatalf("ApplyRoutes beside a blocked lock wait: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ApplyRoutes deadlocked behind a blocked lock wait")
	}

	// Ending the holder's session releases its locks and completes the parked
	// wait: the waiter's admission happened before the routing change, exactly
	// once, and is not re-litigated when the lock is granted.
	if response := h.Handle(ctx, &authoritypb.Request{RequestId: 7, Epoch: epoch, Session: holderProof, Body: &authoritypb.Request_Detach{Detach: &authoritypb.DetachRequest{}}}); response.GetErrno() != 0 {
		t.Fatalf("holder detach = %v", response)
	}
	select {
	case response := <-waitDone:
		if response.GetErrno() != 0 {
			t.Fatalf("the parked wait completed with errno %d after the lock was released", response.GetErrno())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the parked lock wait never completed after the holder detached")
	}
}

func TestRoutingRevisionContractRejectsTheOldExactProtocolAtHello(t *testing.T) {
	h := testVolumeHandler()
	old := h.Handle(context.Background(), &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Hello{
		Hello: &authoritypb.HelloRequest{ProtocolMajor: ProtocolMajor - 1},
	}})
	if old.GetErrno() != int32(syscall.EOPNOTSUPP) || old.GetHello() != nil {
		t.Fatalf("old-protocol hello = %v, want EOPNOTSUPP before attach", old)
	}
	current := h.Handle(context.Background(), &authoritypb.Request{RequestId: 2, Body: &authoritypb.Request_Hello{
		Hello: &authoritypb.HelloRequest{ProtocolMajor: ProtocolMajor, Features: append([]string(nil), requiredHelloFeatures...)},
	}})
	if current.GetErrno() != 0 || current.GetHello().GetProtocolMajor() != ProtocolMajor {
		t.Fatalf("current-protocol hello = %v", current)
	}
	legacy := h.Handle(context.Background(), &authoritypb.Request{RequestId: 3, Body: &authoritypb.Request_Hello{
		Hello: &authoritypb.HelloRequest{ProtocolMajor: ProtocolMajor, Features: []string{"xfs-current-state", "session-exact-epoch", "direct-write"}},
	}})
	if legacy.GetErrno() != int32(syscall.EOPNOTSUPP) || legacy.GetHello() != nil {
		t.Fatalf("legacy-feature hello = %v, want EOPNOTSUPP before attach", legacy)
	}
}

func stampMutation(t *testing.T, request *authoritypb.Request, slot uint32, sequence uint64) {
	t.Helper()
	request.Mutation = &authoritypb.Mutation{Slot: slot, Sequence: sequence, RequestHash: make([]byte, 32)}
	hash, err := canonicalHash(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Mutation.RequestHash = hash[:]
}
