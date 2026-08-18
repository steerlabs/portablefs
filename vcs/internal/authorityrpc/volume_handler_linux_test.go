//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritymetrics"
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
		MaxRetainedReplyBytes:           1 << 20,
		WriteStaging:                    &WriteTransactionStaging{},
		MaxWriteTransactionBytes:        RequiredWriteTransactionBytes,
		MaxWriteStagingBytesPerSession:  16 << 30,
		MaxWriteStagingBytes:            64 << 30,
		MaxWriteTransactionsPerSession:  8,
		MaxWriteTransactions:            32,
		WriteTransactionProgressTimeout: time.Minute,
		WriteTransactionAbsoluteTimeout: time.Hour,
	}
}

func testInitialVisibilityCursor(t *testing.T, visibility *volumeserver.VisibilityCoordinator, id volumeserver.SessionID) volumeserver.VisibilityCursor {
	t.Helper()
	cursor, err := visibility.InitialCursor(id)
	if err != nil {
		t.Fatalf("initial visibility cursor for %x: %v", id, err)
	}
	return cursor
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
		credential, err := runtime.AttachActiveForTest(2, peer, volumeserver.Authorization{Access: volumeserver.AccessRead, Deadline: time.Now().Add(time.Hour)})
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

func TestNextVisibilityAtomicallyAcknowledgesAndWaitsForSuccessor(t *testing.T) {
	runtime, err := volumeserver.New("ack-next", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 2, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := volumeserver.PeerIdentity{0x51}
	credential, err := runtime.AttachActiveForTest(2, peer, volumeserver.Authorization{
		Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: noopMembership{}, Fencer: runtime,
		MaxCachedNameCapacity: 64, MaxRepairBudget: time.Minute, MaxClockSkew: time.Second,
	})
	if err != nil {
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
	h := testVolumeHandler()
	h.Store = &resourceAdmissionFaultStore{}
	h.Runtime = runtime
	h.Authorizer = allowAuthorizer{access: volumeserver.AccessRead | volumeserver.AccessWrite}
	h.Visibility = visibility
	h.Routes = &RoutesController{Visibility: visibility, loaded: true}
	if err := h.startSessionResources(credential.ID, xfsstore.Capability{1}, 2, [32]byte{}, volumeserver.CoherenceStrict); err != nil {
		t.Fatal(err)
	}
	peerContext := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte(peer))
	ctx, cancel := context.WithTimeout(peerContext, 2*time.Second)
	defer cancel()
	request := func(id uint64, value *authoritypb.Request) *authoritypb.Request {
		value.RequestId = id
		value.Epoch = credential.Epoch[:]
		value.Session = &authoritypb.SessionProof{Id: credential.ID[:], Generation: credential.Generation, ResumeSecret: credential.Secret[:]}
		return value
	}

	targets := []volumeserver.VisibilityTarget{{
		Scope: volumeserver.VisibilityAttributes, Identity: [16]byte{7}, KernelIno: 7, Device: 1,
	}}
	// The registered mount is a peer that has actually published this inode to
	// its kernel. The distinct initiator below is therefore excluded nowhere in
	// this one-peer audience, and the peer receives both phases.
	visibility.RecordResolvedInode(credential.ID, targets[0].Identity)
	initialCursor := testInitialVisibilityCursor(t, visibility, credential.ID)
	applied := make(chan error, 1)
	go func() {
		applied <- visibility.Execute(
			ctx, volumeserver.SessionID{0xEE}, volumeserver.MutationID{Sequence: 1},
			volumeserver.MutationDependenciesForTargets(targets),
			func() ([]volumeserver.VisibilityTarget, error) { return targets, nil },
			func() ([]volumeserver.VisibilityTarget, bool) { return targets, true },
		)
	}()
	initial := h.Handle(ctx, request(1, &authoritypb.Request{Body: &authoritypb.Request_NextVisibility{
		NextVisibility: &authoritypb.NextVisibilityRequest{
			After: visibilityCursorProto(initialCursor),
		},
	}}))
	prepare := initial.GetVisibility()
	if initial.GetErrno() != 0 || prepare.GetCursor().GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE {
		t.Fatalf("initial visibility = %+v, want PREPARE", initial)
	}

	advanced := h.Handle(ctx, request(2, &authoritypb.Request{Body: &authoritypb.Request_NextVisibility{
		NextVisibility: &authoritypb.NextVisibilityRequest{
			After: prepare.GetCursor(), AcknowledgeAfter: true,
		},
	}}))
	complete := advanced.GetVisibility()
	if advanced.GetErrno() != 0 || complete.GetCursor().GetPhase() != authoritypb.VisibilityPhase_VISIBILITY_PHASE_COMPLETE {
		t.Fatalf("combined visibility advance = %+v, want COMPLETE", advanced)
	}
	acked := h.Handle(ctx, request(3, &authoritypb.Request{Body: &authoritypb.Request_AckVisibility{
		AckVisibility: &authoritypb.AckVisibilityRequest{Cursor: complete.GetCursor()},
	}}))
	if acked.GetErrno() != 0 {
		t.Fatalf("final COMPLETE acknowledgment = %+v", acked)
	}
	select {
	case err := <-applied:
		if err != nil {
			t.Fatalf("mutation after COMPLETE acknowledgment: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("mutation did not complete after COMPLETE acknowledgment: %v", ctx.Err())
	}
}

func TestWireErrnoPreservesLinuxSyscall(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EACCES, syscall.EXDEV, syscall.ELOOP, syscall.EBADF} {
		if got := wireErrno(errno); got != int32(errno) {
			t.Fatalf("wireErrno(%v) = %d", errno, got)
		}
	}
	if got := wireErrno(volumeserver.ErrVisibilityInterrupted); got != errnos.EINTR {
		t.Fatalf("wireErrno(visibility interruption) = %d, want EINTR", got)
	}
	if got := wireErrno(volumeserver.ErrVisibilityRetry); got != errnos.EINTR {
		t.Fatalf("wireErrno(visibility retry) = %d, want EINTR", got)
	}
	if got := wireErrno(volumeserver.ErrCompatibilityWriterLease); got != errnos.EBUSY {
		t.Fatalf("wireErrno(compatibility writer lease) = %d, want EBUSY", got)
	}
	// Delegated killpriv and logical sync can both fail after one clean
	// mutation. The authority retains both causes, but the syscall-visible
	// result must deterministically preserve the security failure while the EIO
	// remains discoverable for terminal storage classification.
	joined := errors.Join(xfsstore.ErrWritePrivilege, syscall.EPERM, syscall.EIO)
	if got := wireErrno(joined); got != int32(syscall.EPERM) {
		t.Fatalf("wireErrno(joined privilege+sync failure) = %d, want EPERM", got)
	}
	if !fatalStorageErrno(joined) || !storageFailure(joined) {
		t.Fatal("joined privilege+sync failure lost its terminal storage classification")
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

func TestVisibilityRetryMapsToInternalDefiniteEINTR(t *testing.T) {
	h := &VolumeHandler{}
	response := h.errorResponse(7, &volumeserver.VisibilityRetryError{Sequence: 9}, false)
	if response.GetErrno() != errnos.EINTR {
		t.Fatalf("visibility retry errno = %d, want EINTR", response.GetErrno())
	}
	if response.GetUncertain() || response.GetBody() != nil {
		t.Fatalf("visibility retry carried an uncertain or state-bearing result: %+v", response)
	}
	if response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_RETRY {
		t.Fatalf("visibility retry failure class = %v, want VISIBILITY_RETRY", response.GetFailure())
	}
	if response.GetVisibilityRetrySequence() != 9 {
		t.Fatalf("visibility retry sequence = %d, want 9", response.GetVisibilityRetrySequence())
	}
}

func TestVisibilityRetryWithoutSequenceFailsClosed(t *testing.T) {
	h := &VolumeHandler{}
	response := h.errorResponse(7, volumeserver.ErrVisibilityRetry, false)
	if response.GetErrno() != int32(syscall.EIO) || !response.GetUncertain() ||
		response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_INTERNAL || response.GetVisibilityRetrySequence() != 0 {
		t.Fatalf("unsequenced visibility retry = %+v, want uncertain internal EIO", response)
	}
}

// This exercises the retained-mutation path, not only errorResponse. A
// callback-serialized source with a peer COMPLETE outstanding consumes one
// mutation slot as a definite EINTR. Replaying that exact identity must return
// the retained EINTR and must never enter visibility prepare or filesystem
// apply on either delivery. The source never receives a phase for its own
// mutation.
func TestMutateVisibleRetainsPreApplyVisibilityEINTRForExactReplay(t *testing.T) {
	runtime, err := volumeserver.New("visibility-eintr-replay", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 2, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := volumeserver.PeerIdentity{1}
	cred, err := runtime.AttachActiveForTest(2, peer, volumeserver.Authorization{
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

	// A different writer produces the peer COMPLETE state against which this
	// callback-serialized source's next mutation is refused.
	identity := [16]byte{1}
	visibility.RecordResolvedInode(cred.ID, identity)
	targets := []volumeserver.VisibilityTarget{{
		Scope: volumeserver.VisibilityAttributes, Identity: identity,
	}}
	first := make(chan error, 1)
	go func() {
		first <- visibility.Execute(
			context.Background(), volumeserver.SessionID{0xEE}, volumeserver.MutationID{Sequence: 1},
			volumeserver.MutationDependenciesForTargets(targets),
			func() ([]volumeserver.VisibilityTarget, error) { return targets, nil },
			func() ([]volumeserver.VisibilityTarget, bool) { return targets, true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := visibility.Next(ctx, cred.ID, testInitialVisibilityCursor(t, visibility, cred.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := visibility.Ack(cred.ID, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := visibility.Next(ctx, cred.ID, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}

	h := testVolumeHandler()
	h.Store = &resourceAdmissionFaultStore{}
	h.Runtime = runtime
	h.Visibility = visibility
	root := xfsstore.Capability{1}
	if err := h.startSessionResources(cred.ID, root, 2, [32]byte{}, volumeserver.CoherenceStrict); err != nil {
		t.Fatal(err)
	}
	request := &authoritypb.Request{
		RequestId:           7,
		FrontendOperationId: 77,
		SourcePublicationGate: &authoritypb.SourcePublicationGate{Targets: []*authoritypb.SourcePublicationTarget{{
			Coordinate: &authoritypb.SourcePublicationTarget_Item{Item: &authoritypb.SourcePublicationItem{
				Identity: identity[:], Attributes: true,
			}},
		}}},
		Body: &authoritypb.Request_SetXattr{SetXattr: &authoritypb.SetXattrRequest{
			Item: root[:], Name: []byte("user.replay"), Value: []byte("value"),
		}},
	}
	stampMutation(t, request, 0, 1)
	var prepareCalls, applyCalls atomic.Uint32
	handlerPrepare := func() ([]volumeserver.VisibilityTarget, error) {
		prepareCalls.Add(1)
		return []volumeserver.VisibilityTarget{{
			Scope: volumeserver.VisibilityAttributes, Identity: identity,
		}}, nil
	}
	handlerApply := func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
		applyCalls.Add(1)
		response := h.success(0)
		return response, []volumeserver.VisibilityTarget{{
			Scope: volumeserver.VisibilityAttributes, Identity: identity,
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
	// Request ID is transport correlation, not replay identity. The otherwise
	// exact replay must return the retained definite interruption.
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
	if err := <-first; err != nil {
		t.Fatalf("seed peer mutation: %v", err)
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
			for i := 0; i < int(entries); i++ {
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

// A replay slot's retained size is the credit its successor replaces. Admission
// must therefore share the runtime's exact slot mutex with sequence validation
// and apply. Otherwise two pipelined successors can both price themselves
// against the same old large outcome: the first shrinks it, another slot consumes
// those returned bytes, and the second then grows past the worker-wide bound.
func TestReplyAdmissionIsSerializedWithItsReplaySlot(t *testing.T) {
	now := time.Now()
	observeNextBegin := atomic.Bool{}
	nextBegin := make(chan struct{}, 1)
	runtime, err := volumeserver.New("reply-admission-slot", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 2, MaxLockRecords: 8,
		Now: func() time.Time {
			if observeNextBegin.CompareAndSwap(true, false) {
				nextBegin <- struct{}{}
			}
			return now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := runtime.AttachActiveForTest(2, volumeserver.PeerIdentity{0x91}, volumeserver.Authorization{
		Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	h := testVolumeHandler()
	const large, small uint32 = 64, 16
	h.MaxRetainedReplyBytes = uint64(large)
	if err := h.startSessionResources(cred.ID, xfsstore.Capability{0x92}, 2, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		h.closeSessionResources(cred.ID)
		runtime.FenceSession(cred.ID)
	})

	execute := func(id volumeserver.MutationID, reserve, retained uint32, afterSettle func()) (out volumeserver.Outcome, err error) {
		var reserved uint32
		settled := false
		defer func() {
			if !settled {
				h.releaseReplyReservation(reserved)
			}
		}()
		return runtime.ExecuteMutationAdmitted(context.Background(), cred, id, func() error {
			var reserveErr error
			reserved, reserveErr = h.reserveReplyBytes(cred.ID, id.Slot, reserve)
			return reserveErr
		}, func(context.Context) volumeserver.Outcome {
			h.settleReplyBytes(cred.ID, id.Slot, retained, reserved)
			settled = true
			if afterSettle != nil {
				afterSettle()
			}
			return volumeserver.Outcome{Reply: make([]byte, retained)}
		})
	}
	id := func(slot uint32, sequence uint64) volumeserver.MutationID {
		return volumeserver.MutationID{
			Slot: slot, Sequence: sequence,
			Fingerprint: volumeserver.RequestFingerprint{byte(slot + 1), byte(sequence)},
		}
	}
	if _, err := execute(id(0, 1), large, large, nil); err != nil {
		t.Fatal(err)
	}

	shrunk := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		_, err := execute(id(0, 2), large, small, func() {
			close(shrunk)
			<-releaseFirst
		})
		firstDone <- err
	}()
	<-shrunk

	// Pipeline the next sequence while sequence 2 still owns slot 0. Its
	// admission callback must remain behind that ownership boundary.
	secondApplied := atomic.Bool{}
	secondDone := make(chan error, 1)
	observeNextBegin.Store(true)
	go func() {
		var reserved uint32
		settled := false
		defer func() {
			if !settled {
				h.releaseReplyReservation(reserved)
			}
		}()
		_, err := runtime.ExecuteMutationAdmitted(context.Background(), cred, id(0, 3), func() error {
			var reserveErr error
			reserved, reserveErr = h.reserveReplyBytes(cred.ID, 0, large)
			return reserveErr
		}, func(context.Context) volumeserver.Outcome {
			secondApplied.Store(true)
			h.settleReplyBytes(cred.ID, 0, large, reserved)
			settled = true
			return volumeserver.Outcome{Reply: make([]byte, large)}
		})
		secondDone <- err
	}()
	// Begin calls the injected clock before pinning and acquiring the replay
	// slot. Sequence 2 is still inside apply, so this observation proves sequence
	// 3 entered the runtime and can progress only as far as slot 0's mutex.
	<-nextBegin

	// While slot 0 is still locked at its now-small settled outcome, an
	// independent slot consumes exactly the bytes it returned.
	if _, err := execute(id(1, 1), large-small, large-small, nil); err != nil {
		t.Fatalf("independent slot could not consume returned capacity: %v", err)
	}
	h.resourcesMu.Lock()
	retained, reserved := h.retainedReplyBytes, h.reservedReplyBytes
	h.resourcesMu.Unlock()
	if retained != uint64(large) || reserved != 0 {
		t.Fatalf("before successor admission = %d retained / %d reserved, want %d / 0", retained, reserved, large)
	}
	select {
	case err := <-secondDone:
		t.Fatalf("pipelined successor escaped the slot mutex early: %v", err)
	default:
	}

	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("shrinking predecessor: %v", err)
	}
	if err := <-secondDone; !errors.Is(err, volumeserver.ErrAdmission) {
		t.Fatalf("successor at full budget = %v, want ErrAdmission", err)
	}
	if secondApplied.Load() {
		t.Fatal("reply admission refusal reached apply")
	}
	h.resourcesMu.Lock()
	retained, reserved = h.retainedReplyBytes, h.reservedReplyBytes
	h.resourcesMu.Unlock()
	if retained != uint64(large) || reserved != 0 {
		t.Fatalf("refusal exceeded budget: %d retained / %d reserved, want %d / 0", retained, reserved, large)
	}

	// Admission refusal did not advance sequence 3. Once slot 1 returns its
	// capacity, the exact same identity can execute normally.
	if _, err := execute(id(1, 2), 0, 0, nil); err != nil {
		t.Fatalf("release independent slot: %v", err)
	}
	if _, err := execute(id(0, 3), large, large, nil); err != nil {
		t.Fatalf("retry refused identity after capacity returned: %v", err)
	}
	h.resourcesMu.Lock()
	retained, reserved = h.retainedReplyBytes, h.reservedReplyBytes
	h.resourcesMu.Unlock()
	if retained != uint64(large) || reserved != 0 {
		t.Fatalf("successful retry = %d retained / %d reserved, want %d / 0", retained, reserved, large)
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
	if err := h.trackItem(second, xfsstore.Capability{2}, false); !errors.Is(err, syscall.ENFILE) {
		t.Fatalf("global item admission = %v, want ENFILE", err)
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
	if _, err := h.reserveCapabilities(second, 1, 0); !errors.Is(err, syscall.ENFILE) {
		t.Fatalf("item admission past outstanding reservation = %v, want ENFILE", err)
	}
	if _, err := h.reserveCapabilities(second, 0, 1); !errors.Is(err, syscall.ENFILE) {
		t.Fatalf("open admission past outstanding reservation = %v, want ENFILE", err)
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
	failure      error
	create       atomic.Uint32
	mkdir        atomic.Uint32
	symlink      atomic.Uint32
	open         atomic.Uint32
	lookup       atomic.Uint32
	forget       atomic.Uint32
	identityOpen atomic.Uint32
	lookupItem   xfsstore.Capability
}

func (*resourceAdmissionFaultStore) LockMutation([][16]byte) func() { return func() {} }

type sourceGateRefreshStore struct {
	resourceAdmissionFaultStore
	mu             sync.Mutex
	bound          xfsstore.Capability
	lookupCalls    atomic.Uint32
	firstLookup    chan struct{}
	releaseFirst   chan struct{}
	firstForgotten chan struct{}
	secondLookup   chan struct{}
}

type fsyncMetricStore struct {
	resourceAdmissionFaultStore
	batch int
}

func (s *fsyncMetricStore) FsyncCoalesced(xfsstore.Capability, bool) (int, error) {
	return s.batch, nil
}

// CloseOpen must exist on the mock itself: the harness fences the session at
// cleanup, which closes every tracked open, and the embedded volumeStore
// interface is deliberately nil.
func (s *fsyncMetricStore) CloseOpen(xfsstore.Capability) error { return nil }

// renameReplyStore is an in-memory namespace only for exercising the
// authority's response contract. The source frontend is deliberately absent:
// the post identities must come from the authoritative pre-XFS lookup, never
// from a source-side dentry cache.
type renameReplyStore struct {
	resourceAdmissionFaultStore
	mu          sync.Mutex
	bindings    map[string]xfsstore.Capability
	renameCalls atomic.Uint32
}

func (s *renameReplyStore) Getattr(item xfsstore.Capability) (xfsstore.Attr, error) {
	return xfsstore.Attr{
		Kind: xfsstore.KindDirectory, Ino: uint64(item[0]), Mode: 0o755, Nlink: 2, DeviceMinor: 1,
	}, nil
}

func (s *renameReplyStore) Lookup(_ xfsstore.Capability, name string) (xfsstore.Capability, xfsstore.Attr, error) {
	s.lookup.Add(1)
	s.mu.Lock()
	item, ok := s.bindings[name]
	s.mu.Unlock()
	if !ok {
		return xfsstore.Capability{}, xfsstore.Attr{}, syscall.ENOENT
	}
	return item, xfsstore.Attr{
		Kind: xfsstore.KindRegular, Ino: uint64(item[0]), Mode: 0o600, Nlink: 1, DeviceMinor: 1,
	}, nil
}

func (s *renameReplyStore) Rename(
	_ xfsstore.Capability,
	oldName string,
	_ xfsstore.Capability,
	newName string,
	flags xfsstore.RenameFlags,
) error {
	s.renameCalls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	moved, ok := s.bindings[oldName]
	if !ok {
		return syscall.ENOENT
	}
	if flags&xfsstore.RenameExchange != 0 {
		replaced, exists := s.bindings[newName]
		if !exists {
			return syscall.ENOENT
		}
		s.bindings[oldName], s.bindings[newName] = replaced, moved
		return nil
	}
	if flags&xfsstore.RenameNoReplace != 0 {
		if _, exists := s.bindings[newName]; exists {
			return syscall.EEXIST
		}
	}
	if replaced, exists := s.bindings[newName]; exists && replaced == moved {
		// POSIX rename is a successful no-op when two names are hard links to
		// the same inode. Both names remain bound.
		return nil
	}
	delete(s.bindings, oldName)
	s.bindings[newName] = moved
	return nil
}

func (s *sourceGateRefreshStore) Lookup(_ xfsstore.Capability, _ string) (xfsstore.Capability, xfsstore.Attr, error) {
	s.mu.Lock()
	bound := s.bound
	s.mu.Unlock()
	call := s.lookupCalls.Add(1)
	if call == 1 {
		close(s.firstLookup)
		<-s.releaseFirst
	} else if call == 2 {
		close(s.secondLookup)
	}
	return bound, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: uint64(bound[0]), Mode: 0o600, Nlink: 1, DeviceMinor: 1}, nil
}

func (s *sourceGateRefreshStore) Forget(xfsstore.Capability) error {
	if s.forget.Add(1) == 1 {
		close(s.firstForgotten)
	}
	return nil
}

func (s *sourceGateRefreshStore) setBound(bound xfsstore.Capability) {
	s.mu.Lock()
	s.bound = bound
	s.mu.Unlock()
}

func (s *resourceAdmissionFaultStore) Fence(error) {}
func (s *resourceAdmissionFaultStore) Root() (xfsstore.Capability, error) {
	return xfsstore.Capability{0x70}, nil
}
func (s *resourceAdmissionFaultStore) Identity(item xfsstore.Capability) ([16]byte, error) {
	return [16]byte{item[0]}, nil
}
func (s *resourceAdmissionFaultStore) CoordinateItem(item xfsstore.Capability) (xfsstore.ObjectCoordinate, error) {
	ino := uint64(item[0])
	if item == s.lookupItem {
		ino = 2
	}
	return xfsstore.ObjectCoordinate{Stable: [16]byte{item[0]}, Ino: ino, DeviceMinor: 1}, nil
}
func (s *resourceAdmissionFaultStore) IdentityOpen(open xfsstore.Capability) ([16]byte, error) {
	s.identityOpen.Add(1)
	return [16]byte{open[0]}, nil
}
func (s *resourceAdmissionFaultStore) CoordinateOpen(open xfsstore.Capability) (xfsstore.ObjectCoordinate, error) {
	s.identityOpen.Add(1)
	return xfsstore.ObjectCoordinate{Stable: [16]byte{open[0]}, Ino: uint64(open[0]), DeviceMinor: 1}, nil
}
func (s *resourceAdmissionFaultStore) Getattr(xfsstore.Capability) (xfsstore.Attr, error) {
	return xfsstore.Attr{Kind: xfsstore.KindDirectory, Ino: 1, DeviceMinor: 1}, nil
}
func (s *resourceAdmissionFaultStore) Lookup(xfsstore.Capability, string) (xfsstore.Capability, xfsstore.Attr, error) {
	s.lookup.Add(1)
	if s.lookupItem != (xfsstore.Capability{}) {
		return s.lookupItem, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 2, Mode: 0o600, Nlink: 1, DeviceMinor: 1}, nil
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

func TestDeriveSourcePublicationGateCoversVisibleOperationMatrix(t *testing.T) {
	store := &resourceAdmissionFaultStore{lookupItem: xfsstore.Capability{0x33}}
	h := testVolumeHandler()
	h.Store = store
	session := volumeserver.SessionID{0x91}
	root := xfsstore.Capability{0x11}
	item := xfsstore.Capability{0x22}
	handle := xfsstore.Capability{0x22}
	outputHandle := xfsstore.Capability{0x44}
	if err := h.startSessionResources(session, root, 2, [32]byte{}, volumeserver.CoherenceStrict); err != nil {
		t.Fatal(err)
	}
	if err := h.trackItem(session, item, false); err != nil {
		t.Fatal(err)
	}
	if err := h.trackOpen(session, handle, false); err != nil {
		t.Fatal(err)
	}
	if err := h.trackOpen(session, outputHandle, false); err != nil {
		t.Fatal(err)
	}

	rootIdentity := [16]byte{0x11}
	itemIdentity := [16]byte{0x22}
	boundIdentity := [16]byte{0x33}
	itemTarget := func(identity [16]byte, data bool) volumeserver.SourcePublicationTarget {
		return volumeserver.SourcePublicationTarget{Identity: identity, Attributes: true, Data: data}
	}
	namespaceTarget := func(name string, data bool) volumeserver.SourcePublicationTarget {
		return volumeserver.SourcePublicationTarget{
			ParentIdentity: rootIdentity, Name: []byte(name), BoundAttributes: true, BoundData: data,
			BoundIdentities: [][16]byte{boundIdentity},
		}
	}
	rootAndNamespace := func(name string, data bool) volumeserver.SourcePublicationGate {
		return volumeserver.SourcePublicationGate{Targets: []volumeserver.SourcePublicationTarget{
			itemTarget(rootIdentity, false), namespaceTarget(name, data),
		}}
	}

	tests := []struct {
		name    string
		request *authoritypb.Request
		want    volumeserver.SourcePublicationGate
	}{
		{
			name: "setattr attributes", request: &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{
				Item: item[:], Mode: proto.Uint32(0o600),
			}}},
			want: volumeserver.SourcePublicationGate{Targets: []volumeserver.SourcePublicationTarget{itemTarget(itemIdentity, false)}},
		},
		{
			name: "setattr size", request: &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{
				Item: item[:], Size: proto.Int64(7),
			}}},
			want: volumeserver.SourcePublicationGate{Targets: []volumeserver.SourcePublicationTarget{itemTarget(itemIdentity, true)}},
		},
		{
			name: "fallocate", request: &authoritypb.Request{Body: &authoritypb.Request_Fallocate{Fallocate: &authoritypb.FallocateRequest{Handle: handle[:]}}},
			want: volumeserver.SourcePublicationGate{Targets: []volumeserver.SourcePublicationTarget{itemTarget(itemIdentity, true)}},
		},
		{
			name: "copy file range", request: &authoritypb.Request{Body: &authoritypb.Request_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeRequest{
				InputHandle: handle[:], OutputHandle: outputHandle[:],
			}}},
			want: volumeserver.SourcePublicationGate{Targets: []volumeserver.SourcePublicationTarget{
				itemTarget(itemIdentity, true), itemTarget([16]byte{0x44}, true),
			}},
		},
		{
			name: "open truncate", request: &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{
				Item: item[:], Flags: &authoritypb.OpenFlags{Write: true, Truncate: true},
			}}},
			want: volumeserver.SourcePublicationGate{Targets: []volumeserver.SourcePublicationTarget{itemTarget(itemIdentity, true)}},
		},
		{
			name: "create", request: &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
				Parent: root[:], Name: []byte("child"), Flags: &authoritypb.OpenFlags{Write: true},
			}}}, want: rootAndNamespace("child", false),
		},
		{
			name: "create truncate", request: &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
				Parent: root[:], Name: []byte("child"), Flags: &authoritypb.OpenFlags{Write: true, Truncate: true},
			}}}, want: rootAndNamespace("child", true),
		},
		{
			name: "mkdir", request: &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{
				Parent: root[:], Name: []byte("child"),
			}}}, want: rootAndNamespace("child", false),
		},
		{
			name: "unlink", request: &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{
				Parent: root[:], Name: []byte("child"),
			}}}, want: rootAndNamespace("child", false),
		},
		{
			name: "rename", request: &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{
				OldParent: root[:], OldName: []byte("old"), NewParent: root[:], NewName: []byte("new"),
			}}},
			want: volumeserver.SourcePublicationGate{Targets: []volumeserver.SourcePublicationTarget{
				itemTarget(rootIdentity, false), namespaceTarget("new", false), namespaceTarget("old", false),
			}},
		},
		{
			name: "link", request: &authoritypb.Request{Body: &authoritypb.Request_Link{Link: &authoritypb.LinkRequest{
				ExistingItem: item[:], NewParent: root[:], NewName: []byte("child"),
			}}},
			want: volumeserver.SourcePublicationGate{Targets: []volumeserver.SourcePublicationTarget{
				itemTarget(rootIdentity, false), itemTarget(itemIdentity, false), namespaceTarget("child", false),
			}},
		},
		{
			name: "symlink", request: &authoritypb.Request{Body: &authoritypb.Request_Symlink{Symlink: &authoritypb.SymlinkRequest{
				Parent: root[:], Name: []byte("child"), Target: []byte("target"),
			}}}, want: rootAndNamespace("child", false),
		},
		{
			name: "setxattr", request: &authoritypb.Request{Body: &authoritypb.Request_SetXattr{SetXattr: &authoritypb.SetXattrRequest{
				Item: item[:], Name: []byte("user.test"), Value: []byte("value"),
			}}},
			want: volumeserver.SourcePublicationGate{Targets: []volumeserver.SourcePublicationTarget{itemTarget(itemIdentity, false)}},
		},
		{
			name: "removexattr", request: &authoritypb.Request{Body: &authoritypb.Request_RemoveXattr{RemoveXattr: &authoritypb.RemoveXattrRequest{
				Item: item[:], Name: []byte("user.test"),
			}}},
			want: volumeserver.SourcePublicationGate{Targets: []volumeserver.SourcePublicationTarget{itemTarget(itemIdentity, false)}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := newOperationResolutionContext(h, session).deriveSourcePublicationGate(test.request, true)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("derived gate\n got %#v\nwant %#v", got, test.want)
			}
		})
	}
}

func TestDeriveSourcePublicationGateRejectsSetAttrItemHandleMismatch(t *testing.T) {
	store := &resourceAdmissionFaultStore{}
	h := testVolumeHandler()
	h.Store = store
	session := volumeserver.SessionID{0x92}
	item := xfsstore.Capability{0x41}
	handle := xfsstore.Capability{0x42}
	if err := h.startSessionResources(session, item, 1, [32]byte{}, volumeserver.CoherenceStrict); err != nil {
		t.Fatal(err)
	}
	if err := h.trackOpen(session, handle, false); err != nil {
		t.Fatal(err)
	}
	request := &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{
		Item: item[:], Handle: handle[:], Mode: proto.Uint32(0o600),
	}}}
	if _, err := newOperationResolutionContext(h, session).deriveSourcePublicationGate(request, true); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("mismatched SetAttr item/handle = %v, want EINVAL", err)
	}
}

func TestOperationResolutionContextReusesAuthoritativeNamespaceBindings(t *testing.T) {
	root := xfsstore.Capability{0x11}
	for _, test := range []struct {
		name        string
		request     *authoritypb.Request
		prepareName [][]byte
		wantLookups uint32
	}{
		{
			name: "create",
			request: &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
				Parent: root[:], Name: []byte("created"),
			}}},
			prepareName: [][]byte{[]byte("created")}, wantLookups: 1,
		},
		{
			name: "same-directory-rename",
			request: &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{
				OldParent: root[:], OldName: []byte("old"), NewParent: root[:], NewName: []byte("new"),
			}}},
			prepareName: [][]byte{[]byte("old"), []byte("new")}, wantLookups: 2,
		},
		{
			name: "unlink",
			request: &authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{
				Parent: root[:], Name: []byte("removed"),
			}}},
			prepareName: [][]byte{[]byte("removed")}, wantLookups: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &resourceAdmissionFaultStore{lookupItem: xfsstore.Capability{0x42}}
			h := testVolumeHandler()
			h.Store = store
			session := volumeserver.SessionID{0x93}
			if err := h.startSessionResources(session, root, 1, [32]byte{}, volumeserver.CoherenceStrict); err != nil {
				t.Fatal(err)
			}
			resolutions := newOperationResolutionContext(h, session)
			if _, err := resolutions.deriveSourcePublicationGate(test.request, false); err != nil {
				t.Fatal(err)
			}
			if got := store.lookup.Load(); got != 0 {
				t.Fatalf("shape-only namespace lookups = %d, want 0", got)
			}

			resolutions.invalidateNamespaceBindings()
			if _, err := resolutions.deriveSourcePublicationGate(test.request, true); err != nil {
				t.Fatal(err)
			}
			for _, name := range test.prepareName {
				if _, err := resolutions.namespace(root, name); err != nil {
					t.Fatal(err)
				}
			}
			if got := store.lookup.Load(); got != test.wantLookups {
				t.Fatalf("operation namespace lookups = %d, want %d", got, test.wantLookups)
			}
		})
	}
}

func TestMutateVisibleItemGateResolvesStableFallocateIdentityOnce(t *testing.T) {
	runtime, err := volumeserver.New("write-source-gate-identity", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 2, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := runtime.AttachActiveForTest(2, volumeserver.PeerIdentity{0x51}, volumeserver.Authorization{
		Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: noopMembership{}, Fencer: noopFencer{},
		MaxCachedNameCapacity: 32, MaxRepairBudget: time.Minute, MaxClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal := make(chan struct{})
	t.Cleanup(func() { close(terminal) })
	if err := visibility.Register(credential.ID, volumeserver.CoherenceStrict, terminal, volumeserver.VisibilityCommitment{
		CachedNameCapacity: 16, RepairBudget: time.Second, NamespaceRepair: volumeserver.NamespaceRepairParentExclusive,
	}); err != nil {
		t.Fatal(err)
	}

	store := &resourceAdmissionFaultStore{}
	h := testVolumeHandler()
	h.Store, h.Runtime, h.Visibility = store, runtime, visibility
	root := xfsstore.Capability{0x11}
	handle := xfsstore.Capability{0x52}
	if err := h.startSessionResources(credential.ID, root, 2, [32]byte{}, volumeserver.CoherenceStrict); err != nil {
		t.Fatal(err)
	}
	if err := h.trackOpen(credential.ID, handle, false); err != nil {
		t.Fatal(err)
	}
	identity := [16]byte{handle[0]}
	request := &authoritypb.Request{
		RequestId: 1,
		SourcePublicationGate: &authoritypb.SourcePublicationGate{Targets: []*authoritypb.SourcePublicationTarget{{
			Coordinate: &authoritypb.SourcePublicationTarget_Item{Item: &authoritypb.SourcePublicationItem{
				Identity: identity[:], Attributes: true, Data: true,
			}},
		}}},
		Body: &authoritypb.Request_Fallocate{Fallocate: &authoritypb.FallocateRequest{Handle: handle[:], Length: 1, FileMaxSize: 1 << 20}},
	}
	stampMutation(t, request, 0, 1)
	targets := []volumeserver.VisibilityTarget{{
		Scope: volumeserver.VisibilityData, Identity: identity, KernelIno: 52, Device: 1, Size: 1,
	}}
	response := h.mutateVisible(
		context.Background(), request, credential,
		func() ([]volumeserver.VisibilityTarget, error) { return targets, nil },
		func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
			resp := h.success(0)
			resp.PostState = h.mutationPostState(1, postStateSnapshot{
				identity: identity,
				attr:     xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 52, Size: 1, Mode: 0o600, Nlink: 1, DeviceMinor: 1},
				roles:    postStateRoleTarget,
				changed:  true,
			})
			return resp, targets
		},
	)
	if response.GetErrno() != 0 {
		t.Fatalf("fallocate mutation = %+v", response)
	}
	if calls := store.identityOpen.Load(); calls != 1 {
		t.Fatalf("Fallocate stable identity resolutions = %d, want one pre-enqueue resolution", calls)
	}
}

func TestMutateVisibleNamespaceGateRefreshesBindingAfterDependencyWait(t *testing.T) {
	runtime, err := volumeserver.New("namespace-source-gate-refresh", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 2, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := runtime.AttachActiveForTest(2, volumeserver.PeerIdentity{0x61}, volumeserver.Authorization{
		Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: noopMembership{}, Fencer: noopFencer{},
		MaxCachedNameCapacity: 32, MaxRepairBudget: time.Minute, MaxClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal := make(chan struct{})
	t.Cleanup(func() { close(terminal) })
	if err := visibility.Register(credential.ID, volumeserver.CoherenceStrict, terminal, volumeserver.VisibilityCommitment{
		CachedNameCapacity: 16, RepairBudget: time.Second, NamespaceRepair: volumeserver.NamespaceRepairParentExclusive,
	}); err != nil {
		t.Fatal(err)
	}

	oldBinding := xfsstore.Capability{0x71}
	newBinding := xfsstore.Capability{0x72}
	store := &sourceGateRefreshStore{
		bound: oldBinding, firstLookup: make(chan struct{}), releaseFirst: make(chan struct{}),
		firstForgotten: make(chan struct{}), secondLookup: make(chan struct{}),
	}
	h := testVolumeHandler()
	h.Store, h.Runtime, h.Visibility = store, runtime, visibility
	root := xfsstore.Capability{0x11}
	if err := h.startSessionResources(credential.ID, root, 2, [32]byte{}, volumeserver.CoherenceStrict); err != nil {
		t.Fatal(err)
	}
	parentIdentity := [16]byte{root[0]}
	mutationTargets := []volumeserver.VisibilityTarget{
		{Scope: volumeserver.VisibilityNamespace, ParentIdentity: parentIdentity, ParentKernelIno: 0x11, Device: 1, Name: []byte("child")},
		{Scope: volumeserver.VisibilityAttributes, Identity: parentIdentity, KernelIno: 0x11, Device: 1},
	}

	ownerEntered := make(chan struct{})
	releaseOwner := make(chan struct{})
	ownerResult := make(chan error, 1)
	go func() {
		ownerResult <- visibility.Execute(
			context.Background(), volumeserver.SessionID{0xFE}, volumeserver.MutationID{Sequence: 1},
			volumeserver.MutationDependenciesForTargets(mutationTargets),
			func() ([]volumeserver.VisibilityTarget, error) {
				close(ownerEntered)
				<-releaseOwner
				return mutationTargets, nil
			},
			func() ([]volumeserver.VisibilityTarget, bool) { return nil, false },
		)
	}()
	<-ownerEntered

	request := &authoritypb.Request{
		RequestId: 1,
		SourcePublicationGate: &authoritypb.SourcePublicationGate{Targets: []*authoritypb.SourcePublicationTarget{
			{Coordinate: &authoritypb.SourcePublicationTarget_Item{Item: &authoritypb.SourcePublicationItem{
				Identity: parentIdentity[:], Attributes: true,
			}}},
			{Coordinate: &authoritypb.SourcePublicationTarget_Namespace{Namespace: &authoritypb.SourcePublicationNamespace{
				ParentIdentity: parentIdentity[:], Name: []byte("child"), BoundAttributes: true,
			}}},
		}},
		Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: root[:], Name: []byte("child")}},
	}
	stampMutation(t, request, 0, 1)
	mutationResult := make(chan *authoritypb.Response, 1)
	go func() {
		mutationResult <- h.mutateVisible(
			context.Background(), request, credential,
			func() ([]volumeserver.VisibilityTarget, error) { return mutationTargets, nil },
			func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
				resp := h.success(0)
				resp.PostState = h.mutationPostState(1,
					postStateSnapshot{
						identity: [16]byte{newBinding[0]},
						attr:     xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: uint64(newBinding[0]), Mode: 0o600, Nlink: 0, DeviceMinor: 1},
						roles:    postStateRoleRemoved,
						changed:  true,
					},
					postStateSnapshot{
						identity: parentIdentity,
						attr:     xfsstore.Attr{Kind: xfsstore.KindDirectory, Ino: uint64(root[0]), Mode: 0o755, Nlink: 2, DeviceMinor: 1},
						roles:    postStateRoleParent,
						changed:  true,
					},
				)
				return resp, nil
			},
		)
	}()
	select {
	case <-store.firstLookup:
	case <-time.After(2 * time.Second):
		t.Fatal("namespace binding was not resolved before dependency admission")
	}
	close(store.releaseFirst)
	<-store.firstForgotten
	select {
	case <-store.secondLookup:
		t.Fatal("namespace binding refreshed before the conflicting owner released its key")
	default:
	}
	store.setBound(newBinding)
	close(releaseOwner)
	if err := <-ownerResult; err != nil {
		t.Fatal(err)
	}
	select {
	case <-store.secondLookup:
	case <-time.After(2 * time.Second):
		t.Fatal("namespace binding was not refreshed after its dependency version changed")
	}
	if response := <-mutationResult; response.GetErrno() != 0 {
		t.Fatalf("namespace mutation = %+v", response)
	}
	if calls := store.lookupCalls.Load(); calls != 3 {
		t.Fatalf("namespace binding lookups = %d, want initial declaration plus refreshes before and after dependency requeue", calls)
	}

	newIdentity := [16]byte{newBinding[0]}
	peerTargets := []volumeserver.VisibilityTarget{{
		Scope: volumeserver.VisibilityAttributes, Identity: newIdentity, KernelIno: uint64(newBinding[0]), Device: 1,
	}}
	peerResult := make(chan error, 1)
	go func() {
		peerResult <- visibility.Execute(
			context.Background(), volumeserver.SessionID{0xFD}, volumeserver.MutationID{Sequence: 2},
			volumeserver.MutationDependenciesForTargets(peerTargets),
			func() ([]volumeserver.VisibilityTarget, error) { return peerTargets, nil },
			func() ([]volumeserver.VisibilityTarget, bool) { return peerTargets, true },
		)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prepare, err := visibility.Next(ctx, credential.ID, testInitialVisibilityCursor(t, visibility, credential.ID))
	if err != nil {
		t.Fatalf("refreshed binding was not indexed before the next mutation: %v", err)
	}
	if err := visibility.Ack(credential.ID, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := visibility.Next(ctx, credential.ID, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if err := visibility.Ack(credential.ID, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := <-peerResult; err != nil {
		t.Fatal(err)
	}
}

func TestSourcePublicationResolutionsCoverEveryIdentityReturningMutation(t *testing.T) {
	identity := [16]byte{0xC1}
	exchangedIdentity := [16]byte{0xC2}
	item := &authoritypb.Item{StableIdentity: identity[:]}
	tests := []struct {
		name     string
		request  *authoritypb.Request
		response *authoritypb.Response
		want     []volumeserver.VisibilityResolution
	}{
		{
			name:     "create including existing no-change result",
			request:  &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{}}},
			response: &authoritypb.Response{Body: &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Item: item}}},
			want:     []volumeserver.VisibilityResolution{{Identity: identity}},
		},
		{
			name:     "mkdir",
			request:  &authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{}}},
			response: &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: item}}},
			want:     []volumeserver.VisibilityResolution{{Identity: identity}},
		},
		{
			name:     "symlink",
			request:  &authoritypb.Request{Body: &authoritypb.Request_Symlink{Symlink: &authoritypb.SymlinkRequest{}}},
			response: &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: item}}},
			want:     []volumeserver.VisibilityResolution{{Identity: identity}},
		},
		{
			name:     "link",
			request:  &authoritypb.Request{Body: &authoritypb.Request_Link{Link: &authoritypb.LinkRequest{}}},
			response: &authoritypb.Response{Body: &authoritypb.Response_Link{Link: &authoritypb.LinkReply{Item: item}}},
			want:     []volumeserver.VisibilityResolution{{Identity: identity}},
		},
		{
			name:    "normal rename",
			request: &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{}}},
			response: &authoritypb.Response{Body: &authoritypb.Response_Rename{Rename: &authoritypb.RenameReply{
				NewPostIdentity: identity[:],
			}}},
			want: []volumeserver.VisibilityResolution{{Identity: identity}},
		},
		{
			name:    "normal same-inode hard-link no-op",
			request: &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{}}},
			response: &authoritypb.Response{Body: &authoritypb.Response_Rename{Rename: &authoritypb.RenameReply{
				NewPostIdentity: identity[:], OldPostIdentity: identity[:],
			}}},
			want: []volumeserver.VisibilityResolution{{Identity: identity}},
		},
		{
			name: "exchange rename",
			request: &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{
				Exchange: true,
			}}},
			response: &authoritypb.Response{Body: &authoritypb.Response_Rename{Rename: &authoritypb.RenameReply{
				NewPostIdentity: identity[:], OldPostIdentity: exchangedIdentity[:],
			}}},
			want: []volumeserver.VisibilityResolution{{Identity: identity}, {Identity: exchangedIdentity}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolutions, err := sourcePublicationResolutions(test.request, test.response)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(resolutions, test.want) {
				t.Fatalf("resolutions = %#v, want %#v", resolutions, test.want)
			}
		})
	}

	failed := &authoritypb.Response{Errno: int32(syscall.EEXIST)}
	resolutions, err := sourcePublicationResolutions(tests[0].request, failed)
	if err != nil || resolutions != nil {
		t.Fatalf("failed mutation resolutions = (%#v, %v), want nil", resolutions, err)
	}
	if _, err := sourcePublicationResolutions(tests[0].request, &authoritypb.Response{}); !errors.Is(err, syscall.EIO) {
		t.Fatalf("successful identity-returning response without item = %v, want EIO", err)
	}

	malformedRenames := []struct {
		name     string
		request  *authoritypb.Request
		response *authoritypb.Response
	}{
		{
			name:     "normal missing new identity",
			request:  &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{}}},
			response: &authoritypb.Response{Body: &authoritypb.Response_Rename{Rename: &authoritypb.RenameReply{}}},
		},
		{
			name:    "normal mismatched old identity",
			request: &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{}}},
			response: &authoritypb.Response{Body: &authoritypb.Response_Rename{Rename: &authoritypb.RenameReply{
				NewPostIdentity: identity[:], OldPostIdentity: exchangedIdentity[:],
			}}},
		},
		{
			name:    "exchange missing old identity",
			request: &authoritypb.Request{Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{Exchange: true}}},
			response: &authoritypb.Response{Body: &authoritypb.Response_Rename{Rename: &authoritypb.RenameReply{
				NewPostIdentity: identity[:],
			}}},
		},
	}
	for _, test := range malformedRenames {
		t.Run(test.name, func(t *testing.T) {
			if _, err := sourcePublicationResolutions(test.request, test.response); !errors.Is(err, syscall.EIO) {
				t.Fatalf("malformed rename publication = %v, want EIO", err)
			}
		})
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
	cred, err := runtime.AttachActiveForTest(2, peer, volumeserver.Authorization{
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
	routes := &RoutesController{Visibility: visibility, loaded: true, revision: routesRevisionOf("")}
	h := &VolumeHandler{
		Store: store, Runtime: runtime, Authorizer: allowAuthorizer{volumeserver.AccessRead | volumeserver.AccessWrite}, Routes: routes, Visibility: visibility,
		MaxFrame: 1 << 20, MaxRead: 1 << 16, MaxWrite: 1 << 16, MaxInFlight: 8,
		MaxItemsPerSession: maxItems, MaxOpensPerSession: maxOpens,
		MaxItems: maxItems, MaxOpens: maxOpens, MaxRetainedReplyBytes: 1 << 20,
	}
	root := xfsstore.Capability{0x72}
	if err := h.startSessionResources(cred.ID, root, 2, routesRevisionOf("")); err != nil {
		t.Fatal(err)
	}
	terminal, err := runtime.SessionTerminal(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := visibility.Register(cred.ID, volumeserver.CoherenceStrict, terminal, volumeserver.VisibilityCommitment{
		CachedNameCapacity: 16, RepairBudget: time.Second, NamespaceRepair: volumeserver.NamespaceRepairParentExclusive,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.FenceSession(cred.ID) })
	ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte(peer))
	return h, ctx, cred, root
}

func renameReplyRequest(
	t *testing.T,
	cred volumeserver.SessionCredential,
	root xfsstore.Capability,
	exchange bool,
) *authoritypb.Request {
	t.Helper()
	parentIdentity := [16]byte{root[0]}
	request := &authoritypb.Request{
		RequestId: 1,
		Epoch:     cred.Epoch[:],
		Session: &authoritypb.SessionProof{
			Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:],
		},
		FrontendOperationId: 1,
		SourcePublicationGate: &authoritypb.SourcePublicationGate{Targets: []*authoritypb.SourcePublicationTarget{
			{Coordinate: &authoritypb.SourcePublicationTarget_Item{Item: &authoritypb.SourcePublicationItem{
				Identity: parentIdentity[:], Attributes: true,
			}}},
			{Coordinate: &authoritypb.SourcePublicationTarget_Namespace{Namespace: &authoritypb.SourcePublicationNamespace{
				ParentIdentity: parentIdentity[:], Name: []byte("new"), BoundAttributes: true,
			}}},
			{Coordinate: &authoritypb.SourcePublicationTarget_Namespace{Namespace: &authoritypb.SourcePublicationNamespace{
				ParentIdentity: parentIdentity[:], Name: []byte("old"), BoundAttributes: true,
			}}},
		}},
		Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{
			OldParent: root[:], OldName: []byte("old"), NewParent: root[:], NewName: []byte("new"), Exchange: exchange,
		}},
	}
	stampMutation(t, request, 0, 1)
	return request
}

func TestRenameReplyUsesAuthoritativePostBindingAndReplaysWithoutXFS(t *testing.T) {
	moved := xfsstore.Capability{0xA1}
	store := &renameReplyStore{bindings: map[string]xfsstore.Capability{"old": moved}}
	h, ctx, cred, root := resourceAdmissionRequestHarness(t, store, 4, 2)
	request := renameReplyRequest(t, cred, root, false)

	first := h.Handle(ctx, request)
	if first.GetErrno() != 0 || first.GetUncertain() {
		t.Fatalf("Rename = %+v, want definite success", first)
	}
	want := [16]byte{moved[0]}
	if rename := first.GetRename(); rename == nil || !bytes.Equal(rename.GetNewPostIdentity(), want[:]) || len(rename.GetOldPostIdentity()) != 0 {
		t.Fatalf("Rename reply = %+v, want authoritative new identity %x and no old identity", rename, want)
	}
	if calls := store.renameCalls.Load(); calls != 1 {
		t.Fatalf("Rename calls = %d, want one", calls)
	}
	if calls := store.lookup.Load(); calls != 3 {
		t.Fatalf("Rename namespace lookups = %d, want two dependency resolutions plus one locked post-state capability lookup", calls)
	}

	// Request ID is delivery correlation, not replay identity. A lost DATA
	// response must reproduce the authoritative binding without a second XFS
	// rename or any source-side name-cache inference.
	replay := proto.Clone(request).(*authoritypb.Request)
	replay.RequestId = 2
	second := h.Handle(ctx, replay)
	if second.GetErrno() != 0 || !proto.Equal(first.GetRename(), second.GetRename()) {
		t.Fatalf("Rename replay = %+v, first = %+v", second, first)
	}
	if calls := store.renameCalls.Load(); calls != 1 {
		t.Fatalf("exact Rename replay re-executed XFS: calls = %d", calls)
	}
	if calls := store.lookup.Load(); calls != 3 {
		t.Fatalf("exact Rename replay re-resolved namespace: lookups = %d", calls)
	}
}

func TestRenameExchangeReplyCarriesBothAuthoritativePostBindings(t *testing.T) {
	moved := xfsstore.Capability{0xB1}
	replaced := xfsstore.Capability{0xB2}
	store := &renameReplyStore{bindings: map[string]xfsstore.Capability{"old": moved, "new": replaced}}
	h, ctx, cred, root := resourceAdmissionRequestHarness(t, store, 4, 2)
	response := h.Handle(ctx, renameReplyRequest(t, cred, root, true))
	if response.GetErrno() != 0 || response.GetUncertain() {
		t.Fatalf("Rename exchange = %+v, want definite success", response)
	}
	wantNew, wantOld := [16]byte{moved[0]}, [16]byte{replaced[0]}
	rename := response.GetRename()
	if rename == nil || !bytes.Equal(rename.GetNewPostIdentity(), wantNew[:]) || !bytes.Equal(rename.GetOldPostIdentity(), wantOld[:]) {
		t.Fatalf("Rename exchange reply = %+v, want new=%x old=%x", rename, wantNew, wantOld)
	}
	if calls := store.lookup.Load(); calls != 4 {
		t.Fatalf("Rename exchange namespace lookups = %d, want two dependency resolutions plus two locked post-state capability lookups", calls)
	}
}

func TestRenameSameInodeNoOpReportsBothNamesAndReplaysExactly(t *testing.T) {
	shared := xfsstore.Capability{0xB3}
	store := &renameReplyStore{bindings: map[string]xfsstore.Capability{"old": shared, "new": shared}}
	h, ctx, cred, root := resourceAdmissionRequestHarness(t, store, 4, 2)
	request := renameReplyRequest(t, cred, root, false)
	response := h.Handle(ctx, request)
	if response.GetErrno() != 0 || response.GetUncertain() {
		t.Fatalf("same-inode Rename = %+v, want definite no-op success", response)
	}
	want := [16]byte{shared[0]}
	rename := response.GetRename()
	if rename == nil || !bytes.Equal(rename.GetNewPostIdentity(), want[:]) || !bytes.Equal(rename.GetOldPostIdentity(), want[:]) {
		t.Fatalf("same-inode Rename reply = %+v, want both names bound to %x", rename, want)
	}
	resolutions, err := sourcePublicationResolutions(request, response)
	if err != nil {
		t.Fatal(err)
	}
	wantResolutions := []volumeserver.VisibilityResolution{{Identity: want}}
	if !reflect.DeepEqual(resolutions, wantResolutions) {
		t.Fatalf("same-inode resolutions = %#v, want %#v", resolutions, wantResolutions)
	}

	replay := proto.Clone(request).(*authoritypb.Request)
	replay.RequestId = 2
	second := h.Handle(ctx, replay)
	if second.GetErrno() != 0 || !proto.Equal(rename, second.GetRename()) {
		t.Fatalf("same-inode Rename replay = %+v, first = %+v", second, response)
	}
	if calls := store.renameCalls.Load(); calls != 1 {
		t.Fatalf("same-inode exact replay re-executed XFS: calls = %d", calls)
	}
	if calls := store.lookup.Load(); calls != 3 {
		t.Fatalf("same-inode Rename namespace lookups = %d, want two dependency resolutions plus one locked moved-object snapshot lookup", calls)
	}
}

func TestHandlerExportsFsyncBatchEffectiveness(t *testing.T) {
	store := &fsyncMetricStore{batch: 3}
	h, ctx, cred, _ := resourceAdmissionRequestHarness(t, store, 1, 1)
	metrics, err := authoritymetrics.New("fsync-metrics")
	if err != nil {
		t.Fatal(err)
	}
	h.Metrics = metrics
	handle := xfsstore.Capability{0xA5}
	if err := h.trackOpen(cred.ID, handle, false); err != nil {
		t.Fatal(err)
	}
	response := h.Handle(ctx, &authoritypb.Request{
		RequestId: 1, Epoch: cred.Epoch[:],
		Session: &authoritypb.SessionProof{Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:]},
		Body:    &authoritypb.Request_Fsync{Fsync: &authoritypb.FsyncRequest{Handle: handle[:]}},
	})
	if response.GetErrno() != 0 {
		t.Fatalf("Fsync = %+v", response)
	}
	var rendered bytes.Buffer
	if err := metrics.Registry().WritePrometheus(&rendered); err != nil {
		t.Fatal(err)
	}
	for _, sample := range []string{
		`portablefs_authority_fsync_barrier_handles_total{volume="fsync-metrics"} 3`,
		`portablefs_authority_fsync_storage_syncs_total{volume="fsync-metrics"} 1`,
	} {
		if !bytes.Contains(rendered.Bytes(), []byte(sample+"\n")) {
			t.Errorf("metrics omit %q", sample)
		}
	}
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
	if operation != "open" {
		parentIdentity := [16]byte{root[0]}
		name := []byte("capacity-" + operation)
		request.FrontendOperationId = 1
		request.SourcePublicationGate = &authoritypb.SourcePublicationGate{Targets: []*authoritypb.SourcePublicationTarget{
			{Coordinate: &authoritypb.SourcePublicationTarget_Item{Item: &authoritypb.SourcePublicationItem{
				Identity: parentIdentity[:], Attributes: true,
			}}},
			{Coordinate: &authoritypb.SourcePublicationTarget_Namespace{Namespace: &authoritypb.SourcePublicationNamespace{
				ParentIdentity: parentIdentity[:], Name: name, BoundAttributes: true,
			}}},
		}}
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
			if response.GetErrno() != errnos.ENFILE || response.GetUncertain() {
				t.Fatalf("capacity response=%+v, want definite ENFILE", response)
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
	cred, err := runtime.AttachActiveForTest(2, volumeserver.PeerIdentity{1}, volumeserver.Authorization{Access: volumeserver.AccessRead, Deadline: now.Add(time.Hour)})
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

func testAttachAttempt(id uint64) []byte {
	attempt := make([]byte, len(volumeserver.AttachAttemptID{}))
	for index := range 8 {
		attempt[index] = byte(id >> (8 * index))
	}
	if id == 0 {
		attempt[0] = 1
	}
	return attempt
}

// attachAndActivateHandler drives the protocol-5 lifecycle directly at the
// handler boundary. Transport-registry tests separately prove that the two
// nonzero binding generations came from the exact DATA/CONTROL pair.
func attachAndActivateHandler(
	t *testing.T,
	h *VolumeHandler,
	ctx context.Context,
	requestID uint64,
	request *authoritypb.AttachRequest,
) (*authoritypb.ActivateReply, []byte, *authoritypb.SessionProof) {
	t.Helper()
	if len(request.GetAttachAttemptId()) == 0 {
		request.AttachAttemptId = testAttachAttempt(requestID)
	}
	attached := h.Handle(ctx, &authoritypb.Request{
		RequestId: requestID,
		Body:      &authoritypb.Request_Attach{Attach: request},
	})
	if attached.GetErrno() != 0 || attached.GetAttach() == nil {
		t.Fatalf("provisional attach = %v", attached)
	}
	proof := &authoritypb.SessionProof{
		Id: attached.GetAttach().GetSessionId(), Generation: attached.GetAttach().GetGeneration(),
		ResumeSecret: attached.GetAttach().GetResumeSecret(),
	}
	activated := h.Handle(ctx, &authoritypb.Request{
		RequestId: requestID + 1, Epoch: attached.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{
			AttachAttemptId: request.GetAttachAttemptId(), DataBindingGeneration: 1, ControlBindingGeneration: 1,
		}},
	})
	if activated.GetErrno() != 0 || activated.GetActivate() == nil {
		t.Fatalf("activate = %v", activated)
	}
	return activated.GetActivate(), attached.GetEpoch(), proof
}

type countingAuthorizer struct {
	mu       sync.Mutex
	calls    int
	deadline time.Time
	access   volumeserver.Access
	entered  chan struct{}
	release  chan struct{}
}

type provisionalReauthorizer struct {
	*countingAuthorizer
	calls atomic.Uint32
}

func (a *provisionalReauthorizer) Reauthorize(context.Context, string, volumeserver.SessionID, uint64, []byte) (volumeserver.Authorization, [32]byte, error) {
	a.calls.Add(1)
	return volumeserver.Authorization{}, [32]byte{1}, errors.New("provisional reauthorization reached verifier")
}

type failingActivationMembership struct {
	err   error
	calls atomic.Uint32
}

func (m *failingActivationMembership) Activate(volumeserver.SessionID) error {
	m.calls.Add(1)
	return m.err
}

func (*failingActivationMembership) Deactivate(volumeserver.SessionID) error { return nil }

type blockingActivationMembership struct {
	active    atomic.Bool
	activated chan struct{}
	release   chan struct{}
}

func (m *blockingActivationMembership) Activate(volumeserver.SessionID) error {
	m.active.Store(true)
	if m.activated != nil {
		close(m.activated)
	}
	if m.release != nil {
		<-m.release
	}
	return nil
}

func (m *blockingActivationMembership) Deactivate(volumeserver.SessionID) error {
	m.active.Store(false)
	return nil
}

// blockingActivationRootStore lets a test stop the fresh root read at the
// activation transaction's registration boundary. Attach itself must not read
// these attributes: they are a cache fact whose freshness is meaningful only
// when the strict participant becomes visible to mutations.
type blockingActivationRootStore struct {
	*resourceAdmissionFaultStore
	attr     xfsstore.Attr
	identity [16]byte
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
	reads    atomic.Uint32
}

func (s *blockingActivationRootStore) Getattr(xfsstore.Capability) (xfsstore.Attr, error) {
	s.reads.Add(1)
	s.once.Do(func() {
		close(s.entered)
		<-s.release
	})
	return s.attr, nil
}

func (s *blockingActivationRootStore) Identity(xfsstore.Capability) ([16]byte, error) {
	return s.identity, nil
}

type failingActivationRootStore struct {
	*resourceAdmissionFaultStore
	fail atomic.Bool
}

func (s *failingActivationRootStore) Getattr(item xfsstore.Capability) (xfsstore.Attr, error) {
	if s.fail.Load() {
		return xfsstore.Attr{}, syscall.EAGAIN
	}
	return s.resourceAdmissionFaultStore.Getattr(item)
}

func (a *countingAuthorizer) Authorize(ctx context.Context, _ string, _ []byte) (volumeserver.Authorization, error) {
	a.mu.Lock()
	a.calls++
	entered, release := a.entered, a.release
	a.mu.Unlock()
	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return volumeserver.Authorization{}, ctx.Err()
		}
	}
	return volumeserver.Authorization{Access: a.access, Deadline: a.deadline}, nil
}

func (a *countingAuthorizer) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

func newProtocol5Handler(t *testing.T, membership volumeserver.DurableVisibilityMembership) (*VolumeHandler, context.Context, *countingAuthorizer, *RoutesController) {
	t.Helper()
	runtime, err := volumeserver.New("handler-protocol-5", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 8, MaxSessions: 8, MaxLockRecords: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if membership == nil {
		membership = noopMembership{}
	}
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: membership, Fencer: runtime,
		MaxCachedNameCapacity: 1024, MaxRepairBudget: time.Minute, MaxClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	routes := &RoutesController{Visibility: visibility, loaded: true, revision: routesRevisionOf("")}
	authorizer := &countingAuthorizer{
		access:   volumeserver.AccessRead | volumeserver.AccessWrite,
		deadline: time.Now().Add(time.Hour).Round(0),
	}
	h := testVolumeHandler()
	h.Store, h.Runtime, h.Authorizer, h.Routes, h.Visibility = &resourceAdmissionFaultStore{}, runtime, authorizer, routes, visibility
	ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte{0xA5})
	return h, ctx, authorizer, routes
}

func protocol5AttachRequest(id uint64) *authoritypb.Request {
	attach := &authoritypb.AttachRequest{
		VolumeId: "handler-protocol-5", AccessToken: []byte("one-use"), ReplaySlots: 2,
		RoutesRevision: emptyRoutesRevision(), AttachAttemptId: testAttachAttempt(id),
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 64, RepairBudgetMillis: 1000,
		NamespaceRepair: authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION,
	}
	return &authoritypb.Request{RequestId: id, Body: &authoritypb.Request_Attach{Attach: attach}}
}

func proofFromAttach(response *authoritypb.Response) *authoritypb.SessionProof {
	attach := response.GetAttach()
	return &authoritypb.SessionProof{Id: attach.GetSessionId(), Generation: attach.GetGeneration(), ResumeSecret: attach.GetResumeSecret()}
}

func prepareProtocol5ResourceSpec(t *testing.T, h *VolumeHandler, discriminator byte) (sessionResourceSpec, <-chan struct{}) {
	t.Helper()
	attempt := volumeserver.AttachAttemptID{discriminator}
	deadline := time.Now().Add(time.Hour).Round(0)
	peer := volumeserver.PeerIdentity{0xA5}
	credential, err := h.Runtime.PrepareAttach(
		context.Background(), attempt, volumeserver.AttachRequestFingerprint{discriminator}, 2, peer,
		func(context.Context) (volumeserver.Authorization, error) {
			return volumeserver.Authorization{Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: deadline}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := h.Runtime.SessionTerminal(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	return sessionResourceSpec{
		credential: credential, id: credential.ID, attempt: attempt,
		root: xfsstore.Capability{0x70}, slots: 2, routes: routesRevisionOf(""),
		coherence: volumeserver.CoherenceStrict, authorizationDeadline: deadline,
	}, terminal
}

func TestProtocol5ResourceInstallReconcilesRuntimeEndBeforeAndAfterPublication(t *testing.T) {
	t.Run("terminal-before-install", func(t *testing.T) {
		h, _, _, _ := newProtocol5Handler(t, nil)
		h.cleanupOnce.Do(func() { h.Runtime.OnSessionEnd(h.closeSessionResources) })
		spec, terminal := prepareProtocol5ResourceSpec(t, h, 0x21)

		// Hold the publication lock while the runtime becomes terminal. Both
		// possible schedules after release are intentional: either the end hook
		// observes no record and install reconciles the terminal runtime, or
		// install publishes first and the hook removes that exact record.
		h.resourcesMu.Lock()
		installed := make(chan error, 1)
		go func() {
			_, err := h.ensureProvisionalSessionResources(spec)
			installed <- err
		}()
		fenced := make(chan struct{})
		go func() {
			h.Runtime.FenceSession(spec.id)
			close(fenced)
		}()
		select {
		case <-terminal:
		case <-time.After(time.Second):
			h.resourcesMu.Unlock()
			t.Fatal("runtime did not publish terminal state")
		}
		h.resourcesMu.Unlock()
		select {
		case err := <-installed:
			if err == nil {
				t.Fatal("resource install accepted a terminal runtime session")
			}
		case <-time.After(time.Second):
			t.Fatal("resource install did not reconcile terminal runtime state")
		}
		select {
		case <-fenced:
		case <-time.After(time.Second):
			t.Fatal("runtime end hook did not complete")
		}
		h.resourcesMu.Lock()
		remaining := h.resources[spec.id]
		h.resourcesMu.Unlock()
		if remaining != nil {
			t.Fatal("terminal-before-install race leaked session resources")
		}
	})

	t.Run("terminal-after-install", func(t *testing.T) {
		h, _, _, _ := newProtocol5Handler(t, nil)
		h.cleanupOnce.Do(func() { h.Runtime.OnSessionEnd(h.closeSessionResources) })
		spec, _ := prepareProtocol5ResourceSpec(t, h, 0x22)
		resources, err := h.ensureProvisionalSessionResources(spec)
		if err != nil {
			t.Fatal(err)
		}
		h.Runtime.FenceSession(spec.id)
		h.resourcesMu.Lock()
		remaining := h.resources[spec.id]
		ended := resources.ended
		h.resourcesMu.Unlock()
		if remaining != nil || !ended {
			t.Fatalf("terminal-after-install cleanup left record=%p ended=%v", remaining, ended)
		}
	})
}

func TestProtocol5AttachRequiresNonzeroExactAttemptID(t *testing.T) {
	for name, attempt := range map[string][]byte{
		"absent": nil,
		"short":  make([]byte, 31),
		"long":   make([]byte, 33),
		"zero":   make([]byte, 32),
	} {
		t.Run(name, func(t *testing.T) {
			h, ctx, authorizer, _ := newProtocol5Handler(t, nil)
			request := protocol5AttachRequest(31)
			request.GetAttach().AttachAttemptId = attempt
			response := h.Handle(ctx, request)
			if response.GetErrno() != errnos.EINVAL || authorizer.count() != 0 {
				t.Fatalf("Attach = %+v, authorization calls=%d; want EINVAL before authorization", response, authorizer.count())
			}
		})
	}
}

func TestProtocol5AttachRejectsOmittedRetiredCoherenceProfileBeforeAuthorization(t *testing.T) {
	h, ctx, authorizer, _ := newProtocol5Handler(t, nil)
	request := protocol5AttachRequest(32)
	request.GetAttach().CoherenceProfile = authoritypb.CoherenceProfile_COHERENCE_PROFILE_UNSPECIFIED
	response := h.Handle(ctx, request)
	if response.GetErrno() != errnos.EINVAL || authorizer.count() != 0 {
		t.Fatalf("Attach = %+v, authorization calls=%d; want EINVAL before authorization", response, authorizer.count())
	}
}

func TestProtocol5AttachIsExactProvisionalAndConcurrent(t *testing.T) {
	h, ctx, authorizer, _ := newProtocol5Handler(t, nil)
	authorizer.entered = make(chan struct{}, 1)
	authorizer.release = make(chan struct{})
	request := protocol5AttachRequest(41)
	responses := make(chan *authoritypb.Response, 2)
	for range 2 {
		go func() { responses <- h.Handle(ctx, proto.Clone(request).(*authoritypb.Request)) }()
	}
	select {
	case <-authorizer.entered:
	case <-time.After(time.Second):
		t.Fatal("Attach did not reach authorization")
	}
	close(authorizer.release)
	first, second := <-responses, <-responses
	for _, response := range []*authoritypb.Response{first, second} {
		if response.GetErrno() != 0 || response.GetAttach() == nil || response.GetAttach().GetProvisionalDeadlineUnixNanos() <= 0 {
			t.Fatalf("provisional response = %+v", response)
		}
	}
	if authorizer.count() != 1 {
		t.Fatalf("concurrent exact Attach authorized %d times, want one", authorizer.count())
	}
	if !proto.Equal(first.GetAttach(), second.GetAttach()) {
		t.Fatalf("exact Attach results differ: first=%+v second=%+v", first, second)
	}
	if resources := h.resources; len(resources) != 1 {
		t.Fatalf("exact Attach initialized %d resource records, want one", len(resources))
	}
	exactRetry := proto.Clone(request).(*authoritypb.Request)
	exactRetry.RequestId = 42
	retried := h.Handle(ctx, exactRetry)
	if retried.GetErrno() != 0 || !proto.Equal(first.GetAttach(), retried.GetAttach()) || authorizer.count() != 1 {
		t.Fatalf("exact Attach with new envelope = %+v, authorization calls=%d", retried, authorizer.count())
	}

	// Same attempt plus changed canonical body cannot consume authorization or
	// silently inherit the first attempt's session.
	changed := proto.Clone(request).(*authoritypb.Request)
	changed.RequestId = 43
	changed.GetAttach().ReplaySlots = 3
	response := h.Handle(ctx, changed)
	if response.GetErrno() != errnos.EINVAL || authorizer.count() != 1 {
		t.Fatalf("altered Attach = %+v, authorization calls=%d", response, authorizer.count())
	}

	proof := proofFromAttach(first)
	ordinary := h.Handle(ctx, &authoritypb.Request{
		RequestId: 44, Epoch: first.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_StatFs{StatFs: &authoritypb.StatFSRequest{}},
	})
	if ordinary.GetErrno() != errnos.EAGAIN {
		t.Fatalf("ordinary provisional request = %+v, want EAGAIN", ordinary)
	}
	keepAlive := h.Handle(ctx, &authoritypb.Request{
		RequestId: 45, Epoch: first.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}},
	})
	if keepAlive.GetErrno() != errnos.EAGAIN {
		t.Fatalf("provisional KeepAlive = %+v, want EAGAIN", keepAlive)
	}
	verifier := &provisionalReauthorizer{countingAuthorizer: authorizer}
	h.Authorizer = verifier
	reauthorize := h.Handle(ctx, &authoritypb.Request{
		RequestId: 46, Epoch: first.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_Reauthorize{Reauthorize: &authoritypb.ReauthorizeRequest{
			Sequence: 1, AccessToken: []byte("must-not-be-consumed"),
		}},
	})
	if reauthorize.GetErrno() != errnos.EAGAIN || verifier.calls.Load() != 0 {
		t.Fatalf("provisional Reauthorize = %+v, verifier calls=%d; want gated EAGAIN", reauthorize, verifier.calls.Load())
	}
	resumed := h.Handle(ctx, &authoritypb.Request{
		RequestId: 47, Epoch: first.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}},
	})
	if resumed.GetErrno() != 0 || resumed.GetResume().GetState() != authoritypb.SessionState_SESSION_STATE_PROVISIONAL {
		t.Fatalf("provisional Resume = %+v", resumed)
	}
	activated := h.Handle(ctx, &authoritypb.Request{
		RequestId: 48, Epoch: first.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{
			AttachAttemptId: request.GetAttach().GetAttachAttemptId(), DataBindingGeneration: 1, ControlBindingGeneration: 1,
		}},
	})
	if activated.GetErrno() != 0 || activated.GetActivate().GetAuthorizationDeadlineUnixNanos() != authorizer.deadline.UnixNano() {
		t.Fatalf("activation after concurrent Attach = %+v, want authoritative deadline %d", activated, authorizer.deadline.UnixNano())
	}
}

func TestProtocol5ActivateRetainsExactReplyAndRejectsAbortAfterCommit(t *testing.T) {
	h, ctx, authorizer, routes := newProtocol5Handler(t, nil)
	request := protocol5AttachRequest(51)
	attached := h.Handle(ctx, request)
	if attached.GetErrno() != 0 {
		t.Fatalf("Attach = %+v", attached)
	}
	proof := proofFromAttach(attached)
	activate := &authoritypb.Request{
		RequestId: 52, Epoch: attached.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{
			AttachAttemptId: request.GetAttach().GetAttachAttemptId(), DataBindingGeneration: 7, ControlBindingGeneration: 9,
		}},
	}
	first := h.Handle(ctx, activate)
	if first.GetErrno() != 0 || first.GetActivate().GetState() != authoritypb.SessionState_SESSION_STATE_ACTIVE || first.GetActivate().GetRoot() == nil {
		t.Fatalf("Activate = %+v", first)
	}
	if first.GetActivate().GetAuthorizationDeadlineUnixNanos() != authorizer.deadline.UnixNano() {
		t.Fatalf("activation deadline = %d, want %d", first.GetActivate().GetAuthorizationDeadlineUnixNanos(), authorizer.deadline.UnixNano())
	}
	// An exact replay is recovery of the committed transaction, not a new
	// admission decision. It must survive a later route revision and reproduce
	// the exact cursor/root reply the lost response carried.
	routes.mu.Lock()
	routes.revision = routesRevisionOf("later\n")
	routes.canonical = []byte("later\n")
	routes.mu.Unlock()
	replay := proto.Clone(activate).(*authoritypb.Request)
	replay.RequestId = 53
	second := h.Handle(ctx, replay)
	if second.GetErrno() != 0 || !proto.Equal(first.GetActivate(), second.GetActivate()) {
		t.Fatalf("lost-response Activate replay = %+v, first=%+v", second, first)
	}
	resumed := h.Handle(ctx, &authoritypb.Request{
		RequestId: 54, Epoch: attached.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}},
	})
	if resumed.GetErrno() != 0 || resumed.GetResume().GetState() != authoritypb.SessionState_SESSION_STATE_ACTIVE {
		t.Fatalf("active Resume = %+v", resumed)
	}
	abort := h.Handle(ctx, &authoritypb.Request{
		RequestId: 55, Epoch: attached.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_AbortAttach{AbortAttach: &authoritypb.AbortAttachRequest{AttachAttemptId: request.GetAttach().GetAttachAttemptId()}},
	})
	if abort.GetErrno() != errnos.EBUSY {
		t.Fatalf("Abort after activation = %+v, want EBUSY", abort)
	}
}

func TestProtocol5AbortIsIdempotent(t *testing.T) {
	h, ctx, _, _ := newProtocol5Handler(t, nil)
	request := protocol5AttachRequest(61)
	attached := h.Handle(ctx, request)
	if attached.GetErrno() != 0 {
		t.Fatalf("Attach = %+v", attached)
	}
	proof := proofFromAttach(attached)
	abortRequest := &authoritypb.Request{
		RequestId: 62, Epoch: attached.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_AbortAttach{AbortAttach: &authoritypb.AbortAttachRequest{AttachAttemptId: request.GetAttach().GetAttachAttemptId()}},
	}
	for id := uint64(62); id <= 63; id++ {
		attempt := proto.Clone(abortRequest).(*authoritypb.Request)
		attempt.RequestId = id
		response := h.Handle(ctx, attempt)
		if response.GetErrno() != 0 || response.GetAbortAttach().GetState() != authoritypb.SessionState_SESSION_STATE_ABORTED {
			t.Fatalf("Abort attempt %d = %+v", id, response)
		}
	}
}

func TestProtocol5ActivationFailureLeavesSessionProvisional(t *testing.T) {
	membership := &failingActivationMembership{err: errors.New("durable membership unavailable")}
	h, ctx, _, _ := newProtocol5Handler(t, membership)
	request := protocol5AttachRequest(71)
	attached := h.Handle(ctx, request)
	if attached.GetErrno() != 0 {
		t.Fatalf("Attach = %+v", attached)
	}
	proof := proofFromAttach(attached)
	activateRequest := &authoritypb.Request{
		RequestId: 72, Epoch: attached.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{
			AttachAttemptId: request.GetAttach().GetAttachAttemptId(), DataBindingGeneration: 1, ControlBindingGeneration: 1,
		}},
	}
	first := h.Handle(ctx, activateRequest)
	if first.GetErrno() == 0 || first.GetActivate() != nil {
		t.Fatalf("membership failure activated session: %+v", first)
	}
	resumed := h.Handle(ctx, &authoritypb.Request{
		RequestId: 73, Epoch: attached.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}},
	})
	if resumed.GetErrno() != 0 || resumed.GetResume().GetState() != authoritypb.SessionState_SESSION_STATE_PROVISIONAL {
		t.Fatalf("failed activation state = %+v, want PROVISIONAL", resumed)
	}
	if resources := h.resources; len(resources) != 1 {
		t.Fatalf("failed activation changed resource count to %d", len(resources))
	}
	second := h.Handle(ctx, proto.Clone(activateRequest).(*authoritypb.Request))
	if second.GetErrno() == 0 || membership.calls.Load() != 2 {
		t.Fatalf("activation retry = %+v, durable calls=%d", second, membership.calls.Load())
	}
}

func TestProtocol5RootPreparationFailureRollsBackAndCanRetry(t *testing.T) {
	membership := &blockingActivationMembership{}
	h, ctx, _, _ := newProtocol5Handler(t, membership)
	store := &failingActivationRootStore{resourceAdmissionFaultStore: &resourceAdmissionFaultStore{}}
	store.fail.Store(true)
	h.Store = store
	request := protocol5AttachRequest(76)
	attached := h.Handle(ctx, request)
	if attached.GetErrno() != 0 {
		t.Fatalf("Attach = %+v", attached)
	}
	proof := proofFromAttach(attached)
	activateRequest := &authoritypb.Request{
		RequestId: 77, Epoch: attached.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{
			AttachAttemptId: request.GetAttach().GetAttachAttemptId(), DataBindingGeneration: 1, ControlBindingGeneration: 1,
		}},
	}
	failed := h.Handle(ctx, activateRequest)
	if failed.GetErrno() != errnos.EAGAIN || membership.active.Load() {
		t.Fatalf("root-preparation failure = %+v membership-active=%v", failed, membership.active.Load())
	}
	state := h.Handle(ctx, &authoritypb.Request{
		RequestId: 78, Epoch: attached.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}},
	})
	if state.GetErrno() != 0 || state.GetResume().GetState() != authoritypb.SessionState_SESSION_STATE_PROVISIONAL {
		t.Fatalf("state after root-preparation rollback = %+v", state)
	}
	store.fail.Store(false)
	retry := proto.Clone(activateRequest).(*authoritypb.Request)
	retry.RequestId = 79
	activated := h.Handle(ctx, retry)
	if activated.GetErrno() != 0 || activated.GetActivate().GetState() != authoritypb.SessionState_SESSION_STATE_ACTIVE || !membership.active.Load() {
		t.Fatalf("activation retry = %+v membership-active=%v", activated, membership.active.Load())
	}
}

func TestProtocol5ActivationRevalidatesRouteRevision(t *testing.T) {
	h, ctx, _, routes := newProtocol5Handler(t, nil)
	request := protocol5AttachRequest(81)
	attached := h.Handle(ctx, request)
	if attached.GetErrno() != 0 {
		t.Fatalf("Attach = %+v", attached)
	}
	proof := proofFromAttach(attached)
	// Simulate the commit point of a route change between provisional Attach and
	// Activate. RoutesController's writer owns this mutation in production.
	routes.mu.Lock()
	routes.revision = routesRevisionOf("target\n")
	routes.canonical = []byte("target\n")
	routes.mu.Unlock()
	response := h.Handle(ctx, &authoritypb.Request{
		RequestId: 82, Epoch: attached.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{
			AttachAttemptId: request.GetAttach().GetAttachAttemptId(), DataBindingGeneration: 1, ControlBindingGeneration: 1,
		}},
	})
	if response.GetErrno() != errnos.EPERM || response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_ROUTES {
		t.Fatalf("activation after route switch = %+v, want route refusal", response)
	}
	state := h.Handle(ctx, &authoritypb.Request{
		RequestId: 83, Epoch: attached.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}},
	})
	if state.GetErrno() != 0 || state.GetResume().GetState() != authoritypb.SessionState_SESSION_STATE_PROVISIONAL {
		t.Fatalf("route-refused activation state = %+v", state)
	}
}

func TestProtocol5ReplyPrecommitFailureRollsBackMembershipAndRuntime(t *testing.T) {
	membership := &blockingActivationMembership{activated: make(chan struct{}), release: make(chan struct{})}
	h, ctx, _, _ := newProtocol5Handler(t, membership)
	request := protocol5AttachRequest(91)
	attached := h.Handle(ctx, request)
	if attached.GetErrno() != 0 {
		t.Fatalf("Attach = %+v", attached)
	}
	proof := proofFromAttach(attached)
	var id volumeserver.SessionID
	copy(id[:], proof.GetId())
	activate := &authoritypb.Request{
		RequestId: 92, Epoch: attached.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{
			AttachAttemptId: request.GetAttach().GetAttachAttemptId(), DataBindingGeneration: 1, ControlBindingGeneration: 1,
		}},
	}
	done := make(chan *authoritypb.Response, 1)
	go func() { done <- h.Handle(ctx, activate) }()
	select {
	case <-membership.activated:
	case <-time.After(time.Second):
		t.Fatal("activation did not write durable membership")
	}
	h.resourcesMu.Lock()
	resources := h.resources[id]
	// Simulate the only handler-side precommit refusal: resource ownership was
	// invalidated after preparation. ActivateParticipant must roll back its just
	// written durable record and the runtime token must be cancelled.
	resources.ended = true
	h.resourcesMu.Unlock()
	close(membership.release)
	response := <-done
	if response.GetErrno() == 0 || membership.active.Load() {
		t.Fatalf("precommit failure = %+v membership-active=%v", response, membership.active.Load())
	}
	var attempt volumeserver.AttachAttemptID
	copy(attempt[:], request.GetAttach().GetAttachAttemptId())
	cred, err := h.credential(ctx, &authoritypb.Request{Epoch: attached.GetEpoch(), Session: proof})
	if err != nil {
		t.Fatal(err)
	}
	state, err := h.Runtime.SessionState(cred, attempt)
	if err != nil || state != volumeserver.SessionStateProvisional {
		t.Fatalf("runtime after precommit rollback = %v, %v", state, err)
	}
}

func TestProtocol5AbortRacingActivationCannotEraseActive(t *testing.T) {
	membership := &blockingActivationMembership{activated: make(chan struct{}), release: make(chan struct{})}
	h, ctx, _, _ := newProtocol5Handler(t, membership)
	request := protocol5AttachRequest(96)
	attached := h.Handle(ctx, request)
	if attached.GetErrno() != 0 {
		t.Fatalf("Attach = %+v", attached)
	}
	proof := proofFromAttach(attached)
	activate := &authoritypb.Request{
		RequestId: 97, Epoch: attached.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{
			AttachAttemptId: request.GetAttach().GetAttachAttemptId(), DataBindingGeneration: 1, ControlBindingGeneration: 1,
		}},
	}
	activationDone := make(chan *authoritypb.Response, 1)
	go func() { activationDone <- h.Handle(ctx, activate) }()
	select {
	case <-membership.activated:
	case <-time.After(time.Second):
		t.Fatal("activation did not reach durable membership")
	}
	abortDone := make(chan *authoritypb.Response, 1)
	go func() {
		abortDone <- h.Handle(ctx, &authoritypb.Request{
			RequestId: 98, Epoch: attached.GetEpoch(), Session: proof,
			Body: &authoritypb.Request_AbortAttach{AbortAttach: &authoritypb.AbortAttachRequest{
				AttachAttemptId: request.GetAttach().GetAttachAttemptId(),
			}},
		})
	}()
	select {
	case response := <-abortDone:
		t.Fatalf("Abort crossed an unresolved activation: %+v", response)
	case <-time.After(30 * time.Millisecond):
	}
	close(membership.release)
	activated := <-activationDone
	aborted := <-abortDone
	if activated.GetErrno() != 0 || activated.GetActivate().GetState() != authoritypb.SessionState_SESSION_STATE_ACTIVE {
		t.Fatalf("Activate = %+v", activated)
	}
	if aborted.GetErrno() != errnos.EBUSY || !membership.active.Load() {
		t.Fatalf("racing Abort = %+v membership-active=%v; want EBUSY and retained ACTIVE membership", aborted, membership.active.Load())
	}
}

func TestProtocol5ActivationPublishesFreshRootInsideRegistrationBoundary(t *testing.T) {
	h, ctx, _, _ := newProtocol5Handler(t, nil)
	rootIdentity := [16]byte{0xD1, 0x5C}
	rootAttr := xfsstore.Attr{
		Kind: xfsstore.KindDirectory, Ino: 0xA11CE, Mode: 0o755, Nlink: 2,
		CTimeNS: 123456789,
	}
	store := &blockingActivationRootStore{
		resourceAdmissionFaultStore: &resourceAdmissionFaultStore{},
		attr:                        rootAttr, identity: rootIdentity,
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	h.Store = store

	request := protocol5AttachRequest(101)
	attached := h.Handle(ctx, request)
	if attached.GetErrno() != 0 {
		t.Fatalf("Attach = %+v", attached)
	}
	if got := store.reads.Load(); got != 0 {
		t.Fatalf("provisional Attach read root attributes %d times, want zero", got)
	}
	proof := proofFromAttach(attached)
	var participant volumeserver.SessionID
	copy(participant[:], proof.GetId())
	activate := &authoritypb.Request{
		RequestId: 102, Epoch: attached.GetEpoch(), Session: proof,
		Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{
			AttachAttemptId: request.GetAttach().GetAttachAttemptId(), DataBindingGeneration: 1, ControlBindingGeneration: 1,
		}},
	}
	activationDone := make(chan *authoritypb.Response, 1)
	go func() { activationDone <- h.Handle(ctx, activate) }()
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("Activate did not enter its fresh root read")
	}

	target := volumeserver.VisibilityTarget{
		Scope: volumeserver.VisibilityAttributes, Identity: rootIdentity,
		KernelIno: rootAttr.Ino, Device: 1,
	}
	mutationStarted := make(chan struct{})
	prepareEntered := make(chan struct{})
	mutationDone := make(chan error, 1)
	go func() {
		close(mutationStarted)
		mutationDone <- h.Visibility.Execute(
			context.Background(), volumeserver.SessionID{0xEE}, volumeserver.MutationID{Sequence: 1},
			volumeserver.MutationDependenciesForTargets([]volumeserver.VisibilityTarget{target}),
			func() ([]volumeserver.VisibilityTarget, error) {
				close(prepareEntered)
				return []volumeserver.VisibilityTarget{target}, nil
			},
			func() ([]volumeserver.VisibilityTarget, bool) {
				return []volumeserver.VisibilityTarget{target}, true
			},
		)
	}()
	<-mutationStarted
	select {
	case <-prepareEntered:
		t.Fatal("mutation crossed activation while the fresh root fact was not installed")
	case <-time.After(30 * time.Millisecond):
	}
	close(store.release)

	var activated *authoritypb.Response
	select {
	case activated = <-activationDone:
	case <-time.After(time.Second):
		t.Fatal("Activate did not complete after the root read was released")
	}
	if activated.GetErrno() != 0 || activated.GetActivate() == nil {
		t.Fatalf("Activate = %+v", activated)
	}
	root := activated.GetActivate().GetRoot()
	if root.GetAttr().GetInode() != rootAttr.Ino || !bytes.Equal(root.GetStableIdentity(), rootIdentity[:]) {
		t.Fatalf("activated root = %+v, want fresh inode=%d identity=%x", root, rootAttr.Ino, rootIdentity)
	}
	select {
	case <-prepareEntered:
	case <-time.After(time.Second):
		t.Fatal("mutation did not resume after activation committed")
	}

	// The mutation began before activation could publish ACTIVE. It must still
	// address the freshly installed root coordinate, proving there is no gap in
	// which the new mount can serve the returned root without joining its first
	// cache barrier.
	phaseContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	prepare, err := h.Visibility.Next(phaseContext, participant, testInitialVisibilityCursor(t, h.Visibility, participant))
	if err != nil {
		t.Fatalf("root PREPARE = %v", err)
	}
	if prepare.Cursor.Phase != volumeserver.VisibilityPrepare || len(prepare.Targets) != 1 || prepare.Targets[0].Identity != rootIdentity {
		t.Fatalf("root PREPARE = %+v", prepare)
	}
	if err := h.Visibility.Ack(participant, prepare.Cursor); err != nil {
		t.Fatalf("ack root PREPARE: %v", err)
	}
	complete, err := h.Visibility.Next(phaseContext, participant, prepare.Cursor)
	if err != nil {
		t.Fatalf("root COMPLETE = %v", err)
	}
	if complete.Cursor.Phase != volumeserver.VisibilityComplete || len(complete.Targets) != 1 || complete.Targets[0].Identity != rootIdentity {
		t.Fatalf("root COMPLETE = %+v", complete)
	}
	if err := h.Visibility.Ack(participant, complete.Cursor); err != nil {
		t.Fatalf("ack root COMPLETE: %v", err)
	}
	select {
	case err := <-mutationDone:
		if err != nil {
			t.Fatalf("root mutation = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("root mutation did not finish after exact repair acknowledgments")
	}
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
	h := testVolumeHandler()
	h.Store = store
	h.Runtime = runtime
	h.Authorizer = allowAuthorizer{volumeserver.AccessRead | volumeserver.AccessWrite}
	h.Routes = testRoutesControllerWithFencer(t, store, runtime)
	h.Visibility = h.Routes.Visibility
	h.MaxItemsPerSession, h.MaxOpensPerSession = 1024, 1024
	h.MaxItems, h.MaxOpens = 8192, 8192
	h.MaxRetainedReplyBytes = 8 << 20
	ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte{7})

	activated, epoch, proof := attachAndActivateHandler(t, h, ctx, 1, &authoritypb.AttachRequest{
		VolumeId: "volume-e2e", AccessToken: []byte("test-only"), ReplaySlots: 2, RoutesRevision: emptyRoutesRevision(),
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 64, RepairBudgetMillis: 1000,
		NamespaceRepair: authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION,
	})
	var sessionID volumeserver.SessionID
	copy(sessionID[:], proof.GetId())
	var rootCapability xfsstore.Capability
	copy(rootCapability[:], activated.GetRoot().GetToken())
	rootIdentity, err := store.Identity(rootCapability)
	if err != nil {
		t.Fatal(err)
	}

	create := &authoritypb.Request{RequestId: 2, Epoch: epoch, Session: proof, Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: activated.GetRoot().GetToken(), Name: []byte("handler-e2e"), Mode: 0o600, Exclusive: true, Flags: &authoritypb.OpenFlags{Read: true, Write: true}}}}
	stampNamespacePublication(create, 2, rootIdentity, []byte("handler-e2e"))
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
	var createdHandle xfsstore.Capability
	copy(createdHandle[:], created.GetCreate().GetHandle())
	if n, err := store.WriteAt(createdHandle, []byte("hello"), 0); err != nil || n != 5 {
		t.Fatalf("seed through store = (%d, %v)", n, err)
	}

	unlink := &authoritypb.Request{RequestId: 5, Epoch: epoch, Session: proof, Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: activated.GetRoot().GetToken(), Name: []byte("handler-e2e")}}}
	stampNamespacePublication(unlink, 5, rootIdentity, []byte("handler-e2e"))
	stampMutation(t, unlink, 0, 2)
	if got := h.Handle(ctx, unlink); got.GetErrno() != 0 {
		t.Fatalf("unlink = %v", got)
	}

	read := h.Handle(ctx, &authoritypb.Request{RequestId: 6, Epoch: epoch, Session: proof, Body: &authoritypb.Request_Read{Read: &authoritypb.ReadRequest{Handle: created.GetCreate().GetHandle(), Length: 5}}})
	if read.GetErrno() != 0 || string(read.GetRead().GetData()) != "hello" {
		t.Fatalf("read after unlink = %v", read)
	}
	fsync := h.Handle(ctx, &authoritypb.Request{RequestId: 7, Epoch: epoch, Session: proof, Body: &authoritypb.Request_Fsync{Fsync: &authoritypb.FsyncRequest{Handle: created.GetCreate().GetHandle()}}})
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
	h := testVolumeHandler()
	h.Store = store
	h.Runtime = runtime
	h.Authorizer = allowAuthorizer{volumeserver.AccessRead | volumeserver.AccessWrite}
	h.Routes = testRoutesControllerWithFencer(t, store, runtime)
	h.Visibility = h.Routes.Visibility
	h.MaxItemsPerSession, h.MaxOpensPerSession = 1024, 1024
	h.MaxItems, h.MaxOpens = 8192, 8192
	h.MaxRetainedReplyBytes = 8 << 20
	ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte{9})

	attachSession := func(id uint64) (*authoritypb.ActivateReply, []byte, *authoritypb.SessionProof) {
		t.Helper()
		return attachAndActivateHandler(t, h, ctx, id, &authoritypb.AttachRequest{
			VolumeId: "volume-lockwait", AccessToken: []byte("test-only"), ReplaySlots: 2, RoutesRevision: emptyRoutesRevision(),
			CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
			CachedNameCapacity: 64, RepairBudgetMillis: 1000,
			NamespaceRepair: authoritypb.NamespaceRepair_NAMESPACE_REPAIR_LOCKLESS_EXPIRATION,
		})
	}
	holder, epoch, holderProof := attachSession(1)
	var rootCapability xfsstore.Capability
	copy(rootCapability[:], holder.GetRoot().GetToken())
	rootIdentity, err := store.Identity(rootCapability)
	if err != nil {
		t.Fatal(err)
	}

	create := &authoritypb.Request{RequestId: 3, Epoch: epoch, Session: holderProof, Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: holder.GetRoot().GetToken(), Name: []byte("lock-wait-target"), Mode: 0o600, Exclusive: true, Flags: &authoritypb.OpenFlags{Read: true, Write: true}}}}
	stampNamespacePublication(create, 3, rootIdentity, []byte("lock-wait-target"))
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

	// Attach the waiter only after the seed create. A direct handler test has no
	// frontend visibility loop to ACK a create repair, and the waiter is meant to
	// observe the already-created object before it parks on the lock.
	waiter, _, waiterProof := attachSession(2)
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

	// A changed route is terminal for current production frontends. The
	// visibility fencer therefore ends both sessions and releases the holder's
	// lock while Apply owns the topology writer. The parked waiter must unwind
	// with the exact terminal-session errno; it must neither acquire a lock for a
	// stale route nor hold the topology writer indefinitely.
	select {
	case response := <-waitDone:
		if response.GetErrno() != errnos.ESTALE {
			t.Fatalf("the route-fenced parked wait completed with errno %d, want ESTALE", response.GetErrno())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the parked lock wait never completed after the route-change fence released the holder")
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
	request.Mutation = &authoritypb.Mutation{Slot: slot, Sequence: sequence}
}

func stampNamespacePublication(request *authoritypb.Request, operationID uint64, parent [16]byte, name []byte) {
	request.FrontendOperationId = operationID
	request.SourcePublicationGate = &authoritypb.SourcePublicationGate{Targets: []*authoritypb.SourcePublicationTarget{
		{Coordinate: &authoritypb.SourcePublicationTarget_Item{Item: &authoritypb.SourcePublicationItem{
			Identity: append([]byte(nil), parent[:]...), Attributes: true,
		}}},
		{Coordinate: &authoritypb.SourcePublicationTarget_Namespace{Namespace: &authoritypb.SourcePublicationNamespace{
			ParentIdentity: append([]byte(nil), parent[:]...), Name: append([]byte(nil), name...),
			BoundAttributes: true,
		}}},
	}}
}
