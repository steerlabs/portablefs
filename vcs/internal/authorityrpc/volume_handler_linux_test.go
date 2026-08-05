//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
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
	waiterLookup := h.Handle(ctx, &authoritypb.Request{RequestId: 4, Epoch: epoch, Session: waiterProof, Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: waiter.GetRoot().GetToken(), Name: []byte("lock-wait-target")}}})
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
		stampMutation(t, wait, 0, 1)
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
		Hello: &authoritypb.HelloRequest{ProtocolMajor: ProtocolMajor},
	}})
	if current.GetErrno() != 0 || current.GetHello().GetProtocolMajor() != ProtocolMajor {
		t.Fatalf("current-protocol hello = %v", current)
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
