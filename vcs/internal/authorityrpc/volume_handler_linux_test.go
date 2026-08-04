//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

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

func TestSessionResourceAdmissionAndTerminalState(t *testing.T) {
	h := &VolumeHandler{MaxItemsPerSession: 1, MaxOpensPerSession: 1, MaxItems: 1, MaxOpens: 1}
	first := volumeserver.SessionID{1}
	second := volumeserver.SessionID{2}
	if err := h.startSessionResources(first); err != nil {
		t.Fatal(err)
	}
	if err := h.startSessionResources(second); err != nil {
		t.Fatal(err)
	}
	if err := h.trackItem(first, xfsstore.Capability{1}); err != nil {
		t.Fatal(err)
	}
	if err := h.trackItem(second, xfsstore.Capability{2}); !errors.Is(err, volumeserver.ErrAdmission) {
		t.Fatalf("global item admission = %v, want ErrAdmission", err)
	}
	h.closeSessionResources(first)
	if err := h.trackItem(first, xfsstore.Capability{3}); !errors.Is(err, volumeserver.ErrSessionExpired) {
		t.Fatalf("track after session end = %v, want ErrSessionExpired", err)
	}
	if err := h.trackItem(second, xfsstore.Capability{4}); err != nil {
		t.Fatalf("admission was not released by cleanup: %v", err)
	}
}

type allowAuthorizer struct{ access volumeserver.Access }

func (a allowAuthorizer) Authorize(context.Context, string, []byte) (volumeserver.Authorization, error) {
	return volumeserver.Authorization{Access: a.access, Deadline: time.Now().Add(time.Hour)}, nil
}

func TestVolumeHandlerEndToEndOnXFS(t *testing.T) {
	root := os.Getenv("PORTABLEFS_XFS_TEST_ROOT")
	projectRaw := os.Getenv("PORTABLEFS_XFS_TEST_PROJECT")
	if root == "" || projectRaw == "" {
		t.Skip("privileged XFS gate is not configured")
	}
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
		MaxFrame: 1 << 20, MaxRead: 1 << 20, MaxWrite: 1 << 20, MaxInFlight: 8,
		MaxItemsPerSession: 1024, MaxOpensPerSession: 1024, MaxItems: 8192, MaxOpens: 8192,
	}
	ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte{7})

	attach := h.Handle(ctx, &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Attach{Attach: &authoritypb.AttachRequest{VolumeId: "volume-e2e", AccessToken: []byte("test-only"), ReplaySlots: 2}}})
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
	create.RequestId = 3
	replayed := h.Handle(ctx, create)
	if replayed.GetErrno() != 0 || string(replayed.GetCreate().GetItem().GetToken()) != string(created.GetCreate().GetItem().GetToken()) {
		t.Fatalf("create replay = %v", replayed)
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

func stampMutation(t *testing.T, request *authoritypb.Request, slot uint32, sequence uint64) {
	t.Helper()
	request.Mutation = &authoritypb.Mutation{Slot: slot, Sequence: sequence, RequestHash: make([]byte, 32)}
	hash, err := canonicalHash(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Mutation.RequestHash = hash[:]
}
