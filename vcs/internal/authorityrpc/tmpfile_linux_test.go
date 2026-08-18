//go:build linux

package authorityrpc

import (
	"bytes"
	"io/fs"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

type tmpfileHandlerStore struct {
	resourceAdmissionFaultStore
	item         xfsstore.Capability
	handle       xfsstore.Capability
	attr         xfsstore.Attr
	identityErr  error
	tmpfileCalls int
	openCalls    int
	closeCalls   int
	forgetCalls  int
	gotExclusive bool
	gotOpenFlags xfsstore.OpenFlags
}

func (s *tmpfileHandlerStore) Tmpfile(_ xfsstore.Capability, _ fs.FileMode, exclusive bool) (xfsstore.Capability, xfsstore.Attr, error) {
	s.tmpfileCalls++
	s.gotExclusive = exclusive
	return s.item, s.attr, nil
}

func (s *tmpfileHandlerStore) OpenFile(_ xfsstore.Capability, flags xfsstore.OpenFlags) (xfsstore.Capability, error) {
	s.openCalls++
	s.gotOpenFlags = flags
	return s.handle, nil
}

func (s *tmpfileHandlerStore) Identity(item xfsstore.Capability) ([16]byte, error) {
	if s.identityErr != nil {
		return [16]byte{}, s.identityErr
	}
	return [16]byte{item[0]}, nil
}

func (s *tmpfileHandlerStore) CloseOpen(xfsstore.Capability) error {
	s.closeCalls++
	return nil
}

func (s *tmpfileHandlerStore) Forget(xfsstore.Capability) error {
	s.forgetCalls++
	return nil
}

func (s *tmpfileHandlerStore) Getattr(parent xfsstore.Capability) (xfsstore.Attr, error) {
	return xfsstore.Attr{Kind: xfsstore.KindDirectory, Ino: uint64(parent[0]), Mode: 0o755, Nlink: 2, DeviceMinor: 1}, nil
}

func tmpfileMutationRequest(t *testing.T, credentialEpoch, sessionID, secret []byte, generation uint64, parent xfsstore.Capability, requestID uint64) *authoritypb.Request {
	t.Helper()
	parentIdentity := [16]byte{parent[0]}
	request := &authoritypb.Request{
		RequestId: requestID,
		Epoch:     append([]byte(nil), credentialEpoch...),
		Session: &authoritypb.SessionProof{
			Id: append([]byte(nil), sessionID...), Generation: generation, ResumeSecret: append([]byte(nil), secret...),
		},
		Body: &authoritypb.Request_Tmpfile{Tmpfile: &authoritypb.TmpfileRequest{
			Parent: parent[:], Mode: 0o640, Exclusive: true,
			Flags: &authoritypb.OpenFlags{Read: true, Write: true, Sync: true},
		}},
		SourcePublicationGate: &authoritypb.SourcePublicationGate{Targets: []*authoritypb.SourcePublicationTarget{{
			Coordinate: &authoritypb.SourcePublicationTarget_Item{Item: &authoritypb.SourcePublicationItem{
				Identity: parentIdentity[:], Attributes: true,
			}},
		}}},
	}
	stampMutation(t, request, 0, 1)
	return request
}

func TestTmpfileReturnsExactCapabilitiesAndReplaysWithoutStorage(t *testing.T) {
	store := &tmpfileHandlerStore{
		item:   xfsstore.Capability{0x91},
		handle: xfsstore.Capability{0x92},
		attr: xfsstore.Attr{
			Kind: xfsstore.KindRegular, Ino: 0x91, Mode: 0o640, Nlink: 0, DeviceMinor: 1,
		},
	}
	handler, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 4, 4)
	request := tmpfileMutationRequest(t, credential.Epoch[:], credential.ID[:], credential.Secret[:], credential.Generation, root, 1)
	response := handler.Handle(ctx, request)
	item := response.GetTmpfile().GetItem()
	expectedIdentity := [16]byte{0x91}
	if response.GetErrno() != 0 || response.GetUncertain() || item == nil ||
		!bytes.Equal(item.GetToken(), store.item[:]) || !bytes.Equal(item.GetStableIdentity(), expectedIdentity[:]) ||
		!bytes.Equal(response.GetTmpfile().GetHandle(), store.handle[:]) {
		t.Fatalf("tmpfile response = %+v", response)
	}
	if store.tmpfileCalls != 1 || store.openCalls != 1 || !store.gotExclusive ||
		!store.gotOpenFlags.Read || !store.gotOpenFlags.Write || !store.gotOpenFlags.Sync || store.gotOpenFlags.Truncate {
		t.Fatalf("tmpfile dispatch calls=%d opens=%d exclusive=%t flags=%+v", store.tmpfileCalls, store.openCalls, store.gotExclusive, store.gotOpenFlags)
	}

	replay := tmpfileMutationRequest(t, credential.Epoch[:], credential.ID[:], credential.Secret[:], credential.Generation, root, 2)
	replayed := handler.Handle(ctx, replay)
	if replayed.GetErrno() != 0 || !bytes.Equal(replayed.GetTmpfile().GetHandle(), store.handle[:]) ||
		store.tmpfileCalls != 1 || store.openCalls != 1 {
		t.Fatalf("tmpfile replay = %+v calls=%d opens=%d", replayed, store.tmpfileCalls, store.openCalls)
	}
}

func TestTmpfilePostCreateIdentityFailureClosesEveryCapability(t *testing.T) {
	store := &tmpfileHandlerStore{
		item: xfsstore.Capability{0xA1}, handle: xfsstore.Capability{0xA2},
		attr:        xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 0xA1, Mode: 0o600, DeviceMinor: 1},
		identityErr: syscall.EIO,
	}
	handler, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 4, 4)
	response := handler.Handle(ctx, tmpfileMutationRequest(t, credential.Epoch[:], credential.ID[:], credential.Secret[:], credential.Generation, root, 1))
	if response.GetErrno() != int32(syscall.EIO) || !response.GetUncertain() || response.GetTmpfile() != nil {
		t.Fatalf("identity failure response = %+v", response)
	}
	if store.closeCalls != 1 || store.forgetCalls != 1 {
		t.Fatalf("identity failure cleanup close=%d forget=%d, want 1/1", store.closeCalls, store.forgetCalls)
	}

	// The failed mutation is replay-retained as uncertain and must never create
	// a second unnamed inode after a lost response.
	replay := tmpfileMutationRequest(t, credential.Epoch[:], credential.ID[:], credential.Secret[:], credential.Generation, root, 2)
	replayed := handler.Handle(ctx, replay)
	if replayed.GetErrno() != int32(syscall.EIO) || !replayed.GetUncertain() || store.tmpfileCalls != 1 || store.openCalls != 1 {
		t.Fatalf("identity-failure replay = %+v calls=%d opens=%d", replayed, store.tmpfileCalls, store.openCalls)
	}
}

func TestTmpfileRejectsTruncateBeforeStorage(t *testing.T) {
	store := &tmpfileHandlerStore{item: xfsstore.Capability{0xB1}, handle: xfsstore.Capability{0xB2}}
	handler, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 4, 4)
	request := tmpfileMutationRequest(t, credential.Epoch[:], credential.ID[:], credential.Secret[:], credential.Generation, root, 1)
	request.GetTmpfile().Flags.Truncate = true
	response := handler.Handle(ctx, request)
	if response.GetErrno() != int32(syscall.EINVAL) || response.GetUncertain() || store.tmpfileCalls != 0 || store.openCalls != 0 {
		t.Fatalf("truncate tmpfile = %+v calls=%d opens=%d", response, store.tmpfileCalls, store.openCalls)
	}
}

var _ tmpfileStore = (*tmpfileHandlerStore)(nil)
