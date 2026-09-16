//go:build linux

package authorityrpc

import (
	"io/fs"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

type coherenceExistingCreateStore struct {
	resourceAdmissionFaultStore
	item, handle xfsstore.Capability
	openErr      error
}

func (s *coherenceExistingCreateStore) Create(xfsstore.Capability, string, fs.FileMode, bool) (xfsstore.Capability, xfsstore.Attr, error) {
	s.create.Add(1)
	return s.item, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 2, Size: 7, Mode: 0o600, Nlink: 1, DeviceMinor: 1}, nil
}

func (s *coherenceExistingCreateStore) OpenFile(xfsstore.Capability, xfsstore.OpenFlags) (xfsstore.Capability, error) {
	s.open.Add(1)
	if s.openErr != nil {
		return xfsstore.Capability{}, s.openErr
	}
	return s.handle, nil
}

func (s *coherenceExistingCreateStore) Getattr(item xfsstore.Capability) (xfsstore.Attr, error) {
	if item == s.item {
		return xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 2, Size: 7, Mode: 0o600, Nlink: 1, DeviceMinor: 1}, nil
	}
	return xfsstore.Attr{Kind: xfsstore.KindDirectory, Ino: uint64(item[0]), Mode: 0o755, Nlink: 2, DeviceMinor: 1}, nil
}

func (s *coherenceExistingCreateStore) GetattrOpen(handle xfsstore.Capability) (xfsstore.Attr, error) {
	if handle != s.handle {
		return xfsstore.Attr{}, syscall.EBADF
	}
	return xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 2, Size: 7, Mode: 0o600, Nlink: 1, DeviceMinor: 1}, nil
}

func (*coherenceExistingCreateStore) CloseOpen(xfsstore.Capability) error { return nil }

func coherenceExistingCreateRequest(credential volumeserver.SessionCredential, parent xfsstore.Capability) *authoritypb.Request {
	request := coherenceReadRequest(credential)
	request.RequestId = 83
	request.Mutation = &authoritypb.Mutation{Sequence: 1}
	request.Body = &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
		Parent: parent[:], Name: []byte("existing"), Mode: 0o600,
		Flags: &authoritypb.OpenFlags{Write: true}, WriteIntent: true,
	}}
	return request
}

func TestCoherenceExistingCreatePromotesLiveDelegationOnlyAfterSuccess(t *testing.T) {
	item := xfsstore.Capability{0x33}
	store := &coherenceExistingCreateStore{
		resourceAdmissionFaultStore: resourceAdmissionFaultStore{lookupItem: item},
		item:                        item, handle: xfsstore.Capability{0x44},
	}
	h, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 8, 8)
	response := h.Handle(ctx, coherenceExistingCreateRequest(credential, root))
	delegation := response.GetCreate().GetDelegation()
	if response.GetErrno() != 0 || delegation == nil {
		t.Fatalf("existing CREATE = %+v", response)
	}
	id, err := parseCoherenceDelegationID(delegation.GetId())
	if err != nil {
		t.Fatal(err)
	}
	live, ok := h.Coherence.LookupDelegation([16]byte{item[0]})
	if !ok || live.ID != id || live.Generation != delegation.GetGeneration() {
		t.Fatalf("reply delegation = %+v, live delegation = %+v, present %t", delegation, live, ok)
	}
}

func TestCoherenceExistingCreateFailureLeavesNoDelegation(t *testing.T) {
	item := xfsstore.Capability{0x34}
	store := &coherenceExistingCreateStore{
		resourceAdmissionFaultStore: resourceAdmissionFaultStore{lookupItem: item},
		item:                        item, handle: xfsstore.Capability{0x45}, openErr: syscall.EIO,
	}
	h, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 8, 8)
	response := h.Handle(ctx, coherenceExistingCreateRequest(credential, root))
	if response.GetErrno() != int32(syscall.EIO) || response.GetCreate().GetDelegation() != nil {
		t.Fatalf("failed existing CREATE = %+v", response)
	}
	if live, ok := h.Coherence.LookupDelegation([16]byte{item[0]}); ok {
		t.Fatalf("failed existing CREATE retained delegation %+v", live)
	}
	if store.create.Load() != 1 || store.open.Load() != 1 {
		t.Fatalf("storage calls = create %d open %d", store.create.Load(), store.open.Load())
	}
}
