//go:build linux

package authorityrpc

import (
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

type coherenceOpenFailureStore struct {
	resourceAdmissionFaultStore
	handle xfsstore.Capability
	fail   error
	after  func()
	closes atomic.Uint32
}

func (s *coherenceOpenFailureStore) OpenFile(xfsstore.Capability, xfsstore.OpenFlags) (xfsstore.Capability, error) {
	s.open.Add(1)
	if s.after != nil {
		s.after()
	}
	if s.fail != nil {
		return xfsstore.Capability{}, s.fail
	}
	return s.handle, nil
}

func (s *coherenceOpenFailureStore) CloseOpen(handle xfsstore.Capability) error {
	if handle != s.handle {
		return syscall.EBADF
	}
	s.closes.Add(1)
	return nil
}

func coherenceWriteIntentOpenRequest(credential volumeserver.SessionCredential, item xfsstore.Capability) *authoritypb.Request {
	request := coherenceReadRequest(credential)
	request.Mutation = &authoritypb.Mutation{Sequence: 1}
	request.Body = &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{
		Item: item[:], Flags: &authoritypb.OpenFlags{Write: true}, WriteIntent: true,
	}}
	return request
}

func TestCoherenceOpenGrantsOnlyAfterHandleReady(t *testing.T) {
	store := &coherenceOpenFailureStore{handle: xfsstore.Capability{0x43}}
	h, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 8, 8)
	identity := [16]byte{root[0]}
	var sawReservation atomic.Bool
	store.after = func() {
		delegation, ok := h.Coherence.LookupDelegation(identity)
		sawReservation.Store(ok && delegation.State == volumeserver.DelegationReserved)
	}
	request := coherenceWriteIntentOpenRequest(credential, root)
	request.GetOpen().CacheCapable = true

	response := h.Handle(ctx, request)
	delegation := response.GetOpen().GetDelegation()
	if response.GetErrno() != 0 || delegation == nil || response.GetOpen().GetCacheCapable() {
		t.Fatalf("OPEN response = %+v", response)
	}
	if !sawReservation.Load() {
		t.Fatal("OPEN reached storage without reserving delegation ownership")
	}
	id, err := parseCoherenceDelegationID(delegation.GetId())
	if err != nil {
		t.Fatal(err)
	}
	live, ok := h.Coherence.LookupDelegation(identity)
	if !ok || live.ID != id || live.Generation != delegation.GetGeneration() || live.State != volumeserver.DelegationActive {
		t.Fatalf("reply delegation = %+v, live delegation = %+v, present %t", delegation, live, ok)
	}
}

func TestCoherenceOpenStorageFailureAbortsUnpublishedReservation(t *testing.T) {
	store := &coherenceOpenFailureStore{fail: syscall.EIO}
	h, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 8, 8)
	response := h.Handle(ctx, coherenceWriteIntentOpenRequest(credential, root))
	if response.GetErrno() != int32(syscall.EIO) {
		t.Fatalf("OPEN failure = %+v", response)
	}
	if store.open.Load() != 1 || store.closes.Load() != 0 {
		t.Fatalf("storage calls = open %d close %d", store.open.Load(), store.closes.Load())
	}
	if delegation, ok := h.Coherence.LookupDelegation([16]byte{root[0]}); ok {
		t.Fatalf("failed OPEN retained unpublished delegation %+v", delegation)
	}
}

func TestCoherenceOpenStorageFailurePreservesExistingDelegation(t *testing.T) {
	store := &coherenceOpenFailureStore{fail: syscall.EIO}
	h, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 8, 8)
	token, err := h.coherenceToken(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	identity := [16]byte{root[0]}
	reservation, err := h.Coherence.Reserve(t.Context(), token, identity)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := reservation.Grant(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := h.validateCoherenceDelegation(grant); err != nil {
		t.Fatal(err)
	}

	response := h.Handle(ctx, coherenceWriteIntentOpenRequest(credential, root))
	if response.GetErrno() != int32(syscall.EIO) {
		t.Fatalf("OPEN failure = %+v", response)
	}
	retained, ok := h.Coherence.LookupDelegation(identity)
	if !ok || retained.ID != grant.ID || retained.Generation != grant.Generation || retained.State != volumeserver.DelegationActive {
		t.Fatalf("failed OPEN replaced existing delegation: got %+v, want %+v", retained, grant)
	}
}

func TestCoherenceOpenGrantFailureRetiresTrackedHandle(t *testing.T) {
	store := &coherenceOpenFailureStore{handle: xfsstore.Capability{0x44}}
	h, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 8, 8)
	store.after = func() { h.Coherence.ExpireSession(credential.ID) }
	request := coherenceWriteIntentOpenRequest(credential, root)

	first := h.Handle(ctx, request)
	if first.GetErrno() != int32(syscall.EIO) || first.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE {
		t.Fatalf("OPEN grant failure = %+v", first)
	}
	if store.open.Load() != 1 || store.closes.Load() != 1 {
		t.Fatalf("storage calls = open %d close %d", store.open.Load(), store.closes.Load())
	}
	h.resourcesMu.Lock()
	opens := len(h.resources[credential.ID].opens)
	h.resourcesMu.Unlock()
	if opens != 0 {
		t.Fatalf("grant failure retained %d server handles", opens)
	}
	if delegation, ok := h.Coherence.LookupDelegation([16]byte{root[0]}); ok {
		t.Fatalf("grant failure retained delegation %+v", delegation)
	}

	replay := h.Handle(ctx, request)
	if replay.GetErrno() != int32(syscall.EIO) || store.open.Load() != 1 || store.closes.Load() != 1 {
		t.Fatalf("OPEN replay = %+v, storage calls open %d close %d", replay, store.open.Load(), store.closes.Load())
	}
}
