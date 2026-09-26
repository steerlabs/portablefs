//go:build linux

package authorityrpc

import (
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

type closeBatchTestStore struct {
	resourceAdmissionFaultStore
	calls         []xfsstore.Capability
	fail          xfsstore.Capability
	unlockFailure bool
}

func (s *closeBatchTestStore) CloseOpen(handle xfsstore.Capability) error {
	s.calls = append(s.calls, handle)
	if handle == s.fail {
		return syscall.EIO
	}
	return nil
}

func TestCloseBatchRetainsOrderedPartialOutcomesOnReplay(t *testing.T) {
	store := &closeBatchTestStore{fail: xfsstore.Capability{2}}
	h, ctx, cred, _ := resourceAdmissionRequestHarness(t, store, 8, 8)
	request := coherenceReadRequest(cred)
	request.Mutation = &authoritypb.Mutation{Slot: 0, Sequence: 1}
	batch := &authoritypb.CloseBatchRequest{}
	for i := byte(1); i <= 3; i++ {
		handle := xfsstore.Capability{i}
		if err := h.trackOpen(cred.ID, handle, false); err != nil {
			t.Fatal(err)
		}
		batch.Closes = append(batch.Closes, &authoritypb.CloseRequest{Handle: handle[:]})
	}
	request.Body = &authoritypb.Request_CloseBatch{CloseBatch: batch}
	first := h.handleCloseBatch(ctx, request, cred)
	if first.Errno != 0 || len(first.GetCloseBatch().GetResults()) != 3 {
		t.Fatal(first)
	}
	for i, result := range first.GetCloseBatch().Results {
		want := int32(0)
		if i == 1 {
			want = int32(syscall.EIO)
		}
		if result.Errno != want || !result.Retired {
			t.Fatalf("result %d: %v", i, result)
		}
	}
	again := h.handleCloseBatch(ctx, request, cred)
	if !proto.Equal(first, again) || len(store.calls) != 3 {
		t.Fatalf("replayed closes: calls=%d response=%v", len(store.calls), again)
	}
	if _, err := h.open(cred.ID, []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err == nil {
		t.Fatal("successful close remained tracked")
	}
	if _, err := h.open(cred.ID, store.fail[:]); err == nil {
		t.Fatal("consumed close remained tracked after cleanup error")
	}
	mismatch := proto.Clone(request).(*authoritypb.Request)
	mismatch.GetCloseBatch().Closes[0], mismatch.GetCloseBatch().Closes[2] = mismatch.GetCloseBatch().Closes[2], mismatch.GetCloseBatch().Closes[0]
	if reply := h.handleCloseBatch(ctx, mismatch, cred); reply.Errno == 0 || len(store.calls) != 3 {
		t.Fatalf("reordered replay applied: %v", reply)
	}

}

func TestCloseBatchRejectsDuplicateBeforeAnyClose(t *testing.T) {
	store := &closeBatchTestStore{}
	h, ctx, cred, _ := resourceAdmissionRequestHarness(t, store, 8, 8)
	handle := xfsstore.Capability{1}
	if err := h.trackOpen(cred.ID, handle, false); err != nil {
		t.Fatal(err)
	}
	request := coherenceReadRequest(cred)
	request.Mutation = &authoritypb.Mutation{Slot: 0, Sequence: 1}
	request.Body = &authoritypb.Request_CloseBatch{CloseBatch: &authoritypb.CloseBatchRequest{Closes: []*authoritypb.CloseRequest{{Handle: handle[:]}, {Handle: handle[:]}}}}
	result := h.handleCloseBatch(ctx, request, cred)
	if result.Errno != int32(syscall.EINVAL) || len(store.calls) != 0 {
		t.Fatalf("duplicate batch applied: %v calls=%d", result, len(store.calls))
	}
}

func TestCloseBatchMalformedRequestHasNoStoreEffects(t *testing.T) {
	for name, closes := range map[string][]*authoritypb.CloseRequest{
		"empty": {}, "nil": {nil}, "short handle": {{Handle: []byte{1}}}, "too many": make([]*authoritypb.CloseRequest, MaxCloseBatch+1),
	} {
		t.Run(name, func(t *testing.T) {
			store := &closeBatchTestStore{}
			h, ctx, cred, _ := resourceAdmissionRequestHarness(t, store, 8, 8)
			request := coherenceReadRequest(cred)
			request.Mutation = &authoritypb.Mutation{Slot: 0, Sequence: 1}
			request.Body = &authoritypb.Request_CloseBatch{CloseBatch: &authoritypb.CloseBatchRequest{Closes: closes}}
			if result := h.handleCloseBatch(ctx, request, cred); result.Errno != int32(syscall.EINVAL) || len(store.calls) != 0 {
				t.Fatalf("malformed batch applied: %v", result)
			}
		})
	}
}

func (s *closeBatchTestStore) IdentityOpen(handle xfsstore.Capability) ([16]byte, error) {
	if s.unlockFailure {
		return [16]byte{}, syscall.EIO
	}
	return s.resourceAdmissionFaultStore.IdentityOpen(handle)
}
func TestCloseBatchUnlockFailureStillRetiresDescriptor(t *testing.T) {
	store := &closeBatchTestStore{unlockFailure: true}
	h, _, cred, _ := resourceAdmissionRequestHarness(t, store, 8, 8)
	handle := xfsstore.Capability{4}
	if err := h.trackOpen(cred.ID, handle, false); err != nil {
		t.Fatal(err)
	}
	result := h.closeBatchEntry(cred, &authoritypb.CloseRequest{Handle: handle[:], LockOwner: 3, FlockUnlock: true})
	if !result.Retired || result.Errno != int32(syscall.EIO) || len(store.calls) != 1 {
		t.Fatalf("unlock failure skipped descriptor retirement: %v calls=%d", result, len(store.calls))
	}
	if _, err := h.open(cred.ID, handle[:]); err == nil {
		t.Fatal("retired descriptor remained accounted")
	}
}
