//go:build linux

package authorityrpc

import (
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

type directoryProofStore struct {
	coherenceOpenFailureStore
	permitted  bool
	readDenied bool
	checks     int
}

func (s *directoryProofStore) DirectoryReadPermitted(xfsstore.Capability) (bool, error) {
	s.checks++
	return s.permitted, nil
}

func (s *directoryProofStore) OpenFile(item xfsstore.Capability, flags xfsstore.OpenFlags) (xfsstore.Capability, error) {
	if s.readDenied {
		return xfsstore.Capability{}, syscall.EACCES
	}
	return s.coherenceOpenFailureStore.OpenFile(item, flags)
}

func TestDirectoryReadProofChecksAccessOnceAndReplayOwnsDescription(t *testing.T) {
	store := &directoryProofStore{coherenceOpenFailureStore: coherenceOpenFailureStore{handle: xfsstore.Capability{0x43}}, permitted: true}
	h, ctx, cred, root := resourceAdmissionRequestHarness(t, store, 8, 8)
	request := coherenceReadRequest(cred)
	request.Mutation = &authoritypb.Mutation{Sequence: 1}
	request.Body = &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: root[:], Flags: &authoritypb.OpenFlags{Read: true}, ReusableDirectoryReadIncarnation: 1}}
	first := h.Handle(ctx, request)
	if !validDirectoryReadProof(first) {
		t.Fatalf("OPEN=%v", first)
	}
	store.permitted = false
	store.readDenied = true
	if replay := h.Handle(ctx, request); !proto.Equal(first, replay) || store.open.Load() != 1 || store.checks != 1 {
		t.Fatalf("replay=%v opens=%d checks=%d", replay, store.open.Load(), store.checks)
	}
	request.Mutation.Sequence = 2
	if denied := h.Handle(ctx, request); denied.GetErrno() != int32(syscall.EACCES) || store.open.Load() != 1 {
		t.Fatalf("new OPEN=%v opens=%d", denied, store.open.Load())
	}
	closeRequest := coherenceReadRequest(cred)
	closeRequest.Mutation = &authoritypb.Mutation{Sequence: 3}
	closeRequest.Body = &authoritypb.Request_Close{Close: &authoritypb.CloseRequest{Handle: first.GetOpen().GetHandle()}}
	if closed := h.Handle(ctx, closeRequest); closed.GetErrno() != 0 {
		t.Fatal(closed)
	}
	if closed := h.Handle(ctx, closeRequest); closed.GetErrno() != 0 || store.closes.Load() != 1 {
		t.Fatalf("close replay=%v closes=%d", closed, store.closes.Load())
	}
}

func TestDirectoryReadProofAdmitsBothWithdrawalFootprints(t *testing.T) {
	for _, kind := range []volumeserver.ChangeKind{volumeserver.DirectoryChanged, volumeserver.AttributesChanged} {
		t.Run(string(rune('0'+kind)), func(t *testing.T) {
			store := &directoryProofStore{coherenceOpenFailureStore: coherenceOpenFailureStore{handle: xfsstore.Capability{0x43}}, permitted: true}
			h, ctx, cred, root := resourceAdmissionRequestHarness(t, store, 8, 8)
			q := coherenceReadRequest(cred)
			q.Mutation = &authoritypb.Mutation{Sequence: 1}
			q.Body = &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: root[:], Flags: &authoritypb.OpenFlags{Read: true}, ReusableDirectoryReadIncarnation: 1}}
			if r := h.Handle(ctx, q); !validDirectoryReadProof(r) {
				t.Fatal(r)
			}
			requireAdmittedChange(t, h, volumeserver.ChangeEntry{Kind: kind, Identity: [16]byte{root[0]}}, true)
		})
	}
}

func TestDirectoryReadProofDeniesReuseWithoutRegressingReadOnlyDirectoryOpen(t *testing.T) {
	store := &directoryProofStore{coherenceOpenFailureStore: coherenceOpenFailureStore{handle: xfsstore.Capability{0x43}}}
	h, ctx, cred, root := resourceAdmissionRequestHarness(t, store, 8, 8)
	q := coherenceReadRequest(cred)
	q.Mutation = &authoritypb.Mutation{Sequence: 1}
	q.Body = &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: root[:], Flags: &authoritypb.OpenFlags{Read: true}, ReusableDirectoryReadIncarnation: 1}}
	r := h.Handle(ctx, q)
	if !validDirectoryReadProof(r) || r.GetOpen().GetDirectoryReadProof().GetReusable() || store.checks != 1 || store.open.Load() != 1 {
		t.Fatalf("read-only/search-denied OPEN=%v checks=%d opens=%d", r, store.checks, store.open.Load())
	}
}

func TestDirectoryReadProofRefusesWrongIncarnationBeforeOpening(t *testing.T) {
	store := &directoryProofStore{coherenceOpenFailureStore: coherenceOpenFailureStore{handle: xfsstore.Capability{0x43}}, permitted: true}
	h, ctx, cred, root := resourceAdmissionRequestHarness(t, store, 8, 8)
	q := coherenceReadRequest(cred)
	q.Mutation = &authoritypb.Mutation{Sequence: 1}
	q.Body = &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: root[:], Flags: &authoritypb.OpenFlags{Read: true}, ReusableDirectoryReadIncarnation: 2}}
	r := h.Handle(ctx, q)
	if r.GetErrno() != int32(syscall.EIO) || r.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE || store.checks != 0 || store.open.Load() != 0 {
		t.Fatalf("wrong-incarnation OPEN=%v checks=%d opens=%d", r, store.checks, store.open.Load())
	}
}
