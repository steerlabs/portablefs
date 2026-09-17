//go:build linux

package authorityrpc

import (
	"context"
	"io"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

type coherenceReadPathStore struct {
	resourceAdmissionFaultStore
	handle xfsstore.Capability
	data   []byte
	read   atomic.Uint32
	attr   atomic.Uint32
	fsync  atomic.Uint32
}

func (s *coherenceReadPathStore) IdentityOpen(handle xfsstore.Capability) ([16]byte, error) {
	if handle != s.handle {
		return [16]byte{}, syscall.EBADF
	}
	return [16]byte{handle[0]}, nil
}

func (s *coherenceReadPathStore) ReadAt(handle xfsstore.Capability, dst []byte, offset int64) (int, error) {
	if handle != s.handle || offset < 0 {
		return 0, syscall.EBADF
	}
	s.read.Add(1)
	if offset >= int64(len(s.data)) {
		return 0, io.EOF
	}
	n := copy(dst, s.data[offset:])
	if n < len(dst) {
		return n, io.EOF
	}
	return n, nil
}

func (s *coherenceReadPathStore) GetattrOpen(handle xfsstore.Capability) (xfsstore.Attr, error) {
	if handle != s.handle {
		return xfsstore.Attr{}, syscall.EBADF
	}
	s.attr.Add(1)
	return xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: uint64(handle[0]), Size: int64(len(s.data)), Mode: 0o600, Nlink: 1, DeviceMinor: 1}, nil
}

func (s *coherenceReadPathStore) Fsync(handle xfsstore.Capability, _ bool) error {
	if handle != s.handle {
		return syscall.EBADF
	}
	s.fsync.Add(1)
	return nil
}

func (*coherenceReadPathStore) CloseOpen(xfsstore.Capability) error { return nil }

func coherenceReadRequest(cred volumeserver.SessionCredential) *authoritypb.Request {
	return &authoritypb.Request{
		RequestId: 71,
		Epoch:     cred.Epoch[:],
		Session: &authoritypb.SessionProof{
			Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:],
		},
	}
}

func TestCoherenceReadGetattrAndFsyncReturnSampledVersion(t *testing.T) {
	store := &coherenceReadPathStore{handle: xfsstore.Capability{0x44}, data: []byte("coherent")}
	h, ctx, credential, _ := resourceAdmissionRequestHarness(t, store, 8, 8)
	if err := h.trackOpen(credential.ID, store.handle, false); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		request func() *authoritypb.Request
		check   func(*testing.T, *authoritypb.Response)
	}{
		{
			name: "read",
			request: func() *authoritypb.Request {
				request := coherenceReadRequest(credential)
				request.Body = &authoritypb.Request_Read{Read: &authoritypb.ReadRequest{Handle: store.handle[:], Length: 8}}
				return request
			},
			check: func(t *testing.T, response *authoritypb.Response) {
				if string(response.GetRead().GetData()) != "coherent" || response.GetRead().GetVolumeVersion() != response.GetVolumeVersion() {
					t.Fatalf("READ response = %+v", response)
				}
			},
		},
		{
			name: "getattr",
			request: func() *authoritypb.Request {
				request := coherenceReadRequest(credential)
				request.Body = &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Handle: store.handle[:]}}
				return request
			},
			check: func(t *testing.T, response *authoritypb.Response) {
				if response.GetGetAttr().GetAttr().GetSize() != 8 || response.GetGetAttr().GetSnapshotSequence() != response.GetVolumeVersion() {
					t.Fatalf("GETATTR response = %+v", response)
				}
			},
		},
		{
			name: "fsync",
			request: func() *authoritypb.Request {
				request := coherenceReadRequest(credential)
				request.Body = &authoritypb.Request_Fsync{Fsync: &authoritypb.FsyncRequest{Handle: store.handle[:]}}
				return request
			},
			check: func(t *testing.T, response *authoritypb.Response) {
				if response.GetFsync() == nil || response.GetVolumeVersion() == 0 {
					t.Fatalf("FSYNC response = %+v", response)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := h.Handle(ctx, test.request())
			if response.GetErrno() != 0 || response.GetVolumeVersion() == 0 {
				t.Fatalf("response = %+v", response)
			}
			test.check(t, response)
		})
	}
	if store.read.Load() != 1 || store.attr.Load() != 1 || store.fsync.Load() != 1 {
		t.Fatalf("storage calls = read %d attr %d fsync %d", store.read.Load(), store.attr.Load(), store.fsync.Load())
	}
}

func TestCoherenceReadPathsRefuseExpiredSubscriptionBeforeStorage(t *testing.T) {
	tests := []struct {
		name    string
		request func(volumeserver.SessionCredential, xfsstore.Capability) *authoritypb.Request
	}{
		{"read", func(credential volumeserver.SessionCredential, handle xfsstore.Capability) *authoritypb.Request {
			request := coherenceReadRequest(credential)
			request.Body = &authoritypb.Request_Read{Read: &authoritypb.ReadRequest{Handle: handle[:], Length: 1}}
			return request
		}},
		{"getattr", func(credential volumeserver.SessionCredential, handle xfsstore.Capability) *authoritypb.Request {
			request := coherenceReadRequest(credential)
			request.Body = &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Handle: handle[:]}}
			return request
		}},
		{"fsync", func(credential volumeserver.SessionCredential, handle xfsstore.Capability) *authoritypb.Request {
			request := coherenceReadRequest(credential)
			request.Body = &authoritypb.Request_Fsync{Fsync: &authoritypb.FsyncRequest{Handle: handle[:]}}
			return request
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &coherenceReadPathStore{handle: xfsstore.Capability{0x45}, data: []byte("x")}
			h, ctx, credential, _ := resourceAdmissionRequestHarness(t, store, 8, 8)
			if err := h.trackOpen(credential.ID, store.handle, false); err != nil {
				t.Fatal(err)
			}
			h.Coherence.ExpireSession(credential.ID)
			response := h.Handle(ctx, test.request(credential, store.handle))
			if response.GetErrno() != int32(syscall.EIO) || response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE {
				t.Fatalf("expired response = %+v", response)
			}
			if store.read.Load()+store.attr.Load()+store.fsync.Load() != 0 {
				t.Fatal("expired subscription reached storage")
			}
		})
	}
}

func TestCoherenceReadWaitsForDelegationBreakBeforeStorage(t *testing.T) {
	store := &coherenceReadPathStore{handle: xfsstore.Capability{0x46}, data: []byte("x")}
	h, _, reader, root := resourceAdmissionRequestHarness(t, store, 8, 8)
	if err := h.trackOpen(reader.ID, store.handle, false); err != nil {
		t.Fatal(err)
	}
	holder := volumeserver.SessionID{0x92}
	if err := h.startSessionResources(holder, root, 2, routesRevisionOf("")); err != nil {
		t.Fatal(err)
	}
	readerToken, err := h.coherenceToken(reader.ID)
	if err != nil {
		t.Fatal(err)
	}
	holderToken, err := h.coherenceToken(holder)
	if err != nil {
		t.Fatal(err)
	}
	identity := [16]byte{store.handle[0]}
	reservation, err := h.Coherence.Reserve(context.Background(), holderToken, identity)
	if err != nil {
		t.Fatal(err)
	}
	readerEvents, err := h.Coherence.Poll(context.Background(), readerToken, 0, nil, 8)
	if err != nil || len(readerEvents) == 0 {
		t.Fatalf("reader grant withdrawal = events %+v err %v", readerEvents, err)
	}
	if err := h.Coherence.Ack(readerToken, readerEvents[len(readerEvents)-1].Position); err != nil {
		t.Fatal(err)
	}
	holderEvents, err := h.Coherence.Poll(context.Background(), holderToken, 0, nil, 8)
	if err != nil || len(holderEvents) == 0 {
		t.Fatalf("holder grant stream = events %+v err %v", holderEvents, err)
	}
	grant, err := reservation.Grant(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	response := make(chan *authoritypb.Response, 1)
	go func() {
		response <- h.coherenceReadData(context.Background(), 73, reader.ID, &authoritypb.ReadRequest{
			Handle: store.handle[:], Length: 1,
		})
	}()
	select {
	case reply := <-response:
		t.Fatalf("READ completed before delegation break ack: %+v", reply)
	case <-time.After(10 * time.Millisecond):
	}
	if store.read.Load() != 0 {
		t.Fatal("READ reached storage before delegation break ack")
	}

	after := holderEvents[len(holderEvents)-1].Position
	events, err := h.Coherence.Poll(context.Background(), holderToken, after, nil, 8)
	if err != nil {
		t.Fatal(err)
	}
	var event volumeserver.StreamEvent
	for _, candidate := range events {
		if candidate.Kind == volumeserver.StreamBreakForRead {
			event = candidate
			break
		}
	}
	if event.Kind != volumeserver.StreamBreakForRead {
		t.Fatalf("holder events = %+v, want break", events)
	}
	if err := h.Coherence.AckDelegation(holderToken, identity, grant.ID, grant.Generation, event.Request, event.AppliedSequence); err != nil {
		t.Fatal(err)
	}
	select {
	case reply := <-response:
		if reply.GetErrno() != 0 || string(reply.GetRead().GetData()) != "x" {
			t.Fatalf("READ after break = %+v", reply)
		}
	case <-time.After(time.Second):
		t.Fatal("READ did not resume after delegation break ack")
	}
}

type coherenceChangingDirectoryStore struct {
	resourceAdmissionFaultStore
	handle, directory xfsstore.Capability
	calls             atomic.Uint32
}

type coherenceEmptyDirectoryStore struct {
	resourceAdmissionFaultStore
	handle, directory xfsstore.Capability
	calls             atomic.Uint32
}

func (s *coherenceEmptyDirectoryStore) IdentityOpen(handle xfsstore.Capability) ([16]byte, error) {
	if handle != s.handle {
		return [16]byte{}, syscall.EBADF
	}
	return [16]byte{handle[0]}, nil
}

func (s *coherenceEmptyDirectoryStore) ReadDirOpen(
	handle xfsstore.Capability,
	cookie uint64,
	_ int,
) ([]xfsstore.Dirent, uint64, [16]byte, bool, xfsstore.Capability, error) {
	if handle != s.handle {
		return nil, 0, [16]byte{}, false, xfsstore.Capability{}, syscall.EBADF
	}
	s.calls.Add(1)
	return nil, cookie, [16]byte{0x73}, true, s.directory, nil
}

func (*coherenceEmptyDirectoryStore) CloseOpen(xfsstore.Capability) error { return nil }

type coherenceLookupStore struct {
	resourceAdmissionFaultStore
}

func (s *coherenceLookupStore) Getattr(item xfsstore.Capability) (xfsstore.Attr, error) {
	if item == s.lookupItem {
		return xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 2, Size: 7, Mode: 0o600, Nlink: 1, DeviceMinor: 1}, nil
	}
	return s.resourceAdmissionFaultStore.Getattr(item)
}

func TestCoherenceLookupAndEmptyReadDirCarrySampledVersion(t *testing.T) {
	t.Run("positive lookup", func(t *testing.T) {
		store := &coherenceLookupStore{resourceAdmissionFaultStore: resourceAdmissionFaultStore{
			lookupItem: xfsstore.Capability{0x33},
		}}
		h, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 8, 8)
		request := coherenceReadRequest(credential)
		request.Body = &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: root[:], Name: []byte("child")}}
		stampMutation(t, request, 0, 1)

		response := h.Handle(ctx, request)
		item := response.GetLookup().GetItem()
		if response.GetErrno() != 0 || response.GetVolumeVersion() == 0 || item == nil {
			t.Fatalf("LOOKUP response = %+v", response)
		}
		if item.GetSnapshotSequence() != response.GetVolumeVersion() || item.GetObjectVersion() == 0 || item.GetAttr().GetSize() != 7 {
			t.Fatalf("LOOKUP item = %+v, envelope version %d", item, response.GetVolumeVersion())
		}
	})

	t.Run("negative lookup", func(t *testing.T) {
		store := &coherenceLookupStore{}
		h, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 8, 8)
		request := coherenceReadRequest(credential)
		request.Body = &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: root[:], Name: []byte("missing")}}
		stampMutation(t, request, 0, 1)

		response := h.Handle(ctx, request)
		lookup := response.GetLookup()
		if response.GetErrno() != 0 || response.GetVolumeVersion() == 0 || lookup == nil || lookup.GetItem() != nil {
			t.Fatalf("negative LOOKUP response = %+v", response)
		}
		if lookup.GetNegativeSnapshotSequence() != response.GetVolumeVersion() {
			t.Fatalf("negative sequence = %d, envelope version %d", lookup.GetNegativeSnapshotSequence(), response.GetVolumeVersion())
		}
	})

	t.Run("empty readdir", func(t *testing.T) {
		store := &coherenceEmptyDirectoryStore{
			handle: xfsstore.Capability{0x51}, directory: xfsstore.Capability{0x52},
		}
		h, ctx, credential, _ := resourceAdmissionRequestHarness(t, store, 8, 8)
		if err := h.trackOpen(credential.ID, store.handle, false); err != nil {
			t.Fatal(err)
		}
		request := coherenceReadRequest(credential)
		request.Body = &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{Handle: store.handle[:], MaxEntries: 8}}
		stampMutation(t, request, 0, 1)

		response := h.Handle(ctx, request)
		page := response.GetReadDir()
		if response.GetErrno() != 0 || response.GetVolumeVersion() == 0 || page == nil || !page.GetEof() || len(page.GetEntries()) != 0 {
			t.Fatalf("empty READDIR response = %+v", response)
		}
		if calls := store.calls.Load(); calls != 2 {
			t.Fatalf("ReadDirOpen calls = %d, want initial read and locked revalidation", calls)
		}
	})
}

func (s *coherenceChangingDirectoryStore) ReadDirOpen(
	handle xfsstore.Capability,
	cookie uint64,
	max int,
) ([]xfsstore.Dirent, uint64, [16]byte, bool, xfsstore.Capability, error) {
	if handle != s.handle {
		return nil, 0, [16]byte{}, false, xfsstore.Capability{}, syscall.EBADF
	}
	s.calls.Add(1)
	fresh := [16]byte{0x91}
	all := []xfsstore.Dirent{
		{Name: "a", Kind: xfsstore.KindRegular, Ino: 1, NextCookie: 1},
		{Name: "b", Kind: xfsstore.KindRegular, Ino: 2, NextCookie: 2},
		{Name: "c", Kind: xfsstore.KindRegular, Ino: 3, NextCookie: 3},
	}
	if cookie > uint64(len(all)) {
		return nil, uint64(len(all)), fresh, true, s.directory, nil
	}
	end := cookie + uint64(max)
	if end > uint64(len(all)) {
		end = uint64(len(all))
	}
	return append([]xfsstore.Dirent(nil), all[cookie:end]...), end, fresh, end == uint64(len(all)), s.directory, nil
}

func TestCoherenceReadDirContinuesAfterDirectoryChangeWithoutESTALE(t *testing.T) {
	store := &coherenceChangingDirectoryStore{
		handle: xfsstore.Capability{0x41}, directory: xfsstore.Capability{0x42},
	}
	h := &VolumeHandler{Store: store}
	entries, next, verifier, eof, directory, err := h.coherenceReadDirPage(store.handle, 2, 2)
	if err != nil {
		t.Fatalf("continued page: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "c" || next != 3 || !eof {
		t.Fatalf("continued page = entries=%+v next=%d eof=%v", entries, next, eof)
	}
	if verifier != ([16]byte{0x91}) || directory != store.directory {
		t.Fatalf("continued coordinates = verifier=%x directory=%x", verifier, directory)
	}
	if calls := store.calls.Load(); calls != 1 {
		t.Fatalf("ReadDirOpen calls = %d, want direct stable-cookie continuation", calls)
	}
}

func TestCoherenceReadDependenciesCoverBindingsAndObjects(t *testing.T) {
	parent := [16]byte{0x11}
	child := [16]byte{0x22}
	got := coherenceBindingDependencies(parent, []byte("child"), child)
	want := volumeserver.MutationDependenciesForTargets([]volumeserver.VisibilityTarget{
		{
			Scope: volumeserver.VisibilityNamespace, ParentIdentity: parent, Name: []byte("child"),
			RelatedIdentities: [][16]byte{child},
		},
	})
	if !got.Equal(want) {
		t.Fatal("lookup did not acquire the complete parent/name/child footprint")
	}

	h := &VolumeHandler{}
	directory := [16]byte{0x31}
	candidates := []directoryPageCandidate{{
		identity: child,
		dirent:   &authoritypb.Dirent{Name: []byte("child")},
	}}
	got = h.coherenceDirectoryDependencies(directory, candidates)
	want = volumeserver.MutationDependenciesForTargets([]volumeserver.VisibilityTarget{
		{Scope: volumeserver.VisibilityAttributes, Identity: directory},
		{
			Scope: volumeserver.VisibilityNamespace, ParentIdentity: directory, Name: []byte("child"),
			RelatedIdentities: [][16]byte{child},
		},
		{Scope: volumeserver.VisibilityAttributes, Identity: child},
	})
	if !got.Equal(want) {
		t.Fatal("readdir did not acquire the complete directory/name/child footprint")
	}
}

func BenchmarkCoherenceReadGuard(b *testing.B) {
	coordinator := volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{})
	snapshot, err := coordinator.Subscribe(volumeserver.SessionID{0x51})
	if err != nil {
		b.Fatal(err)
	}
	identity := [16]byte{0x61}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		guard, guardErr := coordinator.DataConsumed(ctx, snapshot.Token, identity)
		if guardErr != nil {
			b.Fatal(guardErr)
		}
		guard.Release()
	}
}

func TestCoherenceReadDirRefusesMalformedVerifierBeforeEnumeration(t *testing.T) {
	for _, size := range []int{1, 15, 17} {
		store := &coherenceEmptyDirectoryStore{handle: xfsstore.Capability{0x51}, directory: xfsstore.Capability{0x52}}
		h, ctx, credential, _ := resourceAdmissionRequestHarness(t, store, 8, 8)
		if err := h.trackOpen(credential.ID, store.handle, false); err != nil {
			t.Fatal(err)
		}
		request := coherenceReadRequest(credential)
		request.Body = &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{Handle: store.handle[:], MaxEntries: 8, Verifier: make([]byte, size)}}
		stampMutation(t, request, 0, 1)
		response := h.Handle(ctx, request)
		if response.GetErrno() != int32(syscall.EINVAL) || store.calls.Load() != 0 {
			t.Fatalf("verifier size %d: response=%v enumeration calls=%d", size, response, store.calls.Load())
		}
	}
}
