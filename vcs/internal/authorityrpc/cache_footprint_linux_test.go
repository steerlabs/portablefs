//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

func requireAdmittedChange(t *testing.T, h *VolumeHandler, change volumeserver.ChangeEntry, want bool) {
	t.Helper()
	// A canceled wait still returns nil when no subscriber could cache the
	// coordinate. It returns cancellation when a real withdrawal is pending.
	w := h.Coherence.OnCommitTargeted([]volumeserver.ChangeEntry{change}, volumeserver.SubscriptionToken{}, volumeserver.CacheAdmission{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := h.Coherence.WaitTargeted(ctx, w)
	if errors.Is(err, context.Canceled) != want {
		t.Fatalf("change %+v pending=%v want %v: %v", change, errors.Is(err, context.Canceled), want, err)
	}
}

func TestCoherenceReplyCacheAdmissions(t *testing.T) {
	for _, cacheless := range []bool{false, true} {
		for _, kind := range []string{"negative", "positive", "getattr", "read", "readdir", "readdirplus"} {
			name := kind
			if cacheless {
				name += "-cacheless"
			}
			t.Run(name, func(t *testing.T) {
				store := &footprintReadStore{coherenceReadPathStore: coherenceReadPathStore{handle: xfsstore.Capability{0x44}, data: []byte("coherent")}}
				if kind != "negative" {
					store.lookupItem = xfsstore.Capability{0x33}
				}
				profile := authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES
				if cacheless {
					profile = authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER
				}
				h, ctx, cred, root := resourceAdmissionRequestHarnessForProfile(t, store, 16, 16, profile)
				if err := h.trackOpen(cred.ID, store.handle, false); err != nil {
					t.Fatal(err)
				}
				req := coherenceReadRequest(cred)
				var expected []volumeserver.ChangeEntry
				switch kind {
				case "negative", "positive":
					req.Body = &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: root[:], Name: []byte("name")}}
					expected = append(expected, volumeserver.ChangeEntry{Kind: volumeserver.NamespaceChanged, ParentIdentity: [16]byte{root[0]}})
					if kind == "positive" {
						expected = append(expected, volumeserver.ChangeEntry{Kind: volumeserver.AttributesChanged, Identity: [16]byte{store.lookupItem[0]}})
					}
				case "getattr":
					req.Body = &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Handle: store.handle[:]}}
					expected = append(expected, volumeserver.ChangeEntry{Kind: volumeserver.AttributesChanged, Identity: [16]byte{store.handle[0]}})
				case "read":
					req.Body = &authoritypb.Request_Read{Read: &authoritypb.ReadRequest{Handle: store.handle[:], Length: 8}}
					expected = append(expected, volumeserver.ChangeEntry{Kind: volumeserver.DataChanged, Identity: [16]byte{store.handle[0]}})
				case "readdir", "readdirplus":
					req.Body = &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{Handle: store.handle[:], MaxEntries: 8, WantItems: kind == "readdirplus"}}
					expected = append(expected, volumeserver.ChangeEntry{Kind: volumeserver.DirectoryChanged, Identity: [16]byte{store.handle[0]}})
					if kind == "readdirplus" {
						expected = append(expected, volumeserver.ChangeEntry{Kind: volumeserver.AttributesChanged, Identity: [16]byte{store.lookupItem[0]}})
					}
				}
				stampMutation(t, req, 0, 1)
				response := h.Handle(ctx, req)
				if response.GetErrno() != 0 {
					t.Fatal(response)
				}
				if kind == "readdirplus" && len(response.GetReadDir().GetEntries()) != 1 {
					t.Fatalf("missing plus item: %v", response)
				}
				for _, change := range expected {
					requireAdmittedChange(t, h, change, !cacheless)
				}
				if kind == "readdir" {
					requireAdmittedChange(t, h, volumeserver.ChangeEntry{Kind: volumeserver.AttributesChanged, Identity: [16]byte{store.lookupItem[0]}}, !cacheless)
				}
			})
		}
	}
}

type footprintReadStore struct{ coherenceReadPathStore }

func (s *footprintReadStore) ReadDirOpen(_ xfsstore.Capability, cookie uint64, _ int) ([]xfsstore.Dirent, uint64, [16]byte, bool, xfsstore.Capability, error) {
	return []xfsstore.Dirent{{Name: "name", Kind: xfsstore.KindRegular, Ino: 2, NextCookie: 1}}, cookie + 1, [16]byte{0x77}, true, s.handle, nil
}

func TestCoherenceSourceReplyAdmitsUnchangedCreateAndNewDirectory(t *testing.T) {
	t.Run("existing-create", func(t *testing.T) {
		item := xfsstore.Capability{0x33}
		store := &coherenceExistingCreateStore{resourceAdmissionFaultStore: resourceAdmissionFaultStore{lookupItem: item}, item: item, handle: xfsstore.Capability{0x44}}
		h, ctx, cred, root := resourceAdmissionRequestHarness(t, store, 8, 8)
		req := coherenceExistingCreateRequest(cred, root)
		response := h.Handle(ctx, req)
		if response.GetErrno() != 0 {
			t.Fatal(response)
		}
		requireAdmittedChange(t, h, volumeserver.ChangeEntry{Kind: volumeserver.NamespaceChanged, ParentIdentity: [16]byte{root[0]}}, true)
		requireAdmittedChange(t, h, volumeserver.ChangeEntry{Kind: volumeserver.AttributesChanged, Identity: [16]byte{item[0]}}, true)
	})
	t.Run("mkdir-completeness", func(t *testing.T) {
		h, _ := newCoherenceControlTestHandler(t, 1<<20)
		_, token := subscribeCoherenceControlTest(t, h, volumeserver.SessionID{1})
		parent, child := [16]byte{2}, [16]byte{3}
		gate := volumeserver.SourcePublicationGate{Targets: []volumeserver.SourcePublicationTarget{{ParentIdentity: parent, Name: []byte("dir")}}}
		response := &authoritypb.Response{PostState: &authoritypb.PostState{Objects: []*authoritypb.ObjectPostState{{StableIdentity: child[:], Attr: &authoritypb.Attr{Kind: authoritypb.Attr_DIRECTORY}}}}}
		h.Coherence.OnCommitTargeted(nil, token, sourceCacheAdmission(gate, response))
		requireAdmittedChange(t, h, volumeserver.ChangeEntry{Kind: volumeserver.NamespaceChanged, ParentIdentity: child, Name: "new"}, true)
		requireAdmittedChange(t, h, volumeserver.ChangeEntry{Kind: volumeserver.AttributesChanged, Identity: child}, true)
	})
}

func TestCoherenceSubscribeDoesNotAdmitPreSubscriptionRootAttributes(t *testing.T) {
	h, _ := newCoherenceControlTestHandler(t, 1<<20)
	session := volumeserver.SessionID{1}
	root := [16]byte{9}
	h.resources = map[volumeserver.SessionID]*sessionResources{session: {activationReply: &authoritypb.ActivateReply{Root: &authoritypb.Item{StableIdentity: root[:]}}}}
	subscribeCoherenceControlTest(t, h, session)
	requireAdmittedChange(t, h, volumeserver.ChangeEntry{Kind: volumeserver.AttributesChanged, Identity: root}, false)
}

type coldDuringAttrStore struct {
	coherenceReadPathStore
	cold func()
}

func (s *coldDuringAttrStore) GetattrOpen(handle xfsstore.Capability) (xfsstore.Attr, error) {
	attr, err := s.coherenceReadPathStore.GetattrOpen(handle)
	s.cold()
	return attr, err
}
func TestCacheAdmissionRejectsReadSampledAcrossColdSubscription(t *testing.T) {
	store := &coldDuringAttrStore{coherenceReadPathStore: coherenceReadPathStore{handle: xfsstore.Capability{0x44}, data: []byte("data")}}
	h, ctx, cred, _ := resourceAdmissionRequestHarness(t, store, 8, 8)
	if err := h.trackOpen(cred.ID, store.handle, false); err != nil {
		t.Fatal(err)
	}
	store.cold = func() {
		response := h.handleCoherenceSubscribe(0, cred.ID, &authoritypb.SubscribeRequest{})
		if response.GetErrno() != 0 {
			t.Fatal(response)
		}
	}
	response := h.coherenceGetAttr(ctx, 1, cred.ID, &authoritypb.GetAttrRequest{Handle: store.handle[:]})
	if response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE || response.GetErrno() == 0 {
		t.Fatalf("old sample entered cold incarnation: %v", response)
	}
	requireAdmittedChange(t, h, volumeserver.ChangeEntry{Kind: volumeserver.AttributesChanged, Identity: [16]byte{store.handle[0]}}, false)
}

func TestCoherenceMutationReplyRefusedIfColdSubscribeWinsCommit(t *testing.T) {
	h, cred, store := newWriteHarness(t)
	token, _ := h.coherenceToken(cred.ID)
	grant, err := h.Coherence.DataMutated(t.Context(), token, [16]byte{0x41})
	if err != nil {
		t.Fatal(err)
	}
	target := &writeTestTarget{committed: 4, post: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: 7, Size: 4, Mode: 0600, Nlink: 1}, started: make(chan struct{}), release: make(chan struct{})}
	handle := prepareOneShotTarget(t, h, cred, store, target)
	req := stockWriteTestRequest(1, 0, 1, handle, []byte("data"), 0, 0)
	req.GetWrite().Delegation = coherenceDelegationRefProto(grant)
	done := make(chan *authoritypb.Response, 1)
	go func() { done <- h.handleWrite(t.Context(), req, cred, req.GetWrite()) }()
	<-target.started
	cold := h.handleCoherenceSubscribe(0, cred.ID, &authoritypb.SubscribeRequest{})
	if cold.GetErrno() != 0 {
		t.Fatal(cold)
	}
	close(target.release)
	result := <-done
	if !result.GetUncertain() || result.GetErrno() == 0 || result.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE || result.GetWrite() != nil || result.GetPostState() != nil {
		t.Fatalf("old commit published cache-bearing reply: %v", result)
	}
	if calls, _ := target.commitSnapshot(); calls != 1 {
		t.Fatalf("actual storage applications=%d", calls)
	}
	replay := h.handleWrite(t.Context(), req, cred, req.GetWrite())
	if replay.GetErrno() != result.GetErrno() || replay.GetFailure() != result.GetFailure() || !replay.GetUncertain() || replay.GetWrite() != nil || replay.GetPostState() != nil {
		t.Fatalf("refusal replay changed: %v", replay)
	}
	if calls, _ := target.commitSnapshot(); calls != 1 {
		t.Fatalf("replay reapplied storage %d times", calls)
	}
}
