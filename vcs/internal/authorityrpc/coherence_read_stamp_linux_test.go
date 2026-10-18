//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

type lookupStampCutStore struct {
	coherenceLookupStore
	sampled, proceed chan struct{}
}

func (s *lookupStampCutStore) Getattr(item xfsstore.Capability) (xfsstore.Attr, error) {
	if item == s.lookupItem {
		close(s.sampled)
		<-s.proceed
	}
	return s.coherenceLookupStore.Getattr(item)
}

func (s *lookupStampCutStore) IdentityOpen(xfsstore.Capability) ([16]byte, error) {
	return [16]byte{s.lookupItem[0]}, nil
}
func (s *lookupStampCutStore) GetattrOpen(xfsstore.Capability) (xfsstore.Attr, error) {
	return s.Getattr(s.lookupItem)
}
func (s *lookupStampCutStore) CloseOpen(xfsstore.Capability) error { return nil }

func TestCoherenceMetadataStampsStayInsideStorageReadTurn(t *testing.T) {
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE} {
		for _, kind := range []string{"lookup", "readdir", "item getattr", "handle getattr", "item and handle getattr"} {
			if kind == "item and handle getattr" && profile != authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE {
				continue
			}
			t.Run(profile.String()+"/"+kind, func(t *testing.T) {
				sampled, proceed := make(chan struct{}), make(chan struct{})
				var store volumeStore
				child := xfsstore.Capability{0x75}
				var directory *readdirGuardStore
				if kind != "readdir" {
					store = &lookupStampCutStore{coherenceLookupStore: coherenceLookupStore{resourceAdmissionFaultStore: resourceAdmissionFaultStore{lookupItem: child}}, sampled: sampled, proceed: proceed}
				} else {
					directory = &readdirGuardStore{readdirPageChangeStore: readdirPageChangeStore{root: xfsstore.Capability{0x72}, handle: xfsstore.Capability{0x74}, child: child}, sampling: sampled, proceed: proceed}
					store = directory
				}
				h, ctx, credential, root := resourceAdmissionRequestHarnessForProfile(t, store, 8, 8, profile)
				request := coherenceReadRequest(credential)
				if kind == "lookup" {
					request.Body = &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: root[:], Name: []byte("child")}}
				} else if kind == "item getattr" {
					if err := h.trackItem(credential.ID, child, false); err != nil {
						t.Fatal(err)
					}
					request.Body = &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Item: child[:]}}
				} else if kind == "handle getattr" || kind == "item and handle getattr" {
					if err := h.trackOpen(credential.ID, child, false); err != nil {
						t.Fatal(err)
					}
					get := &authoritypb.GetAttrRequest{Handle: child[:]}
					if kind == "item and handle getattr" {
						if err := h.trackItem(credential.ID, child, false); err != nil {
							t.Fatal(err)
						}
						get.Item = child[:]
					}
					request.Body = &authoritypb.Request_GetAttr{GetAttr: get}
				} else {
					if err := h.trackOpen(credential.ID, directory.handle, false); err != nil {
						t.Fatal(err)
					}
					request.Body = &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{Handle: directory.handle[:], MaxEntries: 8, WantItems: true}}
				}
				if kind == "lookup" || kind == "readdir" {
					stampMutation(t, request, 0, 1)
				}
				done := make(chan *authoritypb.Response, 1)
				go func() { done <- h.Handle(ctx, request) }()
				select {
				case <-sampled:
				case response := <-done:
					t.Fatalf("missing read sample: %v", response)
				case <-time.After(time.Second):
					t.Fatal("missing read sample")
				}
				h.coherenceCommitMu.Lock()
				close(proceed)
				wait, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
				release, err := h.coherenceStorage.Acquire(wait, coherenceInodeDependencies([16]byte{child[0]}))
				cancel()
				if release != nil {
					release()
				}
				h.coherenceCommitMu.Unlock()
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("peer entered while object-version sample was blocked: %v", err)
				}
				select {
				case response := <-done:
					if response.GetErrno() != 0 {
						t.Fatal(response)
					}
				case <-time.After(time.Second):
					t.Fatal("read did not complete after stamp released")
				}
			})
		}
	}
}

func TestReadStampAfterCompactionUsesCurrentCut(t *testing.T) {
	child := xfsstore.Capability{0x75}
	sampled, proceed := make(chan struct{}), make(chan struct{})
	store := &lookupStampCutStore{coherenceLookupStore: coherenceLookupStore{resourceAdmissionFaultStore: resourceAdmissionFaultStore{lookupItem: child}}, sampled: sampled, proceed: proceed}
	h, ctx, credential, _ := resourceAdmissionRequestHarnessForProfile(t, store, 8, 8, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE)
	h.objectVersionLimit = 4
	if err := h.trackItem(credential.ID, child, false); err != nil {
		t.Fatal(err)
	}
	request := coherenceReadRequest(credential)
	request.Body = &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Item: child[:]}}
	done := make(chan *authoritypb.Response, 1)
	go func() { done <- h.Handle(ctx, request) }()
	<-sampled
	// An unrelated storage turn may commit and compact while this read holds
	// the child's attributes stable. The stamp must sample floor and sequence
	// together afterwards, rather than clamp an old sequence to a new floor.
	for n := byte(1); n < 25; n++ {
		identity := postStateTestIdentity(n)
		changed := new(mutationChanges)
		response := &authoritypb.Response{PostState: h.mutationPostState(changed, 1, postStateSnapshot{identity: identity, attr: xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: uint64(n)}, roles: postStateRoleTarget, changed: true})}
		h.publishCoherenceCommit(&authoritypb.Request{}, volumeserver.SessionID{}, [16]byte{}, response, []volumeserver.MutationTarget{}, changed)
	}
	close(proceed)
	response := <-done
	get := response.GetGetAttr()
	if response.GetErrno() != 0 || get.GetObjectVersion() <= 1 || get.GetObjectVersion() > get.GetSnapshotSequence() || get.GetSnapshotSequence() != h.coherenceVersionNow() {
		t.Fatalf("read did not capture the compacted committed cut: %v", response)
	}
}

func TestReadStampCapturesCompactionAtOneCommittedCut(t *testing.T) {
	h := testVolumeHandler()
	h.initCoherence()
	h.objectVersionLimit = 4
	commit := func(n byte) {
		identity := postStateTestIdentity(n)
		changed := &mutationChanges{}
		changed.add(identity)
		h.publishCoherenceCommit(&authoritypb.Request{}, volumeserver.SessionID{}, [16]byte{}, &authoritypb.Response{}, []volumeserver.MutationTarget{}, changed)
	}
	for n := byte(1); n <= 4; n++ {
		commit(n)
	}
	before := h.coherenceVersionNow()
	sampled, proceed := make(chan struct{}), make(chan struct{})
	h.afterVersionSequence = func() { close(sampled); <-proceed }
	defer func() {
		select {
		case <-proceed:
		default:
			close(proceed)
		}
	}()
	type stamp struct {
		sequence uint64
		versions []uint64
	}
	read := make(chan stamp, 1)
	go func() { s, v := h.sampleVersions(postStateTestIdentity(99)); read <- stamp{s, v} }()
	waitWriteTestSignal(t, sampled, "sequence read inside version sample")
	// A commit here must not change the floor between sequence and entry reads.
	// TryLock checks the exclusion at the precise hook, without a scheduling wait.
	if h.coherenceCommitMu.TryLock() {
		h.coherenceCommitMu.Unlock()
		t.Fatal("version sample released commit ordering between tuple fields")
	}
	compacted := make(chan struct{})
	go func() { commit(5); close(compacted) }()
	close(proceed)
	got := <-read
	waitWriteTestSignal(t, compacted, "compaction after coherent version sample")
	if got.sequence != before || len(got.versions) != 1 || got.versions[0] != 1 || h.objectVersionFloor != before {
		t.Fatalf("mixed sample=%+v, before=%d, compacted floor=%d", got, before, h.objectVersionFloor)
	}
}
