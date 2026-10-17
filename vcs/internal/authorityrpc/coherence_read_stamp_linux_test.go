//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
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
	for _, profile := range []authoritypb.FrontendProfile{authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR} {
		for _, kind := range []string{"lookup", "readdir", "item getattr", "handle getattr"} {
			t.Run(profile.String()+"/"+kind, func(t *testing.T) {
				sampled, proceed := make(chan struct{}), make(chan struct{})
				var store volumeStore
				child := xfsstore.Capability{0x75}
				var directory *readdirGuardStore
				if kind != "readdir" {
					store = &lookupStampCutStore{coherenceLookupStore: coherenceLookupStore{resourceAdmissionFaultStore: resourceAdmissionFaultStore{lookupItem: child}}, sampled: sampled, proceed: proceed}
				} else {
					directory = &readdirGuardStore{readdirPostStabilizationChangeStore: readdirPostStabilizationChangeStore{root: xfsstore.Capability{0x72}, handle: xfsstore.Capability{0x74}, child: child}, sampling: sampled, proceed: proceed}
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
				} else if kind == "handle getattr" {
					if err := h.trackOpen(credential.ID, child, false); err != nil {
						t.Fatal(err)
					}
					request.Body = &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Handle: child[:]}}
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
				h.postStateMu.Lock()
				close(proceed)
				wait, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
				release, err := h.coherenceStorage.Acquire(wait, coherenceInodeDependencies([16]byte{child[0]}))
				cancel()
				if release != nil {
					release()
				}
				h.postStateMu.Unlock()
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
