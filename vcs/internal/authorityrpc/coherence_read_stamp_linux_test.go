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

func TestCoherenceMetadataStampsStayInsideStorageReadTurn(t *testing.T) {
	for _, kind := range []string{"lookup", "readdir"} {
		t.Run(kind, func(t *testing.T) {
			sampled, proceed := make(chan struct{}), make(chan struct{})
			var store volumeStore
			child := xfsstore.Capability{0x75}
			var directory *readdirGuardStore
			if kind == "lookup" {
				store = &lookupStampCutStore{coherenceLookupStore: coherenceLookupStore{resourceAdmissionFaultStore: resourceAdmissionFaultStore{lookupItem: child}}, sampled: sampled, proceed: proceed}
			} else {
				directory = &readdirGuardStore{readdirPostStabilizationChangeStore: readdirPostStabilizationChangeStore{root: xfsstore.Capability{0x72}, handle: xfsstore.Capability{0x74}, child: child}, sampling: sampled, proceed: proceed}
				store = directory
			}
			h, ctx, credential, root := resourceAdmissionRequestHarness(t, store, 8, 8)
			request := coherenceReadRequest(credential)
			if kind == "lookup" {
				request.Body = &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: root[:], Name: []byte("child")}}
			} else {
				if err := h.trackOpen(credential.ID, directory.handle, false); err != nil {
					t.Fatal(err)
				}
				request.Body = &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{Handle: directory.handle[:], MaxEntries: 8, WantItems: true}}
			}
			stampMutation(t, request, 0, 1)
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
