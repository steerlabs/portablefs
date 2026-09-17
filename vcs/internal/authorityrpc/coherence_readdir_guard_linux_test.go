//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

type readdirGuardStore struct {
	readdirPostStabilizationChangeStore
	sampling, proceed chan struct{}
}

func (s *readdirGuardStore) ReadDirOpen(handle xfsstore.Capability, cookie uint64, maxEntries int) ([]xfsstore.Dirent, uint64, [16]byte, bool, xfsstore.Capability, error) {
	entries, next, verifier, eof, directory, err := s.readdirPostStabilizationChangeStore.ReadDirOpen(handle, cookie, maxEntries)
	if s.readDirCalls.Load() == 2 {
		close(s.sampling)
		<-s.proceed
	}
	return entries, next, verifier, eof, directory, err
}
func (s *readdirGuardStore) LookupOpen(xfsstore.Capability, string) (xfsstore.Capability, xfsstore.Attr, error) {
	return s.child, xfsstore.Attr{Kind: xfsstore.KindRegular, Ino: uint64(s.child[0]), Mode: os.FileMode(0600), Nlink: 1, DeviceMinor: 1}, nil
}

func TestCoherenceReadDirRetainsEveryReadGuardThroughStorageRevalidation(t *testing.T) {
	store := &readdirGuardStore{readdirPostStabilizationChangeStore: readdirPostStabilizationChangeStore{
		root: xfsstore.Capability{0x72}, handle: xfsstore.Capability{0x74}, child: xfsstore.Capability{0x75},
	}, sampling: make(chan struct{}), proceed: make(chan struct{})}
	h, ctx, credential, _ := resourceAdmissionRequestHarness(t, store, 8, 8)
	if err := h.trackOpen(credential.ID, store.handle, false); err != nil {
		t.Fatal(err)
	}
	peer, err := h.Coherence.Subscribe(volumeserver.SessionID{91})
	if err != nil {
		t.Fatal(err)
	}
	request := coherenceReadRequest(credential)
	request.Body = &authoritypb.Request_ReadDir{ReadDir: &authoritypb.ReadDirRequest{Handle: store.handle[:], MaxEntries: 8, WantItems: true}}
	stampMutation(t, request, 0, 1)
	done := make(chan *authoritypb.Response, 1)
	go func() { done <- h.Handle(ctx, request) }()
	select {
	case <-store.sampling:
	case response := <-done:
		t.Fatalf("read skipped locked sample: %v", response)
	case <-time.After(time.Second):
		t.Fatal("missing storage sample")
	}
	for _, id := range [][16]byte{{store.root[0]}, {store.child[0]}} {
		wait, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		reservation, err := h.Coherence.Reserve(wait, peer.Token, id)
		cancel()
		if reservation != nil {
			reservation.Abort()
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			close(store.proceed)
			t.Fatalf("delegation %x entered during page sample: %v", id, err)
		}
	}
	close(store.proceed)
	select {
	case response := <-done:
		if response.GetErrno() != 0 || len(response.GetReadDir().GetEntries()) != 1 {
			t.Fatalf("read response: %v", response)
		}
	case <-time.After(time.Second):
		t.Fatal("read guard did not release")
	}
	for _, id := range [][16]byte{{store.root[0]}, {store.child[0]}} {
		wait, cancel := context.WithTimeout(t.Context(), time.Second)
		reservation, err := h.Coherence.Reserve(wait, peer.Token, id)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		reservation.Abort()
	}
}
