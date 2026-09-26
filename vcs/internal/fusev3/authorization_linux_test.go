//go:build linux

package fusev3

import (
	"context"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"sync/atomic"
	"testing"
	"time"
)

type authorizationTestRPC struct {
	*recoveringFrontendTestRPC
	id               volumeserver.SessionID
	calls            atomic.Int32
	started, proceed chan struct{}
}

func (r *authorizationTestRPC) AuthorizationSessionID() volumeserver.SessionID { return r.id }
func (r *authorizationTestRPC) InitialAuthorizationDeadline() time.Time {
	return time.Now().Add(time.Hour)
}
func (r *authorizationTestRPC) Reauthorize(ctx context.Context, _ []byte, _ uint64) (time.Time, error) {
	r.calls.Add(1)
	if r.started != nil {
		close(r.started)
		select {
		case <-r.proceed:
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		}
	}
	return r.InitialAuthorizationDeadline(), nil
}
func TestAuthorizationSessionSnapshotNeverCrossesEpoch(t *testing.T) {
	next := &authorizationTestRPC{recoveringFrontendTestRPC: &recoveringFrontendTestRPC{fakeRPC: newFakeRPC()}, id: volumeserver.SessionID{2}}
	old := &authorizationTestRPC{recoveringFrontendTestRPC: &recoveringFrontendTestRPC{fakeRPC: newFakeRPC(), next: next}, id: volumeserver.SessionID{1}, started: make(chan struct{}), proceed: make(chan struct{})}
	facade := newEpochRPC(old)
	mount := &Mount{rpc: facade}
	snapshot, changed, err := mount.CurrentAuthorizationSession()
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := snapshot.Reauthorize(context.Background(), []byte("old"), 1); result <- err }()
	<-old.started
	if err := facade.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	default:
		t.Fatal("epoch publication did not retire snapshot")
	}
	close(old.proceed)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	current, newChanged, err := mount.CurrentAuthorizationSession()
	if err != nil {
		t.Fatal(err)
	}
	if current.AuthorizationSessionID() != next.id || changed == newChanged {
		t.Fatal("replacement snapshot did not change")
	}
	if next.calls.Load() != 0 {
		t.Fatal("old token crossed epoch")
	}
	if _, err := current.Reauthorize(context.Background(), []byte("new"), 1); err != nil {
		t.Fatal(err)
	}
	if next.calls.Load() != 1 || old.calls.Load() != 1 {
		t.Fatal("renewal did not target exact session")
	}
}
