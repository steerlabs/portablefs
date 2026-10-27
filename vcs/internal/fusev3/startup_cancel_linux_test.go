//go:build linux

package fusev3

import (
	"context"
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/permissionclock"
	"sync"
	"testing"
	"time"
)

type startupBlockedRPC struct {
	*fakeRPC
	entered chan struct{}
	once    sync.Once
}

func (r *startupBlockedRPC) Subscribe(ctx context.Context, _, _ []byte) (*authoritypb.SubscribeReply, permissionclock.Permission, error) {
	r.once.Do(func() { close(r.entered) })
	<-ctx.Done()
	return nil, permissionclock.Permission{}, ctx.Err()
}
func TestPreKernelSubscriptionUsesStartupCancellation(t *testing.T) {
	rpc := &startupBlockedRPC{fakeRPC: newFakeRPC(), entered: make(chan struct{})}
	startup, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := MountVolume(context.Background(), startup, t.TempDir(), rpc, testConfig(9))
		done <- err
	}()
	select {
	case <-rpc.entered:
	case <-time.After(time.Second):
		t.Fatal("pre-kernel subscription did not enter")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !FailedStartupClean(err) {
			t.Fatal("startup cancellation did not prove pre-kernel cleanup", err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup cancellation waited for serving lifetime")
	}
	rpc.mu.Lock()
	defer rpc.mu.Unlock()
	if len(rpc.detachProofs) != 1 || rpc.closes != 1 {
		t.Fatal("pre-kernel cancellation did not release session", len(rpc.detachProofs), rpc.closes)
	}
}
