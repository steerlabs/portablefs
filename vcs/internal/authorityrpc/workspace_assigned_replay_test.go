package authorityrpc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

func TestWorkspaceAssignedReplayOutlivesAttemptAndCacheDeadline(t *testing.T) {
	for _, kind := range []string{"mkdir", "close", "barrier"} {
		t.Run(kind, func(t *testing.T) { workspaceAssignedReplayOutlivesAttempt(t, kind) })
	}
}

func workspaceAssignedReplayOutlivesAttempt(t *testing.T, kind string) {
	runtime, err := volumeserver.New("workspace-replay", volumeserver.Config{ContinuousNow: func() (time.Duration, error) { return 0, nil }, SessionLease: 2 * time.Minute, MaxReplaySlots: 9, MaxSessions: 4, MaxLockRecords: 16})
	if err != nil {
		t.Fatal(err)
	}
	h := &replayHandler{runtime: runtime, access: volumeserver.AccessRead | volumeserver.AccessWrite, afterExecution: make(chan struct{}), releaseFirst: make(chan struct{})}
	request := settlementTestMkdir()
	switch kind {
	case "mkdir":
		h.mutationResult = func() *authoritypb.Response { return mkdirTestReply(true) }
	case "close":
		request.Body = &authoritypb.Request_CloseBatch{CloseBatch: &authoritypb.CloseBatchRequest{Closes: []*authoritypb.CloseRequest{{Handle: make([]byte, 16)}}}}
	case "barrier":
		request.Body = &authoritypb.Request_Barrier{Barrier: &authoritypb.BarrierRequest{CutSequence: 7}}
	}
	unblock := sync.OnceFunc(func() { close(h.releaseFirst) })
	defer unblock()
	address, tls, stop := startTestServer(t, h, testMaxInFlight, time.Minute)
	defer func() { unblock(); stop() }()
	cfg := coherentTestClientConfig(address, tls, "workspace-replay", 9, 9)
	cfg.AwaitTLS = func(context.Context) error { return nil } // Explicit fresh test clock.
	cfg.CancelDrainTimeout = 20 * time.Millisecond
	cfg.DispatchFence = NewDispatchFence()
	if err = cfg.DispatchFence.Resume(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	c, err := DialClient(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	assignments := 0
	go func() {
		_, e := c.CallMutationWithIdentity(WithDispatchTimeout(ctx, 20*time.Millisecond), request, func(MutationIdentity) error { assignments++; return nil })
		done <- e
	}()
	select {
	case <-h.afterExecution:
	case <-ctx.Done():
		t.Fatal("original request never applied")
	}
	if err = c.DrainDispatch(func() error { return ErrDispatchExpired }); err != nil {
		t.Fatal(err)
	}
	// The first response stays unavailable beyond the attempt and cancel-drain
	// budgets. Its server execution then releases, allowing DATA replacement.
	timer := time.AfterFunc(100*time.Millisecond, unblock)
	defer timer.Stop()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal("attempt expiry terminalized an assigned replay", err)
		}
	case <-ctx.Done():
		t.Fatal("expired cache permission stranded the original replay")
	}
	unblock()
	if assignments != 1 || h.applyCalls.Load() != 1 || h.mutationCalls.Load() != 2 || c.SessionEndCause() != nil || len(c.DispatchSnapshot().Owners) != 0 {
		t.Fatalf("assignments=%d applications=%d attempts=%d terminal=%v snapshot=%+v", assignments, h.applyCalls.Load(), h.mutationCalls.Load(), c.SessionEndCause(), c.DispatchSnapshot())
	}
	if err = c.ParkDispatch(ctx); err != nil {
		t.Fatal("resolved replay blocked the cold join", err)
	}
}

func TestWorkspaceReplayPermissionCannotAdmitAnotherEffect(t *testing.T) {
	f := NewDispatchFence()
	if err := f.Resume(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	r := settlementTestMkdir()
	r.Mutation = &authoritypb.Mutation{Slot: 1, Sequence: 1}
	release, err := f.own(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	release = sync.OnceFunc(release)
	defer release()
	if err = f.Drain(func() error { return ErrDispatchExpired }); err != nil {
		t.Fatal(err)
	}
	ctx := WithDispatchTimeout(context.WithValue(t.Context(), dispatchReplayKey{}, r), time.Second)
	done, err := f.begin(ctx, false)
	if err != nil {
		t.Fatal("original assigned replay refused", err)
	}
	done()
	other := settlementTestMkdir()
	other.Mutation = &authoritypb.Mutation{Slot: 2, Sequence: 1}
	if done, err = f.own(ctx, other); !errors.Is(err, ErrDispatchExpired) || done != nil {
		t.Fatal("replay permission admitted a new effect", err)
	}
	release()
	// Its identity remains in ctx, but the joined owner no longer grants I/O.
	if done, err = f.begin(ctx, false); !errors.Is(err, ErrDispatchExpired) || done != nil {
		t.Fatal("released replay permission admitted I/O", err)
	}
}
