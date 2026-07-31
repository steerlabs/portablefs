package clientcore

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type operationWaitContextKey struct{}

func TestContendedMutationSuspendsPublicationBeforeExactWait(t *testing.T) {
	suspended := make(chan struct{})
	resumed := make(chan struct{})
	v := &Volume{
		onOperationWait: func(ctx context.Context) func() {
			if got := ctx.Value(operationWaitContextKey{}); got != "mutation" {
				t.Errorf("wait context value = %v, want mutation", got)
			}
			close(suspended)
			return func() { close(resumed) }
		},
	}
	v.exactMu.Lock()

	result := make(chan error, 1)
	ctx := context.WithValue(context.Background(), operationWaitContextKey{}, "mutation")
	go func() {
		err := v.beginMutation(ctx)
		if err == nil {
			v.endMutation()
		}
		result <- err
	}()

	select {
	case <-suspended:
	case <-time.After(5 * time.Second):
		t.Fatal("mutation did not suspend before waiting for exact lock")
	}
	select {
	case err := <-result:
		t.Fatalf("mutation returned while exact lock was held: %v", err)
	default:
	}

	v.exactMu.Unlock()
	select {
	case <-resumed:
	case <-time.After(5 * time.Second):
		t.Fatal("mutation did not resume after acquiring exact lock")
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("begin mutation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mutation did not complete after exact lock was released")
	}
}

func TestContendedExactOperationSuspendsPublicationBeforeExactWait(t *testing.T) {
	suspended := make(chan struct{})
	resumed := make(chan struct{})
	v := &Volume{
		onOperationWait: func(ctx context.Context) func() {
			if got := ctx.Value(operationWaitContextKey{}); got != "exact" {
				t.Errorf("wait context value = %v, want exact", got)
			}
			close(suspended)
			return func() { close(resumed) }
		},
	}
	v.exactMu.RLock()

	type exactResult struct {
		end func()
		err error
	}
	result := make(chan exactResult, 1)
	ctx := context.WithValue(context.Background(), operationWaitContextKey{}, "exact")
	go func() {
		end, err := v.beginExactOperation(ctx)
		result <- exactResult{end: end, err: err}
	}()

	select {
	case <-suspended:
	case <-time.After(5 * time.Second):
		t.Fatal("exact operation did not suspend before waiting for exact lock")
	}
	select {
	case got := <-result:
		if got.end != nil {
			got.end()
		}
		t.Fatalf("exact operation returned while shared exact lock was held: %v", got.err)
	default:
	}

	v.exactMu.RUnlock()
	select {
	case <-resumed:
	case <-time.After(5 * time.Second):
		t.Fatal("exact operation did not resume after acquiring exact lock")
	}
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatalf("begin exact operation: %v", got.err)
		}
		if got.end == nil {
			t.Fatal("begin exact operation returned a nil end function")
		}
		got.end()
	case <-time.After(5 * time.Second):
		t.Fatal("exact operation did not complete after shared lock was released")
	}
}

func TestUncontendedExactLocksDoNotSuspendPublication(t *testing.T) {
	var waits atomic.Int64
	v := &Volume{
		onOperationWait: func(context.Context) func() {
			waits.Add(1)
			return func() {}
		},
	}
	ctx := context.Background()

	if err := v.beginMutation(ctx); err != nil {
		t.Fatalf("begin mutation: %v", err)
	}
	v.endMutation()

	end, err := v.beginExactOperation(ctx)
	if err != nil {
		t.Fatalf("begin exact operation: %v", err)
	}
	end()

	if got := waits.Load(); got != 0 {
		t.Fatalf("uncontended operation wait hooks = %d, want 0", got)
	}
}

func TestAuthorityMutationsShareLaneAndExcludeDelegationInstallation(t *testing.T) {
	v := &Volume{}
	endA, err := v.beginAuthorityMutation(context.Background(), nil, "d/a")
	if err != nil {
		t.Fatal(err)
	}
	endB, err := v.beginAuthorityMutation(context.Background(), nil, "d/b")
	if err != nil {
		endA()
		t.Fatal(err)
	}

	acquired := make(chan struct{})
	go func() {
		claim, claimErr := v.delegationTransitions.begin(
			context.Background(),
			acquireTransition,
			[]string{"d"},
			nil,
		)
		if claimErr != nil {
			return
		}
		close(acquired)
		claim.end()
	}()
	select {
	case <-acquired:
		t.Fatal("delegation installation crossed active authority mutations")
	case <-time.After(20 * time.Millisecond):
	}
	endA()
	select {
	case <-acquired:
		t.Fatal("delegation installation crossed the remaining authority mutation")
	case <-time.After(20 * time.Millisecond):
	}
	endB()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("delegation installation did not resume after authority lane drained")
	}
}
