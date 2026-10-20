package volumeserver

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Done is reached only after admission found a conflicting permit and released
// the state mutex. Holding it lets a test put wake and cancellation in flight
// together, without making either successful execution depend on a timer.
type topologyWaitContext struct {
	context.Context
	waiting chan struct{}
	resume  <-chan struct{}
	once    sync.Once
}

func (c *topologyWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	if c.resume != nil {
		<-c.resume
	}
	return c.Context.Done()
}
func topologyReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("topology schedule stuck")
		var zero T
		return zero
	}
}

func TestTopologyGateDependentReadersAndActiveExclusion(t *testing.T) {
	l, err := NewMountLifecycle(MountLifecycleConfig{Membership: &mountLifecycleMembership{}, Prior: PriorEpochStrictMountsFenced})
	if err != nil {
		t.Fatal(err)
	}
	r1, err := l.AcquireTopologyRead(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer r1.Release()
	ctx := &topologyWaitContext{Context: t.Context(), waiting: make(chan struct{})}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, err := l.ExecuteTopologyExclusive(ctx, func() (int, error) { close(entered); <-release; return 0, nil })
		done <- err
	}()
	topologyReceive(t, ctx.waiting)
	type readResult struct {
		guard *TopologyReadGuard
		err   error
	}
	r2Done := make(chan readResult, 1)
	go func() { guard, err := l.AcquireTopologyRead(t.Context()); r2Done <- readResult{guard, err} }()
	r2Result := topologyReceive(t, r2Done)
	if r2Result.err != nil {
		t.Fatal(r2Result.err)
	}
	r2 := r2Result.guard
	r1.Release()
	r1.Release()
	select {
	case <-entered:
		t.Fatal("writer overlapped remaining reader")
	default:
	}
	r2.Release()
	topologyReceive(t, entered)
	readerCtx := &topologyWaitContext{Context: t.Context(), waiting: make(chan struct{})}
	readerDone := make(chan error, 1)
	go func() {
		r, err := l.AcquireTopologyRead(readerCtx)
		if r != nil {
			r.Release()
		}
		readerDone <- err
	}()
	topologyReceive(t, readerCtx.waiting)
	close(release)
	if err := topologyReceive(t, done); err != nil {
		t.Fatal(err)
	}
	if err := topologyReceive(t, readerDone); err != nil {
		t.Fatal(err)
	}
}

func TestTopologyGateCancellation(t *testing.T) {
	for _, writer := range []bool{false, true} {
		for _, stage := range []string{"before", "waiting", "wake"} {
			name := "reader/"
			if writer {
				name = "writer/"
			}
			t.Run(name+stage, func(t *testing.T) {
				var g topologyGate
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				wait := &topologyWaitContext{Context: ctx, waiting: make(chan struct{})}
				var resume chan struct{}
				if stage == "wake" {
					resume = make(chan struct{})
					wait.resume = resume
				}
				blockerExclusive := !writer
				if stage == "before" {
					cancel()
				} else {
					if err := g.acquire(t.Context(), blockerExclusive); err != nil {
						t.Fatal(err)
					}
				}
				done := make(chan error, 1)
				go func() { done <- g.acquire(wait, writer) }()
				if stage != "before" {
					topologyReceive(t, wait.waiting)
					cancel()
					if stage == "wake" {
						g.release(blockerExclusive)
						close(resume)
					}
				}
				if err := topologyReceive(t, done); !errors.Is(err, context.Canceled) {
					t.Fatalf("acquire=%v", err)
				}
				if stage == "waiting" {
					g.release(blockerExclusive)
				}
				for _, exclusive := range []bool{false, true} {
					if err := g.acquire(t.Context(), exclusive); err != nil {
						t.Fatal(err)
					}
					g.release(exclusive)
				}
			})
		}
	}
}

func TestTopologyExecutorRechecksCancellationAndSettlesStartedWork(t *testing.T) {
	l, _ := NewMountLifecycle(MountLifecycleConfig{Membership: &mountLifecycleMembership{}})
	ctx, cancel := context.WithCancel(t.Context())
	// A context can cancel just after the grant; the executor checkpoint must
	// still refuse it. The second Err sample is that checkpoint.
	c := &topologyCancelAtCheck{Context: ctx, cancel: cancel}
	ran := false
	if _, err := l.ExecuteTopologyExclusive(c, func() (int, error) { ran = true; return 0, nil }); !errors.Is(err, context.Canceled) || ran {
		t.Fatalf("executor=%v ran=%v", err, ran)
	}
	ctx2, cancel2 := context.WithCancel(t.Context())
	defer cancel2()
	result := errors.New("actual transition result")
	if n, err := l.ExecuteTopologyExclusive(ctx2, func() (int, error) { cancel2(); return 7, result }); n != 7 || !errors.Is(err, result) {
		t.Fatalf("started result=%d/%v", n, err)
	}
}

type topologyCancelAtCheck struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *topologyCancelAtCheck) Err() error {
	c.checks++
	if c.checks == 2 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestTopologyGateCountAndReleaseInvariants(t *testing.T) {
	g := topologyGate{readers: ^uint64(0)}
	if err := g.acquire(t.Context(), false); err == nil || g.readers != ^uint64(0) {
		t.Fatalf("reader exhaustion=%v count=%d", err, g.readers)
	}
	for _, exclusive := range []bool{false, true} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("missing release invariant panic")
				}
			}()
			var empty topologyGate
			empty.release(exclusive)
		}()
	}
}
