//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCoherenceProfileGateSharedAdmissionOverlaps(t *testing.T) {
	var gate writerPriorityGate
	gate.RLock()
	defer gate.RUnlock()

	acquired := make(chan struct{})
	released := make(chan struct{})
	go func() {
		gate.RLock()
		close(acquired)
		gate.RUnlock()
		close(released)
	}()

	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("unrelated shared admission did not overlap")
	}
	<-released

	if !gate.mu.TryLock() {
		t.Fatal("shared permit retained the gate mutex across caller work")
	}
	gate.mu.Unlock()
}

func TestCoherenceProfileGateExclusiveAdmissionHasWriterPriority(t *testing.T) {
	var gate writerPriorityGate
	gate.RLock()

	writerCtx := newAdmissionWaitContext(t.Context())
	writerAcquired := make(chan struct{})
	releaseWriter := make(chan struct{})
	go func() {
		if err := gate.LockContext(writerCtx); err != nil {
			panic(err)
		}
		close(writerAcquired)
		<-releaseWriter
		gate.Unlock()
	}()

	admissionReceive(t, writerCtx.waiting)

	readerCtx := newAdmissionWaitContext(t.Context())
	readerAcquired := make(chan struct{})
	go func() {
		if err := gate.RLockContext(readerCtx); err != nil {
			panic(err)
		}
		close(readerAcquired)
		gate.RUnlock()
	}()
	admissionReceive(t, readerCtx.waiting)

	gate.RUnlock()
	select {
	case <-writerAcquired:
	case <-time.After(time.Second):
		t.Fatal("exclusive admission did not follow the last active reader")
	}
	select {
	case <-readerAcquired:
		t.Fatal("shared admission passed an active exclusive admission")
	default:
	}
	close(releaseWriter)
	select {
	case <-readerAcquired:
	case <-time.After(time.Second):
		t.Fatal("shared admission did not resume after exclusive release")
	}
}

func TestCoherenceProfileGateWaitsHonorContext(t *testing.T) {
	t.Run("shared waiter", func(t *testing.T) {
		var gate writerPriorityGate
		gate.Lock()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := gate.RLockContext(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("RLockContext = %v, want context cancellation", err)
		}
		gate.Unlock()
	})
	t.Run("exclusive waiter preserves admission", func(t *testing.T) {
		var gate writerPriorityGate
		gate.RLock()
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := gate.LockContext(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("LockContext = %v, want context cancellation", err)
		}
		gate.RUnlock()
		if err := gate.RLockContext(t.Context()); err != nil {
			t.Fatalf("canceled writer stranded shared admission: %v", err)
		}
		gate.RUnlock()
	})
}

func TestWriterPriorityGateCancellationAtEveryAdmission(t *testing.T) {
	for _, writer := range []bool{false, true} {
		for _, stage := range []string{"before", "waiting", "wake"} {
			name := "reader/"
			if writer {
				name = "writer/"
			}
			t.Run(name+stage, func(t *testing.T) {
				var gate writerPriorityGate
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				wait := newAdmissionWaitContext(ctx)
				var resume chan struct{}
				if stage == "wake" {
					resume = make(chan struct{})
					wait.resume = resume
				}
				release := gate.Unlock
				if writer {
					release = gate.RUnlock
				}
				if stage == "before" {
					cancel()
				} else if writer {
					gate.RLock()
				} else {
					gate.Lock()
				}
				done := make(chan error, 1)
				go func() {
					if writer {
						done <- gate.LockContext(wait)
					} else {
						done <- gate.RLockContext(wait)
					}
				}()
				if stage != "before" {
					admissionReceive(t, wait.waiting)
					cancel()
					if stage == "wake" {
						release()
						close(resume)
					}
				}
				if err := admissionReceive(t, done); !errors.Is(err, context.Canceled) {
					t.Fatalf("acquisition=%v", err)
				}
				if stage == "waiting" {
					release()
				}
				gate.mu.Lock()
				readers, pending, active := gate.readers, gate.writersWaiting, gate.writer
				gate.mu.Unlock()
				if readers != 0 || pending != 0 || active {
					t.Fatalf("canceled waiter retained admission: %d/%d/%v", readers, pending, active)
				}
				if err := gate.RLockContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				gate.RUnlock()
				if err := gate.LockContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				gate.Unlock()
			})
		}
	}
}
