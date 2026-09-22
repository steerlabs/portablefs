package writeback

import (
	"context"
	"testing"
	"time"
)

type observedFlusher struct {
	recordingFlusher
	buffer   *Buffer
	observed chan Stats
}

func (f *observedFlusher) FlushCycleCompleted(_ context.Context, _ Identity) {
	// Stats takes b.mu: the observer must run after application and outside it.
	f.observed <- f.buffer.Stats()
}
func TestBackgroundFlushObserverRunsAfterAppliedCutWithoutBufferLock(t *testing.T) {
	f := &observedFlusher{observed: make(chan Stats, 1)}
	b := newTestBuffer(t, f, Options{MaxBytes: 1024, MaxEntries: 16, FlushInterval: -1})
	f.buffer = b
	mustWrite(t, b, testIdentity(1), 0, "one")
	mustWrite(t, b, testIdentity(1), 3, "two")
	b.trigger()
	stats := await(t, f.observed, "flush observer")
	if stats.Accepted != 0 || stats.Applied != 2 {
		t.Fatalf("observer before application: %+v", stats)
	}
	select {
	case <-f.observed:
		t.Fatal("observer repeated for a chunk instead of the cut")
	case <-time.After(20 * time.Millisecond):
	}
}

type idleObservedFlusher struct {
	recordingFlusher
	buffer *Buffer
	idle   chan bool
}

func (f *idleObservedFlusher) BufferIdle(id Identity) {
	// An idle notification must follow both the active flush and any queued job
	// reference. Taking the buffer lock here also proves callback lock ordering.
	f.buffer.VisibleSequence(^uint64(0))
	f.buffer.DurableSequence(^uint64(0))
	f.idle <- f.buffer.Forget(id)
}

func TestIdleObserverCanForgetAfterFinalBackgroundReference(t *testing.T) {
	f := &idleObservedFlusher{idle: make(chan bool, 2)}
	b := newTestBuffer(t, f, Options{FlushInterval: -1})
	f.buffer = b
	id := testIdentity(1)
	mustWrite(t, b, id, 0, "retained")
	b.trigger()
	if await(t, f.idle, "flush reference") {
		t.Fatal("forgot identity while background job still retained it")
	}
	if !await(t, f.idle, "job reference") {
		t.Fatal("idle identity remained pinned after final background reference")
	}
	if generation, retained := b.RetainedGeneration(id); generation != 0 || retained {
		t.Fatalf("forgotten identity generation=%d retained=%v", generation, retained)
	}
}
