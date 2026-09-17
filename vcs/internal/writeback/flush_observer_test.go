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
