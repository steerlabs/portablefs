package writeback

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestFlushAllBoundsWorkersAndVisitsEveryTargetAfterFailure(t *testing.T) {
	for _, limit := range []int{1, 2, 4} {
		t.Run(string(rune('0'+limit)), func(t *testing.T) {
			const count = 100
			entered := make(chan Identity, count)
			release := make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			var active, high, calls atomic.Int32
			failure := errors.New("injected application refusal")
			explicit := testIdentity(200)
			flusher := flusherFunc(func(ctx context.Context, id Identity, _ Entry) (uint64, error) {
				if id == explicit {
					return 1000, nil
				}
				n := active.Add(1)
				defer active.Add(-1)
				for previous := high.Load(); n > previous; previous = high.Load() {
					if high.CompareAndSwap(previous, n) {
						break
					}
				}
				calls.Add(1)
				entered <- id
				select {
				case <-release:
				case <-ctx.Done():
					return 0, ctx.Err()
				}
				if id == testIdentity(50) {
					return 0, failure
				}
				return uint64(id[0]) + 1, nil
			})
			b := newTestBuffer(t, flusher, Options{MaxBytes: 1024, MaxEntries: 256, FlushInterval: -1, MaxFlushIdentities: limit})
			var cut Cut
			for i := 0; i < count; i++ {
				cut = mustWrite(t, b, testIdentity(byte(i)), 0, "x")
			}
			done := make(chan error, 1)
			go func() { _, err := b.FlushAll(t.Context(), cut); done <- err }()
			for i := 0; i < limit; i++ {
				await(t, entered, "bounded worker")
			}
			assertBlocked(t, entered, "FlushAll fan-out beyond configured bound")
			explicitCut := mustWrite(t, b, explicit, 0, "priority")
			if _, err := b.FlushIdentity(t.Context(), explicit, explicitCut); err != nil {
				t.Fatalf("explicit recall/fsync flush queued behind all-files workers: %v", err)
			}
			releaseOnce.Do(func() { close(release) })
			if err := await(t, done, "complete all-files flush"); !errors.Is(err, failure) {
				t.Fatalf("error=%v want injected refusal", err)
			}
			if calls.Load() != count || high.Load() != int32(limit) {
				t.Fatalf("calls=%d peak=%d want %d/%d", calls.Load(), high.Load(), count, limit)
			}
		})
	}
}
