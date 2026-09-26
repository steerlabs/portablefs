package writeback

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGenerationBoundAdmissionCannotCrossDrop(t *testing.T) {
	for _, kind := range []string{"write", "truncate", "metadata"} {
		t.Run(kind, func(t *testing.T) {
			b := newTestBuffer(t, flusherFunc(func(context.Context, Identity, Entry) (uint64, error) {
				return 0, errors.New("hold capacity")
			}), Options{MaxEntries: 1, FlushInterval: -1})
			id := testIdentity(1)
			generation := b.Generation(id)
			admit := func() (Cut, error) {
				switch kind {
				case "write":
					return b.WriteInGeneration(t.Context(), id, generation, 0, []byte("old"), WriteOptions{})
				case "truncate":
					return b.TruncateInGeneration(t.Context(), id, generation, 10)
				default:
					return b.SetAttrInGeneration(t.Context(), id, generation, Attributes{HasMode: true, Mode: 0600})
				}
			}
			if _, err := b.Write(t.Context(), id, 0, []byte("retained")); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := admit(); done <- err }()
			deadline := time.Now().Add(time.Second)
			for b.Stats().WaitingAdmissions != 1 {
				if time.Now().After(deadline) {
					t.Fatal("admission never waited at capacity")
				}
				time.Sleep(time.Millisecond)
			}
			b.Drop(id, "old grant lost")
			if err := <-done; !errors.Is(err, ErrLost) {
				t.Fatalf("old waiter = %v, want ErrLost", err)
			}
			// The same stale generation must also fail before its first wait.
			if _, err := admit(); !errors.Is(err, ErrLost) {
				t.Fatalf("late old admission = %v, want ErrLost", err)
			}
			if stats := b.Stats(); stats.Entries != 0 || stats.WaitingAdmissions != 0 {
				t.Fatalf("old waiter entered successor: %+v", stats)
			}
			if _, err := b.WriteInGeneration(t.Context(), id, b.Generation(id), 0, []byte("next"), WriteOptions{}); err != nil {
				t.Fatalf("successor admission = %v", err)
			}
		})
	}
}
