package writeback

import (
	"context"
	"errors"
	"testing"
)

func TestRetiredBufferReleasesArenasOnlyAfterSettlement(t *testing.T) {
	b := newTestBuffer(t, &recordingFlusher{}, Options{})
	id := Identity{1}
	if _, err := b.Write(context.Background(), id, 0, []byte("retained")); err != nil {
		t.Fatal(err)
	}
	b.Stop()
	if err := b.ReleaseStorage(); err == nil || b.records == nil {
		t.Fatal("unresolved records released")
	}
	report := b.Drop(id, "definitely unsubmitted tail")
	if report.Entries != 1 {
		t.Fatal(report)
	}
	if err := b.ReleaseStorage(); err != nil {
		t.Fatal(err)
	}
	if b.records != nil || b.pool.nodes != nil || b.free != nil {
		t.Fatal("retired epoch retained arenas")
	}
	if b.IdentityLoss(id) != report.LossSequence {
		t.Fatal("arena retirement erased loss")
	}
}

func TestDrainRetirementNeverReopensFencedAdmissions(t *testing.T) {
	b := newTestBuffer(t, &recordingFlusher{}, Options{})
	id := Identity{2}
	b.FenceAdmissions()
	if _, err := b.BeginRetire(context.Background(), &id); !errors.Is(err, ErrClosed) {
		t.Fatal("ordinary retirement bypassed closure", err)
	}
	r, err := b.BeginDrainRetire(context.Background(), &id)
	if err != nil {
		t.Fatal(err)
	}
	r.Cancel()
	if _, err = b.Write(context.Background(), id, 0, []byte("late")); !errors.Is(err, ErrClosed) {
		t.Fatal("drain reopened serving", err)
	}
	b.Stop()
	if _, err = b.BeginDrainRetire(context.Background(), &id); !errors.Is(err, ErrClosed) {
		t.Fatal("stopped scheduler acquired another cut", err)
	}
}
