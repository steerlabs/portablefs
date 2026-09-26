package writeback

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestReleasedOverlayRetainsDurabilityAndProtectsSuccessor(t *testing.T) {
	b := newTestBuffer(t, &recordingFlusher{})
	id := testIdentity(1)
	if _, err := b.Write(t.Context(), id, 0, []byte("old")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Truncate(t.Context(), id, 2); err != nil {
		t.Fatal(err)
	}
	retirement, err := b.BeginRetire(t.Context(), &id)
	if err != nil {
		t.Fatal(err)
	}
	if err := retirement.DetachOverlay(); !errors.Is(err, ErrPending) {
		t.Fatalf("unapplied detach=%v", err)
	}
	applied, err := b.FlushIdentity(t.Context(), id, retirement.Cut())
	if err != nil {
		t.Fatal(err)
	}
	before := b.Stats()
	if err := retirement.DetachOverlay(); err != nil {
		t.Fatal(err)
	}
	if after := b.Stats(); after != before {
		t.Fatalf("detach changed durability accounting: before=%+v after=%+v", before, after)
	}
	fetch := func(context.Context, int64, int) ([]byte, error) { return []byte("peer"), nil }
	data, err := b.Read(t.Context(), id, 0, 4, fetch)
	if err != nil || !bytes.Equal(data, []byte("peer")) {
		t.Fatalf("released overlay hid peer: %q %v", data, err)
	}
	base := Attributes{HasSize: true, Size: 4, HasMTime: true, MTimeNS: 123}
	if got := b.OverlayAttributes(id, base); got != base {
		t.Fatalf("released metadata hid peer: %+v", got)
	}
	if err := retirement.Resume(); err != nil {
		t.Fatal(err)
	}
	if err := retirement.DetachOverlay(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("resumed detach=%v", err)
	}
	if _, err := b.Truncate(t.Context(), id, 7); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write(t.Context(), id, 4, []byte("new")); err != nil {
		t.Fatal(err)
	}
	b.VisibleSequence(applied)
	b.DurableSequence(applied)
	if b.Stats().Entries != 2 {
		t.Fatal("old prefix retired successor records")
	}
	if got := b.OverlayAttributes(id, base); got.Size != 7 {
		t.Fatalf("old truncate retirement damaged successor size=%d", got.Size)
	}
	data, err = b.Read(t.Context(), id, 0, 7, fetch)
	if err != nil || !bytes.Equal(data, []byte("peernew")) {
		t.Fatalf("old retirement damaged successor: %q %v", data, err)
	}
	last, err := b.FlushIdentity(t.Context(), id, b.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	b.VisibleSequence(last)
	b.DurableSequence(last)
	if b.Stats().Entries != 0 {
		t.Fatal("durable records retained")
	}
}

func TestRetirementCancelPreservesGenerationAndRefusesDetachedAdmission(t *testing.T) {
	b := newTestBuffer(t, &recordingFlusher{})
	id := testIdentity(2)
	cut := mustWrite(t, b, id, 0, "old")
	generation := b.Generation(id)
	retirement, err := b.BeginRetire(t.Context(), &id)
	if err != nil {
		t.Fatal(err)
	}
	retirement.Cancel()
	if b.Generation(id) != generation {
		t.Fatal("cancel changed the live ownership generation")
	}
	if _, err := b.Write(t.Context(), id, 3, []byte("new")); err != nil {
		t.Fatal(err)
	}
	retirement, err = b.BeginRetire(t.Context(), &id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.FlushIdentity(t.Context(), id, retirement.Cut()); err != nil {
		t.Fatal(err)
	}
	if err = retirement.DetachOverlay(); err != nil {
		t.Fatal(err)
	}
	retirement.Cancel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = b.Write(ctx, id, 0, []byte("bad")); err == nil {
		t.Fatal("detached ownership reopened")
	}
	b.mu.Lock()
	retiring := b.file(id).retiring
	b.mu.Unlock()
	if !retiring {
		t.Fatal("cancel reopened a detached generation")
	}
	report := b.Drop(id, "lost after release")
	if report.Entries != 2 || report.Bytes != 6 || report.LossSequence == 0 {
		t.Fatalf("detached records escaped loss accounting: %+v cut=%+v", report, cut)
	}
}
