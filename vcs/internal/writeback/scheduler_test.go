package writeback

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestExplicitFlushCannotConsumeTheOnlyAdmissionWakeup(t *testing.T) {
	a, bid := testIdentity(201), testIdentity(202)
	entered, scanned, retried := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var attempts atomic.Int32
	flusher := flusherFunc(func(ctx context.Context, id Identity, e Entry) (uint64, error) {
		if id == bid {
			close(scanned)
			return 1, nil
		}
		if attempts.Add(1) == 1 {
			close(entered)
			<-ctx.Done()
			return 0, ctx.Err()
		}
		close(retried)
		return 2, nil
	})
	b := newTestBuffer(t, flusher)
	if _, err := b.Write(t.Context(), a, 0, []byte("accepted-before-explicit-flush")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	explicit := make(chan error, 1)
	go func() { _, err := b.FlushIdentity(ctx, a, b.Snapshot()); explicit <- err }()
	<-entered
	// This second identity proves the background scheduler consumed the one kick
	// and inspected every active file while A was explicitly flushing. No new
	// A admission arrives, so progress cannot be borrowed from a later write.
	if _, err := b.Write(t.Context(), bid, 0, []byte("witness")); err != nil {
		t.Fatal(err)
	}
	b.Start()
	select {
	case <-scanned:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not inspect active files")
	}
	cancel()
	if err := <-explicit; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case <-retried:
	case <-time.After(200 * time.Millisecond):
		b.mu.Lock()
		f := b.files[a]
		t.Logf("flushing=%v scheduled=%v reschedule=%v pending=%v accepted=%v kick=%d attempts=%d", f.flushing, f.scheduled, f.reschedule, f.pending != nil, f.accepted != nil, len(b.kick), attempts.Load())
		b.mu.Unlock()
		t.Fatal("accepted wave lost its only scheduling wakeup after explicit cancellation")
	}
}

func TestSuccessfulExplicitCutCannotStrandAlreadyAcceptedTail(t *testing.T) {
	a, bid := testIdentity(203), testIdentity(204)
	entered, scanned, resume, retried := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var attempts atomic.Int32
	flusher := flusherFunc(func(ctx context.Context, id Identity, e Entry) (uint64, error) {
		if id == bid {
			close(scanned)
			return 2, nil
		}
		if attempts.Add(1) == 1 {
			close(entered)
			select {
			case <-resume:
				return 1, nil
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}
		close(retried)
		return 3, nil
	})
	b := newTestBuffer(t, flusher)
	cut, err := b.Write(t.Context(), a, 0, []byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	// A concurrent write was already admitted when the explicit caller begins
	// flushing its earlier cut. No admission occurs during that flush.
	if _, err := b.Write(t.Context(), a, 10, []byte("accepted-tail")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	explicit := make(chan error, 1)
	go func() { _, err := b.FlushIdentity(ctx, a, cut); explicit <- err }()
	<-entered
	if _, err := b.Write(t.Context(), bid, 0, []byte("witness")); err != nil {
		t.Fatal(err)
	}
	b.Start()
	select {
	case <-scanned:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not inspect active files")
	}
	close(resume)
	if err := <-explicit; err != nil {
		t.Fatal(err)
	}
	select {
	case <-retried:
	case <-time.After(200 * time.Millisecond):
		b.mu.Lock()
		f := b.files[a]
		t.Logf("flushing=%v scheduled=%v reschedule=%v pending=%v accepted=%v kick=%d attempts=%d", f.flushing, f.scheduled, f.reschedule, f.pending != nil, f.accepted != nil, len(b.kick), attempts.Load())
		b.mu.Unlock()
		t.Fatal("successful explicit cut stranded its already accepted tail")
	}
}

// A kick inspected while a background owner is busy cannot become a new
// producer event merely because that owner returns an error.
func TestBackgroundFailureDoesNotScheduleItsOwnRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		id, witness := testIdentity(205), testIdentity(206)
		entered, scanned, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var attempts atomic.Int32
		b := newTestBuffer(t, flusherFunc(func(ctx context.Context, next Identity, e Entry) (uint64, error) {
			if next == witness {
				close(scanned)
				return 1, nil
			}
			if attempts.Add(1) == 1 {
				close(entered)
				select {
				case <-finish:
				case <-ctx.Done():
				}
			}
			return 0, errors.New("background failure")
		}))
		if _, err := b.Write(t.Context(), id, 0, []byte("retained")); err != nil {
			t.Fatal(err)
		}
		b.Start()
		<-entered
		if _, err := b.Write(t.Context(), witness, 0, []byte("scan")); err != nil {
			t.Fatal(err)
		}
		<-scanned
		close(finish)
		synctest.Wait()
		if got := attempts.Load(); got != 1 {
			t.Fatalf("background failure retried itself %d times", got)
		}
		b.mu.Lock()
		f := b.files[id]
		retained := f.accepted != nil && f.pending != nil && !f.scheduled && !f.flushing && !f.reschedule
		b.mu.Unlock()
		if !retained {
			t.Fatal("failed background wave did not remain idle and retained")
		}
	})
}
