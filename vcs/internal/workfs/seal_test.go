package workfs

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// TestSealClosesWriteAdmission: after Seal, every mutation path — billy ops,
// direct WAL-record mutations, write-back batches, and orphan management — fails
// with ErrSealed, while reads keep serving the pre-seal state. Everything
// acknowledged before the seal stays visible and snapshot-covered.
func TestSealClosesWriteAdmission(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})

	f, err := fs.Create("pre.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("pre-seal bytes")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fs.MkdirAll("dir", 0o755); err != nil {
		t.Fatal(err)
	}

	if fs.Sealed() {
		t.Fatal("fresh tree must not be sealed")
	}
	if err := fs.Seal(context.Background()); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !fs.Sealed() {
		t.Fatal("Seal did not stick")
	}

	assertSealed := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrSealed) {
			t.Fatalf("%s after seal: err=%v, want ErrSealed", what, err)
		}
	}
	_, err = fs.Create("new.txt")
	assertSealed("create", err)
	assertSealed("remove", fs.Remove("pre.txt"))
	assertSealed("rename", fs.Rename("pre.txt", "moved.txt"))
	assertSealed("mkdir", fs.MkdirAll("dir2", 0o755))
	assertSealed("symlink", fs.Symlink("pre.txt", "link"))
	_, _, err = fs.WriteAt("pre.txt", 0, []byte("x"), 0o644)
	assertSealed("writeAt", err)
	assertSealed("batch", fs.ApplyBatch([]wal.Record{{Op: wal.OpWrite, Path: "pre.txt", Offset: 0, Data: []byte("x")}}, "owner"))
	assertSealed("chmod", fs.MutateAs(wal.Record{Op: wal.OpChmod, Path: "pre.txt", Mode: 0o600}, ""))
	_, err = fs.Orphan("pre.txt", "owner")
	assertSealed("orphan", err)

	// Reads still serve the acknowledged pre-seal state.
	rf, err := fs.Open("pre.txt")
	if err != nil {
		t.Fatalf("post-seal open for read: %v", err)
	}
	got, err := io.ReadAll(rf)
	_ = rf.Close()
	if err != nil || string(got) != "pre-seal bytes" {
		t.Fatalf("post-seal read = %q err=%v", got, err)
	}

	// The sealed snapshot still covers the acknowledged records for the barrier.
	snap := fs.Snapshot()
	if !snap.HasUncommittedRecords() {
		t.Fatal("sealed snapshot must still cover the acknowledged pre-seal records")
	}
}

// latchLog wraps the managed entry log so CommitThrough parks inside the
// durability path until released — a deterministic latch that holds an
// ADMITTED mutation in flight between staging and its acknowledgement, which
// is exactly the window the admission drain must cover.
type latchLog struct {
	pfj3.EntryLog
	arrived  chan struct{} // closed when the first CommitThrough parks
	release  chan struct{} // closed by the test to let it finish
	arriveMu sync.Once
}

func newLatchLog(inner pfj3.EntryLog) *latchLog {
	return &latchLog{EntryLog: inner, arrived: make(chan struct{}), release: make(chan struct{})}
}

func (l *latchLog) CommitThrough(seq uint64) error {
	l.arriveMu.Do(func() { close(l.arrived) })
	<-l.release
	return l.EntryLog.CommitThrough(seq)
}

// TestSealDrainsInFlightMutationThroughDurability is the deterministic latch
// test for the admission drain: a mutation ADMITTED before Seal is parked
// inside its durability path (the journal commit) — the exact window an
// fs.mu-only seal would miss. Seal must NOT return while that mutation is
// still in flight; once it completes (durable + acknowledged), Seal returns.
func TestSealDrainsInFlightMutationThroughDurability(t *testing.T) {
	latch := newLatchLog(newFakeEntryLog())
	fs, err := NewManaged(nil, &fakeBlobs{data: map[string][]byte{}}, latch)
	if err != nil {
		t.Fatal(err)
	}

	ackErr := make(chan error, 1)
	go func() {
		_, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "inflight.txt", Mode: 0o644}, nil, "owner")
		ackErr <- err
	}()
	<-latch.arrived // the mutation is parked mid-durability

	sealDone := make(chan error, 1)
	go func() { sealDone <- fs.Seal(context.Background()) }()

	// Deterministic ordering assertion: with the mutation parked, Seal must
	// still be waiting. (Seal has no side channel to signal "waiting", so a
	// bounded non-completion check is the observable contract.)
	select {
	case err := <-sealDone:
		t.Fatalf("Seal returned (err=%v) while an admitted mutation was still in its durability path", err)
	case <-time.After(150 * time.Millisecond):
	}
	if !fs.Sealed() {
		t.Fatal("admission must be closed the moment Seal begins, before the drain completes")
	}
	// New mutations are already refused while the drain waits.
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "late.txt", Mode: 0o644}, nil, "owner"); !errors.Is(err, ErrSealed) {
		t.Fatalf("mutation during drain: err=%v, want ErrSealed", err)
	}

	close(latch.release) // let the admitted mutation reach its ack boundary
	if err := <-sealDone; err != nil {
		t.Fatalf("Seal after drain: %v", err)
	}
	if err := <-ackErr; err != nil {
		t.Fatalf("the pre-seal mutation must be acknowledged successfully: %v", err)
	}
	// The acknowledged pre-seal write is present in the sealed state.
	if _, err := fs.Lstat("inflight.txt"); err != nil {
		t.Fatalf("acknowledged pre-seal create missing after the drain: %v", err)
	}
}

// TestSealDrainTimeoutFailsClosed: when an admitted mutation cannot drain in
// time, Seal reports the failure but admission STAYS closed — never reopened —
// and a later drain attempt can still complete.
func TestSealDrainTimeoutFailsClosed(t *testing.T) {
	latch := newLatchLog(newFakeEntryLog())
	fs, err := NewManaged(nil, &fakeBlobs{data: map[string][]byte{}}, latch)
	if err != nil {
		t.Fatal(err)
	}

	ackErr := make(chan error, 1)
	go func() {
		_, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "stuck.txt", Mode: 0o644}, nil, "owner")
		ackErr <- err
	}()
	<-latch.arrived

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := fs.Seal(ctx); err == nil {
		t.Fatal("Seal must fail when the drain cannot complete in time")
	}
	if !fs.Sealed() {
		t.Fatal("a timed-out Seal must leave admission closed (fail closed)")
	}
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "late.txt", Mode: 0o644}, nil, "owner"); !errors.Is(err, ErrSealed) {
		t.Fatalf("mutation after failed seal: err=%v, want ErrSealed", err)
	}

	close(latch.release)
	if err := <-ackErr; err != nil {
		t.Fatalf("the admitted mutation still completes: %v", err)
	}
	// A retried seal (idempotent) now drains cleanly.
	if err := fs.Seal(context.Background()); err != nil {
		t.Fatalf("retried Seal after the stall cleared: %v", err)
	}
}
