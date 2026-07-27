package workfs

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

// Terminal sealing closes client write admission, but authority-owned control
// records must still be able to finish cleanup and preserve exact-once state.
// Checkpointing and session cleanup are not ordinary user writes and may run
// after the terminal barrier has drained admitted requests.
func TestInternalControlRecordsBypassTerminalSeal(t *testing.T) {
	fs, _ := newFS(t, nil, &fakeBlobs{data: map[string][]byte{}})
	if _, err := fs.EstablishSession("session-1", 1, "mount-1", 8); err != nil {
		t.Fatalf("establish session: %v", err)
	}
	if err := fs.Seal(context.Background()); err != nil {
		t.Fatalf("seal: %v", err)
	}

	if _, err := fs.EstablishSession("session-2", 1, "mount-2", 8); !errors.Is(err, ErrSealed) {
		t.Fatalf("new client session after seal: err=%v, want ErrSealed", err)
	}
	if err := fs.ExpireSession("session-1", 1); err != nil {
		t.Fatalf("internal session expiry after seal: %v", err)
	}
	if err := fs.AppendControlSnapshot(); err != nil {
		t.Fatalf("control snapshot after seal: %v", err)
	}
}

// latchReplica is a wal.Replica whose AppendBatch parks inside the durability
// path until released — a deterministic latch that holds an ADMITTED mutation
// in flight between fs.mu release and its CommitThrough acknowledgement, which
// is exactly the window the admission drain must cover.
type latchReplica struct {
	mu       sync.Mutex
	arrived  chan struct{} // closed when the first AppendBatch parks
	release  chan struct{} // closed by the test to let it finish
	arriveMu sync.Once
	batches  int
}

func newLatchReplica() *latchReplica {
	return &latchReplica{arrived: make(chan struct{}), release: make(chan struct{})}
}

func (r *latchReplica) Append(wal.Record) error { return nil }
func (r *latchReplica) AppendBatch([]wal.Record) error {
	r.arriveMu.Do(func() { close(r.arrived) })
	<-r.release
	r.mu.Lock()
	r.batches++
	r.mu.Unlock()
	return nil
}
func (r *latchReplica) Reset() error         { return nil }
func (r *latchReplica) Compact(uint64) error { return nil }
func (r *latchReplica) batchCount() int      { r.mu.Lock(); defer r.mu.Unlock(); return r.batches }

// TestSealDrainsInFlightMutationThroughDurability is the deterministic latch
// test for the admission drain: a mutation ADMITTED before Seal is parked
// inside its durability path (WAL replication) with fs.mu already released —
// the exact window the old fs.mu-only seal missed. Seal must NOT return while
// that mutation is still in flight; once it completes (durable + acknowledged),
// Seal returns and a snapshot covers the write.
func TestSealDrainsInFlightMutationThroughDurability(t *testing.T) {
	p := filepath.Join(t.TempDir(), "wal.log")
	w, err := wal.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	replica := newLatchReplica()
	w.SetReplica(replica)

	ackErr := make(chan error, 1)
	go func() {
		ackErr <- fs.ApplyBatch([]wal.Record{
			{Op: wal.OpCreate, Path: "inflight.txt", Mode: 0o644},
			{Op: wal.OpWrite, Path: "inflight.txt", Offset: 0, Data: []byte("admitted before seal")},
		}, "owner")
	}()
	<-replica.arrived // the mutation is parked mid-durability, fs.mu released

	// The WAL-backed store applies before its durability barrier (fs.mu is
	// held only for the in-memory apply); the drain contract below is what
	// Seal guarantees: the ADMITTED mutation must finish its durability
	// boundary before Seal returns, so a sealed snapshot always covers it.
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
	if _, err := fs.Create("late.txt"); !errors.Is(err, ErrSealed) {
		t.Fatalf("mutation during drain: err=%v, want ErrSealed", err)
	}

	close(replica.release) // let the admitted mutation reach its ack boundary
	if err := <-sealDone; err != nil {
		t.Fatalf("Seal after drain: %v", err)
	}
	if err := <-ackErr; err != nil {
		t.Fatalf("the pre-seal mutation must be acknowledged successfully: %v", err)
	}
	if replica.batchCount() == 0 {
		t.Fatal("the admitted mutation never replicated")
	}

	// The post-drain snapshot covers the acknowledged write, and the WAL has no
	// unflushed tail: EnsureSnapshotDurable succeeds without the replica.
	snap := fs.Snapshot()
	if !snap.HasUncommittedRecords() {
		t.Fatal("post-drain snapshot must cover the acknowledged records")
	}
	if err := fs.EnsureSnapshotDurable(snap); err != nil {
		t.Fatalf("post-drain snapshot durability: %v", err)
	}
	found := false
	for _, e := range snap.Entries {
		if e.Path == "inflight.txt" {
			found = true
		}
	}
	if !found {
		t.Fatal("acknowledged pre-seal write missing from the post-drain snapshot")
	}
}

// TestSealDrainTimeoutFailsClosed: when an admitted mutation cannot drain in
// time, Seal reports the failure but admission STAYS closed — never reopened —
// and a later drain attempt can still complete.
func TestSealDrainTimeoutFailsClosed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "wal.log")
	w, err := wal.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := New(nil, &fakeBlobs{data: map[string][]byte{}}, w)
	if err != nil {
		t.Fatal(err)
	}
	replica := newLatchReplica()
	w.SetReplica(replica)

	ackErr := make(chan error, 1)
	go func() {
		ackErr <- fs.ApplyBatch([]wal.Record{{Op: wal.OpCreate, Path: "stuck.txt", Mode: 0o644}}, "")
	}()
	<-replica.arrived

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := fs.Seal(ctx); err == nil {
		t.Fatal("Seal must fail when the drain cannot complete in time")
	}
	if !fs.Sealed() {
		t.Fatal("a timed-out Seal must leave admission closed (fail closed)")
	}
	if _, err := fs.Create("late.txt"); !errors.Is(err, ErrSealed) {
		t.Fatalf("mutation after failed seal: err=%v, want ErrSealed", err)
	}

	close(replica.release)
	if err := <-ackErr; err != nil {
		t.Fatalf("the admitted mutation still completes: %v", err)
	}
	// A retried seal (idempotent) now drains cleanly.
	if err := fs.Seal(context.Background()); err != nil {
		t.Fatalf("retried Seal after the stall cleared: %v", err)
	}
}
