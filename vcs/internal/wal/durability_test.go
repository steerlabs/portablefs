package wal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// failReplica fails every Append (a down/broken standby).
type failReplica struct{}

func (failReplica) Append(Record) error        { return errors.New("replica down") }
func (failReplica) AppendBatch([]Record) error { return errors.New("replica down") }
func (failReplica) Reset() error               { return nil }
func (failReplica) Compact(uint64) error       { return nil }

// localReplica forwards to a second WAL, simulating the replication wire in-process
// (Append preserves LSN via AppendReplicated; Reset/Compact mirror exactly).
type localReplica struct{ w *WAL }

func (l *localReplica) Append(r Record) error             { return l.w.AppendReplicated(r) }
func (l *localReplica) AppendBatch(rs []Record) error     { return l.w.AppendReplicatedBatch(rs) }
func (l *localReplica) Reset() error                      { return l.w.Reset() }
func (l *localReplica) Compact(seq uint64) error          { return l.w.CompactThrough(seq) }
func (l *localReplica) StateExact() (ReplicaState, error) { return l.w.StateExact() }
func (l *localReplica) DigestAtExact(epoch, seq uint64) ([32]byte, error) {
	return l.w.DigestAtExact(epoch, seq)
}
func (l *localReplica) RecordsExact(epoch, from, to uint64) ([]Record, error) {
	return l.w.RecordsExact(epoch, from, to)
}
func (l *localReplica) AdoptExact(epoch, base uint64, digest [32]byte) error {
	return l.w.AdoptExact(epoch, base, digest)
}
func (l *localReplica) AppendBatchExact(epoch uint64, rs []Record) error {
	return l.w.AppendBatchExact(epoch, rs)
}
func (l *localReplica) CompactExact(epoch, seq uint64, digest [32]byte) error {
	return l.w.CompactExact(epoch, seq, digest)
}
func (l *localReplica) SetCheckpointCutExact(cut CheckpointCut) error {
	return l.w.SetCheckpointCutExact(cut)
}
func (l *localReplica) SetMaintenanceCutExact(cut MaintenanceCut) error {
	return l.w.SetMaintenanceCutExact(cut)
}
func (l *localReplica) CompactMaintenanceExact(cut MaintenanceCut) error {
	return l.w.CompactMaintenanceExact(cut)
}

// slowReplica simulates a high-latency (cross-region) standby: each AppendBatch
// sleeps `delay` and counts the round-trips it receives, so a test can prove that
// many concurrent writes share one replication round-trip (group commit).
type slowReplica struct {
	w       *WAL
	delay   time.Duration
	mu      sync.Mutex
	batches int
	records int
}

func (s *slowReplica) Append(r Record) error { return s.AppendBatch([]Record{r}) }
func (s *slowReplica) AppendBatch(rs []Record) error {
	time.Sleep(s.delay)
	s.mu.Lock()
	s.batches++
	s.records += len(rs)
	s.mu.Unlock()
	return s.w.AppendReplicatedBatch(rs)
}
func (s *slowReplica) Reset() error             { return s.w.Reset() }
func (s *slowReplica) Compact(seq uint64) error { return s.w.CompactThrough(seq) }

// TestGroupCommitBatchesConcurrentWrites proves the headline win: N concurrent writers
// against a high-latency replica complete in FAR fewer than N replication round-trips,
// and every record is still durable on the primary and present on the standby in order.
func TestGroupCommitBatchesConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	primary, err := Open(filepath.Join(dir, "p.wal"))
	if err != nil {
		t.Fatal(err)
	}
	standby, err := Open(filepath.Join(dir, "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	rep := &slowReplica{w: standby, delay: 50 * time.Millisecond}
	primary.SetReplica(rep)

	const N = 100
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := primary.Append(Record{Op: OpCreate, Path: fmt.Sprintf("f%03d", i), Mode: 0o644}); err != nil {
				t.Errorf("append %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	rep.mu.Lock()
	batches, records := rep.batches, rep.records
	rep.mu.Unlock()

	// Per-write replication would be N*50ms = 5s and N batches. Group commit must
	// amortize: well under N round-trips and a small multiple of one batch latency.
	if records != N {
		t.Fatalf("replicated %d records, want exactly %d", records, N)
	}
	if batches >= N {
		t.Fatalf("group commit did not batch: %d round-trips for %d writes", batches, N)
	}
	if elapsed > time.Duration(N/5)*rep.delay {
		t.Fatalf("too slow (%v) — group commit is not amortizing replication latency (%d batches)", elapsed, batches)
	}
	t.Logf("group commit: %d concurrent writes in %v via %d replication round-trips (vs %d per-write)", N, elapsed, batches, N)

	if pr, _ := primary.Replay(); len(pr) != N {
		t.Fatalf("primary holds %d records after replay, want %d", len(pr), N)
	}
}

// TestGroupCommitPoisonsOnReplicaFailure: a failed replication round leaves an
// uncertain local suffix. WorkFS applies only after CommitThrough, but the WAL is
// still poisoned so the authority cannot reuse or acknowledge an LSN whose
// standby outcome is unknown. Subsequent appends are refused.
func TestGroupCommitPoisonsOnReplicaFailure(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	w.SetReplica(failReplica{})
	if err := w.Append(Record{Op: OpCreate, Path: "x", Mode: 0o644}); err == nil {
		t.Fatal("append must fail when the replica is down (the write is not acked)")
	}
	// The WAL is poisoned — it refuses all further appends, taking the node out of
	// service so the cluster fails over rather than diverging from the standby.
	if _, err := w.AppendBuffered(Record{Op: OpCreate, Path: "y", Mode: 0o644}); err == nil {
		t.Fatal("a poisoned WAL must refuse further appends (node halts → failover)")
	}
}

// TestAttachReplicaRejectsDivergentEpochWithoutReset proves recovery never
// destroys a standby merely because a different primary tries to attach.
func TestAttachReplicaRejectsDivergentEpochWithoutReset(t *testing.T) {
	dir := t.TempDir()
	primary, err := Open(filepath.Join(dir, "primary.wal"))
	if err != nil {
		t.Fatal(err)
	}
	// Primary's current (e.g. just-replayed-on-restart) records.
	for _, p := range []string{"a", "b"} {
		if err := primary.Append(Record{Op: OpCreate, Path: p, Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	// Standby left over with stale records from a dead primary (never reset).
	standby, err := Open(filepath.Join(dir, "standby.wal"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"stale1", "stale2", "stale3"} {
		if err := standby.Append(Record{Op: OpCreate, Path: p, Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}

	if err := primary.AttachReplica(&localReplica{w: standby}); err == nil {
		t.Fatal("attach accepted a divergent standby epoch")
	}

	recs, err := standby.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || recs[0].Path != "stale1" || recs[2].Path != "stale3" {
		t.Fatalf("failed attach destructively changed standby: %+v", recs)
	}
}

// TestTornTailTruncatedSoLaterAppendsSurvive reproduces the bug where a torn tail
// was discarded on replay but its bytes were NOT truncated: the next append landed
// after the stale torn bytes, and a later replay read [valid][torn][new] and
// rejected the whole log as mid-log corruption — losing the new acknowledged write.
func TestTornTailTruncatedSoLaterAppendsSurvive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(Record{Op: OpCreate, Path: "A", Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	// Simulate a torn trailing write (a crash mid-append): a partial frame header.
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	_, _ = f.Write([]byte{0, 0, 0, 100, 1, 2, 3})
	_ = f.Close()

	// Replay discards AND truncates the torn tail.
	w2, _ := Open(path)
	recs, err := w2.Replay()
	if err != nil {
		t.Fatalf("replay should discard the torn tail, not error: %v", err)
	}
	if len(recs) != 1 || recs[0].Path != "A" {
		t.Fatalf("replay = %+v, want [A]", recs)
	}
	// A new acknowledged write after the torn tail...
	if err := w2.Append(Record{Op: OpCreate, Path: "B", Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	_ = w2.Close()

	// ...must survive a subsequent replay (the torn bytes were truncated, so the log
	// is [A][B], not [A][torn][B] which would be read as mid-log corruption).
	w3, _ := Open(path)
	recs, err = w3.Replay()
	if err != nil {
		t.Fatalf("replay after torn-tail + append must succeed: %v", err)
	}
	if len(recs) != 2 || recs[0].Path != "A" || recs[1].Path != "B" {
		t.Fatalf("replay = %+v, want [A B] — a torn tail must not corrupt later appends", recs)
	}
}

// TestMidLogCorruptionDetected: a corrupt record in the MIDDLE of the log (valid
// records follow it) is reported as an error, not silently truncated — otherwise
// the still-good acked writes after it would be lost without a trace. A torn tail
// (corrupt LAST record) is still discarded silently (the normal crash artifact).
func TestMidLogCorruptionDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := w.Append(Record{Op: OpCreate, Path: fmt.Sprintf("f%d", i), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()

	// Flip a byte inside the SECOND record's data (frame layout: [4B len][4B crc][data]).
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	len0 := binary.BigEndian.Uint32(raw[0:4])
	frame1Data := 8 + int(len0) + 8 // skip frame0, then frame1's [len][crc]
	raw[frame1Data] ^= 0xff
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	w2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w2.Replay(); err == nil {
		t.Fatal("mid-log corruption was silently accepted; records after the fault would be lost")
	}
}
