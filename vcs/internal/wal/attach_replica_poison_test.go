package wal

import (
	"path/filepath"
	"sync"
	"testing"
)

// resetOKReplica is a no-op Replica whose Reset succeeds, so AttachReplica proceeds
// past r.Reset() and into the fsync step we want to fail.
type resetOKReplica struct{}

func (resetOKReplica) Append(Record) error        { return nil }
func (resetOKReplica) AppendBatch([]Record) error { return nil }
func (resetOKReplica) Reset() error               { return nil }
func (resetOKReplica) Compact(uint64) error       { return nil }

// TestAttachReplicaFsyncFailurePoisonsUnderLock guards a data race: AttachReplica's
// fsync-failure path writes w.poisoned, which AppendBuffered reads under w.mu. If the
// poison happens after releasing w.mu, the write is unsynchronized and races a
// concurrent appender. We force f.Sync() to fail (closed fd) while another goroutine
// hammers AppendBuffered, and rely on -race to flag any unsynchronized w.poisoned
// access. With the poison taken before unlocking, the access is clean.
func TestAttachReplicaFsyncFailurePoisonsUnderLock(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "poison.wal"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// Closing the underlying file makes f.Sync() (and any Write) fail, so AttachReplica
	// reaches its poison path deterministically.
	w.mu.Lock()
	_ = w.f.Close()
	w.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Hammer the locked reader of w.poisoned concurrently with the poison write.
		for i := 0; i < 2000; i++ {
			_, _ = w.AppendBuffered(Record{Op: OpCreate, Path: "x", Mode: 0o644})
		}
	}()

	// This must reach f.Sync() (fails) -> poisonLocked while still holding w.mu.
	if err := w.AttachReplica(resetOKReplica{}); err == nil {
		t.Fatal("AttachReplica with a dead fd should fail at fsync")
	}
	wg.Wait()

	select {
	case <-w.PoisonedCh():
	default:
		t.Fatal("a durability failure during AttachReplica must poison the WAL")
	}
}
