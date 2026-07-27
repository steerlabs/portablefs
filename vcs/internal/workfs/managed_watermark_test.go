package workfs

// Tree/cursor atomicity for managed rows: the applied watermark advances
// INSIDE each row's fs.mu visibility unit, so a snapshot/probe can never
// capture a tree that reflects rows the watermark does not cover — single
// rows, mid-group rows, and arbitrary concurrency included. The coherence
// subscription doubles as the deterministic hook at the FORMER torn window
// (publication precedes the old outer-advance point): every published
// revision immediately forces a snapshot and asserts the pair.

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// wmCount counts the marker files a watermark test journals (one per row),
// so tree-visible rows are directly comparable with the applied cursor.
func wmCount(snap *Snapshot, prefix string) uint64 {
	var n uint64
	for _, e := range snap.Entries {
		if e.Kind == "file" && strings.HasPrefix(e.Path, prefix) {
			n++
		}
	}
	return n
}

// requireExactCut fails when a snapshot's tree and applied watermark are
// torn. Every journaled row creates exactly one marker at exactly one LSN
// (fakeEntryLog LSNs start at 0), so visible markers == applied watermark in
// EVERY correct interleaving; the old post-unlock advance made markers >
// watermark observable.
func requireExactCut(t *testing.T, fs *FS, prefix string) {
	t.Helper()
	snap := fs.Snapshot()
	if got, want := wmCount(snap, prefix), snap.WALWatermark(); got != want {
		t.Fatalf("torn capture: %d %s rows visible under applied watermark %d", got, prefix, want)
	}
	if applied := fs.AppliedWatermark(); applied < snap.WALWatermark() {
		t.Fatalf("applied watermark regressed: snapshot %d, live %d", snap.WALWatermark(), applied)
	}
}

func TestManagedSingleRowWatermarkNeverTorn(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	batches, cancel := fs.Subscribe()
	defer cancel()

	const rows = 48
	commitErr := make(chan error, 1)
	go func() {
		for i := 0; i < rows; i++ {
			if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: fmt.Sprintf("wm-%03d", i), Mode: 0o644}, nil, ""); err != nil {
				commitErr <- err
				return
			}
		}
		commitErr <- nil
	}()
	// Each published revision lands exactly at the former torn window (the
	// row's tree mutation was visible, the outer advance had not run yet):
	// snapshot immediately and require the exact pair.
	for seen := 0; seen < rows; seen++ {
		<-batches
		requireExactCut(t, fs, "wm-")
	}
	if err := <-commitErr; err != nil {
		t.Fatalf("commit: %v", err)
	}
	final := fs.Snapshot()
	if got := wmCount(final, "wm-"); got != rows || final.WALWatermark() != rows {
		t.Fatalf("final state: %d rows visible, watermark %d, want %d", got, final.WALWatermark(), rows)
	}
}

func TestManagedGroupApplyAdvancesEachRowExactly(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	batches, cancel := fs.Subscribe()
	defer cancel()

	specs := []entrySpec{
		{tree: &wal.Record{Op: wal.OpCreate, Path: "wmg-0", Mode: 0o644}, through: 10},
		{tree: &wal.Record{Op: wal.OpCreate, Path: "wmg-1", Mode: 0o644}, through: 20},
		{tree: &wal.Record{Op: wal.OpCreate, Path: "wmg-2", Mode: 0o644}, through: 30},
	}
	groupDone := make(chan error, 1)
	go func() {
		through, err := fs.commitEntriesGroup(specs, "")
		if err == nil && through != 30 {
			err = fmt.Errorf("group applied-through %d, want 30", through)
		}
		groupDone <- err
	}()
	// Rows publish one revision each; every one must expose the EXACT row
	// prefix — tree rows and applied watermark advance together mid-group.
	watermarks := make([]uint64, 0, len(specs))
	for range specs {
		<-batches
		snap := fs.Snapshot()
		got, want := wmCount(snap, "wmg-"), snap.WALWatermark()
		if got != want {
			t.Fatalf("mid-group torn capture: %d rows visible under watermark %d", got, want)
		}
		watermarks = append(watermarks, want)
	}
	if err := <-groupDone; err != nil {
		t.Fatalf("group: %v", err)
	}
	for i := 1; i < len(watermarks); i++ {
		if watermarks[i] < watermarks[i-1] {
			t.Fatalf("published watermarks regressed: %v", watermarks)
		}
	}
	if final := fs.Snapshot(); final.WALWatermark() != 3 || wmCount(final, "wmg-") != 3 {
		t.Fatalf("final group state: watermark %d, rows %d", final.WALWatermark(), wmCount(final, "wmg-"))
	}
}

// lsnOpaqueEntryLog hides the fake log's caller-visible LSN/Seq mutation:
// AppendEntriesBuffered stages deep copies, so the caller's JournalEntry and
// tree record keep their zero positions. The applied cursor must derive
// exclusively from the append reservation RETURN values.
type lsnOpaqueEntryLog struct{ *fakeEntryLog }

func (l lsnOpaqueEntryLog) AppendEntriesBuffered(entries []pfj3.JournalEntry) (uint64, uint64, error) {
	copies := make([]pfj3.JournalEntry, len(entries))
	for i := range entries {
		copies[i] = entries[i]
		if entries[i].Tree != nil {
			tree := *entries[i].Tree
			copies[i].Tree = &tree
		}
	}
	return l.fakeEntryLog.AppendEntriesBuffered(copies)
}

func TestManagedAppliedCursorIndependentOfLogLSNMutation(t *testing.T) {
	inner := newFakeEntryLog()
	log := lsnOpaqueEntryLog{inner}
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		record := wal.Record{Op: wal.OpCreate, Path: fmt.Sprintf("opaque-%d", i), Mode: 0o644}
		if _, err := fs.CommitEntry(&record, nil, ""); err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
		if record.Seq != 0 {
			t.Fatalf("caller record %d mutated by the log (seq %d); the contract must not rely on it", i, record.Seq)
		}
	}
	if got := fs.AppliedWatermark(); got != 3 {
		t.Fatalf("applied watermark %d, want 3 (positions must come from the reservation return)", got)
	}
	if got := inner.Watermark(); got != 3 {
		t.Fatalf("durable watermark %d, want 3", got)
	}
	requireExactCut(t, fs, "opaque-")

	// Cold replay over the same durable rows converges (the stored bytes
	// carry the real LSNs regardless of the caller-visible copies).
	fs2, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	if got := fs2.AppliedWatermark(); got != 3 {
		t.Fatalf("replayed applied watermark %d, want 3", got)
	}
	if _, err := fs2.Stat("opaque-2"); err != nil {
		t.Fatalf("replayed tree missing row: %v", err)
	}
}

func TestManagedWatermarkStressRace(t *testing.T) {
	log := newFakeEntryLog()
	fs, err := NewManaged(nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var probes sync.WaitGroup
	probes.Add(1)
	go func() {
		defer probes.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			snap := fs.Snapshot()
			if got, want := wmCount(snap, "race-"), snap.WALWatermark(); got != want {
				panic(fmt.Sprintf("torn capture under race: %d rows at watermark %d", got, want))
			}
		}
	}()
	var writers sync.WaitGroup
	writerErrs := make([]error, 4)
	for w := 0; w < 4; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for k := 0; k < 25; k++ {
				if _, err := fs.CommitEntry(&wal.Record{
					Op: wal.OpCreate, Path: fmt.Sprintf("race-%d-%02d", w, k), Mode: 0o644,
				}, nil, ""); err != nil {
					writerErrs[w] = err
					return
				}
			}
		}(w)
	}
	writers.Wait()
	close(stop)
	probes.Wait()
	for w, err := range writerErrs {
		if err != nil {
			t.Fatalf("writer %d: %v", w, err)
		}
	}
	requireExactCut(t, fs, "race-")
	if got := fs.AppliedWatermark(); got != 100 {
		t.Fatalf("applied watermark %d, want 100", got)
	}
}
