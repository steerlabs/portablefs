package seglog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func value(seed int, size int) []byte {
	out := make([]byte, size)
	state := uint64(seed)*0x9e3779b97f4a7c15 + 1
	for i := 0; i+8 <= len(out); i += 8 {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		binary.LittleEndian.PutUint64(out[i:], state|1)
	}
	return out
}

func openTestStore(t *testing.T, dir string, mutate func(*Options)) *Store {
	t.Helper()
	opts := Options{
		Dir:           dir,
		SegmentBytes:  64 << 10,
		GroupInterval: time.Hour,
		GroupBytes:    1 << 30,
	}
	if mutate != nil {
		mutate(&opts)
	}
	store, err := Open(opts)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return store
}

func TestRecordRoundTrip(t *testing.T) {
	key := []byte("inode/42")
	body := value(7, 4096)
	encoded, err := EncodeRecord(9, KindPut, key, body)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	header, gotKey, gotValue, err := DecodeRecord(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if header.Seq != 9 || header.Kind != KindPut {
		t.Fatalf("header = %+v", header)
	}
	if !bytes.Equal(gotKey, key) || !bytes.Equal(gotValue, body) {
		t.Fatal("round trip changed the payload")
	}
	encoded[HeaderBytes+3] ^= 0x01
	if _, _, _, err := DecodeRecord(encoded); err == nil {
		t.Fatal("a flipped payload bit must fail the checksum")
	}
}

func TestPutGetDeleteSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, nil)
	for i := 0; i < 200; i++ {
		if err := store.Put(fmt.Sprintf("k%04d", i), value(i, 512)); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	for i := 0; i < 200; i += 3 {
		if err := store.Delete(fmt.Sprintf("k%04d", i)); err != nil {
			t.Fatalf("delete %d: %v", i, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened := openTestStore(t, dir, nil)
	defer reopened.Close()
	for i := 0; i < 200; i++ {
		got, found, err := reopened.Get(fmt.Sprintf("k%04d", i))
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		if i%3 == 0 {
			if found {
				t.Fatalf("key %d should be deleted", i)
			}
			continue
		}
		if !found || !bytes.Equal(got, value(i, 512)) {
			t.Fatalf("key %d read back wrong", i)
		}
	}
	if reopened.Recovery().Mode != "full-scan" {
		t.Fatalf("expected a full scan, got %q", reopened.Recovery().Mode)
	}
}

func TestPartialGroupIsDiscarded(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, nil)
	if err := store.Put("committed", value(1, 64)); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := store.Barrier(); err != nil {
		t.Fatalf("barrier: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Simulate a crash between writev and the group trailer: a structurally
	// valid record that was never acknowledged.
	path := filepath.Join(dir, segmentName(0))
	committed, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	orphan, err := EncodeRecord(1000, KindPut, []byte("unacknowledged"), value(2, 128))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := file.Write(orphan); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened := openTestStore(t, dir, nil)
	defer reopened.Close()
	if _, found, err := reopened.Get("unacknowledged"); err != nil || found {
		t.Fatalf("records after the last complete group must not be visible (found=%v err=%v)", found, err)
	}
	if _, found, err := reopened.Get("committed"); err != nil || !found {
		t.Fatalf("committed record lost (found=%v err=%v)", found, err)
	}
	truncated, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if truncated.Size() != committed.Size() {
		t.Fatalf("segment is %d bytes, expected truncation back to %d", truncated.Size(), committed.Size())
	}
}

func TestCleanerReclaimsWithoutLosingData(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, func(o *Options) {
		o.SegmentBytes = 32 << 10
		o.CleanUtilization = 0.7
		o.GroupBytes = 8 << 10
	})
	defer store.Close()

	const keys = 64
	for round := 0; round < 40; round++ {
		for i := 0; i < keys; i++ {
			if err := store.Put(fmt.Sprintf("k%03d", i), value(round*keys+i, 256)); err != nil {
				t.Fatalf("put: %v", err)
			}
		}
		if err := store.Barrier(); err != nil {
			t.Fatalf("barrier: %v", err)
		}
		if err := store.Clean(); err != nil {
			t.Fatalf("clean: %v", err)
		}
	}
	stats := store.Stats()
	if stats.SegmentsReclaimed == 0 {
		t.Fatalf("expected the cleaner to reclaim segments, stats=%+v", stats)
	}
	if stats.LiveBytes > stats.TotalBytes {
		t.Fatalf("live %d exceeds total %d", stats.LiveBytes, stats.TotalBytes)
	}
	for i := 0; i < keys; i++ {
		got, found, err := store.Get(fmt.Sprintf("k%03d", i))
		if err != nil || !found {
			t.Fatalf("key %d missing after cleaning (found=%v err=%v)", i, found, err)
		}
		if !bytes.Equal(got, value(39*keys+i, 256)) {
			t.Fatalf("key %d holds a stale value after cleaning", i)
		}
	}
}

func TestCleanedStoreRecoversFromLogAlone(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, func(o *Options) {
		o.SegmentBytes = 32 << 10
		o.CleanUtilization = 0.7
		o.GroupBytes = 8 << 10
	})
	const keys = 48
	for round := 0; round < 30; round++ {
		for i := 0; i < keys; i++ {
			if err := store.Put(fmt.Sprintf("k%03d", i), value(round*keys+i, 256)); err != nil {
				t.Fatalf("put: %v", err)
			}
		}
		if err := store.Clean(); err != nil {
			t.Fatalf("clean: %v", err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened := openTestStore(t, dir, nil)
	defer reopened.Close()
	for i := 0; i < keys; i++ {
		got, found, err := reopened.Get(fmt.Sprintf("k%03d", i))
		if err != nil || !found {
			t.Fatalf("key %d missing after recovery (found=%v err=%v)", i, found, err)
		}
		if !bytes.Equal(got, value(29*keys+i, 256)) {
			t.Fatalf("key %d recovered a stale value: relocation must not overtake newer writes", i)
		}
	}
}

func TestGroupCommitCoalesces(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, func(o *Options) {
		o.GroupBytes = 1 << 30
		o.GroupInterval = time.Hour
	})
	defer store.Close()
	for i := 0; i < 500; i++ {
		if err := store.Put(fmt.Sprintf("k%03d", i), value(i, 64)); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	if err := store.Barrier(); err != nil {
		t.Fatalf("barrier: %v", err)
	}
	stats := store.Stats()
	if stats.Groups != 1 {
		t.Fatalf("expected one group for 500 staged records, got %d", stats.Groups)
	}
	if stats.Syncs != 1 {
		t.Fatalf("expected one fsync, got %d", stats.Syncs)
	}
	if stats.MaxGroupRecords != 500 {
		t.Fatalf("expected a 500-record group, got %d", stats.MaxGroupRecords)
	}
}

func TestGroupBytesThresholdCommits(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, func(o *Options) {
		o.GroupBytes = 4 << 10
		o.GroupInterval = time.Hour
	})
	defer store.Close()
	for i := 0; i < 64; i++ {
		if err := store.Put(fmt.Sprintf("k%03d", i), value(i, 1024)); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	if err := store.Barrier(); err != nil {
		t.Fatalf("barrier: %v", err)
	}
	stats := store.Stats()
	if stats.Groups < 16 {
		t.Fatalf("a 4 KiB group threshold over 64 KiB should commit at least 16 groups, got %d", stats.Groups)
	}
}

// TestConcurrentWritersKeepDistinctOffsets is the regression test for the
// group-commit reservation bug: the timer goroutine can commit a group while
// another goroutine is staging records, and the staged records must not be
// assigned offsets the in-flight group is about to occupy.
func TestConcurrentWritersKeepDistinctOffsets(t *testing.T) {
	dir := t.TempDir()
	store := openTestStore(t, dir, func(o *Options) {
		o.SegmentBytes = 1 << 20
		o.GroupInterval = 100 * time.Microsecond
		o.GroupBytes = 4 << 10
	})

	const writers = 4
	const perWriter = 400
	errs := make(chan error, writers)
	for w := 0; w < writers; w++ {
		go func(w int) {
			for i := 0; i < perWriter; i++ {
				key := fmt.Sprintf("w%02d-k%04d", w, i)
				if err := store.Put(key, value(w*perWriter+i, 300)); err != nil {
					errs <- err
					return
				}
				if i%7 == 0 {
					if err := store.Barrier(); err != nil {
						errs <- err
						return
					}
				}
			}
			errs <- nil
		}(w)
	}
	for w := 0; w < writers; w++ {
		if err := <-errs; err != nil {
			t.Fatalf("writer: %v", err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened := openTestStore(t, dir, nil)
	defer reopened.Close()
	for w := 0; w < writers; w++ {
		for i := 0; i < perWriter; i++ {
			key := fmt.Sprintf("w%02d-k%04d", w, i)
			got, found, err := reopened.Get(key)
			if err != nil {
				t.Fatalf("get %s: %v", key, err)
			}
			if !found || !bytes.Equal(got, value(w*perWriter+i, 300)) {
				t.Fatalf("key %s read back wrong (found=%v)", key, found)
			}
		}
	}
}

// TestSpaceBudgetBoundsTheLog checks the property that makes a steady-state
// amplification number meaningful: with the cleaner unable to be outrun, the
// log must stop growing rather than absorb the shortfall as space.
func TestSpaceBudgetBoundsTheLog(t *testing.T) {
	dir := t.TempDir()
	const (
		liveKeys     = 512
		valueBytes   = 2048
		segmentBytes = 64 << 10
		utilization  = 0.7
	)
	store := openTestStore(t, dir, func(o *Options) {
		o.SegmentBytes = segmentBytes
		o.GroupBytes = 16 << 10
		o.GroupInterval = time.Millisecond
		o.CleanUtilization = utilization
		o.SpaceHeadroom = 1.10
	})
	defer store.Close()

	for i := 0; i < liveKeys; i++ {
		if err := store.Put(fmt.Sprintf("k%04d", i), value(i, valueBytes)); err != nil {
			t.Fatalf("fill: %v", err)
		}
	}
	if err := store.Barrier(); err != nil {
		t.Fatalf("barrier: %v", err)
	}
	for op := 0; op < liveKeys*20; op++ {
		if err := store.Put(fmt.Sprintf("k%04d", op%liveKeys), value(op, valueBytes)); err != nil {
			t.Fatalf("overwrite: %v", err)
		}
	}
	if err := store.Barrier(); err != nil {
		t.Fatalf("barrier: %v", err)
	}
	stats := store.Stats()
	budget := 1.10/utilization*float64(stats.LiveBytes) + float64(4*segmentBytes)
	if float64(stats.TotalBytes) > budget*1.5 {
		t.Fatalf("log grew to %d bytes against a %.0f-byte budget for %d live bytes (overruns=%d)",
			stats.TotalBytes, budget, stats.LiveBytes, stats.AdmitOverruns)
	}
	for i := 0; i < liveKeys; i++ {
		if _, found, err := store.Get(fmt.Sprintf("k%04d", i)); err != nil || !found {
			t.Fatalf("key %d lost under space pressure (found=%v err=%v)", i, found, err)
		}
	}
}
