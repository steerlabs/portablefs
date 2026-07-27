package session

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// recs builds n records whose Data payload is size bytes each.
func recs(n, size int) []wal.Record {
	out := make([]wal.Record, n)
	for i := range out {
		out[i] = wal.Record{Op: wal.OpWrite, Path: "f", Data: make([]byte, size)}
	}
	return out
}

// TestBatchCut pins the flush-batch sizing rules: zero limits reproduce the
// historical behavior (maxFlushBatch records, no byte bound); MaxRecords and
// MaxBytes bound a batch; and a single record larger than MaxBytes still ships
// alone (bounded progress, never a stall).
func TestBatchCut(t *testing.T) {
	cases := []struct {
		name    string
		pending []wal.Record
		limits  FlushLimits
		want    int
	}{
		{"zero limits default 512", recs(600, 1), FlushLimits{}, maxFlushBatch},
		{"zero limits small pending", recs(10, 1), FlushLimits{}, 10},
		{"max records bounds", recs(10, 1), FlushLimits{MaxRecords: 3}, 3},
		{"max records above pending", recs(2, 1), FlushLimits{MaxRecords: 100}, 2},
		{"negative records means default", recs(600, 1), FlushLimits{MaxRecords: -1}, maxFlushBatch},
		{"byte bound cuts", recs(3, 100), FlushLimits{MaxBytes: 150}, 1},
		{"byte bound fits two", recs(3, 100), FlushLimits{MaxBytes: 200}, 2},
		{"oversized single record ships", recs(3, 1000), FlushLimits{MaxBytes: 10}, 1},
		{"both bounds, records first", recs(10, 1), FlushLimits{MaxRecords: 4, MaxBytes: 1 << 20}, 4},
		{"both bounds, bytes first", recs(10, 100), FlushLimits{MaxRecords: 8, MaxBytes: 250}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := batchCut(tc.pending, tc.limits); got != tc.want {
				t.Fatalf("batchCut = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestBatchCutCountsTargetBytes: MaxBytes bounds the payload (Data+Target), so a
// symlink-heavy batch is bounded too.
func TestBatchCutCountsTargetBytes(t *testing.T) {
	pending := []wal.Record{
		{Op: wal.OpSymlink, Path: "l1", Target: strings.Repeat("t", 100)},
		{Op: wal.OpSymlink, Path: "l2", Target: strings.Repeat("t", 100)},
	}
	if got := batchCut(pending, FlushLimits{MaxBytes: 150}); got != 1 {
		t.Fatalf("batchCut with Target payloads = %d, want 1", got)
	}
}

// batchRecordingAuthority records the record-count of every FlushBatch call.
type batchRecordingAuthority struct {
	mu      sync.Mutex
	batches []int
}

func (a *batchRecordingAuthority) Checkout(string, string) (bool, string, CheckoutGrant, error) {
	return true, "", CheckoutGrant{}, nil
}
func (a *batchRecordingAuthority) Checkin(string, string, CheckoutGrant) error { return nil }
func (a *batchRecordingAuthority) Read(string, int64, int64) ([]byte, int32, error) {
	return nil, 2, nil // ENOENT: nothing exists on the fake authority
}
func (a *batchRecordingAuthority) Stat(string) (string, uint32, int32, error) {
	return "", 0, 2, nil
}
func (a *batchRecordingAuthority) Readlink(string) (string, int32, error) { return "", 2, nil }
func (a *batchRecordingAuthority) FlushBatch(_ string, _ uint64, _ string, _ CheckoutGrant, records []wal.Record) (uint64, int32, error) {
	a.mu.Lock()
	a.batches = append(a.batches, len(records))
	a.mu.Unlock()
	if len(records) == 0 {
		return 0, statusOK, nil
	}
	return records[len(records)-1].Seq, statusOK, nil
}

// TestFlushHonorsFlushLimits proves the plumbing end-to-end at the session layer:
// with MaxRecords=2, five buffered mutations flush as batches of at most 2 with
// nothing lost or reordered; with zero limits they flush as one batch.
func TestFlushHonorsFlushLimits(t *testing.T) {
	newSess := func(t *testing.T, limits FlushLimits) (*Session, *batchRecordingAuthority) {
		t.Helper()
		auth := &batchRecordingAuthority{}
		s, err := New(auth, "M", "sess-limits", "", filepath.Join(t.TempDir(), "sess.wal"))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		s.SetFlushLimits(limits)
		if err := s.Create("f", 0o644); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 4; i++ {
			if _, err := s.Write("f", int64(i), []byte{byte(i)}); err != nil {
				t.Fatal(err)
			}
		}
		return s, auth
	}

	t.Run("bounded", func(t *testing.T) {
		s, auth := newSess(t, FlushLimits{MaxRecords: 2})
		if err := s.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		auth.mu.Lock()
		defer auth.mu.Unlock()
		total := 0
		for _, n := range auth.batches {
			if n > 2 {
				t.Fatalf("a batch carried %d records, limit 2 (batches=%v)", n, auth.batches)
			}
			total += n
		}
		if total != 5 {
			t.Fatalf("flushed %d records total, want 5 (batches=%v)", total, auth.batches)
		}
		if len(auth.batches) != 3 {
			t.Fatalf("batches=%v, want 3 calls (2+2+1)", auth.batches)
		}
	})

	t.Run("default single batch", func(t *testing.T) {
		s, auth := newSess(t, FlushLimits{})
		if err := s.Flush(); err != nil {
			t.Fatalf("Flush: %v", err)
		}
		auth.mu.Lock()
		defer auth.mu.Unlock()
		if len(auth.batches) != 1 || auth.batches[0] != 5 {
			t.Fatalf("batches=%v, want one batch of 5", auth.batches)
		}
	})
}

// TestManagerAppliesFlushLimitsToNewSessions proves the manager plumbing: limits
// set once at startup reach every session it creates.
func TestManagerAppliesFlushLimitsToNewSessions(t *testing.T) {
	auth := &batchRecordingAuthority{}
	m := NewManager(auth, "M", t.TempDir(), 0)
	m.SetFlushLimits(FlushLimits{MaxRecords: 2, MaxBytes: 1 << 20})
	s, err := m.Ensure("work/db")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	s.mu.Lock()
	got := s.limits
	s.mu.Unlock()
	if got.MaxRecords != 2 || got.MaxBytes != 1<<20 {
		t.Fatalf("session limits = %+v, want MaxRecords=2 MaxBytes=1MiB", got)
	}
}
