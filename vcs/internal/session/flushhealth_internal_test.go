package session

import (
	"errors"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// flakyFlushAuthority fails FlushBatch while failing is set and succeeds after.
type flakyFlushAuthority struct {
	mu      sync.Mutex
	failing bool
}

func (a *flakyFlushAuthority) setFailing(v bool) { a.mu.Lock(); a.failing = v; a.mu.Unlock() }

func (a *flakyFlushAuthority) Checkout(string, string) (bool, string, CheckoutGrant, error) {
	return true, "", CheckoutGrant{}, nil
}
func (a *flakyFlushAuthority) Checkin(string, string, CheckoutGrant) error { return nil }
func (a *flakyFlushAuthority) Read(string, int64, int64) ([]byte, int32, error) {
	return nil, 2, nil // ENOENT: nothing exists on the fake authority
}
func (a *flakyFlushAuthority) Stat(string) (string, uint32, int32, error) {
	return "", 0, 2, nil
}
func (a *flakyFlushAuthority) Readlink(string) (string, int32, error) { return "", 2, nil }
func (a *flakyFlushAuthority) FlushBatch(_ string, _ uint64, _ string, _ CheckoutGrant, records []wal.Record) (uint64, int32, error) {
	a.mu.Lock()
	failing := a.failing
	a.mu.Unlock()
	if failing {
		return 0, 0, errors.New("authority unreachable")
	}
	if len(records) == 0 {
		return 0, statusOK, nil
	}
	return records[len(records)-1].Seq, statusOK, nil
}

// TestFlushAllReportsPerRootFlushHealth proves the loud-failure surface end to
// end at the manager layer: a failing flush reaches the health hook with its
// root and a non-nil error (what the daemon uses to flip the attach degraded),
// FlushAll itself returns the error, and the first successful flush after
// recovery reports nil for the same root (what clears the degraded state).
func TestFlushAllReportsPerRootFlushHealth(t *testing.T) {
	auth := &flakyFlushAuthority{}
	m := NewManager(auth, "M", t.TempDir(), 0)
	t.Cleanup(func() { _ = m.Stop() })

	type report struct {
		root string
		err  error
	}
	var mu sync.Mutex
	var reports []report
	m.SetOnFlushHealth(func(root string, err error) {
		mu.Lock()
		reports = append(reports, report{root, err})
		mu.Unlock()
	})

	s, err := m.Ensure("work/db")
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	roots := m.Roots()
	if len(roots) != 1 {
		t.Fatalf("roots=%v, want exactly one session root", roots)
	}
	root := roots[0]
	if err := s.Create("f", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("f", 0, []byte("x")); err != nil {
		t.Fatal(err)
	}

	auth.setFailing(true)
	if err := m.FlushAll(); err == nil {
		t.Fatal("FlushAll returned nil while the authority was refusing flushes")
	}
	mu.Lock()
	if len(reports) == 0 {
		mu.Unlock()
		t.Fatal("failing flush never reached the health hook")
	}
	last := reports[len(reports)-1]
	mu.Unlock()
	if last.root != root || last.err == nil {
		t.Fatalf("failing flush reported {root:%q err:%v}, want root %q with non-nil err", last.root, last.err, root)
	}

	auth.setFailing(false)
	if err := m.FlushAll(); err != nil {
		t.Fatalf("FlushAll after recovery: %v", err)
	}
	mu.Lock()
	last = reports[len(reports)-1]
	mu.Unlock()
	if last.root != root || last.err != nil {
		t.Fatalf("recovered flush reported {root:%q err:%v}, want root %q with nil err", last.root, last.err, root)
	}
}
