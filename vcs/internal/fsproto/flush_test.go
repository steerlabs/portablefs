package fsproto

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

func readFile(t *testing.T, s *Server, path string) string {
	t.Helper()
	r := s.dispatch(&Request{Op: OpRead, Path: path, Size: 64})
	if r.Status != OK {
		t.Fatalf("read %s: status %d", path, r.Status)
	}
	return string(r.Data)
}

// TestFlushBatchExactlyOnce: a resent flush batch is deduped on the mount's local Seq via
// the durable per-session watermark, so it never double-applies — even after newer writes
// have advanced the file. Discriminator: a later write sets work/a="world"; resending the
// original ("hello") batch must NOT revert it. This is the corruption-risk crux.
func TestFlushBatchExactlyOnce(t *testing.T) {
	s, deleg := newEnforceServer(t)
	if r := s.dispatch(&Request{Op: OpMkdir, Path: "work", Mode: 0o755}); r.Status != OK {
		t.Fatalf("mkdir work: %d", r.Status)
	}
	if granted, _ := deleg.Checkout("work", "M"); !granted {
		t.Fatal("checkout work")
	}

	batch1 := []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "work/a", Mode: 0o644},
		{Seq: 1, Op: wal.OpWrite, Path: "work/a", Data: []byte("hello")},
	}
	if r := s.dispatch(&Request{Op: OpFlushBatch, SessionID: "sess1", Owner: "M", Records: batch1}); r.Status != OK || r.AppliedThrough != 1 {
		t.Fatalf("flush batch1: status=%d appliedThrough=%d, want OK/1", r.Status, r.AppliedThrough)
	}
	if got := readFile(t, s, "work/a"); got != "hello" {
		t.Fatalf("after batch1 work/a=%q, want hello", got)
	}

	// A newer write advances the file and the watermark (through 2 -> 3).
	batch2 := []wal.Record{{Seq: 2, Op: wal.OpWrite, Path: "work/a", Data: []byte("world")}}
	if r := s.dispatch(&Request{Op: OpFlushBatch, SessionID: "sess1", Owner: "M", Records: batch2}); r.Status != OK || r.AppliedThrough != 2 {
		t.Fatalf("flush batch2: status=%d appliedThrough=%d, want OK/2", r.Status, r.AppliedThrough)
	}
	if got := readFile(t, s, "work/a"); got != "world" {
		t.Fatalf("after batch2 work/a=%q, want world", got)
	}

	// RESEND batch1 (Seqs 0,1 < watermark 3): a no-op; work/a must stay "world".
	if r := s.dispatch(&Request{Op: OpFlushBatch, SessionID: "sess1", Owner: "M", Records: batch1}); r.Status != OK || r.AppliedThrough != 2 {
		t.Fatalf("resend batch1: status=%d appliedThrough=%d, want OK/2", r.Status, r.AppliedThrough)
	}
	if got := readFile(t, s, "work/a"); got != "world" {
		t.Fatalf("DOUBLE-APPLY: resend reverted work/a to %q, want world (dedup failed)", got)
	}
}

// TestFlushBatchEpochResets: a re-acquired session (new, higher epoch) restarts its local
// Seq space at 0. A higher epoch RESETS the dedup watermark so the Seq-0 batch applies
// (instead of being dropped against the prior generation's watermark); a STALE flush from
// the old, lower epoch is a no-op (it must not revert the new generation).
func TestFlushBatchEpochResets(t *testing.T) {
	s, deleg := newEnforceServer(t)
	s.dispatch(&Request{Op: OpMkdir, Path: "w", Mode: 0o755})
	deleg.Checkout("w", "M")

	gen1 := []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "w/a", Mode: 0o644},
		{Seq: 1, Op: wal.OpWrite, Path: "w/a", Data: []byte("gen1")},
	}
	if r := s.dispatch(&Request{Op: OpFlushBatch, SessionID: "S", Epoch: 100, Owner: "M", Records: gen1}); r.Status != OK {
		t.Fatalf("gen1 flush: status %d", r.Status)
	}
	if got := readFile(t, s, "w/a"); got != "gen1" {
		t.Fatalf("after gen1 w/a=%q, want gen1", got)
	}

	// Re-acquire: NEW generation (epoch 200 > 100), local Seq restarts at 0. The reset makes
	// this apply; without it, Seq 0 < watermark 2 would be silently dropped (the real bug).
	gen2 := []wal.Record{{Seq: 0, Op: wal.OpWrite, Path: "w/a", Data: []byte("GEN2")}}
	if r := s.dispatch(&Request{Op: OpFlushBatch, SessionID: "S", Epoch: 200, Owner: "M", Records: gen2}); r.Status != OK {
		t.Fatalf("gen2 flush: status %d", r.Status)
	}
	if got := readFile(t, s, "w/a"); got != "GEN2" {
		t.Fatalf("re-acquire (higher epoch) must apply the Seq-0 batch; w/a=%q want GEN2", got)
	}

	// A delayed flush from the OLD generation (lower epoch) must NOT revert, AND must return
	// ESTALE — NOT an OK ack carrying the newer generation's AppliedThrough, which would make the
	// stale sender compact un-applied records against a foreign Seq space and silently lose data.
	if r := s.dispatch(&Request{Op: OpFlushBatch, SessionID: "S", Epoch: 100, Owner: "M", Records: gen1}); r.Status != ESTALE {
		t.Fatalf("stale gen1 flush: status %d, want ESTALE (%d)", r.Status, ESTALE)
	}
	if got := readFile(t, s, "w/a"); got != "GEN2" {
		t.Fatalf("stale old-epoch flush must NOT revert; w/a=%q want GEN2", got)
	}
}

// TestFlushBatchGapRejected: a batch whose first record is beyond the watermark (a hole)
// is rejected so the mount resends from the watermark — never applied out of order.
func TestFlushBatchGapRejected(t *testing.T) {
	s, deleg := newEnforceServer(t)
	s.dispatch(&Request{Op: OpMkdir, Path: "w", Mode: 0o755})
	deleg.Checkout("w", "M")
	gap := []wal.Record{{Seq: 5, Op: wal.OpCreate, Path: "w/x", Mode: 0o644}}
	if r := s.dispatch(&Request{Op: OpFlushBatch, SessionID: "s", Owner: "M", Records: gap}); r.Status != EINVAL {
		t.Fatalf("gap batch: status=%d, want EINVAL", r.Status)
	}
}

// TestFlushBatchEnforcesOwnership: a session may not flush mutations into a subtree held
// by a different owner.
func TestFlushBatchEnforcesOwnership(t *testing.T) {
	s, deleg := newEnforceServer(t)
	s.dispatch(&Request{Op: OpMkdir, Path: "w", Mode: 0o755})
	deleg.Checkout("w", "OTHER")
	rec := []wal.Record{{Seq: 0, Op: wal.OpCreate, Path: "w/x", Mode: 0o644}}
	if r := s.dispatch(&Request{Op: OpFlushBatch, SessionID: "s", Owner: "M", Records: rec}); r.Status != EBUSY {
		t.Fatalf("flush into another owner's checkout: status=%d, want EBUSY", r.Status)
	}
}

// TestReservedWatermarkHiddenFromClients: the internal watermark is invisible to clients
// (direct access ENOENT; never in readdir; not client-writable).
func TestReservedWatermarkHiddenFromClients(t *testing.T) {
	s, deleg := newEnforceServer(t)
	s.dispatch(&Request{Op: OpMkdir, Path: "w", Mode: 0o755})
	deleg.Checkout("w", "M")
	s.dispatch(&Request{Op: OpFlushBatch, SessionID: "sess", Owner: "M",
		Records: []wal.Record{{Seq: 0, Op: wal.OpCreate, Path: "w/f", Mode: 0o644}}})

	if r := s.dispatch(&Request{Op: OpGetattr, Path: ".portablefs-sess"}); r.Status != ENOENT {
		t.Fatalf("reserved getattr: status=%d, want ENOENT (hidden)", r.Status)
	}
	r := s.dispatch(&Request{Op: OpReaddir, Path: ""})
	for _, e := range r.Entries {
		if isReserved(e.Name) {
			t.Fatalf("readdir leaked reserved entry %q", e.Name)
		}
	}
	if r := s.dispatch(&Request{Op: OpCreate, Path: ".portablefs-evil", Mode: 0o644}); r.Status != ENOENT {
		t.Fatalf("client create into reserved namespace: status=%d, want ENOENT", r.Status)
	}
}

// TestIsReservedResistsTraversal: the reserved-namespace guard must canonicalize like the
// workfs does, so a client cannot reach a flush watermark via path traversal (which would let
// it read/delete dedup state and break exactly-once). Regression for an audit-found CRITICAL.
func TestIsReservedResistsTraversal(t *testing.T) {
	cases := map[string]bool{
		".portablefs-sess":           true,
		"x/../.portablefs-sess":      true, // traversal back to a root reserved file
		"a/b/../../.portablefs-sess": true,
		"./.portablefs-sess":         true,
		"/.portablefs-sess":          true,
		"ws/app.db":                  false,
		"foo/.portablefs-bar":        false, // a user file named .portablefs-* in a SUBDIR is not reserved
		"app.db":                     false,
		"":                           false,
	}
	for p, want := range cases {
		if got := isReserved(p); got != want {
			t.Errorf("isReserved(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestReservedNamespaceIsRootOnly: the reserved namespace is the volume ROOT only (watermarks
// are flat ".portablefs-<session>" files). A user file legitimately named ".portablefs-*" inside a SUBDIRECTORY
// must be creatable AND listed — readdir/guards key off the full path, not the basename.
// Regression for the audit-found HIGH where basename matching hid (and blocked) such files.
func TestReservedNamespaceIsRootOnly(t *testing.T) {
	s, deleg := newEnforceServer(t)
	s.dispatch(&Request{Op: OpMkdir, Path: "d", Mode: 0o755})
	deleg.Checkout("d", "M")

	// A ".portablefs-*" name in a subdirectory is NOT reserved: a flush that creates it must succeed
	// (the flush guard keys off the full path, so the subdir file is not mistaken for a watermark).
	if r := s.dispatch(&Request{Op: OpFlushBatch, SessionID: "sess", Owner: "M",
		Records: []wal.Record{{Seq: 0, Op: wal.OpCreate, Path: "d/.portablefs-legit", Mode: 0o644}}}); r.Status != OK {
		t.Fatalf("flush create d/.portablefs-legit: status=%d, want OK (subdir .portablefs-* is a normal user file)", r.Status)
	}
	// ...and readdir of the subdir must list it (not hide it as if it were a watermark).
	r := s.dispatch(&Request{Op: OpReaddir, Path: "d"})
	if r.Status != OK {
		t.Fatalf("readdir d: status=%d", r.Status)
	}
	found := false
	for _, e := range r.Entries {
		if e.Name == ".portablefs-legit" {
			found = true
		}
	}
	if !found {
		t.Fatalf("readdir d hid a legitimate subdir file .portablefs-legit; entries=%v", r.Entries)
	}
	// The genuine root watermark stays hidden.
	if r := s.dispatch(&Request{Op: OpCreate, Path: ".portablefs-evil", Mode: 0o644}); r.Status != ENOENT {
		t.Fatalf("root .portablefs-evil create: status=%d, want ENOENT (reserved)", r.Status)
	}
}
