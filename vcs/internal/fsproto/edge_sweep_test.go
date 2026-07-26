package fsproto

// edge_sweep_test.go is an exhaustive boundary + concurrency sweep of the filesystem
// protocol's flush authority and dispatch surface. It reuses the in-package harness:
// newEnforceServer (a real workfs behind an fsproto Server + a delegation.Manager) and
// readFile, and drives the server through s.dispatch (the same entry the wire handler
// uses, minus gob framing). It exists alongside flush_test.go / fsproto_test.go and
// adds the corners those don't: gap exactly-at vs +1, the pure-resend ack value, the
// epoch <,=,> watermark trichotomy with the ESTALE no-revert/no-ack-compaction rule,
// ownership EBUSY on flush (path + rename NewPath), the reserved-namespace hiding +
// canonicalization-vs-traversal matrix, a -race sharded-lock exactly-once stress whose
// discriminator is "a resend must not revert a newer concurrent write", and a full
// per-op round-trip + error-status table (Stat/Readlink/Getattr/Read/Readdir/Create/
// Mkdir/Symlink/Truncate/Setattr/Rename).
//
// NOTE on shared helpers: newEnforceServer, readFile, nopBlobs, serve, watermarkPath,
// isReserved, and prevSeq all live in other files in this package and are deliberately
// reused here (not redefined).

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// seedCheckout makes dir `p` and grants owner `o` an exclusive checkout, the standard
// precondition for a write-back flush. It fails the test on any error.
func seedCheckout(t *testing.T, s *Server, p, o string) {
	t.Helper()
	if r := s.dispatch(&Request{Op: OpMkdir, Path: p, Mode: 0o755}); r.Status != OK {
		t.Fatalf("seed mkdir %q: status %d", p, r.Status)
	}
	if r := s.dispatch(&Request{Op: OpCheckout, Path: p, Owner: o}); r.Status != OK {
		t.Fatalf("seed checkout %q by %q: status %d", p, o, r.Status)
	}
}

func flush(s *Server, sess string, epoch uint64, owner string, recs []wal.Record) *Response {
	return s.dispatch(&Request{Op: OpFlushBatch, SessionID: sess, Epoch: epoch, Owner: owner, Records: recs})
}

// -----------------------------------------------------------------------------
// flushBatch: gap rejection at and around the watermark boundary
// -----------------------------------------------------------------------------

// TestFlushGapBoundary nails the exact gap edge: with the watermark at `through`, a
// batch whose first Seq == through is contiguous (accepted), == through+1 is a gap
// (EINVAL — "resend from the watermark"), and < through is pure resend (no-op). This
// is the +/-1 sweep around the dedup boundary that flush_test.go only touches at one
// point.
func TestFlushGapBoundary(t *testing.T) {
	s, _ := newEnforceServer(t)
	seedCheckout(t, s, "w", "M")

	// Establish watermark = 2 (next-expected Seq) via Seqs 0,1.
	if r := flush(s, "S", 0, "M", []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "w/a", Mode: 0o644},
		{Seq: 1, Op: wal.OpWrite, Path: "w/a", Data: []byte("01")},
	}); r.Status != OK || r.AppliedThrough != 1 {
		t.Fatalf("seed flush: status=%d through=%d, want OK/1", r.Status, r.AppliedThrough)
	}

	// first Seq == through+1 (==3): a hole below this batch -> EINVAL.
	if r := flush(s, "S", 0, "M", []wal.Record{{Seq: 3, Op: wal.OpWrite, Path: "w/a", Data: []byte("x")}}); r.Status != EINVAL {
		t.Fatalf("gap at through+1: status=%d, want EINVAL", r.Status)
	}
	// first Seq == through (==2): contiguous -> accepted, watermark -> 3.
	if r := flush(s, "S", 0, "M", []wal.Record{{Seq: 2, Op: wal.OpWrite, Path: "w/a", Data: []byte("23")}}); r.Status != OK || r.AppliedThrough != 2 {
		t.Fatalf("contiguous at through: status=%d through=%d, want OK/2", r.Status, r.AppliedThrough)
	}
	// A batch straddling the watermark (Seqs 1,2,3 with watermark 3): the already-applied
	// prefix (1,2) is dropped, the survivor (3) is contiguous with `through` -> accepted.
	if r := flush(s, "S", 0, "M", []wal.Record{
		{Seq: 1, Op: wal.OpWrite, Path: "w/a", Data: []byte("XX")},
		{Seq: 2, Op: wal.OpWrite, Path: "w/a", Data: []byte("YY")},
		{Seq: 3, Op: wal.OpWrite, Path: "w/a", Data: []byte("ZZ")},
	}); r.Status != OK || r.AppliedThrough != 3 {
		t.Fatalf("straddling batch: status=%d through=%d, want OK/3", r.Status, r.AppliedThrough)
	}
	// A survivor set with an internal hole (4 then 6, watermark now 4) -> EINVAL (non-contiguous).
	if r := flush(s, "S", 0, "M", []wal.Record{
		{Seq: 4, Op: wal.OpWrite, Path: "w/a", Data: []byte("44")},
		{Seq: 6, Op: wal.OpWrite, Path: "w/a", Data: []byte("66")},
	}); r.Status != EINVAL {
		t.Fatalf("internal hole among survivors: status=%d, want EINVAL", r.Status)
	}
}

// TestFlushPureResendAckValue: a flush whose every Seq is already durable returns OK and
// AppliedThrough == prevSeq(through) (the highest durable Seq), and changes nothing. The
// empty-records flush is the degenerate corner: through is 0 (no watermark yet), every
// Seq is "already applied" (none), so it is a pure resend acking prevSeq(0)==0.
func TestFlushPureResendAckValue(t *testing.T) {
	s, _ := newEnforceServer(t)
	seedCheckout(t, s, "w", "M")

	// Empty batch with NO prior watermark: through==0, first==-1 -> pure resend, ack prevSeq(0)=0.
	if r := flush(s, "S", 0, "M", nil); r.Status != OK || r.AppliedThrough != 0 {
		t.Fatalf("empty flush (no watermark): status=%d through=%d, want OK/0", r.Status, r.AppliedThrough)
	}
	// The empty resend must NOT have created the watermark file (still no .portablefs-S).
	if r := s.dispatch(&Request{Op: OpGetattr, Path: watermarkPath("S")}); r.Status != ENOENT {
		t.Fatalf("empty flush created a watermark? getattr status=%d, want ENOENT", r.Status)
	}

	// Apply Seqs 0,1,2 -> watermark 3.
	if r := flush(s, "S", 0, "M", []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "w/f", Mode: 0o644},
		{Seq: 1, Op: wal.OpWrite, Path: "w/f", Data: []byte("aa")},
		{Seq: 2, Op: wal.OpWrite, Path: "w/f", Data: []byte("bb")},
	}); r.Status != OK || r.AppliedThrough != 2 {
		t.Fatalf("apply 0..2: status=%d through=%d, want OK/2", r.Status, r.AppliedThrough)
	}
	before := readFile(t, s, "w/f")

	// Pure resend of a strict sub-prefix (Seqs 0,1, both < watermark 3): OK, ack prevSeq(3)=2, no change.
	if r := flush(s, "S", 0, "M", []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "w/f", Mode: 0o644},
		{Seq: 1, Op: wal.OpWrite, Path: "w/f", Data: []byte("aa")},
	}); r.Status != OK || r.AppliedThrough != 2 {
		t.Fatalf("pure resend: status=%d through=%d, want OK/2 (prevSeq of watermark 3)", r.Status, r.AppliedThrough)
	}
	if got := readFile(t, s, "w/f"); got != before {
		t.Fatalf("pure resend mutated the file: got %q, was %q", got, before)
	}
	// And an empty batch now (watermark 3): through=3, first=-1 -> ack prevSeq(3)=2.
	if r := flush(s, "S", 0, "M", nil); r.Status != OK || r.AppliedThrough != 2 {
		t.Fatalf("empty resend after watermark: status=%d through=%d, want OK/2", r.Status, r.AppliedThrough)
	}
}

// -----------------------------------------------------------------------------
// flushBatch: the epoch trichotomy (< , == , >) against the stored watermark
// -----------------------------------------------------------------------------

// TestFlushEpochTrichotomy exercises all three epoch relations against one stored
// watermark in one test:
//   - epoch == wmEpoch: ordinary dedup (Seq space continues).
//   - epoch >  wmEpoch: a NEW generation -> dedup resets (through:=0), Seq-0 applies.
//   - epoch <  wmEpoch: a SUPERSEDED generation -> ESTALE, NO apply, NO revert, and
//     crucially NO AppliedThrough (acking the newer gen's `through` against the stale
//     sender's foreign Seq space would make it compact unsent records = silent loss).
func TestFlushEpochTrichotomy(t *testing.T) {
	s, _ := newEnforceServer(t)
	seedCheckout(t, s, "w", "M")

	// epoch 10, Seqs 0,1 -> watermark (epoch=10, through=2), file="v1".
	if r := flush(s, "S", 10, "M", []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "w/k", Mode: 0o644},
		{Seq: 1, Op: wal.OpWrite, Path: "w/k", Data: []byte("v1")},
	}); r.Status != OK || r.AppliedThrough != 1 {
		t.Fatalf("epoch10 seed: status=%d through=%d", r.Status, r.AppliedThrough)
	}

	// epoch == 10: same generation continues at Seq 2.
	if r := flush(s, "S", 10, "M", []wal.Record{{Seq: 2, Op: wal.OpWrite, Path: "w/k", Data: []byte("v2")}}); r.Status != OK || r.AppliedThrough != 2 {
		t.Fatalf("epoch==: status=%d through=%d, want OK/2", r.Status, r.AppliedThrough)
	}
	if got := readFile(t, s, "w/k"); got != "v2" {
		t.Fatalf("epoch== applied wrong: w/k=%q want v2", got)
	}

	// epoch > 10 (say 20): NEW generation, Seq restarts at 0, dedup resets so Seq-0 applies.
	if r := flush(s, "S", 20, "M", []wal.Record{{Seq: 0, Op: wal.OpWrite, Path: "w/k", Data: []byte("GEN20")}}); r.Status != OK {
		t.Fatalf("epoch> reset: status=%d, want OK", r.Status)
	}
	if got := readFile(t, s, "w/k"); got != "GEN20" {
		t.Fatalf("epoch> must reset dedup and apply Seq0: w/k=%q want GEN20", got)
	}

	// epoch < 20 (the old 10): SUPERSEDED -> ESTALE, no apply, no revert, no AppliedThrough.
	r := flush(s, "S", 10, "M", []wal.Record{{Seq: 0, Op: wal.OpWrite, Path: "w/k", Data: []byte("STALE")}})
	if r.Status != ESTALE {
		t.Fatalf("epoch< : status=%d, want ESTALE (%d)", r.Status, ESTALE)
	}
	if r.AppliedThrough != 0 {
		t.Fatalf("ESTALE must carry NO AppliedThrough (got %d): acking the newer gen's through "+
			"would make the stale sender compact unsent records against a foreign Seq space (silent loss)", r.AppliedThrough)
	}
	if got := readFile(t, s, "w/k"); got != "GEN20" {
		t.Fatalf("ESTALE must NOT revert: w/k=%q want GEN20", got)
	}
}

// TestFlushEpochEqualZeroIsNotReset guards the off-by-one in the reset condition: when
// no watermark exists yet, the very first flush has epoch==0==wmEpoch-default but MUST
// be treated as "new" (through:=0) so Seq-0 lands — and a *higher* epoch on a fresh
// session is equally a fresh start. The discriminator is that a subsequent lower epoch
// is then ESTALE (proving the first higher epoch actually became the stored generation).
func TestFlushEpochFirstFlushHonoursEpoch(t *testing.T) {
	s, _ := newEnforceServer(t)
	seedCheckout(t, s, "w", "M")

	// First-ever flush at epoch 5 with Seq 0 (no watermark exists): must apply.
	if r := flush(s, "S", 5, "M", []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "w/g", Mode: 0o644},
		{Seq: 1, Op: wal.OpWrite, Path: "w/g", Data: []byte("five")},
	}); r.Status != OK || r.AppliedThrough != 1 {
		t.Fatalf("first flush epoch5: status=%d through=%d", r.Status, r.AppliedThrough)
	}
	if got := readFile(t, s, "w/g"); got != "five" {
		t.Fatalf("first flush epoch5 not applied: w/g=%q", got)
	}
	// A later epoch-4 flush is now stale (5 became the durable generation).
	if r := flush(s, "S", 4, "M", []wal.Record{{Seq: 0, Op: wal.OpWrite, Path: "w/g", Data: []byte("four")}}); r.Status != ESTALE {
		t.Fatalf("epoch4 after epoch5: status=%d, want ESTALE", r.Status)
	}
	if got := readFile(t, s, "w/g"); got != "five" {
		t.Fatalf("stale epoch4 reverted: w/g=%q want five", got)
	}
}

// -----------------------------------------------------------------------------
// flushBatch: ownership enforcement (EBUSY) including the rename NewPath leg
// -----------------------------------------------------------------------------

// TestFlushOwnershipEBUSY: a flush whose records touch a subtree checked out by a
// DIFFERENT owner is refused with EBUSY before anything is applied — checked on the
// record Path AND, for renames, on NewPath (a flush can't smuggle a write INTO a
// foreign checkout via a rename destination).
func TestFlushOwnershipEBUSY(t *testing.T) {
	s, deleg := newEnforceServer(t)
	// OTHER owns "locked"; M owns "mine".
	seedCheckout(t, s, "locked", "OTHER")
	seedCheckout(t, s, "mine", "M")
	// Seed a file under mine so the rename has a real source.
	if r := flush(s, "S", 0, "M", []wal.Record{{Seq: 0, Op: wal.OpCreate, Path: "mine/f", Mode: 0o644}}); r.Status != OK {
		t.Fatalf("seed mine/f: status %d", r.Status)
	}

	// Flush with the record Path inside OTHER's checkout -> EBUSY, holder reported.
	if r := flush(s, "S", 0, "M", []wal.Record{{Seq: 1, Op: wal.OpCreate, Path: "locked/x", Mode: 0o644}}); r.Status != EBUSY || r.Owner != "OTHER" {
		t.Fatalf("flush into OTHER's checkout: status=%d owner=%q, want EBUSY/OTHER", r.Status, r.Owner)
	}
	// Flush with a RENAME whose NewPath lands in OTHER's checkout -> EBUSY (the NewPath leg).
	if r := flush(s, "S", 0, "M", []wal.Record{{Seq: 1, Op: wal.OpRename, Path: "mine/f", NewPath: "locked/f"}}); r.Status != EBUSY {
		t.Fatalf("flush rename INTO OTHER's checkout: status=%d, want EBUSY (NewPath leg)", r.Status)
	}
	// The rejected flush must not have advanced the watermark: a subsequent legit Seq-1 still applies.
	if r := flush(s, "S", 0, "M", []wal.Record{{Seq: 1, Op: wal.OpWrite, Path: "mine/f", Data: []byte("ok")}}); r.Status != OK || r.AppliedThrough != 1 {
		t.Fatalf("post-EBUSY legit flush: status=%d through=%d, want OK/1 (rejected flush must not advance watermark)", r.Status, r.AppliedThrough)
	}
	// Sanity: OTHER releasing its checkout lets M flush there afterward (no residual block).
	deleg.ReleaseOwner("OTHER")
	if r := flush(s, "S", 0, "M", []wal.Record{{Seq: 2, Op: wal.OpCreate, Path: "locked/x", Mode: 0o644}}); r.Status != OK {
		t.Fatalf("flush after OTHER release: status=%d, want OK", r.Status)
	}
}

// TestFlushMalformedSessionID: a SessionID that is empty, contains a path separator, or
// is itself reserved is EINVAL (a malformed id could otherwise escape into / collide
// with the reserved watermark namespace). Also: a flush whose RECORDS touch a reserved
// path is EINVAL (a client batch may not write authority metadata).
func TestFlushMalformedSessionID(t *testing.T) {
	s, _ := newEnforceServer(t)
	seedCheckout(t, s, "w", "M")
	rec := []wal.Record{{Seq: 0, Op: wal.OpCreate, Path: "w/x", Mode: 0o644}}

	for _, bad := range []string{"", "a/b", "a\\b", ".portablefs-evil", ".portablefs-"} {
		if r := flush(s, bad, 0, "M", rec); r.Status != EINVAL {
			t.Fatalf("flush sessionID=%q: status=%d, want EINVAL", bad, r.Status)
		}
	}
	// A record targeting a reserved path -> EINVAL (covers Path and NewPath legs).
	if r := flush(s, "S", 0, "M", []wal.Record{{Seq: 0, Op: wal.OpCreate, Path: ".portablefs-sneak", Mode: 0o644}}); r.Status != EINVAL {
		t.Fatalf("flush record into reserved Path: status=%d, want EINVAL", r.Status)
	}
	if r := flush(s, "S", 0, "M", []wal.Record{{Seq: 0, Op: wal.OpRename, Path: "w/x", NewPath: "x/../.portablefs-sneak"}}); r.Status != EINVAL {
		t.Fatalf("flush record reserved via NewPath traversal: status=%d, want EINVAL", r.Status)
	}
}

// -----------------------------------------------------------------------------
// Reserved namespace: full hiding + canonicalization vs traversal
// -----------------------------------------------------------------------------

// TestReservedNamespaceFullyHidden drives the three client-visible hiding rules against
// a watermark that genuinely exists: OpGetattr -> ENOENT, never present in readdir of
// the root, and OpCreate into the namespace -> ENOENT (the client cannot materialise a
// reserved file). It also confirms a real non-reserved root file IS listed (so hiding
// is not over-broad).
func TestReservedNamespaceFullyHidden(t *testing.T) {
	s, _ := newEnforceServer(t)
	seedCheckout(t, s, "w", "M")
	// Create a real watermark by flushing.
	if r := flush(s, "realsess", 0, "M", []wal.Record{{Seq: 0, Op: wal.OpCreate, Path: "w/f", Mode: 0o644}}); r.Status != OK {
		t.Fatalf("seed flush: status %d", r.Status)
	}
	// A visible, ordinary root-level file for the "not over-broad" check.
	if r := s.dispatch(&Request{Op: OpCreate, Path: "visible.txt", Mode: 0o644}); r.Status != OK {
		t.Fatalf("create visible.txt: status %d", r.Status)
	}

	wm := watermarkPath("realsess")
	// 1) getattr the genuine watermark -> ENOENT.
	if r := s.dispatch(&Request{Op: OpGetattr, Path: wm}); r.Status != ENOENT {
		t.Fatalf("getattr %q: status=%d, want ENOENT", wm, r.Status)
	}
	// 2) readdir root: watermark absent, visible.txt present.
	rd := s.dispatch(&Request{Op: OpReaddir, Path: ""})
	if rd.Status != OK {
		t.Fatalf("readdir root: status %d", rd.Status)
	}
	sawVisible := false
	for _, e := range rd.Entries {
		if e.Name == wm || isReserved(e.Name) {
			t.Fatalf("readdir leaked reserved entry %q", e.Name)
		}
		if e.Name == "visible.txt" {
			sawVisible = true
		}
	}
	if !sawVisible {
		t.Fatalf("readdir root hid a normal file visible.txt; entries=%v", rd.Entries)
	}
	// 3) client OpCreate into the reserved namespace -> ENOENT (cannot create the file).
	if r := s.dispatch(&Request{Op: OpCreate, Path: wm, Mode: 0o644}); r.Status != ENOENT {
		t.Fatalf("client create reserved %q: status=%d, want ENOENT", wm, r.Status)
	}
	// And every other direct client op on the reserved path is ENOENT too (uniform hiding).
	for _, op := range []Op{OpRead, OpWrite, OpRemove, OpTruncate, OpSetattr, OpReadlink, OpMkdir} {
		if r := s.dispatch(&Request{Op: op, Path: wm, Size: 1, Data: []byte("x"), Mode: 0o644}); r.Status != ENOENT {
			t.Fatalf("client op %d on reserved %q: status=%d, want ENOENT (hidden)", op, wm, r.Status)
		}
	}
	// A rename whose NewPath is reserved is also hidden (ENOENT), tested via the dispatch guard.
	if r := s.dispatch(&Request{Op: OpRename, Path: "visible.txt", NewPath: ".portablefs-evil"}); r.Status != ENOENT {
		t.Fatalf("rename to reserved NewPath: status=%d, want ENOENT", r.Status)
	}
}

// TestIsReservedCanonicalizationMatrix is the focused canonicalization-vs-traversal
// table for isReserved (the guard's correctness crux): every spelling that path.Clean
// resolves to a ROOT ".portablefs-*" file is reserved, while a ".portablefs-*" basename inside a
// SUBDIR is a legitimate user file and must NOT be reserved. This is the audit-found
// CRITICAL (traversal past the guard) plus the HIGH (subdir false-positive) in one
// exhaustive matrix.
func TestIsReservedCanonicalizationMatrix(t *testing.T) {
	cases := map[string]bool{
		// Root reserved file in every traversal spelling.
		// Root reserved file (prefix is ".portablefs-", WITH the dash) in every traversal spelling.
		".portablefs-id":                       true,
		"./.portablefs-id":                     true,
		"/.portablefs-id":                      true,
		"x/../.portablefs-id":                  true,
		"a/b/../../.portablefs-id":             true,
		"a/b/c/../../../.portablefs-z":         true,
		"./x/../.portablefs-id":                true,
		"//.portablefs-id":                     true, // double slash collapses to /.portablefs-id
		".portablefs-":                         true, // bare prefix is reserved
		".portablefs-with/trailing":            true, // a ".portablefs-*" at root with children still starts with the prefix
		"x/../.portablefs-id/../.portablefs-z": true, // /x/.. -> /, /.portablefs-id/.. -> /, /.portablefs-z -> reserved
		// Legitimate: ".portablefs-*" as a basename inside a subdirectory (NOT a root watermark).
		"foo/.portablefs-bar":     false,
		"a/b/.portablefs-id":      false,
		"sub/.portablefs-id":      false,
		"x/y/../.portablefs-here": false, // cleans to x/.portablefs-here (still a subdir, not root)
		// The prefix REQUIRES the trailing dash: bare ".osw" (and ".osw" via any traversal) is
		// NOT reserved, nor is ".oswald" (".oswa..." never matches ".portablefs-").
		".osw":                  false,
		"./.osw":                false,
		"/.osw":                 false,
		"a/b/../../.osw":        false,
		".oswald":               false, // ".oswa..." never matches the ".portablefs-" prefix
		".portablefs-x.tmp":     true,  // a watermark-like name at root is reserved
		"notosw/.portablefs-no": false,
		// Plainly unreserved.
		"app.db":    false,
		"ws/app.db": false,
		"":          false,
		".":         false,
		"/":         false,
	}

	for p, want := range cases {
		if got := isReserved(p); got != want {
			t.Errorf("isReserved(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestReservedSubdirFileIsUsable end-to-ends the subdir exception through real ops: a
// flush that creates "d/.portablefs-legit" succeeds, readdir of d lists it, a client can read
// it back, yet the genuine root ".portablefs-*" stays uncreatable. (Companion to the unit
// matrix above, but via the dispatch path the wire handler uses.)
func TestReservedSubdirFileIsUsable(t *testing.T) {
	s, _ := newEnforceServer(t)
	seedCheckout(t, s, "d", "M")

	if r := flush(s, "sess", 0, "M", []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "d/.portablefs-legit", Mode: 0o644},
		{Seq: 1, Op: wal.OpWrite, Path: "d/.portablefs-legit", Data: []byte("payload")},
	}); r.Status != OK {
		t.Fatalf("flush create d/.portablefs-legit: status=%d, want OK", r.Status)
	}
	rd := s.dispatch(&Request{Op: OpReaddir, Path: "d"})
	if rd.Status != OK {
		t.Fatalf("readdir d: status %d", rd.Status)
	}
	found := false
	for _, e := range rd.Entries {
		if e.Name == ".portablefs-legit" {
			found = true
		}
	}
	if !found {
		t.Fatalf("readdir d hid subdir file .portablefs-legit; entries=%v", rd.Entries)
	}
	// Client can stat + read the legit subdir file directly (not hidden).
	if r := s.dispatch(&Request{Op: OpGetattr, Path: "d/.portablefs-legit"}); r.Status != OK {
		t.Fatalf("getattr d/.portablefs-legit: status=%d, want OK", r.Status)
	}
	if got := readFile(t, s, "d/.portablefs-legit"); got != "payload" {
		t.Fatalf("read d/.portablefs-legit=%q, want payload", got)
	}
	// The genuine root watermark namespace stays closed.
	if r := s.dispatch(&Request{Op: OpCreate, Path: ".portablefs-evil", Mode: 0o644}); r.Status != ENOENT {
		t.Fatalf("root .portablefs-evil create: status=%d, want ENOENT", r.Status)
	}
}

// -----------------------------------------------------------------------------
// Sharded per-session flush lock: concurrent exactly-once under -race
// -----------------------------------------------------------------------------

// TestConcurrentResendNeverRevertsNewerWrite is the -race exactly-once crux: many
// goroutines concurrently RESEND an already-durable batch ("hello") for one SessionID
// while one goroutine applies a strictly NEWER write ("world"). The sharded per-session
// lock must serialize the watermark read+ApplyBatch so no resend can re-apply the old
// bytes after the newer write won — the file must end as "world", and the watermark must
// have advanced exactly once past the newer write (AppliedThrough==2, never higher).
//
// Discriminator: if the dedup read+apply were NOT one critical section, a resend that
// read `through` before the newer write committed could re-apply Seq 0,1 afterward and
// REVERT the file to "hello" — the classic double-apply. -race additionally flags any
// data race on the watermark itself.
func TestConcurrentResendNeverRevertsNewerWrite(t *testing.T) {
	s, _ := newEnforceServer(t)
	seedCheckout(t, s, "w", "M")

	// Establish "hello" at Seqs 0,1 (watermark -> 2). This is the batch that gets resent.
	hello := []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "w/a", Mode: 0o644},
		{Seq: 1, Op: wal.OpWrite, Path: "w/a", Data: []byte("hello")},
	}
	if r := flush(s, "S", 0, "M", hello); r.Status != OK || r.AppliedThrough != 1 {
		t.Fatalf("seed hello: status=%d through=%d", r.Status, r.AppliedThrough)
	}
	// The newer write at Seq 2: applying it advances the watermark to 3 and the file to "world".
	world := []wal.Record{{Seq: 2, Op: wal.OpWrite, Path: "w/a", Data: []byte("world")}}

	const resenders = 32
	var wg sync.WaitGroup
	var maxThrough atomic.Uint64
	var badStatus atomic.Int32 // first unexpected status, if any

	record := func(r *Response) {
		// A resend may legally see status OK (whether before or after the newer write).
		// It must NEVER see anything else here (no EBUSY/EINVAL/ESTALE for a valid, owned,
		// contiguous-or-below-watermark batch).
		if r.Status != OK {
			badStatus.CompareAndSwap(0, r.Status)
			return
		}
		for {
			cur := maxThrough.Load()
			if r.AppliedThrough <= cur {
				break
			}
			if maxThrough.CompareAndSwap(cur, r.AppliedThrough) {
				break
			}
		}
	}

	wg.Add(resenders + 1)
	// One writer applies the newer "world" exactly once.
	go func() {
		defer wg.Done()
		record(flush(s, "S", 0, "M", world))
	}()
	// Many resenders pound the already-durable "hello".
	for i := 0; i < resenders; i++ {
		go func() {
			defer wg.Done()
			record(flush(s, "S", 0, "M", hello))
		}()
	}
	wg.Wait()

	if bs := badStatus.Load(); bs != 0 {
		t.Fatalf("a concurrent flush returned unexpected status %d (want only OK for owned valid batches)", bs)
	}
	// The newer write must win and never be reverted by a late resend.
	if got := readFile(t, s, "w/a"); got != "world" {
		t.Fatalf("DOUBLE-APPLY under concurrency: w/a=%q, want world (a resend reverted the newer write)", got)
	}
	// The watermark advanced exactly to "world" (next Seq 3 => highest durable 2) and NO further:
	// resends below the watermark must not push it past the real frontier.
	if mt := maxThrough.Load(); mt != 2 {
		t.Fatalf("watermark frontier=%d, want 2 (the newer write's Seq); a higher value means a resend over-advanced it", mt)
	}
	// Final settling read after all goroutines: still "world".
	if got := readFile(t, s, "w/a"); got != "world" {
		t.Fatalf("post-settle w/a=%q, want world", got)
	}
}

// TestConcurrentDistinctSessionsApply: independent SessionIDs flush in parallel and each
// applies its own first batch exactly once — the sharded lock serializes WITHIN a
// session but must not lose or cross-apply writes ACROSS sessions (different shards, or
// the same shard harmlessly serialized). Run under -race for the shared workfs.
func TestConcurrentDistinctSessionsApply(t *testing.T) {
	s, deleg := newEnforceServer(t)
	const sessions = 24
	// Each session owns its own subtree.
	for i := 0; i < sessions; i++ {
		dir := fmt.Sprintf("s%d", i)
		owner := fmt.Sprintf("own%d", i)
		if r := s.dispatch(&Request{Op: OpMkdir, Path: dir, Mode: 0o755}); r.Status != OK {
			t.Fatalf("mkdir %s: status %d", dir, r.Status)
		}
		if granted, _ := deleg.Checkout(dir, owner); !granted {
			t.Fatalf("checkout %s by %s", dir, owner)
		}
	}

	var wg sync.WaitGroup
	errs := make(chan error, sessions)
	wg.Add(sessions)
	for i := 0; i < sessions; i++ {
		go func(i int) {
			defer wg.Done()
			dir := fmt.Sprintf("s%d", i)
			owner := fmt.Sprintf("own%d", i)
			sess := fmt.Sprintf("S%d", i)
			val := fmt.Sprintf("val-%d", i)
			// Resend the SAME batch a few times concurrently with itself across the pool;
			// exactly-once must hold per session regardless.
			batch := []wal.Record{
				{Seq: 0, Op: wal.OpCreate, Path: dir + "/f", Mode: 0o644},
				{Seq: 1, Op: wal.OpWrite, Path: dir + "/f", Data: []byte(val)},
			}
			for rep := 0; rep < 3; rep++ {
				if r := flush(s, sess, 0, owner, batch); r.Status != OK {
					errs <- fmt.Errorf("session %s flush rep %d: status %d", sess, rep, r.Status)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	// Every session's file holds exactly its own value (no cross-contamination, no loss).
	for i := 0; i < sessions; i++ {
		if got := readFile(t, s, fmt.Sprintf("s%d/f", i)); got != fmt.Sprintf("val-%d", i) {
			t.Fatalf("session %d file=%q, want val-%d", i, got, i)
		}
	}
}

// -----------------------------------------------------------------------------
// dispatch round-trips + error statuses for every op
// -----------------------------------------------------------------------------

// TestDispatchRoundTripAllOps drives Create/Write/Read/Getattr/Mkdir/Readdir/Symlink/
// Readlink/Truncate/Setattr/Rename/Stat through the dispatch layer and checks the
// happy-path results (kinds, sizes, contents, mode). This complements the over-the-wire
// TestProtocolRoundTrip with the same coverage at the dispatch boundary, where the
// reserved-guard and checkout-enforcement wrappers also run.
func TestDispatchRoundTripAllOps(t *testing.T) {
	s, _ := newEnforceServer(t)

	// Create + Getattr.
	if r := s.dispatch(&Request{Op: OpCreate, Path: "f", Mode: 0o640}); r.Status != OK || r.Attr == nil || r.Attr.Kind != "file" {
		t.Fatalf("create f: status=%d attr=%+v", r.Status, r.Attr)
	}
	if r := s.dispatch(&Request{Op: OpGetattr, Path: "f"}); r.Status != OK || r.Attr.Mode != 0o640 {
		t.Fatalf("getattr f: status=%d attr=%+v, want mode 640", r.Status, r.Attr)
	}

	// Write at offset 0, then read it back; then an interior overwrite.
	if r := s.dispatch(&Request{Op: OpWrite, Path: "f", Offset: 0, Data: []byte("hello world"), Mode: 0o640}); r.Status != OK || r.Count != 11 {
		t.Fatalf("write f: status=%d count=%d, want OK/11", r.Status, r.Count)
	}
	if got := readFile(t, s, "f"); got != "hello world" {
		t.Fatalf("read f=%q, want 'hello world'", got)
	}
	if r := s.dispatch(&Request{Op: OpWrite, Path: "f", Offset: 6, Data: []byte("there"), Mode: 0o640}); r.Status != OK {
		t.Fatalf("interior overwrite: status %d", r.Status)
	}
	if got := readFile(t, s, "f"); got != "hello there" {
		t.Fatalf("after interior write f=%q, want 'hello there'", got)
	}

	// Read with offset past EOF returns zero bytes, OK (ReadAt at/after end -> EOF, n=0).
	if r := s.dispatch(&Request{Op: OpRead, Path: "f", Offset: 1000, Size: 16}); r.Status != OK || len(r.Data) != 0 {
		t.Fatalf("read past EOF: status=%d len=%d, want OK/0", r.Status, len(r.Data))
	}

	// Mkdir + nested Create + Readdir (sorted, single entry).
	if r := s.dispatch(&Request{Op: OpMkdir, Path: "dir", Mode: 0o755}); r.Status != OK || r.Attr.Kind != "directory" {
		t.Fatalf("mkdir dir: status=%d attr=%+v", r.Status, r.Attr)
	}
	if r := s.dispatch(&Request{Op: OpCreate, Path: "dir/child", Mode: 0o644}); r.Status != OK {
		t.Fatalf("nested create: status %d", r.Status)
	}
	rd := s.dispatch(&Request{Op: OpReaddir, Path: "dir"})
	if rd.Status != OK || len(rd.Entries) != 1 || rd.Entries[0].Name != "child" {
		t.Fatalf("readdir dir: status=%d entries=%+v", rd.Status, rd.Entries)
	}

	// Symlink + Readlink.
	if r := s.dispatch(&Request{Op: OpSymlink, Path: "lnk", Target: "f"}); r.Status != OK || r.Attr.Kind != "symlink" {
		t.Fatalf("symlink: status=%d attr=%+v", r.Status, r.Attr)
	}
	if r := s.dispatch(&Request{Op: OpReadlink, Path: "lnk"}); r.Status != OK || r.Target != "f" {
		t.Fatalf("readlink: status=%d target=%q, want f", r.Status, r.Target)
	}

	// Truncate shrink, then grow, checking the reported size each time.
	if r := s.dispatch(&Request{Op: OpTruncate, Path: "f", Size: 5}); r.Status != OK {
		t.Fatalf("truncate shrink: status %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpGetattr, Path: "f"}); r.Attr.Size != 5 {
		t.Fatalf("size after shrink=%d, want 5", r.Attr.Size)
	}
	if r := s.dispatch(&Request{Op: OpTruncate, Path: "f", Size: 100}); r.Status != OK {
		t.Fatalf("truncate grow: status %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpGetattr, Path: "f"}); r.Attr.Size != 100 {
		t.Fatalf("size after grow=%d, want 100", r.Attr.Size)
	}

	// Setattr: chmod, then mtime, then chown — each reflected by getattr.
	if r := s.dispatch(&Request{Op: OpSetattr, Path: "f", SetMode: true, Mode: 0o600}); r.Status != OK || r.Attr.Mode != 0o600 {
		t.Fatalf("setattr chmod: status=%d attr=%+v", r.Status, r.Attr)
	}
	if r := s.dispatch(&Request{Op: OpSetattr, Path: "f", SetTime: true, MtimeMs: 1234567}); r.Status != OK || r.Attr.MtimeMs != 1234567 {
		t.Fatalf("setattr mtime: status=%d mtime=%d, want 1234567", r.Status, r.Attr.MtimeMs)
	}
	if r := s.dispatch(&Request{Op: OpSetattr, Path: "f", SetUID: true, UID: 1000, SetGID: true, GID: 2000}); r.Status != OK || r.Attr.Uid != 1000 || r.Attr.Gid != 2000 {
		t.Fatalf("setattr chown: status=%d uid=%d gid=%d", r.Status, r.Attr.Uid, r.Attr.Gid)
	}
	// chgrp only (uid preserved).
	if r := s.dispatch(&Request{Op: OpSetattr, Path: "f", SetGID: true, GID: 3000}); r.Status != OK || r.Attr.Uid != 1000 || r.Attr.Gid != 3000 {
		t.Fatalf("setattr chgrp only: status=%d uid=%d gid=%d, want uid preserved 1000 / gid 3000", r.Status, r.Attr.Uid, r.Attr.Gid)
	}

	// Stat helper (kind/mode primitives) for a directory and a file.
	if r := s.dispatch(&Request{Op: OpGetattr, Path: "dir"}); r.Status != OK || r.Attr.Kind != "directory" {
		t.Fatalf("getattr dir kind: status=%d attr=%+v", r.Status, r.Attr)
	}

	// Rename a file, then confirm old gone / new present; rename the directory too.
	if r := s.dispatch(&Request{Op: OpRename, Path: "f", NewPath: "f2"}); r.Status != OK {
		t.Fatalf("rename f->f2: status %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpGetattr, Path: "f"}); r.Status != ENOENT {
		t.Fatalf("old name after rename: status=%d, want ENOENT", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpGetattr, Path: "f2"}); r.Status != OK {
		t.Fatalf("new name after rename: status=%d, want OK", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpRename, Path: "dir", NewPath: "dir2"}); r.Status != OK {
		t.Fatalf("rename dir->dir2: status %d", r.Status)
	}
	// The renamed directory keeps its child.
	rd2 := s.dispatch(&Request{Op: OpReaddir, Path: "dir2"})
	if rd2.Status != OK || len(rd2.Entries) != 1 || rd2.Entries[0].Name != "child" {
		t.Fatalf("readdir dir2 after rename: status=%d entries=%+v", rd2.Status, rd2.Entries)
	}

	// Remove the file then the (now empty) child + directory.
	if r := s.dispatch(&Request{Op: OpRemove, Path: "f2"}); r.Status != OK {
		t.Fatalf("remove f2: status %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpRemove, Path: "dir2/child"}); r.Status != OK {
		t.Fatalf("remove dir2/child: status %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpRemove, Path: "dir2"}); r.Status != OK {
		t.Fatalf("remove dir2: status %d", r.Status)
	}
}

// TestDispatchErrorStatuses sweeps the errno mapping for the failure corners of each op:
// missing target, wrong type (EISDIR/ENOTDIR), non-empty dir removal (ENOTEMPTY), bad
// read size (EINVAL), missing parent, rename of a missing source, and readlink of a
// non-symlink.
func TestDispatchErrorStatuses(t *testing.T) {
	s, _ := newEnforceServer(t)
	// A directory and a regular file to provoke type errors.
	if r := s.dispatch(&Request{Op: OpMkdir, Path: "d", Mode: 0o755}); r.Status != OK {
		t.Fatalf("seed mkdir d: %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpCreate, Path: "d/child", Mode: 0o644}); r.Status != OK {
		t.Fatalf("seed d/child: %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpCreate, Path: "file", Mode: 0o644}); r.Status != OK {
		t.Fatalf("seed file: %d", r.Status)
	}

	// Getattr / Readdir / Readlink / Read / Remove / Truncate / Setattr on a MISSING path -> ENOENT.
	for _, tc := range []struct {
		name string
		req  Request
	}{
		{"getattr-missing", Request{Op: OpGetattr, Path: "nope"}},
		{"readdir-missing", Request{Op: OpReaddir, Path: "nope"}},
		{"readlink-missing", Request{Op: OpReadlink, Path: "nope"}},
		{"read-missing", Request{Op: OpRead, Path: "nope", Size: 8}},
		{"remove-missing", Request{Op: OpRemove, Path: "nope"}},
		{"truncate-missing", Request{Op: OpTruncate, Path: "nope", Size: 0}},
		{"setattr-missing", Request{Op: OpSetattr, Path: "nope", SetMode: true, Mode: 0o600}},
		{"rename-missing-src", Request{Op: OpRename, Path: "nope", NewPath: "dst"}},
	} {
		if r := s.dispatch(&tc.req); r.Status != ENOENT {
			t.Errorf("%s: status=%d, want ENOENT", tc.name, r.Status)
		}
	}

	// Readdir of a FILE -> ENOTDIR ("vcs: not a directory").
	if r := s.dispatch(&Request{Op: OpReaddir, Path: "file"}); r.Status != ENOTDIR {
		t.Errorf("readdir of a file: status=%d, want ENOTDIR", r.Status)
	}
	// Readlink of a non-symlink -> EIO (workfs returns "vcs: not a symlink", which maps to EIO).
	if r := s.dispatch(&Request{Op: OpReadlink, Path: "file"}); r.Status != EIO {
		t.Errorf("readlink of a regular file: status=%d, want EIO (not a symlink)", r.Status)
	}
	// Remove of a NON-EMPTY directory -> ENOTEMPTY ("directory not empty").
	if r := s.dispatch(&Request{Op: OpRemove, Path: "d"}); r.Status != ENOTEMPTY {
		t.Errorf("remove non-empty dir: status=%d, want ENOTEMPTY", r.Status)
	}
	// Read with a NEGATIVE size and an over-large size -> EINVAL (bounded before alloc).
	if r := s.dispatch(&Request{Op: OpRead, Path: "file", Offset: 0, Size: -1}); r.Status != EINVAL {
		t.Errorf("read negative size: status=%d, want EINVAL", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpRead, Path: "file", Offset: 0, Size: maxReadBytes + 1}); r.Status != EINVAL {
		t.Errorf("read over-large size: status=%d, want EINVAL", r.Status)
	}
	// Write/Create under a MISSING parent -> ENOENT (applyCreate's resolveParent is nil).
	if r := s.dispatch(&Request{Op: OpWrite, Path: "ghostdir/x", Offset: 0, Data: []byte("x"), Mode: 0o644}); r.Status != ENOENT {
		t.Errorf("write under missing parent: status=%d, want ENOENT", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpCreate, Path: "ghostdir/y", Mode: 0o644}); r.Status != ENOENT {
		t.Errorf("create under missing parent: status=%d, want ENOENT", r.Status)
	}
	// Rename a non-dir ONTO an existing directory -> EISDIR; rename a dir onto a non-dir -> ENOTDIR.
	if r := s.dispatch(&Request{Op: OpRename, Path: "file", NewPath: "d"}); r.Status != EISDIR {
		t.Errorf("rename file onto dir: status=%d, want EISDIR", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpRename, Path: "d", NewPath: "file"}); r.Status != ENOTDIR {
		t.Errorf("rename dir onto file: status=%d, want ENOTDIR", r.Status)
	}
	// An unknown op -> EINVAL (the dispatch default arm).
	if r := s.dispatch(&Request{Op: Op(250), Path: "file"}); r.Status != EINVAL {
		t.Errorf("unknown op: status=%d, want EINVAL", r.Status)
	}
	// OpFsync is a no-op success (durability is the checkpoint's job).
	if r := s.dispatch(&Request{Op: OpFsync, Path: "file"}); r.Status != OK {
		t.Errorf("fsync: status=%d, want OK", r.Status)
	}
}

// TestDispatchIdempotentRepeats: re-issuing the idempotent ops with identical arguments
// is a no-op success and does not corrupt state — create-then-create keeps the file
// (no clobber of content written between the two creates), mkdir-then-mkdir is fine, a
// repeated truncate-to-same-size and repeated chmod are stable. This mirrors the
// client's isIdempotent retry policy at the server boundary.
func TestDispatchIdempotentRepeats(t *testing.T) {
	s, _ := newEnforceServer(t)

	// create, write content, then a SECOND create with O_CREATE (no O_TRUNC) must NOT zero it.
	if r := s.dispatch(&Request{Op: OpCreate, Path: "f", Mode: 0o644}); r.Status != OK {
		t.Fatalf("create1: %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpWrite, Path: "f", Data: []byte("keep me"), Mode: 0o644}); r.Status != OK {
		t.Fatalf("write: %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpCreate, Path: "f", Mode: 0o644}); r.Status != OK {
		t.Fatalf("create2: %d", r.Status)
	}
	if got := readFile(t, s, "f"); got != "keep me" {
		t.Fatalf("second create clobbered content: f=%q, want 'keep me'", got)
	}

	// mkdir then mkdir (MkdirAll is idempotent).
	if r := s.dispatch(&Request{Op: OpMkdir, Path: "d/e", Mode: 0o755}); r.Status != OK {
		t.Fatalf("mkdir1: %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpMkdir, Path: "d/e", Mode: 0o755}); r.Status != OK {
		t.Fatalf("mkdir2 (idempotent): %d", r.Status)
	}

	// truncate to the same size twice; chmod to the same mode twice.
	if r := s.dispatch(&Request{Op: OpTruncate, Path: "f", Size: 4}); r.Status != OK {
		t.Fatalf("truncate1: %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpTruncate, Path: "f", Size: 4}); r.Status != OK {
		t.Fatalf("truncate2: %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpGetattr, Path: "f"}); r.Attr.Size != 4 {
		t.Fatalf("size after repeated truncate=%d, want 4", r.Attr.Size)
	}
	if r := s.dispatch(&Request{Op: OpSetattr, Path: "f", SetMode: true, Mode: 0o600}); r.Status != OK {
		t.Fatalf("chmod1: %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpSetattr, Path: "f", SetMode: true, Mode: 0o600}); r.Status != OK || r.Attr.Mode != 0o600 {
		t.Fatalf("chmod2: status=%d mode=%o", r.Status, r.Attr.Mode)
	}
}

// TestDispatchDeleteThenRecreate: remove a file then recreate it at the same path; the
// recreated file is empty (not the old content) and independently writable. Then the
// same for a directory path turned into a file (delete dir, create file at that name).
func TestDispatchDeleteThenRecreate(t *testing.T) {
	s, _ := newEnforceServer(t)

	if r := s.dispatch(&Request{Op: OpCreate, Path: "f", Mode: 0o644}); r.Status != OK {
		t.Fatalf("create: %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpWrite, Path: "f", Data: []byte("old"), Mode: 0o644}); r.Status != OK {
		t.Fatalf("write: %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpRemove, Path: "f"}); r.Status != OK {
		t.Fatalf("remove: %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpGetattr, Path: "f"}); r.Status != ENOENT {
		t.Fatalf("after remove getattr: status=%d, want ENOENT", r.Status)
	}
	// Recreate at the same path: empty, then writable with new content.
	if r := s.dispatch(&Request{Op: OpCreate, Path: "f", Mode: 0o644}); r.Status != OK || r.Attr.Size != 0 {
		t.Fatalf("recreate: status=%d size=%d, want OK/0", r.Status, r.Attr.Size)
	}
	if r := s.dispatch(&Request{Op: OpRead, Path: "f", Size: 16}); r.Status != OK || len(r.Data) != 0 {
		t.Fatalf("recreated file not empty: status=%d data=%q", r.Status, r.Data)
	}
	if r := s.dispatch(&Request{Op: OpWrite, Path: "f", Data: []byte("new"), Mode: 0o644}); r.Status != OK {
		t.Fatalf("write after recreate: %d", r.Status)
	}
	if got := readFile(t, s, "f"); got != "new" {
		t.Fatalf("recreated f=%q, want new", got)
	}

	// Turn a directory into a file at the same name: remove empty dir, then create a file.
	if r := s.dispatch(&Request{Op: OpMkdir, Path: "x", Mode: 0o755}); r.Status != OK {
		t.Fatalf("mkdir x: %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpRemove, Path: "x"}); r.Status != OK {
		t.Fatalf("remove dir x: %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpCreate, Path: "x", Mode: 0o644}); r.Status != OK || r.Attr.Kind != "file" {
		t.Fatalf("create file at former dir path: status=%d kind=%q, want OK/file", r.Status, func() string {
			if r.Attr != nil {
				return r.Attr.Kind
			}
			return "<nil>"
		}())
	}
}

// TestWriteSparseAndHoles: a write far past EOF leaves a hole; the gap reads back as
// zero bytes and the size reflects the highest written offset. Covers grow-by-sparse-
// write and that an interior region between two writes is zero-filled.
func TestWriteSparseAndHoles(t *testing.T) {
	s, _ := newEnforceServer(t)
	if r := s.dispatch(&Request{Op: OpCreate, Path: "sp", Mode: 0o644}); r.Status != OK {
		t.Fatalf("create: %d", r.Status)
	}
	// Write "AB" at offset 0 and "YZ" at offset 100 — a 98-byte hole between them.
	if r := s.dispatch(&Request{Op: OpWrite, Path: "sp", Offset: 0, Data: []byte("AB"), Mode: 0o644}); r.Status != OK {
		t.Fatalf("write @0: %d", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpWrite, Path: "sp", Offset: 100, Data: []byte("YZ"), Mode: 0o644}); r.Status != OK {
		t.Fatalf("write @100: %d", r.Status)
	}
	// Size is 102 (highest offset 100 + 2 bytes).
	if r := s.dispatch(&Request{Op: OpGetattr, Path: "sp"}); r.Attr.Size != 102 {
		t.Fatalf("sparse size=%d, want 102", r.Attr.Size)
	}
	// Read the whole thing: AB, then 98 zero bytes, then YZ.
	r := s.dispatch(&Request{Op: OpRead, Path: "sp", Offset: 0, Size: 102})
	if r.Status != OK || len(r.Data) != 102 {
		t.Fatalf("sparse read: status=%d len=%d, want OK/102", r.Status, len(r.Data))
	}
	if r.Data[0] != 'A' || r.Data[1] != 'B' || r.Data[100] != 'Y' || r.Data[101] != 'Z' {
		t.Fatalf("sparse bytes wrong at endpoints: %q", r.Data[:2])
	}
	for i := 2; i < 100; i++ {
		if r.Data[i] != 0 {
			t.Fatalf("hole not zero at byte %d: %d", i, r.Data[i])
		}
	}
	// Reading entirely within the hole returns zeros.
	hr := s.dispatch(&Request{Op: OpRead, Path: "sp", Offset: 10, Size: 8})
	if hr.Status != OK || len(hr.Data) != 8 {
		t.Fatalf("hole read: status=%d len=%d", hr.Status, len(hr.Data))
	}
	for i, b := range hr.Data {
		if b != 0 {
			t.Fatalf("hole read byte %d = %d, want 0", i, b)
		}
	}
}
