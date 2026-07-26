package fsproto

// Server-side tests for exact mount sessions (protocol version 3): session
// lifecycle, exact-once mutation identity (duplicates, conflicts, gaps, static
// rejects), promotion/restart replay, reclaim grace, lease expiry, wire
// bounds, and concurrent-slot exactness. Client-side transport behavior (lost
// replies, parking, flap) lives in exact_client_test.go.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"

	"github.com/trendup-ai/portablefs/vcs/internal/delegation"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
	"github.com/trendup-ai/portablefs/vcs/internal/workfs"
)

// newExactAuthority builds an exact-session authority (workfs-backed server)
// over its own WAL file and returns the pieces tests poke at.
func newExactAuthority(t *testing.T) (*Server, *workfs.FS, *wal.WAL, string) {
	t.Helper()
	walPath := filepath.Join(t.TempDir(), "authority.wal")
	return reopenAuthority(t, walPath)
}

// reopenAuthority opens (or re-opens after Close — a restart/promotion) the
// authority state at walPath with a FRESH delegation/lock table, exactly like
// a standby promoting from the replicated WAL.
func reopenAuthority(t *testing.T, walPath string) (*Server, *workfs.FS, *wal.WAL, string) {
	t.Helper()
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	fs, err := workfs.New(nil, nopBlobs{}, w)
	if err != nil {
		t.Fatalf("new workfs: %v", err)
	}
	return NewServer(fs, fs, delegation.New()), fs, w, walPath
}

// openExactSession establishes a session over the wire ops and returns the
// attached connection state.
func openExactSession(t *testing.T, s *Server, id string, gen uint64, owner, token string, slots uint32) *connSession {
	t.Helper()
	cs := &connSession{}
	r := s.dispatchConn(cs, &Request{
		Op: OpSessionOpen, SessionID: id, SessionGen: gen, SessionToken: token, SessionSlots: slots, Owner: owner,
	})
	if r == nil || r.Status != OK {
		t.Fatalf("session open %s/%d: %+v", id, gen, r)
	}
	return cs
}

func attachSession(t *testing.T, s *Server, id string, gen uint64, token string) (*connSession, *Response) {
	t.Helper()
	cs := &connSession{}
	r := s.dispatchConn(cs, &Request{Op: OpSessionAttach, SessionID: id, SessionGen: gen, SessionToken: token})
	return cs, r
}

// exactDo stamps an exact-once identity onto req and dispatches it.
func exactDo(s *Server, cs *connSession, req *Request, slot uint32, seq uint64) *Response {
	req.Env = &wal.Envelope{SessionID: cs.id, Generation: cs.gen, Slot: slot, SlotSeq: seq}
	if req.Owner == "" {
		req.Owner = cs.owner
	}
	return s.dispatchConn(cs, req)
}

func TestProbeNegotiation(t *testing.T) {
	s, _, _, _ := newExactAuthority(t)

	r := s.dispatch(&Request{Op: OpProtocolVersion, Size: int64(ProtocolVersion)})
	if r.Status != OK || r.ProtoVersion != ProtocolVersion {
		t.Fatalf("probe: version=%d status=%d, want %d/OK", r.ProtoVersion, r.Status, ProtocolVersion)
	}
	for _, feat := range []uint64{
		FeatExactSessions, FeatReclaimGrace, FeatHardLinks,
		FeatAtomicAppend, FeatAtomicXattrFlags,
	} {
		if r.Features&feat == 0 {
			t.Fatalf("probe features %b missing bit %b", r.Features, feat)
		}
	}
	if r.Features&FeatJournaledCoordination != 0 {
		t.Fatalf("WAL-backed store must not advertise journaled coordination: %b", r.Features)
	}
	if r.LeaseMs <= 0 {
		t.Fatalf("probe LeaseMs = %d, want > 0", r.LeaseMs)
	}

	// A legacy authority (plain billy fs, no session store) advertises the
	// version with no features; session ops are refused — the CLIENT then
	// keeps plain v1 behavior (graceful downgrade).
	legacy := NewServer(memfs.New(), nil, nil)
	if r := legacy.dispatch(&Request{Op: OpProtocolVersion, Size: int64(ProtocolVersion)}); r.Status != OK || r.Features != 0 {
		t.Fatalf("legacy probe: status=%d features=%b, want OK/0", r.Status, r.Features)
	}
	if r := legacy.dispatch(&Request{Op: OpSessionOpen, SessionID: "x", SessionGen: 1, SessionToken: "t", SessionSlots: 1}); r.Status != EPERM {
		t.Fatalf("legacy session open: status=%d, want EPERM", r.Status)
	}
}

func TestExactAppendDuplicateAndRestartReplayOffset(t *testing.T) {
	s1, _, w1, walPath := newExactAuthority(t)
	cs1 := openExactSession(t, s1, "sess-append", 1, "append-owner", "append-token", 2)
	if r := exactDo(s1, cs1, &Request{Op: OpCreate, Path: "log", Mode: 0o644}, 0, 1); r == nil || r.Status != OK {
		t.Fatalf("create: %+v", r)
	}
	firstReq := &Request{Op: OpWrite, Path: "log", Append: true, Data: []byte("A")}
	first := exactDo(s1, cs1, firstReq, 0, 2)
	if first == nil || first.Status != OK || first.Offset != 0 || first.Count != 1 {
		t.Fatalf("first append: %+v", first)
	}
	if err := w1.Close(); err != nil {
		t.Fatal(err)
	}

	s2, fs2, w2, _ := reopenAuthority(t, walPath)
	defer w2.Close()
	cs2, attached := attachSession(t, s2, "sess-append", 1, "append-token")
	if attached == nil || attached.Status != OK {
		t.Fatalf("attach after restart: %+v", attached)
	}
	dup := exactDo(s2, cs2, &Request{Op: OpWrite, Path: "log", Append: true, Data: []byte("A")}, 0, 2)
	if dup == nil || dup.Status != OK || !dup.Duplicate || dup.Offset != 0 || dup.Count != 1 {
		t.Fatalf("duplicate append after restart: %+v", dup)
	}
	second := exactDo(s2, cs2, &Request{Op: OpWrite, Path: "log", Append: true, Data: []byte("B")}, 0, 3)
	if second == nil || second.Status != OK || second.Offset != 1 || second.Count != 1 {
		t.Fatalf("second append: %+v", second)
	}
	f, err := fs2.Open("log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "AB" {
		t.Fatalf("append replay duplicated/lost bytes: %q", data)
	}
}

func TestSessionOpenBounds(t *testing.T) {
	s, _, _, _ := newExactAuthority(t)
	long := strings.Repeat("a", MaxSessionIDBytes+1)
	cases := []struct {
		name string
		req  Request
	}{
		{"empty id", Request{SessionID: "", SessionGen: 1, SessionToken: "t", SessionSlots: 1}},
		{"id too long", Request{SessionID: long, SessionGen: 1, SessionToken: "t", SessionSlots: 1}},
		{"id with slash", Request{SessionID: "a/b", SessionGen: 1, SessionToken: "t", SessionSlots: 1}},
		{"id with space", Request{SessionID: "a b", SessionGen: 1, SessionToken: "t", SessionSlots: 1}},
		{"empty token", Request{SessionID: "ok", SessionGen: 1, SessionToken: "", SessionSlots: 1}},
		{"token too long", Request{SessionID: "ok", SessionGen: 1, SessionToken: strings.Repeat("t", MaxTokenBytes+1), SessionSlots: 1}},
		{"owner too long", Request{SessionID: "ok", SessionGen: 1, SessionToken: "t", SessionSlots: 1, Owner: strings.Repeat("o", MaxOwnerBytes+1)}},
		{"zero generation", Request{SessionID: "ok", SessionGen: 0, SessionToken: "t", SessionSlots: 1}},
		{"zero slots", Request{SessionID: "ok", SessionGen: 1, SessionToken: "t", SessionSlots: 0}},
		{"slots max+1", Request{SessionID: "ok", SessionGen: 1, SessionToken: "t", SessionSlots: MaxSessionSlots + 1}},
	}
	for _, tc := range cases {
		tc.req.Op = OpSessionOpen
		if r := s.dispatch(&tc.req); r == nil || r.Status != EINVAL {
			t.Fatalf("%s: %+v, want EINVAL", tc.name, r)
		}
	}
	// Max-legal values are accepted.
	ok := Request{Op: OpSessionOpen, SessionID: strings.Repeat("a", MaxSessionIDBytes), SessionGen: 1,
		SessionToken: strings.Repeat("t", MaxTokenBytes), SessionSlots: MaxSessionSlots}
	if r := s.dispatch(&ok); r.Status != OK || r.SessionSlots != MaxSessionSlots || r.LeaseMs <= 0 {
		t.Fatalf("max-legal open: %+v", r)
	}
}

func TestSessionOpenLostResponseAndSupersede(t *testing.T) {
	s, fs, _, _ := newExactAuthority(t)
	cs := openExactSession(t, s, "sess-A", 1, "OA", "tokA", 4)

	// Lost-response replay: the IDENTICAL establish tuple succeeds again.
	if r := s.dispatch(&Request{Op: OpSessionOpen, SessionID: "sess-A", SessionGen: 1, SessionToken: "tokA", SessionSlots: 4, Owner: "OA"}); r.Status != OK {
		t.Fatalf("identical re-establish: status=%d, want OK", r.Status)
	}
	// Same generation, different token: a credential conflict, never granted.
	if r := s.dispatch(&Request{Op: OpSessionOpen, SessionID: "sess-A", SessionGen: 1, SessionToken: "tokEVIL", SessionSlots: 4, Owner: "OA"}); r.Status != EPERM {
		t.Fatalf("same-gen different token: status=%d, want EPERM", r.Status)
	}
	// Same generation, different slots: also a tuple conflict.
	if r := s.dispatch(&Request{Op: OpSessionOpen, SessionID: "sess-A", SessionGen: 1, SessionToken: "tokA", SessionSlots: 8, Owner: "OA"}); r.Status != EPERM {
		t.Fatalf("same-gen different slots: status=%d, want EPERM", r.Status)
	}

	// The gen-1 session still works.
	if r := exactDo(s, cs, &Request{Op: OpMkdir, Path: "d1", Mode: 0o755}, 0, 1); r.Status != OK {
		t.Fatalf("gen1 mkdir: status=%d", r.Status)
	}

	// A HIGHER generation supersedes: gen 1 is fenced, its mutations ESTALE.
	cs2 := openExactSession(t, s, "sess-A", 2, "OA", "tokA2", 4)
	if r := exactDo(s, cs, &Request{Op: OpMkdir, Path: "d2", Mode: 0o755}, 0, 2); r.Status != ESTALE {
		t.Fatalf("superseded gen1 mutation: status=%d, want ESTALE", r.Status)
	}
	// And a LOWER-generation re-establish is stale, not a fresh grant.
	if r := s.dispatch(&Request{Op: OpSessionOpen, SessionID: "sess-A", SessionGen: 1, SessionToken: "tokA", SessionSlots: 4, Owner: "OA"}); r.Status != ESTALE {
		t.Fatalf("stale-generation re-establish: status=%d, want ESTALE", r.Status)
	}
	// The new generation mutates fine.
	if r := exactDo(s, cs2, &Request{Op: OpMkdir, Path: "d3", Mode: 0o755}, 0, 1); r.Status != OK {
		t.Fatalf("gen2 mkdir: status=%d", r.Status)
	}
	if info, ok := fs.CurrentSession("sess-A"); !ok || info.Generation != 2 || info.Expired {
		t.Fatalf("current session = %+v, want live generation 2", info)
	}
}

func TestExactMutationDedupesAndReplaysOutcome(t *testing.T) {
	s, _, _, _ := newExactAuthority(t)
	cs := openExactSession(t, s, "sess-M", 1, "OM", "tokM", 4)

	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "f", Mode: 0o644}, 0, 1); r.Status != OK || r.Ino == 0 {
		t.Fatalf("create: %+v", r)
	}
	first := exactDo(s, cs, &Request{Op: OpWrite, Path: "f", Offset: 0, Data: []byte("hello")}, 0, 2)
	if first.Status != OK || first.Count != 5 || first.Version == 0 {
		t.Fatalf("write: %+v", first)
	}
	// Replay the identical identity: the STORED outcome, byte-identical fields.
	replay := exactDo(s, cs, &Request{Op: OpWrite, Path: "f", Offset: 0, Data: []byte("hello")}, 0, 2)
	if !replay.Duplicate || replay.Status != OK || replay.Count != first.Count ||
		replay.Version != first.Version || replay.Ino != first.Ino {
		t.Fatalf("write replay: first=%+v replay=%+v, want identical stored outcome", first, replay)
	}
	if got := readFile(t, s, "f"); got != "hello" {
		t.Fatalf("file = %q, want hello (replay applied exactly once)", got)
	}

	// The next sequence continues normally after replays.
	if r := exactDo(s, cs, &Request{Op: OpWrite, Path: "f", Offset: 5, Data: []byte("x")}, 0, 3); r.Status != OK {
		t.Fatalf("next write: %+v", r)
	}
	if got := readFile(t, s, "f"); got != "hellox" {
		t.Fatalf("file = %q, want hellox", got)
	}
}

func TestExactDeterministicErrorReplays(t *testing.T) {
	s, _, _, _ := newExactAuthority(t)
	cs := openExactSession(t, s, "sess-E", 1, "OE", "tokE", 4)

	if r := exactDo(s, cs, &Request{Op: OpMkdir, Path: "dir", Mode: 0o755}, 0, 1); r.Status != OK {
		t.Fatalf("mkdir: %+v", r)
	}
	// A deterministic apply rejection (rename with a missing source: ENOENT)
	// is recorded as this identity's outcome and replayed verbatim.
	if r := exactDo(s, cs, &Request{Op: OpRename, Path: "ghost-src", NewPath: "dst"}, 0, 2); r.Status != ENOENT {
		t.Fatalf("rename missing source: status=%d, want ENOENT", r.Status)
	}
	if r := exactDo(s, cs, &Request{Op: OpRename, Path: "ghost-src", NewPath: "dst"}, 0, 2); r.Status != ENOENT || !r.Duplicate {
		t.Fatalf("rename-ENOENT replay: %+v, want stored duplicate ENOENT", r)
	}
	// Remove of a missing path likewise.
	if r := exactDo(s, cs, &Request{Op: OpRemove, Path: "ghost"}, 0, 3); r.Status != ENOENT {
		t.Fatalf("remove missing: status=%d, want ENOENT", r.Status)
	}
	if r := exactDo(s, cs, &Request{Op: OpRemove, Path: "ghost"}, 0, 3); r.Status != ENOENT || !r.Duplicate {
		t.Fatalf("ENOENT replay: %+v, want stored duplicate ENOENT", r)
	}
	// Sequence progression continued through the rejections.
	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "dir/f", Mode: 0o644}, 0, 4); r.Status != OK {
		t.Fatalf("create after rejections: %+v", r)
	}
}

func TestExactConflictFencesSession(t *testing.T) {
	s, fs, _, _ := newExactAuthority(t)
	cs := openExactSession(t, s, "sess-C", 1, "OC", "tokC", 4)

	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "a", Mode: 0o644}, 0, 1); r.Status != OK {
		t.Fatalf("create: %+v", r)
	}
	// The SAME identity replayed with DIFFERENT content: proof of client-state
	// corruption. Fence — never execute, never return the stored outcome.
	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "DIFFERENT", Mode: 0o644}, 0, 1); r.Status != ESTALE {
		t.Fatalf("changed-hash replay: status=%d, want ESTALE", r.Status)
	}
	if _, err := fs.Lstat("DIFFERENT"); err == nil {
		t.Fatal("changed-hash replay must never execute")
	}
	// The fence is durable and generation-wide.
	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "b", Mode: 0o644}, 1, 1); r.Status != ESTALE {
		t.Fatalf("post-fence mutation: status=%d, want ESTALE", r.Status)
	}
	if info, ok := fs.CurrentSession("sess-C"); !ok || !info.Expired {
		t.Fatalf("session after conflict = %+v, want expired (fenced)", info)
	}
}

func TestExactGapFencesSession(t *testing.T) {
	s, fs, _, _ := newExactAuthority(t)

	// Skipping ahead (seq 2 with nothing recorded) is a gap: fence.
	cs := openExactSession(t, s, "sess-G1", 1, "OG", "tokG", 4)
	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "g1", Mode: 0o644}, 0, 2); r.Status != ESTALE {
		t.Fatalf("seq skip: status=%d, want ESTALE", r.Status)
	}
	if info, _ := fs.CurrentSession("sess-G1"); !info.Expired {
		t.Fatalf("session after gap = %+v, want fenced", info)
	}

	// Rewinding (seq 1 after 1,2 recorded) with different content is a
	// conflict fence.
	cs2 := openExactSession(t, s, "sess-G2", 1, "OG2", "tokG2", 4)
	if r := exactDo(s, cs2, &Request{Op: OpCreate, Path: "g2", Mode: 0o644}, 0, 1); r.Status != OK {
		t.Fatalf("seed seq1: %+v", r)
	}
	if r := exactDo(s, cs2, &Request{Op: OpWrite, Path: "g2", Data: []byte("z")}, 0, 2); r.Status != OK {
		t.Fatalf("seed seq2: %+v", r)
	}
	if r := exactDo(s, cs2, &Request{Op: OpCreate, Path: "g2-other", Mode: 0o644}, 0, 1); r.Status != ESTALE {
		t.Fatalf("seq rewind to a DIFFERENT request: status=%d, want ESTALE (conflict fence)", r.Status)
	}

	// A slot index past the session's bound is a state violation too.
	cs3 := openExactSession(t, s, "sess-G3", 1, "OG3", "tokG3", 4)
	if r := exactDo(s, cs3, &Request{Op: OpCreate, Path: "g3", Mode: 0o644}, 4, 1); r.Status != ESTALE {
		t.Fatalf("slot out of range: status=%d, want ESTALE", r.Status)
	}
}

func TestExactEnvelopeAuthentication(t *testing.T) {
	s, fs, _, _ := newExactAuthority(t)

	// Envelope without an attached session: refused, nothing recorded.
	bare := &connSession{}
	r := s.dispatchConn(bare, &Request{Op: OpCreate, Path: "x", Mode: 0o644,
		Env: &wal.Envelope{SessionID: "sess-X", Generation: 1, Slot: 0, SlotSeq: 1}})
	if r.Status != ESTALE {
		t.Fatalf("unattached envelope: status=%d, want ESTALE", r.Status)
	}

	csA := openExactSession(t, s, "sess-XA", 1, "OXA", "tokXA", 4)
	csB := openExactSession(t, s, "sess-XB", 1, "OXB", "tokXB", 4)

	// A connection authenticated as A cannot speak an envelope for B.
	r = s.dispatchConn(csA, &Request{Op: OpCreate, Path: "forged", Mode: 0o644,
		Env: &wal.Envelope{SessionID: "sess-XB", Generation: 1, Slot: 0, SlotSeq: 1}})
	if r.Status != ESTALE {
		t.Fatalf("cross-session envelope: status=%d, want ESTALE", r.Status)
	}
	// ...and that attempt did not damage B: B's own seq 1 works.
	if r := exactDo(s, csB, &Request{Op: OpCreate, Path: "b-own", Mode: 0o644}, 0, 1); r.Status != OK {
		t.Fatalf("B after forged attempt: %+v", r)
	}

	// SlotSeq 0 is never valid.
	r = s.dispatchConn(csA, &Request{Op: OpCreate, Path: "z", Mode: 0o644,
		Env: &wal.Envelope{SessionID: "sess-XA", Generation: 1, Slot: 0, SlotSeq: 0}})
	if r.Status != ESTALE {
		t.Fatalf("seq 0: status=%d, want ESTALE", r.Status)
	}

	// An envelope on a NON-mutating op is malformed and consumes NO sequence.
	r = s.dispatchConn(csA, &Request{Op: OpGetattr, Path: "x",
		Env: &wal.Envelope{SessionID: "sess-XA", Generation: 1, Slot: 0, SlotSeq: 1}})
	if r.Status != EINVAL {
		t.Fatalf("envelope on read: status=%d, want EINVAL", r.Status)
	}
	r = s.dispatchConn(csA, &Request{Op: OpFlushBatch, SessionID: "wb", Owner: "OXA",
		Env: &wal.Envelope{SessionID: "sess-XA", Generation: 1, Slot: 0, SlotSeq: 1}})
	if r.Status != EINVAL {
		t.Fatalf("envelope on flush: status=%d, want EINVAL", r.Status)
	}

	// A client-supplied (forged) request hash is IGNORED: the server computes
	// the canonical hash itself, so seq 1 with garbage hash simply executes.
	r = s.dispatchConn(csA, &Request{Op: OpCreate, Path: "honest", Mode: 0o644,
		Env: &wal.Envelope{SessionID: "sess-XA", Generation: 1, Slot: 0, SlotSeq: 1, ReqHash: []byte("garbage-hash")}})
	if r.Status != OK {
		t.Fatalf("forged-hash create: %+v, want applied (server-computed hash)", r)
	}
	if _, err := fs.Lstat("honest"); err != nil {
		t.Fatalf("honest not created: %v", err)
	}
	// And a replay with a DIFFERENT forged hash still dedupes (server hash rules).
	r = s.dispatchConn(csA, &Request{Op: OpCreate, Path: "honest", Mode: 0o644,
		Env: &wal.Envelope{SessionID: "sess-XA", Generation: 1, Slot: 0, SlotSeq: 1, ReqHash: []byte("other-garbage")}})
	if !r.Duplicate || r.Status != OK {
		t.Fatalf("forged-hash replay: %+v, want stored duplicate", r)
	}
}

func TestExactStaticRejectAdvancesSlot(t *testing.T) {
	s, fs, _, _ := newExactAuthority(t)
	cs := openExactSession(t, s, "sess-S", 1, "OS", "tokS", 4)
	longPath := strings.Repeat("p", MaxPathBytes+1)

	// A statically malformed request gets a DEFINITE, durably recorded reject.
	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: longPath, Mode: 0o644}, 0, 1); r.Status != ENAMETOOLONG {
		t.Fatalf("long path: status=%d, want ENAMETOOLONG", r.Status)
	}
	// Its replay returns the stored outcome.
	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: longPath, Mode: 0o644}, 0, 1); r.Status != ENAMETOOLONG || !r.Duplicate {
		t.Fatalf("static reject replay: %+v, want stored ENAMETOOLONG", r)
	}
	// The slot sequence ADVANCED through the reject: seq 2 executes.
	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "fine", Mode: 0o644}, 0, 2); r.Status != OK {
		t.Fatalf("create after reject: %+v", r)
	}

	// Reusing a rejected identity for a DIFFERENT malformed request (different
	// errno ⇒ different fingerprint) is a conflict: fence.
	if r := exactDo(s, cs, &Request{Op: OpReap, OrphanIno: 0}, 0, 3); r.Status != EINVAL {
		t.Fatalf("reap ino 0: status=%d, want EINVAL", r.Status)
	}
	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: longPath, Mode: 0o644}, 0, 3); r.Status != ESTALE {
		t.Fatalf("different malformed on used identity: status=%d, want ESTALE", r.Status)
	}
	if info, _ := fs.CurrentSession("sess-S"); !info.Expired {
		t.Fatalf("session = %+v, want fenced after reject-identity conflict", info)
	}
}

// TestExactStaticRejectSurvivesRestart proves rejects ride the replicated WAL:
// after a promotion the SAME identity still answers the recorded errno.
func TestExactStaticRejectSurvivesRestart(t *testing.T) {
	s1, _, w1, walPath := newExactAuthority(t)
	openExactSession(t, s1, "sess-SR", 1, "OSR", "tokSR", 4)
	cs1, r := attachSession(t, s1, "sess-SR", 1, "tokSR")
	if r.Status != OK {
		t.Fatalf("attach: %+v", r)
	}
	longPath := strings.Repeat("p", MaxPathBytes+1)
	if r := exactDo(s1, cs1, &Request{Op: OpCreate, Path: longPath, Mode: 0o644}, 0, 1); r.Status != ENAMETOOLONG {
		t.Fatalf("reject: status=%d", r.Status)
	}
	if err := w1.Close(); err != nil {
		t.Fatalf("close wal: %v", err)
	}

	s2, _, _, _ := reopenAuthority(t, walPath)
	cs2, r := attachSession(t, s2, "sess-SR", 1, "tokSR")
	if r.Status != OK {
		t.Fatalf("attach after restart: %+v", r)
	}
	if r := exactDo(s2, cs2, &Request{Op: OpCreate, Path: longPath, Mode: 0o644}, 0, 1); r.Status != ENAMETOOLONG || !r.Duplicate {
		t.Fatalf("reject replay after restart: %+v, want stored ENAMETOOLONG", r)
	}
	if r := exactDo(s2, cs2, &Request{Op: OpCreate, Path: "post", Mode: 0o644}, 0, 2); r.Status != OK {
		t.Fatalf("seq 2 after restart: %+v", r)
	}
}

func TestExactWireBounds(t *testing.T) {
	s, _, _, _ := newExactAuthority(t)
	cs := openExactSession(t, s, "sess-B", 1, "OB", "tokB", 8)
	seq := uint64(0)
	next := func() uint64 { seq++; return seq }

	reject := func(name string, req *Request, want int32) {
		t.Helper()
		if r := exactDo(s, cs, req, 0, next()); r.Status != want {
			t.Fatalf("%s: status=%d, want %d", name, r.Status, want)
		}
	}
	reject("write beyond MaxWriteBytes", &Request{Op: OpWrite, Path: "f", Data: make([]byte, MaxWriteBytes+1)}, EINVAL)
	reject("negative write offset", &Request{Op: OpWrite, Path: "f", Offset: -1, Data: []byte("x")}, EINVAL)
	reject("negative truncate", &Request{Op: OpTruncate, Path: "f", Size: -2}, EINVAL)
	reject("multi-group setattr", &Request{Op: OpSetattr, Path: "f", SetMode: true, Mode: 0o600, SetTime: true, MtimeMs: 1}, EINVAL)
	reject("zero-group setattr", &Request{Op: OpSetattr, Path: "f"}, EINVAL)
	reject("newpath too long", &Request{Op: OpRename, Path: "f", NewPath: strings.Repeat("q", MaxPathBytes+1)}, ENAMETOOLONG)
	reject("target too long", &Request{Op: OpSymlink, Path: "l", Target: strings.Repeat("q", MaxPathBytes+1)}, ENAMETOOLONG)

	// All those definite rejects advanced the slot; a valid op still lands.
	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "valid", Mode: 0o644}, 0, next()); r.Status != OK {
		t.Fatalf("valid create after bound rejects: %+v", r)
	}

	// Read-size and flush-shape bounds (non-envelope admission).
	if r := s.dispatchConn(cs, &Request{Op: OpRead, Path: "valid", Size: maxReadBytes + 1}); r.Status != EINVAL {
		t.Fatalf("read size bound: status=%d, want EINVAL", r.Status)
	}
	if r := s.dispatchConn(cs, &Request{Op: OpFlushBatch, SessionID: strings.Repeat("s", MaxSessionIDBytes+1), Owner: "OB"}); r.Status != EINVAL {
		t.Fatalf("flush session id bound: status=%d, want EINVAL", r.Status)
	}
	if r := s.dispatchConn(cs, &Request{Op: OpFlushBatch, SessionID: "wb", Owner: "OB",
		Records: make([]wal.Record, MaxBatchRecords+1)}); r.Status != EINVAL {
		t.Fatalf("flush batch bound: status=%d, want EINVAL", r.Status)
	}
}

func TestRequireExactSessionsRefusesEnvelopeless(t *testing.T) {
	s, _, _, _ := newExactAuthority(t)

	// Default: permissive — envelope-less v1 mutations stay admitted.
	if r := s.dispatch(&Request{Op: OpMkdir, Path: "d0", Mode: 0o755}); r.Status != OK {
		t.Fatalf("permissive mkdir: status=%d, want OK", r.Status)
	}

	// Fail-closed posture (VCS_REQUIRE_EXACT_SESSIONS=1): refused outright...
	s.SetRequireExactSessions(true)
	if r := s.dispatch(&Request{Op: OpMkdir, Path: "d", Mode: 0o755}); r.Status != EPERM {
		t.Fatalf("legacy mkdir under require: status=%d, want EPERM", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpWrite, Path: "f", Data: []byte("x")}); r.Status != EPERM {
		t.Fatalf("legacy write under require: status=%d, want EPERM", r.Status)
	}
	// ...while reads and coordination ops flow normally.
	if r := s.dispatch(&Request{Op: OpGetattr, Path: "nope"}); r.Status != ENOENT {
		t.Fatalf("read admission: status=%d, want ENOENT (served)", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpCheckout, Path: "w", Owner: "O"}); r.Status != OK {
		t.Fatalf("checkout admission: status=%d", r.Status)
	}

	// Toggling back restores v1 admission.
	s.SetRequireExactSessions(false)
	if r := s.dispatch(&Request{Op: OpRemove, Path: "d0"}); r.Status != OK {
		t.Fatalf("permissive remove: status=%d, want OK", r.Status)
	}
}

func TestFlushBatchSessionAuthenticated(t *testing.T) {
	s, fs, _, _ := newExactAuthority(t)
	s.SetRequireExactSessions(true)

	// Fail-closed: a flush on an UNATTACHED connection is fenced.
	batch := []wal.Record{{Seq: 0, Op: wal.OpCreate, Path: "w/a", Mode: 0o644}}
	if r := s.dispatch(&Request{Op: OpFlushBatch, SessionID: "wb1", Epoch: 1, Owner: "M", Records: batch}); r.Status != ESTALE {
		t.Fatalf("unattached flush: status=%d, want ESTALE", r.Status)
	}

	cs := openExactSession(t, s, "sess-F", 1, "M", "tokF", 4)
	if r := exactDo(s, cs, &Request{Op: OpMkdir, Path: "w", Mode: 0o755}, 0, 1); r.Status != OK {
		t.Fatalf("mkdir: %+v", r)
	}
	if r := s.dispatchConn(cs, &Request{Op: OpFlushBatch, SessionID: "wb1", Epoch: 1, Owner: "M", Records: batch}); r.Status != OK || r.AppliedThrough != 0 {
		t.Fatalf("attached flush: %+v, want OK/0", r)
	}
	// The watermark is REPLICATED CONTROL STATE, not a hidden file.
	if epoch, through, ok := fs.FlushWatermark("wb1"); !ok || epoch != 1 || through != 1 {
		t.Fatalf("control watermark = (%d,%d,%v), want (1,1,true)", epoch, through, ok)
	}
	if r := s.dispatchConn(cs, &Request{Op: OpGetattr, Path: watermarkPath("wb1")}); r.Status != ENOENT {
		t.Fatalf("hidden watermark file exists: status=%d", r.Status)
	}

	// A voluntarily expired (cleanly unmounted) session can NEVER flush again:
	// old dirty bytes from a superseded mount are fenced, not applied.
	if r := s.dispatchConn(cs, &Request{Op: OpSessionExpire, SessionID: "sess-F", SessionGen: 1}); r.Status != OK {
		t.Fatalf("session expire: %+v", r)
	}
	late := []wal.Record{{Seq: 1, Op: wal.OpWrite, Path: "w/a", Data: []byte("zombie")}}
	if r := s.dispatchConn(cs, &Request{Op: OpFlushBatch, SessionID: "wb1", Epoch: 1, Owner: "M", Records: late}); r.Status != ESTALE {
		t.Fatalf("flush after expire: status=%d, want ESTALE", r.Status)
	}
	if got := readFile(t, s, "w/a"); got != "" {
		t.Fatalf("zombie flush applied: %q", got)
	}
}

func TestExactSessionSurvivesPromotion(t *testing.T) {
	s1, _, w1, walPath := newExactAuthority(t)
	openExactSession(t, s1, "sess-P", 1, "OP", "tokP", 4)
	cs1, r := attachSession(t, s1, "sess-P", 1, "tokP")
	if r.Status != OK {
		t.Fatalf("attach: %+v", r)
	}
	if r := exactDo(s1, cs1, &Request{Op: OpCreate, Path: "f", Mode: 0o644}, 0, 1); r.Status != OK {
		t.Fatalf("create: %+v", r)
	}
	if r := exactDo(s1, cs1, &Request{Op: OpWrite, Path: "f", Data: []byte("hello")}, 0, 2); r.Status != OK {
		t.Fatalf("write: %+v", r)
	}
	wr := exactDo(s1, cs1, &Request{Op: OpWrite, Path: "f", Offset: 5, Data: []byte("x")}, 0, 3)
	if wr.Status != OK || wr.Count != 1 {
		t.Fatalf("suffix write: %+v", wr)
	}

	// Crash + promote: a NEW server over the SAME replicated WAL.
	if err := w1.Close(); err != nil {
		t.Fatalf("close wal: %v", err)
	}
	s2, _, _, _ := reopenAuthority(t, walPath)

	// The token-proven prior session attaches (its establish rode the WAL)...
	cs2, r := attachSession(t, s2, "sess-P", 1, "tokP")
	if r.Status != OK {
		t.Fatalf("attach after promotion: %+v", r)
	}
	// ...a wrong token does not (malicious claim of a live session)...
	if _, r := attachSession(t, s2, "sess-P", 1, "tokEVIL"); r.Status != ESTALE {
		t.Fatalf("malicious attach: status=%d, want ESTALE", r.Status)
	}
	// ...and a session the WAL never saw is unknown.
	if _, r := attachSession(t, s2, "sess-NEVER", 1, "tok"); r.Status != ESTALE {
		t.Fatalf("unknown attach: status=%d, want ESTALE", r.Status)
	}

	// The lost-reply replay of the suffix write answers the STORED outcome —
	// across the failover — and does not re-execute.
	wr2 := exactDo(s2, cs2, &Request{Op: OpWrite, Path: "f", Offset: 5, Data: []byte("x")}, 0, 3)
	if !wr2.Duplicate || wr2.Status != OK || wr2.Count != 1 {
		t.Fatalf("write replay after promotion: %+v, want duplicate count 1", wr2)
	}
	if got := readFile(t, s2, "f"); got != "hellox" {
		t.Fatalf("promoted file = %q, want hellox", got)
	}
	// New sequences continue (the reclaimer passes the grace gate).
	if r := exactDo(s2, cs2, &Request{Op: OpWrite, Path: "f", Offset: 6, Data: []byte("y")}, 0, 4); r.Status != OK {
		t.Fatalf("fresh write after promotion: %+v", r)
	}
	if got := readFile(t, s2, "f"); got != "helloxy" {
		t.Fatalf("promoted file after fresh write = %q, want helloxy", got)
	}
}

func TestReclaimGraceBlocksConflictingAcquisition(t *testing.T) {
	s1, _, w1, walPath := newExactAuthority(t)
	openExactSession(t, s1, "sess-R", 1, "OA", "tokR", 4)
	cs1, r := attachSession(t, s1, "sess-R", 1, "tokR")
	if r.Status != OK {
		t.Fatalf("attach: %+v", r)
	}
	if r := exactDo(s1, cs1, &Request{Op: OpCreate, Path: "proj-db", Mode: 0o644}, 0, 1); r.Status != OK {
		t.Fatalf("create: %+v", r)
	}
	// A's volatile coordination state on the OLD server: checkout + lock.
	if r := s1.dispatchConn(cs1, &Request{Op: OpCheckout, Path: "proj", Owner: "OA"}); r.Status != OK {
		t.Fatalf("A checkout: %+v", r)
	}
	if r := s1.dispatchConn(cs1, &Request{Op: OpLock, Path: "proj-db", Owner: "OA", LkID: 1, LkMode: LkSetlk, LkStart: 0, LkEnd: 10, LkWrite: true}); r.Status != OK {
		t.Fatalf("A lock: %+v", r)
	}

	if err := w1.Close(); err != nil {
		t.Fatalf("close wal: %v", err)
	}
	s2, _, _, _ := reopenAuthority(t, walPath)
	if !s2.exact.inGrace(time.Now()) {
		t.Fatal("promoted authority with a live durable session must start in reclaim grace")
	}

	// A NEW session (B) may establish during grace...
	csB := openExactSession(t, s2, "sess-RB", 1, "OB", "tokRB", 4)
	// ...but may not acquire or mutate ANYTHING that could conflict with A's
	// not-yet-reasserted state.
	if r := s2.dispatchConn(csB, &Request{Op: OpCheckout, Path: "proj", Owner: "OB"}); r.Status != EAGAIN {
		t.Fatalf("B checkout during grace: status=%d, want EAGAIN", r.Status)
	}
	if r := s2.dispatchConn(csB, &Request{Op: OpLock, Path: "proj-db", Owner: "OB", LkID: 9, LkMode: LkSetlk, LkStart: 0, LkEnd: 10, LkWrite: true}); r.Status != EAGAIN {
		t.Fatalf("B lock during grace: status=%d, want EAGAIN", r.Status)
	}
	if r := exactDo(s2, csB, &Request{Op: OpCreate, Path: "b-file", Mode: 0o644}, 0, 1); r.Status != EAGAIN {
		t.Fatalf("B mutation during grace: status=%d, want EAGAIN", r.Status)
	}
	// The gate rejection CONSUMED B's identity durably: a replay of the same
	// request dedupes to the stored EAGAIN instead of re-evaluating the gate.
	if r := exactDo(s2, csB, &Request{Op: OpCreate, Path: "b-file", Mode: 0o644}, 0, 1); r.Status != EAGAIN || !r.Duplicate {
		t.Fatalf("gate-reject replay: %+v, want stored duplicate EAGAIN", r)
	}
	if r := s2.dispatchConn(csB, &Request{Op: OpFlushBatch, SessionID: "wbB", Epoch: 1, Owner: "OB",
		Records: []wal.Record{{Seq: 0, Op: wal.OpCreate, Path: "b2", Mode: 0o644}}}); r.Status != EAGAIN {
		t.Fatalf("B flush during grace: status=%d, want EAGAIN", r.Status)
	}
	// Reads, lock queries, and releases flow freely during grace.
	if r := s2.dispatchConn(csB, &Request{Op: OpGetattr, Path: "proj-db"}); r.Status != OK {
		t.Fatalf("B read during grace: status=%d", r.Status)
	}
	if r := s2.dispatchConn(csB, &Request{Op: OpLock, Path: "proj-db", Owner: "OB", LkID: 9, LkMode: LkGetlk, LkStart: 0, LkEnd: 10, LkWrite: true}); r.Status != OK {
		t.Fatalf("B getlk during grace: status=%d", r.Status)
	}
	// B claiming "reclaim done" for itself does NOT lift A's grace.
	s2.dispatchConn(csB, &Request{Op: OpReclaimDone, SessionID: "sess-RB"})
	if r := s2.dispatchConn(csB, &Request{Op: OpCheckout, Path: "proj", Owner: "OB"}); r.Status != EAGAIN {
		t.Fatalf("B checkout after B's own reclaim-done: status=%d, want EAGAIN (A still owed)", r.Status)
	}

	// A resumes with its durable token: told its remaining reclaim budget.
	csA := &connSession{}
	rr := s2.dispatchConn(csA, &Request{Op: OpSessionResume, SessionID: "sess-R", SessionGen: 1, SessionToken: "tokR"})
	if rr.Status != OK || rr.ReclaimMs <= 0 {
		t.Fatalf("A resume: %+v, want OK with ReclaimMs > 0", rr)
	}
	// A re-asserts its coordination state (reclaimers pass the gate).
	if r := s2.dispatchConn(csA, &Request{Op: OpCheckout, Path: "proj", Owner: "OA"}); r.Status != OK {
		t.Fatalf("A re-checkout: %+v", r)
	}
	if r := s2.dispatchConn(csA, &Request{Op: OpLock, Path: "proj-db", Owner: "OA", LkID: 1, LkMode: LkSetlk, LkStart: 0, LkEnd: 10, LkWrite: true}); r.Status != OK {
		t.Fatalf("A re-lock: %+v", r)
	}
	s2.dispatchConn(csA, &Request{Op: OpReclaimDone, SessionID: "sess-R"})

	// Grace lifts EARLY (every prior session reclaimed): B proceeds, subject to
	// the normal conflict rules — A's re-asserted lock now correctly conflicts.
	if r := s2.dispatchConn(csB, &Request{Op: OpLock, Path: "proj-db", Owner: "OB", LkID: 9, LkMode: LkSetlk, LkStart: 20, LkEnd: 30, LkWrite: true}); r.Status != OK {
		t.Fatalf("B non-overlapping lock after reclaim: status=%d, want OK", r.Status)
	}
	if r := s2.dispatchConn(csB, &Request{Op: OpLock, Path: "proj-db", Owner: "OB", LkID: 9, LkMode: LkGetlk, LkStart: 0, LkEnd: 10, LkWrite: true}); !r.LkConflict {
		t.Fatalf("A's reclaimed lock not visible: %+v", r)
	}
	if r := exactDo(s2, csB, &Request{Op: OpCreate, Path: "b-file", Mode: 0o644}, 0, 2); r.Status != OK {
		t.Fatalf("B mutation after reclaim: %+v", r)
	}
}

func TestReclaimGraceTimeoutFencesLateClient(t *testing.T) {
	oldGrace := workfs.SessionReclaimGrace
	workfs.SessionReclaimGrace = 250 * time.Millisecond
	defer func() { workfs.SessionReclaimGrace = oldGrace }()

	s1, _, w1, walPath := newExactAuthority(t)
	openExactSession(t, s1, "sess-T", 1, "OA", "tokT", 4)
	cs1, r := attachSession(t, s1, "sess-T", 1, "tokT")
	if r.Status != OK {
		t.Fatalf("attach: %+v", r)
	}
	if r := exactDo(s1, cs1, &Request{Op: OpCreate, Path: "shared", Mode: 0o644}, 0, 1); r.Status != OK {
		t.Fatalf("create: %+v", r)
	}
	if r := s1.dispatchConn(cs1, &Request{Op: OpLock, Path: "shared", Owner: "OA", LkID: 1, LkMode: LkSetlk, LkStart: 0, LkEnd: 10, LkWrite: true}); r.Status != OK {
		t.Fatalf("A lock: %+v", r)
	}
	if err := w1.Close(); err != nil {
		t.Fatalf("close wal: %v", err)
	}

	s2, _, _, _ := reopenAuthority(t, walPath)
	csB := openExactSession(t, s2, "sess-TB", 1, "OB", "tokTB", 4)

	// During grace B is held off...
	if r := s2.dispatchConn(csB, &Request{Op: OpLock, Path: "shared", Owner: "OB", LkID: 9, LkMode: LkSetlk, LkStart: 0, LkEnd: 10, LkWrite: true}); r.Status != EAGAIN {
		t.Fatalf("B lock during grace: status=%d, want EAGAIN", r.Status)
	}
	// ...but A never reclaims, so the BOUNDED window elapses and B proceeds.
	deadline := time.Now().Add(3 * time.Second)
	for {
		r := s2.dispatchConn(csB, &Request{Op: OpLock, Path: "shared", Owner: "OB", LkID: 9, LkMode: LkSetlk, LkStart: 0, LkEnd: 10, LkWrite: true})
		if r.Status == OK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("grace never elapsed: status=%d", r.Status)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A shows up LATE: its lock was never re-asserted, and the range is gone.
	csA := &connSession{}
	if r := s2.dispatchConn(csA, &Request{Op: OpSessionResume, SessionID: "sess-T", SessionGen: 1, SessionToken: "tokT"}); r.Status != OK || r.ReclaimMs != 0 {
		t.Fatalf("late resume: %+v, want OK with no reclaim window", r)
	}
	if r := s2.dispatchConn(csA, &Request{Op: OpLock, Path: "shared", Owner: "OA", LkID: 1, LkMode: LkSetlk, LkStart: 0, LkEnd: 10, LkWrite: true}); r.Status != EAGAIN {
		t.Fatalf("late re-assert of a lost lock: status=%d, want EAGAIN (B owns it now)", r.Status)
	}
}

func TestLeaseExpiryFencesAndReleasesCoordination(t *testing.T) {
	// Registered before the server cleanups (so it runs AFTER them): restoring
	// the package variable while the sweeper still reads it is a data race.
	oldTTL := workfs.SessionLeaseTTL
	t.Cleanup(func() { workfs.SessionLeaseTTL = oldTTL })
	workfs.SessionLeaseTTL = 400 * time.Millisecond

	s, fs, _, _ := newExactAuthority(t)
	// The lease sweeper runs under Serve.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		select {
		case <-s.exact.sweeperDone:
		case <-time.After(10 * time.Second):
			t.Error("lease sweeper did not stop")
		}
	})
	go func() { _ = s.Serve(ctx, ln) }()

	cs := openExactSession(t, s, "sess-L", 1, "OL", "tokL", 4)
	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "res", Mode: 0o644}, 0, 1); r.Status != OK {
		t.Fatalf("create: %+v", r)
	}
	if r := s.dispatchConn(cs, &Request{Op: OpCheckout, Path: "proj", Owner: "OL"}); r.Status != OK {
		t.Fatalf("checkout: %+v", r)
	}
	if r := s.dispatchConn(cs, &Request{Op: OpLock, Path: "res", Owner: "OL", LkID: 1, LkMode: LkSetlk, LkStart: 0, LkEnd: 10, LkWrite: true}); r.Status != OK {
		t.Fatalf("lock: %+v", r)
	}

	// No renewals arrive; the sweeper must durably fence the session and
	// release its delegations and advisory locks.
	deadline := time.Now().Add(5 * time.Second)
	for {
		info, ok := fs.CurrentSession("sess-L")
		holder, _ := s.deleg.HeldBy("proj")
		if ok && info.Expired && holder == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("lease never swept: info=%+v holder=%q", info, holder)
		}
		time.Sleep(25 * time.Millisecond)
	}

	// The expired session's next mutation is fenced...
	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "late", Mode: 0o644}, 0, 2); r.Status != ESTALE {
		t.Fatalf("mutation after lease expiry: status=%d, want ESTALE", r.Status)
	}
	// ...and its locks are actually free for others.
	csB := openExactSession(t, s, "sess-LB", 1, "OLB", "tokLB", 4)
	if r := s.dispatchConn(csB, &Request{Op: OpLock, Path: "res", Owner: "OLB", LkID: 9, LkMode: LkSetlk, LkStart: 0, LkEnd: 10, LkWrite: true}); r.Status != OK {
		t.Fatalf("lock after expiry release: status=%d, want OK", r.Status)
	}
}

// TestConcurrentSlotsExactOnce hammers one session's slots from many
// goroutines, replaying every request CONCURRENTLY with its original; the
// final file length proves every identity applied exactly once. Run with
// -race.
func TestConcurrentSlotsExactOnce(t *testing.T) {
	s, _, _, _ := newExactAuthority(t)
	const slots, seqsPerSlot = 8, 20
	cs := openExactSession(t, s, "sess-CC", 1, "OCC", "tokCC", slots)

	var wg sync.WaitGroup
	errCh := make(chan error, slots*seqsPerSlot*2)
	for slot := uint32(0); slot < slots; slot++ {
		wg.Add(1)
		go func(slot uint32) {
			defer wg.Done()
			for seq := uint64(1); seq <= seqsPerSlot; seq++ {
				// Each identity creates a DISTINCT path: exactly-once shows
				// up as "created once, duplicate replays dedupe".
				path := fmt.Sprintf("slot-%d-seq-%d", slot, seq)
				mk := func() *Request {
					return &Request{Op: OpCreate, Path: path, Mode: 0o644, Owner: "OCC",
						Env: &wal.Envelope{SessionID: cs.id, Generation: cs.gen, Slot: slot, SlotSeq: seq}}
				}
				// Fire the original and a duplicate CONCURRENTLY: the slot
				// serialization must let exactly one execute.
				var inner sync.WaitGroup
				resps := make([]*Response, 2)
				for i := 0; i < 2; i++ {
					inner.Add(1)
					go func(i int) {
						defer inner.Done()
						resps[i] = s.dispatchConn(cs, mk())
					}(i)
				}
				inner.Wait()
				for i, r := range resps {
					if r == nil || r.Status != OK {
						errCh <- fmt.Errorf("slot %d seq %d resp %d: %+v", slot, seq, i, r)
						return
					}
				}
				if resps[0].Ino != resps[1].Ino {
					errCh <- fmt.Errorf("slot %d seq %d: original/duplicate inos differ (%d vs %d)",
						slot, seq, resps[0].Ino, resps[1].Ino)
					return
				}
				if !resps[0].Duplicate && !resps[1].Duplicate {
					errCh <- fmt.Errorf("slot %d seq %d: neither response marked duplicate", slot, seq)
					return
				}
			}
		}(slot)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	// Every identity created exactly one file.
	rd := s.dispatch(&Request{Op: OpReaddir, Path: ""})
	if rd.Status != OK || len(rd.Entries) != slots*seqsPerSlot {
		t.Fatalf("root entries = %d (status %d), want %d (exactly-once violated)", len(rd.Entries), rd.Status, slots*seqsPerSlot)
	}
}

func TestCanonicalHashSensitivity(t *testing.T) {
	base := wal.Record{Op: wal.OpWrite, Path: "a/b", Offset: 4, Data: []byte("hello")}
	variants := []wal.Record{
		{Op: wal.OpTruncate, Path: "a/b", Offset: 4, Data: []byte("hello")},
		{Op: wal.OpWrite, Path: "a/c", Offset: 4, Data: []byte("hello")},
		{Op: wal.OpWrite, Path: "a/b", Offset: 5, Data: []byte("hello")},
		{Op: wal.OpWrite, Path: "a/b", Offset: 4, Data: []byte("hellp")},
		{Op: wal.OpWrite, Path: "a/b", Offset: 4, Data: []byte("hello"), Append: true},
		{Op: wal.OpWrite, Path: "a/b", Offset: 4, Data: []byte("hello"), Ino: 7},
		{Op: wal.OpWrite, Path: "a/b", Offset: 4, Data: []byte("hello"), Mode: 0o600},
		{Op: wal.OpWrite, Path: "a/b", Offset: 4, Data: []byte("hello"), Excl: true},
		{Op: wal.OpWrite, Path: "a/b", Offset: 4, Data: []byte("hello"), RenameNoReplace: true},
	}
	h := canonicalRecordHash(base)
	if !bytes.Equal(h, canonicalRecordHash(base)) {
		t.Fatal("hash not deterministic")
	}
	for i, v := range variants {
		if bytes.Equal(h, canonicalRecordHash(v)) {
			t.Fatalf("variant %d hashes equal to base (field not covered)", i)
		}
	}
	// Length-prefixing makes field boundaries unambiguous.
	r1 := wal.Record{Op: wal.OpRename, Path: "ab", NewPath: ""}
	r2 := wal.Record{Op: wal.OpRename, Path: "a", NewPath: "b"}
	if bytes.Equal(canonicalRecordHash(r1), canonicalRecordHash(r2)) {
		t.Fatal("boundary ambiguity: (ab,) and (a,b) collide")
	}
	xattr := wal.Record{Op: wal.OpSetxattr, Path: "a/b", XattrName: "user.x", Data: []byte("v")}
	if bytes.Equal(canonicalRecordHash(xattr), canonicalRecordHash(wal.Record{
		Op: wal.OpSetxattr, Path: "a/b", XattrName: "user.x", Data: []byte("v"), XattrFlags: wal.XattrCreate,
	})) {
		t.Fatal("xattr conditional flags are absent from the exact request hash")
	}
}

// FuzzBuildMutationRecord: the request→record mapping must be total (no
// panics), deterministic, and hash-stable for any wire input.
func FuzzBuildMutationRecord(f *testing.F) {
	f.Add(uint8(OpWrite), "a", "", "", int64(0), int64(0), uint32(0o644), []byte("x"), false, false, false, uint64(0))
	f.Add(uint8(OpRename), "a", "b", "", int64(0), int64(0), uint32(0), []byte(nil), true, false, false, uint64(0))
	f.Add(uint8(OpSetattr), "a", "", "", int64(-1), int64(-5), uint32(0o777), []byte(nil), false, true, true, uint64(9))
	f.Add(uint8(OpReap), "", "", "t", int64(7), int64(7), uint32(1), []byte("d"), false, false, false, uint64(3))
	f.Fuzz(func(t *testing.T, op uint8, path, newPath, target string, offset, size int64, mode uint32,
		data []byte, orphanTarget, setMode, setTime bool, ino uint64) {
		req := &Request{
			Op: Op(op), Path: path, NewPath: newPath, Target: target,
			Offset: offset, Size: size, Mode: mode, Data: data,
			OrphanTarget: orphanTarget,
			SetMode:      setMode, SetTime: setTime,
			OrphanIno: ino, HandleIno: ino,
		}
		rec1, errno1 := buildMutationRecord(req)
		rec2, errno2 := buildMutationRecord(req)
		if errno1 != errno2 {
			t.Fatalf("nondeterministic errno: %d vs %d", errno1, errno2)
		}
		if errno1 != OK {
			return
		}
		if !bytes.Equal(canonicalRecordHash(rec1), canonicalRecordHash(rec2)) {
			t.Fatal("nondeterministic canonical hash")
		}
	})
}
