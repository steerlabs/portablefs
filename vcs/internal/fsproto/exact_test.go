package fsproto

// Server-side tests for exact mount sessions (protocol version 3): session
// lifecycle, exact-once mutation identity (duplicates, conflicts, gaps, static
// rejects), promotion/restart replay, reclaim grace, lease expiry, wire
// bounds, and concurrent-slot exactness. Client-side transport behavior (lost
// replies, parking, flap) lives in exact_client_test.go.

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"

	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// newExactAuthority builds an exact-session authority (workfs-backed server)
// over its own WAL file and returns the pieces tests poke at.
func newExactAuthority(t *testing.T) (*Server, *workfs.FS, *wal.WAL, string) {
	t.Helper()
	walPath := filepath.Join(t.TempDir(), "authority.wal")
	return reopenAuthority(t, walPath)
}

// reopenAuthority opens (or re-opens after Close — a restart/failover) the
// managed authority state at walPath: the file-backed PFJ3 entry log replays
// and the coordination state recovers by exact cold replay.
func reopenAuthority(t *testing.T, walPath string) (*Server, *workfs.FS, *wal.WAL, string) {
	t.Helper()
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	flog, err := pfj3.NewFileEntryLog(w)
	if err != nil {
		t.Fatalf("open file entry log: %v", err)
	}
	fs, err := workfs.NewManaged(nil, nopBlobs{}, flog)
	if err != nil {
		t.Fatalf("new managed workfs: %v", err)
	}
	return NewServer(fs, fs), fs, w, walPath
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

// resumeSession durably renews (and re-anchors) a session after a restart —
// the renew loop's job in production. A cold-replayed session admits no
// mutation until this database-time fact lands.
func resumeSession(t *testing.T, s *Server, id string, gen uint64, token string) *connSession {
	t.Helper()
	cs := &connSession{}
	r := s.dispatchConn(cs, &Request{Op: OpSessionResume, SessionID: id, SessionGen: gen, SessionToken: token})
	if r == nil || r.Status != OK {
		t.Fatalf("session resume %s/%d: %+v", id, gen, r)
	}
	return cs
}

func readFile(t *testing.T, s *Server, path string) string {
	t.Helper()
	r := s.dispatch(&Request{Op: OpRead, Path: path, Size: 64})
	if r.Status != OK {
		t.Fatalf("read %s: status %d", path, r.Status)
	}
	return string(r.Data)
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
	// Every optional lane: atomic delegated xattrs, durable birth-time/BSD-flag
	// persistence, and post-op mutation attributes.
	if want := FeatureDelegatedXattrs | FeatureFlagPersistence | FeatureMutationAttrs; r.Features != want {
		t.Fatalf("managed authority features = %b, want %b", r.Features, want)
	}
	if r.LeaseMs <= 0 {
		t.Fatalf("probe LeaseMs = %d, want > 0", r.LeaseMs)
	}

	// A skewed client version is refused EINVAL with our version still in
	// the response, so a newer client reports the mismatch clearly.
	for _, skew := range []int64{0, 3, 4, int64(ProtocolVersion) + 1} {
		if r := s.dispatch(&Request{Op: OpProtocolVersion, Size: skew}); r.Status != EINVAL || r.ProtoVersion != ProtocolVersion {
			t.Fatalf("skewed probe (client v%d): status=%d version=%d, want EINVAL/%d", skew, r.Status, r.ProtoVersion, ProtocolVersion)
		}
	}

	// A reads-only server (plain billy fs, no session store) answers the
	// probe; session opens are refused, and envelope-less mutations are
	// refused too — mutations require a managed session store.
	readsOnly := NewServer(memfs.New(), nil)
	if r := readsOnly.dispatch(&Request{Op: OpProtocolVersion, Size: int64(ProtocolVersion)}); r.Status != OK || r.Features != 0 {
		t.Fatalf("reads-only probe: status=%d features=%b, want OK/0", r.Status, r.Features)
	}
	if r := readsOnly.dispatch(&Request{Op: OpSessionOpen, SessionID: "x", SessionGen: 1, SessionToken: "t", SessionSlots: 1}); r.Status != EPERM {
		t.Fatalf("reads-only session open: status=%d, want EPERM", r.Status)
	}
	if r := readsOnly.dispatch(&Request{Op: OpCreate, Path: "f", Mode: 0o644}); r.Status != EPERM {
		t.Fatalf("reads-only envelope-less create: status=%d, want EPERM", r.Status)
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
	cs2 := resumeSession(t, s2, "sess-append", 1, "append-token")
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
	// Replay the identical identity: the STORED essential outcome
	// (status/count/ino). Version is a coherence hint, not part of the
	// stored outcome — a duplicate replay omits it and the client re-reads.
	replay := exactDo(s, cs, &Request{Op: OpWrite, Path: "f", Offset: 0, Data: []byte("hello")}, 0, 2)
	if !replay.Duplicate || replay.Status != OK || replay.Count != first.Count || replay.Ino != first.Ino {
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

	// Rewinding (seq 1 after 1,2 recorded): the slot retains only its
	// LATEST outcome, so the rewound identity is definitively retired (EIO)
	// — never re-executed, never a fabricated success. (A conflicting
	// replay AT the latest sequence fences; see TestExactConflictFencesSession.)
	cs2 := openExactSession(t, s, "sess-G2", 1, "OG2", "tokG2", 4)
	if r := exactDo(s, cs2, &Request{Op: OpCreate, Path: "g2", Mode: 0o644}, 0, 1); r.Status != OK {
		t.Fatalf("seed seq1: %+v", r)
	}
	if r := exactDo(s, cs2, &Request{Op: OpWrite, Path: "g2", Data: []byte("z")}, 0, 2); r.Status != OK {
		t.Fatalf("seed seq2: %+v", r)
	}
	if r := exactDo(s, cs2, &Request{Op: OpCreate, Path: "g2-other", Mode: 0o644}, 0, 1); r.Status != EIO {
		t.Fatalf("seq rewind below the retained outcome: status=%d, want EIO (retired)", r.Status)
	}
	if got := s.dispatch(&Request{Op: OpGetattr, Path: "g2-other"}); got.Status != ENOENT {
		t.Fatalf("rewound create must never execute: status=%d", got.Status)
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
	cs2 := resumeSession(t, s2, "sess-SR", 1, "tokSR")
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

// TestEnvelopelessMutationsAlwaysRefused: the v8 baseline has no permissive
// posture — every envelope-less mutation and coordination op is refused,
// while reads flow.
func TestEnvelopelessMutationsAlwaysRefused(t *testing.T) {
	s, _, _, _ := newExactAuthority(t)

	if r := s.dispatch(&Request{Op: OpMkdir, Path: "d", Mode: 0o755}); r.Status != EPERM {
		t.Fatalf("envelope-less mkdir: status=%d, want EPERM", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpWrite, Path: "f", Data: []byte("x")}); r.Status != EPERM {
		t.Fatalf("envelope-less write: status=%d, want EPERM", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpCheckout, Path: "w", Owner: "O"}); r.Status != EPERM {
		t.Fatalf("envelope-less checkout: status=%d, want EPERM", r.Status)
	}
	if r := s.dispatch(&Request{Op: OpGetattr, Path: "nope"}); r.Status != ENOENT {
		t.Fatalf("read admission: status=%d, want ENOENT (served)", r.Status)
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

	// The token-proven prior session resumes (its establish rode the log;
	// the durable renewal re-anchors admission on the successor)...
	cs2 := resumeSession(t, s2, "sess-P", 1, "tokP")
	// ...a wrong token does not attach (malicious claim of a live session)...
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

func TestLeaseExpiryFencesAndReleasesCoordination(t *testing.T) {
	// Registered before the server cleanups (so it runs AFTER them): restoring
	// the package variable while the sweeper still reads it is a data race.
	oldTTL := workfs.SessionLeaseTTL()
	t.Cleanup(func() { workfs.SetSessionLeaseTTL(oldTTL) })
	workfs.SetSessionLeaseTTL(400 * time.Millisecond)

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
	if r := exactDo(s, cs, &Request{Op: OpCheckout, Path: "proj"}, 1, 1); r.Status != OK || r.CheckoutEpoch == "" {
		t.Fatalf("checkout: %+v", r)
	}
	if r := exactDo(s, cs, &Request{Op: OpLock, Path: "res", LkID: 1, LkMode: LkSetlk, LkStart: 0, LkEnd: 10, LkWrite: true}, 2, 1); r.Status != OK {
		t.Fatalf("lock: %+v", r)
	}

	// No renewals arrive; the store must durably fence the session and
	// release its journaled checkouts and advisory locks.
	deadline := time.Now().Add(5 * time.Second)
	for {
		info, ok := fs.CurrentSession("sess-L")
		_, held, cerr := fs.ManagedCheckoutAt("proj")
		if cerr != nil {
			t.Fatalf("checkout query: %v", cerr)
		}
		if ok && info.Expired && !held {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("lease never swept: info=%+v held=%v", info, held)
		}
		time.Sleep(25 * time.Millisecond)
	}

	// The expired session's next mutation is fenced...
	if r := exactDo(s, cs, &Request{Op: OpCreate, Path: "late", Mode: 0o644}, 0, 2); r.Status != ESTALE {
		t.Fatalf("mutation after lease expiry: status=%d, want ESTALE", r.Status)
	}
	// ...and its locks are actually free for others.
	csB := openExactSession(t, s, "sess-LB", 1, "OLB", "tokLB", 4)
	if r := exactDo(s, csB, &Request{Op: OpLock, Path: "res", LkID: 9, LkMode: LkSetlk, LkStart: 0, LkEnd: 10, LkWrite: true}, 0, 1); r.Status != OK {
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
	legacyChtimes := wal.Record{
		Op: wal.OpChtimes, Path: "a/b", MtimeMs: 1234,
		AtimeMs: 77, ChtimesSetAtime: true, Ino: 42,
	}
	if got := hex.EncodeToString(canonicalRecordHash(legacyChtimes)); got !=
		"0a825bc3e47b3fffc3d222deb61eedeee8fde081d611c9b1814879bbcb38af5c" {
		t.Fatalf("legacy chtimes request hash drifted across upgrade: %s", got)
	}
	atimeOnly := legacyChtimes
	atimeOnly.ChtimesKeepMtime = true
	if bytes.Equal(canonicalRecordHash(legacyChtimes), canonicalRecordHash(atimeOnly)) {
		t.Fatal("atime-only preserve-mtime intent is absent from the exact request hash")
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
