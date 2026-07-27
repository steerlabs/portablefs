package session_test

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/session"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// countingAuthority is a fake Authority whose network can be turned off, so
// journal-first close semantics are observable: which calls were attempted,
// what was flushed, whether checkin happened.
type countingAuthority struct {
	mu       sync.Mutex
	dead     bool
	flushes  int
	checkins int
	applied  []wal.Record
}

func (a *countingAuthority) setDead(dead bool) {
	a.mu.Lock()
	a.dead = dead
	a.mu.Unlock()
}

func (a *countingAuthority) counts() (flushes, checkins int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.flushes, a.checkins
}

func (a *countingAuthority) Checkout(string, string) (bool, string, session.CheckoutGrant, error) {
	return true, "", session.CheckoutGrant{}, nil
}

func (a *countingAuthority) Checkin(string, string, session.CheckoutGrant) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.checkins++
	if a.dead {
		return errors.New("authority unreachable")
	}
	return nil
}

func (a *countingAuthority) Read(path string, off, length int64) ([]byte, int32, error) {
	if kind, _, st, _ := a.Stat(path); st != fsproto.OK || kind != "file" {
		return nil, fsproto.ENOENT, nil
	}
	data := a.appliedData(path)
	if off >= int64(len(data)) {
		return nil, fsproto.OK, nil
	}
	end := off + length
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	return append([]byte(nil), data[off:end]...), fsproto.OK, nil
}

func (a *countingAuthority) Stat(path string) (string, uint32, int32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range a.applied {
		if r.Path == path && (r.Op == wal.OpCreate || r.Op == wal.OpWrite) {
			return "file", 0o644, fsproto.OK, nil
		}
	}
	return "", 0, fsproto.ENOENT, nil
}

func (a *countingAuthority) Readlink(string) (string, int32, error) {
	return "", fsproto.ENOENT, nil
}

func (a *countingAuthority) FlushBatch(_ string, _ uint64, _ string, _ session.CheckoutGrant, records []wal.Record) (uint64, int32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.flushes++
	if a.dead {
		return 0, fsproto.EIO, errors.New("authority unreachable")
	}
	a.applied = append(a.applied, records...)
	if len(records) == 0 {
		return 0, fsproto.OK, nil
	}
	return records[len(records)-1].Seq, fsproto.OK, nil
}

func (a *countingAuthority) appliedSeqs() map[uint64]bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[uint64]bool{}
	for _, r := range a.applied {
		out[r.Seq] = true
	}
	return out
}

func (a *countingAuthority) appliedData(path string) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []byte
	for _, r := range a.applied {
		if r.Path == path && r.Op == wal.OpWrite {
			end := r.Offset + int64(len(r.Data))
			if int64(len(out)) < end {
				grown := make([]byte, end)
				copy(grown, out)
				out = grown
			}
			copy(out[r.Offset:end], r.Data)
		}
	}
	return out
}

// TestCloseLocalDurableKeepsWALAndCheckoutForRecovery pins the journal-first
// close contract: with the authority dead, CloseLocalDurable (1) never
// attempts a network drain, (2) never checks the subtree in (checking in an
// un-flushed subtree would hand the next holder a stale base — silent loss),
// (3) leaves the WAL on disk, and (4) the next clean open of the same
// (owner, root, walPath) recovers and re-flushes the tail — the crash path
// unmount now deliberately shares.
func TestCloseLocalDurableKeepsWALAndCheckoutForRecovery(t *testing.T) {
	auth := &countingAuthority{}
	walPath := filepath.Join(t.TempDir(), "sess.wal")

	s, err := session.New(auth, "M", "sess-local", "work", walPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create("work/f", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("work/f", 0, []byte("pending")); err != nil {
		t.Fatal(err)
	}

	auth.setDead(true)
	if err := s.CloseLocalDurable(); err != nil {
		t.Fatalf("journal-durable close must succeed on local media alone: %v", err)
	}
	flushes, checkins := auth.counts()
	if flushes != 0 {
		t.Fatalf("journal-durable close attempted %d network flushes, want 0", flushes)
	}
	if checkins != 0 {
		t.Fatalf("journal-durable close checked in %d times; an un-flushed subtree must NEVER check in", checkins)
	}
	if _, err := os.Stat(walPath); err != nil {
		t.Fatalf("the WAL must survive a journal-durable close for recovery: %v", err)
	}

	// A released session refuses further records (no writes can sneak past
	// the closed log).
	if _, err := s.Write("work/f", 0, []byte("late")); !errors.Is(err, session.ErrReleased) {
		t.Fatalf("write after journal-durable close: %v, want ErrReleased", err)
	}

	// Next clean start: authority is back; opening the same identity replays
	// the tail synchronously (New's recovery drain).
	auth.setDead(false)
	s2, err := session.New(auth, "M", "sess-local", "work", walPath)
	if err != nil {
		t.Fatalf("recovery open: %v", err)
	}
	defer func() { _ = s2.Close() }()
	if got := auth.appliedData("work/f"); string(got) != "pending" {
		t.Fatalf("recovered flush applied %q, want %q", got, "pending")
	}
	result := s2.RecoveryResult()
	if result.Records == 0 || !result.Flushed {
		t.Fatalf("recovery result = %+v, want a flushed non-empty tail", result)
	}
}

// gatedAuthority is a countingAuthority whose FIRST FlushBatch is held OPEN
// mid-round-trip: it signals entered, then blocks until the test sends the
// release token (later calls pass straight through, so a serialization
// regression fails on assertions rather than hanging the test). This drives
// close/flush interleavings deterministically.
type gatedAuthority struct {
	countingAuthority
	gate    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (a *gatedAuthority) FlushBatch(id string, epoch uint64, owner string, grant session.CheckoutGrant, records []wal.Record) (uint64, int32, error) {
	a.gate.Do(func() {
		a.entered <- struct{}{}
		<-a.release
	})
	return a.countingAuthority.FlushBatch(id, epoch, owner, grant, records)
}

// TestCloseLocalDurableSerializesWithInFlightFlush pins close/flush
// serialization: a drain abandoned mid-round-trip (the SyncVolumeBounded
// deadline shape) must complete its FlushBatch → CompactThrough pair before
// the log CLOSES — otherwise the batch the authority just applied stays in
// the kept WAL (compaction fails on the closed log) and the next clean start
// replays it under a fresh epoch: double-apply, the write-resurrection
// widening the journal-first design exists to bound. CloseLocalDurable itself
// must still RETURN promptly (local durability only — never waiting out the
// round-trip, which can be a full opTimeout against a dead peer); the log
// close is handed off to the drain, which stops at its batch boundary and
// leaves the WAL holding exactly the records the authority did NOT apply.
func TestCloseLocalDurableSerializesWithInFlightFlush(t *testing.T) {
	auth := &gatedAuthority{entered: make(chan struct{}), release: make(chan struct{})}
	walPath := filepath.Join(t.TempDir(), "sess.wal")
	s, err := session.New(auth, "M", "sess-serial", "work", walPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create("work/f", 0o644); err != nil {
		t.Fatal(err)
	}
	// More than one flush batch's worth of records, so a full drain would need
	// at least two round-trips — the second must never be sent once the close
	// begins.
	const writes = 600
	for i := 0; i < writes; i++ {
		if _, err := s.Write("work/f", int64(i), []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	totalRecords := uint64(1 + writes) // create + writes

	flushDone := make(chan error, 1)
	go func() { flushDone <- s.Flush() }()
	<-auth.entered // the first batch's round-trip is now in flight

	// The close must return promptly on LOCAL durability alone — never wait
	// out the in-flight round-trip (against a black-holed peer that wait is a
	// full opTimeout, the unmount-path stall this design forbids).
	closeDone := make(chan error, 1)
	go func() { closeDone <- s.CloseLocalDurable() }()
	select {
	case cerr := <-closeDone:
		if cerr != nil {
			t.Fatalf("CloseLocalDurable: %v", cerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CloseLocalDurable blocked on the in-flight flush round-trip; the journal-first close must not await the network")
	}

	// Release the in-flight batch: the drain must still be able to COMPACT it
	// (the log close was handed off, not raced), then stop at the boundary.
	auth.release <- struct{}{}
	if ferr := <-flushDone; !errors.Is(ferr, session.ErrClosing) {
		t.Fatalf("the abandoned drain must stop at the batch boundary with ErrClosing, got %v", ferr)
	}

	// THE invariant: applied-at-authority and kept-in-WAL partition the record
	// space — every record is in exactly one place. An overlap is the
	// double-apply; a gap is lost data.
	applied := auth.appliedSeqs()
	if len(applied) == 0 {
		t.Fatal("precondition: the in-flight batch must have been applied by the authority")
	}
	if uint64(len(applied)) == totalRecords {
		t.Fatal("precondition: the drain must have stopped before shipping the whole backlog")
	}
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatalf("reopen WAL: %v", err)
	}
	kept, err := w.Replay()
	_ = w.Close()
	if err != nil {
		t.Fatalf("replay kept WAL: %v", err)
	}
	seen := map[uint64]bool{}
	for _, r := range kept {
		if applied[r.Seq] {
			t.Fatalf("record Seq %d is BOTH applied at the authority AND kept in the WAL: recovery would double-apply it under a fresh epoch", r.Seq)
		}
		seen[r.Seq] = true
	}
	if got := uint64(len(applied) + len(seen)); got != totalRecords {
		t.Fatalf("applied (%d) + kept (%d) = %d records, want %d: every acknowledged record must be in exactly one place", len(applied), len(seen), got, totalRecords)
	}
	base := ^uint64(0)
	for seq := range applied { // the first batch starts at the log's base Seq
		if seq < base {
			base = seq
		}
	}
	for seq := base; seq < base+totalRecords; seq++ {
		if !applied[seq] && !seen[seq] {
			t.Fatalf("record Seq %d is neither applied nor kept in the WAL: acknowledged data lost", seq)
		}
	}
}

// TestCloseLocalDurableDuringInFlightReleaseDrain pins the race the
// journal-first contract is most easily broken by: a recall/idle release()
// whose FINAL drain is parked mid-round-trip against a dying authority when
// the unmount-path CloseLocalDurable arrives. "released" alone must not
// short-circuit the close — release() is not monotonic (it re-opens the
// session if its drain fails), and a record can land between the sweep's
// pending==0 check and release() taking the flag. So the close must STILL:
// fsync the WAL tail immediately (the journal-first promise), return
// promptly (never awaiting the parked round-trip), close the log exactly
// once via the drain handoff, and pin the failed release to a terminally
// released session (re-opening would hand new records to a closed log). The
// WAL stays on disk and replays on the next clean start.
func TestCloseLocalDurableDuringInFlightReleaseDrain(t *testing.T) {
	auth := &gatedAuthority{entered: make(chan struct{}), release: make(chan struct{})}
	walPath := filepath.Join(t.TempDir(), "sess.wal")
	s, err := session.New(auth, "M", "sess-inflight", "work", walPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create("work/f", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("work/f", 0, []byte("pending")); err != nil {
		t.Fatal(err)
	}

	// The recall/idle-release shape: release() marks the session released,
	// then its final drain parks mid-round-trip at the authority gate.
	releaseDone := make(chan error, 1)
	go func() { releaseDone <- s.Close() }()
	<-auth.entered

	// The unmount-path journal-first close arrives NOW.
	closeDone := make(chan error, 1)
	go func() { closeDone <- s.CloseLocalDurable() }()
	select {
	case cerr := <-closeDone:
		if cerr != nil {
			t.Fatalf("CloseLocalDurable during an in-flight release drain: %v", cerr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CloseLocalDurable blocked on the in-flight release round-trip; the journal-first close must not await the network")
	}

	// THE contract: by the time CloseLocalDurable returned, every appended
	// record is fsync-durable — while the release drain is still parked, so
	// the durability cannot have come from anywhere else.
	if !s.AllRecordsDurableForTest() {
		t.Fatal("CloseLocalDurable returned success without fsyncing the WAL tail: the journal-first durability claim is false")
	}

	// The authority dies mid-round-trip: the parked batch fails, so the
	// release drain fails. The failed release must NOT re-open the session.
	auth.setDead(true)
	auth.release <- struct{}{}
	if rerr := <-releaseDone; rerr == nil {
		t.Fatal("release() must surface its failed final drain")
	}
	if !s.LogClosedForTest() {
		t.Fatal("the handed-off close must have closed the log at the drain's exit")
	}
	if _, err := s.Write("work/f", 0, []byte("late")); !errors.Is(err, session.ErrReleased) {
		t.Fatalf("a failed release after a journal-first close must stay terminally released, got %v", err)
	}
	if _, err := os.Stat(walPath); err != nil {
		t.Fatalf("the WAL must survive for recovery: %v", err)
	}
	if _, checkins := auth.counts(); checkins != 0 {
		t.Fatalf("an un-flushed subtree must never check in (got %d checkins)", checkins)
	}

	// Next clean start replays the kept tail — nothing was lost, nothing
	// double-applied (the parked batch was never acked).
	auth.setDead(false)
	s2, err := session.New(auth, "M", "sess-inflight", "work", walPath)
	if err != nil {
		t.Fatalf("recovery open: %v", err)
	}
	defer func() { _ = s2.Close() }()
	if got := auth.appliedData("work/f"); string(got) != "pending" {
		t.Fatalf("recovered flush applied %q, want %q", got, "pending")
	}
	if result := s2.RecoveryResult(); result.Records == 0 || !result.Flushed {
		t.Fatalf("recovery result = %+v, want a flushed non-empty tail", result)
	}
}

// TestJournalFirstAfterCleanReleaseIsNoop pins the completed-release
// short-circuit: after release() drained everything, checked in, and closed
// the log (removing the WAL), a late CloseLocalDurable/FsyncLocal — unmount
// paths legitimately run both — must be a clean no-op, not an error against
// a closed log.
func TestJournalFirstAfterCleanReleaseIsNoop(t *testing.T) {
	auth := &countingAuthority{}
	walPath := filepath.Join(t.TempDir(), "sess.wal")
	s, err := session.New(auth, "M", "sess-clean", "work", walPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create("work/f", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("work/f", 0, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("clean release: %v", err)
	}
	if err := s.CloseLocalDurable(); err != nil {
		t.Fatalf("CloseLocalDurable after a clean release must be a no-op: %v", err)
	}
	if err := s.FsyncLocal(); err != nil {
		t.Fatalf("FsyncLocal after a clean release must be a no-op: %v", err)
	}
}

// TestManagerFsyncAllIsLocalOnly pins the journal-first volume barrier at the
// manager level: FsyncAll makes every session's records locally durable and
// performs zero authority round-trips.
func TestManagerFsyncAllIsLocalOnly(t *testing.T) {
	auth := &countingAuthority{}
	m := session.NewManager(auth, "M", t.TempDir(), 0)
	s, err := m.Ensure("work/f")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create("work/f", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("work/f", 0, []byte("x")); err != nil {
		t.Fatal(err)
	}

	auth.setDead(true)
	if err := m.FsyncAll(); err != nil {
		t.Fatalf("FsyncAll must succeed on local media alone: %v", err)
	}
	if flushes, _ := auth.counts(); flushes != 0 {
		t.Fatalf("FsyncAll performed %d authority flushes, want 0", flushes)
	}
	if err := m.StopLocalDurable(); err != nil {
		t.Fatalf("StopLocalDurable: %v", err)
	}
	if _, checkins := auth.counts(); checkins != 0 {
		t.Fatalf("StopLocalDurable checked in %d times, want 0", checkins)
	}
}
