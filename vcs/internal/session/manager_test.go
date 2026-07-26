package session_test

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/fsproto"
	"github.com/trendup-ai/portablefs/vcs/internal/metrics"
	"github.com/trendup-ai/portablefs/vcs/internal/session"
)

// TestRecallDeferredWhileBusy: a recall (ReleaseSubtree) that arrives while the subtree still has
// OPEN FILES must be DEFERRED — releasing mid-workflow would hand off a torn state (e.g. a SQLite
// transaction in flight) and pull the checkout out from under the running process. The deferred
// recall completes from the periodic pass once the files close, and the holder's writes are durable.
func TestRecallDeferredWhileBusy(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("A")
	if _, st, err := cli.Mkdir("shared", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir shared: %d %v", st, err)
	}
	mgr := session.NewManager(wbAuth{cli}, "A", t.TempDir(), 0) // idle=0: recall-only
	mgr.Start(10 * time.Millisecond)                            // fast ticker drives the deferred-recall pass
	defer mgr.Stop()

	var busy atomic.Bool
	busy.Store(true)
	mgr.SetBusyCheck(func(root string) bool { return busy.Load() })

	s, err := mgr.Ensure("shared/f")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := s.Create("shared/f", 0o644); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Write("shared/f", 0, []byte("data")); err != nil {
		t.Fatalf("write: %v", err)
	}

	mgr.ReleaseSubtree("shared/f") // recall arrives while busy
	time.Sleep(60 * time.Millisecond)
	if mgr.For("shared/f") == nil {
		t.Fatal("a recall must be DEFERRED while the subtree has open files (not released mid-workflow)")
	}

	busy.Store(false) // the workflow finished — files closed
	released := false
	for i := 0; i < 200; i++ {
		time.Sleep(10 * time.Millisecond)
		if mgr.For("shared/f") == nil {
			released = true
			break
		}
	}
	if !released {
		t.Fatal("a deferred recall must complete once the subtree is no longer busy")
	}
	if got, st, _ := cli.Read("shared/f", 0, 16); st != fsproto.OK || string(got) != "data" {
		t.Fatalf("the holder's writes must be durable after the deferred recall completes: got %q st=%d", got, st)
	}
}

// TestIdleReleaseHandsOff: a session idle past the window auto-flushes, checks in, and is
// removed — so another owner can acquire the subtree (the multi-mount handoff), and A's
// writes are durable on the authority BEFORE the checkin (flush-before-checkin).
func TestIdleReleaseHandsOff(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("A")
	if _, st, err := cli.Mkdir("shared", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir shared: %d %v", st, err)
	}
	mgr := session.NewManager(wbAuth{cli}, "A", t.TempDir(), 50*time.Millisecond) // idle-release after 50ms
	mgr.Start(20 * time.Millisecond)                                              // flush + sweep every 20ms
	defer mgr.Stop()

	s, err := mgr.Ensure("shared/f")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := s.Create("shared/f", 0o644); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Write("shared/f", 0, []byte("data")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// After the idle window + a sweep, the session is released (no longer covers the path).
	released := false
	for i := 0; i < 100; i++ {
		time.Sleep(20 * time.Millisecond)
		if mgr.For("shared/f") == nil {
			released = true
			break
		}
	}
	if !released {
		t.Fatal("session was not idle-released within ~2s")
	}
	// Another owner can now acquire the handed-off subtree.
	granted, heldBy, err := cli.Checkout("shared", "B")
	if err != nil || !granted {
		t.Fatalf("B should acquire 'shared' after A's idle-release: granted=%v heldBy=%q err=%v", granted, heldBy, err)
	}
	// A's write was flushed to the authority BEFORE the checkin (handoff loses no data).
	got, st, _ := cli.Read("shared/f", 0, 16)
	if st != fsproto.OK || string(got) != "data" {
		t.Fatalf("A's data must be durable before release: got %q st=%d", got, st)
	}
}

// TestReleaseSubtreeOnRecall: with idle=0 (the recall model — NO time-based release) a session is
// held until explicitly recalled; ReleaseSubtree then flushes-before-checkin so another owner can
// acquire the subtree and observe all of the holder's writes (lossless handoff on contention).
func TestReleaseSubtreeOnRecall(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("A")
	if _, st, err := cli.Mkdir("shared", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir shared: %d %v", st, err)
	}
	mgr := session.NewManager(wbAuth{cli}, "A", t.TempDir(), 0) // idle=0: no timer release — recall only
	mgr.Start(10 * time.Millisecond)                            // ticker completes the recall once the session goes quiet
	defer mgr.Stop()

	s, err := mgr.Ensure("shared/f")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := s.Create("shared/f", 0o644); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Write("shared/f", 0, []byte("data")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if mgr.For("shared/f") == nil {
		t.Fatal("session must still be held with idle=0 (no time-based release)")
	}

	mgr.ReleaseSubtree("shared/f") // the recall (deferred while the session is still active, then completes)
	released := false
	for i := 0; i < 300; i++ {
		time.Sleep(10 * time.Millisecond)
		if mgr.For("shared/f") == nil {
			released = true
			break
		}
	}
	if !released {
		t.Fatal("ReleaseSubtree should release the session once it goes quiet")
	}
	granted, heldBy, err := cli.Checkout("shared", "B")
	if err != nil || !granted {
		t.Fatalf("B should acquire after recall: granted=%v heldBy=%q err=%v", granted, heldBy, err)
	}
	got, st, _ := cli.Read("shared/f", 0, 16)
	if st != fsproto.OK || string(got) != "data" {
		t.Fatalf("A's write must be durable after the recall-release: got %q st=%d", got, st)
	}
}

// TestRootLevelFileCoverage: a write-back session checked out at the VOLUME ROOT (the governing
// subtree of a TOP-LEVEL file is "") must cover that file — and every other path — via For().
// Regression: coveringLocked's prefix test HasPrefix(p, root+"/") is HasPrefix(p, "/") when root
// is "", which never matches a root-relative path, so For() returned nil for root-level files. The
// write landed in the overlay (Ensure resolves root "" via p==root) but the read could not see it
// (For() returned nil → the negative attr cache shadowed it → the file vanished).
func TestRootLevelFileCoverage(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("R")
	mgr := session.NewManager(wbAuth{cli}, "R", t.TempDir(), 0) // idle=0: no release during the test
	defer mgr.Stop()

	if mgr.For("top.db") != nil {
		t.Fatal("no session should exist before Ensure")
	}
	s, err := mgr.Ensure("top.db") // governingSubtree("top.db") == "" (the volume root)
	if err != nil || s == nil {
		t.Fatalf("ensure top.db: %v", err)
	}
	if mgr.For("top.db") != s {
		t.Fatal("a root-level file must be covered by its root checkout (the vanished-file bug)")
	}
	if mgr.For("top.db-journal") != s {
		t.Fatal("a root-level sibling must share the root session")
	}
	if mgr.For("sub/nested") != s {
		t.Fatal("a checkout at the volume root covers the whole volume, nested paths included")
	}
	if err := s.Create("top.db", 0o644); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, _, _, _, _, _, ok := s.LocalStat("top.db"); !ok {
		t.Fatal("LocalStat must see the locally-created root file (what Lookup serves)")
	}
}

// TestManagerAutoCheckoutAndResolve: Ensure auto-checks-out a path's parent dir, siblings
// share that session (parent-dir granularity for SQLite families), unrelated paths are not
// covered, and FlushAll lands every session's writes on the authority.
func TestManagerAutoCheckoutAndResolve(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	if _, st, err := cli.Mkdir("work", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir work: %d %v", st, err)
	}
	mgr := session.NewManager(wbAuth{cli}, "M", t.TempDir(), 0) // idle=0: no idle-release in this test
	defer mgr.Stop()

	if mgr.For("work/db") != nil {
		t.Fatal("no session should exist before Ensure")
	}
	s, err := mgr.Ensure("work/db")
	if err != nil || s == nil {
		t.Fatalf("ensure work/db: %v", err)
	}
	if mgr.For("work/db") != s {
		t.Fatal("the file itself must be covered")
	}
	if mgr.For("work/db-wal") != s {
		t.Fatal("a sibling must share the SAME session (parent-dir granularity)")
	}
	if mgr.For("other/x") != nil {
		t.Fatal("a path outside the checkout must not be covered")
	}
	// Ensure on a sibling reuses the existing session (no second checkout).
	if s2, _ := mgr.Ensure("work/db-wal"); s2 != s {
		t.Fatal("Ensure on a covered sibling must reuse the session")
	}

	if err := s.Create("work/db", 0o644); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.Write("work/db", 0, []byte("data")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := mgr.FlushAll(); err != nil {
		t.Fatalf("flushall: %v", err)
	}
	got, st, _ := cli.Read("work/db", 0, 64)
	if st != fsproto.OK || string(got) != "data" {
		t.Fatalf("authority after FlushAll: %q st=%d, want data", got, st)
	}
}

// TestRecoverAllReflushesCrashLeftoverWALs: on startup, a fresh manager over a PERSISTENT walDir
// proactively re-flushes the un-flushed tail of every session WAL a crash left behind — without
// the mount having to re-touch the subtree.
func TestRecoverAllReflushesCrashLeftoverWALs(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("A")
	if _, st, err := cli.Mkdir("proj", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir proj: %d %v", st, err)
	}
	walDir := t.TempDir()

	// A mount writes to its persistent WAL + makes it durable, then "crashes" (we abandon the
	// manager without Stop, leaving the WAL un-flushed on disk).
	crashed := session.NewManager(wbAuth{cli}, "A", walDir, 0)
	s, err := crashed.Ensure("proj/data")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create("proj/data", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("proj/data", 0, []byte("CRASHED-WRITES")); err != nil {
		t.Fatal(err)
	}
	if err := s.Fsync(); err != nil { // durable in the WAL, but never flushed to the authority
		t.Fatal(err)
	}
	if _, st, _ := cli.Getattr("proj/data"); st == fsproto.OK {
		t.Fatal("proj/data must be absent before recovery (the crash never flushed)")
	}

	// Restart: a fresh manager over the SAME persistent walDir + owner recovers proactively.
	restarted := session.NewManager(wbAuth{cli}, "A", walDir, 0)
	restarted.RecoverAll()
	defer restarted.Stop()
	got, st, err := cli.Read("proj/data", 0, 64)
	if err != nil || st != fsproto.OK || string(got) != "CRASHED-WRITES" {
		t.Fatalf("authority after RecoverAll: %q st=%d err=%v, want CRASHED-WRITES", got, st, err)
	}
}

// TestCleanReleaseRemovesWAL: a graceful release (everything flushed + checked in) deletes the
// session WAL, so a later startup does NOT mistake it for crash debris and re-flush stale data.
func TestCleanReleaseRemovesWAL(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("A")
	if _, st, err := cli.Mkdir("g", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir g: %d %v", st, err)
	}
	walDir := t.TempDir()
	mgr := session.NewManager(wbAuth{cli}, "A", walDir, 0)
	s, err := mgr.Ensure("g/f")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create("g/f", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("g/f", 0, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Stop(); err != nil { // graceful: flush + checkin + close + remove WAL
		t.Fatalf("stop: %v", err)
	}
	left, _ := filepath.Glob(filepath.Join(walDir, "sess-*.wal"))
	if len(left) != 0 {
		t.Fatalf("clean release left WAL(s) behind: %v (would be re-flushed as phantom crash debris)", left)
	}
}

// TestWriteBackMetrics: the manager + client record write-back observability — acquires,
// authority round-trips, flushes, and idle-release handoffs.
func TestWriteBackMetrics(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	if _, st, err := cli.Mkdir("m", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir m: %d %v", st, err)
	}
	reg := metrics.NewRegistry()
	cli.SetMetrics(reg)
	mgr := session.NewManager(wbAuth{cli}, "M", t.TempDir(), 30*time.Millisecond)
	mgr.AttachMetrics(reg)
	mgr.Start(10 * time.Millisecond)
	defer mgr.Stop()

	s, err := mgr.Ensure("m/f")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create("m/f", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("m/f", 0, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if got := reg.Counter("writeback_acquire_total").Value(); got < 1 {
		t.Fatalf("writeback_acquire_total = %d, want >= 1", got)
	}
	if got := reg.Counter("authority_ops_total").Value(); got < 1 {
		t.Fatalf("authority_ops_total = %d, want >= 1 (checkout/read round-trips)", got)
	}

	// After the idle window: the session flushed + handed off.
	flushed, handed := false, false
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		if reg.Counter("writeback_flush_total").Value() >= 1 {
			flushed = true
		}
		if reg.Counter("writeback_idle_release_total").Value() >= 1 {
			handed = true
		}
		if flushed && handed {
			break
		}
	}
	if !flushed {
		t.Fatalf("writeback_flush_total stayed 0 — flush not recorded")
	}
	if !handed {
		t.Fatalf("writeback_idle_release_total stayed 0 — handoff not recorded")
	}
	// The registry snapshots cleanly (JSON + Prometheus paths).
	if len(reg.Snapshot()) == 0 || reg.Prometheus() == "" {
		t.Fatal("registry snapshot/prometheus empty")
	}
}

// TestStopQuiescesInFlightSweep: Stop must wait for the periodic flush/sweep goroutine to finish
// its current tick before closing sessions — otherwise a mid-sweep idle-release (flush + checkin
// + WAL close/remove) races Stop closing the same session: a double WAL close + concurrent flush.
// Run under -race: with the WaitGroup quiesce, churning sessions against an aggressive ticker and
// then Stopping must complete cleanly with no race and no leftover WALs.
func TestStopQuiescesInFlightSweep(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("A")
	if _, st, err := cli.Mkdir("g", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir g: %d %v", st, err)
	}
	walDir := t.TempDir()
	mgr := session.NewManager(wbAuth{cli}, "A", walDir, time.Nanosecond) // idle≈0: every sweep releases
	mgr.Start(time.Millisecond)                                          // aggressive ticker => constant sweeps
	for i := 0; i < 40; i++ {
		if s, err := mgr.Ensure("g/f"); err == nil {
			_ = s.Create("g/f", 0o644)
			_, _ = s.Write("g/f", 0, []byte("x"))
		}
		time.Sleep(300 * time.Microsecond)
	}
	if err := mgr.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	// A graceful Stop (which quiesced the sweeper) leaves no WAL crash-debris behind.
	if left, _ := filepath.Glob(filepath.Join(walDir, "sess-*.wal")); len(left) != 0 {
		t.Fatalf("Stop left WAL(s) behind: %v", left)
	}
}
