package workfs

// THE CONSERVATION LAW, AS A TEST.
//
//	d(resident)/dt = accept_rate - release_rate
//
// The live gate measured accept 7.00 MiB/s against release 1.06 MiB/s. Every
// bound this package had was a CLIFF: writes ran at full speed until resident
// bytes hit VCS_DIRTY_RSS_MAX_MB and then failed with ENOSPC. A cliff cannot
// satisfy the equation — it only decides when the failure arrives — so the
// residency curve climbs to the bound and stays there whatever the trigger
// percentages are set to.
//
// These tests pin the pacing that does satisfy it, and the three properties
// that make it safe: it must not hold any filesystem lock while it waits, it
// must never hold a RELEASING operation, and it must refuse rather than hang
// when nothing is actually being released.

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// paceFixture is a managed FS with a small bound and a pacing setpoint, sized
// so a handful of block writes cross it.
func paceFixture(t *testing.T, maxBytes int64, percent int) (*FS, *fakeBlobs) {
	t.Helper()
	blobs := &fakeBlobs{data: map[string][]byte{}}
	fs, err := NewManaged(nil, blobs, newFakeEntryLog())
	if err != nil {
		t.Fatal(err)
	}
	fs.SetDirtyRSSMax(maxBytes)
	fs.SetDirtyPacePercent(percent)
	return fs, blobs
}

// TestWriteAdmissionRunsFreeBelowTheSetpoint proves pacing costs nothing until
// it is needed: below the setpoint a write must not wait at all.
func TestWriteAdmissionRunsFreeBelowTheSetpoint(t *testing.T) {
	fs, _ := paceFixture(t, 8*blockSize, 50)
	if got, want := fs.DirtyPaceSetpoint(), int64(4*blockSize); got != want {
		t.Fatalf("setpoint = %d, want %d (half an %d-byte bound)", got, want, 8*blockSize)
	}
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "a.bin", Mode: 0o644}, nil, ""); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := managedWrite(fs, "a.bin", 0, blockPayload(1, blockSize)); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a write far below the setpoint waited %v", elapsed)
	}
	if waited := fs.DirtyBlockBytes(); waited != blockSize {
		t.Fatalf("resident = %d, want one block", waited)
	}
}

// TestWriteAdmissionWaitsForAnActualReleaseAtTheSetpoint is the core of the
// design: at the setpoint a write does not fail and does not proceed — it
// waits, and it is admitted by an actual FALL in resident bytes. The release
// here is a truncate, i.e. the same shrink path the fold uses.
func TestWriteAdmissionWaitsForAnActualReleaseAtTheSetpoint(t *testing.T) {
	fs, _ := paceFixture(t, 8*blockSize, 50) // setpoint = 4 blocks
	for _, name := range []string{"a.bin", "b.bin"} {
		if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: name, Mode: 0o644}, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	// Fill to the setpoint: four blocks resident.
	managedWriteBig(t, fs, "a.bin", 0, blockPayload(2, 4*blockSize))
	wantDirty(t, fs, 4*blockSize, "resident sits exactly at the setpoint")

	// The next write must WAIT — not fail, not proceed.
	admitted := make(chan error, 1)
	go func() { admitted <- managedWrite(fs, "b.bin", 0, blockPayload(3, blockSize)) }()
	select {
	case err := <-admitted:
		t.Fatalf("a write at the setpoint was admitted (or refused) instead of paced: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	// A truncate is a RELEASE, and it must stay admissible while a writer is
	// held — that is what makes the wait recoverable rather than a deadlock.
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpTruncate, Path: "a.bin", Size: 0}, nil, ""); err != nil {
		t.Fatalf("a releasing operation must never be paced: %v", err)
	}
	select {
	case err := <-admitted:
		if err != nil {
			t.Fatalf("the paced write failed after the release: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the release did not admit the paced write")
	}
	if released := fs.DirtyReleasedBytes(); released < 4*blockSize {
		t.Fatalf("released bytes = %d, want at least the four blocks the truncate freed", released)
	}
}

// TestOneRowLargerThanTheSetpointIsNotPaced: pacing can only be satisfied by
// releases, so a row whose worst-case growth alone reaches the setpoint could
// never be admitted by it. Pacing such a row would convert a legitimately
// large write into a guaranteed timeout; the hard bound is the right
// authority for "this single operation does not fit".
func TestOneRowLargerThanTheSetpointIsNotPaced(t *testing.T) {
	fs, _ := paceFixture(t, 8*blockSize, 50) // setpoint = 4 blocks
	fs.pace.maxWait.Store(int64(time.Second))
	start := time.Now()
	if err := fs.paceDirtyGrowth(fs.DirtyPaceSetpoint()); err != nil {
		t.Fatalf("a row at the setpoint must fall through to the hard bound, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a row at the setpoint waited %v instead of falling through", elapsed)
	}
}

// TestPacingIsNotHanging: a paced write is bounded, and the bound that ends it
// is dirtyPaceMaxWait and NOTHING ELSE. Running two different bounds is what
// makes that discriminating: any additional, shorter time-based trigger — such
// as the fixed "no release observed lately" window an earlier revision had —
// would end both waits at ITS deadline instead of tracking this one.
func TestPacingIsNotHanging(t *testing.T) {
	for _, bound := range []time.Duration{300 * time.Millisecond, 1500 * time.Millisecond} {
		fs, _ := paceFixture(t, 8*blockSize, 50)
		fs.pace.maxWait.Store(int64(bound))
		for _, name := range []string{"a.bin", "b.bin"} {
			if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: name, Mode: 0o644}, nil, ""); err != nil {
				t.Fatal(err)
			}
		}
		managedWriteBig(t, fs, "a.bin", 0, blockPayload(4, 4*blockSize))

		start := time.Now()
		err := managedWrite(fs, "b.bin", 0, blockPayload(5, blockSize))
		elapsed := time.Since(start)
		if !errors.Is(err, ErrDirtyRSSCapacity) {
			t.Fatalf("bound %v: a write that waited out the bound with no relief must "+
				"refuse definitely, got %v", bound, err)
		}
		if elapsed < bound {
			t.Fatalf("bound %v: refused after only %v — something other than the wait "+
				"bound ended the wait", bound, elapsed)
		}
		if elapsed > bound+3*time.Second {
			t.Fatalf("bound %v: refusal took %v; the wait bound did not bound it", bound, elapsed)
		}
	}
}

// TestPacingToleratesTheNormalGapBetweenCuts is the property the coordinator's
// WAL-back-pressure finding forced. Relief is BURSTY: the fold releases only
// on cut adoption, so a healthy volume sees NO release at all for as long as a
// cut takes — minutes at the rates the live gate measured. An earlier revision
// refused after a fixed 20 s window with no release observed, which fires in
// exactly that normal gap.
//
// It is also coupled the wrong way round: a sustained writer saturates
// Postgres WAL, which slows cut materialization and adoption, so the gap
// between releases WIDENS precisely when writers are queued on it. A
// no-release window tuned at idle would therefore fire hardest under load.
// A paced writer must ride out a quiet period far longer than any fold poll
// cadence and still be admitted the instant relief lands.
func TestPacingToleratesTheNormalGapBetweenCuts(t *testing.T) {
	fs, _ := paceFixture(t, 8*blockSize, 50)
	fs.pace.maxWait.Store(int64(30 * time.Second)) // the shipped bound
	for _, name := range []string{"a.bin", "b.bin"} {
		if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: name, Mode: 0o644}, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	managedWriteBig(t, fs, "a.bin", 0, blockPayload(12, 4*blockSize))

	admitted := make(chan error, 1)
	go func() { admitted <- managedWrite(fs, "b.bin", 0, blockPayload(13, blockSize)) }()

	// A quiet stretch with ZERO releases, many times any fold poll cadence.
	// Nothing may refuse during it.
	select {
	case err := <-admitted:
		t.Fatalf("a paced write was refused during an ordinary no-release gap "+
			"(the interval between cuts, which widens under WAL back-pressure): %v", err)
	case <-time.After(2 * time.Second):
	}
	if refusals := fs.DirtyReleasedBytes(); refusals != 0 {
		t.Fatalf("no release should have been credited during the gap, got %d", refusals)
	}

	// Relief finally lands; the waiter must be admitted immediately.
	released := time.Now()
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpTruncate, Path: "a.bin", Size: 0}, nil, ""); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-admitted:
		if err != nil {
			t.Fatalf("the paced write failed when relief arrived: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("relief arrived but the paced write was not admitted")
	}
	if wake := time.Since(released); wake > 2*time.Second {
		t.Fatalf("the waiter took %v to notice relief: it must wake on the release, "+
			"not on a poll", wake)
	}
}

// TestPacingNeverHoldsAReleasingOrMetadataOperation is the property that keeps
// a paced volume recoverable. Everything that frees memory — and everything
// that merely records control state — must pass a saturated pacer untouched,
// or the only operations able to lift the pressure become the ones the
// pressure blocks.
func TestPacingNeverHoldsAReleasingOrMetadataOperation(t *testing.T) {
	fs, _ := paceFixture(t, 4*blockSize, 50) // setpoint = 2 blocks
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: "a.bin", Mode: 0o644}, nil, ""); err != nil {
		t.Fatal(err)
	}
	managedWriteBig(t, fs, "a.bin", 0, blockPayload(6, 2*blockSize))
	wantDirty(t, fs, 2*blockSize, "resident sits at the setpoint")

	// A pacer this saturated would hold any write. None of these allocate a
	// dirty block, so none of them may wait.
	done := make(chan error, 1)
	go func() {
		for _, rec := range []wal.Record{
			{Op: wal.OpMkdir, Path: "d", Mode: 0o755},
			{Op: wal.OpCreate, Path: "d/new.bin", Mode: 0o644},
			{Op: wal.OpChmod, Path: "a.bin", Mode: 0o600},
			{Op: wal.OpRename, Path: "d/new.bin", NewPath: "d/moved.bin"},
			{Op: wal.OpTruncate, Path: "a.bin", Size: 0},
		} {
			r := rec
			if _, err := fs.CommitEntry(&r, nil, ""); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a non-allocating operation was refused at the setpoint: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a non-allocating operation was PACED: relief and liveness must never " +
			"queue behind the memory pressure they exist to resolve")
	}
	wantDirty(t, fs, 0, "the truncate ran and released everything")
}

// TestPacingWaitsOutsideEveryFilesystemLock is the lock-order property, and it
// is the one that decides whether this is backpressure or a deadlock. While a
// write is parked for memory, the filesystem must remain fully serviceable —
// reads, lookups, and above all the accounting the fold itself needs. If the
// wait were taken inside fs.mu (where the dirty reservation is made) a paced
// writer would block the only thing able to release the memory it waits for.
func TestPacingWaitsOutsideEveryFilesystemLock(t *testing.T) {
	fs, _ := paceFixture(t, 8*blockSize, 50)
	for _, name := range []string{"a.bin", "b.bin"} {
		if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: name, Mode: 0o644}, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	managedWriteBig(t, fs, "a.bin", 0, blockPayload(7, 4*blockSize))

	parked := make(chan error, 1)
	go func() { parked <- managedWrite(fs, "b.bin", 0, blockPayload(8, blockSize)) }()
	time.Sleep(200 * time.Millisecond) // let the writer reach the wait

	// Every one of these takes fs.mu. If the pacing wait held it, they hang.
	probes := make(chan struct{})
	go func() {
		defer close(probes)
		for i := 0; i < 50; i++ {
			_ = fs.DirtyBlockBytes()
			_ = fs.AppliedWatermark()
			_ = fs.FoldedWatermark()
			_ = fs.Snapshot()
		}
	}()
	select {
	case <-probes:
	case <-time.After(5 * time.Second):
		t.Fatal("fs.mu is held across the pacing wait: a writer parked for memory " +
			"blocks the fold that is the only thing able to release it")
	}

	// Release and let the parked writer through so the test does not leak it.
	if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpTruncate, Path: "a.bin", Size: 0}, nil, ""); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-parked:
		if err != nil {
			t.Fatalf("parked write: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the parked write never resumed")
	}
}

// TestSealReleasesEveryPacedWriter: a quiesce must never wait behind memory
// pressure a sealing authority is not going to relieve.
func TestSealReleasesEveryPacedWriter(t *testing.T) {
	fs, _ := paceFixture(t, 8*blockSize, 50)
	for _, name := range []string{"a.bin", "b.bin"} {
		if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: name, Mode: 0o644}, nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	managedWriteBig(t, fs, "a.bin", 0, blockPayload(9, 4*blockSize))
	parked := make(chan error, 1)
	go func() { parked <- managedWrite(fs, "b.bin", 0, blockPayload(10, blockSize)) }()
	time.Sleep(200 * time.Millisecond)

	fs.pace.stop()
	select {
	case err := <-parked:
		if !errors.Is(err, ErrSealed) {
			t.Fatalf("a sealed pacer must release its waiters with ErrSealed, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sealing did not release the paced writer")
	}
}

// TestPacedResidencySawTooths is the whole point, end to end. A writer that
// offers far more than the release rate must NOT drive residency to the hard
// bound: it must be held at the setpoint, and the curve must fall every time
// something is actually released. This is the shape a cliff can never produce.
func TestPacedResidencySawTooths(t *testing.T) {
	const (
		bound     = 32 * blockSize
		files     = 24
		reliefGap = 60 * time.Millisecond // relief far slower than the writer
		runFor    = 2 * time.Second
	)

	// run drives one arm: a writer that never backs off against a relief loop
	// that releases far less than the writer offers. percent=0 is pacing OFF,
	// i.e. exactly the pre-existing behaviour of the hard bound alone.
	run := func(percent int) (peak int64, falls int, samples int, hitBound bool, setpoint int64) {
		fs, _ := paceFixture(t, bound, percent)
		setpoint = fs.DirtyPaceSetpoint()
		names := make([]string, files)
		for i := range names {
			names[i] = "f" + string(rune('a'+i)) + ".bin"
			if _, err := fs.CommitEntry(&wal.Record{Op: wal.OpCreate, Path: names[i], Mode: 0o644}, nil, ""); err != nil {
				t.Fatal(err)
			}
		}

		// The "fold": periodic truncates, which is the same resident-byte
		// shrink path FoldToBase drives (MarkClean), at a rate the writer
		// comfortably outruns.
		stop := make(chan struct{})
		var relief, sampler sync.WaitGroup
		relief.Add(1)
		go func() {
			defer relief.Done()
			for next := 0; ; next++ {
				select {
				case <-stop:
					return
				case <-time.After(reliefGap):
				}
				_, _ = fs.CommitEntry(&wal.Record{
					Op: wal.OpTruncate, Path: names[next%files], Size: 0,
				}, nil, "")
			}
		}()

		var curve []int64
		sampler.Add(1)
		go func() {
			defer sampler.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				resident := fs.DirtyBlockBytes()
				curve = append(curve, resident)
				if resident > peak {
					peak = resident
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()

		deadline := time.Now().Add(runFor)
		for i := 0; time.Now().Before(deadline); i++ {
			// Each write lands on a FRESH block (advancing offset), so the
			// writer genuinely allocates resident memory instead of
			// overwriting blocks it already owns.
			off := int64(i/files) * blockSize
			if err := managedWrite(fs, names[i%files], off, blockPayload(11+i, blockSize)); err != nil {
				if errors.Is(err, ErrDirtyRSSCapacity) {
					hitBound = true
					break
				}
				t.Fatal(err)
			}
		}
		close(stop)
		relief.Wait()
		sampler.Wait()

		for i := 1; i < len(curve); i++ {
			if curve[i] < curve[i-1] {
				falls++
			}
		}
		return peak, falls, len(curve), hitBound, setpoint
	}

	// BASELINE: the hard bound alone. The writer runs at full speed until
	// residency reaches the ceiling and the cliff answers with ENOSPC —
	// which is the conservation law, not a tuning problem.
	basePeak, _, _, baseHitBound, _ := run(0)
	t.Logf("BASELINE (pacing off): peak resident %d MiB of a %d MiB bound, hit the bound: %v",
		basePeak>>20, int64(bound)>>20, baseHitBound)
	if !baseHitBound {
		t.Skipf("this host did not out-write the relief loop even unpaced "+
			"(peak %d of %d); the comparison would prove nothing", basePeak, int64(bound))
	}

	// PACED: the same writer, the same relief, held at the setpoint.
	peak, falls, samples, hitBound, setpoint := run(50)
	t.Logf("PACED: peak resident %d MiB, setpoint %d MiB, bound %d MiB, %d falls across %d samples",
		peak>>20, setpoint>>20, int64(bound)>>20, falls, samples)

	if hitBound {
		t.Fatalf("the writer still reached the HARD BOUND under pacing: admission is not "+
			"being held to the release rate (peak %d, setpoint %d, bound %d)",
			peak, setpoint, int64(bound))
	}
	if peak > setpoint {
		t.Fatalf("resident peaked at %d, above the %d setpoint", peak, setpoint)
	}
	// The curve must come DOWN, repeatedly. A climb that merely stops at the
	// setpoint is not relief, it is a smaller cliff.
	if falls < 5 {
		t.Fatalf("resident dirty bytes fell %d times across %d samples (peak %d, setpoint %d): "+
			"the residency curve must saw-tooth, not climb and hold", falls, samples, peak, setpoint)
	}
}
