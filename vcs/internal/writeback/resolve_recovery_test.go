package writeback

// ROUND 21b, DEFECT 2: the escape hatches formed a closed cycle.
//
// A terminally conflict/corrupt recovery job refused `portablefs umount
// --force` with "requires explicit recovery resolution", --discard-record
// refused with "run portablefs umount --force ... first", and the phrase
// "explicit recovery resolution" appeared in exactly one place in the entire
// product: the error that refused. No command performed one. The operator
// escaped only by running recoveryRunner.contain's step 3 by hand.
//
// These tests are the shipped resolution's contract.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// terminalizeJob rewrites a store's recovery registry into the exact state that
// wedged production: a durable job marked terminally conflict.
func terminalizeJob(t *testing.T, streamDir, state string) RecoveryJob {
	t.Helper()
	job, ok := loadJob(streamDir)
	if !ok {
		t.Fatalf("no recovery registry at %s", streamDir)
	}
	js := newJobState(streamDir, job)
	js.update(func(j *RecoveryJob) {
		j.State = state
		j.LastError = "authority reported a typed recovery conflict"
	})
	if err := js.persist(); err != nil {
		t.Fatalf("persist terminal job: %v", err)
	}
	return js.snapshot()
}

// newTerminalStoreFixture leaves a closed, non-empty store on disk with one
// terminally-conflict recovery job — the shape force-park refuses.
func newTerminalStoreFixture(t *testing.T, state string) (stateDir, streamDir string, job RecoveryJob) {
	t.Helper()
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	stateDir = t.TempDir()
	e, err := Open(context.Background(), Config{
		StateDir: stateDir, VolumeID: "vol", Branch: "main", Remote: auth,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	ctx := context.Background()
	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if _, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("acknowledged payload")); err != nil || !handled {
		t.Fatalf("write: handled=%v err=%v", handled, err)
	}
	if _, err := e.ForceClose("fixture"); err != nil {
		t.Fatalf("force close: %v", err)
	}
	streamDir = filepath.Join(stateDir, streamDirName(1))
	return stateDir, streamDir, terminalizeJob(t, streamDir, state)
}

// TestForceParkRefusalNamesAResolutionThatExists is the cycle's first edge. The
// refusal must be TYPED so the daemon and the CLI can name the exact command,
// instead of a bare string describing a procedure nobody shipped.
func TestForceParkRefusalNamesAResolutionThatExists(t *testing.T) {
	stateDir, _, _ := newTerminalStoreFixture(t, JobConflict)
	_, err := ForceParkAbandonedStore(stateDir, "vol", "main", "proof-1", "test")
	if err == nil {
		t.Fatal("force-park accepted a terminally conflict job")
	}
	if !errors.Is(err, ErrRecoveryResolutionRequired) {
		t.Fatalf("force-park refused with %v; the refusal must be typed so a caller "+
			"can name the resolution command for the mount in hand", err)
	}
}

// TestTerminalRecoveryJobIsResolvableThroughTheShippedCommand is the whole
// defect: after the resolution, force-park — the command that refused — must
// succeed. This is the by-hand `mv` the operator was forced into, shipped.
func TestTerminalRecoveryJobIsResolvableThroughTheShippedCommand(t *testing.T) {
	for _, state := range []string{JobConflict, JobCorrupt} {
		t.Run(state, func(t *testing.T) {
			stateDir, streamDir, before := newTerminalStoreFixture(t, state)

			// The wedge, reproduced.
			if _, err := ForceParkAbandonedStore(stateDir, "vol", "main", "proof-1", "test"); !errors.Is(err, ErrRecoveryResolutionRequired) {
				t.Fatalf("fixture is not wedged: %v", err)
			}

			result, err := ResolveTerminalRecoveryJobs(stateDir, "vol", "main", "operator note", nil)
			if err != nil {
				t.Fatalf("the shipped resolution refused the job it exists to resolve: %v", err)
			}
			if len(result.Resolved) != 1 {
				t.Fatalf("resolution acted on %d job(s), want exactly the terminal one: %+v", len(result.Resolved), result)
			}
			resolved := result.Resolved[0]
			if resolved.JobID != before.JobID {
				t.Fatalf("resolved job %q, want %q", resolved.JobID, before.JobID)
			}

			// ── THE PROOF DISCIPLINE ─────────────────────────────────────────
			//
			// Never delete what cannot be proven disposable. The bytes are the
			// only remaining copy of what was acknowledged.
			if _, err := os.Lstat(streamDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the resolved stream is still in the recovery scan path: %v", err)
			}
			if _, err := os.Lstat(resolved.QuarantinePath); err != nil {
				t.Fatalf("the resolution DELETED the acknowledged bytes instead of retaining them at %q: %v",
					resolved.QuarantinePath, err)
			}
			segs, _ := filepath.Glob(filepath.Join(resolved.QuarantinePath, "wb-*.pfw"))
			if len(segs) == 0 {
				t.Fatal("no WAL segment survived the resolution; the only copy of the acknowledged bytes is gone")
			}

			// ── THE LOSS IS STATED EXACTLY ───────────────────────────────────
			if resolved.LostRecords == 0 || resolved.LostBytes == 0 {
				t.Fatalf("the resolution reported no loss for a job that owed the authority records: %+v", resolved)
			}
			if len(resolved.LostScopes) == 0 {
				t.Fatalf("the resolution named no scope the lost writes were made under: %+v", resolved)
			}
			if resolved.Remedy == "" {
				t.Fatal("the resolution published no operator remedy")
			}
			if !strings.Contains(resolved.Remedy, resolved.QuarantinePath) {
				t.Fatalf("the remedy does not name where the surviving bytes are: %q", resolved.Remedy)
			}

			// ── THE VERDICT IS DURABLE ───────────────────────────────────────
			//
			// A loss that disappears with the command's stdout is not reported.
			persisted, ok := loadJob(resolved.QuarantinePath)
			if !ok {
				t.Fatal("the resolution left no durable verdict beside the retained bytes")
			}
			if !persisted.Quarantined || persisted.QuarantinePath != resolved.QuarantinePath {
				t.Fatalf("durable verdict disagrees with the reported one: %+v", persisted)
			}
			if persisted.ResolvedAtMs == 0 || persisted.ResolvedReason == "" {
				t.Fatalf("the durable verdict does not record that a HUMAN resolved it: %+v", persisted)
			}

			// ── THE BLOCK IS CLEARED ─────────────────────────────────────────
			//
			// The command that refused now succeeds. This is the assertion that
			// closes the cycle.
			if _, err := ForceParkAbandonedStore(stateDir, "vol", "main", "proof-1", "test"); err != nil {
				t.Fatalf("force-park still refuses after the shipped resolution ran: %v", err)
			}
		})
	}
}

// TestResolutionRefusesWhatItCannotProveDisposable is the other half of the
// discipline. A job with a future must survive: quarantining it would throw away
// a tail the next attach replays.
func TestResolutionRefusesWhatItCannotProveDisposable(t *testing.T) {
	stateDir, streamDir, job := newTerminalStoreFixture(t, JobParked)

	result, err := ResolveTerminalRecoveryJobs(stateDir, "vol", "main", "operator note", nil)
	if err != nil {
		t.Fatalf("a sweep over a store with nothing terminal must succeed and do nothing: %v", err)
	}
	if len(result.Resolved) != 0 {
		t.Fatalf("the resolution quarantined a job that is not terminal: %+v", result.Resolved)
	}
	if len(result.Skipped) != 1 || result.Skipped[0].State != JobParked {
		t.Fatalf("the untouched job was not reported: %+v", result.Skipped)
	}
	if _, err := os.Lstat(streamDir); err != nil {
		t.Fatalf("a replayable stream was moved out of the scan path: %v", err)
	}

	// Naming it explicitly is a REFUSAL, not a silent skip: an operator who
	// named it is owed the reason.
	if _, err := ResolveTerminalRecoveryJobs(stateDir, "vol", "main", "note", []string{job.JobID}); err == nil {
		t.Fatal("naming a non-terminal job was silently accepted")
	} else if !strings.Contains(err.Error(), JobParked) {
		t.Fatalf("the refusal does not say what state the job is actually in: %v", err)
	}

	// A job that is not in the store at all is a refusal too — a typo must not
	// read as "resolved nothing, all good".
	if _, err := ResolveTerminalRecoveryJobs(stateDir, "vol", "main", "note", []string{"wbj_nope"}); err == nil {
		t.Fatal("naming a job that does not exist was silently accepted")
	}
}

// TestResolutionRefusesAStoreALiveEngineOwns keeps the resolution off a store
// whose bytes another process is still writing.
func TestResolutionRefusesAStoreALiveEngineOwns(t *testing.T) {
	auth := newFakeAuthority()
	stateDir := t.TempDir()
	e, err := Open(context.Background(), Config{
		StateDir: stateDir, VolumeID: "vol", Branch: "main", Remote: auth,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })

	if _, err := ResolveTerminalRecoveryJobs(stateDir, "vol", "main", "note", nil); err == nil {
		t.Fatal("the resolution took a store a live engine owns")
	} else if !strings.Contains(err.Error(), "owned by another engine") {
		t.Fatalf("the refusal does not name the live owner as the reason: %v", err)
	}
}

// TestInspectStoreRecoveryJobsNeedsNoLock keeps the diagnostic half usable at
// the one moment it matters: while a daemon still owns the store and the
// operator is trying to find out why their unmount will not finish.
func TestInspectStoreRecoveryJobsNeedsNoLock(t *testing.T) {
	stateDir, _, job := newTerminalStoreFixture(t, JobConflict)
	// Re-open so a live engine holds the store lock.
	e, err := Open(context.Background(), Config{
		StateDir: stateDir, VolumeID: "vol", Branch: "main", Remote: newFakeAuthority(),
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })

	reports, err := InspectStoreRecoveryJobs(stateDir)
	if err != nil {
		t.Fatalf("the read-only inventory failed against a live store: %v", err)
	}
	found := false
	for _, rep := range reports {
		if rep.Job.JobID == job.JobID && rep.Job.State == JobConflict {
			found = true
		}
	}
	if !found {
		t.Fatalf("the blocking job is invisible to the inventory: %+v", reports)
	}
}
