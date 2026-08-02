package portablefsd

// ── "PENDING IS ZERO" IS NOT "THE DRAIN COMPLETED" ──────────────────────────
//
// A forced unmount parks its undrained tail as a durable recovery job. The live
// engine then legitimately reports nothing pending while the parked stream
// still holds every byte of it — live, 156 MiB sat unrecoverable while a
// drain-to-zero check read 0 and reported success over lost data.
//
// The daemon therefore reports the two facts separately and always together:
// what is still moving (pending) and what has stopped (unrecovered). A drain is
// complete only when BOTH are zero.
//
// A stopped job also has to say what it is and what to do about it. "state:
// conflict" with no scopes and no next action is a verdict without
// instructions, and the durable job already carried the conflict set the status
// was dropping.

import (
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

func TestWriteBackStatusSeparatesUnrecoveredDebtFromPending(t *testing.T) {
	st := writeback.Status{
		// The live engine has nothing of its own left to ship.
		PendingRecords: 0,
		PendingBytes:   0,
		Jobs: []writeback.RecoveryJob{
			{
				JobID: "job-forced", State: writeback.JobForced,
				PendingRecords: 12, PendingBytes: 156 << 20,
			},
			{
				JobID: "job-replaying", State: writeback.JobReplaying,
				PendingRecords: 3, PendingBytes: 4096,
			},
			{
				JobID: "job-conflict", State: writeback.JobConflict,
				PendingRecords: 5, PendingBytes: 900,
				Conflicts: []writeback.ConflictDetail{
					{Scope: "sat", Epoch: "e7", Kind: "SCOPE_DISCARDED"},
					{Scope: "sat", Epoch: "e8", Kind: "HOLDER_CHANGED"},
					{Scope: "moon", Epoch: "e9", Kind: "SCOPE_MISSING"},
				},
			},
			{
				JobID: "job-corrupt", State: writeback.JobCorrupt,
				PendingRecords: 1, PendingBytes: 64,
			},
		},
	}

	wb := newWriteBackStatus(st)

	// Forced + conflict + corrupt are stopped; replaying is still moving.
	if got, want := wb.UnrecoveredRecords, 12+5+1; got != want {
		t.Fatalf("unrecoveredRecords = %d, want %d", got, want)
	}
	if got, want := wb.UnrecoveredBytes, int64(156<<20)+900+64; got != want {
		t.Fatalf("unrecoveredBytes = %d, want %d", got, want)
	}
	if wb.PendingRecords != 0 || wb.PendingBytes != 0 {
		t.Fatalf("pending = %d/%d, want 0/0: the split must not double-count",
			wb.PendingRecords, wb.PendingBytes)
	}
	// The whole point: a caller reading pending alone would call this clean.
	if wb.PendingBytes == 0 && wb.UnrecoveredBytes == 0 {
		t.Fatal("a status with 156 MiB parked reported nothing unrecovered: a " +
			"drain-to-zero check is told the volume is clean over data that " +
			"never reached the authority")
	}

	byID := map[string]recoveryJobRef{}
	for _, j := range wb.Jobs {
		byID[j.JobID] = j
	}
	if len(byID) != 4 {
		t.Fatalf("jobs = %d, want 4", len(byID))
	}
	for _, id := range []string{"job-forced", "job-conflict", "job-corrupt"} {
		if !byID[id].Unrecovered {
			t.Fatalf("%s is not flagged unrecovered", id)
		}
		if byID[id].Remedy == "" {
			t.Fatalf("%s carries no remedy: an operator is told a decision is "+
				"required and nothing about what it is", id)
		}
	}
	if byID["job-replaying"].Unrecovered {
		t.Fatal("a REPLAYING job was counted as unrecovered: recovery in " +
			"progress is not stopped data")
	}
	if byID["job-replaying"].Remedy != "" {
		t.Fatal("a replaying job was given a remedy: nothing is required of an " +
			"operator while recovery is running")
	}

	// The conflict set reaches the wire, scopes and all, and the remedy names
	// the scopes rather than only the fact that conflicts exist.
	conflict := byID["job-conflict"]
	if len(conflict.Conflicts) != 3 {
		t.Fatalf("conflicts = %d, want 3: the typed conflict set was dropped",
			len(conflict.Conflicts))
	}
	if conflict.Conflicts[0].Scope != "sat" ||
		conflict.Conflicts[0].Kind != "SCOPE_DISCARDED" ||
		conflict.Conflicts[0].Epoch != "e7" {
		t.Fatalf("first conflict = %+v, want sat/SCOPE_DISCARDED/e7",
			conflict.Conflicts[0])
	}
	if !strings.Contains(conflict.Remedy, `"sat"`) ||
		!strings.Contains(conflict.Remedy, `"moon"`) {
		t.Fatalf("conflict remedy %q does not name the affected scopes",
			conflict.Remedy)
	}
	if strings.Count(conflict.Remedy, `"sat"`) != 1 {
		t.Fatalf("conflict remedy %q repeats a scope", conflict.Remedy)
	}
}

// TestWriteBackStatusReportsNothingUnrecoveredWhenNothingIsStopped keeps the
// field from becoming noise: a healthy engine with a live stream and an active
// replay owes no unrecovered debt at all, so `unrecoveredBytes` stays absent
// from the JSON and a drain check that watches it is not permanently red.
func TestWriteBackStatusReportsNothingUnrecoveredWhenNothingIsStopped(t *testing.T) {
	wb := newWriteBackStatus(writeback.Status{
		PendingRecords: 4, PendingBytes: 8192,
		Jobs: []writeback.RecoveryJob{
			{JobID: "live", State: writeback.JobActive, PendingRecords: 4, PendingBytes: 8192},
			{JobID: "draining", State: writeback.JobReplaying, PendingRecords: 2, PendingBytes: 128},
		},
	})
	if wb.UnrecoveredRecords != 0 || wb.UnrecoveredBytes != 0 {
		t.Fatalf("a healthy engine reported %d record(s) / %d byte(s) unrecovered",
			wb.UnrecoveredRecords, wb.UnrecoveredBytes)
	}
	for _, j := range wb.Jobs {
		if j.Unrecovered {
			t.Fatalf("job %s (%s) was flagged unrecovered", j.JobID, j.State)
		}
	}
}
