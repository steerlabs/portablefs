package writeback

// ROUND 21b, DEFECT 3: the contained verdict named the quarantine path BEFORE
// the bytes were at it.
//
// recoveryRunner.contain publishes the unreplayable verdict first (step 1), so
// that everything after it is idempotent — correct. But the verdict it
// published included QuarantinePath already pointing at
// <stateDir>/unreplayable/<stream>, while the rename that makes that true is
// step 3. Between them sits an authority round trip (the grant sweep) and every
// crash point inside it. For that whole window the ONLY durable statement about
// where the last surviving copy of the acknowledged bytes lives named a path
// that did not exist, while the bytes themselves sat, unnamed, at the original
// stream directory.
//
// The verdict is a set of directions an operator follows after a data loss.
// Directions to a nonexistent location are worse than no directions: they read
// as proof the bytes are already gone.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// discardObserverRemote runs a hook inside the containment's authority round
// trip — exactly the window between "verdict published" and "bytes moved".
type discardObserverRemote struct {
	*fakeAuthority
	onDiscard func()
}

func (r *discardObserverRemote) Discard(ctx context.Context, writebackID string, scopes []RebindScope) error {
	if r.onDiscard != nil {
		r.onDiscard()
	}
	return r.fakeAuthority.Discard(ctx, writebackID, scopes)
}

// TestContainedVerdictNeverNamesAPathTheBytesAreNotAtYet asserts the ordering at
// the one instant it was wrong.
func TestContainedVerdictNeverNamesAPathTheBytesAreNotAtYet(t *testing.T) {
	ctx := context.Background()
	f := newParkFixture(t, "sat")
	wedgeUnreplayableStream(t, f)
	if _, err := f.engine.ForceClose("wedged under flood"); err == nil {
		t.Fatal("force-park promised a replay for a snapshot it cannot replay")
	}

	streamDir := f.streamDir(1)
	jobPath := filepath.Join(streamDir, "job.json")

	var (
		observed      *RecoveryJob
		observedExist error
	)
	remote := &discardObserverRemote{fakeAuthority: f.auth, onDiscard: func() {
		if observed != nil {
			return // the first sweep is the window this test is about
		}
		body, err := os.ReadFile(jobPath)
		if err != nil {
			return
		}
		var job RecoveryJob
		if err := json.Unmarshal(body, &job); err != nil {
			return
		}
		// Resolve the claim WHERE IT IS MADE. Asking after the containment
		// finished would ask about a path the rename has since made true, which
		// is precisely the window this test exists to look inside.
		if job.QuarantinePath != "" {
			_, observedExist = os.Lstat(job.QuarantinePath)
		}
		observed = &job
	}}

	f.auth.releaseLaneForTest(StreamLaneData)
	next, err := Open(ctx, Config{
		StateDir: f.dir, VolumeID: "vol", Branch: "main", Remote: remote,
	})
	if err != nil {
		t.Fatalf("a fresh attach must succeed over an unreplayable job: %v", err)
	}
	defer next.Close(ctx)

	if observed == nil {
		t.Fatal("the containment's grant sweep never ran, so the window was not observed")
	}
	if !observed.Quarantined {
		t.Fatalf("the verdict was not published before the grant sweep: %+v", observed)
	}
	if observed.QuarantinePath == "" {
		t.Fatal("the verdict named no location for the retained bytes at all")
	}
	// THE ASSERTION. Whatever the verdict names, at every instant it is
	// durable, has to be where the bytes actually are.
	if err := observedExist; err != nil {
		t.Fatalf("REPRO: mid-containment the verdict named %q, which does not exist: %v\n"+
			"the only surviving copy of the acknowledged bytes was at %q, and the "+
			"durable remedy pointed an operator somewhere else",
			observed.QuarantinePath, err, streamDir)
	}

	// And the published path still ends up at the final quarantine location
	// once the rename has made it true.
	job, ok := jobByEpoch(next.Status().Jobs, 1)
	if !ok {
		t.Fatal("the contained job vanished instead of being reported")
	}
	final := filepath.Join(f.dir, quarantineDirName, streamDirName(1))
	if job.QuarantinePath != final {
		t.Fatalf("settled verdict points at %q, want %q", job.QuarantinePath, final)
	}
	if _, err := os.Lstat(final); err != nil {
		t.Fatalf("contained stream bytes were not retained at the published path: %v", err)
	}
	// The remedy is the field an operator actually reads, and it embeds the
	// location. Republishing the path without recomputing it would leave the
	// pre-rename path inside the directions.
	if job.LostRecords != 0 && !strings.Contains(job.Remedy, final) {
		t.Fatalf("the settled remedy does not name the settled location: %q", job.Remedy)
	}
}
