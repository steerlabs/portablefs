package workspaceguest

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

func TestOutcomeInventoryCrashSurvivesReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outcomes.json")
	store, err := OpenOutcomeInventory(path)
	if err != nil {
		t.Fatal(err)
	}
	id := &pb.MountID{AuthorityId: make([]byte, 32), VolumeId: "volume", Incarnation: make([]byte, 16)}
	id.AuthorityId[0] = 1
	id.Incarnation[0] = 2
	old := initialStatus(id)
	old.Outcome = control.UnknownOutcome()
	old.Loss = []*pb.Loss{{Sequence: 1, AcceptedEntries: 2, AcceptedBytes: 3, Reason: "known prior loss"}}
	if err = store.Commit(old); err != nil {
		t.Fatal(err)
	}
	replacement := clone(old)
	replacement.Mount.Incarnation[0] = 3
	replacement.Loss = nil
	if err = store.Commit(replacement); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenOutcomeInventory(path)
	if err != nil {
		t.Fatal(err)
	}
	rows := reopened.Snapshot()
	if len(rows) != 2 {
		t.Fatal("replacement erased crash run", rows)
	}
	for _, row := range rows {
		if row.Mount.Incarnation[0] == 2 && (row.Outcome.Observation != "unobserved" || row.Outcome.Durability != "unresolved" || len(row.Loss) != 1) {
			t.Fatal("crash became a loss-free result", row)
		}
	}
}
func TestOutcomeInventoryPersistenceFailureRefusesCommit(t *testing.T) {
	for _, cause := range []error{syscall.ENOSPC, syscall.EIO} {
		t.Run(cause.Error(), func(t *testing.T) {
			store, err := OpenOutcomeInventory(filepath.Join(t.TempDir(), "outcomes.json"))
			if err != nil {
				t.Fatal(err)
			}
			id := &pb.MountID{AuthorityId: make([]byte, 32), VolumeId: "volume", Incarnation: make([]byte, 16)}
			id.AuthorityId[0] = 1
			id.Incarnation[0] = 2
			store.syncFile = func(*os.File) error { return cause }
			if err = store.Commit(initialStatus(id)); !errors.Is(err, cause) {
				t.Fatal("failed persistence acknowledged", err)
			}
			if len(store.Snapshot()) != 0 {
				t.Fatal("failed transaction reported committed")
			}
		})
	}
}
