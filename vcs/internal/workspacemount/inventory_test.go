package workspacemount

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

func desired(n byte) *Desired {
	return &Desired{Mount: &pb.MountID{AuthorityId: bytes.Repeat([]byte{1}, 32), VolumeId: "volume", Incarnation: bytes.Repeat([]byte{n}, 16)}, Boot: bytes.Repeat([]byte{2}, 16), Witness: Witness{Intent: "mnt_AAAAAAAAAAAAAAAAAAAAAA", Source: "portablefs:mnt_AAAAAAAAAAAAAAAAAAAAAA", Target: "/workspaces/volume"}, TargetDevice: 1, TargetInode: 2, Outcome: control.UnknownOutcome()}
}
func inventory(t *testing.T) *Inventory {
	t.Helper()
	i, err := OpenInventory(filepath.Join(t.TempDir(), "workspace"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { i.Close() })
	return i
}
func TestInventoryReservesPathAcrossAuthorities(t *testing.T) {
	i := inventory(t)
	d := desired(1)
	if err := i.CommitDesired(d); err != nil {
		t.Fatal(err)
	}
	other := desired(2)
	other.Mount.AuthorityId[0]++
	if err := i.CommitDesired(other); err == nil {
		t.Fatal("different authority stacked same stable target")
	}
	if err := i.Reconcile(d.Mount, func(*Desired) error { return errors.New("kernel alias remains") }); err == nil {
		t.Fatal("ambiguous removal released reservation")
	}
	if err := i.CommitDesired(other); err == nil {
		t.Fatal("failed reconciliation lost reservation")
	}
	if err := i.Reconcile(d.Mount, func(*Desired) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := i.CommitDesired(other); err != nil {
		t.Fatal(err)
	}
}
func TestInventoryPartialBindingPersistsDespiteConflict(t *testing.T) {
	i := inventory(t)
	d := desired(1)
	if err := i.CommitDesired(d); err != nil {
		t.Fatal(err)
	}
	if err := i.BindWitness(d.Mount, Witness{Session: "session"}); err != nil {
		t.Fatal(err)
	}
	if err := i.BindWitness(d.Mount, Witness{Session: "foreign", Kernel: "kernel"}); err == nil {
		t.Fatal("replaced immutable binding")
	}
	w := i.Snapshot()[0].Witness
	if w.Session != "session" || w.Kernel != "kernel" {
		t.Fatal(w)
	}
	path := i.directory
	i.Close()
	j, err := OpenInventory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if got := j.Snapshot()[0].Witness; got != w {
		t.Fatal(got, w)
	}
}
func TestInventoryCrashBetweenIndependentCommits(t *testing.T) {
	for _, first := range []string{"workspace", "cli"} {
		t.Run(first, func(t *testing.T) {
			i := inventory(t)
			d := desired(1)
			if err := i.CommitDesired(d); err != nil {
				t.Fatal(err)
			}
			cli := Witness{Session: "session", Kernel: "kernel"}
			if first == "workspace" {
				if err := i.BindWitness(d.Mount, cli); err != nil {
					t.Fatal(err)
				}
				cli = Witness{}
			}
			path := i.directory
			i.Close()
			j, err := OpenInventory(path)
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			called := false
			err = j.Reconcile(d.Mount, func(run *Desired) error {
				called = true
				// Neither side's absent fields may certify absence in the other.
				if cli.Kernel != "" || run.Witness.Kernel != "" {
					return errors.New("independent exact absence not established")
				}
				return errors.New("starting intent still requires actual absence")
			})
			if !called || err == nil || j.Snapshot()[0].Removed {
				t.Fatal("crash disagreement silently finalized", err)
			}
			next := desired(2)
			if err = j.CommitDesired(next); err == nil {
				t.Fatal("crash admitted replacement")
			}
		})
	}
}
func TestInventoryFailedSyncRetainsAcquiredResources(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			i := inventory(t)
			d := desired(1)
			if err := i.CommitDesired(d); err != nil {
				t.Fatal(err)
			}
			calls := 0
			i.syncFile = func(*os.File) error {
				calls++
				if calls == failAt {
					return errors.New("ENOSPC or fsync failure")
				}
				return nil
			}
			if err := i.BindWitness(d.Mount, Witness{Kernel: "owned"}); err == nil {
				t.Fatal("acknowledged failed durable witness")
			}
			if i.Snapshot()[0].Witness.Kernel != "owned" {
				t.Fatal("partial effect lost its owner")
			}
			if err := i.CommitDesired(desired(2)); err == nil {
				t.Fatal("failed store admitted successor")
			}
		})
	}
}
func TestInventoryUnknownCrashOutcomeSurvivesReplacement(t *testing.T) {
	i := inventory(t)
	d := desired(1)
	if err := i.CommitDesired(d); err != nil {
		t.Fatal(err)
	}
	loss := []*pb.Loss{{Sequence: 1, AcceptedBytes: 9, AcceptedEntries: 1, Reason: "known lost tail"}}
	if err := i.RetainOutcome(d.Mount, loss, control.UnknownOutcome()); err != nil {
		t.Fatal(err)
	}
	if err := i.Reconcile(d.Mount, func(*Desired) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := i.CommitDesired(desired(2)); err != nil {
		t.Fatal(err)
	}
	old := i.Snapshot()[0]
	if !old.Removed || old.Outcome.Observation != "unobserved" || len(old.Loss) != 1 || old.Loss[0].AcceptedBytes != 9 {
		t.Fatal(old)
	}
}

func TestInventoryAckRequiresRemovalAndRetainsFailedCommit(t *testing.T) {
	i := inventory(t)
	d := desired(1)
	if err := i.CommitDesired(d); err != nil {
		t.Fatal(err)
	}
	if err := i.Acknowledge([]*pb.MountID{d.Mount}); err == nil {
		t.Fatal("acknowledgement erased live intent")
	}
	if err := i.Reconcile(d.Mount, func(*Desired) error { return nil }); err != nil {
		t.Fatal(err)
	}
	i.syncFile = func(*os.File) error { return errors.New("ENOSPC") }
	if err := i.Acknowledge([]*pb.MountID{d.Mount}); err == nil || len(i.Snapshot()) != 1 {
		t.Fatal("failed acknowledgement lost retained evidence", err)
	}
}

func TestInventoryBoundedAggregateSurvivesDurableReopen(t *testing.T) {
	i := inventory(t)
	d := desired(1)
	if err := i.CommitDesired(d); err != nil {
		t.Fatal(err)
	}
	var raw []*pb.Loss
	for n := uint64(1); n <= 40; n++ {
		raw = append(raw, &pb.Loss{Sequence: n, AcceptedEntries: 1, AcceptedBytes: 2, Reason: "retained cut"})
	}
	loss, aggregated, err := control.BoundLoss(raw)
	if err != nil || !aggregated {
		t.Fatal(err)
	}
	if err = i.RetainOutcome(d.Mount, loss, control.UnknownOutcome()); err != nil {
		t.Fatal(err)
	}
	dir := i.directory
	i.Close()
	next, err := OpenInventory(dir)
	if err != nil {
		t.Fatal("valid aggregate refused on restart", err)
	}
	defer next.Close()
	got := next.Snapshot()[0].Loss
	if !control.RetainsLoss(got, loss) || len(got) != control.MaxLosses || got[len(got)-1].AcceptedBytes != 18 {
		t.Fatal(got)
	}
	if err = next.RetainOutcome(d.Mount, []*pb.Loss{nil}, control.UnknownOutcome()); err == nil {
		t.Fatal("invalid persisted loss accepted")
	}
}

func TestInventoryRefusesEscapingIntentBeforeCommit(t *testing.T) {
	i := inventory(t)
	for _, intent := range []string{"../foreign", "mnt_invalid", "/absolute"} {
		d := desired(1)
		d.Witness.Intent = intent
		d.Witness.Source = "portablefs:" + intent
		if err := i.CommitDesired(d); err == nil {
			t.Fatal("escaping intent accepted", intent)
		}
	}
	if len(i.Snapshot()) != 0 {
		t.Fatal("invalid intent acquired durable ownership")
	}
}
