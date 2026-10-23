package workspaceguest

import (
	"context"
	"errors"
	"fmt"
	"google.golang.org/protobuf/proto"
	"path/filepath"
	"testing"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	"github.com/steerlabs/portablefs/vcs/internal/workspacemount"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

func retirementInventory(t *testing.T, mid *pb.MountID) (*workspacemount.Inventory, *workspacemount.Desired) {
	t.Helper()
	i, err := workspacemount.OpenInventory(filepath.Join(t.TempDir(), "root-inventory"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { i.Close() })
	d := &workspacemount.Desired{Mount: mid, Boot: id(1), Witness: Witness{Intent: "mnt_AAAAAAAAAAAAAAAAAAAAAA", Source: "portablefs:mnt_AAAAAAAAAAAAAAAAAAAAAA", Target: "/workspaces/example"}, TargetDevice: 1, TargetInode: 2, Outcome: control.UnknownOutcome()}
	return i, d
}

// Boundary probe of the production Manager.Run/remove -> Supervisor.Cleanup
// and RetireAck calls. Kernel/process proof is supplied by the existing fake;
// persistence and supervisor retirement execute their real implementations.
func TestFinalCleanupEvidenceReachesRetirement(t *testing.T) {
	mid := mountID(4)
	i, d := retirementInventory(t, mid)
	if err := i.CommitDesired(d); err != nil {
		t.Fatal(err)
	}
	s, _, _ := fixture(t)
	s.ConfigureRetirementPersistence(i.Acknowledge)
	loss := []*pb.Loss{{Sequence: 1, AcceptedEntries: 1, AcceptedBytes: 23, Reason: "terminal finalization dropped retained cut"}}
	final := &pb.MountOutcome{Durability: "lost", Observation: "observed", Release: "abandoned"}
	s.jobDriver = jobDriverFunc(func(ctx context.Context, j *pb.MountJob, _ *pb.Provision) error {
		if err := s.Terminal(j.Mount, "voluntary unmount requested", nil); err != nil {
			return err
		}
		if err := i.RetainOutcome(j.Mount, loss, final); err != nil {
			return err
		}
		if err := i.Reconcile(j.Mount, func(*workspacemount.Desired) error { return nil }); err != nil {
			return err
		}
		w, err := s.BoundWitness(j.Mount)
		if err != nil {
			return err
		}
		return s.Cleanup(j.Mount, CleanupProof{Witness: w, ProcessExited: true, KernelAbsent: true, Loss: loss, Outcome: final})
	})
	if err := s.AcceptJob(jobRequest(1, mid, "umount")); err != nil {
		t.Fatal(err)
	}
	waitDesiredJobsJoined(t, s)
	retired := s.Status().Retired
	if len(retired) != 1 {
		t.Fatal(retired)
	}
	got := retired[0].MountStatus
	if err := acknowledgeExposedRetired(s, retired[0].RetirementSequence); err != nil {
		t.Fatal(err)
	}
	if len(got.Loss) != 1 || got.Outcome.Release != "abandoned" {
		t.Fatalf("host received loss=%v outcome=%v; root records after successful ACK=%d", got.Loss, got.Outcome, len(i.Snapshot()))
	}
}

func TestFailedStartupRetirementReclaimsRootRecord(t *testing.T) {
	mid := mountID(4)
	i, d := retirementInventory(t, mid)
	driver := jobDriverFunc(func(ctx context.Context, j *pb.MountJob, _ *pb.Provision) error {
		if err := i.CommitDesired(d); err != nil {
			return err
		}
		if err := i.Reconcile(mid, func(*workspacemount.Desired) error { return nil }); err != nil {
			return err
		}
		return &workspacemount.StartupFailure{Cause: errors.New("child startup failed before registration; exact cleanup completed"), Owner: &fakeMount{}, Proof: CleanupProof{Witness: d.Witness, ProcessExited: true, KernelAbsent: true, Outcome: d.Outcome}}
	})
	s, err := New(id(1), id(2), id(3), true, driver)
	if err != nil {
		t.Fatal(err)
	}
	s.ConfigureRetirementPersistence(i.Acknowledge)
	if err := s.AcceptJob(jobRequest(1, mid, "mount")); err != nil {
		t.Fatal(err)
	}
	waitDesiredJobsJoined(t, s)
	r := s.Status().Retired
	if len(r) != 1 || r[0].MountStatus == nil {
		t.Fatal(r)
	}
	if err := acknowledgeExposedRetired(s, r[0].RetirementSequence); err != nil {
		t.Fatal(err)
	}
	if len(i.Snapshot()) != 0 {
		t.Fatalf("ACK retired the job but left %d exactly removed root records", len(i.Snapshot()))
	}
}

func acknowledgeExposedRetired(s *Supervisor, through uint64) error {
	s.mu.Lock()
	s.exposedSequence = max(s.exposedSequence, s.acknowledgedSequence)
	s.mu.Unlock()
	s.observeWrittenStatus(s.Status())
	return s.AcknowledgeRetired(through)
}

func TestCleanupFinalEvidenceSurvivesFailureAndReplacement(t *testing.T) {
	for _, mode := range []string{"voluntary", "spontaneous", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			s, _, mid := fixture(t)
			if err := s.Terminal(mid, "cleanup", nil); err != nil {
				t.Fatal(err)
			}
			w, _ := s.BoundWitness(mid)
			loss := []*pb.Loss{{Sequence: 1, AcceptedEntries: 1, AcceptedBytes: 23, Reason: "final accepted tail lost"}}
			final := &pb.MountOutcome{Durability: "lost", Observation: "observed", Release: "abandoned"}
			// Resource absence is not yet proven; evidence must still reach Status.
			p := CleanupProof{Witness: w, Loss: loss, Outcome: final}
			if err := s.Cleanup(mid, p); err == nil {
				t.Fatal("unproven cleanup completed")
			}
			status := s.Status().Mounts[0]
			if len(status.Loss) != 1 || !proto.Equal(status.Outcome, final) || status.Cleanup == "complete" {
				t.Fatal(status)
			}
			p.ProcessExited, p.KernelAbsent = true, true
			if err := s.Cleanup(mid, p); err != nil {
				t.Fatal(err)
			}
			if mode == "voluntary" {
				s.jobDriver = jobDriverFunc(func(context.Context, *pb.MountJob, *pb.Provision) error { return nil })
				if err := s.AcceptJob(jobRequest(1, mid, "umount")); err != nil {
					t.Fatal(err)
				}
				waitDesiredJobsJoined(t, s)
			} else {
				if err := s.Replace(t.Context(), mid, mountID(5), Witness{}, &fakeMount{}); err != nil {
					t.Fatal(err)
				}
			}
			retained := s.Status()
			r := retained.Retired[0]
			if len(r.MountStatus.Loss) != 1 || !proto.Equal(r.MountStatus.Outcome, final) {
				t.Fatal(r)
			}
			if err := s.AcknowledgeRetired(r.RetirementSequence); err == nil {
				t.Fatal("unwritten Status permitted ACK")
			}
			// An earlier written snapshot with different evidence cannot authorize ACK.
			wrong := proto.Clone(retained).(*pb.StatusReply)
			wrong.Retired[0].MountStatus.Loss = nil
			s.observeWrittenStatus(wrong)
			if err := s.AcknowledgeRetired(r.RetirementSequence); err == nil {
				t.Fatal("different final evidence permitted ACK")
			}
			s.observeWrittenStatus(retained)
			if err := s.AcknowledgeRetired(r.RetirementSequence); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFailedStartupRetirementBoundsAndUnresolvedOwnership(t *testing.T) {
	i, d := retirementInventory(t, mountID(4))
	driver := jobDriverFunc(func(ctx context.Context, j *pb.MountJob, _ *pb.Provision) error {
		run := *d
		run.Mount = j.Mount
		if err := i.CommitDesired(&run); err != nil {
			return err
		}
		clean := j.Mount.VolumeId != "unresolved"
		if clean {
			if err := i.Reconcile(j.Mount, func(*workspacemount.Desired) error { return nil }); err != nil {
				return err
			}
		}
		return &workspacemount.StartupFailure{Cause: errors.New("startup failed"), Owner: &fakeMount{}, Proof: CleanupProof{Witness: run.Witness, ProcessExited: clean, KernelAbsent: clean, Outcome: run.Outcome}}
	})
	s, err := New(id(1), id(2), id(3), true, driver)
	if err != nil {
		t.Fatal(err)
	}
	s.ConfigureRetirementPersistence(i.Acknowledge)
	for n := 0; n < 256; n++ {
		mid := mountID(4)
		mid.VolumeId = fmt.Sprintf("failed-%d", n)
		if err := s.AcceptJob(jobRequest(uint64(n+1), mid, "mount")); err != nil {
			t.Fatal(n, err)
		}
		waitDesiredJobsJoined(t, s)
		page := s.Status()
		if len(page.Retired) != 1 || page.Retired[0].MountStatus == nil {
			t.Fatal(page)
		}
		s.observeWrittenStatus(page)
		if err := s.AcknowledgeRetired(page.Retired[0].RetirementSequence); err != nil {
			t.Fatal(err)
		}
		if len(i.Snapshot()) != 0 {
			t.Fatal("acknowledged startup leaked inventory", n)
		}
	}
	mid := mountID(4)
	mid.VolumeId = "unresolved"
	if err := s.AcceptJob(jobRequest(257, mid, "mount")); err != nil {
		t.Fatal(err)
	}
	waitDesiredJobsJoined(t, s)
	status := s.Status()
	if len(status.Mounts) != 1 || status.Mounts[0].Cleanup != "retained" || len(status.Jobs) != 1 || len(status.Retired) != 0 || i.Snapshot()[0].Removed {
		t.Fatal(status)
	}
	next := mountID(5)
	next.VolumeId = mid.VolumeId
	if err := s.AcceptJob(jobRequest(258, next, "mount")); err == nil {
		t.Fatal("unresolved resources released the volume")
	}
}

func TestFailedStartupUnacknowledgedInventoryFitsRestoreCapacity(t *testing.T) {
	i, d := retirementInventory(t, mountID(4))
	driver := jobDriverFunc(func(ctx context.Context, j *pb.MountJob, _ *pb.Provision) error {
		run := *d
		run.Mount = j.Mount
		if err := i.CommitDesired(&run); err != nil {
			return err
		}
		if err := i.Reconcile(j.Mount, func(*workspacemount.Desired) error { return nil }); err != nil {
			return err
		}
		return &workspacemount.StartupFailure{Cause: errors.New("startup failed"), Owner: &fakeMount{}, Proof: CleanupProof{Witness: run.Witness, ProcessExited: true, KernelAbsent: true, Outcome: run.Outcome}}
	})
	s, err := New(id(1), id(2), id(3), true, driver)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < MaxReservations; n++ {
		mid := mountID(4)
		mid.VolumeId = fmt.Sprintf("retained-%d", n)
		if err = s.AcceptJob(jobRequest(uint64(n+1), mid, "mount")); err != nil {
			t.Fatal(n, err)
		}
		waitDesiredJobsJoined(t, s)
	}
	extra := mountID(5)
	extra.VolumeId = "over-capacity"
	if err = s.AcceptJob(jobRequest(129, extra, "mount")); err == nil {
		t.Fatal("admitted more than restore capacity")
	}
	runs := i.Snapshot()
	if len(runs) != 128 || len(s.Retired()) != 128 {
		t.Fatal(len(runs), len(s.Retired()))
	}
	restored, err := New(id(6), id(7), id(8), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	restored.ConfigureRetirementPersistence(i.Acknowledge)
	for _, run := range runs {
		if err = restored.RestoreCleaned(run.Mount, run.Loss, run.Outcome); err != nil {
			t.Fatal(err)
		}
	}
	for len(restored.Retired()) > 0 {
		page := restored.Status()
		restored.observeWrittenStatus(page)
		if err = restored.AcknowledgeRetired(page.Retired[len(page.Retired)-1].RetirementSequence); err != nil {
			t.Fatal(err)
		}
	}
	if len(i.Snapshot()) != 0 {
		t.Fatal("restore ACK retained root records")
	}
}
