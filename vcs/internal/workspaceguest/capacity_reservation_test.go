package workspaceguest

import (
	"context"
	"math"
	"testing"
	"time"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

// These probes use real supervisor acceptance/registration and no kernel mounts.
func astraFullRegisteredRoster(t *testing.T) (*Supervisor, []*pb.MountID) {
	t.Helper()
	var s *Supervisor
	driver := jobDriverFunc(func(ctx context.Context, job *pb.MountJob, _ *pb.Provision) error {
		return s.Register(ctx, job.Mount, Witness{}, &fakeMount{})
	})
	var err error
	s, err = New(id(1), id(2), id(3), true, driver)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	var ids []*pb.MountID
	for i := range control.MaxMounts {
		mid := retirementVolume(i, 4)
		ids = append(ids, mid)
		if err := s.AcceptJob(jobRequest(uint64(i+1), mid, "mount")); err != nil {
			t.Fatal(err)
		}
	}
	waitDesiredJobsJoined(t, s)
	status := s.Status()
	if len(status.Mounts) != 64 || len(status.Jobs) != 64 || len(status.Retired) != 0 {
		t.Fatalf("not the required reachable full state: mounts=%d jobs=%d retired=%d", len(status.Mounts), len(status.Jobs), len(status.Retired))
	}
	for _, j := range status.Jobs {
		if j.Phase != "complete" {
			t.Fatal(j)
		}
	}
	encodable(t, status)
	return s, ids
}

func TestFullRegisteredRosterStartsRemovalWithoutAcknowledgements(t *testing.T) {
	s, ids := astraFullRegisteredRoster(t)
	err := s.AcceptJob(jobRequest(100, ids[0], "umount"))
	if err != nil {
		t.Fatalf("removal deadlocked with no acknowledgeable records: %v; retired=%d", err, len(s.Status().Retired))
	}
}

func TestFullRegisteredRosterReplacesCleanedMountWithoutAcknowledgements(t *testing.T) {
	s, ids := astraFullRegisteredRoster(t)
	old := ids[0]
	if err := s.Terminal(old, "authority session ended", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Cleanup(old, CleanupProof{Witness: Witness{}, ProcessExited: true, KernelAbsent: true}); err != nil {
		t.Fatal(err)
	}
	next := retirementVolume(0, 5)
	if err := s.Replace(context.Background(), old, next, Witness{}, &fakeMount{}); err != nil {
		t.Fatalf("replacement deadlocked after exact cleanup with no acknowledgeable records: %v; retired=%d", err, len(s.Status().Retired))
	}
}

// Saturate reservations with both active owners and acknowledgeable evidence.
// Every existing owner must still be able to retry, join, remove and drain.
func TestReservedLifecycleProgressAtEvidenceSaturation(t *testing.T) {
	s := r2RegisteringSupervisor(t)
	for i := range control.MaxMounts {
		if err := s.AcceptJob(jobRequest(uint64(i+1), retirementVolume(100+i, 4), "provision")); err != nil {
			t.Fatal(err)
		}
	}
	waitDesiredJobsJoined(t, s)
	for i := range control.MaxMounts {
		if err := s.AcceptJob(jobRequest(uint64(100+i), retirementVolume(i, 4), "mount")); err != nil {
			t.Fatal(err)
		}
	}
	waitDesiredJobsJoined(t, s)
	for i := range 200 {
		if err := s.AcceptJob(jobRequest(uint64(1000+i), retirementVolume(0, 4), "mount")); err != nil {
			t.Fatal(err)
		}
		waitDesiredJobsJoined(t, s)
	}
	s.mu.Lock()
	if s.slotsLocked() != MaxReservations {
		t.Fatal("reservations changed during retry")
	}
	history := clone(s.jobs[control.MountKey(retirementVolume(0, 4))].status)
	s.mu.Unlock()
	if len(history.Prior) != 2 || history.Prior[1].Count != 199 {
		t.Fatalf("unbounded or missing aggregate: %v", history)
	}
	encodable(t, s.Status())
	if err := s.AcceptJob(jobRequest(2000, retirementVolume(250, 4), "mount")); err == nil {
		t.Fatal("new key bypassed saturated reservations")
	}
	for i := range control.MaxMounts {
		if err := s.AcceptJob(jobRequest(uint64(2100+i), retirementVolume(i, 4), "umount")); err != nil {
			t.Fatal(err)
		}
	}
	waitDesiredJobsJoined(t, s)
	st := s.Status()
	if len(st.Mounts) != 0 || len(st.Jobs) != 0 || len(s.Retired()) != MaxReservations {
		t.Fatalf("exact removal did not transfer reservations: %v", st)
	}
	var found bool
	for _, outcome := range s.Retired() {
		if outcome.Job.RequestId == 2100 {
			found = true
			if outcome.MountStatus == nil || len(outcome.Job.Prior) != 2 || outcome.Job.Prior[1].Count != 200 {
				t.Fatal("removal lost cumulative evidence")
			}
		}
	}
	if !found {
		t.Fatal("final retirement missing")
	}
	ack, err := s.Suspend(context.Background(), suspension(s), time.Now().Add(time.Second))
	if err != nil || len(ack.Mounts) != 0 {
		t.Fatalf("saturated drain: %v", err)
	}
	for len(s.Retired()) != 0 {
		page := s.Status().Retired
		if err := s.AcknowledgeRetired(page[len(page)-1].RetirementSequence); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExactUmountJoiningDuringSuspendKeepsFixedRosterThroughResume(t *testing.T) {
	s, _, mid := fixture(t)
	entered := make(chan struct{})
	s.jobDriver = jobDriverFunc(func(ctx context.Context, j *pb.MountJob, _ *pb.Provision) error {
		close(entered)
		<-ctx.Done()
		if err := s.Terminal(j.Mount, "removed", nil); err != nil {
			return err
		}
		return s.Cleanup(j.Mount, CleanupProof{Witness: s.mounts[control.MountKey(mid)].witness, ProcessExited: true, KernelAbsent: true})
	})
	if err := s.AcceptJob(jobRequest(2, mid, "umount")); err != nil {
		t.Fatal(err)
	}
	await(t, entered)
	x := begin(t, s, suspension(s))
	waitDesiredJobsJoined(t, s)
	if len(s.Status().Mounts) != 1 || len(s.Retired()) != 0 {
		t.Fatal("fixed roster retired before token consumption")
	}
	if err := s.Drain(context.Background(), x, mid); err != nil {
		t.Fatal(err)
	}
	ack, err := s.SuspendAck(x)
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := s.Resume(context.Background(), token(ack.Suspension))
	if err != nil {
		t.Fatal(err)
	}
	if len(resumed.Mounts) != 1 || resumed.Mounts[0].Cleanup != "complete" {
		t.Fatal("resume lost fixed-roster proof")
	}
	st := s.Status()
	encodable(t, st)
	if len(st.Mounts) != 0 || len(st.Jobs) != 0 || len(st.Retired) != 1 || st.Retired[0].MountStatus == nil {
		t.Fatal("joined exact removal did not retire after token consumption")
	}
}

func TestRegisteredRetryAndExactRemovalUseLastReservedSequence(t *testing.T) {
	s, _, mid := fixture(t)
	s.retirementSequence, s.acknowledgedSequence = math.MaxUint64-1, math.MaxUint64-1
	for _, rid := range []uint64{2, 3} {
		if err := s.AcceptJob(jobRequest(rid, mid, "mount")); err != nil {
			t.Fatal(err)
		}
		waitDesiredJobsJoined(t, s)
	}
	if err := s.Terminal(mid, "removed", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Cleanup(mid, CleanupProof{Witness: s.mounts[control.MountKey(mid)].witness, ProcessExited: true, KernelAbsent: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptJob(jobRequest(4, mid, "umount")); err != nil {
		t.Fatal(err)
	}
	waitDesiredJobsJoined(t, s)
	r := s.Retired()
	if len(r) != 1 || r[0].RetirementSequence != math.MaxUint64 || r[0].MountStatus == nil || r[0].Job.Prior[0].Count != 2 {
		t.Fatal("reserved final sequence lost")
	}
	encodable(t, s.Status())
}

func TestExactRemovalRetiresOnlyAfterLateDriverEvidenceJoins(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	mid := mountID(4)
	m := &invariantMount{entered: make(chan struct{}), proceed: make(chan struct{}), result: ready()}
	m.result.Loss = []*pb.Loss{{Sequence: 1, Reason: "late admitted tail lost", AcceptedEntries: 1, AcceptedBytes: 4096}}
	if err := s.Register(context.Background(), mid, Witness{}, m); err != nil {
		t.Fatal(err)
	}
	activated := make(chan error, 1)
	go func() { activated <- s.Activate(context.Background(), mid, 0) }()
	await(t, m.entered)
	s.jobDriver = jobDriverFunc(func(_ context.Context, j *pb.MountJob, _ *pb.Provision) error {
		if err := s.Terminal(j.Mount, "removed", nil); err != nil {
			return err
		}
		return s.Cleanup(j.Mount, CleanupProof{Witness: Witness{}, ProcessExited: true, KernelAbsent: true})
	})
	if err := s.AcceptJob(jobRequest(2, mid, "umount")); err != nil {
		t.Fatal(err)
	}
	waitDesiredJobsJoined(t, s)
	if len(s.Retired()) != 0 || len(s.Status().Mounts) != 1 {
		t.Fatal("retired before actual driver call joined")
	}
	close(m.proceed)
	if err := await(t, activated); err == nil {
		t.Fatal("late prepare revived terminal membership")
	}
	st := s.Status()
	encodable(t, st)
	if len(st.Mounts) != 0 || len(st.Retired) != 1 || len(st.Retired[0].MountStatus.Loss) != 1 {
		t.Fatal("immutable retirement missed late evidence")
	}
}
