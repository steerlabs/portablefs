package workspaceguest

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

func r2Witness(id *pb.MountID) Witness {
	return Witness{Process: "pid/" + id.VolumeId, Kernel: "k", Session: "s", Enrollment: "e"}
}

// A driver modelling a real one: Mount registers membership through the only
// membership owner; Umount terminalizes and proves exact cleanup.
func r2RegisteringSupervisor(t *testing.T) *Supervisor {
	t.Helper()
	var s *Supervisor
	drv := jobDriverFunc(func(ctx context.Context, j *pb.MountJob, _ *pb.Provision) error {
		switch j.Operation {
		case "mount":
			return s.Register(ctx, j.Mount, r2Witness(j.Mount), &fakeMount{cold: ColdResult{ColdComplete: true}, recoverResult: ready()})
		case "umount":
			if err := s.Terminal(j.Mount, "removed", nil); err != nil {
				return err
			}
			return s.Cleanup(j.Mount, CleanupProof{Witness: r2Witness(j.Mount), ProcessExited: true, KernelAbsent: true})
		}
		return nil
	})
	var err error
	s, err = New(id(1), id(2), id(3), true, drv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	return s
}

// N1: 64 mounts admitted through jobs and registered. Retirement is empty, so
// there is nothing to acknowledge, yet Umount of an existing mount must retire
// the joined Mount job into a 65th slot and is refused forever.
func TestReservationUmountOfRegisteredMountAtFullBound(t *testing.T) {
	s := r2RegisteringSupervisor(t)
	for i := range control.MaxMounts {
		if err := s.AcceptJob(jobRequest(uint64(i+1), retirementVolume(i, 4), "mount")); err != nil {
			t.Fatal(i, err)
		}
	}
	waitDesiredJobsJoined(t, s)
	writtenStatus(t, s, s.Status())
	st := s.Status()
	if len(st.Mounts) != control.MaxMounts || len(st.Retired) != 0 {
		t.Fatalf("setup: mounts=%d retired=%d", len(st.Mounts), len(st.Retired))
	}
	if err := s.AcceptJob(jobRequest(1000, retirementVolume(0, 4), "umount")); err != nil {
		t.Fatalf("umount of a registered mount refused at the bound with nothing to acknowledge (retired=%d): %v", len(s.Retired()), err)
	}
}

// N2: 64 registered mounts (no jobs), one becomes terminal and exactly cleaned.
// Replace is the only recovery path; it needs a retirement slot that cannot be
// freed because no retirement record exists.
func TestReservationReplaceTerminalMountAtFullBound(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	for i := range control.MaxMounts {
		m := retirementVolume(i, 4)
		if err := s.Register(context.Background(), m, r2Witness(m), &fakeMount{cold: ColdResult{ColdComplete: true}, recoverResult: ready()}); err != nil {
			t.Fatal(i, err)
		}
	}
	old := retirementVolume(0, 4)
	if err := s.Terminal(old, "ended", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Cleanup(old, CleanupProof{Witness: r2Witness(old), ProcessExited: true, KernelAbsent: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(context.Background(), old, retirementVolume(0, 5), r2Witness(old), &fakeMount{}); err != nil {
		t.Fatalf("replace of a cleaned terminal mount refused at the bound with nothing to acknowledge (retired=%d): %v", len(s.Retired()), err)
	}
}

// N3: with a driver that registers (as a real one must), Mount then Umount of
// 64 distinct volumes, acknowledging every retirement, still exhausts capacity:
// a cleaned terminal registered mount has no removal path except Replace.
func TestReservationRealDriverMountUmountCyclesReleaseCapacity(t *testing.T) {
	s := r2RegisteringSupervisor(t)
	rid := uint64(1)
	for i := range 2 * control.MaxMounts {
		for _, op := range []string{"mount", "umount"} {
			rid++
			if err := s.AcceptJob(jobRequest(rid, retirementVolume(i, 4), op)); err != nil {
				t.Fatal(i, op, err)
			}
			waitDesiredJobsJoined(t, s)
			writtenStatus(t, s, s.Status())
			if r := s.Status().Retired; len(r) != 0 {
				if err := acknowledgeExposedRetired(s, r[len(r)-1].RetirementSequence); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	st := s.Status()
	rid++
	if err := s.AcceptJob(jobRequest(rid, retirementVolume(99, 4), "mount")); err != nil {
		t.Fatalf("64 fully acknowledged mount/umount cycles exhaust capacity (mounts=%d jobs=%d retired=%d): %v", len(st.Mounts), len(st.Jobs), len(st.Retired), err)
	}
}

// N4: a full unacknowledged bound does not block Suspend, cold ack, Resume,
// or later acknowledgement; admission resumes after acknowledgement.
func TestReservationSuspendResumeWithFullUnacknowledgedBound(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	for i := range MaxReservations {
		if err := s.AcceptJob(jobRequest(uint64(i+1), retirementVolume(i, 4), "mount")); err != nil {
			t.Fatal(err)
		}
		waitDesiredJobsJoined(t, s)
		writtenStatus(t, s, s.Status())
	}
	waitDesiredJobsJoined(t, s)
	writtenStatus(t, s, s.Status())
	if len(s.Retired()) != MaxReservations {
		t.Fatal("setup")
	}
	x := suspension(s)
	ack, err := s.Suspend(context.Background(), x, time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("suspend at full bound: %v", err)
	}
	// Acknowledgement is accepted outside running (guest has no phase gate).
	if err := acknowledgeExposedRetired(s, s.Status().Retired[15].RetirementSequence); err != nil {
		t.Fatalf("ack while suspended-cold: %v", err)
	}
	if _, err := resumeAndWait(t, s, context.Background(), token(ack.Suspension)); err != nil {
		t.Fatal(err)
	}
	if len(s.Retired()) != MaxReservations-16 {
		t.Fatal("evidence lost across suspend/resume")
	}
	if err := s.AcceptJob(jobRequest(500, retirementVolume(180, 4), "mount")); err != nil {
		t.Fatalf("admission after ack: %v", err)
	}
}

// N5: RetireAck edge cases: lost/duplicate/stale/out-of-order/future/zero/skip.
func TestReservationRetireAckEdgeCases(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	for i := range 40 {
		if err := s.AcceptJob(jobRequest(uint64(i+1), retirementVolume(i, 4), "mount")); err != nil {
			t.Fatal(err)
		}
	}
	waitDesiredJobsJoined(t, s)
	writtenStatus(t, s, s.Status())
	for _, tc := range []struct {
		through uint64
		ok      bool
		left    int
	}{
		{0, false, 40}, {41, false, 40}, {17, false, 40}, // zero, future, skip beyond exposed batch
		{5, true, 35}, {5, true, 35}, {3, true, 35}, // duplicate and stale are no-ops
		{21, true, 19}, {37, true, 3}, {40, true, 0}, {40, true, 0},
	} {
		err := acknowledgeExposedRetired(s, tc.through)
		if (err == nil) != tc.ok || len(s.Retired()) != tc.left {
			t.Fatalf("ack %d: err=%v left=%d want ok=%v left=%d", tc.through, err, len(s.Retired()), tc.ok, tc.left)
		}
	}
	for i, r := range s.Status().Retired {
		_ = i
		t.Fatalf("unexpected residue %v", r)
	}
}

// N6: Status never shows one job as both active and retired, and never loses a
// failure between polls, under concurrent completion, retry and acknowledgement.
func TestReservationStatusNeverShowsRetiredJobActive(t *testing.T) {
	var s *Supervisor
	drv := jobDriverFunc(func(ctx context.Context, j *pb.MountJob, _ *pb.Provision) error {
		time.Sleep(time.Duration(rand.Intn(300)) * time.Microsecond)
		if rand.Intn(2) == 0 {
			return fmt.Errorf("boom")
		}
		return nil
	})
	s, err := New(id(1), id(2), id(3), true, drv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	var mu sync.Mutex
	seen := map[string]bool{}
	retiredSeen := map[string]bool{}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			st := s.Status()
			encodable(t, st)
			active := map[string]bool{}
			for _, j := range st.Jobs {
				active[fmt.Sprintf("%s/%d", control.MountKey(j.Mount), j.RequestId)] = true
			}
			mu.Lock()
			for _, r := range st.Retired {
				k := fmt.Sprintf("%s/%d", control.MountKey(r.Job.Mount), r.Job.RequestId)
				if active[k] {
					t.Errorf("job %s both active and retired", k)
				}
				retiredSeen[k] = true
			}
			for k := range active {
				if retiredSeen[k] {
					t.Errorf("retired job %s shown active again", k)
				}
				seen[k] = true
			}
			mu.Unlock()
			if len(st.Retired) > 0 {
				_ = acknowledgeExposedRetired(s, st.Retired[len(st.Retired)-1].RetirementSequence)
			}
		}
	}()
	rid := uint64(1)
	for n := range 2000 {
		rid++
		_ = s.AcceptJob(jobRequest(rid, retirementVolume(n%80, byte(4+n%3)), []string{"mount", "umount", "provision"}[n%3]))
	}
	waitDesiredJobsJoined(t, s)
	writtenStatus(t, s, s.Status())
	close(stop)
	<-done
}
