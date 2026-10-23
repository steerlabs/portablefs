package workspaceguest

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

// Port both reviewers' sequences: a running victim precedes or follows the
// other retirements. Neither publication timing releases its off-page result.
func TestR4JobOnlyRetirementBeyondPageAdmitsSuccessor(t *testing.T) {
	for _, total := range []int{1, 17, 33, 128} {
		for _, operation := range []string{"mount", "umount", "provision"} {
			t.Run(fmt.Sprintf("%d/%s", total, operation), func(t *testing.T) {
				r4JobRetirementGate(t, total, operation, false)
			})
		}
	}
}
func TestAstraR4SuccessorBeforePredecessorRetirementPage(t *testing.T) {
	r4JobRetirementGate(t, 17, "umount", true)
}
func r4JobRetirementGate(t *testing.T, total int, operation string, victimFirst bool) {
	t.Helper()
	entered, release := make(chan struct{}), make(chan struct{})
	s, err := New(id(1), id(2), id(3), true, jobDriverFunc(func(_ context.Context, j *pb.MountJob, _ *pb.Provision) error {
		if j.RequestId == 1000 {
			close(entered)
			<-release
		}
		return fmt.Errorf("exact diagnostic %d", j.RequestId)
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer s.ChannelLost()
	victim := retirementVolume(159, 4)
	start := func() {
		if err := s.AcceptJob(jobRequest(1000, victim, "mount")); err != nil {
			t.Fatal(err)
		}
		await(t, entered)
		running := s.Status()
		writtenStatus(t, s, running)
		if len(running.Jobs) != 1 || running.Jobs[0].Phase != "running" {
			t.Fatal(running)
		}
	}
	if victimFirst {
		start()
	}
	for i := 0; i < total-1; i++ {
		if err := s.AcceptJob(jobRequest(uint64(i+1), retirementVolume(i, 4), "mount")); err != nil {
			t.Fatal(err)
		}
		waitFor(t, func() bool { return len(s.Retired()) == i+1 })
	}
	if !victimFirst {
		start()
	}
	close(release)
	waitFor(t, func() bool { return len(s.Retired()) == total })
	predecessor := clone(s.Retired()[total-1])
	if predecessor.Job.RequestId != 1000 || predecessor.Job.Reason != "exact diagnostic 1000" || predecessor.MountStatus != nil {
		t.Fatal(predecessor)
	}
	for len(s.Retired()) > 0 {
		if err := s.AcceptJob(jobRequest(1001, victim, operation)); err == nil || !strings.Contains(err.Error(), "acknowledgement") {
			t.Fatalf("unacknowledged predecessor admitted: %v", err)
		}
		driver := &fakeMount{}
		if err := s.Register(context.Background(), victim, r3W(victim), driver); err == nil || !strings.Contains(err.Error(), "acknowledgement") || !driver.cleaned {
			t.Fatalf("Register reused retired job key or failed cleanup: %v", err)
		}
		page := s.Status()
		if len(page.Jobs) != 0 {
			t.Fatal("refusal dispatched successor", page.Jobs)
		}
		if len(page.Retired) == 0 || len(page.Retired) > control.MaxRetiredBatch {
			t.Fatal(page.Retired)
		}
		writtenStatus(t, s, page)
		// Even publication of the exact record leaves acknowledgement ownership.
		if err := s.AcceptJob(jobRequest(1001, victim, operation)); err == nil || !strings.Contains(err.Error(), "acknowledgement") {
			t.Fatal(err)
		}
		if !proto.Equal(s.Retired()[len(s.Retired())-1], predecessor) {
			t.Fatal("terminal evidence changed")
		}
		if err := acknowledgeExposedRetired(s, page.Retired[len(page.Retired)-1].RetirementSequence); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AcceptJob(jobRequest(1001, victim, operation)); err != nil {
		t.Fatalf("retry after ordered acknowledgements: %v", err)
	}
	waitFor(t, func() bool { return len(s.Retired()) == 1 })
	if got := s.Retired()[0].Job; got.RequestId != 1001 || got.Operation != operation || got.Reason != "exact diagnostic 1001" {
		t.Fatal(got)
	}
}

func TestAstraR4ReplaceAcknowledgementCannotRestoreSequence(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.ChannelLost()
	s.retirementSequence, s.acknowledgedSequence = math.MaxUint64-1, math.MaxUint64-1
	old, next := retirementVolume(0, 4), retirementVolume(0, 5)
	if err = s.Register(context.Background(), old, r3W(old), &fakeMount{}); err != nil {
		t.Fatal(err)
	}
	if err = s.Terminal(old, "ended", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.Cleanup(old, r3Proof(old)); err != nil {
		t.Fatal(err)
	}
	err = s.Replace(context.Background(), old, next, r3W(next), &fakeMount{})
	if !errors.Is(err, ErrState) || !strings.Contains(err.Error(), "old incarnation retired; new admission failed") || !strings.Contains(err.Error(), "sequence exhausted") || strings.Contains(err.Error(), "acknowledgement") {
		t.Fatal(err)
	}
	if len(s.Retired()) != 1 || s.Retired()[0].RetirementSequence != math.MaxUint64 {
		t.Fatal(s.Retired())
	}
	writtenStatus(t, s, s.Status())
	if err = acknowledgeExposedRetired(s, math.MaxUint64); err != nil {
		t.Fatal(err)
	}
	err = s.Register(context.Background(), next, r3W(next), &fakeMount{})
	if err == nil || !strings.Contains(err.Error(), "sequence exhausted") {
		t.Fatal(err)
	}
	err = s.Replace(context.Background(), old, next, r3W(next), &fakeMount{})
	if err == nil || !strings.Contains(err.Error(), "old incarnation already absent; Register") || strings.Contains(err.Error(), "acknowledgement") {
		t.Fatal(err)
	}
}
