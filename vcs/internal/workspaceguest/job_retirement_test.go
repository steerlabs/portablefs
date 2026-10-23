package workspaceguest

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

func retirementVolume(i int, inc byte) *pb.MountID {
	m := mountID(inc)
	m.VolumeId = fmt.Sprintf("rv%02d", i)
	return m
}

func waitDesiredJobsJoined(t *testing.T, s *Supervisor) {
	t.Helper()
	waitFor(t, func() bool {
		for _, j := range s.Status().Jobs {
			if j.Phase == "offered" || j.Phase == "running" {
				return false
			}
		}
		return true
	})
}

// A failed job without registration cannot hold a later incarnation hostage.
// Its evidence survives both Umount and fresh Provision/Register.
func TestFinishedUnregisteredJobAllowsNewIncarnation(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	first := retirementVolume(0, 4)
	if err := s.AcceptJob(jobRequest(2, first, "mount")); err != nil {
		t.Fatal(err)
	}
	waitDesiredJobsJoined(t, s)
	if j := s.Retired()[0].Job; j.Phase != "failed" {
		t.Fatalf("expected failed job: %v", j)
	}
	// The host has not acknowledged the failure when it requests removal.
	if err := s.AcceptJob(jobRequest(3, first, "umount")); err == nil || !strings.Contains(err.Error(), "acknowledgement") {
		t.Fatalf("same key reused before retirement acknowledgement: %v", err)
	}
	next := retirementVolume(0, 5)
	errRegister := s.Register(context.Background(), next, Witness{}, &fakeMount{})
	errAccept := s.AcceptJob(jobRequest(4, next, "provision"))
	if errAccept != nil || errRegister != nil {
		t.Fatalf("joined failed desired-only incarnation blocks replacement forever: accept=%v register=%v", errAccept, errRegister)
	}
	waitDesiredJobsJoined(t, s)
	retired := s.Retired()
	if len(retired) < 1 || retired[0].Job.Failure != "unavailable" || retired[0].Job.RequestId != 2 {
		t.Fatalf("unobserved failure lost: %v", retired)
	}
	encodable(t, s.Status())
}

// Completing Umount transfers the slot to acknowledged retirement. Reusing
// capacity requires observing that evidence rather than silently dropping it.
func TestCompletedUmountsReleaseAcknowledgedCapacity(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, jobDriverFunc(func(context.Context, *pb.MountJob, *pb.Provision) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	rid := uint64(1)
	for i := range control.MaxMounts {
		for _, op := range []string{"mount", "umount"} {
			rid++
			if err := s.AcceptJob(jobRequest(rid, retirementVolume(i, 4), op)); err != nil {
				t.Fatal(i, op, err)
			}
			waitDesiredJobsJoined(t, s)
			observed := s.Status().Retired
			if len(observed) != 1 || observed[0].Job.Operation != op || observed[0].Job.Phase != "complete" {
				t.Fatalf("missing exact completion: %v", observed)
			}
			if err := s.AcknowledgeRetired(observed[0].RetirementSequence); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(s.Status().Jobs) != 0 || len(s.Retired()) != 0 {
		t.Fatal("acknowledged jobs retained slots")
	}
	rid++
	if err := s.AcceptJob(jobRequest(rid, retirementVolume(99, 4), "mount")); err != nil {
		t.Fatalf("64 completed umounts permanently exhaust desired capacity: %v", err)
	}
}

// Prompt acceptance over the real paired stream with a driver that never
// cooperates; Status keeps the job separate from the roster.
func TestTransportPromptJobsRetainBlockedOwners(t *testing.T) {
	c, s, done := transportRig(t)
	release := make(chan struct{})
	defer close(release)
	s.jobDriver = jobDriverFunc(func(ctx context.Context, _ *pb.MountJob, _ *pb.Provision) error {
		<-release
		return nil
	})
	pairTransport(t, c)
	rid := uint64(1)
	for i, op := range []string{"mount", "umount", "provision"} {
		rid++
		start := time.Now()
		r := exchange(t, c, jobRequest(rid, retirementVolume(i, 4), op))
		if r.GetResult().GetCode() != "accepted" || time.Since(start) > 200*time.Millisecond {
			t.Fatalf("%s not promptly accepted: %v %v", op, r, time.Since(start))
		}
		rid++
		r = exchange(t, c, jobRequest(rid, retirementVolume(i, 4), "mount"))
		if r.GetResult().GetCode() != "refused" {
			t.Fatalf("second job on occupied mount accepted: %v", r)
		}
	}
	rid++
	st := exchange(t, c, &pb.Envelope{Version: 8, RequestId: rid, Body: &pb.Envelope_Status{Status: &pb.StatusRequest{}}}).GetStatusReply()
	if len(st.Mounts) != 0 || len(st.Jobs) != 3 {
		t.Fatalf("desired job masquerades as mount: %v", st)
	}
	c.Close()
	await(t, done)
}

// Suspend with a job driver ignoring cancellation: discard at the budget, no
// ack, lane retained, no new job, late result cannot change phase.
func TestTransportUncooperativeJobDiscardsAtSharedBudget(t *testing.T) {
	c, s, done := transportRig(t)
	entered, release := make(chan struct{}), make(chan struct{})
	s.jobDriver = jobDriverFunc(func(ctx context.Context, _ *pb.MountJob, _ *pb.Provision) error {
		close(entered)
		<-release // ignores ctx
		return nil
	})
	pairTransport(t, c)
	mid := retirementVolume(0, 4)
	if r := exchange(t, c, jobRequest(2, mid, "mount")); r.GetResult().GetCode() != "accepted" {
		t.Fatal(r)
	}
	await(t, entered)
	budget := 200 * time.Millisecond
	start := time.Now()
	if err := control.Write(c, &pb.Envelope{Version: 8, RequestId: 3, DrainBudgetNanos: uint64(budget), Body: &pb.Envelope_Suspend{Suspend: suspension(s)}}); err != nil {
		t.Fatal(err)
	}
	if r, err := control.Read(c); err == nil {
		t.Fatalf("uncooperative job acknowledged: %v", r)
	}
	err := await(t, done)
	elapsed := time.Since(start)
	if err == nil || elapsed < budget || elapsed > budget+150*time.Millisecond {
		t.Fatalf("wrong discard timing/result: %v %v", err, elapsed)
	}
	if st := s.Status(); st.State != "discard-only" || st.Jobs[0].Phase != "running" {
		t.Fatalf("lane released or eligibility retained: %v", st)
	}
	if err := s.AcceptJob(jobRequest(9, mid, "mount")); err == nil {
		t.Fatal("new job started on owned lane")
	}
	close(release)
	waitDesiredJobsJoined(t, s)
	if st := s.Status(); st.State != "discard-only" || len(st.Jobs) != 0 || st.Retired[0].Job.Phase != "failed" || st.Retired[0].Job.Failure != "stopped" {
		t.Fatalf("late success changed state: %v", st)
	}
}

// 64 registered mounts, one stuck ignoring ctx: one deadline total, siblings
// cancelled, no partial ack, stuck lane still owned.
func TestParallelDrain64RetainsStuckOwnerAndCancelsSiblings(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	var cancelled atomic.Int32
	release := make(chan struct{})
	defer close(release)
	var stuck *entry
	for i := range control.MaxMounts {
		mid := retirementVolume(i, 4)
		isStuck := i == 37
		m := &fakeMount{suspend: func(ctx context.Context, _ *pb.Suspension) (ColdResult, error) {
			if isStuck {
				<-release
				return ColdResult{ColdComplete: true}, nil
			}
			<-ctx.Done()
			cancelled.Add(1)
			return ColdResult{}, ctx.Err()
		}}
		if err := s.Register(context.Background(), mid, Witness{}, m); err != nil {
			t.Fatal(err)
		}
		if isStuck {
			stuck = s.mounts[control.MountKey(mid)]
		}
	}
	budget := 300 * time.Millisecond
	start := time.Now()
	ack, err := s.Suspend(context.Background(), suspension(s), start.Add(budget))
	elapsed := time.Since(start)
	if err == nil || ack != nil {
		t.Fatal("partial ack")
	}
	if elapsed < budget || elapsed > budget+150*time.Millisecond {
		t.Fatalf("budget spent per mount or not at all: %v", elapsed)
	}
	waitFor(t, func() bool { return cancelled.Load() == control.MaxMounts-1 })
	select {
	case stuck.serial <- struct{}{}:
		<-stuck.serial
		t.Fatal("stuck lane released")
	default:
	}
	if s.Status().State != "discard-only" {
		t.Fatal("failed drain did not discard")
	}
}

func TestParallelDrainExpiredBudgetRefusesIncludingEmptyRoster(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	release := make(chan struct{})
	defer close(release)
	m := &fakeMount{suspend: func(context.Context, *pb.Suspension) (ColdResult, error) {
		<-release
		return ColdResult{ColdComplete: true}, nil
	}}
	if err := s.Register(context.Background(), retirementVolume(0, 4), Witness{}, m); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := s.Suspend(context.Background(), suspension(s), start.Add(time.Nanosecond)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired budget: %v", err)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("expired budget did not fail fast")
	}
	// Empty roster, expired budget: must still refuse.
	s2, _ := New(id(1), id(2), id(3), true, nil)
	t.Cleanup(s2.ChannelLost)
	if ack, err := s2.Suspend(context.Background(), suspension(s2), time.Now().Add(-time.Second)); err == nil || ack != nil {
		t.Fatal("expired empty-roster suspend acknowledged")
	}
}

// Two frames pipelined behind a blocked response writer refuse; one is held.
func TestTransportPipelinedReadAheadReportsReaderCause(t *testing.T) {
	c, s, done := transportRig(t)
	pairTransport(t, c)
	for rid := uint64(2); rid <= 4; rid++ {
		if err := control.Write(c, &pb.Envelope{Version: 8, RequestId: rid, Body: &pb.Envelope_Status{Status: &pb.StatusRequest{}}}); err != nil {
			t.Fatal(err)
		}
	}
	err := await(t, done)
	if err == nil || !strings.Contains(err.Error(), "read-ahead exceeded") {
		t.Fatal("pipelined burst accepted")
	}
	if s.Status().State != "discard-only" {
		t.Fatal("pipelining retained eligibility")
	}
}

// One pipelined frame is legitimately held, and replies stay ordered.
func TestTransportOnePipelinedFramePreservesReplyOrder(t *testing.T) {
	c, _, done := transportRig(t)
	pairTransport(t, c)
	for rid := uint64(2); rid <= 3; rid++ {
		if err := control.Write(c, &pb.Envelope{Version: 8, RequestId: rid, Body: &pb.Envelope_Status{Status: &pb.StatusRequest{}}}); err != nil {
			t.Fatal(err)
		}
	}
	for rid := uint64(2); rid <= 3; rid++ {
		r, err := control.Read(c)
		if err != nil || r.RequestId != rid {
			t.Fatalf("out of order: %v %v", r, err)
		}
	}
	c.Close()
	await(t, done)
}

func TestTransportDrainBudgetBoundaryValidation(t *testing.T) {
	x := &pb.Suspension{BootId: id(1), HostServiceId: id(2), GuestServiceId: id(3), Generation: 1, Nonce: id(9)}
	for _, tc := range []struct {
		body   func(*pb.Envelope)
		budget uint64
		ok     bool
	}{
		{func(e *pb.Envelope) { e.Body = &pb.Envelope_Suspend{Suspend: x} }, 0, false},
		{func(e *pb.Envelope) { e.Body = &pb.Envelope_Suspend{Suspend: x} }, 1, true},
		{func(e *pb.Envelope) { e.Body = &pb.Envelope_Suspend{Suspend: x} }, uint64(15 * time.Second), true},
		{func(e *pb.Envelope) { e.Body = &pb.Envelope_Suspend{Suspend: x} }, uint64(15*time.Second) + 1, false},
		{func(e *pb.Envelope) { e.Body = &pb.Envelope_Suspend{Suspend: x} }, ^uint64(0), false},
		{func(e *pb.Envelope) { e.Body = &pb.Envelope_Status{Status: &pb.StatusRequest{}} }, 1, false},
		{func(e *pb.Envelope) { e.Body = &pb.Envelope_Mount{Mount: &pb.MountRequest{Mount: mountID(4)}} }, 1, false},
		{func(e *pb.Envelope) { e.Body = &pb.Envelope_Status{Status: &pb.StatusRequest{}} }, 0, true},
	} {
		e := &pb.Envelope{Version: 8, RequestId: 1, DrainBudgetNanos: tc.budget}
		tc.body(e)
		if got := control.Validate(e) == nil; got != tc.ok {
			t.Errorf("%T budget %d: valid=%v", e.Body, tc.budget, got)
		}
	}
}

func TestJobRetirementCountsUnacknowledgedReservations(t *testing.T) {
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
	}
	waitDesiredJobsJoined(t, s)
	if len(s.Retired()) != MaxReservations || len(s.Status().Jobs) != 0 {
		t.Fatal("joined owners did not transfer their slots")
	}
	before := s.Retired()
	for _, mid := range []*pb.MountID{retirementVolume(99, 4), retirementVolume(0, 5)} {
		if err := s.AcceptJob(jobRequest(200, mid, "provision")); err == nil {
			t.Fatal("unacknowledged evidence bypassed capacity")
		}
		if err := s.Register(context.Background(), mid, Witness{}, &fakeMount{}); err == nil {
			t.Fatal("registration bypassed retained evidence")
		}
	}
	for i, outcome := range s.Retired() {
		if !proto.Equal(outcome, before[i]) {
			t.Fatal("refusal erased evidence")
		}
	}
	for len(s.Retired()) != 0 {
		batch := s.Status().Retired
		encodable(t, s.Status())
		if len(batch) == 0 || len(batch) > control.MaxRetiredBatch {
			t.Fatal("unbounded observation")
		}
		if err := s.AcknowledgeRetired(batch[len(batch)-1].RetirementSequence); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.AcceptJob(jobRequest(201, retirementVolume(0, 5), "mount")); err != nil {
		t.Fatal(err)
	}
	waitDesiredJobsJoined(t, s)
	if err := s.Register(context.Background(), retirementVolume(0, 6), Witness{}, &fakeMount{}); err != nil {
		t.Fatal(err)
	}
}

func TestRunningJobRetainsIncarnationUntilActualJoin(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	s, err := New(id(1), id(2), id(3), true, jobDriverFunc(func(context.Context, *pb.MountJob, *pb.Provision) error {
		close(entered)
		<-release
		return ErrUnavailable
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	if err := s.AcceptJob(jobRequest(2, retirementVolume(0, 4), "mount")); err != nil {
		t.Fatal(err)
	}
	await(t, entered)
	next := retirementVolume(0, 5)
	if err := s.AcceptJob(jobRequest(3, next, "mount")); err == nil {
		t.Fatal("running incarnation replaced")
	}
	if err := s.Register(context.Background(), next, Witness{}, &fakeMount{}); err == nil {
		t.Fatal("registration bypassed running owner")
	}
	close(release)
	waitDesiredJobsJoined(t, s)
	if err := s.Register(context.Background(), next, Witness{}, &fakeMount{}); err != nil {
		t.Fatal(err)
	}
	if len(s.Retired()) != 1 || s.Retired()[0].Job.Failure != "unavailable" {
		t.Fatal("joined failure erased")
	}
}

func TestReplaceRetiresRegisteredJobFailureWithExactMount(t *testing.T) {
	s, _, old := fixture(t)
	if err := s.AcceptJob(jobRequest(2, old, "mount")); err != nil {
		t.Fatal(err)
	}
	waitDesiredJobsJoined(t, s)
	failed := s.Status().Jobs[0]
	if err := s.Terminal(old, "ended", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Cleanup(old, CleanupProof{Witness: s.mounts[control.MountKey(old)].witness, ProcessExited: true, KernelAbsent: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(context.Background(), old, mountID(5), Witness{}, &fakeMount{}); err != nil {
		t.Fatal(err)
	}
	outcomes := s.Retired()
	if len(outcomes) != 1 || !proto.Equal(outcomes[0].MountStatus.Mount, old) || !proto.Equal(outcomes[0].Job, failed) {
		t.Fatalf("replacement lost job evidence: %v", outcomes)
	}
	encodable(t, s.Status())
	if err := s.AcknowledgeRetired(outcomes[0].RetirementSequence); err != nil {
		t.Fatal(err)
	}
	if len(s.Retired()) != 0 {
		t.Fatal("acknowledged evidence retained")
	}
}

func TestRegisteredJobRetryAfterObservation(t *testing.T) {
	s, _, mid := fixture(t)
	for _, request := range []uint64{2, 3} {
		if err := s.AcceptJob(jobRequest(request, mid, "mount")); err != nil {
			t.Fatal(err)
		}
		waitDesiredJobsJoined(t, s)
		status := s.Status()
		if status.Jobs[0].RequestId != request || status.Jobs[0].Failure != "unavailable" {
			t.Fatal("exact failure missing")
		}
		s.observeWrittenStatus(status)
	}
	if len(s.Retired()) != 0 {
		t.Fatal("retry allocated retirement")
	}
	encodable(t, s.Status())
}

func TestJobRetirementReservesFinalSequenceBeforeDispatch(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	s, err := New(id(1), id(2), id(3), true, jobDriverFunc(func(context.Context, *pb.MountJob, *pb.Provision) error { close(entered); <-release; return nil }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	s.retirementSequence, s.acknowledgedSequence = math.MaxUint64-1, math.MaxUint64-1
	if err := s.AcceptJob(jobRequest(2, mountID(4), "mount")); err != nil {
		t.Fatal(err)
	}
	await(t, entered)
	if err := s.AcceptJob(jobRequest(3, retirementVolume(1, 4), "mount")); err == nil {
		t.Fatal("unreserved sequence accepted")
	}
	close(release)
	waitDesiredJobsJoined(t, s)
	if s.Retired()[0].RetirementSequence != math.MaxUint64 {
		t.Fatal("reserved final sequence lost")
	}
	if err := s.AcknowledgeRetired(math.MaxUint64); err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptJob(jobRequest(4, mountID(5), "mount")); err == nil {
		t.Fatal("exhausted sequence wrapped")
	}
}
