package workspaceguest

import (
	"context"
	"errors"
	"testing"
	"time"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

type dispatchMount struct {
	*fakeMount
	prepare func(context.Context, uint64) (Recovery, error)
}

func (m *dispatchMount) Prepare(ctx context.Context, g uint64) (Recovery, error) {
	return m.prepare(ctx, g)
}

func TestTransportSuspendInterruptsInitialPrepareAndJoinsActualWork(t *testing.T) {
	c, s, done := transportRig(t)
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	m := &dispatchMount{fakeMount: &fakeMount{cold: ColdResult{ColdComplete: true}}, prepare: func(ctx context.Context, g uint64) (Recovery, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return Recovery{Generation: g}, ctx.Err()
	}}
	mid := mountID(4)
	if err := s.Register(context.Background(), mid, Witness{}, m); err != nil {
		t.Fatal(err)
	}
	s.jobDriver = jobDriverFunc(func(ctx context.Context, j *pb.MountJob, _ *pb.Provision) error {
		return s.Activate(ctx, j.Mount, j.Generation)
	})
	pairTransport(t, c)
	accepted := exchange(t, c, jobRequest(2, mid, "mount"))
	if accepted.GetResult().GetCode() != "accepted" {
		t.Fatal("initial job not accepted")
	}
	await(t, entered)
	status := exchange(t, c, &pb.Envelope{Version: 8, RequestId: 3, Body: &pb.Envelope_Status{Status: &pb.StatusRequest{}}}).GetStatusReply()
	if len(status.Jobs) != 1 || status.Jobs[0].Phase != "running" || status.Mounts[0].State != "recovering" {
		t.Fatalf("retry blocked observation: %v", status)
	}
	request := &pb.Envelope{Version: 8, RequestId: 4, DrainBudgetNanos: uint64(time.Second), Body: &pb.Envelope_Suspend{Suspend: suspension(s)}}
	if err := control.Write(c, request); err != nil {
		t.Fatal(err)
	}
	await(t, cancelled)
	if m.isOpen() {
		t.Fatal("Close waited behind Prepare")
	}
	s.mu.Lock()
	job := s.jobs[control.MountKey(mid)]
	s.mu.Unlock()
	select {
	case <-job.done:
		t.Fatal("cancellation fabricated a joined owner")
	default:
	}
	close(release)
	reply, err := control.Read(c)
	if err != nil || reply.GetSuspendAck() == nil {
		t.Fatalf("joined prepare refused cold: %v %v", reply, err)
	}
	if m.isOpen() || s.Status().Jobs[0].Phase != "failed" {
		t.Fatal("late Prepare result escaped its generation")
	}
	c.Close()
	await(t, done)
}

func TestTransportSlowProvisionAndUmountCannotObstructSuspend(t *testing.T) {
	for _, operation := range []string{"provision", "umount"} {
		t.Run(operation, func(t *testing.T) {
			c, s, done := transportRig(t)
			entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			s.jobDriver = jobDriverFunc(func(ctx context.Context, j *pb.MountJob, p *pb.Provision) error {
				if (j.Operation == "provision") != (p != nil) {
					return errors.New("provision binding missing")
				}
				close(entered)
				<-ctx.Done()
				close(cancelled)
				<-release
				return nil
			})
			pairTransport(t, c)
			if got := exchange(t, c, jobRequest(2, mountID(4), operation)); got.GetResult().GetCode() != "accepted" {
				t.Fatal(got)
			}
			await(t, entered)
			if err := control.Write(c, &pb.Envelope{Version: 8, RequestId: 3, DrainBudgetNanos: uint64(time.Second), Body: &pb.Envelope_Suspend{Suspend: suspension(s)}}); err != nil {
				t.Fatal(err)
			}
			await(t, cancelled)
			if s.Status().State != "suspending" || s.Status().Jobs[0].Phase != "running" {
				t.Fatal("lost unjoined desired owner")
			}
			close(release)
			reply, err := control.Read(c)
			if err != nil || reply.GetSuspendAck() == nil || len(reply.GetSuspendAck().Mounts) != 0 {
				t.Fatalf("desired intent became a mount: %v %v", reply, err)
			}
			if s.Retired()[0].Job.Failure != "stopped" {
				t.Fatal("late job success survived cancellation")
			}
			c.Close()
			await(t, done)
		})
	}
}

func TestTransportEOFWhileDispatchingCancelsAndRetainsPhysicalLane(t *testing.T) {
	c, s, done := transportRig(t)
	entered, cancelled, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	m := &fakeMount{suspend: func(ctx context.Context, _ *pb.Suspension) (ColdResult, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		close(joined)
		return ColdResult{ColdComplete: true}, nil
	}}
	mid := mountID(4)
	if err := s.Register(context.Background(), mid, Witness{}, m); err != nil {
		t.Fatal(err)
	}
	pairTransport(t, c)
	if err := control.Write(c, &pb.Envelope{Version: 8, RequestId: 2, DrainBudgetNanos: uint64(control.MaxDrainBudget), Body: &pb.Envelope_Suspend{Suspend: suspension(s)}}); err != nil {
		t.Fatal(err)
	}
	await(t, entered)
	c.Close()
	await(t, cancelled)
	if err := await(t, done); err == nil {
		t.Fatal("EOF dispatch returned success")
	}
	if s.Status().State != "discard-only" {
		t.Fatal("EOF did not close admission during dispatch")
	}
	s.mu.Lock()
	e := s.mounts[control.MountKey(mid)]
	s.mu.Unlock()
	select {
	case e.serial <- struct{}{}:
		<-e.serial
		t.Fatal("EOF released a stuck notification owner")
	default:
	}
	close(release)
	await(t, joined)
	waitFor(t, func() bool {
		select {
		case e.serial <- struct{}{}:
			<-e.serial
			return true
		default:
			return false
		}
	})
	if s.Status().State != "discard-only" || m.isOpen() {
		t.Fatal("late result recreated eligibility")
	}
}

func TestTransportReceiptBudgetChargesDispatchWait(t *testing.T) {
	c, s, done := transportRig(t)
	entered := make(chan time.Time, 1)
	m := &fakeMount{suspend: func(ctx context.Context, _ *pb.Suspension) (ColdResult, error) {
		deadline, ok := ctx.Deadline()
		if !ok {
			return ColdResult{}, errors.New("no forwarded deadline")
		}
		entered <- deadline
		return ColdResult{ColdComplete: true}, nil
	}}
	if err := s.Register(context.Background(), mountID(4), Witness{}, m); err != nil {
		t.Fatal(err)
	}
	pairTransport(t, c)
	// Hold the sole response writer with a Status response. The reader must
	// anchor the later Suspend now, rather than when dispatch becomes free.
	if err := control.Write(c, &pb.Envelope{Version: 8, RequestId: 2, Body: &pb.Envelope_Status{Status: &pb.StatusRequest{}}}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := control.Write(c, &pb.Envelope{Version: 8, RequestId: 3, DrainBudgetNanos: uint64(200 * time.Millisecond), Body: &pb.Envelope_Suspend{Suspend: suspension(s)}}); err != nil {
		t.Fatal(err)
	}
	// Read-ahead owns the frame by the time this unbuffered pipe write returns.
	time.Sleep(50 * time.Millisecond)
	if _, err := control.Read(c); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Read(c); err != nil {
		t.Fatal(err)
	}
	deadline := await(t, entered)
	if deadline.Before(start.Add(200*time.Millisecond)) || deadline.After(start.Add(230*time.Millisecond)) {
		t.Fatalf("dispatch wait renewed the budget: %v", deadline.Sub(start))
	}
	c.Close()
	await(t, done)
}

func TestTransportFramingConsumesDrainBudgetBeforeAcceptance(t *testing.T) {
	c, s, done := transportRig(t)
	pairTransport(t, c)
	raw, err := control.Encode(&pb.Envelope{Version: 8, RequestId: 2, DrainBudgetNanos: uint64(20 * time.Millisecond), Body: &pb.Envelope_Suspend{Suspend: suspension(s)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(raw[:1]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	if _, err := c.Write(raw[1:]); err != nil {
		t.Fatal(err)
	}
	if reply, err := control.Read(c); err == nil {
		t.Fatalf("expired framing budget acknowledged: %v", reply)
	}
	if err := await(t, done); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wrong expired-frame result: %v", err)
	}
	if s.Status().State != "discard-only" {
		t.Fatal("spent deadline retained resume eligibility")
	}
}
