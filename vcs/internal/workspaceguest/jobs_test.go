package workspaceguest

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

type jobDriverFunc func(context.Context, *pb.MountJob, *pb.Provision) error

func (f jobDriverFunc) Run(ctx context.Context, j *pb.MountJob, p *pb.Provision) error {
	return f(ctx, j, p)
}

func waitFor(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if predicate() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("owner did not reach expected state")
}

func await[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatal("owner did not join")
		var zero T
		return zero
	}
}

func jobRequest(requestID uint64, id *pb.MountID, operation string) *pb.Envelope {
	e := &pb.Envelope{Version: 8, RequestId: requestID}
	switch operation {
	case "mount":
		e.Body = &pb.Envelope_Mount{Mount: &pb.MountRequest{Mount: id}}
	case "umount":
		e.Body = &pb.Envelope_Umount{Umount: &pb.UmountRequest{Mount: id}}
	case "provision":
		e.Body = &pb.Envelope_Provision{Provision: &pb.Provision{Mount: id, ServerName: "authority.example", AuthorityEndpoint: "authority.example:7443", CaCertificate: []byte("ca"), ClientCertificate: []byte("cert"), Capability: []byte("cap"), PublicKey: []byte("public"), RoutesRevision: makeDigest(1)}}
	}
	return e
}

func makeDigest(n byte) []byte {
	d := make([]byte, 32)
	for i := range d {
		d[i] = n
	}
	return d
}

func TestDesiredJobAcceptanceOwnsLaneAndRetainsFailure(t *testing.T) {
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	driver := jobDriverFunc(func(ctx context.Context, j *pb.MountJob, _ *pb.Provision) error {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return errors.New("exact removal remains unproven")
	})
	s, err := New(id(1), id(2), id(3), true, driver)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	request := jobRequest(2, mountID(4), "umount")
	if err := s.AcceptJob(request); err != nil {
		t.Fatal(err)
	}
	await(t, entered)
	if err := s.AcceptJob(jobRequest(3, mountID(4), "provision")); err == nil {
		t.Fatal("occupied lane replaced")
	}
	x := begin(t, s, suspension(s))
	await(t, cancelled)
	if _, err := s.SuspendAck(x); err == nil {
		t.Fatal("unjoined desired-only job certified cold")
	}
	for range 100 {
		status := s.Status()
		if len(status.Jobs) != 1 || len(status.Mounts) != 0 || status.Jobs[0].Phase != "running" || status.Jobs[0].RequestId != 2 {
			t.Fatalf("lost actual lane owner: %v", status)
		}
	}
	close(release)
	waitFor(t, func() bool { return len(s.Retired()) == 1 })
	j := s.Retired()[0].Job
	if j.Failure != "handler-failed" || j.Reason != "exact removal remains unproven" || j.Generation != 0 {
		t.Fatalf("independent failure erased: %v", j)
	}
}

func TestDesiredAndRegisteredMountsShareCapacity(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, jobDriverFunc(func(ctx context.Context, _ *pb.MountJob, _ *pb.Provision) error { <-ctx.Done(); return ctx.Err() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	for i := range control.MaxMounts {
		mid := mountID(4)
		mid.VolumeId = fmt.Sprintf("v%02d", i)
		if err := s.AcceptJob(jobRequest(uint64(i+1), mid, "mount")); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool {
		for _, j := range s.Status().Jobs {
			if j.Phase != "running" {
				return false
			}
		}
		return true
	})
	if err := s.AcceptJob(jobRequest(65, mountID(5), "mount")); err == nil {
		t.Fatal("65th desired mount accepted")
	}
	mid := mountID(4)
	mid.VolumeId = "v00"
	if err := s.Register(context.Background(), mid, Witness{}, &fakeMount{}); err != nil {
		t.Fatal("same desired mount consumed another slot", err)
	}
	conflict := clone(mid)
	conflict.Incarnation = id(6)
	if err := s.AcceptJob(jobRequest(66, conflict, "mount")); err == nil {
		t.Fatal("conflicting incarnation accepted")
	}
	if err := s.AcceptJob(jobRequest(1, mid, "umount")); err == nil {
		t.Fatal("consumed request repeated an effect")
	}
	encodable(t, s.Status())
}

func TestParallelDrainUsesOneDeadlineAndCanonicalWholeRoster(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.ChannelLost)
	entered := make(chan time.Time, control.MaxMounts)
	release := make(chan struct{})
	for i := control.MaxMounts - 1; i >= 0; i-- {
		mid := mountID(4)
		mid.VolumeId = fmt.Sprintf("v%02d", i)
		m := &fakeMount{suspend: func(ctx context.Context, x *pb.Suspension) (ColdResult, error) {
			deadline, ok := ctx.Deadline()
			if !ok {
				return ColdResult{}, errors.New("missing propagated deadline")
			}
			entered <- deadline
			select {
			case <-release:
				return ColdResult{ColdComplete: true}, nil
			case <-ctx.Done():
				return ColdResult{}, ctx.Err()
			}
		}}
		if err := s.Register(context.Background(), mid, Witness{}, m); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	type result struct {
		ack *pb.SuspendAck
		err error
	}
	done := make(chan result, 1)
	go func() { a, e := s.Suspend(context.Background(), suspension(s), deadline); done <- result{a, e} }()
	for range control.MaxMounts {
		if got := await(t, entered); !got.Equal(deadline) {
			t.Fatalf("renewed per-mount budget: %v != %v", got, deadline)
		}
	}
	select {
	case <-done:
		t.Fatal("partial cold acknowledgment")
	default:
	}
	close(release)
	r := await(t, done)
	if r.err != nil || control.ColdAck(r.ack) != nil {
		t.Fatalf("whole roster refused: %v", r.err)
	}
	for i, m := range r.ack.Mounts {
		if m.Mount.VolumeId != fmt.Sprintf("v%02d", i) || !proto.Equal(m.Mount, r.ack.Suspension.Roster[i]) {
			t.Fatal("completion order replaced roster order")
		}
	}
}

func TestParallelDrainFailureCancelsSiblingWithoutReleasingOwner(t *testing.T) {
	s, _, first := fixture(t)
	second := clone(first)
	second.VolumeId = "second"
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	m := &fakeMount{suspend: func(ctx context.Context, _ *pb.Suspension) (ColdResult, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-release
		return ColdResult{ColdComplete: true}, nil
	}}
	if err := s.Register(context.Background(), second, Witness{}, m); err != nil {
		t.Fatal(err)
	}
	s.mounts[control.MountKey(first)].driver.(*fakeMount).suspend = func(context.Context, *pb.Suspension) (ColdResult, error) {
		<-entered
		return ColdResult{}, errors.New("notification failed")
	}
	ack, err := s.Suspend(context.Background(), suspension(s), time.Now().Add(time.Second))
	if err == nil || ack != nil {
		t.Fatal("partial failure acknowledged")
	}
	await(t, cancelled)
	e := s.mounts[control.MountKey(second)]
	select {
	case e.serial <- struct{}{}:
		releaseEntry := e
		<-releaseEntry.serial
		t.Fatal("cancelled waiter released physical owner")
	default:
	}
	close(release)
	waitFor(t, func() bool {
		select {
		case e.serial <- struct{}{}:
			<-e.serial
			return true
		default:
			return false
		}
	})
	s.ChannelLost()
	if m.isOpen() {
		t.Fatal("late successful result reopened admission")
	}
}

func TestParallelDrainNewGenerationDefeatsLateCompletion(t *testing.T) {
	s, m, _ := fixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	m.suspend = func(context.Context, *pb.Suspension) (ColdResult, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return ColdResult{ColdComplete: true}, nil
	}
	old := make(chan error, 1)
	go func() {
		_, err := s.Suspend(context.Background(), suspension(s), time.Now().Add(time.Second))
		old <- err
	}()
	await(t, entered)
	request := suspension(s)
	type result struct {
		ack *pb.SuspendAck
		err error
	}
	current := make(chan result, 1)
	go func() {
		a, e := s.Suspend(context.Background(), request, time.Now().Add(time.Second))
		current <- result{a, e}
	}()
	if err := await(t, old); err == nil {
		t.Fatal("overtaken suspension acknowledged")
	}
	if got := s.Status(); got.Generation != 2 || got.State != "suspending" {
		t.Fatalf("old failure discarded newer generation: %v", got)
	}
	select {
	case <-current:
		t.Fatal("new drain escaped old physical lane")
	default:
	}
	close(release)
	r := await(t, current)
	if r.err != nil || r.ack == nil || r.ack.Suspension.Generation != 2 || calls.Load() != 2 {
		t.Fatalf("late old completion defeated new drain: %v %v", r.ack, r.err)
	}
	if m.isOpen() {
		t.Fatal("new cold generation reopened admission")
	}
}
