package workspaceguest

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

type fakeMount struct {
	mu            sync.Mutex
	generation    uint64
	open          bool
	opens         int
	cold          ColdResult
	recoverResult Recovery
	suspend       func(context.Context, *pb.Suspension) (ColdResult, error)
	recover       func(context.Context, *pb.ResumeToken) (Recovery, error)
}

func ready() Recovery {
	return Recovery{State: "ready", SessionValidated: true, AuthorizationValidated: true, InitialRenewalInstalled: true, ColdSubscriptionInstalled: true}
}
func (m *fakeMount) CloseAdmission(g uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g >= m.generation {
		m.generation = g
		m.open = false
	}
}
func (m *fakeMount) OpenAdmission(g uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g != m.generation {
		return ErrState
	}
	m.open = true
	m.opens++
	return nil
}
func (m *fakeMount) Suspend(ctx context.Context, s *pb.Suspension) (ColdResult, error) {
	if m.suspend != nil {
		return m.suspend(ctx, s)
	}
	return m.cold, nil
}
func (m *fakeMount) Recover(ctx context.Context, t *pb.ResumeToken) (Recovery, error) {
	if m.recover != nil {
		return m.recover(ctx, t)
	}
	return m.recoverResult, nil
}
func (m *fakeMount) isOpen() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.open }
func id(n byte) []byte            { return bytes.Repeat([]byte{n}, 16) }
func mountID(n byte) *pb.MountID {
	return &pb.MountID{AuthorityId: bytes.Repeat([]byte{1}, 32), VolumeId: "example", Incarnation: id(n)}
}
func fixture(t *testing.T) (*Supervisor, *fakeMount, *pb.MountID) {
	t.Helper()
	s, err := New(id(1), id(2), id(3), true)
	if err != nil {
		t.Fatal(err)
	}
	m := &fakeMount{cold: ColdResult{ColdComplete: true}, recoverResult: ready()}
	mid := mountID(4)
	if err = s.Register(mid, Witness{Process: "pid/start", Kernel: "retained-fuse-witness", Session: "session", Enrollment: "enrollment"}, m); err != nil {
		t.Fatal(err)
	}
	if err = s.Activate(mid, 0, ready()); err != nil {
		t.Fatal(err)
	}
	return s, m, mid
}
func suspension(s *Supervisor) *pb.Suspension {
	status := s.Status()
	x := &pb.Suspension{BootId: status.BootId, HostServiceId: status.HostServiceId, GuestServiceId: status.GuestServiceId, Generation: status.Generation + 1, Nonce: id(byte(status.Generation + 8))}
	for _, m := range status.Mounts {
		x.Roster = append(x.Roster, m.Mount)
	}
	return x
}
func cold(t *testing.T, s *Supervisor, mid *pb.MountID) *pb.Suspension {
	t.Helper()
	x := suspension(s)
	if err := s.BeginSuspend(x); err != nil {
		t.Fatal(err)
	}
	if err := s.Drain(context.Background(), x, mid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SuspendAck(x); err != nil {
		t.Fatal(err)
	}
	return x
}
func token(x *pb.Suspension) *pb.ResumeToken { return &pb.ResumeToken{Suspension: x, WakeNonce: id(9)} }
func TestGuestColdAdmissionAndSingleUseRecovery(t *testing.T) {
	s, m, mid := fixture(t)
	x := cold(t, s, mid)
	if m.isOpen() {
		t.Fatal("suspended mount serving")
	}
	a, err := s.Resume(context.Background(), token(x))
	if err != nil || a.Mounts[0].State != "ready" || !m.isOpen() {
		t.Fatalf("recovery: %v", err)
	}
	if _, err = s.Resume(context.Background(), token(x)); err == nil {
		t.Fatal("replayed token accepted")
	}
}
func TestGuestMissingAndFailedColdAcknowledgements(t *testing.T) {
	for _, mode := range []string{"missing", "invalidation", "partial", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			s, m, mid := fixture(t)
			x := suspension(s)
			if err := s.BeginSuspend(x); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "invalidation":
				m.suspend = func(context.Context, *pb.Suspension) (ColdResult, error) {
					return ColdResult{}, errors.New("kernel notification failed")
				}
			case "partial":
				m.cold.ColdComplete = false
			case "cancelled":
				cancel()
			}
			if mode != "missing" {
				if err := s.Drain(ctx, x, mid); err == nil {
					t.Fatal("failed drain acknowledged")
				}
			}
			if _, err := s.SuspendAck(x); err == nil {
				t.Fatal("incomplete roster acknowledged")
			}
			if m.isOpen() {
				t.Fatal("failed invalidation reopened mount")
			}
		})
	}
}
func TestGuestLateAckCannotCertifyNextGeneration(t *testing.T) {
	s, m, mid := fixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	m.suspend = func(context.Context, *pb.Suspension) (ColdResult, error) {
		close(entered)
		<-release
		return ColdResult{ColdComplete: true}, nil
	}
	x := suspension(s)
	if err := s.BeginSuspend(x); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Drain(context.Background(), x, mid) }()
	<-entered
	next := suspension(s)
	if err := s.BeginSuspend(next); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("late ack accepted")
	}
	if _, err := s.SuspendAck(next); err == nil {
		t.Fatal("old drain certified new roster")
	}
}
func TestGuestMountStartRacingSuspendStaysClosed(t *testing.T) {
	s, _, mid := fixture(t)
	x := suspension(s)
	if err := s.BeginSuspend(x); err != nil {
		t.Fatal(err)
	}
	late := &fakeMount{open: true}
	other := proto.Clone(mid).(*pb.MountID)
	other.VolumeId = "other"
	if err := s.Register(other, Witness{}, late); err == nil || late.isOpen() {
		t.Fatal("racing start entered roster or stayed open")
	}
	if err := s.Activate(mid, 0, ready()); err == nil {
		t.Fatal("delayed mount startup reopened")
	}
}
func TestGuestTokenBindingRefusesEveryStaleDimension(t *testing.T) {
	for _, field := range []string{"boot", "host", "guest", "generation", "roster", "suspend-nonce", "wake-nonce"} {
		t.Run(field, func(t *testing.T) {
			s, m, mid := fixture(t)
			x := cold(t, s, mid)
			tok := token(proto.Clone(x).(*pb.Suspension))
			switch field {
			case "boot":
				tok.Suspension.BootId = id(30)
			case "host":
				tok.Suspension.HostServiceId = id(30)
			case "guest":
				tok.Suspension.GuestServiceId = id(30)
			case "generation":
				tok.Suspension.Generation++
			case "roster":
				tok.Suspension.Roster[0].Incarnation = id(30)
			case "suspend-nonce":
				tok.Suspension.Nonce = id(30)
			case "wake-nonce":
				tok.WakeNonce = nil
			}
			if _, err := s.Resume(context.Background(), tok); err == nil || m.isOpen() {
				t.Fatal("invalid token opened mount")
			}
		})
	}
}
func TestGuestDelayedRecoveryLosesToSecondSleep(t *testing.T) {
	s, m, mid := fixture(t)
	x := cold(t, s, mid)
	entered := make(chan struct{})
	release := make(chan struct{})
	m.recover = func(context.Context, *pb.ResumeToken) (Recovery, error) {
		close(entered)
		<-release
		return ready(), nil
	}
	done := make(chan error, 1)
	go func() { _, err := s.Resume(context.Background(), token(x)); done <- err }()
	<-entered
	next := suspension(s)
	if err := s.BeginSuspend(next); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err == nil || m.isOpen() {
		t.Fatal("delayed reply reopened newer generation")
	}
}
func TestGuestSecondSleepBeforeTokenConsumption(t *testing.T) {
	s, m, mid := fixture(t)
	x := cold(t, s, mid)
	tok := token(x)
	if err := s.BeginSuspend(suspension(s)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resume(context.Background(), tok); err == nil || m.isOpen() {
		t.Fatal("old wake token survived second sleep")
	}
}
func TestGuestServiceRestartDefaultsToDiscard(t *testing.T) {
	s, _, mid := fixture(t)
	x := cold(t, s, mid)
	restarted, err := New(id(1), id(2), id(30), false)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Status().State != "discard-only" {
		t.Fatal("missing state inferred cold")
	}
	if _, err = restarted.Resume(context.Background(), token(x)); err == nil {
		t.Fatal("restart accepted old token")
	}
	m := &fakeMount{open: true}
	if err = restarted.Register(mid, Witness{}, m); err == nil || m.isOpen() {
		t.Fatal("restart admitted old process")
	}
}
func TestGuestRecoveryRequiresEveryFreshProof(t *testing.T) {
	for _, missing := range []string{"session", "authorization", "renewal", "subscription"} {
		t.Run(missing, func(t *testing.T) {
			s, m, mid := fixture(t)
			x := cold(t, s, mid)
			switch missing {
			case "session":
				m.recoverResult.SessionValidated = false
			case "authorization":
				m.recoverResult.AuthorizationValidated = false
			case "renewal":
				m.recoverResult.InitialRenewalInstalled = false
			case "subscription":
				m.recoverResult.ColdSubscriptionInstalled = false
			}
			a, err := s.Resume(context.Background(), token(x))
			if err != nil {
				t.Fatal(err)
			}
			if m.isOpen() || a.Mounts[0].State != "closed" {
				t.Fatal("incomplete proof reopened mount")
			}
		})
	}
}
func TestGuestColdCompleteRetainsLossSeparately(t *testing.T) {
	s, m, mid := fixture(t)
	m.cold.Loss = []*pb.Loss{{Sequence: 1, AcceptedEntries: 2, AcceptedBytes: 8192, Reason: "old accepted cut unprovable"}}
	x := cold(t, s, mid)
	if s.Status().Mounts[0].Loss[0].Sequence != 1 {
		t.Fatal("cold ack erased loss")
	}
	if _, err := s.Resume(context.Background(), token(x)); err != nil {
		t.Fatal(err)
	}
	if s.Status().Mounts[0].Loss[0].AcceptedBytes != 8192 {
		t.Fatal("recovery erased failed barrier outcome")
	}
}
func TestGuestTerminalReplacementRequiresExactCleanupAndAuthorization(t *testing.T) {
	s, _, mid := fixture(t)
	loss := []*pb.Loss{{Sequence: 1, Reason: "old run failed"}}
	if err := s.Terminal(mid, "session ended", loss); err != nil {
		t.Fatal(err)
	}
	replacement := mountID(10)
	m := &fakeMount{}
	if err := s.Replace(mid, replacement, Witness{}, m, ready()); err == nil {
		t.Fatal("mounted over retained old instance")
	}
	w := Witness{Process: "pid/start", Kernel: "retained-fuse-witness", Session: "session", Enrollment: "enrollment"}
	wrong := w
	wrong.Kernel = "reused numeric fuse connection"
	if err := s.Cleanup(mid, CleanupProof{Witness: wrong, ProcessExited: true, KernelAbsent: true}); err == nil {
		t.Fatal("wrong witness accepted")
	}
	if err := s.Cleanup(mid, CleanupProof{Witness: w, ProcessExited: true}); err == nil {
		t.Fatal("process exit inferred kernel absence")
	}
	if err := s.Cleanup(mid, CleanupProof{Witness: w, ProcessExited: true, KernelAbsent: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(mid, replacement, Witness{}, m, Recovery{State: "ready"}); err == nil {
		t.Fatal("missing fresh authorization accepted")
	}
	if err := s.Replace(mid, replacement, Witness{}, m, ready()); err != nil {
		t.Fatal(err)
	}
	if len(s.Retired()) != 1 || s.Retired()[0].Loss[0].Sequence != 1 {
		t.Fatal("replacement erased old run")
	}
}
func TestGuestTerminalDoesNotReviveAcrossCancelledSleep(t *testing.T) {
	s, m, mid := fixture(t)
	if err := s.Terminal(mid, "authorization expired", nil); err != nil {
		t.Fatal(err)
	}
	x := cold(t, s, mid)
	if _, err := s.Resume(context.Background(), token(x)); err != nil {
		t.Fatal(err)
	}
	if m.isOpen() || s.Status().Mounts[0].State != "terminal" {
		t.Fatal("terminal mount revived")
	}
}
func TestGuestCancelledSleepUsesFreshColdRecovery(t *testing.T) {
	s, m, mid := fixture(t)
	x := cold(t, s, mid)
	if _, err := s.Resume(context.Background(), token(x)); err != nil || !m.isOpen() {
		t.Fatal("cancelled sleep left workspace cold")
	}
}

func TestGuestFailedAndLateDrainsRetainLossWithoutColdProof(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed invalidation", true: "late result"}[late], func(t *testing.T) {
			s, m, mid := fixture(t)
			entered := make(chan struct{})
			release := make(chan struct{})
			m.suspend = func(context.Context, *pb.Suspension) (ColdResult, error) {
				close(entered)
				<-release
				return ColdResult{Loss: []*pb.Loss{{Sequence: 1, AcceptedEntries: 1, Reason: "tail lost during failed drain"}}}, errors.New("invalidation blocked")
			}
			x := suspension(s)
			if err := s.BeginSuspend(x); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- s.Drain(context.Background(), x, mid) }()
			<-entered
			if late {
				if err := s.BeginSuspend(suspension(s)); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			if err := <-done; err == nil {
				t.Fatal("failed drain accepted")
			}
			status := s.Status()
			if len(status.Mounts[0].Loss) != 1 || m.isOpen() {
				t.Fatal("loss erased or failed drain opened")
			}
			if _, err := s.SuspendAck(x); err == nil {
				t.Fatal("failed drain earned cold proof")
			}
		})
	}
}
func TestGuestWholeRosterMustCompleteBeforeSuspension(t *testing.T) {
	s, _, first := fixture(t)
	second := mountID(12)
	second.VolumeId = "second"
	m := &fakeMount{cold: ColdResult{ColdComplete: true}, recoverResult: ready()}
	if err := s.Register(second, Witness{}, m); err != nil {
		t.Fatal(err)
	}
	x := suspension(s)
	if err := s.BeginSuspend(x); err != nil {
		t.Fatal(err)
	}
	if err := s.Drain(context.Background(), x, first); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SuspendAck(x); err == nil {
		t.Fatal("partial roster earned eligibility")
	}
	if err := s.Drain(context.Background(), x, second); err != nil {
		t.Fatal(err)
	}
	a, err := s.SuspendAck(x)
	if err != nil || len(a.Mounts) != 2 {
		t.Fatal("complete roster not acknowledged")
	}
}

func TestGuestNewColdProofWaitsForOvertakenControlCalls(t *testing.T) {
	s, m, mid := fixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	m.suspend = func(_ context.Context, x *pb.Suspension) (ColdResult, error) {
		if x.Generation == 1 {
			close(entered)
			<-release
			return ColdResult{ColdComplete: true, Loss: []*pb.Loss{{Sequence: 1, Reason: "late old-generation tail loss"}}}, nil
		}
		return ColdResult{ColdComplete: true, Loss: []*pb.Loss{{Sequence: 1, Reason: "late old-generation tail loss"}, {Sequence: 2, Reason: "next-generation tail loss"}}}, nil
	}
	old := suspension(s)
	if err := s.BeginSuspend(old); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Drain(context.Background(), old, mid) }()
	<-entered
	next := suspension(s)
	if err := s.BeginSuspend(next); err != nil {
		t.Fatal(err)
	}
	if err := s.Drain(context.Background(), next, mid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SuspendAck(next); err == nil {
		t.Fatal("acknowledged before overtaken control call settled")
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("late old acknowledgement accepted")
	}
	ack, err := s.SuspendAck(next)
	if err != nil {
		t.Fatal(err)
	}
	if len(ack.Mounts[0].Loss) != 2 {
		t.Fatal("late snapshot erased current ledger")
	}
}

func TestGuestRepeatedColdSuspensionRetainsCumulativeLoss(t *testing.T) {
	s, m, mid := fixture(t)
	m.cold.Loss = []*pb.Loss{{Sequence: 1, Reason: "old run failed"}}
	first := cold(t, s, mid)
	if _, err := s.Resume(context.Background(), token(first)); err != nil {
		t.Fatal(err)
	}
	second := cold(t, s, mid)
	if _, err := s.Resume(context.Background(), token(second)); err != nil {
		t.Fatal(err)
	}
	if got := s.Status().Mounts[0].Loss; len(got) != 1 || got[0].Sequence != 1 {
		t.Fatal("cumulative snapshot duplicated or erased old failure")
	}
}
