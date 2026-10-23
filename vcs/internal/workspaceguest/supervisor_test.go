package workspaceguest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	"sync"
	"testing"
	"time"

	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
)

type fakeMount struct {
	mu            sync.Mutex
	generation    uint64
	gateSerial    uint64
	open          bool
	opens         int
	cold          ColdResult
	recoverResult Recovery
	prepareResult *Recovery
	cleaned       bool
	suspend       func(context.Context, *pb.Suspension) (ColdResult, error)
	recover       func(context.Context, *pb.ResumeToken) (Recovery, error)
}

var testDeadline = time.Unix(2000000000, 0)

func testRenewal() mountenrollment.RenewalReadiness {
	return mountenrollment.RenewalReadiness{State: "installed", InstalledSequence: 1, SessionID: "test-session", AuthorizationDeadline: testDeadline}
}
func (m *fakeMount) bindProof(r *Recovery) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r.GateSerial = m.gateSerial
	r.Renewal.Permit = mountenrollment.Permit{Generation: r.Generation, GateSerial: m.gateSerial}
}
func ready() Recovery {
	return Recovery{State: "ready", SessionValidated: true, AuthorizationValidated: true, Renewal: testRenewal(), SessionID: "test-session", AuthorizationDeadline: testDeadline, ColdSubscriptionInstalled: true}
}
func (m *fakeMount) CloseAdmission(g uint64) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g >= m.generation {
		m.generation = g
		m.open = false
	}
	m.gateSerial++
	return m.gateSerial
}
func (m *fakeMount) OpenAdmission(g, serial uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if g != m.generation || serial != m.gateSerial {
		return ErrState
	}
	m.open = true
	m.opens++
	return nil
}
func (m *fakeMount) Suspend(ctx context.Context, s *pb.Suspension) (ColdResult, error) {
	if m.suspend != nil {
		r, err := m.suspend(ctx, s)
		if r.Generation == 0 {
			r.Generation = s.Generation
		}
		return r, err
	}
	r := m.cold
	r.Generation = s.Generation
	return r, nil
}
func (m *fakeMount) Recover(ctx context.Context, t *pb.ResumeToken) (Recovery, error) {
	if m.recover != nil {
		return m.recover(ctx, t)
	}
	r := m.recoverResult
	r.Generation = t.Suspension.Generation
	m.bindProof(&r)
	return r, nil
}
func (m *fakeMount) Prepare(_ context.Context, g uint64) (Recovery, error) {
	if m.prepareResult != nil {
		return *m.prepareResult, nil
	}
	r := ready()
	r.Generation = g
	m.bindProof(&r)
	return r, nil
}
func (m *fakeMount) Cleanup(_ context.Context, w Witness) (CleanupProof, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleaned = true
	return CleanupProof{Witness: w, ProcessExited: true, KernelAbsent: true}, nil
}
func begin(t *testing.T, s *Supervisor, x *pb.Suspension) *pb.Suspension {
	t.Helper()
	fixed, err := s.BeginSuspend(x)
	if err != nil {
		t.Fatal(err)
	}
	return fixed
}
func waitRecovered(t *testing.T, s *Supervisor) []*pb.MountStatus {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ms := s.Status().Mounts
		pending := false
		for _, m := range ms {
			pending = pending || m.State == "recovering"
		}
		if !pending {
			return ms
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("mount recovery did not settle")
	return nil
}
func resumeAndWait(t *testing.T, s *Supervisor, ctx context.Context, tok *pb.ResumeToken) (*pb.ResumeAck, error) {
	t.Helper()
	a, err := s.Resume(ctx, tok)
	if err != nil {
		return nil, err
	}
	a.Mounts = waitRecovered(t, s)
	return a, nil
}
func (m *fakeMount) isOpen() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.open }
func id(n byte) []byte            { return bytes.Repeat([]byte{n}, 16) }
func mountID(n byte) *pb.MountID {
	return &pb.MountID{AuthorityId: bytes.Repeat([]byte{1}, 32), VolumeId: "example", Incarnation: id(n)}
}
func fixture(t *testing.T) (*Supervisor, *fakeMount, *pb.MountID) {
	t.Helper()
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	m := &fakeMount{cold: ColdResult{ColdComplete: true}, recoverResult: ready()}
	mid := mountID(4)
	if err = s.Register(context.Background(), mid, Witness{Process: "pid/start", Kernel: "retained-fuse-witness", Session: "session", Enrollment: "enrollment"}, m); err != nil {
		t.Fatal(err)
	}
	if err = s.Activate(context.Background(), mid, 0); err != nil {
		t.Fatal(err)
	}
	return s, m, mid
}
func suspension(s *Supervisor) *pb.Suspension {
	status := s.Status()
	x := &pb.Suspension{BootId: status.BootId, HostServiceId: status.HostServiceId, GuestServiceId: status.GuestServiceId, Generation: status.Generation + 1, Nonce: id(byte(status.Generation + 8))}
	return x
}
func cold(t *testing.T, s *Supervisor, mid *pb.MountID) *pb.Suspension {
	t.Helper()
	x := suspension(s)
	x = begin(t, s, x)
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
	a, err := resumeAndWait(t, s, context.Background(), token(x))
	if err != nil || a.Mounts[0].State != "ready" || !m.isOpen() {
		t.Fatalf("recovery: %v", err)
	}
	if _, err = resumeAndWait(t, s, context.Background(), token(x)); err == nil {
		t.Fatal("replayed token accepted")
	}
}
func TestGuestMissingAndFailedColdAcknowledgements(t *testing.T) {
	for _, mode := range []string{"missing", "invalidation", "partial", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			s, m, mid := fixture(t)
			x := suspension(s)
			x = begin(t, s, x)
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
	x = begin(t, s, x)
	done := make(chan error, 1)
	go func() { done <- s.Drain(context.Background(), x, mid) }()
	<-entered
	next := suspension(s)
	next = begin(t, s, next)
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
	x = begin(t, s, x)
	late := &fakeMount{}
	other := proto.Clone(mid).(*pb.MountID)
	other.VolumeId = "other"
	if err := s.Register(context.Background(), other, Witness{}, late); err == nil || late.isOpen() || !late.cleaned {
		t.Fatal("racing start entered roster or stayed open")
	}
	if err := s.Activate(context.Background(), mid, 0); err == nil {
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
			if _, err := resumeAndWait(t, s, context.Background(), tok); err == nil || m.isOpen() {
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
	next = begin(t, s, next)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if m.isOpen() {
		t.Fatal("delayed reply reopened newer generation")
	}
}
func TestGuestSecondSleepBeforeTokenConsumption(t *testing.T) {
	s, m, mid := fixture(t)
	x := cold(t, s, mid)
	tok := token(x)
	_ = begin(t, s, suspension(s))
	if _, err := resumeAndWait(t, s, context.Background(), tok); err == nil || m.isOpen() {
		t.Fatal("old wake token survived second sleep")
	}
}
func TestGuestServiceRestartDefaultsToDiscard(t *testing.T) {
	s, _, mid := fixture(t)
	x := cold(t, s, mid)
	restarted, err := New(id(1), id(2), id(30), false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Status().State != "discard-only" {
		t.Fatal("missing state inferred cold")
	}
	if _, err = restarted.Resume(context.Background(), token(x)); err == nil {
		t.Fatal("restart accepted old token")
	}
	m := &fakeMount{}
	if err = restarted.Register(context.Background(), mid, Witness{}, m); err == nil || m.isOpen() || !m.cleaned {
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
				m.recoverResult.Renewal.State = "pending"
			case "subscription":
				m.recoverResult.ColdSubscriptionInstalled = false
			}
			a, err := resumeAndWait(t, s, context.Background(), token(x))
			if err != nil {
				t.Fatal(err)
			}
			if m.isOpen() || a.Mounts[0].State != "terminal" {
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
	if _, err := resumeAndWait(t, s, context.Background(), token(x)); err != nil {
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
	if err := s.Replace(context.Background(), mid, replacement, Witness{}, m); err == nil {
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
	if err := s.Replace(context.Background(), mid, replacement, Witness{}, m); err != nil {
		t.Fatal(err)
	}
	m.prepareResult = &Recovery{State: "ready"}
	if err := s.Activate(context.Background(), replacement, 0); err == nil || m.isOpen() {
		t.Fatal("missing driver proof accepted")
	}
	m.prepareResult = nil
	if err := s.Activate(context.Background(), replacement, 0); err == nil {
		t.Fatal("failed Prepare retried on terminal incarnation")
	}
	if err := s.Cleanup(replacement, CleanupProof{ProcessExited: true, KernelAbsent: true}); err != nil {
		t.Fatal(err)
	}
	next := mountID(11)
	if err := s.Replace(context.Background(), replacement, next, Witness{}, m); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(context.Background(), next, 0); err != nil {
		t.Fatal(err)
	}
	if len(s.Retired()) != 2 || s.Retired()[0].MountStatus.Loss[0].Sequence != 1 {
		t.Fatal("replacement erased old run")
	}
}
func TestGuestTerminalDoesNotReviveAcrossCancelledSleep(t *testing.T) {
	s, m, mid := fixture(t)
	if err := s.Terminal(mid, "authorization expired", nil); err != nil {
		t.Fatal(err)
	}
	x := cold(t, s, mid)
	if _, err := resumeAndWait(t, s, context.Background(), token(x)); err != nil {
		t.Fatal(err)
	}
	if m.isOpen() || s.Status().Mounts[0].State != "terminal" {
		t.Fatal("terminal mount revived")
	}
}
func TestGuestCancelledSleepUsesFreshColdRecovery(t *testing.T) {
	s, m, mid := fixture(t)
	x := cold(t, s, mid)
	if _, err := resumeAndWait(t, s, context.Background(), token(x)); err != nil || !m.isOpen() {
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
			x = begin(t, s, x)
			done := make(chan error, 1)
			go func() { done <- s.Drain(context.Background(), x, mid) }()
			<-entered
			if late {
				_ = begin(t, s, suspension(s))
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
	if err := s.Register(context.Background(), second, Witness{}, m); err != nil {
		t.Fatal(err)
	}
	x := suspension(s)
	x = begin(t, s, x)
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
	old = begin(t, s, old)
	done := make(chan error, 1)
	go func() { done <- s.Drain(context.Background(), old, mid) }()
	<-entered
	next := suspension(s)
	next = begin(t, s, next)
	nextDone := make(chan error, 1)
	go func() { nextDone <- s.Drain(context.Background(), next, mid) }()
	if _, err := s.SuspendAck(next); err == nil {
		t.Fatal("acknowledged before overtaken control call settled")
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("late old acknowledgement accepted")
	}
	if err := <-nextDone; err != nil {
		t.Fatal(err)
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
	if _, err := resumeAndWait(t, s, context.Background(), token(first)); err != nil {
		t.Fatal(err)
	}
	second := cold(t, s, mid)
	if _, err := resumeAndWait(t, s, context.Background(), token(second)); err != nil {
		t.Fatal(err)
	}
	if got := s.Status().Mounts[0].Loss; len(got) != 1 || got[0].Sequence != 1 {
		t.Fatal("cumulative snapshot duplicated or erased old failure")
	}
}

// Review reproduction 1: a recovering driver is still in flight when the next
// drain arrives. The second withdrawal must run after that driver settles.
func TestReviewOvertakenRecoverCannotUndoNewColdProof(t *testing.T) {
	s, m, mid := fixture(t)
	first := cold(t, s, mid)
	entered := make(chan struct{})
	releaseRecovery := make(chan struct{})
	cancelled := make(chan struct{})
	var effectsMu sync.Mutex
	live := false
	m.recover = func(ctx context.Context, tok *pb.ResumeToken) (Recovery, error) {
		close(entered)
		<-ctx.Done()
		close(cancelled)
		<-releaseRecovery
		// Simulate an adapter that ignored cancellation while finishing its old
		// call. Serial withdrawal must still remove this effect before any ack.
		effectsMu.Lock()
		live = true
		effectsMu.Unlock()
		r := ready()
		r.Generation = tok.Suspension.Generation
		m.bindProof(&r)
		return r, nil
	}
	m.suspend = func(_ context.Context, _ *pb.Suspension) (ColdResult, error) {
		effectsMu.Lock()
		live = false
		effectsMu.Unlock()
		return ColdResult{ColdComplete: true}, nil
	}
	if _, err := s.Resume(context.Background(), token(first)); err != nil {
		t.Fatal(err)
	}
	<-entered
	next := begin(t, s, suspension(s))
	<-cancelled
	done := make(chan error, 1)
	go func() { done <- s.Drain(context.Background(), next, mid) }()
	if _, err := s.SuspendAck(next); err == nil {
		t.Fatal("proof preceded overtaken recovery completion")
	}
	close(releaseRecovery)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := s.SuspendAck(next); err != nil {
		t.Fatal(err)
	}
	effectsMu.Lock()
	defer effectsMu.Unlock()
	if live || m.isOpen() {
		t.Fatal("new cold proof retained an overtaken subscription")
	}
}

func TestReviewIdentityMatchingRefusedSuspendClosesAll(t *testing.T) {
	for _, mode := range []string{"stale generation", "host roster", "bad nonce", "discard-only"} {
		t.Run(mode, func(t *testing.T) {
			s, m, mid := fixture(t)
			x := suspension(s)
			switch mode {
			case "stale generation":
				x.Generation = 0
			case "host roster":
				x.Roster = []*pb.MountID{mid}
			case "bad nonce":
				x.Nonce = nil
			case "discard-only":
				s.mu.Lock()
				s.phase = "discard-only"
				s.mu.Unlock()
			}
			if _, err := s.BeginSuspend(x); err == nil {
				t.Fatal("invalid suspend accepted")
			}
			if m.isOpen() {
				t.Fatal("refused identity-matching suspend left admission open")
			}
			if err := s.Activate(context.Background(), mid, 0); err == nil {
				t.Fatal("refusal permitted reopen")
			}
		})
	}
}
func TestGuestOwnsRosterAcrossRegistrationAndReplacement(t *testing.T) {
	s, _, first := fixture(t)
	second := mountID(20)
	second.VolumeId = "late"
	if err := s.Register(context.Background(), second, Witness{}, &fakeMount{cold: ColdResult{ColdComplete: true}}); err != nil {
		t.Fatal(err)
	}
	request := suspension(s)
	if len(request.Roster) != 0 {
		t.Fatal("host owns a roster")
	}
	fixed := begin(t, s, request)
	if len(fixed.Roster) != 2 {
		t.Fatal("guest did not fix all members")
	}
	for _, id := range fixed.Roster {
		if err := s.Drain(context.Background(), fixed, id); err != nil {
			t.Fatal(err)
		}
	}
	ack, err := s.SuspendAck(fixed)
	if err != nil {
		t.Fatal(err)
	}
	if !control.MatchesSuspension(ack.Suspension, request) {
		t.Fatal("acked roster changed transaction identity")
	}
	if _, err := s.Resume(context.Background(), token(request)); err == nil {
		t.Fatal("token omitted acked roster")
	}
	if first == nil {
		t.Fatal("missing first mount")
	}
}
func TestReviewActivateCannotBypassTokenRecovery(t *testing.T) {
	s, m, mid := fixture(t)
	x := cold(t, s, mid)
	m.recoverResult.SessionValidated = false
	if _, err := resumeAndWait(t, s, context.Background(), token(x)); err != nil {
		t.Fatal(err)
	}
	if err := s.Activate(context.Background(), mid, s.Status().Generation); err == nil || m.isOpen() {
		t.Fatal("initial activation bypassed token recovery")
	}
}
func TestGuestDriverProofMustMatchGeneration(t *testing.T) {
	s, m, mid := fixture(t)
	x := cold(t, s, mid)
	m.recover = func(context.Context, *pb.ResumeToken) (Recovery, error) { return ready(), nil }
	if _, err := resumeAndWait(t, s, context.Background(), token(x)); err != nil {
		t.Fatal(err)
	}
	if m.isOpen() {
		t.Fatal("stale driver proof opened mount")
	}
}
func TestGuestMountRecoveryIsIndependent(t *testing.T) {
	s, m, first := fixture(t)
	second := mountID(20)
	second.VolumeId = "second"
	other := &fakeMount{cold: ColdResult{ColdComplete: true}, recoverResult: ready()}
	if err := s.Register(context.Background(), second, Witness{}, other); err != nil {
		t.Fatal(err)
	}
	x := begin(t, s, suspension(s))
	for _, mid := range []*pb.MountID{first, second} {
		if err := s.Drain(context.Background(), x, mid); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SuspendAck(x); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	m.recover = func(ctx context.Context, tok *pb.ResumeToken) (Recovery, error) {
		close(entered)
		<-release
		r := ready()
		r.Generation = tok.Suspension.Generation
		m.bindProof(&r)
		return r, nil
	}
	ack, err := s.Resume(context.Background(), token(x))
	if err != nil {
		t.Fatal(err)
	}
	if ack.Mounts[0].State != "recovering" || s.Status().State != "running" {
		t.Fatal("resume waited for network recovery")
	}
	<-entered
	deadline := time.Now().Add(3 * time.Second)
	for !other.isOpen() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !other.isOpen() || m.isOpen() {
		t.Fatal("one unavailable authority blocked another mount")
	}
	close(release)
	waitRecovered(t, s)
}
func TestGuestCleanedTerminalMountIsTriviallyCold(t *testing.T) {
	for _, cleaned := range []bool{false, true} {
		t.Run(fmt.Sprint(cleaned), func(t *testing.T) {
			s, m, mid := fixture(t)
			if err := s.Terminal(mid, "session ended", nil); err != nil {
				t.Fatal(err)
			}
			if cleaned {
				if err := s.Cleanup(mid, CleanupProof{Witness: s.mounts[control.MountKey(mid)].witness, ProcessExited: true, KernelAbsent: true}); err != nil {
					t.Fatal(err)
				}
			}
			m.suspend = func(context.Context, *pb.Suspension) (ColdResult, error) {
				return ColdResult{}, errors.New("daemon gone but kernel withdrawal unproven")
			}
			x := begin(t, s, suspension(s))
			err := s.Drain(context.Background(), x, mid)
			if cleaned {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.SuspendAck(x); err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("terminal state inferred kernel absence")
			}
		})
	}
}
func TestGuestLossCapacityClosesOnlyMountAndStillAcknowledgesCold(t *testing.T) {
	s, m, mid := fixture(t)
	for i := 1; i <= 129; i++ {
		m.cold.Loss = append(m.cold.Loss, &pb.Loss{Sequence: uint64(i), AcceptedEntries: 1, AcceptedBytes: 10, Reason: "unprovable accepted tail"})
	}
	x := cold(t, s, mid)
	status := s.Status().Mounts[0]
	if status.State != "terminal" || len(status.Loss) != control.MaxLosses || !status.Loss[control.MaxLosses-1].Aggregated {
		t.Fatal("loss capacity lost outcome or failed entire suspension")
	}
	ack := &pb.ResumeAck{Token: token(x), Mounts: []*pb.MountStatus{status}}
	if _, err := control.Encode(&pb.Envelope{Version: 8, RequestId: 1, Body: &pb.Envelope_ResumeAck{ResumeAck: ack}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resume(context.Background(), token(x)); err != nil {
		t.Fatal(err)
	}
	if m.isOpen() {
		t.Fatal("overflowed mount revived")
	}
}
func TestGuestRetiredCapacityCanBeAcknowledgedAndReused(t *testing.T) {
	s, _, mid := fixture(t)
	for i := 0; i < MaxReservations+1; i++ {
		if err := s.Terminal(mid, "session ended", []*pb.Loss{{Sequence: 1, Reason: "retained failure"}}); err != nil {
			t.Fatal(err)
		}
		w := s.mounts[control.MountKey(mid)].witness
		if err := s.Cleanup(mid, CleanupProof{Witness: w, ProcessExited: true, KernelAbsent: true}); err != nil {
			t.Fatal(err)
		}
		next := mountID(byte(i + 10))
		m := &fakeMount{}
		if i == MaxReservations-1 {
			if err := s.Replace(context.Background(), mid, next, Witness{}, m); err == nil || !m.cleaned {
				t.Fatal("unobserved retired outcomes discarded")
			}
			observed := s.Retired()
			if err := s.AcknowledgeRetired(s.retirementSequence + 1); err == nil {
				t.Fatal("unchecked acknowledgement erased loss")
			}
			for len(observed) > 0 {
				batch := min(len(observed), control.MaxRetiredBatch)
				if err := s.AcknowledgeRetired(observed[batch-1].RetirementSequence); err != nil {
					t.Fatal(err)
				}
				observed = observed[batch:]
			}
			m = &fakeMount{}
		}
		var err error
		if i == MaxReservations-1 {
			// Replace retired the old key before new-key backpressure. The
			// acknowledged exact cleanup needs no retained membership tombstone.
			err = s.Register(context.Background(), next, Witness{}, m)
		} else {
			err = s.Replace(context.Background(), mid, next, Witness{}, m)
		}
		if err != nil {
			t.Fatal(err)
		}
		if m.isOpen() {
			t.Fatal("replacement starts open")
		}
		if err := s.Activate(context.Background(), next, s.Status().Generation); err != nil {
			t.Fatal(err)
		}
		mid = next
	}
}

func TestGuestColdProofMustMatchDriverGeneration(t *testing.T) {
	s, m, mid := fixture(t)
	first := cold(t, s, mid)
	if _, err := resumeAndWait(t, s, context.Background(), token(first)); err != nil {
		t.Fatal(err)
	}
	m.suspend = func(context.Context, *pb.Suspension) (ColdResult, error) {
		return ColdResult{Generation: 1, ColdComplete: true}, nil
	}
	next := begin(t, s, suspension(s))
	if err := s.Drain(context.Background(), next, mid); err == nil {
		t.Fatal("stale driver cold proof accepted")
	}
	if _, err := s.SuspendAck(next); err == nil {
		t.Fatal("stale generation earned cold acknowledgement")
	}
}

func TestGuestRecoveryOutlivesCompletedResumeRequest(t *testing.T) {
	s, m, mid := fixture(t)
	x := cold(t, s, mid)
	entered := make(chan struct{})
	release := make(chan struct{})
	m.recover = func(ctx context.Context, tok *pb.ResumeToken) (Recovery, error) {
		close(entered)
		<-release
		if err := ctx.Err(); err != nil {
			return Recovery{}, err
		}
		r := ready()
		r.Generation = tok.Suspension.Generation
		m.bindProof(&r)
		return r, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := s.Resume(ctx, token(x)); err != nil {
		t.Fatal(err)
	}
	<-entered
	cancel()
	close(release)
	if ms := waitRecovered(t, s); ms[0].State != "ready" || !m.isOpen() {
		t.Fatal("request lifetime canceled generation-owned recovery")
	}
}

func TestGuestTerminalizationRetainsLateRecoveryLoss(t *testing.T) {
	s, m, mid := fixture(t)
	x := cold(t, s, mid)
	entered := make(chan struct{})
	release := make(chan struct{})
	m.recover = func(context.Context, *pb.ResumeToken) (Recovery, error) {
		close(entered)
		<-release
		return Recovery{Loss: []*pb.Loss{{Sequence: 1, AcceptedBytes: 4096, Reason: "late failed recovery tail"}}}, errors.New("recovery failed")
	}
	if _, err := s.Resume(context.Background(), token(x)); err != nil {
		t.Fatal(err)
	}
	<-entered
	if err := s.Terminal(mid, "session ended", nil); err != nil {
		t.Fatal(err)
	}
	close(release)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ms := s.Status().Mounts[0]
		if len(ms.Loss) == 1 {
			if ms.State != "terminal" || m.isOpen() {
				t.Fatal("late recovery revived terminal mount")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("terminalization erased late driver loss")
}
