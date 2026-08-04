package volumeserver

import (
	"context"
	"errors"
	"testing"
	"time"
)

func testAuthority(t *testing.T) (*Authority, *time.Time) {
	t.Helper()
	now := time.Unix(1_000, 0)
	a, err := New("volume-a", Config{
		SessionLease: time.Minute, MaxReplaySlots: 4, MaxSessions: 8, MaxLockRecords: 64,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return a, &now
}

func testAuthorization(access Access) Authorization {
	return Authorization{Access: access, Deadline: time.Unix(10_000, 0)}
}

func TestMutationDuplicateDoesNotReexecute(t *testing.T) {
	a, _ := testAuthority(t)
	cred, err := a.Attach(2, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	if err != nil {
		t.Fatal(err)
	}
	id := MutationID{Slot: 0, Sequence: 1, Hash: RequestHash{1}}
	calls := 0
	apply := func(context.Context) Outcome { calls++; return Outcome{Reply: []byte("done")} }
	first, err := a.ExecuteMutation(context.Background(), cred, id, apply)
	if err != nil {
		t.Fatal(err)
	}
	first.Reply[0] = 'X'
	second, err := a.ExecuteMutation(context.Background(), cred, id, apply)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || string(second.Reply) != "done" {
		t.Fatalf("calls=%d reply=%q", calls, second.Reply)
	}
}

func TestMutationIdentityMismatchFencesSession(t *testing.T) {
	a, _ := testAuthority(t)
	cred, _ := a.Attach(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	_, err := a.ExecuteMutation(context.Background(), cred, MutationID{Slot: 0, Sequence: 1, Hash: RequestHash{1}}, func(context.Context) Outcome { return Outcome{} })
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.ExecuteMutation(context.Background(), cred, MutationID{Slot: 0, Sequence: 1, Hash: RequestHash{2}}, func(context.Context) Outcome { t.Fatal("reexecuted"); return Outcome{} })
	if !errors.Is(err, ErrRequestMismatch) {
		t.Fatalf("err=%v", err)
	}
	if err := a.Resume(cred); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Resume after terminal fencing=%v", err)
	}
}

func TestSequenceGapFencesBeforeApply(t *testing.T) {
	a, _ := testAuthority(t)
	cred, _ := a.Attach(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	called := false
	_, err := a.ExecuteMutation(context.Background(), cred, MutationID{Slot: 0, Sequence: 2}, func(context.Context) Outcome { called = true; return Outcome{} })
	if !errors.Is(err, ErrSequenceGap) || called {
		t.Fatalf("err=%v called=%t", err, called)
	}
}

func TestNewAuthorityRejectsOldEpoch(t *testing.T) {
	a, _ := testAuthority(t)
	cred, _ := a.Attach(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	b, _ := testAuthority(t)
	if err := b.Resume(cred); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("Resume=%v", err)
	}
}

func TestSessionIsBoundToAuthenticatedPeer(t *testing.T) {
	a, _ := testAuthority(t)
	cred, _ := a.Attach(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	cred.Peer = PeerIdentity{2}
	if err := a.Resume(cred); !errors.Is(err, ErrSessionFenced) {
		t.Fatalf("Resume from different peer = %v", err)
	}
}

func TestLeaseExpiry(t *testing.T) {
	a, now := testAuthority(t)
	cred, _ := a.Attach(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	*now = now.Add(2 * time.Minute)
	if got := a.Sweep(); got != 1 {
		t.Fatalf("Sweep=%d", got)
	}
	if err := a.Resume(cred); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Resume=%v", err)
	}
}

func TestAuthorizationDeadlineCannotBeRenewed(t *testing.T) {
	a, now := testAuthority(t)
	deadline := now.Add(90 * time.Second)
	cred, err := a.Attach(1, PeerIdentity{1}, Authorization{Access: AccessRead, Deadline: deadline})
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(50 * time.Second)
	if err := a.Resume(cred); err != nil {
		t.Fatalf("Resume before authorization deadline: %v", err)
	}
	*now = deadline
	if err := a.Resume(cred); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Resume at authorization deadline = %v, want ErrSessionExpired", err)
	}
}

func TestSessionCleanupWaitsForAdmittedOperations(t *testing.T) {
	a, _ := testAuthority(t)
	cred, err := a.Attach(1, PeerIdentity{1}, testAuthorization(AccessRead))
	if err != nil {
		t.Fatal(err)
	}
	ended := make(chan SessionID, 1)
	a.OnSessionEnd(func(id SessionID) { ended <- id })
	use, err := a.Begin(cred)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Detach(cred); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ended:
		t.Fatal("session resources ended while an admitted operation was active")
	default:
	}
	use.End()
	select {
	case got := <-ended:
		if got != cred.ID {
			t.Fatalf("ended session = %x, want %x", got, cred.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("session cleanup did not run after the last admitted operation ended")
	}
}

func TestIndependentReplaySlotsExecuteConcurrently(t *testing.T) {
	a, _ := testAuthority(t)
	cred, err := a.Attach(2, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		_, err := a.ExecuteMutation(context.Background(), cred, MutationID{Slot: 0, Sequence: 1}, func(context.Context) Outcome {
			close(started)
			<-release
			return Outcome{}
		})
		firstDone <- err
	}()
	<-started
	secondDone := make(chan error, 1)
	go func() {
		_, err := a.ExecuteMutation(context.Background(), cred, MutationID{Slot: 1, Sequence: 1}, func(context.Context) Outcome { return Outcome{} })
		secondDone <- err
	}()
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("independent replay slot blocked behind unrelated operation")
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestSessionAdmissionIsBoundedAndReleased(t *testing.T) {
	a, err := New("bounded", Config{SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 1, MaxLockRecords: 8})
	if err != nil {
		t.Fatal(err)
	}
	first, err := a.Attach(1, PeerIdentity{1}, Authorization{Access: AccessRead, Deadline: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Attach(1, PeerIdentity{2}, Authorization{Access: AccessRead, Deadline: time.Now().Add(time.Hour)}); !errors.Is(err, ErrAdmission) {
		t.Fatalf("second Attach = %v, want ErrAdmission", err)
	}
	use, err := a.Begin(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Detach(first); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Attach(1, PeerIdentity{2}, Authorization{Access: AccessRead, Deadline: time.Now().Add(time.Hour)}); !errors.Is(err, ErrAdmission) {
		t.Fatalf("Attach while terminal session is still draining = %v, want ErrAdmission", err)
	}
	use.End()
	if _, err := a.Attach(1, PeerIdentity{2}, Authorization{Access: AccessRead, Deadline: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("Attach after release: %v", err)
	}
}
