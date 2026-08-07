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

func TestValidateAttachSlotsMatchesAttachAdmission(t *testing.T) {
	a, _ := testAuthority(t)
	for _, slots := range []uint32{0, 5} {
		if err := a.ValidateAttachSlots(slots); !errors.Is(err, ErrSlotRange) {
			t.Fatalf("ValidateAttachSlots(%d) = %v, want ErrSlotRange", slots, err)
		}
	}
	for _, slots := range []uint32{1, 4} {
		if err := a.ValidateAttachSlots(slots); err != nil {
			t.Fatalf("ValidateAttachSlots(%d) = %v", slots, err)
		}
	}
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

// TestBlockingLockAcrossASweepIsNotGranted is the sequence the authority is
// deployed into: the connection idle timeout is required to exceed the session
// lease, so a swept session's connection and request contexts stay alive for
// minutes afterwards. Two sessions attach, one holds an exclusive range, the
// other blocks on it, the partition expires both leases, and the sweep runs.
// Lock ownership used to be surrendered only when the last pin dropped — and the
// blocked waiter was itself the pin — so the holder's cleanup granted the
// waiter, F_SETLKW reported success under a session the authority had already
// destroyed, and the range then became available to a fresh mount while the
// client still believed it held it.
func TestBlockingLockAcrossASweepIsNotGranted(t *testing.T) {
	a, now := testAuthority(t)
	holder, err := a.Attach(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := a.Attach(1, PeerIdentity{2}, testAuthorization(AccessRead|AccessWrite))
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectKey{7}
	if err := a.Locks().Set(writeLock(object, LockOwner{Session: holder.ID}, ToEOF(0))); err != nil {
		t.Fatal(err)
	}

	// The blocked request is an admitted operation: its pin is exactly what
	// keeps the session's cleanup deferred.
	pin, err := a.Begin(blocked)
	if err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() {
		waited <- a.Locks().Wait(context.Background(), writeLock(object, LockOwner{Session: blocked.ID}, ToEOF(0)))
	}()
	waitForQueued(t, a.Locks(), object, 1)

	*now = now.Add(3 * time.Minute)
	if swept := a.Sweep(); swept != 2 {
		t.Fatalf("Sweep=%d, want 2", swept)
	}
	select {
	case err := <-waited:
		if !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("blocking lock across a sweep = %v, want ErrSessionExpired", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a blocked waiter kept its session pin after the sweep, so cleanup could never run")
	}
	if got := len(heldRecords(a.Locks(), object)); got != 0 {
		t.Fatalf("swept sessions left %d records behind", got)
	}
	pin.End()

	fresh, err := a.Attach(1, PeerIdentity{3}, testAuthorization(AccessRead|AccessWrite))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Locks().Set(writeLock(object, LockOwner{Session: fresh.ID}, ToEOF(0))); err != nil {
		t.Fatalf("fresh mount could not take the vacated range: %v", err)
	}
}

// TestExpiredSessionCannotAcquireBeforeTheSweep: the sweeper is periodic, so
// lease expiry and session removal are not the same instant. An operation
// admitted before the expiry must not be able to install a record after it.
func TestExpiredSessionCannotAcquireBeforeTheSweep(t *testing.T) {
	a, now := testAuthority(t)
	cred, err := a.Attach(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectKey{4}
	if err := a.Locks().Set(writeLock(object, LockOwner{Session: cred.ID}, ToEOF(0))); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(2 * time.Minute)
	if err := a.Locks().Set(writeLock(object, LockOwner{Session: cred.ID}, LockRange{Start: 0, End: 0})); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Set on an expired lease = %v, want ErrSessionExpired", err)
	}
	if err := a.Locks().Wait(context.Background(), writeLock(object, LockOwner{Session: cred.ID}, LockRange{Start: 0, End: 0})); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Wait on an expired lease = %v, want ErrSessionExpired", err)
	}
}

func TestDetachSurrendersLocksBeforeInFlightOperationsDrain(t *testing.T) {
	a, _ := testAuthority(t)
	cred, err := a.Attach(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectKey{5}
	if err := a.Locks().Set(writeLock(object, LockOwner{Session: cred.ID}, ToEOF(0))); err != nil {
		t.Fatal(err)
	}
	pin, err := a.Begin(cred)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Detach(cred); err != nil {
		t.Fatal(err)
	}
	if got := len(heldRecords(a.Locks(), object)); got != 0 {
		t.Fatalf("a terminal session still held %d records while draining", got)
	}
	if err := a.Locks().Set(writeLock(object, LockOwner{Session: cred.ID}, ToEOF(0))); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Set under a detached session = %v, want ErrSessionExpired", err)
	}
	pin.End()
}

// TestCredentialGenerationIsVerified pins the credential generation as a
// checked protocol constant rather than a field that is compared but can never
// differ.
func TestCredentialGenerationIsVerified(t *testing.T) {
	a, _ := testAuthority(t)
	cred, err := a.Attach(1, PeerIdentity{1}, testAuthorization(AccessRead))
	if err != nil {
		t.Fatal(err)
	}
	if cred.Generation != sessionCredentialGeneration {
		t.Fatalf("minted generation = %d, want %d", cred.Generation, sessionCredentialGeneration)
	}
	forged := cred
	forged.Generation = cred.Generation + 1
	if err := a.Resume(forged); !errors.Is(err, ErrSessionFenced) {
		t.Fatalf("Resume with a foreign generation = %v, want ErrSessionFenced", err)
	}
	if err := a.Resume(cred); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Resume after terminal fencing = %v", err)
	}
}

func TestPerSessionLockBudgetDefaultsToAnEqualShare(t *testing.T) {
	a, err := New("shares", Config{SessionLease: time.Minute, MaxReplaySlots: 1, MaxSessions: 4, MaxLockRecords: 16})
	if err != nil {
		t.Fatal(err)
	}
	if got := a.cfg.MaxLockRecordsPerSession; got != 4 {
		t.Fatalf("derived per-session lock budget = %d, want 4", got)
	}
	explicit, err := New("explicit", Config{SessionLease: time.Minute, MaxReplaySlots: 1, MaxSessions: 4, MaxLockRecords: 16, MaxLockRecordsPerSession: 12})
	if err != nil {
		t.Fatal(err)
	}
	if got := explicit.cfg.MaxLockRecordsPerSession; got != 12 {
		t.Fatalf("explicit per-session lock budget = %d", got)
	}
	if _, err := New("oversized", Config{SessionLease: time.Minute, MaxReplaySlots: 1, MaxSessions: 4, MaxLockRecords: 16, MaxLockRecordsPerSession: 17}); err == nil {
		t.Fatal("a per-session budget larger than the table was accepted")
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

// FenceSession is the action behind participant-scoped cache fencing. It must
// end the session at once, close the terminal boundary the coordinator watches,
// and be safe to repeat, because the path that fences and the watcher that sees
// the result can both reach it.
func TestFenceSessionEndsOneSessionIdempotently(t *testing.T) {
	a, _ := testAuthority(t)
	fenced, err := a.Attach(2, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	if err != nil {
		t.Fatal(err)
	}
	survivor, err := a.Attach(2, PeerIdentity{2}, testAuthorization(AccessRead|AccessWrite))
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := a.SessionTerminal(fenced.ID)
	if err != nil {
		t.Fatal(err)
	}
	a.FenceSession(fenced.ID)
	select {
	case <-terminal:
	default:
		t.Fatal("fencing did not cross the session's terminal boundary")
	}
	if _, err := a.Begin(fenced); !errors.Is(err, ErrSessionFenced) && !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("fenced session Begin = %v, want a terminal session error", err)
	}
	a.FenceSession(fenced.ID)
	a.FenceSession(SessionID{9})

	use, err := a.Begin(survivor)
	if err != nil {
		t.Fatalf("fencing one session ended another: %v", err)
	}
	use.End()
}
