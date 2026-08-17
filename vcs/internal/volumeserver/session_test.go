package volumeserver

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
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

func TestSessionLifecycleObserversTrackExactActiveBoundary(t *testing.T) {
	var active, terminal atomic.Int64
	now := time.Unix(1_000, 0)
	authority, err := New("observed", Config{
		SessionLease: time.Minute, MaxReplaySlots: 4, MaxSessions: 8, MaxLockRecords: 64,
		Now:               func() time.Time { return now },
		OnSessionActive:   func(SessionID) { active.Add(1) },
		OnSessionTerminal: func(SessionID) { terminal.Add(1) },
	})
	if err != nil {
		t.Fatal(err)
	}
	attempt := AttachAttemptID{1}
	credential := prepareTestSession(t, authority, &now, attempt)
	if active.Load() != 0 || terminal.Load() != 0 {
		t.Fatalf("provisional observers = active %d terminal %d", active.Load(), terminal.Load())
	}
	token, err := authority.PrepareActivation(t.Context(), credential, attempt)
	if err != nil {
		t.Fatal(err)
	}
	authority.CommitActivation(token)
	if active.Load() != 1 || terminal.Load() != 0 {
		t.Fatalf("active observers = active %d terminal %d", active.Load(), terminal.Load())
	}
	authority.FenceSession(credential.ID)
	authority.FenceSession(credential.ID)
	if active.Load() != 1 || terminal.Load() != 1 {
		t.Fatalf("terminal observers = active %d terminal %d", active.Load(), terminal.Load())
	}
}

func prepareTestSession(t *testing.T, a *Authority, now *time.Time, attempt AttachAttemptID) SessionCredential {
	t.Helper()
	cred, err := a.PrepareAttach(
		context.Background(), attempt, AttachRequestFingerprint{9}, 2, PeerIdentity{1},
		func(context.Context) (Authorization, error) {
			return Authorization{Access: AccessRead | AccessWrite, Deadline: now.Add(10 * time.Minute)}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

func TestPreparedSessionCannotExecuteOrOwnLocksBeforeActivation(t *testing.T) {
	a, now := testAuthority(t)
	attempt := AttachAttemptID{1}
	cred := prepareTestSession(t, a, now, attempt)
	if deadline, err := a.ProvisionalDeadline(cred, attempt); err != nil || !deadline.Equal(now.Add(time.Minute)) {
		t.Fatalf("provisional deadline = %s, %v; want %s", deadline, err, now.Add(time.Minute))
	}
	if deadline, err := a.AuthorizationDeadline(cred, attempt); err != nil || !deadline.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("authorization deadline = %s, %v; want %s", deadline, err, now.Add(10*time.Minute))
	}
	if state, err := a.SessionState(cred, attempt); err != nil || state != SessionStateProvisional {
		t.Fatalf("prepared state = %v, %v", state, err)
	}
	if _, err := a.Begin(cred); !errors.Is(err, ErrSessionProvisional) {
		t.Fatalf("Begin provisional = %v, want ErrSessionProvisional", err)
	}
	if _, err := a.Access(cred); !errors.Is(err, ErrSessionProvisional) {
		t.Fatalf("Access provisional = %v, want ErrSessionProvisional", err)
	}
	if err := a.Resume(cred); !errors.Is(err, ErrSessionProvisional) {
		t.Fatalf("Resume provisional = %v, want ErrSessionProvisional", err)
	}
	if err := a.Reauthorize(cred, Authorization{Access: AccessRead, Deadline: now.Add(time.Hour)}, 1, [32]byte{1}); !errors.Is(err, ErrSessionProvisional) {
		t.Fatalf("Reauthorize provisional = %v, want ErrSessionProvisional", err)
	}
	object := ObjectKey{7}
	if err := a.Locks().Set(writeLock(object, LockOwner{Session: cred.ID}, ToEOF(0))); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("lock under provisional session = %v, want ErrSessionExpired", err)
	}

	token, err := a.PrepareActivation(context.Background(), cred, attempt)
	if err != nil {
		t.Fatal(err)
	}
	if token.Replay() {
		t.Fatal("first activation was reported as replay")
	}
	a.CommitActivation(token)
	if state, err := a.SessionState(cred, attempt); err != nil || state != SessionStateActive {
		t.Fatalf("activated state = %v, %v", state, err)
	}
	use, err := a.Begin(cred)
	if err != nil {
		t.Fatalf("Begin active = %v", err)
	}
	use.End()
	if err := a.Locks().Set(writeLock(object, LockOwner{Session: cred.ID}, ToEOF(0))); err != nil {
		t.Fatalf("lock under active session = %v", err)
	}
}

func TestSessionStateByIDReconcilesLiveAndRetainedTerminalStateWithoutRenewal(t *testing.T) {
	a, now := testAuthority(t)
	attempt := AttachAttemptID{11}
	cred := prepareTestSession(t, a, now, attempt)
	if state, ok := a.SessionStateByID(cred.ID); !ok || state != SessionStateProvisional {
		t.Fatalf("prepared state by ID = %v, %t", state, ok)
	}
	token, err := a.PrepareActivation(context.Background(), cred, attempt)
	if err != nil {
		t.Fatal(err)
	}
	a.CommitActivation(token)
	if state, ok := a.SessionStateByID(cred.ID); !ok || state != SessionStateActive {
		t.Fatalf("active state by ID = %v, %t", state, ok)
	}

	// The query is observational: it cannot renew the active lease. At its
	// original boundary Sweep must still remove the session. The attempt's
	// bounded tombstone may expire in that same sweep; absence is the exact
	// non-live fact transport reconciliation needs.
	*now = now.Add(time.Minute)
	if got := a.Sweep(); got != 1 {
		t.Fatalf("Sweep after read-only state query = %d, want 1", got)
	}
	if state, ok := a.SessionStateByID(cred.ID); ok || state != SessionStateUnknown {
		t.Fatalf("expired state by ID = %v, %t", state, ok)
	}
	if state, ok := a.SessionStateByID(SessionID{99}); ok || state != SessionStateUnknown {
		t.Fatalf("unknown state by ID = %v, %t", state, ok)
	}

	b, nowB := testAuthority(t)
	attemptB := AttachAttemptID{12}
	credB := prepareTestSession(t, b, nowB, attemptB)
	if err := b.AbortProvisional(context.Background(), credB, attemptB); err != nil {
		t.Fatal(err)
	}
	if state, ok := b.SessionStateByID(credB.ID); !ok || state != SessionStateAborted {
		t.Fatalf("aborted state by ID = %v, %t", state, ok)
	}
}

func TestPrepareAttachConcurrentDuplicateAuthorizesExactlyOnce(t *testing.T) {
	a, now := testAuthority(t)
	attempt := AttachAttemptID{2}
	fingerprint := AttachRequestFingerprint{3}
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	authorize := func(context.Context) (Authorization, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return Authorization{Access: AccessRead, Deadline: now.Add(time.Hour)}, nil
	}
	type result struct {
		cred SessionCredential
		err  error
	}
	results := make(chan result, 16)
	for range 16 {
		go func() {
			cred, err := a.PrepareAttach(context.Background(), attempt, fingerprint, 2, PeerIdentity{4}, authorize)
			results <- result{cred: cred, err: err}
		}()
	}
	<-started
	if _, err := a.PrepareAttach(context.Background(), attempt, AttachRequestFingerprint{8}, 2, PeerIdentity{4}, func(context.Context) (Authorization, error) {
		t.Fatal("changed reuse invoked authorization")
		return Authorization{}, nil
	}); !errors.Is(err, ErrAttachAttemptMismatch) {
		t.Fatalf("changed attach reuse = %v", err)
	}
	close(release)
	var first SessionCredential
	for range 16 {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		if first == (SessionCredential{}) {
			first = got.cred
		} else if got.cred != first {
			t.Fatalf("duplicate returned a second credential: %+v != %+v", got.cred, first)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("authorization calls = %d, want 1", got)
	}
}

func TestPrepareAttachReservesAdmissionBeforeAuthorization(t *testing.T) {
	now := time.Unix(1_000, 0)
	a, err := New("bounded-prepare", Config{
		SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 1, MaxLockRecords: 8,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		_, err := a.PrepareAttach(context.Background(), AttachAttemptID{1}, AttachRequestFingerprint{1}, 1, PeerIdentity{1}, func(context.Context) (Authorization, error) {
			close(started)
			<-release
			return Authorization{Access: AccessRead, Deadline: now.Add(time.Hour)}, nil
		})
		firstDone <- err
	}()
	<-started
	called := false
	_, err = a.PrepareAttach(context.Background(), AttachAttemptID{2}, AttachRequestFingerprint{2}, 1, PeerIdentity{2}, func(context.Context) (Authorization, error) {
		called = true
		return Authorization{}, nil
	})
	if !errors.Is(err, ErrAdmission) || called {
		t.Fatalf("second prepare = %v, authorization called=%t", err, called)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestPrepareAttachPublishesAuthorizationDeadlineDuringConcurrentSweep(t *testing.T) {
	now := time.Unix(1_000, 0)
	a, err := New("atomic-prepare-publication", Config{
		SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 8, MaxLockRecords: 64,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	attempt := AttachAttemptID{4}
	fingerprint := AttachRequestFingerprint{4}
	started := make(chan struct{})
	release := make(chan struct{})
	type result struct {
		cred SessionCredential
		err  error
	}
	prepared := make(chan result, 1)
	go func() {
		cred, err := a.PrepareAttach(context.Background(), attempt, fingerprint, 1, PeerIdentity{4}, func(context.Context) (Authorization, error) {
			close(started)
			<-release
			return Authorization{Access: AccessRead, Deadline: now.Add(30 * time.Second)}, nil
		})
		prepared <- result{cred: cred, err: err}
	}()
	<-started

	// Exercise attempt sweeping continuously across the authorization result's
	// publication. An incomplete attempt must remain admitted; once complete,
	// its credential and authorization-derived deadline become visible as one
	// locked result.
	stopSweep := make(chan struct{})
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		for {
			select {
			case <-stopSweep:
				return
			default:
				a.Sweep()
			}
		}
	}()
	close(release)
	got := <-prepared
	close(stopSweep)
	<-sweepDone
	if got.err != nil {
		t.Fatal(got.err)
	}
	wantDeadline := now.Add(30 * time.Second)
	if deadline, err := a.ProvisionalDeadline(got.cred, attempt); err != nil || !deadline.Equal(wantDeadline) {
		t.Fatalf("provisional deadline = %s, %v; want %s", deadline, err, wantDeadline)
	}
	if deadline, err := a.AuthorizationDeadline(got.cred, attempt); err != nil || !deadline.Equal(wantDeadline) {
		t.Fatalf("authorization deadline = %s, %v; want %s", deadline, err, wantDeadline)
	}
	if replay, err := a.PrepareAttach(context.Background(), attempt, fingerprint, 1, PeerIdentity{4}, func(context.Context) (Authorization, error) {
		t.Fatal("exact replay invoked authorization")
		return Authorization{}, nil
	}); err != nil || replay != got.cred {
		t.Fatalf("exact replay = %+v, %v; want original credential", replay, err)
	}
}

func TestProvisionalDeadlineIsAbsoluteAndAttemptIsTombstoned(t *testing.T) {
	a, now := testAuthority(t)
	attempt := AttachAttemptID{5}
	deadline := now.Add(30 * time.Second)
	cred, err := a.PrepareAttach(context.Background(), attempt, AttachRequestFingerprint{5}, 1, PeerIdentity{1}, func(context.Context) (Authorization, error) {
		return Authorization{Access: AccessRead, Deadline: deadline}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(20 * time.Second)
	if err := a.Resume(cred); !errors.Is(err, ErrSessionProvisional) {
		t.Fatalf("provisional Resume = %v", err)
	}
	*now = deadline
	if got := a.Sweep(); got != 1 {
		t.Fatalf("Sweep at absolute deadline = %d, want 1", got)
	}
	if _, err := a.Begin(cred); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Begin expired provisional = %v", err)
	}

	// An explicit abort earlier than the lease keeps an exact tombstone, so a
	// retry cannot spend authorization or create another session.
	a2, now2 := testAuthority(t)
	attempt2 := AttachAttemptID{6}
	cred2 := prepareTestSession(t, a2, now2, attempt2)
	if err := a2.AbortProvisional(context.Background(), cred2, attempt2); err != nil {
		t.Fatal(err)
	}
	if err := a2.AbortProvisional(context.Background(), cred2, attempt2); err != nil {
		t.Fatalf("idempotent abort = %v", err)
	}
	called := false
	if _, err := a2.PrepareAttach(context.Background(), attempt2, AttachRequestFingerprint{9}, 2, PeerIdentity{1}, func(context.Context) (Authorization, error) {
		called = true
		return Authorization{}, nil
	}); !errors.Is(err, ErrSessionExpired) || called {
		t.Fatalf("aborted retry = %v, authorization called=%t", err, called)
	}

	// A forged abort is not an oracle that leaves the real provisional
	// credential usable. Credential disagreement fences the attempt.
	a3, now3 := testAuthority(t)
	attempt3 := AttachAttemptID{9}
	cred3 := prepareTestSession(t, a3, now3, attempt3)
	forged := cred3
	forged.Secret[0] ^= 1
	if err := a3.AbortProvisional(context.Background(), forged, attempt3); !errors.Is(err, ErrSessionFenced) {
		t.Fatalf("forged abort = %v, want ErrSessionFenced", err)
	}
	if state, err := a3.SessionState(cred3, attempt3); err != nil || state != SessionStateTerminal {
		t.Fatalf("state after forged abort = %v, %v; want terminal", state, err)
	}
}

func TestActivationAndAbortHaveOneWinnerAndActiveReplayIsIdempotent(t *testing.T) {
	a, now := testAuthority(t)
	attempt := AttachAttemptID{7}
	cred := prepareTestSession(t, a, now, attempt)
	token, err := a.PrepareActivation(context.Background(), cred, attempt)
	if err != nil {
		t.Fatal(err)
	}
	abortDone := make(chan error, 1)
	go func() { abortDone <- a.AbortProvisional(context.Background(), cred, attempt) }()
	select {
	case err := <-abortDone:
		t.Fatalf("abort crossed a prepared activation: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	a.CommitActivation(token)
	if err := <-abortDone; !errors.Is(err, ErrSessionActive) {
		t.Fatalf("abort after activation commit = %v, want ErrSessionActive", err)
	}
	replay, err := a.PrepareActivation(context.Background(), cred, attempt)
	if err != nil {
		t.Fatalf("active activation replay = %v", err)
	}
	if !replay.Replay() {
		t.Fatal("active activation replay was not identified")
	}
	a.CommitActivation(replay)
	if state, err := a.SessionState(cred, attempt); err != nil || state != SessionStateActive {
		t.Fatalf("state after activation replay = %v, %v", state, err)
	}
	*now = now.Add(time.Minute)
	if _, err := a.PrepareActivation(context.Background(), cred, attempt); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("activation replay after active lease = %v, want ErrSessionExpired", err)
	}
	if state, err := a.SessionState(cred, attempt); err != nil || state != SessionStateTerminal {
		t.Fatalf("state after expired active replay = %v, %v; want terminal", state, err)
	}

	b, nowB := testAuthority(t)
	attemptB := AttachAttemptID{8}
	credB := prepareTestSession(t, b, nowB, attemptB)
	tokenB, err := b.PrepareActivation(context.Background(), credB, attemptB)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	wait.Add(1)
	aborted := make(chan error, 1)
	go func() {
		defer wait.Done()
		aborted <- b.AbortProvisional(context.Background(), credB, attemptB)
	}()
	b.CancelActivation(tokenB)
	wait.Wait()
	if err := <-aborted; err != nil {
		t.Fatalf("abort after activation cancel = %v", err)
	}
	if state, err := b.SessionState(credB, attemptB); err != nil || state != SessionStateAborted {
		t.Fatalf("canceled/aborted state = %v, %v", state, err)
	}
}

func TestActivationReservationMakesCommitInfallibleAgainstFence(t *testing.T) {
	a, now := testAuthority(t)
	attempt := AttachAttemptID{10}
	cred := prepareTestSession(t, a, now, attempt)
	token, err := a.PrepareActivation(context.Background(), cred, attempt)
	if err != nil {
		t.Fatal(err)
	}
	fenced := make(chan struct{})
	go func() {
		a.FenceSession(cred.ID)
		close(fenced)
	}()

	deadline := time.Now().Add(time.Second)
	for {
		a.mu.Lock()
		s := a.sessions[cred.ID]
		requested := false
		if s != nil {
			s.mu.Lock()
			requested = s.fenced
			s.mu.Unlock()
		}
		a.mu.Unlock()
		if requested {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("concurrent fence did not reach activation reservation")
		}
		runtime.Gosched()
	}
	select {
	case <-fenced:
		t.Fatal("fence tore down a prepared activation before its commit verdict")
	default:
	}

	// Commit remains infallible: it crosses ACTIVE and then applies the pending
	// fence under the same authority/session critical section.
	a.CommitActivation(token)
	select {
	case <-fenced:
	case <-time.After(time.Second):
		t.Fatal("fence did not finish after activation commit")
	}
	if state, err := a.SessionState(cred, attempt); err != nil || state != SessionStateTerminal {
		t.Fatalf("state after commit/fence = %v, %v; want terminal", state, err)
	}
	if err := a.AbortProvisional(context.Background(), cred, attempt); !errors.Is(err, ErrSessionActive) {
		t.Fatalf("abort after committed-then-fenced activation = %v, want ErrSessionActive", err)
	}
}

func TestReplayFingerprintIsKeyedAndPinned(t *testing.T) {
	a, _ := testAuthority(t)
	for index := range a.replayFingerprintKey {
		a.replayFingerprintKey[index] = byte(index)
	}
	body := []byte("portablefs protocol 4 replay body")
	got, err := a.ReplayFingerprint(func(writer io.Writer) error {
		_, err := writer.Write(body)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("0ece4064962fd377c07cc8139a1144fee18aa0e9eaf179f999fe06ce6d5015b8")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("fingerprint = %x, want %x", got, want)
	}

	other, _ := testAuthority(t)
	for index := range other.replayFingerprintKey {
		other.replayFingerprintKey[index] = byte(len(other.replayFingerprintKey) - index)
	}
	otherFingerprint, err := other.ReplayFingerprint(func(writer io.Writer) error {
		_, err := writer.Write(body)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got[:], otherFingerprint[:]) {
		t.Fatal("different authority-epoch keys produced the same fingerprint")
	}
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
	cred, err := a.AttachActiveForTest(2, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	if err != nil {
		t.Fatal(err)
	}
	id := MutationID{Slot: 0, Sequence: 1, Fingerprint: RequestFingerprint{1}}
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

func TestMutationReplayRetainsTerminalDeliveryMetadata(t *testing.T) {
	a, _ := testAuthority(t)
	cred, err := a.AttachActiveForTest(2, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	if err != nil {
		t.Fatal(err)
	}
	id := MutationID{Slot: 0, Sequence: 1, Fingerprint: RequestFingerprint{1}}
	calls := 0
	apply := func(context.Context) Outcome {
		calls++
		return Outcome{Reply: []byte("terminal"), TerminalDeliveryRequired: true}
	}
	first, err := a.ExecuteMutation(context.Background(), cred, id, apply)
	if err != nil {
		t.Fatal(err)
	}
	first.Reply[0] = 'X'
	first.TerminalDeliveryRequired = false
	second, err := a.ExecuteMutation(context.Background(), cred, id, apply)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || string(second.Reply) != "terminal" || !second.TerminalDeliveryRequired {
		t.Fatalf("calls=%d replay=%+v", calls, second)
	}
}

func TestMutationAdmissionRefusalDoesNotAdvanceAndDuplicateSkipsAdmission(t *testing.T) {
	a, _ := testAuthority(t)
	cred, err := a.AttachActiveForTest(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	if err != nil {
		t.Fatal(err)
	}
	id := MutationID{Slot: 0, Sequence: 1, Fingerprint: RequestFingerprint{1}}
	refused := errors.New("reply capacity refused")
	applied := false
	if _, err := a.ExecuteMutationAdmitted(context.Background(), cred, id, func() error {
		return refused
	}, func(context.Context) Outcome {
		applied = true
		return Outcome{}
	}); !errors.Is(err, refused) || applied {
		t.Fatalf("refused mutation = %v applied=%t, want refusal before apply", err, applied)
	}

	want := Outcome{Reply: []byte("admitted")}
	got, err := a.ExecuteMutationAdmitted(context.Background(), cred, id, nil, func(context.Context) Outcome {
		applied = true
		return want
	})
	if err != nil || !applied || !bytes.Equal(got.Reply, want.Reply) {
		t.Fatalf("retry = %+v, %v applied=%t", got, err, applied)
	}
	got, err = a.ExecuteMutationAdmitted(context.Background(), cred, id, func() error {
		t.Fatal("duplicate replay reached admission")
		return nil
	}, func(context.Context) Outcome {
		t.Fatal("duplicate replay reached apply")
		return Outcome{}
	})
	if err != nil || !bytes.Equal(got.Reply, want.Reply) {
		t.Fatalf("duplicate = %+v, %v", got, err)
	}
}

func TestMutationIdentityMismatchFencesSession(t *testing.T) {
	a, _ := testAuthority(t)
	cred, _ := a.AttachActiveForTest(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	_, err := a.ExecuteMutation(context.Background(), cred, MutationID{Slot: 0, Sequence: 1, Fingerprint: RequestFingerprint{1}}, func(context.Context) Outcome { return Outcome{} })
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.ExecuteMutation(context.Background(), cred, MutationID{Slot: 0, Sequence: 1, Fingerprint: RequestFingerprint{2}}, func(context.Context) Outcome { t.Fatal("reexecuted"); return Outcome{} })
	if !errors.Is(err, ErrRequestMismatch) {
		t.Fatalf("err=%v", err)
	}
	if err := a.Resume(cred); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Resume after terminal fencing=%v", err)
	}
}

func TestSequenceGapFencesBeforeApply(t *testing.T) {
	a, _ := testAuthority(t)
	cred, _ := a.AttachActiveForTest(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	called := false
	_, err := a.ExecuteMutation(context.Background(), cred, MutationID{Slot: 0, Sequence: 2}, func(context.Context) Outcome { called = true; return Outcome{} })
	if !errors.Is(err, ErrSequenceGap) || called {
		t.Fatalf("err=%v called=%t", err, called)
	}
}

func TestNewAuthorityRejectsOldEpoch(t *testing.T) {
	a, _ := testAuthority(t)
	cred, _ := a.AttachActiveForTest(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	b, _ := testAuthority(t)
	if err := b.Resume(cred); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("Resume=%v", err)
	}
}

func TestSessionIsBoundToAuthenticatedPeer(t *testing.T) {
	a, _ := testAuthority(t)
	cred, _ := a.AttachActiveForTest(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	cred.Peer = PeerIdentity{2}
	if err := a.Resume(cred); !errors.Is(err, ErrSessionFenced) {
		t.Fatalf("Resume from different peer = %v", err)
	}
}

func TestLeaseExpiry(t *testing.T) {
	a, now := testAuthority(t)
	cred, _ := a.AttachActiveForTest(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
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
	cred, err := a.AttachActiveForTest(1, PeerIdentity{1}, Authorization{Access: AccessRead, Deadline: deadline})
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

func TestExactReauthorizationExtendsDeadlineAndRotatesPeer(t *testing.T) {
	a, now := testAuthority(t)
	originalDeadline := now.Add(90 * time.Second)
	cred, err := a.AttachActiveForTest(1, PeerIdentity{1}, Authorization{Access: AccessRead | AccessWrite, Deadline: originalDeadline})
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(30 * time.Second)
	cred.Peer = PeerIdentity{2}
	proof := [32]byte{9, 8, 7}
	newDeadline := now.Add(5 * time.Minute)
	if err := a.Reauthorize(cred, Authorization{Access: AccessRead, Deadline: newDeadline}, 1, proof); err != nil {
		t.Fatalf("Reauthorize = %v", err)
	}
	if err := a.Reauthorize(cred, Authorization{Access: AccessRead, Deadline: newDeadline}, 1, proof); err != nil {
		t.Fatalf("idempotent Reauthorize = %v", err)
	}
	if access, err := a.Access(cred); err != nil || access != AccessRead {
		t.Fatalf("Access = %v, %v", access, err)
	}
	*now = now.Add(50 * time.Second)
	if err := a.Resume(cred); err != nil {
		t.Fatalf("lease renewal under the rotated authorization failed: %v", err)
	}
	*now = originalDeadline.Add(time.Second)
	if err := a.Resume(cred); err != nil {
		t.Fatalf("renewed authorization expired at the original deadline: %v", err)
	}
}

func TestEnrollmentOwnedSessionRefusesAnotherIssuerWithoutFencing(t *testing.T) {
	a, now := testAuthority(t)
	initial := Authorization{Access: AccessRead, Deadline: now.Add(time.Minute), MountEnrollmentID: "enrollment-a"}
	cred, err := a.AttachActiveForTest(1, PeerIdentity{1}, initial)
	if err != nil {
		t.Fatal(err)
	}
	manual := Authorization{Access: AccessRead, Deadline: now.Add(2 * time.Minute)}
	if err := a.Reauthorize(cred, manual, 1, [32]byte{1}); !errors.Is(err, ErrAuthorizationOwner) {
		t.Fatalf("competing issuer = %v, want ErrAuthorizationOwner", err)
	}
	if err := a.Resume(cred); err != nil {
		t.Fatalf("competing issuer killed the healthy enrollment-owned session: %v", err)
	}
	enrolled := Authorization{Access: AccessRead, Deadline: now.Add(2 * time.Minute), MountEnrollmentID: "enrollment-a"}
	if err := a.Reauthorize(cred, enrolled, 1, [32]byte{2}); err != nil {
		t.Fatalf("enrollment owner could not continue after refused competitor: %v", err)
	}
}

func TestReauthorizationCannotBroadenOrChangeAnExactReplay(t *testing.T) {
	for name, change := range map[string]func(*SessionCredential, *Authorization, *[32]byte, *uint64){
		"broaden": func(_ *SessionCredential, authorization *Authorization, _ *[32]byte, _ *uint64) {
			authorization.Access = AccessRead | AccessWrite
		},
		"sequence gap": func(_ *SessionCredential, _ *Authorization, _ *[32]byte, sequence *uint64) {
			*sequence = 2
		},
	} {
		t.Run(name, func(t *testing.T) {
			a, now := testAuthority(t)
			cred, err := a.AttachActiveForTest(1, PeerIdentity{1}, Authorization{Access: AccessRead, Deadline: now.Add(time.Minute)})
			if err != nil {
				t.Fatal(err)
			}
			authorization := Authorization{Access: AccessRead, Deadline: now.Add(2 * time.Minute)}
			proof := [32]byte{1}
			sequence := uint64(1)
			change(&cred, &authorization, &proof, &sequence)
			if err := a.Reauthorize(cred, authorization, sequence, proof); err == nil {
				t.Fatal("unsafe reauthorization succeeded")
			}
			if err := a.Resume(cred); !errors.Is(err, ErrSessionExpired) && !errors.Is(err, ErrSessionFenced) {
				t.Fatalf("unsafe reauthorization did not fence the session: %v", err)
			}
		})
	}

	a, now := testAuthority(t)
	cred, _ := a.AttachActiveForTest(1, PeerIdentity{1}, Authorization{Access: AccessRead, Deadline: now.Add(time.Minute)})
	authorization := Authorization{Access: AccessRead, Deadline: now.Add(2 * time.Minute)}
	if err := a.Reauthorize(cred, authorization, 1, [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := a.Reauthorize(cred, authorization, 1, [32]byte{2}); !errors.Is(err, ErrRequestMismatch) {
		t.Fatalf("changed exact replay = %v, want ErrRequestMismatch", err)
	}
}

func TestSessionCleanupWaitsForAdmittedOperations(t *testing.T) {
	a, _ := testAuthority(t)
	cred, err := a.AttachActiveForTest(1, PeerIdentity{1}, testAuthorization(AccessRead))
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
	cred, err := a.AttachActiveForTest(2, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
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
	holder, err := a.AttachActiveForTest(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := a.AttachActiveForTest(1, PeerIdentity{2}, testAuthorization(AccessRead|AccessWrite))
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

	fresh, err := a.AttachActiveForTest(1, PeerIdentity{3}, testAuthorization(AccessRead|AccessWrite))
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
	cred, err := a.AttachActiveForTest(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
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
	cred, err := a.AttachActiveForTest(1, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
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
	cred, err := a.AttachActiveForTest(1, PeerIdentity{1}, testAuthorization(AccessRead))
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
	first, err := a.AttachActiveForTest(1, PeerIdentity{1}, Authorization{Access: AccessRead, Deadline: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.AttachActiveForTest(1, PeerIdentity{2}, Authorization{Access: AccessRead, Deadline: time.Now().Add(time.Hour)}); !errors.Is(err, ErrAdmission) {
		t.Fatalf("second Attach = %v, want ErrAdmission", err)
	}
	use, err := a.Begin(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Detach(first); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AttachActiveForTest(1, PeerIdentity{2}, Authorization{Access: AccessRead, Deadline: time.Now().Add(time.Hour)}); !errors.Is(err, ErrAdmission) {
		t.Fatalf("Attach while terminal session is still draining = %v, want ErrAdmission", err)
	}
	use.End()
	if _, err := a.AttachActiveForTest(1, PeerIdentity{2}, Authorization{Access: AccessRead, Deadline: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("Attach after release: %v", err)
	}
}

// FenceSession is the action behind participant-scoped cache fencing. It must
// end the session at once, close the terminal boundary the coordinator watches,
// and be safe to repeat, because the path that fences and the watcher that sees
// the result can both reach it.
func TestFenceSessionEndsOneSessionIdempotently(t *testing.T) {
	a, _ := testAuthority(t)
	fenced, err := a.AttachActiveForTest(2, PeerIdentity{1}, testAuthorization(AccessRead|AccessWrite))
	if err != nil {
		t.Fatal(err)
	}
	survivor, err := a.AttachActiveForTest(2, PeerIdentity{2}, testAuthorization(AccessRead|AccessWrite))
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
