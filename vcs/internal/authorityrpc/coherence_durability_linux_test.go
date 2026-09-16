//go:build linux

package authorityrpc

import (
	"errors"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
)

func TestCoherenceDurabilityMapsVolumeCutsToSessionPrefixes(t *testing.T) {
	var state coherenceDurability
	firstSession := volumeserver.SessionID{1}
	secondSession := volumeserver.SessionID{2}
	firstIdentity := [16]byte{0x11}
	secondIdentity := [16]byte{0x22}

	if got := state.recordApplied(firstSession, firstIdentity, 1); got != 1 {
		t.Fatalf("first session ticket = %d, want 1", got)
	}
	if got := state.recordApplied(secondSession, secondIdentity, 2); got != 1 {
		t.Fatalf("second session ticket = %d, want 1", got)
	}
	if got := state.recordApplied(firstSession, secondIdentity, 4); got != 2 {
		t.Fatalf("first session second ticket = %d, want 2", got)
	}

	for _, test := range []struct {
		name        string
		session     volumeserver.SessionID
		volumeCut   uint64
		wantApplied uint64
		wantDurable uint64
	}{
		{name: "empty cut", session: firstSession, volumeCut: 0, wantApplied: 2, wantDurable: 0},
		{name: "first ticket", session: firstSession, volumeCut: 1, wantApplied: 2, wantDurable: 1},
		{name: "other session only", session: firstSession, volumeCut: 2, wantApplied: 2, wantDurable: 1},
		{name: "skipped namespace version", session: firstSession, volumeCut: 3, wantApplied: 2, wantDurable: 1},
		{name: "complete", session: firstSession, volumeCut: 4, wantApplied: 2, wantDurable: 2},
		{name: "independent session", session: secondSession, volumeCut: 2, wantApplied: 1, wantDurable: 1},
		{name: "unknown session", session: volumeserver.SessionID{3}, volumeCut: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			applied, durable := state.latest(test.session, test.volumeCut)
			if applied != test.wantApplied || durable != test.wantDurable {
				t.Fatalf("latest = (%d, %d), want (%d, %d)", applied, durable, test.wantApplied, test.wantDurable)
			}
		})
	}

	state.forget(firstSession)
	if applied, durable := state.latest(firstSession, 4); applied != 0 || durable != 0 {
		t.Fatalf("latest after forget = (%d, %d), want (0, 0)", applied, durable)
	}
}

type coherenceSyncTestStore struct {
	volumeStore
	started chan struct{}
	release chan struct{}
	err     error
	calls   atomic.Uint32
}

func (s *coherenceSyncTestStore) SyncFS() error {
	s.calls.Add(1)
	if s.started != nil {
		close(s.started)
	}
	if s.release != nil {
		<-s.release
	}
	return s.err
}

func TestCoherenceSyncPublishesOnlyCapturedVolumeCut(t *testing.T) {
	store := &coherenceSyncTestStore{started: make(chan struct{}), release: make(chan struct{})}
	h := &VolumeHandler{Store: store, Coherence: volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{})}
	h.initCoherence()
	session := volumeserver.SessionID{1}
	identity := [16]byte{1}

	h.coherenceCommitMu.Lock()
	h.coherenceVersion = 1
	h.coherenceDurability.recordApplied(session, identity, 1)
	h.coherenceCommitMu.Unlock()

	type result struct {
		applied uint64
		durable uint64
		err     error
	}
	done := make(chan result, 1)
	go func() {
		applied, durable, err := h.coherenceSyncVolume(session)
		done <- result{applied: applied, durable: durable, err: err}
	}()
	<-store.started

	// This mutation applies after syncfs captured its cut. The syscall may
	// incidentally cover it, but the authority has no proof and must not say so.
	h.coherenceCommitMu.Lock()
	h.coherenceVersion = 2
	h.coherenceDurability.recordApplied(session, identity, 2)
	h.coherenceCommitMu.Unlock()
	close(store.release)

	got := <-done
	if got.err != nil || got.applied != 2 || got.durable != 1 {
		t.Fatalf("coherenceSyncVolume = (%d, %d, %v), want (2, 1, nil)", got.applied, got.durable, got.err)
	}
	if durableCut := h.Coherence.LatestDurable(); durableCut != 1 {
		t.Fatalf("published volume cut = %d, want captured cut 1", durableCut)
	}
}

func TestCoherenceSyncFailureMakesNoDurabilityClaim(t *testing.T) {
	syncErr := errors.New("injected syncfs failure")
	store := &coherenceSyncTestStore{err: syncErr}
	h := &VolumeHandler{Store: store, Coherence: volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{})}
	h.initCoherence()
	session := volumeserver.SessionID{1}

	h.coherenceCommitMu.Lock()
	h.coherenceVersion = 1
	h.coherenceDurability.recordApplied(session, [16]byte{1}, 1)
	h.coherenceCommitMu.Unlock()

	if _, _, err := h.coherenceSyncVolume(session); !errors.Is(err, syncErr) {
		t.Fatalf("coherenceSyncVolume error = %v, want %v", err, syncErr)
	}
	if durableCut := h.Coherence.LatestDurable(); durableCut != 0 {
		t.Fatalf("published volume cut after failure = %d, want 0", durableCut)
	}
	if store.calls.Load() != 1 {
		t.Fatalf("syncfs calls = %d, want 1", store.calls.Load())
	}
}

func TestCoherenceBarrierValidatesAppliedPrefixBeforeSync(t *testing.T) {
	store := &coherenceSyncTestStore{}
	h := &VolumeHandler{Store: store, Coherence: volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{})}
	h.initCoherence()
	session := volumeserver.SessionID{1}

	if _, _, err := h.coherenceBarrier(session, 1); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("future barrier error = %v, want EINVAL", err)
	}
	if store.calls.Load() != 0 {
		t.Fatalf("future barrier called syncfs %d times", store.calls.Load())
	}

	// An empty data cut still performs the volume barrier so namespace changes
	// acknowledged before it are covered.
	h.coherenceCommitMu.Lock()
	h.coherenceVersion = 3
	h.coherenceCommitMu.Unlock()
	applied, durable, err := h.coherenceBarrier(session, 0)
	if err != nil || applied != 0 || durable != 0 {
		t.Fatalf("empty barrier = (%d, %d, %v), want (0, 0, nil)", applied, durable, err)
	}
	if store.calls.Load() != 1 {
		t.Fatalf("empty barrier syncfs calls = %d, want 1", store.calls.Load())
	}
	if durableCut := h.Coherence.LatestDurable(); durableCut != 3 {
		t.Fatalf("empty barrier volume cut = %d, want namespace-inclusive cut 3", durableCut)
	}
}

func TestCoherenceBarrierHandlerIsReplaySafe(t *testing.T) {
	store := &coherenceSyncTestStore{}
	h, ctx, session, _ := resourceAdmissionRequestHarness(t, store, 4, 4)
	identity := [16]byte{1}
	h.coherenceCommitMu.Lock()
	h.coherenceVersion = 2
	h.coherenceDurability.recordApplied(session.ID, identity, 2)
	h.coherenceCommitMu.Unlock()

	request := &authoritypb.Request{
		RequestId: 1,
		Epoch:     session.Epoch[:],
		Session: &authoritypb.SessionProof{
			Id: session.ID[:], Generation: session.Generation, ResumeSecret: session.Secret[:],
		},
		Body: &authoritypb.Request_Barrier{Barrier: &authoritypb.BarrierRequest{
			CutSequence: 1,
		}},
	}
	stampMutation(t, request, 0, 1)
	first := h.Handle(ctx, request)
	if first.GetErrno() != 0 || first.GetBarrier().GetAppliedSequence() != 1 || first.GetBarrier().GetDurableSequence() != 1 {
		t.Fatalf("Barrier = %+v, want applied=durable=1", first)
	}
	if store.calls.Load() != 1 {
		t.Fatalf("Barrier syncfs calls = %d, want 1", store.calls.Load())
	}

	replay := proto.Clone(request).(*authoritypb.Request)
	replay.RequestId = 2
	second := h.Handle(ctx, replay)
	if second.GetErrno() != 0 || !proto.Equal(first.GetBarrier(), second.GetBarrier()) {
		t.Fatalf("Barrier replay = %+v, first = %+v", second, first)
	}
	if store.calls.Load() != 1 {
		t.Fatalf("Barrier replay repeated syncfs: calls = %d", store.calls.Load())
	}

	future := proto.Clone(request).(*authoritypb.Request)
	future.RequestId = 3
	future.Mutation.Sequence = 2
	future.GetBarrier().CutSequence = 2
	refused := h.Handle(ctx, future)
	if refused.GetErrno() != int32(syscall.EINVAL) || refused.GetUncertain() {
		t.Fatalf("future Barrier = %+v, want definite EINVAL", refused)
	}
	if store.calls.Load() != 1 {
		t.Fatalf("future Barrier reached syncfs: calls = %d", store.calls.Load())
	}
}

func TestCoherenceDurableTicketsDoNotAccumulateInLongLivedSessions(t *testing.T) {
	var ledger coherenceDurability
	writer, idle := volumeserver.SessionID{1}, volumeserver.SessionID{2}
	identity := [16]byte{9}
	ledger.recordApplied(idle, identity, 1)
	for ticket := uint64(1); ticket <= 100000; ticket++ {
		if got := ledger.recordApplied(writer, identity, ticket+1); got != ticket {
			t.Fatalf("ticket=%d want=%d", got, ticket)
		}
		if ticket%64 == 0 {
			ledger.retire(ticket) // Leave the newest application unproven.
			state := ledger.sessions[writer]
			if len(state.applications) != 1 || state.durable != ticket-1 {
				t.Fatalf("retained=%d durable=%d", len(state.applications), state.durable)
			}
			if cap(state.applications) > 64 {
				t.Fatalf("retained backing capacity=%d", cap(state.applications))
			}
		}
	}
	ledger.retire(100001)
	for _, session := range []volumeserver.SessionID{writer, idle} {
		state := ledger.sessions[session]
		if state.applications != nil || state.durable != state.applied {
			t.Fatalf("durable session retained history: %+v", state)
		}
	}
	if applied, durable := ledger.latest(writer, 100001); applied != 100000 || durable != 100000 {
		t.Fatalf("prefix=%d/%d", applied, durable)
	}
	if next := ledger.recordApplied(writer, identity, 100002); next != 100001 {
		t.Fatalf("retirement reset sequence: %d", next)
	}
}
