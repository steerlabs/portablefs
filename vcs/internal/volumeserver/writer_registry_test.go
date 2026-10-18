package volumeserver

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestWriterActivationDeferredFenceCanRunSessionEndHook(t *testing.T) {
	a, now := testAuthority(t)
	registry, err := NewWriterRegistry(WriterRegistryConfig{Prior: PriorEpochStrictMountsFenced, Fencer: a})
	if err != nil {
		t.Fatal(err)
	}
	hookRan := make(chan struct{})
	// VolumeHandler's session-end cleanup sweeps the same registry synchronously.
	a.OnSessionEnd(func(SessionID) { registry.SweepExclusions(); close(hookRan) })
	attempt := AttachAttemptID{1}
	cred := prepareTestSession(t, a, now, attempt)
	exclusion, err := a.WriterExclusion(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := a.SessionTerminal(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	token, err := a.PrepareActivation(t.Context(), cred, attempt)
	if err != nil {
		t.Fatal(err)
	}
	bad := cred
	bad.Secret[0] ^= 1
	if _, err := a.Begin(bad); err == nil {
		t.Fatal("mismatched credential did not defer a fence")
	}
	done := make(chan error, 1)
	go func() {
		done <- registry.Activate(cred.ID, terminal, exclusion, func() error { return nil }, func() { a.CommitActivation(token) })
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime commit deadlocked against session-end registry cleanup")
	}
	select {
	case <-hookRan:
	default:
		t.Fatal("commit did not finish deferred session teardown")
	}
	// Retirement is idempotent with the terminal watcher and leaves no owner.
	registry.Fence(cred.ID)
	if err := registry.CheckOwner(cred.ID); !errors.Is(err, ErrSessionFenced) {
		t.Fatalf("terminal session remained owner: %v", err)
	}
	if err := registry.CheckWriter(SessionID{2}); err != nil {
		t.Fatalf("ungranted proof retained foreign exclusion: %v", err)
	}
}

func TestWriterCheckOwnerRequiresExactLiveOwner(t *testing.T) {
	for _, state := range []string{"live", "non-owner", "retired", "closed", "poisoned"} {
		t.Run(state, func(t *testing.T) {
			_, cred, registry, exclusion, _ := writerSession(t, time.Minute, time.Hour)
			id := cred.ID
			var want error
			switch state {
			case "non-owner":
				id[0] ^= 1
				want = ErrSessionFenced
			case "retired":
				registry.Fence(id)
				want = ErrSessionFenced
			case "closed":
				exclusion.stop(false)
				want = ErrSessionFenced
			case "poisoned":
				registry.Poison(errors.New("completion defect"))
				want = ErrMutationPoisoned
			}
			err := registry.CheckOwner(id)
			if !errors.Is(err, want) {
				t.Fatalf("CheckOwner=%v, want %v", err, want)
			}
		})
	}
}

func TestWriterActivationFenceBetweenOwnerPublicationAndCommit(t *testing.T) {
	a, now := testAuthority(t)
	registry, err := NewWriterRegistry(WriterRegistryConfig{Prior: PriorEpochStrictMountsFenced, Fencer: a})
	if err != nil {
		t.Fatal(err)
	}
	membership := &mountLifecycleMembership{}
	lifecycle, err := NewMountLifecycle(MountLifecycleConfig{Membership: membership, Prior: PriorEpochStrictMountsFenced})
	if err != nil {
		t.Fatal(err)
	}
	a.OnSessionEnd(func(SessionID) { registry.SweepExclusions() })
	attempt := AttachAttemptID{19}
	cred := prepareTestSession(t, a, now, attempt)
	exclusion, err := a.WriterExclusion(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := a.SessionTerminal(cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	token, err := a.PrepareActivation(t.Context(), cred, attempt)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := lifecycle.AcquireTopologyRead(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Release()
	published, commit := make(chan struct{}), make(chan struct{})
	releaseCommit := sync.OnceFunc(func() { close(commit) })
	defer releaseCommit()
	done := make(chan error, 1)
	go func() {
		done <- lifecycle.Activate(cred.ID, func() error {
			return registry.Activate(cred.ID, terminal, exclusion, func() error { return nil }, func() { close(published); <-commit; a.CommitActivation(token) })
		})
	}()
	topologyReceive(t, published)
	// The commit boundary has published the exact owner, but the runtime token
	// is still provisional. Registry calls must be safe before commit resolves.
	ownerCheck := make(chan error, 1)
	go func() { ownerCheck <- registry.CheckOwner(cred.ID) }()
	if err := topologyReceive(t, ownerCheck); err != nil {
		t.Fatal(err)
	}
	registry.mu.Lock()
	left := registry.left
	registry.mu.Unlock()
	if _, err := a.Begin(cred); !errors.Is(err, ErrSessionProvisional) {
		t.Fatalf("precommit runtime=%v", err)
	}
	bad := cred
	bad.Secret[0] ^= 1
	if _, err := a.Begin(bad); err == nil {
		t.Fatal("bad proof did not request fence")
	}
	releaseCommit()
	if err := topologyReceive(t, done); err != nil {
		t.Fatal(err)
	}
	topologyReceive(t, terminal)
	topologyReceive(t, left)
	if _, err := a.Begin(cred); err == nil {
		t.Fatal("deferred fence admitted new work")
	}
	if err := registry.CheckOwner(cred.ID); !errors.Is(err, ErrSessionFenced) {
		t.Fatalf("owner did not retire: %v", err)
	}
	if _, ok := membership.active[cred.ID]; !ok {
		t.Fatal("fence erased durable membership")
	}
	if err := lifecycle.RequireCleanRouteAbsence(); !errors.Is(err, ErrRoutesLive) {
		t.Fatalf("terminal activation cleared route obligation: %v", err)
	}
}
