package volumeserver

import (
	"context"
	"errors"
	"testing"
)

func TestStorageDeclarationSeparatesReadTurnsFromBindingChanges(t *testing.T) {
	for _, changed := range []bool{false, true} {
		s := NewStorageSequencer()
		deps := MutationDependenciesForTargets([]VisibilityTarget{{Scope: VisibilityNamespace, ParentIdentity: [16]byte{1}, Name: []byte("child")}})
		d := s.Declare(deps)
		var release func()
		var err error
		if changed {
			release, err = s.Acquire(t.Context(), deps)
		} else {
			release, err = s.AcquireRead(t.Context(), deps)
		}
		if err != nil {
			t.Fatal(err)
		}
		release()
		release, unchanged, err := s.AcquireDeclared(t.Context(), deps, d)
		if err != nil || unchanged == changed {
			t.Fatalf("changed=%v unchanged=%v err=%v", changed, unchanged, err)
		}
		release()
		d.Release()
		s.sequencer.mu.Lock()
		left := len(s.sequencer.versions)
		s.sequencer.mu.Unlock()
		if left != 0 {
			t.Fatal("declaration leaked watchers")
		}
	}
}
func TestStorageDeclarationCancellationReleasesWatchers(t *testing.T) {
	s := NewStorageSequencer()
	deps := MutationDependenciesForTargets([]VisibilityTarget{{Scope: VisibilityAttributes, Identity: [16]byte{2}}})
	release, err := s.Acquire(t.Context(), deps)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	d := s.Declare(deps)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := s.AcquireDeclared(ctx, deps, d); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	d.Release()
	s.sequencer.mu.Lock()
	defer s.sequencer.mu.Unlock()
	if len(s.sequencer.versions) != 0 {
		t.Fatal("canceled declaration leaked watchers")
	}
}

func TestStorageReadExpansionKeepsTurnAndRespectsOlderClaims(t *testing.T) {
	for _, edge := range []string{"free", "held", "older queued", "younger queued"} {
		t.Run(edge, func(t *testing.T) {
			s := NewStorageSequencer()
			parent, child, other := testInodeDependencies(1), testInodeDependencies(2), testInodeDependencies(3)
			complete := testInodeDependencies(1, 2)
			reserved := s.sequencer.reserveOrdinal()
			turn, err := s.AcquireReadTurn(t.Context(), parent)
			if err != nil {
				t.Fatal(err)
			}
			defer turn.Release()
			var blocker *mutationSequencerWaiter
			var waiter *mutationSequencerWaiter
			if edge == "held" {
				blocker, err = s.sequencer.acquire(t.Context(), child)
			}
			if edge == "older queued" || edge == "younger queued" {
				blocker, err = s.sequencer.acquire(t.Context(), other)
				both := MutationDependencies{keys: append(append([]string{}, child.keys...), other.keys...)}
				if edge == "older queued" {
					waiter = s.sequencer.enqueueFor(both, reserved)
				} else {
					waiter = s.sequencer.enqueue(both)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if blocker != nil {
				defer blocker.settle()
			}
			if waiter != nil {
				defer waiter.abandon()
			}
			before := s.sequencer.nextOrdinal
			got := turn.TryExpand(complete)
			if want := edge == "free" || edge == "younger queued"; got != want {
				t.Fatalf("expanded=%v want %v", got, want)
			}
			if s.sequencer.nextOrdinal != before {
				t.Fatal("expansion acquired another turn")
			}
		})
	}
}
