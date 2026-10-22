//go:build linux

package mountcontrol

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDeathAtEveryBootstrapAndHandoffBoundary(t *testing.T) {
	for _, who := range []string{"root", "child"} {
		for _, boundary := range []string{"before-begin", "before-mount", "after-mount", "before-handoff", "after-handoff", "after-acceptance", "after-observation"} {
			t.Run(who+"/"+boundary, func(t *testing.T) {
				var b Bootstrap
				var mounts atomic.Int32
				lost := func() {
					if who == "root" {
						b.OwnerLost()
					} else {
						b.ChildLost()
					}
				}
				if boundary == "before-begin" {
					lost()
					if err := b.Begin(*phase()); !errors.Is(err, ErrRetired) {
						t.Fatal(err)
					}
					return
				}
				if err := b.Begin(*phase()); err != nil {
					t.Fatal(err)
				}
				if boundary == "before-mount" {
					lost()
					if err := b.Begin(*phase()); !errors.Is(err, ErrRetired) {
						t.Fatal(err)
					}
					return
				}
				mounts.Add(1)
				originals, fds := descriptors(t)
				if boundary == "after-mount" {
					lost()
				}
				if err := b.Finish(originals, witness()); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = b.Finalize(absentBootstrap(&b)) }()
				if boundary == "after-mount" || boundary == "before-handoff" {
					lost()
					if _, err := b.Handoff(); !errors.Is(err, ErrRetired) {
						t.Fatal(err)
					}
				} else {
					first, err := b.Handoff()
					if err != nil {
						t.Fatal(err)
					}
					if boundary == "after-handoff" {
						first.Close()
						lost()
					} else {
						// Both deliveries are copies of the first root-owned descriptions; there
						// is no second mount to repair an unknown response.
						retry, err := b.Handoff()
						if err != nil {
							t.Fatal(err)
						}
						retry.Close()
						offered, release := make(chan struct{}), make(chan struct{})
						o := testOwner(t, func(ctx context.Context, j *Job) error {
							j.OfferInstall(*phase())
							close(offered)
							<-release
							return nil
						})
						j := start(t, o, request("workspace-prepare", 1, 1))
						awaitResult(t, offered)
						do(t, o, installRequest(3, 1), first)
						if boundary == "after-acceptance" {
							lost()
						} else {
							snap := observe(t, o, 4, 1)
							if err := b.ObserveInstall(snap.Workspace.Phases.Install, snap.Workspace.Witness); err != nil {
								t.Fatal(err)
							}
							if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
								t.Fatal("root FUSE copy retained", err)
							}
							lost()
						}
						close(release)
						awaitResult(t, j.done)
						o.Close()
					}
				}
				if err := b.Begin(*phase()); !errors.Is(err, ErrRetired) || mounts.Load() != 1 {
					t.Fatal("death rearmed bootstrap", err, mounts.Load())
				}
				if err := b.Finalize(Absence{KernelAbsent: true, SourceAbsent: true, AliasesAbsent: true}); !errors.Is(err, ErrGrammar) {
					t.Fatal("ack replaced process-exit proof", err)
				}
				if _, err := unix.FcntlInt(uintptr(fds[1]), unix.F_GETFD, 0); err != nil {
					t.Fatal("abort owner lost before finalization", err)
				}
				if err := b.Finalize(absentBootstrap(&b)); err != nil {
					t.Fatal(err)
				}
				assertClosed(t, fds)
			})
		}
	}
}

func TestBootstrapNeverRemountsToRepairUnknownDelivery(t *testing.T) {
	var b Bootstrap
	if err := b.Begin(*phase()); err != nil {
		t.Fatal(err)
	}
	rights, _ := descriptors(t)
	if err := b.Finish(rights, witness()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Finalize(absentBootstrap(&b)) }()
	for i := 0; i < 16; i++ {
		copy, err := b.Handoff()
		if err != nil {
			t.Fatal(err)
		}
		copy.Close()
		if err := b.Begin(*phase()); !errors.Is(err, ErrActionConsumed) {
			t.Fatal(err)
		}
	}
	s := ActionStatus{Progress: "running", Action: kernelAction(*phase())}
	if err := b.ObserveInstall(s, witness()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Handoff(); !errors.Is(err, ErrActionConsumed) {
		t.Fatal(err)
	}
}

func TestRootRemovalJoinsBeforeTerminalEscalation(t *testing.T) {
	var b Bootstrap
	if err := b.Begin(*phase()); err != nil {
		t.Fatal(err)
	}
	rights, fds := descriptors(t)
	if err := b.Finish(rights, witness()); err != nil {
		t.Fatal(err)
	}
	p := Phase{ActionID: "2", Mode: "voluntary", Reason: "cleanup", Witness: witness()}
	voluntary := ActionStatus{Progress: "offered", Action: kernelAction(p)}
	if err := b.BeginRemoval(voluntary, witness()); err != nil {
		t.Fatal(err)
	}
	p.ActionID = "3"
	p.Mode = "terminal"
	terminal := ActionStatus{Progress: "offered", Action: kernelAction(p)}
	if err := b.BeginRemoval(terminal, witness()); !errors.Is(err, ErrOccupied) {
		t.Fatal("terminal overtook root action", err)
	}
	if err := b.Finalize(absentBootstrap(&b)); !errors.Is(err, ErrOccupied) {
		t.Fatal("cleanup bypassed root join", err)
	}
	if err := b.FinishRemoval("voluntary", Removal{}, unix.EBUSY); !errors.Is(err, unix.EBUSY) {
		t.Fatal("EBUSY was erased", err)
	}
	if err := b.BeginRemoval(voluntary, witness()); !errors.Is(err, ErrActionConsumed) {
		t.Fatal("voluntary action rearmed", err)
	}
	if err := b.BeginRemoval(terminal, witness()); err != nil {
		t.Fatal(err)
	}
	if err := b.FinishRemoval("terminal", Removal{KernelAbsent: true, AbortCompleted: true}, nil); err != nil {
		t.Fatal(err)
	}
	p.ActionID = "4"
	terminal.Action = kernelAction(p)
	if err := b.BeginRemoval(terminal, witness()); !errors.Is(err, ErrActionConsumed) {
		t.Fatal("removal reversed", err)
	}
	if err := b.Finalize(absentBootstrap(&b)); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, fds)
}

// This fixture models an independent exact-inventory observation, never an
// acknowledgment. Production must supply actual process and mount inventories.
func absentBootstrap(b *Bootstrap) Absence {
	proof, _ := b.ObserveAbsence(func(w Witness) (Absence, error) {
		return Absence{Witness: w, ProcessExited: true, KernelAbsent: true, SourceAbsent: true, AliasesAbsent: true}, nil
	})
	return proof
}
