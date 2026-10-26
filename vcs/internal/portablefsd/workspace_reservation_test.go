package portablefsd

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
)

func TestFSKitEntryRefusesPendingWorkspaceReservationIncludingReadOnly(t *testing.T) {
	pki := newV3TestPKI(t)
	for _, readOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "writer", true: "reader"}[readOnly], func(t *testing.T) {
			root := privateTestDir(t)
			state := filepath.Join(root, "portablefsd")
			r := newRegistry(state)
			r.reservationStateDir = root
			req := v3TestEnsureRequest("127.0.0.1:1", pki, "/not-a-real-test-mount")
			// Both requests hit the shared guard before any authority dial. A signed
			// capability's access rights never waive the per-account placement rule.
			if readOnly {
				req.AuthToken = "generated-test-read-only-grant"
			}
			authority, err := mountlifecycle.AuthorityIdentity(req.DataPlaneServerName)
			if err != nil {
				t.Fatal(err)
			}
			transition, err := mountlifecycle.BeginTransition(root)
			if err != nil {
				t.Fatal(err)
			}
			err = transition.Reserve(mountlifecycle.Reservation{Authority: authority, Volume: req.VolumeID, Frontend: "workspace", Owner: "pending-or-crashed-linux-intent"})
			transition.Close()
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = r.ensure(context.Background(), req); err == nil || err.Error() != mountlifecycle.LinuxVolumeConflict {
				t.Fatalf("FSKit attach = %v", err)
			}
			if len(r.list()) != 0 {
				t.Fatal("refusal acquired daemon attach")
			}
		})
	}
}

func TestFSKitCrashReservationReconcilesOnlyExactAbsentInventories(t *testing.T) {
	for _, test := range []struct {
		name             string
		present, unknown bool
	}{{"absent", false, false}, {"mounted", true, false}, {"unknown", false, true}} {
		t.Run(test.name, func(t *testing.T) {
			root := privateTestDir(t)
			r := newRegistry(filepath.Join(root, "portablefsd"))
			r.reservationStateDir = root
			reservation := mountlifecycle.Reservation{Authority: "abababababababababababababababababababababababababababababababab", Volume: "vol-1", Frontend: "fskit", Owner: testFSKitAttachRef, Target: "/Volumes/OwnedCrashFixture"}
			transition, err := mountlifecycle.BeginTransition(root)
			if err != nil {
				t.Fatal(err)
			}
			if err = transition.Reserve(reservation); err != nil {
				t.Fatal(err)
			}
			transition.Close()
			observed := false
			err = r.reconcileVolumeReservations(func(path, ref string) error {
				observed = true
				if path != reservation.Target || ref != reservation.Owner {
					t.Fatal("wrong absence witness")
				}
				if test.present || test.unknown {
					return fmt.Errorf("exact kernel absence unconfirmed")
				}
				return nil
			})
			if !observed || (err != nil) != (test.present || test.unknown) {
				t.Fatalf("observed=%v err=%v", observed, err)
			}
			transition, err = mountlifecycle.BeginTransition(root)
			if err != nil {
				t.Fatal(err)
			}
			defer transition.Close()
			if (len(transition.Inventory()) == 0) != (!test.present && !test.unknown) {
				t.Fatal("lost or leaked reservation")
			}
		})
	}
}

func TestFSKitUnmountKeepsDurableOwnerWhenTransitionLockIsBusy(t *testing.T) {
	root := privateTestDir(t)
	state := filepath.Join(root, "portablefsd")
	writeFSKitDetachFixture(t, state)
	r := newRegistry(state)
	r.reservationStateDir = root
	a := r.get(testFSKitAttachRef)
	reservation, err := reservationForAttach(a)
	if err != nil {
		t.Fatal(err)
	}
	transition, err := mountlifecycle.BeginTransition(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = transition.Reserve(reservation); err != nil {
		t.Fatal(err)
	}
	ops := fskitKernelOps{present: func(string, string) (bool, error) { return false, nil }, unmountExact: func(string, string, bool) error { t.Fatal("absent mount was unmounted"); return nil }}
	if _, err = r.unmountFSKitWith(testFSKitAttachRef, false, ops); err == nil {
		t.Fatal("busy transition reported completed cleanup")
	}
	if r.get(testFSKitAttachRef) == nil {
		t.Fatal("lost retryable detached object")
	}
	inventory, err := ReadPersistedAttachInventory(state)
	if err != nil || len(inventory) != 1 {
		t.Fatal("lost durable attach owner", err)
	}
	transition.Close()
	if found, err := r.unmountFSKitWith(testFSKitAttachRef, false, ops); err != nil || !found {
		t.Fatal("exact cleanup retry failed", err)
	}
	transition, err = mountlifecycle.BeginTransition(root)
	if err != nil {
		t.Fatal(err)
	}
	defer transition.Close()
	if len(transition.Inventory()) != 0 {
		t.Fatal("completed cleanup retained reservation")
	}
}
