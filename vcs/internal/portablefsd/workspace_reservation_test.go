package portablefsd

import (
	"context"
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
