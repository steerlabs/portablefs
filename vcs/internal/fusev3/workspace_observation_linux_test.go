//go:build linux

package fusev3

import (
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/continuous"
)

func TestWorkspaceObservationTerminal(t *testing.T) {
	for _, published := range []string{"none", "prepared", "cold"} {
		for _, terminal := range []string{"revoked", "owner-dead", "shutdown", "session-ended"} {
			t.Run(published+"/"+terminal, func(t *testing.T) {
				f, gate, _ := coldFixture(t)
				serial := gate.Close(1)
				switch published {
				case "prepared":
					o, err := f.mount.PrepareWorkspace(t.Context(), 1, serial)
					if err != nil || !o.Prepared {
						t.Fatal(o, err)
					}
				case "cold":
					o, err := f.mount.SuspendWorkspace(t.Context(), 1, serial, continuous.Time().Add(time.Second))
					if err != nil || !o.ColdComplete {
						t.Fatal(o, err)
					}
				}
				switch terminal {
				case "revoked":
					f.mount.revoked.Store(true)
				case "owner-dead":
					if err := gate.Dispose(); err != nil {
						t.Fatal(err)
					}
					select {
					case <-f.mount.workspace.Done():
					case <-time.After(time.Second):
						t.Fatal("owner death not observed")
					}
				case "shutdown":
					f.mount.cancel()
				case "session-ended":
					f.rpc.mu.Lock()
					f.rpc.sessionEnd = authorityrpc.ErrSessionEnded
					f.rpc.mu.Unlock()
				}
				if o := f.mount.WorkspaceObservation(); o.State != WorkspaceTerminal || o.Prepared || o.ColdComplete {
					t.Fatal("terminal mount reported a recovery opportunity", o)
				}
			})
		}
	}
}
