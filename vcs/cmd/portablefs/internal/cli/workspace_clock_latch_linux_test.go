//go:build linux

package cli

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceclock"
)

type childClockSource struct{ unavailable atomic.Bool }

func (s *childClockSource) Check(uint64) error {
	if s.unavailable.Load() {
		return workspaceclock.ErrUnavailable
	}
	return nil
}
func (s *childClockSource) Changed() <-chan struct{} { return nil }

func TestWorkspaceClockRefusalLatchesServingUntilFreshClosedPermit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root sealed gate owner")
	}
	start, err := mountcontrol.ProcessStart(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	b := workspaceadmission.Binding{Boot: [16]byte{1}, HostService: [16]byte{2}, GuestService: [16]byte{3}, Incarnation: [16]byte{4}, SupervisorPID: int32(os.Getpid()), SupervisorStart: start}
	g, err := workspaceadmission.New(b)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Dispose()
	files, err := g.ChildFiles()
	if err != nil {
		t.Fatal(err)
	}
	r, err := workspaceadmission.Adopt(files[0], files[1], b, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Retire()
	c := &workspaceChild{reader: r}
	c.generation.Store(1)
	c.localOpen.Store(true)
	source := new(childClockSource)
	c.clockBinding = workspaceclock.Binding{Owner: source, Generation: c.generation.Load, Current: c.current}
	p, err := g.Recovery(1)
	if err != nil {
		t.Fatal(err)
	}
	if err = g.Prepared(p); err != nil {
		t.Fatal(err)
	}
	if err = g.Open(1, p.Serial()); err != nil {
		t.Fatal(err)
	}
	permit := mountenrollment.Permit{Generation: 1, GateSerial: p.Serial()}
	source.unavailable.Store(true)
	if err = c.Check(permit); !errors.Is(err, workspaceclock.ErrUnavailable) || c.localOpen.Load() {
		t.Fatal("serving clock refusal did not latch closure", err)
	}
	source.unavailable.Store(false)
	if err = c.Check(permit); !errors.Is(err, workspaceclock.ErrObsolete) {
		t.Fatal("correction revived old serving permission", err)
	}
	serial := g.Close(1)
	c.localOpen.Store(true)
	permit.GateSerial = serial
	source.unavailable.Store(true)
	if err = c.Check(permit); !errors.Is(err, workspaceclock.ErrUnavailable) || !c.localOpen.Load() {
		t.Fatal("cold preparation clock wait became a permanent serving latch", err)
	}
	source.unavailable.Store(false)
	if err = c.Wait(context.Background(), permit); err != nil {
		t.Fatal("fresh closed permit did not await corrected clock", err)
	}
}
