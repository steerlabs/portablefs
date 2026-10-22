//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	"golang.org/x/sys/unix"
)

func r4Cleanup(n, op, mode string) mountcontrol.Request {
	q := workspaceRequest(n, "workspace-cleanup")
	q.Workspace.OperationID = op
	q.Workspace.Phase = &mountcontrol.Phase{Mode: mode, Witness: mountcontrol.Witness{Process: "p", Source: "s", Target: "/t"}}
	return q
}

func r4Try(t *testing.T, c *unixReauthorizationControl, q mountcontrol.Request) (mountcontrol.Response, error) {
	t.Helper()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.SocketPath(), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := json.NewEncoder(conn).Encode(q); err != nil {
		t.Fatal(err)
	}
	conn.CloseWrite()
	body, rights, err := mountcontrol.Receive(conn, mountcontrol.MaxWorkspaceResponse)
	defer rights.Close()
	if err != nil {
		return mountcontrol.Response{}, err
	}
	if len(body) == 0 {
		return mountcontrol.Response{}, errors.New("empty response (EOF)")
	}
	return mountcontrol.DecodeResponse(body, true)
}

func r4WaitNoConnections(t *testing.T, c *unixReauthorizationControl) {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		c.mu.Lock()
		n, changed := len(c.connections), c.changed
		c.mu.Unlock()
		if n == 0 {
			return
		}
		select {
		case <-changed:
		case <-timer.C:
			t.Fatal("listener did not join frame disposal")
		}
	}
}

// L5 re-check: authenticated malformed half-closed frames rejected by Receive.
func TestR4ReceiveRejectionFromRootClosesAdmission(t *testing.T) {
	for _, name := range []string{"three-rights", "oversize-body", "truncated-ancillary", "oversize-full-loss", "incomplete-full-loss"} {
		t.Run(name, func(t *testing.T) {
			var closed atomic.Int32
			c, _ := rootWorkspace(t, nil, func(cfg *workspaceControlConfig) { cfg.Owner.CloseAdmission = func() { closed.Add(1) } })
			conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.SocketPath(), Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			waitForFuseMountControlConnections(t, c, 1)
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			var pipe [2]int
			if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pipe[0])
			defer func() {
				if pipe[1] >= 0 {
					unix.Close(pipe[1])
				}
			}()
			body, _ := json.Marshal(workspaceRequest("1", "workspace-prepare"))
			count := 3
			switch name {
			case "truncated-ancillary":
				count = 253
			case "oversize-body", "oversize-full-loss":
				body = []byte(strings.Repeat(" ", mountcontrol.MaxWorkspaceRequest+1))
				count = 1
			case "incomplete-full-loss":
				body = []byte(`{"workspace":`)
				count = 1
			}
			fds := make([]int, count)
			for i := range fds {
				fds[i] = pipe[1]
			}
			n, _, err := conn.WriteMsgUnix(body, unix.UnixRights(fds...), nil)
			if err != nil {
				t.Fatal(err)
			}
			if n < len(body) {
				conn.Write(body[n:])
			}
			unix.Close(pipe[1])
			pipe[1] = -1
			if strings.HasSuffix(name, "full-loss") {
				conn.Close()
			} else {
				conn.CloseWrite()
				raw := make([]byte, 4096)
				conn.Read(raw)
			}
			r4WaitNoConnections(t, c)
			want := int32(1)
			if name == "incomplete-full-loss" {
				want = 0
			}
			if closed.Load() != want {
				t.Fatalf("%s admission invalidations=%d want=%d", name, closed.Load(), want)
			}
			if n, err := unix.Read(pipe[0], make([]byte, 1)); n != 0 || err != nil {
				t.Fatalf("rejected frame retained writer rights: n=%d err=%v", n, err)
			}
		})
	}
}

// R4-2 through the listener: a retired voluntary Cleanup frame, delivered
// fully framed after terminal escalation, cancels the live terminal job.
func TestR4RetiredCloseFrameCancelsTerminalThroughListener(t *testing.T) {
	var terminalCanceled atomic.Bool
	offered := make(chan string, 4)
	c, _ := rootWorkspace(t, func(ctx context.Context, j *mountcontrol.Job) error {
		q := j.Request()
		mode := q.Workspace.Phase.Mode
		p := mountcontrol.Phase{ActionID: "2", Mode: mode, Reason: "cleanup", Witness: q.Workspace.Phase.Witness}
		if mode == "terminal" {
			p.ActionID = "3"
		}
		if err := j.OfferRemoval(p); err != nil {
			return err
		}
		offered <- mode
		err := j.WaitRemoval(ctx, mode)
		if mode == "terminal" && errors.Is(err, context.Canceled) {
			terminalCanceled.Store(true)
		}
		return err
	})
	if out, err := r4Try(t, c, r4Cleanup("1", "1", "voluntary")); err != nil || !out.OK {
		t.Fatal(out, err)
	}
	<-offered
	deadline := time.Now().Add(3 * time.Second)
	for {
		out, err := r4Try(t, c, r4Cleanup("2", "2", "terminal"))
		if err == nil && out.OK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("terminal not accepted", out, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if m := <-offered; m != "terminal" {
		t.Fatal(m)
	}
	out, err := r4Try(t, c, r4Cleanup("1", "1", "voluntary"))
	t.Logf("R4-2/CLI stale voluntary frame: refusal=%q err=%v", out.Workspace.Refusal, err)
	time.Sleep(200 * time.Millisecond)
	snap, _ := r4Try(t, c, workspaceRequest("9", "workspace-observe"))
	q := workspaceRequest("9", "workspace-observe")
	q.Workspace.OperationID = "2"
	snap, err = r4Try(t, c, q)
	t.Logf("R4-2/CLI terminal job after stale frame: state=%q canceled=%v err=%v", snap.Workspace.State, terminalCanceled.Load(), err)
	if terminalCanceled.Load() {
		t.Errorf("REPRO R4-2/CLI: retired frame canceled the live terminal cleanup")
	}
	again, err := r4Try(t, c, r4Cleanup("3", "3", "terminal"))
	t.Logf("R4-2/CLI restart terminal: refusal=%q err=%v", again.Workspace.Refusal, err)
}

// R4-1 through the listener: once the failed job is rewritten, every
// observation produces no response at all.
func TestR4FailedCleanupUnmountBreaksObservationThroughListener(t *testing.T) {
	offered, fail := make(chan struct{}), make(chan struct{})
	c, _ := rootWorkspace(t, func(ctx context.Context, j *mountcontrol.Job) error {
		q := j.Request()
		p := mountcontrol.Phase{ActionID: "2", Mode: "voluntary", Reason: "cleanup", Witness: q.Workspace.Phase.Witness}
		if err := j.OfferRemoval(p); err != nil {
			return err
		}
		close(offered)
		<-fail
		return errors.New("detach failed after offering removal")
	})
	if out, err := r4Try(t, c, r4Cleanup("1", "1", "voluntary")); err != nil || !out.OK {
		t.Fatal(out, err)
	}
	<-offered
	close(fail)
	obs := workspaceRequest("2", "workspace-observe")
	var snap mountcontrol.Response
	for i := 0; i < 100; i++ {
		snap, _ = r4Try(t, c, obs)
		if snap.Workspace != nil && snap.Workspace.State == "failed" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	u := workspaceRequest("3", "workspace-unmount-complete")
	u.Workspace.Phase = snap.Workspace.Phases.VoluntaryRemoval.Action.WithWitness(snap.Workspace.Witness)
	u.Workspace.Phase.Removal = &mountcontrol.Removal{KernelAbsent: true}
	ack, err := r4Try(t, c, u)
	t.Logf("R4-1/CLI unmount-complete after failure: state=%q err=%v", ack.Workspace.State, err)
	after, err := r4Try(t, c, obs)
	t.Logf("R4-1/CLI observation afterwards: %+v err=%v", after.Workspace, err)
	if err != nil || after.Workspace.State != "failed" || after.Workspace.Phases.VoluntaryRemoval.Progress != "complete" {
		t.Fatalf("failed job lost removal evidence: %+v %v", after, err)
	}
}
