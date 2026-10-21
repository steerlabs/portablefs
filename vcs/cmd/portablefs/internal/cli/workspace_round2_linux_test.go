//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func closeRequest(t *testing.T, op string) mountcontrol.Request {
	t.Helper()
	q := workspaceRequest("1", op)
	q.Workspace.Phase = &mountcontrol.Phase{Mode: "terminal", Witness: mountcontrol.Witness{Process: "p", Source: "s", Target: "/t"}}
	if op == "workspace-suspend" {
		q.Workspace.Phase = nil
		q.Workspace.Generation = "1"
		q.Workspace.DrainBudgetNanos = "15000000000"
		q.Workspace.HostRequestID = "1"
		var err error
		q.Workspace.Transaction, err = mountcontrol.EncodeTransaction(&pb.Suspension{BootId: bytes.Repeat([]byte{1}, 16), HostServiceId: bytes.Repeat([]byte{2}, 16), GuestServiceId: bytes.Repeat([]byte{3}, 16), Generation: 1, Nonce: bytes.Repeat([]byte{4}, 16)})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := q.ValidateWorkspace(); err != nil {
		t.Fatal(err)
	}
	return q
}

// Imported Astra r2 cli_probe.go. The normal live case also falsifies closing
// twice at the socket and job layers. Expired acceptance leaves no job.
func TestFramedCloseHasOneAdmissionOwnerBeforeBudgetAndLaneExit(t *testing.T) {
	for _, op := range []string{"workspace-cleanup", "workspace-suspend"} {
		for _, mode := range []string{"expired-free", "expired-occupied", "live-free", "live-occupied"} {
			t.Run(op+"/"+mode, func(t *testing.T) {
				var closed, calls atomic.Int32
				ran := make(chan struct{}, 1)
				c, _ := rootWorkspace(t, func(context.Context, *mountcontrol.Job) error { calls.Add(1); ran <- struct{}{}; return nil }, func(cfg *workspaceControlConfig) { cfg.Owner.CloseAdmission = func() { closed.Add(1) } })
				q := closeRequest(t, op)
				if mode == "expired-free" || mode == "expired-occupied" {
					q.Workspace.BudgetNanos = "1"
				}
				if mode == "expired-occupied" || mode == "live-occupied" {
					c.mu.Lock()
					c.workspacePhase = true
					c.mu.Unlock()
				}
				conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.SocketPath(), Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if err := json.NewEncoder(conn).Encode(q); err != nil {
					t.Fatal(err)
				}
				if err := conn.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, conn)
				waitForFuseMountControlConnections(t, c, 0)
				if closed.Load() != 1 {
					t.Fatal("framed Close advanced admission serial", closed.Load())
				}
				want := int32(0)
				if mode == "live-free" {
					want = 1
					select {
					case <-ran:
					case <-time.After(3 * time.Second):
						t.Fatal("worker did not run")
					}
				}
				if calls.Load() != want {
					t.Fatal("wrong acceptance count", calls.Load(), want)
				}
				if want == 0 {
					// Same ID must still be available after an expired/occupied attempt.
					c.mu.Lock()
					c.workspacePhase = false
					c.mu.Unlock()
					q.Workspace.BudgetNanos = "1000000000"
					out := workspaceRoundtrip(t, c, q)
					select {
					case <-ran:
					case <-time.After(3 * time.Second):
						t.Fatal("worker did not run")
					}
					if !out.OK || calls.Load() != 1 || closed.Load() != 2 {
						t.Fatal("unaccepted Close consumed a job", out, calls.Load(), closed.Load())
					}
				}
			})
		}
	}
}

// Opus FullHangup window: queue the entire valid request and close the root
// before running the authenticated handler. No job is accepted, but Close is
// already authoritative. A partial frame remains transport loss.
func TestFullyFramedCloseSurvivesRootHangupBeforePoll(t *testing.T) {
	for _, op := range []string{"workspace-cleanup", "workspace-suspend"} {
		t.Run(op, func(t *testing.T) {
			var closed, calls atomic.Int32
			ran := make(chan struct{}, 1)
			c, cfg := rootWorkspace(t, func(context.Context, *mountcontrol.Job) error { calls.Add(1); ran <- struct{}{}; return nil }, func(cfg *workspaceControlConfig) { cfg.Owner.CloseAdmission = func() { closed.Add(1) } })
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "root.sock"), Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			conn, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
			if err != nil {
				t.Fatal(err)
			}
			server, err := listener.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			peer, err := mountcontrol.Credentials(server)
			if err != nil {
				t.Fatal(err)
			}
			peer.Start, err = mountcontrol.ProcessStart(int32(os.Getpid()))
			if err != nil {
				t.Fatal(err)
			}
			if mountcontrol.Classify(peer, uint32(os.Geteuid()), &cfg.Supervisor) != mountcontrol.WorkspacePeer {
				t.Fatal("not authenticated root")
			}
			q := closeRequest(t, op)
			if err := json.NewEncoder(conn).Encode(q); err != nil {
				t.Fatal(err)
			}
			conn.CloseWrite()
			conn.Close()
			c.handlePeer(server, 1, mountcontrol.WorkspacePeer, peer)
			if closed.Load() != 1 || calls.Load() != 0 {
				t.Fatal("full hangup lost Close or accepted job", closed.Load(), calls.Load())
			}
			out := workspaceRoundtrip(t, c, q)
			select {
			case <-ran:
			case <-time.After(3 * time.Second):
				t.Fatal("worker did not run")
			}
			if !out.OK || calls.Load() != 1 {
				t.Fatal("full hangup consumed job", out, calls.Load())
			}
		})
	}
}

func TestCloseBypassesBusyObservationLane(t *testing.T) {
	var closed atomic.Int32
	ran := make(chan struct{}, 1)
	c, _ := rootWorkspace(t, func(context.Context, *mountcontrol.Job) error { ran <- struct{}{}; return nil }, func(cfg *workspaceControlConfig) { cfg.Owner.CloseAdmission = func() { closed.Add(1) } })
	c.mu.Lock()
	c.workspaceObservation = true
	c.mu.Unlock()
	out := workspaceRoundtrip(t, c, closeRequest(t, "workspace-cleanup"))
	select {
	case <-ran:
	case <-time.After(3 * time.Second):
		t.Fatal("Close waited behind observation")
	}
	if !out.OK || closed.Load() != 1 {
		t.Fatal(out, closed.Load())
	}
}

func TestFullSocketLossAfterAcceptanceLeavesLiveJob(t *testing.T) {
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	c, _ := rootWorkspace(t, func(ctx context.Context, j *mountcontrol.Job) error {
		close(entered)
		<-release
		if ctx.Err() != nil {
			t.Error("socket loss canceled live root job", ctx.Err())
		}
		close(finished)
		return nil
	})
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.SocketPath(), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(conn).Encode(workspaceRequest("1", "workspace-prepare")); err != nil {
		t.Fatal(err)
	}
	conn.CloseWrite()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("job not accepted")
	}
	conn.Close()
	waitForFuseMountControlConnections(t, c, 0)
	snap := workspaceRoundtrip(t, c, workspaceRequest("2", "workspace-observe"))
	if snap.Workspace.State != "preparing" {
		t.Fatal(snap)
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("job did not finish")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		snap = workspaceRoundtrip(t, c, workspaceRequest("2", "workspace-observe"))
		if snap.Workspace.State == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("completion not observable")
		}
	}
	out := workspaceRoundtrip(t, c, workspaceRequest("1", "workspace-prepare"))
	if !out.OK || out.Workspace.State != "accepted" {
		t.Fatal("socket loss reopened Prepare", out)
	}
}
