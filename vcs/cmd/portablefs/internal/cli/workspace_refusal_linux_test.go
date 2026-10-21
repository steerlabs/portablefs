//go:build linux

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
)

type workspaceHandlerFunc func(context.Context, mountcontrol.Request, *mountcontrol.Rights) (mountcontrol.Response, error)

func (f workspaceHandlerFunc) Handle(c context.Context, q mountcontrol.Request, d *mountcontrol.Rights) (mountcontrol.Response, error) {
	return f(c, q, d)
}
func workspaceRequest(n, op string) mountcontrol.Request {
	return mountcontrol.Request{Operation: op, MountInstanceID: lossTestInstance, Workspace: &mountcontrol.Workspace{Version: 8, RequestID: n, OperationID: "1", BootID: strings.Repeat("01", 16), HostServiceID: strings.Repeat("02", 16), GuestServiceID: strings.Repeat("03", 16), Generation: "0", GateSerial: "0", BudgetNanos: "1000000000"}}
}
func workspaceResponse(q mountcontrol.Request, state string) mountcontrol.Response {
	return mountcontrol.Response{OK: true, MountInstanceID: q.MountInstanceID, Workspace: &mountcontrol.WorkspaceResponse{Binding: q.Workspace.ResponseBinding(), State: state, AuthorizationDeadlineUnixNanos: "0", Outcome: mountcontrol.Outcome{Durability: "unresolved", Observation: "unobserved", Release: "unresolved", CleanupDebt: "0"}}}
}
func rootWorkspace(t *testing.T, h mountcontrol.Handler) (*unixReauthorizationControl, *workspaceControlConfig) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("owned root Linux test container")
	}
	start, err := mountcontrol.ProcessStart(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &workspaceControlConfig{Supervisor: mountcontrol.Peer{UID: 0, PID: int32(os.Getpid()), Start: start}, Handler: h}
	control, err := startFuseMountControl(nil, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := control.(*unixReauthorizationControl)
	t.Cleanup(func() { c.Close() })
	return c, cfg
}
func workspaceRoundtrip(t *testing.T, c *unixReauthorizationControl, q mountcontrol.Request) mountcontrol.Response {
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
		t.Fatal(err)
	}
	out, err := mountcontrol.DecodeResponse(body, true)
	if err != nil {
		t.Fatal(string(body), err)
	}
	if out.Workspace.Binding.RequestID != q.Workspace.RequestID || out.MountInstanceID != q.MountInstanceID {
		t.Fatal("refusal lost correlation", out)
	}
	return out
}
func TestWorkspaceRefusalsRoundTripExactTransport(t *testing.T) {
	t.Run("unavailable", func(t *testing.T) {
		c, _ := rootWorkspace(t, nil)
		out := workspaceRoundtrip(t, c, workspaceRequest("1", "workspace-prepare"))
		if out.OK || out.Workspace.Refusal != "unavailable" {
			t.Fatal(out)
		}
	})
	t.Run("occupied", func(t *testing.T) {
		c, _ := rootWorkspace(t, nil)
		c.mu.Lock()
		c.workspacePhase = true
		c.mu.Unlock()
		out := workspaceRoundtrip(t, c, workspaceRequest("1", "workspace-prepare"))
		if out.OK || out.Workspace.Refusal != "occupied" {
			t.Fatal(out)
		}
	})
	t.Run("retired", func(t *testing.T) {
		h := workspaceHandlerFunc(func(_ context.Context, q mountcontrol.Request, _ *mountcontrol.Rights) (mountcontrol.Response, error) {
			if q.Operation == "workspace-observe" {
				return workspaceResponse(q, "preparing"), nil
			}
			return workspaceResponse(q, "accepted"), nil
		})
		c, _ := rootWorkspace(t, h)
		for _, q := range []mountcontrol.Request{workspaceRequest("1", "workspace-prepare"), workspaceRequest("2", "workspace-observe"), workspaceRequest("3", "workspace-observe")} {
			workspaceRoundtrip(t, c, q)
		}
		out := workspaceRoundtrip(t, c, workspaceRequest("2", "workspace-observe"))
		if out.OK || out.Workspace.Refusal != "retired" {
			t.Fatal(out)
		}
	})
	t.Run("retained-handler-error", func(t *testing.T) {
		var calls atomic.Int32
		c, _ := rootWorkspace(t, workspaceHandlerFunc(func(context.Context, mountcontrol.Request, *mountcontrol.Rights) (mountcontrol.Response, error) {
			calls.Add(1)
			return mountcontrol.Response{}, errors.New("private unbounded error")
		}))
		q := workspaceRequest("1", "workspace-prepare")
		for i := 0; i < 2; i++ {
			out := workspaceRoundtrip(t, c, q)
			if out.OK || out.Workspace.Refusal != "handler-failed" {
				t.Fatal(out)
			}
		}
		if calls.Load() != 1 {
			t.Fatal("error receipt executed twice", calls.Load())
		}
	})
}

// Imported Opus zz_truncation_probe_linux_test.go. Full hangup is transport
// loss; a half-closed malformed frame is a grammar failure that closes admission.
func TestTruncatedWorkspaceDistinguishesFullAndHalfClose(t *testing.T) {
	for _, half := range []bool{false, true} {
		t.Run(map[bool]string{false: "full-hangup", true: "framing-half-close"}[half], func(t *testing.T) {
			c, cfg := rootWorkspace(t, nil)
			var closed atomic.Int32
			cfg.Replay.CloseAdmission = func() { closed.Add(1) }
			body, _ := json.Marshal(workspaceRequest("1", "workspace-prepare"))
			conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.SocketPath(), Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			conn.Write(body[:len(body)/2])
			waitForFuseMountControlConnections(t, c, 1)
			if half {
				conn.CloseWrite()
				io.Copy(io.Discard, conn)
			}
			conn.Close()
			waitForFuseMountControlConnections(t, c, 0)
			want := int32(0)
			if half {
				want = 1
			}
			if closed.Load() != want {
				t.Fatal("transport loss confused with invalid grammar", closed.Load(), want)
			}
		})
	}
}

func TestOrdinaryWorkspaceRefusalUsesExactCodec(t *testing.T) {
	control, err := startFuseMountControl(nil, nil, &workspaceControlConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	out := workspaceRoundtrip(t, control.(*unixReauthorizationControl), workspaceRequest("1", "workspace-prepare"))
	if out.OK || out.Workspace.Refusal != "peer-refused" {
		t.Fatal(out)
	}
}

func TestDifferentUIDRefusalClient(t *testing.T) {
	path := os.Getenv("PFS_TEST_REFUSED_UID_SOCKET")
	if path == "" {
		return
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	body, err := io.ReadAll(io.LimitReader(conn, mountcontrol.MaxOrdinaryResponse+1))
	if err != nil {
		t.Fatal(err)
	}
	out, err := mountcontrol.DecodeResponse(body, false)
	if err != nil || out.OK || out.Error != "peer refused" {
		t.Fatal(string(body), err)
	}
}
func TestDifferentUIDPeerRetainsBoundedRefusal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("owned root Linux container required for a real different-UID peer")
	}
	control, err := startFuseReauthorizationControl(nil, func() (mountLossSnapshot, error) {
		return mountLossSnapshot{MountInstanceID: lossTestInstance, LossSequence: "0"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	// Go's build directory is private. Only this owned helper copy is exposed
	// to the second UID; the source tree and test process keep their permissions.
	dir, err := os.MkdirTemp("/tmp", "portablefs-peer-refusal-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(dir, "peer-client")
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.OpenFile(executable, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(target, source)
	closeErr := errors.Join(target.Close(), source.Close())
	if err := errors.Join(copyErr, closeErr); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestDifferentUIDRefusalClient$")
	child.Env = append(os.Environ(), "PFS_TEST_REFUSED_UID_SOCKET="+control.SocketPath())
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if out, err := child.CombinedOutput(); err != nil {
		t.Fatalf("different-UID control refusal: %v\n%s", err, out)
	}
}
