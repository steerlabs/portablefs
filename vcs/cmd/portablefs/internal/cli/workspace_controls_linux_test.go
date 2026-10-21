//go:build linux

package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkspaceManualSameUIDCannotRenewButCanReadLoss(t *testing.T) {
	installs := 0
	c, err := startFuseMountControl(func(context.Context, string, uint64, []byte) (time.Time, error) {
		installs++
		return time.Now().Add(time.Minute), nil
	}, func() (mountLossSnapshot, error) {
		return mountLossSnapshot{MountInstanceID: lossTestInstance, LossSequence: "5"}, nil
	}, &workspaceControlConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	state := &mountState{Strategy: "fuse", MountInstanceID: lossTestInstance, ReauthorizationControlSocket: c.SocketPath()}
	if _, err := reauthorizeFuseMount(context.Background(), state, "grant", 1, []byte("cert")); err == nil || installs != 0 {
		t.Fatal("managed manual bypass")
	}
	if loss, err := readFuseMountLoss(context.Background(), state, lossTestInstance); err != nil || loss.LossSequence != "5" {
		t.Fatal(loss, err)
	}
}

// This child is an ordinary same-UID process, never the exact seeded root owner.
func TestWorkspaceOrdinarySaturationChild(t *testing.T) {
	path := os.Getenv("PFS_TEST_PARTIAL_SOCKET")
	if path == "" {
		return
	}
	var clients []*net.UnixConn
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	for i := 0; i < 8; i++ {
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		if _, err := c.Write([]byte(`{"capability":`)); err != nil {
			t.Fatal(err)
		}
	}
	fmt.Println("ready")
	io.Copy(io.Discard, os.Stdin)
}
func TestWorkspaceRootReserveBypassesPartialOrdinarySaturation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact root supervisor boundary requires the owned Linux test container")
	}
	start, err := mountcontrol.ProcessStart(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	c, err := startFuseMountControl(nil, func() (mountLossSnapshot, error) {
		return mountLossSnapshot{MountInstanceID: lossTestInstance, LossSequence: "0"}, nil
	}, &workspaceControlConfig{Supervisor: mountcontrol.Peer{UID: 0, PID: int32(os.Getpid()), Start: start}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(binary, "-test.run=^TestWorkspaceOrdinarySaturationChild$")
	child.Env = append(os.Environ(), "PFS_TEST_PARTIAL_SOCKET="+c.SocketPath())
	out, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	in, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		in.Close()
		if err := child.Wait(); err != nil {
			t.Error(err)
		}
	}()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatal(line, err)
	}
	waitForFuseMountControlConnections(t, c, 8)
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.SocketPath(), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(2 * time.Second))
	request := mountcontrol.Request{Operation: "workspace-prepare", MountInstanceID: lossTestInstance, Workspace: &mountcontrol.Workspace{Version: 8, RequestID: "1", OperationID: "1", BootID: strings.Repeat("01", 16), HostServiceID: strings.Repeat("02", 16), GuestServiceID: strings.Repeat("03", 16), Generation: "0", GateSerial: "0", BudgetNanos: "1000000000"}}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		t.Fatal(err)
	}
	connection.CloseWrite()
	body, rights, err := mountcontrol.Receive(connection, mountcontrol.MaxWorkspaceResponse)
	defer rights.Close()
	if err != nil {
		t.Fatal(err)
	}
	response, err := mountcontrol.DecodeResponse(body, true)
	if err != nil {
		t.Fatal(err)
	}
	if response.OK || response.Workspace.Refusal != "unavailable" {
		t.Fatal("real workspace handler unexpectedly enabled", response)
	}
}
func TestManagedInstallerRefusesMissingAndStalePermit(t *testing.T) {
	for _, provided := range []bool{false, true} {
		m := &fuseV3Mount{managed: true, checkPermit: func(p mountenrollment.Permit) bool {
			return p == (mountenrollment.Permit{Generation: 2, GateSerial: 4})
		}}
		ctx := context.Background()
		if provided {
			ctx = mountenrollment.WithPermit(ctx, mountenrollment.Permit{Generation: 2, GateSerial: 3})
		}
		// No client/kernel is constructed: reaching either would panic and prove
		// that a stale manual caller bypassed the installer boundary.
		if _, err := m.Reauthorize(ctx, "grant", 1, []byte("cert")); err == nil {
			t.Fatal("stale installer")
		}
	}
}

type unavailableWorkspaceHandler struct{ calls atomic.Int32 }

func (h *unavailableWorkspaceHandler) Run(context.Context, *mountcontrol.Job) error {
	h.calls.Add(1)
	return mountcontrol.ErrUnavailable
}
func TestWorkspaceSocketBudgetIncludesPartialRequestRead(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("exact root supervisor boundary requires the owned Linux test container")
	}
	start, err := mountcontrol.ProcessStart(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	handler := &unavailableWorkspaceHandler{}
	c, err := startFuseMountControl(nil, nil, &workspaceControlConfig{Supervisor: mountcontrol.Peer{UID: 0, PID: int32(os.Getpid()), Start: start}, Owner: mountcontrol.Owner{Driver: mountcontrol.Driver{Run: handler.Run}, CheckPermit: func(mountcontrol.Workspace) bool { return true }}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: c.SocketPath(), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(2 * time.Second))
	q := mountcontrol.Request{Operation: "workspace-prepare", MountInstanceID: lossTestInstance, Workspace: &mountcontrol.Workspace{Version: 8, RequestID: "1", OperationID: "1", BootID: strings.Repeat("01", 16), HostServiceID: strings.Repeat("02", 16), GuestServiceID: strings.Repeat("03", 16), Generation: "0", GateSerial: "0", BudgetNanos: "50000000"}}
	body, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(body[:1]); err != nil {
		t.Fatal(err)
	}
	waitForFuseMountControlConnections(t, c, 1)
	// The framing read consumes the whole attempt budget before dispatch.
	time.Sleep(100 * time.Millisecond)
	if _, err := connection.Write(body[1:]); err != nil {
		t.Fatal(err)
	}
	connection.CloseWrite()
	io.Copy(io.Discard, connection)
	if handler.calls.Load() != 0 {
		t.Fatal("partial framing restarted the socket attempt budget")
	}
}
