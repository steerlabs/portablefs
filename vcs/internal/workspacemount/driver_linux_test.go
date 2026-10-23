//go:build linux

package workspacemount

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

func TestRootSuspendAdapterChild(t *testing.T) {
	address := os.Getenv("PFS_DRIVER_ADAPTER_HELPER")
	if address == "" {
		return
	}
	start, err := mountcontrol.ProcessStart(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	w := mountcontrol.Witness{Process: strconv.Itoa(os.Getpid()) + ":" + strconv.FormatUint(start, 10), Source: "portablefs:mnt_AAAAAAAAAAAAAAAAAAAAAA", Target: "/workspaces/adapter"}
	joined := make(chan struct{})
	o := &mountcontrol.Owner{CheckPermit: func(mountcontrol.Workspace) bool { return true }}
	o.Driver.Run = func(ctx context.Context, j *mountcontrol.Job) mountcontrol.LifecycleResult {
		if j.Request().Operation != "workspace-suspend" {
			return authorityrpc.LifecycleCompletion(ctx, errors.New("unexpected adapter operation"))
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]int64{"remaining": time.Until(j.DrainDeadline()).Nanoseconds()})
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		defer close(joined)
		return authorityrpc.LifecycleCompletion(ctx, ctx.Err())
	}
	if err = o.Record(mountcontrol.Facts{Witness: w}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: address, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	fmt.Println("ready")
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				raw, rights, err := mountcontrol.Receive(conn, mountcontrol.MaxWorkspaceRequest)
				if err != nil {
					return
				}
				q, err := mountcontrol.DecodeRequest(raw)
				if err != nil {
					rights.Close()
					return
				}
				r, err := o.Do(context.Background(), q, rights)
				if err != nil {
					r = mountcontrol.WorkspaceRefusal(q, err)
				}
				body, err := mountcontrol.EncodeResponse(r)
				if err == nil {
					_, _ = conn.Write(body)
				}
			}()
		}
	}()
	<-joined
	o.Close()
}

func TestRootSuspendForwardsRemainingBudgetAndJoinsLocalOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root adapter and UID 1000 socket owner")
	}
	directory, err := os.MkdirTemp("/tmp", "pfs-pr6-adapter-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if err = os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	copyPath := filepath.Join(directory, "adapter-test")
	output, err := os.OpenFile(copyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(output, input)
	output.Close()
	if err != nil {
		t.Fatal(err)
	}
	address := "@portablefs-reauthorization-1000-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 16)
	cmd := exec.Command(copyPath, "-test.run=^TestRootSuspendAdapterChild$")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + directory, "PFS_DRIVER_ADAPTER_HELPER=" + address}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	lines := bufio.NewScanner(stdout)
	if !lines.Scan() || lines.Text() != "ready" {
		t.Fatal("adapter child unavailable", lines.Text(), lines.Err())
	}
	start, err := mountcontrol.ProcessStart(int32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	i := inventory(t)
	desired := desired(1)
	desired.Witness = Witness{Intent: "mnt_AAAAAAAAAAAAAAAAAAAAAA", Process: strconv.Itoa(cmd.Process.Pid) + ":" + strconv.FormatUint(start, 10), Source: "portablefs:mnt_AAAAAAAAAAAAAAAAAAAAAA", Target: "/workspaces/adapter"}
	if err = i.CommitDesired(desired); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Inventory: i, Boot: bytesID(1), HostService: bytesID(2), GuestService: bytesID(3)}
	d := &Driver{manager: m, id: desired.Mount, witness: desired.Witness, child: cmd, socket: address, generation: 1, exited: make(chan struct{})}
	go func() { d.exitErr = cmd.Wait(); close(d.exited) }()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	// Model residence in the guest lane before the local adapter reaches send.
	time.Sleep(300 * time.Millisecond)
	type result struct {
		cold ColdResult
		err  error
	}
	done := make(chan result, 1)
	s := &pb.Suspension{BootId: m.Boot, HostServiceId: m.HostService, GuestServiceId: m.GuestService, Generation: 1, Nonce: bytesID(4)}
	go func() { r, err := d.Suspend(ctx, s); done <- result{r, err} }()
	if !lines.Scan() {
		t.Fatal("local Suspend did not start", lines.Err())
	}
	var admitted map[string]int64
	if err = json.Unmarshal(lines.Bytes(), &admitted); err != nil {
		t.Fatal(err)
	}
	if admitted["remaining"] <= 0 || admitted["remaining"] > int64(210*time.Millisecond) {
		t.Fatal("adapter created a fresh allowance", admitted)
	}
	<-ctx.Done()
	select {
	case r := <-done:
		t.Fatal("deadline released an unjoined local owner", r)
	case <-time.After(30 * time.Millisecond):
	}
	_, _ = stdin.Write([]byte{'j'})
	select {
	case r := <-done:
		if r.err == nil || r.cold.ColdComplete {
			t.Fatal("expired local owner certified coldness", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("local join did not settle")
	}
	<-d.exited
}

func bytesID(n byte) []byte {
	v := make([]byte, 16)
	for i := range v {
		v[i] = n
	}
	return v
}

func TestRootOperationSequenceCannotWrap(t *testing.T) {
	d := new(Driver)
	d.sequence.Store(^uint64(0) - 2)
	if _, err := d.next(); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		if _, err := d.next(); err == nil {
			t.Fatal("operation sequence wrapped")
		}
	}
}
