//go:build linux

package workspacemount

import (
	"bufio"
	"context"
	"encoding/binary"
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
	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"golang.org/x/sys/unix"
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
	initLoss := os.Getenv("PFS_DRIVER_INIT_LOSS") != ""
	if initLoss {
		w.Target = os.Getenv("PFS_DRIVER_TARGET")
	}
	joined := make(chan struct{})
	o := &mountcontrol.Owner{CheckPermit: func(mountcontrol.Workspace) bool { return true }}
	o.Driver.Run = func(ctx context.Context, j *mountcontrol.Job) mountcontrol.LifecycleResult {
		if initLoss {
			err := j.OfferInstall(mountcontrol.Phase{ActionID: "1", Options: fusev3.ManagedKernelOptions(1 << 20), Witness: w})
			if err == nil {
				err = j.WaitInstall(ctx)
			}
			return authorityrpc.LifecycleCompletion(ctx, err)
		}
		if j.Request().Operation != "workspace-suspend" {
			return authorityrpc.LifecycleCompletion(ctx, errors.New("unexpected adapter operation"))
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]int64{"remaining": time.Until(j.DrainDeadline()).Nanoseconds()})
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		defer close(joined)
		return authorityrpc.LifecycleCompletion(ctx, ctx.Err())
	}
	if initLoss {
		o.Driver.ValidateInstall = func(r *mountcontrol.Rights, p mountcontrol.Phase) error {
			return fusev3.ValidateManagedDescriptors(r.FDs[0], r.FDs[1], p.Witness.Source, p.Witness.Target)
		}
		o.Driver.Install = func(ctx context.Context, _ *mountcontrol.Job, r *mountcontrol.Rights) (mountcontrol.Witness, error) {
			kernel, err := fusev3.ObserveManagedKernelIdentity(w.Source, w.Target)
			out := w
			out.Kernel = kernel
			if err != nil {
				return out, err
			}
			frame := make([]byte, 8192)
			n, err := unix.Read(r.FDs[0], frame)
			if err != nil || n < 40 || binary.LittleEndian.Uint32(frame[4:]) != 26 {
				return out, errors.New("missing real INIT")
			}
			if os.Getenv("PFS_DRIVER_HOLD_INIT") == "1" {
				fmt.Println("init-owned")
				<-ctx.Done()
				return out, ctx.Err()
			}
			reply := make([]byte, 16)
			binary.LittleEndian.PutUint32(reply, 16)
			errno := -int32(syscall.EPROTO)
			binary.LittleEndian.PutUint32(reply[4:], uint32(errno))
			copy(reply[8:], frame[8:16])
			if _, err = unix.Write(r.FDs[0], reply); err != nil {
				return out, err
			}
			return out, errors.Join(syscall.EPROTO, o.RequireRemoval(ctx, "terminal", "real INIT refused"))
		}
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
				if initLoss && q.Operation == "workspace-install-kernel" {
					// The real owner accepted the rights; deliberately lose only its
					// response while its failed INIT waits for the root removal.
					return
				}
				if !initLoss && q.Operation == "workspace-suspend" {
					// Acceptance is real, but the root must learn it by observation
					// and keep ownership beyond the original caller deadline.
					return
				}
				body, err := mountcontrol.EncodeResponse(r)
				if err == nil {
					_, _ = conn.Write(body)
				}
			}()
		}
	}()
	if initLoss {
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		o.Close()
		return
	}
	<-joined
	// Death cannot stand in for a final observation. Keep this actual owner
	// alive until the parent has observed the joined failed lifecycle.
	_, _ = io.Copy(io.Discard, os.Stdin)
	o.Close()
}

func TestRootLostInstallResponseKeepsOriginalFailedINITOwner(t *testing.T) {
	for _, death := range []bool{false, true} {
		t.Run("child-death-"+strconv.FormatBool(death), func(t *testing.T) { testRootLostInstallResponse(t, death) })
	}
}

func testRootLostInstallResponse(t *testing.T, death bool) {
	if os.Geteuid() != 0 {
		t.Skip("root protected bootstrap and UID 1000 local owner")
	}
	dir, err := os.MkdirTemp("/tmp", "pfs-pr6-init-loss-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	binaryPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	copyPath := filepath.Join(dir, "owner-test")
	out, err := os.OpenFile(copyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(out, source)
	out.Close()
	if err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(dir, "protected")
	if err = os.Mkdir(targetPath, 0); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(targetPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	target := os.NewFile(uintptr(fd), "protected pinned target")
	defer target.Close()
	address := "@portablefs-reauthorization-init-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 16)
	cmd := exec.Command(copyPath, "-test.run=^TestRootSuspendAdapterChild$")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "PFS_DRIVER_ADAPTER_HELPER=" + address, "PFS_DRIVER_INIT_LOSS=1", "PFS_DRIVER_TARGET=" + targetPath}
	if death {
		cmd.Env = append(cmd.Env, "PFS_DRIVER_HOLD_INIT=1")
	}
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
		t.Fatal("INIT owner not ready", lines.Text(), lines.Err())
	}
	start, err := mountcontrol.ProcessStart(int32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	i := inventory(t)
	run := desired(1)
	run.Witness = Witness{Intent: "mnt_AAAAAAAAAAAAAAAAAAAAAA", Process: strconv.Itoa(cmd.Process.Pid) + ":" + strconv.FormatUint(start, 10), Source: "portablefs:mnt_AAAAAAAAAAAAAAAAAAAAAA", Target: targetPath}
	if err = i.CommitDesired(run); err != nil {
		t.Fatal(err)
	}
	rootStart, err := mountcontrol.ProcessStart(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	binding := workspaceadmission.Binding{Boot: [16]byte{1}, HostService: [16]byte{2}, GuestService: [16]byte{3}, Incarnation: [16]byte{4}, SupervisorPID: int32(os.Getpid()), SupervisorStart: rootStart}
	gate, err := workspaceadmission.New(binding)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Dispose()
	serial := gate.Close(1)
	m := &Manager{Inventory: i, Boot: bytesID(1), HostService: bytesID(2), GuestService: bytesID(3)}
	d := &Driver{manager: m, id: run.Mount, witness: run.Witness, child: cmd, socket: address, generation: 1, serial: serial, gate: gate, target: target, exited: make(chan struct{})}
	go func() { d.exitErr = cmd.Wait(); close(d.exited) }()
	defer func() {
		if d.kernel != nil {
			_ = d.kernel.Remove(true)
			_ = d.kernel.Finalize()
		}
	}()
	type completion struct {
		r   *mountcontrol.WorkspaceResponse
		err error
	}
	completed := make(chan completion, 1)
	go func() { r, e := d.job(t.Context(), "workspace-prepare", nil, ""); completed <- completion{r, e} }()
	if death {
		if !lines.Scan() || lines.Text() != "init-owned" {
			t.Fatal("child did not own real pending INIT", lines.Text(), lines.Err())
		}
		if err = cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		<-d.exited
		result := <-completed
		if result.err == nil {
			t.Fatal("dead child certified preparation")
		}
		proof, cleanupErr := d.remove(t.Context(), "terminal")
		if cleanupErr == nil || proof.ProcessExited || proof.KernelAbsent {
			t.Fatal("missing CLI reconciliation invented cleanup proof", proof, cleanupErr)
		}
		if d.removals[1] == nil || d.removals[1].err != nil || i.Snapshot()[0].Removed {
			t.Fatal("dead child erased root removal/inventory ownership", cleanupErr)
		}
		if err = d.kernel.Absent(); err != nil {
			t.Fatal("root did not remove before finalization", err)
		}
		return
	}
	result := <-completed
	r, err := result.r, result.err
	if err == nil || r == nil || r.State != "failed" || r.Phases.Install.Progress != "failed" || r.Phases.TerminalRemoval.Progress != "complete" {
		t.Fatal("lost response discarded the actual INIT/removal owner", r, err)
	}
	if !d.bootstrapAttempted || d.kernel == nil || d.binding().GateSerial != strconv.FormatUint(serial, 10) || d.removals[1] == nil || d.removals[1].err != nil {
		t.Fatal("delivery failure rearmed bootstrap or changed ownership", d.binding(), err)
	}
	if err = d.kernel.Absent(); err != nil {
		t.Fatal(err)
	}
	_, _ = stdin.Write([]byte{'j'})
	<-d.exited
	if d.exitErr != nil {
		t.Fatal(d.exitErr)
	}
	if err = d.kernel.Finalize(); err != nil {
		t.Fatal(err)
	}
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
		if r.err == nil || r.cold.ColdComplete || r.err.Error() == "workspace child exited before lifecycle completion" {
			t.Fatal("expired local owner certified coldness", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("local join did not settle")
	}
	stdin.Close()
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

func TestRootLocalConnectChargesSaturatedBacklog(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root local adapter boundary")
	}
	name := "@pfs-pr6-backlog-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 16)
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Bind(fd, &unix.SockaddrUnix{Name: name}); err != nil {
		t.Fatal(err)
	}
	if err = unix.Listen(fd, 0); err != nil {
		t.Fatal(err)
	}
	filler, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: name, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer filler.Close()
	d := &Driver{manager: &Manager{Boot: bytesID(1), HostService: bytesID(2), GuestService: bytesID(3)}, socket: name}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := d.exchange(ctx, "workspace-observe", d.binding(), nil, nil); done <- err }()
	select {
	case err := <-done:
		var unsent *localRequestUnsent
		if !errors.As(err, &unsent) || !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, syscall.EAGAIN) {
			t.Fatal("local connect lost definite non-delivery", err)
		}
	case <-time.After(time.Second):
		unix.Close(fd)
		t.Fatal("local connect escaped its lifecycle deadline")
	}
	// Linux can refuse a full UNIX backlog synchronously with EAGAIN. That
	// proves no bytes were sent; unlike a lost reply it needs no remote join.
	d.exited = make(chan struct{})
	_, err = d.job(ctx, "workspace-prepare", nil, "")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("unsent start could not finish at caller expiry", err)
	}
}

type stalledRegistrationHost struct {
	Host
	entered, release chan struct{}
}

func (h *stalledRegistrationHost) Registered(*pb.MountID) bool {
	close(h.entered)
	<-h.release
	return false
}
func TestRootRegistrationObservationCannotBlockClockClosure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root manager and real admission boundary")
	}
	start, err := mountcontrol.ProcessStart(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	gate := func(n byte) *workspaceadmission.Supervisor {
		b := workspaceadmission.Binding{SupervisorPID: int32(os.Getpid()), SupervisorStart: start}
		copy(b.Boot[:], bytesID(1))
		copy(b.HostService[:], bytesID(2))
		copy(b.GuestService[:], bytesID(3))
		copy(b.Incarnation[:], bytesID(n))
		g, err := workspaceadmission.New(b)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { g.Dispose() })
		return g
	}
	h := &stalledRegistrationHost{entered: make(chan struct{}), release: make(chan struct{})}
	defer func() {
		select {
		case <-h.release:
		default:
			close(h.release)
		}
	}()
	old := &Driver{id: desired(1).Mount, gate: gate(1)}
	old.cleaned.Store(true)
	active := &Driver{id: desired(2).Mount, gate: gate(2)}
	p, err := active.gate.Recovery(0)
	if err != nil {
		t.Fatal(err)
	}
	if err = active.gate.Prepared(p); err != nil {
		t.Fatal(err)
	}
	if err = active.gate.Open(0, p.Serial()); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Host: h, mounts: map[string]*Driver{"old": old, "active": active}}
	pruned := make(chan struct{})
	go func() { m.pruneMounts(); close(pruned) }()
	<-h.entered
	closed := make(chan struct{})
	go func() { m.ClockUnavailable(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("supervisor observation held the clock closure lock")
	}
	next, err := active.gate.Recovery(0)
	if err != nil || next.Serial() <= p.Serial() {
		t.Fatal("clock callback did not close the serving interval", next, err)
	}
	close(h.release)
	select {
	case <-pruned:
	case <-time.After(time.Second):
		t.Fatal("registration observer not joined")
	}
	if _, ok := m.snapshotMounts()["old"]; ok {
		t.Fatal("exact cleaned incarnation not pruned")
	}
	if m.snapshotMounts()["active"] != active {
		t.Fatal("active owner was pruned")
	}
}
