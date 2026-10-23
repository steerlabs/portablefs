//go:build linux

package fusev3

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
)

// Root owns the real sealed page and only pipe writer. The actual XFS authority
// and kernel frontend run under the provisioned unprivileged service identity.
// This qualifies the gate on an ordinary mount, not the future workspace driver.
func TestKernelWorkspaceGateAndOwnerLifetime(t *testing.T) {
	runWorkspaceKernelParent(t, workspaceKernelChild)
}
func TestKernelWorkspaceControlledPause(t *testing.T) {
	runWorkspaceKernelParent(t, workspaceKernelPauseChild)
}
func runWorkspaceKernelParent(t *testing.T, child func(*testing.T)) {
	if os.Getenv("PFS_WORKSPACE_KERNEL_CHILD") == "1" {
		child(t)
		return
	}
	if os.Getenv(envFUSE) != "1" || os.Getenv("PORTABLEFS_SERVICE_UID") == "" {
		t.Skip("privileged root workspace gate inventory is not configured")
	}
	if os.Geteuid() != 0 {
		t.Skip("root parent is required by the separate privileged root inventory")
	}
	start, err := mountcontrol.ProcessStart(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	binding := workspaceadmission.Binding{Boot: [16]byte{1}, HostService: [16]byte{2}, GuestService: [16]byte{3}, Incarnation: [16]byte{4}, SupervisorPID: int32(os.Getpid()), SupervisorStart: start}
	g, err := workspaceadmission.New(binding)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Dispose()
	proof, err := g.Recovery(1)
	if err != nil {
		t.Fatal(err)
	}
	files, err := g.ChildFiles()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/var/tmp", "workspace-kernel-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target := filepath.Join(dir, "frontend.test")
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0555)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(out, source)
	if err := errors.Join(copyErr, out.Close()); err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.ParseUint(os.Getenv("PORTABLEFS_SERVICE_UID"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.ParseUint(os.Getenv("PORTABLEFS_SERVICE_GID"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(target, "-test.run=^"+t.Name()+"$", "-test.timeout=2m", "-test.v")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	cmd.Env = append(os.Environ(), "PFS_WORKSPACE_KERNEL_CHILD=1", fmt.Sprintf("PFS_WORKSPACE_KERNEL_PID=%d", binding.SupervisorPID), fmt.Sprintf("PFS_WORKSPACE_KERNEL_START=%d", binding.SupervisorStart), envRequired+"=1")
	cmd.ExtraFiles = files[:]
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	for _, f := range files {
		_ = f.Close()
	}
	// Drain independently of the protocol, including subtest failures before a
	// marker and cleanup failures after the final marker. Wait must follow EOF.
	var outputMu sync.Mutex
	var output []string
	var scanErr error
	changed, outputDone := make(chan struct{}, 1), make(chan struct{})
	go func() {
		defer close(outputDone)
		lines := bufio.NewScanner(stdout)
		lines.Buffer(make([]byte, 4096), 1<<20)
		for lines.Scan() {
			outputMu.Lock()
			output = append(output, lines.Text())
			outputMu.Unlock()
			select {
			case changed <- struct{}{}:
			default:
			}
		}
		scanErr = lines.Err()
		if scanErr != nil {
			_, _ = io.Copy(io.Discard, stdout)
		}
	}()
	diagnostics := func() string {
		outputMu.Lock()
		defer outputMu.Unlock()
		return strings.Join(output, "\n")
	}
	cursor := 0
	expect := func(want string) {
		t.Helper()
		for {
			outputMu.Lock()
			found := false
			for cursor < len(output) {
				line := output[cursor]
				cursor++
				if line == want {
					found = true
					break
				}
			}
			outputMu.Unlock()
			if found {
				return
			}
			select {
			case <-changed:
			case <-outputDone:
				// Consume any lines appended after the previous snapshot.
				outputMu.Lock()
				more := cursor < len(output)
				outputMu.Unlock()
				if !more {
					t.Fatalf("kernel child did not reach %s (scanner: %v):\n%s", want, scanErr, diagnostics())
				}
			}
		}
	}

	expect("prepared")
	if err := g.Prepared(proof); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(1, proof.Serial()); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write([]byte{'O'}); err != nil {
		t.Fatal(err)
	}
	expect("served")
	g.Close(1)
	if _, err := stdin.Write([]byte{'C'}); err != nil {
		t.Fatal(err)
	}
	expect("closed")
	if t.Name() == "TestKernelWorkspaceControlledPause" {
		if _, err := stdin.Write([]byte{'R'}); err != nil {
			t.Fatal(err)
		}
		expect("reprepared")
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
		if _, err := stdin.Write([]byte{'O'}); err != nil {
			t.Fatal(err)
		}
		expect("resumed")
	}
	// Closing the sole writer requires no socket/control handler. Child teardown
	// must prove its real connection is gone before reporting completion.
	if err := g.Dispose(); err != nil {
		t.Fatal(err)
	}
	expect("owner-exit")
	<-outputDone
	if err := cmd.Wait(); err != nil {
		t.Fatalf("kernel child Wait: %v (scanner: %v):\n%s", err, scanErr, diagnostics())
	}
	if scanErr != nil {
		t.Fatalf("kernel child output: %v:\n%s", scanErr, diagnostics())
	}
	t.Logf("kernel child output:\n%s", diagnostics())
}

func workspaceKernelChild(t *testing.T) {
	pid, _ := strconv.ParseInt(os.Getenv("PFS_WORKSPACE_KERNEL_PID"), 10, 32)
	start, _ := strconv.ParseUint(os.Getenv("PFS_WORKSPACE_KERNEL_START"), 10, 64)
	binding := workspaceadmission.Binding{Boot: [16]byte{1}, HostService: [16]byte{2}, GuestService: [16]byte{3}, Incarnation: [16]byte{4}, SupervisorPID: int32(pid), SupervisorStart: start}
	var mounted atomic.Pointer[Mount]
	reader, err := workspaceadmission.Adopt(os.NewFile(3, "gate"), os.NewFile(4, "owner"), binding, func() {
		if m := mounted.Load(); m != nil {
			m.revoke(errors.New("workspace test owner EOF"))
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Retire()
	proof, err := reader.Recovery(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	revoked := make(chan RevocationReport, 1)
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1, workspace: reader, workspaceRecovery: &proof, onRevoked: func(r RevocationReport) { revoked <- r }})
	mounted.Store(f.mounts[0])
	// Closed INIT and cold Subscribe must finish without serving permission.
	if _, err := os.Stat(f.join(0, "missing")); !errors.Is(err, syscall.EIO) {
		t.Fatal("closed-start kernel lookup served", err)
	}
	fmt.Println("prepared")
	command := func(want byte) {
		t.Helper()
		var b [1]byte
		if _, err := io.ReadFull(os.Stdin, b[:]); err != nil || b[0] != want {
			t.Fatal("supervisor command", b, err)
		}
	}
	command('O')
	path := f.join(0, "data")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("accepted")); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "accepted" {
		t.Fatal(string(data), err)
	}
	local := f.join(0, "node_modules")
	if err := os.Mkdir(local, 0700); err != nil {
		t.Fatal(err)
	}
	fmt.Println("served")
	command('C')
	if _, err := os.Stat(path); !errors.Is(err, syscall.EIO) {
		t.Fatal("cached kernel getattr bypassed Close", err)
	}
	if _, err := os.ReadDir(f.mountPath(0)); !errors.Is(err, syscall.EIO) {
		t.Fatal("kernel READDIR bypassed Close", err)
	}
	if err := os.WriteFile(f.join(0, "new"), []byte("refused"), 0600); !errors.Is(err, syscall.EIO) {
		t.Fatal("closed kernel create applied", err)
	}
	if _, err := os.Stat(filepath.Join(f.volumeRoot, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("closed CREATE changed XFS", err)
	}
	fmt.Println("closed")
	select {
	case <-reader.Done():
	case <-time.After(15 * time.Second):
		t.Fatal("owner EOF did not initiate teardown")
	}
	select {
	case <-f.mounts[0].kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("owner EOF stranded kernel connection")
	}
	waitWorkspaceKernelWithdrawal(t, revoked)
	fmt.Println("owner-exit")
}

func waitWorkspaceKernelWithdrawal(t *testing.T, reports <-chan RevocationReport) {
	t.Helper()
	select {
	case report := <-reports:
		if !report.KernelStateWithdrawn {
			t.Fatal("owner EOF did not withdraw kernel state", report)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("owner EOF did not report kernel withdrawal")
	}
}
