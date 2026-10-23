//go:build linux

package fusev3

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/continuous"
	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
	"golang.org/x/sys/unix"
)

// Generic root servant: the child asks for Open/Close/Dispose by line.
func runReviewKernelParent(t *testing.T, child func(*testing.T)) {
	if os.Getenv("PFS_WORKSPACE_KERNEL_CHILD") == "1" {
		child(t)
		return
	}
	if os.Getenv(envFUSE) != "1" || os.Getenv("PORTABLEFS_SERVICE_UID") == "" || os.Geteuid() != 0 {
		t.Skip("root parent required")
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
	files, err := g.ChildFiles()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/var/tmp", "review-kernel-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	_ = os.Chmod(dir, 0755)
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
	uid, _ := strconv.ParseUint(os.Getenv("PORTABLEFS_SERVICE_UID"), 10, 32)
	gid, _ := strconv.ParseUint(os.Getenv("PORTABLEFS_SERVICE_GID"), 10, 32)
	cmd := exec.Command(target, "-test.run=^"+t.Name()+"$", "-test.timeout=20m", "-test.v")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}, Pdeathsig: syscall.SIGKILL}
	cmd.Env = append(os.Environ(), "PFS_WORKSPACE_KERNEL_CHILD=1", fmt.Sprintf("PFS_WORKSPACE_KERNEL_PID=%d", binding.SupervisorPID), fmt.Sprintf("PFS_WORKSPACE_KERNEL_START=%d", binding.SupervisorStart), envRequired+"=1")
	cmd.ExtraFiles = files[:]
	cmd.Stderr = os.Stderr
	stdout, _ := cmd.StdoutPipe()
	stdin, _ := cmd.StdinPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	for _, f := range files {
		_ = f.Close()
	}
	lines := bufio.NewScanner(stdout)
	for lines.Scan() {
		line := lines.Text()
		switch {
		case line == "REQ open":
			p, err := g.Recovery(1)
			if err == nil {
				err = g.Prepared(p)
			}
			if err == nil {
				err = g.Open(1, p.Serial())
			}
			fmt.Fprintf(stdin, "%v\n", err)
		case line == "REQ close":
			fmt.Fprintf(stdin, "%d\n", g.Close(1))
		case line == "REQ dispose":
			fmt.Fprintf(stdin, "%v\n", g.Dispose())
		default:
			fmt.Println(line)
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal("child failed: ", err)
	}
}

func reviewAdopt(t *testing.T) (*workspaceadmission.Reader, *workspaceadmission.RecoveryPermit, *atomic.Pointer[Mount]) {
	pid, _ := strconv.ParseInt(os.Getenv("PFS_WORKSPACE_KERNEL_PID"), 10, 32)
	start, _ := strconv.ParseUint(os.Getenv("PFS_WORKSPACE_KERNEL_START"), 10, 64)
	binding := workspaceadmission.Binding{Boot: [16]byte{1}, HostService: [16]byte{2}, GuestService: [16]byte{3}, Incarnation: [16]byte{4}, SupervisorPID: int32(pid), SupervisorStart: start}
	var mounted atomic.Pointer[Mount]
	reader, err := workspaceadmission.Adopt(os.NewFile(3, "gate"), os.NewFile(4, "owner"), binding, func() {
		if m := mounted.Load(); m != nil {
			m.revoke(errors.New("review owner EOF"))
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := reader.Recovery(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	return reader, &proof, &mounted
}

type reviewChild struct {
	t   *testing.T
	in  *bufio.Reader
	f   *integrationFixture
	m   *Mount
	off *atomic.Int64
	bad []string
}

func (c *reviewChild) req(cmd string) string {
	fmt.Println("REQ " + cmd)
	line, err := c.in.ReadString('\n')
	if err != nil {
		c.t.Fatal(err)
	}
	return strings.TrimSpace(line)
}
func (c *reviewChild) fail(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	c.bad = append(c.bad, msg)
	fmt.Println("" + msg)
}
func (c *reviewChild) now() time.Time { return replaySubscriptionClock{c.off}.Now() }
func (c *reviewChild) suspend() uint64 {
	serial, _ := strconv.ParseUint(c.req("close"), 10, 64)
	ctx, cancel := context.WithTimeout(c.t.Context(), 30*time.Second)
	defer cancel()
	o, err := c.m.SuspendWorkspace(ctx, 1, serial, c.now().Add(8*time.Second))
	if err != nil || !o.ColdComplete {
		c.t.Fatalf("Suspend serial %d: cold=%v err=%v", serial, o.ColdComplete, err)
	}
	fmt.Printf("suspended serial=%d loss=%d outcome=%v\n", serial, len(o.Loss), o.Outcome)
	return serial
}
func (c *reviewChild) recover(serial uint64) {
	ctx, cancel := context.WithTimeout(c.t.Context(), 90*time.Second)
	defer cancel()
	o, err := c.m.RecoverWorkspace(ctx, 1, serial)
	if err != nil || !o.Prepared {
		c.t.Fatalf("Recover serial %d: prepared=%v err=%v", serial, o.Prepared, err)
	}
	if r := c.req("open"); r != "<nil>" {
		c.t.Fatal("open:", r)
	}
}
func (c *reviewChild) write(path, data string, mode os.FileMode) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err = file.Write([]byte(data)); err == nil {
		err = file.Sync()
	}
	if err = errors.Join(err, file.Close()); err != nil {
		c.t.Fatal(err)
	}
}
func preadAll(fd *os.File) (string, error) {
	buf := make([]byte, 256)
	n, err := unix.Pread(int(fd.Fd()), buf, 0)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

type reviewWarm struct {
	a, b, dir     *os.File
	pa, pb, pd    string
	sa            string
	names         []string
	negative, mod string
}

// Warm every cache class on the managed mount, including a dirty delegated
// write which the cold cut must flush.
func (c *reviewChild) warm(tag string) reviewWarm {
	t := c.t
	f := c.f
	w := reviewWarm{sa: "old-" + tag}
	_ = os.Mkdir(f.join(1, "d"+tag), 0755)
	c.write(f.join(1, "a"+tag), w.sa, 0644)
	c.write(f.join(1, "b"+tag), "old-b-"+tag, 0644)
	c.write(f.join(1, "d"+tag, "x"), "x", 0644)
	c.write(f.join(1, "d"+tag, "gone"), "g", 0644)
	w.pa, w.pb, w.pd = f.join(0, "a"+tag), f.join(0, "b"+tag), f.join(0, "d"+tag)
	var err error
	if w.a, err = os.Open(w.pa); err != nil {
		t.Fatal(err)
	}
	if s, _ := preadAll(w.a); s != w.sa {
		t.Fatal("warm read", s)
	}
	_, _ = os.Stat(w.pa)
	_, _ = os.Stat(filepath.Join(w.pd, "x"))
	_, _ = os.Stat(filepath.Join(w.pd, "gone"))
	if _, err := os.Stat(filepath.Join(w.pd, "newname")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("negative warm", err)
	}
	if w.dir, err = os.Open(w.pd); err != nil {
		t.Fatal(err)
	}
	w.names, _ = w.dir.Readdirnames(-1)
	if w.b, err = os.OpenFile(w.pb, os.O_RDWR, 0); err != nil {
		t.Fatal(err)
	}
	if s, _ := preadAll(w.b); s != "old-b-"+tag {
		t.Fatal("warm b", s)
	}
	if _, err := unix.Pwrite(int(w.b.Fd()), []byte("M0"), 0); err != nil {
		t.Fatal(err)
	}
	return w
}
func (c *reviewChild) peerMutate(tag string) {
	f := c.f
	if data, err := os.ReadFile(f.join(1, "b"+tag)); err != nil || !strings.HasPrefix(string(data), "M0") {
		c.fail("%s: cold cut did not publish accepted write before peer: %q %v", tag, data, err)
	}
	c.write(f.join(1, "a"+tag), "peer-a-longer-"+tag, 0644)
	if err := os.Chmod(f.join(1, "a"+tag), 0640); err != nil {
		c.t.Fatal(err)
	}
	c.write(f.join(1, "b"+tag), "peer-b-"+tag, 0644)
	c.write(f.join(1, "d"+tag, "newname"), "n", 0644)
	if err := os.Remove(f.join(1, "d"+tag, "gone")); err != nil {
		c.t.Fatal(err)
	}
	if err := os.Rename(f.join(1, "d"+tag, "x"), f.join(1, "d"+tag, "y")); err != nil {
		c.t.Fatal(err)
	}
}
func (c *reviewChild) verify(tag string, w reviewWarm) {
	want := "peer-a-longer-" + tag
	if s, err := preadAll(w.a); s != want {
		c.fail("%s: held RDONLY fd served stale data %q err=%v", tag, s, err)
	}
	if st, err := w.a.Stat(); err != nil || st.Size() != int64(len(want)) {
		c.fail("%s: held fd fstat stale %v %v", tag, st, err)
	}
	if data, err := os.ReadFile(w.pa); string(data) != want {
		c.fail("%s: fresh open read stale %q %v", tag, data, err)
	}
	if st, err := os.Stat(w.pa); err != nil || st.Mode().Perm() != 0640 {
		c.fail("%s: stale mode %v %v", tag, st, err)
	}
	if s, err := preadAll(w.b); s != "peer-b-"+tag {
		c.fail("%s: held RDWR (delegated) fd served stale %q err=%v", tag, s, err)
	}
	if _, err := os.Stat(filepath.Join(w.pd, "newname")); err != nil {
		c.fail("%s: stale negative name: %v", tag, err)
	}
	if _, err := os.Stat(filepath.Join(w.pd, "gone")); !errors.Is(err, os.ErrNotExist) {
		c.fail("%s: removed name still served: %v", tag, err)
	}
	if _, err := os.Stat(filepath.Join(w.pd, "x")); !errors.Is(err, os.ErrNotExist) {
		c.fail("%s: renamed-from name still served: %v", tag, err)
	}
	if _, err := os.Stat(filepath.Join(w.pd, "y")); err != nil {
		c.fail("%s: renamed-to name missing: %v", tag, err)
	}
	if _, err := w.dir.Seek(0, io.SeekStart); err != nil {
		c.fail("%s: rewinddir %v", tag, err)
	}
	names, err := w.dir.Readdirnames(-1)
	sort.Strings(names)
	if err != nil || strings.Join(names, ",") != "newname,y" {
		c.fail("%s: held dir fd stale listing %v %v (before %v)", tag, names, err, w.names)
	}
	_ = w.a.Close()
	_ = w.b.Close()
	_ = w.dir.Close()
}

func countReviewFDs() int {
	entries, _ := os.ReadDir("/proc/self/fd")
	return len(entries)
}

func reviewKernelPauseChild(t *testing.T) {
	reader, proof, mounted := reviewAdopt(t)
	defer reader.Retire()
	var off atomic.Int64
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: &workspaceTestClockOwner{}, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, workspaceClock: replaySubscriptionClock{&off}})
	f.transports[0].clockOffset = &off
	c := &reviewChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	opusPollHack(t, f.mountPath(0))

	// Phase A: lease clock frozen across a 15 s pause; guest time resumes from
	// the frozen value (lags real time), peer completes writes while cold.
	for _, phase := range []struct {
		tag   string
		pause time.Duration
		lag   bool
		aged  time.Duration
	}{{"lag15", 15 * time.Second, true, 0}, {"jump15", 15 * time.Second, false, 0}, {"aged90", 2 * time.Second, true, 90 * time.Second}} {
		fmt.Println("phase", phase.tag)
		w := c.warm(phase.tag)
		serial := c.suspend()
		frozenAt := continuous.Time()
		time.Sleep(phase.pause)
		if phase.aged != 0 {
			f.advanceClock(phase.aged)
		}
		c.peerMutate(phase.tag)
		if _, err := os.Stat(w.pa); !errors.Is(err, syscall.EIO) {
			c.fail("%s: closed mount answered %v", phase.tag, err)
		}
		if phase.lag {
			off.Add(-int64(continuous.Time().Sub(frozenAt)))
		}
		c.recover(serial)
		c.verify(phase.tag, w)
	}

	// Phase B: leak accounting over park/resume cycles with real reclaim/close.
	settle := func() (int, int) {
		time.Sleep(2 * time.Second)
		runtime.GC()
		return runtime.NumGoroutine(), countReviewFDs()
	}
	cycle := func(i int) {
		path := f.join(0, fmt.Sprintf("cyc%d", i))
		c.write(path, "v", 0644)
		_, _ = os.ReadFile(path)
		c.recover(c.suspend())
	}
	cycle(0)
	g0, fd0 := settle()
	for i := 1; i <= 12; i++ {
		cycle(i)
	}
	g1, fd1 := settle()
	fmt.Printf("leak-check goroutines %d -> %d fds %d -> %d\n", g0, g1, fd0, fd1)
	if g1 > g0+8 || fd1 > fd0+4 {
		buf := make([]byte, 4<<20)
		n := runtime.Stack(buf, true)
		_ = os.WriteFile("/var/tmp/review-leak-stacks.txt", buf[:n], 0644)
		c.fail("leak over 12 cycles: goroutines %d->%d fds %d->%d", g0, g1, fd0, fd1)
	}

	// Phase C: session expired while cold. Recovery must end definitively, not
	// spin in transient retry.
	fmt.Println("phase session-expired")
	serial := c.suspend()
	f.advanceClock(3 * time.Minute)
	f.sweepSessions()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	begin := time.Now()
	o, err := c.m.RecoverWorkspace(ctx, 1, serial)
	cancel()
	fmt.Printf("expired-session Recover after %v: prepared=%v err=%v\n", time.Since(begin), o.Prepared, err)
	if o.Prepared || err == nil || errors.Is(err, context.DeadlineExceeded) {
		c.fail("expired session: Recover prepared=%v err=%v (no definitive verdict)", o.Prepared, err)
	}
	for _, b := range c.bad {
		t.Error(b)
	}
	c.req("dispose")
	select {
	case <-c.m.kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Error("owner EOF stranded connection")
	}
}

func TestReviewKernelFrozenLeasePause(t *testing.T) {
	runReviewKernelParent(t, reviewKernelPauseChild)
}

func reviewKernelSessionExpiredChild(t *testing.T) {
	reader, proof, mounted := reviewAdopt(t)
	defer reader.Retire()
	var off atomic.Int64
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: &workspaceTestClockOwner{}, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, workspaceClock: replaySubscriptionClock{&off}})
	c := &reviewChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	opusPollHack(t, f.mountPath(0))
	c.write(f.join(0, "e"), "v", 0644)
	serial := c.suspend()
	f.advanceClock(3 * time.Minute)
	fmt.Println("swept", f.sweepSessions())
	_, perr := os.Stat(f.join(1, "e"))
	fmt.Printf("peer stat after expiry: %v; m0 SessionEndCause=%v\n", perr, c.m.rpc.SessionEndCause())
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	begin := time.Now()
	o, err := c.m.RecoverWorkspace(ctx, 1, serial)
	cancel()
	fmt.Printf("expired-session Recover after %v: prepared=%v err=%v cause=%v\n", time.Since(begin), o.Prepared, err, c.m.rpc.SessionEndCause())
	if o.Prepared || o.Result.Disposition != authorityrpc.LifecycleFailed || !errors.Is(err, authorityrpc.ErrSessionEnded) || !errors.Is(c.m.rpc.SessionEndCause(), authorityrpc.ErrSessionEnded) {
		t.Fatalf("session expiry lacked definitive terminal result: %+v %v cause=%v", o, err, c.m.rpc.SessionEndCause())
	}

	c.req("dispose")
	select {
	case <-c.m.kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Error("owner EOF stranded connection")
	}
}
func TestReviewKernelSessionExpired(t *testing.T) {
	runReviewKernelParent(t, reviewKernelSessionExpiredChild)
}

func reviewKernelLeaseExpiryChild(t *testing.T) {
	reader, proof, mounted := reviewAdopt(t)
	defer reader.Retire()
	var off atomic.Int64
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: &workspaceTestClockOwner{}, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 20 * time.Second, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, workspaceClock: replaySubscriptionClock{&off}})
	c := &reviewChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	opusPollHack(t, f.mountPath(0))
	c.write(f.join(0, "e"), "v", 0644)
	serial := c.suspend()
	time.Sleep(26 * time.Second)
	fmt.Println("swept", f.sweepSessions())
	_, perr := os.Stat(f.join(1, "e"))
	fmt.Printf("peer stat after m0 lease expiry: %v; m0 SessionEndCause=%v\n", perr, c.m.rpc.SessionEndCause())
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	begin := time.Now()
	o, err := c.m.RecoverWorkspace(ctx, 1, serial)
	cancel()
	fmt.Printf("lease-expired Recover after %v: prepared=%v err=%v cause=%v\n", time.Since(begin), o.Prepared, err, c.m.rpc.SessionEndCause())
	if o.Prepared || o.Result.Disposition != authorityrpc.LifecycleFailed || !errors.Is(err, authorityrpc.ErrSessionEnded) || !errors.Is(c.m.rpc.SessionEndCause(), authorityrpc.ErrSessionEnded) {
		t.Fatalf("session expiry lacked definitive terminal result: %+v %v cause=%v", o, err, c.m.rpc.SessionEndCause())
	}

	c.req("dispose")
	select {
	case <-c.m.kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Error("owner EOF stranded connection")
	}
}
func TestReviewKernelLeaseExpiry(t *testing.T) {
	runReviewKernelParent(t, reviewKernelLeaseExpiryChild)
}

func reviewKernelClockReadinessChild(t *testing.T) {
	reader, proof, mounted := reviewAdopt(t)
	defer reader.Retire()
	var off atomic.Int64
	clock := &workspaceTestClockOwner{refused: make(chan struct{})}
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: clock, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, workspaceClock: replaySubscriptionClock{&off}})
	c := &reviewChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	opusPollHack(t, f.mountPath(0))
	c.write(f.join(0, "e"), "v", 0644)
	// Install the lifecycle-owned dispatch check through a real cold/recover.
	c.recover(c.suspend())
	// The TLS clock owner reports a transient readiness problem while serving.
	held, err := os.OpenFile(f.join(0, "e"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := held.Write([]byte("w")); err != nil {
		t.Fatal(err)
	}
	clock.unavailable.Store(true)
	// New frontend Flush must refuse immediately; accepted bytes remain owned.
	if err := held.Close(); !errors.Is(err, syscall.EIO) {
		t.Fatal("close under invalid serving proof", err)
	}
	select {
	case <-clock.refused:
	case <-time.After(5 * time.Second):
		t.Fatal("no synchronous clock refusal")
	}
	if c.m.isRevoked() || c.m.rpc.SessionEndCause() != nil || c.m.delegations.LossSequence() != 0 {
		t.Fatal("readiness refusal became terminal or lost data")
	}
	// Root closes and drains the accepted cut through the existing TLS owner.
	serial := c.suspend()
	<-clock.restoreAfter(3 * time.Second)
	c.recover(serial)
	data, err := os.ReadFile(f.join(1, "e"))
	if err != nil || string(data) != "w" || c.m.isRevoked() || c.m.rpc.SessionEndCause() != nil || c.m.delegations.LossSequence() != 0 {
		t.Fatalf("readiness gap lost accepted data: %q %v revoked=%v cause=%v", data, err, c.m.isRevoked(), c.m.rpc.SessionEndCause())
	}
	c.req("dispose")
	select {
	case <-c.m.kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Error("owner EOF stranded connection")
	}
}
func TestReviewKernelClockReadiness(t *testing.T) {
	runReviewKernelParent(t, reviewKernelClockReadinessChild)
}

func reviewKernelChurnChild(t *testing.T) {
	reader, proof, mounted := reviewAdopt(t)
	defer reader.Retire()
	var off atomic.Int64
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: &workspaceTestClockOwner{}, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, workspaceClock: replaySubscriptionClock{&off}})
	c := &reviewChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	opusPollHack(t, f.mountPath(0))
	for i := 0; i < 8; i++ {
		c.write(f.join(0, fmt.Sprintf("churn%d", i)), "seed", 0644)
	}
	var stop atomic.Bool
	var ops, fails atomic.Int64
	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			path := f.join(0, fmt.Sprintf("churn%d", g))
			var held []*os.File
			for i := 0; !stop.Load(); i++ {
				file, err := os.OpenFile(path, os.O_RDWR, 0)
				if err == nil {
					_, _ = file.Write([]byte(fmt.Sprintf("g%d-%d", g, i)))
					if i%3 == 0 {
						_ = unix.FcntlFlock(file.Fd(), unix.F_SETLK, &unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 1})
					}
					if i%5 == 0 {
						_ = file.Sync()
					}
					held = append(held, file)
				} else {
					fails.Add(1)
				}
				if len(held) > 3 {
					_ = held[0].Close()
					held = held[1:]
				}
				_, _ = os.Stat(path)
				ops.Add(1)
				time.Sleep(time.Millisecond)
			}
			for _, h := range held {
				_ = h.Close()
			}
		}(g)
	}
	for cycle := 0; cycle < 20; cycle++ {
		serial, _ := strconv.ParseUint(c.req("close"), 10, 64)
		ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
		begin := time.Now()
		o, err := c.m.SuspendWorkspace(ctx, 1, serial, c.now().Add(8*time.Second))
		cancel()
		if err != nil || !o.ColdComplete {
			buf := make([]byte, 8<<20)
			n := runtime.Stack(buf, true)
			_ = os.WriteFile("/var/tmp/review-churn-stacks.txt", buf[:n], 0644)
			c.fail("cycle %d: Suspend under cleanup churn took %v cold=%v err=%v", cycle, time.Since(begin), o.ColdComplete, err)
			break
		}
		time.Sleep(200 * time.Millisecond)
		c.recover(serial)
		time.Sleep(300 * time.Millisecond)
	}
	stop.Store(true)
	for g := 0; g < 8; g++ {
		<-done
	}
	fmt.Printf("churn ops=%d failed-opens=%d revoked=%v\n", ops.Load(), fails.Load(), c.m.isRevoked())
	if c.m.isRevoked() {
		c.fail("mount revoked under churn: fatal=%v session=%v", c.m.fatalError(), c.m.rpc.SessionEndCause())
	}
	for _, b := range c.bad {
		t.Error(b)
	}
	c.req("dispose")
	select {
	case <-c.m.kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Error("owner EOF stranded connection")
	}
}
func TestReviewKernelChurn(t *testing.T) {
	runReviewKernelParent(t, reviewKernelChurnChild)
}

func reviewKernelInterruptedRecoverChild(t *testing.T) {
	reader, proof, mounted := reviewAdopt(t)
	defer reader.Retire()
	var off atomic.Int64
	clock := &reviewBlockingClock{}
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: clock, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, workspaceClock: replaySubscriptionClock{&off}})
	c := &reviewChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	opusPollHack(t, f.mountPath(0))
	c.write(f.join(0, "e"), "v", 0644)
	serial := c.suspend()
	// Wake: the TLS clock has not been corrected yet; a newer sleep cancels
	// the pending Recover.
	clock.uncorrected.Store(true)
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	o, err := c.m.RecoverWorkspace(ctx, 1, serial)
	cancel()
	fmt.Printf("cancelled Recover: prepared=%v err=%v\n", o.Prepared, err)
	time.Sleep(12 * time.Second) // the old 10 s subscription horizon elapses naturally
	clock.uncorrected.Store(false)
	serial2, _ := strconv.ParseUint(c.req("close"), 10, 64)
	ctx, cancel = context.WithTimeout(t.Context(), 20*time.Second)
	o, err = c.m.SuspendWorkspace(ctx, 1, serial2, c.now().Add(8*time.Second))
	cancel()
	fmt.Printf("newer Suspend: cold=%v err=%v\n", o.ColdComplete, err)
	if err != nil || !o.ColdComplete {
		t.Fatal("interrupted recovery could not re-acknowledge cold", o, err)
	}

	ctx, cancel = context.WithTimeout(t.Context(), 20*time.Second)
	o, err = c.m.RecoverWorkspace(ctx, 1, serial2)
	cancel()
	fmt.Printf("Recover: prepared=%v err=%v\n", o.Prepared, err)
	if !o.Prepared {
		c.fail("interrupted Recover stranded the incarnation: %v", err)
	}
	for _, b := range c.bad {
		t.Error(b)
	}
	c.req("dispose")
	select {
	case <-c.m.kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Error("owner EOF stranded connection")
	}
}
func TestReviewKernelInterruptedRecover(t *testing.T) {
	runReviewKernelParent(t, reviewKernelInterruptedRecoverChild)
}

type reviewBlockingClock struct{ uncorrected atomic.Bool }

func (c *reviewBlockingClock) Wait(ctx context.Context, p mountenrollment.Permit) error {
	for c.uncorrected.Load() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return nil
}
func (c *reviewBlockingClock) Check(mountenrollment.Permit) error { return nil }
