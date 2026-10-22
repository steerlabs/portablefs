//go:build linux

package workspaceadmission

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	"golang.org/x/sys/unix"
)

func binding(t *testing.T) Binding {
	t.Helper()
	start, err := mountcontrol.ProcessStart(int32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	return Binding{Boot: [16]byte{1}, HostService: [16]byte{2}, GuestService: [16]byte{3}, Incarnation: [16]byte{4}, SupervisorPID: int32(os.Getpid()), SupervisorStart: start}
}
func gate(t *testing.T) (*Supervisor, *Reader) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root supervisor required; covered by the Linux container gate")
	}
	b := binding(t)
	g, err := New(b)
	if err != nil {
		t.Fatal(err)
	}
	files, err := g.ChildFiles()
	if err != nil {
		t.Fatal(err)
	}
	r, err := Adopt(files[0], files[1], b, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.Dispose(); _ = r.Retire() })
	return g, r
}
func prepared(t *testing.T, g *Supervisor, generation uint64) RecoveryPermit {
	t.Helper()
	p, err := g.Recovery(generation)
	if err != nil {
		t.Fatal(err)
	}
	if err = g.Prepared(p); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestClosedStartAndExactPreparedCAS(t *testing.T) {
	g, r := gate(t)
	if _, err := r.Check(); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed startup admitted: %v", err)
	}
	p := prepared(t, g, 1)
	if err := r.Recover(p); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(1, p.Serial()); err != nil {
		t.Fatal(err)
	}
	admitted, err := r.Check()
	if err != nil {
		t.Fatal(err)
	}
	first := g.Close(1)
	if err := admitted.Check(); !errors.Is(err, ErrClosed) {
		t.Fatal("old serving proof survived Close")
	}
	old := prepared(t, g, 1)
	second := g.Close(1)
	if second != first+1 {
		t.Fatalf("same-generation Close reused serial: %d %d", first, second)
	}
	if err := g.Open(1, old.Serial()); !errors.Is(err, ErrClosed) {
		t.Fatal("delayed Open used cleared proof")
	}
	if err := g.Prepared(old); !errors.Is(err, ErrClosed) {
		t.Fatal("old preparation installed after Close")
	}
	if err := r.Recover(old); !errors.Is(err, ErrClosed) {
		t.Fatal("old recovery permit survived Close")
	}
	current := prepared(t, g, 1)
	if err := g.Open(1, current.Serial()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Check(); err != nil {
		t.Fatal(err)
	}
	if err := g.Open(1, current.Serial()); !errors.Is(err, ErrClosed) {
		t.Fatal("Open reused consumed proof")
	}
}
func TestReadOnlyHandoffAndDescriptorSeals(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root supervisor required")
	}
	b := binding(t)
	g, err := New(b)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Dispose()
	files, err := g.ChildFiles()
	if err != nil {
		t.Fatal(err)
	}
	defer files[0].Close()
	defer files[1].Close()
	fd := int(files[0].Fd())
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatal(flags, err)
	}
	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil || seals != requiredSeals {
		t.Fatal(seals, err)
	}
	for _, f := range []*os.File{g.file, files[0]} {
		if _, err := unix.Pwrite(int(f.Fd()), []byte{255}, 0); err == nil {
			t.Fatal("sealed header was writable")
		}
		if page, err := unix.Mmap(int(f.Fd()), 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED); err == nil {
			_ = unix.Munmap(page)
			t.Fatal("new writable mapping succeeded")
		}
		if err := unix.Ftruncate(int(f.Fd()), int64(os.Getpagesize()*2)); err == nil {
			t.Fatal("gate grew")
		}
		if err := unix.Ftruncate(int(f.Fd()), 0); err == nil {
			t.Fatal("gate shrank")
		}
		if _, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE); err == nil {
			t.Fatal("seals changed")
		}
	}
	// Closing is still a real shared atomic store through the sole old mapping.
	if serial := g.Close(7); serial != 1 {
		t.Fatal(serial)
	}
}
func TestHandoffRejectsWritableOrUnboundDescriptors(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root supervisor required")
	}
	for _, kind := range []string{"writable", "binding", "writer"} {
		t.Run(kind, func(t *testing.T) {
			b := binding(t)
			g, err := New(b)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Dispose()
			files, err := g.ChildFiles()
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "writable":
				_ = files[0].Close()
				fd, err := unix.Dup(int(g.file.Fd()))
				if err != nil {
					t.Fatal(err)
				}
				files[0] = os.NewFile(uintptr(fd), "writable")
			case "binding":
				b.Incarnation[0]++
			case "writer":
				_ = files[1].Close()
				fd, err := unix.Dup(int(g.writer.Fd()))
				if err != nil {
					t.Fatal(err)
				}
				files[1] = os.NewFile(uintptr(fd), "writer")
			}
			if _, err := Adopt(files[0], files[1], b, nil); err == nil {
				t.Fatal("invalid descriptor handoff admitted")
			}
			for _, f := range files {
				if _, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0); err == nil {
					t.Fatal("rejection leaked a descriptor")
				}
			}
		})
	}
}
func TestOwnerEOFIsIndependentAndPermanent(t *testing.T) {
	g, r := gate(t)
	p := prepared(t, g, 1)
	if err := g.Open(1, p.Serial()); err != nil {
		t.Fatal(err)
	}
	if err := g.writer.Close(); err != nil {
		t.Fatal(err)
	}
	g.writer = nil
	select {
	case <-r.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("EOF watcher did not run")
	}
	if _, err := r.Check(); !errors.Is(err, ErrClosed) {
		t.Fatal("dead owner admitted serving")
	}
	g.Close(1)
	p = prepared(t, g, 1)
	if err := g.Open(1, p.Serial()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Check(); !errors.Is(err, ErrClosed) {
		t.Fatal("new Open revived dead child")
	}
}

func TestStalledChildCloseAndSoleWriter(t *testing.T) {
	if os.Getenv("PFS_ADMISSION_CHILD") == "1" {
		b := binding(t)
		pid, _ := strconv.ParseInt(os.Getenv("PFS_ADMISSION_PID"), 10, 32)
		start, _ := strconv.ParseUint(os.Getenv("PFS_ADMISSION_START"), 10, 64)
		b.SupervisorPID = int32(pid)
		b.SupervisorStart = start
		r, err := Adopt(os.NewFile(3, "gate"), os.NewFile(4, "owner"), b, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Retire()
		var pipe unix.Stat_t
		if err := unix.Fstat(int(r.owner.Fd()), &pipe); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			fd, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			var st unix.Stat_t
			if unix.Fstat(fd, &st) != nil || st.Ino != pipe.Ino || st.Dev != pipe.Dev {
				continue
			}
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
			if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
				t.Fatal("child inherited a lifetime writer")
			}
		}
		fmt.Println("ready")
		var b1 [1]byte
		if _, err := os.Stdin.Read(b1[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Check(); !errors.Is(err, ErrClosed) {
			t.Fatal("stalled child missed Close")
		}
		select {
		case <-r.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("a helper retained the writer")
		}
		fmt.Println("closed")
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("root supervisor required")
	}
	b := binding(t)
	g, err := New(b)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Dispose()
	p := prepared(t, g, 1)
	if err := g.Open(1, p.Serial()); err != nil {
		t.Fatal(err)
	}
	files, err := g.ChildFiles()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStalledChildCloseAndSoleWriter$")
	cmd.Env = append(os.Environ(), "PFS_ADMISSION_CHILD=1", fmt.Sprintf("PFS_ADMISSION_PID=%d", b.SupervisorPID), fmt.Sprintf("PFS_ADMISSION_START=%d", b.SupervisorStart))
	cmd.ExtraFiles = files[:]
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	in, err := cmd.StdinPipe()
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
	lines := bufio.NewScanner(out)
	if !lines.Scan() || lines.Text() != "ready" {
		t.Fatal("child failed before stop")
	}
	if err := cmd.Process.Signal(unix.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	var status unix.WaitStatus
	if _, err := unix.Wait4(cmd.Process.Pid, &status, unix.WUNTRACED, nil); err != nil || !status.Stopped() {
		t.Fatal(status, err)
	}
	// This executes while the child cannot execute any instruction or handler.
	serial := g.Close(1)
	if serial != 1 {
		t.Fatal(serial)
	}
	if err := g.writer.Close(); err != nil {
		t.Fatal(err)
	}
	g.writer = nil
	if _, err := in.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(unix.SIGCONT); err != nil {
		t.Fatal(err)
	}
	if !lines.Scan() || lines.Text() != "closed" {
		t.Fatal("stopped child retained permission/owner")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestCloseSerialExhaustionAndGenerationFloor(t *testing.T) {
	g, r := gate(t)
	g.Close(9)
	if _, err := g.Recovery(8); !errors.Is(err, ErrClosed) {
		t.Fatal("generation floor regressed")
	}
	g.word.Store((^uint64(0)>>1-1)<<1 | 1)
	serial := g.Close(9)
	if serial != ^uint64(0)>>1 {
		t.Fatal("serial wrapped", serial)
	}
	if _, err := g.Recovery(9); !errors.Is(err, ErrClosed) {
		t.Fatal("exhausted gate prepared")
	}
	if _, err := r.Check(); !errors.Is(err, ErrClosed) {
		t.Fatal("exhausted gate served")
	}
	if _, err := r.Recovery(9, serial); !errors.Is(err, ErrClosed) {
		t.Fatal("exhausted reader retained recovery permission")
	}

	if next := g.Close(9); next != serial {
		t.Fatal("exhausted serial wrapped")
	}
}

func TestRetireInterruptsOwnerReadWhileSupervisorLives(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root supervisor required")
	}
	b := binding(t)
	g, err := New(b)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Dispose()
	files, err := g.ChildFiles()
	if err != nil {
		t.Fatal(err)
	}
	// Model the inherited blocking description that os.NewFile sees after exec.
	fd, err := unix.Dup(int(files[1].Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = files[1].Close()
	if err := unix.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}
	r, err := Adopt(files[0], os.NewFile(uintptr(fd), "inherited-owner"), b, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Retire() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("retirement waited for the live supervisor writer")
	}
}
