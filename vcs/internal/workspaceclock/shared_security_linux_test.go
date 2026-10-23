//go:build linux

package workspaceclock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testBootTime() time.Duration {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)
}

func sharedOwner(t *testing.T) *Owner {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root")
	}
	o := New(&backend{rtc: time.Now().UTC().Truncate(time.Second), wall: time.Now(), elapsed: testBootTime()}, nil)
	if err := o.share(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Close() })
	return o
}

// Torn-read falsifier: state B (gen 2, ready, bad interval) and state C
// (gen 2, not ready, good interval) never authorize generation 2. Only a torn
// read mixing generation/readiness with another state's interval could.
func TestSharedClockSeqlockCannotMixAuthorization(t *testing.T) {
	o := sharedOwner(t)
	f, binding, err := o.ChildFile()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	readers := make([]*Reader, 8)
	for i := range readers {
		dup, err := unix.Dup(int(f.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		if readers[i], err = OpenReader(os.NewFile(uintptr(dup), "r"), binding); err != nil {
			t.Fatal(err)
		}
		defer readers[i].Close()
	}
	var stop atomic.Bool
	var torn, oneOK atomic.Int64
	var wg sync.WaitGroup
	for _, r := range readers {
		wg.Add(1)
		go func(r *Reader) {
			defer wg.Done()
			for !stop.Load() {
				if r.Check(2) == nil {
					torn.Add(1)
				}
				if r.Check(1) == nil {
					oneOK.Add(1)
				}
			}
		}(r)
	}
	deadline := time.Now().Add(5 * time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		now := time.Now()
		o.mu.Lock()
		o.active, o.closed = true, false
		o.measured = testBootTime()
		switch i % 3 {
		case 0: // A
			o.generation, o.ready = 1, true
			o.low, o.high = now.Add(-1500*time.Millisecond), now.Add(1500*time.Millisecond)
		case 1: // B
			o.generation, o.ready = 2, true
			o.low, o.high = now.Add(time.Hour), now.Add(time.Hour+time.Second)
		case 2: // C
			o.generation, o.ready = 2, false
			o.low, o.high = now.Add(-1500*time.Millisecond), now.Add(1500*time.Millisecond)
		}
		o.signalLocked()
		o.mu.Unlock()
	}
	stop.Store(true)
	wg.Wait()
	if torn.Load() != 0 {
		t.Fatalf("torn read authorized generation 2 %d times", torn.Load())
	}
	t.Logf("gen-1 authorizations observed: %d", oneOK.Load())
}

func TestSharedClockChildCannotForgePage(t *testing.T) {
	o := sharedOwner(t)
	if err := o.Begin(0); err != nil {
		t.Fatal(err)
	}
	f, binding, err := o.ChildFile()
	if err != nil {
		t.Fatal(err)
	}
	// Root child: DAC override lets it reopen read-write; seals must still hold.
	rw, err := unix.Open("/proc/self/fd/"+strconv.Itoa(int(f.Fd())), unix.O_RDWR, 0)
	if err == nil {
		defer unix.Close(rw)
		if _, e := unix.Pwrite(rw, []byte{1}, 128+8*5); e == nil {
			t.Fatal("root reopen wrote readiness word")
		}
		if m, e := unix.Mmap(rw, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED); e == nil {
			unix.Munmap(m)
			t.Fatal("root reopen mapped page writable")
		}
		if e := unix.Fallocate(rw, unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, 0, int64(os.Getpagesize())); e == nil {
			t.Fatal("root reopen punched the page")
		}
		if e := unix.Ftruncate(rw, 0); e == nil {
			t.Fatal("root reopen truncated")
		}
	} else {
		t.Logf("root reopen O_RDWR refused: %v", err)
	}
	m, err := unix.Mmap(int(f.Fd()), 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	if e := unix.Mprotect(m, unix.PROT_READ|unix.PROT_WRITE); e == nil {
		t.Fatal("mprotect upgraded read-only shared mapping")
	}
	unix.Munmap(m)
	// Unprivileged child (UID 1000) with the inherited descriptor.
	// Go's build directory is private. Give the child a traversable copy so
	// the descriptor seals, rather than an unrelated directory mode, decide.
	dir, err := os.MkdirTemp("", "workspace-clock-child-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "clock.test")
	if err := os.WriteFile(child, binary, 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(child, "-test.run=^TestSharedClockUnprivilegedHelper$")
	cmd.Env = append(os.Environ(), "PFS_CLOCK_TEST_HELPER=1")
	cmd.ExtraFiles = []*os.File{f}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unprivileged helper: %v\n%s", err, out)
	}
	t.Logf("%s", out)
	r, err := OpenReader(f, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !errors.Is(r.Check(0), ErrUnavailable) {
		t.Fatal("page forged ready")
	}
}

func TestSharedClockUnprivilegedHelper(t *testing.T) {
	if os.Getenv("PFS_CLOCK_TEST_HELPER") != "1" {
		t.Skip("helper")
	}
	if _, err := unix.Open("/proc/self/fd/3", unix.O_RDWR, 0); err == nil {
		t.Fatal("UID 1000 reopened clock read-write")
	}
	if m, err := unix.Mmap(3, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED); err == nil {
		unix.Munmap(m)
		t.Fatal("UID 1000 writable mapping")
	}
	m, err := unix.Mmap(3, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
	if err == nil {
		m[128+8*5] = 1 // private COW only
		unix.Munmap(m)
	}
}

func TestSharedClockClosedOwnerAndIdempotentReaderClose(t *testing.T) {
	o := sharedOwner(t)
	o.Begin(0)
	if _, err := o.Measure(); err != nil {
		t.Fatal(err)
	}
	f, binding, _ := o.ChildFile()
	r, err := OpenReader(f, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Check(0); err != nil {
		t.Fatal(err)
	}
	o.Close()
	if r.Check(0) == nil {
		t.Fatal("closed owner page still ready")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}
