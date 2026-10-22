//go:build linux

package mountcontrol

import (
	"errors"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

// Count the exact pipe, including every duplicated description, rather than
// runtime/test-harness descriptors that may open independently of this test.
func bootstrapPipeFDCount(t *testing.T, pipe unix.Stat_t) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); errors.Is(err, unix.EBADF) {
			continue // The directory reader or an unrelated owner has closed it.
		} else if err != nil {
			t.Fatal(err)
		}
		if stat.Dev == pipe.Dev && stat.Ino == pipe.Ino {
			count++
		}
	}
	return count
}

func TestBootstrapPipeFDAccountingDetectsRetainedCopy(t *testing.T) {
	rights := r4Pipe()
	defer rights.Close()
	var pipe unix.Stat_t
	if err := unix.Fstat(rights.FDs[0], &pipe); err != nil {
		t.Fatal(err)
	}
	copy, err := unix.FcntlInt(uintptr(rights.FDs[0]), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(copy)
	unrelated := r4Pipe()
	defer unrelated.Close()
	rights.Close()
	if n := bootstrapPipeFDCount(t, pipe); n != 1 {
		t.Fatalf("retained handoff copy count %d != 1", n)
	}
}

func TestR4BootstrapConcurrentHandoffObserveFinalize(t *testing.T) {
	var lateCopies atomic.Int32
	for i := 0; i < 300; i++ {
		rights := r4Pipe()
		var pipe unix.Stat_t
		if err := unix.Fstat(rights.FDs[0], &pipe); err != nil {
			rights.Close()
			t.Fatal(err)
		}
		if n := bootstrapPipeFDCount(t, pipe); n != 2 {
			t.Fatalf("iteration %d: initial pipe fd count %d != 2", i, n)
		}
		var b Bootstrap
		if err := b.Begin(*phase()); err != nil {
			t.Fatal(err)
		}
		if err := b.Finish(rights, witness()); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var finalized atomic.Bool
		for g := 0; g < 3; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < 5; k++ {
					if c, err := b.Handoff(); err == nil {
						if finalized.Load() {
							lateCopies.Add(1)
						}
						c.Close()
					}
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.ObserveInstall(ActionStatus{Progress: "running", Action: kernelAction(*phase())}, witness())
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := ActionStatus{Progress: "offered", Action: kernelAction(Phase{ActionID: "2", Mode: "voluntary", Reason: "cleanup"})}
			if b.BeginRemoval(s, witness()) == nil {
				b.FinishRemoval("voluntary", Removal{KernelAbsent: true}, nil)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b.Finalize(absentBootstrap(&b)) != nil {
			}
			finalized.Store(true)
		}()
		wg.Wait()
		// Join all handoffs, the observer (which closes the root copy outside
		// its lock), removal and finalization before asserting exact absence.
		if n := bootstrapPipeFDCount(t, pipe); n != 0 {
			t.Fatalf("iteration %d: leaked %d pipe descriptors", i, n)
		}
	}
	t.Logf("R4-13 handoff copies produced after Finalize returned: %d (copies racing finalization)", lateCopies.Load())
}
