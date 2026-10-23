//go:build linux

package fusev3

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// R3 stress: concurrent delegated writers and namespace churn across many
// Suspend/Recover cycles with mixed drain budgets (including ones too short to
// drain). Invariants: no fsync-acknowledged write is ever lost; any lost
// close-acknowledged write is visible through the pre-existing root barrier;
// no revocation or session end; bounded transitions; fd/goroutine stability.
func opusR3StressChild(t *testing.T) {
	reader, proof, mounted := opusAdopt(t)
	defer reader.Retire()
	var off atomic.Int64
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: &workspaceTestClockOwner{}, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, workspaceClock: replaySubscriptionClock{&off}})
	c := &opusChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	opusPollHack(t, f.mountPath(0))
	const writers = 6
	for i := 0; i < writers; i++ {
		c.write(f.join(0, fmt.Sprintf("s%d", i)), fmt.Sprintf("%08d", 0), 0644)
	}
	if err := os.Mkdir(f.join(0, "ns"), 0755); err != nil {
		t.Fatal(err)
	}
	countFDs := func() int { e, _ := os.ReadDir("/proc/self/fd"); return len(e) }
	runtime.GC()
	fd0, gr0 := countFDs(), runtime.NumGoroutine()
	root, err := os.Open(f.mountPath(0))
	if err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var wg sync.WaitGroup
	lastFsync := make([]atomic.Int64, writers)
	lastClose := make([]atomic.Int64, writers)
	var fsyncEIO, closeEIO, writeErr, otherErr, nsOps, nsErr atomic.Int64
	seed := time.Now().UnixNano()
	fmt.Printf("R3S seed=%d\n", seed)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			path := f.join(0, fmt.Sprintf("s%d", w))
			for i := int64(1); !stop.Load(); i++ {
				file, err := os.OpenFile(path, os.O_RDWR, 0)
				if err != nil {
					otherErr.Add(1)
					time.Sleep(5 * time.Millisecond)
					continue
				}
				if _, err := unix.Pwrite(int(file.Fd()), []byte(fmt.Sprintf("%08d", i)), 0); err != nil {
					writeErr.Add(1)
					_ = file.Close()
					continue
				}
				if i%2 == 0 {
					if err := file.Sync(); err == nil {
						lastFsync[w].Store(i)
					} else if errors.Is(err, syscall.EIO) {
						fsyncEIO.Add(1)
					} else {
						otherErr.Add(1)
					}
				}
				if err := file.Close(); err == nil {
					lastClose[w].Store(i)
				} else if errors.Is(err, syscall.EIO) {
					closeEIO.Add(1)
				} else {
					otherErr.Add(1)
				}
				time.Sleep(time.Millisecond)
			}
		}(w)
	}
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; !stop.Load(); i++ {
				a := f.join(0, filepath.Join("ns", fmt.Sprintf("t%d-%d", g, i%7)))
				b := a + ".r"
				err := os.WriteFile(a, []byte("x"), 0644)
				if err == nil {
					err = os.Rename(a, b)
				}
				if err == nil {
					_, err = os.ReadDir(f.join(0, "ns"))
				}
				if err == nil && i%3 == 0 {
					err = os.Remove(b)
				}
				nsOps.Add(1)
				if err != nil {
					nsErr.Add(1)
				}
				time.Sleep(2 * time.Millisecond)
			}
		}(g)
	}
	rng := rand.New(rand.NewSource(seed))
	budgets := []time.Duration{20 * time.Millisecond, 300 * time.Millisecond, 8 * time.Second}
	if os.Getenv("OPUS_R3_BUDGETS") == "elapsed" {
		budgets = []time.Duration{-time.Millisecond, -time.Millisecond, 2 * time.Millisecond, 8 * time.Second}
	}
	var maxSuspend, maxRecover time.Duration
	lostCycles := 0
	for cycle := 0; cycle < 25; cycle++ {
		time.Sleep(time.Duration(100+rng.Intn(400)) * time.Millisecond)
		serial, _ := strconv.ParseUint(c.req("close"), 10, 64)
		budget := budgets[rng.Intn(len(budgets))]
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		begin := time.Now()
		o, err := c.m.SuspendWorkspace(ctx, 1, serial, c.now().Add(budget))
		cancel()
		d := time.Since(begin)
		maxSuspend = max(maxSuspend, d)
		durability := ""
		if o.Outcome != nil {
			durability = o.Outcome.Durability
		}
		if durability == "lost" {
			lostCycles++
		}
		fmt.Printf("R3S cycle %d budget=%v suspend=%v cold=%v result=%v err=%v durability=%s loss=%d\n", cycle, budget, d.Round(time.Millisecond), o.ColdComplete, o.Result.Disposition, err, durability, len(o.Loss))
		if !o.ColdComplete {
			// A refused cut must still be reconcilable by Recover (B1).
			fmt.Printf("R3S cycle %d: Suspend not cold; reconciling through Recover\n", cycle)
		}
		time.Sleep(time.Duration(rng.Intn(300)) * time.Millisecond)
		ctx, cancel = context.WithTimeout(t.Context(), 60*time.Second)
		begin = time.Now()
		r, rerr := c.m.RecoverWorkspace(ctx, 1, serial)
		cancel()
		d = time.Since(begin)
		maxRecover = max(maxRecover, d)
		if rerr != nil || !r.Prepared {
			c.fail("cycle %d: Recover prepared=%v err=%v after %v", cycle, r.Prepared, rerr, d)
			break
		}
		if res := c.req("open"); res != "<nil>" {
			c.fail("cycle %d: open %s", cycle, res)
			break
		}
		if c.m.isRevoked() || c.m.rpc.SessionEndCause() != nil {
			c.fail("cycle %d: revoked=%v session=%v", cycle, c.m.isRevoked(), c.m.rpc.SessionEndCause())
			break
		}
	}
	stop.Store(true)
	wg.Wait()
	time.Sleep(time.Second)
	// Quiesce: one full cut and recovery with a generous budget.
	serial, _ := strconv.ParseUint(c.req("close"), 10, 64)
	o, err := c.m.SuspendWorkspace(t.Context(), 1, serial, c.now().Add(8*time.Second))
	fmt.Printf("R3S final Suspend cold=%v err=%v outcome=%v\n", o.ColdComplete, err, o.Outcome)
	c.recover(serial)
	silent, closeLost := 0, 0
	for w := 0; w < writers; w++ {
		data, err := os.ReadFile(filepath.Join(f.volumeRoot, fmt.Sprintf("s%d", w)))
		v, perr := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		fmt.Printf("R3S s%d authority=%q lastFsync=%d lastClose=%d\n", w, data, lastFsync[w].Load(), lastClose[w].Load())
		if err != nil || perr != nil {
			c.fail("s%d unreadable: %v %v", w, err, perr)
			continue
		}
		if v < lastFsync[w].Load() {
			silent++
			c.fail("FSYNC-ACKED LOSS: s%d authority=%d < last fsync-acked %d", w, v, lastFsync[w].Load())
		}
		if v < lastClose[w].Load() {
			closeLost++
		}
	}
	rootErr := root.Sync()
	_ = root.Close()
	fmt.Printf("R3S lostCycles=%d closeLost=%d rootBarrier=%v fsyncEIO=%d closeEIO=%d writeErr=%d otherErr=%d nsOps=%d nsErr=%d maxSuspend=%v maxRecover=%v loss=%d\n", lostCycles, closeLost, rootErr, fsyncEIO.Load(), closeEIO.Load(), writeErr.Load(), otherErr.Load(), nsOps.Load(), nsErr.Load(), maxSuspend.Round(time.Millisecond), maxRecover.Round(time.Millisecond), c.m.delegations.LossSequence())
	if closeLost > 0 && !errors.Is(rootErr, syscall.EIO) {
		c.fail("close-acknowledged loss (%d files) invisible to the pre-existing root barrier: %v", closeLost, rootErr)
	}
	if c.m.delegations.LossSequence() == 0 && rootErr != nil {
		c.fail("root barrier failed without any recorded loss: %v", rootErr)
	}
	if c.m.isRevoked() || c.m.rpc.SessionEndCause() != nil || c.m.fatalError() != nil {
		c.fail("terminal: revoked=%v session=%v fatal=%v", c.m.isRevoked(), c.m.rpc.SessionEndCause(), c.m.fatalError())
	}
	time.Sleep(2 * time.Second)
	runtime.GC()
	fd1, gr1 := countFDs(), runtime.NumGoroutine()
	fmt.Printf("R3S fds %d -> %d goroutines %d -> %d\n", fd0, fd1, gr0, gr1)
	if fd1 > fd0+4 {
		c.fail("fd growth %d -> %d", fd0, fd1)
	}
	if gr1 > gr0+30 {
		c.fail("goroutine growth %d -> %d", gr0, gr1)
	}
	_ = silent
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

func TestOpusR3KernelStressIntegrity(t *testing.T) {
	opusKernelParent(t, opusR3StressChild)
}
