//go:build linux

package mountcontrol

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestR4BootstrapConcurrentHandoffObserveFinalize(t *testing.T) {
	var lateCopies atomic.Int32
	for i := 0; i < 300; i++ {
		base := r4FDCount(t)
		var b Bootstrap
		if err := b.Begin(*phase()); err != nil {
			t.Fatal(err)
		}
		if err := b.Finish(r4Pipe(), witness()); err != nil {
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
		if n := r4FDCount(t); n != base {
			t.Fatalf("iteration %d: fd count %d != base %d", i, n, base)
		}
	}
	t.Logf("R4-13 handoff copies produced after Finalize returned: %d (copies racing finalization)", lateCopies.Load())
}
