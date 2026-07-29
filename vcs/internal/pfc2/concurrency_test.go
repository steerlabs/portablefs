package pfc2

import (
	"sync"
	"testing"
)

// TestConcurrentReadersDuringApply exercises the state lock discipline under
// the race detector: one writer applies a full workload while readers hammer
// every query surface, including whole projections.
func TestConcurrentReadersDuringApply(t *testing.T) {
	d := newDriver(1234)
	// Pre-populate so readers see real state immediately.
	for i := 0; i < 200; i++ {
		d.step(t)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for reader := 0; reader < 4; reader++ {
		wg.Add(1)
		go func(r int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				switch i % 6 {
				case 0:
					d.st.CheckExact(key("pfs-0", 1, 0, 1, byte(r)))
				case 1:
					d.st.HeldLocks(uint64(1 + i%4))
					d.st.LockConflict(1, LockOwner{Session: ref("pfs-0", 1)}, 0, 10, true)
				case 2:
					d.st.CheckoutAt("dir0/leaf0")
					d.st.OverlappingCheckouts("dir1/leaf1")
					d.st.NextCheckoutEpoch()
				case 3:
					d.st.PinHolders(uint64(1 + i%6))
					d.st.StreamState("wbpfs-1")
					d.st.StreamCheckouts("wbpfs-1")
					d.st.DbTimeFloorMs()
				case 4:
					d.st.Counts()
					d.st.Session("pfs-2")
				case 5:
					if p := d.st.Project(); p != nil {
						if _, err := p.Digest(); err != nil {
							t.Errorf("reader digest: %v", err)
							return
						}
					}
				}
			}
		}(reader)
	}

	for i := 0; i < 600; i++ {
		d.step(t)
	}
	close(stop)
	wg.Wait()

	// The workload replays identically after the concurrent reads.
	replayed := NewState()
	for i, enc := range d.log {
		rec, err := Decode(enc)
		if err != nil {
			t.Fatalf("decode %d: %v", i, err)
		}
		if _, err := replayed.Apply(&rec); err != nil {
			t.Fatalf("replay %d: %v", i, err)
		}
	}
	if stateDigest(t, replayed) != stateDigest(t, d.st) {
		t.Fatal("replay diverged after concurrent reads")
	}
}

// TestParallelReplayDeterminism replays one journal into many states on
// separate goroutines; every result must be byte-identical regardless of
// scheduling.
func TestParallelReplayDeterminism(t *testing.T) {
	d := newDriver(555)
	for i := 0; i < 700; i++ {
		d.step(t)
	}
	want := stateDigest(t, d.st)

	var wg sync.WaitGroup
	digests := make([][32]byte, 8)
	errs := make([]error, 8)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			st := NewState()
			for _, enc := range d.log {
				rec, err := Decode(enc)
				if err != nil {
					errs[w] = err
					return
				}
				if _, err := st.Apply(&rec); err != nil {
					errs[w] = err
					return
				}
			}
			p := st.Project()
			digests[w], errs[w] = p.Digest()
		}(w)
	}
	wg.Wait()
	for w := 0; w < 8; w++ {
		if errs[w] != nil {
			t.Fatalf("worker %d: %v", w, errs[w])
		}
		if digests[w] != want {
			t.Fatalf("worker %d diverged", w)
		}
	}
}
