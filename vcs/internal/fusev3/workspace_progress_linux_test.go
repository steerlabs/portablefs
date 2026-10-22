//go:build linux

package fusev3

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// Adapted from zz_review_r2_stall_linux_test.go. Gated, no-churn concurrent workload (the stress "single-close" mode) with a
// progress watchdog: on the first 300ms stall, dump all goroutines once.
func TestReviewR2GatedStall(t *testing.T) {
	gated := os.Getenv("REVIEW_UNGATED") != "1"
	for round := 0; round < 2; round++ {
		f := newStockFixture(t)
		entry := f.lookup(t, 1, "cached")
		f.lookup(t, 1, "missing-name-negative")
		if gated {
			bindWorkspaceTestGate(t, f.mount)
		}
		opened := openDelegatedWriter(t, f, entry.NodeId)
		writeDelegated(t, f, entry.NodeId, opened.Fh, 0, []byte("seed"))
		node := entry.NodeId
		var unique atomic.Uint64
		unique.Store(1 << 41)
		reply := func(u uint64, opcode uint32, size int) bool {
			if f.raw.ReplyWriteTracked(u) {
				_, status, _ := f.raw.PrepareReplyPayload(u, node, opcode, nil, nil, size)
				f.raw.ReplyWritten(u, fuse.OK)
				return status == fuse.OK
			}
			return false
		}
		var lastOp [6]atomic.Int64
		ops := []func() fuse.Status{
			func() fuse.Status {
				u := unique.Add(2)
				var out fuse.AttrOut
				st := testEntryFileSystem(f.raw).GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: u, NodeId: node}}, &out)
				reply(u, 3, 0)
				return st
			},
			func() fuse.Status {
				u := unique.Add(2)
				var out fuse.EntryOut
				st := testEntryFileSystem(f.raw).Lookup(nil, &fuse.InHeader{Unique: u, NodeId: 1}, "cached", &out)
				if reply(u, 1, 0) && st == fuse.OK && out.NodeId != 0 {
					f.raw.Forget(out.NodeId, 1)
				}
				return st
			},
			func() fuse.Status {
				u := unique.Add(2)
				_, st := f.raw.GetXAttr(nil, &fuse.InHeader{Unique: u, NodeId: node}, "user.x", make([]byte, 64))
				reply(u, 22, 0)
				return st
			},
			func() fuse.Status {
				u := unique.Add(2)
				_, st := f.raw.Write(nil, &fuse.WriteIn{InHeader: fuse.InHeader{Unique: u, NodeId: node}, Fh: opened.Fh, Offset: 4, Size: 1, Flags: uint32(syscall.O_RDWR)}, []byte("x"))
				reply(u, 16, 0)
				return st
			},
			func() fuse.Status {
				u := unique.Add(2)
				buf := make([]byte, 8)
				res, st := f.raw.Read(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: u, NodeId: node}, Fh: opened.Fh, Size: 8}, buf)
				n := 0
				if res != nil {
					n = res.Size()
				}
				reply(u, 15, n)
				return st
			},
			func() fuse.Status {
				u := unique.Add(2)
				st := f.raw.Fsync(nil, &fuse.FsyncIn{InHeader: fuse.InHeader{Unique: u, NodeId: node}, Fh: opened.Fh})
				reply(u, 20, 0)
				return st
			},
		}
		var progress atomic.Int64
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for w := 0; w < 16; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					k := (w + i) % len(ops)
					ops[k]()
					lastOp[k].Add(1)
					progress.Add(1)
				}
			}(w)
		}
		dumped := false
		last, lastChange := progress.Load(), time.Now()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
			if p := progress.Load(); p != last {
				last, lastChange = p, time.Now()
			} else if !dumped && time.Since(lastChange) > 300*time.Millisecond {
				dumped = true
				buf := make([]byte, 16<<20)
				n := runtime.Stack(buf, true)
				t.Logf("round %d: stall after %d ops; revoked=%v\n%s", round, last, f.mount.isRevoked(), buf[:n])
				f.raw.mu.RLock()
				for u, p := range f.raw.replyPublications {
					t.Logf("  pub unique=%d self=%p arena=%v callbackOwned=%v workspaceDone=%v finalized=%v wrote=%v owner=%v cachedCount=%d coords=%v holder=%v holders=%d source=%v names=%d attrs=%d data=%d",
						u, p, p.cachedArena, p.callbackOwned, p.workspaceDone != nil, p.originalFinalized, p.originalWrote, p.responseConsumptionOwner, p.cachedCount, p.cachedCoordinates[:p.cachedCount], p.holderAdmission != nil, len(p.holderAdmissions), p.source != nil, len(p.names), len(p.attrs), len(p.data))
				}
				for c, n := range f.raw.sourcePublishing {
					if n != 0 {
						t.Logf("  sourcePublishing %v = %d", c, n)
					}
				}
				f.raw.mu.RUnlock()
			}
		}
		close(stop)
		wg.Wait()
		fatal := ""
		if err := f.mount.fatalError(); err != nil {
			fatal = err.Error()
			if len(fatal) > 200 {
				fatal = fatal[:200]
			}
		}
		t.Logf("round %d gated=%v ops=%d revoked=%v fatal=%q", round, gated, progress.Load(), f.mount.isRevoked(), fatal)
		if dumped || f.mount.isRevoked() || progress.Load() < 256 {
			t.Fatal("managed workload stalled, revoked, or collapsed in throughput")
		}
	}
}
