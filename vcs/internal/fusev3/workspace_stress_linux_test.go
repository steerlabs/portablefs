//go:build linux

package fusev3

import (
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
)

func reviewArenaFree(r *rawFileSystem) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for p := r.cachedReplyFree; p != nil; p = p.cachedNext {
		n++
	}
	return n
}

// Close/Recovery/Prepared/Open churn against concurrent cached, slow, data and
// barrier callbacks; each tracked reply follows go-fuse's physical lifecycle.
func TestReviewGateChurnStress(t *testing.T) {
	for _, mode := range []string{"ordinary", "ordinary-churn-resubscribe", "single-close", "churn-resubscribe"} {
		gated := mode == "single-close" || mode == "churn-resubscribe"
		t.Run(mode, func(t *testing.T) {
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "cached")
			f.lookup(t, 1, "missing-name-negative")
			var g *workspaceadmission.Supervisor
			if gated {
				g = bindWorkspaceTestGate(t, f.mount)
			}
			opened := openDelegatedWriter(t, f, entry.NodeId)
			writeDelegated(t, f, entry.NodeId, opened.Fh, 0, []byte("seed"))
			node := entry.NodeId
			var unique atomic.Uint64
			unique.Store(1 << 41)
			stop := make(chan struct{})
			var stats [8]atomic.Int64
			reply := func(u uint64, opcode uint32, size int) bool {
				if f.raw.ReplyWriteTracked(u) {
					_, status, _ := f.raw.PrepareReplyPayload(u, node, opcode, nil, nil, size)
					f.raw.ReplyWritten(u, fuse.OK)
					return status == fuse.OK
				}
				return false
			}
			ops := []func() fuse.Status{
				func() fuse.Status {
					u := unique.Add(2)
					var out fuse.AttrOut
					st := f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: u, NodeId: node}}, &out)
					reply(u, 3, 0)
					return st
				},
				func() fuse.Status {
					u := unique.Add(2)
					var out fuse.EntryOut
					st := f.raw.Lookup(nil, &fuse.InHeader{Unique: u, NodeId: 1}, "cached", &out)
					delivered := reply(u, 1, 0)
					// A refused physical LOOKUP owns its rollback; the kernel never
					// acquires that reference and therefore cannot FORGET it again.
					if delivered && st == fuse.OK && out.NodeId != 0 {
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
						n := len(ops)
						if strings.Contains(mode, "churn") {
							n = 3 // namespace/metadata only; delegated churn trips the fake's release model
						}
						if ops[(w+i)%n]() == fuse.OK {
							stats[0].Add(1)
						} else {
							stats[1].Add(1)
						}
					}
				}(w)
			}
			churns, firstRevoke := 0, 0
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if mode == "churn-resubscribe" {
					g.Close(1)
					time.Sleep(200 * time.Microsecond)
					p, err := g.Recovery(1)
					if err != nil {
						t.Fatal(err)
					}
					child, err := f.mount.workspace.Recovery(1, p.Serial())
					if err != nil {
						t.Fatal(err)
					}
					if err := f.mount.subscription.subscribe(context.WithValue(t.Context(), workspaceRecoveryKey{}, child)); err != nil {
						t.Fatal("cold resubscribe", err)
					}
					if err := g.Prepared(p); err != nil {
						t.Fatal(err)
					}
					if err := g.Open(1, p.Serial()); err != nil {
						t.Fatal(err)
					}
					churns++
				}
				if mode == "ordinary-churn-resubscribe" {
					if err := f.mount.subscription.subscribe(t.Context()); err != nil {
						t.Fatal("cold resubscribe", err)
					}
					churns++
				}
				if f.mount.isRevoked() {
					firstRevoke = churns
					break
				}
				time.Sleep(2 * time.Millisecond)
			}
			t.Logf("first revocation observed after churn %d", firstRevoke)
			if gated {
				g.Close(1)
				cut := f.raw.captureWorkspaceReplies()
				close(stop)
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				if err := cut.wait(ctx); err != nil {
					t.Errorf("fixed cohort did not join: %v", err)
				}
			} else {
				close(stop)
			}
			finished := make(chan struct{})
			go func() { wg.Wait(); close(finished) }()
			select {
			case <-finished:
			case <-time.After(20 * time.Second):
				buf := make([]byte, 1<<20)
				n := runtimeStack(buf)
				os.Stderr.Write(buf[:n])
				t.Fatal("workers deadlocked")
			}
			f.raw.mu.RLock()
			left := len(f.raw.replyPublications)
			f.raw.mu.RUnlock()
			fatal := ""
			if err := f.mount.fatalError(); err != nil {
				fatal = err.Error()
				if len(fatal) > 300 {
					fatal = fatal[:300]
				}
			}
			t.Logf("gated=%v churns=%d ok=%d refused=%d leftover-publications=%d arena-free=%d revoked=%v fatal=%s",
				gated, churns, stats[0].Load(), stats[1].Load(), left, reviewArenaFree(f.raw), f.mount.isRevoked(), fatal)
			if left != 0 || reviewArenaFree(f.raw) != len(f.raw.cachedReplyArena) || f.mount.isRevoked() {
				t.Errorf("leaked publication/arena owner or revoked mount")
			}
		})
	}
}
