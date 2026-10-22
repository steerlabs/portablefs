//go:build linux

package fusev3

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
)

func reviewR2ColdRecovery(t *testing.T, f *stockFixture, g *workspaceadmission.Supervisor) <-chan error {
	done := make(chan error, 1)
	go func() {
		p, err := g.Recovery(1)
		if err != nil {
			done <- err
			return
		}
		child, err := f.mount.workspace.Recovery(1, p.Serial())
		if err != nil {
			done <- err
			return
		}
		done <- f.mount.subscription.subscribe(context.WithValue(t.Context(), workspaceRecoveryKey{}, child))
	}()
	return done
}

// Imported from zz_review_r2_reset_linux_test.go. R2-B: an FSYNC admitted under the open word that is inside its flush (parked
// in the authority WRITE or FSYNC RPC) when Close lands and the lifecycle then
// starts a cold recovery reset. The reset must not drop the accepted cut out
// from under the FSYNC, and FSYNC may report success only if the cut reached
// the authority and was persisted.
func TestReviewR2AdmittedFsyncCloseThenColdReset(t *testing.T) {
	for _, park := range []string{"flush-write", "authority-fsync"} {
		t.Run(park, func(t *testing.T) {
			f := newStockFixture(t)
			entry := f.lookup(t, 1, "cached")
			g := bindWorkspaceTestGate(t, f.mount)
			opened := openDelegatedWriter(t, f, entry.NodeId)
			writeDelegated(t, f, entry.NodeId, opened.Fh, 0, []byte("dirty"))
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			installAuthorityHook(f, func(req *authoritypb.Request) {
				if park == "flush-write" && req.GetWrite() != nil || park == "authority-fsync" && req.GetFsync() != nil {
					once.Do(func() { close(entered); <-release })
				}
			})
			u := f.unique.Add(2)
			done := make(chan fuse.Status, 1)
			go func() {
				done <- f.raw.Fsync(nil, &fuse.FsyncIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}, Fh: opened.Fh})
			}()
			<-entered
			g.Close(1)
			reset := reviewR2ColdRecovery(t, f, g)
			resetBeforeRelease := false
			select {
			case err := <-reset:
				resetBeforeRelease = true
				t.Logf("cold reset finished while FSYNC parked: %v", err)
				reset = nil
			case <-time.After(300 * time.Millisecond):
			}
			close(release)
			status := <-done
			if f.raw.ReplyWriteTracked(u) {
				f.raw.PrepareReplyPayload(u, entry.NodeId, 20, nil, nil, 0)
				f.raw.ReplyWritten(u, fuse.OK)
			}
			var resetErr error
			if reset != nil {
				resetErr = <-reset
			}
			writes, fsyncs := 0, 0
			f.rpc.snapshot(func(rpc *fakeRPC) { writes, fsyncs = len(rpc.writes), len(rpc.fsyncs) })
			after := f.rawCall(func(u uint64) fuse.Status {
				return f.raw.Fsync(nil, &fuse.FsyncIn{InHeader: fuse.InHeader{Unique: u, NodeId: entry.NodeId}, Fh: opened.Fh})
			})
			t.Logf("FSYNC=%v resetBeforeRelease=%v resetErr=%v authorityWrites=%d authorityFsyncs=%d loss=%d bufferEntries=%d revoked=%v postResetFSYNC=%v",
				status, resetBeforeRelease, resetErr, writes, fsyncs, f.mount.delegations.LossSequence(), f.mount.delegations.buf.Stats().Entries, f.mount.isRevoked(), after)
			if resetBeforeRelease {
				t.Error("cold reset did not wait for the admitted FSYNC callback")
			}
			if status != fuse.OK || writes != 1 || fsyncs != 1 || resetErr != nil || after != fuse.EIO {
				t.Error("BUG: FSYNC succeeded without a persisted authority cut")
			}
			if f.mount.isRevoked() {
				t.Error("revoked")
			}
		})
	}
}
