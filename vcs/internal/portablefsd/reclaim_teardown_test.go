package portablefsd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func newReclaimTestAttach(t *testing.T) *attach {
	t.Helper()
	return newAttach(testFSKitAttachRef, "reclaim-teardown", ensureAttachRequest{
		AttachRef:          testFSKitAttachRef,
		VolumeID:           "vol-reclaim-teardown",
		Branch:             "main",
		MountPath:          "/Volumes/PortableFSReclaimTest",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
	}, privateTestDir(t))
}

// The kernel detach (unmount(2)) reclaims every cached vnode through the
// frontend while the detach callback is still running. The detach must not
// hold the frontend admission freeze across that callback, or the daemon
// deadlocks against its own kernel unmount.
func TestDetachFinalizerAdmitsKernelReclaim(t *testing.T) {
	a := newReclaimTestAttach(t)
	reclaimed := make(chan int32, 1)
	_, err := a.detachWithFinalizer(func() error {
		go func() {
			unlock := a.lockFrontendRequest(&pfslocal.ReclaimRequest{})
			defer unlock()
			reclaimed <- a.reclaim(&pfslocal.ReclaimRequest{
				Item: pfslocal.Item{ItemID: 42, ItemGeneration: 1},
			})
		}()
		select {
		case eno := <-reclaimed:
			if eno != 0 {
				return errors.New("kernel reclaim refused during detach")
			}
			return nil
		case <-time.After(10 * time.Second):
			return errors.New("kernel reclaim starved by the detach admission freeze")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	a.mu.RLock()
	detached := a.detached
	a.mu.RUnlock()
	if !detached {
		t.Fatal("detach did not publish terminal state")
	}
}

// forceUnmountFSKit shares the same reentrancy contract: the exact kernel
// detach callback must be able to reclaim through the frontend.
func TestForceUnmountAdmitsKernelReclaim(t *testing.T) {
	stateDir := privateTestDir(t)
	req := ensureAttachRequest{
		AttachRef:          testFSKitAttachRef,
		VolumeID:           "vol-fskit-unmount",
		Branch:             "main",
		MountPath:          "/Volumes/PortableFSUnmountTest",
		AuthorityURL:       serveAuthority(t),
		DataPlaneTransport: "plaintext",
	}
	seed := newAttach(testFSKitAttachRef, attachKey(req.VolumeID, req.Branch, req.MountPath), req, stateDir)
	if err := seed.activate(context.Background(), "", 0); err != nil {
		t.Fatal(err)
	}
	seed.mu.RLock()
	vol := seed.vol
	seed.mu.RUnlock()
	vol.Writeback().Abandon()
	if err := vol.Close(); err != nil {
		t.Fatal(err)
	}
	seed.mu.Lock()
	seed.vol = nil
	seed.detachForce = true
	seed.credentialPending = true
	seed.mu.Unlock()
	if err := writePersistedAttaches(stateDir, []persistedAttachEntry{seed.persistedEntry()}); err != nil {
		t.Fatal(err)
	}
	r := newRegistry(stateDir)
	t.Cleanup(r.stopPersister)
	a := r.get(testFSKitAttachRef)
	if a == nil {
		t.Fatal("fixture attach missing")
	}
	reclaimed := make(chan int32, 1)
	found, _, err := r.unmountFSKitWith(testFSKitAttachRef, false, fskitKernelOps{
		present: func(string, string) (bool, error) { return true, nil },
		unmountExact: func(string, string, bool) error {
			go func() {
				unlock := a.lockFrontendRequest(&pfslocal.ReclaimRequest{})
				defer unlock()
				reclaimed <- a.reclaim(&pfslocal.ReclaimRequest{
					Item: pfslocal.Item{ItemID: 7, ItemGeneration: 1},
				})
			}()
			select {
			case eno := <-reclaimed:
				if eno != 0 {
					return errors.New("kernel reclaim refused during exact detach")
				}
				return nil
			case <-time.After(10 * time.Second):
				return errors.New("kernel reclaim starved by the detach admission freeze")
			}
		},
	})
	if err != nil || !found {
		t.Fatalf("unmount=(%v,%v)", found, err)
	}
}

// Reclaim is teardown, not new work: the prepared-detach quarantine must not
// refuse it, and a reclaim after full detach is an idempotent no-op.
func TestReclaimAdmittedDuringPreparedDetach(t *testing.T) {
	a := newReclaimTestAttach(t)
	a.mu.Lock()
	a.detachPrepared = true
	a.mu.Unlock()
	if eno := a.reclaim(&pfslocal.ReclaimRequest{
		Item: pfslocal.Item{ItemID: 9, ItemGeneration: 1},
	}); eno != 0 {
		t.Fatalf("prepared-detach reclaim refused: eno=%d", eno)
	}
	a.mu.Lock()
	a.detachPrepared = false
	a.detached = true
	a.mu.Unlock()
	if eno := a.reclaim(&pfslocal.ReclaimRequest{
		Item: pfslocal.Item{ItemID: 9, ItemGeneration: 1},
	}); eno != 0 {
		t.Fatalf("detached reclaim must be idempotent: eno=%d", eno)
	}
}
