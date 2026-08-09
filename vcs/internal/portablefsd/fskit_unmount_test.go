package portablefsd

import (
	"context"
	"errors"
	"testing"
	"time"
)

const testFSKitAttachRef = "att_UUUUUUUUUUUUUUUUUUUUUU"

func TestActivateIfPendingNeverRollsBackActiveCredential(t *testing.T) {
	a := newAttach(testFSKitAttachRef, "credential-race", ensureAttachRequest{
		AttachRef:          testFSKitAttachRef,
		VolumeID:           "vol-credential-race",
		Branch:             "main",
		MountPath:          "/Volumes/CredentialRace",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
	}, privateTestDir(t))
	a.setCredential("newest-token", 0)

	activated, err := a.activateIfPending(context.Background(), "stale-recorded-token", 0, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if activated {
		t.Fatal("active attach accepted a credential-pending-only activation")
	}
	a.credMu.Lock()
	token := a.token
	a.credMu.Unlock()
	if token != "newest-token" {
		t.Fatalf("active credential was rolled back to %q", token)
	}
}

func writeFSKitDetachFixture(t *testing.T, stateDir string, prepared, force bool) {
	t.Helper()
	if err := writePersistedAttaches(stateDir, []persistedAttachEntry{{
		Ref:                testFSKitAttachRef,
		VolumeID:           "vol-fskit-unmount",
		Branch:             "main",
		MountPath:          "/Volumes/PortableFSUnmountTest",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
		IdentityEpoch:      1,
		DetachPrepared:     prepared,
		DetachForce:        force,
	}}); err != nil {
		t.Fatal(err)
	}
}

func TestPreparedFSKitDetachRecoveryClassifiesAndRemoves(t *testing.T) {
	for _, tc := range []struct {
		name       string
		present    bool
		wantDetach int
	}{
		{name: "already absent", present: false},
		{name: "still present", present: true, wantDetach: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stateDir := privateTestDir(t)
			writeFSKitDetachFixture(t, stateDir, true, false)
			r := newRegistry(stateDir)
			t.Cleanup(r.stopPersister)
			detaches := 0
			found, jobID, err := r.unmountFSKitWith(testFSKitAttachRef, false, fskitKernelOps{
				present: func(path, ref string) (bool, error) {
					if path != "/Volumes/PortableFSUnmountTest" || ref != testFSKitAttachRef {
						t.Fatalf("unexpected exact identity %q %q", path, ref)
					}
					return tc.present, nil
				},
				unmountExact: func(path, ref string, _ bool) error {
					detaches++
					return nil
				},
			})
			if err != nil || !found || jobID != "" {
				t.Fatalf("unmount=(%v,%q,%v)", found, jobID, err)
			}
			if detaches != tc.wantDetach {
				t.Fatalf("exact detaches=%d want %d", detaches, tc.wantDetach)
			}
			if got := r.get(testFSKitAttachRef); got != nil {
				t.Fatal("prepared attach remained registered")
			}
			entries, err := loadPersistedAttaches(stateDir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("persisted entries=%+v err=%v", entries, err)
			}
		})
	}
}

func TestPreparedFSKitIdentityMismatchPreservesAttach(t *testing.T) {
	stateDir := privateTestDir(t)
	writeFSKitDetachFixture(t, stateDir, true, false)
	r := newRegistry(stateDir)
	t.Cleanup(r.stopPersister)
	mismatch := errors.New("foreign kernel mount at persisted path")
	found, _, err := r.unmountFSKitWith(testFSKitAttachRef, false, fskitKernelOps{
		present: func(string, string) (bool, error) { return false, mismatch },
		unmountExact: func(string, string, bool) error {
			t.Fatal("identity mismatch reached unmount")
			return nil
		},
	})
	if !found || !errors.Is(err, mismatch) {
		t.Fatalf("unmount=(%v,%v), want preserved mismatch", found, err)
	}
	if got := r.get(testFSKitAttachRef); got == nil {
		t.Fatal("identity mismatch removed attach")
	}
	entries, loadErr := loadPersistedAttaches(stateDir)
	if loadErr != nil || len(entries) != 1 || !entries[0].DetachPrepared {
		t.Fatalf("prepared evidence=%+v err=%v", entries, loadErr)
	}
}

func TestRevivedUnpreparedNormalFSKitDetachRequiresBarrier(t *testing.T) {
	stateDir := privateTestDir(t)
	writeFSKitDetachFixture(t, stateDir, false, false)
	r := newRegistry(stateDir)
	t.Cleanup(r.stopPersister)
	found, _, err := r.unmountFSKitWith(testFSKitAttachRef, false, fskitKernelOps{
		present:      func(string, string) (bool, error) { return true, nil },
		unmountExact: func(string, string, bool) error { t.Fatal("unverified detach"); return nil },
	})
	if !found || err == nil {
		t.Fatalf("unmount=(%v,%v), want active-volume barrier refusal", found, err)
	}
	if r.get(testFSKitAttachRef) == nil {
		t.Fatal("barrier refusal removed attach")
	}
}

func TestFailFrozenPreparedAttachDoesNotDeadlockShutdown(t *testing.T) {
	stateDir := privateTestDir(t)
	writeFSKitDetachFixture(t, stateDir, true, false)
	r := newRegistry(stateDir)
	a := r.get(testFSKitAttachRef)
	if a == nil {
		t.Fatal("missing revived attach")
	}
	a.mu.Lock()
	a.detachFailFrozen = true
	a.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- r.closeAll(context.Background()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("fail-frozen shutdown did not report the prepared detach")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fail-frozen prepared attach held namespace mutex across shutdown")
	}
}

// A CLEAN unmount never forces. A mount that would need MNT_FORCE is not
// cleanly unmountable, and saying so is the only way a leaked reference is ever
// found rather than papered over.
func TestNormalFSKitDetachNeverForcesTheKernel(t *testing.T) {
	stateDir := privateTestDir(t)
	writeFSKitDetachFixture(t, stateDir, true, false)
	r := newRegistry(stateDir)
	t.Cleanup(r.stopPersister)
	detaches := 0
	forced := false
	found, _, err := r.unmountFSKitWith(testFSKitAttachRef, false, fskitKernelOps{
		present: func(string, string) (bool, error) { return true, nil },
		unmountExact: func(_, _ string, force bool) error {
			detaches++
			forced = force
			return nil
		},
	})
	if err != nil || !found || detaches != 1 {
		t.Fatalf("unmount=(%v,%v) detaches=%d", found, err, detaches)
	}
	if forced {
		t.Fatal("clean unmount asked the kernel to force a busy mount")
	}
}
