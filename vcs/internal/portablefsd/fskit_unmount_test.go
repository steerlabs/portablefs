package portablefsd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

const testFSKitAttachRef = "att_UUUUUUUUUUUUUUUUUUUUUU"

func TestActivateIfPendingNeverRollsBackActiveCredential(t *testing.T) {
	a := newAttach(testFSKitAttachRef, "credential-race", ensureAttachRequest{
		AttachRef:          testFSKitAttachRef,
		VolumeID:           "vol-credential-race",
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
func writeFSKitDetachFixture(t *testing.T, stateDir string) {
	t.Helper()
	err := writePersistedAttaches(stateDir, []persistedAttachEntry{{Ref: testFSKitAttachRef, VolumeID: "vol-fskit-unmount", MountPath: "/Volumes/PortableFSUnmountTest", AuthorityURL: "authority.example:2050", DataPlaneTransport: "tls-system-pki", DataPlaneServerName: "authority.example", IdentityEpoch: 1, V3: &persistedV3Attach{RoutesRevision: strings.Repeat("ab", 32)}}})
	if err != nil {
		t.Fatal(err)
	}
}
func TestRevivedFSKitExactUnmount(t *testing.T) {
	for _, test := range []struct {
		name    string
		present bool
		busy    bool
	}{{"absent", false, false}, {"present", true, false}, {"busy", true, true}} {
		t.Run(test.name, func(t *testing.T) {
			dir := privateTestDir(t)
			writeFSKitDetachFixture(t, dir)
			r := newRegistry(dir)
			present := test.present
			attempts := 0
			found, _, err := r.unmountFSKitWith(testFSKitAttachRef, false, fskitKernelOps{
				present: func(string, string) (bool, error) { return present, nil },
				unmountExact: func(_, _ string, force bool) error {
					attempts++
					if force {
						return errors.New("normal unmount forced")
					}
					if test.busy {
						return syscall.EBUSY
					}
					present = false
					return nil
				},
			})
			if !found {
				t.Fatal("lost registration")
			}
			if test.busy {
				if !errors.Is(err, syscall.EBUSY) || attempts != 1 || r.get(testFSKitAttachRef) == nil {
					t.Fatalf("busy: attempts=%d err=%v", attempts, err)
				}
				return
			}
			if err != nil || r.get(testFSKitAttachRef) != nil {
				t.Fatalf("unmount err=%v", err)
			}
			want := 0
			if test.present {
				want = 1
			}
			if attempts != want {
				t.Fatalf("attempts=%d", attempts)
			}
		})
	}
}
func TestFSKitIdentityMismatchPreservesAttach(t *testing.T) {
	dir := privateTestDir(t)
	writeFSKitDetachFixture(t, dir)
	r := newRegistry(dir)
	mismatch := errors.New("foreign kernel mount")
	found, _, err := r.unmountFSKitWith(testFSKitAttachRef, false, fskitKernelOps{present: func(string, string) (bool, error) { return false, mismatch }, unmountExact: func(string, string, bool) error { return errors.New("unexpected unmount") }})
	if !found || !errors.Is(err, mismatch) || r.get(testFSKitAttachRef) == nil {
		t.Fatalf("identity refusal=%v", err)
	}
}
func TestRegistryRestoresDetachedRecordAfterRemovalPersistenceFailure(t *testing.T) {
	dir := privateTestDir(t)
	writeFSKitDetachFixture(t, dir)
	r := newRegistry(dir)
	a := r.get(testFSKitAttachRef)
	bad := filepath.Join(dir, "not-directory")
	if err := os.WriteFile(bad, nil, 0600); err != nil {
		t.Fatal(err)
	}
	r.stateDir = bad
	ops := fskitKernelOps{present: func(string, string) (bool, error) { return false, nil }, unmountExact: func(string, string, bool) error { return errors.New("unexpected unmount") }}
	found, _, err := r.unmountFSKitWith(a.ref, false, ops)
	if !found || err == nil || !a.isDetached() || r.get(a.ref) != a || r.byKey[a.key] != a {
		t.Fatalf("failed removal lost exact detached owner: %v", err)
	}
	r.stateDir = dir
	ops.present = func(string, string) (bool, error) {
		t.Error("completed teardown repeated kernel observation")
		return false, nil
	}
	found, _, err = r.unmountFSKitWith(a.ref, false, ops)
	if !found || err != nil || r.get(a.ref) != nil {
		t.Fatalf("retry=%v", err)
	}
	entries, err := loadPersistedAttaches(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("persisted removal=%v %v", entries, err)
	}
}
func TestFailedUnmountRetryNeverJoinsStaleCompletedOutcome(t *testing.T) {
	for range 100 {
		dir := privateTestDir(t)
		writeFSKitDetachFixture(t, dir)
		r := newRegistry(dir)
		var observations atomic.Int32
		first := errors.New("first observation failed")
		ops := fskitKernelOps{present: func(string, string) (bool, error) { observations.Add(1); return false, first }, unmountExact: func(string, string, bool) error { return errors.New("unexpected unmount") }}
		_, _, err := r.unmountFSKitWith(testFSKitAttachRef, false, ops)
		if !errors.Is(err, first) {
			t.Fatal(err)
		}
		ops.present = func(string, string) (bool, error) { observations.Add(1); return false, nil }
		found, _, err := r.unmountFSKitWith(testFSKitAttachRef, false, ops)
		if !found || err != nil || observations.Load() != 2 {
			t.Fatalf("retry=%v observations=%d", err, observations.Load())
		}
	}
}
