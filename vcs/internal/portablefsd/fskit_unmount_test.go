package portablefsd

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
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
	a.setCredential("newest-token")

	activated, err := a.activateIfPending(context.Background(), "stale-recorded-token")
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
				unmountExact: func(path, ref string) error {
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
		unmountExact: func(string, string) error {
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
		unmountExact: func(string, string) error { t.Fatal("unverified detach"); return nil },
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

func TestForcedFSKitDetachWithoutParkProofRefuses(t *testing.T) {
	stateDir := privateTestDir(t)
	writeFSKitDetachFixture(t, stateDir, false, false)
	r := newRegistry(stateDir)
	t.Cleanup(r.stopPersister)
	found, jobID, err := r.unmountFSKitWith(testFSKitAttachRef, true, fskitKernelOps{
		present: func(string, string) (bool, error) {
			t.Fatal("force authorization without park proof reached kernel classification")
			return false, nil
		},
		unmountExact: func(string, string) error {
			t.Fatal("force authorization without park proof reached exact detach")
			return nil
		},
	})
	if err == nil || !found || jobID != "" {
		t.Fatalf("unmount=(%v,%q,%v), want preserved proof refusal", found, jobID, err)
	}
	entries, loadErr := loadPersistedAttaches(stateDir)
	if loadErr != nil || len(entries) != 1 || !entries[0].DetachForce || entries[0].DetachPrepared {
		t.Fatalf("force authorization evidence=%+v err=%v", entries, loadErr)
	}
}

func TestForcedFSKitPreparedProofPermitsExactRecovery(t *testing.T) {
	stateDir := privateTestDir(t)
	writeFSKitDetachFixture(t, stateDir, true, true)
	r := newRegistry(stateDir)
	t.Cleanup(r.stopPersister)
	detaches := 0
	found, jobID, err := r.unmountFSKitWith(testFSKitAttachRef, false, fskitKernelOps{
		present: func(string, string) (bool, error) { return true, nil },
		unmountExact: func(string, string) error {
			detaches++
			return nil
		},
	})
	if err != nil || !found || jobID != "" || detaches != 1 {
		t.Fatalf("unmount=(%v,%q,%v) detaches=%d", found, jobID, err, detaches)
	}
}

func TestForcedFSKitJobWithoutExactStoreProofIsPreserved(t *testing.T) {
	stateDir := privateTestDir(t)
	const jobID = "jobaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := writePersistedAttaches(stateDir, []persistedAttachEntry{{
		Ref:                testFSKitAttachRef,
		VolumeID:           "vol-fskit-unmount",
		Branch:             "main",
		MountPath:          "/Volumes/PortableFSUnmountTest",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
		IdentityEpoch:      1,
		DetachForce:        true,
		DetachJobID:        jobID,
	}}); err != nil {
		t.Fatal(err)
	}
	r := newRegistry(stateDir)
	t.Cleanup(r.stopPersister)
	found, gotJobID, err := r.unmountFSKitWith(testFSKitAttachRef, false, fskitKernelOps{
		present:      func(string, string) (bool, error) { return false, nil },
		unmountExact: func(string, string) error { t.Fatal("absent mount was detached"); return nil },
	})
	if err == nil || !found || gotJobID != jobID {
		t.Fatalf("unmount=(%v,%q,%v), want exact-store proof refusal", found, gotJobID, err)
	}
	if r.get(testFSKitAttachRef) == nil {
		t.Fatal("unproven forced attach was removed")
	}
}

func TestRevivedForcedFSKitPublishesOfflineZeroTailProofBeforeDetach(t *testing.T) {
	stateDir := privateTestDir(t)
	req := ensureAttachRequest{
		AttachRef:           testFSKitAttachRef,
		VolumeID:            "vol-fskit-unmount",
		Branch:              "main",
		MountPath:           "/Volumes/PortableFSUnmountTest",
		AuthorityURL:        serveAuthority(t),
		DataPlaneTransport:  "plaintext",
		DataPlaneServerName: "",
	}
	a := newAttach(testFSKitAttachRef, attachKey(req.VolumeID, req.Branch, req.MountPath), req, stateDir)
	if err := a.activate(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	a.mu.RLock()
	vol := a.vol
	a.mu.RUnlock()
	if vol == nil || vol.Writeback() == nil {
		t.Fatal("active attach did not open its write-back store")
	}
	// Model daemon death: descriptors and the store lock disappear without a
	// close frame. The restarted registry has only durable attach metadata.
	vol.Writeback().Abandon()
	if err := vol.Close(); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.vol = nil
	a.detachForce = true
	a.credentialPending = true
	a.mu.Unlock()
	entry := a.persistedEntry()
	if err := writePersistedAttaches(stateDir, []persistedAttachEntry{entry}); err != nil {
		t.Fatal(err)
	}

	r := newRegistry(stateDir)
	t.Cleanup(r.stopPersister)
	detaches := 0
	found, jobID, err := r.unmountFSKitWith(testFSKitAttachRef, false, fskitKernelOps{
		present: func(path, ref string) (bool, error) { return true, nil },
		unmountExact: func(path, ref string) error {
			detaches++
			return nil
		},
	})
	if err != nil || !found || jobID != "" || detaches != 1 {
		t.Fatalf("unmount=(%v,%q,%v) detaches=%d", found, jobID, err, detaches)
	}
	if r.get(testFSKitAttachRef) != nil {
		t.Fatal("offline-proven forced attach remained registered")
	}
}

func TestControlLocalWriteWaitsForDetachGateAndHonorsQuarantine(t *testing.T) {
	a := newAttach(testFSKitAttachRef, "key", ensureAttachRequest{
		VolumeID: "vol-local", Branch: "main", MountPath: "/Volumes/Local",
		AuthorityURL: "127.0.0.1:1", DataPlaneTransport: "plaintext",
		Options: AttachOptions{LocalDirs: []string{"cache"}},
	}, privateTestDir(t))
	body := []byte(`{"path":"cache/file.txt","dataBase64":"` +
		base64.StdEncoding.EncodeToString([]byte("must-not-land")) + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/attaches/"+testFSKitAttachRef+"/fs/write", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	a.nsMu.Lock()
	done := make(chan struct{})
	go func() {
		(&Server{}).controlFSWrite(rec, req, a)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("local graft control write bypassed the detach namespace gate")
	case <-time.After(100 * time.Millisecond):
	}
	a.mu.Lock()
	a.detachPrepared = true
	a.mu.Unlock()
	a.nsMu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("control write did not resume after detach gate released")
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
}
