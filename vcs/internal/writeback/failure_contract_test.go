package writeback

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWALInitializationFailureFailsClosedWithoutAuthorityFallback(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()

	health := make(chan error, 1)
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main", Remote: auth,
		Events: Events{OnHealth: func(err error) { health <- err }},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })

	injected := errors.New("injected WAL initialization failure")
	e.createWAL = func(string, [16]byte, string, string, uint64) (*streamWAL, error) {
		return nil, injected
	}

	if _, handled, err := e.Create(context.Background(), "d/file", 0o644, false, false); !errors.Is(err, ErrFailedClosed) || !errors.Is(err, injected) || handled {
		t.Fatalf("first mutation: handled=%v err=%v, want fail-closed initialization error", handled, err)
	}
	auth.mu.Lock()
	acquires := auth.acquires
	auth.mu.Unlock()
	if acquires != 0 {
		t.Fatalf("authority acquire count = %d, want 0 when local WAL initialization failed", acquires)
	}

	// Even a path that normally selects the authority lane is refused after
	// the terminal verdict. Failure never changes the mount's write mode.
	if _, handled, err := e.Create(context.Background(), "top-level", 0o644, false, false); !errors.Is(err, ErrFailedClosed) || handled {
		t.Fatalf("later authority-native mutation: handled=%v err=%v, want same fail-closed verdict", handled, err)
	}
	if st := e.Status(); !st.Degraded || !strings.Contains(st.LastFailure, "local WAL create stream") {
		t.Fatalf("status did not expose terminal WAL failure: %+v", st)
	}
	select {
	case err := <-health:
		if !errors.Is(err, ErrFailedClosed) {
			t.Fatalf("health error = %v, want ErrFailedClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("terminal WAL failure was not reported through OnHealth")
	}
}

func TestMalformedMountIdentityFailsClosedWithoutReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mount-id")
	const malformed = "not-a-mount-identity\n"
	if err := os.WriteFile(path, []byte(malformed), 0o600); err != nil {
		t.Fatalf("write malformed identity: %v", err)
	}

	_, err := Open(context.Background(), Config{
		StateDir: dir, VolumeID: "vol", Branch: "main", Remote: newFakeAuthority(),
	})
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("open error = %v, want ErrCorrupt", err)
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read identity after refusal: %v", readErr)
	}
	if string(body) != malformed {
		t.Fatalf("malformed identity was silently replaced with %q", body)
	}
}

func TestAcquireTransportFailureIsNotReinterpretedAsDenial(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	injected := errors.New("injected pre-grant transport failure")
	auth.acquireErr = injected
	auth.mu.Unlock()

	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main", Remote: auth,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })

	if _, handled, err := e.Create(context.Background(), "d/file", 0o644, false, false); !errors.Is(err, injected) || handled {
		t.Fatalf("failed acquire: handled=%v err=%v, want visible transport error", handled, err)
	}
	e.mu.RLock()
	_, denied := e.denials["d"]
	e.mu.RUnlock()
	if denied {
		t.Fatal("transport failure was recorded as a policy denial")
	}

	// A later application operation may make a fresh attempt; the engine
	// does not background-repair or silently route the failed operation.
	auth.mu.Lock()
	auth.acquireErr = nil
	auth.mu.Unlock()
	if _, handled, err := e.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("fresh mutation after transport recovery: handled=%v err=%v", handled, err)
	}
}

func TestWALAppendFailureSealsTheMountMutationGate(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()

	health := make(chan error, 1)
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main", Remote: auth,
		Events: Events{OnHealth: func(err error) { health <- err }},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(e.Abandon)

	if _, handled, err := e.Create(context.Background(), "d/file", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if err := e.DrainAll(context.Background()); err != nil {
		t.Fatalf("drain setup mutation: %v", err)
	}

	injected := errors.New("injected WAL media failure")
	e.mu.RLock()
	w := e.wal
	e.mu.RUnlock()
	w.mu.Lock()
	w.syncErr = injected
	w.mu.Unlock()

	if _, handled, err := e.WriteAt(context.Background(), "d/file", 0, []byte("must fail")); !handled || !errors.Is(err, ErrFailedClosed) || !errors.Is(err, injected) {
		t.Fatalf("append failure: handled=%v err=%v, want handled fail-closed error", handled, err)
	}
	if _, handled, err := e.Create(context.Background(), "top-level", 0o644, false, false); handled || !errors.Is(err, ErrFailedClosed) {
		t.Fatalf("post-failure authority-native mutation: handled=%v err=%v", handled, err)
	}
	if st := e.Status(); !st.Degraded || !strings.Contains(st.LastFailure, "local WAL append mutation") {
		t.Fatalf("status did not retain append failure: %+v", st)
	}
	select {
	case err := <-health:
		if !errors.Is(err, injected) {
			t.Fatalf("health error = %v, want injected media failure", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("append failure was not reported through OnHealth")
	}
}

func TestWriteAndFsyncHaveDistinctLocalDurabilityBoundaries(t *testing.T) {
	oldDelay := groupSyncDelay
	groupSyncDelay = time.Hour
	defer func() { groupSyncDelay = oldDelay }()

	var mountID [16]byte
	copy(mountID[:], "durability-test-")
	w, err := createStreamWAL(t.TempDir(), mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create WAL: %v", err)
	}
	defer func() { _ = w.Close() }()

	if _, err := w.appendMutations([][]byte{canonicalPayload(mkRec("d/file", []byte("accepted")))}); err != nil {
		t.Fatalf("append: %v", err)
	}
	w.mu.Lock()
	unsyncedAfterWrite := w.unsyncedBytes
	timerArmed := w.syncTimer != nil
	w.mu.Unlock()
	if unsyncedAfterWrite == 0 || !timerArmed {
		t.Fatalf("plain write unexpectedly crossed the sync boundary: unsynced=%d timer=%v", unsyncedAfterWrite, timerArmed)
	}

	if err := w.Sync(); err != nil {
		t.Fatalf("explicit sync: %v", err)
	}
	w.mu.Lock()
	unsyncedAfterFsync := w.unsyncedBytes
	w.mu.Unlock()
	if unsyncedAfterFsync != 0 {
		t.Fatalf("explicit sync left %d unsynced WAL bytes", unsyncedAfterFsync)
	}
}

func TestBackgroundGroupSyncFailureIsStickyAndReported(t *testing.T) {
	oldDelay := groupSyncDelay
	groupSyncDelay = time.Millisecond
	defer func() { groupSyncDelay = oldDelay }()

	var mountID [16]byte
	copy(mountID[:], "sync-fail-test--")
	w, err := createStreamWAL(t.TempDir(), mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create WAL: %v", err)
	}
	defer w.Abandon()

	failures := make(chan error, 1)
	w.onFailure = func(err error) { failures <- err }
	if _, err := w.appendMutations([][]byte{canonicalPayload(mkRec("d/file", []byte("accepted")))}); err != nil {
		t.Fatalf("append: %v", err)
	}
	w.mu.Lock()
	if err := w.active.Close(); err != nil {
		w.mu.Unlock()
		t.Fatalf("close active segment: %v", err)
	}
	w.mu.Unlock()

	select {
	case err := <-failures:
		if err == nil {
			t.Fatal("background group-sync reported a nil failure")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("background group-sync failure was not reported")
	}
	if err := w.Sync(); err == nil {
		t.Fatal("background group-sync failure did not remain sticky")
	}
}
