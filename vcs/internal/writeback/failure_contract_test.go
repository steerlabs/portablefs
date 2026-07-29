package writeback

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
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

func TestBackgroundGroupSyncDoesNotSerializeAppends(t *testing.T) {
	oldDelay := groupSyncDelay
	groupSyncDelay = time.Millisecond
	defer func() { groupSyncDelay = oldDelay }()

	var mountID [16]byte
	copy(mountID[:], "async-sync-test-")
	w, err := createStreamWAL(t.TempDir(), mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create WAL: %v", err)
	}
	defer func() { _ = w.Close() }()

	syncStarted := make(chan struct{})
	releaseSync := make(chan struct{})
	var calls atomic.Int32
	w.mu.Lock()
	w.syncFile = func(f *os.File) error {
		if calls.Add(1) == 1 {
			close(syncStarted)
			<-releaseSync
		}
		return f.Sync()
	}
	w.mu.Unlock()

	if _, err := w.appendMutations([][]byte{canonicalPayload(mkRec("d/first", []byte("one")))}); err != nil {
		t.Fatalf("first append: %v", err)
	}
	select {
	case <-syncStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("background group-sync did not start")
	}

	appended := make(chan error, 1)
	go func() {
		_, err := w.appendMutations([][]byte{canonicalPayload(mkRec("d/second", []byte("two")))})
		appended <- err
	}()
	select {
	case err := <-appended:
		if err != nil {
			t.Fatalf("append during group-sync: %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("background fsync serialized a later WAL append")
	}

	close(releaseSync)
	if err := w.Sync(); err != nil {
		t.Fatalf("explicit sync after background generation: %v", err)
	}
	w.mu.Lock()
	unsynced := w.unsyncedBytes
	syncing := w.syncing
	w.mu.Unlock()
	if unsynced != 0 || syncing {
		t.Fatalf("explicit sync left WAL debt: unsynced=%d syncing=%v", unsynced, syncing)
	}
	if calls.Load() < 2 {
		t.Fatalf("explicit sync did not cover the post-snapshot append: sync calls=%d", calls.Load())
	}
}

func TestGroupSyncByteThresholdDoesNotExposePartialAppendState(t *testing.T) {
	oldDelay := groupSyncDelay
	groupSyncDelay = time.Hour
	defer func() { groupSyncDelay = oldDelay }()

	var mountID [16]byte
	copy(mountID[:], "threshold-test--")
	dir := t.TempDir()
	w, err := createStreamWAL(dir, mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create WAL: %v", err)
	}

	syncStarted := make(chan struct{})
	releaseSync := make(chan struct{})
	defer func() {
		select {
		case <-releaseSync:
		default:
			close(releaseSync)
		}
		w.Abandon()
	}()
	var calls atomic.Int32
	w.mu.Lock()
	w.syncFile = func(f *os.File) error {
		if calls.Add(1) == 1 {
			close(syncStarted)
			<-releaseSync
		}
		return f.Sync()
	}
	w.mu.Unlock()

	// Four one-megabyte records cross the byte threshold. The append that
	// crosses it must commit its sequence/segment metadata before returning,
	// even though the resulting background sync remains blocked.
	for i, path := range []string{"d/large-0", "d/large-1", "d/large-2", "d/large-3"} {
		rec := mkRec(path, make([]byte, 1<<20))
		if _, err := w.appendMutations([][]byte{canonicalPayload(rec)}); err != nil {
			t.Fatalf("threshold append %d: %v", i, err)
		}
	}
	select {
	case <-syncStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("byte-threshold background sync did not start")
	}

	appended := make(chan error, 1)
	go func() {
		_, err := w.appendMutations([][]byte{canonicalPayload(mkRec("d/after-threshold", []byte("tail")))})
		appended <- err
	}()
	select {
	case err := <-appended:
		if err != nil {
			t.Fatalf("append behind threshold sync: %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("byte-threshold sync serialized a later append")
	}

	close(releaseSync)
	if err := w.Sync(); err != nil {
		t.Fatalf("sync complete stream: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close WAL: %v", err)
	}
	scan, err := scanStream(dir)
	if err != nil {
		t.Fatalf("scan WAL: %v", err)
	}
	var gotPaths []string
	for _, fr := range scan.frames {
		if fr.typ != frameMutation {
			continue
		}
		rec, err := wal.DecodePFR1(fr.payload)
		if err != nil {
			t.Fatalf("decode sequence %d: %v", fr.seq, err)
		}
		if fr.seq != uint64(len(gotPaths)+1) {
			t.Fatalf("non-dense recovered sequence %d after %d records", fr.seq, len(gotPaths))
		}
		gotPaths = append(gotPaths, rec.Path)
	}
	if len(gotPaths) != 5 || gotPaths[4] != "d/after-threshold" {
		t.Fatalf("recovered append order = %v", gotPaths)
	}
}

func TestAbandonWaitsForBackgroundSyncDescriptorOwnership(t *testing.T) {
	oldDelay := groupSyncDelay
	groupSyncDelay = time.Millisecond
	defer func() { groupSyncDelay = oldDelay }()

	var mountID [16]byte
	copy(mountID[:], "abandon-sync---")
	w, err := createStreamWAL(t.TempDir(), mountID, "vol", "main", 1)
	if err != nil {
		t.Fatalf("create WAL: %v", err)
	}
	syncStarted := make(chan struct{})
	releaseSync := make(chan struct{})
	injected := errors.New("abandoned in-flight sync")
	failures := make(chan error, 1)
	w.mu.Lock()
	w.onFailure = func(err error) { failures <- err }
	w.syncFile = func(*os.File) error {
		close(syncStarted)
		<-releaseSync
		return injected
	}
	w.mu.Unlock()
	if _, err := w.appendMutations([][]byte{canonicalPayload(mkRec("d/file", []byte("accepted")))}); err != nil {
		t.Fatalf("append: %v", err)
	}
	select {
	case <-syncStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("background sync did not start")
	}

	abandoned := make(chan struct{})
	go func() {
		w.Abandon()
		close(abandoned)
	}()
	select {
	case <-abandoned:
		t.Fatal("Abandon closed a descriptor still owned by background sync")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseSync)
	select {
	case <-abandoned:
	case <-time.After(2 * time.Second):
		t.Fatal("Abandon did not finish after background sync released the descriptor")
	}
	select {
	case err := <-failures:
		t.Fatalf("post-abandon sync failure escaped as a live mount failure: %v", err)
	default:
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed || w.active != nil || len(w.files) != 0 {
		t.Fatalf("abandoned WAL retained descriptors: closed=%v active=%v files=%d", w.closed, w.active != nil, len(w.files))
	}
}
