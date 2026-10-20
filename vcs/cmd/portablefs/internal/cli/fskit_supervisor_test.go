//go:build darwin

package cli

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type testFSKitWatcher struct{ wake chan error }

func (w *testFSKitWatcher) events() <-chan error { return w.wake }
func (w *testFSKitWatcher) close() error         { return nil }

func TestFSKitSupervisorWaitsForSignalsAndKernelEvents(t *testing.T) {
	st := validFSKitMountState(t, filepath.Join(t.TempDir(), "mount"))
	var mounted atomic.Bool
	mounted.Store(true)
	stubMountIdentification(t, nil, func(path string) ([]kernelMountIdentity, error) {
		if !mounted.Load() {
			return nil, nil
		}
		return []kernelMountIdentity{{path: path, fsType: defaultFskitType, source: "dev.portablefs.oss://" + st.AttachRef}}, nil
	})
	watcher := &testFSKitWatcher{make(chan error, 1)}
	signals := make(chan os.Signal)
	var snapshots, unmounts, finalizations, forces atomic.Int32
	original := platformUnmountOpsSource
	platformUnmountOpsSource = func(time.Duration) unmountOps {
		forces.Add(1)
		t.Error("supervisor reached platform force")
		return unmountOps{}
	}
	t.Cleanup(func() { platformUnmountOpsSource = original })
	done := make(chan error, 1)
	go func() {
		done <- superviseFSKit(&st, signals, func() (fsKitMountWatcher, error) { return watcher, nil }, func(st *mountState) (bool, error) { snapshots.Add(1); return recordedKernelMountPresent(st) }, func() error { unmounts.Add(1); return syscall.EBUSY }, func() error { finalizations.Add(1); return io.EOF }, io.Discard)
	}()
	for snapshots.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	// Even repeated wakeups produce no HTTP health probes, terminal verdict,
	// unmount attempt or cleanup. Only a signal requests one normal unmount.
	for range 12 {
		watcher.wake <- nil
	}
	signals <- syscall.SIGTERM
	for unmounts.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	for range 12 {
		watcher.wake <- nil
	}
	if unmounts.Load() != 1 || finalizations.Load() != 0 || forces.Load() != 0 {
		t.Fatalf("unmounts=%d finalizations=%d forces=%d", unmounts.Load(), finalizations.Load(), forces.Load())
	}
	// An exact external absence causes one finalization, whose error terminates
	// supervision for explicit reconciliation. No automatic retry is scheduled.
	mounted.Store(false)
	select {
	case watcher.wake <- nil:
	default:
	}
	select {
	case err := <-done:
		if err == nil || !errors.Is(err, io.EOF) {
			t.Fatalf("lost absent-kernel daemon error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("supervisor did not stop on unconfirmed finalization")
	}
	if finalizations.Load() != 1 || forces.Load() != 0 {
		t.Fatal("finalization retried or forced")
	}
}

func TestFSKitSupervisorRegistersBeforeFirstSnapshotAndRefusesNotificationFailure(t *testing.T) {
	st := validFSKitMountState(t, filepath.Join(t.TempDir(), "mount"))
	sentinel := errors.New("native notification unavailable")
	snapshots := 0
	err := superviseFSKit(&st, nil, func() (fsKitMountWatcher, error) { return nil, sentinel }, func(*mountState) (bool, error) { snapshots++; return false, nil }, func() error { t.Fatal("unmount after failed registration"); return nil }, func() error { t.Fatal("cleanup after failed registration"); return nil }, io.Discard)
	if !errors.Is(err, sentinel) || snapshots != 0 {
		t.Fatalf("error=%v snapshots=%d", err, snapshots)
	}
	watcher := &testFSKitWatcher{make(chan error, 1)}
	watcher.wake <- sentinel
	registered := false
	err = superviseFSKit(&st, nil, func() (fsKitMountWatcher, error) { registered = true; return watcher, nil }, func(*mountState) (bool, error) {
		if !registered {
			t.Error("snapshot precedes registration")
		}
		return true, nil
	}, func() error { t.Fatal("unmount after notifier failure"); return nil }, func() error { t.Fatal("cleanup after notifier failure"); return nil }, io.Discard)
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
}
