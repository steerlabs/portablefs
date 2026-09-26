//go:build linux

package fusev3

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func fakeAbortFile(t *testing.T) *kernelAbortFile {
	t.Helper()
	path := filepath.Join(t.TempDir(), "abort")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := openKernelAbortFile(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.close() })
	return a
}

func TestKernelAbortUsesRetainedInodeAfterPathReplacement(t *testing.T) {
	a := fakeAbortFile(t)
	old := a.file.Name() + ".retired"
	if err := os.Rename(a.file.Name(), old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.file.Name(), []byte("successor"), 0600); err != nil {
		t.Fatal(err)
	}
	k := kernelMount{device: "0:123", abortFile: a}
	if err := k.abortKernelConnection(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(old); err != nil || string(got) != "1" {
		t.Fatalf("original inode = %q, %v", got, err)
	}
	if got, err := os.ReadFile(a.file.Name()); err != nil || string(got) != "successor" {
		t.Fatalf("successor changed: %q, %v", got, err)
	}
	if current, err := a.current(); err != nil || current {
		t.Fatalf("retired inode current = %t, %v", current, err)
	}
	if err := a.close(); err != nil {
		t.Fatal(err)
	}
	if err := k.abortKernelConnection(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("abort after close = %v", err)
	}
	if err := a.close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	if got, _ := os.ReadFile(a.file.Name()); string(got) != "successor" {
		t.Fatal("closed handle reopened numeric path")
	}
}

func TestKernelAbortRequiresRetainedWritableDescriptor(t *testing.T) {
	if err := (kernelMount{device: "0:123"}).abortKernelConnection(); err == nil {
		t.Fatal("unretained numeric device accepted")
	}
	path := filepath.Join(t.TempDir(), "absent")
	if _, err := openKernelAbortFile(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing control file = %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("abort capture created a control file")
	}
	a := fakeAbortFile(t)
	link := a.file.Name() + ".link"
	if err := os.Symlink(a.file.Name(), link); err != nil {
		t.Fatal(err)
	}
	if _, err := openKernelAbortFile(link); err == nil {
		t.Fatal("abort capture followed symlink")
	}
	readOnly, err := os.Open(a.file.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	if err := (&kernelAbortFile{file: readOnly}).abort(); err == nil {
		t.Fatal("read-only control descriptor silently succeeded")
	}
}

func TestKernelAbortConcurrentCloseNeverReopens(t *testing.T) {
	a := fakeAbortFile(t)
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 32 {
				if err := a.abort(); err != nil && !errors.Is(err, os.ErrClosed) {
					t.Error(err)
				}
			}
		}()
	}
	if err := a.close(); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if _, err := a.file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("descriptor remains open: %v", err)
	}
}

func TestKernelMountIdentityRejectsRecycledNumbersAndDetachTargets(t *testing.T) {
	k := kernelMount{id: "42", device: "0:99", point: "/workspaces/owned", filesystem: "fuse.portablefs", source: "portablefs:original"}
	for _, test := range []struct {
		name, records  string
		absent, detach bool
	}{
		{"original", "42 1 0:99 / /workspaces/owned rw - fuse.portablefs portablefs:original rw\n", false, true},
		{"recycled mount ID", "42 1 0:100 / /workspaces/owned rw - fuse.portablefs portablefs:successor rw\n", true, false},
		{"recycled ID and device", "42 1 0:99 / /workspaces/owned rw - fuse.portablefs portablefs:successor rw\n", true, false},
		{"same source different device", "42 1 0:100 / /workspaces/owned rw - fuse.portablefs portablefs:original rw\n", true, false},
		{"different filesystem", "42 1 0:99 / /workspaces/owned rw - fuse.other portablefs:original rw\n", true, false},
		{"moved original", "42 1 0:99 / /workspaces/moved rw - fuse.portablefs portablefs:original rw\n", false, false},
		{"retained alias", "43 1 0:99 / /workspaces/alias rw - fuse.portablefs portablefs:original rw\n", false, false},
		{"overmount", "42 1 0:99 / /workspaces/owned rw - fuse.portablefs portablefs:original rw\n43 1 0:100 / /workspaces/owned rw - tmpfs tmpfs rw\n", false, false},
		{"malformed", "1 0 0:1 / / rw - ext4 root rw\nmalformed\n", false, false},
		{"empty", "", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			prior := readMountInfo
			readMountInfo = func() ([]byte, error) { return []byte(test.records), nil }
			defer func() { readMountInfo = prior }()
			_, err := k.absent()
			if (err == nil) != test.absent {
				t.Fatalf("absence = %v, want %t", err, test.absent)
			}
			present, err := k.detachTargetInstalled()
			if (present && err == nil) != test.detach {
				t.Fatalf("detach target = %t, %v, want %t", present, err, test.detach)
			}
		})
	}
}

func TestKernelMountRetainedAbortDistinguishesIdenticalReusedRecord(t *testing.T) {
	a := fakeAbortFile(t)
	k := kernelMount{id: "42", device: "0:99", point: "/owned", filesystem: "fuse.portablefs", source: "portablefs:reused", abortFile: a}
	prior := readMountInfo
	readMountInfo = func() ([]byte, error) {
		return []byte("42 1 0:99 / /owned rw - fuse.portablefs portablefs:reused rw\n"), nil
	}
	defer func() { readMountInfo = prior }()
	if _, err := k.absent(); err == nil {
		t.Fatal("current original reported absent")
	}
	if err := os.Rename(a.file.Name(), a.file.Name()+".retired"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.file.Name(), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := k.absent(); err != nil {
		t.Fatalf("successor mistaken for original: %v", err)
	}
	m := &Mount{kernelMount: k}
	// No server: reaching the helper branch would fail. A successor must be skipped.
	if err := m.productionKernelWithdrawal().detach(k.point); err != nil {
		t.Fatalf("successor passed to detach: %v", err)
	}
	if err := m.unmountOwnedKernelMount(); err != nil {
		t.Fatalf("successor passed to ordinary unmount: %v", err)
	}
}

func TestMountCloseJoinsWithdrawalBeforeClosingAbortDescriptor(t *testing.T) {
	f := newStrictFixture(t)
	a := fakeAbortFile(t)
	f.mount.kernelMount = kernelMount{id: "999999999", device: "0:999", point: "/nonexistent", filesystem: "fuse.portablefs", source: "portablefs:unit-close", abortFile: a}
	close(f.mount.kernelConnectionDone)
	f.mount.kernelWithdrawalMu.Lock()
	done := make(chan error, 1)
	go func() { done <- f.mount.Close() }()
	select {
	case err := <-done:
		t.Fatalf("close crossed active withdrawal: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := a.file.Stat(); err != nil {
		t.Fatalf("abort descriptor closed during withdrawal: %v", err)
	}
	f.mount.kernelWithdrawalMu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join withdrawal")
	}
	if _, err := a.file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("abort descriptor not closed: %v", err)
	}
	if err := f.mount.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestKernelMountMissingControlPathCannotProveMatchingMountAbsent(t *testing.T) {
	a := fakeAbortFile(t)
	k := kernelMount{id: "42", device: "0:99", point: "/owned", filesystem: "fuse.portablefs", source: "portablefs:original", abortFile: a}
	prior := readMountInfo
	readMountInfo = func() ([]byte, error) {
		return []byte("42 1 0:99 / /owned rw - fuse.portablefs portablefs:original rw\n"), nil
	}
	defer func() { readMountInfo = prior }()
	if err := os.Remove(a.file.Name()); err != nil {
		t.Fatal(err)
	}
	if _, err := k.absent(); err == nil {
		t.Fatal("missing fusectl pathname proved live mount absent")
	}
	if _, err := k.detachTargetInstalled(); err == nil {
		t.Fatal("missing fusectl pathname authorized detach")
	}
}

func TestMountCloseReleasesAbortDescriptorOnDetachFailure(t *testing.T) {
	f := newStrictFixture(t)
	a := fakeAbortFile(t)
	f.mount.kernelMount = kernelMount{id: "999999999", device: "0:999", point: "/nonexistent", filesystem: "fuse.portablefs", source: "portablefs:unit-close", abortFile: a}
	close(f.mount.kernelConnectionDone)
	f.rpc.detachErr = errors.New("detach delivery failed")
	if err := f.mount.Close(); !errors.Is(err, f.rpc.detachErr) {
		t.Fatalf("Close lost detach error: %v", err)
	}
	if _, err := a.file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("failed close leaked abort descriptor: %v", err)
	}
}
