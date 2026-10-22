//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"golang.org/x/sys/unix"
)

// The stock fake answers GETATTR from one file. A kernel mount also asks for
// its root, whose directory type and search permission must remain exact.
type recoveryKernelRPC struct {
	*fakeRPC
	root *authoritypb.Item
}

func (r *recoveryKernelRPC) CallReadRetained(ctx context.Context, request *authoritypb.Request, _ func(error)) (*authoritypb.Response, authorityrpc.ResponseConsumption, error) {
	if query := request.GetGetAttr(); query != nil && bytes.Equal(query.GetItem(), r.root.GetToken()) {
		return &authoritypb.Response{VolumeVersion: 2, Body: &authoritypb.Response_GetAttr{GetAttr: &authoritypb.GetAttrReply{Attr: cloneItem(r.root).Attr, ObjectVersion: 1, SnapshotSequence: 1}}}, nil, nil
	}
	return r.fakeRPC.CallReadRetained(ctx, request, nil)
}

// Keep the deterministic authority/storage from the review repro while using
// actual syscalls, kernel inode state, go-fuse writers and reverse notifications.
// No writeback runner applies the dirty tail before the interruption cut.
func newRecoveryKernel(t *testing.T, wrap func(*rawFileSystem) fuse.RawFileSystem) (*stockFixture, string) {
	t.Helper()
	if os.Getenv(envFUSE) != "1" {
		t.Skip("set PORTABLEFS_FUSE_TEST=1 for real kernel recovery races")
	}
	f := newStockFixture(t)
	f.mount.uid, f.mount.gid = uint32(os.Geteuid()), uint32(os.Getegid())
	root := cloneItem(f.raw.nodesByID[1].node.item)
	root.Attr.Mode, root.Attr.Nlink = 0700, 2
	f.raw.nodesByID[1].node.item = root
	f.mount.rpc = &recoveryKernelRPC{fakeRPC: f.rpc, root: root}
	point := filepath.Join(t.TempDir(), "mount")
	if err := os.Mkdir(point, 0700); err != nil {
		t.Fatal(err)
	}
	options := mountOptions(testConfig(8), 64<<10, 64<<10)
	options.Debug = os.Getenv(envFUSEDebug) == "1"
	options.FsName = "portablefs:recovery-" + filepath.Base(filepath.Dir(filepath.Dir(point)))
	server, err := fuse.NewServer(wrap(f.raw), point, options)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := captureKernelMount(options.FsName, point)
	f.mount.server = server
	f.mount.setNotifier(server)
	if err == nil {
		f.mount.kernelMount = installed
	}
	f.mount.startKernelConnection()
	t.Cleanup(func() {
		_ = server.Unmount()
		f.mount.Wait()
		if installed.abortFile != nil {
			_ = installed.abortFile.close()
		}
	})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if err := server.WaitMount(); err != nil {
		t.Fatalf("wait mount: %v, fatal: %v", err, f.mount.fatalError())
	}
	return f, filepath.Join(point, "cached")
}

// The test owns teardown explicitly so stockFixture's fake Authority need not
// implement a supervisor. Every serving entry and physical reply is inherited.
type recoveryKernelFS struct{ *rawFileSystem }

func (r *recoveryKernelFS) OnUnmount() {}

func TestKernelReadDuringInterruptKeepsOverlay(t *testing.T) {
	f, path := newRecoveryKernel(t, func(r *rawFileSystem) fuse.RawFileSystem { return &recoveryKernelFS{r} })
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if n, err := file.WriteAt([]byte("dirty"), 0); err != nil || n != 5 {
		t.Fatalf("write = %d, %v", n, err)
	}
	f.rpc.snapshot(func(rpc *fakeRPC) {
		if len(rpc.writes) != 0 {
			t.Fatal("dirty bytes already applied")
		}
	})
	m := f.mount.delegations
	m.epoch.Lock()
	locked := true
	defer func() {
		if locked {
			m.epoch.Unlock()
		}
	}()
	type result struct {
		data string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		buf := make([]byte, 32)
		n, err := unix.Pread(int(file.Fd()), buf, 0)
		done <- result{string(buf[:n]), err}
	}()
	waitRecoveryStack(t, "(*delegationManager).Read(")
	reset := make(chan error, 1)
	go func() { reset <- f.mount.subscription.subscribe(t.Context()) }()
	waitUntil(t, time.Second, "kernel READ interruption", func() bool { return m.inc.Load() == 0 })
	m.epoch.Unlock()
	locked = false
	r := <-done
	if err := <-reset; err != nil {
		t.Fatal(err)
	}
	if r.data != "dirty" || r.err != nil {
		t.Errorf("pread returned %q, %v instead of acknowledged dirty bytes", r.data, r.err)
	}
	if loss := m.LossSequence(); loss != 1 {
		t.Errorf("reset loss = %d, want exactly 1", loss)
	}
}

type recoveryTrackingKernelFS struct {
	*recoveryKernelFS
	armed   atomic.Bool
	entered chan uint64
	resume  chan struct{}
}

func (r *recoveryTrackingKernelFS) ReplyWriteTracked(unique uint64) bool {
	r.mu.RLock()
	p := r.replyPublications[unique]
	cached := p != nil && p.cachedArena && p.originalFinalized
	r.mu.RUnlock()
	if cached && r.armed.CompareAndSwap(true, false) {
		r.entered <- unique
		<-r.resume
	}
	return r.rawFileSystem.ReplyWriteTracked(unique)
}

type recoveryKernelNotifier struct {
	kernelNotifier
	aborted         *atomic.Bool
	beforeAbort     atomic.Uint32
	dataBeforeAbort atomic.Uint32
}

func (n *recoveryKernelNotifier) InodeNotify(inode uint64, off, length int64) fuse.Status {
	status := n.kernelNotifier.InodeNotify(inode, off, length)
	if !n.aborted.Load() && (status.Ok() || status == fuse.ENOENT) {
		n.beforeAbort.Add(1)
		if off == 0 && length == 0 {
			n.dataBeforeAbort.Add(1)
		}
	}
	return status
}

func TestKernelCachedWriterJoinsTerminalWithdrawal(t *testing.T) {
	var fs *recoveryTrackingKernelFS
	f, path := newRecoveryKernel(t, func(r *rawFileSystem) fuse.RawFileSystem {
		fs = &recoveryTrackingKernelFS{recoveryKernelFS: &recoveryKernelFS{r}, entered: make(chan uint64, 1), resume: make(chan struct{})}
		return fs
	})
	var resume sync.Once
	defer resume.Do(func() { close(fs.resume) })
	warm, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer warm.Close()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Stat(); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, time.Second, "cacheable OPEN physical settlement", func() bool {
		f.raw.mu.RLock()
		defer f.raw.mu.RUnlock()
		return len(f.raw.cachedData) != 0
	})
	fs.armed.Store(true)
	stat := make(chan error, 1)
	go func() { _, err := file.Stat(); stat <- err }()
	var unique uint64
	select {
	case unique = <-fs.entered:
	case <-time.After(time.Second):
		t.Fatal("cached writer did not reach tracking sample")
	}
	aborted := &atomic.Bool{}
	notify := &recoveryKernelNotifier{kernelNotifier: f.mount.notifier(), aborted: aborted}
	f.mount.setNotifier(notify)
	ops := f.mount.withdrawalOps()
	abort := ops.abort
	ops.abort = func(k kernelMount) error { aborted.Store(true); return abort(k) }
	f.mount.withdrawal, f.mount.withdrawalTimeout = ops, 2*time.Second
	done := make(chan withdrawalOutcome, 1)
	go func() { done <- f.mount.withdrawKernelState() }()
	waitUntil(t, time.Second, "terminal join before tracking sample", func() bool {
		f.raw.mu.RLock()
		defer f.raw.mu.RUnlock()
		p := f.raw.replyPublications[unique]
		return f.raw.replyTerminalizing && p != nil && p.originalDone != nil
	})
	resume.Do(func() { close(fs.resume) })
	select {
	case out := <-done:
		if !out.withdrawn {
			t.Errorf("real kernel withdrawal failed: %+v", out)
		}
	case <-time.After(time.Second):
		t.Error("real cached writer waited for terminal join deadline")
		<-done
	}
	<-stat // Abort releases the syscall whose reply preparation was refused.
	if notify.beforeAbort.Load() == 0 || notify.dataBeforeAbort.Load() == 0 {
		t.Error("terminal join skipped real kernel cache withdrawal")
	}
}
