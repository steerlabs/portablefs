//go:build linux

package fusev3

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

const proofDirectoryHandle = uint64(0x1020304050607080)

type barrierProofFS struct {
	*kernelProofFS
	opendirs  atomic.Int64
	syncfs    atomic.Int64
	barrierMu sync.Mutex
	barriers  []fuse.FsyncIn
}

func (f *barrierProofFS) OpenDir(_ <-chan struct{}, in *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	if in.NodeId != 1 {
		return fuse.ENOENT
	}
	f.opendirs.Add(1)
	out.Fh = proofDirectoryHandle
	return fuse.OK
}

func (f *barrierProofFS) FsyncDir(_ <-chan struct{}, in *fuse.FsyncIn) fuse.Status {
	f.barrierMu.Lock()
	f.barriers = append(f.barriers, *in)
	f.barrierMu.Unlock()
	return fuse.OK
}

func (f *barrierProofFS) SyncFS(_ <-chan struct{}, _ *fuse.SyncFSIn) fuse.Status {
	f.syncfs.Add(1)
	return fuse.OK
}

func TestBarrierDeliveryProof(t *testing.T) {
	requireIntegrationEnvironment(t)
	logProofKernel(t)
	fs := &barrierProofFS{kernelProofFS: &kernelProofFS{RawFileSystem: fuse.NewDefaultRawFileSystem()}}
	fs.replace('A')
	server, root := mountKernelProof(t, fs)
	if server.KernelSettings().Minor < 34 {
		t.Fatal("barrier proof requires kernel FUSE 7.34 or later to rule out unsupported SYNCFS")
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	if err := unix.Fsync(rootFD); err != nil {
		t.Fatalf("fsync root directory: %v", err)
	}
	fs.barrierMu.Lock()
	barriers := append([]fuse.FsyncIn(nil), fs.barriers...)
	fs.barrierMu.Unlock()
	t.Logf("OPENDIR=%d FSYNCDIR=%d returned fh=%#x", fs.opendirs.Load(), len(barriers), proofDirectoryHandle)
	if fs.opendirs.Load() != 1 || len(barriers) != 1 {
		t.Fatal("directory barrier was not delivered exactly once")
	}
	t.Logf("FSYNCDIR nodeid=%d fh=%#x flags=%#x", barriers[0].NodeId, barriers[0].Fh, barriers[0].FsyncFlags)
	if barriers[0].NodeId != 1 || barriers[0].Fh != proofDirectoryHandle {
		t.Fatal("directory barrier lost OPENDIR handle or root identity")
	}
	fd, err := unix.Open(filepath.Join(root, "file"), unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	// syncfs is synchronous. If the kernel sends opcode 50, the callback must
	// have run before this syscall returns, even if it returned ENOSYS.
	if err := unix.Syncfs(fd); err != nil {
		t.Fatalf("syncfs file descriptor: %v", err)
	}
	t.Logf("syncfs(2) calls=1 daemon SYNCFS opcodes=%d", fs.syncfs.Load())
	if fs.syncfs.Load() != 0 {
		t.Fatal("stock mount delivered SYNCFS; F6 assumption disproven")
	}
	fs.barrierMu.Lock()
	defer fs.barrierMu.Unlock()
	if len(fs.barriers) != 1 {
		t.Fatalf("syncfs unexpectedly delivered %d additional FSYNCDIR requests", len(fs.barriers)-1)
	}
}
