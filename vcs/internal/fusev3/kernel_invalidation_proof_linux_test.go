//go:build linux

package fusev3

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

const proofInode = 2

// kernelProofFS deliberately has no PortableFS coherence machinery: the only
// cache withdrawal is the test's single reverse notification. Immutable reply
// snapshots let the race test release an old READ after changing daemon data.
type kernelProofFS struct {
	fuse.RawFileSystem
	reads   atomic.Int64
	mu      sync.Mutex
	data    []byte
	entered chan struct{}
	release chan struct{}
}

func (f *kernelProofFS) attr(ino uint64) fuse.Attr {
	a := fuse.Attr{Ino: ino, Mode: unix.S_IFREG | 0o444, Nlink: 1,
		Owner: fuse.Owner{Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid())}}
	if ino == 1 {
		a.Mode = unix.S_IFDIR | 0o755
	} else {
		a.Size = uint64(os.Getpagesize())
	}
	return a
}

func (f *kernelProofFS) Lookup(_ <-chan struct{}, _ *fuse.InHeader, name string, out *fuse.EntryOut) fuse.Status {
	if name != "file" {
		return fuse.ENOENT
	}
	out.NodeId, out.Generation, out.Attr = proofInode, 1, f.attr(proofInode)
	out.SetEntryTimeout(time.Hour)
	out.SetAttrTimeout(time.Hour)
	return fuse.OK
}

func (f *kernelProofFS) GetAttr(_ <-chan struct{}, in *fuse.GetAttrIn, out *fuse.AttrOut) fuse.Status {
	out.Attr = f.attr(in.NodeId)
	out.SetTimeout(time.Hour)
	return fuse.OK
}

func (f *kernelProofFS) Open(_ <-chan struct{}, _ *fuse.OpenIn, out *fuse.OpenOut) fuse.Status {
	out.Fh, out.OpenFlags = 17, fuse.FOPEN_KEEP_CACHE
	return fuse.OK
}

func (f *kernelProofFS) Read(_ <-chan struct{}, in *fuse.ReadIn, _ []byte) (fuse.ReadResult, fuse.Status) {
	f.reads.Add(1)
	f.mu.Lock()
	data := bytes.Clone(f.data)
	entered, release := f.entered, f.release
	f.entered, f.release = nil, nil
	f.mu.Unlock()
	if entered != nil {
		close(entered)
		<-release
	}
	start := min(uint64(len(data)), in.Offset)
	end := min(uint64(len(data)), start+uint64(in.Size))
	return fuse.ReadResultData(data[start:end]), fuse.OK
}

func (f *kernelProofFS) replace(b byte) {
	f.mu.Lock()
	f.data = bytes.Repeat([]byte{b}, os.Getpagesize())
	f.mu.Unlock()
}

func logProofKernel(t *testing.T) {
	t.Helper()
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatal(err)
	}
	t.Logf("kernel uname -r: %s", unix.ByteSliceToString(uts.Release[:]))
}

func mountKernelProof(t *testing.T, raw fuse.RawFileSystem) (*fuse.Server, string) {
	t.Helper()
	requireIntegrationEnvironment(t)
	root := t.TempDir()
	// Reuse the shipping profile, not a lookalike. The filesystem itself does
	// not use the shipping mount, authority, leases, or publication drain.
	opts := mountOptions(Config{MountInstanceID: "kernel-proof", MaxBackground: 16}, 1<<20, 1<<20)
	if err := verifyMountDecisions(opts); err != nil {
		t.Fatal(err)
	}
	if opts.DisabledCapabilities&(fuse.CAP_WRITEBACK_CACHE|fuse.CAP_AUTO_INVAL_DATA) != fuse.CAP_WRITEBACK_CACHE|fuse.CAP_AUTO_INVAL_DATA || !opts.ExplicitDataCacheControl {
		t.Fatal("proof requires explicit cache control with writeback and auto invalidation disabled")
	}
	server, err := fuse.NewServer(raw, root, opts)
	if err != nil {
		t.Fatalf("mount proof filesystem: %v", err)
	}
	go server.Serve()
	t.Cleanup(func() {
		if err := server.Unmount(); err != nil {
			t.Errorf("unmount proof: %v", err)
		}
	})
	if err := server.WaitMount(); err != nil {
		t.Fatalf("wait for proof mount: %v", err)
	}
	t.Logf("profile: writeback=off auto-inval=off explicit-data-cache-control=true read-open=KEEP_CACHE; kernel FUSE %d.%d", server.KernelSettings().Major, server.KernelSettings().Minor)
	return server, root
}

func proofRead(fd int) ([]byte, error) {
	if _, err := unix.Seek(fd, 0, 0); err != nil {
		return nil, err
	}
	buf := make([]byte, os.Getpagesize())
	n, err := unix.Read(fd, buf)
	if err != nil {
		return nil, err
	}
	if n != len(buf) {
		return nil, fmt.Errorf("read returned %d bytes, want %d", n, len(buf))
	}
	return buf, nil
}

func TestKernelInvalidationProof(t *testing.T) {
	requireIntegrationEnvironment(t)
	logProofKernel(t)
	for _, kind := range []string{"read", "private-mapping", "in-flight-read"} {
		t.Run(kind, func(t *testing.T) {
			fs := &kernelProofFS{RawFileSystem: fuse.NewDefaultRawFileSystem()}
			fs.replace('A')
			server, root := mountKernelProof(t, fs)
			fd, err := unix.Open(filepath.Join(root, "file"), unix.O_RDONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			checkRead := func(want byte, delta int64) {
				t.Helper()
				before := fs.reads.Load()
				data, err := proofRead(fd)
				got := fs.reads.Load() - before
				t.Logf("read(2): daemon READ delta=%d total=%d content-%c=%t", got, fs.reads.Load(), want, bytes.Equal(data, bytes.Repeat([]byte{want}, os.Getpagesize())))
				if err != nil || !bytes.Equal(data, bytes.Repeat([]byte{want}, os.Getpagesize())) || got != delta {
					t.Fatalf("read: err=%v READ delta=%d want=%d content matches %q=%t", err, got, delta, want, bytes.Equal(data, bytes.Repeat([]byte{want}, os.Getpagesize())))
				}
			}
			checkRead('A', 1)
			checkRead('A', 0)
			if kind == "private-mapping" {
				mapping, err := unix.Mmap(fd, 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_PRIVATE)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Munmap(mapping)
				if !bytes.Equal(mapping, bytes.Repeat([]byte{'A'}, len(mapping))) {
					t.Fatal("initial mapping bytes")
				}
				if got := fs.reads.Load(); got != 1 {
					t.Fatalf("resident mapping READ count=%d want=1", got)
				}
				fs.replace('B')
				if status := server.InodeNotify(proofInode, 0, 0); status != fuse.OK {
					t.Fatal(status)
				}
				good := bytes.Equal(mapping, bytes.Repeat([]byte{'B'}, len(mapping)))
				t.Logf("post-notify private fault: daemon READ delta=%d total=%d content-B=%t", fs.reads.Load()-1, fs.reads.Load(), good)
				if !good || fs.reads.Load() != 2 {
					t.Fatal("mapped page was not withdrawn")
				}
				checkRead('B', 0)
				return
			}
			if kind == "in-flight-read" {
				if status := server.InodeNotify(proofInode, 0, 0); status != fuse.OK {
					t.Fatal(status)
				}
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				fs.mu.Lock()
				fs.entered, fs.release = entered, release
				fs.mu.Unlock()
				type readReply struct {
					data []byte
					err  error
				}
				readDone := make(chan readReply, 1)
				go func() { data, err := proofRead(fd); readDone <- readReply{data, err} }()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("READ never reached daemon")
				}
				fs.replace('B')
				notifyDone := make(chan fuse.Status, 1)
				notifyThread := make(chan int, 1)
				go func() {
					runtime.LockOSThread()
					defer runtime.UnlockOSThread()
					notifyThread <- unix.Gettid()
					notifyDone <- server.InodeNotify(proofInode, 0, 0)
				}()
				// A sleeping goroutine is not evidence of a blocked notification.
				// Observe the locked OS thread in writev before releasing the READ,
				// or observe notify's return while that READ is still held. This
				// proves overlap without assuming a scheduling delay is sufficient.
				notified := awaitProofNotification(t, <-notifyThread, notifyDone)
				t.Logf("notify returned while old READ held=%t; READ total=%d", notified, fs.reads.Load())
				unblock()
				select {
				case reply := <-readDone:
					old := bytes.Equal(reply.data, bytes.Repeat([]byte{'A'}, os.Getpagesize()))
					fresh := bytes.Equal(reply.data, bytes.Repeat([]byte{'B'}, os.Getpagesize()))
					t.Logf("in-flight read completed: READ total=%d content-A=%t content-B=%t error=%v", fs.reads.Load(), old, fresh, reply.err)
					if reply.err != nil || (!old && !fresh) || (old && fs.reads.Load() != 2) || (fresh && fs.reads.Load() != 3) {
						t.Fatal("in-flight read did not return exactly the captured snapshot or one fresh daemon retry")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("in-flight READ deadlocked")
				}
				if !notified {
					select {
					case status := <-notifyDone:
						if status != fuse.OK {
							t.Fatal(status)
						}
					case <-time.After(5 * time.Second):
						t.Fatal("notify deadlocked after releasing READ")
					}
				}
				// Linux may retry the interrupted page fill inside the original
				// syscall. In either case exactly one fresh READ must supply B;
				// accepting cached A here would disprove withdrawal.
				checkRead('B', 3-fs.reads.Load())
				checkRead('B', 0)
				return
			}
			fs.replace('B')
			if status := server.InodeNotify(proofInode, 0, 0); status != fuse.OK {
				t.Fatal(status)
			}
			checkRead('B', 1)
			checkRead('B', 0)
		})
	}
}

// The notification goroutine performs no other writev. Keeping it on one OS
// thread makes /proc's syscall observation an exact submission witness. The
// held READ keeps the notification blocked until the test releases the reply.
func awaitProofNotification(t *testing.T, tid int, done <-chan fuse.Status) bool {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case status := <-done:
			if status != fuse.OK {
				t.Fatal(status)
			}
			return true
		case <-deadline.C:
			t.Fatal("notification did not enter writev or return while READ held")
		case <-tick.C:
			data, err := os.ReadFile(fmt.Sprintf("/proc/self/task/%d/syscall", tid))
			if err != nil {
				t.Fatalf("observe notification syscall: %v", err)
			}
			fields := strings.Fields(string(data))
			if len(fields) == 0 {
				continue
			}
			syscallNumber, err := strconv.ParseInt(fields[0], 0, 64)
			if err == nil && syscallNumber == int64(unix.SYS_WRITEV) {
				t.Logf("notification thread observed in writev syscall=%d while old READ held", syscallNumber)
				return false
			}
		}
	}
}
