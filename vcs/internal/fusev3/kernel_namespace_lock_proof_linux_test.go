//go:build linux

package fusev3

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// A namespace callback runs inside a VFS parent-lock interval that starts
// before userspace sees the request. No daemon mutex participates in this proof.
type kernelNamespaceLockProofFS struct {
	*kernelProofFS
	entered chan struct{}
	release chan struct{}
}

func (f *kernelNamespaceLockProofFS) Create(_ <-chan struct{}, _ *fuse.CreateIn, _ string, _ *fuse.CreateOut) fuse.Status {
	close(f.entered)
	<-f.release
	return fuse.EACCES
}

func TestKernelEntryNotifyWaitsForNamespaceCallback(t *testing.T) {
	fs := &kernelNamespaceLockProofFS{
		kernelProofFS: &kernelProofFS{RawFileSystem: fuse.NewDefaultRawFileSystem()},
		entered:       make(chan struct{}), release: make(chan struct{}),
	}
	fs.replace('A')
	server, root := mountKernelProof(t, fs)
	fd, err := os.Open(filepath.Join(root, "file"))
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	var once sync.Once
	release := func() { once.Do(func() { close(fs.release) }) }
	defer release()
	created := make(chan error, 1)
	go func() {
		fd, err := os.OpenFile(filepath.Join(root, "new"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if fd != nil {
			fd.Close()
		}
		created <- err
	}()
	select {
	case <-fs.entered:
	case <-time.After(time.Second):
		t.Fatal("CREATE callback did not enter")
	}
	notified := make(chan fuse.Status, 1)
	started := make(chan struct{})
	go func() { close(started); notified <- server.EntryNotify(fuse.FUSE_ROOT_ID, "file") }()
	<-started
	select {
	case status := <-notified:
		t.Fatalf("EntryNotify returned before parent-lock callback: %v", status)
	case <-time.After(100 * time.Millisecond):
	}
	release()
	select {
	case status := <-notified:
		if !status.Ok() {
			t.Fatal(status)
		}
	case <-time.After(time.Second):
		t.Fatal("EntryNotify did not return after callback released parent lock")
	}
	select {
	case err := <-created:
		if !os.IsPermission(err) {
			t.Fatalf("CREATE result=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("CREATE did not finish")
	}
}
