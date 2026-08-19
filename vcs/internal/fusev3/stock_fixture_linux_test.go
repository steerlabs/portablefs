//go:build linux

package fusev3

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

var testSelfSession = []byte("this-mount-0001x")

type recordedNotify struct {
	kind     string
	parent   uint64
	child    uint64
	name     string
	inode    uint64
	off      int64
	length   int64
	size     uint64
	sequence uint64
	version  uint64
	flags    uint32
	birthNS  int64
}

type fakeNotifier struct {
	mu       sync.Mutex
	calls    []recordedNotify
	deleteST fuse.Status
	entryST  fuse.Status
	inodeST  fuse.Status
	block    chan struct{}
	onDelete func()
	onInode  func(uint64, int64, int64)
	onEntry  func(uint64, string)
}

func (n *fakeNotifier) wait() {
	n.mu.Lock()
	block := n.block
	n.mu.Unlock()
	if block != nil {
		<-block
	}
}

func (n *fakeNotifier) record(call recordedNotify) {
	n.wait()
	n.mu.Lock()
	n.calls = append(n.calls, call)
	n.mu.Unlock()
}

func (n *fakeNotifier) InodeNotify(node uint64, off, length int64) fuse.Status {
	n.mu.Lock()
	hook := n.onInode
	n.mu.Unlock()
	if hook != nil {
		hook(node, off, length)
	}
	n.record(recordedNotify{kind: "inode", inode: node, off: off, length: length})
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.inodeST
}

func (n *fakeNotifier) EntryNotify(parent uint64, name string) fuse.Status {
	n.mu.Lock()
	hook := n.onEntry
	n.mu.Unlock()
	if hook != nil {
		hook(parent, name)
	}
	n.record(recordedNotify{kind: "entry", parent: parent, name: name})
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.entryST
}

func (n *fakeNotifier) DeleteNotify(parent, child uint64, name string) fuse.Status {
	n.mu.Lock()
	hook := n.onDelete
	n.mu.Unlock()
	if hook != nil {
		hook()
	}
	n.record(recordedNotify{kind: "delete", parent: parent, child: child, name: name})
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.deleteST
}

func (n *fakeNotifier) snapshot() []recordedNotify {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]recordedNotify(nil), n.calls...)
}

type strictFixture struct {
	t      *testing.T
	raw    *rawFileSystem
	mount  *Mount
	rpc    *fakeRPC
	notify *fakeNotifier
	unique atomic.Uint64
}

func newStrictFixture(t *testing.T) *strictFixture {
	t.Helper()
	rpc := newFakeRPC()
	rpc.session = testSelfSession
	cfg := testConfig(8)
	cfg.Coherence = CoherenceStrict
	cfg.CachedNameCapacity = 32
	cfg.RepairBudget = 5 * time.Second
	mount := newMount(context.Background(), rpc, cfg)
	t.Cleanup(mount.cancel)
	root := &node{mount: mount, item: testItem(1, authoritypb.Attr_DIRECTORY, 0), requestTimeout: time.Second, maxRead: 64 * 1024, maxWrite: 64 * 1024}
	raw := newRawFileSystem(mount, root)
	notify := &fakeNotifier{}
	mount.setNotifier(notify)
	fixture := &strictFixture{t: t, raw: raw, mount: mount, rpc: rpc, notify: notify}
	fixture.unique.Store(2)
	return fixture
}

func (f *strictFixture) rawCall(call func(unique uint64) fuse.Status) fuse.Status {
	unique := f.unique.Add(2)
	status := call(unique)
	completeTestReply(f.t, f.raw, unique, fuse.OK)
	return status
}

func (f *strictFixture) lookup(t *testing.T, parentNode uint64, name string) *fuse.EntryOut {
	t.Helper()
	out := &fuse.EntryOut{}
	status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: parentNode}, name, out)
	})
	if !status.Ok() {
		t.Fatalf("LOOKUP %q = %v", name, status)
	}
	return out
}

func (f *strictFixture) rename(oldParent, newParent uint64, oldName, newName string, flags uint32) fuse.Status {
	return f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.Rename(nil, &fuse.RenameIn{InHeader: fuse.InHeader{Unique: unique, NodeId: oldParent}, Newdir: newParent, Flags: flags}, oldName, newName)
	})
}

func (f *strictFixture) openForData(t *testing.T, node uint64) *fuse.OpenOut {
	t.Helper()
	var out *fuse.OpenOut
	for attempt := 0; attempt < 2; attempt++ {
		out = &fuse.OpenOut{}
		status := f.rawCall(func(unique uint64) fuse.Status {
			return f.raw.Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: unique, NodeId: node}, Flags: 0}, out)
		})
		if !status.Ok() {
			t.Fatalf("OPEN %d = %v", attempt+1, status)
		}
	}
	if out.OpenFlags != fuse.FOPEN_KEEP_CACHE {
		t.Fatalf("warm OPEN flags = %#x, want KEEP_CACHE", out.OpenFlags)
	}
	return out
}
