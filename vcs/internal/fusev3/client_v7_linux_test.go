//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"sync"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func openV7Writer(t *testing.T, f *strictFixture, node uint64) *fuse.OpenOut {
	t.Helper()
	out := &fuse.OpenOut{}
	status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: unique, NodeId: node}, Flags: uint32(syscall.O_RDWR)}, out)
	})
	if status != fuse.OK {
		t.Fatalf("open writer: %v", status)
	}
	if out.OpenFlags&fuse.FOPEN_DIRECT_IO == 0 {
		t.Fatal("write description admitted kernel writeback")
	}
	return out
}

func writeV7(t *testing.T, f *strictFixture, node, handle uint64, offset uint64, data []byte) {
	t.Helper()
	status := f.rawCall(func(unique uint64) fuse.Status {
		count, status := f.raw.Write(nil, &fuse.WriteIn{InHeader: fuse.InHeader{Unique: unique, NodeId: node}, Fh: handle, Offset: offset, Size: uint32(len(data)), Flags: uint32(syscall.O_RDWR)}, data)
		if status == fuse.OK && count != uint32(len(data)) {
			t.Errorf("accepted %d/%d", count, len(data))
		}
		return status
	})
	if status != fuse.OK {
		t.Fatalf("write: %v", status)
	}
}

func TestV7FullWriteHolderReadAndGetattr(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "file")
	opened := openV7Writer(t, f, entry.NodeId)
	writeV7(t, f, entry.NodeId, opened.Fh, 4, []byte("new"))
	f.rpc.snapshot(func(rpc *fakeRPC) {
		if len(rpc.writes) != 0 {
			t.Fatal("FULL admission dispatched an authority write")
		}
	})
	status := f.rawCall(func(unique uint64) fuse.Status {
		result, status := f.raw.Read(nil, &fuse.ReadIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Fh: opened.Fh, Offset: 4, Size: 3}, make([]byte, 3))
		if status != fuse.OK {
			return status
		}
		defer result.Done()
		data, status := result.Bytes(make([]byte, 3))
		if !bytes.Equal(data, []byte("new")) {
			t.Errorf("overlay read %q", data)
		}
		return status
	})
	if status != fuse.OK {
		t.Fatalf("holder read: %v", status)
	}
	out := &fuse.AttrOut{}
	status = f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Flags_: fuse.FUSE_GETATTR_FH, Fh_: opened.Fh}, out)
	})
	if status != fuse.OK || out.Size != 7 {
		t.Fatalf("holder getattr = %v size %d", status, out.Size)
	}
}

func TestV7F4RenameFlushesBeforeMutation(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "before")
	opened := openV7Writer(t, f, entry.NodeId)
	writeV7(t, f, entry.NodeId, opened.Fh, 0, []byte("dirty"))
	var mu sync.Mutex
	var order []string
	f.rpc.mu.Lock()
	f.rpc.hook = func(request *authoritypb.Request) {
		mu.Lock()
		defer mu.Unlock()
		if request.GetWrite() != nil {
			order = append(order, "write")
		}
		if request.GetRename() != nil {
			order = append(order, "rename")
		}
	}
	f.rpc.mu.Unlock()
	if status := f.rename(1, 1, "before", "after", 0); status != fuse.OK {
		t.Fatalf("rename: %v", status)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "write" || order[1] != "rename" {
		t.Fatalf("dependency order: %v", order)
	}
}

func TestV7RootDirectoryBarrierLossSinceOpen(t *testing.T) {
	f := newStrictFixture(t)
	root := &fuse.OpenOut{}
	if status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.OpenDir(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: unique, NodeId: 1}}, root)
	}); status != fuse.OK {
		t.Fatal(status)
	}
	entry := f.lookup(t, 1, "file")
	opened := openV7Writer(t, f, entry.NodeId)
	writeV7(t, f, entry.NodeId, opened.Fh, 0, []byte("unrecoverable"))
	if err := f.mount.delegations.DropIdentity(f.rpc.item.GetStableIdentity(), "test forced loss"); err != nil {
		t.Fatal(err)
	}
	status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.FsyncDir(nil, &fuse.FsyncIn{InHeader: fuse.InHeader{Unique: unique, NodeId: 1}, Fh: root.Fh})
	})
	if status != fuse.EIO {
		t.Fatalf("barrier after loss = %v, want EIO", status)
	}
	if f.mount.revoked.Load() {
		t.Fatal("loss aborted the mount")
	}
	// A directory opened after the loss observes a new baseline.
	record, handle := f.raw.acquireDirHandle(root.Fh)
	if handle == nil {
		t.Fatal("lost root handle")
	}
	defer f.raw.releaseHandleOperation(record)
	if handle.barrierLoss == f.mount.delegations.LossSequence() {
		t.Fatal("directory baseline advanced retroactively")
	}
	if err := f.mount.delegations.Barrier(context.Background(), f.mount.delegations.LossSequence()); err != nil {
		t.Fatalf("new baseline barrier: %v", err)
	}
}

func TestV7PeerOpenHonorsAuthorityCacheRefusal(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "delegated")
	f.rpc.mu.Lock()
	f.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetOpen() == nil || !request.GetOpen().GetCacheCapable() || request.GetOpen().GetWriteIntent() {
			t.Errorf("unexpected read open intent: %v", request)
		}
		return &authoritypb.Response{VolumeVersion: 2, Body: &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: testToken(901), CacheCapable: false}}}, nil
	}
	f.rpc.mu.Unlock()
	out := &fuse.OpenOut{}
	status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, out)
	})
	if status != fuse.OK || out.OpenFlags != fuse.FOPEN_DIRECT_IO {
		t.Fatalf("peer delegated read open = %v flags %#x", status, out.OpenFlags)
	}
}

func TestV7AcceptedWriteInvalidatesLocalCacheableReadHandle(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "file")
	f.openForData(t, entry.NodeId)
	writer := openV7Writer(t, f, entry.NodeId)
	f.notify.mu.Lock()
	f.notify.calls = nil
	f.notify.mu.Unlock()
	writeV7(t, f, entry.NodeId, writer.Fh, 5, []byte("abcd"))
	f.notify.mu.Lock()
	defer f.notify.mu.Unlock()
	matched := 0
	for _, call := range f.notify.calls {
		if call.kind == "inode" && call.inode == entry.NodeId && call.off == 5 && call.length == 4 {
			matched++
		}
	}
	if matched != 1 {
		t.Fatalf("accepted write range notifications = %d, calls=%+v", matched, f.notify.calls)
	}
}

func TestV7SetattrUsesCurrentDelegationBase(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "file")
	opened := openV7Writer(t, f, entry.NodeId)
	f.rpc.mu.Lock()
	f.rpc.item.Attr.Size = 41
	f.rpc.mu.Unlock()
	out := &fuse.AttrOut{}
	status := f.rawCall(func(unique uint64) fuse.Status {
		in := &fuse.SetAttrIn{}
		in.Unique, in.NodeId, in.Fh = unique, entry.NodeId, opened.Fh
		in.Valid, in.Mode = fuse.FATTR_MODE|fuse.FATTR_FH, 0o640
		return f.raw.SetAttr(nil, in, out)
	})
	if status != fuse.OK || out.Size != 41 || out.Mode&0o777 != 0o640 {
		t.Fatalf("setattr current base: status=%v size=%d mode=%o", status, out.Size, out.Mode)
	}
}
