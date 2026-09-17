//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

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
	for _, kind := range []string{"rename", "unlink", "link", "evicted-unlink"} {
		t.Run(kind, func(t *testing.T) {
			f := newStrictFixture(t)
			entry := f.lookup(t, 1, "before")
			opened := openV7Writer(t, f, entry.NodeId)
			writeV7(t, f, entry.NodeId, opened.Fh, 0, []byte("dirty"))
			if kind == "evicted-unlink" {
				f.raw.mu.Lock()
				parent := f.raw.nodesByID[1]
				f.raw.dropCachedNameLocked(nameKey{parent: parent.key.inode, name: "before"})
				f.raw.mu.Unlock()
			}
			var mu sync.Mutex
			var order []string
			f.rpc.mu.Lock()
			f.rpc.hook = func(request *authoritypb.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch {
				case request.GetWrite() != nil:
					order = append(order, "write")
				case request.GetRename() != nil:
					order = append(order, "rename")
				case request.GetUnlink() != nil:
					order = append(order, "unlink")
				case request.GetLink() != nil:
					order = append(order, "link")
				case request.GetLookup() != nil && kind == "evicted-unlink":
					order = append(order, "lookup")
				}
			}
			f.rpc.mu.Unlock()
			var status fuse.Status
			switch kind {
			case "rename":
				status = f.rename(1, 1, "before", "after", 0)
			case "unlink", "evicted-unlink":
				status = f.rawCall(func(unique uint64) fuse.Status {
					return f.raw.Unlink(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "before")
				})
			case "link":
				status = f.rawCall(func(unique uint64) fuse.Status {
					return f.raw.Link(nil, &fuse.LinkIn{InHeader: fuse.InHeader{Unique: unique, NodeId: 1}, Oldnodeid: entry.NodeId}, "after", &fuse.EntryOut{})
				})
			}
			if status != fuse.OK {
				t.Fatalf("namespace operation=%v", status)
			}
			want := []string{"write", kind}
			if kind == "evicted-unlink" {
				want = []string{"lookup", "write", "unlink"}
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(order, want) {
				t.Fatalf("dependency order=%v, want %v", order, want)
			}
		})
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

func TestV7BufferedWritePublishesImplicitTimesBeforeFlush(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.item.Attr.MtimeNs, f.rpc.item.Attr.CtimeNs = 11, 12
	entry := f.lookup(t, 1, "file")
	opened := openV7Writer(t, f, entry.NodeId)
	before := time.Now().UnixNano()
	writeV7(t, f, entry.NodeId, opened.Fh, 0, []byte("new"))
	after := time.Now().UnixNano()
	out := &fuse.AttrOut{}
	if status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Flags_: fuse.FUSE_GETATTR_FH, Fh_: opened.Fh}, out)
	}); status != fuse.OK {
		t.Fatal(status)
	}
	mtime, ctime := int64(out.Mtime)*1e9+int64(out.Mtimensec), int64(out.Ctime)*1e9+int64(out.Ctimensec)
	if mtime < before || mtime > after || ctime != mtime {
		t.Fatalf("accepted write times: mtime=%d ctime=%d range=[%d,%d]", mtime, ctime, before, after)
	}
	f.rpc.snapshot(func(rpc *fakeRPC) {
		if len(rpc.writes) != 0 {
			t.Fatal("implicit timestamps forced a write RPC")
		}
	})
}

func TestV7BufferedWritePreservesKernelFlagsAndLockOwner(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.item.Attr.Mode = 0o6755
	entry := f.lookup(t, 1, "file")
	opened := openV7Writer(t, f, entry.NodeId)
	flags := uint32(fuse.WRITE_KILL_SUIDGID | fuse.WRITE_LOCKOWNER)
	if status := f.rawCall(func(unique uint64) fuse.Status {
		_, status := f.raw.Write(nil, &fuse.WriteIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Fh: opened.Fh, Size: 3, WriteFlags: flags, LockOwner: 91, Flags: uint32(syscall.O_RDWR)}, []byte("new"))
		return status
	}); status != fuse.OK {
		t.Fatal(status)
	}
	out := &fuse.AttrOut{}
	if status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Flags_: fuse.FUSE_GETATTR_FH, Fh_: opened.Fh}, out)
	}); status != fuse.OK || out.Mode&0o7777 != 0o755 {
		t.Fatalf("buffered killpriv: %v mode=%o", status, out.Mode)
	}
	if status := f.rename(1, 1, "file", "after", 0); status != fuse.OK {
		t.Fatal(status)
	}
	f.rpc.snapshot(func(rpc *fakeRPC) {
		if len(rpc.writes) != 1 || rpc.writes[0].GetWriteFlags() != flags || rpc.writes[0].GetLockOwner() != 91 {
			t.Fatalf("flushed write metadata: %v", rpc.writes)
		}
	})
}

func TestV7FallocateCarriesExactDelegationReference(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, 1, "allocated")
	opened := openV7Writer(t, f, entry.NodeId)
	var captured *authoritypb.DelegationRef
	f.rpc.mu.Lock()
	f.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if allocation := request.GetFallocate(); allocation != nil {
			captured = cloneDelegationRef(allocation.GetDelegation())
			item := cloneItem(f.rpc.item)
			item.Attr.Size = 4096
			return &authoritypb.Response{VolumeVersion: 2, PostState: exactTestPostState(2, struct {
				item  *authoritypb.Item
				roles uint32
			}{item, postStateRoleTarget}), Body: &authoritypb.Response_Fallocate{Fallocate: &authoritypb.FallocateReply{Flags: rangeResultApplied, PostSize: 4096, VisibilitySequence: 2}}}, nil
		}
		return nil, syscall.EIO
	}
	f.rpc.mu.Unlock()
	status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.Fallocate(nil, &fuse.FallocateIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, Fh: opened.Fh, Length: 4096})
	})
	f.rpc.mu.Lock()
	f.rpc.replyOverride = nil
	f.rpc.mu.Unlock()
	if status != fuse.OK {
		t.Fatalf("fallocate=%v", status)
	}
	expected := testDelegation()
	if captured == nil || !bytes.Equal(captured.GetId(), expected.GetId()) || captured.GetGeneration() != expected.GetGeneration() {
		t.Fatalf("fallocate grant=%v, want %v", captured, expected)
	}
}

func TestV7CachedMetadataHasZeroValidityRPCsAndAllocations(t *testing.T) {
	for _, kind := range []string{"lookup", "getattr", "negative"} {
		t.Run(kind, func(t *testing.T) {
			f := newStrictFixture(t)
			if kind == "negative" {
				f.rpc.missingNames["cached"] = true
			}
			entry := f.lookup(t, 1, "cached")
			if entry.EntryValid != 0 || entry.EntryValidNsec != 0 || entry.AttrValid != 0 || entry.AttrValidNsec != 0 {
				t.Errorf("kernel entry/attribute validity must be zero: %+v", entry)
			}
			f.rpc.mu.Lock()
			before := f.rpc.calls
			f.rpc.mu.Unlock()
			var out fuse.EntryOut
			var attr fuse.AttrOut
			var status fuse.Status
			var badValidity bool
			allocs := testing.AllocsPerRun(1000, func() {
				unique := f.unique.Add(2)
				if kind == "getattr" {
					status = f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &attr)
					badValidity = badValidity || attr.AttrValid != 0 || attr.AttrValidNsec != 0
				} else {
					status = f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "cached", &out)
					badValidity = badValidity || out.AttrValid != 0 || out.AttrValidNsec != 0 || out.EntryValid != 0 || out.EntryValidNsec != 0
				}
				f.raw.PrepareReplyPayload(unique, 1, 1, nil, nil, 0)
				if f.raw.ReplyWriteTracked(unique) {
					f.raw.ReplyWritten(unique, fuse.OK)
				}
			})
			if status != fuse.OK || badValidity {
				t.Errorf("cached reply status=%v nonzero validity=%v", status, badValidity)
			}
			if allocs != 0 {
				t.Errorf("cached %s allocations=%g, want zero", kind, allocs)
			}
			f.rpc.mu.Lock()
			defer f.rpc.mu.Unlock()
			if f.rpc.calls != before {
				t.Errorf("cached metadata Authority calls=%d", f.rpc.calls-before)
			}
		})
	}
}

func TestV7CachedMetadataWithdrawalJoinsPhysicalReply(t *testing.T) {
	for _, kind := range []string{"lookup", "getattr", "negative"} {
		t.Run(kind, func(t *testing.T) {
			f := newStrictFixture(t)
			if kind == "negative" {
				f.rpc.missingNames["cached"] = true
			}
			entry := f.lookup(t, 1, "cached")
			unique := f.unique.Add(2)
			var status fuse.Status
			coordinate := publicationCoordinate{kind: publicationNamespaceName, parent: f.raw.nodesByID[1].identity, name: "cached"}
			if kind == "getattr" {
				coordinate = publicationCoordinate{kind: publicationItemAttributes, item: f.raw.nodesByID[entry.NodeId].identity}
				status = f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &fuse.AttrOut{})
			} else {
				status = f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "cached", &fuse.EntryOut{})
			}
			if status != fuse.OK {
				t.Fatal(status)
			}
			f.raw.mu.Lock()
			publication := f.raw.replyPublications[unique]
			if publication == nil || publication.cachedCount == 0 {
				f.raw.mu.Unlock()
				t.Fatal("cached reply escaped physical ownership")
			}
			if !f.raw.sourceCoordinateBusyLocked(coordinate, nil) {
				f.raw.mu.Unlock()
				t.Fatal("initiator gate omitted cached reply")
			}
			f.raw.mu.Unlock()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- f.raw.closeCacheCoordinate(ctx, coordinate) }()
			// Observe the withdrawal's locked cut, including its installed receipt.
			for {
				f.raw.mu.Lock()
				waiting := f.raw.repairingCoordinates[coordinate] && publication.originalDone != nil
				f.raw.mu.Unlock()
				if waiting {
					break
				}
				select {
				case err := <-done:
					t.Fatalf("withdrawal crossed unwritten reply: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				default:
				}
				time.Sleep(time.Millisecond)
			}
			select {
			case err := <-done:
				t.Fatalf("withdrawal crossed unwritten reply: %v", err)
			default:
			}
			f.raw.ReplyWritten(unique, fuse.OK)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			f.raw.mu.Lock()
			busy := f.raw.sourceCoordinateBusyLocked(coordinate, nil)
			f.raw.mu.Unlock()
			if busy {
				t.Fatal("physical reply left initiator gate busy")
			}
		})
	}
}

func TestV7CachedReplyTerminalizationWaitsForPhysicalWrite(t *testing.T) {
	f := newStrictFixture(t)
	f.lookup(t, 1, "cached")
	unique := f.unique.Add(2)
	if status := f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "cached", &fuse.EntryOut{}); status != fuse.OK {
		t.Fatal(status)
	}
	f.raw.mu.Lock()
	p := f.raw.replyPublications[unique]
	if p == nil || p.cachedCount == 0 || p.originalDone != nil {
		f.raw.mu.Unlock()
		t.Fatal("cached reply did not retain lazy ownership")
	}
	f.raw.mu.Unlock()
	if f.raw.terminalizeReplyCacheOwnership(time.Now()) {
		t.Fatal("terminalization passed an unwritten cached reply")
	}
	f.raw.ReplyWritten(unique, fuse.OK)
	if !f.raw.terminalizeReplyCacheOwnership(time.Now().Add(time.Second)) {
		t.Fatal("terminalization did not join written cached reply")
	}
	f.raw.mu.Lock()
	defer f.raw.mu.Unlock()
	if len(f.raw.replyPublications) != 0 {
		t.Fatal("terminalization retained cached reply ownership")
	}
}
