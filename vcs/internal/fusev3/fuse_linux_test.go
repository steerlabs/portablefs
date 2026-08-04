//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
)

type fakeRPC struct {
	mu           sync.Mutex
	writes       []*authoritypb.WriteRequest
	setattrs     []*authoritypb.SetAttrRequest
	short        bool
	writeFailure syscall.Errno
	xattrValue   []byte
	xattrNames   [][]byte
	flushes      []*authoritypb.FlushRequest
	fileCloses   []*authoritypb.CloseRequest
	reads        int
	closes       int
	keepAliveErr syscall.Errno
}

var fakeSessionDone = make(chan struct{})

func (f *fakeRPC) Root() *authoritypb.Item      { return nil }
func (f *fakeRPC) IOLimits() (uint32, uint32)   { return 3, 3 }
func (f *fakeRPC) SessionLease() time.Duration  { return time.Minute }
func (f *fakeRPC) SessionDone() <-chan struct{} { return fakeSessionDone }
func (f *fakeRPC) SessionError() error          { return nil }
func (f *fakeRPC) Close() error {
	f.mu.Lock()
	f.closes++
	f.mu.Unlock()
	return nil
}
func (f *fakeRPC) CallRead(_ context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	f.mu.Lock()
	f.reads++
	value := cloneBytes(f.xattrValue)
	names := make([][]byte, len(f.xattrNames))
	for index, name := range f.xattrNames {
		names[index] = cloneBytes(name)
	}
	keepAliveErr := f.keepAliveErr
	if flush := request.GetFlush(); flush != nil {
		f.flushes = append(f.flushes, proto.Clone(flush).(*authoritypb.FlushRequest))
	}
	f.mu.Unlock()
	if request.GetKeepAlive() != nil && keepAliveErr != 0 {
		return &authoritypb.Response{Errno: int32(keepAliveErr)}, nil
	}
	if request.GetGetXattr() != nil {
		return &authoritypb.Response{Body: &authoritypb.Response_GetXattr{GetXattr: &authoritypb.GetXattrReply{Value: value}}}, nil
	}
	if request.GetListXattr() != nil {
		return &authoritypb.Response{Body: &authoritypb.Response_ListXattr{ListXattr: &authoritypb.ListXattrReply{Names: names}}}, nil
	}
	return &authoritypb.Response{}, nil
}
func (f *fakeRPC) CallMutation(_ context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if write := request.GetWrite(); write != nil {
		copy := &authoritypb.WriteRequest{Handle: cloneBytes(write.GetHandle()), Offset: write.GetOffset(), Data: cloneBytes(write.GetData()), Append: write.GetAppend()}
		f.writes = append(f.writes, copy)
		if f.writeFailure != 0 {
			return &authoritypb.Response{Errno: int32(f.writeFailure)}, nil
		}
		count := uint32(len(write.GetData()))
		response := &authoritypb.Response{Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{Count: count}}}
		if f.short {
			response.GetWrite().Count, response.Errno = 2, int32(syscall.ENOSPC)
		}
		return response, nil
	}
	if setattr := request.GetSetAttr(); setattr != nil {
		f.setattrs = append(f.setattrs, setattr)
		return &authoritypb.Response{PostAttr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Mode: 0o600}}, nil
	}
	if closeRequest := request.GetClose(); closeRequest != nil {
		f.fileCloses = append(f.fileCloses, proto.Clone(closeRequest).(*authoritypb.CloseRequest))
		return &authoritypb.Response{}, nil
	}
	return &authoritypb.Response{}, nil
}

func TestMountOptionsDoNotEnableSharedMmap(t *testing.T) {
	options := mountOptions(Config{FSName: "test", MaxBackground: 8}, 64*1024)
	if options.ExtraCapabilities&fuse.CAP_DIRECT_IO_ALLOW_MMAP != 0 {
		t.Fatal("direct-I/O shared-mmap capability must remain disabled")
	}
	foundDefaultPermissions := false
	for _, option := range options.Options {
		foundDefaultPermissions = foundDefaultPermissions || option == "default_permissions"
	}
	if !foundDefaultPermissions {
		t.Fatal("kernel default_permissions enforcement must be enabled")
	}
}

func TestWriteUsesOneAuthorityMutation(t *testing.T) {
	rpc := new(fakeRPC)
	mount := &Mount{rpc: rpc}
	n := &node{mount: mount, requestTimeout: time.Second, maxWrite: 8}
	handle := &fileHandle{node: n, token: make([]byte, 16)}
	written, errno := n.Write(context.Background(), handle, []byte("abcdefg"), 10)
	if errno != 0 || written != 7 {
		t.Fatalf("Write = (%d, %v), want (7, 0)", written, errno)
	}
	if len(rpc.writes) != 1 || rpc.writes[0].GetOffset() != 10 || !bytes.Equal(rpc.writes[0].GetData(), []byte("abcdefg")) {
		t.Fatalf("authority writes = %#v", rpc.writes)
	}
}

func TestWriteRejectsRequestBeyondNegotiatedLimit(t *testing.T) {
	rpc := new(fakeRPC)
	n := &node{mount: &Mount{rpc: rpc}, requestTimeout: time.Second, maxWrite: 3}
	written, errno := n.Write(context.Background(), &fileHandle{node: n, token: make([]byte, 16)}, []byte("abcdefg"), 10)
	if written != 0 || errno != syscall.EIO {
		t.Fatalf("oversized Write = (%d, %v), want (0, EIO)", written, errno)
	}
	if len(rpc.writes) != 0 {
		t.Fatalf("oversized write reached authority: %#v", rpc.writes)
	}
}

func TestAppendNeverSynthesizesEOFOffset(t *testing.T) {
	rpc := new(fakeRPC)
	mount := &Mount{rpc: rpc}
	n := &node{mount: mount, requestTimeout: time.Second, maxWrite: 8}
	handle := &fileHandle{node: n, token: make([]byte, 16), append: true}
	written, errno := n.Write(context.Background(), handle, []byte("abcdef"), 999)
	if errno != 0 || written != 6 {
		t.Fatalf("Write append = (%d, %v)", written, errno)
	}
	if len(rpc.writes) != 1 || !rpc.writes[0].GetAppend() || rpc.writes[0].GetOffset() != 0 || !bytes.Equal(rpc.writes[0].GetData(), []byte("abcdef")) {
		t.Fatalf("append requests = %#v", rpc.writes)
	}
}

func TestPositiveShortWritePreservesProgress(t *testing.T) {
	rpc := &fakeRPC{short: true}
	n := &node{mount: &Mount{rpc: rpc}, requestTimeout: time.Second, maxWrite: 4}
	written, errno := n.Write(context.Background(), &fileHandle{node: n, token: make([]byte, 16)}, []byte("data"), 0)
	if written != 2 || errno != 0 {
		t.Fatalf("short Write = (%d, %v), want positive progress", written, errno)
	}
}

func TestZeroProgressWritePreservesAuthorityErrno(t *testing.T) {
	rpc := &fakeRPC{writeFailure: syscall.ENOSPC}
	n := &node{mount: &Mount{rpc: rpc}, requestTimeout: time.Second, maxWrite: 4}
	written, errno := n.Write(context.Background(), &fileHandle{node: n, token: make([]byte, 16)}, []byte("data"), 0)
	if written != 0 || errno != syscall.ENOSPC {
		t.Fatalf("failed Write = (%d, %v), want (0, ENOSPC)", written, errno)
	}
	if len(rpc.writes) != 1 {
		t.Fatalf("authority writes = %d, want 1", len(rpc.writes))
	}
}

func TestGetxattrSupportsSizeProbe(t *testing.T) {
	rpc := &fakeRPC{xattrValue: []byte("value")}
	n := &node{mount: &Mount{rpc: rpc}, item: &authoritypb.Item{Token: make([]byte, 16)}, requestTimeout: time.Second}
	if size, errno := n.Getxattr(context.Background(), "user.test", nil); size != 5 || errno != 0 {
		t.Fatalf("Getxattr probe = (%d, %v), want (5, 0)", size, errno)
	}
	if size, errno := n.Getxattr(context.Background(), "user.test", make([]byte, 4)); size != 5 || errno != syscall.ERANGE {
		t.Fatalf("Getxattr short buffer = (%d, %v), want (5, ERANGE)", size, errno)
	}
	dest := make([]byte, 5)
	if size, errno := n.Getxattr(context.Background(), "user.test", dest); size != 5 || errno != 0 || !bytes.Equal(dest, []byte("value")) {
		t.Fatalf("Getxattr value = (%d, %v, %q)", size, errno, dest)
	}
}

func TestListxattrSupportsSizeProbe(t *testing.T) {
	rpc := &fakeRPC{xattrNames: [][]byte{[]byte("user.a"), []byte("user.bb")}}
	n := &node{mount: &Mount{rpc: rpc}, item: &authoritypb.Item{Token: make([]byte, 16)}, requestTimeout: time.Second}
	want := []byte("user.a\x00user.bb\x00")
	if size, errno := n.Listxattr(context.Background(), nil); size != uint32(len(want)) || errno != 0 {
		t.Fatalf("Listxattr probe = (%d, %v), want (%d, 0)", size, errno, len(want))
	}
	if size, errno := n.Listxattr(context.Background(), make([]byte, len(want)-1)); size != uint32(len(want)) || errno != syscall.ERANGE {
		t.Fatalf("Listxattr short buffer = (%d, %v), want (%d, ERANGE)", size, errno, len(want))
	}
	dest := make([]byte, len(want))
	if size, errno := n.Listxattr(context.Background(), dest); size != uint32(len(want)) || errno != 0 || !bytes.Equal(dest, want) {
		t.Fatalf("Listxattr value = (%d, %v, %q)", size, errno, dest)
	}
}

func TestSetattrProjectsSinglePrincipal(t *testing.T) {
	rpc := new(fakeRPC)
	n := &node{mount: &Mount{rpc: rpc, uid: 501, gid: 20}, item: &authoritypb.Item{Token: make([]byte, 16)}, requestTimeout: time.Second}
	in := &fuse.SetAttrIn{}
	in.Valid = fuse.FATTR_UID | fuse.FATTR_GID | fuse.FATTR_MODE
	in.Uid, in.Gid, in.Mode = 501, 20, 0o600
	if errno := n.Setattr(context.Background(), nil, in, &fuse.AttrOut{}); errno != 0 {
		t.Fatal(errno)
	}
	if len(rpc.setattrs) != 1 || rpc.setattrs[0].Uid != nil || rpc.setattrs[0].Gid != nil || rpc.setattrs[0].GetMode() != 0o600 {
		t.Fatalf("projected setattr = %#v", rpc.setattrs)
	}
	in.Uid = 502
	if errno := n.Setattr(context.Background(), nil, in, &fuse.AttrOut{}); errno != syscall.EPERM {
		t.Fatalf("foreign chown errno = %v, want EPERM", errno)
	}
}

func TestSetattrPreservesServerClockNowIntent(t *testing.T) {
	rpc := new(fakeRPC)
	n := &node{mount: &Mount{rpc: rpc, uid: 501, gid: 20}, item: &authoritypb.Item{Token: make([]byte, 16)}, requestTimeout: time.Second}
	in := &fuse.SetAttrIn{}
	in.Valid = fuse.FATTR_ATIME_NOW | fuse.FATTR_MTIME_NOW
	if errno := n.Setattr(context.Background(), nil, in, &fuse.AttrOut{}); errno != 0 {
		t.Fatal(errno)
	}
	if len(rpc.setattrs) != 1 {
		t.Fatalf("setattr calls = %d, want 1", len(rpc.setattrs))
	}
	request := rpc.setattrs[0]
	if !request.GetAtimeNow() || !request.GetMtimeNow() || request.AtimeNs != nil || request.MtimeNs != nil {
		t.Fatalf("server-clock setattr intent lost: %#v", request)
	}
}

func TestFlushAndReleaseCarryKernelLockOwners(t *testing.T) {
	rpc := new(fakeRPC)
	n := &node{mount: &Mount{rpc: rpc}, item: &authoritypb.Item{Token: make([]byte, 16)}, requestTimeout: time.Second}
	handle := &fileHandle{node: n, token: make([]byte, 16)}
	if errno := n.Flush(context.Background(), handle, 41); errno != 0 {
		t.Fatal(errno)
	}
	if errno := handle.close(context.Background(), 42, true); errno != 0 {
		t.Fatal(errno)
	}
	rpc.mu.Lock()
	defer rpc.mu.Unlock()
	if len(rpc.flushes) != 1 || rpc.flushes[0].GetLockOwner() != 41 {
		t.Fatalf("flush lock owner = %#v", rpc.flushes)
	}
	if len(rpc.fileCloses) != 1 || rpc.fileCloses[0].GetLockOwner() != 42 || !rpc.fileCloses[0].GetFlockUnlock() {
		t.Fatalf("release flock owner = %#v", rpc.fileCloses)
	}
}

func TestLockRequestPreservesFlockNamespace(t *testing.T) {
	spec := lockRequest(make([]byte, 16), 7, &fuse.FileLock{Typ: syscall.F_WRLCK, End: ^uint64(0)}, fuse.FUSE_LK_FLOCK)
	if !spec.GetFlock() || !spec.GetWrite() || spec.GetOwner() != 7 {
		t.Fatalf("flock request = %#v", spec)
	}
}

func TestUncertainResponseFailsClosed(t *testing.T) {
	if got := responseErrno(&authoritypb.Response{Uncertain: true}); got != syscall.EIO {
		t.Fatalf("uncertain errno = %v", got)
	}
}

func TestRawInodeInterningReclaimsEveryCapabilityExactlyOnce(t *testing.T) {
	frontend, mount, rpc := testRawFileSystem(t, 64)
	const lookups = 64
	records := make([]*inodeRecord, lookups)
	var wg sync.WaitGroup
	for index := range lookups {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			item := testItem(42, authoritypb.Attr_REGULAR, uint64(index+1))
			var ok bool
			records[index], ok = frontend.intern(item)
			if !ok {
				t.Errorf("intern %d failed", index)
			}
		}(index)
	}
	wg.Wait()
	first := records[0]
	for index, record := range records {
		if record == nil || record.id != first.id {
			t.Fatalf("record %d = %#v, want NodeID %d", index, record, first.id)
		}
	}
	frontend.Forget(first.id, lookups)
	seen := make(map[string]bool, lookups)
	for range lookups {
		select {
		case token := <-mount.reclaim:
			seen[string(token)] = true
		default:
			t.Fatalf("reclaims = %d, want %d", len(seen), lookups)
		}
	}
	if len(seen) != lookups {
		t.Fatalf("unique reclaimed capabilities = %d, want %d", len(seen), lookups)
	}
	rpc.mu.Lock()
	reads := rpc.reads
	rpc.mu.Unlock()
	if reads != 0 {
		t.Fatalf("FORGET performed %d RPC reads", reads)
	}
}

func TestForgetCannotReclaimCapabilityUsedByInflightOperation(t *testing.T) {
	frontend, mount, _ := testRawFileSystem(t, 4)
	oldRecord, ok := frontend.intern(testItem(42, authoritypb.Attr_REGULAR, 1))
	if !ok {
		t.Fatal("intern old record")
	}
	inflight := frontend.acquire(oldRecord.id)
	if inflight == nil {
		t.Fatal("acquire old record")
	}
	frontend.Forget(oldRecord.id, 1)
	if len(mount.reclaim) != 0 {
		t.Fatal("FORGET reclaimed a capability still used by an operation")
	}
	newRecord, ok := frontend.intern(testItem(42, authoritypb.Attr_REGULAR, 2))
	if !ok || newRecord.id == oldRecord.id {
		t.Fatalf("replacement record = %#v, old NodeID %d", newRecord, oldRecord.id)
	}
	frontend.release(inflight)
	if got := <-mount.reclaim; !bytes.Equal(got, testToken(1)) {
		t.Fatalf("reclaimed token = %x, want old token", got)
	}
	frontend.Forget(newRecord.id, 1)
	if got := <-mount.reclaim; !bytes.Equal(got, testToken(2)) {
		t.Fatalf("reclaimed token = %x, want replacement token", got)
	}
}

func TestOpenHandlePinsForgottenInode(t *testing.T) {
	frontend, mount, _ := testRawFileSystem(t, 2)
	record, ok := frontend.intern(testItem(42, authoritypb.Attr_REGULAR, 1))
	if !ok {
		t.Fatal("intern")
	}
	handle := &fileHandle{node: record.node, token: testToken(100)}
	id, ok := frontend.addHandle(record, &handleRecord{file: handle})
	if !ok {
		t.Fatal("add handle")
	}
	frontend.Forget(record.id, 1)
	if len(mount.reclaim) != 0 || frontend.acquire(record.id) == nil {
		t.Fatal("forgotten inode was not retained by its open handle")
	}
	frontend.release(record)
	taken, ok := frontend.takeHandle(id, false)
	if !ok {
		t.Fatal("take handle")
	}
	frontend.unpin(taken.inode)
	if got := <-mount.reclaim; !bytes.Equal(got, testToken(1)) {
		t.Fatalf("reclaimed token = %x", got)
	}
}

func TestReleaseWaitsForInflightHandleOperation(t *testing.T) {
	frontend, _, _ := testRawFileSystem(t, 2)
	record, ok := frontend.intern(testItem(42, authoritypb.Attr_REGULAR, 1))
	if !ok {
		t.Fatal("intern")
	}
	id, ok := frontend.addHandle(record, &handleRecord{file: &fileHandle{node: record.node, token: testToken(100)}})
	if !ok {
		t.Fatal("add handle")
	}
	operation, handle := frontend.acquireFileHandle(id)
	if handle == nil {
		t.Fatal("acquire handle operation")
	}
	released := make(chan *handleRecord, 1)
	go func() {
		taken, _ := frontend.takeHandle(id, false)
		released <- taken
	}()
	select {
	case <-released:
		t.Fatal("release passed an in-flight handle operation")
	case <-time.After(20 * time.Millisecond):
	}
	frontend.releaseHandleOperation(operation)
	select {
	case taken := <-released:
		frontend.unpin(taken.inode)
	case <-time.After(time.Second):
		t.Fatal("release did not resume after operation completed")
	}
}

func TestReclaimQueueOverflowAbortsSession(t *testing.T) {
	_, mount, _ := testRawFileSystem(t, 1)
	if !mount.enqueueReclaim(testToken(1)) {
		t.Fatal("first reclaim unexpectedly failed")
	}
	if mount.enqueueReclaim(testToken(2)) {
		t.Fatal("overflowing reclaim unexpectedly succeeded")
	}
	select {
	case <-mount.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("reclaim overflow did not abort mount session")
	}
}

func TestKeepAliveFailureAbortsSession(t *testing.T) {
	_, mount, rpc := testRawFileSystem(t, 1)
	rpc.keepAliveErr = syscall.EIO
	mount.wg.Add(1)
	go mount.keepAlive(mount.ctx, 15*time.Millisecond)
	select {
	case <-mount.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("keepalive failure did not abort mount session")
	}
}

func TestTerminalSessionSignalAbortsMount(t *testing.T) {
	_, mount, _ := testRawFileSystem(t, 1)
	done := make(chan struct{})
	mount.wg.Add(1)
	go mount.watchSession(mount.ctx, done)
	close(done)
	select {
	case <-mount.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("terminal session signal did not abort mount")
	}
}

func testRawFileSystem(t *testing.T, reclaimCapacity int) (*rawFileSystem, *Mount, *fakeRPC) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rpc := new(fakeRPC)
	mount := &Mount{rpc: rpc, ctx: ctx, cancel: cancel, reclaim: make(chan []byte, reclaimCapacity), uid: 501, gid: 20}
	root := &node{mount: mount, item: testItem(1, authoritypb.Attr_DIRECTORY, 0), requestTimeout: time.Second, maxRead: 64 * 1024, maxWrite: 64 * 1024}
	frontend := newRawFileSystem(mount, root)
	mount.frontend = frontend
	return frontend, mount, rpc
}

func testItem(inode uint64, kind authoritypb.Attr_Kind, tokenID uint64) *authoritypb.Item {
	return &authoritypb.Item{Token: testToken(tokenID), Attr: &authoritypb.Attr{Inode: inode, Kind: kind, Mode: 0o600}}
}

func testToken(id uint64) []byte {
	token := make([]byte, 16)
	binary.BigEndian.PutUint64(token[8:], id)
	return token
}
