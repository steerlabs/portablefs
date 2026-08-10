//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

// fakeRPC is a programmable stand-in for the authority. It answers every
// request shape the frontend issues, so the real mount path -- including
// MountVolume -- is reachable without a kernel.
type fakeRPC struct {
	mu sync.Mutex

	writes     []*authoritypb.WriteRequest
	setattrs   []*authoritypb.SetAttrRequest
	flushes    []*authoritypb.FlushRequest
	fsyncs     []*authoritypb.FsyncRequest
	fileCloses []*authoritypb.CloseRequest
	readdirs   []*authoritypb.ReadDirRequest
	reclaims   [][]byte
	keepAlives int
	reads      int
	calls      int
	closes     int
	canceled   int

	short          bool
	writeFailure   syscall.Errno
	closeFailure   syscall.Errno
	mkdirFailure   syscall.Errno
	reclaimFailure syscall.Errno
	keepAliveErr   syscall.Errno
	xattrValue     []byte
	xattrNames     [][]byte
	fileData       []byte

	root *authoritypb.Item
	item *authoritypb.Item
	// byName, when non-nil, mints one distinct object per name so a test can
	// walk a volume path of several different directories. Without it every
	// lookup answers with the same object and a path has no shape.
	byName   map[string]*authoritypb.Item
	handle   []byte
	maxRead  uint32
	maxWrite uint32
	lease    time.Duration
	done     chan struct{}

	dirPages     []*authoritypb.ReadDirReply
	dirPageIndex int

	// The strict cache contract. events is the programmed visibility stream;
	// acked records every cursor the frontend acknowledged, which is what the
	// liveness assertions read.
	session        []byte
	initial        *authoritypb.VisibilityCursor
	events         chan *authoritypb.VisibilityEvent
	acked          []*authoritypb.VisibilityCursor
	blocked        []*authoritypb.VisibilityCursor
	blockedParents [][]uint64
	blockedErr     error
	// onBlocked models the authority's nonterminal cycle break: it refuses the
	// queued overlapping mutation before returning success to the report.
	onBlocked     func()
	detachProofs  []MountAbsenceProof
	detachErr     error
	visibilityErr error
	// mutationStates are attached, in order, to successful mutation responses.
	// afterMutation runs after the envelope has been attached but before the
	// response is returned to the frontend, allowing ordering tests to place a
	// raw callback precisely on either side of transport delivery.
	mutationStates []*authoritypb.MutationState
	mutationSeq    uint64
	afterMutation  func()

	// observeCancel makes every call wait briefly on its own context so a test
	// can prove whether the kernel's INTERRUPT reached the authority.
	observeCancel bool
	// block, when non-nil, holds every call except Detach until it is closed.
	block chan struct{}
	// hook runs outside the lock before a reply is produced.
	hook func(*authoritypb.Request)
}

func newFakeRPC() *fakeRPC {
	return &fakeRPC{
		root:     testItem(1, authoritypb.Attr_DIRECTORY, 1),
		item:     testItem(7, authoritypb.Attr_REGULAR, 7),
		handle:   testToken(900),
		maxRead:  64 * 1024,
		maxWrite: 64 * 1024,
		lease:    time.Minute,
		done:     make(chan struct{}),
	}
}

func (f *fakeRPC) Root() *authoritypb.Item      { return cloneItem(f.root) }
func (f *fakeRPC) IOLimits() (uint32, uint32)   { return f.maxRead, f.maxWrite }
func (f *fakeRPC) SessionLease() time.Duration  { return f.lease }
func (f *fakeRPC) SessionDone() <-chan struct{} { return f.done }
func (f *fakeRPC) SessionError() error          { return nil }

func (f *fakeRPC) Close() error {
	f.mu.Lock()
	f.closes++
	f.mu.Unlock()
	return nil
}

func (f *fakeRPC) CallRead(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	f.mu.Lock()
	f.reads++
	f.mu.Unlock()
	return f.dispatch(ctx, request)
}

func (f *fakeRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	response, err := f.dispatch(ctx, request)
	if err != nil || response == nil {
		return response, err
	}
	f.mu.Lock()
	if len(f.mutationStates) != 0 {
		response.Mutation = proto.Clone(f.mutationStates[0]).(*authoritypb.MutationState)
		f.mutationStates = f.mutationStates[1:]
	} else {
		f.mutationSeq++
		response.Mutation = &authoritypb.MutationState{Slot: 0, AcceptedSequence: f.mutationSeq}
	}
	after := f.afterMutation
	f.mu.Unlock()
	if after != nil {
		after()
	}
	return response, nil
}

func (f *fakeRPC) dispatch(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	f.mu.Lock()
	f.calls++
	block, observe, hook := f.block, f.observeCancel, f.hook
	f.mu.Unlock()
	// Detach is the shutdown path and is never held: closeLocked must be able
	// to end the session even when everything else is stalled.
	if request.GetDetach() == nil {
		if block != nil {
			select {
			case <-block:
			case <-ctx.Done():
				return nil, f.noteCancel(ctx)
			}
		}
		if observe {
			select {
			case <-ctx.Done():
				return nil, f.noteCancel(ctx)
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
	if hook != nil {
		hook(request)
	}
	return f.reply(request)
}

func (f *fakeRPC) noteCancel(ctx context.Context) error {
	f.mu.Lock()
	f.canceled++
	f.mu.Unlock()
	return ctx.Err()
}

func (f *fakeRPC) reply(request *authoritypb.Request) (*authoritypb.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case request.GetKeepAlive() != nil:
		f.keepAlives++
		if f.keepAliveErr != 0 {
			return &authoritypb.Response{Errno: int32(f.keepAliveErr)}, nil
		}
	case request.GetReclaim() != nil:
		f.reclaims = append(f.reclaims, cloneBytes(request.GetReclaim().GetItem()))
		if f.reclaimFailure != 0 {
			return &authoritypb.Response{Errno: int32(f.reclaimFailure)}, nil
		}
	case request.GetClose() != nil:
		f.fileCloses = append(f.fileCloses, proto.Clone(request.GetClose()).(*authoritypb.CloseRequest))
		if f.closeFailure != 0 {
			return &authoritypb.Response{Errno: int32(f.closeFailure)}, nil
		}
	case request.GetFlush() != nil:
		f.flushes = append(f.flushes, proto.Clone(request.GetFlush()).(*authoritypb.FlushRequest))
	case request.GetFsync() != nil:
		f.fsyncs = append(f.fsyncs, proto.Clone(request.GetFsync()).(*authoritypb.FsyncRequest))
	case request.GetGetXattr() != nil:
		return &authoritypb.Response{Body: &authoritypb.Response_GetXattr{GetXattr: &authoritypb.GetXattrReply{Value: cloneBytes(f.xattrValue)}}}, nil
	case request.GetListXattr() != nil:
		names := make([][]byte, len(f.xattrNames))
		for index, name := range f.xattrNames {
			names[index] = cloneBytes(name)
		}
		return &authoritypb.Response{Body: &authoritypb.Response_ListXattr{ListXattr: &authoritypb.ListXattrReply{Names: names}}}, nil
	case request.GetGetAttr() != nil:
		return &authoritypb.Response{Body: &authoritypb.Response_GetAttr{GetAttr: &authoritypb.GetAttrReply{Attr: cloneItem(f.item).GetAttr()}}}, nil
	case request.GetLookup() != nil:
		return &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: f.namedItem(request.GetLookup().GetName())}}}, nil
	case request.GetMkdir() != nil:
		if f.mkdirFailure != 0 {
			return &authoritypb.Response{Errno: int32(f.mkdirFailure)}, nil
		}
		return &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: f.namedItem(request.GetMkdir().GetName())}}}, nil
	case request.GetSymlink() != nil:
		return &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: f.namedItem(request.GetSymlink().GetName())}}}, nil
	case request.GetOpen() != nil:
		return &authoritypb.Response{Body: &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: cloneBytes(f.handle)}}}, nil
	case request.GetCreate() != nil:
		return &authoritypb.Response{Body: &authoritypb.Response_Create{Create: &authoritypb.CreateReply{Item: cloneItem(f.item), Handle: cloneBytes(f.handle)}}}, nil
	case request.GetRead() != nil:
		offset := int(request.GetRead().GetOffset())
		length := int(request.GetRead().GetLength())
		data := []byte(nil)
		if offset < len(f.fileData) {
			data = cloneBytes(f.fileData[offset:min(offset+length, len(f.fileData))])
		}
		return &authoritypb.Response{Body: &authoritypb.Response_Read{Read: &authoritypb.ReadReply{Data: data}}}, nil
	case request.GetReadDir() != nil:
		f.readdirs = append(f.readdirs, proto.Clone(request.GetReadDir()).(*authoritypb.ReadDirRequest))
		if f.dirPageIndex >= len(f.dirPages) {
			return &authoritypb.Response{Body: &authoritypb.Response_ReadDir{ReadDir: &authoritypb.ReadDirReply{Verifier: testToken(5), Eof: true}}}, nil
		}
		page := f.dirPages[f.dirPageIndex]
		f.dirPageIndex++
		return &authoritypb.Response{Body: &authoritypb.Response_ReadDir{ReadDir: proto.Clone(page).(*authoritypb.ReadDirReply)}}, nil
	case request.GetWrite() != nil:
		write := request.GetWrite()
		f.writes = append(f.writes, &authoritypb.WriteRequest{Handle: cloneBytes(write.GetHandle()), Offset: write.GetOffset(), Data: cloneBytes(write.GetData()), Append: write.GetAppend()})
		if f.writeFailure != 0 {
			return &authoritypb.Response{Errno: int32(f.writeFailure)}, nil
		}
		response := &authoritypb.Response{Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{Count: uint32(len(write.GetData()))}}}
		if f.short {
			response.GetWrite().Count, response.Errno = 2, int32(syscall.ENOSPC)
		}
		return response, nil
	case request.GetSetAttr() != nil:
		f.setattrs = append(f.setattrs, request.GetSetAttr())
		return &authoritypb.Response{PostAttr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Mode: 0o600}}, nil
	}
	return &authoritypb.Response{}, nil
}

// namedItem answers with the object this fake associates with one name. The
// caller holds f.mu.
func (f *fakeRPC) namedItem(name []byte) *authoritypb.Item {
	if f.byName == nil {
		return cloneItem(f.item)
	}
	if item, known := f.byName[string(name)]; known {
		return cloneItem(item)
	}
	inode := uint64(1000 + len(f.byName))
	item := testItem(inode, authoritypb.Attr_DIRECTORY, inode)
	f.byName[string(name)] = item
	return cloneItem(item)
}

func (f *fakeRPC) snapshot(read func(*fakeRPC)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	read(f)
}

func testConfig(watermark int) Config {
	return Config{
		MountInstanceID: "mnt_AAAAAAAAAAAAAAAAAAAAAA", RequestTimeout: 2 * time.Second,
		MaxBackground: 8, MaxInFlight: 16, ReclaimQueue: watermark,
		PresentedUID: 501, PresentedGID: 20,
	}
}

func testMount(t *testing.T, watermark int) (*Mount, *fakeRPC) {
	t.Helper()
	rpc := newFakeRPC()
	mount := newMount(context.Background(), rpc, testConfig(watermark))
	t.Cleanup(mount.cancel)
	return mount, rpc
}

func testRawFileSystem(t *testing.T, watermark int) (*rawFileSystem, *Mount, *fakeRPC) {
	t.Helper()
	mount, rpc := testMount(t, watermark)
	root := &node{mount: mount, item: testItem(1, authoritypb.Attr_DIRECTORY, 0), requestTimeout: time.Second, maxRead: 64 * 1024, maxWrite: 64 * 1024}
	return newRawFileSystem(mount, root), mount, rpc
}

func testNode(mount *Mount) *node {
	return &node{mount: mount, item: testItem(7, authoritypb.Attr_REGULAR, 7), requestTimeout: time.Second, maxRead: 64 * 1024, maxWrite: 64 * 1024}
}

func popReclaim(t *testing.T, mount *Mount) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	token, ok := mount.reclaim.pop(ctx)
	if !ok {
		t.Fatal("expected a queued reclaim")
	}
	return token
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func testItem(inode uint64, kind authoritypb.Attr_Kind, tokenID uint64) *authoritypb.Item {
	return &authoritypb.Item{Token: testToken(tokenID), Attr: &authoritypb.Attr{Inode: inode, Kind: kind, Mode: 0o600}}
}

func testToken(id uint64) []byte {
	token := make([]byte, 16)
	binary.BigEndian.PutUint64(token[8:], id)
	return token
}

// --- Defect 8: the direct-I/O decision is explicit and asserted -------------

func TestOpenAndCreateAlwaysReturnDirectIO(t *testing.T) {
	mount, _ := testMount(t, 8)
	n := testNode(mount)
	_, flags, errno := n.Open(context.Background(), syscall.O_RDONLY)
	if errno != 0 {
		t.Fatalf("Open errno = %v", errno)
	}
	if flags != fuse.FOPEN_DIRECT_IO {
		t.Fatalf("Open OpenFlags = %#x, want exactly FOPEN_DIRECT_IO", flags)
	}
	_, _, createFlags, errno := n.Create(context.Background(), "child", syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if errno != 0 {
		t.Fatalf("Create errno = %v", errno)
	}
	if createFlags != fuse.FOPEN_DIRECT_IO {
		t.Fatalf("Create OpenFlags = %#x, want exactly FOPEN_DIRECT_IO", createFlags)
	}
	if createFlags&fuse.FOPEN_KEEP_CACHE != 0 || flags&fuse.FOPEN_KEEP_CACHE != 0 {
		t.Fatal("FOPEN_KEEP_CACHE would let this kernel serve reads that never reached the authority")
	}
}

func TestMountOptionsRefuseSharedMmapAsADecision(t *testing.T) {
	options := mountOptions(testConfig(8), 64*1024)
	if options.DisabledCapabilities&fuse.CAP_DIRECT_IO_ALLOW_MMAP == 0 {
		t.Fatal("shared mmap over direct I/O must be disabled explicitly, not left to kernel defaults")
	}
	if options.ExtraCapabilities&fuse.CAP_DIRECT_IO_ALLOW_MMAP != 0 {
		t.Fatal("direct-I/O shared-mmap capability must never be requested")
	}
	if !options.EnableLocks || !options.DisableReadDirPlus || options.MaxWrite != 64*1024 || options.MaxReadAhead != 0 {
		t.Fatalf("mount options = %#v", options)
	}
	foundDefaultPermissions := false
	for _, option := range options.Options {
		foundDefaultPermissions = foundDefaultPermissions || option == "default_permissions"
	}
	if !foundDefaultPermissions {
		t.Fatal("kernel default_permissions enforcement must be enabled")
	}
	if err := verifyMountDecisions(options); err != nil {
		t.Fatalf("verifyMountDecisions rejected the shipped options: %v", err)
	}
	tampered := mountOptions(testConfig(8), 64*1024)
	tampered.DisabledCapabilities = 0
	if err := verifyMountDecisions(tampered); err == nil {
		t.Fatal("a mount that permits shared mmap must be refused")
	}
	tampered = mountOptions(testConfig(8), 64*1024)
	tampered.EnableLocks = false
	if err := verifyMountDecisions(tampered); err == nil {
		t.Fatal("a mount that does not forward locks must be refused")
	}
}

// --- Defect 7: the kernel must actually grant what the contract needs -------

func TestKernelGuaranteesRequireForwardedLocksAndRequestSize(t *testing.T) {
	settings := func(flags uint64) *fuse.InitIn {
		in := &fuse.InitIn{}
		in.Flags = uint32(flags)
		in.Flags2 = uint32(flags >> 32)
		return in
	}
	// A strict mount also needs a kernel that can receive invalidations, so
	// every case here advertises a protocol new enough for them; the notify
	// requirement has its own test.
	notifying := func(in *fuse.InitIn) *fuse.InitIn {
		in.Major, in.Minor = 7, 31
		return in
	}
	locks := uint64(fuse.CAP_POSIX_LOCKS | fuse.CAP_FLOCK_LOCKS)
	if err := verifyKernelGuarantees(notifying(settings(locks)), 64*1024, CoherenceStrict); err != nil {
		t.Fatalf("a lock-forwarding kernel was refused: %v", err)
	}
	if err := verifyKernelGuarantees(notifying(settings(fuse.CAP_POSIX_LOCKS)), 64*1024, CoherenceStrict); err == nil {
		t.Fatal("a kernel without CAP_FLOCK_LOCKS silently falls back to the local lock manager and must be refused")
	}
	if err := verifyKernelGuarantees(notifying(settings(fuse.CAP_FLOCK_LOCKS)), 64*1024, CoherenceStrict); err == nil {
		t.Fatal("a kernel without CAP_POSIX_LOCKS must be refused")
	}
	if err := verifyKernelGuarantees(nil, 64*1024, CoherenceStrict); err == nil {
		t.Fatal("unavailable INIT settings must be refused")
	}
	big := uint32(kernelDefaultMaxPages*syscall.Getpagesize()) + 1
	if err := verifyKernelGuarantees(notifying(settings(locks)), big, CoherenceStrict); err == nil {
		t.Fatal("a kernel that ignores MaxPages cannot carry the negotiated write size and must be refused")
	}
	if err := verifyKernelGuarantees(notifying(settings(locks|fuse.CAP_MAX_PAGES)), big, CoherenceStrict); err != nil {
		t.Fatalf("a CAP_MAX_PAGES kernel was refused: %v", err)
	}
}

// --- Defect 2: the coherence contract is pinned down -----------------------

func TestUncachedProfilePublishesNoLifetimeAtAll(t *testing.T) {
	raw, mount, _ := testRawFileSystem(t, 8)
	if mount.profile != CoherenceUncached {
		t.Fatalf("profile = %v, want uncached", mount.profile)
	}
	record, errno := raw.intern(context.Background(), testItem(5, authoritypb.Attr_REGULAR, 5))
	if errno != 0 {
		t.Fatal(errno)
	}
	out := &fuse.EntryOut{}
	out.SetEntryTimeout(time.Hour)
	out.SetAttrTimeout(time.Hour)
	raw.publishEntry(out, 1, "child", record, record.node.item.GetAttr())
	if out.EntryValid != 0 || out.EntryValidNsec != 0 || out.AttrValid != 0 || out.AttrValidNsec != 0 {
		t.Fatalf("uncached entry timeouts = (%d.%09d, %d.%09d); an uncached mount must publish nothing the kernel may reuse", out.EntryValid, out.EntryValidNsec, out.AttrValid, out.AttrValidNsec)
	}
	if len(raw.cachedNames) != 0 {
		t.Fatalf("uncached mount recorded %d cached names; it has no repair obligation and must record none", len(raw.cachedNames))
	}
	attrOut := &fuse.AttrOut{}
	attrOut.SetTimeout(time.Hour)
	if errno := testNode(mount).Getattr(context.Background(), nil, attrOut); errno != 0 {
		t.Fatal(errno)
	}
	if attrOut.AttrValid != 0 || attrOut.AttrValidNsec != 0 {
		t.Fatalf("uncached GETATTR timeout = %d.%09d, want 0", attrOut.AttrValid, attrOut.AttrValidNsec)
	}
}

// --- Defect 1: cleanup pressure throttles, it does not destroy the mount ----

func TestCleanupPressureThrottlesInterningAndNeverDestroysTheMount(t *testing.T) {
	frontend, mount, _ := testRawFileSystem(t, 2)
	// FORGET produces cleanup debt without any admission at all, so it can and
	// does push the backlog past the watermark. That must never be fatal.
	for id := uint64(1); id <= 3; id++ {
		mount.deferReclaim(testToken(id))
	}
	if mount.ctx.Err() != nil || mount.fatalError() != nil {
		t.Fatalf("cleanup pressure destroyed the mount: %v", mount.fatalError())
	}
	if got := mount.reclaim.pending(); got != 3 {
		t.Fatalf("backlog = %d, want 3 (no capability may ever be discarded)", got)
	}
	interned := make(chan syscall.Errno, 1)
	go func() {
		_, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_REGULAR, 10))
		interned <- errno
	}()
	select {
	case errno := <-interned:
		t.Fatalf("intern completed without backpressure (errno %v)", errno)
	case <-time.After(75 * time.Millisecond):
	}
	popReclaim(t, mount)
	popReclaim(t, mount)
	select {
	case errno := <-interned:
		if errno != 0 {
			t.Fatalf("throttled intern = %v, want success once the backlog drained", errno)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("intern never resumed after the backlog drained")
	}
	if mount.ctx.Err() != nil || mount.fatalError() != nil {
		t.Fatalf("mount aborted under ordinary cleanup pressure: %v", mount.fatalError())
	}
}

func TestForgetNeverBlocksUnderCleanupPressure(t *testing.T) {
	frontend, mount, _ := testRawFileSystem(t, 1)
	records := make([]*inodeRecord, 0, 64)
	for id := uint64(1); id <= 64; id++ {
		record, errno := frontend.intern(context.Background(), testItem(id, authoritypb.Attr_REGULAR, id))
		if errno != 0 {
			t.Fatalf("intern %d = %v", id, errno)
		}
		records = append(records, record)
		// Drain immediately so interning is never itself throttled here; the
		// point of this test is FORGET, which must not block even at watermark.
		if mount.reclaim.pending() > 0 {
			popReclaim(t, mount)
		}
	}
	done := make(chan struct{})
	go func() {
		for _, record := range records {
			frontend.Forget(record.id, 1)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("FORGET blocked; go-fuse spawns no replacement reader for it, so the whole request loop would stall")
	}
	if mount.ctx.Err() != nil || mount.fatalError() != nil {
		t.Fatalf("FORGET storm destroyed the mount: %v", mount.fatalError())
	}
	if got := mount.reclaim.pending(); got != len(records) {
		t.Fatalf("queued reclaims = %d, want %d", got, len(records))
	}
}

func TestReclaimDrainIsConcurrent(t *testing.T) {
	mount, rpc := testMount(t, 1024)
	width := mount.reclaimWorkers
	if width < 2 {
		t.Fatalf("reclaim lane width = %d, want at least 2", width)
	}
	reached := make(chan struct{}, width)
	release := make(chan struct{})
	rpc.hook = func(request *authoritypb.Request) {
		if request.GetReclaim() == nil {
			return
		}
		reached <- struct{}{}
		<-release
	}
	for id := uint64(1); id <= uint64(width); id++ {
		mount.deferReclaim(testToken(id))
	}
	mount.start(time.Hour)
	defer func() {
		close(release)
		_ = mount.Close()
	}()
	for count := 0; count < width; count++ {
		select {
		case <-reached:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of %d reclaims were in flight at once; a serial drain cannot keep up with ordinary path walking", count, width)
		}
	}
}

// --- Defect 3: a cancelled shutdown is not a fatal error -------------------

func TestCancelledShutdownIsNotReportedAsFailure(t *testing.T) {
	mount, rpc := testMount(t, 64)
	rpc.block = make(chan struct{})
	mount.start(time.Hour)
	for id := uint64(1); id <= 8; id++ {
		mount.deferReclaim(testToken(id))
	}
	waitFor(t, "a reclaim to be in flight", func() bool {
		blocked := false
		rpc.snapshot(func(f *fakeRPC) { blocked = f.calls > 0 })
		return blocked
	})
	if err := mount.Close(); err != nil {
		t.Fatalf("clean shutdown reported a fatal error: %v", err)
	}
	if err := mount.fatalError(); err != nil {
		t.Fatalf("shutdown recorded a fatal error: %v", err)
	}
}

func TestCancelledKeepAliveIsNotReportedAsFailure(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.block = make(chan struct{})
	mount.wg.Add(1)
	go mount.keepAlive(mount.ctx, 15*time.Millisecond)
	waitFor(t, "a keepalive to be in flight", func() bool {
		started := false
		rpc.snapshot(func(f *fakeRPC) { started = f.calls > 0 })
		return started
	})
	mount.cancel()
	mount.wg.Wait()
	if err := mount.fatalError(); err != nil {
		t.Fatalf("a keepalive cancelled by shutdown was reported as an authority failure: %v", err)
	}
}

// --- Defect 4: INTERRUPT never reaches the authority -----------------------

func TestKernelInterruptNeitherCancelsTheMutationNorTearsDownTheMount(t *testing.T) {
	frontend, mount, rpc := testRawFileSystem(t, 8)
	rpc.observeCancel = true
	interrupt := make(chan struct{})
	close(interrupt)
	input := &fuse.MkdirIn{Mode: 0o755}
	input.NodeId = fuse.FUSE_ROOT_ID
	if status := frontend.Mkdir(interrupt, input, "child", &fuse.EntryOut{}); status != fuse.OK {
		t.Fatalf("interrupted mkdir = %v, want OK; FUSE permits ignoring INTERRUPT and this path must", status)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if f.canceled != 0 {
			t.Fatalf("the kernel INTERRUPT reached %d authority call(s); a cancelled mutation poisons the session and unmounts the volume", f.canceled)
		}
	})
	if mount.ctx.Err() != nil || mount.fatalError() != nil {
		t.Fatalf("INTERRUPT tore the mount down: %v", mount.fatalError())
	}
}

// --- Defect 6: a timeout is not an interrupt -------------------------------

func TestRequestTimeoutIsNeverReportedAsEINTR(t *testing.T) {
	if got := rpcErrno(nil, context.DeadlineExceeded); got != syscall.ETIMEDOUT {
		t.Fatalf("deadline errno = %v, want ETIMEDOUT; EINTR makes applications retry forever", got)
	}
	if got := rpcErrno(nil, fmt.Errorf("call: %w", context.DeadlineExceeded)); got != syscall.ETIMEDOUT {
		t.Fatalf("wrapped deadline errno = %v, want ETIMEDOUT", got)
	}
	if got := rpcErrno(nil, context.Canceled); got != syscall.ENOTCONN {
		t.Fatalf("cancelled errno = %v, want ENOTCONN", got)
	}
	if got := rpcErrno(nil, errors.New("transport")); got != syscall.EIO {
		t.Fatalf("transport errno = %v, want EIO", got)
	}
	mount, rpc := testMount(t, 8)
	rpc.block = make(chan struct{})
	n := testNode(mount)
	n.requestTimeout = 20 * time.Millisecond
	if _, errno := n.Lookup(context.Background(), "slow"); errno != syscall.ETIMEDOUT {
		t.Fatalf("timed-out lookup = %v, want ETIMEDOUT", errno)
	}
}

// --- Defect 5: liveness and cleanup have reserved capacity -----------------

func TestLivenessAndCleanupLanesAreReserved(t *testing.T) {
	cfg := testConfig(8)
	mount, rpc := testMount(t, 8)
	if cap(mount.bulk)+mount.reclaimWorkers+livenessReserve != cfg.MaxInFlight {
		t.Fatalf("bulk %d + cleanup %d + liveness %d != authority in-flight budget %d", cap(mount.bulk), mount.reclaimWorkers, livenessReserve, cfg.MaxInFlight)
	}
	for range cap(mount.bulk) {
		mount.bulk <- struct{}{}
	}
	saturated, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if errno := mount.acquireBulk(saturated); errno != syscall.ETIMEDOUT {
		t.Fatalf("saturated bulk lane admitted a call (errno %v)", errno)
	}
	mount.wg.Add(1)
	go mount.keepAlive(mount.ctx, 30*time.Millisecond)
	waitFor(t, "a keepalive to complete while bulk I/O is saturated", func() bool {
		renewed := false
		rpc.snapshot(func(f *fakeRPC) { renewed = f.keepAlives > 0 })
		return renewed
	})
	mount.cancel()
	mount.wg.Wait()
	if err := mount.fatalError(); err != nil {
		t.Fatalf("keepalive starved behind bulk work: %v", err)
	}
}

// --- Defect 9: a refused release is never discarded ------------------------

func TestReleaseSurfacesARefusedClose(t *testing.T) {
	frontend, mount, rpc := testRawFileSystem(t, 8)
	rpc.closeFailure = syscall.EIO
	record, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_REGULAR, 1))
	if errno != 0 {
		t.Fatal(errno)
	}
	id, ok := frontend.addHandle(record, &handleRecord{file: &fileHandle{node: record.node, token: testToken(100)}})
	if !ok {
		t.Fatal("add handle")
	}
	frontend.Release(nil, &fuse.ReleaseIn{Fh: id})
	err := mount.fatalError()
	if err == nil {
		t.Fatal("a refused close was discarded; the authority keeps the open file description until the session ends")
	}
	if !strings.Contains(err.Error(), "frontend-owned resource") {
		t.Fatalf("diagnostic does not name the cause: %v", err)
	}
}

func TestReleaseDirSurfacesARefusedClose(t *testing.T) {
	frontend, mount, rpc := testRawFileSystem(t, 8)
	rpc.closeFailure = syscall.EIO
	record, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_DIRECTORY, 1))
	if errno != 0 {
		t.Fatal(errno)
	}
	id, ok := frontend.addHandle(record, &handleRecord{dir: &dirHandle{node: record.node, token: testToken(100)}})
	if !ok {
		t.Fatal("add handle")
	}
	frontend.ReleaseDir(&fuse.ReleaseIn{Fh: id})
	if mount.fatalError() == nil {
		t.Fatal("a refused directory close was discarded")
	}
}

// --- Defect 10: the authority's Open reply is validated at the boundary -----

func TestOpendirRejectsMalformedOpenReply(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.handle = nil
	if _, _, errno := testNode(mount).OpendirHandle(context.Background(), syscall.O_RDONLY); errno != syscall.EIO {
		t.Fatalf("OpendirHandle on a malformed reply = %v, want EIO", errno)
	}
	rpc.handle = testToken(900)
	if _, _, errno := testNode(mount).OpendirHandle(context.Background(), syscall.O_WRONLY); errno != syscall.EISDIR {
		t.Fatalf("writable opendir = %v, want EISDIR", errno)
	}
}

// --- Defect 11: the kernel's max_write floor -------------------------------

func TestMountVolumeRejectsBoundsBelowTheKernelWriteFloor(t *testing.T) {
	rpc := newFakeRPC()
	rpc.maxRead, rpc.maxWrite = 1024, 1024
	_, err := MountVolume(context.Background(), "/nonexistent-portablefs-mountpoint", rpc, testConfig(8))
	if err == nil || !strings.Contains(err.Error(), "floor") {
		t.Fatalf("MountVolume with a 1 KiB max_write = %v, want a refusal naming the kernel floor", err)
	}
}

func TestMountVolumeRequiresACompleteConfiguration(t *testing.T) {
	cfg := testConfig(8)
	cfg.MountInstanceID = "volume-wide-source"
	rpc := newFakeRPC()
	if _, err := MountVolume(context.Background(), "/nonexistent-portablefs-mountpoint", rpc, cfg); err == nil {
		t.Fatal("a non-random mount identity must be refused")
	}
	rpc.mu.Lock()
	closes := rpc.closes
	rpc.mu.Unlock()
	if closes != 1 {
		t.Fatalf("RPC closes after invalid mount identity = %d, want 1", closes)
	}
	cfg = testConfig(8)
	cfg.MaxInFlight = 0
	if _, err := MountVolume(context.Background(), "/nonexistent-portablefs-mountpoint", newFakeRPC(), cfg); err == nil {
		t.Fatal("a mount without the authority in-flight budget cannot reserve a liveness lane and must be refused")
	}
	cfg = testConfig(8)
	cfg.MaxInFlight = minMaxInFlight - 1
	if _, err := MountVolume(context.Background(), "/nonexistent-portablefs-mountpoint", newFakeRPC(), cfg); err == nil {
		t.Fatal("an in-flight budget too small to carve lanes from must be refused")
	}
	rpc = newFakeRPC()
	rpc.root = nil
	if _, err := MountVolume(context.Background(), "/nonexistent-portablefs-mountpoint", rpc, testConfig(8)); err == nil {
		t.Fatal("a missing authority root must be refused")
	}
}

func TestFailedStartupCleanRequiresExactSessionRelease(t *testing.T) {
	for _, test := range []struct {
		name      string
		detachErr error
		wantClean bool
	}{
		{name: "released", wantClean: true},
		{name: "detach refused", detachErr: syscall.EIO, wantClean: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			rpc := newFakeRPC()
			rpc.detachErr = test.detachErr
			cfg := testConfig(8)
			cfg.Coherence = CoherenceStrict
			cfg.MaxInFlight = 0
			_, err := MountVolume(context.Background(), "/nonexistent-portablefs-mountpoint", rpc, cfg)
			if err == nil {
				t.Fatal("an incomplete mount configuration was accepted")
			}
			wrapped := fmt.Errorf("supervisor boundary: %w", err)
			if got := FailedStartupClean(wrapped); got != test.wantClean {
				t.Fatalf("FailedStartupClean(%v) = %t, want %t", err, got, test.wantClean)
			}
			rpc.snapshot(func(f *fakeRPC) {
				if len(f.detachProofs) != 1 {
					t.Fatalf("detach proofs = %d, want 1", len(f.detachProofs))
				}
				if f.closes != 1 {
					t.Fatalf("RPC closes = %d, want 1", f.closes)
				}
			})
		})
	}
}

// --- Defect 12: mknod ------------------------------------------------------

func TestMknodCreatesRegularFilesAndRefusesUnrepresentableTypes(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	item, errno := n.Mknod(context.Background(), "plain", syscall.S_IFREG|0o644, 0)
	if errno != 0 || item == nil {
		t.Fatalf("mknod regular = (%v, %v)", item, errno)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if len(f.fileCloses) != 1 {
			t.Fatalf("mknod left %d open file descriptions behind, want 0", len(f.fileCloses))
		}
	})
	if _, errno := n.Mknod(context.Background(), "untyped", 0o644, 0); errno != 0 {
		t.Fatalf("mknod with no type bits = %v, want a regular file", errno)
	}
	for name, mode := range map[string]uint32{"fifo": syscall.S_IFIFO, "socket": syscall.S_IFSOCK} {
		if _, errno := n.Mknod(context.Background(), name, mode|0o644, 0); errno != syscall.EOPNOTSUPP {
			t.Fatalf("mknod %s = %v, want EOPNOTSUPP (never ENOSYS)", name, errno)
		}
	}
	for name, mode := range map[string]uint32{"chr": syscall.S_IFCHR, "blk": syscall.S_IFBLK} {
		if _, errno := n.Mknod(context.Background(), name, mode|0o644, 0x100); errno != syscall.EPERM {
			t.Fatalf("mknod %s = %v, want EPERM", name, errno)
		}
	}
}

func TestMknodIsWiredIntoTheRawFileSystem(t *testing.T) {
	frontend, _, _ := testRawFileSystem(t, 8)
	input := &fuse.MknodIn{Mode: syscall.S_IFIFO | 0o644}
	input.NodeId = fuse.FUSE_ROOT_ID
	status := frontend.Mknod(nil, input, "fifo", &fuse.EntryOut{})
	if status == fuse.ENOSYS {
		t.Fatal("MKNOD still falls through to the default ENOSYS implementation")
	}
	if status != fuse.Status(syscall.EOPNOTSUPP) {
		t.Fatalf("MKNOD status = %v, want EOPNOTSUPP", status)
	}
}

// --- Defect 13: directory paging, cookies, fsync bits, append, rename ------

func testDirPage(count int, eof bool, cookie func(int) []byte) *authoritypb.ReadDirReply {
	page := &authoritypb.ReadDirReply{Verifier: testToken(5), Eof: eof}
	for index := range count {
		page.Entries = append(page.Entries, &authoritypb.Dirent{
			Name:       []byte{byte('a' + index)},
			Attr:       &authoritypb.Attr{Inode: uint64(index + 10), Kind: authoritypb.Attr_REGULAR, Mode: 0o644},
			NextCookie: cookie(index),
		})
	}
	return page
}

func testDirHandle(t *testing.T, frontend *rawFileSystem, pages ...*authoritypb.ReadDirReply) (uint64, *fakeRPC) {
	t.Helper()
	record, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_DIRECTORY, 1))
	if errno != 0 {
		t.Fatal(errno)
	}
	rpc := frontend.mount.rpc.(*fakeRPC)
	rpc.dirPages = pages
	id, ok := frontend.addHandle(record, &handleRecord{dir: &dirHandle{node: record.node, token: testToken(100)}})
	if !ok {
		t.Fatal("add directory handle")
	}
	return id, rpc
}

// readDirOnce issues one kernel READDIR into a buffer that holds exactly
// `entries` one-byte-named entries, and returns the offset the kernel would
// resume from (the Off of the last entry that fitted).
func readDirOnce(t *testing.T, frontend *rawFileSystem, id, offset uint64, entries int) uint64 {
	t.Helper()
	const oneByteNameEntrySize = 32
	list := fuse.NewDirEntryList(make([]byte, entries*oneByteNameEntrySize), offset)
	if status := frontend.ReadDir(nil, &fuse.ReadIn{Fh: id, Offset: offset}, list); status != fuse.OK {
		t.Fatalf("ReadDir at %d = %v", offset, status)
	}
	return list.Offset
}

func TestDirHandleBuffersOneAuthorityPageAcrossEntries(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.dirPages = []*authoritypb.ReadDirReply{testDirPage(4, true, func(index int) []byte { return encodeCookie(uint64(index + 1)) })}
	handle := &dirHandle{node: testNode(mount), token: testToken(100)}
	ctx := context.Background()
	names := []string(nil)
	for range 4 {
		entry, errno := handle.peek(ctx)
		if errno != 0 || entry == nil {
			t.Fatalf("peek = (%v, %v)", entry, errno)
		}
		// Peeking twice must not advance: the entry is only consumed when the
		// kernel buffer has accepted it.
		again, _ := handle.peek(ctx)
		if again.Name != entry.Name {
			t.Fatalf("peek is not idempotent: %q then %q", entry.Name, again.Name)
		}
		names = append(names, entry.Name)
		handle.consume()
	}
	entry, errno := handle.peek(ctx)
	if errno != 0 || entry != nil {
		t.Fatalf("end of directory = (%v, %v)", entry, errno)
	}
	if len(names) != 4 || names[0] != "a" || names[3] != "d" {
		t.Fatalf("entries = %v", names)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if len(f.readdirs) != 1 {
			t.Fatalf("authority READDIR calls = %d, want 1; the buffered page was discarded", len(f.readdirs))
		}
	})
}

func TestReadDirContinuesFromTheBufferedPage(t *testing.T) {
	frontend, _, _ := testRawFileSystem(t, 8)
	page := testDirPage(4, true, func(index int) []byte { return encodeCookie(uint64(index + 1)) })
	id, rpc := testDirHandle(t, frontend, page)
	if got := readDirOnce(t, frontend, id, 0, 2); got != 2 {
		t.Fatalf("first READDIR resume offset = %d, want 2", got)
	}
	if got := readDirOnce(t, frontend, id, 2, 2); got != 4 {
		t.Fatalf("second READDIR resume offset = %d; an entry that did not fit was lost", got)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if len(f.readdirs) != 1 {
			t.Fatalf("authority READDIR calls = %d, want 1; Seekdir discarded the buffered page", len(f.readdirs))
		}
	})
}

func TestReadDirRewindDiscardsTheBufferedPage(t *testing.T) {
	frontend, _, _ := testRawFileSystem(t, 8)
	cookie := func(index int) []byte { return encodeCookie(uint64(index + 1)) }
	id, rpc := testDirHandle(t, frontend, testDirPage(4, true, cookie), testDirPage(4, true, cookie))
	if got := readDirOnce(t, frontend, id, 0, 2); got != 2 {
		t.Fatalf("first READDIR resume offset = %d", got)
	}
	if got := readDirOnce(t, frontend, id, 0, 2); got != 2 {
		t.Fatalf("rewound READDIR resume offset = %d, want the directory from the start", got)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if len(f.readdirs) != 2 {
			t.Fatalf("authority READDIR calls = %d, want 2 (rewind must refetch)", len(f.readdirs))
		}
		if len(f.readdirs[1].GetVerifier()) != 0 {
			t.Fatal("a rewind to offset 0 must drop the directory verifier")
		}
	})
}

func TestReadDirRejectsACookieItCannotResumeFrom(t *testing.T) {
	for name, cookie := range map[string]func(int) []byte{
		"short": func(int) []byte { return []byte{1, 2, 3, 4} },
		"zero":  func(int) []byte { return make([]byte, 8) },
		"empty": func(int) []byte { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			frontend, _, _ := testRawFileSystem(t, 8)
			id, _ := testDirHandle(t, frontend, testDirPage(2, true, cookie))
			list := fuse.NewDirEntryList(make([]byte, 256), 0)
			if status := frontend.ReadDir(nil, &fuse.ReadIn{Fh: id}, list); status != fuse.EIO {
				t.Fatalf("ReadDir with a %s cookie = %v, want EIO; go-fuse would substitute an offset the authority cannot resume from and `ls` would never terminate", name, status)
			}
		})
	}
}

func TestFsyncUsesOnlyTheDataSyncBit(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	handle := &fileHandle{node: n, token: testToken(100)}
	for flags, want := range map[uint32]bool{0: false, 1: true, 2: false, 3: true} {
		if errno := n.Fsync(context.Background(), handle, flags); errno != 0 {
			t.Fatal(errno)
		}
		var got bool
		rpc.snapshot(func(f *fakeRPC) { got = f.fsyncs[len(f.fsyncs)-1].GetDataOnly() })
		if got != want {
			t.Fatalf("Fsync(%#b) DataOnly = %v, want %v", flags, got, want)
		}
	}
}

func TestReadOnlyOpenDropsOAppend(t *testing.T) {
	flags, errno := protocolOpenFlags(syscall.O_RDONLY | syscall.O_APPEND)
	if errno != 0 {
		t.Fatal(errno)
	}
	if flags.GetAppend() {
		t.Fatal("O_APPEND on a read-only open is legal and ignored on every other Linux filesystem; forwarding it makes the authority reject the open with EINVAL")
	}
	if flags, _ := protocolOpenFlags(syscall.O_WRONLY | syscall.O_APPEND); !flags.GetAppend() {
		t.Fatal("O_APPEND must survive on a writable open")
	}
	if flags, _ := protocolOpenFlags(syscall.O_RDWR | syscall.O_APPEND); !flags.GetAppend() {
		t.Fatal("O_APPEND must survive on a read-write open")
	}
}

func TestRenameValidatesFlagCombinations(t *testing.T) {
	mount, _ := testMount(t, 8)
	n := testNode(mount)
	parent := testNode(mount)
	for _, flags := range []uint32{4, renameNoReplace | renameExchange, 0xffffffff} {
		if errno := n.Rename(context.Background(), "a", parent, "b", flags); errno != syscall.EINVAL {
			t.Fatalf("Rename flags %#x = %v, want EINVAL", flags, errno)
		}
	}
	for _, flags := range []uint32{0, renameNoReplace, renameExchange} {
		if errno := n.Rename(context.Background(), "a", parent, "b", flags); errno != 0 {
			t.Fatalf("Rename flags %#x = %v, want success", flags, errno)
		}
	}
	if errno := n.Rename(context.Background(), "a", nil, "b", 0); errno != syscall.EINVAL {
		t.Fatalf("Rename without a destination parent = %v, want EINVAL", errno)
	}
}

func TestReadChunksAtTheNegotiatedMaxRead(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.fileData = []byte("0123456789")
	n := testNode(mount)
	n.maxRead = 4
	handle := &fileHandle{node: n, token: testToken(100)}
	dest := make([]byte, 16)
	result, errno := n.Read(context.Background(), handle, dest, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	data, status := result.Bytes(make([]byte, 16))
	if status != fuse.OK || !bytes.Equal(data, rpc.fileData) {
		t.Fatalf("Read = (%q, %v), want the whole file", data, status)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if f.reads != 3 {
			t.Fatalf("authority READ calls = %d, want 3 chunks of at most maxRead", f.reads)
		}
	})
	if _, errno := n.Read(context.Background(), handle, dest, -1); errno != syscall.EBADF {
		t.Fatalf("Read at a negative offset = %v", errno)
	}
	if _, errno := n.Read(context.Background(), nil, dest, 0); errno != syscall.EBADF {
		t.Fatalf("Read without a handle = %v", errno)
	}
}

// --- Preserved behaviour ---------------------------------------------------

func TestWriteUsesOneAuthorityMutation(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	n.maxWrite = 8
	handle := &fileHandle{node: n, token: testToken(100)}
	written, errno := n.Write(context.Background(), handle, []byte("abcdefg"), 10)
	if errno != 0 || written != 7 {
		t.Fatalf("Write = (%d, %v), want (7, 0)", written, errno)
	}
	if len(rpc.writes) != 1 || rpc.writes[0].GetOffset() != 10 || !bytes.Equal(rpc.writes[0].GetData(), []byte("abcdefg")) {
		t.Fatalf("authority writes = %#v", rpc.writes)
	}
}

func TestWriteRejectsRequestBeyondNegotiatedLimit(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	n.maxWrite = 3
	written, errno := n.Write(context.Background(), &fileHandle{node: n, token: testToken(100)}, []byte("abcdefg"), 10)
	if written != 0 || errno != syscall.EIO {
		t.Fatalf("oversized Write = (%d, %v), want (0, EIO)", written, errno)
	}
	if len(rpc.writes) != 0 {
		t.Fatalf("oversized write reached authority: %#v", rpc.writes)
	}
}

func TestAppendNeverSynthesizesEOFOffset(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	n.maxWrite = 8
	handle := &fileHandle{node: n, token: testToken(100), append: true}
	written, errno := n.Write(context.Background(), handle, []byte("abcdef"), 999)
	if errno != 0 || written != 6 {
		t.Fatalf("Write append = (%d, %v)", written, errno)
	}
	if len(rpc.writes) != 1 || !rpc.writes[0].GetAppend() || rpc.writes[0].GetOffset() != 0 || !bytes.Equal(rpc.writes[0].GetData(), []byte("abcdef")) {
		t.Fatalf("append requests = %#v", rpc.writes)
	}
}

func TestPositiveShortWritePreservesProgress(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.short = true
	n := testNode(mount)
	n.maxWrite = 4
	written, errno := n.Write(context.Background(), &fileHandle{node: n, token: testToken(100)}, []byte("data"), 0)
	if written != 2 || errno != 0 {
		t.Fatalf("short Write = (%d, %v), want positive progress", written, errno)
	}
}

func TestZeroProgressWritePreservesAuthorityErrno(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.writeFailure = syscall.ENOSPC
	n := testNode(mount)
	n.maxWrite = 4
	written, errno := n.Write(context.Background(), &fileHandle{node: n, token: testToken(100)}, []byte("data"), 0)
	if written != 0 || errno != syscall.ENOSPC {
		t.Fatalf("failed Write = (%d, %v), want (0, ENOSPC)", written, errno)
	}
	if len(rpc.writes) != 1 {
		t.Fatalf("authority writes = %d, want 1", len(rpc.writes))
	}
}

func TestGetxattrSupportsSizeProbe(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.xattrValue = []byte("value")
	n := testNode(mount)
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

func TestSetxattrReadonlyContractIsLocal(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	var beforeCalls, beforeSequence uint64
	rpc.snapshot(func(f *fakeRPC) {
		beforeCalls, beforeSequence = uint64(f.calls), f.mutationSeq
	})

	// VFS owns public xattr-name syntax before this callback. Once a valid set
	// mode reaches the filesystem, user-xattr-readonly is the exact result even
	// for a name a direct authority caller could not use.
	for _, name := range []string{"user.test", "", "security.capability", "user.portablefs.internal"} {
		for _, flags := range []uint32{0, unix.XATTR_CREATE, unix.XATTR_REPLACE} {
			if errno := n.Setxattr(context.Background(), name, []byte("value"), flags); errno != syscall.EOPNOTSUPP {
				t.Fatalf("Setxattr(%q, flags=%#x)=%v, want EOPNOTSUPP", name, flags, errno)
			}
		}
	}
	rpc.snapshot(func(f *fakeRPC) {
		if uint64(f.calls) != beforeCalls || f.mutationSeq != beforeSequence {
			t.Fatalf("local setxattr refusal advanced RPC calls %d->%d or mutation sequence %d->%d", beforeCalls, f.calls, beforeSequence, f.mutationSeq)
		}
	})
}

func TestSetxattrInvalidFlagsPrecedeReadonlyRefusal(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	for _, test := range []struct {
		name  string
		flags uint32
	}{
		{name: "user.test", flags: unix.XATTR_CREATE | unix.XATTR_REPLACE},
		{name: "", flags: 1 << 31},
	} {
		if errno := n.Setxattr(context.Background(), test.name, nil, test.flags); errno != syscall.EINVAL {
			t.Fatalf("Setxattr(%q, flags=%#x)=%v, want EINVAL", test.name, test.flags, errno)
		}
	}
	rpc.snapshot(func(f *fakeRPC) {
		if f.calls != 0 || f.mutationSeq != 0 {
			t.Fatalf("invalid setxattr flags reached RPC: calls=%d mutation_sequence=%d", f.calls, f.mutationSeq)
		}
	})
}

func TestRemovexattrStillForwardsToAuthority(t *testing.T) {
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	removed := 0
	rpc.hook = func(request *authoritypb.Request) {
		if remove := request.GetRemoveXattr(); remove != nil && string(remove.GetName()) == "user.test" {
			removed++
		}
	}
	if errno := n.Removexattr(context.Background(), "user.test"); errno != 0 {
		t.Fatalf("Removexattr=%v", errno)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if removed != 1 || f.calls != 1 || f.mutationSeq != 1 {
			t.Fatalf("remove forwarding: matched=%d calls=%d mutation_sequence=%d", removed, f.calls, f.mutationSeq)
		}
	})
}

func TestListxattrSupportsSizeProbe(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.xattrNames = [][]byte{[]byte("user.a"), []byte("user.bb")}
	n := testNode(mount)
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
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
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
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
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
	mount, rpc := testMount(t, 8)
	n := testNode(mount)
	handle := &fileHandle{node: n, token: testToken(100)}
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
	frontend, mount, rpc := testRawFileSystem(t, 1024)
	const lookups = 64
	records := make([]*inodeRecord, lookups)
	var wg sync.WaitGroup
	for index := range lookups {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			item := testItem(42, authoritypb.Attr_REGULAR, uint64(index+1))
			var errno syscall.Errno
			records[index], errno = frontend.intern(context.Background(), item)
			if errno != 0 {
				t.Errorf("intern %d failed: %v", index, errno)
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
		seen[string(popReclaim(t, mount))] = true
	}
	if len(seen) != lookups {
		t.Fatalf("unique reclaimed capabilities = %d, want %d", len(seen), lookups)
	}
	rpc.snapshot(func(f *fakeRPC) {
		if f.calls != 0 {
			t.Fatalf("interning and FORGET performed %d authority calls", f.calls)
		}
	})
}

func TestForgetCannotReclaimCapabilityUsedByInflightOperation(t *testing.T) {
	frontend, mount, _ := testRawFileSystem(t, 8)
	oldRecord, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_REGULAR, 1))
	if errno != 0 {
		t.Fatal("intern old record")
	}
	inflight := frontend.acquire(oldRecord.id)
	if inflight == nil {
		t.Fatal("acquire old record")
	}
	frontend.Forget(oldRecord.id, 1)
	if mount.reclaim.pending() != 0 {
		t.Fatal("FORGET reclaimed a capability still used by an operation")
	}
	newRecord, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_REGULAR, 2))
	if errno != 0 || newRecord.id == oldRecord.id {
		t.Fatalf("replacement record = %#v, old NodeID %d", newRecord, oldRecord.id)
	}
	frontend.release(inflight)
	if got := popReclaim(t, mount); !bytes.Equal(got, testToken(1)) {
		t.Fatalf("reclaimed token = %x, want old token", got)
	}
	frontend.Forget(newRecord.id, 1)
	if got := popReclaim(t, mount); !bytes.Equal(got, testToken(2)) {
		t.Fatalf("reclaimed token = %x, want replacement token", got)
	}
}

func TestOpenHandlePinsForgottenInode(t *testing.T) {
	frontend, mount, _ := testRawFileSystem(t, 8)
	record, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_REGULAR, 1))
	if errno != 0 {
		t.Fatal("intern")
	}
	handle := &fileHandle{node: record.node, token: testToken(100)}
	id, ok := frontend.addHandle(record, &handleRecord{file: handle})
	if !ok {
		t.Fatal("add handle")
	}
	frontend.Forget(record.id, 1)
	if mount.reclaim.pending() != 0 || frontend.acquire(record.id) == nil {
		t.Fatal("forgotten inode was not retained by its open handle")
	}
	frontend.release(record)
	taken, ok := frontend.takeHandle(id, handleAuthorityFile)
	if !ok {
		t.Fatal("take handle")
	}
	frontend.unpin(taken.inode)
	if got := popReclaim(t, mount); !bytes.Equal(got, testToken(1)) {
		t.Fatalf("reclaimed token = %x", got)
	}
}

func TestReleaseWaitsForInflightHandleOperation(t *testing.T) {
	frontend, _, _ := testRawFileSystem(t, 8)
	record, errno := frontend.intern(context.Background(), testItem(42, authoritypb.Attr_REGULAR, 1))
	if errno != 0 {
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
		taken, _ := frontend.takeHandle(id, handleAuthorityFile)
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

func TestKeepAliveFailureAbortsSession(t *testing.T) {
	mount, rpc := testMount(t, 8)
	rpc.keepAliveErr = syscall.EIO
	mount.wg.Add(1)
	go mount.keepAlive(mount.ctx, 15*time.Millisecond)
	select {
	case <-mount.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("keepalive failure did not abort mount session")
	}
}

func TestStrictKeepAliveIsBoundedByTheRepairBudget(t *testing.T) {
	const (
		lease  = 2 * time.Minute
		budget = 15 * time.Second
	)
	if got, want := keepAliveInterval(lease, CoherenceStrict, budget), budget/3; got != want {
		t.Fatalf("strict keepalive interval = %s, want %s", got, want)
	}
	if got, want := keepAliveInterval(lease, CoherenceUncached, budget), lease/3; got != want {
		t.Fatalf("uncached keepalive interval = %s, want %s", got, want)
	}
	if got, want := keepAliveInterval(9*time.Second, CoherenceStrict, time.Minute), 3*time.Second; got != want {
		t.Fatalf("short-lease keepalive interval = %s, want %s", got, want)
	}
}

func TestTerminalSessionSignalAbortsMount(t *testing.T) {
	mount, _ := testMount(t, 8)
	done := make(chan struct{})
	mount.wg.Add(1)
	go mount.watchSession(mount.ctx, done)
	close(done)
	select {
	case <-mount.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("terminal session signal did not abort mount")
	}
}

func TestRefusedReclaimIsTerminal(t *testing.T) {
	mount, rpc := testMount(t, 64)
	rpc.reclaimFailure = syscall.EIO
	mount.start(time.Hour)
	mount.deferReclaim(testToken(1))
	select {
	case <-mount.ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("a refused reclaim left the frontend and the authority disagreeing about ownership")
	}
}

// --- the strict cache contract --------------------------------------------

func (f *fakeRPC) SessionID() []byte { return cloneBytes(f.session) }

func (f *fakeRPC) InitialVisibilityCursor() *authoritypb.VisibilityCursor {
	if f.initial == nil {
		return nil
	}
	return proto.Clone(f.initial).(*authoritypb.VisibilityCursor)
}

func (f *fakeRPC) NextVisibility(ctx context.Context, _ *authoritypb.VisibilityCursor) (*authoritypb.VisibilityEvent, error) {
	f.mu.Lock()
	failure, stream := f.visibilityErr, f.events
	f.mu.Unlock()
	if failure != nil {
		return nil, failure
	}
	if stream == nil {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	select {
	case event := <-stream:
		return event, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *fakeRPC) AckVisibility(_ context.Context, cursor *authoritypb.VisibilityCursor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acked = append(f.acked, proto.Clone(cursor).(*authoritypb.VisibilityCursor))
	return nil
}

// ReportVisibilityBlocked records the exact-cycle report and lets a test model
// the authority's pre-apply interruption before the report returns.
func (f *fakeRPC) ReportVisibilityBlocked(_ context.Context, cursor *authoritypb.VisibilityCursor, parents []uint64) error {
	f.mu.Lock()
	f.blocked = append(f.blocked, proto.Clone(cursor).(*authoritypb.VisibilityCursor))
	f.blockedParents = append(f.blockedParents, append([]uint64(nil), parents...))
	err, hook := f.blockedErr, f.onBlocked
	f.mu.Unlock()
	if err == nil && hook != nil {
		hook()
	}
	return err
}

func (f *fakeRPC) DetachAfterUnmount(_ context.Context, proof MountAbsenceProof) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detachProofs = append(f.detachProofs, proof)
	return f.detachErr
}
