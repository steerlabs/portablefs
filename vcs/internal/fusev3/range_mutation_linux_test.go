//go:build linux

package fusev3

import (
	"bytes"
	"math"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

type sharedRangeFile struct {
	item   *authoritypb.Item
	nodeID uint64
	handle uint64
	token  []byte
}

func openSharedRangeFile(t *testing.T, fixture *strictFixture, name string, inode, itemToken, handleToken uint64) sharedRangeFile {
	t.Helper()
	item := testItem(inode, authoritypb.Attr_REGULAR, itemToken)
	fixture.rpc.mu.Lock()
	if fixture.rpc.byName == nil {
		fixture.rpc.byName = make(map[string]*authoritypb.Item)
	}
	fixture.rpc.byName[name] = cloneItem(item)
	fixture.rpc.handle = testToken(handleToken)
	fixture.rpc.mu.Unlock()
	entry := fixture.lookup(t, fuse.FUSE_ROOT_ID, name)
	out := &fuse.OpenOut{}
	status := fixture.rawCall(func(unique uint64) fuse.Status {
		return fixture.raw.Open(nil, &fuse.OpenIn{
			InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId},
			Flags:    uint32(syscall.O_RDWR),
		}, out)
	})
	if !status.Ok() {
		t.Fatalf("OPEN %q = %v", name, status)
	}
	if out.OpenFlags != coherentOpenFlags {
		t.Fatalf("OPEN %q flags = %#x, want %#x", name, out.OpenFlags, coherentOpenFlags)
	}
	return sharedRangeFile{item: item, nodeID: entry.NodeId, handle: out.Fh, token: testToken(handleToken)}
}

func assertExactDataAttrGate(t *testing.T, gate *authoritypb.SourcePublicationGate, items ...*authoritypb.Item) {
	t.Helper()
	if gate == nil || len(gate.GetTargets()) != len(items) {
		t.Fatalf("source gate = %+v, want %d exact item targets", gate, len(items))
	}
	want := make(map[string]struct{}, len(items))
	for _, item := range items {
		want[string(item.GetStableIdentity())] = struct{}{}
	}
	for _, target := range gate.GetTargets() {
		item := target.GetItem()
		if item == nil || !item.GetAttributes() || !item.GetData() {
			t.Fatalf("source target = %+v, want DATA+ATTR item", target)
		}
		if _, ok := want[string(item.GetIdentity())]; !ok {
			t.Fatalf("unexpected source target identity %x", item.GetIdentity())
		}
		delete(want, string(item.GetIdentity()))
	}
	if len(want) != 0 {
		t.Fatalf("source gate omitted identities: %x", want)
	}
}

func finishPrivatePublication(t *testing.T, fixture *strictFixture, requestUnique, nodeID uint64, opcode uint32) {
	t.Helper()
	if !fixture.raw.ReplyWriteOrdered(requestUnique) {
		t.Fatalf("private reply %d did not retain physical-write ownership", requestUnique)
	}
	if !fixture.raw.ReplyPublishMarked(requestUnique, nodeID, opcode) {
		t.Fatalf("private reply %d was not marked for opcode %d publication", requestUnique, opcode)
	}
	fixture.raw.ReplyWritten(requestUnique, fuse.OK)

	fixture.raw.mu.Lock()
	retained := fixture.raw.replyPublications[requestUnique] != nil
	fixture.raw.mu.Unlock()
	if !retained {
		t.Fatal("source/publication ownership released at the original reply instead of post-VFS PUBLISH")
	}

	publishUnique := fixture.unique.Add(2)
	publishID := requestUnique + 1 // ordinary request IDs are even; publication IDs are positive odd.
	in := &fuse.PFSPublishIn{
		InHeader:      fuse.InHeader{Unique: publishUnique},
		RequestUnique: requestUnique,
		PublicationID: publishID,
		Nodeid:        nodeID,
		Opcode:        opcode,
	}
	out := &fuse.PFSPublishOut{}
	if status := fixture.raw.PFSPublish(nil, in, out); !status.Ok() {
		t.Fatalf("PFS_PUBLISH for opcode %d = %v", opcode, status)
	}
	if out.RequestUnique != requestUnique || out.PublicationID != publishID || out.Nodeid != nodeID ||
		out.Opcode != opcode || out.Flags != fuse.PFS_PUBLISH_ACK {
		t.Fatalf("PFS_PUBLISH ACK = %+v", out)
	}
	fixture.raw.ReplyWritten(publishUnique, fuse.OK)
	fixture.raw.mu.Lock()
	retained = fixture.raw.replyPublications[requestUnique] != nil
	fixture.raw.mu.Unlock()
	if retained {
		t.Fatal("private reply survived its physically written PFS_PUBLISH ACK")
	}
}

func TestPFSFallocateMapsExactGateAndPublishesAppliedResult(t *testing.T) {
	fixture := newStrictFixture(t)
	file := openSharedRangeFile(t, fixture, "file", 41, 141, 241)
	consumption := &recordingResponseConsumption{}
	fixture.rpc.retainedConsumption = consumption
	var captured *authoritypb.Request
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetFallocate() == nil {
			t.Fatalf("unexpected authority request: %T", request.GetBody())
		}
		captured = proto.Clone(request).(*authoritypb.Request)
		return &authoritypb.Response{
			Body: &authoritypb.Response_Fallocate{Fallocate: &authoritypb.FallocateReply{
				PostSize: 12, VisibilitySequence: 33, Flags: fuse.PFS_RANGE_OUT_APPLIED,
			}},
			PostAttr: &authoritypb.Attr{Inode: 41, Kind: authoritypb.Attr_REGULAR, Mode: 0o600, Size: 12},
		}, nil
	}
	unique := fixture.unique.Add(2)
	in := &fuse.PFSFallocateIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: file.nodeID},
		Fh:       file.handle, Offset: 4, Length: 8,
		RlimitFsize: math.MaxUint64, FileMaxSize: math.MaxInt64,
		Mode: uint32(unix.FALLOC_FL_ZERO_RANGE), WriteFlags: fuse.WRITE_KILL_SUIDGID,
	}
	out := &fuse.PFSRangeOut{}
	if status := fixture.raw.PFSFallocate(nil, in, out); !status.Ok() {
		t.Fatalf("PFS_FALLOCATE = %v", status)
	}
	if *out != (fuse.PFSRangeOut{PostSize: 12, Sequence: 33, Flags: fuse.PFS_RANGE_OUT_APPLIED}) {
		t.Fatalf("PFS_FALLOCATE result = %+v", out)
	}
	request := captured.GetFallocate()
	if request == nil || !bytes.Equal(request.GetHandle(), file.token) || request.GetOffset() != 4 || request.GetLength() != 8 ||
		request.GetRlimitFsize() != math.MaxUint64 || request.GetFileMaxSize() != math.MaxInt64 ||
		request.GetMode() != uint32(unix.FALLOC_FL_ZERO_RANGE) || request.GetWriteFlags() != fuse.WRITE_KILL_SUIDGID {
		t.Fatalf("authority PFS_FALLOCATE mapping = %+v", request)
	}
	assertExactDataAttrGate(t, captured.GetSourcePublicationGate(), file.item)
	if consumption.calls.Load() != 0 {
		t.Fatal("authority response was consumed before its kernel reply")
	}
	if !fixture.raw.ReplyWriteOrdered(unique) || !fixture.raw.ReplyPublishMarked(unique, file.nodeID, fuse.PFS_FALLOCATE_OPCODE) {
		t.Fatal("applied PFS_FALLOCATE omitted generic publication ownership")
	}
	fixture.raw.ReplyWritten(unique, fuse.OK)
	if consumption.calls.Load() != 0 {
		t.Fatal("original /dev/fuse write consumed an applied response before PFS_PUBLISH")
	}
	publishUnique := fixture.unique.Add(2)
	publish := &fuse.PFSPublishIn{
		InHeader: fuse.InHeader{Unique: publishUnique}, RequestUnique: unique,
		PublicationID: unique + 1, Nodeid: file.nodeID, Opcode: fuse.PFS_FALLOCATE_OPCODE,
	}
	if status := fixture.raw.PFSPublish(nil, publish, &fuse.PFSPublishOut{}); !status.Ok() {
		t.Fatalf("PFS_PUBLISH = %v", status)
	}
	if consumption.calls.Load() != 0 {
		t.Fatal("constructing PFS_PUBLISH ACK consumed authority response before physical ACK write")
	}
	fixture.raw.ReplyWritten(publishUnique, fuse.OK)
	if consumption.calls.Load() != 1 {
		t.Fatalf("physical PFS_PUBLISH ACK consumed response %d times, want once", consumption.calls.Load())
	}
	if fixture.mount.isRevoked() {
		t.Fatalf("valid PFS_FALLOCATE revoked mount: %v", fixture.mount.fatalError())
	}
}

func TestPFSFallocateEveryFrozenModeMapsUnchangedAndPublishesExactSize(t *testing.T) {
	for _, test := range []struct {
		name     string
		mode     uint32
		postSize uint64
	}{
		{name: "allocate", mode: 0, postSize: 16},
		{name: "keep size", mode: uint32(unix.FALLOC_FL_KEEP_SIZE), postSize: 4},
		{name: "punch hole", mode: uint32(unix.FALLOC_FL_PUNCH_HOLE | unix.FALLOC_FL_KEEP_SIZE), postSize: 4},
		{name: "zero range", mode: uint32(unix.FALLOC_FL_ZERO_RANGE), postSize: 16},
		{name: "zero range keep size", mode: uint32(unix.FALLOC_FL_ZERO_RANGE | unix.FALLOC_FL_KEEP_SIZE), postSize: 4},
		{name: "collapse", mode: uint32(unix.FALLOC_FL_COLLAPSE_RANGE), postSize: 24},
		{name: "insert", mode: uint32(unix.FALLOC_FL_INSERT_RANGE), postSize: 40},
		{name: "unshare", mode: uint32(unix.FALLOC_FL_UNSHARE_RANGE), postSize: 32},
		{name: "unshare keep size", mode: uint32(unix.FALLOC_FL_UNSHARE_RANGE | unix.FALLOC_FL_KEEP_SIZE), postSize: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newStrictFixture(t)
			file := openSharedRangeFile(t, fixture, "file", 44, 144, 244)
			var captured *authoritypb.Request
			fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
				captured = proto.Clone(request).(*authoritypb.Request)
				return &authoritypb.Response{
					Body: &authoritypb.Response_Fallocate{Fallocate: &authoritypb.FallocateReply{
						PostSize: test.postSize, VisibilitySequence: 35, Flags: fuse.PFS_RANGE_OUT_APPLIED,
					}},
					PostAttr: &authoritypb.Attr{Inode: 44, Kind: authoritypb.Attr_REGULAR, Mode: 0o600, Size: int64(test.postSize)},
				}, nil
			}
			unique := fixture.unique.Add(2)
			in := &fuse.PFSFallocateIn{
				InHeader: fuse.InHeader{Unique: unique, NodeId: file.nodeID}, Fh: file.handle,
				Offset: 8, Length: 8, RlimitFsize: 64, FileMaxSize: 64,
				Mode: test.mode, WriteFlags: fuse.WRITE_KILL_SUIDGID,
			}
			out := &fuse.PFSRangeOut{}
			if status := fixture.raw.PFSFallocate(nil, in, out); !status.Ok() {
				t.Fatalf("PFS_FALLOCATE %s = %v", test.name, status)
			}
			if *out != (fuse.PFSRangeOut{PostSize: test.postSize, Sequence: 35, Flags: fuse.PFS_RANGE_OUT_APPLIED}) ||
				captured.GetFallocate().GetMode() != test.mode {
				t.Fatalf("PFS_FALLOCATE %s result=%+v request=%+v", test.name, out, captured.GetFallocate())
			}
			assertExactDataAttrGate(t, captured.GetSourcePublicationGate(), file.item)
			finishPrivatePublication(t, fixture, unique, file.nodeID, fuse.PFS_FALLOCATE_OPCODE)
			if fixture.mount.isRevoked() {
				t.Fatalf("PFS_FALLOCATE %s revoked mount: %v", test.name, fixture.mount.fatalError())
			}
		})
	}
}

func TestPFSFallocateStructuredRefusalIsPhysicalButUnpublished(t *testing.T) {
	fixture := newStrictFixture(t)
	file := openSharedRangeFile(t, fixture, "file", 42, 142, 242)
	consumption := &recordingResponseConsumption{}
	fixture.rpc.retainedConsumption = consumption
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetFallocate() == nil {
			t.Fatalf("unexpected authority request: %T", request.GetBody())
		}
		return &authoritypb.Response{Body: &authoritypb.Response_Fallocate{Fallocate: &authoritypb.FallocateReply{
			PostSize: 20, Flags: fuse.PFS_RANGE_OUT_REJECTED_RLIMIT, Error: -int32(syscall.EFBIG),
		}}}, nil
	}
	unique := fixture.unique.Add(2)
	in := &fuse.PFSFallocateIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: file.nodeID}, Fh: file.handle,
		Offset: 8, Length: 8, RlimitFsize: 24, FileMaxSize: 64,
		Mode: uint32(unix.FALLOC_FL_INSERT_RANGE),
	}
	out := &fuse.PFSRangeOut{}
	if status := fixture.raw.PFSFallocate(nil, in, out); !status.Ok() {
		t.Fatalf("structured PFS_FALLOCATE refusal = %v", status)
	}
	if *out != (fuse.PFSRangeOut{PostSize: 20, Flags: fuse.PFS_RANGE_OUT_REJECTED_RLIMIT, Error: -int32(syscall.EFBIG)}) {
		t.Fatalf("structured PFS_FALLOCATE refusal = %+v", out)
	}
	if !fixture.raw.ReplyWriteOrdered(unique) {
		t.Fatal("structured refusal lost its physical reply boundary")
	}
	if fixture.raw.ReplyPublishMarked(unique, file.nodeID, fuse.PFS_FALLOCATE_OPCODE) {
		t.Fatal("definite no-change PFS_FALLOCATE requested a post-VFS publication")
	}
	if consumption.calls.Load() != 0 {
		t.Fatal("definite refusal was consumed before its physical kernel reply")
	}
	fixture.raw.ReplyWritten(unique, fuse.OK)
	if consumption.calls.Load() != 1 {
		t.Fatalf("physical refusal reply consumed response %d times, want once", consumption.calls.Load())
	}
	fixture.raw.mu.Lock()
	_, retained := fixture.raw.replyPublications[unique]
	fixture.raw.mu.Unlock()
	if retained || fixture.mount.isRevoked() {
		t.Fatalf("structured refusal lifecycle retained=%v revoked=%v cause=%v", retained, fixture.mount.isRevoked(), fixture.mount.fatalError())
	}
}

func TestFallocateRlimitRejectionRequiresAuthoritativeGrowthProof(t *testing.T) {
	base := fuse.PFSFallocateIn{
		Offset: 8, Length: 8, RlimitFsize: 10, FileMaxSize: 64,
	}
	for _, test := range []struct {
		name    string
		change  func(*fuse.PFSFallocateIn)
		preSize uint64
		want    bool
	}{
		{name: "finite zero", change: func(in *fuse.PFSFallocateIn) {
			in.Offset, in.Length, in.RlimitFsize = 0, 1, 0
		}, preSize: 0, want: true},
		{name: "finite one", change: func(in *fuse.PFSFallocateIn) {
			in.Offset, in.Length, in.RlimitFsize = 0, 2, 1
		}, preSize: 0, want: true},
		{name: "allocate growth", preSize: 4, want: true},
		{name: "zero growth", change: func(in *fuse.PFSFallocateIn) { in.Mode = uint32(unix.FALLOC_FL_ZERO_RANGE) }, preSize: 4, want: true},
		{name: "unshare growth", change: func(in *fuse.PFSFallocateIn) { in.Mode = uint32(unix.FALLOC_FL_UNSHARE_RANGE) }, preSize: 4, want: true},
		{name: "insert authoritative growth", change: func(in *fuse.PFSFallocateIn) {
			in.Mode, in.RlimitFsize = uint32(unix.FALLOC_FL_INSERT_RANGE), 24
		}, preSize: 20, want: true},
		{name: "infinite limit", change: func(in *fuse.PFSFallocateIn) { in.RlimitFsize = math.MaxUint64 }, preSize: 4},
		{name: "allocate no growth", preSize: 16},
		{name: "allocate below limit", change: func(in *fuse.PFSFallocateIn) { in.RlimitFsize = 16 }, preSize: 4},
		{name: "keep size", change: func(in *fuse.PFSFallocateIn) { in.Mode = uint32(unix.FALLOC_FL_KEEP_SIZE) }, preSize: 4},
		{name: "punch hole", change: func(in *fuse.PFSFallocateIn) {
			in.Mode = uint32(unix.FALLOC_FL_PUNCH_HOLE | unix.FALLOC_FL_KEEP_SIZE)
		}, preSize: 20},
		{name: "zero keep size", change: func(in *fuse.PFSFallocateIn) {
			in.Mode = uint32(unix.FALLOC_FL_ZERO_RANGE | unix.FALLOC_FL_KEEP_SIZE)
		}, preSize: 4},
		{name: "collapse", change: func(in *fuse.PFSFallocateIn) { in.Mode = uint32(unix.FALLOC_FL_COLLAPSE_RANGE) }, preSize: 20},
		{name: "unshare keep size", change: func(in *fuse.PFSFallocateIn) {
			in.Mode = uint32(unix.FALLOC_FL_UNSHARE_RANGE | unix.FALLOC_FL_KEEP_SIZE)
		}, preSize: 4},
		{name: "insert offset not before eof", change: func(in *fuse.PFSFallocateIn) {
			in.Mode, in.RlimitFsize = uint32(unix.FALLOC_FL_INSERT_RANGE), 24
		}, preSize: 8},
		{name: "insert below limit", change: func(in *fuse.PFSFallocateIn) {
			in.Mode, in.RlimitFsize = uint32(unix.FALLOC_FL_INSERT_RANGE), 28
		}, preSize: 20},
		{name: "insert beyond file maximum", change: func(in *fuse.PFSFallocateIn) {
			in.Mode, in.RlimitFsize, in.FileMaxSize = uint32(unix.FALLOC_FL_INSERT_RANGE), 63, 64
		}, preSize: 60},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := base
			if test.change != nil {
				test.change(&in)
			}
			if got := validFallocateRlimitRejection(&in, test.preSize); got != test.want {
				t.Fatalf("validFallocateRlimitRejection(%+v, pre=%d) = %t, want %t", in, test.preSize, got, test.want)
			}
		})
	}
}

func TestPFSFallocatePostDispatchErrorPublishesExactAppliedState(t *testing.T) {
	fixture := newStrictFixture(t)
	file := openSharedRangeFile(t, fixture, "file", 43, 143, 243)
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetFallocate() == nil {
			t.Fatalf("unexpected authority request: %T", request.GetBody())
		}
		return &authoritypb.Response{
			Body: &authoritypb.Response_Fallocate{Fallocate: &authoritypb.FallocateReply{
				PostSize: 8, VisibilitySequence: 34,
				Flags: fuse.PFS_RANGE_OUT_APPLIED | fuse.PFS_RANGE_OUT_POSTAPPLY_ERROR,
				Error: -int32(syscall.ENOSPC),
			}},
			PostAttr: &authoritypb.Attr{Inode: 43, Kind: authoritypb.Attr_REGULAR, Mode: 0o600, Size: 8},
		}, nil
	}
	unique := fixture.unique.Add(2)
	in := &fuse.PFSFallocateIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: file.nodeID}, Fh: file.handle,
		Offset: 8, Length: 12, RlimitFsize: math.MaxUint64, FileMaxSize: math.MaxInt64,
		Mode: uint32(unix.FALLOC_FL_COLLAPSE_RANGE),
	}
	out := &fuse.PFSRangeOut{}
	if status := fixture.raw.PFSFallocate(nil, in, out); !status.Ok() {
		t.Fatalf("post-dispatch PFS_FALLOCATE transport = %v", status)
	}
	want := fuse.PFSRangeOut{
		PostSize: 8, Sequence: 34,
		Flags: fuse.PFS_RANGE_OUT_APPLIED | fuse.PFS_RANGE_OUT_POSTAPPLY_ERROR,
		Error: -int32(syscall.ENOSPC),
	}
	if *out != want {
		t.Fatalf("post-dispatch PFS_FALLOCATE = %+v, want %+v", out, want)
	}
	finishPrivatePublication(t, fixture, unique, file.nodeID, fuse.PFS_FALLOCATE_OPCODE)
	if fixture.mount.isRevoked() {
		t.Fatalf("valid post-dispatch result revoked mount: %v", fixture.mount.fatalError())
	}
}

func TestPFSFallocateMalformedSuccessfulPostStateFences(t *testing.T) {
	for _, test := range []struct {
		name     string
		mode     uint32
		postSize uint64
		rlimit   uint64
		fileMax  uint64
	}{
		{name: "allocate below end", postSize: 15, rlimit: math.MaxUint64, fileMax: 64},
		{name: "zero below end", mode: uint32(unix.FALLOC_FL_ZERO_RANGE), postSize: 15, rlimit: math.MaxUint64, fileMax: 64},
		{name: "unshare below end", mode: uint32(unix.FALLOC_FL_UNSHARE_RANGE), postSize: 15, rlimit: math.MaxUint64, fileMax: 64},
		{name: "insert not larger than end", mode: uint32(unix.FALLOC_FL_INSERT_RANGE), postSize: 16, rlimit: 64, fileMax: 64},
		{name: "insert beyond rlimit", mode: uint32(unix.FALLOC_FL_INSERT_RANGE), postSize: 40, rlimit: 32, fileMax: 64},
		{name: "collapse not larger than offset", mode: uint32(unix.FALLOC_FL_COLLAPSE_RANGE), postSize: 8, rlimit: math.MaxUint64, fileMax: 64},
		{name: "collapse above possible pre-size", mode: uint32(unix.FALLOC_FL_COLLAPSE_RANGE), postSize: 57, rlimit: math.MaxUint64, fileMax: 64},
		{name: "post size beyond file maximum", mode: uint32(unix.FALLOC_FL_KEEP_SIZE), postSize: 65, rlimit: math.MaxUint64, fileMax: 64},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newStrictFixture(t)
			file := openSharedRangeFile(t, fixture, "file", 45, 145, 245)
			consumption := &recordingResponseConsumption{}
			fixture.rpc.retainedConsumption = consumption
			fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
				return &authoritypb.Response{
					Body: &authoritypb.Response_Fallocate{Fallocate: &authoritypb.FallocateReply{
						PostSize: test.postSize, VisibilitySequence: 36, Flags: fuse.PFS_RANGE_OUT_APPLIED,
					}},
					PostAttr: &authoritypb.Attr{Inode: 45, Kind: authoritypb.Attr_REGULAR, Mode: 0o600, Size: int64(test.postSize)},
				}, nil
			}
			in := &fuse.PFSFallocateIn{
				InHeader: fuse.InHeader{Unique: fixture.unique.Add(2), NodeId: file.nodeID}, Fh: file.handle,
				Offset: 8, Length: 8, RlimitFsize: test.rlimit, FileMaxSize: test.fileMax, Mode: test.mode,
			}
			if status := fixture.raw.PFSFallocate(nil, in, &fuse.PFSRangeOut{}); status != fuse.Status(syscall.ENOTCONN) {
				t.Fatalf("malformed successful PFS_FALLOCATE = %v, want ENOTCONN", status)
			}
			if !fixture.mount.isRevoked() {
				t.Fatal("malformed successful PFS_FALLOCATE did not fence mount")
			}
			if consumption.calls.Load() != 1 {
				t.Fatalf("malformed local result consumed response %d times after revocation, want once", consumption.calls.Load())
			}
		})
	}
}

func TestPFSFallocateCollapseAcceptsExactFileMaximumBoundary(t *testing.T) {
	fixture := newStrictFixture(t)
	file := openSharedRangeFile(t, fixture, "collapse-boundary", 46, 146, 246)
	const fileMax, length = uint64(64), uint64(8)
	fixture.rpc.replyOverride = func(*authoritypb.Request) (*authoritypb.Response, error) {
		return &authoritypb.Response{
			Body: &authoritypb.Response_Fallocate{Fallocate: &authoritypb.FallocateReply{
				PostSize: fileMax - length, VisibilitySequence: 37, Flags: fuse.PFS_RANGE_OUT_APPLIED,
			}},
			PostAttr: &authoritypb.Attr{Inode: 46, Kind: authoritypb.Attr_REGULAR, Mode: 0o600, Size: int64(fileMax - length)},
		}, nil
	}
	unique := fixture.unique.Add(2)
	in := &fuse.PFSFallocateIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: file.nodeID}, Fh: file.handle,
		Offset: 8, Length: length, RlimitFsize: math.MaxUint64, FileMaxSize: fileMax,
		Mode: uint32(unix.FALLOC_FL_COLLAPSE_RANGE),
	}
	if status := fixture.raw.PFSFallocate(nil, in, &fuse.PFSRangeOut{}); !status.Ok() {
		t.Fatalf("boundary clean COLLAPSE = %v", status)
	}
	finishPrivatePublication(t, fixture, unique, file.nodeID, fuse.PFS_FALLOCATE_OPCODE)
	if fixture.mount.isRevoked() {
		t.Fatalf("boundary clean COLLAPSE revoked mount: %v", fixture.mount.fatalError())
	}
}

func TestPFSCopyFileRangeMapsTwoDataDependenciesAndPublishesDestination(t *testing.T) {
	fixture := newStrictFixture(t)
	source := openSharedRangeFile(t, fixture, "source", 51, 151, 251)
	destination := openSharedRangeFile(t, fixture, "destination", 52, 152, 252)
	var captured *authoritypb.Request
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetCopyFileRange() == nil {
			t.Fatalf("unexpected authority request: %T", request.GetBody())
		}
		captured = proto.Clone(request).(*authoritypb.Request)
		return &authoritypb.Response{
			Body: &authoritypb.Response_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeReply{
				ResultSize: 5, PostSize: 15, VisibilitySequence: 39, Flags: fuse.PFS_RANGE_OUT_APPLIED,
			}},
			PostAttr: &authoritypb.Attr{Inode: 52, Kind: authoritypb.Attr_REGULAR, Mode: 0o600, Size: 15},
		}, nil
	}
	unique := fixture.unique.Add(2)
	in := &fuse.PFSCopyFileRangeIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: source.nodeID},
		FhIn:     source.handle, OffIn: 2, NodeIdOut: destination.nodeID, FhOut: destination.handle, OffOut: 10, Len: 5,
		RlimitFsize: math.MaxUint64, FileMaxSize: math.MaxInt64, WriteFlags: fuse.WRITE_KILL_SUIDGID,
	}
	out := &fuse.PFSRangeOut{}
	if status := fixture.raw.PFSCopyFileRange(nil, in, out); !status.Ok() {
		t.Fatalf("PFS_COPY_FILE_RANGE = %v", status)
	}
	if *out != (fuse.PFSRangeOut{ResultSize: 5, PostSize: 15, Sequence: 39, Flags: fuse.PFS_RANGE_OUT_APPLIED}) {
		t.Fatalf("PFS_COPY_FILE_RANGE result = %+v", out)
	}
	request := captured.GetCopyFileRange()
	if request == nil || !bytes.Equal(request.GetInputHandle(), source.token) || request.GetInputOffset() != 2 ||
		!bytes.Equal(request.GetOutputHandle(), destination.token) || request.GetOutputOffset() != 10 || request.GetLength() != 5 ||
		request.GetRlimitFsize() != math.MaxUint64 || request.GetFileMaxSize() != math.MaxInt64 ||
		request.GetWriteFlags() != fuse.WRITE_KILL_SUIDGID || request.GetFlags() != 0 {
		t.Fatalf("authority PFS_COPY_FILE_RANGE mapping = %+v", request)
	}
	assertExactDataAttrGate(t, captured.GetSourcePublicationGate(), source.item, destination.item)
	finishPrivatePublication(t, fixture, unique, source.nodeID, fuse.PFS_COPY_FILE_RANGE_OPCODE)
	if fixture.mount.isRevoked() {
		t.Fatalf("valid PFS_COPY_FILE_RANGE revoked mount: %v", fixture.mount.fatalError())
	}
}

func TestPFSCopyFileRangeZeroBytePostapplyPublishesExactAttributeState(t *testing.T) {
	fixture := newStrictFixture(t)
	source := openSharedRangeFile(t, fixture, "source", 53, 153, 253)
	destination := openSharedRangeFile(t, fixture, "destination", 54, 154, 254)
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetCopyFileRange() == nil {
			t.Fatalf("unexpected authority request: %T", request.GetBody())
		}
		return &authoritypb.Response{
			Body: &authoritypb.Response_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeReply{
				PostSize: 4, VisibilitySequence: 41,
				Flags: fuse.PFS_RANGE_OUT_APPLIED | fuse.PFS_RANGE_OUT_POSTAPPLY_ERROR,
				Error: -int32(syscall.EIO),
			}},
			PostAttr: &authoritypb.Attr{Inode: 54, Kind: authoritypb.Attr_REGULAR, Mode: 0o600, Size: 4},
		}, nil
	}
	unique := fixture.unique.Add(2)
	in := &fuse.PFSCopyFileRangeIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: source.nodeID},
		FhIn:     source.handle, OffIn: 32, NodeIdOut: destination.nodeID, FhOut: destination.handle, OffOut: 128, Len: 8,
		RlimitFsize: math.MaxUint64, FileMaxSize: math.MaxInt64, WriteFlags: fuse.WRITE_KILL_SUIDGID,
	}
	out := &fuse.PFSRangeOut{}
	if status := fixture.raw.PFSCopyFileRange(nil, in, out); !status.Ok() {
		t.Fatalf("zero-byte post-apply PFS_COPY_FILE_RANGE transport = %v", status)
	}
	want := fuse.PFSRangeOut{
		PostSize: 4, Sequence: 41,
		Flags: fuse.PFS_RANGE_OUT_APPLIED | fuse.PFS_RANGE_OUT_POSTAPPLY_ERROR,
		Error: -int32(syscall.EIO),
	}
	if *out != want {
		t.Fatalf("zero-byte post-apply PFS_COPY_FILE_RANGE = %+v, want %+v", out, want)
	}
	finishPrivatePublication(t, fixture, unique, source.nodeID, fuse.PFS_COPY_FILE_RANGE_OPCODE)
	if fixture.mount.isRevoked() {
		t.Fatalf("valid zero-byte post-apply result revoked mount: %v", fixture.mount.fatalError())
	}
}

func TestPFSCopyFileRangeAuthoritativeNoopIsUnpublished(t *testing.T) {
	fixture := newStrictFixture(t)
	source := openSharedRangeFile(t, fixture, "source", 61, 161, 261)
	destination := openSharedRangeFile(t, fixture, "destination", 62, 162, 262)
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetCopyFileRange() == nil {
			t.Fatalf("unexpected authority request: %T", request.GetBody())
		}
		return &authoritypb.Response{Body: &authoritypb.Response_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeReply{
			Flags: fuse.PFS_RANGE_OUT_NOOP,
		}}}, nil
	}
	unique := fixture.unique.Add(2)
	in := &fuse.PFSCopyFileRangeIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: source.nodeID}, FhIn: source.handle,
		NodeIdOut: destination.nodeID, FhOut: destination.handle, Len: 8,
		RlimitFsize: math.MaxUint64, FileMaxSize: math.MaxInt64,
	}
	out := &fuse.PFSRangeOut{}
	if status := fixture.raw.PFSCopyFileRange(nil, in, out); !status.Ok() {
		t.Fatalf("PFS_COPY_FILE_RANGE NOOP = %v", status)
	}
	if *out != (fuse.PFSRangeOut{Flags: fuse.PFS_RANGE_OUT_NOOP}) {
		t.Fatalf("PFS_COPY_FILE_RANGE NOOP = %+v", out)
	}
	if !fixture.raw.ReplyWriteOrdered(unique) || fixture.raw.ReplyPublishMarked(unique, source.nodeID, fuse.PFS_COPY_FILE_RANGE_OPCODE) {
		t.Fatal("authoritative NOOP did not remain physical-only")
	}
	fixture.raw.ReplyWritten(unique, fuse.OK)
	if fixture.mount.isRevoked() {
		t.Fatalf("valid PFS_COPY_FILE_RANGE NOOP revoked mount: %v", fixture.mount.fatalError())
	}
}

func TestPFSCopyFileRangeNoopCannotBypassDestinationCeilings(t *testing.T) {
	for _, test := range []struct {
		name    string
		rlimit  uint64
		fileMax uint64
		output  uint64
	}{
		{name: "zero rlimit", rlimit: 0, fileMax: math.MaxInt64, output: 0},
		{name: "at finite rlimit", rlimit: 7, fileMax: math.MaxInt64, output: 7},
		{name: "at file maximum", rlimit: math.MaxUint64, fileMax: 11, output: 11},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newStrictFixture(t)
			source := openSharedRangeFile(t, fixture, "source", 64, 164, 264)
			destination := openSharedRangeFile(t, fixture, "destination", 65, 165, 265)
			fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
				if request.GetCopyFileRange() == nil {
					t.Fatalf("unexpected authority request: %T", request.GetBody())
				}
				return &authoritypb.Response{Body: &authoritypb.Response_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeReply{
					Flags: fuse.PFS_RANGE_OUT_NOOP,
				}}}, nil
			}
			in := &fuse.PFSCopyFileRangeIn{
				InHeader: fuse.InHeader{Unique: fixture.unique.Add(2), NodeId: source.nodeID}, FhIn: source.handle,
				NodeIdOut: destination.nodeID, FhOut: destination.handle, OffOut: test.output, Len: 1,
				RlimitFsize: test.rlimit, FileMaxSize: test.fileMax,
			}
			if status := fixture.raw.PFSCopyFileRange(nil, in, &fuse.PFSRangeOut{}); status != fuse.Status(syscall.ENOTCONN) {
				t.Fatalf("ceiling-bypassing NOOP = %v, want ENOTCONN", status)
			}
			if !fixture.mount.isRevoked() {
				t.Fatal("ceiling-bypassing NOOP did not fence the mount")
			}
		})
	}
}

func TestPFSCopyFileRangeDefersSameFileOverlapUntilAuthorityEOFClipping(t *testing.T) {
	fixture := newStrictFixture(t)
	file := openSharedRangeFile(t, fixture, "file", 63, 163, 263)
	var requests int
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		copyRequest := request.GetCopyFileRange()
		if copyRequest == nil {
			t.Fatalf("unexpected authority request: %T", request.GetBody())
		}
		requests++
		switch requests {
		case 1:
			// Requested [90,110) and [105,125) overlap only in the source tail
			// beyond authoritative EOF 100. The effective ten-byte ranges do not.
			return &authoritypb.Response{
				Body: &authoritypb.Response_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeReply{
					ResultSize: 10, PostSize: 115, VisibilitySequence: 40, Flags: fuse.PFS_RANGE_OUT_APPLIED,
				}},
				PostAttr: &authoritypb.Attr{Inode: 63, Kind: authoritypb.Attr_REGULAR, Mode: 0o600, Size: 115},
			}, nil
		case 2:
			// The effective ranges really overlap. Only the authority can prove
			// that, and it returns a definite pre-apply EINVAL rather than making
			// the frontend guess from the untrimmed syscall request.
			return &authoritypb.Response{Body: &authoritypb.Response_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeReply{
				Flags: fuse.PFS_RANGE_OUT_REJECTED, Error: -int32(syscall.EINVAL),
			}}}, nil
		default:
			t.Fatalf("unexpected request %d", requests)
			return nil, nil
		}
	}

	firstUnique := fixture.unique.Add(2)
	first := &fuse.PFSCopyFileRangeIn{
		InHeader: fuse.InHeader{Unique: firstUnique, NodeId: file.nodeID},
		FhIn:     file.handle, OffIn: 90, NodeIdOut: file.nodeID, FhOut: file.handle, OffOut: 105, Len: 20,
		RlimitFsize: math.MaxUint64, FileMaxSize: math.MaxInt64,
	}
	firstOut := &fuse.PFSRangeOut{}
	if status := fixture.raw.PFSCopyFileRange(nil, first, firstOut); !status.Ok() {
		t.Fatalf("EOF-clipped false-tail overlap = %v", status)
	}
	if *firstOut != (fuse.PFSRangeOut{ResultSize: 10, PostSize: 115, Sequence: 40, Flags: fuse.PFS_RANGE_OUT_APPLIED}) {
		t.Fatalf("EOF-clipped result = %+v", firstOut)
	}
	finishPrivatePublication(t, fixture, firstUnique, file.nodeID, fuse.PFS_COPY_FILE_RANGE_OPCODE)

	secondUnique := fixture.unique.Add(2)
	second := *first
	second.Unique, second.OffOut = secondUnique, 95
	secondOut := &fuse.PFSRangeOut{}
	if status := fixture.raw.PFSCopyFileRange(nil, &second, secondOut); !status.Ok() {
		t.Fatalf("authority-rejected true overlap transport = %v", status)
	}
	if *secondOut != (fuse.PFSRangeOut{Flags: fuse.PFS_RANGE_OUT_REJECTED, Error: -int32(syscall.EINVAL)}) {
		t.Fatalf("authority-rejected true overlap = %+v", secondOut)
	}
	if !fixture.raw.ReplyWriteOrdered(secondUnique) || fixture.raw.ReplyPublishMarked(secondUnique, file.nodeID, fuse.PFS_COPY_FILE_RANGE_OPCODE) {
		t.Fatal("definite true-overlap rejection incorrectly requested post-VFS publication")
	}
	fixture.raw.ReplyWritten(secondUnique, fuse.OK)
	if requests != 2 || fixture.mount.isRevoked() {
		t.Fatalf("overlap authority requests=%d revoked=%v cause=%v", requests, fixture.mount.isRevoked(), fixture.mount.fatalError())
	}
}

func TestPrivateRangeInputsFailClosedBeforeAuthorityDispatch(t *testing.T) {
	t.Run("fallocate", func(t *testing.T) {
		fixture := newStrictFixture(t)
		file := openSharedRangeFile(t, fixture, "file", 71, 171, 271)
		fixture.rpc.mu.Lock()
		baseline := fixture.rpc.calls
		fixture.rpc.mu.Unlock()
		tests := []struct {
			name   string
			change func(*fuse.PFSFallocateIn)
		}{
			{name: "zero length", change: func(in *fuse.PFSFallocateIn) { in.Length = 0 }},
			{name: "unknown mode combination", change: func(in *fuse.PFSFallocateIn) {
				in.Mode = uint32(unix.FALLOC_FL_COLLAPSE_RANGE | unix.FALLOC_FL_KEEP_SIZE)
			}},
			{name: "unknown write flag", change: func(in *fuse.PFSFallocateIn) { in.WriteFlags = fuse.WRITE_LOCKOWNER }},
			{name: "zero file maximum", change: func(in *fuse.PFSFallocateIn) { in.FileMaxSize = 0 }},
			{name: "signed range overflow", change: func(in *fuse.PFSFallocateIn) { in.Offset = math.MaxInt64; in.Length = 2 }},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				in := &fuse.PFSFallocateIn{
					InHeader: fuse.InHeader{Unique: fixture.unique.Add(2), NodeId: file.nodeID}, Fh: file.handle,
					Length: 1, RlimitFsize: math.MaxUint64, FileMaxSize: math.MaxInt64,
				}
				test.change(in)
				if status := fixture.raw.PFSFallocate(nil, in, &fuse.PFSRangeOut{}); status != rangeMutationProtocolError {
					t.Fatalf("invalid PFS_FALLOCATE = %v, want EPROTO", status)
				}
			})
		}
		fixture.rpc.mu.Lock()
		calls := fixture.rpc.calls
		fixture.rpc.mu.Unlock()
		if calls != baseline {
			t.Fatalf("invalid PFS_FALLOCATE requests reached authority: calls %d -> %d", baseline, calls)
		}
	})

	t.Run("copy file range", func(t *testing.T) {
		fixture := newStrictFixture(t)
		file := openSharedRangeFile(t, fixture, "file", 72, 172, 272)
		fixture.rpc.mu.Lock()
		baseline := fixture.rpc.calls
		fixture.rpc.mu.Unlock()
		tests := []struct {
			name   string
			change func(*fuse.PFSCopyFileRangeIn)
		}{
			{name: "zero length", change: func(in *fuse.PFSCopyFileRangeIn) { in.Len = 0 }},
			{name: "reserved flags", change: func(in *fuse.PFSCopyFileRangeIn) { in.Flags = 1 }},
			{name: "unknown write flag", change: func(in *fuse.PFSCopyFileRangeIn) { in.WriteFlags = fuse.WRITE_LOCKOWNER }},
			{name: "signed destination overflow", change: func(in *fuse.PFSCopyFileRangeIn) { in.OffOut = math.MaxInt64; in.Len = 2 }},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				in := &fuse.PFSCopyFileRangeIn{
					InHeader: fuse.InHeader{Unique: fixture.unique.Add(2), NodeId: file.nodeID},
					FhIn:     file.handle, NodeIdOut: file.nodeID, FhOut: file.handle, OffIn: 0, OffOut: 8, Len: 4,
					RlimitFsize: math.MaxUint64, FileMaxSize: math.MaxInt64,
				}
				test.change(in)
				if status := fixture.raw.PFSCopyFileRange(nil, in, &fuse.PFSRangeOut{}); status != rangeMutationProtocolError {
					t.Fatalf("invalid PFS_COPY_FILE_RANGE = %v, want EPROTO", status)
				}
			})
		}
		fixture.rpc.mu.Lock()
		calls := fixture.rpc.calls
		fixture.rpc.mu.Unlock()
		if calls != baseline {
			t.Fatalf("invalid PFS_COPY_FILE_RANGE requests reached authority: calls %d -> %d", baseline, calls)
		}
	})
}
