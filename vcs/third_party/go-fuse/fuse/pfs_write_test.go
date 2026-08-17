// Copyright 2026 the Go-FUSE Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package fuse

import (
	"encoding/binary"
	"math"
	"syscall"
	"testing"
	"unsafe"
)

func TestPFSWriteABILayout(t *testing.T) {
	if FOPEN_PFS_SHARED != 1<<8 || FOPEN_PFS_LOCAL != 1<<9 ||
		FUSE_ATTR_PFS_SHARED != 1<<2 || FUSE_ATTR_PFS_LOCAL != 1<<3 {
		t.Fatal("PortableFS inode/open classification ABI bits changed")
	}
	var in PFSWriteIn
	if got, want := unsafe.Sizeof(in)-unsafe.Sizeof(in.InHeader), uintptr(80); got != want {
		t.Fatalf("fuse_pfs_write_in size = %d, want %d", got, want)
	}
	base := unsafe.Offsetof(in.Fh)
	for name, test := range map[string]struct {
		got  uintptr
		want uintptr
	}{
		"fh":              {unsafe.Offsetof(in.Fh) - base, 0},
		"txid":            {unsafe.Offsetof(in.Txid) - base, 8},
		"requested_size":  {unsafe.Offsetof(in.RequestedSize) - base, 16},
		"fragment_offset": {unsafe.Offsetof(in.FragmentOffset) - base, 24},
		"position":        {unsafe.Offsetof(in.Position) - base, 32},
		"rlimit_fsize":    {unsafe.Offsetof(in.RlimitFsize) - base, 40},
		"file_max_size":   {unsafe.Offsetof(in.FileMaxSize) - base, 48},
		"lock_owner":      {unsafe.Offsetof(in.LockOwner) - base, 56},
		"size":            {unsafe.Offsetof(in.Size) - base, 64},
		"write_flags":     {unsafe.Offsetof(in.WriteFlags) - base, 68},
		"flags":           {unsafe.Offsetof(in.Flags) - base, 72},
		"phase":           {unsafe.Offsetof(in.Phase) - base, 76},
	} {
		if test.got != test.want {
			t.Errorf("%s offset = %d, want %d", name, test.got, test.want)
		}
	}

	var out PFSWriteOut
	if got, want := unsafe.Sizeof(out), uintptr(48); got != want {
		t.Fatalf("fuse_pfs_write_out size = %d, want %d", got, want)
	}
	if unsafe.Offsetof(out.Error) != 44 {
		t.Fatalf("fuse_pfs_write_out.error offset = %d, want 44", unsafe.Offsetof(out.Error))
	}
	if got, want := unsafe.Sizeof(NotifyPFSSizeOut{}), uintptr(24); got != want {
		t.Fatalf("fuse_notify_pfs_size_out size = %d, want %d", got, want)
	}
	var publishIn PFSPublishIn
	if got, want := unsafe.Sizeof(publishIn)-unsafe.Sizeof(publishIn.InHeader), uintptr(32); got != want {
		t.Fatalf("fuse_pfs_publish_in size = %d, want %d", got, want)
	}
	if got, want := unsafe.Sizeof(PFSPublishOut{}), uintptr(32); got != want {
		t.Fatalf("fuse_pfs_publish_out size = %d, want %d", got, want)
	}
	var fallocate PFSFallocateIn
	if got, want := unsafe.Sizeof(fallocate)-unsafe.Sizeof(fallocate.InHeader), uintptr(48); got != want {
		t.Fatalf("fuse_pfs_fallocate_in size = %d, want %d", got, want)
	}
	base = unsafe.Offsetof(fallocate.Fh)
	for name, test := range map[string]struct{ got, want uintptr }{
		"fh": {unsafe.Offsetof(fallocate.Fh) - base, 0}, "offset": {unsafe.Offsetof(fallocate.Offset) - base, 8},
		"length": {unsafe.Offsetof(fallocate.Length) - base, 16}, "rlimit_fsize": {unsafe.Offsetof(fallocate.RlimitFsize) - base, 24},
		"file_max_size": {unsafe.Offsetof(fallocate.FileMaxSize) - base, 32}, "mode": {unsafe.Offsetof(fallocate.Mode) - base, 40},
		"write_flags": {unsafe.Offsetof(fallocate.WriteFlags) - base, 44},
	} {
		if test.got != test.want {
			t.Errorf("fuse_pfs_fallocate_in.%s offset = %d, want %d", name, test.got, test.want)
		}
	}
	var copyRange PFSCopyFileRangeIn
	if got, want := unsafe.Sizeof(copyRange)-unsafe.Sizeof(copyRange.InHeader), uintptr(72); got != want {
		t.Fatalf("fuse_pfs_copy_file_range_in size = %d, want %d", got, want)
	}
	base = unsafe.Offsetof(copyRange.FhIn)
	for name, test := range map[string]struct{ got, want uintptr }{
		"fh_in": {unsafe.Offsetof(copyRange.FhIn) - base, 0}, "off_in": {unsafe.Offsetof(copyRange.OffIn) - base, 8},
		"nodeid_out": {unsafe.Offsetof(copyRange.NodeIdOut) - base, 16}, "fh_out": {unsafe.Offsetof(copyRange.FhOut) - base, 24},
		"off_out": {unsafe.Offsetof(copyRange.OffOut) - base, 32}, "len": {unsafe.Offsetof(copyRange.Len) - base, 40},
		"rlimit_fsize": {unsafe.Offsetof(copyRange.RlimitFsize) - base, 48}, "file_max_size": {unsafe.Offsetof(copyRange.FileMaxSize) - base, 56},
		"write_flags": {unsafe.Offsetof(copyRange.WriteFlags) - base, 64}, "flags": {unsafe.Offsetof(copyRange.Flags) - base, 68},
	} {
		if test.got != test.want {
			t.Errorf("fuse_pfs_copy_file_range_in.%s offset = %d, want %d", name, test.got, test.want)
		}
	}
	if got, want := unsafe.Sizeof(PFSRangeOut{}), uintptr(32); got != want || unsafe.Offsetof(PFSRangeOut{}.Error) != 28 {
		t.Fatalf("fuse_pfs_range_out layout = size %d error %d, want 32/28", got, unsafe.Offsetof(PFSRangeOut{}.Error))
	}
}

func TestPFSWriteABIConstants(t *testing.T) {
	if PFS_WRITE_OPCODE != 4097 || PFS_PUBLISH_OPCODE != 4098 || PFS_FALLOCATE_OPCODE != 4099 || PFS_COPY_FILE_RANGE_OPCODE != 4100 || PFS_UNIQUE_PUBLISH != uint64(1)<<62 ||
		FOPEN_PFS_SHARED != 1<<8 || FOPEN_PFS_LOCAL != 1<<9 || FUSE_ATTR_PFS_SHARED != 1<<2 ||
		FUSE_ATTR_PFS_LOCAL != 1<<3 || CAP_PFS_STRICT_COHERENCE != uint64(1)<<63 || NOTIFY_PFS_SIZE != -10 || PFS_PUBLISH_ACK != 1 ||
		CAP_PFS_CACHED_DATA != uint64(1)<<62 {
		t.Fatalf("private ABI constants changed")
	}
	// The two halves of the private profile must be distinct bits: the strict
	// kernel refuses an INIT that selects one without the other, which is what
	// makes a kernel/daemon version mismatch a failed mount instead of an
	// -EPROTO at first open.
	if CAP_PFS_STRICT_COHERENCE&CAP_PFS_CACHED_DATA != 0 {
		t.Fatalf("private profile capability bits collide")
	}
	wantPhases := [...]uint32{PFS_WRITE_BEGIN, PFS_WRITE_DATA, PFS_WRITE_COMMIT, PFS_WRITE_ABORT}
	for index, phase := range wantPhases {
		if phase != uint32(index+1) {
			t.Fatalf("phase %d = %d", index+1, phase)
		}
	}
	wantFlags := [...]uint32{PFS_WRITE_OUT_BEGUN, PFS_WRITE_OUT_STAGED, PFS_WRITE_OUT_COMMITTED, PFS_WRITE_OUT_ABORTED, PFS_WRITE_OUT_REJECTED, PFS_WRITE_OUT_POSTAPPLY_ERROR, PFS_WRITE_OUT_REJECTED_RLIMIT}
	for index, flag := range wantFlags {
		if flag != 1<<index {
			t.Fatalf("reply flag %d = %#x", index, flag)
		}
	}
	for index, flag := range [...]uint32{PFS_RANGE_OUT_APPLIED, PFS_RANGE_OUT_REJECTED, PFS_RANGE_OUT_POSTAPPLY_ERROR, PFS_RANGE_OUT_REJECTED_RLIMIT, PFS_RANGE_OUT_NOOP} {
		if flag != 1<<index {
			t.Fatalf("range reply flag %d = %#x", index, flag)
		}
	}
}

func TestReplyPublicationMarkerPermitsOnlyStateBearingHeaderErrors(t *testing.T) {
	requestFor := func(opcode uint32, status Status) *request {
		input := make([]byte, unsafe.Sizeof(InHeader{}))
		req := &request{inputBuf: input, status: status}
		req.inHeader().Opcode = opcode
		return req
	}
	for _, test := range []struct {
		name   string
		opcode uint32
		status Status
		want   bool
	}{
		{name: "successful lookup", opcode: _OP_LOOKUP, status: OK, want: true},
		{name: "negative lookup", opcode: _OP_LOOKUP, status: ENOENT, want: true},
		{name: "lookup transport error", opcode: _OP_LOOKUP, status: EIO},
		{name: "non-lookup ENOENT", opcode: _OP_GETATTR, status: ENOENT},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := replyMayRequestPFSPublish(requestFor(test.opcode, test.status)); got != test.want {
				t.Fatalf("replyMayRequestPFSPublish(%d, %v) = %t, want %t", test.opcode, test.status, got, test.want)
			}
		})
	}
}

type recordingWriteFS struct {
	RawFileSystem
	called          bool
	in              PFSWriteIn
	data            []byte
	publishCalled   bool
	publish         PFSPublishIn
	fallocateCalled bool
	fallocate       PFSFallocateIn
	copyRangeCalled bool
	copyRange       PFSCopyFileRangeIn
	tmpfileCalled   bool
	tmpfile         CreateIn
	tmpfileName     string
	syncFSCalled    bool
	syncFS          SyncFSIn
}

func (fs *recordingWriteFS) PFSPublish(_ <-chan struct{}, in *PFSPublishIn, out *PFSPublishOut) Status {
	fs.publishCalled = true
	fs.publish = *in
	*out = PFSPublishOut{RequestUnique: in.RequestUnique, PublicationID: in.PublicationID, Nodeid: in.Nodeid, Opcode: in.Opcode, Flags: PFS_PUBLISH_ACK}
	return OK
}

func (fs *recordingWriteFS) PFSWrite(_ <-chan struct{}, in *PFSWriteIn, data []byte, out *PFSWriteOut) Status {
	fs.called = true
	fs.in = *in
	fs.data = append([]byte(nil), data...)
	out.Txid = in.Txid
	out.Flags = PFS_WRITE_OUT_STAGED
	return OK
}

func (fs *recordingWriteFS) PFSFallocate(_ <-chan struct{}, in *PFSFallocateIn, out *PFSRangeOut) Status {
	fs.fallocateCalled, fs.fallocate = true, *in
	*out = PFSRangeOut{PostSize: 99, Sequence: 7, Flags: PFS_RANGE_OUT_APPLIED}
	return OK
}

func (fs *recordingWriteFS) PFSCopyFileRange(_ <-chan struct{}, in *PFSCopyFileRangeIn, out *PFSRangeOut) Status {
	fs.copyRangeCalled, fs.copyRange = true, *in
	*out = PFSRangeOut{ResultSize: 3, PostSize: 99, Sequence: 8, Flags: PFS_RANGE_OUT_APPLIED}
	return OK
}

func (fs *recordingWriteFS) Tmpfile(_ <-chan struct{}, in *CreateIn, name string, out *CreateOut) Status {
	fs.tmpfileCalled, fs.tmpfile, fs.tmpfileName = true, *in, name
	out.EntryOut.NodeId, out.OpenOut.Fh = 41, 43
	return OK
}

func (fs *recordingWriteFS) SyncFS(_ <-chan struct{}, in *SyncFSIn) Status {
	fs.syncFSCalled, fs.syncFS = true, *in
	return OK
}

func writeTransactionRequestBytes(in PFSWriteIn) ([]byte, []byte) {
	headerSize := unsafe.Sizeof(InHeader{})
	all := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(&in)), unsafe.Sizeof(in))...)
	return all[:headerSize], all[headerSize:]
}

func TestPFSWriteSparseOpcodeDispatchAndFraming(t *testing.T) {
	fs := &recordingWriteFS{RawFileSystem: NewDefaultRawFileSystem()}
	ps := NewProtocolServer(fs, &MountOptions{})
	in := PFSWriteIn{
		InHeader: InHeader{Length: uint32(unsafe.Sizeof(PFSWriteIn{}) + 3), Opcode: PFS_WRITE_OPCODE, Unique: 8, NodeId: 11},
		Fh:       13, Txid: 17, RequestedSize: 3, RlimitFsize: 1 << 20, FileMaxSize: 1 << 20,
		Size: 3, Flags: syscall.O_APPEND, Phase: PFS_WRITE_DATA,
	}
	header, body := writeTransactionRequestBytes(in)
	out := [][]byte{make([]byte, sizeOfOutHeader), make([]byte, unsafe.Sizeof(PFSWriteOut{}))}
	n, status := ps.HandleRequest([][]byte{header, body, []byte("abc")}, out)
	if status != OK || n != int(sizeOfOutHeader+unsafe.Sizeof(PFSWriteOut{})) {
		t.Fatalf("PFS_WRITE dispatch = (%d, %v)", n, status)
	}
	if !fs.called || fs.in.Txid != in.Txid || string(fs.data) != "abc" {
		t.Fatalf("raw dispatch = called=%v in=%+v data=%q", fs.called, fs.in, fs.data)
	}
	if got := binary.LittleEndian.Uint32(out[1][40:44]); got != PFS_WRITE_OUT_STAGED {
		t.Fatalf("reply flags = %#x", got)
	}

	fs.called = false
	in.Size = 2
	header, body = writeTransactionRequestBytes(in)
	_, status = ps.HandleRequest([][]byte{header, body, []byte("abc")}, out)
	if status != OK || fs.called {
		t.Fatalf("malformed DATA framing reached filesystem: status=%v called=%v", status, fs.called)
	}
	if got := int32(binary.LittleEndian.Uint32(out[0][4:8])); got != -int32(EIO) {
		t.Fatalf("malformed framing reply status = %d, want %d", got, -int32(EIO))
	}
}

func TestPFSPublishSparseOpcodeDispatchAndHeaderMarker(t *testing.T) {
	fs := &recordingWriteFS{RawFileSystem: NewDefaultRawFileSystem()}
	ps := NewProtocolServer(fs, &MountOptions{})
	in := PFSPublishIn{
		InHeader:      InHeader{Length: uint32(unsafe.Sizeof(PFSPublishIn{})), Opcode: PFS_PUBLISH_OPCODE, Unique: 20, NodeId: 23},
		RequestUnique: 8, PublicationID: 11, Nodeid: 23, Opcode: 15,
	}
	headerSize := unsafe.Sizeof(InHeader{})
	wire := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(&in)), unsafe.Sizeof(in))...)
	out := [][]byte{make([]byte, sizeOfOutHeader), make([]byte, unsafe.Sizeof(PFSPublishOut{}))}
	n, status := ps.HandleRequest([][]byte{wire[:headerSize], wire[headerSize:]}, out)
	if status != OK || n != int(sizeOfOutHeader+unsafe.Sizeof(PFSPublishOut{})) || !fs.publishCalled {
		t.Fatalf("PFS_PUBLISH dispatch = (%d, %v, called=%v)", n, status, fs.publishCalled)
	}
	if fs.publish.RequestUnique != 8 || binary.LittleEndian.Uint64(out[1][8:16]) != 11 || binary.LittleEndian.Uint32(out[1][28:32]) != PFS_PUBLISH_ACK {
		t.Fatalf("PFS_PUBLISH echo = %+v wire=%x", fs.publish, out[1])
	}

	request := request{inputBuf: make([]byte, unsafe.Sizeof(InHeader{})), outHeaderBuf: make([]byte, sizeOfOutHeader), publishMarked: true}
	request.inHeader().Unique = 30
	request.serializeHeader(0)
	if got := request.outHeader().Unique; got != 30|PFS_UNIQUE_PUBLISH {
		t.Fatalf("marked response unique = %#x", got)
	}

	fs.publishCalled = false
	in.Flags = 1
	wire = append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(&in)), unsafe.Sizeof(in))...)
	_, status = ps.HandleRequest([][]byte{wire[:headerSize], wire[headerSize:]}, out)
	if status != OK || fs.publishCalled || int32(binary.LittleEndian.Uint32(out[0][4:8])) != -int32(EIO) {
		t.Fatal("malformed PFS_PUBLISH reached filesystem")
	}

	for _, malformed := range []PFSPublishIn{
		{InHeader: InHeader{Length: uint32(unsafe.Sizeof(PFSPublishIn{})), Opcode: PFS_PUBLISH_OPCODE, Unique: 19}, RequestUnique: 8, PublicationID: 11, Nodeid: 23, Opcode: 15},
		{InHeader: InHeader{Length: uint32(unsafe.Sizeof(PFSPublishIn{})), Opcode: PFS_PUBLISH_OPCODE, Unique: PFS_UNIQUE_PUBLISH}, RequestUnique: 8, PublicationID: 11, Nodeid: 23, Opcode: 15},
		{InHeader: InHeader{Length: uint32(unsafe.Sizeof(PFSPublishIn{})), Opcode: PFS_PUBLISH_OPCODE, Unique: 20}, RequestUnique: PFS_UNIQUE_PUBLISH, PublicationID: 11, Nodeid: 23, Opcode: 15},
		{InHeader: InHeader{Length: uint32(unsafe.Sizeof(PFSPublishIn{})), Opcode: PFS_PUBLISH_OPCODE, Unique: 20}, RequestUnique: 8, PublicationID: 8, Nodeid: 23, Opcode: 15},
		{InHeader: InHeader{Length: uint32(unsafe.Sizeof(PFSPublishIn{})), Opcode: PFS_PUBLISH_OPCODE, Unique: 20}, RequestUnique: 8, PublicationID: uint64(math.MaxInt64) + 1, Nodeid: 23, Opcode: 15},
		{InHeader: InHeader{Length: uint32(unsafe.Sizeof(PFSPublishIn{})), Opcode: PFS_PUBLISH_OPCODE, Unique: 20}, RequestUnique: 8, PublicationID: 12, Nodeid: 23, Opcode: 15},
	} {
		fs.publishCalled = false
		wire = append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(&malformed)), unsafe.Sizeof(malformed))...)
		_, status = ps.HandleRequest([][]byte{wire[:headerSize], wire[headerSize:]}, out)
		if status != OK || fs.publishCalled || int32(binary.LittleEndian.Uint32(out[0][4:8])) != -int32(EIO) {
			t.Fatalf("malformed publication identity reached filesystem: %+v", malformed)
		}
	}
}

func privateFixedRequestBytes[T any](in *T, headerSize uintptr) ([]byte, []byte) {
	wire := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(in)), unsafe.Sizeof(*in))...)
	return wire[:headerSize], wire[headerSize:]
}

func TestPFSRangeSparseOpcodeDispatchAndFraming(t *testing.T) {
	fs := &recordingWriteFS{RawFileSystem: NewDefaultRawFileSystem()}
	ps := NewProtocolServer(fs, &MountOptions{})
	headerSize := unsafe.Sizeof(InHeader{})

	fallocate := PFSFallocateIn{
		InHeader: InHeader{Length: uint32(unsafe.Sizeof(PFSFallocateIn{})), Opcode: PFS_FALLOCATE_OPCODE, Unique: 24, NodeId: 11},
		Fh:       12, Offset: 13, Length: 14, RlimitFsize: 15, FileMaxSize: 16, Mode: 17, WriteFlags: 4,
	}
	header, body := privateFixedRequestBytes(&fallocate, headerSize)
	out := [][]byte{make([]byte, sizeOfOutHeader), make([]byte, unsafe.Sizeof(PFSRangeOut{}))}
	n, status := ps.HandleRequest([][]byte{header, body}, out)
	if status != OK || n != int(sizeOfOutHeader+unsafe.Sizeof(PFSRangeOut{})) || !fs.fallocateCalled || fs.fallocate.Length != 14 {
		t.Fatalf("PFS_FALLOCATE dispatch=(%d,%v,called=%t,in=%+v)", n, status, fs.fallocateCalled, fs.fallocate)
	}
	if got := binary.LittleEndian.Uint32(out[1][24:28]); got != PFS_RANGE_OUT_APPLIED {
		t.Fatalf("PFS_FALLOCATE out flags=%#x", got)
	}

	copyRange := PFSCopyFileRangeIn{
		InHeader: InHeader{Length: uint32(unsafe.Sizeof(PFSCopyFileRangeIn{})), Opcode: PFS_COPY_FILE_RANGE_OPCODE, Unique: 26, NodeId: 11},
		FhIn:     12, OffIn: 13, NodeIdOut: 14, FhOut: 15, OffOut: 16, Len: 17,
		RlimitFsize: 18, FileMaxSize: 19, WriteFlags: 4,
	}
	header, body = privateFixedRequestBytes(&copyRange, headerSize)
	n, status = ps.HandleRequest([][]byte{header, body}, out)
	if status != OK || n != int(sizeOfOutHeader+unsafe.Sizeof(PFSRangeOut{})) || !fs.copyRangeCalled || fs.copyRange.Len != 17 {
		t.Fatalf("PFS_COPY_FILE_RANGE dispatch=(%d,%v,called=%t,in=%+v)", n, status, fs.copyRangeCalled, fs.copyRange)
	}
	if got := binary.LittleEndian.Uint64(out[1][:8]); got != 3 {
		t.Fatalf("PFS_COPY_FILE_RANGE result=%d", got)
	}

	for _, malformed := range []struct {
		opcode uint32
		unique uint64
	}{
		{PFS_FALLOCATE_OPCODE, 25}, {PFS_FALLOCATE_OPCODE, PFS_UNIQUE_PUBLISH},
		{PFS_COPY_FILE_RANGE_OPCODE, 27}, {PFS_COPY_FILE_RANGE_OPCODE, PFS_UNIQUE_PUBLISH},
	} {
		fs.fallocateCalled, fs.copyRangeCalled = false, false
		if malformed.opcode == PFS_FALLOCATE_OPCODE {
			fallocate.Unique = malformed.unique
			header, body = privateFixedRequestBytes(&fallocate, headerSize)
		} else {
			copyRange.Unique = malformed.unique
			header, body = privateFixedRequestBytes(&copyRange, headerSize)
		}
		_, status = ps.HandleRequest([][]byte{header, body}, out)
		if status != OK || fs.fallocateCalled || fs.copyRangeCalled || int32(binary.LittleEndian.Uint32(out[0][4:8])) != -int32(EIO) {
			t.Fatalf("malformed private range reached filesystem: opcode=%d unique=%d", malformed.opcode, malformed.unique)
		}
	}
}

func TestTmpfileStandardCreateWireDispatch(t *testing.T) {
	fs := &recordingWriteFS{RawFileSystem: NewDefaultRawFileSystem()}
	ps := NewProtocolServer(fs, &MountOptions{})
	in := CreateIn{
		InHeader: InHeader{Length: uint32(unsafe.Sizeof(CreateIn{}) + 2), Opcode: _OP_TMPFILE, Unique: 28, NodeId: 11},
		Flags:    uint32(syscall.O_RDWR | syscall.O_EXCL), Mode: 0o640, Umask: 0o027,
	}
	headerSize := unsafe.Sizeof(InHeader{})
	header, body := privateFixedRequestBytes(&in, headerSize)
	out := [][]byte{make([]byte, sizeOfOutHeader), make([]byte, unsafe.Sizeof(CreateOut{}))}
	n, status := ps.HandleRequest([][]byte{header, body, []byte{'/', 0}}, out)
	if status != OK || n != int(sizeOfOutHeader+unsafe.Sizeof(CreateOut{})) || !fs.tmpfileCalled ||
		fs.tmpfileName != "/" || fs.tmpfile.Flags != in.Flags || fs.tmpfile.Mode != in.Mode {
		t.Fatalf("TMPFILE dispatch=(%d,%v,called=%t,name=%q,in=%+v)", n, status, fs.tmpfileCalled, fs.tmpfileName, fs.tmpfile)
	}
	if got := binary.LittleEndian.Uint64(out[1][:8]); got != 41 {
		t.Fatalf("TMPFILE entry nodeid=%d", got)
	}
}

func TestSyncFSProtocol741Dispatch(t *testing.T) {
	fs := &recordingWriteFS{RawFileSystem: NewDefaultRawFileSystem()}
	ps := NewProtocolServer(fs, &MountOptions{})
	in := SyncFSIn{InHeader: InHeader{
		Length: uint32(unsafe.Sizeof(SyncFSIn{})), Opcode: _OP_SYNCFS, Unique: 30, NodeId: FUSE_ROOT_ID,
	}}
	headerSize := unsafe.Sizeof(InHeader{})
	header, body := privateFixedRequestBytes(&in, headerSize)
	out := [][]byte{make([]byte, sizeOfOutHeader)}
	n, status := ps.HandleRequest([][]byte{header, body}, out)
	if status != OK || n != int(sizeOfOutHeader) || !fs.syncFSCalled || fs.syncFS.NodeId != FUSE_ROOT_ID || fs.syncFS.Padding != 0 {
		t.Fatalf("SYNCFS dispatch=(%d,%v,called=%t,in=%+v)", n, status, fs.syncFSCalled, fs.syncFS)
	}
}

func TestPFSSizeNotifyWireAndCapability(t *testing.T) {
	var wire []byte
	server := &protocolServer{
		kernelSettings: InitIn{Flags2: uint32(CAP_PFS_STRICT_COHERENCE >> 32)},
		opts:           &MountOptions{},
		writev: func(iov [][]byte) (int, syscall.Errno) {
			for _, part := range iov {
				wire = append(wire, part...)
			}
			return len(wire), 0
		},
	}
	if status := server.PFSSizeNotify(7, 99, 123); status != OK {
		t.Fatalf("PFSSizeNotify: %v", status)
	}
	if len(wire) != int(sizeOfOutHeader+unsafe.Sizeof(NotifyPFSSizeOut{})) {
		t.Fatalf("notify wire size = %d", len(wire))
	}
	if got := int32(binary.LittleEndian.Uint32(wire[4:8])); got != -int32(NOTIFY_PFS_SIZE) {
		t.Fatalf("notify code = %d, want %d", got, -NOTIFY_PFS_SIZE)
	}
	if got := binary.LittleEndian.Uint64(wire[16:24]); got != 7 {
		t.Fatalf("notify nodeid = %d", got)
	}
	if got := binary.LittleEndian.Uint64(wire[24:32]); got != 99 {
		t.Fatalf("notify size = %d", got)
	}
	if got := binary.LittleEndian.Uint64(wire[32:40]); got != 123 {
		t.Fatalf("notify sequence = %d", got)
	}

	server.kernelSettings = InitIn{}
	if status := server.PFSSizeNotify(7, 99, 123); status != EINVAL {
		t.Fatalf("unnegotiated PFSSizeNotify = %v, want EINVAL", status)
	}
}
