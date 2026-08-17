//go:build linux

package fuse

import (
	"testing"
	"unsafe"
)

func TestLinuxProtocol741WireLayout(t *testing.T) {
	if _FUSE_KERNEL_VERSION != 7 || _OUR_MINOR_VERSION != 41 {
		t.Fatalf("advertised FUSE protocol = %d.%d, want 7.41", _FUSE_KERNEL_VERSION, _OUR_MINOR_VERSION)
	}
	if got, want := unsafe.Sizeof(InitIn{})-unsafe.Sizeof(InHeader{}), uintptr(64); got != want {
		t.Fatalf("fuse_init_in payload size = %d, want %d", got, want)
	}
	if got, want := unsafe.Sizeof(InitOut{}), uintptr(64); got != want {
		t.Fatalf("fuse_init_out size = %d, want %d", got, want)
	}
	var out InitOut
	if unsafe.Offsetof(out.MapAlignment) != 30 || unsafe.Offsetof(out.Flags2) != 32 ||
		unsafe.Offsetof(out.MaxStackDepth) != 36 || unsafe.Offsetof(out.Unused) != 40 {
		t.Fatalf("fuse_init_out 7.41 offsets changed: map_alignment=%d flags2=%d max_stack=%d unused=%d",
			unsafe.Offsetof(out.MapAlignment), unsafe.Offsetof(out.Flags2), unsafe.Offsetof(out.MaxStackDepth), unsafe.Offsetof(out.Unused))
	}
	var header InHeader
	if unsafe.Sizeof(header) != 40 || unsafe.Offsetof(header.TotalExtlen) != 36 || unsafe.Offsetof(header.Padding) != 38 {
		t.Fatalf("fuse_in_header 7.41 layout changed: size=%d total_extlen=%d padding=%d",
			unsafe.Sizeof(header), unsafe.Offsetof(header.TotalExtlen), unsafe.Offsetof(header.Padding))
	}

	// These are the protocol additions from 7.29 through 7.41 that this fork
	// can be sent or can negotiate. Keeping the audit executable prevents a
	// future minor bump from becoming a constant-only assertion.
	if _OP_SETUPMAPPING != 48 || _OP_REMOVEMAPPING != 49 || _OP_SYNCFS != 50 ||
		_OP_TMPFILE != 51 || _OP_STATX != 52 || _OP_COPY_FILE_RANGE_64 != 53 {
		t.Fatal("FUSE 7.29-7.41 opcode assignments changed")
	}
	if CAP_NO_OPENDIR_SUPPORT != 1<<24 || CAP_EXPLICIT_INVAL_DATA != 1<<25 ||
		CAP_MAP_ALIGNMENT != 1<<26 || CAP_SUBMOUNTS != 1<<27 ||
		CAP_HANDLE_KILLPRIV_V2 != 1<<28 || CAP_SETXATTR_EXT != 1<<29 ||
		CAP_INIT_EXT != 1<<30 || CAP_SECURITY_CTX != 1<<32 ||
		CAP_CREATE_SUPP_GROUP != 1<<34 || CAP_HAS_EXPIRE_ONLY != 1<<35 ||
		CAP_DIRECT_IO_ALLOW_MMAP != 1<<36 || CAP_PASSTHROUGH != 1<<37 ||
		CAP_NO_EXPORT_SUPPORT != 1<<38 || CAP_HAS_RESEND != 1<<39 || CAP_ALLOW_IDMAP != 1<<40 {
		t.Fatal("FUSE 7.29-7.41 capability assignments changed")
	}
	for name, layout := range map[string]struct{ got, want uintptr }{
		"fuse_attr size":           {unsafe.Sizeof(Attr{}), 88},
		"fuse_attr flags offset":   {unsafe.Offsetof(Attr{}.Flags), 84},
		"fuse_setxattr_in payload": {unsafe.Sizeof(SetXAttrIn{}) - unsafe.Sizeof(InHeader{}), 8},
		"fuse_create_in payload":   {unsafe.Sizeof(CreateIn{}) - unsafe.Sizeof(InHeader{}), 16},
		"fuse_syncfs_in payload":   {unsafe.Sizeof(SyncFSIn{}) - unsafe.Sizeof(InHeader{}), 8},
		"fuse_open_out size":       {unsafe.Sizeof(OpenOut{}), 16},
		"fuse_open_out backing_id": {unsafe.Offsetof(OpenOut{}.BackingID), 12},
		"fuse_statx_in payload":    {unsafe.Sizeof(StatxIn{}) - unsafe.Sizeof(InHeader{}), 24},
		"fuse_statx_out size":      {unsafe.Sizeof(StatxOut{}), 288},
	} {
		if layout.got != layout.want {
			t.Errorf("%s = %d, want %d", name, layout.got, layout.want)
		}
	}
}

func TestInitNegotiatesExactLinuxProtocol741(t *testing.T) {
	fs := &recordingWriteFS{RawFileSystem: NewDefaultRawFileSystem()}
	ps := NewProtocolServer(fs, &MountOptions{
		EnableLocks:       true,
		MaxWrite:          64 * 1024,
		MaxStackDepth:     1,
		ExtraCapabilities: CAP_ATOMIC_O_TRUNC | CAP_HANDLE_KILLPRIV_V2 | CAP_PFS_STRICT_COHERENCE | CAP_PFS_CACHED_DATA | CAP_PFS_WRITE_ONESHOT,
		DisabledCapabilities: CAP_NO_OPEN_SUPPORT | CAP_NO_OPENDIR_SUPPORT | CAP_PASSTHROUGH |
			CAP_DIRECT_IO_ALLOW_MMAP | CAP_HAS_RESEND,
	})
	requested := uint64(CAP_POSIX_LOCKS | CAP_FLOCK_LOCKS | CAP_ATOMIC_O_TRUNC | CAP_HANDLE_KILLPRIV_V2 |
		CAP_NO_OPEN_SUPPORT | CAP_NO_OPENDIR_SUPPORT | CAP_PASSTHROUGH | CAP_DIRECT_IO_ALLOW_MMAP |
		CAP_HAS_RESEND | CAP_PFS_STRICT_COHERENCE | CAP_PFS_CACHED_DATA | CAP_PFS_WRITE_ONESHOT)
	in := InitIn{InHeader: InHeader{
		Length: uint32(unsafe.Sizeof(InitIn{})), Opcode: _OP_INIT, Unique: 32,
	}, Major: 7, Minor: 41, Flags: uint32(requested), Flags2: uint32(requested >> 32)}
	headerSize := unsafe.Sizeof(InHeader{})
	header, body := privateFixedRequestBytes(&in, headerSize)
	out := [][]byte{make([]byte, sizeOfOutHeader), make([]byte, unsafe.Sizeof(InitOut{}))}
	n, status := ps.HandleRequest([][]byte{header, body}, out)
	if status != OK || n != int(sizeOfOutHeader+unsafe.Sizeof(InitOut{})) {
		t.Fatalf("INIT dispatch=(%d,%v)", n, status)
	}
	reply := (*InitOut)(unsafe.Pointer(&out[1][0]))
	if reply.Major != 7 || reply.Minor != 41 || reply.MapAlignment != 0 || reply.MaxStackDepth != 1 {
		t.Fatalf("INIT reply=%+v", reply)
	}
	granted := reply.Flags64()
	if granted&uint64(CAP_POSIX_LOCKS|CAP_FLOCK_LOCKS|CAP_ATOMIC_O_TRUNC|CAP_HANDLE_KILLPRIV_V2) !=
		uint64(CAP_POSIX_LOCKS|CAP_FLOCK_LOCKS|CAP_ATOMIC_O_TRUNC|CAP_HANDLE_KILLPRIV_V2) ||
		granted&(CAP_PFS_STRICT_COHERENCE|CAP_PFS_CACHED_DATA|CAP_PFS_WRITE_ONESHOT) !=
			CAP_PFS_STRICT_COHERENCE|CAP_PFS_CACHED_DATA|CAP_PFS_WRITE_ONESHOT {
		t.Fatalf("INIT omitted strict required capabilities: %#x", granted)
	}
	if granted&(CAP_NO_OPEN_SUPPORT|CAP_NO_OPENDIR_SUPPORT|CAP_PASSTHROUGH|CAP_DIRECT_IO_ALLOW_MMAP|CAP_HAS_RESEND) != 0 {
		t.Fatalf("INIT granted an explicitly disabled capability: %#x", granted)
	}
}
