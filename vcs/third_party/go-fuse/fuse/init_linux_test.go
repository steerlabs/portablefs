//go:build linux

package fuse

import (
	"testing"
	"unsafe"
)

func TestLinuxStockProtocolWireLayout(t *testing.T) {
	if _FUSE_KERNEL_VERSION != 7 || _OUR_MINOR_VERSION < 31 {
		t.Fatalf("advertised FUSE protocol = %d.%d, want stock 7.31 or newer", _FUSE_KERNEL_VERSION, _OUR_MINOR_VERSION)
	}
	if got, want := unsafe.Sizeof(InitIn{})-unsafe.Sizeof(InHeader{}), uintptr(64); got != want {
		t.Fatalf("fuse_init_in payload size = %d, want %d", got, want)
	}
	if got, want := unsafe.Sizeof(InitOut{}), uintptr(64); got != want {
		t.Fatalf("fuse_init_out size = %d, want %d", got, want)
	}
	if _OP_SETUPMAPPING != 48 || _OP_REMOVEMAPPING != 49 || _OP_SYNCFS != 50 ||
		_OP_TMPFILE != 51 || _OP_STATX != 52 || _OP_COPY_FILE_RANGE_64 != 53 {
		t.Fatal("stock FUSE opcode assignments changed")
	}
	if CAP_NO_OPENDIR_SUPPORT != 1<<24 || CAP_EXPLICIT_INVAL_DATA != 1<<25 ||
		CAP_HANDLE_KILLPRIV_V2 != 1<<28 || CAP_INIT_EXT != 1<<30 ||
		CAP_DIRECT_IO_ALLOW_MMAP != 1<<36 || CAP_PASSTHROUGH != 1<<37 || CAP_HAS_RESEND != 1<<39 {
		t.Fatal("stock FUSE capability assignments changed")
	}
}
