package portablefsd

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestGraftFlagsMaskExcludesKernelManagedBits pins the flag subset a graft
// backing file may republish. UF_COMPRESSED is the load-bearing exclusion:
// passing it through would make the kernel run decmpfs decompression over
// content the daemon serves uncompressed, corrupting every read.
func TestGraftFlagsMaskExcludesKernelManagedBits(t *testing.T) {
	excluded := map[string]uint32{
		"UF_COMPRESSED": unix.UF_COMPRESSED,
		"UF_TRACKED":    unix.UF_TRACKED,
		"UF_DATAVAULT":  unix.UF_DATAVAULT,
		"SF_RESTRICTED": unix.SF_RESTRICTED,
		"SF_DATALESS":   unix.SF_DATALESS,
		"SF_FIRMLINK":   unix.SF_FIRMLINK,
		"SF_SYNTHETIC":  unix.SF_SYNTHETIC,
	}
	for name, bit := range excluded {
		if graftFlagsMask&bit != 0 {
			t.Fatalf("graftFlagsMask republishes kernel-managed %s", name)
		}
	}

	included := map[string]uint32{
		"UF_NODUMP":    unix.UF_NODUMP,
		"UF_IMMUTABLE": unix.UF_IMMUTABLE,
		"UF_APPEND":    unix.UF_APPEND,
		"UF_OPAQUE":    unix.UF_OPAQUE,
		"UF_HIDDEN":    unix.UF_HIDDEN,
		"SF_ARCHIVED":  unix.SF_ARCHIVED,
		"SF_IMMUTABLE": unix.SF_IMMUTABLE,
		"SF_APPEND":    unix.SF_APPEND,
		"SF_NOUNLINK":  unix.SF_NOUNLINK,
	}
	for name, bit := range included {
		if graftFlagsMask&bit != bit {
			t.Fatalf("graftFlagsMask drops user-meaningful %s", name)
		}
	}

	// A backing file carrying a compressed flag reports only the user bits.
	raw := uint32(unix.UF_COMPRESSED | unix.UF_HIDDEN | unix.UF_TRACKED)
	if got := raw & graftFlagsMask; got != uint32(unix.UF_HIDDEN) {
		t.Fatalf("masked flags = %#x, want %#x", got, uint32(unix.UF_HIDDEN))
	}
}

// TestGraftStatReportsMaskedBackingFlags pins that the stat path applies the
// mask and still carries the user-settable flags a caller can observe.
// UF_COMPRESSED itself is kernel-set and cannot be produced by chflags(2), so
// the exclusion is asserted on the mask above.
func TestGraftStatReportsMaskedBackingFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backing")
	if err := os.WriteFile(path, []byte("graft"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chflags(path, unix.UF_NODUMP|unix.UF_HIDDEN); err != nil {
		t.Skipf("backing filesystem rejects chflags: %v", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	attr := localAttr(fi)
	want := uint32(unix.UF_NODUMP | unix.UF_HIDDEN)
	if attr.Flags != want {
		t.Fatalf("graft flags = %#x, want %#x", attr.Flags, want)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if attr.Flags != st.Flags&graftFlagsMask {
		t.Fatalf("graft flags %#x are not the masked st_flags %#x",
			attr.Flags, st.Flags&graftFlagsMask)
	}
}
