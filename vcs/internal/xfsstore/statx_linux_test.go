//go:build linux

package xfsstore

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAttrFromStatxUsesOnlyReportedAttributeBits(t *testing.T) {
	tests := []struct {
		name       string
		attributes uint64
		mask       uint64
		want       uint32
	}{
		{name: "none reported", attributes: 0x00200870, mask: 0, want: 0},
		{name: "unset reported bits stay clear", attributes: 0, mask: 0x00200870, want: 0},
		{name: "unreported set bits are omitted", attributes: 0x00200870, mask: 0x00100070, want: 0x00000070},
		{name: "all reported set bits survive", attributes: 0x00300870, mask: 0x00300870, want: 0x00300870},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attr, err := attrFromStatx(unix.Statx_t{
				Mode: unix.S_IFREG | 0o600, Attributes: test.attributes, Attributes_mask: test.mask,
			})
			if err != nil {
				t.Fatal(err)
			}
			if attr.Flags != test.want {
				t.Fatalf("flags = %#x, want %#x from attributes=%#x mask=%#x", attr.Flags, test.want, test.attributes, test.mask)
			}
		})
	}
}

func TestStatFDSymlinkUsesOPathEmptyPathSnapshot(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(filepath.Base(target), link); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(link, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)

	var raw unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_ALL, &raw); err != nil {
		t.Fatal(err)
	}
	attr, err := statFD(fd)
	if err != nil {
		t.Fatal(err)
	}
	if attr.Kind != KindSymlink {
		t.Fatalf("kind = %v, want symlink; the O_PATH snapshot followed the link", attr.Kind)
	}
	want := uint32(raw.Attributes & raw.Attributes_mask)
	if attr.Flags != want {
		t.Fatalf("symlink flags = %#x, want masked statx attributes %#x", attr.Flags, want)
	}
}
