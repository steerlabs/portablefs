//go:build linux

package confinedfs

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxOpenat2CapabilityProbe(t *testing.T) {
	if err := platformProbe(t.TempDir()); err != nil {
		if errors.Is(err, ErrUnsupportedPlatform) {
			t.Fatalf("supported production/CI kernel is missing required openat2 confinement: %v", err)
		}
		t.Fatal(err)
	}
}

func TestLinuxOpenat2ProbeFailsClosed(t *testing.T) {
	original := linuxOpenat2
	linuxOpenat2 = func(int, string, *unix.OpenHow) (int, error) {
		return -1, unix.ENOSYS
	}
	t.Cleanup(func() { linuxOpenat2 = original })

	err := platformProbe(t.TempDir())
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("missing openat2 must fail closed with ErrUnsupportedPlatform, got %v", err)
	}
}
