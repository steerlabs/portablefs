//go:build linux

package workspacemount

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"golang.org/x/sys/unix"
)

func TestRootBusyRemovalRetriesAndEscalatesOriginalOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root protected FUSE owner")
	}
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "retry", true: "terminal"}[terminal], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "protected")
			if err := os.Mkdir(path, 0); err != nil {
				t.Fatal(err)
			}
			fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			target := os.NewFile(uintptr(fd), "protected backing")
			defer target.Close()
			var st unix.Stat_t
			if err = unix.Fstat(fd, &st); err != nil {
				t.Fatal(err)
			}
			k, err := fusev3.InstallClosedFUSE(target, path, "mnt_AAAAAAAAAAAAAAAAAAAAAA", fusev3.ManagedKernelOptions(1<<20), uint64(st.Dev), st.Ino)
			if k != nil {
				defer func() { _ = k.Remove(true); _ = k.Finalize() }()
			}
			if err != nil {
				t.Fatal(err)
			}
			d := &Driver{kernel: k}
			holder, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if holder >= 0 {
					_ = unix.Close(holder)
				}
			}()
			for range 2 {
				if err = d.removeKernelLocked("voluntary", "2"); !errors.Is(err, unix.EBUSY) {
					t.Fatal("busy original was not retained", err)
				}
				if err = k.Absent(); err == nil {
					t.Fatal("busy mount fabricated absence")
				}
			}
			if terminal {
				err = d.removeKernelLocked("terminal", "3")
			} else {
				if err = unix.Close(holder); err != nil {
					t.Fatal(err)
				}
				holder = -1
				err = d.removeKernelLocked("voluntary", "2")
			}
			if err != nil {
				t.Fatal("original removal could not complete", err)
			}
			if err = k.Absent(); err != nil {
				t.Fatal(err)
			}
			if err = k.Finalize(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
