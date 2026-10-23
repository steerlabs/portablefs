//go:build linux

package fusev3

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func managedBootstrapFixture(t *testing.T) (*ManagedKernel, *os.File, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root protected-path bootstrap boundary")
	}
	path := filepath.Join(t.TempDir(), "protected")
	if err := os.Mkdir(path, 0); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	target := os.NewFile(uintptr(fd), "protected backing")
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	k, err := InstallClosedFUSE(target, path, "mnt_AAAAAAAAAAAAAAAAAAAAAA", ManagedKernelOptions(1<<20), uint64(st.Dev), st.Ino)
	if err != nil {
		target.Close()
		if k != nil {
			_ = k.Remove(true)
			_ = k.Finalize()
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k.Remove(true); _ = k.Finalize(); target.Close() })
	return k, target, path
}
func TestManagedKernelProtectedBootstrapAndExactRemoval(t *testing.T) {
	k, target, path := managedBootstrapFixture(t)
	var backing unix.Stat_t
	if err := unix.Fstat(int(target.Fd()), &backing); err != nil || backing.Mode&0777 != 0 || backing.Uid != 0 {
		t.Fatal(backing, err)
	}
	if k.Witness() == "" {
		t.Fatal("installed kernel lacks exact witness")
	}
	files, err := k.Handoff()
	if err != nil {
		t.Fatal(err)
	}
	defer files[0].Close()
	defer files[1].Close()
	if err = ValidateManagedDescriptors(int(files[0].Fd()), int(files[1].Fd()), "portablefs:mnt_AAAAAAAAAAAAAAAAAAAAAA", path); err != nil {
		t.Fatal(err)
	}
	if err = ValidateManagedDescriptors(int(files[1].Fd()), int(files[0].Fd()), "portablefs:mnt_AAAAAAAAAAAAAAAAAAAAAA", path); err == nil {
		t.Fatal("swapped bootstrap roles accepted")
	}
	if err = k.ChildOwnsFUSE(); err != nil {
		t.Fatal(err)
	}
	if _, err = k.Handoff(); err == nil {
		t.Fatal("root replay after child ownership")
	}
	if err = k.Remove(true); err != nil {
		t.Fatal(err)
	}
	if err = k.Absent(); err != nil {
		t.Fatal(err)
	}
	if err = k.Finalize(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode().Perm() != 0 {
		t.Fatal(st, err)
	}
}
func TestManagedKernelVoluntaryEBUSYRetainsOriginalOwner(t *testing.T) {
	k, _, path := managedBootstrapFixture(t)
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = k.Remove(false); !errors.Is(err, syscall.EBUSY) {
		t.Fatal("voluntary removal erased EBUSY", err)
	}
	if err = k.Absent(); err == nil {
		t.Fatal("busy removal fabricated absence")
	}
	if err = k.Remove(true); err != nil {
		t.Fatal(err)
	}
	if err = k.Absent(); err != nil {
		t.Fatal(err)
	}
}
func TestManagedKernelExternalUnmountNeedsIndependentAbsence(t *testing.T) {
	k, _, path := managedBootstrapFixture(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Mkdir(alias, 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(path, alias, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(alias, unix.MNT_DETACH)
	if err := unix.Unmount(path, unix.MNT_DETACH); err != nil {
		t.Fatal(err)
	}
	if err := k.Absent(); err == nil {
		t.Fatal("external path removal hid retained source alias")
	}
	if err := k.Remove(true); err == nil {
		t.Fatal("terminal removal hid foreign alias")
	}
	if err := unix.Unmount(alias, unix.MNT_DETACH); err != nil {
		t.Fatal(err)
	}
	if err := k.Absent(); err != nil {
		t.Fatal(err)
	}
}
