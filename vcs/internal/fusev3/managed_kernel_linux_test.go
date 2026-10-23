//go:build linux

package fusev3

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestManagedKernelFailedINITRetainsExactRemovalOwner(t *testing.T) {
	k, _, path := managedBootstrapFixture(t)
	files, err := k.Handoff()
	if err != nil {
		t.Fatal(err)
	}
	defer files[0].Close()
	defer files[1].Close()
	frame := make([]byte, 8192)
	n, err := unix.Read(int(files[0].Fd()), frame)
	if err != nil || n < 40 || binary.LittleEndian.Uint32(frame[4:]) != 26 {
		t.Fatal("kernel did not request real FUSE INIT", n, err)
	}
	reply := make([]byte, 16)
	binary.LittleEndian.PutUint32(reply, uint32(len(reply)))
	errno := int32(-int32(syscall.EPROTO))
	binary.LittleEndian.PutUint32(reply[4:], uint32(errno))
	copy(reply[8:], frame[8:16])
	if n, err = unix.Write(int(files[0].Fd()), reply); err != nil || n != len(reply) {
		t.Fatal("failed INIT reply did not settle", n, err)
	}
	if err = k.ChildOwnsFUSE(); err != nil {
		t.Fatal(err)
	}
	if err = k.Absent(); err == nil {
		t.Fatal("failed INIT fabricated kernel absence")
	}
	if err = k.Remove(true); err != nil {
		t.Fatal("root could not remove its failed INIT", err)
	}
	if err = k.Finalize(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode().Perm() != 0 {
		t.Fatal("failed INIT exposed writable backing", st, err)
	}
}

func TestManagedKernelRejectsForeignBootstrapDescriptions(t *testing.T) {
	k, _, path := managedBootstrapFixture(t)
	files, err := k.Handoff()
	if err != nil {
		t.Fatal(err)
	}
	defer files[0].Close()
	defer files[1].Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	for _, pair := range [][2]int{{int(r.Fd()), int(w.Fd())}, {int(files[0].Fd()), int(w.Fd())}, {int(files[0].Fd()), int(files[0].Fd())}, {int(files[1].Fd()), int(files[0].Fd())}} {
		if err = ValidateManagedDescriptors(pair[0], pair[1], "portablefs:mnt_AAAAAAAAAAAAAAAAAAAAAA", path); err == nil {
			t.Fatal("foreign or duplicate descriptor roles accepted", pair)
		}
	}
	if err = ValidateManagedDescriptors(int(files[0].Fd()), int(files[1].Fd()), "portablefs:mnt_AAAAAAAAAAAAAAAAAAAAAA", path); err != nil {
		t.Fatal("rejected handoff damaged the original owner", err)
	}
	if err = k.Absent(); err == nil {
		t.Fatal("rejected bootstrap erased the installed original")
	}
}

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
	if !k.aborted {
		t.Fatal("alias ambiguity erased successful original abort")
	}
	if err := unix.Unmount(alias, unix.MNT_DETACH); err != nil {
		t.Fatal(err)
	}
	if err := k.Absent(); err != nil {
		t.Fatal(err)
	}
	if err := k.Remove(true); err != nil {
		t.Fatal("original terminal owner could not finish after alias removal", err)
	}
}
