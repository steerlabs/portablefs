//go:build linux

package fusev3

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"golang.org/x/sys/unix"
)

// ManagedKernel retains the root's original bootstrap descriptions. It never
// reconstructs abort authority from an inventory's reusable connection number.
type ManagedKernel struct {
	mu        sync.Mutex
	fuse      *os.File
	installed kernelMount
}

func ObserveManagedKernelIdentity(source, target string) (string, error) {
	k, err := observeExactPlannedKernelMount(source, target)
	if err != nil {
		return "", err
	}
	return k.id + "@" + k.device, nil
}

func ManagedKernelOptions(maxRead uint32) []string {
	return []string{"nodev", "nosuid", "default_permissions", "rootmode=40000", "user_id=1000", "group_id=1000", "max_read=" + strconv.FormatUint(uint64(maxRead), 10)}
}

// InstallClosedFUSE performs the single privileged bootstrap. The caller has
// already committed its intent and reserved its once-only install action.
// Return even partial ownership on failure; a failed INIT still needs removal.
func InstallClosedFUSE(target *os.File, path, instance string, options []string, device, inode uint64) (*ManagedKernel, error) {
	if os.Geteuid() != 0 || target == nil || !mountid.ValidMountInstance(instance) {
		return nil, errors.New("fusev3: exact root bootstrap required")
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(target.Fd()), &st); err != nil {
		return nil, err
	}
	if st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0777 != 0 || uint64(st.Dev) != device || st.Ino != inode {
		return nil, errors.New("fusev3: protected pinned target changed")
	}
	if len(options) != 7 {
		return nil, errors.New("fusev3: invalid managed kernel options")
	}
	read, err := strconv.ParseUint(strings.TrimPrefix(options[6], "max_read="), 10, 32)
	if err != nil || read < kernelMinMaxWrite || !slices.Equal(options, ManagedKernelOptions(uint32(read))) {
		return nil, errors.New("fusev3: invalid managed kernel options")
	}
	source := "portablefs:" + instance
	if _, err := ObservePlannedKernelMountAbsent(source, path); err != nil {
		return nil, err
	}
	// Resolve the live pathname independently before mounting through the pinned
	// description. A replaced path cannot redirect the privileged effect.
	var named unix.Stat_t
	if err := unix.Lstat(path, &named); err != nil {
		return nil, err
	}
	if named.Dev != st.Dev || named.Ino != st.Ino {
		return nil, errors.New("fusev3: target pathname no longer names pinned directory")
	}
	fd, err := unix.Open("/dev/fuse", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	k := &ManagedKernel{fuse: os.NewFile(uintptr(fd), "managed original FUSE"), installed: kernelMount{point: path, source: source, filesystem: "fuse.portablefs"}}
	data := strings.Join(append(append([]string{}, options[2:]...), fmt.Sprintf("fd=%d", fd)), ",")
	if err = unix.Mount(source, fmt.Sprintf("/proc/self/fd/%d", target.Fd()), "fuse.portablefs", unix.MS_NODEV|unix.MS_NOSUID, data); err != nil {
		k.fuse.Close()
		k.fuse = nil
		return k, fmt.Errorf("fusev3: install protected FUSE: %w", err)
	}
	installed, err := captureKernelMount(source, path)
	if err != nil {
		return k, err
	}
	k.installed = installed
	return k, nil
}
func (k *ManagedKernel) Witness() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.installed.id == "" {
		return ""
	}
	return k.installed.id + "@" + k.installed.device
}
func (k *ManagedKernel) Handoff() ([2]*os.File, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out [2]*os.File
	if k.fuse == nil || k.installed.abortFile == nil {
		return out, errors.New("fusev3: incomplete bootstrap description ownership")
	}
	for n, f := range []*os.File{k.fuse, k.installed.abortFile.file} {
		fd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			if out[0] != nil {
				out[0].Close()
			}
			return [2]*os.File{}, err
		}
		out[n] = os.NewFile(uintptr(fd), "managed handoff")
	}
	return out, nil
}
func (k *ManagedKernel) ChildOwnsFUSE() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fuse == nil {
		return nil
	}
	err := k.fuse.Close()
	k.fuse = nil
	return err
}

// Remove keeps EBUSY on voluntary removal. Terminal removal follows cache
// withdrawal in the child, then original-inode abort, exact detach and absence.
// The root never waits for the child connection to exit before this handoff.
func (k *ManagedKernel) Remove(terminal bool) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	installed := k.installed
	if installed.id == "" {
		if _, err := ObservePlannedKernelMountAbsent(installed.source, installed.point); err == nil {
			return nil
		}
		return errors.New("fusev3: installed mount lacks original abort witness; VM discard required")
	}
	if terminal {
		if err := installed.abortFile.abort(); err != nil {
			return err
		}
	}
	present, err := installed.detachTargetInstalled()
	if err != nil {
		return err
	}
	if present {
		flags := 0
		if terminal {
			flags = unix.MNT_DETACH
		}
		if err = unix.Unmount(installed.point, flags); err != nil {
			return err
		}
	}
	_, err = installed.cleanAbsent()
	return err
}
func (k *ManagedKernel) Absent() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.installed.id == "" {
		_, err := ObservePlannedKernelMountAbsent(k.installed.source, k.installed.point)
		return err
	}
	_, err := k.installed.cleanAbsent()
	return err
}
func (k *ManagedKernel) Finalize() error {
	if err := k.Absent(); err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	var err error
	if k.fuse != nil {
		err = k.fuse.Close()
		k.fuse = nil
	}
	return errors.Join(err, k.installed.abortFile.close())
}

// ValidateManagedDescriptors verifies roles and the original connection while
// the mount pins its device identity. No descriptor is reopened by number.
func ValidateManagedDescriptors(fuseFD, abortFD int, source, target string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fuseFD, &st); err != nil {
		return err
	}
	flags, err := unix.FcntlInt(uintptr(fuseFD), unix.F_GETFL, 0)
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(uint64(st.Rdev)) != 10 || unix.Minor(uint64(st.Rdev)) != 229 || flags&unix.O_ACCMODE != unix.O_RDWR {
		return errors.New("fusev3: supplied FUSE role invalid")
	}
	flags, err = unix.FcntlInt(uintptr(abortFD), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_WRONLY {
		return errors.New("fusev3: supplied abort role invalid")
	}
	fd, err := unix.FcntlInt(uintptr(abortFD), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "validate original abort")
	defer f.Close()
	k, err := captureKernelMountWithAbort(source, target, f)
	if err != nil {
		return err
	}
	return k.abortFile.close()
}
