//go:build linux

package fusev3

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// kernelAbortFile retains the original fusectl inode, not a reusable connection
// number. Linux clears that inode's connection pointer on retirement; writes to
// an old open file then do nothing, even when the numeric path names a successor.
type kernelAbortFile struct {
	file     *os.File
	identity os.FileInfo
	once     sync.Once
	closeErr error
}

func openKernelAbortFile(path string) (*kernelAbortFile, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("fusev3: retain original FUSE abort descriptor: %w", err)
	}
	identity, err := file.Stat()
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return &kernelAbortFile{file: file, identity: identity}, nil
}

func (a *kernelAbortFile) abort() error {
	_, err := a.file.Write([]byte("1"))
	return err
}

func (a *kernelAbortFile) close() error {
	if a == nil {
		return nil
	}
	a.once.Do(func() { a.closeErr = a.file.Close() })
	return a.closeErr
}

// current is read-only. It disambiguates even a caller reusing a source name
// together with a recycled mount ID, device number, and mountpoint.
func (a *kernelAbortFile) current() (bool, error) {
	info, err := os.Stat(a.file.Name())
	if err != nil {
		return false, fmt.Errorf("fusev3: inspect original FUSE abort inode: %w", err)
	}
	return os.SameFile(a.identity, info), nil
}

func readKernelMounts() ([]kernelMount, error) {
	data, err := readMountInfo()
	if err != nil {
		return nil, fmt.Errorf("fusev3: read %s: %w", mountInfoPath, err)
	}
	var records []kernelMount
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		separator := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				separator = i
				break
			}
		}
		if len(fields) < 10 || separator < 0 || separator+3 >= len(fields) {
			return nil, fmt.Errorf("fusev3: %s contains a malformed mount record", mountInfoPath)
		}
		records = append(records, kernelMount{id: fields[0], device: fields[2], point: unescapeMountField(fields[4]), filesystem: fields[separator+1], source: unescapeMountField(fields[separator+2])})
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("fusev3: %s produced no mount records; absence cannot be observed", mountInfoPath)
	}
	return records, nil
}

func (k kernelMount) matches(record kernelMount) (bool, error) {
	if k.id == "" || k.device == "" || k.point == "" || k.filesystem == "" || k.source == "" {
		return false, errors.New("fusev3: recorded kernel mount identity is incomplete")
	}
	// A moved mount or bind alias still refers to the original filesystem even
	// if its mount ID or path differs. It cannot authorize a clean detach.
	if k.device != record.device || k.filesystem != record.filesystem || k.source != record.source {
		return false, nil
	}
	if k.abortFile != nil {
		return k.abortFile.current()
	}
	return true, nil
}

// detachTargetInstalled refuses moved or overmounted targets and skips a path
// already occupied by a successor. The fusermount helper still owns the actual
// namespace operation, so administrative replacement must serialize with it.
func (k kernelMount) detachTargetInstalled() (bool, error) {
	records, err := readKernelMounts()
	if err != nil {
		return false, err
	}
	present, atPath := false, 0
	for _, record := range records {
		if record.point == k.point {
			atPath++
		}
		matches, err := k.matches(record)
		if err != nil {
			return false, err
		}
		if !matches {
			continue
		}
		if record.point != k.point || record.id != k.id {
			return false, errors.New("fusev3: original filesystem moved or has a retained mount alias")
		}
		present = true
	}
	if present && atPath != 1 {
		return false, errors.New("fusev3: original mountpoint has an ambiguous kernel identity")
	}
	return present, nil
}

// captureKernelMount runs before Serve and before any background teardown can
// start. O_PATH pins the superblock during capture: /dev/fuse alone does not
// prevent kill_anon_super from releasing its anonymous device number. The
// temporary root reference is released before serving, so it cannot keep an
// ordinary or external unmount busy.
func captureKernelMount(fsName, mountpoint string) (kernelMount, error) {
	root, err := os.OpenFile(mountpoint, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return kernelMount{}, fmt.Errorf("fusev3: pin mounted root during identity capture: %w", err)
	}
	defer root.Close()
	installed, err := observeExactPlannedKernelMount(fsName, mountpoint)
	if err != nil {
		return kernelMount{}, err
	}
	fdinfo, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", root.Fd()))
	if err != nil {
		return kernelMount{}, fmt.Errorf("fusev3: inspect pinned root mount ID: %w", err)
	}
	var mountID string
	for _, line := range strings.Split(string(fdinfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "mnt_id:" {
			mountID = fields[1]
		}
	}
	if mountID != installed.id {
		return kernelMount{}, errors.New("fusev3: mounted root changed during identity capture")
	}
	major, minor, ok := strings.Cut(installed.device, ":")
	if _, err := strconv.ParseUint(minor, 10, 32); !ok || err != nil || major != "0" {
		return kernelMount{}, fmt.Errorf("fusev3: unexpected FUSE mount device %q", installed.device)
	}
	abort, err := openKernelAbortFile("/sys/fs/fuse/connections/" + minor + "/abort")
	if err != nil {
		return kernelMount{}, err
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(int(abort.file.Fd()), &filesystem); err != nil || filesystem.Type != 0x65735543 /* FUSE_CTL_SUPER_MAGIC */ {
		return kernelMount{}, errors.Join(errors.New("fusev3: original abort descriptor is not on fusectl"), err, abort.close())
	}
	installed.abortFile = abort
	return installed, nil
}

func (m *Mount) unmountOwnedKernelMount() error {
	installed := m.kernelMount
	if installed.point == "" {
		if _, err := observePlannedKernelMountAbsent(m.plannedFSName, m.plannedMountpoint); err == nil {
			return nil
		}
		var err error
		installed, err = observeExactPlannedKernelMount(m.plannedFSName, m.plannedMountpoint)
		if err != nil {
			return err
		}
	}
	present, err := installed.detachTargetInstalled()
	if err != nil || !present {
		return err
	}
	return m.server.Unmount()
}
