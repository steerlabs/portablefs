//go:build darwin

package portablefsd

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// The macOS 26 repair actuator, daemon-side.
//
// These are the exact synchronous-VFS repair sequences the coherence contract
// specifies — scratch create+unlink to purge a negative dentry, exact source
// unlink to evict a positive binding, and open/attest/unlink/truncate/invalidate
// to drop cached data — issued by the daemon because the sandboxed extension is
// forbidden write-class VFS operations on its own mount. Every syscall here
// re-enters the kernel and surfaces at the extension as an FSKit callback:
// the reserved operands are HMAC-authenticated by the extension's armed
// registry, so this process performs the motion while the extension keeps
// sole authority over what is admitted as repair.
const repairReservedPrefix = ".portablefs-v3-r1-"

const (
	repairItemFile      = "file"
	repairItemDirectory = "directory"
	repairItemSymlink   = "symlink"
)

func actuateRepair(rootFD int, plan repairActuationPlan) (errnoValue byte, err error) {
	operand, err := decodeRepairName(plan.Operand)
	if err != nil {
		return 0, fmt.Errorf("operand: %w", err)
	}
	if !strings.HasPrefix(string(operand), repairReservedPrefix) {
		return 0, errors.New("operand is not in the reserved repair namespace")
	}
	parentFD, err := openRepairParent(rootFD, plan.Parent)
	if err != nil {
		return errnoOf(err), err
	}
	defer unix.Close(parentFD)

	switch plan.Kind {
	case "scratch":
		if plan.ItemKind != "" {
			return 0, errors.New("scratch repair unexpectedly names an item kind")
		}
		fd, err := unix.Openat(parentFD, string(operand), unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			return errnoOf(err), fmt.Errorf("create repair scratch: %w", err)
		}
		unix.Close(fd)
		if err := unix.Unlinkat(parentFD, string(operand), 0); err != nil {
			return errnoOf(err), fmt.Errorf("remove repair scratch: %w", err)
		}
		return 0, nil

	case "evict":
		unlinkFlags, err := repairUnlinkFlags(plan.ItemKind)
		if err != nil {
			return 0, err
		}
		name, err := decodeRepairName(plan.Name)
		if err != nil {
			return 0, fmt.Errorf("name: %w", err)
		}
		if err := unix.Unlinkat(parentFD, string(name), unlinkFlags); err != nil {
			if errors.Is(err, unix.ENOENT) {
				// A post-COMPLETE lookup may have already retired the cached
				// binding. ENOENT is the same kernel-visible postcondition.
				return 0, nil
			}
			return errnoOf(err), fmt.Errorf("evict repair source: %w", err)
		}
		return 0, nil

	case "refresh":
		if plan.ItemKind == repairItemSymlink {
			return 0, errors.New("attribute refresh cannot safely chmod a symlink")
		}
		if plan.ItemKind != repairItemFile && plan.ItemKind != repairItemDirectory {
			return 0, fmt.Errorf("attribute refresh item kind %q is unsupported", plan.ItemKind)
		}
		name, err := decodeRepairName(plan.Name)
		if err != nil {
			return 0, fmt.Errorf("name: %w", err)
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if plan.ItemKind == repairItemDirectory {
			flags |= unix.O_DIRECTORY
		}
		itemFD, err := unix.Openat(parentFD, string(name), flags, 0)
		if err != nil {
			return errnoOf(err), fmt.Errorf("open attribute repair source: %w", err)
		}
		defer unix.Close(itemFD)
		var st unix.Stat_t
		if err := unix.Fstat(itemFD, &st); err != nil {
			return errnoOf(err), fmt.Errorf("stat attribute repair source: %w", err)
		}
		if st.Ino != plan.ExpectedFileID {
			return 0, fmt.Errorf("attribute repair source inode %d is not the attested %d", st.Ino, plan.ExpectedFileID)
		}
		if err := unix.Fchmod(itemFD, uint32(st.Mode&0o7777)); err != nil {
			return errnoOf(err), fmt.Errorf("refresh repair source attributes: %w", err)
		}
		return 0, nil

	case "invalidate":
		if plan.ItemKind != repairItemFile {
			return 0, fmt.Errorf("data repair item kind %q is not file", plan.ItemKind)
		}
		name, err := decodeRepairName(plan.Name)
		if err != nil {
			return 0, fmt.Errorf("name: %w", err)
		}
		fileFD, err := unix.Openat(parentFD, string(name), unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return errnoOf(err), fmt.Errorf("open data repair source: %w", err)
		}
		defer unix.Close(fileFD)
		var st unix.Stat_t
		if err := unix.Fstat(fileFD, &st); err != nil {
			return errnoOf(err), fmt.Errorf("stat data repair source: %w", err)
		}
		if st.Ino != plan.ExpectedFileID {
			return 0, fmt.Errorf("data repair source inode %d is not the attested %d", st.Ino, plan.ExpectedFileID)
		}
		if err := unix.Unlinkat(parentFD, string(name), 0); err != nil {
			return errnoOf(err), fmt.Errorf("evict data repair source: %w", err)
		}
		if err := invalidateOpenData(fileFD, plan); err != nil {
			return errnoOf(err), err
		}
		return 0, nil

	default:
		return 0, fmt.Errorf("unknown repair kind %q", plan.Kind)
	}
}

func repairUnlinkFlags(itemKind string) (int, error) {
	switch itemKind {
	case repairItemFile, repairItemSymlink:
		return 0, nil
	case repairItemDirectory:
		return unix.AT_REMOVEDIR, nil
	default:
		return 0, fmt.Errorf("unknown repair item kind %q", itemKind)
	}
}

func invalidateOpenData(fileFD int, plan repairActuationPlan) error {
	// Unconditional by design: on macOS 26 fstat may already report the new
	// length while stale cached pages still expose the old EOF.
	if err := unix.Ftruncate(fileFD, int64(plan.AuthoritativeSize)); err != nil {
		return fmt.Errorf("truncate data repair source: %w", err)
	}
	const window = 128 << 20
	for offset := uint64(0); offset < plan.AuthoritativeSize; offset += window {
		length := plan.AuthoritativeSize - offset
		if length > window {
			length = window
		}
		mapped, err := unix.Mmap(fileFD, int64(offset), int(length), unix.PROT_READ, unix.MAP_SHARED)
		if err != nil {
			return fmt.Errorf("map data repair source: %w", err)
		}
		syncErr := unix.Msync(mapped, unix.MS_INVALIDATE)
		unmapErr := unix.Munmap(mapped)
		if syncErr != nil {
			return fmt.Errorf("invalidate cached pages: %w", syncErr)
		}
		if unmapErr != nil {
			return fmt.Errorf("unmap data repair source: %w", unmapErr)
		}
	}
	return nil
}

func openRepairParent(rootFD int, components []string) (int, error) {
	current, err := unix.Dup(rootFD)
	if err != nil {
		return -1, fmt.Errorf("dup mount root: %w", err)
	}
	for _, encoded := range components {
		component, err := decodeRepairName(encoded)
		if err != nil {
			unix.Close(current)
			return -1, fmt.Errorf("path component: %w", err)
		}
		next, err := unix.Openat(current, string(component), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(current)
		if err != nil {
			return -1, fmt.Errorf("open path component: %w", err)
		}
		current = next
	}
	return current, nil
}

// decodeRepairName decodes one base64 filesystem name and refuses everything
// that is not a single ordinary directory entry.
func decodeRepairName(encoded string) ([]byte, error) {
	name, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(name) == 0 || len(name) > 255 ||
		string(name) == "." || string(name) == ".." ||
		strings.ContainsAny(string(name), "/\x00") {
		return nil, errors.New("not a single directory-entry name")
	}
	return name, nil
}

func errnoOf(err error) byte {
	var errno unix.Errno
	if errors.As(err, &errno) && errno > 0 && errno < 255 {
		return byte(errno)
	}
	return 0
}
