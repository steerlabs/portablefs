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
// specifies — scratch create+unlink to purge a negative dentry, isolate-and-
// remove to evict a positive binding, isolate/attest/truncate/invalidate to
// drop cached data — issued by the daemon because the sandboxed extension is
// forbidden write-class VFS operations on its own mount. Every syscall here
// re-enters the kernel and surfaces at the extension as an FSKit callback:
// the reserved operands are HMAC-authenticated by the extension's armed
// registry, so this process performs the motion while the extension keeps
// sole authority over what is admitted as repair.
const repairReservedPrefix = ".portablefs-v3-r1-"

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
		fd, err := unix.Openat(parentFD, string(operand), unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			return errnoOf(err), fmt.Errorf("create repair scratch: %w", err)
		}
		unix.Close(fd)
		if err := unix.Unlinkat(parentFD, string(operand), 0); err != nil {
			return errnoOf(err), fmt.Errorf("remove repair scratch: %w", err)
		}
		return 0, nil

	case "evict", "invalidate":
		name, err := decodeRepairName(plan.Name)
		if err != nil {
			return 0, fmt.Errorf("name: %w", err)
		}
		if err := unix.Renameat(parentFD, string(name), parentFD, string(operand)); err != nil {
			return errnoOf(err), fmt.Errorf("isolate repair target: %w", err)
		}
		finish := func(inner error, innerErrno byte) (byte, error) {
			if inner == nil {
				if err := unix.Unlinkat(parentFD, string(operand), 0); err != nil {
					return errnoOf(err), fmt.Errorf("remove isolated name: %w", err)
				}
				return 0, nil
			}
			// The user's name was moved to the operand and the repair failed:
			// restore the namespace this actuation disturbed, and report the
			// rollback's own failure loudly if even that is denied.
			if rollback := unix.Renameat(parentFD, string(operand), parentFD, string(name)); rollback != nil {
				return innerErrno, fmt.Errorf("%w; ROLLBACK ALSO FAILED, name stranded at operand: %v", inner, rollback)
			}
			return innerErrno, inner
		}
		if plan.Kind == "evict" {
			return finish(nil, 0)
		}
		return finish(invalidateIsolatedData(parentFD, string(operand), plan))

	default:
		return 0, fmt.Errorf("unknown repair kind %q", plan.Kind)
	}
}

func invalidateIsolatedData(parentFD int, operand string, plan repairActuationPlan) (error, byte) {
	fileFD, err := unix.Openat(parentFD, operand, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open isolated target: %w", err), errnoOf(err)
	}
	defer unix.Close(fileFD)
	var st unix.Stat_t
	if err := unix.Fstat(fileFD, &st); err != nil {
		return fmt.Errorf("stat isolated target: %w", err), errnoOf(err)
	}
	if st.Ino != plan.ExpectedFileID {
		return fmt.Errorf("isolated target inode %d is not the attested %d", st.Ino, plan.ExpectedFileID), 0
	}
	// Unconditional by design: on macOS 26 fstat may already report the new
	// length while stale cached pages still expose the old EOF.
	if err := unix.Ftruncate(fileFD, int64(plan.AuthoritativeSize)); err != nil {
		return fmt.Errorf("truncate isolated target: %w", err), errnoOf(err)
	}
	const window = 128 << 20
	for offset := uint64(0); offset < plan.AuthoritativeSize; offset += window {
		length := plan.AuthoritativeSize - offset
		if length > window {
			length = window
		}
		mapped, err := unix.Mmap(fileFD, int64(offset), int(length), unix.PROT_READ, unix.MAP_SHARED)
		if err != nil {
			return fmt.Errorf("map isolated target: %w", err), errnoOf(err)
		}
		syncErr := unix.Msync(mapped, unix.MS_INVALIDATE)
		unmapErr := unix.Munmap(mapped)
		if syncErr != nil {
			return fmt.Errorf("invalidate cached pages: %w", syncErr), errnoOf(syncErr)
		}
		if unmapErr != nil {
			return fmt.Errorf("unmap isolated target: %w", unmapErr), errnoOf(unmapErr)
		}
	}
	return nil, 0
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
