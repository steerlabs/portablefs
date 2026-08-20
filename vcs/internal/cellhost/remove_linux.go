//go:build linux

package cellhost

import (
	"errors"
	"fmt"
	"regexp"

	"golang.org/x/sys/unix"
)

const (
	// maxRemoveDepth bounds the descent. The walk holds one open descriptor
	// per level, so the bound is both the recursion guard and the descriptor
	// budget; 256 is far beyond any real workspace tree (a deep node_modules
	// is ~20) and a tree deeper than that fails closed with a named error
	// rather than being partially removed or exhausting descriptors.
	maxRemoveDepth = 256
	// removeDirentBuffer is one getdents batch. The walk rescans a directory
	// from the start after each batch, which stays near-linear because the
	// entries it already removed are gone from the front of the directory.
	removeDirentBuffer = 32 << 10
)

// removableEntry is the shape of every entry the helper is allowed to remove
// under a pinned root: one path component, no separator, no dot-dot. Volume
// UUIDs, "portablefs-volume-<uuid>.conf", and
// "portablefs-authority@<uuid>.service.d" all match; nothing that could
// re-enter path resolution does.
var removableEntry = regexp.MustCompile(`^[A-Za-z0-9_@.-]+$`)

func validRemovableEntry(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 255 && removableEntry.MatchString(name)
}

// removeTreeBeneath removes root/name and everything under it, confined to the
// root by construction: the root is opened once with O_NOFOLLOW, every descent
// is an openat2 with RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
// from the descriptor of the directory being emptied, and every removal is an
// unlinkat against that descriptor. No path string below the root is ever
// re-resolved, so a symlink, bind mount, or rename racing under the helper
// cannot redirect a single unlink out of the tree.
//
// A symlink - anywhere, including at name itself - is removed as the symlink
// it is; unlinkat never follows, and the walk only ever descends into a
// descriptor it opened as a directory with O_NOFOLLOW. Crossing a device is
// refused rather than removed: a mount that appeared inside a volume tree is
// not this placement's data.
//
// Absence is success at every level. That is what makes destroy idempotent:
// the second run removes nothing and reports the same end state as the first.
func removeTreeBeneath(root, name string) error {
	if !safeRoot(root) || !validRemovableEntry(name) {
		return fmt.Errorf("%w: refusing to remove %q beneath %q", ErrInvalid, name, root)
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("cellhost: open removal root %s: %w", root, err)
	}
	defer unix.Close(rootFD)
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		return fmt.Errorf("cellhost: stat removal root %s: %w", root, err)
	}
	var entry unix.Stat_t
	if err := unix.Fstatat(rootFD, name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("cellhost: stat %s/%s: %w", root, name, err)
	}
	if entry.Mode&unix.S_IFMT != unix.S_IFDIR {
		return unlinkAbsentOK(rootFD, name, 0)
	}
	if entry.Dev != rootStat.Dev {
		return fmt.Errorf("cellhost: %s/%s is on another device; removal refuses to cross a mount", root, name)
	}
	directoryFD, err := openDirectoryBeneath(rootFD, name)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("cellhost: open %s/%s for removal: %w", root, name, err)
	}
	emptyErr := removeDirectoryContents(directoryFD, rootStat.Dev)
	_ = unix.Close(directoryFD)
	if emptyErr != nil {
		return emptyErr
	}
	return unlinkAbsentOK(rootFD, name, unix.AT_REMOVEDIR)
}

// removalFrame is one open directory on the descent. name is the frame's own
// entry name in its parent, empty for the top frame, whose descriptor belongs
// to the caller.
type removalFrame struct {
	fd   int
	name string
}

// removeDirectoryContents empties topFD without removing it. The walk is
// iterative and post-order: a directory is unlinked only once it is empty, and
// only through its parent's descriptor.
func removeDirectoryContents(topFD int, device uint64) error {
	stack := []removalFrame{{fd: topFD}}
	defer func() {
		// Only frames below the top are ours to close; the top descriptor
		// belongs to the caller. On the success path the stack is empty.
		for index := 1; index < len(stack); index++ {
			_ = unix.Close(stack[index].fd)
		}
	}()
	buffer := make([]byte, removeDirentBuffer)
	for len(stack) > 0 {
		frame := stack[len(stack)-1]
		child, seen, err := drainDirectoryBatch(frame.fd, buffer)
		if err != nil {
			return err
		}
		if child != "" {
			if len(stack) >= maxRemoveDepth {
				return fmt.Errorf("cellhost: refusing to descend past %d directory levels while removing a volume tree", maxRemoveDepth)
			}
			childFD, err := openDirectoryBeneath(frame.fd, child)
			if err != nil {
				if errors.Is(err, unix.ENOENT) {
					continue
				}
				return fmt.Errorf("cellhost: open %s for removal: %w", child, err)
			}
			var stat unix.Stat_t
			if err := unix.Fstat(childFD, &stat); err != nil {
				_ = unix.Close(childFD)
				return err
			}
			if stat.Dev != device {
				_ = unix.Close(childFD)
				return fmt.Errorf("cellhost: %s is on another device; removal refuses to cross a mount", child)
			}
			stack = append(stack, removalFrame{fd: childFD, name: child})
			continue
		}
		if seen > 0 {
			// The batch made progress; rescan this directory for the rest.
			continue
		}
		stack = stack[:len(stack)-1]
		if len(stack) == 0 {
			return nil
		}
		_ = unix.Close(frame.fd)
		if err := unlinkAbsentOK(stack[len(stack)-1].fd, frame.name, unix.AT_REMOVEDIR); err != nil {
			return err
		}
	}
	return nil
}

// drainDirectoryBatch reads one batch of entries, unlinks every non-directory
// in it, and returns the first subdirectory it meets so the caller can descend.
// The count of entries seen distinguishes "this directory is empty" from "this
// batch is done": only a batch with no entries at all proves emptiness.
func drainDirectoryBatch(fd int, buffer []byte) (string, int, error) {
	if _, err := unix.Seek(fd, 0, unix.SEEK_SET); err != nil {
		return "", 0, fmt.Errorf("cellhost: rewind directory for removal: %w", err)
	}
	read, err := unix.ReadDirent(fd, buffer)
	if err != nil {
		return "", 0, fmt.Errorf("cellhost: read directory for removal: %w", err)
	}
	if read <= 0 {
		return "", 0, nil
	}
	var names []string
	_, _, names = unix.ParseDirent(buffer[:read], -1, names)
	seen := 0
	for _, name := range names {
		if name == "." || name == ".." {
			continue
		}
		seen++
		var stat unix.Stat_t
		if err := unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return "", seen, fmt.Errorf("cellhost: stat %s for removal: %w", name, err)
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFDIR {
			return name, seen, nil
		}
		// Symlinks land here and are unlinked as themselves: unlinkat with a
		// zero flag removes the link, never its target.
		if err := unlinkAbsentOK(fd, name, 0); err != nil {
			return "", seen, err
		}
	}
	return "", seen, nil
}

func openDirectoryBeneath(parentFD int, name string) (int, error) {
	return unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
}

func unlinkAbsentOK(parentFD int, name string, flags int) error {
	if err := unix.Unlinkat(parentFD, name, flags); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("cellhost: remove %s: %w", name, err)
	}
	return nil
}

// absentBeneath is the postcondition check: it answers only from a fresh
// lstat through a descriptor opened with O_NOFOLLOW, never from what an action
// reported. A missing root means the entry beneath it is missing too.
func absentBeneath(root, name string) (bool, error) {
	if !safeRoot(root) || !validRemovableEntry(name) {
		return false, fmt.Errorf("%w: cannot verify %q beneath %q", ErrInvalid, name, root)
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return true, nil
		}
		return false, fmt.Errorf("cellhost: open %s to verify removal: %w", root, err)
	}
	defer unix.Close(rootFD)
	var stat unix.Stat_t
	if err := unix.Fstatat(rootFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return true, nil
		}
		return false, fmt.Errorf("cellhost: stat %s/%s to verify removal: %w", root, name, err)
	}
	return false, nil
}
