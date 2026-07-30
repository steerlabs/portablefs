//go:build linux

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// pinnedInstallerDir keeps every edge from / to one installer directory open.
// Mutations use final(), while validate() proves the canonical name chain still
// resolves to those same inodes before the installer reports success.
type pinnedInstallerDir struct {
	path      string
	homeDepth int
	files     []*os.File
	names     []string
}

func openPinnedInstallerDir(home, target string, createBelowHome bool) (*pinnedInstallerDir, error) {
	if err := validateInstallerRoot(home, "account home"); err != nil {
		return nil, err
	}
	if target != home {
		if err := validatePathWithinHome(home, target, "directory"); err != nil {
			return nil, err
		}
	}
	homeParts := installerPathParts(home)
	targetParts := installerPathParts(target)
	if len(targetParts) < len(homeParts) {
		return nil, fmt.Errorf("installer directory %s is outside account home %s", target, home)
	}
	for index := range homeParts {
		if targetParts[index] != homeParts[index] {
			return nil, fmt.Errorf("installer directory %s is outside account home %s", target, home)
		}
	}

	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("pin filesystem root: %w", err)
	}
	chain := &pinnedInstallerDir{
		path:      target,
		homeDepth: len(homeParts),
		files:     []*os.File{os.NewFile(uintptr(rootFD), "/")},
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = chain.Close()
		}
	}()

	for index, component := range targetParts {
		parent := chain.files[len(chain.files)-1]
		fd, openErr := unix.Openat(
			int(parent.Fd()),
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		belowHome := index >= len(homeParts)
		if errors.Is(openErr, unix.ENOENT) && createBelowHome && belowHome {
			if err := unix.Mkdirat(int(parent.Fd()), component, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
				return nil, fmt.Errorf("create installer directory component %s in %s: %w", component, target, err)
			}
			if err := parent.Sync(); err != nil {
				return nil, fmt.Errorf("sync installer directory parent while creating %s: %w", target, err)
			}
			fd, openErr = unix.Openat(
				int(parent.Fd()),
				component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
				0,
			)
		}
		if openErr != nil {
			return nil, fmt.Errorf("open installer directory component %s in %s without symlinks: %w", component, target, openErr)
		}
		child := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), component))
		if child == nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("pin installer directory component %s: invalid file descriptor", component)
		}
		if err := validatePinnedInstallerEdge(parent, component, child); err != nil {
			_ = child.Close()
			return nil, err
		}
		if index >= len(homeParts)-1 {
			if err := validateInstallerDirectoryFD(child, filepath.Join("/", filepath.Join(targetParts[:index+1]...))); err != nil {
				_ = child.Close()
				return nil, err
			}
		}
		chain.names = append(chain.names, component)
		chain.files = append(chain.files, child)
	}
	closeOnError = false
	return chain, nil
}

func installerPathParts(path string) []string {
	return strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
}

func (d *pinnedInstallerDir) final() *os.File {
	return d.files[len(d.files)-1]
}

func (d *pinnedInstallerDir) validate() error {
	for index, name := range d.names {
		parent := d.files[index]
		child := d.files[index+1]
		if err := validatePinnedInstallerEdge(parent, name, child); err != nil {
			return fmt.Errorf("installer directory chain for %s changed: %w", d.path, err)
		}
		if index >= d.homeDepth-1 {
			if err := validateInstallerDirectoryFD(child, child.Name()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *pinnedInstallerDir) Close() error {
	var result error
	for index := len(d.files) - 1; index >= 0; index-- {
		if err := d.files[index].Close(); err != nil && result == nil {
			result = err
		}
	}
	d.files = nil
	return result
}

func validatePinnedInstallerEdge(parent *os.File, name string, child *os.File) error {
	var opened, named unix.Stat_t
	if err := unix.Fstat(int(child.Fd()), &opened); err != nil {
		return fmt.Errorf("inspect pinned installer directory %s: %w", child.Name(), err)
	}
	if err := unix.Fstatat(int(parent.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("recheck pinned installer directory %s: %w", child.Name(), err)
	}
	if opened.Dev != named.Dev || opened.Ino != named.Ino || opened.Mode&unix.S_IFMT != unix.S_IFDIR ||
		named.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("component %s no longer names the pinned directory inode", child.Name())
	}
	return nil
}

func validateInstallerDirectoryFD(directory *os.File, path string) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &stat); err != nil {
		return fmt.Errorf("inspect installer directory %s: %w", path, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("installer path component %s is not a real directory", path)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("path %s is owned by uid %d, want %d", path, stat.Uid, os.Geteuid())
	}
	if stat.Mode&0o022 != 0 {
		return fmt.Errorf("installer path component %s is writable by another account (mode %04o)", path, stat.Mode&0o777)
	}
	return nil
}

func readInstallerDirNames(directory *os.File) ([]string, error) {
	fd, err := unix.Openat(int(directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	copy := os.NewFile(uintptr(fd), directory.Name())
	defer copy.Close()
	entries, err := copy.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

func rejectLinuxInstallerOrphans(directory *pinnedInstallerDir, prefix, allowed, kind string) error {
	if err := directory.validate(); err != nil {
		return err
	}
	names, err := readInstallerDirNames(directory.final())
	if err != nil {
		return fmt.Errorf("inspect %s for incomplete %s transactions: %w", directory.path, kind, err)
	}
	for _, name := range names {
		if strings.HasPrefix(name, prefix) && name != allowed {
			return fmt.Errorf(
				"incomplete PortableFS %s transaction remains at %s; archive or remove that exact path after reviewing it, then retry",
				kind,
				filepath.Join(directory.path, name),
			)
		}
	}
	return nil
}

type installerNamedSnapshot struct {
	exists bool
	dev    uint64
	ino    uint64
	mode   uint32
	uid    uint32
	nlink  uint64
	target string
}

func snapshotInstallerNameAt(parent *os.File, name string) (installerNamedSnapshot, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return installerNamedSnapshot{}, nil
	}
	if err != nil {
		return installerNamedSnapshot{}, err
	}
	snapshot := installerNamedSnapshot{
		exists: true,
		dev:    uint64(stat.Dev),
		ino:    stat.Ino,
		mode:   stat.Mode,
		uid:    stat.Uid,
		nlink:  uint64(stat.Nlink),
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
		target, err := readlinkatExact(int(parent.Fd()), name)
		if err != nil {
			return installerNamedSnapshot{}, err
		}
		snapshot.target = target
	}
	return snapshot, nil
}

func snapshotInstallerFileInfo(info os.FileInfo, target string) (installerNamedSnapshot, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return installerNamedSnapshot{}, fmt.Errorf("installer path has unavailable inode metadata")
	}
	return installerNamedSnapshot{
		exists: true,
		dev:    uint64(stat.Dev),
		ino:    stat.Ino,
		mode:   stat.Mode,
		uid:    stat.Uid,
		nlink:  uint64(stat.Nlink),
		target: target,
	}, nil
}

func readlinkatExact(parentFD int, name string) (string, error) {
	buffer := make([]byte, 4097)
	n, err := unix.Readlinkat(parentFD, name, buffer)
	if err != nil {
		return "", err
	}
	if n == len(buffer) {
		return "", fmt.Errorf("symlink %s exceeds installer validation limit", name)
	}
	return string(buffer[:n]), nil
}

func sameInstallerSnapshot(first, second installerNamedSnapshot) bool {
	return first == second
}

func sameInstallerFileStat(first, second unix.Stat_t) bool {
	return first.Dev == second.Dev &&
		first.Ino == second.Ino &&
		first.Mode == second.Mode &&
		first.Uid == second.Uid &&
		first.Gid == second.Gid &&
		first.Nlink == second.Nlink &&
		first.Size == second.Size &&
		first.Mtim == second.Mtim &&
		first.Ctim == second.Ctim
}

func unlinkInstallerNameDurable(parent *os.File, name string, flags int) error {
	if err := unix.Unlinkat(int(parent.Fd()), name, flags); err != nil {
		return err
	}
	return parent.Sync()
}
