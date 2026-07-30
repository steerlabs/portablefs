package privatepath

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func privateFileParts(path string) (string, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", "", fmt.Errorf("private file must be an absolute clean path: %q", path)
	}
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) || name == "" {
		return "", "", fmt.Errorf("invalid private file path %q", path)
	}
	return filepath.Dir(path), name, nil
}

// WriteFileAtomic replaces one private 0600 regular file relative to a pinned
// 0700 parent descriptor and fsyncs both the file and parent publication.
func WriteFileAtomic(path string, data []byte) error {
	dirPath, name, err := privateFileParts(path)
	if err != nil {
		return err
	}
	parent, err := OpenDir(dirPath)
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := validateExistingPrivateFileAt(parent, name, path); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	var entropy [12]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return fmt.Errorf("generate private temporary file name: %w", err)
	}
	tmpName := "." + name + ".tmp-" + hex.EncodeToString(entropy[:])
	fd, err := unix.Openat(int(parent.Fd()), tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create private temporary file in %s: %w", dirPath, err)
	}
	file := os.NewFile(uintptr(fd), filepath.Join(dirPath, tmpName))
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = unix.Unlinkat(int(parent.Fd()), tmpName, 0)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write private temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync private temporary file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close private temporary file: %w", err)
	}
	if err := unix.Renameat(int(parent.Fd()), tmpName, int(parent.Fd()), name); err != nil {
		return fmt.Errorf("replace private file %s: %w", path, err)
	}
	keep = true
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("sync private directory %s: %w", dirPath, err)
	}
	return nil
}

// ReadFile opens a private file relative to a pinned no-symlink parent and
// validates the named inode before reading.
func ReadFile(path string) ([]byte, error) {
	dirPath, name, err := privateFileParts(path)
	if err != nil {
		return nil, err
	}
	parent, err := OpenExistingDir(dirPath)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	if err := validateOpenPrivateFileAt(parent, name, path, file); err != nil {
		return nil, err
	}
	return io.ReadAll(file)
}

func OpenFileTruncate(path string) (*os.File, error) {
	return openPrivateLog(path, unix.O_TRUNC)
}

func OpenFileAppend(path string) (*os.File, error) {
	return openPrivateLog(path, unix.O_APPEND)
}

func RemoveFileDurable(path string) error {
	dirPath, name, err := privateFileParts(path)
	if err != nil {
		return err
	}
	parent, err := OpenExistingDir(dirPath)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := validateExistingPrivateFileAt(parent, name, path); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open private file %s for removal: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if err := validateOpenPrivateFileAt(parent, name, path, file); err != nil {
		_ = file.Close()
		return err
	}
	if err := unix.Unlinkat(int(parent.Fd()), name, 0); err != nil {
		_ = file.Close()
		return fmt.Errorf("remove private file %s: %w", path, err)
	}
	_ = file.Close()
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("sync private directory after removing %s: %w", path, err)
	}
	return nil
}

func openPrivateLog(path string, mode int) (*os.File, error) {
	dirPath, name, err := privateFileParts(path)
	if err != nil {
		return nil, err
	}
	parent, err := OpenDir(dirPath)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err := validateExistingPrivateFileAt(parent, name, path); err != nil && !errors.Is(err, unix.ENOENT) {
		return nil, err
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_WRONLY|unix.O_CREAT|mode|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open private log %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if err := validateOpenPrivateFileAt(parent, name, path, file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateExistingPrivateFileAt(parent *os.File, name, path string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	return validatePrivateFileStat(path, &stat)
}

func validatePrivateFileStat(path string, stat *unix.Stat_t) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("private file %s is not a real regular file", path)
	}
	if stat.Mode&0o777 != 0o600 {
		return fmt.Errorf("private file %s has permissions %04o, want 0600", path, stat.Mode&0o777)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("private file %s is not owned by uid %d", path, os.Geteuid())
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("private file %s has %d links, want 1", path, stat.Nlink)
	}
	return nil
}

func validateOpenPrivateFileAt(parent *os.File, name, path string, file *os.File) error {
	var opened, named unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &opened); err != nil {
		return fmt.Errorf("inspect open private file %s: %w", path, err)
	}
	if err := validatePrivateFileStat(path, &opened); err != nil {
		return err
	}
	if err := unix.Fstatat(int(parent.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("recheck private file %s: %w", path, err)
	}
	if opened.Dev != named.Dev || opened.Ino != named.Ino {
		return fmt.Errorf("private file %s changed while it was being opened", path)
	}
	return nil
}

// OpenLockFile creates or opens one stable 0600 lock inode relative to a
// pinned private directory descriptor.
func OpenLockFile(parent *os.File, dirPath, name string) (*os.File, error) {
	if filepath.Base(name) != name || name == "." || name == "" {
		return nil, fmt.Errorf("invalid private lock filename %q", name)
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(int(parent.Fd()), name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("open private lock %s: %w", filepath.Join(dirPath, name), err)
	}
	file := os.NewFile(uintptr(fd), filepath.Join(dirPath, name))
	if created {
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("set private lock permissions on %s: %w", file.Name(), err)
		}
	}
	if err := validateOpenPrivateFileAt(parent, name, file.Name(), file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

// ValidateOpenFile revalidates an already-open private file against the name
// in its still-pinned parent directory.
func ValidateOpenFile(parent *os.File, dirPath, name string, file *os.File) error {
	return validateOpenPrivateFileAt(parent, name, filepath.Join(dirPath, name), file)
}
