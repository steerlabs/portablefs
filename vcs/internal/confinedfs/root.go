// Package confinedfs provides a race-resistant capability boundary around a
// directory tree. Every path operation is relative to an already-open root
// descriptor; callers never resolve untrusted graft paths with filepath.Join.
package confinedfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
)

// ErrUnsupportedPlatform means the host cannot provide the kernel primitive
// required by PortableFS's local-graft security contract.
var ErrUnsupportedPlatform = errors.New("confinedfs: required kernel path-confinement support is unavailable")

// Root is an open capability for one backing directory.
type Root struct {
	root *os.Root
	once sync.Once
}

// Open creates backingRoot if needed, verifies the platform confinement
// primitive, and opens the directory as a capability. Linux deliberately
// fails closed when openat2 is unavailable or blocked.
func Open(backingRoot string, perm fs.FileMode) (*Root, error) {
	if backingRoot == "" {
		return nil, errors.New("confinedfs: backing root is required")
	}
	if err := os.MkdirAll(backingRoot, perm); err != nil {
		return nil, fmt.Errorf("create backing root: %w", err)
	}
	if err := platformProbe(backingRoot); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(backingRoot)
	if err != nil {
		return nil, fmt.Errorf("open backing root capability: %w", err)
	}
	return &Root{root: r}, nil
}

// Close releases the root capability. It is safe to call more than once.
func (r *Root) Close() error {
	if r == nil || r.root == nil {
		return nil
	}
	var err error
	r.once.Do(func() { err = r.root.Close() })
	return err
}

// clean validates a capability-relative path. os.Root performs the same
// containment checks internally; doing it here makes malformed caller input
// fail consistently before reaching platform-specific traversal.
func clean(name string) (string, error) {
	if strings.IndexByte(name, 0) >= 0 || strings.HasPrefix(name, "/") {
		return "", fs.ErrInvalid
	}
	cleaned := path.Clean(name)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fs.ErrInvalid
	}
	return cleaned, nil
}

func (r *Root) Lstat(name string) (os.FileInfo, error) {
	name, err := clean(name)
	if err != nil {
		return nil, err
	}
	return r.root.Lstat(name)
}

func (r *Root) Stat(name string) (os.FileInfo, error) {
	name, err := clean(name)
	if err != nil {
		return nil, err
	}
	return r.root.Stat(name)
}

func (r *Root) Open(name string) (*os.File, error) {
	return r.OpenFile(name, os.O_RDONLY, 0)
}

func (r *Root) OpenFile(name string, flag int, perm fs.FileMode) (*os.File, error) {
	name, err := clean(name)
	if err != nil {
		return nil, err
	}
	return r.root.OpenFile(name, flag, perm)
}

func (r *Root) Mkdir(name string, perm fs.FileMode) error {
	name, err := clean(name)
	if err != nil {
		return err
	}
	return r.root.Mkdir(name, perm)
}

func (r *Root) MkdirAll(name string, perm fs.FileMode) error {
	name, err := clean(name)
	if err != nil {
		return err
	}
	return r.root.MkdirAll(name, perm)
}

func (r *Root) Remove(name string) error {
	name, err := clean(name)
	if err != nil {
		return err
	}
	return r.root.Remove(name)
}

func (r *Root) Rename(oldname, newname string) error {
	oldname, err := clean(oldname)
	if err != nil {
		return err
	}
	newname, err = clean(newname)
	if err != nil {
		return err
	}
	return r.root.Rename(oldname, newname)
}

func (r *Root) Link(oldname, newname string) error {
	oldname, err := clean(oldname)
	if err != nil {
		return err
	}
	newname, err = clean(newname)
	if err != nil {
		return err
	}
	return r.root.Link(oldname, newname)
}

// Symlink preserves target bytes exactly. A later traversal is still confined:
// safe relative targets work, relative escapes and all absolute targets fail.
func (r *Root) Symlink(target, newname string) error {
	newname, err := clean(newname)
	if err != nil {
		return err
	}
	return r.root.Symlink(target, newname)
}

func (r *Root) Readlink(name string) (string, error) {
	name, err := clean(name)
	if err != nil {
		return "", err
	}
	return r.root.Readlink(name)
}

func (r *Root) ReadDir(name string) ([]os.DirEntry, error) {
	f, err := r.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadDir(-1)
}

func (r *Root) ReadFile(name string) ([]byte, error) {
	name, err := clean(name)
	if err != nil {
		return nil, err
	}
	return r.root.ReadFile(name)
}

func (r *Root) WriteFile(name string, data []byte, perm fs.FileMode) error {
	name, err := clean(name)
	if err != nil {
		return err
	}
	return r.root.WriteFile(name, data, perm)
}
