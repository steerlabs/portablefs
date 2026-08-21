package archiver

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/steerlabs/portablefs/vcs/archive"
)

// MaxWalkDepth bounds how deep the walk descends. It is a resource bound rather
// than a format rule: the walk holds one open descriptor per level of the
// current path, and a tree deeper than this could not be expressed as a path
// inside the format's 4096-byte path bound anyway.
const MaxWalkDepth = 1024

// maxXattrListBytes bounds one flistxattr result. The format carries at most 64
// attributes of at most 255 name bytes each, so a list larger than this cannot
// describe an entry the format can hold.
const maxXattrListBytes = 64 << 10

// Walker enumerates one volume tree as an archive.Source: depth-first, names in
// byte order, one raw name component at a time from an open root descriptor.
//
// It is deliberately not safe for concurrent use. The builder drains it from
// one goroutine and then opens file content through the closures it produced;
// both phases use the same one-entry parent-directory cache.
type Walker struct {
	root     *os.File
	stack    []*walkDir
	next     uint32
	started  bool
	finished bool

	// cachedDir is the parent directory of the most recently opened file. The
	// builder groups small files by parent directory, so a one-entry cache
	// turns a per-file path walk into a single openat for the common case.
	cachedDir *os.File
	cachedKey string
}

type walkDir struct {
	file  *os.File
	index uint32
	names []string
	at    int
	path  []string
	// owned is false for the volume root, whose descriptor belongs to the
	// walker for its whole life: the builder reads file content after the walk
	// has popped every level, and every content read starts from the root.
	owned bool
}

// OpenVolume opens the volume tree's root and prepares the walk. The root is
// the only path string this package resolves; every descendant is reached
// descriptor-relative from the descriptor opened here.
func OpenVolume(root string) (*Walker, error) {
	file, err := openRootDirectory(root)
	if err != nil {
		return nil, fmt.Errorf("archiver: open volume root: %w", err)
	}
	return &Walker{root: file}, nil
}

// Close releases every descriptor the walk still holds. It is safe to call more
// than once and after a failed walk.
func (w *Walker) Close() error {
	for _, directory := range w.stack {
		if directory.owned {
			_ = directory.file.Close()
		}
	}
	w.stack = nil
	if w.cachedDir != nil {
		_ = w.cachedDir.Close()
		w.cachedDir = nil
		w.cachedKey = ""
	}
	if w.root != nil {
		err := w.root.Close()
		w.root = nil
		return err
	}
	return nil
}

// Next returns the next entry in depth-first order, reporting io.EOF when the
// walk is complete. An entry the format cannot carry — any inode kind but
// regular, directory, and symlink — fails the walk with a typed error naming
// the path, because the authority's create surface makes exactly those three
// kinds and anything else means the tree is not what the volume claims.
func (w *Walker) Next() (archive.SourceEntry, error) {
	if w.finished {
		return archive.SourceEntry{}, io.EOF
	}
	if !w.started {
		w.started = true
		return w.emitRoot()
	}
	for {
		if len(w.stack) == 0 {
			w.finished = true
			return archive.SourceEntry{}, io.EOF
		}
		top := w.stack[len(w.stack)-1]
		if top.at >= len(top.names) {
			if top.owned {
				_ = top.file.Close()
			}
			w.stack = w.stack[:len(w.stack)-1]
			continue
		}
		name := top.names[top.at]
		top.at++
		entry, err := w.emitChild(top, name)
		if err != nil {
			return archive.SourceEntry{}, err
		}
		return entry, nil
	}
}

func (w *Walker) emitRoot() (archive.SourceEntry, error) {
	stat, err := statFD(int(w.root.Fd()))
	if err != nil {
		return archive.SourceEntry{}, fmt.Errorf("archiver: stat volume root: %w", err)
	}
	if stat.Kind != kindDirectory {
		return archive.SourceEntry{}, fmt.Errorf("%w: the volume root is not a directory", ErrInvalid)
	}
	xattrs, err := readUserXattrs(int(w.root.Fd()), "")
	if err != nil {
		return archive.SourceEntry{}, err
	}
	names, err := readNames(w.root, "")
	if err != nil {
		return archive.SourceEntry{}, err
	}
	index := w.take()
	w.stack = append(w.stack, &walkDir{file: w.root, index: index, names: names})
	return archive.SourceEntry{
		ParentIndex: 0,
		Name:        nil,
		Type:        archive.TypeDirectory,
		Mode:        stat.Mode,
		MTimeNanos:  stat.MTimeNanos,
		CTimeNanos:  stat.CTimeNanos,
		Xattrs:      xattrs,
	}, nil
}

func (w *Walker) emitChild(parent *walkDir, name string) (archive.SourceEntry, error) {
	display := displayPath(parent.path, name)
	if err := validateComponent(name); err != nil {
		return archive.SourceEntry{}, fmt.Errorf("archiver: %q: %w", display, err)
	}
	stat, err := statChild(int(parent.file.Fd()), name)
	if err != nil {
		return archive.SourceEntry{}, fmt.Errorf("archiver: stat %q: %w", display, err)
	}
	entry := archive.SourceEntry{
		ParentIndex: parent.index,
		Name:        []byte(name),
		Mode:        stat.Mode,
		MTimeNanos:  stat.MTimeNanos,
		CTimeNanos:  stat.CTimeNanos,
	}
	switch stat.Kind {
	case kindDirectory:
		if len(w.stack) >= MaxWalkDepth {
			return archive.SourceEntry{}, fmt.Errorf("%w: %q is deeper than %d levels", ErrInvalid, display, MaxWalkDepth)
		}
		child, err := openChildDirectory(int(parent.file.Fd()), name)
		if err != nil {
			return archive.SourceEntry{}, openFailure(display, stat.Mode, err)
		}
		if err := sameInode(child, stat, display); err != nil {
			_ = child.Close()
			return archive.SourceEntry{}, err
		}
		xattrs, err := readUserXattrs(int(child.Fd()), display)
		if err != nil {
			_ = child.Close()
			return archive.SourceEntry{}, err
		}
		names, err := readNames(child, display)
		if err != nil {
			_ = child.Close()
			return archive.SourceEntry{}, err
		}
		entry.Type = archive.TypeDirectory
		entry.Xattrs = xattrs
		index := w.take()
		w.stack = append(w.stack, &walkDir{
			file:  child,
			index: index,
			names: names,
			path:  appendComponent(parent.path, name),
			owned: true,
		})
		return entry, nil

	case kindSymlink:
		target, err := readLinkChild(int(parent.file.Fd()), name, stat.Size)
		if err != nil {
			return archive.SourceEntry{}, fmt.Errorf("archiver: readlink %q: %w", display, err)
		}
		// Linux permits user.* attributes on regular files and directories
		// only, so a symlink cannot carry one and none is read.
		entry.Type = archive.TypeSymlink
		entry.LinkName = target
		entry.Size = uint64(len(target))
		w.take()
		return entry, nil

	case kindRegular:
		file, err := openChildFile(int(parent.file.Fd()), name)
		if err != nil {
			return archive.SourceEntry{}, openFailure(display, stat.Mode, err)
		}
		if err := sameInode(file, stat, display); err != nil {
			_ = file.Close()
			return archive.SourceEntry{}, err
		}
		xattrs, err := readUserXattrs(int(file.Fd()), display)
		_ = file.Close()
		if err != nil {
			return archive.SourceEntry{}, err
		}
		entry.Type = archive.TypeRegular
		entry.Size = uint64(stat.Size)
		entry.Nlink = stat.Nlink
		entry.InodeKey = stat.Ino
		entry.Xattrs = xattrs
		if stat.Size > 0 {
			path := appendComponent(parent.path, name)
			expected := stat
			entry.Open = func() (archive.SourceFile, error) { return w.openContent(path, expected) }
		}
		w.take()
		return entry, nil

	default:
		return archive.SourceEntry{}, &UnsupportedInodeError{Path: display, Kind: stat.Kind.String()}
	}
}

// openFailure turns a refused open into the typed error when the refusal is the
// node's own mode. Every other failure keeps its cause verbatim: an archive that
// could not read part of the tree must say exactly why.
func openFailure(display string, mode uint32, err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return &UnreadableInodeError{Path: display, Mode: mode, Err: err}
	}
	return fmt.Errorf("archiver: open %q: %w", display, err)
}

func (w *Walker) take() uint32 {
	index := w.next
	w.next++
	return index
}

// openContent reopens one regular file for the builder, which pulls content
// after the walk has finished and every walk descriptor is closed.
//
// The path is re-resolved one confined component at a time and the result is
// proved to be the same inode of the same size the walk recorded. The archiver
// runs against a read-only bind of a quiesced volume, so nothing can move
// underneath it; the check is what makes that a proof rather than an assumption.
func (w *Walker) openContent(path []string, expected fileStat) (archive.SourceFile, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("%w: content path is empty", ErrInvalid)
	}
	parent, err := w.parentDirectory(path[:len(path)-1])
	if err != nil {
		return nil, err
	}
	display := displayPath(path[:len(path)-1], path[len(path)-1])
	file, err := openChildFile(int(parent.Fd()), path[len(path)-1])
	if err != nil {
		return nil, fmt.Errorf("archiver: reopen %q: %w", display, err)
	}
	stat, err := statFD(int(file.Fd()))
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("archiver: stat %q: %w", display, err)
	}
	if stat.Kind != kindRegular || stat.Ino != expected.Ino || stat.Dev != expected.Dev || stat.Size != expected.Size {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %q changed between the walk and its read", ErrInvalid, display)
	}
	return &sourceFile{file: file, size: stat.Size}, nil
}

// parentDirectory resolves a directory path from the root descriptor, caching
// the most recent one. The cache is a performance property only: a miss
// re-resolves from the root, and every component is opened confined.
func (w *Walker) parentDirectory(components []string) (*os.File, error) {
	if w.root == nil {
		return nil, fmt.Errorf("%w: the volume root descriptor is closed", ErrInvalid)
	}
	if len(components) == 0 {
		return w.root, nil
	}
	key := strings.Join(components, "\x00")
	if w.cachedDir != nil && w.cachedKey == key {
		return w.cachedDir, nil
	}
	current := w.root
	var owned *os.File
	closeOwned := func() {
		if owned != nil {
			_ = owned.Close()
			owned = nil
		}
	}
	for index, component := range components {
		if err := validateComponent(component); err != nil {
			closeOwned()
			return nil, err
		}
		child, err := openChildDirectory(int(current.Fd()), component)
		if err != nil {
			closeOwned()
			return nil, fmt.Errorf("archiver: open %q: %w", displayPath(components[:index], component), err)
		}
		closeOwned()
		owned = child
		current = child
	}
	if w.cachedDir != nil {
		_ = w.cachedDir.Close()
	}
	w.cachedDir = owned
	w.cachedKey = key
	return owned, nil
}

// sameInode proves an opened descriptor is the inode the preceding stat
// described. Between the stat and the open, a hostile or merely surprising peer
// could have replaced the name; the archiver's tree is read-only and quiesced,
// and this is what makes that structural rather than assumed.
func sameInode(file *os.File, expected fileStat, display string) error {
	stat, err := statFD(int(file.Fd()))
	if err != nil {
		return fmt.Errorf("archiver: stat %q: %w", display, err)
	}
	if stat.Ino != expected.Ino || stat.Dev != expected.Dev || stat.Kind != expected.Kind {
		return fmt.Errorf("%w: %q changed between its stat and its open", ErrInvalid, display)
	}
	return nil
}

// readNames lists one directory's raw child names in byte order. Sorting makes
// the walk deterministic, which makes the manifest of an unchanged tree
// deterministic, which is what lets a re-archive be compared against its
// predecessor.
func readNames(directory *os.File, display string) ([]string, error) {
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("archiver: read directory %q: %w", display, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

// validateComponent enforces the format's name rules on a raw byte name before
// it is used in any syscall: one component, never a path, never a dot segment,
// never containing NUL.
func validateComponent(name string) error {
	switch {
	case name == "" || name == "." || name == "..":
		return fmt.Errorf("%w: %q is not a usable name component", ErrInvalid, name)
	case len(name) > archive.MaxNameBytes:
		return fmt.Errorf("%w: name exceeds %d bytes", ErrInvalid, archive.MaxNameBytes)
	case strings.ContainsAny(name, "/\x00"):
		return fmt.Errorf("%w: name contains a separator or NUL", ErrInvalid)
	}
	return nil
}

func appendComponent(path []string, name string) []string {
	out := make([]string, len(path), len(path)+1)
	copy(out, path)
	return append(out, name)
}

// displayPath renders a path for an error message only. It is never handed to a
// syscall, so rendering a non-UTF-8 name through %q is safe and readable.
func displayPath(path []string, name string) string {
	if len(path) == 0 {
		return name
	}
	return strings.Join(path, "/") + "/" + name
}

// readUserXattrs reads an entry's pre-existing portable user.* attributes.
// PortableFS exposes them through the mounted API, so an archive that dropped
// them would silently erase visible data; every other namespace is deliberately
// not recorded.
func readUserXattrs(fd int, display string) ([]archive.Xattr, error) {
	size, err := listXattrNames(fd, nil)
	if err != nil {
		if xattrUnsupported(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("archiver: list attributes of %q: %w", display, err)
	}
	if size <= 0 {
		return nil, nil
	}
	if size > maxXattrListBytes {
		return nil, fmt.Errorf("%w: %q has an attribute list of %d bytes", ErrInvalid, display, size)
	}
	buffer := make([]byte, size)
	read, err := listXattrNames(fd, buffer)
	if err != nil {
		if xattrUnsupported(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("archiver: list attributes of %q: %w", display, err)
	}
	if read > len(buffer) {
		return nil, fmt.Errorf("%w: attribute list of %q grew while it was read", ErrInvalid, display)
	}
	var xattrs []archive.Xattr
	for _, raw := range bytes.Split(buffer[:read], []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		name := string(raw)
		if !strings.HasPrefix(name, archive.XattrPrefix) {
			continue
		}
		if len(name) > archive.MaxXattrNameBytes {
			return nil, fmt.Errorf("%w: %q has an attribute name of %d bytes", ErrInvalid, display, len(name))
		}
		value, err := readXattrValue(fd, name, display)
		if err != nil {
			return nil, err
		}
		if value == nil {
			continue
		}
		if len(xattrs) >= archive.MaxXattrsPerEntry {
			return nil, fmt.Errorf("%w: %q has more than %d portable attributes",
				ErrInvalid, display, archive.MaxXattrsPerEntry)
		}
		xattrs = append(xattrs, archive.Xattr{Name: []byte(name), Value: value})
	}
	return xattrs, nil
}

// readXattrValue returns one attribute's raw value, or nil when the attribute
// disappeared between the list and the read. A vanished attribute is not an
// error: the value is simply not part of the archive, exactly as if the list
// had never mentioned it.
func readXattrValue(fd int, name, display string) ([]byte, error) {
	size, err := getXattrValue(fd, name, nil)
	if err != nil {
		if xattrUnsupported(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("archiver: read attribute %q of %q: %w", name, display, err)
	}
	if size < 0 || size > archive.MaxXattrValueSize {
		return nil, fmt.Errorf("%w: attribute %q of %q is %d bytes", ErrInvalid, name, display, size)
	}
	if size == 0 {
		return []byte{}, nil
	}
	value := make([]byte, size)
	read, err := getXattrValue(fd, name, value)
	if err != nil {
		if xattrUnsupported(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("archiver: read attribute %q of %q: %w", name, display, err)
	}
	if read > len(value) {
		return nil, fmt.Errorf("%w: attribute %q of %q grew while it was read", ErrInvalid, name, display)
	}
	return value[:read], nil
}

// sourceFile is one open regular file as the builder reads it: content by
// offset through the descriptor, and the extent map the platform scanner
// produced. Nothing is buffered; the builder holds one chunk at a time.
type sourceFile struct {
	file *os.File
	size int64
}

func (f *sourceFile) ReadAt(p []byte, off int64) (int, error) { return f.file.ReadAt(p, off) }

func (f *sourceFile) Extents() ([]archive.Extent, error) { return scanExtents(f.file, f.size) }

func (f *sourceFile) Close() error { return f.file.Close() }
