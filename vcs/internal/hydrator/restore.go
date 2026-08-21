package hydrator

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/steerlabs/portablefs/vcs/archive"
)

// MaxRestoreDepth bounds how deep the restorer descends. It is a resource bound
// — one open descriptor per level of the current path — and a tree deeper than
// this could not be expressed inside the format's 4096-byte path bound anyway.
const MaxRestoreDepth = 1024

// materialize creates the whole namespace under an empty volume root and
// returns the manifest-entry to inode-identity bindings.
//
// It runs in two passes over the same depth-first entry table.
//
// Pass one creates every node: directories at 0700 so their children can be
// created inside them, files at their full logical size and fully sparse — the
// extents are marked data as the authority hydrates them, so a restored file
// starts as all hole — symlinks, and the additional links of every hardlink
// group. Files, symlinks, and extended attributes are finished here.
//
// Pass two walks the directories again and finalizes them from the bottom up:
// the exact nanosecond mtime, then the archived mode (including set-ID and
// sticky bits), then fsync. Directory mtimes must be applied after every child
// exists, because creating a child bumps its parent's mtime; splitting the pass
// is what makes that ordering structural rather than delicate. It also means
// every directory is still 0700 while the tree is being built, so the link
// source of a hardlink group is always reachable no matter what mode the
// archive recorded for the directory it lives in.
//
// The single invariant that makes an archived mode denying its own owner
// restorable is that nothing addresses a node by name after that node's mode
// has landed. An archive can contain such modes - the archiver is granted
// CAP_DAC_READ_SEARCH so it can read them, see
// deploy/systemd/portablefs-archiver@.service - and the restorer holds no
// capability at all, so it must never need one. For a file that is free: the
// creating descriptor carries the access the creation granted, so truncate,
// attributes, and the mode itself are all fd-relative, and only the mtime is
// applied by name, while the parent is still 0700 and the file's own mode is
// irrelevant to a utimensat the owner is entitled to make. For a directory it
// is this pass: children first, then the directory's own mtime, then its mode
// last, deepest first.
func materialize(root *os.File, manifest *archive.Manifest) ([]Binding, error) {
	if err := requireEmpty(root); err != nil {
		return nil, err
	}
	state := &restorer{
		root:     root,
		manifest: manifest,
		bindings: make([]Binding, len(manifest.Entries)),
		filled:   make([]bool, len(manifest.Entries)),
	}
	defer state.closeCache()
	if err := state.create(); err != nil {
		return nil, err
	}
	if err := state.finalizeDirectories(); err != nil {
		return nil, err
	}
	if err := syncFS(int(root.Fd())); err != nil {
		return nil, fmt.Errorf("hydrator: sync volume: %w", err)
	}
	for index, done := range state.filled {
		if !done {
			return nil, fmt.Errorf("%w: entry %d was never materialized", ErrInvalid, index)
		}
	}
	return state.bindings, nil
}

type restorer struct {
	root     *os.File
	manifest *archive.Manifest
	bindings []Binding
	filled   []bool

	// cachedDir is the most recently used hardlink source directory. Hardlink
	// group members are usually near each other, and the cache turns a
	// per-member path walk into a single openat for that case.
	cachedDir *os.File
	cachedKey string
}

// openDir is one directory on the descent stack.
type openDir struct {
	file  *os.File
	index uint32
	// owned is false for the volume root, whose descriptor belongs to the
	// caller and outlives both passes.
	owned bool
}

func (r *restorer) closeCache() {
	if r.cachedDir != nil {
		_ = r.cachedDir.Close()
		r.cachedDir = nil
		r.cachedKey = ""
	}
}

func (r *restorer) create() error {
	stack := []*openDir{}
	defer func() {
		for _, directory := range stack {
			if directory.owned {
				_ = directory.file.Close()
			}
		}
	}()
	plan := r.manifest.NamespacePlan()
	for {
		step, ok := plan.Next()
		if !ok {
			return nil
		}
		if step.Index == 0 {
			// The volume root already exists: the helper provisioned it. Its
			// attributes are applied here and its mode and mtime in pass two,
			// exactly like any other directory.
			if err := r.applyXattrs(int(r.root.Fd()), step.Xattrs, "."); err != nil {
				return err
			}
			identity, err := identityFD(int(r.root.Fd()))
			if err != nil {
				return fmt.Errorf("hydrator: identity of the volume root: %w", err)
			}
			r.bind(0, identity)
			stack = append(stack, &openDir{file: r.root, index: 0})
			continue
		}
		for len(stack) > 0 && stack[len(stack)-1].index != step.ParentIndex {
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if top.owned {
				_ = top.file.Close()
			}
		}
		if len(stack) == 0 {
			return fmt.Errorf("%w: entry %d names parent %d, which is not on the path", ErrInvalid, step.Index, step.ParentIndex)
		}
		parent := stack[len(stack)-1]
		name, err := componentOf(step.Name)
		if err != nil {
			return fmt.Errorf("hydrator: entry %d: %w", step.Index, err)
		}
		if step.Type == archive.TypeDirectory {
			if len(stack) >= MaxRestoreDepth {
				return fmt.Errorf("%w: entry %d is deeper than %d levels", ErrInvalid, step.Index, MaxRestoreDepth)
			}
			child, err := r.createDirectory(parent, name, step)
			if err != nil {
				return err
			}
			stack = append(stack, child)
			continue
		}
		if err := r.createLeaf(parent, name, step); err != nil {
			return err
		}
	}
}

func (r *restorer) createDirectory(parent *openDir, name string, step archive.PlanStep) (*openDir, error) {
	if err := makeDirectory(int(parent.file.Fd()), name); err != nil {
		return nil, err
	}
	child, err := openChildDirectory(int(parent.file.Fd()), name)
	if err != nil {
		return nil, err
	}
	if err := r.applyXattrs(int(child.Fd()), step.Xattrs, name); err != nil {
		_ = child.Close()
		return nil, err
	}
	identity, err := identityFD(int(child.Fd()))
	if err != nil {
		_ = child.Close()
		return nil, fmt.Errorf("hydrator: identity of entry %d: %w", step.Index, err)
	}
	r.bind(step.Index, identity)
	return &openDir{file: child, index: step.Index, owned: true}, nil
}

func (r *restorer) createLeaf(parent *openDir, name string, step archive.PlanStep) error {
	switch step.Type {
	case archive.TypeSymlink:
		target := string(step.LinkName)
		if strings.IndexByte(target, 0) >= 0 || len(target) == 0 || len(target) > archive.MaxLinkNameBytes {
			return fmt.Errorf("%w: entry %d has an unusable symlink target", ErrInvalid, step.Index)
		}
		if len(step.Xattrs) != 0 {
			// Linux carries user.* attributes on regular files and directories
			// only, so a symlink that claims one describes a tree that cannot
			// be restored faithfully.
			return fmt.Errorf("%w: entry %d is a symlink carrying extended attributes", ErrInvalid, step.Index)
		}
		if err := symlinkAt(target, int(parent.file.Fd()), name); err != nil {
			return err
		}
		if err := setTimes(int(parent.file.Fd()), name, step.MTimeNanos); err != nil {
			return err
		}
		identity, err := identityChild(int(parent.file.Fd()), name)
		if err != nil {
			return fmt.Errorf("hydrator: identity of entry %d: %w", step.Index, err)
		}
		r.bind(step.Index, identity)
		return nil

	case archive.TypeRegular:
		if !step.Creates() {
			return r.linkExisting(parent, name, step)
		}
		return r.createRegular(parent, name, step)

	default:
		return fmt.Errorf("%w: entry %d has type %s, which the restorer does not create", ErrInvalid, step.Index, step.Type)
	}
}

func (r *restorer) createRegular(parent *openDir, name string, step archive.PlanStep) error {
	file, err := createFile(int(parent.file.Fd()), name)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if step.Size > 0 {
		if step.Size > uint64(1<<62) {
			return fmt.Errorf("%w: entry %d claims %d bytes", ErrInvalid, step.Index, step.Size)
		}
		// Fully sparse: the file has its final logical size and no allocated
		// block. Every chunk the archive stores becomes data as the authority
		// hydrates it; every chunk the archive stored nothing for is a hole
		// already, and is born hydrated.
		if err := truncateFD(int(file.Fd()), int64(step.Size)); err != nil {
			return fmt.Errorf("hydrator: size entry %d: %w", step.Index, err)
		}
	}
	if err := r.applyXattrs(int(file.Fd()), step.Xattrs, name); err != nil {
		return err
	}
	if err := chmodFD(int(file.Fd()), step.Mode); err != nil {
		return fmt.Errorf("hydrator: mode entry %d: %w", step.Index, err)
	}
	identity, err := identityFD(int(file.Fd()))
	if err != nil {
		return fmt.Errorf("hydrator: identity of entry %d: %w", step.Index, err)
	}
	closed = true
	if err := file.Close(); err != nil {
		return fmt.Errorf("hydrator: close entry %d: %w", step.Index, err)
	}
	// The mtime is applied last: truncating and setting attributes both move
	// it, and the archived mtime is what a wake must preserve so that make does
	// not rebuild and git status stays clean.
	if err := setTimes(int(parent.file.Fd()), name, step.MTimeNanos); err != nil {
		return err
	}
	r.bind(step.Index, identity)
	return nil
}

// linkExisting adds another name for an inode an earlier step created. Hardlink
// groups are recreated as real hardlinks — one inode per group — so the two
// names share their content, their attributes, and, because identity is the
// inode's, exactly one hydration-map entry.
func (r *restorer) linkExisting(parent *openDir, name string, step archive.PlanStep) error {
	source := uint32(step.LinkFrom)
	if int(source) >= len(r.bindings) || !r.filled[source] {
		return fmt.Errorf("%w: entry %d links from entry %d, which has not been created", ErrInvalid, step.Index, source)
	}
	components, err := r.manifest.Path(source)
	if err != nil {
		return err
	}
	if len(components) == 0 {
		return fmt.Errorf("%w: entry %d links from the volume root", ErrInvalid, step.Index)
	}
	sourceName, err := componentOf(components[len(components)-1])
	if err != nil {
		return fmt.Errorf("hydrator: entry %d link source: %w", step.Index, err)
	}
	sourceParent, err := r.directoryAt(components[:len(components)-1])
	if err != nil {
		return err
	}
	if err := linkAt(int(sourceParent.Fd()), sourceName, int(parent.file.Fd()), name); err != nil {
		return err
	}
	r.bind(step.Index, r.bindings[source].Identity)
	return nil
}

// directoryAt resolves a directory path from the volume root, one confined
// component at a time, caching the most recent result. Every directory is still
// 0700 during pass one, so this walk cannot be blocked by an archived mode.
func (r *restorer) directoryAt(components [][]byte) (*os.File, error) {
	if len(components) == 0 {
		return r.root, nil
	}
	names := make([]string, len(components))
	for index, raw := range components {
		name, err := componentOf(raw)
		if err != nil {
			return nil, err
		}
		names[index] = name
	}
	key := strings.Join(names, "\x00")
	if r.cachedDir != nil && r.cachedKey == key {
		return r.cachedDir, nil
	}
	current := r.root
	var owned *os.File
	closeOwned := func() {
		if owned != nil {
			_ = owned.Close()
			owned = nil
		}
	}
	for _, name := range names {
		child, err := openChildDirectory(int(current.Fd()), name)
		if err != nil {
			closeOwned()
			return nil, err
		}
		closeOwned()
		owned = child
		current = child
	}
	r.closeCache()
	r.cachedDir = owned
	r.cachedKey = key
	return owned, nil
}

// finalizeDirectories is pass two: descend the directory tree again and, on the
// way back up, apply the archived mode, the archived mtime, and fsync. Bottom
// up is the order that makes the fsyncs meaningful, and it is the order the
// restore contract names.
func (r *restorer) finalizeDirectories() error {
	stack := []*openDir{{file: r.root, index: 0}}
	defer func() {
		for _, directory := range stack {
			if directory.owned {
				_ = directory.file.Close()
			}
		}
	}()
	for index := 1; index < len(r.manifest.Entries); index++ {
		entry := &r.manifest.Entries[index]
		if entry.Type != archive.TypeDirectory {
			continue
		}
		for len(stack) > 0 && stack[len(stack)-1].index != entry.ParentIndex {
			finished := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if err := r.finalizeDirectory(finished); err != nil {
				return err
			}
		}
		if len(stack) == 0 {
			return fmt.Errorf("%w: directory %d names parent %d, which is not on the path", ErrInvalid, index, entry.ParentIndex)
		}
		name, err := componentOf(entry.Name)
		if err != nil {
			return err
		}
		child, err := openChildDirectory(int(stack[len(stack)-1].file.Fd()), name)
		if err != nil {
			return err
		}
		stack = append(stack, &openDir{file: child, index: uint32(index), owned: true})
	}
	for len(stack) > 0 {
		finished := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if err := r.finalizeDirectory(finished); err != nil {
			return err
		}
	}
	return nil
}

// finalizeDirectory applies one directory's archived mtime and then its
// archived mode, in that order and never the reverse.
//
// The order is a correctness requirement, not a preference. setTimesSelf is
// utimensat(fd, ".", ...), and resolving even a single "." component costs
// search permission on the directory it resolves in: against an archived mode
// with no owner execute bit - 0000, 0400, 0600 - that call answers EACCES even
// for the identity that owns the volume. The mode is therefore
// the last thing applied to a directory, exactly as it is the last thing
// applied to the subtree beneath it. chmod moves ctime only, never mtime, so
// applying the mode afterwards cannot disturb the timestamp just restored.
func (r *restorer) finalizeDirectory(directory *openDir) error {
	entry := &r.manifest.Entries[directory.index]
	if err := setTimesSelf(int(directory.file.Fd()), entry.MTimeNanos); err != nil {
		return err
	}
	if err := chmodFD(int(directory.file.Fd()), entry.Mode); err != nil {
		return fmt.Errorf("hydrator: mode directory %d: %w", directory.index, err)
	}
	if err := fsyncFD(int(directory.file.Fd())); err != nil {
		return fmt.Errorf("hydrator: sync directory %d: %w", directory.index, err)
	}
	if directory.owned {
		return directory.file.Close()
	}
	return nil
}

func (r *restorer) applyXattrs(fd int, xattrs []archive.Xattr, display string) error {
	for _, xattr := range xattrs {
		name := string(xattr.Name)
		if !strings.HasPrefix(name, archive.XattrPrefix) || strings.IndexByte(name, 0) >= 0 ||
			len(name) > archive.MaxXattrNameBytes || len(xattr.Value) > archive.MaxXattrValueSize {
			return fmt.Errorf("%w: %q carries an attribute the format does not permit", ErrInvalid, display)
		}
		if err := setXattr(fd, name, xattr.Value); err != nil {
			return err
		}
	}
	return nil
}

func (r *restorer) bind(index uint32, identity [16]byte) {
	r.bindings[index] = Binding{EntryIndex: index, Identity: identity}
	r.filled[index] = true
}

// requireEmpty proves the volume tree holds nothing before the restore writes
// into it. A non-empty tree means the phase is being run against a volume that
// is not freshly provisioned, and continuing would merge an archive into
// somebody else's data.
func requireEmpty(root *os.File) error {
	names, err := root.ReadDir(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("hydrator: read volume root: %w", err)
	}
	if len(names) != 0 {
		return fmt.Errorf("%w: the volume tree is not empty (%q is present)", ErrInvalid, names[0].Name())
	}
	return nil
}

// componentOf validates one raw name from the manifest before it is used in a
// syscall. The decoder has already proved these are single components; checking
// again here is defence in depth at the exact point where a name would become a
// path if it were not.
func componentOf(raw []byte) (string, error) {
	name := string(raw)
	switch {
	case name == "" || name == "." || name == "..":
		return "", fmt.Errorf("%w: %q is not a usable name component", ErrInvalid, name)
	case len(name) > archive.MaxNameBytes:
		return "", fmt.Errorf("%w: name exceeds %d bytes", ErrInvalid, archive.MaxNameBytes)
	case strings.ContainsAny(name, "/\x00"):
		return "", fmt.Errorf("%w: name contains a separator or NUL", ErrInvalid)
	}
	return name, nil
}
