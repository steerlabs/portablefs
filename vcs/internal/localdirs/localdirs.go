package localdirs

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/trendup-ai/portablefs/vcs/internal/clientcore"
	"github.com/trendup-ai/portablefs/vcs/internal/confinedfs"
	"github.com/trendup-ai/portablefs/vcs/internal/fsproto"
)

// Normalize cleans, validates, and deduplicates workspace-relative graft
// roots. Blank entries are dropped; dirs nested inside another configured dir
// are dropped because the outer graft already owns the whole subtree. This is
// the permissive form used when unioning config sources; the same rules as
// portablefsd's normalizeLocalDirs so the two clients accept identical config.
func Normalize(dirs []string) ([]string, error) {
	cleaned := make([]string, 0, len(dirs))
	seen := map[string]bool{}
	for _, raw := range dirs {
		p, err := cleanOne(raw)
		if err != nil {
			return nil, err
		}
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		cleaned = append(cleaned, p)
	}
	sort.Strings(cleaned)
	out := make([]string, 0, len(cleaned))
	for _, p := range cleaned {
		nested := false
		for _, parent := range out {
			if strings.HasPrefix(p, parent+"/") {
				nested = true
				break
			}
		}
		if !nested {
			out = append(out, p)
		}
	}
	return out, nil
}

// cleanOne canonicalizes one entry with forward slashes; "" means "drop this
// blank entry". Absolute paths and paths escaping the workspace are errors.
func cleanOne(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if strings.HasPrefix(trimmed, "/") {
		return "", fmt.Errorf("local dirs must be workspace-relative paths: %q", raw)
	}
	p := path.Clean(strings.Trim(strings.ReplaceAll(trimmed, "\\", "/"), "/"))
	if p == "" || p == "." || p == ".." || strings.HasPrefix(p, "../") {
		return "", fmt.Errorf("local dirs must be workspace-relative paths: %q", raw)
	}
	if p == ".portablefs" || p == VolumeConfigPath {
		return "", fmt.Errorf("local dir %q would shadow the local-dirs declaration", raw)
	}
	return p, nil
}

// ValidateStrict enforces the CLI flag contract on one explicit list: empty
// strings, duplicates, and nesting one graft under another are refused with a
// clear error rather than silently dropped. Union across sources (flags plus
// the volume's .portablefs/local-dirs file) uses Normalize instead, where the
// outer-graft-wins rule is the friendly behavior.
func ValidateStrict(dirs []string) error {
	seen := map[string]string{}
	var cleanedAll []string
	for _, raw := range dirs {
		if strings.TrimSpace(raw) == "" {
			return fmt.Errorf("--local-dir value must not be empty")
		}
		p, err := cleanOne(raw)
		if err != nil {
			return err
		}
		if prev, dup := seen[p]; dup {
			return fmt.Errorf("duplicate --local-dir %q (also given as %q)", raw, prev)
		}
		seen[p] = raw
		cleanedAll = append(cleanedAll, p)
	}
	sort.Strings(cleanedAll)
	for i := 1; i < len(cleanedAll); i++ {
		if strings.HasPrefix(cleanedAll[i], cleanedAll[i-1]+"/") {
			return fmt.Errorf("--local-dir %q is nested under --local-dir %q; the outer graft already serves the whole subtree", cleanedAll[i], cleanedAll[i-1])
		}
	}
	return nil
}

// VolumeConfigPath is the in-volume declaration file: one workspace-relative
// path per line, '#' comments, unioned with --local-dir flags at mount time.
const VolumeConfigPath = ".portablefs/local-dirs"

// ParseVolumeConfig parses VolumeConfigPath content. Invalid lines are
// returned separately so the mount can warn without failing: the file is repo
// config, and refusing to mount over a typo in it would lock users out.
func ParseVolumeConfig(data []byte) (dirs []string, badLines []string) {
	for _, line := range strings.Split(string(data), "\n") {
		entry := strings.TrimSpace(line)
		if i := strings.IndexByte(entry, '#'); i >= 0 {
			entry = strings.TrimSpace(entry[:i])
		}
		if entry == "" {
			continue
		}
		p, err := cleanOne(entry)
		if err != nil || p == "" {
			badLines = append(badLines, strings.TrimSpace(line))
			continue
		}
		dirs = append(dirs, p)
	}
	return dirs, badLines
}

// ReadVolumeConfig reads the volume's VolumeConfigPath declaration through
// the normal client read path. Absence is fine; other failures warn through
// logf and degrade to flag-only config rather than failing the mount.
func ReadVolumeConfig(ctx context.Context, vol *clientcore.Volume, logf func(string, ...any)) []string {
	const maxConfigBytes = 1 << 16
	if logf == nil {
		logf = func(string, ...any) {}
	}
	a, st := vol.Lookup(ctx, VolumeConfigPath)
	if st == fsproto.ENOENT {
		return nil
	}
	if st != fsproto.OK {
		logf("read %s: status %d; continuing without volume-declared local dirs", VolumeConfigPath, st)
		return nil
	}
	n := clientcore.NewNodeState(a.Ino, a.Ino != 0)
	data, st := vol.Read(ctx, VolumeConfigPath, n, 0, maxConfigBytes)
	if st != fsproto.OK {
		logf("read %s: status %d; continuing without volume-declared local dirs", VolumeConfigPath, st)
		return nil
	}
	dirs, badLines := ParseVolumeConfig(data)
	for _, line := range badLines {
		logf("%s: ignoring invalid line %q", VolumeConfigPath, line)
	}
	return dirs
}

// StorageID keys one mount's machine-local backing under the state dir,
// mirroring portablefsd's stableStorageID convention: backing lives at
// <stateBase>/local/<StorageID>/ and survives remounts of the same
// volume+branch+mountPath.
func StorageID(volumeID, branch, mountPath string) string {
	sum := sha256.Sum256([]byte(volumeID + "\x00" + branch + "\x00" + mountPath))
	return fmt.Sprintf("%x", sum[:16])
}

// BackingRoot is the conventional backing directory for one mount.
func BackingRoot(stateBase, volumeID, branch, mountPath string) string {
	return filepath.Join(stateBase, "local", StorageID(volumeID, branch, mountPath))
}

// localInoMarker tags every kernel inode number minted for grafted paths.
// Authority inodes are allocator-assigned small integers and can never carry
// the top bit, so kernel dcache entries for local and volume nodes can never
// collide. (The path-hash fallback for pre-identity authorities is a random
// 64-bit FNV value; a collision with a marked backing st_ino needs an exact
// 64-bit match AND the same file-type bits — negligible, and no worse than two
// path hashes colliding today.)
const localInoMarker = uint64(1) << 63

// LocalIno maps a backing-filesystem inode into the mount's local ino range.
// Backing st_ino identity is exactly right for grafts: stable across renames
// within the graft, shared by hard links, and released with the backing file.
func LocalIno(backingIno uint64) uint64 {
	return backingIno | localInoMarker
}

// Grafts is one mount's immutable-at-match-time graft configuration plus its
// machine-local backing root. The dirs slice is swapped atomically so the
// non-graft hot path pays one atomic load and a short prefix scan; mutations
// (ancestor-rename remaps) serialize on mu.
type Grafts struct {
	root *confinedfs.Root
	dirs atomic.Value // []string, sorted, normalized
	mu   sync.Mutex   // serializes remaps (writers to dirs)
	fsMu sync.Mutex   // serializes compound no-replace mutations

	// onChange, when set, observes every configured-dirs change (ancestor
	// renames). The CLI persists the new list into its mount state so a
	// remount reuses the carried names.
	onChange func([]string)
}

// New builds a Grafts set rooted at backingRoot. dirs are normalized; an
// empty result returns (nil, nil) so callers keep a nil fast path.
func New(backingRoot string, dirs []string, onChange func([]string)) (*Grafts, error) {
	norm, err := Normalize(dirs)
	if err != nil {
		return nil, err
	}
	if len(norm) == 0 {
		return nil, nil
	}
	if backingRoot == "" {
		return nil, errors.New("localdirs: backing root is required")
	}
	root, err := confinedfs.Open(backingRoot, 0o700)
	if err != nil {
		return nil, fmt.Errorf("localdirs: open confined backing: %w", err)
	}
	g := &Grafts{root: root, onChange: onChange}
	g.dirs.Store(norm)
	return g, nil
}

// Close releases the backing-directory capability.
func (g *Grafts) Close() error {
	if g == nil {
		return nil
	}
	return g.root.Close()
}

// Dirs returns the current normalized graft roots.
func (g *Grafts) Dirs() []string {
	if g == nil {
		return nil
	}
	return append([]string(nil), g.dirs.Load().([]string)...)
}

// Owner returns the configured graft root that owns p ("" if p is served by
// the authority volume). Safe on a nil receiver so adapters can call it
// unconditionally.
func (g *Grafts) Owner(p string) string {
	if g == nil {
		return ""
	}
	for _, dir := range g.dirs.Load().([]string) {
		if p == dir || strings.HasPrefix(p, dir+"/") {
			return dir
		}
	}
	return ""
}

// RootsUnder lists graft roots whose parent directory is dir.
func (g *Grafts) RootsUnder(dir string) []string {
	if g == nil {
		return nil
	}
	var out []string
	for _, root := range g.dirs.Load().([]string) {
		if parentPath(root) == dir {
			out = append(out, root)
		}
	}
	return out
}

// ensureScaffold creates the machine-local bookkeeping directories that lead
// up to (but do not include) the backing path for a graft root. Scaffold
// segments are storage layout, not namespace: only the root's own backing
// directory decides whether the root exists.
func (g *Grafts) ensureScaffold(root string) error {
	return g.root.MkdirAll(parentPath(root), 0o755)
}

// RemapForRename follows a successful authority rename of a volume path:
// graft roots under the renamed subtree move with it, and their backing
// directories are relocated so contents survive — a graft travels with its
// directory exactly like a mountpoint travels with its vnode.
func (g *Grafts) RemapForRename(oldp, newp string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	cur := g.dirs.Load().([]string)
	var next []string
	changed := false
	for _, dir := range cur {
		np, ok := renamedPath(dir, oldp, newp)
		if !ok {
			next = append(next, dir)
			continue
		}
		if err := g.root.MkdirAll(parentPath(np), 0o755); err == nil {
			// Best-effort like portablefsd: a backing move failure leaves the
			// rule pointing at empty backing (root simply not created yet),
			// never at stale content under the old name.
			_ = g.root.Rename(dir, np)
		}
		next = append(next, np)
		changed = true
	}
	if changed {
		sort.Strings(next)
		g.dirs.Store(next)
	}
	g.mu.Unlock()
	if changed && g.onChange != nil {
		g.onChange(append([]string(nil), next...))
	}
}

// VolumeRenameCheck answers renames seen by VOLUME nodes. handled means the
// rename must not reach the authority: any endpoint at or under a graft is a
// cross-filesystem move (EXDEV), exactly like a bind mount. Renames entirely
// inside one graft never reach volume nodes (those directories are local
// nodes). An ancestor rename (neither endpoint graft-owned) passes through;
// the caller invokes RemapForRename after the authority accepts it.
func (g *Grafts) VolumeRenameCheck(oldp, newp string) (syscall.Errno, bool) {
	if g == nil {
		return 0, false
	}
	if g.Owner(oldp) != "" || g.Owner(newp) != "" {
		return syscall.EXDEV, true
	}
	return 0, false
}

func renamedPath(p, oldp, newp string) (string, bool) {
	if p != oldp && !strings.HasPrefix(p, oldp+"/") {
		return "", false
	}
	return newp + strings.TrimPrefix(p, oldp), true
}

func parentPath(p string) string {
	d := path.Dir(strings.Trim(path.Clean("/"+p), "/"))
	if d == "." || d == "/" {
		return ""
	}
	return d
}

// ---- local backing operations (the semantics core) ----
//
// These operate on workspace-relative paths owned by a graft and return FUSE
// errnos directly. They are deliberately independent of go-fuse so the graft
// contract is unit-testable without a kernel mount; fusenode.go is a thin
// adapter over them.

// errno maps a backing-filesystem error onto the errno the kernel should see.
// The darwin rmdir(2) EEXIST-for-non-empty quirk is normalized to ENOTEMPTY so
// semantics (and tests) are identical across development and CI platforms.
func errnoOf(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	var eno syscall.Errno
	if errors.As(err, &eno) {
		return eno
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return syscall.ENOENT
	case errors.Is(err, fs.ErrExist):
		return syscall.EEXIST
	case errors.Is(err, fs.ErrPermission):
		return syscall.EACCES
	}
	return syscall.EIO
}

// Lstat stats a grafted path. A graft root whose backing directory does not
// exist is ENOENT like any other missing path: rules route names, they do not
// synthesize existence.
func (g *Grafts) Lstat(p string) (syscall.Stat_t, syscall.Errno) {
	var st syscall.Stat_t
	fi, err := g.root.Lstat(p)
	if err != nil {
		return st, errnoOf(err)
	}
	raw, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return st, syscall.EIO
	}
	st = *raw
	return st, 0
}

// Mkdir creates a grafted directory. Creating the graft root itself also
// creates the machine-local scaffold directories that lead up to its backing
// path.
func (g *Grafts) Mkdir(p string, mode uint32) syscall.Errno {
	if g.Owner(p) == p {
		if err := g.ensureScaffold(p); err != nil {
			return errnoOf(err)
		}
	}
	if err := g.root.Mkdir(p, os.FileMode(mode)&os.ModePerm); err != nil {
		return errnoOf(err)
	}
	return 0
}

// Remove unlinks or rmdirs a grafted path with explicit POSIX type guards so
// the errno contract is platform-independent. The graft root itself is
// removable like any directory (rmdir semantics, ENOTEMPTY while it has
// contents): wholesale rebuilds (npm ci) must be able to remove and recreate
// it.
func (g *Grafts) Remove(p string, directory bool) syscall.Errno {
	st, eno := g.Lstat(p)
	if eno != 0 {
		return eno
	}
	isDir := st.Mode&syscall.S_IFMT == syscall.S_IFDIR
	if directory && !isDir {
		return syscall.ENOTDIR
	}
	if !directory && isDir {
		return syscall.EISDIR
	}
	eno = errnoOf(g.root.Remove(p))
	if eno == syscall.EEXIST {
		// darwin rmdir(2) reports a non-empty directory as EEXIST; POSIX (and
		// the Linux kernel the FUSE client fronts) speaks ENOTEMPTY.
		eno = syscall.ENOTEMPTY
	}
	return eno
}

// Rename renames within grafts. Both endpoints must be owned by the SAME
// graft rule; anything else crosses a filesystem boundary and fails EXDEV.
// noReplace emulates RENAME_NOREPLACE portably (the same lstat-then-rename
// emulation portablefsd ships); exchange is not supported.
func (g *Grafts) Rename(oldp, newp string, flags uint32) syscall.Errno {
	const renameNoReplace = 1 // RENAME_NOREPLACE, identical on every linux arch
	const renameExchange = 2  // RENAME_EXCHANGE
	if flags&^uint32(renameNoReplace) != 0 {
		if flags&renameExchange != 0 {
			return syscall.EINVAL
		}
		return syscall.EINVAL
	}
	srcOwner, dstOwner := g.Owner(oldp), g.Owner(newp)
	if srcOwner == "" || dstOwner == "" || srcOwner != dstOwner || oldp == srcOwner || newp == dstOwner {
		// Leaving or entering a graft — including moving the root itself out
		// of its rule or over it — crosses the boundary.
		return syscall.EXDEV
	}
	g.fsMu.Lock()
	defer g.fsMu.Unlock()
	if flags&renameNoReplace != 0 {
		if _, err := g.root.Lstat(newp); err == nil {
			return syscall.EEXIST
		} else if !errors.Is(err, fs.ErrNotExist) {
			return errnoOf(err)
		}
	}
	if err := g.root.Rename(oldp, newp); err != nil {
		return errnoOf(err)
	}
	return 0
}

// Link creates a hard link inside one graft. Crossing between a graft and the
// shared volume, or between two graft roots, is an honest EXDEV boundary just
// like separate bind mounts.
func (g *Grafts) Link(oldp, newp string) syscall.Errno {
	srcOwner, dstOwner := g.Owner(oldp), g.Owner(newp)
	if srcOwner == "" || dstOwner == "" || srcOwner != dstOwner {
		return syscall.EXDEV
	}
	if newp == dstOwner {
		return syscall.EISDIR
	}
	st, err := g.root.Lstat(oldp)
	if err != nil {
		return errnoOf(err)
	}
	if st.IsDir() {
		return syscall.EPERM
	}
	if err := g.root.Link(oldp, newp); err != nil {
		return errnoOf(err)
	}
	return 0
}

// Create opens (creating if needed) a grafted file and returns the raw
// backing fd for a kernel handle (raw so no os.File finalizer can close it
// behind the handle's back). The graft root itself can never be a file.
func (g *Grafts) Create(p string, flags uint32, mode uint32) (int, syscall.Errno) {
	if g.Owner(p) == p {
		// A graft rule is a directory rule: the root can only ever be a
		// directory (mkdir), never a file or symlink.
		return -1, syscall.EISDIR
	}
	file, err := g.root.OpenFile(p, int(flags)|os.O_CREATE, os.FileMode(mode)&os.ModePerm)
	if err != nil {
		return -1, errnoOf(err)
	}
	return transferFD(file)
}

// Open opens an existing grafted file with the kernel's flags, returning the
// raw backing fd.
func (g *Grafts) Open(p string, flags uint32) (int, syscall.Errno) {
	file, err := g.root.OpenFile(p, int(flags), 0)
	if err != nil {
		return -1, errnoOf(err)
	}
	return transferFD(file)
}

func transferFD(file *os.File) (int, syscall.Errno) {
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	closeErr := file.Close()
	if err != nil {
		return -1, errnoOf(err)
	}
	if closeErr != nil {
		_ = syscall.Close(fd)
		return -1, errnoOf(closeErr)
	}
	return fd, 0
}

// Symlink creates a symlink inside a graft; the root itself can never be one.
func (g *Grafts) Symlink(target, p string) syscall.Errno {
	if g.Owner(p) == p {
		return syscall.EISDIR
	}
	if err := g.root.Symlink(target, p); err != nil {
		return errnoOf(err)
	}
	return 0
}

// Readlink reads a grafted symlink target.
func (g *Grafts) Readlink(p string) (string, syscall.Errno) {
	target, err := g.root.Readlink(p)
	if err != nil {
		return "", errnoOf(err)
	}
	return target, 0
}

// ReadDirNames lists a grafted directory (names only; attrs come from
// per-entry Lookup, which the kernel's readdirplus drives anyway).
func (g *Grafts) ReadDirNames(p string) ([]os.DirEntry, syscall.Errno) {
	entries, err := g.root.ReadDir(p)
	if err != nil {
		return nil, errnoOf(err)
	}
	return entries, 0
}

// Fsync forces a grafted path's backing durability (used for the no-handle
// fallback and fsyncdir).
func (g *Grafts) Fsync(p string) syscall.Errno {
	f, err := g.root.Open(p)
	if err != nil {
		return errnoOf(err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil {
		return errnoOf(err)
	}
	return 0
}

// SetattrRequest mirrors the subset of POSIX metadata changes grafts apply.
// Ownership changes are accepted and ignored to match the volume's noowners
// semantics (portablefsd does the same for grafted paths).
type SetattrRequest struct {
	SetMode bool
	Mode    uint32

	SetSize bool
	Size    int64

	SetMtime bool
	MtimeMs  int64
	SetAtime bool
	AtimeMs  int64
}

// Setattr applies metadata changes to a grafted path's backing file.
func (g *Grafts) Setattr(p string, req SetattrRequest) syscall.Errno {
	flags := os.O_RDONLY
	if req.SetSize {
		flags = os.O_WRONLY
	}
	file, err := g.root.OpenFile(p, flags, 0)
	if err != nil {
		return errnoOf(err)
	}
	defer file.Close()
	if req.SetMode {
		if err := file.Chmod(os.FileMode(req.Mode) & os.ModePerm); err != nil {
			return errnoOf(err)
		}
	}
	if req.SetSize {
		if err := file.Truncate(req.Size); err != nil {
			return errnoOf(err)
		}
	}
	if req.SetMtime || req.SetAtime {
		fi, err := file.Stat()
		if err != nil {
			return errnoOf(err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return syscall.EIO
		}
		atimeMs, mtimeMs := statAtimeMs(st), statMtimeMs(st)
		if req.SetAtime {
			atimeMs = req.AtimeMs
		}
		if req.SetMtime {
			mtimeMs = req.MtimeMs
		}
		times := []unix.Timeval{
			unix.NsecToTimeval(atimeMs * int64(time.Millisecond)),
			unix.NsecToTimeval(mtimeMs * int64(time.Millisecond)),
		}
		if err := unix.Futimes(int(file.Fd()), times); err != nil {
			return errnoOf(err)
		}
	}
	return 0
}
