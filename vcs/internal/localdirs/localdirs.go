package localdirs

import (
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
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/steerlabs/portablefs/vcs/internal/confinedfs"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
)

// ---- literal-path config (the macOS daemon's reader) ----
//
// portablefsd serves grafts to the FSKit frontend from a fixed list of
// literal paths, so it keeps reading the declaration as literal paths. The
// FUSE client reads the same file through localroutes instead, which is the
// full pattern language; the two agree on every literal line, and a line
// carrying pattern metacharacters is refused here rather than turned into a
// graft literally named "**".

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
	if strings.ContainsAny(trimmed, "*?[]") {
		// A literal reader must never mint a graft named after a pattern it
		// cannot evaluate; the pattern engine owns those lines.
		return "", fmt.Errorf("local dir %q is a pattern; this client accepts literal paths only", raw)
	}
	p := path.Clean(strings.Trim(strings.ReplaceAll(trimmed, "\\", "/"), "/"))
	if p == "" || p == "." || p == ".." || strings.HasPrefix(p, "../") {
		return "", fmt.Errorf("local dirs must be workspace-relative paths: %q", raw)
	}
	for _, comp := range strings.Split(p, "/") {
		if localroutes.Protected(comp) {
			return "", fmt.Errorf("local dir %q names the protected path %q", raw, comp)
		}
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

// VolumeConfigPath is the in-volume declaration file: one rule per line, '#'
// comments. It is the ONE source of a volume's routing: the revision every
// mount reports is the hash of this file's canonical form and of nothing
// else. The pattern language it is written in lives in localroutes.
const VolumeConfigPath = localroutes.ConfigPath

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

// StorageID keys one VOLUME's machine-local backing under the state dir,
// keeping portablefsd's 32-hex storage-id convention.
func StorageID(volumeID string) string {
	sum := sha256.Sum256([]byte(volumeID))
	return fmt.Sprintf("%x", sum[:16])
}

// BackingRoot is the backing tree for one volume: route roots live under it
// at their volume-relative paths.
func BackingRoot(stateBase, volumeID string) string {
	return filepath.Join(stateBase, "local", StorageID(volumeID))
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

// Grafts is one mount's route set plus its machine-local backing tree. The
// rule set is IMMUTABLE for the life of the mount: routing is a pure function
// of the declared configuration, which is what makes the revision the mount
// reports to the authority describe the routing it is actually serving. There
// is no remap-on-rename path, and nothing here ever rewrites the declaration.
type Grafts struct {
	root  *confinedfs.Root
	rules localroutes.RuleSet
	fsMu  sync.Mutex // serializes compound no-replace mutations

	// onShadow, when set, observes the instantiation of a route root whose
	// name already exists on the volume. The CLI logs what became hidden.
	onShadow func(root string)
}

// Config builds one mount's graft set.
type Config struct {
	// BackingRoot is <stateBase>/local/<volume storage id>, the tree route
	// roots live in at their volume-relative paths.
	BackingRoot string
	// Rules is the activated route set (the volume's declaration, or — only
	// on a volume that declares nothing — this machine's --local-dir flags).
	Rules localroutes.RuleSet
	// OnShadow reports a route root that was just instantiated over an
	// existing volume subtree. It is called from a goroutine: shadowing is a
	// warning, never a blocking check on the mkdir path.
	OnShadow func(root string)
}

// New builds a Grafts set. An empty rule set returns (nil, nil) so callers
// keep a nil fast path.
func New(cfg Config) (*Grafts, error) {
	if cfg.Rules.Empty() {
		return nil, nil
	}
	if cfg.BackingRoot == "" {
		return nil, errors.New("localdirs: backing root is required")
	}
	root, err := confinedfs.Open(cfg.BackingRoot, 0o700)
	if err != nil {
		return nil, fmt.Errorf("localdirs: open confined backing: %w", err)
	}
	return &Grafts{root: root, rules: cfg.Rules, onShadow: cfg.OnShadow}, nil
}

// Close releases the backing-directory capability.
func (g *Grafts) Close() error {
	if g == nil {
		return nil
	}
	return g.root.Close()
}

// Rules returns the activated route set.
func (g *Grafts) Rules() localroutes.RuleSet {
	if g == nil {
		return localroutes.RuleSet{}
	}
	return g.rules
}

// Patterns returns the canonical rule texts this mount serves.
func (g *Grafts) Patterns() []string {
	if g == nil {
		return nil
	}
	return g.rules.Patterns()
}

// RevisionHex is the hex revision of the activated route set — the value the
// authority pins this mount to.
func (g *Grafts) RevisionHex() string {
	if g == nil {
		return localroutes.RuleSet{}.RevisionHex()
	}
	return g.rules.RevisionHex()
}

// Owner returns the route root that owns p ("" if p is served by the
// authority volume). Safe on a nil receiver so adapters can call it
// unconditionally, and allocation-free for the overwhelmingly common
// literal-name rule set.
func (g *Grafts) Owner(p string) string {
	if g == nil {
		return ""
	}
	root, _ := g.rules.Match(p)
	return root
}

// ActiveRootsUnder lists the route roots at or under dir whose machine-local
// backing exists — the roots that are real, as opposed to names the rules
// merely own. Scaffold directories are walked through; an active root is
// never descended into, so the cost is the scaffold, not the dependency tree.
func (g *Grafts) ActiveRootsUnder(dir string) ([]string, syscall.Errno) {
	if g == nil {
		return nil, 0
	}
	var out []string
	_, eno := g.walkBacking(dir, 0, func(p string) bool {
		out = append(out, p)
		return true
	})
	sort.Strings(out)
	return out, eno
}

// HasActiveRouteUnder reports whether any route root at or under p has
// machine-local backing. It stops at the first one: a rename only needs to
// know that the subtree carries local storage, not how much.
func (g *Grafts) HasActiveRouteUnder(p string) bool {
	if g == nil {
		return false
	}
	stopped, _ := g.walkBacking(p, 0, func(string) bool { return false })
	return stopped
}

// maxScaffoldDepth bounds the backing walk. Scaffold depth is the depth of
// the deepest rule, so this only ever truncates a backing tree that no longer
// matches any rule — which prune-local is the tool for.
const maxScaffoldDepth = 32

// walkBacking visits every existing route root at or under rel, calling visit
// with its volume-relative path; visit returns false to stop the walk, which
// walkBacking reports as stopped.
func (g *Grafts) walkBacking(rel string, depth int, visit func(string) bool) (stopped bool, eno syscall.Errno) {
	if depth > maxScaffoldDepth {
		return false, 0
	}
	if rel != "" {
		if root, ok := g.rules.Match(rel); ok {
			if root != rel {
				return false, 0 // inside another root; the outer one counted
			}
			if st, e := g.Lstat(rel); e == 0 && st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
				return !visit(rel), 0
			}
			return false, 0
		}
	}
	entries, err := g.root.ReadDir(rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, 0
		}
		return false, errnoOf(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		child := e.Name()
		if rel != "" {
			child = rel + "/" + child
		}
		stopped, eno := g.walkBacking(child, depth+1, visit)
		if stopped || eno != 0 {
			return stopped, eno
		}
	}
	return false, 0
}

// ensureScaffold creates the machine-local bookkeeping directories that lead
// up to (but do not include) the backing path for a graft root. Scaffold
// segments are storage layout, not namespace: only the root's own backing
// directory decides whether the root exists.
func (g *Grafts) ensureScaffold(root string) error {
	return g.root.MkdirAll(parentPath(root), 0o755)
}

// VolumeRenameCheck answers renames seen by VOLUME nodes. handled means the
// rename must not reach the authority. There are exactly three answers, and
// the declared configuration is never one of the things that changes:
//
//   - an endpoint at or under a route root is a cross-filesystem move:
//     EXDEV, exactly like a bind mount, and callers may fall back to
//     copy+delete because that is what crossing a filesystem means;
//   - a shared directory whose subtree holds ACTIVE machine-local backing is
//     EBUSY — the errno Linux returns for renaming a directory that contains
//     a mount point. EXDEV would be actively dangerous here: the fallback
//     would copy machine-local backing into shared storage. Tools do not fall
//     back on EBUSY;
//   - a rename that would make some path in the subtree newly match, or stop
//     matching, a rule is EBUSY too. Routing is path-based, so ownership
//     would silently flip under directories nobody touched; refusing the
//     rename is the only answer that keeps the declaration authoritative.
//
// Anything else passes through to the authority and needs no follow-up: the
// route set is a pure function of the declaration, so there is nothing to
// remap afterwards.
func (g *Grafts) VolumeRenameCheck(oldp, newp string) (syscall.Errno, bool) {
	if g == nil {
		return 0, false
	}
	if g.Owner(oldp) != "" || g.Owner(newp) != "" {
		return syscall.EXDEV, true
	}
	if g.HasActiveRouteUnder(oldp) || g.HasActiveRouteUnder(newp) {
		return syscall.EBUSY, true
	}
	if g.rules.SubtreeKey(oldp) != g.rules.SubtreeKey(newp) {
		return syscall.EBUSY, true
	}
	return 0, false
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

// Mkdir creates a grafted directory. Creating a route ROOT — which is how a
// route root comes into existence, including one a floating pattern matched
// for the first time at some depth nobody enumerated in advance — also
// creates the machine-local scaffold directories leading up to its backing
// path, and reports the shadowing it just started.
func (g *Grafts) Mkdir(p string, mode uint32) syscall.Errno {
	root := g.Owner(p) == p
	if root {
		if err := g.ensureScaffold(p); err != nil {
			return errnoOf(err)
		}
	}
	if err := g.root.Mkdir(p, os.FileMode(mode)&os.ModePerm); err != nil {
		return errnoOf(err)
	}
	if root && g.onShadow != nil {
		// Off the hot path deliberately: what is being hidden is a warning
		// for the operator, never a check the mkdir waits on.
		go g.onShadow(p)
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
// noReplace uses the host's descriptor-relative atomic primitive; exchange is
// not supported.
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
		return errnoOf(g.root.RenameNoReplace(oldp, newp))
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
