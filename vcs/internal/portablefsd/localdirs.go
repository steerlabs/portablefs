package portablefsd

// Local dirs graft machine-local subtrees over the mounted volume namespace.
//
// A local dir is a workspace-relative directory (for example "node_modules" or
// "agent-app/node_modules") whose contents are served from per-machine disk
// under the daemon state dir instead of from the shared authority volume. The
// volume never sees reads or writes under a local dir, and any same-named
// subtree that exists on the volume is shadowed while the graft is configured.
//
// This is the macOS counterpart of the Linux sandbox bind-mount overlays that
// Hosted products layer over FUSE mounts: heavy, platform-specific artifact
// directories (package installs, build caches) stay machine-local so that
// several machines can mount one volume concurrently and each run its own
// toolchain without corrupting the others. Grafts are opt-in per attach via
// AttachOptions.LocalDirs and can be extended at runtime through the control
// API; they change nothing for attaches that do not configure them.
//
// A graft rule owns a NAME, not a node: it routes every operation at or under
// the path to machine-local backing and unconditionally shadows any same-named
// volume subtree, but it never synthesizes existence.
//   - the graft root exists exactly when its backing directory exists: it is
//     created by an ordinary mkdir and removed by an ordinary rmdir, so tools
//     that rebuild dependency trees from scratch (npm ci removes and recreates
//     node_modules wholesale) work unchanged;
//   - a graft root whose backing does not exist resolves to ENOENT and is
//     omitted from its parent's enumeration — no phantom directories;
//   - renames across the graft boundary fail with EXDEV (callers fall back to
//     copy+delete, exactly as they do across bind mounts);
//   - renaming a volume ancestor of a graft root moves the graft with it.

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/trendup-ai/portablefs/vcs/internal/clientcore"
	"github.com/trendup-ai/portablefs/vcs/internal/confinedfs"
	"github.com/trendup-ai/portablefs/vcs/internal/fsproto"
	"github.com/trendup-ai/portablefs/vcs/internal/localdirs"
	"github.com/trendup-ai/portablefs/vcs/internal/pfslocal"
)

// normalizeLocalDirs cleans, validates, and deduplicates workspace-relative
// graft roots. Dirs nested inside another configured dir are dropped because
// the outer graft already owns the whole subtree.
func normalizeLocalDirs(dirs []string) ([]string, error) {
	cleaned := make([]string, 0, len(dirs))
	seen := map[string]bool{}
	for _, raw := range dirs {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "/") {
			return nil, errors.New("local dirs must be workspace-relative paths: " + raw)
		}
		p := path.Clean(strings.Trim(strings.ReplaceAll(trimmed, "\\", "/"), "/"))
		if p == "" || p == "." || p == ".." || strings.HasPrefix(p, "../") {
			return nil, errors.New("local dirs must be workspace-relative paths: " + raw)
		}
		if p == ".portablefs" || p == localdirs.VolumeConfigPath {
			return nil, errors.New("local dir would shadow the local-dirs declaration: " + raw)
		}
		if seen[p] {
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

// localDirForLocked returns the configured graft root that owns p ("" if p is
// served by the authority volume). Callers hold a.mu or a.nsMu.
func (a *attach) localDirForLocked(p string) string {
	for _, dir := range a.localDirs {
		if p == dir || strings.HasPrefix(p, dir+"/") {
			return dir
		}
	}
	return ""
}

// localDirFor is the lock-taking variant of localDirForLocked.
func (a *attach) localDirFor(p string) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.localDirForLocked(p)
}

// graftRootsUnderLocked lists graft roots whose parent directory is dir.
func (a *attach) graftRootsUnderLocked(dir string) []string {
	var out []string
	for _, root := range a.localDirs {
		if parentPath(root) == dir {
			out = append(out, root)
		}
	}
	return out
}

func (a *attach) graftRootsUnder(dir string) []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.graftRootsUnderLocked(dir)
}

// ensureLocalScaffold creates the machine-local bookkeeping directories that
// lead up to (but do not include) the backing path for p. Scaffold segments
// (for example "<localRoot>/agent-app" for the rule "agent-app/node_modules")
// are storage layout, not namespace: only the graft root's own backing
// directory decides whether the root exists.
func (a *attach) ensureLocalScaffold(p string) error {
	return a.localFS.MkdirAll(parentPath(p), 0o755)
}

// addLocalDirs merges new graft roots into a live attach, persists the change,
// and invalidates affected kernel state so the new namespace is visible
// immediately.
func (a *attach) addLocalDirs(dirs []string) ([]string, error) {
	a.nsMu.Lock()
	defer a.nsMu.Unlock()
	requested, err := normalizeLocalDirs(dirs)
	if err != nil {
		return nil, err
	}
	if len(requested) > 0 {
		a.mu.RLock()
		hasCapability := a.localFS != nil
		a.mu.RUnlock()
		if !hasCapability {
			root, openErr := confinedfs.Open(a.localRoot, 0o700)
			if openErr != nil {
				return nil, openErr
			}
			a.mu.Lock()
			if a.localFS == nil {
				a.localFS = root
				root = nil
			}
			a.mu.Unlock()
			if root != nil {
				_ = root.Close()
			}
		}
	}
	a.mu.Lock()
	merged, err := normalizeLocalDirs(append(append([]string(nil), a.localDirs...), requested...))
	if err != nil {
		a.mu.Unlock()
		return nil, err
	}
	var added []string
	previous := map[string]bool{}
	for _, dir := range a.localDirs {
		previous[dir] = true
	}
	for _, dir := range merged {
		if !previous[dir] {
			added = append(added, dir)
		}
	}
	a.localDirs = merged
	a.options.LocalDirs, err = normalizeLocalDirs(append(append([]string(nil), a.options.LocalDirs...), requested...))
	if err != nil {
		a.mu.Unlock()
		return nil, err
	}
	a.mu.Unlock()

	if err := a.persistState(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	for _, dir := range added {
		// A new rule changes the parent's merged listing (it can shadow an
		// authority entry) with no authority-side change, so the parent's
		// overlay version must move for the enumeration verifier to change.
		a.bumpLocalVersionLocked(parentPath(dir))
		// The graft shadows whatever the volume had at this path; force the
		// kernel to re-resolve the name and drop stale attrs/pages.
		a.publishNamespaceInvalidationLocked(dir, 0, 0)
		a.publishContentInvalidationLocked(dir, 0, 0)
	}
	a.mu.Unlock()
	return merged, nil
}

// remapLocalDirsForRenameLocked follows a successful authority rename of a
// volume path: graft roots under the renamed subtree move with it, and their
// backing directories are relocated so contents survive. Callers hold a.mu.
func (a *attach) remapLocalDirsForRenameLocked(oldp, newp string) bool {
	changed := false
	for i, dir := range a.localDirs {
		np, ok := renamedPath(dir, oldp, newp)
		if !ok {
			continue
		}
		if err := a.localFS.MkdirAll(parentPath(np), 0o755); err == nil {
			_ = a.localFS.Rename(dir, np)
		}
		a.localDirs[i] = np
		if ver, ok := a.localVersions[dir]; ok {
			delete(a.localVersions, dir)
			a.localVersions[np] = ver
		}
		changed = true
	}
	if changed {
		sort.Strings(a.localDirs)
		// A carried graft becomes explicit persisted mount state so a
		// remount keeps serving the backing under its new name even when the
		// volume declaration still contains the pre-rename path.
		a.options.LocalDirs = append([]string(nil), a.localDirs...)
	}
	return changed
}

// bumpLocalVersionLocked advances the namespace/content version of a local
// directory. Local versions are daemon-synthesized: local paths are only ever
// mutated through this daemon, so a monotonic counter is fully coherent.
// (Counters reset on daemon restart; that is acceptable because enumeration
// cookies from a previous daemon generation already answer ESTALE and the
// kernel's frontend connection does not survive the restart.)
func (a *attach) bumpLocalVersionLocked(dir string) uint64 {
	if a.localVersions == nil {
		a.localVersions = map[string]uint64{}
	}
	a.localVersions[dir]++
	return a.localVersions[dir]
}

func (a *attach) localVersionLocked(dir string) uint64 {
	return a.localVersions[dir]
}

// mergedDirVersionLocked is the single source of the enumeration-verifier
// version for a directory: grafted directories are versioned purely by the
// daemon-local counter, and graft parents combine the authority version with
// the local overlay counter so graft-root transitions move the verifier even
// though the authority never changed. Every listing and namespace
// invalidation must derive its version here so the two can never disagree.
func (a *attach) mergedDirVersionLocked(dir string) uint64 {
	if a.localDirForLocked(dir) != "" {
		return a.localVersionLocked(dir)
	}
	var ver uint64
	if a.vol != nil {
		_, ver = a.vol.VersionCache.GenAndVersion(dir)
	}
	return ver + a.localVersionLocked(dir)
}

// localAttr converts a backing-file Lstat result into the fsproto attr shape
// used across the daemon. Ino is left zero: local identity is minted through
// the daemon's local item-ID namespace, never from backing-disk inodes, so
// authority inodes and local backing inodes can never collide in the item
// table.
func localAttr(fi fs.FileInfo) fsproto.Attr {
	kind := "file"
	switch {
	case fi.IsDir():
		kind = "directory"
	case fi.Mode()&fs.ModeSymlink != 0:
		kind = "symlink"
	}
	mtime := fi.ModTime().UnixMilli()
	attr := fsproto.Attr{
		Kind:    kind,
		Size:    fi.Size(),
		Mode:    uint32(fi.Mode().Perm()),
		MtimeMs: mtime,
		CtimeMs: mtime,
		AtimeMs: mtime,
		Nlink:   1,
	}
	// ctime/atime/nlink come from the raw stat when available; the field names
	// differ per GOOS, so the extraction lives in localdirs_stat_*.go.
	applyLocalStatTimes(fi, &attr)
	return attr
}

// localErrno maps backing-filesystem errors onto the darwin errnos the
// frontend protocol speaks.
func localErrno(err error) int32 {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, fs.ErrNotExist):
		return darwinENOENT
	case errors.Is(err, fs.ErrExist):
		return darwinEEXIST
	case errors.Is(err, fs.ErrPermission):
		return darwinEACCES
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ENOENT:
			return darwinENOENT
		case syscall.EEXIST:
			return darwinEEXIST
		case syscall.ENOTDIR:
			return darwinENOTDIR
		case syscall.EISDIR:
			return darwinEISDIR
		case syscall.ENOTEMPTY:
			return darwinENOTEMPTY
		case syscall.EACCES, syscall.EPERM:
			return darwinEACCES
		case syscall.EXDEV:
			return darwinEXDEV
		case syscall.EBUSY:
			return darwinEBUSY
		case syscall.EINVAL:
			return darwinEINVAL
		case syscall.ENAMETOOLONG:
			return darwinENAMETOOLONG
		case syscall.ENOSPC:
			return darwinENOSPC
		}
	}
	return darwinEIO
}

// statLocal Lstats a grafted path. A graft root whose backing directory does
// not exist is ENOENT like any other missing path: rules route names, they do
// not synthesize existence.
func (a *attach) statLocal(p string) (fsproto.Attr, int32) {
	fi, err := a.localFS.Lstat(p)
	if err != nil {
		return fsproto.Attr{}, localErrno(err)
	}
	return localAttr(fi), 0
}

// readLocalDir lists a grafted directory as frontend-neutral entries.
func (a *attach) readLocalDir(p string) ([]clientcore.DirEntry, int32) {
	entries, err := a.localFS.ReadDir(p)
	if err != nil {
		return nil, localErrno(err)
	}
	out := make([]clientcore.DirEntry, 0, len(entries))
	for _, entry := range entries {
		fi, err := entry.Info()
		if err != nil {
			// The entry raced with a concurrent delete; skip it rather than
			// failing the whole listing.
			continue
		}
		out = append(out, clientcore.DirEntry{Name: entry.Name(), Attr: localAttr(fi)})
	}
	return out, 0
}

// registerLocalLocked registers (or refreshes) the item identity for a grafted
// path. Existing identities are preserved; new paths mint daemon-local item
// IDs exactly like unflushed write-back creates, so identities never derive
// from recyclable path hashes or backing-disk inodes.
func (a *attach) registerLocalLocked(p string, attr fsproto.Attr) *itemRecord {
	if rec := a.paths[p]; rec != nil {
		rec.attr = attr
		return rec
	}
	return a.registerWithItemLocked(p, attr, a.newLocalItemIDLocked(p), false, false)
}

func (a *attach) registerLocalAliasLocked(p string, source *itemRecord, attr fsproto.Attr) *itemRecord {
	if a.paths[p] != nil {
		a.removePathLocked(p)
	}
	rec := &itemRecord{item: source.item, path: p, state: source.state, attr: attr}
	a.paths[p] = rec
	if a.items[rec.item.ItemID] == nil {
		a.items[rec.item.ItemID] = rec
	}
	a.pendBindingLocked(rec)
	return rec
}

func (a *attach) registerLocal(p string, attr fsproto.Attr) *itemRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.registerLocalLocked(p, attr)
}

// removeLocal unlinks or rmdirs a grafted path with the same POSIX type
// guards the authority path enforces. The graft root itself is removable like
// any directory (rmdir semantics, so ENOTEMPTY while it has contents): tools
// that rebuild dependency trees wholesale (npm ci) must be able to remove and
// recreate it.
func (a *attach) removeLocal(p string, directory bool) int32 {
	fi, err := a.localFS.Lstat(p)
	if err != nil {
		return localErrno(err)
	}
	isDir := fi.IsDir()
	if directory {
		if !isDir {
			return darwinENOTDIR
		}
	} else if isDir {
		return darwinEISDIR
	}
	if err := a.localFS.Remove(p); err != nil {
		eno := localErrno(err)
		if eno == darwinEEXIST {
			// Darwin rmdir(2) reports a non-empty directory as EEXIST; the
			// frontend contract (like the authority path) speaks ENOTEMPTY.
			eno = darwinENOTEMPTY
		}
		return eno
	}
	a.mu.Lock()
	a.removePathLocked(p)
	a.bumpLocalVersionLocked(parentPath(p))
	a.mu.Unlock()
	a.flushBindingDelta()
	return 0
}

// renameLocal renames within a single graft with plain POSIX semantics (a
// rename that leaves or enters the graft never reaches here; the caller
// answers EXDEV at the boundary).
func (a *attach) renameLocal(oldp, newp string, noReplace bool) int32 {
	if noReplace {
		if _, err := a.localFS.Lstat(newp); err == nil {
			return darwinEEXIST
		} else if !errors.Is(err, fs.ErrNotExist) {
			return localErrno(err)
		}
	}
	replaced := false
	if _, err := a.localFS.Lstat(newp); err == nil {
		replaced = true
	}
	if err := a.localFS.Rename(oldp, newp); err != nil {
		return localErrno(err)
	}
	a.mu.Lock()
	if replaced {
		a.removePathLocked(newp)
	}
	a.renamePathLocked(oldp, newp)
	a.bumpLocalVersionLocked(parentPath(oldp))
	if parentPath(newp) != parentPath(oldp) {
		a.bumpLocalVersionLocked(parentPath(newp))
	}
	a.mu.Unlock()
	a.flushBindingDelta()
	return 0
}

// setattrLocal applies POSIX metadata changes directly to grafted backing
// files. Ownership changes are ignored to match the volume's noowners mounts.
func (a *attach) setattrLocal(rec *itemRecord, req *pfslocal.SetAttrRequest) (*pfslocal.SetAttrReply, int32) {
	flags := os.O_RDONLY
	if req.Size != nil {
		flags = os.O_WRONLY
	}
	file, err := a.localFS.OpenFile(rec.path, flags, 0)
	if err != nil {
		return nil, localErrno(err)
	}
	defer file.Close()
	if req.Mode != nil {
		if err := file.Chmod(os.FileMode(*req.Mode) & os.ModePerm); err != nil {
			return nil, localErrno(err)
		}
	}
	if req.Size != nil {
		if err := file.Truncate(int64(*req.Size)); err != nil {
			return nil, localErrno(err)
		}
	}
	if req.MtimeMs != nil || req.AtimeMs != nil {
		fi, err := file.Stat()
		if err != nil {
			return nil, localErrno(err)
		}
		current := localAttr(fi)
		atime := current.AtimeMs
		mtime := current.MtimeMs
		if req.AtimeMs != nil {
			atime = *req.AtimeMs
		}
		if req.MtimeMs != nil {
			mtime = *req.MtimeMs
		}
		times := []unix.Timeval{
			unix.NsecToTimeval(atime * 1_000_000),
			unix.NsecToTimeval(mtime * 1_000_000),
		}
		if err := unix.Futimes(int(file.Fd()), times); err != nil {
			return nil, localErrno(err)
		}
	}
	attr, eno := a.statLocal(rec.path)
	if eno != 0 {
		return nil, eno
	}
	updated := a.registerLocal(rec.path, attr)
	a.flushBindingDelta()
	return &pfslocal.SetAttrReply{Attr: fsAttrToLocal(attr, updated.item)}, 0
}

// readLocalFile serves a bounded control-API read from grafted backing disk,
// mirroring the volume path's offset/length contract.
func (a *attach) readLocalFile(p string, offset int64, length int) ([]byte, int32) {
	file, err := a.localFS.Open(p)
	if err != nil {
		return nil, localErrno(err)
	}
	defer func() { _ = file.Close() }()
	fi, err := file.Stat()
	if err != nil {
		return nil, localErrno(err)
	}
	if fi.IsDir() {
		return nil, darwinEISDIR
	}
	if length < 0 {
		length = 0
	}
	data := make([]byte, length)
	n, err := file.ReadAt(data, offset)
	if err != nil && err != io.EOF {
		return nil, localErrno(err)
	}
	return data[:n], 0
}

// writeLocalFile replaces a grafted file's contents from the control API,
// mirroring the frontend create+write identity bookkeeping. Creating the
// graft root's scaffold and parents on demand lets management writes land
// before anything mkdir'ed the root through the mount.
func (a *attach) writeLocalFile(p string, graft string, data []byte) int32 {
	if p == graft {
		// A graft rule is a directory rule; the root itself is never a file.
		return darwinEISDIR
	}
	if err := a.ensureLocalScaffold(graft); err != nil {
		return localErrno(err)
	}
	rootExisted := true
	if _, err := a.localFS.Lstat(graft); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return localErrno(err)
		}
		rootExisted = false
	}
	if err := a.localFS.MkdirAll(parentPath(p), 0o755); err != nil {
		return localErrno(err)
	}
	if err := a.localFS.WriteFile(p, data, 0o644); err != nil {
		return localErrno(err)
	}
	attr, eno := a.statLocal(p)
	if eno != 0 {
		return eno
	}
	a.mu.Lock()
	a.registerLocalLocked(p, attr)
	a.bumpLocalVersionLocked(parentPath(p))
	if !rootExisted {
		// The write materialized the graft root implicitly: the root's parent
		// listing changed, so its overlay version must move too.
		a.bumpLocalVersionLocked(parentPath(graft))
		a.publishNamespaceInvalidationLocked(graft, 0, 0)
	}
	a.publishNamespaceInvalidationLocked(p, 0, 0)
	a.publishContentInvalidationLocked(p, 0, 0)
	a.mu.Unlock()
	a.flushBindingDelta()
	return 0
}

func localOpenFlags(mode pfslocal.OpenMode) int {
	switch mode {
	case pfslocal.OpenModeWrite, pfslocal.OpenModeReadWrite:
		// The kernel reuses handles across fadvise/mmap paths; opening
		// read-write for any write-intent open keeps reads on the same
		// handle valid.
		return os.O_RDWR
	default:
		return os.O_RDONLY
	}
}
