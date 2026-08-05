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
//   - renaming a volume ancestor of a graft root fails with EBUSY: routing is
//     path-owned, so carrying the backing would rewrite the declared topology.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// normalizeLocalDirs is intentionally only a package-local name for the
// shared literal-path contract. Requests can reach the daemon directly,
// without passing through the CLI, so keeping a second validator here would
// let the two activation boundaries disagree about protected names.
func normalizeLocalDirs(dirs []string) ([]string, error) {
	return localdirs.Normalize(dirs)
}

// declaredLocalDirsForFSKit parses the declaration with the one canonical
// language implementation, then lowers only the subset portablefsd can serve
// exactly: anchored, wildcard-free directory roots. A floating rule such as
// node_modules/ also owns nested node_modules directories; treating it as the
// one literal root "node_modules" would apply a different topology while
// appearing to accept the declaration. Unsupported semantics therefore fail
// activation as a whole.
func declaredLocalDirsForFSKit(data []byte) ([]string, error) {
	rules, err := localroutes.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", localdirs.VolumeConfigPath, err)
	}
	dirs := make([]string, 0, len(rules.Patterns()))
	for _, pattern := range rules.Patterns() {
		if !strings.HasPrefix(pattern, "/") || strings.ContainsAny(pattern, "*?") {
			return nil, fmt.Errorf(
				"%s contains route %q, whose floating or wildcard semantics this FSKit daemon cannot serve; "+
					"portablefsd currently accepts only anchored literal rules such as /node_modules/ and refuses the whole declaration rather than applying a different topology",
				localdirs.VolumeConfigPath, pattern,
			)
		}
		dirs = append(dirs, strings.TrimSuffix(strings.TrimPrefix(pattern, "/"), "/"))
	}
	return localdirs.Normalize(dirs)
}

// ── THE VOLUME'S DECLARATION IS THE ONLY SOURCE OF ROUTING TRUTH ───────────
//
// Route topology is volume-declared. .portablefs/local-dirs is the one place a
// volume's machine-local routing is written, the revision every mount reports
// at attach is the hash of that file, and the authority refuses a mount whose
// revision disagrees.
//
// A per-machine addition breaks that. It would take a directory every peer
// still treats as shared and hide it on ONE machine, with no peer able to see
// that it happened and no revision reflecting it: an agent on the laptop would
// write into local disk while an agent in the sandbox wrote into the volume,
// under the same path, and neither would be wrong from where it stood.
//
// The Linux FUSE client already refuses this. The FSKit branch of `portablefs
// mount` hands --local-dir straight to this daemon without reading the
// declaration, so refusing it there is not enough - macOS could still skew the
// topology. The refusal therefore also lives HERE, at both places a graft rule
// can enter a live daemon: activation, and the runtime control API.
//
// When the volume publishes no declaration, the legacy per-machine path is
// unchanged: there is no volume-wide topology for a per-machine rule to
// contradict.
var errVolumeDeclaresRoutes = errors.New("volume declares its machine-local routes")

// volumeDeclaresRoutesError words the refusal exactly as the FUSE client words
// it. Two frontends refusing the same thing for the same reason in two
// different sentences is how an operator concludes they are two different
// rules.
func volumeDeclaresRoutesError(requested, declared []string) error {
	existing := strings.Join(declared, " ")
	if existing == "" {
		existing = "(none; the declaration is present but declares no rules)"
	}
	return fmt.Errorf(
		"%w in %s, so --local-dir is not accepted: a per-machine addition would hide from this machine a "+
			"directory every peer still treats as shared. Add the rule to %s and apply it volume-wide "+
			"(requested: %s; existing rules: %s)",
		errVolumeDeclaresRoutes, localdirs.VolumeConfigPath, localdirs.VolumeConfigPath,
		strings.Join(requested, " "), existing)
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

func localDirForRules(p string, dirs []string) string {
	for _, dir := range dirs {
		if p == dir || strings.HasPrefix(p, dir+"/") {
			return dir
		}
	}
	return ""
}

// transitionGraftProvenanceLocked reincarnates every active pathname whose
// routing owner changes under a new effective graft rule set. Item provenance
// is immutable: mutating rec.graft in place would let an FSKit Item already
// published for authority storage silently become a machine-local inode (or
// vice versa). The retired Item remains detached until Reclaim; the next
// lookup publishes a fresh identity with the new owner.
func (a *attach) transitionGraftProvenanceLocked(effective []string) []string {
	var paths []string
	for p, rec := range a.paths {
		if rec == nil || p == "" {
			continue
		}
		wantGraft := localDirForRules(p, effective) != ""
		if rec.graft != wantGraft {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		if rec := a.paths[p]; rec != nil {
			a.detachReincarnatedPathLocked(p, rec, detachReprovisioned)
		}
	}
	return paths
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
	unlockNamespace := a.lockExternalNamespaceWrite()
	defer unlockNamespace()
	requested, err := normalizeLocalDirs(dirs)
	if err != nil {
		return nil, err
	}
	if len(requested) > 0 {
		// The runtime half of the volume-declaration gate. A rule that
		// activation would have refused must not be able to arrive through the
		// control API a moment later.
		a.mu.RLock()
		declaredOwnsRouting := a.volumeRoutesDeclared
		declaredRules := append([]string(nil), a.localDirs...)
		a.mu.RUnlock()
		if declaredOwnsRouting {
			return nil, volumeDeclaresRoutesError(requested, declaredRules)
		}
		a.mu.RLock()
		hasCapability := a.localFS != nil
		a.mu.RUnlock()
		if !hasCapability {
			// Adding a graft rule to a live attach acquires the backing for the
			// first time, so it is a second activation boundary and carries the
			// same case-safety probe (localcasesafety.go). A rule added at
			// runtime must not be able to reach a backing that activation would
			// have refused.
			root, openErr := openLocalBacking(a.localRoot)
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
	previousOptions := append([]string(nil), a.options.LocalDirs...)
	nextOptions, err := normalizeLocalDirs(append(append([]string(nil), previousOptions...), requested...))
	if err != nil {
		a.mu.Unlock()
		return nil, err
	}
	// Commit the durable routing rule before changing live ownership. If this
	// snapshot fails, no published Item is detached and the old routing view
	// remains coherent. A crash after the snapshot but before the transition
	// is also safe: activation applies the effective rule set and performs
	// this same reincarnation before the frontend can serve.
	a.options.LocalDirs = nextOptions
	a.mu.Unlock()
	if err := a.persistState(); err != nil {
		a.mu.Lock()
		a.options.LocalDirs = previousOptions
		a.mu.Unlock()
		return nil, err
	}

	a.mu.Lock()
	changedItems := a.transitionGraftProvenanceLocked(merged)
	a.localDirs = merged
	// A new rule changes the parent's merged listing (it can shadow an
	// authority entry) with no authority-side change, so the parent's overlay
	// version must move for the enumeration verifier to change.
	for _, dir := range added {
		a.bumpLocalVersionLocked(parentPath(dir))
	}
	a.mu.Unlock()

	journalErr := a.flushBindingDeltaError()
	// Publish invalidations even if the binding journal failed. That failure
	// freezes the attach, but already-live vnodes must still be told that
	// their immutable provenance was retired.
	a.mu.Lock()
	for _, dir := range added {
		// The graft shadows whatever the volume had at this path; force the
		// kernel to re-resolve the name and drop stale attrs/pages.
		a.publishNamespaceInvalidationLocked(dir, 0, 0)
		a.publishContentInvalidationLocked(dir, 0, 0)
	}
	for _, p := range changedItems {
		a.publishNamespaceInvalidationLocked(p, 0, 0)
	}
	a.mu.Unlock()
	if journalErr != nil {
		return nil, fmt.Errorf("persist local-dir identity transition: %w", journalErr)
	}
	return merged, nil
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
		Kind:      kind,
		Size:      fi.Size(),
		AllocSize: fi.Size(),
		Mode:      uint32(fi.Mode().Perm()),
		MtimeMs:   mtime,
		CtimeMs:   mtime,
		AtimeMs:   mtime,
		Nlink:     1,
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
		case syscall.ENOTSUP:
			// A backing filesystem that cannot honor the operation at all
			// (chflags(2) on a graft, say). EIO would read as a transient
			// failure; ENOTSUP is the definite answer the caller needs.
			return darwinENOTSUP
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
		// This arm bypasses registerWithItemLocked, where publication admission
		// otherwise lives, and it is still a publication: it overwrites the
		// record's attributes with an observation this caller is about to
		// expose. It is taken HERE rather than at the top of the function so
		// the other arm is admitted exactly once, by registerWithItemLocked.
		a.publishRecordAttrLocked(rec, attr, true)
		return rec
	}
	return a.registerWithItemLocked(p, attr, a.newLocalItemIDLocked(p), false, false, true)
}

func (a *attach) registerLocalAliasLocked(p string, source *itemRecord, attr fsproto.Attr) *itemRecord {
	// Binding a new name onto an existing identity publishes attributes for
	// that name, so it is admitted like any other publication. It does not
	// reach registerWithItemLocked, where the check otherwise lives.
	a.admitPublicationLocked(p)
	if a.paths[p] != nil {
		a.removePathLocked(p)
	}
	rec := &itemRecord{
		item: source.item, path: p, state: source.state, graft: true,
	}
	a.publishRecordAttrLocked(rec, attr, false) // p was admitted at the top
	a.paths[p] = rec
	a.addItemAliasLocked(rec)
	a.frontendPathEpoch.Add(1)
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
	return a.flushBindingDelta()
}

// renameLocal renames within a single graft with plain POSIX semantics (a
// rename that leaves or enters the graft never reaches here; the caller
// answers EXDEV at the boundary).
func (a *attach) renameLocal(oldp, newp string, noReplace bool) int32 {
	replaced := false
	if noReplace {
		if err := a.localFS.RenameNoReplace(oldp, newp); err != nil {
			return localErrno(err)
		}
	} else {
		if _, err := a.localFS.Lstat(newp); err == nil {
			replaced = true
		}
		if err := a.localFS.Rename(oldp, newp); err != nil {
			return localErrno(err)
		}
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
	return a.flushBindingDelta()
}

// setattrLocal applies POSIX metadata changes directly to grafted backing
// files. Ownership changes are ignored to match the volume's noowners mounts.
func (a *attach) setattrLocal(
	rec *itemRecord,
	exactHandle *handleRecord,
	scope string,
	detached bool,
	req *pfslocal.SetAttrRequest,
	commit *setattrCommit,
) (*pfslocal.SetAttrReply, int32) {
	// EVERY exit after the host truncate commits publishes the size it applied.
	// A mode, flags or timestamp step below the truncate can still fail on its
	// own terms, and each of those returns an errno for a size change that
	// really happened; none of them may close the item's mutation sequence over
	// a registry that still holds the pre-truncate size. The publish is inert
	// until the truncate records one and inert again once a real registration
	// has published it.
	defer func() {
		a.publishSetattrCommit(context.Background(), nil, rec.item.ItemID, commit)
	}()
	var file *os.File
	closeFile := false
	if exactHandle != nil {
		if exactHandle.file == nil {
			return nil, darwinEIO
		}
		file = exactHandle.file
	} else {
		flags := os.O_RDONLY
		if req.Size != nil {
			flags = os.O_WRONLY
		}
		var err error
		file, err = a.localFS.OpenFile(rec.path, flags, 0)
		if err != nil {
			return nil, localErrno(err)
		}
		closeFile = true
	}
	if closeFile {
		defer file.Close()
	}
	if req.Mode != nil {
		if err := file.Chmod(os.FileMode(*req.Mode) & os.ModePerm); err != nil {
			return nil, localErrno(err)
		}
	}
	if req.Size != nil {
		if err := file.Truncate(int64(*req.Size)); err != nil {
			return nil, localErrno(err)
		}
		// Committed on the host inode. Every step below can still fail and
		// return an errno, and none of them may close this item's mutation
		// sequence over a registry that still holds the pre-truncate size; see
		// the bracket in attach.setattr.
		commit.recordExact(int64(*req.Size))
	}
	if req.SetFlags {
		// Grafts need no FeatureFlagPersistence: their backing IS a real host
		// inode, so chflags(2) on it is the durable store. Read the current
		// word first — the safe subset is authoritative from the request, the
		// rest of the host's flags are preserved (see applyLocalGraftFlags).
		fi, err := file.Stat()
		if err != nil {
			return nil, localErrno(err)
		}
		if err := applyLocalGraftFlags(int(file.Fd()), fi, req.Flags); err != nil {
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
	fi, err := file.Stat()
	if err != nil {
		return nil, localErrno(err)
	}
	attr := localAttr(fi)
	var updated *itemRecord
	if exactHandle != nil {
		a.mu.Lock()
		updated = a.registerHandleAttrLocked(exactHandle, attr)
		a.mu.Unlock()
	} else {
		updated = a.registerLocal(rec.path, attr)
	}
	if updated == nil {
		return nil, darwinEIO
	}
	commit.published = true
	if eno := a.flushBindingDelta(); eno != 0 {
		return nil, eno
	}
	return &pfslocal.SetAttrReply{
		Attr: a.localAttrForRecordPath(attr, updated, scope, detached),
	}, 0
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
//
// ── IT IS A BRACKETED, TWO-STEP MUTATION LIKE ITS AUTHORITY TWIN ────────────
//
// It used to be one os.WriteFile call followed by a stat, which hid two
// separate defects behind one line. os.WriteFile opens O_TRUNC, so a failure
// after the open left the host inode at ZERO with nothing recorded; and a
// failure of the stat AFTER a completely successful write returned an errno for
// a size change that had really happened, with no bracket to keep the item
// unstable and no committed size to publish. Either way the registry kept the
// pre-write size and the next refresh armed on it.
//
// So the host mutation is now explicit and in the same order the authority arm
// uses: write the bytes at offset 0 first — never truncating first, which would
// make a mid-flight failure destroy the file's contents in exchange for
// nothing — then cut the old tail. Progress is recorded as a FLOOR after the
// write, because the old contents may still extend past it, and upgraded to the
// exact size once the truncate commits.
func (a *attach) writeLocalFile(p string, graft string, data []byte) (uint64, int32) {
	if p == graft {
		// A graft rule is a directory rule; the root itself is never a file.
		return 0, darwinEISDIR
	}
	if err := a.ensureLocalScaffold(graft); err != nil {
		return 0, localErrno(err)
	}
	rootExisted := true
	if _, err := a.localFS.Lstat(graft); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return 0, localErrno(err)
		}
		rootExisted = false
	}
	if err := a.localFS.MkdirAll(parentPath(p), 0o755); err != nil {
		return 0, localErrno(err)
	}
	// published starts TRUE for the same reason every other carrier's does:
	// every exit before the first committed byte leaves nothing for the registry
	// to be behind on. The publish defer is registered AFTER the bracket so it
	// unwinds BEFORE the settle.
	commit := &setattrCommit{published: true}
	if existing := a.itemByPath(p); existing != nil {
		bracketed := existing.item.ItemID
		settleMutation := a.beginItemMutation(bracketed)
		defer func() { settleMutation(commit.published) }()
		defer func() {
			a.publishSetattrCommit(context.Background(), nil, bracketed, commit)
		}()
	}
	if eno := a.replaceLocalFileContents(p, data, commit); eno != 0 {
		return 0, eno
	}
	if hook := a.testAfterLocalFileWrite; hook != nil {
		hook(p)
	}
	attr, eno := a.statLocal(p)
	if eno != 0 {
		return 0, eno
	}
	a.mu.Lock()
	refreshItemID := a.registerLocalLocked(p, attr).item.ItemID
	// A real registration has stated this item's attributes, so the commit's
	// own fallback publication is inert from here on.
	commit.published = true
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
	if eno := a.flushBindingDelta(); eno != 0 {
		return 0, eno
	}
	return refreshItemID, 0
}

// replaceLocalFileContents performs the host half of a control replacement
// write on one descriptor, recording what it commits as it commits it.
//
// The descriptor is opened WITHOUT O_TRUNC deliberately: truncating first turns
// every subsequent failure into data destruction, and the tail the truncate at
// the end removes is the only thing the ordering costs. A short write reports
// both a count and an error, and the count is committed progress that outranks
// the error for the reason it does everywhere else in this daemon.
func (a *attach) replaceLocalFileContents(p string, data []byte, commit *setattrCommit) int32 {
	file, err := a.localFS.OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return localErrno(err)
	}
	defer func() { _ = file.Close() }()
	wrote, werr := file.WriteAt(data, 0)
	if wrote > 0 {
		commit.recordFloor(int64(wrote))
	}
	if werr != nil {
		return localErrno(werr)
	}
	if err := file.Truncate(int64(len(data))); err != nil {
		return localErrno(err)
	}
	commit.recordExact(int64(len(data)))
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
