//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

// The routing declaration lives in the volume, at the one path every client
// reads. The two components are derived from that single constant rather than
// repeated, and a ConfigPath that is not exactly "<directory>/<file>" is
// refused at construction: this code creates, fsyncs and renames within one
// parent, and it must not silently do that at the wrong depth if the constant
// ever changes shape.
var routesDirName, routesFileName, routesPendingName = func() (string, string, string) {
	parts := strings.Split(localroutes.ConfigPath, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", ""
	}
	return parts[0], parts[1], parts[1] + ".pending"
}()

// maxRoutesBytes bounds the declaration this authority will read or install.
// It is a rule file, not a data file; anything near this size is a mistake, and
// refusing it is better than allocating for it.
const maxRoutesBytes = 1 << 20

// maxRoutesGitIndexBytes is deliberately much larger than the route
// declaration while still bounding the authority's activation-time proof. A
// route may never hide content the repository already tracks. If the index is
// larger than this, malformed, sparse, split, or otherwise not completely
// enumerable, the authority refuses the route change instead of treating an
// incomplete parse as an empty tracked set.
const maxRoutesGitIndexBytes = 64 << 20

// routesWriteMode is the declaration file's mode. It is readable by every mount
// - clients must read it to know the topology they have to agree with - and
// writable only through ApplyRoutes, which mount mutations cannot reach.
const routesWriteMode fs.FileMode = 0o644

// routesDirMode is the protected directory's mode.
const routesDirMode fs.FileMode = 0o755

// RoutesController owns the volume's active machine-local routing revision.
//
// The authority is the source of truth for it. Every mount reads the same file
// out of the same volume, but only this process decides which revision is
// active, because only this process can refuse a mount that disagrees. A mount
// that routed node_modules to local disk while its peer shared it would upload
// one machine's platform-specific dependency tree into a subtree the other has
// hidden, and neither side would see an error - so the disagreement has to be
// caught where both sides are visible, which is here.
type RoutesController struct {
	Store      *xfsstore.Volume
	Visibility *volumeserver.VisibilityCoordinator

	mu        sync.RWMutex
	loaded    bool
	revision  [32]byte
	canonical []byte
	// syncDirectory is the durability boundary after the pending declaration was
	// renamed live. Production uses Store.SyncObject; the narrow dependency makes
	// the rename-success/fsync-failure outcome fault-injectable.
	syncDirectory func(xfsstore.Capability) error
}

// AcquireTopologyRead pins the active route revision across one attach or
// filesystem request. The caller checks admission only after acquiring it and
// releases it only after the request can no longer reach XFS.
func (r *RoutesController) AcquireTopologyRead() *volumeserver.TopologyReadGuard {
	return r.Visibility.AcquireTopologyRead()
}

func NewRoutesController(store *xfsstore.Volume, visibility *volumeserver.VisibilityCoordinator) (*RoutesController, error) {
	if store == nil || visibility == nil {
		return nil, errors.New("authorityrpc: routing needs the volume store and the visibility coordinator")
	}
	if routesDirName == "" || routesFileName == "" {
		return nil, fmt.Errorf("authorityrpc: %q is not a two-component in-volume path", localroutes.ConfigPath)
	}
	return &RoutesController{Store: store, Visibility: visibility}, nil
}

// Load reads the declaration out of this authority's own volume root and makes
// its revision active. An absent file is an empty rule set, which has a
// revision of its own - the digest of no rules - so "no routing configured" is
// a value every mount must agree with rather than a case that skips the check.
//
// A file that is present and does not parse is fatal. The alternative would be
// to serve some other topology than the one the volume declares, and every
// mount that then attached would agree with a revision the volume does not
// have.
func (r *RoutesController) Load() error {
	raw, err := r.read()
	if err != nil {
		return err
	}
	rules, err := localroutes.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse %s from the volume root: %w", localroutes.ConfigPath, err)
	}
	if err := r.checkGitTracked(rules); err != nil {
		return fmt.Errorf("activate %s from the volume root: %w", localroutes.ConfigPath, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revision, r.canonical, r.loaded = rules.Revision(), rules.Canonical(), true
	return nil
}

// Revision is the active routing revision. It is only meaningful after Load.
func (r *RoutesController) Revision() ([32]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.loaded {
		return [32]byte{}, errors.New("authorityrpc: routing revision was never loaded from the volume")
	}
	return r.revision, nil
}

// Admit checks one peer's declared revision against the active one. It is the
// same check at attach and on every later request, because the two failures are
// the same failure: a mount running a topology this volume does not.
func (r *RoutesController) Admit(presented [32]byte, declared bool, subject string, sessionRefused bool) error {
	r.mu.RLock()
	loaded, active, canonical := r.loaded, r.revision, append([]byte(nil), r.canonical...)
	r.mu.RUnlock()
	if !loaded {
		return errors.New("authorityrpc: routing revision was never loaded from the volume")
	}
	if declared && presented == active {
		return nil
	}
	mismatch := &RoutesMismatchError{
		Active: active, Presented: presented, Declared: declared,
		Subject: subject, SessionRefused: sessionRefused,
	}
	if !sessionRefused {
		// Only an attach refusal carries the declaration. A session that has
		// gone stale already read it once; repeating it on every later request
		// would put the whole rule set on a hot error path.
		mismatch.Canonical = canonical
	}
	return mismatch
}

// Apply installs a new declaration through the visibility barrier.
//
// expected is a compare-and-swap against the active revision. Two operators
// editing the routing file must not last-writer-win silently, and the CAS is
// also what makes a retry after an uncertain outcome readable: it either
// applies once, or it comes back naming the revision that is active now.
func (r *RoutesController) Apply(ctx context.Context, raw []byte, expected [32]byte) (*authoritypb.ApplyRoutesReply, error) {
	if len(raw) > maxRoutesBytes {
		return nil, syscall.EFBIG
	}
	rules, err := localroutes.Parse(raw)
	if err != nil {
		// The rules never reached the volume, so this is an ordinary refusal of
		// a bad request and not an uncertain outcome.
		return nil, fmt.Errorf("%w: %w", errRoutesInvalid, err)
	}
	next := volumeserver.RoutesChange{Revision: rules.Revision(), Canonical: rules.Canonical()}

	var active [32]byte
	var activeCanonical []byte
	apply := false
	acknowledged, err := r.Visibility.ExecuteRoutesChecked(ctx, next, func() (bool, error) {
		// This is the authoritative CAS. ExecuteRoutesChecked holds the topology
		// writer before calling it, so no admitted request or attach is still
		// running and no competing routing change can decide against the same old
		// value.
		r.mu.RLock()
		loaded := r.loaded
		active = r.revision
		activeCanonical = append([]byte(nil), r.canonical...)
		r.mu.RUnlock()
		if !loaded {
			return false, errors.New("authorityrpc: routing revision was never loaded from the volume")
		}
		if expected != active {
			return false, &RoutesMismatchError{Active: active, Presented: expected, Declared: true, Subject: "apply routes"}
		}
		if err := r.checkGitTracked(rules); err != nil {
			return false, fmt.Errorf("%w: %w", errRoutesInvalid, err)
		}
		if next.Revision == active {
			return false, nil
		}
		apply = true
		return true, nil
	}, func() (volumeserver.RoutesChange, error) {
		published, err := r.write(raw)
		if err != nil && !published {
			r.mu.RLock()
			current := volumeserver.RoutesChange{Revision: r.revision, Canonical: append([]byte(nil), r.canonical...)}
			r.mu.RUnlock()
			return current, err
		}
		// Rename is the logical publication point. Even when syncing its parent
		// reports an uncertain failure, the live name may already be the new file;
		// in-memory state and COMPLETE must never lie by announcing the old rules.
		r.mu.Lock()
		r.revision, r.canonical = next.Revision, append([]byte(nil), next.Canonical...)
		r.mu.Unlock()
		return next, err
	})
	if err != nil {
		return nil, err
	}
	if !apply {
		// The declaration was already in force. The decision was made under the
		// same topology writer as a real change, so a concurrent Apply cannot move
		// it between the comparison and this reply.
		return &authoritypb.ApplyRoutesReply{
			Revision: append([]byte(nil), active[:]...), Canonical: activeCanonical,
		}, nil
	}
	return &authoritypb.ApplyRoutesReply{
		Revision:                 append([]byte(nil), next.Revision[:]...),
		Canonical:                append([]byte(nil), next.Canonical...),
		AcknowledgedParticipants: uint32(acknowledged),
	}, nil
}

var errRoutesInvalid = errors.New("authorityrpc: routing declaration is not valid")

var errRoutesTrackedByGit = errors.New("authorityrpc: route matches git-tracked content")

// checkGitTracked is the authority-side activation guard. Client checks are a
// useful early diagnostic, but they are not an authorization boundary: an
// admin caller can invoke ApplyRoutes directly and an older frontend may not
// implement the check at all. The authority therefore reads the shared,
// protected .git/index while the topology writer excludes filesystem RPCs and
// refuses any route whose subtree already contains a tracked path.
//
// This is intentionally an activation-time invariant. Git may later replace
// its index through ordinary shared filesystem operations; enforcing a
// lifetime invariant would require a transactional Git-index protocol rather
// than guessing at transient index.lock writes. The declaration remains
// fail-closed at every Load and Apply boundary.
func (r *RoutesController) checkGitTracked(rules localroutes.RuleSet) error {
	if rules.Empty() {
		return nil
	}
	data, present, err := r.readGitIndex()
	if err != nil {
		return fmt.Errorf("cannot prove routes avoid git-tracked content: %w", err)
	}
	if !present {
		return nil
	}
	return checkGitIndexTracked(rules, data)
}

func checkGitIndexTracked(rules localroutes.RuleSet, data []byte) error {
	paths, err := localroutes.ParseGitIndexPaths(data)
	if err != nil {
		return fmt.Errorf("cannot prove routes avoid git-tracked content: parse %s/index: %w", localroutes.ProtectedGit, err)
	}
	if path, root, rule, found := rules.FirstTrackedMatch(paths); found {
		return fmt.Errorf("%w: rule %s routes %q, which git tracks at %q", errRoutesTrackedByGit, rule, root, path)
	}
	return nil
}

// readGitIndex reads the root repository's index through the same confined XFS
// capability API as every other authority operation. A .git indirection file
// is deliberately unproven: its target cannot be followed without accepting a
// host path, and treating it as an empty repository would make the guard lie.
func (r *RoutesController) readGitIndex() ([]byte, bool, error) {
	root, err := r.Store.Root()
	if err != nil {
		return nil, false, err
	}
	dir, attr, err := r.Store.Lookup(root, localroutes.ProtectedGit)
	if absentEntry(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = r.Store.Forget(dir) }()
	if attr.Kind != xfsstore.KindDirectory {
		return nil, true, fmt.Errorf("%s is not a directory; linked-worktree gitdir indirection is not a complete in-volume tracked-path proof", localroutes.ProtectedGit)
	}
	item, attr, err := r.Store.Lookup(dir, "index")
	if absentEntry(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	defer func() { _ = r.Store.Forget(item) }()
	if attr.Kind != xfsstore.KindRegular || attr.Nlink != 1 {
		return nil, true, fmt.Errorf("%s/index must be a regular file with exactly one link; got kind %d, mode %v, and link count %d",
			localroutes.ProtectedGit, attr.Kind, attr.Mode, attr.Nlink)
	}
	if attr.Size < 0 || attr.Size > maxRoutesGitIndexBytes {
		return nil, true, fmt.Errorf("%s/index is %d bytes; this authority reads at most %d",
			localroutes.ProtectedGit, attr.Size, maxRoutesGitIndexBytes)
	}
	handle, err := r.Store.OpenFile(item, xfsstore.OpenFlags{Read: true})
	if err != nil {
		return nil, true, err
	}
	defer func() { _ = r.Store.CloseOpen(handle) }()
	buf := make([]byte, 0, attr.Size)
	chunk := make([]byte, 64<<10)
	for offset := int64(0); offset < attr.Size; {
		want := chunk
		if remaining := attr.Size - offset; remaining < int64(len(want)) {
			want = want[:remaining]
		}
		n, readErr := r.Store.ReadAt(handle, want, offset)
		buf = append(buf, want[:n]...)
		offset += int64(n)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return nil, true, readErr
		}
		if n == 0 {
			break
		}
	}
	if int64(len(buf)) != attr.Size {
		return nil, true, fmt.Errorf("%s/index changed or became short while it was read: got %d of %d bytes",
			localroutes.ProtectedGit, len(buf), attr.Size)
	}
	return buf, true, nil
}

// read returns the declaration bytes, or nil when the protected directory or
// the file inside it does not exist yet.
func (r *RoutesController) read() ([]byte, error) {
	root, err := r.Store.Root()
	if err != nil {
		return nil, err
	}
	dir, _, err := r.Store.Lookup(root, routesDirName)
	if absentEntry(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Store.Forget(dir) }()
	item, attr, err := r.Store.Lookup(dir, routesFileName)
	if absentEntry(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Store.Forget(item) }()
	if attr.Kind != xfsstore.KindRegular || attr.Nlink != 1 {
		return nil, fmt.Errorf("%s must be a regular file with exactly one link; got kind %d, mode %v, and link count %d",
			localroutes.ConfigPath, attr.Kind, attr.Mode, attr.Nlink)
	}
	if attr.Size > maxRoutesBytes {
		return nil, fmt.Errorf("%s is %d bytes; this authority reads at most %d", localroutes.ConfigPath, attr.Size, maxRoutesBytes)
	}
	handle, err := r.Store.OpenFile(item, xfsstore.OpenFlags{Read: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Store.CloseOpen(handle) }()
	buf := make([]byte, 0, attr.Size)
	chunk := make([]byte, 64<<10)
	for offset := int64(0); ; {
		n, err := r.Store.ReadAt(handle, chunk, offset)
		buf = append(buf, chunk[:n]...)
		offset += int64(n)
		if errors.Is(err, io.EOF) || n == 0 {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(buf) > maxRoutesBytes {
			return nil, fmt.Errorf("%s exceeds %d bytes", localroutes.ConfigPath, maxRoutesBytes)
		}
	}
	return buf, nil
}

// write installs the declaration crash-atomically: the replacement is written
// and fsynced under a pending name, renamed over the live one, and the parent
// directory is fsynced so the rename itself is durable. A crash therefore
// leaves either the old declaration or the new one, never a truncated file that
// would refuse to parse and take the next authority epoch down with it.
//
// The operator's bytes are stored verbatim rather than the canonical form.
// Nothing depends on the file being canonical - the revision is defined as the
// digest of what Parse canonicalizes it to - and a file that comes back from
// the volume with its comments and ordering intact is one an operator can edit
// again.
func (r *RoutesController) write(raw []byte) (bool, error) {
	root, err := r.Store.Root()
	if err != nil {
		return false, err
	}
	dir, err := r.directory(root)
	if err != nil {
		return false, err
	}
	defer func() { _ = r.Store.Forget(dir) }()
	if err := r.Store.Unlink(dir, routesPendingName, false); err != nil && !absentEntry(err) {
		return false, err
	}
	item, _, err := r.Store.Create(dir, routesPendingName, routesWriteMode, true)
	if err != nil {
		return false, err
	}
	defer func() { _ = r.Store.Forget(item) }()
	handle, err := r.Store.OpenFile(item, xfsstore.OpenFlags{Read: true, Write: true})
	if err != nil {
		return false, err
	}
	writeErr := r.writeAll(handle, raw)
	if writeErr == nil {
		// The data is durable before the rename that publishes it, so a crash
		// leaves either the old declaration or the new one and never a
		// truncated file the next epoch would refuse to parse.
		writeErr = r.Store.Fsync(handle, false)
	}
	closeErr := r.Store.CloseOpen(handle)
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = r.Store.Unlink(dir, routesPendingName, false)
		return false, err
	}
	if err := r.Store.Rename(dir, routesPendingName, dir, routesFileName, 0); err != nil {
		_ = r.Store.Unlink(dir, routesPendingName, false)
		return false, err
	}
	syncDirectory := r.syncDirectory
	if syncDirectory == nil {
		syncDirectory = r.Store.SyncObject
	}
	if err := syncDirectory(dir); err != nil {
		return true, fmt.Errorf("%w: routing declaration was renamed live before its directory sync failed: %w", xfsstore.ErrOutcomeUncertain, err)
	}
	return true, nil
}

func (r *RoutesController) writeAll(handle xfsstore.Capability, raw []byte) error {
	for offset := 0; offset < len(raw); {
		n, err := r.Store.WriteAt(handle, raw[offset:], int64(offset))
		offset += n
		if err != nil {
			return err
		}
		if n == 0 {
			// A short write that made no progress would otherwise spin here.
			return syscall.ENOSPC
		}
	}
	return nil
}

// directory resolves the protected directory, creating it if the volume has
// never had one. A concurrent creation is impossible: mounts cannot create this
// name, and ApplyRoutes holds the barrier's write side.
func (r *RoutesController) directory(root xfsstore.Capability) (xfsstore.Capability, error) {
	dir, _, err := r.Store.Lookup(root, routesDirName)
	if err == nil {
		return dir, nil
	}
	if !absentEntry(err) {
		return xfsstore.Capability{}, err
	}
	created, _, err := r.Store.Mkdir(root, routesDirName, routesDirMode)
	if err != nil {
		return xfsstore.Capability{}, err
	}
	if err := r.Store.SyncObject(root); err != nil {
		_ = r.Store.Forget(created)
		return xfsstore.Capability{}, err
	}
	return created, nil
}

// admitSessionRoutes refuses every request from a session whose routing
// revision is no longer the active one.
//
// This is the "epoch-visible value" a routing change bumps, and it is held here
// rather than echoed on each request on purpose. An echo is a peer assertion:
// a mount that failed to install the new declaration could still send the new
// revision on every request and keep operating under the old topology, and the
// authority would have no way to tell. The revision recorded at attach is the
// one the authority itself admitted, so the only way to present the active one
// is to have attached with it. It also costs nothing on the wire and stays out
// of the canonical mutation hash, so a routing change cannot desynchronize a
// replay slot.
//
// It is airtight because the switch happens under the barrier's registration
// write lock: no Execute is running, none can start, and no attach can be in
// progress, so no request exists that was admitted under one revision and
// executes under the other.
func (h *VolumeHandler) admitSessionRoutes(id volumeserver.SessionID) error {
	h.resourcesMu.Lock()
	resources := h.resources[id]
	if resources == nil || resources.ended {
		h.resourcesMu.Unlock()
		return volumeserver.ErrSessionExpired
	}
	presented := resources.routes
	h.resourcesMu.Unlock()
	return h.Routes.Admit(presented, true, "this mount's session", true)
}

// beginTopologyRequest combines the topology read guard and revision admission
// into one operation. The caller holds the returned guard through the final
// filesystem result, so ApplyRoutes cannot fit between "this session agrees"
// and the XFS operation that depended on that answer.
func (h *VolumeHandler) beginTopologyRequest(id volumeserver.SessionID) (*volumeserver.TopologyReadGuard, error) {
	guard := h.Routes.AcquireTopologyRead()
	if err := h.admitSessionRoutes(id); err != nil {
		guard.Release()
		return nil, err
	}
	return guard, nil
}

// attachRoutesRevision decodes the revision a mount declares. An absent one is
// reported as undeclared rather than rejected here, so the refusal that reaches
// the operator is the one that names the volume's active revision instead of a
// bare EINVAL.
func attachRoutesRevision(raw []byte) ([32]byte, bool, error) {
	var revision [32]byte
	if len(raw) == 0 {
		return revision, false, nil
	}
	if len(raw) != len(revision) {
		return revision, false, syscall.EINVAL
	}
	copy(revision[:], raw)
	return revision, true, nil
}

// routesRevision decodes a revision that must be present and exact.
func routesRevision(raw []byte) ([32]byte, error) {
	var revision [32]byte
	if len(raw) != len(revision) {
		return revision, syscall.EINVAL
	}
	copy(revision[:], raw)
	return revision, nil
}

func namespaceRepair(repair authoritypb.NamespaceRepair) (volumeserver.NamespaceRepair, error) {
	switch repair {
	case authoritypb.NamespaceRepair_NAMESPACE_REPAIR_UNSPECIFIED:
		return volumeserver.NamespaceRepairUnspecified, nil
	case authoritypb.NamespaceRepair_NAMESPACE_REPAIR_PARENT_EXCLUSIVE:
		return volumeserver.NamespaceRepairParentExclusive, nil
	case authoritypb.NamespaceRepair_NAMESPACE_REPAIR_INDEPENDENT:
		return volumeserver.NamespaceRepairIndependent, nil
	case authoritypb.NamespaceRepair_NAMESPACE_REPAIR_CALLBACK_SERIALIZED:
		return volumeserver.NamespaceRepairCallbackSerialized, nil
	case authoritypb.NamespaceRepair_NAMESPACE_REPAIR_CALLBACK_SERIALIZED_PIPELINED:
		return volumeserver.NamespaceRepairCallbackSerializedPipelined, nil
	default:
		return volumeserver.NamespaceRepairUnspecified, syscall.EINVAL
	}
}

func absentEntry(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOENT)
}
