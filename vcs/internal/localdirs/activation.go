package localdirs

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
)

// VolumeReader is the slice of the volume client activation needs. It is an
// interface so the guards below are testable without an authority, and so
// this package can never reach for a write path: activation READS the
// declaration, the git index, and the directories a route is about to shadow.
// It writes nothing to the volume — in particular it never touches
// .gitignore, which is the user's file and none of our business.
type VolumeReader interface {
	Lookup(ctx context.Context, path string) (fsproto.Attr, clientcore.Status)
	Read(ctx context.Context, path string, n *clientcore.NodeState, off int64, length int) ([]byte, clientcore.Status)
	Readdir(ctx context.Context, dir string) ([]clientcore.DirEntry, clientcore.Status)
}

// maxRouteConfigBytes bounds the declaration read. A rule set is human
// written config; anything larger is a mistake worth failing on.
const maxRouteConfigBytes = 1 << 16

// ReadRouteConfig reads the volume's route declaration. present reports
// whether the volume publishes one at all, which is a different question from
// whether it declares any rules: a declaration holding only comments is still
// the volume asserting that IT owns routing. Absence is normal and yields no
// bytes; every other failure is an error, because a mount that silently
// degraded to "no routes" would serve the shared volume where the workspace
// asked for machine-local disk and would report a revision for a declaration
// it never read.
func ReadRouteConfig(ctx context.Context, vol VolumeReader) (data []byte, present bool, err error) {
	a, st := vol.Lookup(ctx, VolumeConfigPath)
	if st == fsproto.ENOENT {
		return nil, false, nil
	}
	if st != fsproto.OK {
		return nil, false, fmt.Errorf("read %s: status %d", VolumeConfigPath, st)
	}
	if a.Size > maxRouteConfigBytes {
		return nil, true, fmt.Errorf("%s is %d bytes; the limit is %d", VolumeConfigPath, a.Size, maxRouteConfigBytes)
	}
	data, st = vol.Read(ctx, VolumeConfigPath, clientcore.NewNodeState(a.Ino, a.Ino != 0), 0, maxRouteConfigBytes)
	if st != fsproto.OK {
		return nil, true, fmt.Errorf("read %s: status %d", VolumeConfigPath, st)
	}
	return data, true, nil
}

// gitIndexPath is the volume-relative index of the workspace's repository.
// It is unroutable by construction (see localroutes' protected namespace), so
// reading it here always reads the SHARED file every machine sees.
const gitIndexPath = localroutes.ProtectedGit + "/index"

// maxGitIndexBytes bounds the tracked-file check. A 64 MiB index is roughly a
// million tracked paths; past that the check reports that it could not prove
// anything rather than pretending the repository is clean.
const maxGitIndexBytes = 64 << 20

// ErrRoutesTrackedByGit is the activation refusal: a route would take
// version-controlled content machine-local, where it would be invisible to
// every other machine while git still believes it owns it.
var ErrRoutesTrackedByGit = errors.New("localdirs: route matches git-tracked content")

// CheckGitTracked refuses activation when the rule set routes a path the
// repository tracks. It parses .git/index directly (no git binary, no
// assumption that one is installed) and reports honestly when it cannot
// decide: an index in version 4 stores paths prefix-compressed, and an index
// past the size cap is not read at all. In those cases the caller gets
// (false, reason) and must say so rather than claim the routes are clean —
// the boundary of this guard is exactly "index versions 2 and 3, up to
// maxGitIndexBytes, of the repository at the volume root".
func CheckGitTracked(ctx context.Context, vol VolumeReader, rules localroutes.RuleSet) (proven bool, unprovenReason string, err error) {
	if rules.Empty() {
		return true, "", nil
	}
	a, st := vol.Lookup(ctx, gitIndexPath)
	switch {
	case st == fsproto.ENOENT:
		// No repository (or no index yet): nothing is tracked, so nothing can
		// be shadowed. That is a proof, not a gap.
		return true, "", nil
	case st != fsproto.OK:
		return false, fmt.Sprintf("%s is unreadable (status %d)", gitIndexPath, st), nil
	case a.Size > maxGitIndexBytes:
		return false, fmt.Sprintf("%s is %d bytes, past the %d-byte read limit", gitIndexPath, a.Size, maxGitIndexBytes), nil
	}
	data, st := vol.Read(ctx, gitIndexPath, clientcore.NewNodeState(a.Ino, a.Ino != 0), 0, int(a.Size))
	if st != fsproto.OK {
		return false, fmt.Sprintf("%s is unreadable (status %d)", gitIndexPath, st), nil
	}
	paths, perr := localroutes.ParseGitIndexPaths(data)
	if errors.Is(perr, localroutes.ErrGitIndexUnsupported) {
		return false, perr.Error() + " (paths are prefix-compressed; this check cannot enumerate them)", nil
	}
	if perr != nil {
		return false, perr.Error(), nil
	}
	if p, root, rule, found := rules.FirstTrackedMatch(paths); found {
		return false, "", fmt.Errorf("%w: rule %s routes %q, which git tracks at %q", ErrRoutesTrackedByGit, rule, root, p)
	}
	return true, "", nil
}

// ShadowedEntries lists what a route root hides on the volume: the names
// directly under it, when the volume has a non-empty directory there. Nothing
// is ever deleted — the volume's copy stays exactly as it is, and reappears
// the moment the route is removed.
func ShadowedEntries(ctx context.Context, vol VolumeReader, root string, limit int) []string {
	a, st := vol.Lookup(ctx, root)
	if st != fsproto.OK || a.Kind != "directory" {
		return nil
	}
	ents, st := vol.Readdir(ctx, root)
	if st != fsproto.OK || len(ents) == 0 {
		return nil
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	if limit > 0 && len(names) > limit {
		names = append(names[:limit:limit], fmt.Sprintf("… and %d more", len(names)-limit))
	}
	return names
}

// WarnAnchoredShadowing reports, at activation, every ANCHORED route root the
// volume already has content at. Anchored roots are the ones whose paths are
// known before anything is created; a floating pattern's roots are reported
// by Grafts.OnShadow as they are instantiated, because enumerating them in
// advance would mean walking the whole shared tree.
func WarnAnchoredShadowing(ctx context.Context, vol VolumeReader, rules localroutes.RuleSet, warnf func(string, ...any)) {
	if rules.Empty() || warnf == nil {
		return
	}
	for _, pattern := range rules.Patterns() {
		if !strings.HasPrefix(pattern, "/") || strings.ContainsAny(pattern, "*?") {
			continue
		}
		root := strings.Trim(pattern, "/")
		if names := ShadowedEntries(ctx, vol, root, 16); len(names) > 0 {
			warnf("machine-local route %q shadows the volume's existing %s/ (hidden while the route is configured, never deleted): %s",
				pattern, root, strings.Join(names, ", "))
		}
	}
}
