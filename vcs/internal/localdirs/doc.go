// Package localdirs implements machine-local dirs (grafts) for the FUSE mount
// clients: workspace-relative directories (for example "node_modules" or
// "agent-app/node_modules") whose contents are served from per-machine disk
// under a mount state dir instead of from the shared authority volume. The
// volume never sees reads or writes under a local dir, and any same-named
// subtree that exists on the volume is shadowed while the graft is configured.
//
// WHICH directories are local is decided by the pattern language in
// vcs/internal/localroutes, parsed from the volume's ".portablefs/local-dirs"
// declaration — routing is volume-wide state, identical on every machine, and
// the declaration's revision is what the authority pins a mount to. A rule can
// float ("node_modules/" at any depth), so the set of graft ROOTS is not a
// list known at mount time: a root comes into existence when a matching
// directory is created, at whatever depth, and the same rules decide it.
//
// This is the Linux-unprivileged counterpart of two existing mechanisms: the
// bind-mount overlays that privileged sandboxes layer over FUSE mounts, and the
// native grafts the macOS portablefsd daemon serves to the FSKit frontend
// (vcs/internal/portablefsd/localdirs.go). The semantics are identical across
// all three, so a repository behaves the same no matter which client mounts it:
//
//   - a graft rule owns a NAME, not a node: it routes every operation at or
//     under the path to machine-local backing and unconditionally shadows any
//     same-named volume subtree, but it never synthesizes existence;
//   - the graft root exists exactly when its backing directory exists: it is
//     created by an ordinary mkdir and removed by an ordinary rmdir, so tools
//     that rebuild dependency trees wholesale (npm ci removes and recreates
//     node_modules) work unchanged;
//   - a graft root whose backing does not exist resolves to ENOENT and is
//     omitted from its parent's listing — no phantom directories;
//   - renames across the graft boundary fail with EXDEV (callers fall back to
//     copy+delete, exactly as they do across bind mounts); the root itself can
//     only ever be a directory (EISDIR for create/symlink at the root);
//   - renaming a shared directory whose subtree holds ACTIVE machine-local
//     backing, or whose rename would change what the rules route, fails with
//     EBUSY. Routing is a pure function of the declaration: nothing here
//     rewrites the configured rules, so nothing can drift from the revision
//     the mount reported to the authority. EBUSY rather than EXDEV is the
//     point — EXDEV invites a copy+delete fallback, which would copy
//     machine-local backing into shared storage; EBUSY is what Linux answers
//     for renaming a directory that contains a mount point, and tools do not
//     fall back on it.
//
// Backing is keyed by (volume, route root path) and by nothing else: the
// volume's backing tree holds each root at its own volume-relative path, so a
// dependency tree survives unmount, remount, and remount at a different path,
// while a different volume mounted at the same path can never inherit it.
// `portablefs prune-local` reclaims backing whose route no longer exists.
//
// Performance is the point: operations under a graft go straight to the local
// filesystem — no fsproto round trips, no write-back flush batching, no
// invalidation subscriptions. Graft matching on the non-graft hot path is a
// nil check plus, for the literal-name rule sets real workspaces declare, one
// map lookup per path component with no allocation.
package localdirs
