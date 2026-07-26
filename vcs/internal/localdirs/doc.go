// Package localdirs implements machine-local dirs (grafts) for the FUSE mount
// clients: workspace-relative directories (for example "node_modules" or
// "agent-app/node_modules") whose contents are served from per-machine disk
// under a mount state dir instead of from the shared authority volume. The
// volume never sees reads or writes under a local dir, and any same-named
// subtree that exists on the volume is shadowed while the graft is configured.
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
//   - renaming a volume ancestor of a graft root moves the graft and its
//     machine-local backing with it.
//
// Performance is the point: operations under a graft go straight to the local
// filesystem — no fsproto round trips, no write-back flush batching, no
// invalidation subscriptions. Graft matching on the non-graft hot path is a
// nil check plus a prefix scan over a small immutable slice swapped atomically.
package localdirs
