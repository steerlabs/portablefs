# Agent Workspaces

How to run coding agents (Claude Code, Codex, custom harnesses) on PortableFS
volumes. This is the long-form companion to `portablefs help` — the CLI text is
what you hand to an agent; this document explains the patterns and why they
work.

The model in one paragraph: a volume is a workspace that lives in the network,
not a folder on one machine. One XFS authority owns its durable state, so every
mount — laptop, server, sandbox — is a window onto the same ordered filesystem.
Linux production writes are direct. Shipping macOS builds currently refuse a
production mount before Attach; separately build-stamped qualification builds
use `fsync` when they need an explicit cross-machine completion boundary. There
is no history graph, no branch, no snapshot and no fork: there is the current
state of the workspace, and every machine that mounts it sees exactly that.
Machines are disposable; the workspace is not.

## Continuity: The Workspace Outlives The Session

An agent run today is usually welded to the machine it started on: laptop
sleeps, SSH drops, sandbox recycles — work gone or stranded. On PortableFS the
machine is just a viewport:

```bash
# day 1, laptop
portablefs mount refactor-auth ~/work \
  --addr 10.0.0.7:2050 --mount-token "$CAP" \
  --data-plane-transport tls-private-ca --data-plane-server-name authority.internal \
  --data-plane-ca ca.pem --client-cert client.pem --client-key client.key
cd ~/work && git clone git@github.com:acme/api . && claude

# day 1, later, a server: pick up mid-run with a fresh capability
portablefs mount refactor-auth /srv/work \
  --addr 10.0.0.7:2050 --mount-token "$CAP2" \
  --data-plane-transport tls-private-ca --data-plane-server-name authority.internal \
  --data-plane-ca ca.pem --client-cert client.pem --client-key client.key
cd /srv/work    # same files, same git state, same half-finished edit
```

The handoff is safe with no barrier discipline at all, and that is the whole
point:

- **There is no PortableFS durability debt.** A v3 mount holds no daemon WAL or
  offline tail. Linux direct writes return after XFS application. In the macOS
  qualification policy, ordinary kernel page-cache semantics remain, so an
  agent that needs a handoff or durability boundary calls `fsync`, which waits
  for the authoritative server descriptor. `close` alone is not that boundary.
- **There is no stale handover, because there is no second truth.** Both mounts
  are windows onto the same live authority. Names and attributes are cached only
  while every mount participates in the authority's synchronous visibility
  barrier: a mutation that returned on one mount is not observable as older
  state on another. A writer installs its exact source-publication gate before
  dispatch, and peers repair before that writer's result is released. Protocol
  5 has no non-participating mount mode.

For scheduled or resumable agents, make the mount the first step of the job and
the unmount the last; the workspace carries all state between runs, including
`.git`, caches, and SQLite files. Both are exercised across two mounts by the
required privileged Linux gate (`TestWorkloadGitAcrossMounts`,
`TestWorkloadSQLiteAcrossMounts` — see [local-dev.md](./local-dev.md)). That gate
counts for the strict profile only when its host is booted into the checked-in
patched Linux 6.12.100 kernel; a stock-kernel refusal is expected.

An initial mount capability is single-use. A hosted mount that explicitly opts
into automatic reauthorization also receives a bounded, volume- and key-scoped
enrollment. The Linux mount supervisor or the macOS qualification daemon then
obtains and installs short-lived grants automatically without remounting; there
is one sequencer per mount and the filesystem session, locks, handles, and
strict-cache membership stay intact. A definitive denial or missed safety
cutoff fails closed and detaches. Standalone mounts omit the
enrollment and can use the explicit `portablefs reauthorize` command; they never
silently switch modes.

## Parallel Agents

Several agents can work in one volume at once, from one machine or from several.
Coordinate them with ordinary filesystem semantics, which the authority orders
for every mount:

- **Distinct files.** Two agents writing different files never interfere, and
  both see the complete result. This is the cheapest and most reliable
  partition: give each agent its own subtree.
- **Atomic rename.** Write to a temporary file, then `rename(2)` over the
  target. Another mount observes either the old inode with the old bytes or the
  new inode with the new bytes, never a mixture.
- **Linux POSIX locks.** On Linux, `fcntl` byte-range locks and `flock` are held
  by the authority, not by one kernel, so they coordinate across mounts. A
  blocked waiter is released when the holder's session ends rather than hanging
  forever. In macOS qualification builds, FSKit exposes no advisory-lock
  callbacks: an agent must use `O_EXCL` create, atomic rename, or disjoint files
  for cross-machine coordination, and must not treat a locally successful lock
  as distributed.

Concurrent whole-record overwrites of one file leave one writer's record, never
a mixture; concurrent Linux `O_APPEND` writers lose no record and tear no record,
though the interleaving is free. Those are named cases in the two-mount
coherence matrix ([cross-mount-coherence-matrix.md](./cross-mount-coherence-matrix.md)).

What is *not* available is a cheap copy of the workspace. There are no forks and
no snapshots, so "run N agents on the same task and compare" means N volumes: provision
them separately, seed each from your source of truth (a `git clone`, a build
artifact), and mount one per runner. Budget for that — it is real copying, not a
metadata operation — and prefer partitioning one workspace when the attempts do
not actually need to diverge.

## Compute Near The Volume

Mounting needs the platform transport (FSKit on macOS, FUSE on Linux — see
[fskit-mount.md](./fskit-mount.md)) and a machine you control. There is no
server-side `exec` and no server-side `grep`: the storage plane never runs tenant
commands, and content search is `rg` inside a mount like anywhere else. An
environment that cannot mount needs a different isolated runner that can, not a
weaker remote-command surface.

Protocol 5 accepts one coherence profile. `strict` is the default and every
mount participates; `--coherence uncached` is rejected before Attach rather
than mapped to another mode. Shipping macOS builds currently fail even earlier,
before constructing an authority transport, because public FSKit cannot yet
prove exact peer namespace/attribute invalidation or publish every required
post-mutation attribute. Only the separately build-stamped qualification
artifact exercises the candidate native repair policy; production agent mounts
currently use Linux FUSE.

A standalone sandbox mounts with direct credentials and nothing else:

- `--addr host:port` — the authority;
- `--mount-token` (or `PORTABLEFS_MOUNT_TOKEN`) — one single-use volume mount
  capability;
- `--data-plane-transport tls-system-pki` with `--data-plane-server-name`, or
  `tls-private-ca` with that name plus `--data-plane-ca ca.pem`;
- `--client-cert` / `--client-key` — the mutual-TLS client identity (the key
  must be `chmod 600`).

The hosted manager returns the same credential shape from a proof-of-possession
CSR and can renew the live session without receiving the private key. See
[hosted-control-plane.md](./hosted-control-plane.md).

v3 authority sessions are mutually authenticated TLS 1.3, so plaintext cannot
mount and there is no transport fallback to configure. Copy the static
`portablefs` binary into the sandbox, mount inside its isolation boundary, run
the agent, unmount. Because the capability is single-use, a leaked sandbox
credential is not a standing key to the workspace.

## Keep Per-Machine Dependencies Local

Dependency trees and build caches are platform-specific: a `node_modules`
installed by a Linux sandbox must never be executed by the macOS laptop that
mounts the same volume, and neither should pay to sync it. Machine-local routes
(grafts) serve those directories from local disk instead of the volume.

Which directories is a property of the **volume**, not of a machine. The
declaration is `.portablefs/local-dirs` — one directory rule per line, `#`
comments — with `node_modules/` matching at any depth, `/target/` only at the
volume root, `*` and `?` within one component and `**` across components:

```text
# per-machine dirs: served from local disk, never synced
node_modules/
.venv/
/target/
```

The revision a mount presents at attach is the hash of that file, and the
authority refuses any mount whose revision is not the volume's active one. That
is what makes the topology a volume-wide fact instead of a per-machine
accident. Two consequences follow:

- **`--local-dir` is refused unconditionally**, on every platform. A rule that
  existed on one machine only would hide a directory every peer still treats as
  shared — invisibly, with no revision recording it, and with no peer able to
  observe that it happened. `--no-local-dirs` likewise refuses a declaring
  volume instead of ignoring its topology.
- **The mounted `.portablefs` namespace is read-only.** The authority marks the
  subtree protected, so an ordinary `cp` or editor write into it is refused
  before it can start. Reading stays open because every client must read the
  declaration to learn the revision it has to present. Changing routes is the
  authority's admin `ApplyRoutes` call, which moves the revision through the
  same barrier every mount is pinned to.

Machine-local routing is served by the Linux FUSE frontend. The macOS attach
refuses graft options and declares the empty rule set, so a volume that declares
routes mounts from Linux ([fskit-mount.md](./fskit-mount.md)).

`portablefs route <path>` answers the operational question directly: which mount
serves this path, whether it comes from machine-local disk or the shared volume,
which rule decided that, and which revision the mount activated.

### Never local-route irreplaceable user data

The list above is deliberately only rebuildable artifacts. A local route is not
a performance hint; it is a statement that the directory's contents are
**disposable and reproducible on this machine**.

`uploads/` is the named counterexample. A directory holding user-supplied
files — uploads, attachments, generated reports a user will come back for,
anything the machine cannot regenerate from a lockfile or a build — must never
appear in a `local-dirs` declaration. Route it local and it stops being part of
the volume: it is not on any other machine that mounts the same volume, and not
in any backup that covers the volume. It lives on one machine's disk, and the
day that machine is replaced or its state dir is cleared, it is gone with no
error and no trace, because from the volume's point of view nothing was ever
there.

The test is one question: *if this machine were destroyed right now, could the
directory be rebuilt by running a command?* `node_modules` and `target` pass.
`uploads/` does not.

### Graft semantics an agent will actually hit

Inside a graft everything behaves like a local filesystem at local-disk speed
(`npm install`, `npm ci`, `cargo build`): operations go straight to local disk on
file-descriptor-backed handles and reach the authority zero times.

- **Shadow, do not synthesize.** A rule owns the name but creates nothing. It
  shadows any same-named volume subtree unconditionally, while the graft root
  itself exists exactly when an ordinary `mkdir` created it and is removable
  like any directory — so `rm -rf node_modules && npm ci` works unchanged.
- **`EXDEV` across the boundary.** A `mv` between grafted and shared space fails
  with `EXDEV`, and callers fall back to copy+delete exactly as they do across a
  bind mount. The root can only ever be a directory.
- **`EBUSY` on a shared-ancestor rename.** Renaming a *shared* directory whose
  subtree still holds an active local route fails with `EBUSY`, not `EXDEV`, and
  the difference is load-bearing: `EXDEV` is the errno that invites a recursive
  copy, and that copy would drag machine-local content into shared storage,
  silently. `EBUSY` is what Linux returns for renaming a directory that contains
  a mount point — the errno that makes tools stop rather than improvise.
- **Backing survives remount and never travels.** Backing is keyed by (volume,
  route root), so unmounting and remounting on the same machine finds the same
  tree. It is invisible to every other mount, which also means each machine
  installs its own dependencies once.
- **Reclaim is explicit.** Removing a rule from the declaration never deletes
  data. `portablefs prune-local` lists machine-local backing that no route can
  reach any more — a retired rule, or a whole retired volume — and `--delete`
  actually reclaims it. Dry-run is the default.

The full contract, including the confinement rules that make graft backing a
security boundary rather than a trusted path prefix, is in
[graft-security.md](./graft-security.md) and
[xfs-authority-architecture.md](./xfs-authority-architecture.md#machine-local-routing).
