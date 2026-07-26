# Architecture

PortableFS is a live filesystem for agents. The product contract is simple:

```text
mount a volume
run Codex, Claude Code, shells, Git, SQLite, build tools, or scripts in that mount
files behave like one shared filesystem
```

Everything below exists to preserve that contract.

## Root Invariants

1. **The live filesystem is the product.**
   Users and agents should think in paths, files, directories, renames, locks, and `fsync`.
   Checkpoints, commits, snapshots, and object storage are infrastructure underneath.

2. **The custom mount protocol is the production data plane.**
   Linux FUSE, macOS FSKit, Kubernetes CSI, and container bind mounts should all terminate
   in the same custom protocol. NFS is compatibility only.

3. **One active volume has one logical authority.**
   A single ordered authority decides the current filesystem state for a mounted active
   volume. This keeps rename ordering, directory mutation, file locking, SQLite journaling,
   and Git behavior understandable.

4. **One logical authority must not mean one fragile process.**
   Production writes must be stored in a replicated durable log before acknowledgement.
   The VCS satisfies this contract with the remote journal: every acknowledged write
   commits to a fenced, synchronously replicated PostgreSQL journal
   ([journal.md](./journal.md)) before the client hears "done". The authority process is
   a disposable cache over that truth — a replacement claims the journal and cold-replays.

5. **Object storage is not the synchronous write path.**
   Railway Buckets/S3 hold checkpointed content, cold data, snapshots, forks, and long-term
   durable history. Normal file writes acknowledge from the live durable layer, then
   checkpoint in the background.

6. **Shared writing uses filesystem semantics, not magical merge.**
   Two agents can read the same files. Writes are ordered by the authority. When performance
   or safety requires exclusive ownership of a file or subtree, use delegations/checkouts.
   Same-file concurrent edits are handled like a normal filesystem: locks, atomic rename,
   last writer wins where the application chooses that pattern, or clear write errors.

7. **Fail closed in production.**
   `VCS_PRODUCTION=1` requires the remote journal and refuses every local-durability
   shape by name: local WAL files, persistent cache directories, NFS serving, operator
   listener addresses, and unauthenticated data or lifecycle planes (per-instance
   `VCS_AUTH_TOKEN` + `VCS_ADMIN_TOKEN`, even on loopback). The child refuses to serve
   until the journal database's durability evidence satisfies the structured HA policy.

## Target Shape

```text
agent machine A              agent machine B              agent machine C
Codex / Claude Code          shell / Git / SQLite         build / tests
      |                            |                            |
      | FUSE / FSKit / CSI / bind-mounted custom protocol       |
      v                            v                            v
                  stable PortableFS volume endpoint
                                  |
                                  v
              one logical VCS authority for the active volume
                                  |
                    replicated durable filesystem log
                                  |
                 live working tree + cache + delegations
                                  |
                      automatic checkpoints/history
                                  |
          Postgres metadata + Railway Bucket content-addressed blobs
```

The stable volume endpoint is resolved by the PortableFS authority manager. Product
workers call the manager for `ensure`, `session`, `health`, and `stop`; the manager owns
the registry that maps a volume branch to the live VCS authority. The manager also owns
a single public TCP/TLS router. The router selects a loopback VCS backend by the mount
session token and then forwards the custom filesystem protocol. Product workers and
agent sandboxes see only the stable router address; they never see per-volume loopback
ports or launch VCS processes themselves. This keeps PortableFS, rather than each
product, responsible for authority provisioning wherever the manager runs.

The implementation follows a shared-filesystem model: a custom filesystem protocol, a durable
storage layer between clients and object storage, strong connected-client disk consistency,
ownership for shared writers, and eventual synchronization to the backing data source.

## Production Runtime Contract

Production is the authority manager's production mode
(`PORTABLEFS_AUTHORITY_MODE=production`, [authority-manager.md](./authority-manager.md))
spawning one disposable journal child per active `teamId + volumeId + branch`. The
manager claims a database-fenced singleton epoch in the `pfm` control database, and
each child journals to the fenced remote PostgreSQL journal ([journal.md](./journal.md)).
No durable fact lives on the manager host: no persistent work directory, no local WAL,
no file ledger.

Each child runs with `VCS_PRODUCTION=1 VCS_WRITABLE=1` and the manager-built
environment:

```bash
VCS_JOURNAL_DSN=<restricted authority login to the journal database>
VCS_TENANT_ID=<volume-api tenant id>
VCS_JOURNAL_HA_POLICY_JSON=<versioned structured HA policy>
VCS_AUTHORITY_INSTANCE_ID=<manager-assigned instance identity>
VCS_MANAGER_EPOCH=... VCS_MANAGER_RUNTIME_ID=...
VCS_AUTHORITY_RUNTIME_SEQ=... VCS_AUTHORITY_RUNTIME_ID=...
VCS_AUTHORITY_RUNTIME_CAPABILITY=<per-runtime capability; only its hash is stored>
VCS_AUTH_TOKEN=<per-instance data-plane token>
VCS_ADMIN_TOKEN=<per-instance lifecycle token>
VCS_HEARTBEAT_FD=3 VCS_BOOTSTRAP_FD=4
```

There are no listener addresses in that environment: the child binds fsproto and
metrics on `127.0.0.1:0` itself and reports the exact addresses (plus its identity,
journal generation, protocol version, and canonical HA-policy hash) in one bounded
bootstrap frame on fd 4. Fd 3 carries the manager's lease frames; the child fences
itself on EOF, a malformed or foreign frame, or a lease deadline that passes without
a database-grounded extension. Readiness comes only after the HA policy is verified
against `pfj.durability_facts()`, the journal claim binds, the cold replay completes,
and the first lease deadline grounds in capability-bound `pfj.authority_lease_facts`.

Failover has no promotion protocol: a second claimant fences the first in the journal,
and recovery is a fresh child anywhere — claim, cold-replay (immutable base + journal
suffix, [history.md](./history.md)), serve. Ordinary teardown seals admission, drains
admitted appends through their durable acknowledgement, records the exact receipted
journal suspension, and exits; an unresolved suspension exits non-zero with the lease
unreleased so database-time expiry fences it.

`VCS_ALLOW_PLAINTEXT_PRODUCTION=1` (for a network-reachable self-host data plane) is
only acceptable behind an authenticated private network or tunnel such as WireGuard.
It is never the public internet default.

Local development runs a single writable VCS with a file WAL and none of those guards;
that shape is explicitly not production.

## Mounting Contract

The CLI experience is:

```bash
portablefs mount vol_123 /workspace
(cd /workspace && ls -la)
```

Underneath, that means:

- Linux hosts mount with FUSE (fusermount3/fusermount, the fuse3 package).
- macOS mounts through the FSKit extension: the CLI drives the same
  `portablefsd` + PortableFS.app extension pair the menu-bar app uses
  ([fskit-mount.md](./fskit-mount.md)).
- One transport per platform, no fallback transports: a host that cannot
  serve its platform's transport fails with guidance rather than degrading
  to a weaker consistency model.
- Docker/Podman containers normally receive a bind mount from the host.
- MicroVMs mount inside the guest.
- Kubernetes uses a CSI driver.
- Environments that cannot mount need a separately isolated runner that
  receives a short-lived mount credential; the storage/control plane never
  runs tenant commands.

The agent should never need the old attach/sync/flush local-folder workflow.

### Machine-Local Dirs (Grafts)

Several machines mount one volume concurrently (a laptop and a cloud sandbox),
but dependency trees and build caches are platform-specific and must never be
shared through the volume. Each mount client keeps a configured set of
workspace-relative directories machine-local. All clients implement one
contract:

- A graft rule owns the name but synthesizes nothing: it shadows any same-named
  volume subtree unconditionally, while the graft root itself exists exactly
  when an ordinary mkdir created it and is removable like any directory — so
  wholesale rebuilds such as `npm ci` (rm -rf node_modules, recreate) work
  unchanged.
- Renames across the graft boundary fail with EXDEV (callers fall back to
  copy+delete, exactly as across a bind mount). The root can only ever be a
  directory (EISDIR for create/symlink at the root). Volume renames of an
  ancestor directory carry the graft and its local backing along.
- Nothing under a graft is ever written to or read from the authority.

Three implementations serve the contract:

- macOS `portablefsd` grafts subtrees natively for the FSKit frontend:
  `AttachOptions.localDirs` (extendable at runtime via
  `POST /v1/attaches/{ref}/local-dirs`) serves those paths from
  `<stateDir>/local/<storageID>/` instead of the authority. The control `fs/*`
  API serves the identical grafted namespace as the FSKit frontend.
- The FUSE clients (`portablefs mount` and `cmd/mount`) implement the same
  semantics natively in `vcs/internal/localdirs`, so grafts work on Linux
  without the privileges bind mounts require. Grafted operations go straight
  to local disk on file-descriptor-backed handles: no fsproto round trips, no
  write-back flush batching, no invalidation subscriptions, and local inode
  numbers are minted in a marked range so they can never collide with volume
  inodes in the kernel dcache. Backing lives at `<stateBase>/local/<storageID>/`
  (the CLI state dir; `PORTABLEFS_LOCAL_DIRS_STATE` for raw `cmd/mount`).
- Privileged sandboxes may still bind-mount local disk over the FUSE mount;
  grafts make that unnecessary where privileges are absent.

Configuration: `portablefs mount --local-dir <rel>` (repeatable; persisted per
volume+branch+mountPath; explicit flags update the persisted set;
`--no-local-dirs` clears it and ignores the declaration), or a
`.portablefs/local-dirs` file in the volume
(one workspace-relative path per line, `#` comments) that is unioned with the
flags at mount time so a repository declares its per-machine dirs once for
every machine. Linux FUSE and macOS FSKit resolve the same union and reject a
graft of `.portablefs` or `.portablefs/local-dirs`, which would hide the
configuration source ([fskit-mount.md](./fskit-mount.md)).
Raw `cmd/mount` reads `PORTABLEFS_LOCAL_DIRS` (comma-separated).
Grafts are orthogonal to `--fast`: write-back batches volume writes while graft
writes never enter the flush path at all.

Graft backing is a security boundary, not a trusted path prefix. The daemon and
FUSE clients open the backing directory once and perform every lookup, open,
create, mkdir, remove, rename, link, symlink, readlink, metadata mutation, and
directory enumeration relative to that directory capability. Traversal is
component-wise and race resistant: safe relative symlinks within the backing
work, `readlink` preserves exact target bytes, but relative escapes, absolute
symlinks, and Linux magic links are never traversed by the server. Rename and
hard-link destination parents use the same confinement, so swapping a directory
for a symlink cannot redirect a mutation outside the backing. Metadata changes
run on an already-confined file descriptor rather than re-resolving a path.
Linux additionally requires `openat2(2)` with `RESOLVE_IN_ROOT` and
`RESOLVE_NO_MAGICLINKS` (kernel 5.6 or later) and fails the mount closed if that
primitive is unavailable or blocked. macOS uses fd-relative, component-wise
`openat(2)` traversal with `O_NOFOLLOW`. Once a file is open, normal reads,
writes, mmap, fsync, and locks stay on that descriptor, so confinement adds no
per-I/O data-path lookup or network overhead.
The repeatable audit commands and external kernel certification gates are in
[graft-security.md](./graft-security.md).

Shared source lives on the volume; per-machine artifacts live on machine-local
disk — one invariant, expressed at the same layer on every platform.

## Durability Contract

For live writes (the journal contract, [journal.md](./journal.md)):

- the authority orders the mutation;
- the canonical record bytes commit to the durable log before acknowledgement —
  the fenced remote journal in production, the local file WAL in development;
- reads from connected clients observe authority-ordered state;
- history (cuts, snapshots, forks — [history.md](./history.md)) is asynchronous
  and can never change the meaning of an acknowledged write.

For history materialization:

- dirty content is uploaded as content-addressed blobs/chunks;
- metadata advances the branch head atomically;
- snapshots and forks reference immutable committed states;
- garbage collection can sweep unreferenced objects after the grace window.

## What Not To Build

- Do not reintroduce local-folder sync as an agent runtime.
- Do not put S3/Railway Buckets directly in the syscall write acknowledgement path.
- Do not make active-active multi-master the default for one live volume.
- Do not make users think about checkpoints for ordinary agent runs.
- Do not make NFS the production path for agent coherence.
- Do not silently merge two agents' writes to the same file.

## Verification Contract

The baseline local gate is:

```bash
pnpm verify
```

It checks install/lockfile consistency, TypeScript builds/tests, Go VCS tests, Go vet,
the VCS race suite, the surviving manifest-index benchmark, and stale legacy references.

The local Postgres integration gate is:

```bash
pnpm verify:postgres
```

The real Railway Bucket gate remains credential-gated:

```bash
pnpm test:railway-bucket
```
