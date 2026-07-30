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

2. **The custom mount protocol is the only data plane.**
   Linux FUSE, macOS FSKit, and container bind mounts terminate in the same custom
   protocol (fsproto v7) today; the Kubernetes CSI surface is a planned addition that
   will terminate there too (not yet packaged here).

3. **One active volume has one logical authority.**
   A single ordered authority decides the current filesystem state for a mounted active
   volume. This keeps rename ordering, directory mutation, file locking, SQLite journaling,
   and Git behavior understandable.

4. **One logical authority must not mean one fragile process.**
   Authority-lane writes and completed filesystem durability barriers must be stored in a
   replicated durable log before acknowledgement. The VCS satisfies this contract with the
   remote journal: authority-lane mutations commit to a fenced, synchronously replicated
   PostgreSQL journal ([journal.md](./journal.md)) before reply. Delegated `write(2)` calls
   are accepted into the mount WAL first; `fsync` drains them into the replicated journal.
   The authority process is a disposable cache over that truth — a replacement claims the
   journal and cold-replays.

5. **Object storage is not the synchronous write path.**
   Railway Buckets/S3 hold checkpointed content, cold data, snapshots, forks, and long-term
   durable history. Normal file writes are accepted into the live filesystem layer, then
   checkpoint in the background.

6. **Shared writing uses filesystem semantics, not magical merge.**
   Two agents can read the same files. Writes are ordered by the authority. When performance
   or safety requires exclusive ownership of a file or subtree, use delegations/checkouts.
   Same-file concurrent edits are handled like a normal filesystem: locks, atomic rename,
   last writer wins where the application chooses that pattern, or clear write errors.

7. **Fail closed in production.**
   `VCS_PRODUCTION=1` requires the remote journal and refuses every removed
   local-durability shape by name: operator listener addresses and unauthenticated data
   or lifecycle planes (per-instance `VCS_AUTH_TOKEN` + `VCS_ADMIN_TOKEN`, even on
   loopback). The child refuses to serve until the journal database's durability
   evidence satisfies the structured HA policy.

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

The mount layer ships FUSE (Linux) and FSKit (macOS) today, plus host bind mounts
for containers; the Kubernetes CSI driver shown in the transport row is planned and
not yet packaged in this repository.

The stable volume endpoint is resolved by the PortableFS authority manager. Product
workers call the manager for `ensure`, `session`, `health`, and `stop`; the manager owns
the registry that maps a volume branch to the live VCS authority. The manager also owns
a single public TCP router (TLS in either declared TLS mode). The router selects a loopback VCS backend by the mount
session token and then forwards the custom filesystem protocol. Product workers and
agent sandboxes see only the stable router address; they never see per-volume loopback
ports or launch VCS processes themselves. This keeps PortableFS, rather than each
product, responsible for authority provisioning wherever the manager runs.

Each access lease binds that endpoint to exactly one transport contract:
private-CA TLS (strict CA PEM, SHA-256, exact server name), system-PKI TLS
(exact server name), or explicitly authorized plaintext. Mount clients do not
probe for trust material, reuse profile CA state, infer plaintext from an
empty CA, or fall back between modes.
The manager canonicalizes every public endpoint through one bracketed-IPv6-safe
host/port parser and, before publishing a TLS listener, proves the serving
leaf/key/name/chain. Private-CA mode also performs an actual local TLS 1.3
handshake against the lease CA; system-PKI performs it against the manager
runtime's default roots. The latter cannot prove future remote client
root-store refresh, so deployment readiness retains an end-to-end dial across
the supported platform matrix.

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

Local development runs the same managed shape through quickstart (manager +
PostgreSQL in Docker); the file WAL survives only as the mount's write-back
stream log and the bench/test entry-log backend, never as an authority's
production truth.

## Mounting Contract

The CLI experience is:

```bash
portablefs mount vol_123 /workspace
(cd /workspace && ls -la)
```

Underneath, that means:

- Linux hosts mount with FUSE. One uncached host-facts observation selects
  exactly one mount mechanism before any mount side effect: direct `mount(2)`
  when the process has positive `CAP_SYS_ADMIN` evidence, otherwise one exact,
  root-managed `fusermount3`/`fusermount` helper. The selected mechanism and
  helper path are persisted and revalidated at the mount and unmount
  boundaries. Failure is final for that operation; the client never switches
  mechanisms after an attempted mount.
- macOS mounts through the FSKit extension: the CLI drives the same
  `portablefsd` + PortableFS.app extension pair the menu-bar app uses
  ([fskit-mount.md](./fskit-mount.md)).
- One transport per platform, no fallback transports: a host that cannot
  serve its platform's transport fails with guidance rather than degrading
  to a weaker consistency model.
- Docker/Podman containers normally receive a bind mount from the host.
- MicroVMs mount inside the guest.
- Kubernetes is a planned surface: a CSI driver that terminates in the same
  custom protocol. It is not yet packaged in this repository.
- Environments that cannot mount need a separately isolated runner that
  receives a short-lived mount credential; the storage/control plane never
  runs tenant commands.

The agent should never need the old attach/sync/flush local-folder workflow.

Transport selection is a pure platform decision (`fskit` on macOS, `fuse` on
Linux). A separate uncached host-facts check reports only evidence available
without mutating the machine. In particular, macOS exposes no reliable public
query for whether a third-party FSKit extension is enabled, and Linux
capabilities cannot predict seccomp, LSM, device-cgroup, or namespace policy.
Those cases remain **unverified**. Only a real mount with an exact kernel
identity and a successful root operation verifies that the transport works.
`doctor` reports this uncertainty rather than converting inventory hints into
enablement claims.

### Local Lifecycle And Installation

Operational state has one fixed per-account root:
`~/.local/state/portablefs`, where `~` is resolved from the effective user's
account record rather than `HOME` or XDG environment overrides. Mount records
bind the canonical mount path to the transport, kernel filesystem/source,
process start identity, and (for FSKit) exact attach reference. Unmount refuses
an unrelated filesystem or recycled PID; Linux signals a recorded mount
process through a pidfd, while FSKit teardown is driven by the exact kernel
mount and daemon attach instead of PID signaling.

An effective UID without an account-database entry is a configuration error;
containers must provision a real account identity instead of deriving one from
mutable environment or temporary storage. Private state and coordination paths
are opened component-by-component without following symlinks and are pinned by
directory descriptors across sensitive operations.

Two stable, private per-user locks express the cross-process invariants:

- mount and app lifetimes hold the mount-lifecycle lock shared; an installer
  must hold it exclusive before rechecking kernel mounts, daemon state, and
  processes and publishing a replacement;
- mount lifetimes hold the account-session lock shared; credential or active
  profile mutation must hold it exclusive, so account identity cannot change
  underneath a mount.

Both locks are fixed inodes under the canonical state root. Unsafe ownership,
permissions, links, replacement, or contention is a visible refusal; runtime
code never repairs or relocates them.

Linux releases store each verified `portablefs`/`portablefsd` pair together in
a content-addressed per-user directory and atomically switch one CLI activation
link. macOS releases one signed and notarized `PortableFS.app` containing the
matching CLI, daemon, and FSKit extension; the installer atomically publishes
that bundle under `~/Applications` and links its embedded CLI. Neither
platform replaces a live mount/runtime, publishes half of a CLI/daemon pair,
or falls back to a system-wide installation.

### Write Path

Write mode is not a mount property. Every mount runs one adaptive write-back
engine per (volume, branch) ([writeback-engine.md](./writeback-engine.md)):
the authority delegates an uncontended subtree on first write, mutations
under a held scope are accepted into a segmented mount WAL and local overlay,
then flushed as dense batches whose watermark and stream digest commit
atomically with the tree state. Plain `write(2)` may return before the local
group-sync; `fsync` forces it. Peer operations that overlap a delegation wait
for recall — a reader is never answered from stale pre-delegation state.
Contended scopes execute write-through and re-delegate once contention
clears. `fsync`/`synchronize`/clean unmount always mean durable at the
authority. A verified fsynced or group-synced tail can be replayed exactly on
the next attach; ambiguous or corrupt state blocks instead of being repaired.

Any local WAL persistence failure seals the mount mutation gate until remount.
It never causes a silent switch to write-through, and a terminal
fence/conflict does not leave unrelated scopes mutating through another lane.
One OS account may have at most one live local mount of a given
`(volume, branch)`, so one machine never creates competing owners for the same
write-back store. Other machines may mount that branch concurrently; authority
delegation and recall are the cross-machine coherence boundary.

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
- The Linux FUSE frontend (`portablefs mount`) implements the same
  semantics natively in `vcs/internal/localdirs`, so grafts work on Linux
  without the privileges bind mounts require. Grafted operations go straight
  to local disk on file-descriptor-backed handles: no fsproto round trips, no
  write-back flush batching, no invalidation subscriptions, and local inode
  numbers are minted in a marked range so they can never collide with volume
  inodes in the kernel dcache. Backing lives at `<stateBase>/local/<storageID>/`
  (the CLI state dir).
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
Grafts are orthogonal to the write-back engine: delegated write-back batches
volume writes while graft writes never enter the flush path at all.

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
- the canonical record bytes commit to the fenced remote journal before
  acknowledgement;
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

The real S3 bucket gate remains credential-gated:

```bash
pnpm test:s3-bucket
```
