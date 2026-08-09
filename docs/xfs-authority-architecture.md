# PortableFS authoritative-XFS architecture

Status: **v3 architecture decision and implementation contract**

PortableFS v3 is a remote gateway to ordinary, authoritative directories on
XFS. XFS and the block device beneath it are the only durable filesystem
state. PortableFS does not maintain a second inode tree, content index,
permanent operation history, branch graph, or write-back overlay.

This was a deliberate compatibility reset. The v2 journal architecture and its
journal control plane were removed rather than deprecated, and the protocol handshake
refuses anything that does not speak the v3 contract rather than entering a
mixed mode. See [../COMPATIBILITY.md](../COMPATIBILITY.md).

## Root design

```text
Linux FUSE mount        macOS FSKit mount            another mount
       |                       |                    |
       +---------- authenticated TLS RPC ----------+
                               |
                     volume routing endpoint
                               |
                    one active authority epoch
                               |
                descriptor-relative Linux syscalls
                               |
                   /srv/portablefs/<volume-id>
                       XFS project directory
                               |
                    encrypted SSD / AWS EBS
```

The data plane has one active authority for a volume. Many volumes may share a
storage cell, but every request is bound to exactly one volume capability and
one authority epoch. Clients never mount or attach the block device.

The control plane stores identity, organization membership, volume placement,
policy, quota entitlements, billing metadata, and short-lived credentials. It
does not store file bytes, inode metadata, directory entries, locks, or the
current filesystem tree and is not on the per-operation data path.

The macOS frontend is not a second data plane. `portablefsd` owns the same v3
authority client used by the Linux architecture: mutual TLS, access capability,
authority epoch, replay slots, keepalive, route revision, visibility polling,
fencing, and evidence-bearing detach. The FSKit extension receives only a
versioned, ordered local stream describing the already-authenticated session and
its cache obligations, and returns exact cursor acknowledgements. Authority TLS
credentials and replay secrets never cross the local frontend socket.

macOS 27 is the primary FSKit target because it is the first SDK line with
module-initiated synchronous kernel data-cache control. That API is still beta
as of August 2026 and its documented contract does not separately promise
negative-name invalidation. Release therefore remains gated on the final SDK and
the live namespace/data/attribute matrix; an OS version number is not accepted
as proof. Nothing in this tree implements it, and the policy string that would
select it fails closed.

What ships on macOS today is an explicitly declared compatibility cache policy,
`macos26-synchronous-vfs-repair-v2`, implementing the same local visibility
interface through synthetic VFS repair. It is selected by name, validated on both
sides, and refused if it does not match — never an automatic fallback, never a
silent downgrade — and it does not change the authority, filesystem, or session
architecture. It is composed and wired end to end: both client indexes, a real
publication barrier, an installed repair gate, identity-aware callback-serialized
authority ordering, and direct source, attribute, and data repair under exact
provenance. Attribute refresh uses an authenticated no-op `fchmod` on the exact
file or directory vnode; symlinks fail closed. Targeted attribute/data repair is
live-proven. Four exactly characterised callback-coalescing limits and the open
full breadth/fault matrix are recorded in
[macos-26-coherence-contract.md](./macos-26-coherence-contract.md); none is
elided here.

## Source of truth

For a live volume, the source of truth is exactly the mounted XFS instance:
its server-side VFS/page-cache state, metadata journal, and persisted device
state. Unflushed page-cache data is authoritative current state but is not
durable across power loss; `fsync` is the boundary that asks XFS and the device
to persist it.

Filesystem authority state is disposable: connections, open file descriptors,
advisory locks, cancellation state, and bounded reply slots for the current
epoch. Losing that RAM interrupts mounts, but cannot roll the durable
filesystem back to a different logical tree. One small control-plane exception
is durable strict-mount membership. It records only which cached kernel mounts a
previous epoch admitted, so a *new* epoch refuses to serve until each of them is
proven absent or externally fenced. It is not a live write gate: inside a running
epoch a lost participant is fenced individually and mutations continue (see
[Cache coherence](#cache-coherence)). It contains no paths, inodes, file bytes,
mutations, or history and is bound to exactly one volume.

There is no PortableFS checkpoint, manifest head, custom mutation log,
segmented store, Pebble index, or garbage collector. EBS snapshots are
operator backups and never participate in reads, writes, cache coherence, or
the user-visible namespace.

## Ordinary filesystem semantics

The authority translates one RPC into the corresponding Linux operation. XFS
supplies inode allocation, directory structure, hard links, symlinks, sparse
files, timestamps, atomic rename, allocation accounting, metadata
journaling, and crash replay. Its journal is an internal crash-recovery
mechanism, not PortableFS history; see the
[kernel XFS logging design](https://docs.kernel.org/5.17/filesystems/xfs-delayed-logging-design.html).

PortableFS preserves these boundaries:

- A successful `write` means server `pwrite`/`write` accepted the reported
  bytes into authoritative XFS state. No acknowledged bytes exist only in an
  unsent client cache.
- A successful `fsync` means the authority successfully completed `fsync(2)`
  or `fdatasync(2)` on the authoritative open file description, with the normal
  [Linux durability contract](https://man7.org/linux/man-pages/man2/fsync.2.html).
- `close` is not an implicit `fsync`.
- On the current regular-FUSE Linux interface, `syncfs(2)` does not issue a
  userspace `FUSE_SYNCFS` request (the kernel currently enables that request
  only for `fuseblk`). Applications must use file and directory `fsync` for a
  remote durability boundary. PortableFS does not pretend the local-only
  `syncfs` completion flushed XFS on the authority; this follows the
  [current kernel implementation](https://github.com/torvalds/linux/blob/master/fs/fuse/inode.c#L721-L759).
- A namespace operation is atomically visible when the XFS syscall completes.
  An application that needs it durable across power loss syncs the changed
  file and affected parent directory or directories, as on local Linux.
- An open descriptor remains usable after unlink until final close. The
  authority retains the real server descriptor; there is no orphan table.
- Two whole-file replacements are ordered atomic renames. The later ordered
  rename is visible. PortableFS does not merge file contents.
- POSIX record locks and BSD `flock` locks are authority-epoch runtime state.
  `FLUSH` removes a closing process owner's POSIX locks, final `RELEASE`
  removes an open-description flock, and session expiry/restart removes every
  remaining lock. The two lock namespaces remain independent, as on local
  Linux.

The server is the only supported writer to a volume tree. Operators, sidecars,
and backup agents must not mutate it behind the authority because those writes
cannot participate in authorization or cache coherence.

## Object identity and confinement

Requests are object-relative, not path-relative. Attach returns an opaque root
token. Lookup accepts a parent token and one raw filename component. Later
operations use object or open-handle tokens.

The Linux frontend owns the FUSE `NodeID` table and kernel lookup reference
counts directly. A successful authority lookup returns a fresh object
capability. Under one frontend mutex, the client either installs it as a new
`NodeID`, or increments the already-known inode's lookup count and reclaims the
duplicate capability. `FORGET` decrements that same table and queues the exact
capability for reclamation only when the final lookup reference disappears.
This avoids both an O_PATH descriptor leak and a stale-token race during
concurrent lookup/forget; it is why v3 uses the raw FUSE interface instead of a
high-level inode wrapper that can discard a candidate only after the callback
returns. A full bounded reclaim queue is a fatal mount/session condition, never
permission to drop ownership records.

The authority:

- opens the volume root once and treats its descriptor as the capability root;
- rejects empty names, NUL, `/`, `.`, `..`, and components over `NAME_MAX`;
- uses `openat2` with `RESOLVE_BENEATH`, `RESOLVE_NO_MAGICLINKS`, and
  `RESOLVE_NO_XDEV`, plus `O_NOFOLLOW` when addressing a symlink itself;
- uses descriptor-relative `*at` syscalls for namespace changes;
- verifies every object is on the expected device;
- never accepts a host path or client-supplied inode number;
- binds each token to volume ID, epoch, kind, and a random server table entry;
- rejects cross-volume link and rename by construction; and
- invalidates all tokens on epoch change.

Symlink contents are stored and returned exactly, including absolute or
escaping targets. The mounting kernel performs normal symlink traversal; the
authority never follows client-controlled symlinks while addressing XFS.

Only regular files, directories, and symlinks may be created. Device nodes,
FIFOs, sockets, setuid execution, user-xattr writes, privileged xattrs,
cross-filesystem mount traversal, and exported kernel handles are denied.
Storage is mounted `nodev,nosuid,noexec,noatime`; encryption at rest and in
transit is mandatory. `noatime` is a coherence invariant, not merely a tuning
flag: ordinary reads must remain read-only at the authority instead of becoming
hidden attribute mutations that would require the distributed write barrier.
Applications may still set timestamps explicitly through ordinary filesystem
operations.

## Ordering and retry semantics

Linux VFS/XFS provides each syscall's atomicity. The authority adds only:

1. validate the TLS peer, volume access claim, session, epoch, capability, and
   operation identity;
2. execute the descriptor-relative XFS operation;
3. retain the bounded exact reply in that session's replay slot; and
4. return the result.

Different replay slots may execute concurrently. XFS supplies the same
operation atomicity and locking it supplies to local processes; PortableFS does
not serialize an entire volume behind a userspace global mutex.

When at least one strict cached frontend is attached, cache-visible mutations
are the deliberate exception: one volume-wide visibility ticket orders
PREPARE, the XFS syscall, and COMPLETE. This serialization exists only to close
and repair kernel publication gates. With no strict participants, it is absent
and ordinary XFS concurrency remains unchanged.

There is no honest way to atomically commit an arbitrary XFS syscall and a
separate durable reply record. PortableFS makes the boundary explicit:

- Duplicate delivery inside a live epoch returns the cached outcome and never
  re-executes the operation.
- A client never automatically replays an uncertain mutation across an epoch.
- If an authority dies after XFS applies a mutation but before its reply is
  received, that request has an `UNCERTAIN` transport outcome and the mount is
  re-established. The application may inspect current state and decide.
- Side-effect-free calls may reconnect and retry only inside the same authority
  epoch. No request—read or mutation—is silently continued across an epoch.
  Mutations use exact same-epoch replay slots; append and namespace outcomes are
  never guessed.

This gives session-exact execution without inventing a second durable truth.
Transparent exactly-once semantics across server death are not claimed.

## Cache coherence

The exact Linux baseline has no distributed cache protocol. Regular files open
with FUSE direct I/O, attributes and positive/negative dentries have zero TTL,
and write-back caching is disabled. Every completed read and write therefore
crosses the authority; there is no stale client page that an asynchronous
notification must race.

Shared file-backed `mmap` is deliberately unsupported in this baseline.
PortableFS does not advertise `FUSE_DIRECT_IO_ALLOW_MMAP`, so Linux rejects
both writable and read-only `MAP_SHARED` mappings instead of creating mapped
pages that the authority cannot revoke coherently. `MAP_PRIVATE` remains
available: it is a process-local copy-on-write view, never writes through to
the underlying file, and POSIX leaves visibility of later external file changes
unspecified. That is ordinary filesystem behavior rather than a distributed
coherence promise. This follows the kernel's documented [distinction between
FUSE cached, direct, and write-back modes](https://cdn.kernel.org/doc/html/latest/filesystems/fuse/fuse-io.html)
and the [`MAP_PRIVATE` contract](https://man7.org/linux/man-pages/man2/mmap.2.html).

SQLite rollback-journal mode is part of the tested Linux compatibility
contract. SQLite WAL mode is not: its wal-index requires a shared `-shm`
mapping, and SQLite itself requires every WAL participant to be on the same
host. Presenting WAL as safe across PortableFS mounts on different machines
would be a false guarantee, not ordinary shared-filesystem behavior. Workloads
that require SQLite WAL must keep that database local or use a database service.
See SQLite's [WAL limitations](https://www.sqlite.org/wal.html) and
[rollback-locking protocol](https://www.sqlite.org/lockingv3.html).

This is intentionally less complex and may be slower over a high-RTT network.
Read caching is a future measured optimization, not hidden baseline behavior.
If measurements or application compatibility require caching or shared
file-backed mapping, the only acceptable extension is a synchronous lease protocol: a
writer waits until every live holder has flushed any authorized dirty mapping
and completed kernel invalidation, or an external proof fences the exact kernel
mount/host, before changing XFS. Lease expiry alone is not fencing. An
asynchronous event stream by itself is insufficient because a peer
could read stale pages before processing the event. Ordinary client dirty
write-back remains out of scope.

Apple's June 2026 FSKit beta adds `DataCacheHandler`, `noCache`, synchronous
cache-state changes, invalidate, and revoke. The locally installed Xcode 26.6 /
macOS 26.5 SDK does not contain those APIs. macOS 27 support therefore remains
gated on the final SDK/OS plus direct tests for data, attributes, positive and
negative dentries, rename, unlink, writable mappings, and failed revocation. The
macOS 27 path never falls back to synthetic VFS repair, and the macOS 26 declared
policy never claims to be it: they are two named policies, each validated
exactly, and a mount that asks for one and is offered the other fails closed.
The platform gate is tracked against Apple's
[FSKit updates](https://developer.apple.com/documentation/updates/fskit) and
[`DataCacheHandler`](https://developer.apple.com/documentation/fskit/fsvolume/datacachehandler),
not inferred from asynchronous notifications.

The implemented strict protocol is fail-closed: every cached participant gets
PREPARE before XFS apply; peers repair and acknowledge COMPLETE before the
mutation reply; the initiating mount receives a deferred COMPLETE and must
acknowledge its ordinary FSKit callback publication before the next mutation.
Visibility polling and acknowledgements use a reserved client lane so the event
stream cannot consume the last ordinary request slot.

Failure has two scopes and the implementation never mixes them
(`vcs/internal/volumeserver/visibility.go`).

**A lost participant is fenced individually.** A broken session, a missed repair
budget, or a cursor violation removes exactly that mount from admission to later
barriers and ends its authority session immediately through the `SessionFencer`.
The obligation already held by the running mutation is retained for one full
additional declared repair-budget grace, then discharged. That grace is
load-bearing only when the frontend can prove that its old kernel cache became
unservable before the grace ends. Linux does this by revoking published FUSE
bindings and aborting the connection, after which every request on that mount
fails `ENOTCONN`. macOS 26 uses an identity-checked `MNT_FORCE` watchdog. Live
testing with cached bytes on a held descriptor proved that after daemon death
the watchdog force-unmounted at about 10 seconds and every later `pread` failed
`EIO`, inside the fencing grace. A kernel that refuses forced unmount past the
grace remains the explicit residual. A phase that first consumes its ordinary
deadline therefore costs at most two budgets rather than an unbounded volume
outage, and later requests on the fenced mount must fail.

Linux parent-exclusive repair breaks its one closed lock cycle without losing
the mount. COMPLETE atomically closes admission only for parents with exact
cached-name work. If a callback was admitted first, the frontend reports the
exact parent coordination inode; the authority maps it through that pending
event and returns definite-preapply `EINTR` only to an overlapping request. The
callback releases `i_rwsem`, reverse invalidation completes, and the same mount
acknowledges COMPLETE. A callback arriving after the gate is refused locally
before an authority request. The interruption remains active through Ack, and
stale or response-lost control replays cannot affect a later cursor.

A routing change is different: releasing one parent lock cannot make a fixed
mount topology adopt a new declaration. Its blocked report is therefore still
terminal and revokes that participant immediately. Current production frontends revoke during route PREPARE and are fenced before
the durable commit; a later commit failure does not resurrect them. The
coordinator still sends the truthful reported active revision in COMPLETE to any
future frontend that explicitly staged and ACKed PREPARE without leaving, but
that path is not evidence that today's FUSE or FSKit mount survived. A definite
pre-publication failure reports the old revision with `Applied=false`; a
post-rename durability-uncertain failure reports the next revision with
`Applied=true`. Fresh attaches use that reported active revision. The ordinary phase deadline remains the hard
bound for every repair that does not drain.

**Poison is reserved for authority-internal invariant violations** — a completion
naming a coordinate PREPARE did not, a participant found holding two outstanding
events. Those are defects no mount can cause. Poison is permanent for the epoch
and recovery needs a new epoch.

Durable membership is deliberately *not* cleared by fencing. Only a
session-bound mount-absence proof accepted by the configured
`MountAbsenceVerifier` (`CleanDetach`) deactivates a record; a syntactically
plausible client blob and a deployment with no verifier both fail closed. So a fenced mount is
gone from this epoch's barrier while still recorded, and a replacement authority
refuses to serve until an external fencing proof covers every recorded old kernel
mount. Availability is preserved inside an epoch and paid for across one.

The macOS 26 Swift implementation is composed into the production FSKit volume:
the operations adapter maintains the namespace and live-object indexes, the
publication barrier closes and reopens callback admission, and the repair gate is
installed at resolve time so that a composition failure fails the mount rather
than serving without coherence. Its identity-aware callback-serialized authority
profile, direct exact-source removal, scratch repair, same-vnode attribute
refresh, and held-vnode truncate carry unforgeable event-scoped provenance. The
attribute path uses a no-op `fchmod` only after exact path, stable-item, kind, and
projected-VFS-inode checks; the gate coalesces exact-item mode-only callbacks
during the bounded actuator window and the adapter returns full authority
attributes without emitting an authority
mutation. Symlinks fail closed. Distinct repair locators are retained only after
data invalidation, while authority still owns the exact pathname, and are
invalidated at the next COMPLETE namespace target before planning. Positive
eviction always forgets its old attested item/coordinate pair, including the
already-absent path that emits no removal callback. Sequential actuation binds
nameless attribute callbacks to one active hard-link plan rather than relying on
pre-armed dictionary order. An unpathable object remains unsupported unless a
later COMPLETE namespace target carries an authority-attested post-binding identity
that can be matched to the retained mount-local vnode and inode projection. Four exact
callback-coalescing limits, including a same-vnode mode-only setattr during
armed attribute refresh, are declared. This
is a bounded compatibility policy, not exact native equivalence, and it is never
selected as a fallback. The complete contract and final live acceptance evidence
are in [macos-26-coherence-contract.md](./macos-26-coherence-contract.md).

## Machine-local routing

`.portablefs/local-dirs` is protected volume-wide configuration, not an
ordinary mount-writable file. Only admin `ApplyRoutes` may replace it. The
authority canonicalizes the declaration, compare-and-swaps its revision under
the topology writer, and pins that revision from request admission through XFS
completion; an attach or existing session on another revision fails closed.
Linux graft operations stay behind a confined machine-local directory
capability and do not reach the authority data plane.

Route activation also reads the root repository's shared `.git/index` through
the confined XFS API and refuses a rule that already covers tracked content.
Index versions 2 and 3 in SHA-1 or SHA-256 repositories are accepted only with
an exact checksum and no split/sparse/unknown extension; unreadable, malformed,
oversized, linked, or unsupported indexes are an unproven result and refuse the
whole route change. This check runs in both the frontend and the authority, so a
direct admin RPC cannot bypass it.

That Git check is deliberately activation-time, not a transactional lifetime
invariant. Git may later atomically replace `.git/index` through the shared
filesystem after routes are active. Preventing a later `git add` from tracking
a machine-local path requires an explicit Git-index transaction/interposition
contract; the authority does not infer one by inspecting transient
`.git/index.lock` writes. Operators should treat tracked paths as ineligible for
machine-local routing and re-run `ApplyRoutes` (or restart validation) after
changing that boundary.

## Multi-tenancy and quotas

Each volume is an XFS project directory with `PROJINHERIT`. Project block and
inode quotas come from the customer's entitlement. PortableFS has no universal
one-GiB memory or volume limit. Cell admission follows measured SSD capacity,
IOPS, throughput, memory, descriptors, and recovery SLO.

Short-lived capability claims include subject, volume, read/write access,
credential validity, peer-certificate identity, and a nonce. Hosted grants also
pin cell, authority identity and generation, and contain the product's separate
authorization assertion. Authorization precedes handle resolution. Keepalive
cannot extend a signed authorization deadline. Per-tenant concurrency and I/O scheduling
protect unrelated volumes; quota errors remain the kernel's `EDQUOT`/`ENOSPC`
outcomes.

An initial grant's absolute deadline is still the standalone behavior. The
hosted lifecycle implements the additive v3 control-plane contract:
the mount creates its TLS key locally, the control plane validates proof of
possession and returns a short-lived client certificate plus a single-use
Ed25519 grant bound to the leaf SPKI, and the authority verifies both end to
end. The client private key never leaves the machine and the FSKit extension
never receives it. Ambiguous grant creation returns one durable byte-identical
receipt. A lost initial Attach still requires the product to request another
short-lived grant; no client may reuse a spent capability.

Long-lived mounts renew authorization inside the existing session with a fresh
grant bound to the volume, authority generation, session, peer SPKI, access,
monotone authorization sequence, and new deadline. Reauthorization is an exact
replay operation on a reserved lifecycle lane; it may extend the deadline and
renew the same-key client certificate but cannot broaden access. Keepalive
remains only a liveness proof. A changed replay or sequence gap fences the
session.

`portablefs-manager`, the outbound cell agent, the narrow root helper, and the
systemd units implementing that lifecycle now live in this tree. Standalone
operators may continue minting direct credentials out of band. The hosted trust
boundaries, lifecycle, API, and explicit single-manager/single-AZ limits are in
[hosted-control-plane.md](./hosted-control-plane.md).

The unprivileged request process verifies the root's project ID and
`PROJINHERIT` flag but deliberately has no quota-administration capability.
Privileged provisioning and monitoring attest each project's block/inode hard
limits; XFS enforces them. `statfs` retains the ordinary local-XFS meaning of
cell-wide physical capacity, while quota/billing APIs report the purchased
per-volume entitlement. Granting the authority `CAP_SYS_ADMIN` merely to query
quota records would weaken the tenant boundary.

XFS attribute-fork blocks are
[not charged to project quotas](https://www.kernel.org/pub/linux/utils/fs/xfs/docs/xfs_filesystem_structure.pdf).
Project quotas therefore cannot isolate user-xattr writes on a shared cell, and
a PortableFS counter could not commit atomically with XFS. Launch does not
expose `setxattr`: the Linux frontend and direct authority requests return
`EOPNOTSUPP`. Because authority protocol v3 makes `user-xattr-readonly` an exact
Attach requirement, Linux rejects valid set modes locally without spending an
RPC, replay sequence, or visibility transition. Read, list, and removal remain
available for pre-existing portable `user.*` attributes. Writable xattrs
require a future substrate with one kernel-enforced aggregate capacity boundary;
they are not enabled by a per-inode limit or an in-memory counter.

On macOS, resolve advertises the xattr family and independently declares xattr
set unsupported. FSKit validates item/name/mode and refuses
set/create/replace/upsert locally before emitting a daemon or ordered-mutation
frame. Its internal refusal is `ENOTSUP` (45), but the FSKit xattr boundary
exposes `EOPNOTSUPP` (102). XNU reserves 45 to request its AppleDouble `._*`
fallback; returning 102 keeps XFS as the only durable truth. This local gate
changes no successful daemon-forwarded read/list or pre-existing removal.

The initial volume model is deliberately single-principal, like an agent's
private workspace rather than a multi-user Unix server. Every XFS inode must be
owned by the volume worker's stable, unprivileged service UID/GID. Each mount
projects that principal to its local mounting user; a request to chown to a
different principal fails `EPERM`. Modes, sticky/set-ID bits, timestamps, and
pre-existing portable user xattrs remain XFS state. Supporting multiple
independent POSIX principals inside one volume would require an explicit
portable identity-mapping design and is not silently approximated with host
IDs.

Every worker also has explicit deployment-sized bounds for live sessions,
same-epoch replay slots, held/waiting lock records, in-flight requests, frame
allocations, descriptors, tasks, and process memory. These are denial-of-service
admission controls, not universal volume-size or product-memory limits. Because
launch isolates one worker per volume, exhausting them can fail that volume but
cannot consume another tenant's worker state.

The request-serving process refuses to run as root. Provisioning assigns the
project directory to its stable service UID/GID before startup. Production
runs it in a private mount/user namespace with a syscall allowlist and access
only to that volume root. Volume roots are not exposed to agent containers or
sandboxes.

## Launch topology and failure model

Launch uses one Nitro EC2 instance and one encrypted, non-Multi-Attach EBS
volume formatted XFS. The EBS volume outlives the instance
(`DeleteOnTermination=false`). Same-AZ instance replacement is: fence the old
process, detach, attach, mount/replay XFS, increment epoch, accept clients.

This is single-AZ durable storage, not cross-AZ HA. EBS replicates within one
AZ. SLOs must use those facts rather than call one volume a replica set.

Optional active-passive HA is a separate topology, never another write path. It
requires independent fencing, one-writer enforcement, epoch advancement, and
destructive split-brain tests:

- Same-AZ compute HA may use Multi-Attach io2, NVMe reservations, and external
  STONITH, with XFS mounted read-write on exactly one host.
- Cross-AZ HA needs two devices plus synchronous replication, quorum, and
  fencing, or a separately validated managed multi-AZ filesystem.

Heartbeats, DNS, and leases do not fence an old writer. Force-detach is an
emergency action, not a promotion protocol.

After restart/failover, sessions, locks, tokens, and open handles are
stale. Unlinked-but-open files cannot be recovered after their last server fd
is lost; affected applications receive `ESTALE`/`EIO`.

Any storage `EIO` permanently fences the active store and terminates that
authority epoch. It never remains ready and attempts more mutations against a
possibly shut-down or detached filesystem.

## Backups

Backups protect against deletion, bugs, compromised credentials, and operator
error that a live replica would faithfully copy. They are outside filesystem
semantics. The backup controller freezes or syncs XFS, takes an
application-consistent EBS snapshot, unfreezes promptly, locks/copies it per DR
policy, and exercises restores. Users see no snapshot, commit, branch, or
historical namespace.

## Deliberate boundaries

- One volume has one active server and one machine's throughput ceiling.
- Cross-region syscall latency is not hidden; place authority near clients.
- Memory scales with active sessions, handles, locks, and bounded retry
  slots—not stored files or keys.
- Unsupported FUSE/FSKit operations fail explicitly; they are not emulated with
  divergent semantics.

Scale comes from placing volumes across cells and moving hot volumes to a
dedicated cell. A measured need for one volume to exceed one cell is a decision
to adopt a distributed filesystem, not to grow a custom inode database here.

## Proof required before production

The list is kept as a ledger rather than a wish: an item moves only when
something in the tree establishes it, and partial progress is stated as partial.

**Established.**

1. **Linux coherence on a real kernel.** `scripts/xfs-fuse-integration.sh` builds
   a disposable project-quota XFS filesystem in a privileged container, runs the
   production provisioning script against it, and executes 43 required tests
   against real kernel FUSE mounts as an unprivileged service account.
   `scripts/coherence-matrix-linux.sh` then drives 23 black-box cases across two
   real mounts in both `strict` and `uncached` profiles, bracketed by two
   falsifiability controls — a disjoint-namespace phase and a stale-view phase —
   that must turn the mountpoint-dependent cases red or the run fails. Data,
   attributes, positive and negative names, rename-over, unlink,
   open-after-unlink, hard links, symlinks, concurrent writers, routing
   revisions, and peer loss are all in that matrix.
2. **Rejection of unsupported mappings.** Shared file-backed `mmap` and user-xattr
   writes are refused rather than served, and the refusal is in the privileged
   suite.
3. **Confinement.** `openat2` with `RESOLVE_BENEATH`/`RESOLVE_NO_MAGICLINKS`/
   `RESOLVE_NO_XDEV`, descriptor-relative `*at` syscalls, device verification,
   cross-volume rejection by construction, and a machine-local backing boundary
   that fails closed when `openat2` is unavailable. Fuzzing breadth is still
   thinner than this item eventually wants.
4. **Storage-failure fencing.** Corruption and shutdown errnos — `EIO`,
   `EUCLEAN`, `ESHUTDOWN`, `ENOTRECOVERABLE` — fence the volume and carry the
   storage failure class rather than being reported as ordinary errors.
5. **A mount-absence verification hook.** `portablefs-authority` accepts a
   verification command that corroborates a strict mount's kernel-absence claim,
   and clean detach fails closed when no command is configured. The frontend
   produces evidence-bearing detach to feed it.
6. **Targeted macOS 26 attribute and data repair.** A real macOS 26.5 FSKit
   mount and Linux FUSE peer against the XFS authority converged through a
   `0755 -> 0700 -> 0755` mode cycle. Two hundred recursive `.git` traversals
   during rapid Linux mode toggles reported zero mismatches and the mount stayed
   healthy; 100 rapid data cycles reported zero size or content-hash mismatches.
7. **Final macOS 26 breadth, saturation, and daemon-death run.** Bidirectional
   namespace/data breadth, links, byte-invalid names, sparse I/O, xattrs, Git,
   SQLite, and recursive macOS = Linux = raw-XFS manifests passed with zero
   retries. Retry-free 4-by-50-per-side saturation verified every successful
   prefix after bounded convergence and post-storm liveness. Killing the daemon
   forced exact mount absence in 6.410 seconds, made a held descriptor return
   `EIO`, and was followed by successful detach, remount, recovery smoke, and
   clean FSKit/FUSE detach.

**Open.**

8. Broader performance and soak comparison on package installs, compilers,
   longer metadata storms, larger I/O, and more concurrent mounts. The final
   correctness breadth report is published; this item is expansion rather than
   a missing macOS 26 acceptance gate. See [performance.md](./performance.md).
9. Frontend liveness fault expansion for daemon freeze, an open-but-dead local
   event socket, and authority partition. Linux revoke/abort and macOS 26 forced
   unmount are implemented; daemon-kill macOS revocation is live-proven.
10. File and directory sync fault tests over process kill, kernel crash, detach,
    full disk, quota exhaustion, short writes, and injected `EIO`.
11. Multi-tenant saturation tests proving bounded RAM and descriptors and fair
    progress for unrelated volumes.
12. Recovery drills from live EBS and locked backup with measured RTO/RPO, and
    the authority-restart drill against a live prior strict mount.
13. A branchless XFS cell and runtime control plane that attests placement,
    exclusive-writer state, project and quota identity, endpoint identity, and
    authority epoch before issuing a mount grant — together with lost-response
    tests for idempotent grant creation and Attach, and saturated in-session
    reauthorization tests proving a long-lived mount neither expires at the short
    grant boundary nor silently broadens its authorization. None of this exists
    yet; mounts are credentialed directly.
13. Per-RPC observability at the authority, without which several matrix
    assertions can only check behaviour and not work performed.

The segmented-log experiment remains evidence about append-only write
amplification. Its spike module was removed with the rest of the v2 tree; it was
never a production dependency and never compared the prototype with XFS on
PortableFS workloads. See
[direct-store-exploration.md](./direct-store-exploration.md).
