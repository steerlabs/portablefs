# PortableFS authoritative-XFS architecture

Status: **protocol-7 verification candidate; local qualification and remaining
production gates are recorded in [coherence-v2/integration.md](./coherence-v2/integration.md).**

PortableFS is a remote gateway to one ordinary XFS project directory while a
volume is serving. READY uses that XFS instance; ARCHIVED uses one sealed
immutable archive; RESTORING composes the sealed base, a monotone hydration map,
and XFS. The authority adds
confinement, authentication, replay, distributed locks, subscription/delegation coherence, and
bounded resource admission. It does not add an inode database, content index,
live mutation history, or branch graph. Linux delegated writes may remain in a
volatile daemon buffer until the run/file durability barrier.

The subscription/delegation algorithm and stock-FUSE mapping are normative in
[portable-coherence.md](./portable-coherence.md). This document defines the
authority and storage beneath it.

## Root design

```text
stock Linux FUSE mounts
          |
 authenticated protocol-7 DATA + CONTROL pair
          |
 one active authority epoch for one volume
          |
 descriptor-relative Linux syscalls
          |
 /srv/portablefs/<volume-id>
     XFS project directory
          |
 encrypted SSD / EBS
```

Many volumes may share a cell, but each request is bound to exactly one volume,
one capability, and one authority epoch. Clients never attach the block device.
The optional manager controls placement and credentials but is not on the
filesystem request path.

Linux uses stock FUSE. FSKit uses the separate synchronous-repair profile and
retains compatibility-writer exclusion for every attached Mac mount. The files
gateway is an authenticated cacheless reader and never excludes Linux writers.
Neither profile is silently promoted to Linux cache-withdrawal semantics.

## Source of truth and durability

XFS is durable filesystem truth. The sole delegated holder can accept bytes
into its volatile buffer; peer data/attribute reads break that holder for read
before the Authority answers. Applied XFS page-cache state is current but is
not durable across power loss. File fsync/O_SYNC wait for a durable application
prefix. A run opens the mount root before work and fsyncs that same directory
handle at completion; loss since open fails the barrier. Stock-FUSE syncfs is
not this completion surface.

Runtime subscriptions, delegations, connections, locks, handles, and replay
outcomes are epoch-local. Restart permanently stales old handles; cold
reattachment permits new opens. The Authority fences prior Linux membership
through the subscription horizon before conflicting writes. Prior Mac or
unproven membership retains its separate compatibility/lifecycle fence.
No client checkpoint or journal reconstructs XFS.

### Tiered canonical representation

Exactly one representation is canonical for each `(State, ArchiveCycleStep)`.
An ARCHIVED volume has no XFS placement or authority: its sealed,
attempt-addressed manifest and packs are canonical. During RESTORING, a durable
hydration mark selects XFS for one chunk; an unmarked chunk comes from the
sealed base. The map is monotone, is not a mutation log, and stops participating
after the durable convergence commit.

The archiver reads one quiesced tree while the authority is absent. The
namespace restorer materializes the initial tree before serving. During serving,
the hydrator fetches and verifies recall bytes but never writes XFS; the
authority alone writes them through its confined store. These phase-qualified
roles do not create a second writable truth.

The cell mount is `prjquota,nodev,nosuid,noexec,noatime`. `noatime` prevents an
ordinary read from becoming an undeclared metadata mutation. Encryption at rest
and mutually authenticated TLS 1.3 are required.

## Object identity and confinement

Activate returns an opaque root token. Lookup takes a parent token and one raw
name component; later operations use stable object tokens or authoritative open
handles. Clients never supply host paths or inode numbers. Every token is bound
to its volume, session, access mode, and epoch.

The authority opens the volume root once, verifies its device, filesystem type,
project identity, ownership, and mount options, then executes descriptor-relative
operations beneath it. Resolution rejects `.`/`..`, embedded separators, NUL,
magic links, mount crossings, and symlink escape. Cross-volume link and rename
fail by construction.

An unlink removes a binding, not the open object. Authority handle state pins
the server open file description until final release, preserving
open-after-unlink semantics.

## Protocol and replay

Authority protocol 7 uses ALPN `portablefs-authority-v7` and exactly one DATA
and one CONTROL connection in a random authenticated connection set. Attach is
provisional; Activate makes it usable only after both transport bindings and
their generations are proven. There is no single-transport or protocol-6 path.

Hello/Activate require all exact features for the selected profile listed in
[wire.md](./coherence-v2/wire.md#required-features). Missing features refuse the
session; they do not select an older engine. Frozen old message numbers remain
in the schema, but executable Linux lease handlers and clients are deleted.

Mutation operation identities are daemon-owned. Within one epoch, exact replay
returns the retained outcome without re-execution. Reusing an identity for a
different canonical body or violating its sequence fences the session. Replay
state dies with the epoch; a reply lost across authority death is uncertain and
is never resubmitted automatically.

DATA carries filesystem calls and bounded bulk bodies. CONTROL carries change batches and delegation
events, acknowledgements, renewals, keepalive, detach, and reauthorization so
bulk traffic cannot starve recall. The framing budget remains charged until the
handler releases the body.

## Subscription and delegation coherence

A volume subscription has a ten-second Authority horizon, renewed every three
seconds. Subscribe returns an atomic watermark and delegated-identity set.
Acknowledging a change position certifies complete withdrawal through that
position in the same incarnation. Grant activation and committed namespace
responses wait for acknowledgments or the old horizon, without holding a
storage commit lock across peer waits.

CREATE/OPEN reserve a file delegation before publishing ownership. A FULL
holder may buffer data and attributes. Pre-existing cacheable peer handles
force write-through; new peer handles on delegated files use direct I/O.
Reads of data, size, or attributes break the holder for read. Peer mutation
recalls ownership, and stale-generation flushes are rejected before application.

The source mount drains exact identity/name publications. Shared kernel entry
validity is zero, so source completion requires no private namespace receipt.
Inode notifications withdraw data and attributes. Directory iteration uses
stable XFS cookies across mutation without ESTALE. Reverse d_path rendering
is outside the namespace contract.

Application tickets retire at the session durable prefix. Completed CONTROL
obligations retire at the explicit acknowledged completion position, and a
session retains bounded replay and event-batch storage. A missed recall
advances loss on the affected handles; it does not abort the mount.

## Operation semantics

XFS supplies each syscall's locking and atomicity. Dependency coordinates
serialize conflicting mutations while disjoint operations run concurrently.
Rename acquires both parent/name coordinates and relevant object coordinates as
one set. Copy-range names both endpoints. Directory membership changes publish ordered namespace entries.

Write-capable Linux opens use direct I/O with kernel write-back off. Delegated
accepted entries flush in per-file order through bounded WRITE requests.
Append first flushes earlier accepted data, then uses Authority EOF placement;
per-call RWF_APPEND/RWF_NOAPPEND remain disclosed stock-FUSE deviations. Item
capabilities are session/epoch-local: stable identity never authorizes reopening
an object after epoch loss.

The authority implements independent POSIX record and BSD flock namespaces.
Deadlock detection rejects a cycle instead of hanging. Session or epoch loss
releases its locks.

User xattr writes are refused because XFS attribute-fork blocks are not charged
to project quota. Read, list, and remove are limited to portable `user.*` names;
the reserved internal prefix and privileged namespaces never cross the wire.

## Routing

`.portablefs/local-dirs` declares names served from per-machine Linux storage.
The authority owns the canonical declaration and its revision. Admin
`ApplyRoutes` replaces it by compare-and-swap; ordinary mounts cannot mutate it.
Attach refuses a different revision. A live change fences old sessions because
their shared/local classification is no longer valid.

Route-matched operations never reach XFS authority data. The Linux daemon uses
descriptor-confined local handles and refuses a platform without `openat2`
`RESOLVE_IN_ROOT`/`RESOLVE_NO_MAGICLINKS`. Machine-local graft execution remains a Linux frontend capability.

## Multi-tenancy and quotas

Each volume has a unique nonzero XFS project ID and an unprivileged service
UID/GID. The project directory and descendants retain PROJINHERIT. Block and
inode hard limits are installed and verified before authority startup.

The authority refuses root execution. The cell root remains root-owned and not
writable by volume identities. Write staging is a service-owned project-
inheriting directory on the same XFS filesystem, so staged bytes cannot escape
the volume quota.

With project block and inode hard limits installed, XFS `statfs` on the volume
root reports the project's limits and remaining usage. That projection is
load-bearing for `df` and tiered capacity accounting. A project without hard
limits reports cell-wide XFS capacity; neither case requires granting the
authority quota-administration capability.

In-memory budgets cover sessions, handles, subscriptions, delegations, replay outcomes, frame bytes,
locks, and queued work. Exhaustion rejects new work before unbounded allocation.
It never spills authoritative data onto another filesystem.

The current volume is single-principal. Mounts project the service identity to
their local user; host numeric IDs are not treated as portable identities.

## Failure model

Ordinary request errors remain request-scoped. Protocol, replay, or authentication defects fence one session. Coherence
expiry or recall loss withdraws cache/delegation permission at its own scope. Storage corruption and shutdown
errors (`EIO`, `EUCLEAN`, `ESHUTDOWN`, `ENOTRECOVERABLE`) fence the volume
epoch. No scope redirects to weaker storage or coherence.

A lost subscriber is fenced until it invalidates and resubscribes cold;
conflicting work waits for its old horizon. An Authority epoch change stales
all old handles. Accepted write loss is visible through the run barrier. The
stalled-daemon resident-page residual and delayed quota errors are explicit in
[failure-modes.md](./failure-modes.md).

## Backup and recovery

Backups are storage operations on XFS/EBS, not PortableFS snapshots. A backup
process must establish application-appropriate fsync and quiescence, take the
provider snapshot, and record the exact volume/device identity. Restoring
creates a new authority epoch; no client session or replay record survives.

Recovery drills must verify XFS repair policy, project IDs, quotas, ownership,
mount options, TLS identity, capability keys, route revision, and the restart
subscription horizon fence before admitting conflicting writes.

The archive tier is distinct from operator XFS/EBS snapshots. It is a
first-class Manager-verified representation governed by the identity,
lifecycle, capacity, and restore ordering in
[the tiered-storage contracts](./tiered-storage/identity-lifecycle-and-capacity.md).

## Production proof gates

- stock Linux FUSE 7.31+ INIT and real-VFS integration on supported LTS kernels;
- two independent mounts passing the black-box coherence matrix and its red
  controls;
- subscription/delegation grant, break, recall and renewal, stale-generation
  rejection, exact publication, stable-cookie enumeration, append placement,
  root-directory barrier delivery, and epoch/loss fault tests;
- XFS project/quota, confinement, storage-failure, and open-after-unlink tests;
- Go race, native Swift qualification/refusal, release-identity, and workflow
  policy gates;
- power-loss and authority-restart drills;
- archive/restore round-trip on real project-quota XFS, including bytes,
  namespace, exact modes, nanosecond mtimes, symlinks, sparse extents, xattrs,
  and hard links;
- recall saturation, restore-blocked recovery, post-convergence equivalence,
  quiesce admission closure, and project-`statfs` capacity tests; and
- protocol-7 measurements with workload/VM caveats, and production measurement
  before any SLO claim.

The protocol-5 qualification receipt and the private vNext design remain in-tree
as historical evidence. The Linux 6.12.100 private patch series is no longer
checked in; it lives only in git history. None of the three is a build, test,
deployment, or runtime dependency of this architecture.
