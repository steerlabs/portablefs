# PortableFS authoritative-XFS architecture

Status: **protocol-6 storage and authority target; writable Linux is not yet
production-ready**

PortableFS is a remote gateway to one ordinary XFS project directory. XFS and
its block device are the only durable filesystem state. The authority adds
confinement, authentication, replay, distributed locks, lease coherence, and
bounded resource admission. It does not add an inode database, content index,
mutation history, branch graph, or write-back overlay.

The lease algorithm and stock-FUSE mapping are normative in
[portable-coherence.md](./portable-coherence.md). This document defines the
authority and storage beneath it.

## Root design

```text
stock Linux FUSE mounts
          |
 authenticated protocol-6 DATA + CONTROL pair
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

Production mounting is Linux-only. FSKit adapters share protocol and local
framing code for qualification, but current FSKit cannot satisfy protocol-6
N/A/E discharge, per-reply metadata installation control, append intent, or locks and is refused before
Attach.

## Source of truth and durability

Current state is the mounted XFS instance, including its server page cache.
Unflushed XFS state is authoritative but not durable across power loss.
`fsync`/`fdatasync` on an authoritative open file description and ordinary
directory-fsync discipline define persistence. `close` is not an implicit
durability barrier.

Authority runtime state—connections, leases, locks, handles, cancellation, and
bounded replay outcomes—is disposable at epoch loss. A restart therefore ends
all sessions and holds a maximum-lease grace period before admitting conflicts.
No PortableFS checkpoint or log reconstructs XFS.

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

Authority protocol 6 uses ALPN `portablefs-authority-v6` and exactly one DATA
and one CONTROL connection in a random authenticated connection set. Attach is
provisional; Activate makes it usable only after both transport bindings and
their generations are proven. There is no single-transport or protocol-5 path.

Hello requires `lease-coherence-v1` and
`directory-enumeration-lease-v1`. Activate requires `lease-renewal-v1`,
`lease-recall-v1`, and `open-by-identity-v1`. Required feature absence refuses
the session rather than selecting another profile.

Mutation operation identities are daemon-owned. Within one epoch, exact replay
returns the retained outcome without re-execution. Reusing an identity for a
different canonical body or violating its sequence fences the session. Replay
state dies with the epoch; a reply lost across authority death is uncertain and
is never resubmitted automatically.

DATA carries filesystem calls and bounded bulk bodies. CONTROL carries lease
events, acknowledgements, renewals, keepalive, detach, and reauthorization so
bulk traffic cannot starve recall. The framing budget remains charged until the
handler releases the body.

## Lease coherence

The authority grants TTL-bounded rights for:

- N(parent,name): one positive or negative binding;
- A(object): the complete attribute record;
- D(object,whole): clean whole-file data; and
- E(directory): complete membership enumeration.

The authority grants a TTL duration representing its full horizon. The client
anchors that horizon at request start and ends cache validity five seconds
earlier so withdrawal has a fixed interval; transport and processing time can
only shorten either interval. No cross-host absolute-clock comparison is
required. Renewal I/O cannot block expiry scheduling, withdrawal, or the
terminal watchdog.

Successful responses can carry grants. A conflicting mutation closes grant
admission, sends recall on CONTROL, applies to XFS, sends exact post-state, and
waits for peer discharge before acknowledging the source. A holder purges all
covered state. Whole-file D leases recall only to none in v1; range-successor
continuity is not implemented. Epochs reject late acknowledgements.

The source mount receives an exact source obligation instead of a CONTROL
self-recall. It purges A/D/E and daemon N state before reply. Kernel name-entry
validity is always zero, so rename cannot transplant an old leased timeout and
source completion needs no private or undocumented namespace receipt.
This proves forward pathname and directory-enumeration coherence. Reverse
rendering of an already-held dentry (`getcwd` and other `d_path` users) is
outside the contract because stock Linux does not revalidate it.

Lease state is volatile in v1. On restart, grace prevents conflicting mutation
for the frozen 20-second protocol maximum, even when the newly configured TTL
is lower. Persisting lease state is future work, not an implicit recovery promise.

## Operation semantics

XFS supplies each syscall's locking and atomicity. Dependency coordinates
serialize conflicting mutations while disjoint operations run concurrently.
Rename acquires both parent/name coordinates and relevant object coordinates as
one set. Copy-range names both endpoints. Directory membership changes also
conflict with E.

Write-capable Linux opens use direct I/O. Each FUSE write maps to one
daemon-owned authority operation; large writes use the protocol-6 stream without
a kernel transaction ABI. `O_APPEND` is refused at open, but stock FUSE does
not forward `RWF_APPEND`; that unobservable path blocks production readiness of
the writable profile. `FUSE_CREATE` can use resolve-open; ordinary open-existing reaches
the authority by stable identity after lookup.

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
`RESOLVE_IN_ROOT`/`RESOLVE_NO_MAGICLINKS`. Grafts do not exist on production
macOS because production macOS mounting itself is refused.

## Multi-tenancy and quotas

Each volume has a unique nonzero XFS project ID and an unprivileged service
UID/GID. The project directory and descendants retain PROJINHERIT. Block and
inode hard limits are installed and verified before authority startup.

The authority refuses root execution. The cell root remains root-owned and not
writable by volume identities. Write staging is a service-owned project-
inheriting directory on the same XFS filesystem, so staged bytes cannot escape
the volume quota.

In-memory budgets cover sessions, handles, leases, replay outcomes, frame bytes,
locks, and queued work. Exhaustion rejects new work before unbounded allocation.
It never spills authoritative data onto another filesystem.

The current volume is single-principal. Mounts project the service identity to
their local user; host numeric IDs are not treated as portable identities.

## Failure model

Ordinary request errors remain request-scoped. Protocol, replay, lease, or
authentication defects fence one session. Storage corruption and shutdown
errors (`EIO`, `EUCLEAN`, `ESHUTDOWN`, `ENOTRECOVERABLE`) fence the volume
epoch. No scope redirects to weaker storage or coherence.

A lost lease participant is fenced individually; a conflicting mutation then
waits until the lease expiry bound. Authority death ends the epoch. The two
accepted stock-FUSE clean-page residuals are stated, with exact triggers, in
[failure-modes.md](./failure-modes.md).

## Backup and recovery

Backups are storage operations on XFS/EBS, not PortableFS snapshots. A backup
process must establish application-appropriate fsync and quiescence, take the
provider snapshot, and record the exact volume/device identity. Restoring
creates a new authority epoch; no client session or replay record survives.

Recovery drills must verify XFS repair policy, project IDs, quotas, ownership,
mount options, TLS identity, capability keys, route revision, and the restart
lease grace before admitting clients.

## Production proof gates

- stock Linux FUSE 7.31+ INIT and real-VFS integration on supported LTS kernels;
- two independent mounts passing the black-box coherence matrix and its red
  controls;
- lease grant/recall/renewal, late-epoch rejection, self-exemption, bypass-lane
  liveness, E-lease enumeration, `O_APPEND` refusal, an explicit
  `RWF_APPEND` blocker gate, and fencing fault tests;
- XFS project/quota, confinement, storage-failure, and open-after-unlink tests;
- Go race, native Swift qualification/refusal, release-identity, and workflow
  policy gates;
- power-loss and authority-restart drills; and
- fresh protocol-6 performance measurements before any SLO claim.

The protocol-5 qualification receipt and the private vNext design remain in-tree
as historical evidence. The Linux 6.12.100 private patch series is no longer
checked in; it lives only in git history. None of the three is a build, test,
deployment, or runtime dependency of this architecture.
