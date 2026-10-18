# The FSKit mount (macOS)

Status: **supported protocol-7 FSKit profile with explicitly weaker cache,
append, and lock guarantees than Linux**

PortableFS ships the app, daemon, and FSKit extension for macOS 26 and 27. A
mount declares the immutable `FSKIT_SYNC_REPAIR` frontend profile before Attach;
it never claims or negotiates the Linux subscription/delegation profile.

## Platform contract

Protocol 7 gives Linux exact cache withdrawal through Authority subscriptions
and per-file delegations. Before a conflicting mutation returns, affected peers
must prove they discharged the relevant name binding, attributes, clean data,
and directory-enumeration state. Linux also preserves `O_APPEND` intent for
authority-placed writes and forwards POSIX record and `flock` operations.

Current public FSKit does not expose all of those primitives:

- no documented exact negative/positive namespace invalidation;
- no documented inode-attribute invalidation;
- no complete directory-enumeration invalidation contract;
- `FSVolume.OpenModes` carries read/write access but not append intent; and
- no advisory-lock callbacks.

`DataCacheHandler` on macOS 27 covers retained item data, but does not fill the
namespace, attribute, enumeration, append, or lock gaps. The FSKit profile
therefore retains ordered synchronous repair and states those edges as
best-effort instead of representing them as exact Linux coherence.

## Admission behavior

On Darwin, `portablefs mount` selects the FSKit profile exactly. Attach and
Activate echo that profile; replay or reconnect with a different profile is a
protocol error. The authority admits only the FSKit repair,
source-publication, fragmented-write, one-frame write, and shared filesystem
operations for that session. It does not issue lease grants or accept
lease-control requests. The current daemon requires `fskit-direct-write-v1`,
`fskit-durable-mutations-v1`, `fskit-versioned-metadata-v1`, and
`batched-close-v1`, and refuses an authority that lacks any of them.

## Writes and durability

FSKit delivers no fsync, directory-sync, or F_FULLFSYNC callback; the only
module-visible events that can carry durability are the mutation callbacks
themselves. Every successful FSKit mutation reply therefore waits until its
storage effect is durable on the authority, covering data, size, attributes,
and namespace changes, including new empty files and unlinks. A failed or
uncertain reply is not a durability receipt, and a failed storage sync fences
the epoch; there is no success after it.

`write(2)` on the shipping profile still returns at kernel page-cache
acceptance, as POSIX permits. The kernel pushes those pages through write
callbacks on fsync, close, unmount, or memory pressure. Each callback chunk of
up to the negotiated maximum write is one authority request.

A native `fsync` or `F_FULLFSYNC` is durable only if macOS pushes the file's
dirty pages as write callbacks, waits for every reply, and reports their
errors; ordinary unmount needs the same drain. That is host-kernel behavior.
It remains unproven pending delayed- and failing-callback tests and authority
crash tests on each supported macOS release and FSKit profile. Per-callback
durability is necessary for the guarantee but does not by itself prove it.
A forced unmount can discard writes the kernel accepted but never delivered.

## Identity and enumeration

FSKit file IDs are XFS inode numbers offset by one; the volume root is ID 2.
They are stable across local reclaim and re-lookup, so `d_ino` equals `st_ino`
for the same object. They are not persistent across inode reuse, restore, or
volume replacement, and PortableFS does not implement lookup by ID, so the
volume does not advertise persistent object IDs. Directory listings return
non-owning entry snapshots and retain no authority capability; only lookup
and create hand FSKit an item.

Each item FSKit holds retains one authority capability until FSKit reclaims
it. The authority bounds capabilities per session (65,536 by default) and
refuses a lookup beyond that with `ENFILE` rather than evicting an item the
kernel still holds. A workload that keeps more vnodes alive on one mount needs
a correspondingly provisioned authority budget.

Close and reclaim complete locally. The daemon retires the handle or item,
transfers the authority release to one background owner, and replies; it does
not wait a network round trip per callback, which matters because the kernel
reclaims items one at a time at unmount. Each work batch holds at most 128
tokens and sends up to two sequential requests: one `CLOSE_BATCH`, then one
batched Reclaim. The owner keeps one batch in flight and one forming, so the
authority retains at most 256 accepted-but-unsent tokens beyond local
retirement. Releases still being handed over add at most two tokens per
in-flight request and per abandoned provisional reply on each frontend
connection, with 1,024 of each per connection and at most 256 connections:
a conservative total of `256 + 256 * 2 * (1024 + 1024)` = 1,048,832 tokens. A
mount normally has one frontend connection, so its reachable lag is far
smaller; authority capacity must cover live items and handles plus the lag a
deployment can reach. A failed release ends the mount; it is never retried
item by item.
After observing exact kernel absence, unmount drains accepted releases on the
original session before delivering that proof. A failed or timed-out drain
still completes local teardown but returns failure.

## Metadata cache

While this Mac holds the volume's writer exclusion, it is the only client
that can change metadata the mount can observe, and every change it makes
returns through its own daemon with a versioned post-state. The daemon
therefore answers attribute requests and name lookups, including negative
ones, from state its session already received, without an authority round
trip. Misses take the ordinary authority path.

The cache is not a TTL. Its entries are ordered by the authority's storage
sequence: an older read or mutation result never replaces a newer one, a name
is filled only from an observation at or after that directory's last applied
namespace change, and a record learned from an old lookup stays uncacheable
until a fresh observation. A hit is admitted only when no conflicting
mutation of the same callback window is in flight, and only within the
validity the authority last proved through KeepAlive, at most 60 seconds
ahead and measured on a clock that advances across sleep. The authority keeps
the writer exclusion for every proof it granted even if the session is fenced
earlier, so no other client can write while a hit can still be served. Any
terminal condition clears the cache permanently for that attach.

Size, mtime, mode, ownership, link count, type, and names are exact under
these rules. Allocated size (`st_blocks`) is the value from the last authority
observation: XFS can trim speculative preallocation, and restore-mode
hydration allocates blocks, without a client mutation. Restore-mode ctime is
already outside its contract. Extended attributes, symlink targets, and
volume statistics are not cached. The cache does not change FSKit's own
kernel caching, which keeps the limits stated above.

The frozen policy spellings `macos26-synchronous-vfs-repair-v1`,
`macos26-synchronous-vfs-repair-v2`, and `fskit-native-revocation-v1` remain
exact. They choose the host actuator inside the FSKit profile; none selects the
Linux subscription/delegation profile.

## Qualification topology

Qualification builds keep the same three-piece local architecture:

```text
portablefs CLI -- owner-private control socket --> portablefsd
portablefsd    -- versioned pfslocal socket ----> FSKit extension
FSKit extension <-------------------------------> macOS kernel
```

The daemon owns authority credentials and session state; the extension owns
FSKit item identity and kernel callbacks. `pfslocal` frames are length-delimited
and versioned, and the extension validates daemon identity, mount identity, and
request shape before dispatch. Host, daemon, and extension must share the exact
signed app-group and bundle identity described in
[release-identity.md](./release-identity.md).

Ordinary callback execution is bounded before daemon request submission so
kernel reclaim bursts cannot exhaust the connection's request limit. Queued
ingress remains visible to PREPARE until admission or the actual framework
reply returns. Authenticated repair callbacks bypass this execution window;
publication, cancellation, and terminal failure release or retire its waiters.

Ordinary macOS 27 selects the same shipping v2 synchronous-repair actuator as
macOS 26. The stronger SDK-27 native actuator remains build-stamped; runtime
flags cannot promote an older signed app into it or silently reinterpret an
unknown OS. The historical qualification spelling is retained as release
identity; it does not permit a protocol-6 handshake.

## Install and lifecycle

The notarized `PortableFS.app` remains the distribution unit. It contains the
CLI, per-user daemon service, and FSKit extension with one exact identity chain.
Users enable the extension in System Settings; installers cannot do that
silently. Replacement or re-registration of the host app can terminate the
live extension, so packaging and updater tests must continue to prove identity
and drain behavior.

Keep one enabled provider for filesystem type `pfs` and resource scheme
`dev.portablefs.oss` at the installed app path. Archived pre-OSS providers can
also claim `pfs`. macOS retains extension registrations for development builds
and archived app copies; waking the current host does not prove that FSKit
selected its extension. The installer rejects conflicting providers. A manual
development installation must retire both the obsolete extension's PlugInKit
entry and its enclosing app's LaunchServices registration, preserving the app
files. Live qualification must check the executing extension path as well as
the kernel mount identity.

LAN authorities also require macOS Local Network permission for the signed
host or its `PortableFSDService` agent, under System Settings > Privacy &
Security > Local Network. Both bundles declare the connection's purpose.
Terminal and SSH tools can reach an address while the background agent is
denied with `EHOSTUNREACH` ("no route to host"); a successful shell connection
therefore does not prove that the agent can connect. Grant the app permission
and retry the mount. Do not change the service to root or bypass the permission.

On first access to a mounted volume, macOS can also prompt for Network Volumes
access. Allow it for the signed host or its `PortableFSDService` agent under
System Settings > Privacy & Security > Files & Folders > Network Volumes.
Both bundles declare this access's purpose. An unanswered prompt can leave
mount readiness waiting for the daemon's root-directory open. Full Disk Access
is not required.
Apple documents this distinction in
[TN3179](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy).

The CLI and daemon private control API require exact release identity. A foreign
or stale daemon is left untouched and the command fails with clean-stop
guidance. There is no automatic replacement of an unknown socket owner.
The host owns service replacement: it derives the outgoing release from the
authenticated live daemon and its signed owning app, proves an empty mount and
attach inventory, and unregisters that exact execution before registering its
own sealed service. Saved preferences do not identify the running release.
Authentication identifies whose mount inventory may be trusted; the
empty-inventory guard is what proves that daemon serves no mounts. An owner
the host cannot authenticate is therefore never stopped. Examples are a
daemon whose app was deleted or replaced while it ran, a foreign process or
another signed product on the control socket, an endpoint the host cannot
connect to, and a state lock held without an endpoint. Startup fails and
reports what it observed. Where the cause is established it also gives the
sanctioned recovery: quit the other app, let a running installer finish, or
unmount and log out to end an orphaned daemon. Otherwise it reports the
authentication step that failed and the underlying error. While replacing a
service that has no endpoint, the host holds the state lock across
unregistration, so a daemon cannot start between the absence proof and the
stop. Updates go through the installer, which quiesces the running daemon
before it replaces the app.

An FSKit frontend loss immediately ends local serving. The daemon retains the
original authenticated authority transport until the mount supervisor proves
the exact kernel mount absent and delivers that proof through the existing
detach operation. An accepted proof clears the durable mount membership and
the session's cache-proof obligation; writer exclusion still waits for the
session's admitted storage work to drain. The terminal frontend cannot
reconnect. Without an accepted proof, after a lost authority transport or an
unprovable unmount, durable membership remains for topology safety. Within the
same authority process, Linux writers and another Mac wait until every
metadata-cache proof granted to the old session has expired and its admitted
storage work has drained. After an authority restart only the Linux writer
refusal expires, after the full 61.06-second grace; Mac activation requires
operator reconciliation.

The launchd-managed daemon appends to
`~/.local/state/portablefs/portablefsd.log`; per-mount logs are separate, under
`~/.local/state/portablefs/mounts/`. The per-mount wrapper and the attach's
renewal owner append there without sharing file offsets. Automatic mount-credential
renewal emits structured scheduled, succeeded, retrying, denied, cutoff, and
stopped events carrying sequence, deadline, retry, and bounded error metadata
only; capabilities, certificates, and tokens are never logged.

## Verification

- app, daemon, extension, entitlement, and bundle identity;
- daemon lifecycle and owner-private control sockets;
- `pfslocal` framing, version negotiation, item identity, and error mapping;
- callback implementations through unit and native Xcode tests;
- explicitly stamped live macOS 27 mounts and the macOS coherence matrix;
- profile mismatch refusal before Attach.

The native Swift suite is run with:

```bash
bash scripts/test-swift-xcode.sh
```

The live matrix accepts already-mounted paths and never changes their profile:

```bash
scripts/coherence-matrix-macos.sh --mount-a /path/a --mount-b /path/b
```

## Historical evidence

[macos-26-coherence-contract.md](./macos-26-coherence-contract.md) defines the
current best-effort profile and labels its protocol-5 measurements as dated
evidence.
[protocol5-hosted-qualification-2026-08-16.md](./protocol5-hosted-qualification-2026-08-16.md)
records the hosted protocol-5 qualification. That receipt remains dated
evidence, not a protocol-7 result.

[macos-27-native-coherence.md](./macos-27-native-coherence.md) tracks the SDK-27
API audit and the remaining gaps. New host primitives can strengthen the
profile without silently changing its current guarantees.
