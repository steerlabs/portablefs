# The FSKit mount (macOS)

Status: **specified for protocol 8; not yet qualified on native macOS 26 or
27.** The open native gates are listed under [Verification](#verification).

PortableFS ships one app, daemon, and FSKit extension for macOS 26 and 27. A
mount declares the immutable `FRONTEND_PROFILE_FSKIT_EXCLUSIVE` profile before
Attach. The profile is the same on both releases; there is no cache-policy
name, selector, or separately built macOS 27 variant. An unsupported OS fails
before Attach through the platform-support check.

## Platform contract

Linux gets exact cache withdrawal from authority subscriptions and per-file
delegations: before a conflicting mutation returns, every affected peer proves
it discharged the relevant name binding, attributes, clean data, and directory
listing. Current public FSKit does not expose the primitives that would let a
Mac do the same:

- no documented exact positive or negative namespace invalidation;
- no documented inode-attribute invalidation;
- no complete directory-enumeration invalidation contract;
- `FSVolume.OpenModes` carries read/write access but not append intent; and
- no advisory-lock callbacks.

The macOS 27 `FSVolume.DataCacheHandler` acts only on retained item data; it
fills none of the other gaps. Apple has stated that inode and attribute
invalidation does not currently exist and that FSKit does not yet fully support
shared or network file systems
([Apple Developer Forums thread 821376](https://developer.apple.com/forums/thread/821376)).
A TTL, polling loop, hidden retry, or synthetic nested VFS call cannot
manufacture these primitives.

The profile therefore makes the missing invalidation unnecessary rather than
approximating it: **a mounted Mac is the volume's only writer.** Linux peers
can stay mounted and read the Mac's changes; their visible mutations and
write-intent opens return `EBUSY` before any storage effect. A second Mac mount
of the volume is refused at activation, even if its access happens to be
read-only, because FSKit's kernel caches could not be kept coherent under
another writer. Cross-machine `fcntl`/`flock` exclusion and cross-client
atomic append are not available while a Mac writer is attached; they need
Linux mounts only. Single-writer append works because the Mac kernel supplies
the offset.

### Kernel cache control and terminal enforcement

One shared VolumeCore, mapping, publication gate and daemon serve both OS
releases. Construction selects the native lifecycle adapter once with
`#available(macOS 27, *)`. macOS 26 keeps its per-mode open/close callbacks;
macOS 27 adopts `FSVolume.DataCacheHandler` as its only open/upgrade/final-close
owner. A macOS 27 error never retries through the macOS 26 adapter.

On macOS 27, `readWriteWithCache` receives `writeBack` only with live
exclusive-writer/authorization proof and legitimately retained read/write
rights. `readWithCache` and read-only rights can receive `readCache`; `none`
and write-only rights receive `noCache`. Existing-file `O_WRONLY`/`O_APPEND`
and mode 0200 never trigger a read OPEN merely to fill a cache. CREATE's
legitimate read/write description remains reusable, including on a newly
created 0200 inode. Upgrades change cache permission, not descriptor access.
Terminal or authorization loss fails access. Descriptions retain their rights
until V3's final item close, after kernel cache management; new opens acquire
only missing access through authority checks. Final close cannot return an
error, so cleanup failure ends serving.
On 27, reclaim settles pending item publications and checks `FSItem.tryReclaim`
under the shared publication gate; a retained kernel reference restores the
canonical item without releasing authority ownership. Reentrant failure replies
complete before the shutdown owner waits for cache withdrawal.

The existing pfslocal event binding carries the daemon's proof horizon on the
shared sleep-inclusive boot clock and the installed signed authorization
deadline. Usable-session proof expiry stops new grants and completes
`pushInvalidate` before certifying `noCache`. Plain invalidate would discard
healthy dirty data. Direct durable WRITE callbacks remain admissible during
the drain. Ordinary unmount drains before closing the connection and releasing
ownership. Link, rename and unlink push the relevant earlier dirty cut,
including a rename replacement, before namespace dispatch. These pushes run
before callback-window admission and source publication, outside lifecycle
gates; descriptions are pinned through completion and ownership is revalidated.
A concurrent renewal cannot grant caching while the drain is in flight.
Terminal ownership or authorization loss, including daemon death, revokes
retained items and fails pending work; it never pushes old dirty pages into
another owner/session/epoch. An ordinary open-unlinked inode remains accessible and is not revoked merely because its link count is
zero. `setCacheState` runs outside module locks, with ownership retained through
completion, including reentrant close/reclaim. A failure leaves the kernel state
unchanged and is terminal; it never certifies withdrawal. Kernel-call results
are logged with the item, action and error code for native observation. These
rules follow Apple's [DataCacheHandler lifecycle](https://developer.apple.com/documentation/fskit/fsvolume/datacachehandler)
and [setCacheState contract](https://developer.apple.com/documentation/fskit/fsvolume/setcachestate(for:cachemode:coherencytype:action:)).

A stopped extension cannot revoke, and cached reads can race resume after
sleep before the extension executes. The per-item API does not establish exact
negative-name, inode-attribute or directory-enumeration withdrawal. Native loss
and sleep qualification remain open. macOS 26 keeps today's residual: terminal
publication stops new PortableFS serving, but retained kernel names, attributes
and pages may remain observable until unmount. Authority exclusion does not
revoke old kernel state after exclusion ends. Neither OS automatically unmounts
on fence.

### Callback publication and local teardown

Once the session is terminal, no FSKit callback that publishes data, metadata,
namespace or durability reports success. Resource loading, volume activation
and mounting are serving callbacks and obey the same rule. Session termination
and each serving callback's final synchronous reply share one publication gate:
a reply that wins the gate precedes termination; when termination wins, the
final gate rejects publication with the first terminal cause. Earlier definite
request refusals remain failures.

Volume deactivation and resource unloading acknowledge local teardown only.
They must perform their local cleanup even after terminal failure and report
success only after the cleanup they acknowledge has completed. An earlier
session-terminal cause does not make completed cleanup fail. A genuine error
in the teardown request or its local cleanup remains an error. Repeated
completed teardown is idempotent. Unmount's errorless completion acknowledges
the same local cleanup boundary.

A teardown acknowledgement does not certify durability, erase or replace the
first terminal cause, revive a session, prove kernel mount absence, prove
authority acceptance of absence, or certify daemon/CLI reconciliation. Mutation
and synchronize failures retain their existing error paths. Every successful
FSKit mutation reply still requires authority-storage durability before
publication.

The named teardown operations are `deactivate`, `unloadResource`, and
`unmount`; the last has a void completion with no error or errno. Close,
reclaim, release, cancellation, and other cleanup activity retain their existing
publication and resource-settlement rules. `loadResource`, `activate`, `mount`,
and `synchronize` remain gated. Teardown revokes serving publication before
its first suspension, then releases local ownership without depending on a
remote response. It adds no durability barrier, reconnect, authority release
drain, timer, or kernel unmount attempt. Malformed unload requests and genuine
local cleanup errors still fail. Overlapping teardown callers must wait for
the cleanup they acknowledge; an absent registration alone does not prove
that in-flight cleanup has completed.

## Writer exclusion

Activation takes the authority's profile admission exclusively, recalls
outstanding Linux delegations and waits for their exact generations to drain,
then publishes the Mac as the writer. An ordinary Mac mutation does not take
profile admission: it holds its session's runtime pin, and the writer registry
confirms under its mutex, immediately before apply admission, that this session
is the current unfenced writer. A fence that wins that race refuses the
mutation without applying it; a mutation admitted first keeps the exclusion in
force until its apply, withdrawal, durability, and replay obligations retire.

A clean unmount ends the exclusion after an exact kernel absence proof and the
drain of the session's admitted storage work. Without a clean unmount, the
authority keeps refusing Linux visible mutations and another Mac's activation
until every KeepAlive cache proof granted to the session has expired (at most
60 seconds) **and** its admitted storage work has drained. After an authority
restart that finds prior FSKit membership, Linux writes wait 61.06 seconds
after safe takeover of the store, and Mac activation requires operator
reconciliation. That restart bound assumes the predecessor authority's renewal
and storage work have irrevocably stopped; process disappearance alone is not
that proof.

## Writes and durability

FSKit delivers no fsync, directory-sync, or `F_FULLFSYNC` callback. Every
successful FSKit mutation reply therefore waits until its effect is durable on
the authority: data, size, attributes, and namespace changes, including new
empty files and unlinks. A handle-backed mutation full-fsyncs its retained
description; a handleless mutation uses `syncfs` on the authority's retained
XFS-root description, whose error and latency scope is the whole XFS cell (see
[COMPATIBILITY.md](../COMPATIBILITY.md#two-limits-that-apply-to-every-deployment)).
A failed or uncertain reply is not a durability receipt, and a failed storage
sync fences the store; no later barrier can certify durability.

The volume's `synchronize` callback waits for the authority SyncVolume barrier
over its captured applied cut, then Statfs. Barrier and Statfs errors propagate;
even after both succeed, termination that wins the final publication gate
fails the callback with the first terminal cause. This barrier cannot cover
mutations outside that cut or dirty kernel pages not yet delivered as
callbacks. Successful local teardown supplies no second durability verdict.

Delivered writes are direct: each callback chunk of up to the negotiated
maximum write is one positioned authority WRITE, without append, sync, delegation, flush
sequence, or lock owner. There is no fragmented or staged write.

On macOS 27, writeBack buffers ordinary writes in the kernel like V2 on
macOS 26. `write(2)` can return at kernel page-cache acceptance; every delivered
FSKit callback remains durable at the authority before successful reply. The
kernel pushes pages for barriers, close, unmount or memory pressure. Writer
loss or forced unmount may lose undelivered dirty data, as on V2 and a local
disk without fsync. An unacknowledged in-flight write may already have applied;
this does not imply prefix-atomic recovery. Linux peers see delivered state
only while newer bytes remain solely in Mac pages. Neither longer deferred
retention nor close timing is qualified as exactly equivalent to V2.

A native `fsync` or `F_FULLFSYNC` must cover buffered data by delivering every
covered callback, waiting for all durable replies and reporting errors. That
host-kernel contract is pending native proof on both releases; writeBack is
**not qualified until those proofs pass**. Per-callback durability alone does
not prove it. `scripts/test-macos27-writeback.py` collects two held-WRITE
barrier proofs, faults and close/reopen error delivery on an exact signed
artifact. The kernel-cache observer separately records page geometry and
stopped/sleep/wake residuals. Neither collector claims an automatic pass.

## CREATE and OPEN

CREATE returns a real read/write open description created with the new inode,
and the extension installs it. An immediately following open whose access that
description covers reuses it without another authority OPEN. The description
keeps its create-time access across a later chmod or unlink. If no open follows
CREATE, the description is still a real, charged authority resource owned by
the item; it lives until close, reclaim, or session teardown, never until a
timeout.

An item can hold distinct read and write descriptions. An open that needs
missing access acquires only that access; if the authority refuses it, earlier
descriptions stay usable. A write needs only write access, so a mode-0200 file
can be written. A first open after a final close, or an access expansion, is a
fresh authority OPEN with its own permission check.

## Metadata cache

While this Mac is the writer, it is the only client that can change metadata
the mount observes, and every change returns through its own daemon with the
complete versioned post-state. The daemon therefore answers attribute requests
and name lookups, including negative ones, from state its session already
received. Misses take the ordinary authority path.

The cache is not a TTL. Entries are ordered by the authority's committed
storage sequence: an older result never replaces a newer one, a name is filled
only from an observation at or after the directory's last applied namespace
change, and versions may advance without a logical change without creating an
event. A hit is eligible only after the complete effect of every in-flight
callback on the same coordinate has settled, and only while the last KeepAlive
proof and the installed authorization remain valid. The proof `R` is at most 60
seconds; the daemon serves only before `t0 + R - epsilon(R)`, with
`epsilon(R) = 1 s + ceil(R / 1000)`, measured from before the request was
queued on a clock that advances across sleep. A final exposure check repeats
the liveness, authorization, horizon, and resource-ownership tests immediately
before a cached reply leaves the daemon. When only the proof has expired, the
request makes one ordinary authority read; a terminal or clock failure never
selects a successful alternative. Any terminal condition clears the cache
permanently for that attach.

Size, mtime, mode, ownership, link count, type, and names are exact under these
rules. Allocated size (`st_blocks`) is the value from the last authority
observation: XFS can trim speculative preallocation, and restore hydration
allocates blocks, without a client mutation. Restore-mode ctime is outside the
contract. Extended attributes, symlink targets, and volume statistics are not
cached.

### Directories this mount created

The daemon can also answer an absent name locally for a directory this mount
created. A successful MKDIR returns the new directory's empty membership and an
authority kernel check of search permission on the new directory at the same
committed cut. Only a true search observation, still newer than every
superseding namespace, permission, and attach floor, seeds a names-only
completeness record; a false observation seeds no local negative answer. Later
complete namespace effects from this mount update the record atomically with
their post-state. Any permission-affecting change (including a change back to
the same mode), contradictory errno, uncertain or partial effect, delayed
effect whose ordering cannot be established, parent retirement, or bound
overflow discards the whole record. Bounds are 1,024 directories, 16,384
names, and 1 MiB of name bytes per mount, with no eviction of live
capabilities. A present name without an owned usable capability still asks the
authority. Paginated ReadDir never seeds completeness.

## Identity, enumeration, and resources

FSKit file IDs are pfslocal file IDs plus one: the volume root is ID 2, and an
ordinary file ID satisfies `2 <= fileID < UInt64.max`; zero and overflow are
refused. File IDs come from XFS inode numbers, so `d_ino` equals `st_ino` and
they are stable across local reclaim and re-lookup, but not across inode reuse,
restore, or volume replacement; the volume does not advertise persistent object
IDs. Daemon item handles are a separate namespace of nonzero 64-bit values that
are never reused. Directory listings return non-owning entry snapshots with
explicit file IDs and retain no authority capability; only lookup and create
hand FSKit an item.

Each item FSKit holds retains one authority capability until FSKit reclaims it.
The authority bounds capabilities per session (65,536 by default) and refuses a
lookup beyond that with `ENFILE` rather than evicting an item the kernel still
holds.

Every resource-producing request first reserves one of 1,024 mount-wide pending
slots, each covering at most two new authority resources, before it can hold
locks or reach the authority; a request that produced nothing returns its slot.
Close and reclaim complete locally: the daemon retires the handle or item and
transfers the authority release to one background owner, which keeps one batch
in flight and one forming, each at most 128 tokens, sent as one `CLOSE_BATCH`
then one batched Reclaim. A failed release ends the mount; it is never retried
item by item. Callback state shared across frontend connections is keyed by the
connection's never-reused incarnation and the callback's operation ID, so one
connection's acknowledgment or close cannot settle another's. The extension
admits at most 128 concurrent serving callbacks; terminal loss fails that
window, wakes every waiter, and revokes outstanding tickets.

## Liveness and readiness

The daemon is the only authority renewal owner. It performs the initial
KeepAlive and every renewal at `min(session lease / 3, 5 s, MaxCacheProof / 3)`
with at most one renewal in flight. A renewal may wait up to one session lease,
capped at the authorization deadline; the cadence is not a deadline. A local
timeout that settles on a still-valid transport is not terminal: caching stops
when the old proof expires and renewal continues at the normal cadence.
Refusal, malformed proof, epoch or session mismatch, transport loss, and clock
failure are terminal. Automatic reauthorization keeps a 15-second minimum
safety margin. The extension sends no heartbeat.

The daemon attests `frontend-ready` only when it holds a currently usable
initial proof for the exact activated attach, a live authenticated shipping
frontend has completed Hello and Resolve with its event binding, the exact
kernel mount identity is observed, and nothing is terminal or detaching. A CLI
probe or a connected but unbound socket cannot supply any of these. Readiness
performs no I/O on the mounted root and holds no mount-root descriptor.

## Unmount and detach

`portablefs umount` makes one unforced unmount attempt with the default mount
options. A real reference from Finder, Spotlight, `fseventsd`, or a user process
returns the actual `EBUSY`, and the mount stays usable or reports its existing
terminal state. Only an explicit user `--force` ever forces an unmount, with
the data-loss boundary above. A forced unmount parks no recovery job and keeps
no replay record, and pages the kernel never delivered are gone. No daemon
failure, terminal authority session, slow reply, or proven daemon death forces
an unmount: none of them proves that FSKit delivered every dirty page.
A real sync failure or busy reference can prevent ordinary unmount of a
terminal writable mount. Cleanup-only acknowledgements remove no genuine
sync veto and do not promise that normal unmount will succeed. Explicit force
promises removal only if the OS completes it, and never certifies undelivered
kernel writes as durable.

The mount supervisor owns startup, readiness and its exact mount records, not
the authority session's health. In steady state it waits for user signals and
for Darwin's kernel mount-table notifications (`EVFILT_FS`, mount and unmount
events), registered before its first inventory snapshot; each notification is
only a wakeup, and the supervisor re-reads the exact mount inventory every time.
It runs no periodic probe or timer. On SIGINT or SIGTERM it makes one normal
daemon-owned unmount attempt; `EBUSY` leaves the mount and records in place. If
it observes the exact kernel mount gone, it makes one authenticated daemon
finalization attempt and, if that fails, reports kernel absence with the daemon
error, preserves state and intent, and exits with failure for explicit
reconciliation. If notification setup fails it reports supervision failure
instead of polling. Daemon fencing and terminal publication stop PortableFS
serving. macOS 27 also withdraws retained item caches through DataCacheHandler,
subject to the execution and namespace limits above; macOS 26 retains its
kernel-cache residual.

After exact absence of the original kernel mount is observed, the daemon
delivers the absence proof on the original CONTROL transport without first
draining DATA, and hands unsent cleanup to session teardown; it keeps the
proof-delivery and cleanup errors separately and attempts the proof even if
release cleanup fails. Over operational control it answers with an empty 204
for a completed unmount or with one combined error. A Swift teardown
acknowledgement neither authorizes that 204 nor removes a durable registry
record. The CLI independently classifies the exact kernel mount:

- daemon error and kernel absent: "kernel mount is absent; daemon unmount
  completion is unconfirmed (absence-proof delivery or cleanup may be
  incomplete)", with the daemon error; a timed-out or lost reply is reported
  the same way, because the daemon may have completed after the reply was lost;
- daemon error and kernel present: "kernel mount remains present; daemon-owned
  FSKit unmount failed or is incomplete", with the daemon error;
- kernel query failure: "kernel mount presence is unverified", with any daemon
  error, and nothing that could detach a replacement mount;
- empty 204 and kernel absent: durable CLI cleanup completes and the mount is
  reported unmounted;
- empty 204 but the kernel mount present, or a malformed success: an error.

Every daemon-error, present, unverified, or malformed-success case preserves
state and intent and exits with failure, and none triggers another automatic
kernel action. A later 204 or a 404 is not a receipt that the authority accepted
an earlier absence proof. A poisoned or lost session is never reconnected to
submit evidence. An accepted proof clears
durable membership and the session's cache-proof obligation; writer exclusion
still waits for admitted storage work to drain.

Timeout or EOF does not prove that authority proof delivery failed, and nil
local teardown does not prove delivery succeeded. CLI cleanup requires both
valid empty 204 and independently observed exact kernel absence; even that
local reconciliation does not certify pages abandoned by force as durable.

## Local topology

```text
portablefs CLI -- owner-private control socket --> portablefsd
portablefsd    -- pfslocal 2.0 socket -----------> FSKit extension
FSKit extension <-------------------------------> macOS kernel
```

The daemon owns authority credentials, sessions, and the metadata cache; the
extension owns FSKit item identity and kernel callbacks and keeps no second
metadata cache. `pfslocal` is exactly version 2.0, paired within one signed
release:
Hello carries the version, a diagnostic client name and version, and the
daemon's required positive request deadline. Resolve binds a connection
permanently to one attach; loss of that binding is terminal for its operations
and the connection never re-resolves. A separate event connection binds
explicitly to the same attach. Cache-producing callbacks send one
PublicationAck saying whether the result crossed the FSKit reply boundary, and
resource-bearing replies receive one ResourceReplyDisposition.

Symlinks, hard links, case-sensitive names, and extended-attribute get, list,
and remove are fixed behavior; the Resolve capabilities carry only the name,
file-size, and preferred I/O limits. Extended-attribute set is refused locally
after the request and the live item validate, with `EOPNOTSUPP` so macOS does
not fall back to AppleDouble files.

## Install and lifecycle

The notarized `PortableFS.app` is the distribution unit. It contains the CLI,
the per-user daemon service, and the FSKit extension with one exact identity
chain ([release-identity.md](./release-identity.md)). Users enable the extension
in System Settings; installers cannot do that silently. Replacing or
re-registering the host app can terminate the live extension, so packaging and
updater tests must keep proving identity and drain behavior.

Keep one enabled provider for filesystem type `pfs` and resource scheme
`dev.portablefs.oss` at the installed app path. macOS retains extension
registrations for development builds and archived app copies; waking the
current host does not prove that FSKit selected its extension, and the
installer rejects conflicting providers. A manual development installation
must retire both an obsolete extension's PlugInKit entry and its enclosing
app's LaunchServices registration. Live qualification must check the executing
extension path as well as the kernel mount identity.

LAN authorities require macOS Local Network permission for the signed host or
its `PortableFSDService` agent (System Settings > Privacy & Security > Local
Network). A terminal can reach an address while the background agent is denied
with `EHOSTUNREACH`; grant the app permission and retry. Do not run the service
as root or bypass the permission. On first access to a mounted volume, macOS can
also prompt for Network Volumes access for the same bundles; until it is
answered, access to the volume waits. Full Disk Access is not required. See
Apple's
[TN3179](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy).

A release is identified by its daemon's CodeDirectory hash, executable SHA-256
and version. Before any request on a daemon socket, the CLI and the app
authenticate the peer the same way, from that connection's kernel audit token:
same user, the exact canonical daemon path inside the authenticated owning
bundle, the running image's kernel CodeDirectory hash equal to the release's,
and valid hardened-runtime code (`CS_VALID`, `CS_RUNTIME`). A substitute image
renamed onto the daemon's path therefore fails. Protocol numbers come from the
authenticated daemon's live identity: ordinary operations and incoming
activation require them to equal the incoming build's exact constants (schema
1, control 2, `pfslocal` 2.0); a foreign or stale daemon is left untouched and
the command fails with clean-stop guidance.

To replace a service, the host authenticates the outgoing release and its
running daemon, accepts that release's own reported numbers, and uses
lifecycle v1 to read its complete inventory and to stop it only if idle; it
never decodes the outgoing daemon's private registry or speaks its operational
protocol. With no outgoing daemon running, the host holds the state singleton
and lifecycle exclusion and proceeds only if `attaches.json` is absent from the
validated daemon state directory; any entry at that name blocks. The daemon
durably unlinks that file when its registry becomes empty. An owner the host
cannot authenticate is never stopped. The daemon state singleton is one
canonical flock inode that is never unlinked or replaced; the host holds it
across unregistration so no daemon can start between the absence proof and the
stop. A holder stuck in kernel exit blocks startup until the kernel releases
it.

An FSKit frontend loss immediately ends local serving; the terminal frontend
cannot reconnect, and detach proceeds as above.

The launchd-managed daemon appends to `~/.local/state/portablefs/portablefsd.log`;
per-mount logs are under `~/.local/state/portablefs/mounts/`. Automatic
credential renewal emits structured scheduled, succeeded, retrying, denied,
cutoff, and stopped events with sequence, deadline, retry, and bounded error
metadata only; capabilities, certificates, and tokens are never logged.

## Verification

Exercised by the repository suites (not native FSKit qualification):

- app, daemon, extension, entitlement, and bundle identity;
- daemon lifecycle, owner-private control sockets, lifecycle v1, and singleton
  acquisition;
- `pfslocal` framing, exact 2.0 pairing, shared golden frames, item identity,
  and error mapping;
- callback, window, resource, and cache behavior through Go unit tests and the
  native Xcode suite: `bash scripts/test-swift-xcode.sh`.

Deterministic native regressions must invoke the imported
`any FSVolume.Operations` completion-handler requirements and actual
`loadResource`/`unloadResource` callbacks. They must cover termination before
teardown, ordinary unmount followed by teardown, completed repeats and
overlapping unloads, preserving the first cause and malformed-request errors.
Continuation handshakes must prove that replies follow cleanup, including
request cancellation, and that held serving replies and synchronize still lose
to termination. Cleanup must finish without a remote response or new authority
barrier. These are local ordering and ownership proofs, not live-mount evidence.

Not yet qualified on native macOS 26 and 27:

- first usable proof before readiness, terminal enforcement, and the callback
  window under real teardown;
- no product-owned mount-root descriptor, one unforced unmount with real
  `EBUSY` under normal Finder and Spotlight activity, and explicit force;
- buffered-I/O delivery for `fsync`, `F_FULLFSYNC`, and unmount;
- audit-token peer authentication refusing a substitute image renamed onto
  the daemon path, the two-release lifecycle upgrade, and the supervisor's
  mount-table notification handling;
- power-cut recovery of the FSKit authority handler
  ([power-loss-testing.md](./power-loss-testing.md)) and suspend/resume;
- the Mac plus Linux-peer matrix, run against already-mounted paths:

```bash
scripts/coherence-matrix-macos.sh --mount-a /path/on/mac \
  --remote user@linux-host --remote-mount /path/on/linux
```

For teardown qualification, use isolated signed real mounts on both releases
with healthy and terminal sessions, busy references, and undelivered dirty
pages. Record callbacks, `/sbin/umount` status, exact kernel inventory, and
PortableFS reconciliation. Check ordinary refusal and explicit force
independently, eventual cleanup, and a fresh attach incarnation. A test-only
deactivate/unload error injected after cleanup may distinguish framework
bookkeeping from kernel removal; it must not become a production policy switch.
Neither unit fixtures nor static framework inspection qualify these outcomes.
Do not restart fskitd or disturb existing mounts to obtain this evidence.
