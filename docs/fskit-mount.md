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

### Terminal enforcement does not withdraw kernel state

When the Mac's session ends, is fenced, or loses its daemon, the daemon stops
answering from its caches, stops publishing replies, and the extension fails
every waiting callback. That bounds what PortableFS serves. It does not
synchronously remove names, attributes, or pages the macOS kernel already
holds for the mount; processes on that Mac can observe retained kernel state
until the mount is unmounted. PortableFS does not unmount automatically on
fence. The authority's retained writer exclusion keeps every other client from
writing while the old daemon could still serve; it does not revoke the old
Mac's kernel caches.

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

FSKit delivers no fsync, directory-sync, or `F_FULLFSYNC` callback; the
mutation callbacks are the only events that can carry durability. Every
successful FSKit mutation reply therefore waits until its effect is durable on
the authority: data, size, attributes, and namespace changes, including new
empty files and unlinks. A handle-backed mutation full-fsyncs its retained
description; a handleless mutation uses `syncfs` on the authority's retained
XFS-root description, whose error and latency scope is the whole XFS cell (see
[COMPATIBILITY.md](../COMPATIBILITY.md#two-limits-that-apply-to-every-deployment)).
A failed or uncertain reply is not a durability receipt, and a failed storage
sync fences the store; there is no success after it.

Writes are direct: each callback chunk of up to the negotiated maximum write is
one positioned authority WRITE, without append, sync, delegation, flush
sequence, or lock owner. There is no fragmented or staged write.

`write(2)` still returns at kernel page-cache acceptance, as POSIX permits. The
kernel pushes those pages as write callbacks on fsync, close, unmount, or memory
pressure. A native `fsync` or `F_FULLFSYNC` is durable only if macOS pushes the
file's dirty pages as callbacks, waits for every reply, and reports their
errors; ordinary unmount needs the same drain. That is host-kernel behavior and
is not yet qualified on either release. Per-callback durability is necessary
for the guarantee but does not prove it. A forced unmount can discard pages the
kernel accepted but never delivered.

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
admits at most 128 concurrent callbacks; terminal loss fails that window, wakes
every waiter, and revokes outstanding tickets.

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
terminal state. Only an explicit `--force` requests forced revocation, with the
data-loss boundary above. A forced unmount parks no recovery job and keeps no
replay record: the daemon acknowledges it with an empty response, and pages the
kernel never delivered are gone.

After exact absence of the original kernel mount is observed, the daemon
delivers the absence proof on the original CONTROL transport without first
draining DATA, and hands unsent cleanup to session teardown. Kernel absence,
proof delivery, and release cleanup are reported separately; a failed cleanup
does not claim the mount is still live. A poisoned or lost session is never
reconnected to submit evidence. An accepted proof clears durable membership and
the session's cache-proof obligation; writer exclusion still waits for admitted
storage work to drain.

## Local topology

```text
portablefs CLI -- owner-private control socket --> portablefsd
portablefsd    -- pfslocal 2.0 socket -----------> FSKit extension
FSKit extension <-------------------------------> macOS kernel
```

The daemon owns authority credentials, sessions, and the metadata cache; the
extension owns FSKit item identity and kernel callbacks and keeps no second
metadata cache. `pfslocal` is exactly version 2.0, paired by the sealed release:
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

The CLI and app require the daemon's exact paired release identity before any
operational request; a foreign or stale daemon is left untouched and the command
fails with clean-stop guidance. To replace a service, the host first
authenticates the outgoing daemon's executable, code signature, sealed release,
and socket peer, then uses lifecycle v1 to read its inventory and to stop it only
if idle; it never assumes the outgoing release speaks the incoming operational
protocol. An owner the host cannot authenticate is never stopped. The daemon
state singleton is one canonical flock inode that is never unlinked or replaced;
the host holds it across unregistration so no daemon can start between the
absence proof and the stop. A holder stuck in kernel exit blocks startup until
the kernel releases it.

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

Not yet qualified on native macOS 26 and 27:

- first usable proof before readiness, terminal enforcement, and the callback
  window under real teardown;
- no product-owned mount-root descriptor, one unforced unmount with real
  `EBUSY` under normal Finder and Spotlight activity, and explicit force;
- buffered-I/O delivery for `fsync`, `F_FULLFSYNC`, and unmount;
- power-cut recovery of the FSKit authority handler
  ([power-loss-testing.md](./power-loss-testing.md)) and suspend/resume;
- the Mac plus Linux-peer matrix, run against already-mounted paths:

```bash
scripts/coherence-matrix-macos.sh --mount-a /path/on/mac \
  --remote user@linux-host --remote-mount /path/on/linux
```
