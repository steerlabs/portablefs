# The FSKit qualification mount (macOS)

Status: **non-shipping qualification path; production refuses before Attach**

No currently documented FSKit version can satisfy PortableFS protocol 5's exact
source-publication and peer-invalidation boundaries. An ordinary
`portablefs mount` on macOS therefore fails at the platform gate before starting
portablefsd or contacting the authority. The shipping extension independently
refuses before socket resolution, and the shipping daemon refuses a direct
`EnsureAttach` before constructing an authority transport. There is no fallback
transport or degraded cache policy.

The mechanics below describe the retained SDK-26/SDK-27 development and
separately signed qualification path. They are useful for protocol and live-
kernel testing, but they are not a production mount contract.

`--strategy auto` (the default) resolves to `fskit` on macOS and `fuse` on
Linux; an explicit `--strategy fskit` requires darwin, and an explicit
`--strategy fuse` requires linux. Those are the only strategies, and the choice
is a pure platform decision that never depends on installed packages or mutable
host state (`vcs/internal/mounthost`).

What is proven differs by layer. Credential shape, daemon-owned authority
sessions, the kernel mount scheme, and teardown have qualification coverage.
The synthetic SDK-26 cache machinery and SDK-27 data-cache adapter also have
unit and targeted live evidence. None supplies the missing documented peer
namespace/attribute invalidator, and SDK 26 additionally cannot return complete
source post-mutation attributes. The exact support boundary is in
[macos-26-coherence-contract.md](./macos-26-coherence-contract.md). A current
Mac must not be treated as a supported shared-write peer.

## FSKit API And Deployment Track

The shipping app, development harness, and Swift package compile from a macOS
26.0 deployment baseline. The SDK-26 qualification adapter uses
`FSVolume.Operations`,
`OpenCloseOperations`, `ReadWriteOperations`, `XattrOperations`, and
`PathConfOperations`. Those protocols cannot represent the complete source
result contract and are not a production API for PortableFS, regardless of
their deployment availability. Apple's June 2026 documentation deprecates them
in favor of the new
[`Handler`](https://developer.apple.com/documentation/fskit/fsvolume/handler)
family.

The replacement handlers, including
[`DataCacheHandler`](https://developer.apple.com/documentation/fskit/fsvolume/datacachehandler),
are beta API for the next OS/SDK track and are not present in the stable macOS
26.5 SDK. The separate SDK-27 adapter compiles against those symbols and can
reuse `VolumeCore`, but `DataCacheHandler` covers only retained item data. It
does not establish exact peer namespace or inode-attribute invalidation.

Before any future support claim, the final SDK must expose every missing
primitive and a separately compiled adapter must pass the signed live-kernel
source/peer namespace, data, attribute, rename, unlink, mapping, and failure
matrix. `#available` cannot make unknown SDK symbols compile, and a compiler
guard that hides an uncompiled implementation is not verification. See
[macos-27-native-coherence.md](./macos-27-native-coherence.md) for the SDK-27
data-cache contract and the namespace and attribute rows that remain missing.
The ordinary CLI refuses every current macOS version before authority Attach.
Only the separately signed and build-stamped SDK-27 qualification lane can
select the native candidate policy; the stamp does not admit SDK 26, macOS 28,
or a shipping extension.

Apple's stable `FSVolume.OpenModes` contains only read and write access bits; it
does not carry `O_APPEND`. That is the append boundary described under
[consistency-model.md](./consistency-model.md).

## How a qualification mount happens

This transaction is reachable only from explicit development/qualification
composition. The production gate runs before step 1.

Three cooperating pieces:

```text
portablefs mount ──control socket──▶ portablefsd ◀──frontend socket── FSKit extension ◀─ kernel
      (CLI)        (HTTP over UDS)  (per-user daemon)    (pfslocal)   (PortableFSExt.appex)
```

1. **Ensure the daemon.** The CLI probes the external owner-private
   `portablefsd` control socket under
   `~/.local/state/portablefs/portablefsd/control.sock`
   (`GET /healthz`) and requires an exact `/v1/identity` match for the
   CLI/daemon release, exact daemon executable SHA-256, private control
   protocol, and `pfslocal` major protocol. A healthy compatible daemon is
   adopted — the daemon is per-user and multi-attach, so one instance serves
   every qualification mount. An incompatible
   live daemon fails closed with clean-stop guidance; the CLI never replaces it
   automatically. Otherwise the unentitled CLI asks `NSWorkspace` to launch the
   exact app bundle that contains it, with running-app substitution disabled,
   and waits for the host's registered ServiceManagement agent. The
   asynchronous `NSWorkspace` completion callback is not an identity or
   readiness proof: a bounded callback timeout is treated as ambiguous and may
   continue only into the exact daemon control identity check below. An explicit
   callback error is a launch failure. The native request runs only on the
   process main thread and pumps the main RunLoop until the callback or bounded
   timeout; a wrong-thread call is refused before issuing the request. The CLI never starts
   a daemon directly and never enters the app-group container. The daemon must be the
   exact executable sealed at
   `Contents/Library/LaunchAgents/PortableFSDService.app/Contents/MacOS/portablefsd`
   in the app that contains the canonical real `portablefs` executable.
   The CLI pins and hashes that file and requires the running daemon to report
   the same executable identity; it never searches `PATH` or accepts an
   executable override.
2. **Register the attach.** `POST /v1/attaches` on the control socket carries
   everything the daemon needs to own the authority connection itself: the
   resolved authority URL, the single-use volume mount capability, and the
   transport contract — exactly one of `tls-private-ca` (bounded CA PEM +
   SHA-256 + exact server name) or `tls-system-pki` (system roots + exact server
   name). Plaintext is refused: a v3 authority session is mutually authenticated
   TLS 1.3 and cannot be established over anything else, and an empty CA never
   means plaintext. The request also carries the v3 block: the mutual-TLS client
   certificate and key the daemon will present, the declared cache policy, the
   cached-name capacity and repair budget the authority sizes its visibility
   barrier from, and this mount's routing revision. The daemon answers with an
   attach reference.
3. **Mount.** The CLI hands the kernel that reference:
   `/sbin/mount -t pfs dev.portablefs.oss://<attachRef> <mountPath>`. The
   filesystem type and globally scoped generic-resource scheme are separate,
   signed identity axes: FSKit routes the URL by `FSSupportedSchemes`, while
   statfs publishes `FSShortName`. The enabled FSKit extension serves the mount
   by dialing the daemon's frontend socket inside the canonical account home's
   PortableFS app-group container
   (`Library/Group Containers/B47U2LLKHW.pfsoss/portablefsd/pfs.sock`, relative
   to that home). The app group is load-bearing, not a convention: the macOS app
   sandbox permits `connect(2)` on a unix socket only inside app-group container
   paths, so a socket anywhere else — `/tmp` included — is unreachable from the
   sandboxed extension no matter what file-access exceptions it holds. The
   daemon the CLI ensures must therefore serve exactly that container socket.
   macOS also protects another team's group-container path from an ordinary
   unentitled process. Exactly the signed host, embedded daemon, and extension
   carry the same single app-group entitlement. The CLI explicitly carries no
   app-group entitlement and uses only the external private control socket.
   There is no alternate container bypass (see the overrides below).

Before the kernel mount the CLI calls a versioned daemon control endpoint. The
authorized daemon then performs one preflight on the *same* frontend socket the
registered extension will dial — `Hello` plus `Resolve(attachRef)` —
so the one foreseeable misconfiguration (the CLI attached to daemon A while the
installed extension's Info.plist points at daemon B) surfaces as a typed error
rather than an opaque I/O error afterwards.

The qualification command returns only after two matching kernel mount-table proofs surround
the exact readiness witness declared by the cache policy. macOS 26's
`macos26-synchronous-vfs-repair-v1/v2` witness is the daemon opening, attesting,
and retaining the mount-root descriptor its VFS repair channel needs. macOS
27's qualification-only `fskit-native-revocation-v1` witness is instead a live
`portablefskit` connection which completed `Hello` and `Resolve` for this exact
attach. The native policy never opens the mounted path and never installs a
root-descriptor repair channel. A control self-preflight uses a different
client name and cannot satisfy this witness. In both cases, a changed second
kernel identity is a substitution failure, not a retry.

After that proof the command daemonizes (state under
`~/.local/state/portablefs/mounts/`).
`portablefs umount` invokes one daemon-owned `POST /v1/attaches/{ref}/unmount`
transaction. For authority-v3 it begins planned detach, proves the exact
`dev.portablefs.oss://<attachRef>` kernel mount, and issues a normal kernel
unmount. That pass runs FSKit synchronize; the daemon accepts only success or
exact `EBUSY` after synchronization, which authorizes the forced vnode-revocation
pass required for PortableFS's retained repair-root descriptor. It then proves
mount-table absence, delivers that evidence to the authority, and only then
removes the local attach. A failure preserves the attach and its exact recovery
evidence; no second delete or path-based unmount can mutate one side of the
boundary without the other. `DELETE
/v1/attaches/{ref}` is refused for that reason — it cannot prove exact kernel
teardown.

## What the qualification daemon owns

`portablefsd` is the v3 data plane, and the split of responsibility across the
local socket is the point of the design.

The daemon dials the authority over mutual TLS with no mode fallback. It owns
the authority session and everything derived from it: the resolved epoch and
session identity, replay of the ordered visibility stream, the liveness
keepalive, the routing revision the attach is pinned to, and the fencing verdict
when the session ends. Over `pfslocal` it exposes to the FSKit extension only a
versioned, ordered local stream — a derived cache contract plus visibility
obligations with cursor and blocked acknowledgments. The mutual-TLS identity,
the mount capability, and the authority connection never cross the local socket,
so a compromised or merely buggy extension cannot present the volume's
credentials to anything.

The attach declares, and the authority validates:

| field | value | meaning |
|---|---|---|
| cache policy | one exact qualification policy | SDK 26 tests use `macos26-synchronous-vfs-repair-v2`; the separately tagged SDK-27 lane uses `fskit-native-revocation-v1` |
| cached-name capacity | 65536 | the bound on directory bindings this mount may hold cached (`mountv3.CachedNameCapacity`) |
| repair budget | 15s | the per-phase deadline the mount commits to before the authority may consider it blocked (`mountv3.RepairBudget`) |
| routes revision | the empty rule set's revision | see [Machine-Local Dirs](#machine-local-dirs) |
| client identity | mutual-TLS certificate and key | the identity the daemon presents to the authority |

The authority refuses any commitment larger than its own maxima, so a mount that
would over-promise fails at attach rather than at the first repair. What those
two numbers bound, what the barrier guarantees, and which live-kernel proofs are
still outstanding are specified in
[macos-26-coherence-contract.md](./macos-26-coherence-contract.md).

## Install and enable (qualification hosts only)

Live qualification requires the development or separately signed
qualification FSKit extension to be registered and enabled. Installing the
shipping app does not admit a production mount:

1. Build and install the separately signed qualification app with the exact
   qualification stamp/tag. Its installer uses the same canonical per-user app,
   CLI-link, and extension-registration transaction as the release package. An
   ordinary release install may prove packaging and registration, but its CLI,
   extension, and daemon still refuse a production mount.
2. Open System Settings → General → Login Items & Extensions, scroll to the
   Extensions section, and open the **File System Extensions** category (click
   its ⓘ). Enable the PortableFS extension there. Use the category view
   specifically: on macOS 26 the same toggle rendered in the per-app list is
   unreliable and can silently do nothing. This approval is a user-controlled
   macOS setting and cannot be automated.

FSKit extensions are user-space: no kernel extension, no reboot, no sudo.
Exactly one installed qualification provider may claim the `pfs` fs type during
a live run. The installer refuses publication when it finds another provider,
such as the dev harness's `PortableFSDev.appex`; remove that provider explicitly
before installing the intended qualification artifact.

The release archive is one `PortableFS.app`. Its unentitled CLI lives at
`Contents/Helpers/portablefs`; its entitled daemon lives only inside
`Contents/Library/LaunchAgents/PortableFSDService.app`, next to the sealed
RunAtLoad/KeepAlive LaunchAgent plist; and its FSKit extension lives under
`Contents/Extensions/` as exactly one `PortableFSExt.appex`. The installer verifies that code
hierarchy, takes the exclusive per-user mount lifecycle lock, rechecks exact
kernel mounts, mount records, running PortableFS processes, and canonical
sockets. On upgrade, the installed host alone unregisters the old service,
hands the installer a one-use prepared token, and exits; the installer then
reacquires both exclusive guards, re-inventories, and atomically exchanges the
whole bundle while retaining the displaced release. It retires that rollback
copy only after the new host and daemon prove the exact sealed release.
Cleanly unmount volumes before upgrading.

## Daemon Lifecycle

- **Per-user, multi-attach.** One launchd-managed `portablefsd` serves every
  attach for the user. The CLI adopts it only when its exact external control
  identity is compatible and never duplicates or automatically replaces it.
- **Start.** When nothing healthy answers, the CLI launches the exact containing
  app through `NSWorkspace`; the host owns registration of the always-running
  ServiceManagement agent. Launch completion alone is never success; the CLI
  requires the exact embedded daemon release on the owner-private control
  socket within the bounded wake interval. There is no direct helper spawn or weaker fallback.
  A
  crashed daemon or reboot can leave socket inodes behind; after acquiring both
  the state, external-control, and app-group-frontend singleton locks, the new daemon reclaims only a private,
  same-UID, single-link canonical socket that refuses a connection. It moves
  that exact inode aside with an atomic no-replace rename before removal, so a
  concurrent replacement is restored rather than unlinked.
- **Roots.** Control lives under the canonical owner-private daemon state.
  The frontend socket lives under the app-group because only the sandboxed
  qualification FSKit peer consumes it. The SDK-26 qualification policy also
  uses the canonical mount-root handoff socket there; the SDK-27 native
  qualification policy has no such channel. These roots are independently
  pinned, locked, and safely reconciled; the CLI never resolves the app-group
  root.
- **Sockets are the authentication boundary.** The daemon creates the socket
  directory 0700 and the sockets 0600; same-user filesystem access is the
  control plane's entire auth model — there is no bearer token on the control
  API. Authority credentials live only in daemon memory and are never written
  into the daemon's durable attach registry, so a restarted daemon revives
  attaches inert.
- **The initial mount capability is single-use.** In standalone mode, expiry
  ends the session and a fresh capability plus remount re-establishes it. In
  hosted mode, `POST /v1/attaches/{ref}/credential` can carry the exact next
  nonzero authorization sequence, a session-bound grant, and a renewed
  same-key client certificate. The daemon invokes the authority's
  `Reauthorize` operation before publishing that credential. It cannot broaden
  access, skip a sequence, change the mount key, or turn keepalive into
  authorization. The endpoint also retains its earlier pending-attach recovery
  role after a daemon restart.
- **Outlives qualification mounts.** Exact unmount durably removes the attach
  but leaves the launchd agent running for the next qualification run.
  `portablefs daemon stop` is refused on macOS; only the host-owned update
  transaction may prove zero kernel mounts and zero daemon attaches, unregister
  the agent, and permit app replacement.
- **Two-phase updates.** The installer wakes the exact installed host and uses
  a credential-checked owner-private Unix-socket session. Before unregistering,
  that host durably records a five-minute activation lease containing the exact
  old and target release identities, phase, and SHA-256 of a one-use random
  token; plaintext token material remains only in installer memory. The host
  proves an empty inventory, authenticates the daemon on its control socket,
  and binds a kernel process witness to the peer's exact audit-token PID and
  PID version. It then unregisters the old agent and requires Service
  Management to report `notRegistered`, all three runtime socket names to be
  absent, and the exact witnessed execution to deliver `NOTE_EXIT`; unrelated
  or uninspectable processes are never scanned. If a newly registered daemon
  failed before it exposed an authenticated control peer, the equivalent
  no-publication proof is a safely pinned, nonblocking acquisition of the
  canonical state-singleton lock, which the daemon acquires first and releases
  last. Only then does the host release its guards and return the token. The
  installer takes both account and mount exclusives, repeats the exact
  inventory, and token-commits the old host's exit. Every host-exit path first
  closes the update listener and removes only its pinned, owned socket inode,
  then re-proves the canonical name absent before acknowledging or terminating.
  A replaced or otherwise unsafe inode leaves the durable phase intact and the
  host running; it is never unlinked. If the commit reply is lost, the installer
  retains the plaintext token. An exact `old-absent` lease plus disappearance of
  the authenticated prepared-host PID enters the ordinary tokenized
  prepublication rollback; an exact `rollback-complete` marker is accepted only
  after the installed old hierarchy and live daemon full tuple are re-proved.
  A stale socket pathname alone is neither process identity nor transaction
  authority.

  While the host remains live, its accept loop re-proves that exact listener
  inode before every attempt and retries only `EINTR` or `ECONNABORTED` from an
  abandoned queued client. Any other accept failure unpublishes the listener
  fail-closed instead of recreating it in-process.

  The target host sees the durable lease before normal startup, so it cannot
  register merely because the app was launched. A distinct same-UID,
  token-bound session makes it register and live-prove only the exact sealed
  target. The installer independently proves the same control identity and
  retains the displaced app until that activation is accepted. An acknowledged
  activation failure first unregisters and fences the target; only then does an
  atomic exchange restore the displaced app and a third token-bound session
  live-prove the old release. Cancel before old-host commit similarly restores
  the old service while holding an empty-inventory guard. Wrong, replayed,
  expired, malformed, or ambiguous state never triggers registration or
  rollback; both exact app copies and the lease remain for reconciliation. No
  mutable notification, launch argument, `launchctl`, daemon self-unregister,
  or shell-accessible app-group path participates.

  A completion reply may be lost after the host has durably replaced the active
  phase with `target-complete` or `rollback-complete`. The installer treats that
  as complete only when the owner-private terminal marker still matches the
  token hash and exact old/target tuples, transaction finalization has already
  retired the alternate app, the installed signed hierarchy and service tuple
  equal the marker's active release, and the live daemon independently proves
  the full tuple; the mutable marker and identity are rechecked. The terminal
  marker does not expire or disappear. A later authenticated prepare may
  replace it only after re-proving the exact sealed, registered, and live active
  release. Any weaker observation remains ambiguous. Conversely, an
  expired/orphaned nonterminal lease never authorizes automatic registration,
  fencing, deletion, or rollback: the host stays fail-closed and requires
  explicit operator recovery. There is intentionally no tokenless stale-lease
  recovery path in this release.

  Activation reply loss is also phase-exact. A ready reply that cannot be
  validated causes the host to fence itself to `rollback-absent`; the installer
  waits for that token-bound phase plus disappearance of the authenticated host
  PID and listener before restoring or retrying. Once acceptance is durable,
  the service is never implicitly fenced. Instead, the installer reconnects
  with `resume-target` or `resume-rollback`, carrying its still-memory-only
  token and both release identities. The host accepts that request only for the
  corresponding exact active phase and only after re-proving its sealed and
  live release, then exposes completion on the new connection. Duplicate,
  replayed, wrong-token, expired, terminal, or cross-release resumes cause no
  state change.

  The installer also treats time as transaction state, not as unrelated
  request timeouts. Before launching an activation host or sending
  Accept/Complete, it admits that child operation only when the shared parent
  deadline still contains the full downstream reconciliation reserve plus a
  fixed scheduling/cancellation margin at each nested boundary. A late
  host action can therefore be resolved after its child request expires. If a
  ready release lacks enough time to accept safely, the installer uses the
  official token-bound Fence, proves the exact host and listener absent, and
  restores or retains the rollback transaction; it never starts an irreversible
  edge with no time left to determine its durable outcome.

The complete control API is `/healthz`, `/v1/identity`, `/v1/attaches`,
`/v1/attaches/{ref}`, `/v1/attaches/{ref}/frontend-preflight`, `/v1/attaches/{ref}/unmount`,
`/v1/attaches/{ref}/credential`, `/v1/attaches/{ref}/sync`, and
`/v1/lifecycle/stop-if-idle` (`vcs/internal/portablefsd/control.go`).

## Signed runtime identity

The filesystem type, resource scheme, app group, sockets, CLI, and daemon form
one signed release identity. `PORTABLEFS_FSKIT_TYPE` may assert the compiled
`pfs` type, but cannot change it. `PORTABLEFS_FSKIT_SOCKET`,
`PORTABLEFS_FSKIT_CONTROL_SOCKET`, and `PORTABLEFS_FSKIT_DAEMON` are rejected.
A fork or development product compiles its own app-group identity and packages
its matching extension, CLI, and nested daemon service as one sealed hierarchy
rather than selecting any of them from the environment.

The OSS resource scheme is the immutable `dev.portablefs.oss`; it is not an
environment override. The matching app and CLI are installed atomically and the
installer requires the extension to advertise exactly that one scheme. An
embedder uses its own extension metadata and matching mount client instead of
aliasing the OSS scheme.

Changing the frontend socket only works with an extension whose Info.plist
resolves the new path, and any custom location must still be inside an app-group
container the extension is entitled to — the sandbox denies unix socket connects
everywhere else. The stock PortableFS.app extension expects the default, so with
it these overrides are read-only facts, not knobs. The packaging build stamps
one `PORTABLEFS_APP_GROUP` value derived from the signing team into the
extension Info.plist, its signed entitlement, the CLI, and the daemon
(`portablefs lifecycle identity` and `portablefsd -identity-json` print it).
The host, extension, and daemon signatures must each contain that same single
app-group entitlement. The CLI must contain none. Packaging and installation
reject a missing, extra, or mismatched privileged entitlement and reject an
app-group entitlement on the CLI.
Forks set their signing team once; there are no independent source constants to
keep synchronized.

## Write Path

This section records qualification-adapter behavior, not a production macOS
durability promise. There is no PortableFS-managed or offline write-back layer
and no write-mode knob. FSKit still has its ordinary kernel page cache:
`write(2)` may return when that cache accepts bytes, before the framework sends
them to the daemon. In the qualification adapter, `fsync`, FSKit synchronize,
and normal unmount wait through the authoritative server descriptor.
PortableFS itself buffers no durable tail on the Mac, so:

- there is no local WAL, no flush interval, no group-sync window, and no
  unshipped tail that could be lost with the machine;
- there is no "accepted but not yet durable" state to reason about, and no
  replay on the next attach, because there was never a client-side record to
  replay;
- `POST /v1/attaches/{ref}/sync` is exactly the authority's own `SyncVolume`
  (backed by `syncfs(2)` on the authority host). Success means the authority has
  made this volume durable, and the reply's pending counters are structurally
  zero — there is never a PortableFS-managed backlog to report. A normal kernel
  unmount reaches this boundary through FSKit synchronize;
- `portablefs umount --force` has no PortableFS tail to park, but it deliberately
  skips the trustworthy kernel synchronize pass. It is a revocation path, not a
  durability claim.

These server-side facts do not make a current FSKit-mounted path a safe
multi-machine handoff point: the missing source and peer cache primitives remain
decisive. `--fast` is retired and cannot bypass that boundary.

The cost side is equally plain: every mutation is a round trip to the authority,
so latency to the authority is the write latency. See
[performance.md](./performance.md).

## Extended Attributes

The production XFS authority exposes a deliberately read-only portable xattr
surface: read/list and removal of pre-existing portable `user.*` attributes are
real authority operations, while set is refused because XFS attribute-fork
blocks are outside project-quota accounting. Linux receives `EOPNOTSUPP`
directly. In the qualification pfslocal contract, Resolve advertises
`xattrs=true` and `xattr_set_supported=false`; the adapter validates the item
and name and refuses set/create/replace/upsert locally without emitting a daemon
mutation. Its FSKit boundary returns Darwin's distinct `EOPNOTSUPP` (102)
instead of internal `ENOTSUP` (45), because XNU uses 45 to trigger AppleDouble
`._*` emulation. That tested mapping is not a production mount surface while
the platform gate refuses before Resolve.

## Machine-Local Dirs

Machine-local routing is a Linux capability today. A qualification macOS v3
attach **refuses local-dir and graft options outright** — the daemon rejects the
whole attach rather than accepting an option it would not serve — and the CLI refuses
`--local-dir` unconditionally on every platform, because a per-machine route
would hide from one machine a directory every peer still treats as shared, with
no revision recording it and no peer able to observe it.

The consequence is a hard, stated boundary rather than a partial
implementation:

- routes are declared volume-wide in the volume's `.portablefs/local-dirs`, and
  the revision a mount presents at attach is the hash of that declaration;
- `portablefsd` does not join the route adoption protocol, so a qualification macOS attach
  declares the **empty** rule set's revision;
- the authority refuses a mount whose revision is not the volume's active one,
  naming both revisions and the volume's canonical rules. So **a volume that
  declares machine-local routes mounts from Linux**, not from a Mac. Removing
  the declaration is the only other way to mount it here;
- `--no-local-dirs` refuses a declaring volume rather than ignoring its topology
  and serving a different one.

The mounted `.portablefs` namespace is readable and not writable, on every
platform: the authority marks the subtree protected by capability, so create,
link, and rename into it are refused before a capability could be minted.
Reading stays open because every client must read the declaration to learn the
revision it has to present at attach. The only way the declaration changes is
the authority's admin `ApplyRoutes` call, which moves the revision through the
same barrier every mount is pinned to.

The full graft contract — shadow-without-synthesize, `EXDEV` at the boundary,
`EBUSY` on a shared-ancestor rename, and confinement to an open backing-directory
capability — is in
[graft-security.md](./graft-security.md) and
[xfs-authority-architecture.md](./xfs-authority-architecture.md#machine-local-routing), and it is served by the Linux FUSE
frontend.

## Qualification troubleshooting

The cases below apply only after deliberately building and installing a
qualification artifact. An ordinary production command should stop at the
unsupported-FSKit refusal and must not reach these states.

### The extension is not enabled

Symptom: `portablefs mount` fails, and the CLI rewrites the kernel's opaque
`mount -t pfs` refusal into the fix:

```text
the "pfs" FSKit extension is not enabled: install PortableFS.app, then in
System Settings → General → Login Items & Extensions open the FILE SYSTEM
EXTENSIONS category (the per-app list's toggle is unreliable on macOS 26)
and enable it, then retry
```

Do exactly that. If the toggle is missing from System Settings, launch
PortableFS.app once more so LaunchServices registers the appex, then reopen
System Settings. If two PortableFS extensions are listed (app and dev harness),
remove the unintended provider and reinstall; a valid qualification setup has
exactly one installed `pfs` provider.

If another enabled PortableFS-based product exists, it may remain enabled only
when both its `FSShortName` and `FSSupportedSchemes` differ from the OSS
identity. Sharing a generic-resource scheme is ambiguous even when filesystem
types differ, so the installer rejects either kind of collision.

### "Final mount step ended with error: … already exists"

Symptom: the module resolves, the extension activates, and macOS itself fails
the last step of `mount -t pfs` with a file-exists error, for every volume and
every mount path.

This is FSKit host state, not PortableFS configuration. `fskitd` retains a
record of a mounted volume until the extension completes `deactivateVolume`;
an extension that dies abnormally — killed mid-teardown, or replaced on disk
while its volume was live — leaves that record behind, and it can wedge the
module's future activations. Registering, rebuilding, or toggling the
extension does not clear it. Restart the FSKit host daemon (`sudo pkill
fskitd`; launchd relaunches it on demand) or reboot.

PortableFS reduces its exposure to this state by scoping each mount's FSKit
volume identity to the attach — a record left by a dead incarnation can never
collide with a live one by name — but the host daemon itself can still wedge
after repeated abnormal teardown, and only its restart recovers it.

### Enabled, but "Loading resource: … Input/output error"

The module is enabled and the kernel reached it, but the extension's
`loadResource` failed — almost always because it could not reach `portablefsd`'s
frontend socket. Every process independently resolves the exact signed
app-group container through Foundation, and the CLI and daemon reject any
different root or socket. A rebuilt extension can also linger as a stale
process from a previous version; `pkill -x
PortableFSDev` (or the qualification app's extension name) forces a fresh
instance on the next mount.

### A foreign daemon owns a socket

The CLI requires both liveness and an exact control identity on the control
socket. A stale dev build or older release is refused before an attach is
created. The external control socket is under the canonical account's private
state root; the frontend sockets are under the signed app-group root.

Stop the foreign daemon only after cleanly unmounting its attaches and use the
host-owned agent lifecycle; the CLI never replaces or directly spawns it.
A development extension that needs a different container must use a distinct
compiled app-group identity and matching signed helper pair.

### The daemon does not become healthy

The qualification mount fails after 15 seconds with the log path. Read
`~/.local/state/portablefs/portablefsd.log` — the daemon logs why it could not
start, most often a socket path it cannot create or bind.

### The qualification mount is refused for its routing revision

The volume publishes `.portablefs/local-dirs` and this Mac declared the empty
rule set. That is the documented boundary above, not a misconfiguration: mount
the volume from Linux, or have an administrator remove the declaration with
`ApplyRoutes`.

## Why there is no fallback

Earlier releases fell back to a loopback bridge over the macOS kernel's built-in
network-filesystem client when the native mount was unavailable. That fallback
was removed because it silently delivered a weaker consistency model than the
one this system exists to provide: the kernel client cached reads and attributes
for up to ~60 seconds regardless of server validators, and concurrent appends
from two machines to one shared file collapsed into whole-file
last-writer-wins uploads — precisely the shapes agent workspaces hit (tailing a
log another machine appends to, two mounts sharing state files). A mount that
sometimes has those semantics is worse than an explicit platform refusal.
Production macOS currently has no admitted transport; qualification uses FSKit
only and never substitutes the removed loopback path.

The framework boundaries stay explicit rather than being papered over. SDK 26
has no general kernel-cache invalidation primitive and cannot publish complete
source result attributes. SDK 27 adds data-cache control and richer results but
still lacks exact peer namespace and inode-attribute invalidation. Current
FSKit write callbacks also do not expose `O_APPEND` intent. The
callback-serialized and native adapters remain qualification instruments; none
of these gaps is converted into a compatibility policy, heuristic repair, or
production fallback. See
[macos-26-coherence-contract.md](./macos-26-coherence-contract.md).
