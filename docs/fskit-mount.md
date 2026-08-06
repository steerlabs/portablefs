# The FSKit Mount (macOS)

`portablefs mount` on macOS has exactly one transport: the `fskit` strategy.
The CLI drives the same `portablefsd` + FSKit extension pair the PortableFS
menu-bar app uses. There is deliberately no fallback transport — a Mac that
cannot serve an FSKit mount fails with install guidance instead of degrading to
a weaker consistency model.

`--strategy auto` (the default) resolves to `fskit` on macOS and `fuse` on
Linux; an explicit `--strategy fskit` requires darwin, and an explicit
`--strategy fuse` requires linux. Those are the only strategies, and the choice
is a pure platform decision that never depends on installed packages or mutable
host state (`vcs/internal/mounthost`).

What is proven differs by layer, and this document is explicit about the
boundary. The credential shape, the daemon-owned authority session, the kernel
mount scheme, and the unmount transaction are implemented and tested here. The
kernel-cache half is composed and wired — both client indexes, a real publication
barrier, the installed repair gate, and armed data invalidation — but it runs
under an explicitly declared compatibility cache policy with a stated fidelity
target, one known residual race, and a set of proofs that still require a live
kernel. `VolumeCore` admits exactly that declared policy and fails `ENOTSUP` on
any other, including the macOS 27 native one. Every open gate is enumerated in
[macos-26-coherence-contract.md](./macos-26-coherence-contract.md). Read that
document before treating a Mac as a shared-write peer.

## FSKit API And Deployment Track

The production app, development harness, and Swift package all target macOS
26.0. That release uses the macOS 26 `FSVolume.Operations`,
`OpenCloseOperations`, `ReadWriteOperations`, `XattrOperations`, and
`PathConfOperations` protocols. They remain the compatible production API for
the deployed OS even though Apple's June 2026 documentation deprecates them in
favor of the new
[`Handler`](https://developer.apple.com/documentation/fskit/fsvolume/handler)
family.

The replacement handlers, including
[`DataCacheHandler`](https://developer.apple.com/documentation/fskit/fsvolume/datacachehandler),
are beta API for the next OS/SDK track and are not present in the stable macOS
26.5 SDK. They are therefore a macOS 27 release gate, not a reason to raise this
release's deployment target or to make the macOS 26 adapter depend on beta
symbols. `VolumeCore` deliberately owns all pfslocal, identity, open handle, and
filesystem semantics independently of the adapter, so a future
availability-guarded macOS 27 handler can reuse the same tested core.

Before claiming macOS 27 support, build that handler in a separate SDK-27 source
target and CI lane against the final SDK, negotiate the least-permissive correct
`DataCacheHandler` coherency mode, drive remote invalidations through the
handler's cache-state API, and pass the signed live-kernel
read/write/mmap/rename/unlink/remote-invalidation matrix on macOS 27.
`#available` cannot make unknown SDK symbols compile, and a compiler guard that
hides an uncompiled implementation is not verification. The macOS 26
compatibility policy is selected explicitly, never as an automatic fallback, and
must pass its own matrix on macOS 26; there is no conditional beta
implementation or silent downgrade in the binary.

Apple's stable `FSVolume.OpenModes` contains only read and write access bits; it
does not carry `O_APPEND`. That is the append boundary described under
[consistency-model.md](./consistency-model.md).

## How A Mount Happens

Three cooperating pieces:

```text
portablefs mount ──control socket──▶ portablefsd ◀──frontend socket── FSKit extension ◀─ kernel
      (CLI)        (HTTP over UDS)  (per-user daemon)    (pfslocal)   (PortableFSExt.appex)
```

1. **Ensure the daemon.** The CLI probes the `portablefsd` control socket
   (`GET /healthz`) and requires an exact `/v1/identity` match for the
   CLI/daemon release, exact daemon executable SHA-256, private control
   protocol, and `pfslocal` major protocol. A healthy compatible daemon is
   adopted — the daemon is per-user and multi-attach, so one instance serves
   every mount, whether the CLI or the menu-bar app started it. An incompatible
   live daemon fails closed with clean-stop guidance; the CLI never replaces it
   automatically. Otherwise the CLI spawns one, detached into its own session so
   it outlives the mount process and serves later mounts. The daemon must be the
   exact `portablefsd` sibling of the canonical real `portablefs` executable.
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
   daemon the CLI ensures must therefore serve exactly that container socket
   (see the overrides below).

Before the kernel mount the CLI performs one preflight on the *same* frontend
socket the registered extension will dial — `Hello` plus `Resolve(attachRef)` —
so the one foreseeable misconfiguration (the CLI attached to daemon A while the
installed extension's Info.plist points at daemon B) surfaces as a typed error
rather than an opaque I/O error afterwards.

The command then behaves like every `portablefs mount`: it returns only after
the kernel reports the exact mount present and a real root enumeration succeeds,
then daemonizes (state under `~/.local/state/portablefs/mounts/`).
`portablefs umount` invokes one daemon-owned `POST /v1/attaches/{ref}/unmount`
transaction. That request freezes every frontend and control admission,
completes the final authority barrier, durably records the prepared detach,
proves the exact `dev.portablefs.oss://<attachRef>` kernel mount, unmounts it
in-process, and only then durably removes the attach. A failure preserves the
attach and its exact recovery evidence; no second delete or path-based unmount
can mutate one side of the boundary without the other. `DELETE
/v1/attaches/{ref}` is refused for that reason — it cannot prove exact kernel
teardown.

## What The Daemon Owns

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
| cache policy | `macos26-synchronous-vfs-repair-v1` | the declared macOS 26 compatibility cache policy (`vcs/internal/portablefsd/v3coherence.go`) |
| cached-name capacity | 65536 | the bound on directory bindings this mount may hold cached (`mountv3.CachedNameCapacity`) |
| repair budget | 15s | the per-phase deadline the mount commits to before the authority may consider it blocked (`mountv3.RepairBudget`) |
| routes revision | the empty rule set's revision | see [Machine-Local Dirs](#machine-local-dirs) |
| client identity | mutual-TLS certificate and key | the identity the daemon presents to the authority |

The authority refuses any commitment larger than its own maxima, so a mount that
would over-promise fails at attach rather than at the first repair. What those
two numbers bound, what the barrier guarantees, and which live-kernel proofs are
still outstanding are specified in
[macos-26-coherence-contract.md](./macos-26-coherence-contract.md).

## Install And Enable (Once Per Mac)

The strategy requires the PortableFS FSKit extension to be registered and
enabled:

1. Run the PortableFS installer (`portablefs install-macos-app`). It places the
   notarized app at the canonical per-user path `~/Applications/PortableFS.app`,
   links its embedded CLI into `~/.local/bin`, and launches that exact app so
   macOS registers its File System Extension.
2. Open System Settings → General → Login Items & Extensions, scroll to the
   Extensions section, and open the **File System Extensions** category (click
   its ⓘ). Enable the PortableFS extension there. Use the category view
   specifically: on macOS 26 the same toggle rendered in the per-app list is
   unreliable and can silently do nothing. This approval is a user-controlled
   macOS setting and cannot be automated.

FSKit extensions are user-space: no kernel extension, no reboot, no sudo.
Exactly one installed PortableFS provider may claim the `pfs` fs type. The
release installer refuses publication when it finds another provider, such as
the dev harness's `PortableFSDev.appex`; remove that provider explicitly before
installing the release app.

The release archive is one `PortableFS.app`. Its CLI and daemon live under
`Contents/Helpers/`, and its FSKit extension lives under `Contents/Extensions/`
as exactly one `PortableFSExt.appex`. The installer verifies that code
hierarchy, takes the exclusive per-user mount lifecycle lock, rechecks exact
kernel mounts, mount records, running PortableFS processes, and canonical
sockets, and atomically replaces the whole bundle plus CLI symlink. It never
updates a live app, daemon, or mount. Cleanly unmount volumes and quit the app
before upgrading.

## Daemon Lifecycle

- **Per-user, multi-attach.** One `portablefsd` serves every attach for the
  user. The CLI adopts a healthy daemon only when its exact control identity is
  compatible and never duplicates or automatically replaces it. CLI and app
  mounts can ride the same compatible daemon when they share sockets.
- **Spawn.** When nothing healthy answers, the CLI starts
  `portablefsd -frontend-socket ... -control-socket ...` with a state dir at
  `~/.local/state/portablefs/portablefsd`, detached, and waits up to 15 seconds
  for `/healthz` and a verified identity before failing with the log path. A
  crashed daemon or reboot can leave socket inodes behind; after acquiring both
  the state and socket singleton locks, the new daemon reclaims only a private,
  same-UID, single-link canonical socket that refuses a connection. It moves
  that exact inode aside with an atomic no-replace rename before removal, so a
  concurrent replacement is restored rather than unlinked.
- **Log.** A CLI-spawned daemon appends to
  `~/.local/state/portablefs/portablefsd.log`. Per-mount logs are separate,
  under `~/.local/state/portablefs/mounts/`. The menu-bar app invokes the same
  embedded CLI and does not own another daemon or state root.
- **Sockets are the authentication boundary.** The daemon creates the socket
  directory 0700 and the sockets 0600; same-user filesystem access is the
  control plane's entire auth model — there is no bearer token on the control
  API. Authority credentials live only in daemon memory and are never written
  into the daemon's durable attach registry, so a restarted daemon revives
  attaches inert.
- **The mount capability is single-use and is never renewed.** There is no
  credential rotation and no lease keeper. When a mount's credential ends,
  `portablefs mounts` reports it as `credential-expired`; mounting again with a
  fresh capability is what re-establishes the mount. `POST
  /v1/attaches/{ref}/credential` exists to hand a revived daemon back the exact
  credential recorded for an attach it is about to tear down, not to keep a live
  mount alive.
- **Outlives mounts.** Exact unmount durably removes the attach but leaves the
  daemon running for the next mount. A v3 attach carries no client-side
  durability debt, so a daemon with no attaches owns nothing and is safe to
  stop; `portablefs daemon stop` (`POST /v1/lifecycle/stop-if-idle`) refuses
  while any live attach exists.

The complete control API is `/healthz`, `/v1/identity`, `/v1/attaches`,
`/v1/attaches/{ref}`, `/v1/attaches/{ref}/unmount`,
`/v1/attaches/{ref}/credential`, `/v1/attaches/{ref}/sync`, and
`/v1/lifecycle/stop-if-idle` (`vcs/internal/portablefsd/control.go`).

## Environment Overrides

Defaults match PortableFS.app's extension. The socket overrides exist for dev
extensions that use a separate app-group container:

| variable | default | meaning |
|---|---|---|
| `PORTABLEFS_FSKIT_TYPE` | `pfs` | optional assertion of the release's signed filesystem type; a different value is rejected |
| `PORTABLEFS_FSKIT_SOCKET` | `~/Library/Group Containers/B47U2LLKHW.pfsoss/portablefsd/pfs.sock` | the daemon frontend socket the extension dials (resolved from `PFSAppGroupIdentifier` in the extension's Info.plist) |
| `PORTABLEFS_FSKIT_CONTROL_SOCKET` | `~/Library/Group Containers/B47U2LLKHW.pfsoss/portablefsd/control.sock` | the daemon control socket the CLI drives; setting a custom frontend socket implies a `control.sock` next to it unless this is set explicitly |

`PORTABLEFS_FSKIT_DAEMON` is rejected. A fork or development build packages its
matching CLI and daemon as one sibling pair rather than selecting code from the
environment.

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
Forks set their signing team once; there are no independent source constants to
keep synchronized.

## Write Path

There is no write-back cache and no write-mode knob. `write(2)` returns after
the authority has applied the bytes to XFS; `fsync` waits for the authoritative
server descriptor. Nothing is buffered on the Mac on the volume's behalf, so:

- there is no local WAL, no flush interval, no group-sync window, and no
  unshipped tail that could be lost with the machine;
- there is no "accepted but not yet durable" state to reason about, and no
  replay on the next attach, because there was never a client-side record to
  replay;
- `POST /v1/attaches/{ref}/sync` is exactly the authority's own `SyncVolume`
  (backed by `syncfs(2)` on the authority host). Success means the authority has
  made this volume durable, and the reply's pending counters are structurally
  zero — there is never a backlog to report. `portablefs umount` runs it before
  the kernel unmount;
- `portablefs umount --force` therefore has nothing to park. It gives up on
  proving the drain, not on data the Mac was still holding.

This is what makes a mounted path a safe handoff point between machines without
an explicit barrier discipline: an acknowledged write is already the volume's
current state for every other mount. `--fast` is retired and fails with a
pointer at this model.

The cost side is equally plain: every mutation is a round trip to the authority,
so latency to the authority is the write latency. See
[performance.md](./performance.md).

## Machine-Local Dirs

Machine-local routing is a Linux capability today. The macOS v3 attach **refuses
local-dir and graft options outright** — the daemon rejects the whole attach
rather than accepting an option it would not serve — and the CLI refuses
`--local-dir` unconditionally on every platform, because a per-machine route
would hide from one machine a directory every peer still treats as shared, with
no revision recording it and no peer able to observe it.

The consequence is a hard, stated boundary rather than a partial
implementation:

- routes are declared volume-wide in the volume's `.portablefs/local-dirs`, and
  the revision a mount presents at attach is the hash of that declaration;
- `portablefsd` does not join the route adoption protocol, so a macOS attach
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

## Troubleshooting

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
remove the non-release provider and reinstall; a valid release setup has exactly
one installed `pfs` provider.

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
frontend socket. The extension may only connect to sockets inside its app-group
container; if the CLI was pointed elsewhere via `PORTABLEFS_FSKIT_SOCKET`, the
extension cannot follow it there. Clear the override (or align it with the
extension's `PFSAppGroupIdentifier` container) and remount. A rebuilt extension
can also linger as a stale process from a previous version; `pkill -x
PortableFSDev` (or the app's extension name) forces a fresh instance on the next
mount.

### A foreign daemon owns the sockets

The CLI requires both liveness and an exact control identity on the control
socket. A stale dev build or older release is refused before an attach is
created. The sockets live in the canonical account home's per-user app-group
container, so unlike a `/tmp` path they cannot belong to another account.

The fix depends on which extension you run:

- Stock PortableFS.app extension: it dials the default frontend socket, so the
  default sockets must be yours. Stop the foreign daemon (unmount its attaches,
  then terminate the `portablefsd` process) and remount; the CLI spawns a fresh
  daemon on the now-free sockets.
- Dev extension with its own Info.plist socket: point the CLI at your own
  sockets — `PORTABLEFS_FSKIT_SOCKET` (frontend) and
  `PORTABLEFS_FSKIT_CONTROL_SOCKET` — and package the matching
  `portablefs`/`portablefsd` sibling pair. The signed filesystem type remains
  `pfs`.

### The daemon does not become healthy

`portablefs mount` fails after 15 seconds with the log path. Read
`~/.local/state/portablefs/portablefsd.log` — the daemon logs why it could not
start, most often a socket path it cannot create or bind.

### The mount is refused for its routing revision

The volume publishes `.portablefs/local-dirs` and this Mac declared the empty
rule set. That is the documented boundary above, not a misconfiguration: mount
the volume from Linux, or have an administrator remove the declaration with
`ApplyRoutes`.

## Why One Transport, No Fallback

Earlier releases fell back to a loopback bridge over the macOS kernel's built-in
network-filesystem client when the native mount was unavailable. That fallback
was removed because it silently delivered a weaker consistency model than the
one this system exists to provide: the kernel client cached reads and attributes
for up to ~60 seconds regardless of server validators, and concurrent appends
from two machines to one shared file collapsed into whole-file
last-writer-wins uploads — precisely the shapes agent workspaces hit (tailing a
log another machine appends to, two mounts sharing state files). A mount that
sometimes has those semantics is worse than a mount error that says how to get
the real one. One transport per platform keeps authority ordering uniform.

Two framework boundaries stay explicit rather than being papered over. FSKit on
macOS 26 exposes no general kernel-cache invalidation primitive, which is why
the cache half of the contract is a release gate and not a claim
([macos-26-coherence-contract.md](./macos-26-coherence-contract.md)). And
current FSKit write callbacks do not expose `O_APPEND` intent, so cross-machine
atomic append cannot be inferred without misclassifying legitimate positional
writes; see
[consistency-model.md](./consistency-model.md).
