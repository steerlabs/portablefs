# The FSKit Mount (macOS)

`portablefs mount` on macOS has exactly one transport: the `fskit` strategy.
The CLI drives the same `portablefsd` + FSKit extension pair the PortableFS
menu-bar app uses. There is deliberately no fallback transport: a Mac that
cannot serve an FSKit mount fails with install guidance instead of degrading
to the retired fallback transport. A mounted path gets authority-ordered
operations, real POSIX modes and symlinks, and the durability contract below.
On macOS 26, PortableFS provides an exact pre-acknowledgment refresh for known
regular-file data and size. FSKit does not expose a general kernel-cache
invalidation primitive, so cached namespace bindings and other attributes
remain a documented framework boundary.

`--strategy auto` (the default) resolves to `fskit` on macOS and `fuse` on
Linux; an explicit `--strategy fskit` requires darwin, and an explicit
`--strategy fuse` requires linux. Those are the only strategies.

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
are currently beta API for the next OS/SDK track and are not present in the
stable macOS 26.5 SDK. They are therefore a macOS 27 release gate, not a reason
to raise this release's deployment target or make the macOS 26 adapter depend
on beta symbols. `VolumeCore` deliberately owns all pfslocal, identity, open
handle, and filesystem semantics independently of the adapter so a future
availability-guarded macOS 27 handler can reuse the same tested core.

Before claiming macOS 27 support, build that handler against the final SDK,
negotiate the least-permissive correct `DataCacheHandler` coherency mode, drive
remote invalidations through the handler's cache-state API, and pass the
signed live-kernel read/write/mmap/rename/unlink/remote-invalidation matrix on
both macOS 26 and 27. Until then, macOS 26 keeps the descriptor-confined
`ftruncate` plus `msync(MS_INVALIDATE)` refresh described by the implementation.
There is no conditional beta implementation or silent downgrade in the
production binary.

Apple's stable `FSVolume.OpenModes` contains only read and write access bits;
it does not carry `O_APPEND`. The new documentation does not change the
current append boundary described under
[concurrent appends](./consistency-model.md#concurrent-appends).

## How A Mount Happens

Three cooperating pieces:

```text
portablefs mount ──control socket──▶ portablefsd ◀──frontend socket── FSKit extension ◀─ kernel
      (CLI)        (HTTP over UDS)  (per-user daemon)    (pfslocal)   (PortableFSExt.appex)
```

1. **Ensure the daemon.** The CLI probes the `portablefsd` control socket
   (`GET /healthz`) and requires an exact `/v1/identity` match for the
   CLI/daemon release, exact daemon executable SHA-256, private control
   protocol, and `pfslocal` major protocol. A
   healthy compatible daemon is adopted — the daemon is per-user and
   multi-attach, so one instance serves every mount, whether the CLI or the
   menu-bar app started it. An incompatible live daemon fails closed with
   clean-stop guidance; the CLI never replaces it automatically. Otherwise
   the CLI spawns one, detached into its own session so it outlives the mount
   process and serves later mounts. The daemon must be the exact
   `portablefsd` sibling of the canonical real `portablefs` executable. The
   CLI pins and hashes that file and requires the running daemon to report
   the same executable identity; it never searches `PATH` or accepts an
   executable override.
2. **Register the attach.** `POST /v1/attaches` on the control socket carries
   everything the daemon needs to own the authority connection itself: the
   resolved authority URL, the data-plane token, and the lease-bound transport
   contract returned by the manager: exactly one of `tls-private-ca` (strict,
   bounded CA PEM + SHA-256 + exact server name), `tls-system-pki` (system
   roots + exact server name), or explicit `plaintext`. The daemon persists
   that exact mode, name, and CA fingerprint and validates them again on
   restart. Login never probes a CA endpoint, cached profile trust is not
   reused, and an empty CA never means plaintext. The request also carries the tuning options
   (write policy, fsync policy, flush interval, machine-local dirs). The
   daemon answers with an attach reference.
3. **Mount.** The CLI hands the kernel that reference:
   `/sbin/mount -t pfs dev.portablefs.oss://<attachRef> <mountPath>`. The
   filesystem type and globally scoped generic-resource scheme are separate,
   signed identity axes: FSKit routes the URL by `FSSupportedSchemes`, while
   statfs publishes `FSShortName`. The enabled FSKit extension serves the
   mount by dialing the daemon's frontend socket inside
   the canonical account home's PortableFS app-group container
   (`Library/Group Containers/B47U2LLKHW.pfsoss/portablefsd/pfs.sock`,
   relative to that home). The app group is load-bearing, not a convention:
   the macOS app sandbox permits `connect(2)` on a unix socket only inside
   app-group container paths, so a socket anywhere else — `/tmp` included —
   is unreachable from the sandboxed extension no matter what file-access
   exceptions it holds. The daemon the CLI ensures must therefore serve
   exactly that container socket (see the overrides below).

The command then behaves like every `portablefs mount`: it returns only after
the kernel reports the path mounted and a real root enumeration succeeds, then
daemonizes (state under `~/.local/state/portablefs/mounts/`),
the mount process keeps the access lease renewed and pushes rotated
credentials into the daemon (`POST /v1/attaches/{ref}/credential`), and
`portablefs umount` invokes one daemon-owned
`POST /v1/attaches/{ref}/unmount` transaction. That request freezes every
frontend and control admission, completes the final authority barrier,
durably records the prepared detach, proves the exact
`dev.portablefs.oss://<attachRef>` kernel mount, unmounts it in-process, and
only then durably removes the attach. A failure preserves the attach and its
exact recovery evidence; no second delete or path-based unmount can mutate
one side of the boundary without the other.

## Install And Enable (Once Per Mac)

The strategy requires the PortableFS FSKit extension to be registered and
enabled:

1. Run the PortableFS installer. It places the notarized app at the canonical
   per-user path `~/Applications/PortableFS.app`, links its embedded CLI into
   `~/.local/bin`, and launches that exact app so macOS registers its File
   System Extension.
2. Open System Settings → General → Login Items & Extensions, scroll to the
   Extensions section, and open the **File System Extensions** category
   (click its ⓘ). Enable the PortableFS extension there. Use the category
   view specifically: on macOS 26 the same toggle rendered in the per-app
   list is unreliable and can silently do nothing. This approval is a
   user-controlled macOS setting and cannot be automated.

FSKit extensions are user-space: no kernel extension, no reboot, no sudo.
Exactly one installed PortableFS provider may claim the `pfs` fs type. The
release installer refuses publication when it finds another provider, such as
the dev harness's `PortableFSDev.appex`; remove that provider explicitly
before installing the release app.

The release archive is one `PortableFS.app`. Its CLI and daemon live under
`Contents/Helpers/`, and its FSKit extension lives under
`Contents/Extensions/`. The installer verifies that code hierarchy, takes the
exclusive per-user mount lifecycle lock, rechecks exact kernel mounts, mount
records, running PortableFS processes, and canonical sockets, and atomically
replaces the whole bundle plus CLI symlink. It never updates a live app,
daemon, or mount. Cleanly unmount volumes and quit the app before upgrading.

## Daemon Lifecycle

- **Per-user, multi-attach.** One `portablefsd` serves every attach for the
  user. The CLI adopts a healthy daemon only when its exact control identity
  is compatible and never duplicates or automatically replaces it. CLI and
  app mounts can ride the same compatible daemon when they share sockets.
- **Spawn.** When nothing healthy answers, the CLI starts
  `portablefsd -frontend-socket ... -control-socket ...` with a state dir at
  `~/.local/state/portablefs/portablefsd`, detached, and waits up to 15
  seconds for `/healthz` before failing with the log path. A crashed daemon or
  reboot can leave socket inodes behind; after acquiring both the state and
  socket singleton locks, the new daemon reclaims only a private, same-UID,
  single-link canonical socket that refuses a connection. It moves that exact
  inode aside with an atomic no-replace rename before removal, so a concurrent
  replacement is restored rather than unlinked.
- **Log.** A CLI-spawned daemon appends to
  `~/.local/state/portablefs/portablefsd.log`. Per-mount daemon logs are
  separate, under `~/.local/state/portablefs/mounts/`. The menu-bar app invokes
  the same embedded CLI and does not own another daemon or state root.
- **Sockets are the authentication boundary.** The daemon creates the socket
  directory 0700 and the sockets 0600; same-user filesystem access is the
  control plane's entire auth model — there is no bearer token on the control
  API. Authority credentials live only in daemon memory and are refreshed
  through the credential endpoint; they are never written into the daemon's
  durable attach registry. After a restart, an explicit normal unmount of a
  managed mount reactivates the exact attach with the access-lease credential
  already protected in its mount transaction before running the final
  authority barrier. A direct-address mount has no persisted credential: if
  its daemon is gone, normal unmount fails closed and only the explicit
  `umount --force` transaction may durably park its offline tail.
- **Outlives mounts.** Exact unmount durably removes the attach but leaves the
  daemon running for the next mount. Active delegated attaches may own local
  WAL state, so they must `fsync`, synchronize, or detach cleanly before the
  daemon is stopped. A truly idle daemon with no attaches owns no live tail
  and is safe to stop.

## Environment Overrides

Defaults match PortableFS.app's extension. The socket overrides exist for dev
extensions that use a separate app-group container:

| variable | default | meaning |
|---|---|---|
| `PORTABLEFS_FSKIT_TYPE` | `pfs` | optional assertion of the release's signed filesystem type; a different value is rejected |
| `PORTABLEFS_FSKIT_SOCKET` | `~/Library/Group Containers/B47U2LLKHW.pfsoss/portablefsd/pfs.sock` | the daemon frontend socket the extension dials (resolved from `PFSAppGroupIdentifier` in the extension's Info.plist) |
| `PORTABLEFS_FSKIT_CONTROL_SOCKET` | `~/Library/Group Containers/B47U2LLKHW.pfsoss/portablefsd/control.sock` | the daemon control socket the CLI drives; setting a custom frontend socket implies a `control.sock` next to it unless this is set explicitly |

`PORTABLEFS_FSKIT_DAEMON` is rejected. A fork or development build packages
its matching CLI and daemon as one sibling pair rather than selecting code
from the environment.

The OSS resource scheme is the immutable `dev.portablefs.oss`; it is not an
environment override. The matching app and CLI are installed atomically and
the installer requires the extension to advertise exactly that one scheme.
An embedder uses its own extension metadata and matching mount client instead
of aliasing the OSS scheme.

Changing the frontend socket only works with an extension whose Info.plist
resolves the new path, and any custom location must still be inside an
app-group container the extension is entitled to — the sandbox denies unix
socket connects everywhere else. The stock PortableFS.app extension expects
the default, so with it these overrides are read-only facts, not knobs.
The packaging build stamps one `PORTABLEFS_APP_GROUP` value derived from the
signing team into the extension Info.plist, its signed entitlement, the CLI,
and the daemon. Forks set their signing team once; there are no independent
source constants to keep synchronized.

## Write Path

There is no write-mode knob (`--fast` is retired and fails with a pointer at
this model). Every FSKit mount runs the adaptive write-back engine
([writeback-engine.md](./writeback-engine.md)): the authority delegates a
subtree on the first uncontended write, after which mutations under it are
accepted into the mount's stream WAL file descriptor and local overlay while
one flusher ships them in batches. The local WAL group-sync runs at 5 ms /
4 MiB; plain writes do not wait for it. Contended scopes run write-through
and re-delegate once contention clears. `fsync`, FSKit `synchronize`, and
clean unmount force local sync and then authority durability — Git commits
and SQLite transactions are durable at the authority when those barriers
return. A verified local tail replays exactly on the next attach;
`portablefs mounts` and attach status surface parked jobs. WAL failure seals
all later mutations until remount and never changes them to write-through.
The only remaining environment knob is `PORTABLEFS_NEGATIVE_CACHE`
([performance.md](./performance.md)); it travels to the daemon as an attach
option.

## Machine-Local Dirs

`--local-dir <rel>` grafts are served natively by `portablefsd`: the attach's
`localDirs` shadow those workspace-relative paths from machine-local disk
instead of the authority, under the same graft contract as the Linux FUSE
client ([architecture.md](./architecture.md)).

The daemon reads the volume's `.portablefs/local-dirs` declaration before it
activates the attach and unions it with the explicit/persisted `--local-dir`
set, matching Linux FUSE. `--no-local-dirs` clears persisted explicit grafts
and tells the daemon to ignore the volume declaration for that mount. Attach
status and the CLI readiness record report the effective union. Declaring
`.portablefs` itself (or the declaration file) as a graft is rejected so the
configuration cannot shadow its own source.

Graft ownership is immutable for the lifetime of an FSKit Item. When the
effective rule set changes—during revived activation or a live additive
update—the daemon durably retires every affected active Item and invalidates
its namespace before a lookup can publish a fresh Item with the new
authority-versus-local provenance. The durable routing option is committed
before the live transition, so a failed config persist leaves the old routing
and identities intact; startup applies any committed transition before the
frontend serves.

Every graft operation is relative to an open backing-directory capability.
Safe relative symlinks within a graft work; `readlink` returns the exact stored
target, while server-side traversal of an absolute link or a relative link that
would escape the backing fails. The check is race resistant and also covers
rename/link destination parents and metadata operations. File data I/O remains
descriptor-backed after open, so this isolation does not add work to reads,
writes, mmap, fsync, or locking.

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
System Settings. If two PortableFS extensions are listed (app and dev
harness), remove the non-release provider and reinstall; a valid release
setup has exactly one installed `pfs` provider.

If another enabled PortableFS-based product exists, it may remain enabled only
when both its `FSShortName` and `FSSupportedSchemes` differ from the OSS
identity. Sharing a generic-resource scheme is ambiguous even when filesystem
types differ, so the installer rejects either kind of collision.

### Enabled, but "Loading resource: … Input/output error"

The module is enabled and the kernel reached it, but the extension's
`loadResource` failed — almost always because it could not reach
`portablefsd`'s frontend socket. The extension may only connect to sockets
inside its app-group container; if the CLI was pointed elsewhere via
`PORTABLEFS_FSKIT_SOCKET`, the extension cannot follow it there. Clear the
override (or align it with the extension's `PFSAppGroupIdentifier`
container) and remount. A rebuilt extension can also linger as a stale
process from a previous version; `pkill -x PortableFSDev` (or the app's
extension name) forces a fresh instance on the next mount.

### A foreign daemon owns the sockets

The CLI requires both liveness and an exact control identity on the control
socket. A stale dev build or older release is refused before an attach is
created. The sockets live in the canonical account home's per-user app-group
container, so unlike a `/tmp` path they cannot belong to another account.

The fix depends on which extension you run:

- Stock PortableFS.app extension: it dials the default frontend socket, so
  the default sockets must be yours. Stop the foreign daemon (unmount its
  attaches, then terminate the `portablefsd` process) and remount; the CLI
  spawns a fresh daemon on the now-free sockets.
- Dev extension with its own Info.plist socket: point the CLI at your own
  sockets — `PORTABLEFS_FSKIT_SOCKET` (frontend) and
  `PORTABLEFS_FSKIT_CONTROL_SOCKET` — and package the matching
  `portablefs`/`portablefsd` sibling pair. The signed filesystem type remains
  `pfs`.

### The daemon does not become healthy

`portablefs mount` fails after 15 seconds with the log path. Read
`~/.local/state/portablefs/portablefsd.log` — the daemon logs why it could
not start, most often a socket path it cannot create or bind.

## Why One Transport, No Fallback

Earlier releases fell back to a loopback bridge over the macOS kernel's
built-in network-filesystem client when the native mount was unavailable.
That fallback was retired because it silently delivered a weaker consistency
model than the one this system exists to provide: the kernel client cached
reads and attributes for up to ~60 seconds regardless of server validators,
and concurrent appends from two machines to one shared file collapsed into
whole-file last-writer-wins uploads — precisely the shapes agent workspaces
hit (tailing a log another machine appends to, two mounts sharing state
files). A mount that sometimes has those semantics is worse than a mount
error that says how to get the real one. One transport per platform keeps
authority ordering uniform. PortableFS explicitly refreshes known
regular-file data and size, while cached namespace bindings and other
attributes remain advisory until FSKit exposes general cache control. A
second framework boundary remains explicit: current FSKit write
callbacks do not expose `O_APPEND` intent, so cross-machine atomic append
cannot be inferred without misclassifying legitimate positional writes. See
[`consistency-model.md`](./consistency-model.md#concurrent-appends).
