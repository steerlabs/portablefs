# The FSKit Mount (macOS)

`portablefs mount` on macOS has exactly one transport: the `fskit` strategy.
The CLI drives the same `portablefsd` + FSKit extension pair the PortableFS
menu-bar app uses. There is deliberately no fallback transport: a Mac that
cannot serve an FSKit mount fails with install guidance instead of degrading
to the retired fallback transport. A mounted path gets authority-ordered
operations, real POSIX modes and symlinks, and the durability contract below.
On macOS 26, FSKit does not expose a kernel-cache invalidation primitive;
cross-machine cache visibility is therefore a documented framework boundary,
not an exact guarantee.

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
   process and serves later mounts. The daemon binary is discovered next to
   the `portablefs` executable first (the release-archive layout), then on
   `PATH`; `PORTABLEFS_FSKIT_DAEMON` points at an explicit binary.
2. **Register the attach.** `POST /v1/attaches` on the control socket carries
   everything the daemon needs to own the authority connection itself: the
   resolved authority URL, the data-plane token, the TLS CA bundle as PEM
   (the daemon dials the authority, so the trust material travels with the
   request — `portablefs login` captures the deployment's published router CA
   from `GET /router-ca.pem` into the profile automatically, and
   `PORTABLEFS_TLS_CA`/`VCS_TLS_CA` override it), and the tuning options
   (write policy, fsync policy, flush interval, machine-local dirs). The
   daemon answers with an attach reference.
3. **Mount.** The CLI hands the kernel that reference:
   `/sbin/mount -t pfs pfs://<attachRef> <mountPath>`. The enabled FSKit
   extension serves the mount by dialing the daemon's frontend socket inside
   the PortableFS app-group container (`~/Library/Group Containers/
   B47U2LLKHW.pfsoss/portablefsd/pfs.sock`). The app group is load-bearing,
   not a convention: the macOS app sandbox permits `connect(2)` on a unix
   socket only inside app-group container paths, so a socket anywhere else —
   `/tmp` included — is unreachable from the sandboxed extension no matter
   what file-access exceptions it holds. The daemon the CLI ensures must
   therefore serve exactly that container socket (see the overrides below).

The command then behaves like every `portablefs mount`: it returns only after
the kernel reports the path mounted and a real root enumeration succeeds, then
daemonizes (state under `~/.local/state/portablefs/mounts/`),
the mount process keeps the access lease renewed and pushes rotated
credentials into the daemon (`POST /v1/attaches/{ref}/credential`), and
`portablefs umount` unmounts through `/sbin/umount` (falling back to
`diskutil unmount`) and only then deletes the attach, so the daemon flushes
everything the extension handed it before the attach drops.

## Install And Enable (Once Per Mac)

The strategy requires the PortableFS FSKit extension to be registered and
enabled:

1. Install PortableFS.app (built from `swift/PortableFSApp`) into
   `/Applications` and launch it once so macOS registers its File System
   Extension.
2. Open System Settings → General → Login Items & Extensions, scroll to the
   Extensions section, and open the **File System Extensions** category
   (click its ⓘ). Enable the PortableFS extension there. Use the category
   view specifically: on macOS 26 the same toggle rendered in the per-app
   list is unreliable and can silently do nothing. This approval is a
   user-controlled macOS setting and cannot be automated.

FSKit extensions are user-space: no kernel extension, no reboot, no sudo.
Enable only one PortableFS file system extension at a time — the app's
`PortableFSExt.appex` and the dev harness's `PortableFSDev.appex` both claim
the `pfs` fs type.

The release archive ships `portablefsd` alongside the `portablefs` binary;
keeping them siblings (or `portablefsd` on `PATH`) is all the daemon setup
there is. The installer validates both downloaded versions before changing
the destination and refuses while any same-user `portablefsd` is running. It
never restarts or replaces a live daemon; cleanly unmount and stop the idle
daemon before upgrading. Use the matching installed CLI's
`portablefs daemon stop` after all mounts are gone; the daemon atomically
refuses the stop if any attach still exists.

## Daemon Lifecycle

- **Per-user, multi-attach.** One `portablefsd` serves every attach for the
  user. The CLI adopts a healthy daemon only when its exact control identity
  is compatible and never duplicates or automatically replaces it. CLI and
  app mounts can ride the same compatible daemon when they share sockets.
- **Spawn.** When nothing healthy answers, the CLI starts
  `portablefsd -frontend-socket ... -control-socket ...` with a state dir at
  `~/.local/state/portablefs/portablefsd`, detached, and waits up to 15
  seconds for `/healthz` before failing with the log path.
- **Log.** A CLI-spawned daemon appends to
  `~/.local/state/portablefs/portablefsd.log`. Per-mount daemon logs are
  separate, under `~/.local/state/portablefs/mounts/`. (The menu-bar app
  manages its own child daemon and logs it under `~/Library/Logs/PortableFS/`.)
- **Sockets are the authentication boundary.** The daemon creates the socket
  directory 0700 and the sockets 0600; same-user filesystem access is the
  control plane's entire auth model — there is no bearer token on the control
  API. Authority credentials are stored per attach and refreshed through the
  credential endpoint.
- **Outlives mounts.** Unmounting deletes the attach but leaves the daemon
  running for the next mount. Active delegated attaches may own local WAL
  state, so they must `fsync`, synchronize, or detach cleanly before the
  daemon is stopped. A truly idle daemon with no attaches owns no live tail
  and is safe to stop.

## Environment Overrides

Defaults match PortableFS.app's extension. The overrides exist for dev
extensions registered under another fs type or socket path:

| variable | default | meaning |
|---|---|---|
| `PORTABLEFS_FSKIT_TYPE` | `pfs` | fs type passed to `/sbin/mount -t`; must match the FSKit short name the enabled extension claims |
| `PORTABLEFS_FSKIT_SOCKET` | `~/Library/Group Containers/B47U2LLKHW.pfsoss/portablefsd/pfs.sock` | the daemon frontend socket the extension dials (resolved from `PFSAppGroupIdentifier` in the extension's Info.plist) |
| `PORTABLEFS_FSKIT_CONTROL_SOCKET` | `~/Library/Group Containers/B47U2LLKHW.pfsoss/portablefsd/control.sock` | the daemon control socket the CLI drives; setting a custom frontend socket implies a `control.sock` next to it unless this is set explicitly |
| `PORTABLEFS_FSKIT_DAEMON` | discovery | explicit `portablefsd` binary (otherwise: sibling of the `portablefs` binary, then `PATH`) |

Changing the frontend socket only works with an extension whose Info.plist
resolves the new path, and any custom location must still be inside an
app-group container the extension is entitled to — the sandbox denies unix
socket connects everywhere else. The stock PortableFS.app extension expects
the default, so with it these overrides are read-only facts, not knobs.
Forks that build under their own Apple team id change the group id in
`AppPaths.swift`, the extension Info.plist/entitlements, and the CLI's
`fskitAppGroup` constant together.

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
harness), enable only one.

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
created. (The sockets live in the per-user app-group container under `$HOME`,
so unlike a `/tmp` path they can never be another user's.)

The fix depends on which extension you run:

- Stock PortableFS.app extension: it dials the default frontend socket, so
  the default sockets must be yours. Stop the foreign daemon (unmount its
  attaches, then terminate the `portablefsd` process) and remount; the CLI
  spawns a fresh daemon on the now-free sockets.
- Dev extension with its own Info.plist socket: point the CLI at your own
  coordinates — `PORTABLEFS_FSKIT_SOCKET` (frontend),
  `PORTABLEFS_FSKIT_CONTROL_SOCKET`, `PORTABLEFS_FSKIT_TYPE` (the dev fs
  type), and `PORTABLEFS_FSKIT_DAEMON` for the matching daemon build.

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
authority ordering uniform without pretending the macOS 26 SDK can evict
kernel pages: daemon-side invalidations are advisory until FSKit exposes that
hook. A second framework boundary remains explicit: current FSKit write
callbacks do not expose `O_APPEND` intent, so cross-machine atomic append
cannot be inferred without misclassifying legitimate positional writes. See
[`consistency-model.md`](./consistency-model.md#concurrent-appends).
