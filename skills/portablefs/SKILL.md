---
name: portablefs
description: "Live shared filesystems for agent workspaces. Use when you need one workspace mounted on several machines at once, workspace continuity across sessions, or to diagnose a PortableFS mount."
---

# PortableFS Workspaces

PortableFS gives you a workspace that is a place in the network, not a folder on
one machine. You mount it, you use ordinary files, and another machine mounting
the same volume sees the same live filesystem.

Everything you need is the `portablefs` CLI and this file. Every command accepts
`--json`; parse that instead of scraping text.

## Concepts

- **Volume.** One workspace. It is one XFS directory on one Linux host, served by
  one authority process. That directory is the truth.
- **Authority.** The process that owns the volume. Every namespace change
  (create, rename, unlink, mkdir) is applied there before it returns. File data
  can be accepted earlier: on Linux an uncontended writer's bytes may wait in a
  bounded daemon buffer until `fsync`, a peer read, or unmount flushes them, and
  on macOS `write(2)` returns at kernel page-cache acceptance, as on a local
  disk.
- **Mount.** One machine's live view of a volume. Several Linux mounts can be
  live at once, on different machines, and they see one filesystem. A macOS
  mount is the volume's only writer while it is mounted: Linux mounts keep
  reading, their writes fail with `EBUSY` until the Mac unmounts, and a second
  Mac cannot mount the same volume.
- **Machine-local routes.** Directories the volume declares as per-machine —
  typically `node_modules`, `.venv`, `target`. They are served from local disk and
  never travel. The declaration belongs to the volume, not to your machine.

There is no history, no branch, no snapshot, no fork, and no server-side command
execution. If you need a second independent copy of a workspace, you need a
second volume.

## Mounting

A mount needs four things, all passed directly: the authority's address, a
single-use mount capability, a verified TLS transport, and your mutual-TLS client
identity.

```bash
portablefs mount my-workspace ~/work \
  --addr 10.0.0.7:2050 --mount-token "$PORTABLEFS_MOUNT_TOKEN" \
  --data-plane-transport tls-private-ca \
  --data-plane-server-name authority.internal --data-plane-ca ca.pem \
  --client-cert client.pem --client-key client.key --json
```

Use `--data-plane-transport tls-system-pki` with `--data-plane-server-name` when
the authority has a publicly trusted certificate, and `tls-private-ca` with that
name plus `--data-plane-ca` when it does not. Plaintext is refused. The client
key must be `chmod 600`.

The command daemonizes and returns; the mount persists. `--foreground` keeps it
attached and unmounts on interrupt.

The capability is **single-use**: it authorizes one attach. When the mount's
authorization ends, the mount ends, and mounting again with a fresh capability
re-establishes it. Hosted mounts can instead rotate a live mount's authorization
in place with `portablefs reauthorize`.

Then just use the directory. Read, write, create, rename, lock. It is a
filesystem.

```bash
portablefs umount ~/work --json
```

A normal unmount runs the full drain barrier and makes one ordinary unmount
attempt. If the drain cannot complete, or something still holds the mount open
(a shell's working directory, an open file, Finder or Spotlight on macOS), it
fails with the real error, such as `EBUSY`, and leaves the mount attached.
`--force` detaches without that drain, so writes still buffered in the local
page cache or a delegated write buffer can be lost. Use `--force` only when the
authority is unreachable and you need the mount gone now.

## The commands that exist

| Command | Use it for |
| --- | --- |
| `portablefs mount <volumeId> <path>` | Attach a volume on this machine. |
| `portablefs reauthorize` | Rotate a hosted live mount's authorization in place. |
| `portablefs umount <path>` | Drain and detach. `--force` skips the drain proof. `unmount` is an alias. |
| `portablefs mounts` | This machine's mounts and their health: live, stale, or credential-expired. |
| `portablefs mount-loss <path>` | Linux: read the exact writeback loss counter of a live mount. |
| `portablefs route <path>` | Whether a path is machine-local or shared, and which rule decided. |
| `portablefs prune-local` | Reclaim machine-local backing no route can reach. Dry-run by default; `--delete` to act. |
| `portablefs mount-check` | Inspect this host's mount prerequisites. Contacts nothing, changes nothing. |
| `portablefs doctor` | Read-only health check of transport, extension, daemon, and mounts. |
| `portablefs daemon stop` | Stop the per-user daemon, only when it is atomically proven idle. |
| `portablefs version` | The CLI version. |

`portablefs help <command>` has the detailed text for each. Anything not in this
table is either an installer surface or does not exist.

## Working in a shared workspace

Two agents on two machines writing the same volume is the normal case, and the
coordination primitives are the ordinary filesystem ones.

- **Write to distinct files.** This is the answer most of the time and it needs
  no coordination at all.
- **Use atomic rename for whole-file replacement.** Write a temporary file, then
  rename it over the target. The later rename wins, completely. Contents are
  never merged.
- **Use POSIX record locks or `flock`** when two writers genuinely need the same
  file. Both work across mounts and both are released when your process exits.
- **Do not assume a shared `mmap`.** `MAP_SHARED` on a file is refused; use read
  and write. `MAP_PRIVATE` works.
- **Do not use SQLite WAL mode** on the shared volume. Rollback-journal mode
  works; WAL requires all participants on one host. Keep a WAL database on
  machine-local backing.

## Keep dependency trees off the volume

A `node_modules` or `.venv` directory is thousands of small files with no meaning
on another machine. Shipping them through the authority is the single worst thing
you can do to a workspace's speed.

The volume declares which directories are machine-local in `.portablefs/local-dirs`.
Your mount adopts that declaration when it attaches, and every machine routes
identically. There is no per-machine override, because a per-machine route
would hide from you a directory your peers still treat as shared.

```bash
portablefs route ~/work/agent-app/node_modules/react   # machine-local, and why
portablefs route ~/work/src/main.go                    # shared
```

Machine-local backing survives unmount and remount deliberately. `prune-local`
is the explicit step that frees it.

**Never route a directory that holds irreplaceable data.** A machine-local
directory is not backed up, not replicated, and not visible to anyone else. It is
for reproducible build output. If losing that machine would lose something that
matters, it does not belong behind a route.

macOS does not join the route adoption protocol. A volume that declares routes
mounts from Linux.

## Continuity

Your workspace outlives your session and your machine. Mount it from a laptop
today and a sandbox tomorrow, with a fresh capability each time, and it is the
same live filesystem — including whatever the last session left half-finished.

Any Linux sandbox that can run a static binary and reach the authority can mount
a workspace. It needs the address, its own capability, and its own client
identity.

## Troubleshooting

| Symptom | What it means |
| --- | --- |
| `mount` fails naming the credential shape | A required flag is missing. All of `--addr`, `--mount-token`, `--data-plane-transport`, `--data-plane-server-name`, `--client-cert`, `--client-key` are needed. |
| `mounts` shows `credential-expired` | The single-use capability ended. Mount again with a fresh one. |
| `mounts` shows `stale` | The daemon is gone. `portablefs umount <path>` cleans it up. |
| On macOS, mount fails on the extension | `PortableFS.app` must be installed and its File System Extension enabled once under System Settings. `portablefs mount-check` reports the prerequisite; `portablefs doctor` reports the rest. |
| Unmount refuses because an intent is stuck | `portablefs umount <path> --discard-record` removes bookkeeping only, and only after proving nothing is mounted and no owner survives. Never edit the mount state directory by hand. |
| Everything on the mount returns `ENOTCONN` | The mount revoked itself after losing its authority session. Remount. |
| A write on Linux returns `EBUSY` | A Mac currently mounts the volume and is its only writer. Writes succeed again after the Mac unmounts. |
| A Mac mount is refused while another Mac has the volume mounted | One Mac writer at a time. Unmount the other Mac first. |
| `umount` returns `EBUSY` | Something holds the mount open. Close it (including a shell whose working directory is inside) and retry; reach for `--force` only if you accept losing undelivered writes. |

## Safety notes

- **A returned `write(2)` is accepted, not yet durable.** It may still sit in
  the macOS page cache or a Linux delegated write buffer, as on a local disk.
  On macOS, each operation the kernel actually delivers to PortableFS is durable
  when it completes; whether `fsync` forces delivery of every dirty page is not
  yet qualified.
- **`close` is not `fsync`.** If you need durability across power loss, `fsync`
  the file and its parent directory, as you would locally.
- **`syncfs(2)` does not reach the authority** on Linux FUSE. Use file and
  directory `fsync`.
- **There is no undo.** No history, no snapshots. A `rm -rf` on the volume is a
  `rm -rf` on the volume.
- **Reads never block on writers**, and one slow peer cannot stall the volume
  indefinitely — it is fenced individually.
