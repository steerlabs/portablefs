# Deploying and self-hosting an authoritative-XFS volume

Status: **the single deployment and self-hosting document for PortableFS v3**

This is the operator's runbook for the v3 stack: provisioning storage, running
the authority, issuing credentials, mounting from Linux and macOS, operating the
volume, and handling failure. It replaces the v2 self-hosting document, whose
Postgres database, blob buckets, journal maintenance jobs, and control-plane
service were removed with the v2 architecture and are not coming back in that
shape. See [xfs-authority-architecture.md](./xfs-authority-architecture.md) for
why the stack looks like this and [../COMPATIBILITY.md](../COMPATIBILITY.md) for
what the reset broke.

The launch topology is one active authority process per volume over one
encrypted XFS filesystem. It is single-AZ durable storage, not multi-AZ high
availability, and it has no automatic second writer.

Two things an operator has to accept before deploying:

- **There is no control plane in this tree.** Nothing here mints mount
  capabilities, issues client certificates, or renews an authorization inside a
  live session. Minting is currently an operator or integration responsibility;
  see [Issuing credentials](#issuing-credentials).
- **Clean strict detach fails closed by default.** Without
  `--mount-absence-verify-command`, a strict mount can never leave durable
  membership on its own, so every authority restart after a strict mount depends
  on an unverified operator assertion. See [Restarting the
  authority](#restarting-the-authority).

## Host and disk

Use a current Nitro EC2 instance on a supported Linux baseline (6.12 or newer
for the complete tested syscall and FUSE contract). Attach a dedicated,
encrypted EBS data volume with `DeleteOnTermination=false`. Choose gp3 or io2
from measured IOPS, throughput, latency, and durability requirements; the
architecture does not impose one capacity tier. Do not use EBS Multi-Attach: two
hosts mounting ordinary XFS read-write is data loss, not replication.

Format and mount the cell once. `provision-xfs-volume.sh` deliberately does not
run `mkfs`; making a filesystem is a one-time, irreversible act and is kept out
of the per-volume tool.

```bash
mkfs.xfs -f /dev/disk/by-id/<validated-ebs-device>
mkdir -p /srv/portablefs
mount -t xfs -o prjquota,nodev,nosuid,noexec,noatime \
  /dev/disk/by-id/<validated-ebs-device> /srv/portablefs
```

Resolve and verify the exact device identity before formatting. Never use a
discovery glob or an unvalidated environment variable as the `mkfs` target.
Persist the UUID in `/etc/fstab` with the same options and verify an automatic
boot before admitting data. The mount point itself must stay `root:root` and
must not be group- or other-writable.

## Provisioning a volume

Allocate a stable, unprivileged numeric UID/GID and a unique nonzero XFS project
ID for the volume. The block and inode hard limits come from that volume's
purchased entitlement, not a universal PortableFS limit.

```bash
sudo scripts/provision-xfs-volume.sh \
  /srv/portablefs vol_01JXYZ 42001 200001 200001 100g 10000000
```

The script takes exactly seven positional arguments and has no flags:

```text
provision-xfs-volume.sh <xfs-mount> <volume-name> <project-id> \
    <service-uid> <service-gid> <block-hard-limit> <inode-hard-limit>
```

`<project-id>` is a nonzero uint32. `<service-uid>` and `<service-gid>` are
nonzero and at most 4294967294 — the all-ones value is the `chown(2)` sentinel,
not a usable identity. `<block-hard-limit>` is a decimal with an optional
`k/m/g/t/p` suffix; `<inode-hard-limit>` is a plain decimal.

### Preconditions it enforces

The script refuses rather than repairs. It requires:

- to be running as root (`$EUID -eq 0`);
- `find`, `findmnt`, `flock`, `mktemp`, `readlink`, `stat`, `sync`, `xfs_io` and
  `xfs_quota` on `PATH`;
- `<xfs-mount>` to resolve to a real, non-symlink directory that is *itself* the
  XFS mount point, not a nested directory beneath it;
- `FSTYPE` to be `xfs`;
- mount options to include all of `nodev`, `nosuid`, `noexec`, `noatime`, plus
  `prjquota` or `pquota`;
- the mount point to be owned `root:root` and not writable by group or other.

### What it does

1. **Reserves the project ID in a fail-closed registry.** `<mount>/.portablefs-projects`
   is a `root:root` mode-0700 directory holding one subdirectory per allocated
   project ID, serialized by `flock` on `.lock`. It is initialized only on an
   empty cell, so an existing tree can never be silently adopted without
   registering the IDs it already uses. The reservation is written as `reserved`
   before any quota work and flipped to `published` at the end. **A failed run
   intentionally leaves the reservation behind**: reusing an ID whose quota setup
   may have partially completed would merge accounting and limits with another
   volume. Clearing a stale reservation is a deliberate manual act.
2. **Applies the project and its limits to a staging directory.** It sets the
   project with `xfs_quota -x -c "project -s -p ..."` and then
   `limit -p bhard=<blocks> ihard=<inodes>`.
3. **Reads the result back through the same ioctl the data plane uses.**
   `xfs_io -r -c stat` must report the exact project ID and must show
   `FS_XFLAG_PROJINHERIT` (`0x200`) set. Without inheritance, children escape the
   project and its quota, which is the whole isolation guarantee. The check reads
   `fsxattr` rather than parsing `xfs_quota`'s progress text.
4. **Chowns the staging directory to the service UID/GID and publishes it** by
   renaming it to `<mount>/<volume-name>`, with `sync -f` on the mount to force
   the quota transaction as well as the directory metadata.
5. **Creates the visibility control directory.** `<mount>/.portablefs-control` is
   `root:root` mode 0711; `<mount>/.portablefs-control/<volume-name>` is mode 0700
   owned by the service UID/GID. The authority's durable strict-membership file
   lives there — beside the volumes but outside the user-visible project
   directory, so an authority restart cannot forget a still-mounted kernel while
   agents can never reach or mutate the record through PortableFS.

On success it prints the destination, project, owner, limits, and the exact
membership path to pass to the authority.

### Exit codes

| Code | Meaning |
| --- | --- |
| 64 | usage, or an invalid argument (path shape, volume name, project ID, UID/GID, limits) |
| 65 | generic precondition failure (not XFS, wrong mount options, wrong ownership, validation read-back failed) |
| 66 | `<xfs-mount>` could not be resolved to a safe directory |
| 69 | a required command is missing |
| 73 | the volume directory already exists, or the project ID is already reserved |
| 77 | not run as root |

## Running the authority

`portablefs-authority` is Linux-only and **refuses to run as root**: provision
XFS first, then run the request process as the volume's service owner. It sees
only its own volume directory and verifies the root's project ID, the
`PROJINHERIT` flag, and its expected owner UID/GID before it listens. The
request process is intentionally not given quota-administration capability; XFS
enforces the limits and privileged provisioning attests them.

Use one sandboxed worker per active volume at launch. A stable per-volume Unix
identity plus a private mount namespace prevents a compromised worker from
opening another tenant's directory. Consolidating hostile volumes into one
unsandboxed process would weaken that boundary and is not an allowed
optimization.

```bash
portablefs-authority \
  --listen 0.0.0.0:7443 \
  --volume-id vol_01JXYZ \
  --root /srv/portablefs/vol_01JXYZ \
  --project-id 42001 \
  --tls-cert /run/portablefs/server.crt \
  --tls-key /run/portablefs/server.key \
  --client-ca /run/portablefs/client-ca.pem \
  --capability-public-key /run/portablefs/capability-public.pem \
  --visibility-membership-file \
    /srv/portablefs/.portablefs-control/vol_01JXYZ/strict-membership \
  --mount-absence-verify-command /usr/local/libexec/portablefs-verify-absence \
  --max-sessions 1024 \
  --max-lock-records 65536
```

### Required flags

All nine are mandatory and startup refuses without them.

| Flag | Meaning |
| --- | --- |
| `--listen` | TCP address to listen on |
| `--volume-id` | exact volume identity served by this process |
| `--root` | absolute provisioned XFS project-directory root |
| `--project-id` | expected nonzero XFS project ID |
| `--tls-cert` | server certificate PEM |
| `--tls-key` | server private key PEM; must be a regular file unreadable by group and other, opened `O_NOFOLLOW` |
| `--client-ca` | client CA bundle PEM |
| `--capability-public-key` | one `PUBLIC KEY` PEM block holding an Ed25519 key; anything else is refused |
| `--visibility-membership-file` | absolute durable strict-mount membership file |

### Coherence and mount-lifecycle flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--mount-absence-verify-command` | *(unset)* | program that corroborates a strict mount's kernel-absence claim. **Unset means clean detach always fails closed.** |
| `--mount-absence-verify-timeout` | `30s` | bound on one verification command run |
| `--prior-strict-mounts-fenced` | `false` | operator assertion that every recorded prior strict kernel mount was proven unusable |
| `--capability-max-lifetime` | `15m` | longest capability validity window this authority will honour; the verified expiry is an absolute non-renewable session deadline |
| `--session-lease` | `2m` | renewable session lease |
| `--max-repair-budget` | `30s` | longest per-phase cache-repair deadline a strict mount may commit to before it is fenced. Must be at least the mount's own `--repair-budget`, whose default is `15s`. |
| `--visibility-clock-skew` | `5s` | clock disagreement tolerated when a mount timestamps its own kernel-mount absence |
| `--max-cached-name-capacity` | `65536` | largest kernel-cache bound a strict mount may declare; sizes the per-session resolved index |

### Deployment-sized bounds

These protect one volume worker from denial of service. They are not PortableFS
filesystem-size limits and do not imply a universal RAM budget. Size them from
the worker class and workload measurements.

| Flag | Default |
| --- | --- |
| `--max-frame-bytes` | `16 MiB` |
| `--max-read-bytes` | `1 MiB` |
| `--max-write-bytes` | `1 MiB` |
| `--max-replay-slots` | `256` |
| `--max-sessions` | `1024` |
| `--max-lock-records` | `65536` |
| `--max-items` | `65536` |
| `--max-items-per-session` | `8192` |
| `--max-opens` | `32768` |
| `--max-opens-per-session` | `4096` |
| `--max-retained-reply-bytes` | `512 MiB` |
| `--max-frame-bytes-in-flight` | `512 MiB` |
| `--max-in-flight` | `256` |
| `--max-connections` | `2048` |
| `--capability-nonce-records` | `65536` |
| `--tls-handshake-timeout` | `10s` |
| `--connection-idle-timeout` | `5m` |
| `--connection-write-timeout` | `30s` |

Startup cross-checks them rather than accepting any combination: `--max-frame-bytes`
must leave a fixed reserve around each read/write payload, `--max-retained-reply-bytes`
must admit at least one maximal reply, `--max-frame-bytes-in-flight` must admit at
least one maximal request, `--connection-idle-timeout` must exceed `--session-lease`,
and `--max-in-flight` must be at least 2 so an ordinary request can proceed
alongside a blocking lock wait.

### Clean detach and the absence verifier

The authority cannot observe a remote kernel's mount table, and the proof bytes
arrive from the very frontend whose absence they claim. So a strict mount's
claim that its kernel mount is gone is never self-verifying, and the only honest
verifier is one the operator supplies.

`--mount-absence-verify-command` names one program, executed directly and never
through a shell. It receives a single JSON document on stdin with the fields
`sessionId` (hex), `observedUnixNanos`, `component`, and `observationBase64` —
the frontend's claim forwarded verbatim, for the verifier to corroborate, never
trusted by the authority itself. **Exit status is the whole verdict: exit 0
verifies, anything else refuses.** There is no partial credit and no retry; a
refusal leaves the session to end fenced, exactly as if no verifier were
configured. The run is bounded by `--mount-absence-verify-timeout`.

A correct verifier checks the claim against evidence the frontend does not
control: a host agent's own mount scan, an infrastructure fence record, or a
signed attestation. Treat that as a deployment gate. Never substitute a verifier
that accepts the frontend's opaque bytes on trust.

If the flag is unset, clean detach always fails closed. The volume still serves;
what you lose is the ability for a strict mount to leave durable membership, so
the next authority restart requires `--prior-strict-mounts-fenced`.

### Restarting the authority

The membership file contains only active strict mount-session identifiers. It is
not filesystem content or operation history. Startup proceeds only when the
record is empty or when every recorded prior strict mount has been cleared.

If the previous process stopped with recorded strict mounts, the new process
refuses to serve: `prior strict mounts remain active; fence their kernel mounts
before starting a new authority epoch`. Recovery is to prove each exact kernel
mount absent — or fence its host — and only then start once with
`--prior-strict-mounts-fenced`. The assertion is unverified and it is the only
input that can erase this authority's memory of an unsafe mount, so it is
durably audited inside the membership record and also printed to stderr:

```text
portablefs-authority: operator asserted prior strict mount <id> fenced; cleared from durable membership for volume <volume>
```

Never set the flag merely because the authority process or a network connection
stopped.

### Service hardening

The service manager should additionally provide a read-only root filesystem,
`NoNewPrivileges`, an empty capability bounding set, a private mount namespace,
a syscall allowlist, bounded file descriptors/tasks/memory, a restart policy,
and access to only the volume directory and the required credential files. Do
not expose the raw XFS mount to agent machines or containers.

Note one launch restriction that surprises operators: **user-xattr writes are
disabled.** XFS does not charge attribute-fork blocks to a project, so per-inode
RPC limits cannot isolate a shared cell, and a separate logical counter would
not be crash-atomic with XFS. The Linux frontend returns `EOPNOTSUPP` without
sending a mutation, and the authority rejects a direct or older-client set-xattr
request the same way. Read, list, and removal remain available for pre-existing
portable user attributes.

The authority prints its loaded routing revision at startup and refuses to serve
at all if the volume's machine-local routing declaration will not parse: a volume
with no loaded revision cannot tell an agreeing mount from a disagreeing one.

## Issuing credentials

A mount presents two independent credentials, and the authority requires both.

**Transport identity.** Sessions are mutual TLS 1.3 with
`RequireAndVerifyClientCert` against `--client-ca`, and ALPN
`portablefs-authority-v2`. Plaintext cannot mount.

**A mount capability.** A capability is an Ed25519-signed token of the form
`v1.<base64url payload>.<base64url signature>`, signed over a domain-separated
JSON payload with these claims:

| Claim | Meaning |
| --- | --- |
| `volume_id` | the exact volume; a token for another volume is refused |
| `subject` | the principal |
| `access` | `read`, `write` (implies read), or `admin` (implies read and write) |
| `not_before` / `expires` | validity window |
| `peer_spki_sha256` | base64url SHA-256 of the client certificate's SPKI |
| `nonce` | makes the capability single-use |

The authority enforces the window against `--capability-max-lifetime`
regardless of what was signed, so one minting mistake cannot produce a
capability nothing can revoke. It retains accepted nonces until they expire and
refuses a second presentation; if it cannot retain the record it refuses rather
than silently dropping replay protection. **Expiry is an absolute, non-renewable
mount-session deadline.** Keepalive is liveness only. Issue a new credential and
remount instead of extending an old grant.

Note that `write` deliberately does not imply `admin`: changing
`.portablefs/local-dirs` changes what every *other* machine can see, so an
ordinary mount's capability must not be able to do it.

### There is no minting service in this tree

Nothing in this repository runs as a control plane that authenticates a user,
places a volume, issues a client certificate, or mints a capability. Today an
operator or an integration mints capabilities out of band with
`volumecap.Sign` and hands each mount its address, its single-use capability,
and its client identity directly.

For a worked, runnable example of the complete credential set — a CA, a server
identity, a client identity, the Ed25519 capability key, and single-use
read/write and admin capabilities — see
`vcs/test/coherence/cmd/pfs-coherence-credentials`. It links the production
signer rather than reimplementing the token format, so a credential it produces
is one the authority will actually accept. It is a test harness tool, not a
production issuer: it writes private keys to a directory and has no identity,
audit, or revocation story.

The v3 control plane — grant minting bound to a locally generated client key,
ambiguous-creation receipts, and in-session reauthorization that may extend a
deadline but never broaden access — is future work. Its required contract is
described in [xfs-authority-architecture.md](./xfs-authority-architecture.md).
Until it exists, a long-lived mount ends at its capability's absolute deadline.

## Mounting from Linux

The ordinary client is `portablefs mount`, which attaches through FUSE and then
daemonizes, keeping its state under `~/.local/state/portablefs/mounts`.

```bash
portablefs mount vol_01JXYZ /workspace \
  --addr authority.example.internal:7443 \
  --mount-token "$CAP" \
  --data-plane-transport tls-private-ca \
  --data-plane-server-name authority.example.internal \
  --data-plane-ca /run/portablefs/server-ca.pem \
  --client-cert /run/portablefs/client.pem \
  --client-key /run/portablefs/client.key
```

Every mount takes the same direct v3 credential shape: `--addr`, a single-use
capability via `--mount-token` or `PORTABLEFS_MOUNT_TOKEN`, a verified TLS
transport, and a mutual-TLS client identity. `--data-plane-transport` is
required and must be `tls-private-ca` (with `--data-plane-server-name` and
`--data-plane-ca`) or `tls-system-pki` (with `--data-plane-server-name`);
`plaintext` is refused with the reason named. `--client-key` must be mode 0600.
Store the token and key in ordinary `0600` files.

`--coherence` picks the kernel cache contract: `strict` (default — names and
attributes are cached and repaired through the authority's synchronous
visibility barrier) or `uncached` (cache nothing; Linux only). `--foreground`
stays attached and unmounts on Ctrl-C. `--branch` and `--fast` are retired and
passing either is an error.

Machine-local directories are declared volume-wide in `.portablefs/local-dirs`,
not per mount. `--local-dir` is refused unconditionally, because a route only
one machine knows about desynchronizes the topology the authority pins every
mount to; `--no-local-dirs` refuses a declaring volume rather than ignoring its
routes.

`portablefs-mount-v3` is the standalone Linux mount binary the test harnesses
use, including `scripts/coherence-matrix-linux.sh`. It takes the credential set
as files rather than through the CLI's state directory:

```bash
portablefs-mount-v3 \
  --authority authority.example.internal:7443 \
  --volume-id vol_01JXYZ \
  --mountpoint /workspace \
  --access-token-file /run/portablefs/access.token \
  --tls-cert /run/portablefs/client.crt \
  --tls-key /run/portablefs/client.key \
  --tls-server-ca /run/portablefs/server-ca.pem \
  --tls-server-name authority.example.internal
```

All eight of those are required. Notable optional flags are `--coherence`
(`strict` default, or `uncached`), `--cached-name-capacity` (default `65536`),
`--repair-budget` (default `15s`, and the authority's `--max-repair-budget` must
be at least this), `--max-in-flight` (`128`), `--max-background` (`128`),
`--reclaim-queue` (`4096`), `--dial-timeout` (`10s`), `--cancel-drain-timeout`
(`10s`), `--request-timeout` (`45s`), `--local-backing`, and `--no-local-dirs`.
`--local-dir` exists only to be refused with an explanation. The mountpoint must
be a clean absolute path naming a real, empty directory that is not a symlink.

### What the Linux mount does and does not promise

The exact Linux mount uses direct I/O and does not advertise shared file-backed
`mmap`. It does not fall back to incoherent page caching. Process-local
`MAP_PRIVATE` mappings retain their ordinary copy-on-write semantics. Workloads
that require `MAP_SHARED` remain outside the launch compatibility contract until
a synchronous lease/invalidation design is implemented and proven.

There is no write-back cache: `write(2)` returns after the authority has applied
the bytes to XFS, and `fsync` waits for the authoritative server descriptor. Use
`fsync`/`fdatasync` on files and `fsync` on changed parent directories for
durability. Linux currently does not forward `syncfs(2)` to ordinary FUSE
userspace servers, so it is not a remote durability boundary for this mount.

SQLite is verified in rollback-journal mode. WAL mode is outside the
multi-machine contract because SQLite's wal-index requires shared memory among
all participants on one host; keep WAL databases local or use a database
service.

`portablefs umount <path>` runs the full drain barrier and fails, leaving the
mount attached, if the drain cannot complete. `--force` detaches without
draining; a v3 mount holds no client-side durability debt, so nothing is parked
and nothing is replayed — `--force` simply gives up on proving the drain.

## Mounting from macOS

macOS mounts through the PortableFS FSKit extension. There is one transport per
platform and no fallback: a host that cannot serve its platform's transport
fails with guidance rather than degrading to a weaker consistency model.

1. Install PortableFS.app from the notarized release (see
   [release-identity.md](./release-identity.md)).
2. Enable its File System Extension once, under System Settings ->
   General -> Login Items & Extensions -> File System Extensions. This is an
   interactive user-controlled toggle and is deliberately not automatable. The
   app never claims the toggle is on; only a successful mount verifies it.
3. Mount with the same `portablefs mount` command shape as Linux.

The CLI manages the `portablefsd` daemon, which owns the authority session.
Authority TLS credentials and replay secrets never cross the local frontend
socket to the extension. The daemon is always the exact `portablefsd` sibling
from the same installed release; `PORTABLEFS_FSKIT_DAEMON` is rejected.
`PORTABLEFS_FSKIT_SOCKET` and `PORTABLEFS_FSKIT_CONTROL_SOCKET` may override the
daemon sockets explicitly, and `PORTABLEFS_FSKIT_TYPE` may only assert the
signed release type.

Two current macOS restrictions:

- `--coherence uncached` is Linux only.
- macOS does not yet join the route adoption protocol, so a volume that declares
  machine-local routes mounts from Linux.

The macOS coherence policy that ships today is an explicitly declared
compatibility policy with open live-kernel gates. Read
[macos-26-coherence-contract.md](./macos-26-coherence-contract.md) before
treating a macOS mount as equivalent to a Linux one.

## Verifying cross-mount coherence

The claim this topology exists to support is that one volume mounted on several
machines behaves like one POSIX filesystem. That claim is verified by a runnable
matrix, not by inspection:

```bash
scripts/coherence-matrix-linux.sh
```

It provisions a real XFS cell with project quotas in a privileged container
using `scripts/provision-xfs-volume.sh`, mints credentials with
`pfs-coherence-credentials`, starts the real `portablefs-authority` process,
starts two real `portablefs-mount-v3` processes against it, and then drives both
mountpoints with ordinary syscalls from a separate black-box program
(`vcs/test/coherence/cmd/pfs-coherence-matrix`). Nothing is in process and no
kernel is faked, which is also what makes the last case possible: the mounts are
separate processes, so one can be killed uncleanly and the other required to
keep serving.

Each case asserts the real quantity. Content is compared against the bytes a
descriptor actually returns when read to EOF, never against `stat.Size`; the
namespace is compared against the entries `readdir` actually enumerates; an
atomic replacement is compared against the inode number the surviving mount
resolves. No case polls or retries: with zero cache timeouts the correct answer
is the first answer, so a case that needed a settling delay would be reporting a
defect, not a timing artefact.

The run has three phases. The first points the second mount at a directory that
is not the volume and requires every mountpoint-dependent case to fail. The
second replays mount A's first successful pathname observations and requires
every case declared sensitive to that stale-view fault to fail; stateful
descriptor behavior and the attach-time route contract are intentionally not
misclassified as pathname-cache tests. Only then does the third report the real
result. A case that misses its declared control result fails the job. A case
that cannot be honestly asserted — for example the ownership case with no
alternate GID available — skips with a stated reason and a nonzero exit, never a
quiet pass.

The case list, the falsifiability controls and the macOS half are documented in
[the cross-mount coherence matrix](./cross-mount-coherence-matrix.md).

`scripts/coherence-matrix-macos.sh` runs the same named cases against two live
mounts, either two on one Mac or one local macOS mount and a remote macOS or
Linux peer over ssh, so the platforms' matrices can be compared line for line.
It refuses to run against ordinary directories and skips loudly when the second
verified peer mount is unavailable.

## Failure and replacement

The launch topology has no automatic second writer. On instance failure:

1. prove the previous instance/process cannot write;
2. detach the EBS volume normally;
3. attach it to the replacement in the same AZ;
4. mount XFS and allow journal replay to finish;
5. start a fresh authority epoch — which means resolving durable strict
   membership as described in [Restarting the authority](#restarting-the-authority);
   and
6. publish the replacement endpoint.

All old sessions, handles, locks, and in-flight outcomes are stale. A client
never replays an uncertain mutation into the new epoch.

A storage `EIO` fences the store, cancels the server, and exits the authority
process with `authoritative storage failed and this epoch was fenced`. A strict
coherence failure exits the same way with `strict cache coherence failed and
this epoch was fenced`. Treat either exit as not-ready and investigate the
filesystem, device, or mount before restarting; do not restart-loop a volume
onto unhealthy storage. Fencing a *single* strict mount is different and is not
a process failure — it is logged as `fenced strict mount <id>` and the volume
keeps serving every other mount.

Do not call EBS Multi-Attach a replica and do not mount ordinary XFS read-write
on two hosts. Same-AZ active/passive later requires io2 NVMe reservations plus
independent STONITH fencing before promotion. Cross-AZ HA requires a separate
synchronous replication/quorum design or a validated managed filesystem.

Failure behavior visible to applications is enumerated in
[failure-modes.md](./failure-modes.md).

## Backups

Backups are disaster recovery, not live filesystem state. A controller should
quiesce the authority, sync/freeze XFS, take an application-consistent EBS
snapshot, and unfreeze promptly. Copy snapshots to the required account/region,
lock retention, and run scheduled restore tests. A snapshot is never mounted
inside the live namespace, and users see no snapshot, version, or branch
namespace — there is nothing to expose, because v3 keeps no history.

## Monitoring

Monitor EBS status, queue/latency/throughput, filesystem free space and inodes,
project quota headroom, authority restarts, TLS and capability rejection,
session count, open descriptors, request latency and error codes, and backup
restore age. Two log lines deserve alerts of their own: `refused strict attach`
(a mount declared a bound this authority will not accept) and `fenced strict
mount` (a mount left the visibility barrier).
