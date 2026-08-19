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

Two things an operator has to decide or accept before deploying:

- **Choose standalone or hosted lifecycle.** This runbook shows a directly
  operated authority and out-of-band credentials. The same repository now also
  contains a standalone hosted manager, outbound cell agent, narrow root helper,
  and systemd templates; see
  [hosted-control-plane.md](./hosted-control-plane.md) and
  [hosted-cell-deployment.md](./hosted-cell-deployment.md).
- **Lease recovery is TTL-bounded.** Clean detach returns leases immediately.
  After an unclean stop, the authority waits the maximum lease TTL plus clock
  skew before admitting conflicting mutations. See [Clean detach](#clean-detach)
  and [Restarting the authority](#restarting-the-authority).

## Host and disk

Use a current Nitro EC2 instance on a supported Linux baseline with stock FUSE
protocol 7.31 or newer (Linux 5.10 is the product floor). Attach a dedicated,
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
6. **Creates private transactional-write staging.** The 0700
   `<mount>/.portablefs-control/<volume-name>/write-staging` directory is owned by
   the service identity, carries the volume's exact XFS project ID and
   `PROJINHERIT`, and remains outside the served namespace. Unnamed O_TMPFILE
   staging therefore consumes the same hard quota as visible volume data rather
   than becoming an unbounded cell-wide side channel.

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
  --admin-listen 127.0.0.1:7444 \
  --volume-id vol_01JXYZ \
  --root /srv/portablefs/vol_01JXYZ \
  --project-id 42001 \
  --tls-cert /run/portablefs/server.crt \
  --tls-key /run/portablefs/server.key \
  --client-ca /run/portablefs/client-ca.pem \
  --capability-public-key /run/portablefs/capability-public.pem \
  --visibility-membership-file \
    /srv/portablefs/.portablefs-control/vol_01JXYZ/strict-membership \
  --write-staging-dir \
    /srv/portablefs/.portablefs-control/vol_01JXYZ/write-staging \
  --max-sessions 1024 \
  --max-connections 4096 \
  --max-lock-records 65536
```

### Required flags

All ten are mandatory and startup refuses without them.

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
| `--visibility-membership-file` | legacy-named durable session audit file; it is not a cache-coherence mechanism in protocol 6 |
| `--write-staging-dir` | private 0700 directory for unnamed transactional-write staging; the provisioner places it outside the served namespace under the volume's XFS project quota |

### Coherence and mount-lifecycle bounds

Protocol 6 bounds session authorization, session liveness, lease TTL, clock
skew, recall discharge, and the number of outstanding grants. Pin them
explicitly in production. A lease TTL is permission to cache, not a mutation
lease; every mutation remains write-through. The recall budget must be shorter
than the lease-expiry bound so a nonresponsive holder is fenced before the
authority relies on expiry. Exact flag names and defaults are printed by the
deployed protocol-6 authority and must be reviewed with its release manifest.

### Admin listener

`--admin-listen` defaults to `127.0.0.1:7444` and serves plaintext HTTP for
the node-local monitoring agent. It is a separate listener from the mutually
authenticated TLS data plane. Keep it on loopback or behind an authenticated
host-local proxy; the endpoint itself has no authentication layer and must not
be exposed to an untrusted network. Give each worker a distinct admin address
when several volume workers share one host.

The worker binds both listeners before it begins serving. An unavailable admin
address is therefore a startup failure, just like an unavailable authority
address: running without the declared monitoring surface would make a fresh
deployment deceptively healthy. An unexpected admin HTTP failure after a
successful bind is different. It is logged as `event=admin_listener_failed`
and does not stop the data plane; alert on the missing scrape and repair the
monitoring path without turning an observability fault into a filesystem
outage.

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
| `--max-items-per-session` | `65536` |
| `--max-opens` | `32768` |
| `--max-opens-per-session` | `4096` |
| `--max-retained-reply-bytes` | `512 MiB` |
| `--max-frame-bytes-in-flight` | `512 MiB` |
| `--max-in-flight` | `256` |
| `--max-write-transactions` | `4096` |
| `--max-write-transactions-per-session` | effective `--max-in-flight`, capped by `--max-write-transactions` (`256` with stock defaults) |
| `--max-connections` | `4096` |
| `--capability-nonce-records` | `65536` |
| `--tls-handshake-timeout` | `10s` |
| `--connection-idle-timeout` | `5m` |
| `--connection-write-timeout` | `30s` |

Startup cross-checks them rather than accepting any combination: `--max-frame-bytes`
must leave a fixed reserve around each read/write payload, `--max-retained-reply-bytes`
must admit at least one maximal reply, `--max-frame-bytes-in-flight` must admit at
least one maximal request, `--connection-idle-timeout` must exceed `--session-lease`,
and `--max-in-flight` must be at least 2 so an ordinary request can proceed
alongside a blocking lock wait. Protocol 6 also requires `--max-connections` to
be at least four times `--max-sessions`: two slots hold each mount's current
DATA and CONTROL lanes, while exact pair recovery must authenticate both
candidate roles before either old generation can be retired. The authority
refuses startup when that invariant is false; neither the old 2048-connection
default nor a 3072 three-slot configuration can recover every saturated mount
without waiting for an old connection to time out.

Protocol-6 frames account protobuf metadata and the one optional bulk body
together against both `--max-frame-bytes` and
`--max-frame-bytes-in-flight`. The inbound reservation remains charged while a
handler references the body and is released only after that handler returns.
An out-of-line body on a message that does not declare one closes the connection
as malformed.

### Clean detach

The Linux supervisor first closes request admission, drains in-flight work,
returns every lease, closes the FUSE connection, verifies the recorded mount ID
is gone from `/proc/self/mountinfo`, and sends authenticated detach for that
exact session. A lazy detach with retained references is not clean while its
serve loop remains capable of answering.

If any step fails, the supervisor does not invent success. The authority fences
the session and relies on lease expiry before conflicting work proceeds. The
client model is cooperative rather than Byzantine: the authority authenticates
which session reported detach but cannot independently inspect a remote kernel.

### Restarting the authority

The v1 lease table is volatile. A restarted authority creates a new epoch,
refuses old sessions, and holds a grace period for the configured conservative
maximum lease-expiry bound before admitting any mutation that could conflict
with an unknown prior lease. Do not shorten or bypass this grace merely because the
old authority process is gone. Fencing a host can make the old cache unservable,
but it does not rewrite the configured lease bound.

### Service hardening

The service manager should additionally provide a read-only root filesystem,
`NoNewPrivileges`, an empty capability bounding set, a private mount namespace,
a syscall allowlist, bounded file descriptors/tasks/memory, a restart policy,
and access to only the volume directory and the required credential files. Do
not expose the raw XFS mount to agent machines or containers.

Note one launch restriction that surprises operators: **user-xattr writes are
disabled.** XFS does not charge attribute-fork blocks to a project, so per-inode
RPC limits cannot isolate a shared cell, and a separate logical counter would
not be crash-atomic with XFS. Because authority protocol v5 requires the exact
`user-xattr-readonly` feature at Activate, the Linux frontend validates the FUSE
flags and returns `EOPNOTSUPP` locally without spending an authority RPC, replay
sequence, or visibility transition. Direct authority requests receive the same
answer. Read, list, and removal remain available for pre-existing portable user
attributes.

The macOS resolve contract separately declares xattr set unsupported while
leaving read/list/removal enabled. FSKit validates set input and refuses it
locally without a daemon mutation, reporting `EOPNOTSUPP` (Darwin errno 102) to
callers. It must not expose its internal Darwin `ENOTSUP` (45), because XNU
interprets 45 as permission to create an AppleDouble `._*` sidecar. A sidecar
on a PortableFS mount is a contract violation, not an expected compatibility
file.

The authority prints its loaded routing revision at startup and refuses to serve
at all if the volume's machine-local routing declaration will not parse: a volume
with no loaded revision cannot tell an agreeing mount from a disagreeing one.

## Issuing credentials

A mount presents two independent credentials, and the authority requires both.

**Transport identity.** Sessions are mutual TLS 1.3 with
`RequireAndVerifyClientCert` against `--client-ca`, and ALPN
`portablefs-authority-v6`. Plaintext cannot mount. Every active session owns one
DATA and one CONTROL connection in the same authenticated connection set; a
single transport cannot attach active and there is no older-protocol path.

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

An automatic in-session grant additionally carries `mount_enrollment_id`, the
exact authority session ID, and its monotonic sequence. It omits the expired
product token: the Manager signature attests that the durable, originally
product-authorized enrollment is still active. This basis is never accepted for
an initial attach.

The authority enforces the window against `--capability-max-lifetime`
regardless of what was signed, so one minting mistake cannot produce a
capability nothing can revoke. It retains accepted nonces until they expire and
refuses a second presentation; if it cannot retain the record it refuses rather
than silently dropping replay protection. In standalone mode, **expiry is the
absolute mount-session deadline**. Keepalive is liveness only. Hosted mode can
extend the deadline only through the separately signed, session-bound,
monotonic `Reauthorize` operation described below.

Note that `write` deliberately does not imply `admin`: changing
`.portablefs/local-dirs` changes what every *other* machine can see, so an
ordinary mount's capability must not be able to do it.

### Standalone minting and the hosted issuer

For a standalone authority, an operator or integration mints capabilities out
of band with
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

The hosted `portablefs-manager` implements grant minting bound to a locally
generated client key, byte-identical idempotency receipts, independent product
and infrastructure signatures, and bounded key-scoped mount enrollments. The
per-mount owner uses an enrollment to obtain exact, short-lived in-session
reauthorizations without keeping the original product assertion alive. The
manager does not authenticate end users itself; it verifies the product's
signed authorization at enrollment creation. See
[hosted-control-plane.md](./hosted-control-plane.md). A standalone mount has no
manager to ask, so it renews from the credential file its own issuer rotates:
see [Renewing a standalone mount](#renewing-a-standalone-mount).

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

Protocol 6 has one lease-coherence contract. Every cacheable name, attribute,
clean-data, or directory-enumeration answer requires an N/A/D/E lease. A
conflicting mutation recalls peer leases and waits for discharge before the
mutating syscall returns. The source response is the publication boundary;
there is no private kernel publication message.
`--coherence uncached` is retired and rejected before Attach; it is never an
alias for `strict` and never selects a fallback. `--foreground` stays attached
and unmounts on Ctrl-C. `--branch` and `--fast` are also retired and passing any
of these retired options is an error.

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
(`strict` is the only accepted value), `--cached-name-capacity` (default
`65536`), `--repair-budget` (default `15s`, and the authority's
`--max-repair-budget` must be at least this), `--max-in-flight` (`128`),
`--max-background` (`128`),
`--reclaim-queue` (`4096`), `--dial-timeout` (`10s`), `--cancel-drain-timeout`
(`10s`), `--request-timeout` (`45s`), `--local-backing`, and `--no-local-dirs`.
`--local-dir` exists only to be refused with an explanation. The mountpoint must
be a clean absolute path naming a real, empty directory that is not a symlink.

### Renewing a standalone mount

A capability is short lived and the authority bounds it further with
`--capability-max-lifetime`. Session keepalive never extends a signed
authorization deadline; only a new session-bound signed authorization does. A
mount that never gets one is fenced when its deadline passes, and every open
file under it fails.

`portablefs-mount-v3` therefore renews from `--access-token-file`, the same file
it attached with. There is no second flag and no second credential path: the
issuer that minted the attach capability rotates the file in place, and the
mount picks it up. Renewal is always running, so there is no configuration in
which it is off.

A reauthorization capability is bound to one session and one exact sequence, so
the mount publishes both. At mount time it logs

```
authorization session <id> expires <RFC3339>; write the capability for sequence 1
of this session to /run/portablefs/access.token to extend it
```

and after each renewal it logs the next sequence and the new deadline. Mint the
replacement with `volumecap.Sign`, setting `session_id` and `sequence` to the
logged values, the same `volume_id` and `peer_spki_sha256` as the attach
capability, and access no broader than the mount already holds — the authority
fences a session that is offered more access than it holds, and the mount
refuses to present such a capability rather than provoke that. Replace the file
atomically (write a sibling, then `rename`); mode `0600` is enforced on every
read, as it is at startup.

Rotation is the operator's only obligation and failing to meet it is safe. The
mount retries with backoff, and if no usable capability appears before a safety
margin ahead of the deadline it unmounts itself while its current authorization
is still valid. That is the same fail-closed end state as having no renewal at
all, reached slightly earlier and as an orderly unmount rather than as
`ESTALE` in the middle of application I/O. The margin is a tenth of the
authorization window, at least five seconds and at most a minute.

Access may narrow across renewals and never broadens: a mount can be demoted to
read-only by rotating in a narrower capability, and the narrowed access becomes
the ceiling for every later renewal.

The mutual-TLS client identity is not renewed this way. The capability is bound
to that key, so `--tls-cert` must outlive the mount.

### What the Linux mount does and does not promise

Write-capable Linux opens use direct I/O. Read-only opens may retain clean
kernel pages under D leases. Shared writable file-backed `mmap` is refused;
read-only and `MAP_PRIVATE` mappings use the clean-data regime. There is no
incoherent page-cache fallback.

There is no write-back cache: `write(2)` returns after the authority has applied
the bytes to XFS, and `fsync` waits for the authoritative server descriptor. Use
`fsync`/`fdatasync` on files and `fsync` on changed parent directories for
targeted durability. FUSE SYNCFS is used when the stock kernel advertises it.
The 7.31 floor predates that request, so PortableFS does not claim a remote
volume `syncfs(2)` barrier on every supported kernel and does not emulate one.

SQLite is verified in rollback-journal mode. WAL mode is outside the
multi-machine contract because SQLite's wal-index requires shared memory among
all participants on one host; keep WAL databases local or use a database
service.

`portablefs umount <path>` runs the full drain barrier and fails, leaving the
mount attached, if the drain cannot complete. `--force` detaches without
draining; a v3 mount holds no client-side durability debt, so nothing is parked
and nothing is replayed — `--force` simply gives up on proving the drain.

## Mounting from macOS

The shipping macOS build refuses protocol-6 FSKit mounting before it
constructs an authority transport or sends Attach. Current public FSKit has no
exact peer namespace/attribute invalidation primitive, and the macOS 26 callback
result shapes cannot publish the complete post-mutation attributes required by
the lease-discharge contract. This is a production admission decision, not a
runtime feature flag: there is no opt-in, `uncached` mode, or fallback.

1. Install PortableFS.app from the notarized release (see
   [release-identity.md](./release-identity.md)).
2. Enable its File System Extension once, under System Settings ->
   General -> Login Items & Extensions -> File System Extensions. This is an
   interactive user-controlled toggle and is deliberately not automatable. The
   app never claims the toggle is on; only a successful mount verifies it.
3. Do not issue a production mount until a release explicitly qualifies the
   native FSKit repair contract. The current daemon returns the admission error
   without opening an authority session.

The host's launchd-managed `portablefsd` owns the authority session; the CLI
adopts it through the external owner-private control socket or wakes the exact
containing app through NSWorkspace.
An NSWorkspace callback timeout is an ambiguous request outcome, not a failed
or successful daemon launch. The CLI proceeds only to a bounded exact control
socket and release-identity proof; an explicit callback error still fails. The
native bridge issues the request only from the process main thread and pumps
that thread's RunLoop until the callback or timeout. A wrong-thread call is a
definite pre-request refusal, never launch ambiguity.
Authority TLS credentials and replay secrets never cross the local frontend
socket to the extension. The daemon is always the exact `portablefsd` inside
the sealed `PortableFSDService.app` from the same installed release;
`PORTABLEFS_FSKIT_DAEMON` is rejected. The
frontend sockets are fixed by the release's signed app-group identity and the
control socket is fixed under canonical account state, so
`PORTABLEFS_FSKIT_SOCKET` and `PORTABLEFS_FSKIT_CONTROL_SOCKET` are rejected.
`PORTABLEFS_FSKIT_TYPE` may only assert the signed release type.

A separately build-stamped qualification artifact may exercise the candidate
native-revocation policy and remains fail-closed on any unrepresentable repair;
it is not a shipping compatibility path. macOS also does not yet join the route
adoption protocol. Read
[macos-26-coherence-contract.md](./macos-26-coherence-contract.md) for the live
evidence and remaining platform gates.

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

Scrape `http://127.0.0.1:7444/metrics` in Prometheus text exposition format.
The admin listener also serves:

- `GET /healthz`: HTTP 200 while the process and admin HTTP server are live. It
  deliberately says nothing about whether the worker can serve filesystem
  requests.
- `GET /readyz`: HTTP 200 only while the validated TLS accept loop is active,
  the volume remains open and unfenced, and a fresh `statx` through the already
  open authoritative XFS root descriptor succeeds. It returns 503 during
  startup, shutdown, and after a terminal storage fence. The probe never
  re-resolves the configured root path.

Every series has the bounded `volume` label. RPC series use a closed opcode
set; write transactions are split into `write_transaction_begin`, `_data`,
`_commit`, and `_abort`, because those phases have different load and failure
profiles. `portablefs_authority_rpc_requests_total` adds one closed `outcome`
label: `success`, `not_found`, `permission`, `stale`, `invalid`, `saturation`,
`unsupported`, `conflict`, `canceled`, `storage`, `internal`, `coherence`,
`routes`, `visibility_interrupted`, `visibility_retry`, `io`, or `other`.
The storage, internal, coherence, routes, and visibility values come from the
protocol's explicit failure class; the remaining values group Linux wire
errnos. No peer-controlled string or numeric request ID becomes a metric
label.

| Metric | Operational question |
| --- | --- |
| `portablefs_authority_rpc_requests_total{opcode,outcome}` | Which operation is failing, saturating, or being retried, and in which semantic errno class? |
| `portablefs_authority_rpc_duration_seconds{opcode}` | Which operation is consuming the handler latency budget? |
| `portablefs_authority_active_sessions` | How many mounts are currently ACTIVE, rather than merely provisional or draining? |
| `portablefs_authority_session_items_high_water` | Has one session approached `--max-items-per-session` since this worker started? The shared root descriptor is excluded, matching the configured bound. |
| `portablefs_authority_write_transactions_active` | How much of the configured transaction-count admission capacity is occupied? |
| `portablefs_authority_write_transactions_waiting` | Is the FIFO write admission queue currently saturated? |
| `portablefs_authority_write_staged_bytes` | How many payload bytes currently live in inert transaction staging? This is actual DATA received, not the larger requested-size reservation. |
| `portablefs_authority_write_admission_blocks_total` | How often did a BEGIN find transaction-count or byte capacity unavailable? |
| `portablefs_authority_write_admission_wait_seconds` | How long did blocked BEGIN requests remain in FIFO capacity admission? |
| `portablefs_authority_fsync_barrier_handles_total` / `portablefs_authority_fsync_storage_syncs_total` | How many fsync barrier requests did each completed storage sync serve? The ratio is group-commit effectiveness. |
| `portablefs_authority_visibility_barrier_duration_seconds` | How long did PREPARE, XFS apply, and peer COMPLETE acknowledgment take end to end? |
| `portablefs_authority_visibility_barrier_audience` | How many peer sessions had cache state to repair for each barrier? Routing changes count every strict participant. |
| `portablefs_authority_fence_events_total{reason}` | Why was a participant told to revoke: `visibility_lost`, `repair_deadline`, `routes_blocked`, `protocol_violation`, `write_transaction_mismatch`, or `other`? |

The counters and gauges are atomics. RPC counter handles and every label set are
precomputed at startup; a request does no metric-map lookup, label formatting,
or allocation. Histograms use fixed buckets and render cumulative buckets only
at scrape time. The worker has no Prometheus client-library dependency.

Start with these alerts and tune duration windows from production baselines:

- page when `/readyz` is not 200 for a running unit, or when the admin target is
  absent while the authority TLS port still accepts connections;
- page on any sustained increase in RPC outcomes `storage`, `internal`, or
  `coherence`; investigate `io` and `other` immediately because they are
  unclassified or direct I/O failures even when the epoch has not yet exited;
- alert when `write_transactions_waiting` remains nonzero, the rate of
  `write_admission_blocks_total` rises, or admission-wait p95 consumes a
  material fraction of `--write-transaction-progress-timeout`;
- alert before active transactions or staged bytes reach their configured
  worker bounds, and before `session_items_high_water` reaches
  `--max-items-per-session`;
- compare visibility-barrier p99 with `--max-repair-budget`. A tail approaching
  that budget predicts participant fencing; correlate it with audience size to
  distinguish one slow mount from broad fan-out;
- alert on every `repair_deadline`, `protocol_violation`, or
  `write_transaction_mismatch` fence. A visibility-lost fence may accompany a
  deliberate host loss, but it still leaves durable membership requiring the
  restart proof described above.

Continue monitoring EBS status and latency, filesystem and project-quota block
and inode headroom, process restarts, file descriptors, TLS/capability
rejections at the service boundary, and backup restore age; those facts are
outside this per-worker registry.

RPC lifecycle results and non-routine failures are also structured on stderr
with `volume`, `request_id`, `session`, `opcode`, `outcome`, `errno`, and
`duration_us`. Participant fencing and refused commitments retain the existing
operator-facing `fenced strict mount` and `refused strict attach` lines, and add
structured companion events with volume, session, and reason. Routine POSIX
results such as a missing lookup are counted but not logged per request. Logs
are for correlation by request ID; metrics and readiness, rather than grepping
two string literals, are the monitoring contract.
