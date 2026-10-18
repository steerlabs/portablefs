# Deploying and self-hosting an authoritative-XFS volume

Status: **the deployment runbook for authority protocol 8; specified and not yet
qualified.** The open gates are listed in
[COMPATIBILITY.md](../COMPATIBILITY.md#qualification-status).

This is the operator's runbook: provisioning storage, running the authority,
issuing credentials, mounting from Linux and macOS, operating the volume, and
handling failure. See
[xfs-authority-architecture.md](./xfs-authority-architecture.md) for why the
stack looks like this and [COMPATIBILITY.md](../COMPATIBILITY.md) for the exact
versions and frozen surfaces.

The launch topology is one active authority process per volume over one
encrypted XFS filesystem. It is single-AZ durable storage, not multi-AZ high
availability, and it has no automatic second writer. Protocol-8 deployments are
provisioned fresh: the membership file and every other private format carry
one exact marker, and no earlier format is read or converted.

Decide or accept three things before deploying:

- **Standalone or hosted lifecycle.** This runbook shows a directly operated
  authority with out-of-band credentials. The repository also contains a
  hosted manager, an outbound cell agent, a narrow root helper, and systemd
  templates; see [hosted-control-plane.md](./hosted-control-plane.md) and
  [hosted-cell-deployment.md](./hosted-cell-deployment.md).
- **The shared-cell durability domain.** Volumes on one XFS filesystem share
  its writeback-error and latency domain. Read
  [Shared-cell durability domain](#shared-cell-durability-domain) before
  choosing how many volumes a filesystem carries.
- **Restart recovery is bounded, not instant.** A clean detach discharges a
  mount as soon as its admitted work drains. After an unclean stop, the restarted authority fences
  prior Linux caches through one subscription horizon and prior Mac membership
  through a fixed writer grace plus operator reconciliation; see
  [Restarting the authority](#restarting-the-authority).

## Host and disk

Use a current Nitro EC2 instance running Linux 5.17 final or newer for the
authority. Storage startup refuses older kernels and 5.17 release candidates;
release candidates of later versions are accepted. A vendor kernel with a lower
release number is refused even if it carries backports. Handleless FSKit
mutations and the Linux root-directory barrier rely on syncfs reporting XFS
log-force errors; mainline 5.17 includes both
[the XFS error propagation](https://github.com/torvalds/linux/blob/v5.17/fs/xfs/xfs_super.c#L689-L707)
and [the VFS sync_fs error propagation](https://github.com/torvalds/linux/blob/v5.17/fs/sync.c).
The Linux mount client separately requires stock FUSE protocol 7.31 or newer
(Linux 5.10 or newer).

Attach a dedicated, encrypted EBS data volume with `DeleteOnTermination=false`.
Choose gp3 or io2 from measured IOPS, throughput, latency, and durability
requirements; the architecture does not impose one capacity tier. Do not use EBS
Multi-Attach: two hosts mounting ordinary XFS read-write is data loss, not
replication.

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

## Shared-cell durability domain

Every volume provisioned on one XFS filesystem is a project directory on the
same superblock. That filesystem is one durability-error and latency domain,
and sizing and qualification must treat it as one.

**Which barriers are shared.** A FSKit mutation without a retained syncable
description (namespace changes and item-backed metadata), and the Linux
root-directory barrier, persist through `syncfs` on the authority's retained
XFS-root description. A handle-backed FSKit mutation and a Linux file fsync
use the file's own description instead.

**Errors.** Since Linux 5.8, `syncfs` reports the superblock-wide writeback
error sequence against the cursor stored in the calling open file
description; it is not a per-inode or per-project query. A writeback or log
failure caused by another project's inode can therefore surface at this
volume's next `syncfs`. The authority treats every failed barrier as a storage
failure: it fences this volume's store, retains the first failure, and exits
the epoch (see [Failure and replacement](#failure-and-replacement)). It never
filters, relabels, resets, or ignores such an error, and it never rotates its
root description to obtain a fresh cursor. Separate workers' descriptions hold
separate cursors against the same sequence, so one fault is not observed by
every volume at the same instant, and a description opened after a fault need
not report it.

**Latency.** `sync_filesystem` schedules and waits for the whole filesystem's
dirty inodes, not a project-filtered set. Another project's dirty data, and
contention on the shared log and device, lengthen this volume's handleless
FSKit mutation replies and Linux run barriers. A reservation or project quota
does not bound that wait.

**What does not isolate.** Project quotas, per-volume service identities,
private mount namespaces, and one worker per volume do not separate either
effect. They confine access and capacity, not the superblock.

**Project-quota exhaustion.** XFS reserves project quota and free space when it
accepts delayed-allocation writes, so exhausting one project's quota is
normally a synchronous `ENOSPC` refusal at reservation inside that project, not
an established tenant-triggered asynchronous fault in a neighbor. Reservation
does not prove later writeback succeeds: I/O faults, log shutdown, and
delayed-allocation conversion failures remain possible and propagate as above.

**Isolation.** A deployment that needs durability-error or latency isolation
places each volume on its own filesystem. Even then, filesystems on one device
share device contention and media failure; separate filesystems are not
separate failure domains for the device. Loop files on one shared backing
filesystem add an allocation layer and do not establish independent domains.
The repository's provisioning and hosted cell tooling place volumes as
projects on one shared cell; they do not create a filesystem per volume.

**Sizing.** Count every project on the filesystem when budgeting barrier
latency, not just the volume under test. Watch
`portablefs_authority_fskit_durability_duration_seconds{target="syncfs"}` per
volume ([Monitoring](#monitoring)); a tail that tracks a neighbor's write load
is this domain, not a defect in that volume's worker.

**Qualification status.** A real two-project XFS writeback fault observed by a
healthy neighbor's barrier, the dirty-neighbor barrier-latency measurement, and
the separate-filesystem control have not been run on protocol 8. Until they
are, the statements above rest on the kernel source and the authority's
storage-failure policy, not on a measured cell.

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
nonzero and at most 4294967294; the all-ones value is the `chown(2)` sentinel,
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
   project and its quota, which is the whole quota guarantee. The check reads
   `fsxattr` rather than parsing `xfs_quota`'s progress text.
4. **Chowns the staging directory to the service UID/GID and publishes it** by
   renaming it to `<mount>/<volume-name>`, with `sync -f` on the mount to force
   the quota transaction as well as the directory metadata.
5. **Creates the private control directory.** `<mount>/.portablefs-control` is
   `root:root` mode 0711; `<mount>/.portablefs-control/<volume-name>` is mode 0700
   owned by the service UID/GID. The authority's durable mount membership file,
   `mount.membership`, lives there: beside the volumes but outside the
   user-visible project directory, so an authority restart cannot forget a
   still-mounted kernel while agents can never reach or mutate the record through
   PortableFS.

The authority writes no payload or staging file outside the served namespace;
write payloads stay in bounded frame memory. On success the script prints the
destination, project, owner, limits, and the exact membership path to pass to
the authority.

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

Use one sandboxed worker per active volume. A stable per-volume Unix identity
plus a private mount namespace prevents a compromised worker from opening
another tenant's directory. Consolidating hostile volumes into one unsandboxed
process would weaken that boundary and is not an allowed optimization. It does
not change the shared-cell durability domain above.

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
  --mount-membership-file \
    /srv/portablefs/.portablefs-control/vol_01JXYZ/mount.membership \
  --max-sessions 1024 \
  --max-connections 4096 \
  --max-lock-records 65536
```

### Required flags

All nine are mandatory and startup refuses without them. A systemd-activated
listener replaces `--listen`.

| Flag | Meaning |
| --- | --- |
| `--listen` | TCP address to listen on, unless systemd passes the listener |
| `--volume-id` | exact volume identity served by this process |
| `--root` | absolute provisioned XFS project-directory root |
| `--project-id` | expected nonzero XFS project ID |
| `--tls-cert` | server certificate PEM |
| `--tls-key` | server private key PEM; must be a regular file unreadable by group and other, opened `O_NOFOLLOW` |
| `--client-ca` | client CA bundle PEM |
| `--capability-public-key` | one `PUBLIC KEY` PEM block holding an Ed25519 key; anything else is refused |
| `--mount-membership-file` | absolute path ending in `mount.membership`, in a directory with no group or other permission bits |

The membership file holds the exact durable set of mounted sessions and their
profiles (`linux`, `fskit-exclusive`, `cacheless`) under the header
`PFS-MEMBERSHIP-1`, through the one codec the cell host also uses. The
authority creates it empty on first start, holds `mount.membership.lock` for its
lifetime, and refuses to start on a malformed record, an unknown profile, a
different volume binding, or a file larger than 1 MiB. It is restart safety
state, not a cache.

### Mount lifecycle bounds

| Flag | Default | Meaning |
| --- | --- | --- |
| `--session-lease` | `2m` | renewable session lease; at least `1s` |
| `--capability-max-lifetime` | `15m` | longest capability validity window honoured, whatever was signed |
| `--terminal-delivery-timeout` | `45s` | drain from a terminal exact result through source kernel publication receipt |
| `--mount-absence-clock-skew` | `5s` | clock disagreement tolerated when a mount timestamps its own kernel-mount absence |
| `--prior-strict-mounts-fenced` | off | operator assertion that every recorded prior mount is unusable; see [Restarting the authority](#restarting-the-authority) |

Cache horizons are not configurable. The Linux subscription horizon is 10
seconds, renewed every 3; the FSKit KeepAlive cache proof is at most 60
seconds; both are part of the protocol, not deployment settings.

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
| `--max-connections` | `4096` |
| `--capability-nonce-records` | `65536` |
| `--tls-handshake-timeout` | `10s` |
| `--connection-idle-timeout` | `5m` |
| `--connection-write-timeout` | `30s` |

There is no separate write-admission queue, byte budget, or write timer. Frame
bytes, per-connection execution lanes, replay slots and retained reply bytes,
and the session, connection, item, and open limits are the bounded owners of a
write. An applied mutation keeps its resources through durability and replay
settlement.

Startup cross-checks the bounds rather than accepting any combination:

- `--max-in-flight` must be at least 9. The authority serves Linux mounts, and
  a Linux DATA connection reserves a mandatory ordered delegated-flush window of
  4 beside its ordinary and blocking lanes; there is no serial alternative.
- `--max-frame-bytes` must leave a fixed reserve around each read/write payload,
  and `--max-retained-reply-bytes` must admit at least one maximal reply.
- `--max-frame-bytes-in-flight` must admit one maximal DATA allocation (rounded
  to its 64 KiB frame-pool class) plus a fixed 12 MiB CONTROL/bootstrap reserve:
  64 allocations at the 192 KiB CONTROL frame cap. The floor is 13,697,024 bytes
  with the default 1 MiB write bound. All inbound frames share that total; DATA
  acquisitions must leave the reserve available, while CONTROL and bootstrap may
  use any available bytes. The reserve protects against DATA saturation, not
  saturation by CONTROL itself.
- `--connection-idle-timeout` must exceed `--session-lease`.
- `--max-connections` must be at least four times `--max-sessions`. Each mount
  holds one DATA and one CONTROL connection, and exact pair recovery must
  authenticate both replacement roles before either old generation retires, so
  a recovering mount transiently holds four.

Frames account protobuf metadata and the one optional bulk body together
against both `--max-frame-bytes` and `--max-frame-bytes-in-flight`. Only READ
and WRITE carry bulk. The inbound reservation remains charged while a handler
references the body and is released only after that handler returns. An
out-of-line body on a message that does not declare one closes the connection
as malformed.

### Clean detach

A Linux supervisor first closes request admission, drains in-flight work and
delegated writes, closes the FUSE connection, verifies the recorded mount ID is
gone from `/proc/self/mountinfo`, and sends authenticated detach for that exact
session. A lazy detach with retained references is not clean while its serve
loop remains capable of answering. A Mac daemon delivers the exact kernel
absence proof for the original mount on its original CONTROL transport.

If any step fails, the client does not invent success. The authority fences the
session; Linux peers wait out its subscription horizon and a Mac's writer
exclusion persists until its proofs expire and its admitted work drains. The
client model is cooperative rather than Byzantine: the authority authenticates
which session reported detach but cannot independently inspect a remote kernel.

### Restarting the authority

Sessions, subscriptions, delegations, handles, locks, and replay outcomes are
epoch-local. A restarted authority creates a new epoch and refuses old
sessions. Durable mount membership is what it remembers:

- **Prior Linux membership.** The authority admits no conflicting write until
  one subscription horizon (10 seconds) after startup, the longest any prior
  Linux mount could still have served cached state.
- **Prior FSKit membership.** The authority refuses Linux visible mutations and
  write-intent opens for 61.06 seconds on `CLOCK_BOOTTIME`: the 60-second
  maximum KeepAlive cache proof plus its clock margin. The wait starts only
  after safe takeover: exclusive ownership of the volume root and membership
  file, irreversibly closed predecessor renewal, and completion of every
  predecessor storage apply. Linux reads continue during that window, and the
  wait restarts with every authority restart. Mac activation additionally
  requires operator reconciliation; the timer never clears that membership.

Startup refuses an unusable continuous clock even when prior membership was
reconciled, because the new epoch may grant proofs. The restart bound assumes
the predecessor's renewal and storage work have irrevocably stopped; process
disappearance alone is not that proof. The root flock does not fence another
host: promoting a replacement authority on another host requires independent
fencing first. Do not shorten or bypass these waits because the old process is
gone.

Reconciliation is `--prior-strict-mounts-fenced`: an unverified operator
assertion that every recorded prior kernel mount is unusable. It is the only
input that clears durable membership. Before rewriting the membership file the
authority appends and fsyncs an audit record per cleared session to
`mount.membership.audit`, and it logs each cleared session on stderr. Use it
only with evidence, such as proof that the old host is powered off or the old
kernel mount is gone.

### Service hardening

The service manager should additionally provide a read-only root filesystem,
`NoNewPrivileges`, an empty capability bounding set, a private mount namespace,
a syscall allowlist, bounded file descriptors/tasks/memory, a restart policy,
and access to only the volume directory, its control directory, and the
required credential files. Do not expose the raw XFS mount to agent machines or
containers.

One launch restriction surprises operators: **user-xattr writes are refused.**
XFS does not charge attribute-fork blocks to a project, so per-inode RPC limits
cannot isolate a shared cell, and a separate logical counter would not be
crash-atomic with XFS. The Linux frontend validates the FUSE flags and returns
`EOPNOTSUPP` locally without spending an authority request or replay sequence;
direct authority requests receive the same answer. Read, list, and removal
remain available for portable `user.*` attributes.

The macOS frontend refuses xattr set locally after validating the request and
the live item, reporting `EOPNOTSUPP` (Darwin errno 102). It must not expose
Darwin `ENOTSUP` (45), because XNU interprets 45 as permission to create an
AppleDouble `._*` sidecar. A sidecar on a PortableFS mount is a contract
violation, not an expected compatibility file.

The authority prints its loaded routing revision at startup and refuses to serve
at all if the volume's machine-local routing declaration will not parse: a volume
with no loaded revision cannot tell an agreeing mount from a disagreeing one.

## Issuing credentials

A mount presents two independent credentials, and the authority requires both.

**Transport identity.** Sessions are mutual TLS 1.3 with
`RequireAndVerifyClientCert` against `--client-ca`, and ALPN
`portablefs-authority-v8`. Plaintext cannot mount. Every active session owns one
DATA and one CONTROL connection in the same authenticated connection set; a
single transport cannot activate. Hello carries exactly protocol major 8 and
one frontend profile; an unequal major is refused at the handshake and there is
no feature negotiation.

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

The token's `v1` prefix names the capability format, not the authority
protocol. An automatic in-session grant additionally carries
`mount_enrollment_id`, the exact authority session ID, and its monotonic
sequence. It omits the expired product token: the Manager signature attests
that the durable, originally product-authorized enrollment is still active. This
basis is never accepted for an initial attach.

The authority enforces the window against `--capability-max-lifetime`
regardless of what was signed, so one minting mistake cannot produce a
capability nothing can revoke. It retains accepted nonces until they expire and
refuses a second presentation; if it cannot retain the record it refuses rather
than silently dropping replay protection. In standalone mode, **expiry is the
absolute mount-session deadline**. KeepAlive is liveness only. Hosted mode can
extend the deadline only through the separately signed, session-bound,
monotonic `Reauthorize` operation described below.

`write` deliberately does not imply `admin`: changing `.portablefs/local-dirs`
changes what every *other* machine can see, so an ordinary mount's capability
must not be able to do it.

### Standalone minting and the hosted issuer

For a standalone authority, an operator or integration mints capabilities out
of band with `volumecap.Sign` and hands each mount its address, its single-use
capability, and its client identity directly.

For a worked, runnable example of the complete credential set (a CA, a server
identity, a client identity, the Ed25519 capability key, and single-use
read/write and admin capabilities), see
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

The ordinary client is `portablefs mount`, which attaches through FUSE under
`FRONTEND_PROFILE_LINUX` and then daemonizes, keeping its state under
`~/.local/state/portablefs/mounts`. That private state carries exact format
markers (mount state schema 1, active-route state schema 1, operation intent
schema 3) and fails closed on any other marker; an earlier client's records are
not read or converted.

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

Every mount takes the same direct credential shape: `--addr`, a single-use
capability via `--mount-token` or `PORTABLEFS_MOUNT_TOKEN`, a verified TLS
transport, and a mutual-TLS client identity. `--data-plane-transport` is
required and must be `tls-private-ca` (with `--data-plane-server-name` and
`--data-plane-ca`) or `tls-system-pki` (with `--data-plane-server-name`);
`plaintext` is refused with the reason named. `--client-key` must be mode 0600.
Store the token and key in ordinary `0600` files. `--foreground` stays attached
and unmounts on Ctrl-C. There is no cache-mode selector: one profile, no
fallback.

Machine-local directories are declared volume-wide in `.portablefs/local-dirs`,
not per mount. The mount adopts the volume's declaration through the attach
refusal and presents its revision, because a route only one machine knows about
desynchronizes the topology the authority pins every mount to.

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

All eight of those are required. Notable optional flags are
`--name-cache-capacity` (default `65536`, the local bound on names, attributes,
and proven absences the daemon caches under its subscription),
`--withdrawal-timeout` (default `15s`, the bound on one withdrawal of kernel
cache state before the mount revokes itself), `--max-in-flight` (`128`; at
least 9), `--max-background` (`128`), `--reclaim-queue` (`4096`),
`--dial-timeout` (`10s`), `--cancel-drain-timeout` (`10s`), `--request-timeout`
(`45s`), `--local-backing`, and `--no-local-dirs`. Neither cache bound is
declared to the authority. The mountpoint must be a clean absolute path naming
a real, empty directory that is not a symlink.

### Renewing a standalone mount

A capability is short lived and the authority bounds it further with
`--capability-max-lifetime`. Session KeepAlive never extends a signed
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
capability, and access no broader than the mount already holds. The authority
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

The cache contract is the volume subscription and per-file write delegations
in [portable-coherence.md](./portable-coherence.md). Names, attributes, clean
data, and directory listings are cached only under a live subscription; a
conflicting mutation completes peer withdrawal before it returns. Write-capable
opens use direct I/O and kernel write-back is off. Under a full file delegation
the daemon may hold accepted writes in its bounded, volatile buffer; otherwise
`write(2)` returns after the authority has applied the bytes to XFS. Shared
writable file-backed `mmap` is refused; read-only and `MAP_PRIVATE` mappings use
the clean-data regime. There is no incoherent page-cache fallback.

Completion is explicit. File `fsync` and `O_SYNC`/`O_DSYNC` wait for durability
of that file's accepted cut on the authoritative server descriptor. The run
barrier is `fsync` on a root-directory handle opened before the run, which
fails if mount loss advanced since its open. Stock FUSE `syncfs(2)` is not a
completion surface. `close` alone is not a durability boundary.

SQLite is exercised in rollback-journal mode. WAL mode is outside the
multi-machine contract because SQLite's wal-index requires shared memory among
all participants on one host; keep WAL databases local or use a database
service.

`portablefs umount <path>` runs the full drain barrier and fails, leaving the
mount attached, if the drain cannot complete. `--force` detaches without
draining: nothing is parked or replayed, so accepted writes still in a
delegated write buffer or kernel page cache are lost.

## Mounting from macOS

macOS 26 and 27 mount through `FRONTEND_PROFILE_FSKIT_EXCLUSIVE`, with one app,
daemon, and extension for both releases. The complete contract is
[fskit-mount.md](./fskit-mount.md); the operator-facing consequences are:

- **A mounted Mac is the volume's only writer.** Linux peers stay mounted and
  read; their visible mutations and write-intent opens return `EBUSY`. A second
  Mac mount of the volume is refused at activation. A clean Mac unmount lets
  Linux write again and lets another Mac mount.
- **Every successful FSKit mutation reply is durable** on the authority before
  it is sent. Handleless mutations use the shared `syncfs` barrier described in
  [Shared-cell durability domain](#shared-cell-durability-domain), so their
  latency includes the whole cell's dirty data.
- **Terminal enforcement does not withdraw kernel cache state.** A fenced or
  disconnected Mac stops serving from PortableFS caches but the macOS kernel can
  keep names, attributes, and pages until unmount. PortableFS does not unmount
  automatically on fence.
- **Cross-machine locks and atomic append need Linux mounts only.** FSKit has
  no advisory-lock callbacks and no per-write append intent.
- **Routes.** The Mac attach presents the empty route revision and does not
  serve machine-local directories, so a volume that declares routes mounts from
  Linux.

To mount:

1. Install `PortableFS.app` from the notarized release (see
   [release-identity.md](./release-identity.md)).
2. Enable its File System Extension once, under System Settings ->
   General -> Login Items & Extensions -> File System Extensions. This is an
   interactive user-controlled toggle and is deliberately not automatable. The
   app never claims the toggle is on; only a successful mount verifies it.
3. For a LAN authority, grant the app Local Network permission; a terminal can
   reach an address the background service is denied.
4. Run `portablefs mount` with the same credential shape as Linux. The command
   returns only after the daemon attests `frontend-ready`: a usable initial
   KeepAlive proof for the exact attach, an authenticated frontend bound to it,
   and the kernel mount identity observed. Readiness performs no I/O on the
   mounted root.

The host's launchd-managed `portablefsd` owns the authority session; the CLI
reaches it through the owner-private control socket or wakes the exact
containing app. An activation callback timeout is an ambiguous request
outcome, not a failed or successful launch; the CLI proceeds only to a bounded
exact control-socket and release-identity proof, and an explicit callback error
still fails. Authority TLS credentials and replay secrets never cross the local
frontend socket to the extension. The daemon is always the exact `portablefsd`
inside the sealed `PortableFSDService.app` of the same installed release, and
the CLI, daemon, and extension must be one paired release (daemon control 2,
`pfslocal` 2.0). The daemon executable, sockets, and filesystem type are fixed
by the signed layout and app-group identity; no environment variable selects
them.

`portablefs umount` makes one unforced attempt and returns the real `EBUSY` when
Finder, Spotlight, or a process holds the mount. Only an explicit user
`--force` ever forces an unmount, and it can discard pages the kernel accepted
but never delivered; no daemon failure or terminal session triggers one. The
daemon answers with an empty 204 or one combined error, and the CLI reports
the exact kernel mount as absent, present, or unverified alongside any daemon
error, preserving state and intent on every error (see
[fskit-mount.md](./fskit-mount.md#unmount-and-detach)).

Native macOS 26 and 27 qualification of this profile has not been run; see
[fskit-mount.md](./fskit-mount.md#verification).

## Verifying cross-mount coherence

The claim this topology exists to support is that one volume mounted on several
Linux machines behaves like one POSIX filesystem. That claim is verified by a
runnable matrix, not by inspection:

```bash
scripts/coherence-matrix-linux.sh
```

It provisions a real XFS cell with project quotas in a privileged container
using `scripts/provision-xfs-volume.sh`, mints credentials with
`pfs-coherence-credentials`, starts the real `portablefs-authority` process,
starts two real `portablefs-mount-v3` processes against it, and then drives both
mountpoints with ordinary syscalls from a separate black-box program
(`vcs/test/coherence/cmd/pfs-coherence-matrix`). Nothing is in process and no
kernel is faked, which is also what makes the lifecycle cases possible: the
mounts are separate processes, so one can be paused or killed uncleanly and the
other required to keep serving.

Each case asserts the real quantity. Content is compared against the bytes a
descriptor actually returns when read to EOF, never against `stat.Size`; the
namespace is compared against the entries `readdir` actually enumerates; an
atomic replacement is compared against the inode number the surviving mount
resolves. Coherence observations do not poll or retry: the correct answer is the
first answer, so a case that needed a settling delay would be reporting a
defect, not a timing artefact.

The run has three phases. The first points the second mount at a directory that
is not the volume and requires every mountpoint-dependent case to fail. The
second replays mount A's first successful pathname observations and requires
every case declared sensitive to that stale-view fault to fail; stateful
descriptor behavior and the attach-time route contract are intentionally not
misclassified as pathname-cache tests. Only then does the third report the real
result. A case that misses its declared control result fails the job. A case
that cannot be honestly asserted, for example the ownership case on a
single-principal volume, skips with a stated reason and a nonzero exit unless
the skip is declared, never a quiet pass.

The case list, the falsifiability controls, and the macOS form are documented in
[the cross-mount coherence matrix](./cross-mount-coherence-matrix.md).

`scripts/coherence-matrix-macos.sh` runs the same named cases between one
FSKit mount on this Mac and one Linux kernel-FUSE mount on a remote peer over
ssh. There is no Mac-to-Mac form: writer exclusion refuses a second Mac mount
of the volume. The script never mounts anything, refuses ordinary directories,
and skips loudly when the verified Linux peer mount is unavailable.

## Failure and replacement

The launch topology has no automatic second writer. On instance failure:

1. prove the previous instance/process cannot write;
2. detach the EBS volume normally;
3. attach it to the replacement in the same AZ;
4. mount XFS and allow journal replay to finish;
5. start a fresh authority epoch, which resolves durable membership as
   described in [Restarting the authority](#restarting-the-authority); and
6. publish the replacement endpoint.

All old sessions, handles, locks, and in-flight outcomes are stale. A client
never replays an uncertain mutation into the new epoch.

A storage failure, including any failed fsync, fdatasync, or syncfs, fences the
store, cancels the server, and exits the authority process with
`authoritative storage failed and this epoch was fenced`. A coherence failure
exits the same way with `strict cache coherence failed and this epoch was
fenced`. Treat either exit as not-ready and investigate the filesystem, device,
or mount before restarting; do not restart-loop a volume onto unhealthy storage.
On a shared cell, also inspect the other projects' workers: a writeback or log
fault can originate in a neighbor (see
[Shared-cell durability domain](#shared-cell-durability-domain)). Fencing a
*single* session is different and is not a process failure: the volume keeps
serving every other mount, and the fence is counted in
`portablefs_authority_fence_events_total`.

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
namespace: there is nothing to expose, because PortableFS keeps no history.
The hosted archive tier is a separate, Manager-verified representation; see
[the tiered-storage contracts](./tiered-storage/identity-lifecycle-and-capacity.md).

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

Every series has the bounded `volume` label. RPC series use a closed `opcode`
set. `portablefs_authority_rpc_requests_total` adds one closed `outcome` label:
`success`, `not_found`, `permission`, `stale`, `invalid`, `saturation`,
`unsupported`, `conflict`, `canceled`, `storage`, `internal`, `coherence`,
`routes`, `io`, or `other`. The storage, internal, coherence, and routes values
come from the protocol's explicit failure class; the remaining values group
Linux wire errnos. No peer-controlled string or numeric request ID becomes a
metric label. The metric names in this table are the documented monitoring
surface; anything else the registry exposes is internal.

| Metric | Operational question |
| --- | --- |
| `portablefs_authority_rpc_requests_total{opcode,outcome}` | Which operation is failing, saturating, or being retried, and in which semantic errno class? |
| `portablefs_authority_rpc_duration_seconds{opcode}` | Which operation is consuming the handler latency budget? |
| `portablefs_authority_active_sessions` | How many mounts are currently ACTIVE, rather than merely provisional or draining? |
| `portablefs_authority_session_items_high_water` | Has one session approached `--max-items-per-session` since this worker started? The shared root descriptor is excluded, matching the configured bound. |
| `portablefs_authority_fsync_barrier_handles_total` / `portablefs_authority_fsync_storage_syncs_total` | How many fsync barrier requests did each completed storage sync serve? The ratio is group-commit effectiveness. |
| `portablefs_authority_fskit_durability_syncs_total{target}` | How many required FSKit mutation barriers ran, including failed attempts? `target` is `handle` or `syncfs`. |
| `portablefs_authority_fskit_durability_duration_seconds{target}` | How long did those barriers take? The `syncfs` series carries the shared-cell latency. |
| `portablefs_authority_subscription_horizons` | How many Linux subscription horizons are retained, including fenced ones awaiting sweep? |
| `portablefs_authority_subscription_resets_total` / `portablefs_authority_subscription_expirations_total` | How often do Linux mounts resubscribe cold, and how often does a horizon expire unrenewed? |
| `portablefs_authority_change_log_entries` | How much of the bounded change stream is retained? |
| `portablefs_authority_delegations{state}` | How many file delegations are `reserved`, `active`, `recalling`, or `retiring`? |
| `portablefs_authority_delegation_capacity_reservations` | How much grant capacity is reserved ahead of namespace mutations? |
| `portablefs_authority_delegation_recalls_total{outcome}` / `portablefs_authority_delegation_breaks_total{outcome}` | Are recalls and read breaks `completed`, or `lost` before acknowledgment? |
| `portablefs_authority_fence_events_total{reason}` | Why was a participant fenced? |

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
- alert on any `lost` delegation recall or break and on a rising
  subscription-expiration rate: each is a Linux mount that stopped answering
  CONTROL within its bound;
- alert on every fence event; a fence after a deliberate host loss still leaves
  durable membership that needs the restart handling above;
- alert before `session_items_high_water` reaches `--max-items-per-session`;
- track `fskit_durability_duration_seconds{target="syncfs"}` p99 per volume and
  across every volume of the same cell; a correlated rise is the shared-cell
  domain.

Continue monitoring EBS status and latency, filesystem and project-quota block
and inode headroom, process restarts, file descriptors, TLS/capability
rejections at the service boundary, and backup restore age; those facts are
outside this per-worker registry.

RPC lifecycle results and non-routine failures are also structured on stderr
with `volume`, `request_id`, `session`, `opcode`, `outcome`, `errno`, and
`duration_us`. Routine POSIX results such as a missing lookup are counted but
not logged per request. Logs are for correlation by request ID; metrics and
readiness are the monitoring contract.
