# Deploying an authoritative-XFS volume

This runbook describes the clean launch topology for PortableFS v3. It has one
active authority and one encrypted XFS/EBS filesystem. It is single-AZ durable
storage, not multi-AZ high availability.

## Host and disk

Use a current Nitro EC2 instance on a supported Linux baseline (6.12 or newer
for the complete tested syscall and FUSE contract). Attach a dedicated,
encrypted EBS data volume with `DeleteOnTermination=false`. Choose gp3 or io2
from measured IOPS, throughput, latency, and durability requirements; the
architecture does not impose one capacity tier.

Format and mount the cell once:

```bash
mkfs.xfs -f /dev/disk/by-id/<validated-ebs-device>
mkdir -p /srv/portablefs
mount -t xfs -o prjquota,nodev,nosuid,noexec,noatime \
  /dev/disk/by-id/<validated-ebs-device> /srv/portablefs
```

Resolve and verify the exact device identity before formatting. Never use a
discovery glob or an unvalidated environment variable as the `mkfs` target.
Persist the UUID in `/etc/fstab` with the same options and verify an automatic
boot before admitting data.

## One isolated volume worker

Allocate a stable, unprivileged numeric UID/GID and a unique nonzero XFS
project ID for the volume. The block and inode hard limits come from that
volume's purchased entitlement, not a universal PortableFS limit.

```bash
sudo ./scripts/provision-xfs-volume.sh \
  /srv/portablefs vol_01JXYZ 42001 200001 200001 100g 10000000
```

Provisioning is privileged and separate from request serving. The authority
process must run as exactly `200001:200001` in this example and sees only
`/srv/portablefs/vol_01JXYZ`. It refuses to run as root and verifies XFS,
project inheritance, and root ownership before listening. The provisioner and
privileged cell monitor attest the enforced block/inode hard limits; the
request process is intentionally not given quota-administration capability.
XFS itself enforces those limits.

Use one sandboxed worker per active volume at launch. A stable per-volume Unix
identity plus a private mount namespace prevents a compromised worker from
opening another tenant's directory. Consolidating hostile volumes into one
unsandboxed process would weaken that boundary and is not an allowed
optimization.

The worker requires:

- a server certificate and `0600` private key;
- the client CA used for mount identities;
- the control plane's Ed25519 public verification key;
- explicit protocol allocation/concurrency bounds;
- a TCP listener reachable only through the intended security group/load
  balancer.

Example process invocation (run under the stable volume UID/GID):

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
  --max-sessions 1024 \
  --max-lock-records 65536
```

Size session, lock, replay, in-flight, descriptor, cgroup-memory, and I/O
admission from the worker class and workload measurements. They protect one
volume worker from denial of service; they are not PortableFS filesystem-size
limits and do not imply a universal RAM budget.

User-xattr writes are disabled at launch. XFS does not charge attribute-fork
blocks to a project, so per-inode RPC limits cannot isolate a shared cell and a
separate logical counter would not be crash-atomic with XFS. The Linux frontend
returns `EOPNOTSUPP` without sending a mutation, and the authority rejects a
direct or older-client set-xattr request the same way. Read, list, and removal
remain available for pre-existing portable user attributes.

The service manager should additionally provide a read-only root filesystem,
`NoNewPrivileges`, an empty capability bounding set, a private mount namespace,
a syscall allowlist, bounded file descriptors/tasks/memory, restart policy,
and access to only the volume directory and required credential files. Do not
expose the raw XFS mount to agent machines or containers.

## Connecting a Linux mount

The control plane mints a short-lived Ed25519-signed capability bound to the
exact volume, read/write scope, expiry, subject, nonce, and SHA-256 of the
client certificate's SPKI. Store the token and client key in regular `0600`
files. Expiry is an absolute non-renewable mount-session deadline; issue a new
credential and remount instead of extending an old grant. Then run as the local
user who should own the projected workspace:

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

The exact Linux mount uses direct I/O and does not advertise shared file-backed
`mmap`. It does not fall back to incoherent page caching. Process-local
`MAP_PRIVATE` mappings retain their ordinary copy-on-write semantics. Workloads
that require `MAP_SHARED` remain outside the launch compatibility contract
until a synchronous lease/invalidation design is implemented and proven.
SQLite is verified in rollback-journal mode. WAL mode is outside the
multi-machine contract because SQLite's wal-index requires shared memory among
all participants on one host; keep WAL databases local or use a database
service.
The mountpoint must be a clean absolute, real, empty directory.

Use `fsync`/`fdatasync` on files and `fsync` on changed parent directories for
durability. Linux currently does not forward `syncfs(2)` to ordinary FUSE
userspace servers, so it is not a remote durability boundary for this mount.

## Failure and replacement

The launch topology has no automatic second writer. On instance failure:

1. prove the previous instance/process cannot write;
2. detach the EBS volume normally;
3. attach it to the replacement in the same AZ;
4. mount XFS and allow journal replay to finish;
5. start a fresh authority epoch; and
6. publish the replacement endpoint.

All old sessions, handles, locks, and in-flight outcomes are stale. A client
never replays an uncertain mutation into the new epoch.

A storage `EIO` fences the store, cancels the server, and exits the authority
process. Treat that exit as not-ready and investigate the filesystem/device;
do not restart-loop a volume onto unhealthy storage.

Do not call EBS Multi-Attach a replica and do not mount ordinary XFS read-write
on two hosts. Same-AZ active/passive later requires io2 NVMe reservations plus
independent STONITH fencing before promotion. Cross-AZ HA requires a separate
synchronous replication/quorum design or a validated managed filesystem.

## Backups

Backups are disaster recovery, not live filesystem state. A controller should
quiesce the authority, sync/freeze XFS, take an application-consistent EBS
snapshot, and unfreeze promptly. Copy snapshots to the required account/region,
lock retention, and run scheduled restore tests. A snapshot is never mounted
inside the live namespace and users do not see versions or branches.

Monitor EBS status, queue/latency/throughput, filesystem free space and inodes,
project quota headroom, authority restarts, TLS/capability rejection, session
count, open descriptors, request latency/error codes, and backup restore age.
