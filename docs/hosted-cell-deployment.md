# Deploying a hosted storage cell

Status: **Linux reference deployment for the hosted v1 foundation**

Read [hosted-control-plane.md](./hosted-control-plane.md) first. This document
only covers the host boundary. The standalone authority runbook remains in
[xfs-authority-deployment.md](./xfs-authority-deployment.md).

## Host prerequisites

- Linux with `openat2`, cgroup v2, systemd, and XFS project quotas.
- One PortableFS cell identity per storage host. Volumes are the isolation unit
  inside that cell; do not run independent cell trust domains under one helper.
- One dedicated encrypted XFS filesystem mounted at `/srv/portablefs` with
  `prjquota,nodev,nosuid,noexec,noatime`.
- `/usr/sbin/xfs_quota`, `/usr/bin/systemctl`, and
  `/usr/bin/systemd-sysusers` at the pinned paths, or explicit absolute
  overrides on the helper.
- A stable unprivileged `portablefs-agent` account and group. Record its numeric
  UID and GID; the root helper checks the UID with `SO_PEERCRED` and owns its
  socket to the configured group.

The reference paths are:

| Path | Owner/mode | Purpose |
| --- | --- | --- |
| `/srv/portablefs` | root, not tenant-writable | XFS cell root |
| `/etc/portablefs/trust` | root | manager CA and plan public key |
| `/etc/portablefs/cells` | root | cell mTLS identity and root-owned environment |
| `/etc/portablefs/cells/<cell-uuid>-archive.env` | root `0600` | archive-store read/write credentials and root-pinned endpoint, bucket, and prefix |
| `/etc/portablefs/volumes` | root | generated per-volume authority config/keys/certs |
| `/var/lib/portablefs/volumes` | per-volume UID | strict membership, restore hydration/convergence records, and runtime state |
| `/var/lib/portablefs-cell-helper` | root `0700` | pinned assignments and plan generation |
| `/var/lib/portablefs-cell-helper/sysusers.d` | root | persistent, exact per-volume service-account definitions |
| `/run/portablefs-cell-helper` | root:agent `0750` | cell-specific local helper sockets |
| `/run/portablefs-cell-helper/<cell-uuid>.sock` | root:agent `0660` | local signed-plan boundary |

## Install the six host binaries

Install root-owned, non-group-writable binaries at these reference locations:

```text
/usr/local/bin/portablefs-cell-agent
/usr/local/bin/portablefs-authority
/usr/local/bin/portablefs-archiver
/usr/local/bin/portablefs-hydrator
/usr/local/libexec/portablefs-cell-helper
/usr/local/libexec/portablefs-authority-launcher
```

The launcher refuses an authority binary that is not a root-owned regular file
or is writable by group/other. Build production binaries with an exact release
stamp, for example `-ldflags '-X main.version=v3.x.y+build-id'`; `dev` is visible
and should never be mistaken for a release.

Install the six units from `deploy/systemd/`:

```text
portablefs-cell-helper@.service
portablefs-cell-agent@.service
portablefs-authority@.socket
portablefs-authority@.service
portablefs-archiver@.service
portablefs-hydrator@.service
```

The helper generates only typed per-volume drop-ins. The service template gives
an authority an empty capability set, `NoNewPrivileges`, private devices/tmp/
network, a read-only system, syscall restrictions, and its unchanged three bind
mounts for the volume, config, and state roots. During RESTORING the authority's
state-root bind exposes the hydrator AF_UNIX socket directory, so the authority
does not gain a fourth bind. The hydrator unit separately receives network,
read-scoped credentials, and that socket-directory bind, with no volume data-dir
access. The archiver unit receives network, write-scoped credentials, and a
read-only bind of the quiesced volume data directory. The socket unit owns the
public TCP listener and passes one descriptor to the authority. Do not add a
second `ListenStream` or a second authority unit for the same volume.

## Cell trust and identity

Provision these root-owned files out of band:

- `/etc/portablefs/trust/manager-ca.pem`
- `/etc/portablefs/trust/plan-public.pem`
- `/etc/portablefs/cells/<cell-uuid>.cert`
- `/etc/portablefs/cells/<cell-uuid>.key` (agent-owned `0600`, inside a
  root-controlled, non-agent-writable directory)
- `/etc/portablefs/cells/<cell-uuid>.env` (`0600`)
- `/etc/portablefs/cells/<cell-uuid>-archive.env` (`0600`)

The cell certificate has exactly this URI SAN:

```text
spiffe://portablefs/control/cell/<cell-uuid>
```

The environment file contains only root-controlled deployment facts used by
the unit templates:

```text
PORTABLEFS_AGENT_UID=200100
PORTABLEFS_AGENT_GID=200100
PORTABLEFS_MANAGER_URL=https://manager.internal:8443
PORTABLEFS_MANAGER_SERVER_NAME=manager.internal
```

The archive environment is root-provisioned, never plan-selected. It pins the
archive-store endpoint, bucket, root prefix, and key version and supplies
separate write scope for the archiver and read scope for the hydrator. Signed
plans carry only attempt identities and digests; object keys are derived below
that pinned prefix, and credentials never appear in a plan or observation.

The plan public key is independent of control-channel TLS. Compromise of one
does not silently turn an unsigned manager response into a root command: both
the agent and helper still require a valid cell-plan signature.

## Start and verify

Register the cell through the manager operator API before starting the agent.
The registered capacity is admission capacity, not a replacement for XFS's own
free-space accounting. Choose non-overlapping allocator starts for project ID,
service UID, and TCP port.

Then enable the two cell services using the cell UUID as the instance:

```bash
sudo systemctl enable --now portablefs-cell-helper@<cell-uuid>.service
sudo systemctl enable --now portablefs-cell-agent@<cell-uuid>.service
```

Verify:

```bash
systemctl status portablefs-cell-helper@<cell-uuid>.service
systemctl status portablefs-cell-agent@<cell-uuid>.service
ss -lx | grep /run/portablefs-cell-helper/<cell-uuid>.sock
xfs_quota -x -c 'state' /srv/portablefs
```

After a volume is allocated, verify its project and hard limits with
`xfs_quota`, its generated `.socket` listener, its service UID, and the bind
mounts/capability set shown by `systemctl show` and `/proc/<pid>/mountinfo`.
Never treat the manager's `READY` state alone as the host acceptance test.

The helper writes a deterministic `systemd-sysusers` entry for each volume,
runs the pinned account tool in a short-lived hardened systemd unit, and
verifies both name-to-ID and ID-to-name mappings before it creates or starts
the authority. The long-running helper does not receive general write access
to `/etc`. These system users and groups are persistent and are not deleted on
retirement because allocator identities are never reused.

XFS project assignment and hard-limit changes also run as fixed short-lived
systemd units in the host mount namespace. Do not add `PrivateDevices` or
`PrivateTmp` to those quota units: either creates a private mount namespace in
which `xfs_quota` can report success against a bind view without changing the
host XFS project. The quota units have no network, accept no command or path
from the signed plan, and hold `CAP_SYS_ADMIN` only for their brief execution;
the long-running helper does not hold that capability.

## Failure behavior

- An invalid, expired, stale, equivocated, or wrong-cell plan never reaches host
  mutation.
- A helper-state mismatch is a stop condition. Do not delete helper state to
  make it pass; reconcile the signed assignment and on-disk project first.
- A `RELEASE` entry whose placement sequence, authority epoch, or destroy-proof
  digest does not exactly match the helper's recorded proof is a stop condition;
  reconciliation fails closed without removing the assignment.
- If an authority or socket remains active after fencing, the helper reports an
  error and the manager quarantines the volume. It does not start a successor.
- A cell heartbeat loss makes mount issuance fail closed after the configured
  freshness window. Existing authority sessions continue until their own
  liveness/authorization/fencing rules end them.
- `RETIRE` preserves the XFS directory. Operator snapshots and device
  replacement remain offline runbooks; archive, restore, destroy, and release
  run only as the typed v2 plan phases with their specified proofs.

Before a production rollout, exercise the failure paths on a disposable real
XFS host: kill/stop races, a `SIGSTOP`ed worker, cgroup population, full block
and inode quota, manager/agent/helper restart, expired plans and certificates,
same-generation CSR substitution, cell identity substitution, and strict-mount
fence refusal.
