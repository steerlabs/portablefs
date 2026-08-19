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
| `/srv/portablefs/.portablefs-control/<volume>/write-staging` | volume UID `0700`, root-pinned parent | unnamed transactional-write staging, charged to the volume's exact XFS project quota |
| `/etc/portablefs/trust` | root | manager CA and plan public key |
| `/etc/portablefs/cells` | root | cell mTLS identity and root-owned environment |
| `/etc/portablefs/volumes` | root | generated per-volume authority config/keys/certs |
| `/var/lib/portablefs/volumes` | per-volume UID | strict membership and runtime state |
| `/var/lib/portablefs-cell-helper` | root `0700` | pinned assignments and plan generation |
| `/var/lib/portablefs-cell-helper/sysusers.d` | root | persistent, exact per-volume service-account definitions |
| `/run/portablefs-cell-helper` | root:agent `0750` | cell-specific local helper sockets |
| `/run/portablefs-cell-helper/<cell-uuid>.sock` | root:agent `0660` | local signed-plan boundary |

## Install one immutable hosted release

Build one clean-commit release with `scripts/build-hosted-linux-release.sh`.
The bundle contains all five hosted executables and all five unit templates;
each executable reports the same `pfs-hosted-YYYYMMDD-<commit>` identity and the
bundle has exact-member SHA-256 verification. Install it beneath:

```text
/opt/portablefs/releases/<release-id>
/opt/portablefs/current -> /opt/portablefs/releases/<release-id>
```

`deploy/gcp/activate-hosted-release.sh` verifies every member and binary release
identity before stopping a control process, installs the release under its
immutable name, swaps the one `current` symlink, reloads systemd, and verifies
the new process executable. A failed activation restores the former link and
unit files. The launcher also refuses an authority binary that is not a
root-owned regular file or is writable by group/other.

A cell software activation restarts only the cell helper and agent. It never
restarts an active authority: replacing the one XFS writer remains a manager
restart request, a strict-mount fence proof, local process-absence observation,
and a monotonic authority generation. The next generation starts from the new
release root.

The release carries these five units from `deploy/systemd/`:

```text
portablefs-cell-helper@.service
portablefs-cell-agent@.service
portablefs-authority@.socket
portablefs-authority@.service
```

The helper generates only typed per-volume drop-ins. The service template gives
an authority an empty capability set, `NoNewPrivileges`, private devices/tmp/
network, a read-only system, syscall restrictions, and exactly four bind
mounts: the served XFS project, read-only configuration, runtime state, and a
separate write-staging directory under that same XFS project quota. The two
control parents are root-owned and non-replaceable by the service identity.
The socket unit owns the public TCP listener and passes one descriptor
to the authority. Do not add a second `ListenStream` or a second authority unit
for the same volume.

For a new host, keep credentials in a separate root-only configuration stage
and run:

```bash
sudo deploy/gcp/install-cell.sh \
  /absolute/portablefs-hosted_<release>_linux_<arch> \
  /absolute/cell-config-stage CELL_UUID AGENT_UID AGENT_GID
```

## Cell trust and identity

Provision these root-owned files out of band:

- `/etc/portablefs/trust/manager-ca.pem`
- `/etc/portablefs/trust/plan-public.pem`
- `/etc/portablefs/cells/<cell-uuid>.cert`
- `/etc/portablefs/cells/<cell-uuid>.key` (agent-owned `0600`, inside a
  root-controlled, non-agent-writable directory)
- `/etc/portablefs/cells/<cell-uuid>.env` (`0600`)

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

Each successful volume assignment also records the exact helper release that
applied it. Installing a new helper release therefore re-applies an unchanged
signed plan once before it can return to observation. This is how new mandatory
host resources are migrated without weakening plan identity or requiring an
operator to manufacture a semantically empty plan change.

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
- If an authority or socket remains active after fencing, the helper reports an
  error and the manager quarantines the volume. It does not start a successor.
- A cell heartbeat loss makes mount issuance fail closed after the configured
  freshness window. Existing authority sessions continue until their own
  liveness/authorization/fencing rules end them.
- `RETIRE` preserves the XFS directory. Deletion, snapshot, restore, and device
  replacement are offline runbooks and require separately validated targets.

Before a production rollout, exercise the failure paths on a disposable real
XFS host: kill/stop races, a `SIGSTOP`ed worker, cgroup population, full block
and inode quota, manager/agent/helper restart, expired plans and certificates,
same-generation CSR substitution, cell identity substitution, and strict-mount
fence refusal.
