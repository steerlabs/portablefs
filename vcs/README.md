# vcs — the PortableFS v3 Go data plane

This module is the whole non-Swift half of PortableFS: the authority that owns
an XFS volume, the Linux kernel-FUSE frontend, the macOS `portablefsd` data
plane behind the FSKit extension, and the `portablefs` CLI.

It has four direct dependencies — `go-fuse`, `golang.org/x/sys`, `protobuf`,
and HighwayHash for authority-private replay fingerprints — and
no build system above `go`. The directory is named `vcs` for historical reasons;
nothing in it is a version control system.

There is no file-data journal, history, branch, or PortableFS-managed offline
write-back cache. XFS is the only durable filesystem truth. The optional hosted
control plane manages placement and credentials, never file contents. Ordinary
OS kernel page caches remain part of each mount contract. For why, read
[../docs/xfs-authority-architecture.md](../docs/xfs-authority-architecture.md).

## Commands

| Command | What it is |
| --- | --- |
| `cmd/portablefs` | The user-facing CLI: mount, reauthorize, umount, mounts, mount-loss, route, prune-local, daemon, doctor, mount-check, version, and the installer and lifecycle coordination subcommands. Linux and macOS. |
| `cmd/portablefs-authority` | The volume authority. Linux only. One process serves exactly one volume, refuses to run as root, and terminates its epoch on any storage failure. |
| `cmd/portablefs-manager` | The product-neutral hosted manager. It owns desired state, placement, PKI, grants, and fencing generations, but never filesystem contents. |
| `cmd/portablefs-cell-agent` | The unprivileged outbound reconciliation loop on each Linux storage cell. |
| `cmd/portablefs-cell-helper` | The narrow root helper that applies only a verified, manager-signed cell plan. Linux only. |
| `cmd/portablefs-authority-launcher` | The fixed-argument systemd launcher for an isolated per-volume authority. Linux only. |
| `cmd/portablefs-files` | The bounded, non-mounting read gateway for product file browsers. It accepts request-bound Ed25519 tokens, holds cacheless read-only authority sessions, pages directories, bounds previews, and streams downloads. |
| `cmd/portablefs-archiver`, `cmd/portablefs-hydrator` | The tiered-storage archive writer and restore recall fetcher. Linux only; never write XFS while an authority serves it. |
| `cmd/portablefsd` | The per-user macOS registry, control daemon, and FSKit data plane. It declares the FSKit exclusive-writer profile and never claims Linux subscription semantics. |
| `cmd/portablefs-mount-v3` | A standalone Linux mount client. This is what the coherence harnesses drive; ordinary users go through `portablefs mount`. |

## Layout

```text
hostedauth/       Public product assertion signer and CSR SPKI helper.
readonlyfs/       Public non-mounting read client with byte-safe path keys,
                  exact authority handle cleanup, and live directory cursors.
internal/
  xfsstore/        XFS-only, descriptor-relative volume backend: openat2 under
                   RESOLVE_BENEATH, *at syscalls, device verification, stable
                   export-handle identity, xattr namespace restriction.
  volumeserver/    Epoch sessions, replay slots, cancellation, POSIX and flock
                   lock tables, the Linux subscription/delegation coordinator,
                   the FSKit writer registry and retained exclusion, durable
                   mount lifecycle, and fail-closed fencing.
  authorityrpc/    The wire: TLS 1.3 mutual authentication, ALPN
                   portablefs-authority-v8, mandatory DATA/CONTROL transports,
                   provisional activation, schema-bound bulk framing,
                   canonical replay fingerprinting, the XFS request handler,
                   routing topology, and subscription/delegation control.
  mountmembership/ The one mount-membership file codec (mount.membership,
                   PFS-MEMBERSHIP-1) shared by the authority and the cell host.
  pathcomponent/   The raw directory-entry name validator.
  authoritypb/     Generated protobuf bindings for proto/authority/v1.
  volumecap/       Ed25519 mount capabilities: signed, single-use, short-lived,
                   volume- and peer-bound.
  productauth/     Independent product authorization assertions bound to the
                   same volume, access, subject, client key, nonce, and time.
  controlplane/    Hosted desired state, placement, PKI, exact receipts, API,
                   reconciliation, generation fencing, and release identity.
  cellplan/        Canonical signed host plans with immutable isolation IDs.
  cellagent/       Outbound-only unprivileged hosted cell reconciliation.
  cellhelper/      Durable assignment pinning and the narrow root boundary.
  cellhost/        Closed XFS quota, local authority identity, and systemd host
                   operations derived only from signed volume assignments.
  fusev3/          The Linux frontend. Stock FUSE 7.31, subscription and
                   delegation coherence, daemon and kernel cache withdrawal,
                   ordered delegated flush, and machine-local route grafts.
  writeback/       The Linux delegated write buffer.
  portablefsd/     The macOS daemon registry, control and lifecycle API, FSKit
                   data plane, proof-checked metadata cache, and
                   evidence-bearing detach.
  pfslocal/        The local protocol between the daemon and the FSKit
                   extension: exact version 2.0, paired by the sealed release.
  mountv3/         The shared mount engine used by both the CLI and the
                   standalone mount binary.
  localdirs/       The .portablefs/local-dirs declaration: parsing,
                   canonicalization, and the revision hash every mount must agree
                   on.
  localroutes/     Machine-local backing directories, keyed by (volume, route
                   root) so they survive unmount.
  confinedfs/      The machine-local backing capability boundary: openat2 with
                   RESOLVE_IN_ROOT, failing closed where it is unavailable.
  fskitidentity/   The signed macOS identity tuple: app group, filesystem type,
                   resource scheme.
  daemonctl/       Daemon identity (schema 1), operational control 2, and the
                   cross-release lifecycle v1 API.
  mountlifecycle/  The per-user mount lifecycle guard.
  accountsession/  The per-user account session guard.
  accountpath/     The account record the state directory is resolved from,
  privatepath/     rather than from HOME or XDG, plus the component-wise
  mountid/         O_NOFOLLOW walk that refuses foreign-owned or unsafe paths,
  mounthost/       and mount record identity.
  errnos/          Shared errno classification.

test/coherence/       The black-box cross-mount matrix and its driver commands
                      (pfs-coherence-matrix, pfs-coherence-routes,
                      pfs-coherence-credentials). Driven by
                      ../scripts/coherence-matrix-linux.sh.
test/powerloss/       The dm-log-writes power-cut harness. Driven by
                      ../scripts/run-powerloss.sh.
bench/                Measurement tools. See ../docs/performance.md.
```

## Build and test

```bash
go -C vcs build ./...
go -C vcs test ./...
go -C vcs test -race ./...
go -C vcs vet ./...
```

Add `GOOS=darwin` or `GOOS=linux` to cross-check the other platform: the
authority, the frontends, and the daemon all carry per-GOOS files, so building
only the host platform hides breakage until a release job runs.

The native suite runs against real syscalls, sockets, and mounts, so it is only
meaningful on the host platform. The parts that need real XFS, real project
quotas, and a real kernel FUSE mount are gated behind
`bash ../scripts/xfs-fuse-integration.sh`, which builds a disposable XFS
filesystem in a privileged container and requires every test named in the
three package-owned lists `../scripts/xfs-required-*-tests.txt` to pass. The
cross-mount behaviour matrix is `bash ../scripts/coherence-matrix-linux.sh`.

The single merge gate for the whole repository is `bash ../scripts/verify-local.sh`.

## Running an authority by hand

See [../docs/xfs-authority-deployment.md](../docs/xfs-authority-deployment.md).
The short version: provision an XFS project directory with
`scripts/provision-xfs-volume.sh`, then run `portablefs-authority` as the volume's
service account with its TLS material, its capability verification key, and its
mount-membership file. Every required flag is required for a reason and the
process refuses to start without them.
