# vcs — the PortableFS v3 Go data plane

This module is the whole non-Swift half of PortableFS: the authority that owns
an XFS volume, the Linux kernel-FUSE frontend, the macOS `portablefsd` data
plane behind the FSKit extension, and the `portablefs` CLI.

It has three dependencies — `go-fuse`, `golang.org/x/sys`, and `protobuf` — and
no build system above `go`. The directory is named `vcs` for historical reasons;
nothing in it is a version control system.

There is no journal, no history, no branch, no client write-back cache, and no
control plane. XFS is the only durable filesystem truth. For why, read
[../docs/xfs-authority-architecture.md](../docs/xfs-authority-architecture.md).

## Commands

| Command | What it is |
| --- | --- |
| `cmd/portablefs` | The user-facing CLI: mount, umount, mounts, route, prune-local, daemon, doctor, mount-check, version, and the installer and lifecycle coordination subcommands. Linux and macOS. |
| `cmd/portablefs-authority` | The volume authority. Linux only. One process serves exactly one volume, refuses to run as root, and terminates its epoch on any storage failure. |
| `cmd/portablefsd` | The per-user daemon. On macOS it is the v3 data plane behind the FSKit extension: it owns the authority session and never exposes authority credentials to the extension. |
| `cmd/portablefs-mount-v3` | A standalone Linux mount client. This is what the coherence harnesses drive; ordinary users go through `portablefs mount`. |

## Layout

```text
internal/
  xfsstore/        XFS-only, descriptor-relative volume backend: openat2 under
                   RESOLVE_BENEATH, *at syscalls, device verification, stable
                   export-handle identity, xattr namespace restriction.
  volumeserver/    Epoch sessions, replay slots, cancellation, POSIX and flock
                   lock tables, the two-phase visibility barrier, durable strict
                   membership, and fail-closed fencing.
  authorityrpc/    The wire: TLS 1.3 mutual authentication, ALPN
                   portablefs-authority-v2, canonical protobuf framing, the XFS
                   request handler, routing topology, and visibility events.
  authoritypb/     Generated protobuf bindings for proto/authority/v1.
  volumecap/       Ed25519 mount capabilities: signed, single-use, short-lived,
                   volume- and peer-bound.
  fusev3/          The Linux frontend. Raw FUSE, direct I/O, the strict and
                   uncached cache profiles, kernel binding revocation, and
                   machine-local route grafts.
  portablefsd/     The daemon: attach registry, control API, the v3 attach and
                   its coherence bridge, and the evidence-bearing detach.
  pfslocal/        The local protocol between the daemon and the FSKit
                   extension. Major 1, currently minor 9, additive.
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
  daemonctl/       Daemon discovery, identity matching, and lifecycle control.
  mountlifecycle/  The per-user mount lifecycle guard.
  accountsession/  The per-user account session guard.
  accountpath/     The account record the state directory is resolved from,
  privatepath/     rather than from HOME or XDG, plus the component-wise
  mountid/         O_NOFOLLOW walk that refuses foreign-owned or unsafe paths,
  mounthost/       and mount record identity.
  errnos/          Shared errno classification.
  directstoremodel/     Concluded exploration substrate. Not on any product
  directstoreharness/   path; see ../docs/direct-store-exploration.md.

test/coherence/       The black-box cross-mount matrix and its driver commands
                      (pfs-coherence-matrix, pfs-coherence-routes,
                      pfs-coherence-credentials). Driven by
                      ../scripts/coherence-matrix-linux.sh.
spikes/               Concluded measurement spikes.
bench/                Measurement tools. See ../docs/performance.md, including
                      which of them are currently broken.
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
filesystem in a privileged container and requires 43 named tests to pass. The
cross-mount behaviour matrix is `bash ../scripts/coherence-matrix-linux.sh`.

The single merge gate for the whole repository is `bash ../scripts/verify-local.sh`.

## Running an authority by hand

See [../docs/xfs-authority-deployment.md](../docs/xfs-authority-deployment.md).
The short version: provision an XFS project directory with
`scripts/provision-xfs-volume.sh`, then run `portablefs-authority` as the volume's
service account with its TLS material, its capability verification key, and its
strict-membership file. Every required flag is required for a reason and the
process refuses to start without them.
