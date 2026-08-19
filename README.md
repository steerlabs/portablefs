# PortableFS

PortableFS makes one durable workspace appear as an ordinary, live directory on
several machines at once. Every mount reads and writes the same current
filesystem. There are no commits, no branches, and no user-visible history: the
mounted tree is the product.

Protocol 6 is under implementation and qualification. The writable Linux
profile is not production-ready while stock FUSE hides `RWF_APPEND`. macOS 26
and 27 remain available through an explicit FSKit synchronous-repair profile;
that profile is useful but does not claim Linux-equivalent cache withdrawal.
The contracts below state the target and its blockers, not a claim that this
migration has completed qualification.

One volume is one XFS project directory on one Linux host, served by one
`portablefs-authority` process. XFS is the only durable filesystem truth.
PortableFS adds authentication, object capabilities, session-exact replay, an
authority implementation of distributed POSIX locks, and authority-issued
cache leases. Linux uses stock FUSE protocol 7.31 or newer and forwards those
locks. macOS uses a separate, explicitly declared protocol-6
`FSKIT_SYNC_REPAIR` profile: the authority orders its existing PREPARE/COMPLETE
repair around the same XFS mutation, while the daemon drives the best cache
repair the host API exposes. PortableFS adds no second inode tree, mutation
log, checkpoint format, or managed or offline write-back layer.

```text
stock Linux FUSE 7.31+ mounts     macOS 26/27 FSKit mounts
                 |
        mutually authenticated TLS 1.3
                     |
        portablefs-authority (one per volume)
                     |
         descriptor-relative Linux syscalls
                     |
        one XFS project directory (PROJINHERIT)
                     |
              encrypted SSD / EBS

Optional hosted lifecycle (never on filesystem I/O):
product authorization -> portablefs-manager -> outbound cell agent -> root helper/systemd
```

## What a two-machine demo looks like

In standalone mode, two machines mount the same volume with direct credentials — an authority
address, a single-use capability, and a mutual-TLS client identity. There is no
control plane in between.

```bash
# machine A
portablefs mount my-workspace ~/work \
  --addr 10.0.0.7:2050 --mount-token "$PORTABLEFS_MOUNT_TOKEN" \
  --data-plane-transport tls-private-ca --data-plane-server-name authority.internal \
  --data-plane-ca ca.pem --client-cert a.pem --client-key a.key

# machine B, same volume, its own capability and identity
portablefs mount my-workspace /mnt/work \
  --addr 10.0.0.7:2050 --mount-token "$PORTABLEFS_MOUNT_TOKEN" \
  --data-plane-transport tls-private-ca --data-plane-server-name authority.internal \
  --data-plane-ca ca.pem --client-cert b.pem --client-key b.key
```

A file created on A is visible on B. `write(2)` on either mount returns only
after the authority has applied the bytes to XFS, so there is no window in which
one machine has acknowledged data the other cannot see. `portablefs umount
<path>` drains and detaches.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/steerlabs/portablefs/main/scripts/install.sh | sh
```

`PORTABLEFS_VERSION` pins a release; `PORTABLEFS_INSTALL_DIR` chooses the
activation-link directory (default `~/.local/bin`).

On Linux the installer downloads the two-binary client archive
(`portablefs` and `portablefsd`), verifies its SHA-256 against `checksums.txt`,
and verifies the published GitHub artifact attestation with a pinned, digest-
checked `gh` — bound to the exact repository, the exact release workflow, the
exact tag, and non-self-hosted runners — **before** extracting anything. The
archive's member list must be exactly those two regular files. Both binaries
must then print the expected version. Activation is a lock-held atomic symlink
swap performed by the verified binary itself.

On macOS there is no standalone CLI. PortableFS ships only as the notarized
`PortableFS.app`, which carries the CLI, the `portablefsd` daemon, and the FSKit
extension as one signed unit. The installer audits the zip before extraction,
then checks the Developer ID signature, the hardened runtime, Gatekeeper
assessment, and the exact bundle identity: team ID, bundle identifier, app
group, FSKit type, and resource scheme. Host, daemon, and extension share the
exact app-group entitlement; the shell CLI is explicitly unentitled while its
stamped routing identity still matches. Enabling the extension under System Settings is a
one-time manual step Apple does not let an installer perform.

What establishes a release's identity, and the one known gap in the release
pipeline, is in [docs/release-identity.md](./docs/release-identity.md).

## Quickstart: run your own volume

Provision an XFS project directory on a dedicated XFS mount that carries
`prjquota` and `nodev,nosuid,noexec,noatime`:

```bash
sudo scripts/provision-xfs-volume.sh /srv/portablefs my-workspace 42001 200001 200001 100g 10000000
```

Run the authority as the volume's service account. It refuses to run as root.

```bash
portablefs-authority \
  -listen 0.0.0.0:2050 \
  -volume-id my-workspace \
  -root /srv/portablefs/my-workspace \
  -project-id 42001 \
  -tls-cert server.pem -tls-key server.key \
  -client-ca clients-ca.pem \
  -capability-public-key capability.pub.pem \
  -visibility-membership-file /srv/portablefs/.portablefs-control/my-workspace/membership \
  -write-staging-dir /srv/portablefs/.portablefs-control/my-workspace/write-staging
```

Then mount it, as above. On clean unmount the supervisor closes the FUSE
connection, returns its leases, and sends a session-authenticated detach. If the
supervisor crashes, the authority fences the session and reclaims its leases
only after their conservative TTL bound. A restart grace period prevents a new
mutation from racing leases the restarted authority no longer has in memory.

Full operator guidance — provisioning, credentials, bounds, restart, and backups
— is in [docs/xfs-authority-deployment.md](./docs/xfs-authority-deployment.md).

## Hosted lifecycle

The repository also contains a product-neutral hosted foundation:

- `portablefs-manager` allocates volumes, signs complete cell plans, issues
  proof-of-possession client certificates, and mints exact dual-authorized mount
  and reauthorization grants.
- `portablefs-cell-agent` is unprivileged and outbound-only.
- `portablefs-cell-helper` is the narrow root/XFS boundary and independently
  verifies signed plans.
- systemd owns each listener and supervises one sandboxed, unprivileged
  authority per active volume.

The manager is not in the read/write path. Client private keys are generated on
the mount host and never delivered by the manager. Long-lived v3 mounts renew an
existing session with an exact monotonic `Reauthorize` operation; access may
narrow but never broaden. See
[docs/hosted-control-plane.md](./docs/hosted-control-plane.md) and
[docs/hosted-cell-deployment.md](./docs/hosted-cell-deployment.md).

## What PortableFS guarantees

- **XFS is the truth.** There is no PortableFS journal, manifest, checkpoint, or
  content index. XFS's own metadata journal is a crash-recovery mechanism inside
  XFS; it is not PortableFS history and is not user-visible.
- **Protocol writes are through.** Linux write-capable opens use stock FUSE
  direct I/O. `write(2)` returns only after the authority applies the bytes to
  XFS and discharges conflicting peer data leases. PortableFS adds no daemon or
  offline write-back tail.
- **`fsync` means fsync.** A successful `fsync`/`fdatasync` means the authority
  completed it on the authoritative open file description. `close` is not an
  implicit `fsync`. `FUSE_SYNCFS` is used when the stock kernel advertises it;
  kernels at the 7.31 floor predate that request, so PortableFS does not claim a
  remote-volume `syncfs(2)` barrier there.
- **Execution is session-exact.** Duplicate delivery inside a live epoch returns
  the retained outcome from a replay slot and never re-executes. Nothing is
  silently continued across an epoch: a mutation whose reply is lost to authority
  death is reported `UNCERTAIN`, and the application inspects current state.
  Transparent exactly-once across server death is not claimed.
- **Cached state is lease-governed.** Name, attribute, clean-data, and complete
  directory-enumeration caches require authority leases. A conflicting mutation
  recalls those leases, applies to XFS, and returns only after peer discharge.
  A nonresponsive holder is fenced and the mutation waits for lease expiry.
- **The platform contract stays explicit.** Atomic rename decides whole-file
  replacement, and open descriptors keep working after unlink until final
  close. Linux POSIX record locks and BSD `flock` are distributed and
  independent. macOS declares the separate FSKit synchronous-repair profile and
  its weaker cache, append, and lock edges rather than claiming Linux semantics.

## What PortableFS is not

- **Not versioned storage.** No history, forks, branches, snapshots, commits, or
  `adopt`. That was the v2 product, and the v3 reset removed its journal and
  journal control plane. The hosted v3 manager controls placement and access;
  it never stores filesystem history. See [COMPATIBILITY.md](./COMPATIBILITY.md).
- **Not eventually consistent.** A cache right is discharged before a
  conflicting mutation returns. The two bounded stock-FUSE clean-data
  residuals are disclosed in the consistency contract rather than hidden as a
  weaker mode.
- **Not offline-capable.** There is no local write-back tail to replay. A mount
  that cannot reach its authority stops serving rather than diverging.
- **Not a multi-user filesystem yet.** A volume is single-principal: every inode
  is owned by the volume worker's service UID/GID, and each mount projects that
  principal onto its local user.
- **Not a home for shared file-backed `mmap` or SQLite WAL.** `MAP_SHARED` on a
  file is refused rather than served incoherently, and SQLite's WAL mode requires
  every participant to be on one host.

## Platforms

| Platform | Transport | Status |
| --- | --- | --- |
| Linux | stock kernel FUSE protocol 7.31+ (`vcs/internal/fusev3`) | The protocol-6 implementation target. The writable profile is not production-ready because stock FUSE does not forward `RWF_APPEND`; `O_APPEND` is refused, but `RWF_APPEND` cannot yet be detected. No private kernel capability or opcode is accepted. CI currently exercises one hosted Ubuntu stock kernel; the broader LTS matrix remains an open qualification gate. |
| macOS 26 | FSKit synchronous VFS repair | Supported by the explicit protocol-6 FSKit profile. Mutations are ordered through PREPARE/COMPLETE, but host cache repair remains best-effort and append/lock/cache edges are not claimed equivalent to Linux. |
| macOS 27 | FSKit synchronous VFS repair; separately signed native `DataCacheHandler` build | The ordinary app uses the same admitted v2 repair contract as macOS 26. A build-stamped native artifact strengthens retained-data revocation. Neither claims exact namespace/attribute withdrawal, append intent, or distributed locks. |

The macOS 26 policy and its historical measurements remain evidence for that
weaker profile. The remaining platform gaps are in
[docs/macos-26-coherence-contract.md](./docs/macos-26-coherence-contract.md).

## Development and verification

```bash
bash scripts/verify-local.sh        # the single local merge gate
```

`verify-local.sh` runs cross-OS Go builds and vet, the pinned reachable-call
vulnerability scan, the Go suite, the Go race suite, the native Xcode Swift
gate on macOS, pinned workflow semantic validation, the release-trust policy
checkers, and a stale-architecture scan. The Xcode gate separately enumerates
the test inventory, executes one test process, and requires the xcresult to
contain the same unique all-passing set. Socket-backed integration tests
declare their process-wide resource constraint through a serialized Swift
Testing suite; pure tests remain parallel.

Deeper gates:

```bash
bash scripts/xfs-fuse-integration.sh    # privileged: stock kernel FUSE + real XFS
bash scripts/coherence-matrix-linux.sh  # stock kernel, two-mount black-box matrix
bash scripts/package-manager-matrix.sh  # npm/yarn/bun installs on a shared volume, recorded not gated
```

The macOS matrix runs against two already-mounted paths, optionally with a
remote peer:

```bash
scripts/coherence-matrix-macos.sh --mount-a /path/a --remote user@host --remote-mount /path/b
```

## Documentation

- [docs/architecture.md](./docs/architecture.md) — the product contract, in brief.
- [docs/xfs-authority-architecture.md](./docs/xfs-authority-architecture.md) — the
  XFS authority, confinement, and storage foundation.
- [docs/portable-coherence.md](./docs/portable-coherence.md) — the protocol-6
  stock-FUSE lease architecture and proof obligations.
- [docs/xfs-authority-deployment.md](./docs/xfs-authority-deployment.md) — running
  a volume yourself.
- [docs/hosted-control-plane.md](./docs/hosted-control-plane.md) — the hosted
  manager, authorization, lifecycle, fencing, and deliberate v1 limits.
- [docs/hosted-cell-deployment.md](./docs/hosted-cell-deployment.md) — deploying
  the outbound agent, root helper, and systemd authority units on a cell.
- [docs/consistency-model.md](./docs/consistency-model.md) — the exact
  visibility, durability, and retry rules.
- [docs/failure-modes.md](./docs/failure-modes.md) — what breaks, and what a
  process observes when it does.
- [docs/macos-26-coherence-contract.md](./docs/macos-26-coherence-contract.md) —
  the declared macOS 26 cache policy and its open gates.
- [docs/fskit-mount.md](./docs/fskit-mount.md) — how a macOS mount happens.
- [docs/cross-mount-coherence-matrix.md](./docs/cross-mount-coherence-matrix.md) —
  the black-box behaviour matrix and its falsifiability controls.
- [docs/agents.md](./docs/agents.md) — using a workspace from an agent.
- [docs/open-after-unlink.md](./docs/open-after-unlink.md) and
  [docs/graft-security.md](./docs/graft-security.md) — two specific contracts
  worth reading before relying on them.
- [docs/performance.md](./docs/performance.md) — the deliberate baseline costs,
  the measurement tools that exist, and the absence of published v3 numbers.
- [docs/local-dev.md](./docs/local-dev.md),
  [docs/release-identity.md](./docs/release-identity.md),
  [docs/liveness-followups.md](./docs/liveness-followups.md) — working on it.
- [docs/direct-store-exploration.md](./docs/direct-store-exploration.md) and
  [docs/direct-store-consensus-evaluation.md](./docs/direct-store-consensus-evaluation.md)
  — concluded exploration records, kept for their reasoning.

Agents changing this repository should read [AGENTS.md](./AGENTS.md); agents
using a workspace should read [skills/portablefs/SKILL.md](./skills/portablefs/SKILL.md).

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
