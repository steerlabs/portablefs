# PortableFS

PortableFS makes one durable workspace appear as an ordinary, live directory on
several machines at once. Every mount reads and writes the same current
filesystem. There are no commits, no branches, and no user-visible history: the
mounted tree is the product.

One volume is one XFS project directory on one Linux host, served by one
`portablefs-authority` process. XFS is the only durable filesystem truth.
PortableFS adds authentication, object capabilities, session-exact replay,
distributed POSIX locks, and — for cached frontends — a synchronous visibility
barrier. It adds no second inode tree, no mutation log, no checkpoint format,
and no PortableFS-managed or offline write-back layer. Ordinary kernel page
caches still obey each operating system's filesystem contract.

```text
Linux FUSE mount            macOS FSKit mount
       \                          /
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
group, FSKit type, and resource scheme, with the CLI, daemon, and extension all
agreeing on that tuple. Enabling the extension under System Settings is a
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
  -mount-absence-verify-command /usr/local/libexec/portablefs-verify-absence
```

Then mount it, as above. Without `-mount-absence-verify-command` a clean detach
always fails closed: the authority cannot observe a remote kernel's mount table,
so every restart after a strict mount then depends on the operator asserting
`-prior-strict-mounts-fenced`.

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
- **Protocol writes are through.** Linux direct-I/O `write(2)`, and every write
  callback FSKit sends, return only after the authority applied the reported
  bytes to XFS. macOS may acknowledge an application `write(2)` into its ordinary
  kernel page cache before invoking FSKit; `fsync`/synchronize is the explicit
  authority boundary there. PortableFS adds no daemon or offline write-back tail.
- **`fsync` means fsync.** A successful `fsync`/`fdatasync` means the authority
  completed it on the authoritative open file description. `close` is not an
  implicit `fsync`. On regular FUSE, `syncfs(2)` does not reach the authority at
  all, so applications that need a durability boundary use file and directory
  `fsync`.
- **Execution is session-exact.** Duplicate delivery inside a live epoch returns
  the retained outcome from a replay slot and never re-executes. Nothing is
  silently continued across an epoch: a mutation whose reply is lost to authority
  death is reported `UNCERTAIN`, and the application inspects current state.
  Transparent exactly-once across server death is not claimed.
- **Visibility is two-phase for cached mounts.** With a strict frontend attached,
  a cache-affecting mutation quiesces every participant, applies to XFS, repairs
  and collects acknowledgements, and only then returns. A mount that misses its
  declared repair budget is fenced individually; the volume keeps serving.
- **POSIX stays POSIX.** Atomic rename decides whole-file replacement. Open
  descriptors keep working after unlink until final close. POSIX record locks and
  BSD `flock` are distributed and independent of each other.

## What PortableFS is not

- **Not versioned storage.** No history, forks, branches, snapshots, commits, or
  `adopt`. That was the v2 product, and the v3 reset removed its journal and
  journal control plane. The hosted v3 manager controls placement and access;
  it never stores filesystem history. See [COMPATIBILITY.md](./COMPATIBILITY.md).
- **Not eventually consistent.** There is no asynchronous invalidation stream
  that a reader can race. Either a mount holds no cached state for a name, or the
  authority repaired it synchronously before the mutation returned.
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
| Linux | kernel FUSE (`vcs/internal/fusev3`) | Production path. `strict` (default) and `uncached` profiles; proven by the privileged XFS + kernel-FUSE gate and the two-mount coherence matrix. |
| macOS 26 | `portablefsd` v3 data plane + FSKit extension | Runs under the declared compatibility policy `macos26-synchronous-vfs-repair-v2`. The final macOS 26.5 breadth, retry-free saturation, same-vnode attribute/data, daemon-death revocation/recovery, and clean-detach runs are live-proven against Linux FUSE and raw XFS. Exact overlapping operations may surface definite-preapply `ECANCELED`; authority `EINTR` never crosses the FSKit edge. |
| macOS 27 | native FSKit cache control (`DataCacheHandler`) | Primary target. No implementation exists; gated on the final SDK. Selecting the native policy today fails closed with `ENOTSUP`. |

The macOS 26 policy is an explicitly declared, owner-accepted compatibility
policy with a bounded contract — never an automatic fallback and never a silent
downgrade. Its exact callback-provenance deviations, live proofs, and remaining
breadth/fault gates are in
[docs/macos-26-coherence-contract.md](./docs/macos-26-coherence-contract.md).

## Development and verification

```bash
bash scripts/verify-local.sh        # the single local merge gate
```

`verify-local.sh` runs cross-OS Go builds and vet, the Go suite, the Go race
suite, the Swift suite (`swift test --package-path swift/PortableFSKit
--no-parallel`; serial execution is required, not a tuning knob), the
release-trust policy checkers, and a stale-architecture scan.

Deeper gates:

```bash
bash scripts/xfs-fuse-integration.sh    # privileged: real XFS + kernel FUSE, 43 required tests
bash scripts/coherence-matrix-linux.sh  # 23-case two-mount black-box matrix, with falsifiability controls
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
  full v3 design, failure model, security boundaries, and proof gates.
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
