# PortableFS

PortableFS makes one durable workspace appear as an ordinary, live directory
on multiple machines. Every mount reads and writes the same current filesystem;
there are no branches, merges, commits, or user-visible history.

## v3 root architecture

```text
Linux FUSE mount       macOS 27+ FSKit mount
        \                    /
         authenticated TLS RPC
                  |
       one active authority per volume
                  |
       descriptor-relative Linux syscalls
                  |
     one project-quota directory on XFS
                  |
          encrypted SSD / EBS
```

XFS is the durable filesystem truth. The authority is a disposable,
single-epoch coordinator for authentication, opaque object handles, retained
open file descriptions, same-epoch request replay, cancellation, and POSIX
advisory locks. It does not contain a second inode tree, custom storage engine,
permanent operation log, checkpoint format, branch graph, or write-back cache.

Normal filesystem durability rules apply:

- `write` returns after the authority has applied the reported bytes to XFS;
- `fsync`/`fdatasync` waits for the authoritative server descriptor;
- `close` does not imply `fsync`;
- atomic rename decides whole-file replacement conflicts; and
- open descriptors continue working after unlink until final close.

Distributed POSIX record locks and BSD `flock` are authority runtime state;
normal close/flush cleanup is forwarded to the same authority, and all locks
disappear at the epoch boundary.

The full design, failure model, security boundaries, HA choices, and proof
gates are in [the v3 architecture decision](./docs/xfs-authority-architecture.md).
The decision also records the current regular-FUSE `syncfs(2)` platform gap;
applications use file and directory `fsync` when they require durability.

## Current implementation

The greenfield v3 path lives beside the frozen v2 implementation until its
production gates are complete:

- `vcs/internal/xfsstore`: XFS-only, descriptor-relative volume backend;
- `proto/authority/v1`: bounded branchless protobuf protocol;
- `vcs/internal/volumeserver`: epoch sessions, replay slots, cancellation,
  locks, fail-closed strict-cache barriers, and runtime cleanup;
- `vcs/internal/authorityrpc`: TLS 1.3/mTLS transport and XFS request handler;
- `vcs/internal/volumecap`: signed, short-lived, volume- and peer-bound access
  capabilities;
- `vcs/internal/fusev3`: exact Linux frontend with direct file I/O, a
  synchronous strict name/attribute cache profile, and an uncached profile;
  and
- `vcs/cmd/portablefs-authority` and `vcs/cmd/portablefs-mount-v3`: standalone
  authority and mount binaries.

These binaries are the semantic/integration surface, not yet a production
control plane. The retained authority manager issues branch-bound renewable v2
HMAC leases and proxies the v2 transport; it neither provisions XFS authority
workers nor issues the end-to-end client identity and SPKI-bound Ed25519 grant
that v3 requires. The standalone grant also has an absolute, non-renewable
deadline (15 minutes by default), and an Attach reply lost after the one-time
grant is consumed is not yet replayable. Production registration therefore
requires an additive branchless v3 mount-grant/runtime contract, exact Attach
replay, and in-session reauthorization shared by Linux and macOS.

Linux is the first exact frontend. The mount binary defaults to `strict`: file
data stays direct-I/O, while names and attributes use bounded lifetimes backed
by the authority's synchronous PREPARE/apply/COMPLETE visibility barrier. The
`uncached` profile keeps zero name and attribute TTLs. Both profiles pass the
same two-mount behavior matrix; strict additionally proves that repeated path
walks avoid authority lookups without weakening the observable result.
Shared file-backed `mmap` is explicitly unsupported because PortableFS does not
advertise the FUSE capability that would allow shared mapped pages on a
direct-I/O inode. `MAP_PRIVATE` remains available with normal process-local
copy-on-write semantics; it is not a shared write path, and visibility of later
external file changes is unspecified just as it is for ordinary filesystems.
PortableFS does not silently substitute incoherent page caching. macOS 27 is
the primary FSKit architecture: Apple added module-initiated synchronous cache
state control in its June 2026 beta SDK. Production support remains gated on
the final SDK and the namespace, negative-name, data-cache, and failure matrix;
the documented data-cache API alone is not proof of every namespace cache
transition.

The authority now contains the exact two-phase protocol and durable
strict-mount membership needed by a cached frontend. pfslocal minor 8 carries
that ordered contract, and minor 9 adds a frontend-demanded end-to-end liveness
proof, to a tested Swift transport without exposing authority credentials to
the extension. A standalone portablefsd v3 data plane now maps
the FSKit operation surface to the authority, including incarnation-stable XFS
identity, readdir-plus items, source publication IDs, keepalive, and a real
authority `syncfs(2)` barrier. It is deliberately not registered as a production
attach yet. The production volume continues to refuse a v3 resolve until that
composition, both local indexes, the callback barrier, and the native macOS 27
handler are installed; it cannot advertise strict participation and ignore
events.

A separately selected macOS 26 synchronous-VFS-repair policy exercises the
same contract, including the initiating-callback deadlock boundary, but Apple
exposes no general invalidation primitive on that release and its remaining
live-kernel proofs have not passed. It is an explicit compatibility policy,
never an automatic fallback, and not a claim that macOS 26 multi-writer mounting
is production-ready. See the
[macOS 26 coherence contract](./docs/macos-26-coherence-contract.md).

## Build and test

```bash
bash scripts/verify-local.sh

go -C vcs test -race ./internal/authorityrpc ./internal/volumeserver \
  ./internal/volumecap ./internal/xfsstore

GOOS=linux GOARCH=amd64 go -C vcs build \
  ./cmd/portablefs-authority ./cmd/portablefs-mount-v3
```

The privileged Linux gate creates a disposable project-quota XFS filesystem
and two real kernel mounts. It verifies cross-mount visibility,
open-after-unlink, rejection of shared file-backed `mmap` and user-xattr writes,
locks, paged enumeration, Git integrity, and SQLite rollback-journal behavior. See the
environment-gated integration test in
`vcs/internal/fusev3/integration_linux_test.go`.

The previous v2 contract remains frozen as documented in
[COMPATIBILITY.md](./COMPATIBILITY.md). v2 and v3 reject one another at the
protocol handshake; this work does not silently reinterpret existing volumes.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
