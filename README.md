# PortableFS

PortableFS makes one durable workspace appear as an ordinary, live directory
on multiple machines. Every mount reads and writes the same current filesystem;
there are no branches, merges, commits, or user-visible history.

## v3 root architecture

```text
Linux FUSE mount       future verified FSKit mount
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
  locks, and runtime cleanup;
- `vcs/internal/authorityrpc`: TLS 1.3/mTLS transport and XFS request handler;
- `vcs/internal/volumecap`: signed, short-lived, volume- and peer-bound access
  capabilities;
- `vcs/internal/fusev3`: exact Linux frontend with direct I/O and zero cache
  TTLs; and
- `vcs/cmd/portablefs-authority` and `vcs/cmd/portablefs-mount-v3`: standalone
  authority and mount binaries.

Linux is the first exact frontend. It uses direct I/O and zero cache TTLs.
Shared file-backed `mmap` is explicitly unsupported because PortableFS does not
advertise the FUSE capability that would allow shared mapped pages on a
direct-I/O inode. `MAP_PRIVATE` remains available with normal process-local
copy-on-write semantics; it is not a shared write path, and visibility of later
external file changes is unspecified just as it is for ordinary filesystems.
PortableFS does not silently substitute incoherent page caching. Apple added synchronous
FSKit data-cache coherency APIs in its June 2026 beta SDK, but production macOS
support remains a release gate until those APIs are available in the selected
non-beta minimum OS and pass namespace, negative-dentry, data-cache, and failure
tests. There is no legacy cache-refresh workaround in v3.

## Build and test

```bash
pnpm verify

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
