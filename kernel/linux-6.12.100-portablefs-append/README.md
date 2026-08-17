# PortableFS Linux 6.12.100 strict-coherence series

This directory contains an isolated, private FUSE patch series for upstream and
Debian Linux 6.12.100.  It does not modify PortableFS Go code and it is not a
stock-FUSE compatibility shim.

The historical directory name says `append`; the implementation now covers the
whole strict kernel publication boundary:

- exact 7.41 profile negotiation and immutable SHARED/LOCAL classification;
- cacheable SHARED regular opens (`FOPEN_KEEP_CACHE|FOPEN_PFS_SHARED`) whose
  page cache is withdrawn by ordered DATA publication under
  `mapping->invalidate_lock`, plus the whole-inode withdrawal a revoking mount
  uses to stop serving retained pages;
- transactional positioned and effective-append writes;
- a generic post-VFS publication ACK for marked replies;
- ordered exact-size/full-data invalidation notifications;
- private full-mode XFS fallocate and SHARED copy-file-range requests;
- stock classified TMPFILE with post-VFS publication;
- exact write/splice/AIO/io_uring position and post-apply handling; and
- fail-closed removal of stock mutation and ENOSYS fallback paths.

The complete protocol, marker matrix, lock ordering, failure semantics, and
qualification limits are in
[`docs/linux-exact-append-abi.md`](../../docs/linux-exact-append-abi.md).

## Verification

Run:

```sh
./verify.sh
```

The verifier checks pinned source hashes, applies the series independently to
kernel.org and Debian 6.12.100, checks every affected path and invariant on both
trees, compiles the UAPI layout assertions against both headers, runs
deterministic protocol/concurrency and source-hook tests, runs checkpatch, and
builds every affected object for x86_64 and arm64 in a disposable container.

For a fast host-side pass without cross-architecture builds:

```sh
./verify.sh --no-build
```

The optional direct-XFS oracle is deliberately opt-in because it creates and
mutates disposable files on the named filesystem:

```sh
PFS_XFS_TEST_DIR=/explicit/disposable/xfs/path \
  python3 tests/test_xfs_fallocate.py
```

Do not point it at an inferred or production data directory.
When the XFS path is supplied, the runner fails qualification unless the live
kernel release is exactly the 6.12.100 release family (for example,
`6.12.100-pfs-strict-kasan`); results from a stock 6.8 or other kernel are not
accepted as evidence.

The privileged boundary test requires an explicitly named disposable path on
an already mounted strict PortableFS instance.  It proves that overlay lower
and upper stacking, the pre-INIT race, and read-only loop backing are rejected,
while a LOCAL file remains usable as ordinary loop backing:

```sh
PFS_STRICT_STACK_TEST_DIR=/explicit/disposable/strict/path \
  python3 tests/test_strict_stacking.py
```

## Qualification status

The exact protocol-5 Linux candidate is qualified on the pinned arm64
`6.12.100-pfs-strict` diagnostic kernel.  The matching userspace passed the
service-identity privileged suite, real two-mount coherence and syscall matrix,
root-only stacking/export/loop boundaries, direct-XFS oracle, KASAN/lockdep
post-run scan, full Go normal/race/vet suites, and the native Swift release
gate.  The final receipt is
[`qualification/2026-08-15-live-qualification.md`](qualification/2026-08-15-live-qualification.md).

Qualification is exact, not compatible-by-approximation: a stock kernel, a
different FUSE minor, or a daemon implementing only part of the private dialect
must not be deployed with the strict capability. Performance measurements are
engineering evidence and do not create a service SLO.

The isolated arm64 VM's pinned build, boot, static-verifier, and direct-XFS
preflight evidence is recorded in
[`qualification/2026-08-13-kernel-preflight.md`](qualification/2026-08-13-kernel-preflight.md).
That receipt records the earlier preflight only; the August 15 receipt is the
completion boundary for the live userspace/FUSE matrix.
