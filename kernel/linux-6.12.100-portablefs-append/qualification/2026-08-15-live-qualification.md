# Linux 6.12.100 protocol-5 live qualification

Status: **qualified for the exact matching Linux protocol-5 candidate**.

Captured on 2026-08-15 (America/Los_Angeles) in the isolated Lima
`pfs-k612100-qual` VZ/aarch64 VM. The final boot ID was
`783c232f-f7ce-4ae7-b055-14ea1d8177c7` and the running release was exactly
`6.12.100-pfs-strict`.

This receipt completes the boundary left open by
`2026-08-13-kernel-preflight.md`: matching userspace was exercised through real
kernel FUSE mounts, two independent strict sessions, real project-quota XFS,
and the post-VFS publication protocol. It does not qualify a stock kernel, a
different FUSE minor, an incomplete daemon dialect, macOS FSKit, or a service
performance SLO.

## Exact inputs and booted artifacts

- Base repository commit: `e13ea8ee695460833028503ebe15409a30a6be58` on
  `codex/root-performance-architecture`.
- Qualified tracked working-tree delta, excluding this self-referential receipt:
  134 paths; binary-diff SHA-256
  `42f1cbb5816d34d5bbac61bbbc2b8c252d73c17bac7bd1ad3d1a465da07f1d50`.
- Qualified untracked source payload, excluding the local checkpatch scratch
  file, a built CLI binary, Python caches, and this receipt: 339 files;
  path-sorted content-manifest SHA-256
  `d2ab59d44b74f1f20b376f3de36593d74c2aa9ca8df9411ec92891457e2f09d5`.
- Upstream `linux-6.12.100.tar.xz` SHA-256:
  `67f973533406492e86774bacbcefae50d50d5c34cbf703c47ec526a5efdcee90`.
- Patch 1 SHA-256:
  `096d01915824d909316498fdc9de9252730ac4292294fd421a7fa4b24fffa417`.
- Patch 2 SHA-256:
  `2534c6889f73d02bd2166791298da6e1a8a7689e92166bbf6fd74945c19cc786`.
- Reconstructed final kernel source commit:
  `7904f7b40640682e3e3650661ca0095572d48c9c`.
- Installed kernel image SHA-256:
  `5a850cbf7caaf1f818a188b23789ea66dc7ebdb67032bbd1b5c4bf0176aa844b`.
- Installed config SHA-256:
  `45148991bfb952bdffd4392262c401abd1a078ac79cfb6b44ba78e1641f58972`.
- Installed initramfs SHA-256:
  `ccda7852c9be851ea90d8131e9e7c1d81df880c3b1ef9276d1936338adf377b2`.

The config has built-in FUSE and XFS plus XFS debug, generic KASAN,
lockdep/`PROVE_LOCKING`, `DEBUG_ATOMIC_SLEEP`, and kernel fault-injection
facilities. The persistent GRUB default remained stock Debian
`6.1.0-44-cloud-arm64`; the diagnostic kernel was selected one-shot and
`next_entry` was empty after boot.

## Storage identity and containment

- Dedicated disk `/dev/vdb`, 32 GiB; exact partition `/dev/vdb1`.
- PARTUUID `6210c012-0435-9448-a3bc-ac76917aab88`.
- XFS UUID `9489d5be-f811-438b-9a12-df97179909eb`.
- Mount options:
  `rw,nosuid,nodev,noexec,noatime,attr2,inode64,logbufs=8,logbsize=32k,prjquota`.
- Performance project: id 43001, uid/gid 200001, 8 GiB block limit and
  500,000-inode limit.
- Final root/XFS use: 10,502,307,840 / 101,240,397,824 bytes and
  273,043,456 / 34,290,532,352 bytes. The 70 GiB actual-use stop was never
  approached.

No shared host Docker state was pruned. The stock recovery kernel was retained.

## Static and build verification

The exact final series passed `verify.sh --no-build` after the live suite:

- clean sequential application to official upstream and Debian 6.12.100;
- checkpatch: 0 errors and 0 warnings for both patches;
- UAPI layout assertions on both baselines;
- 24/24 patched-source invariants on each baseline;
- 44/44 executable state/order models; and
- strict optional tests correctly skipped unless an explicit live path was
  supplied.

Before the final boot, every affected object compiled with `W=1` for arm64 and
x86_64 and the complete arm64 Image/modules/initramfs were rebuilt from the
exact final patches. The post-suite direct-XFS oracle then passed 5/5 on the
running kernel, covering allocate/keep/punch/zero/unshare, collapse/insert byte
shifting, end-at-EOF precedence, and RLIMIT signaling.

## Live strict-FUSE qualification

The official fail-closed privileged entry point
`scripts/xfs-fuse-integration.sh` passed on the booted kernel:

- all 49 required unprivileged service-identity tests;
- the root-only `TestStrictKernelRefusesStackingExportAndLoopBacking` wrapper;
- all four delayed-INIT, overlay-lower, overlay-upper, and read-only loop
  boundary oracles; and
- no required test skipped or disappeared from the exact manifest.

The live matrix includes two-mount content/size/attribute/positive and negative
dentry/rename/readdir coherence, concurrent writers, authority loss, lock wait
and session expiry, remount durability, exact detach, route graft isolation,
large positioned/append writes, every supported shared fallocate mode,
copy-file-range and cross-domain `EXDEV`, TMPFILE first-link/`O_EXCL`, syncfs,
Git, SQLite rollback-journal, and visibility saturation. Write BEGIN/DATA/ABORT
use retained physical-reply receipts; COMMIT remains replay-slot retained and
publishes only after VFS postprocessing.

## Whole-repository userspace gates

After the final clone-free staged-write change and the complete route-attach
fixture update:

- Linux `go test ./... -count=1`: passed with the real XFS production gate.
- Linux `go test -race -p 1 ./... -count=1`: passed. `-p 1` is required because
  the single provisioned volume deliberately admits exactly one authority
  owner; parallel package binaries correctly contend on that lock.
- Linux `go vet ./...`: passed.
- `scripts/verify-local.sh`: passed Darwin+cgo and Linux-static build/vet,
  native Go normal/race, the maintained go-fuse reply-publication seam,
  release trust/stale-architecture scans, and 340/340 Xcode-native Swift tests.
- Focused owned-idempotent request and retained-response race tests passed ten
  repeated race-enabled runs.

## Performance and efficiency evidence

`TestStrictPerformanceAgainstDirectXFS` ran five complete, isolated repetitions
as uid/gid 200001 against project 43001. Every source and peer bulk file matched
SHA-256. Median results were:

| observation | direct XFS | one strict mount | active overlapping peer |
| --- | ---: | ---: | ---: |
| 4 KiB write p50 | 0.016 ms | 0.822 ms | 1.053 ms |
| 4 KiB write p99 | 0.039 ms | 57.434 ms | 28.776 ms |
| 64 MiB acknowledged write | 1,781.1 MiB/s | 140.2 MiB/s | 201.9 MiB/s |
| 64 MiB read | 2,181.9 MiB/s | 105.6 MiB/s | 110.5 MiB/s |
| complete workload | 0.194 s | 2.611 s | 3.867 s |

The active-peer write ranges overlap, so its higher median is variance rather
than an acceleration claim. The peer had deliberately acquired every affected
cache coordinate, and its final data hash matched before the source run
completed.

The final optimization removed a 1 MiB protobuf clone from every staged DATA
RPC without weakening the general defensive-copy API. The framing microbench
remained one 24-byte allocation per 1 MiB write frame; the eliminated clone was
1,048,889 B and five allocations per fragment. In the post-change CPU profile,
`runtime.memmove` fell to 0.04 seconds and actual TLS/kernel syscalls dominated.

Periodic 29–57 ms 4 KiB p99 stalls remain visible on the KASAN/lockdep kernel.
Tracing found no matching 50–100 ms XFS syscall and no Go stop-the-world pause
of that size. This is recorded as diagnostic-kernel tail work, not hidden as an
average and not promoted to a service SLO.

No current Archil endpoint or account was in scope. Historical Archil figures
remain directional only; no external resources were provisioned or charged for
this receipt.

## Final kernel health

After all static, direct-XFS, live FUSE, two-mount, performance, and race work:

- `/proc/sys/kernel/tainted` was `0`;
- lockdep remained initialized and `/proc/lockdep_stats` reported 1,631 lock
  classes and 18,112 direct dependencies;
- final `dmesg` SHA-256 was
  `32182e461c5d3599a741a808e84972c97c85df1e72a64d0ee996905b4259d98b`;
- the failure scan found zero KASAN reports, BUG/WARNING splats, circular-lock
  warnings, deadlocks, XFS corruption/shutdown, use-after-free, or
  out-of-bounds reports. The expected boot line saying KASAN was initialized
  was excluded from the failure count.

This is the completion boundary for the exact Linux candidate. Any change to
the two patch bytes, kernel config, private FUSE ABI, userspace protocol-5
dialect, publication lifecycle, or storage mutation contract requires a new
receipt.
