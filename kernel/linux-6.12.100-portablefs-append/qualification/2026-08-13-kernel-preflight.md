# Linux 6.12.100 strict-coherence VM preflight

Status: **kernel preflight passed; full PortableFS qualification not yet run**.
The userspace tree was intentionally not snapshotted and no privileged FUSE or
two-mount suite was started while its terminal-receipt work was still changing.

Captured at 2026-08-13T10:28:45-07:00 (America/Los_Angeles) in the isolated
Lima `pfs-k612100-qual` VZ/aarch64 VM.  Boot ID:
`f596acba-0605-46ca-96bc-86bb4c648abe`.

## Reproducible inputs and artifacts

- Upstream `linux-6.12.100.tar.xz`:
  `67f973533406492e86774bacbcefae50d50d5c34cbf703c47ec526a5efdcee90`
- Patch 1:
  `096d01915824d909316498fdc9de9252730ac4292294fd421a7fa4b24fffa417`
- Patch 2:
  `4bdb9ee8fc7abf7fc8588b1aaaea63f282e9621bb9ef1f118f9750f73a817448`
- Host pinned-tree patch-2 commit: `a7475bb8110f05fdc57bcb670f7b14c1e9d7b51d`
- Guest reconstructed-tree patch-2 commit:
  `48996d9f2e32436204eb84d2809c7c825ff51786`
- `fs/fuse/dev.c`:
  `00daf99586d8e625d1b2fc874df41aaa8bec7f9e6537358714354e088bb95093`
- `.config` and installed config:
  `2bcdffeb6845a0e98b74f64c08c095fadeba15bf18b0c7bc3772066973a3c2ea`
- `arch/arm64/boot/Image` and installed image:
  `cfd0db844d0d752fff7d3c75fd41920ea9bb46c1e6484843fa0600aa86f72ff3`
- `vmlinux`:
  `a030d2fdc2b81544e4dd21528f76187252a298e7b10e11c86ef9f1ed53edd4ab`
- `System.map`:
  `f5fb34061248854654381db0bd8d0284930dc3799742cdc4eccad17bed44d916`
- Installed initramfs:
  `ce213ff8c956ad6fb09c25b313d4779cb95284ec049f19bc0610a6b56cd1bfa6`
- Compiler: GCC 12.2.0 (`12.2.0-14+deb12u1`), GNU ld 2.40.

The running kernel is exactly `6.12.100-pfs-strict`, build `#3 SMP PREEMPT`,
booted 2026-08-13 10:25:21 PDT.  FUSE and XFS are built in; the config enables
`XFS_DEBUG`, generic KASAN, lockdep/`PROVE_LOCKING`, `DEBUG_ATOMIC_SLEEP`,
`FAULT_INJECTION`, `FAILSLAB`, and `FAIL_PAGE_ALLOC`.

## Isolated storage and recovery

- Raw additional disk: `/dev/vdb`, 34,359,738,368 bytes, GPT UUID
  `8f3ab373-68ca-3b42-8d92-2539b236bb5a`.
- Exact partition: `/dev/vdb1`, 34,357,641,216 bytes, PARTUUID
  `6210c012-0435-9448-a3bc-ac76917aab88`.
- XFS label/UUID: `pfs612100xfs` /
  `9489d5be-f811-438b-9a12-df97179909eb`.
- XFS has 4 KiB blocks, reflink and bigtime enabled, and was mounted only at
  `/srv/pfs-k612100-xfs`.
- VM root use was 8,432,025,600 bytes and XFS use 272,932,864 bytes, both far
  below the 70 GiB actual-use stop threshold.
- Persistent GRUB saved default remains Debian's stock
  `6.1.0-44-cloud-arm64`; the patched kernel was selected with one-shot
  `grub-reboot`, and `next_entry` was empty after boot.

No host Docker images, containers, volumes, or caches were pruned or changed by
the VM qualification setup.

## Checks completed on the running kernel

- Full static `verify.sh --no-build` from the exact patch SHAs: passed on clean
  upstream and Debian 6.12.100 sources.
- Checkpatch: 0 errors and 0 warnings for both patches.
- ABI layout checks: passed.
- Patched-source invariants: 17/17 passed on each source baseline.
- Executable state/order model: 40/40 passed.
- Direct-XFS oracle on `/dev/vdb1`: 5/5 passed, including allocate/keep/punch,
  zero/unshare, collapse/insert byte shifting, end-at-EOF rejection, and RLIMIT
  signaling precedence.
- Earlier host builds of the changed `fs/fuse/dev.o` passed with `W=1` for both
  arm64 and x86_64; the VM subsequently completed a full Image/modules relink.
- Kernel taint was 0 and lockdep reported `debug_locks: 1` after the checks.
- Point-in-time complete `dmesg` SHA-256:
  `550b44005b3233e3e75677872d5cbe11666e6faa0798ce99ade724bd8af10e6b`.
  The failure scan found no KASAN report, BUG/WARNING, circular lock warning,
  deadlock, XFS corruption/shutdown, use-after-free, or out-of-bounds report.
  The only boot warnings were the known VZ cache-topology notice and missing
  optional regulatory firmware.

## Remaining qualification boundary

Before a completion claim, snapshot and hash one explicitly handed-off green
userspace tree, build it inside this VM, and run the privileged strict-FUSE,
fault-injection, and two-mount coherence/stress matrix.  Recheck taint, lockdep,
XFS health, and `dmesg` after every destructive/fault phase.  This receipt is
deliberately not a substitute for that live matrix.
