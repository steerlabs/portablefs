# Power-loss testing

`docs/direct-store-consensus-evaluation.md` records one open item plainly:

> Successful `fsync` and directory `fsync` are assumptions until power-cut
> testing confirms them.

This document describes the harness that turns that assumption into evidence,
what the evidence covers, and - at least as importantly - what it does not.

## The contract under test

A write acknowledged by the authority is present in the served XFS page cache.
It is durable across a power cut only once an `fsync` or `fdatasync` through the
mount has returned success.

That is the whole promise, and it is narrow on purpose. Following it through the
code:

- A mount's `fsync` becomes an `authoritypb.Request_Fsync`
  (`vcs/internal/fusev3/fuse_linux.go`), and `fsyncdir` becomes the same request
  on the directory handle.
- The authority's handler calls `Store.Fsync`
  (`vcs/internal/authorityrpc/volume_handler_linux.go`), which is
  `xfsstore.Volume.Fsync` (`vcs/internal/xfsstore/volume_linux.go`), which is
  `unix.Fdatasync` or `unix.Fsync` on the target descriptor.
- A write transaction is different. Payload bytes are staged in a sealed
  `memfd` and applied to the XFS inode with `sendfile`
  (`vcs/internal/authorityrpc/write_transaction_linux.go`,
  `xfsstore.writeTarget.CommitWrite`). The commit is acknowledged once that
  apply has happened. Nothing has been fsynced at that point. The staging code
  says so itself: "Staging was never fsynced, so anonymous memory does not
  change write-through acknowledgement or the target descriptor's later fsync
  durability barrier."

So an acknowledged write lives in the page cache, and a power cut discards the
page cache. **The harness therefore asserts presence only for writes whose
`fsync` had already returned, and asserts nothing about the survival of a write
that was merely acknowledged.** Widening that would make the harness demand a
promise the code does not make; narrowing it would make a green run meaningless.

### Exactly what is asserted about an un-fsynced write

One thing, and it is not about survival. A checkpoint file is written once and
never rewritten, so if recovery leaves any of it behind, every non-zero byte
must be a byte this workload wrote at that offset. Anything else would be stale
data XFS exposed from a previously freed extent, which is a defect at any cut.
Absent, empty, partial and complete are all conforming outcomes; a byte that was
never written is not.

This is `RequirePermitted` in `vcs/test/powerloss/verify.go`. The rule is
enforced by reconstructing the payload with `GenerateContent`, and if the ledger
turns out not to be reproducible the verifier fails rather than silently
skipping the check.

## The two instruments

### Device instrument: dm-log-writes

`dm-log-writes` is stacked under the XFS the authority serves. It passes every
bio through to the target device and records it - with its flush and FUA flags,
in issue order - on a separate log device. Replaying that log onto a zeroed
image up to entry N reconstructs the platter state a power cut immediately after
the Nth bio would have left. Dirty page cache is not replayed, because a power
cut does not write it back. This is a real power-cut simulation.

The run:

1. Stack `dm-log-writes` over two loop-backed images, `mkfs.xfs` through it, and
   mount the cell. Everything from mkfs onwards is in the log, so a replay onto
   zeros reproduces the whole device.
2. Provision the volume with the shipped `scripts/provision-xfs-volume.sh`, so
   the layout is the one a deployment runs rather than a private copy of it.
3. Start the real `portablefs-authority` and a real `portablefs-mount-v3`, both
   as the unprivileged volume identity.
4. Drive `pfs-powerloss-driver` over the mount. Each round writes one file,
   fsyncs it, fsyncs its directory, and only then asks for a log mark; then
   writes a second file it never fsyncs. The mark request goes out on the
   driver's stdout and the harness answers on its stdin, so the mark always
   lands after the fsync returned and before the next write starts.
5. Establish the device-release precondition in order: SIGKILL and reap the
   authority; SIGKILL and reap the mount server; force-detach its FUSE mount
   and prove that exact kernel mount absent; then unmount the write-staging bind
   whose source is inside the cell. Only after every service-side holder is
   gone does the harness take the `power-cut` mark, unmount XFS, and release the
   device-mapper target. Everything the tidy-up XFS unmount writes lands after
   that mark and is truncated away by `Log.Through`, so no cut is contaminated
   by a write that only exists because the harness had to clean up after
   itself.
6. For each replay point - every checkpoint mark, plus a bounded sweep of the
   filesystem's own flush/FUA barriers spread across the whole log, plus the
   cut itself - replay to a fresh image, mount it (which runs XFS log recovery),
   check the contract, unmount, and require `xfs_repair -n` to find nothing it
   would correct.

Both halves of step 6 matter. Content that survives on a filesystem
`xfs_repair` would rebuild is not durable, and a clean `xfs_repair` over content
that vanished is not durable either.

### Process instrument: SIGKILL and restart

`SIGKILL` removes the authority process but not the kernel's dirty page cache.
It is **not** a power-loss test and does not stand in for one, and every report
it produces says so. What it covers is the half the device instrument cannot
reach: that the authority restarts over a volume it was killed in the middle of
writing, that a fresh mount attaches, that the volume serves again, and that
nothing an `fsync` had already promised was lost. The kill lands at a different
point in each round, at fixed delays rather than random ones - a harness whose
coverage changes between runs cannot say what a green result covered.

The strict-membership restart gate remains part of this instrument. Killing an
authority cannot authenticate `Detach`, so the harness reaps the killed round's
mount process, force-detaches its exact kernel mount, proves that mount absent,
and only then starts the replacement with the audited
`--prior-strict-mounts-fenced` operator assertion. Authority loss by itself is
never treated as fencing evidence. The fresh liveness-probe mount then shuts
down normally while the replacement authority is alive, which sends the
authenticated `Detach` and leaves no active membership for the next round.

In practice an un-fsynced write usually still survives this instrument, because
the page cache does. The harness records that as an observation and never as a
requirement (`ExpectationsAfterRestart`).

## What this harness does not claim

- It does not test whether the physical block device honours its cache flushes.
  Loop files and `dm-log-writes` measure what the filesystem asked the device to
  do, not whether a disk lied about it.
- It does not cover multi-node or consensus durability. One authority, one XFS.
- It does not assert anything about writes acknowledged but not fsynced, beyond
  the stale-data rule above.
- It does not exercise `ENOSPC`, torn-write injection or lying syncs. Those are
  named separately in `docs/direct-store-exploration.md` and are the simulated
  fault harness's job (`vcs/internal/directstoreharness`), not this one's.

## Where the pieces live

| Path | What it is |
| --- | --- |
| `vcs/test/powerloss/logwrites.go` | dm-log-writes log parser and replayer, portable, unit tested anywhere |
| `vcs/test/powerloss/ledger.go` | the workload's record of what may be claimed, and its validation rules |
| `vcs/test/powerloss/points.go` | replay-point selection: every checkpoint mark, a bounded barrier sweep |
| `vcs/test/powerloss/verify.go` | the durability contract, expressed as requirements per cut |
| `vcs/test/powerloss/device_linux.go` | loop, device-mapper, mount and `xfs_repair` orchestration |
| `vcs/test/powerloss/engine_linux_test.go` | harness self-calibration and the kernel-level control |
| `vcs/test/powerloss/authority_linux_test.go` | the two product-level instruments |
| `vcs/test/powerloss/cmd/pfs-powerloss-driver` | the workload, run as the unprivileged volume identity |
| `scripts/run-powerloss.sh` | the entrypoint CI calls |
| `.github/workflows/powerloss.yml` | weekly and on-demand, on the privileged self-hosted runner |

## Gates

The gates follow the same discipline as `PORTABLEFS_XFS_TEST_ROOT` and
`PORTABLEFS_FUSE_TEST`: one named variable per prerequisite, a skip that says
which one is missing, and a `REQUIRED` switch the CI job sets that turns every
skip into a hard failure.

| Variable | Meaning |
| --- | --- |
| `PORTABLEFS_POWERLOSS_TEST` | `=1` enables the harness at all |
| `PORTABLEFS_POWERLOSS_REQUIRED` | `=1` turns every skip into a failure. The CI job sets it |
| `PORTABLEFS_POWERLOSS_WORK_DIR` | scratch directory for device images and mount points |
| `PORTABLEFS_POWERLOSS_BIN_DIR` | directory holding the binaries built from this tree |
| `PORTABLEFS_POWERLOSS_CREDS_DIR` | the minted credential set |
| `PORTABLEFS_POWERLOSS_PROVISIONER` | path to `scripts/provision-xfs-volume.sh` |
| `PORTABLEFS_POWERLOSS_SERVICE_UID` / `_GID` | the unprivileged volume identity |
| `PORTABLEFS_POWERLOSS_VOLUME`, `_PROJECT_ID`, `_AUTHORITY_PORT` | volume identity and listen port |
| `PORTABLEFS_POWERLOSS_CAPABILITY_LIFETIME` | window the credential set was minted with |
| `PORTABLEFS_POWERLOSS_IMAGE_SIZE`, `_CHECKPOINTS`, `_BARRIER_POINTS`, `_KILL_ROUNDS` | run size |

One rule is inverted relative to the XFS and FUSE gates. Those refuse to run as
root, because root makes their DAC assertions vacuous. This harness **requires**
root, because it creates loop devices, a device-mapper target and filesystem
mounts. It keeps the data plane unprivileged the same way the deployment does:
the authority, the mount and the workload driver are all spawned with the
service identity's credentials, never as root.

On top of the Go gates, `scripts/run-powerloss.sh` greps the run for the exact
test names that had to execute and fails the job if any is missing, and fails on
any `--- SKIP` at all, since `REQUIRED=1` should have made one impossible.

## What runs where

| | Any machine | Privileged Docker on a dev host | Self-hosted `portablefs-strict-6-12-100` |
| --- | --- | --- | --- |
| Log parsing, replay, point selection, verification, ledger, driver protocol | yes | yes | yes |
| `TestReplayReproducesTheDeviceTheKernelWrote` | no | yes | yes |
| `TestXFSHonoursFsyncAtEveryCut` | no | yes | yes |
| `TestFsyncedWritesSurvivePowerLoss` | no | **no** | yes |
| `TestAuthorityKillDuringWritesKeepsFsyncedData` | no | **no** | yes |

The two product-level instruments need a kernel that can carry a strict mount,
and a strict mount pins exactly one FUSE protocol version. A Docker Desktop VM
running Linux 6.8 offers FUSE 7.39 and the mount refuses it outright:

```
fusev3: strict coherence requires the pinned FUSE protocol 7.41 exactly; kernel offered 7.39
```

The harness reports that through the ordinary gate, so it is a named skip on a
developer machine and a hard failure in CI - never a quiet pass. Everything else
about those two tests - the device stack, the provisioner, the authority start,
the credential set, the mark channel, the teardown - has been exercised on a
dev host up to that exact point.

`dm-log-writes` itself is available in privileged Docker on a dev host provided
the host kernel has `CONFIG_DM_LOG_WRITES` and `/lib/modules` is bind-mounted so
`modprobe` can load it. The entrypoint does both.

## Notes from bringing this up

Three of these are recorded because they cost real time and would cost it again.

- **The log must be read after the target is released, and through the loop
  device.** `dm-log-writes` flushes its queued entries and rewrites the
  superblock's entry count in its destructor, so a log read while the target is
  live is short by an unpredictable amount - and a short log understates what
  reached the device, which makes every cut optimistic. Reading the backing file
  rather than the loop device has the same effect for a different reason: the
  loop driver has not necessarily written it back. `ParseLogDevice` refuses to
  run while the target exists.
- **A replayed image must be mounted with the same options as the cell.** XFS
  rebuilds quota metadata during recovery only when quotas are enabled. A replay
  mounted without `prjquota` leaves quota blocks `xfs_repair -n` reports it
  would correct - a difference introduced by the harness, not by the cut. This
  produced a real, reproducible false failure at an early cut before the options
  were made to match.
- **The capability bound must be wider than the minted window, not equal to
  it.** The credential tool back-dates `not_before` by a second, so a token
  minted for exactly `L` declares a window of `L+1s`, and `volumecap` refuses a
  declared window larger than the authority's `--capability-max-lifetime`. That
  refusal arrives as `EPERM` on attach, which reads exactly like a durability
  harness that cannot mount.

Containers add two more, both handled in the entrypoint: `dmsetup` needs
`DM_DISABLE_UDEV=1` and `dmsetup mknodes` because there is no udev to publish
the device node, and the loop device nodes must be pre-created with `mknod` for
the same reason - otherwise `losetup --find` reports `ENOENT` for a device the
kernel did allocate.

## Running it

```sh
# Full run, in a privileged container, from a checkout:
bash scripts/run-powerloss.sh

# The portable logic, anywhere:
go -C vcs test ./test/powerloss/...
```

The device-mapper namespace is kernel-global and shared with everything else on
a runner, so the harness names its target after its own pid, tears the stack
down in an order that cannot leave a mounted filesystem holding it, and treats a
failed teardown as a failure of the run - a leaked target breaks the *next* run,
which is the worst way for a harness to fail.
