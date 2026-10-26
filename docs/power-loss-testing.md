# Power-loss testing

The authority makes two durability claims, one per frontend profile. This
harness records each at simulated power cuts on a real XFS cell and asserts it
exactly as the code makes it. This document states the two contracts, how each
instrument checks them, what has and has not been run, and what the evidence
does not cover.

## The contracts under test

### Linux mount: durable after successful `fsync`

`write(2)` through a Linux kernel FUSE mount can return while the bytes are in
the kernel page cache, in the mount's delegated write buffer, or applied to the
authority's XFS page cache. A power cut discards all three. A write is durable
only once an `fsync` or `fdatasync` through the mount has returned success:

- The mount flushes its delegated writes in order and sends
  `authoritypb.Request_Fsync` for the handle (`vcs/internal/fusev3`); `fsyncdir`
  becomes the same request on the directory handle.
- The authority's handler calls the store's `Fsync`
  (`vcs/internal/authorityrpc/volume_handler_linux.go`), which is
  `xfsstore.Volume.Fsync` (`vcs/internal/xfsstore/volume_linux.go`): `fdatasync`
  or `fsync` on the target descriptor.

The harness therefore asserts presence only for writes whose `fsync` had
returned success, and asserts nothing about the survival of a write that `write(2)`
merely accepted.

### FSKit: durable after a successful mutation reply

FSKit has no fsync callback. The authority therefore makes every successful
FSKit mutation reply durable on authority storage before the reply is sent or
retained for replay:

- Handle-backed mutations - WRITE, CREATE, a truncating OPEN and a SETATTR that
  carries a handle - fully `fsync` the retained open description.
- Handleless mutations - namespace changes and item-backed metadata changes -
  run `syncfs` on the authority's retained XFS-root description.

The barrier is chosen from the operation, never by trying one and falling back
after an error. So, unlike the Linux workload, an acknowledged FSKit mutation
must survive every later cut. The driver takes a mark once each success reply
has arrived, so at a cut that reaches the mark of step *k*, every step up to *k*
must be present exactly:

- every acknowledged name exists with its recorded kind, every name an
  acknowledged UNLINK or RENAME removed is gone, and every directory lists
  exactly its recorded names;
- every file has exactly its recorded bytes, size, mode and hard-link count,
  names recorded as hard links are one inode, and an explicitly set atime and
  mtime are exactly what was set;
- every symlink has its recorded target and every directory its mode; explicit
  atime and mtime on either kind are checked as well.

At the exact mark of step *k*, only that marked state is admissible: the
driver waits for the mark to complete before sending the next mutation.
Strictly after that mark, the driver may have sent step *k+1*. The cut must
then match the
state after step *k* or the state after step *k+1* as a whole. A cut between
step *k+1*'s reply and its mark cannot be told apart from one before the reply,
so it is judged this way too; the mark is the earliest point the log can name.
Two allowances apply to that one unacknowledged step, and to nothing
acknowledged:

- File bytes and size it rewrites follow the stale-data rule below. Data pages,
  the on-disk size and a truncated tail are separate device writes and a write
  is never promised to be atomic, so a page-granular mix of acknowledged and
  in-flight bytes conforms. Its own mtime is unchecked, because a write moves
  it.
- An object it creates may carry a mode other than the requested one. The
  authority creates the object and applies the exact mode in a second
  transaction.

Namespace changes are not relaxed: each is one XFS transaction, so a
half-applied RENAME or LINK fails the cut even though no reply was sent.

The fixed workload has 30 acknowledged steps, including item-backed chmod to
mode 000 and timestamps on that file, MKDIR mode 0300 and timestamps on that
unreadable directory, and explicit symlink timestamps. The authority and driver
run as the unprivileged volume identity. Recovery verification runs as root on
the replayed image so it can inspect those objects without changing permissions.
It samples metadata for every candidate path before any file read, readlink or
directory enumeration; both interpretations of an in-flight cut use that same
sample. Only explicitly promised timestamps are asserted.


### Exactly what is asserted about bytes nothing promised

Workload content comes from `GenerateContent`, which never produces a zero
byte, so a zero always means "never landed" and can never hide a lost byte.

- Linux (`RequirePermitted`): a checkpoint file is written once and never
  rewritten, so whatever recovery leaves of an un-fsynced one must be bytes the
  workload wrote at those offsets, or zeros. Absent, empty, partial and complete
  all conform.
- FSKit (`permittedInFlightContent`): the size lies between the two states'
  sizes, and every byte is the acknowledged byte, the in-flight byte, or a zero
  at an offset where one of the two states has no byte.

Any other byte is stale data from a freed extent or a lost acknowledged byte,
and fails every cut. Both verifiers rebuild the expected bytes from the ledger;
a ledger whose content cannot be rebuilt is a failure, never a skipped check.

## The instruments

### Device instrument: dm-log-writes

`dm-log-writes` is stacked under the XFS the authority serves. It passes every
bio through to the target device and records it - with its flush and FUA flags,
in issue order - on a separate log device. Replaying that log onto a zeroed
image up to entry N reconstructs the platter state a power cut immediately after
the Nth bio would have left. Dirty page cache is not replayed, because a power
cut does not write it back.

Each run:

1. Stacks `dm-log-writes` over two loop-backed images, runs `mkfs.xfs` through
   it, and mounts the cell. Everything from mkfs onwards is in the log, so a
   replay onto zeros reproduces the whole device.
2. Provisions the volume with the shipped `scripts/provision-xfs-volume.sh`.
3. Starts the real `portablefs-authority` as the unprivileged volume identity,
   with its durable mount membership in the provisioner's private control
   directory (`--mount-membership-file .../mount.membership`), outside the
   volume root the verifier inspects.
4. Runs a workload driver as the same identity. After each durability claim
   the driver writes a mark request on stdout and blocks on the harness's
   answer on stdin (`MarkChannel`), so every mark lands after its claim and
   before the driver's next operation.
5. Releases every service-side holder of the cell: for the Linux workload,
   SIGKILL and reap the authority, SIGKILL and reap the mount server, then
   force-detach its FUSE mount and prove that exact kernel mount absent; for
   the FSKit workload, SIGKILL and reap the authority, which is the only holder.
   Only then does the harness take the `power-cut` mark, unmount XFS and release
   the device-mapper target. Everything the tidy-up unmount writes lands after
   that mark and is truncated away by `Log.Through`.
6. For each replay point - every ledger mark, a bounded sweep of the
   filesystem's own flush/FUA barriers spread across the whole log, and the cut
   itself - replays to a fresh image, mounts it (which runs XFS log recovery),
   checks that workload's contract, unmounts, and requires `xfs_repair -n` to
   find nothing it would correct.

Both halves of step 6 matter. Content that survives on a filesystem
`xfs_repair` would rebuild is not durable, and a clean `xfs_repair` over
content that vanished is not durable either.

#### Linux workload

`TestFsyncedWritesSurvivePowerLoss` mounts a real `portablefs-mount-v3` and
runs `pfs-powerloss-driver`. Each round writes one file, fsyncs it, fsyncs its
directory, and only then asks for a mark; then writes a second file it never
fsyncs, so every cut has an un-fsynced write in flight.

#### FSKit workload

`TestFSKitAcknowledgedMutationsSurvivePowerLoss` runs
`pfs-powerloss-fskit-driver`, which dials the authority with the
platform-neutral client exactly as `portablefsd` does: a MOUNT session attached
and activated with `FRONTEND_PROFILE_FSKIT_EXCLUSIVE`, an initial KeepAlive
before the first mutation, renewal at the daemon's cadence of
`min(lease / 3, 5 s, MaxCacheProof / 3)`, direct positioned WRITE with no
append, sync or delegation fields, CLOSE_BATCH instead of individual CLOSE, a
batched Reclaim, and an authenticated Detach whose mount-absence evidence is
true because the driver never installs a kernel mount. No daemon, extension or
kernel is in the path.

The driver accepts a reply as an acknowledgement only in its complete success
shape (no errno, uncertainty or failure class, and a recorded replay outcome),
compares the attributes the authority reported with the state it is about to
record, records the whole expected workload subtree, and then takes the mark.
The sequence is fixed:

| Step | Mutation | Barrier the authority declares |
| --- | --- | --- |
| 0-2 | MKDIR `fskit` and `fskit/docs` (0755), `fskit/archive` (0700) | `syncfs` |
| 3 | CREATE `docs/alpha` (read/write description) | handle `fsync` |
| 4-6 | WRITE alpha: extend from empty, overwrite in place, extend to an unaligned size | handle `fsync` |
| 7-8 | CREATE `docs/beta`, WRITE 16 KiB | handle `fsync` |
| 9 | SETATTR size through beta's handle | handle `fsync` |
| 10 | SETATTR size through alpha's item | `syncfs` |
| 11 | chmod alpha | `syncfs` |
| 12 | set alpha's atime and mtime explicitly | `syncfs` |
| 13 | LINK alpha as `archive/alpha-link` | `syncfs` |
| 14 | SYMLINK `docs/alpha-symlink` | `syncfs` |
| 15-16 | RENAME beta within `docs`, then into `archive` | `syncfs` |
| 17-18 | CREATE `archive/gamma`, WRITE leaving a hole at its start | handle `fsync` |
| 19 | RENAME gamma over `archive/beta`, replacing it | `syncfs` |
| 20-21 | UNLINK `docs/alpha` (alpha keeps its other name), UNLINK the symlink | `syncfs` |
| 22-23 | MKDIR then remove `docs/scratch` | `syncfs` |

The harness observes survival, not which syscall the authority ran. Barrier
selection, and fencing after a failed `fsync` or `syncfs`, are for the
authority's own tests to prove.

### Process instrument: SIGKILL and restart

`TestAuthorityKillDuringWritesKeepsFsyncedData` injects only an authority
SIGKILL. That removes the process but not the kernel's dirty page cache, so it
is **not** a power-loss test and does not stand in for one; process kill and
network interruption are never power-loss evidence. It covers what the device
instruments do not reach: that the authority restarts over a volume it was
killed in the middle of writing, that a fresh mount attaches, that the volume
serves again, and that nothing an `fsync` had already promised was lost. The
kill lands at a different point in each round, at fixed delays - a harness
whose coverage changes between runs cannot say what a green result covered.

Each round reaps the killed round's mount process, detaches its FUSE mount and
proves it absent, and only then starts the replacement authority with
`--prior-strict-mounts-fenced`. That audited operator assertion clears the
killed session's durable membership record, so the replacement owes it no
prior-cache wait. Without the assertion the authority is stricter: a
replacement that finds prior Linux membership grants no writer delegation and
applies no conflicting mutation for a full subscription horizon (10 s), and one
that finds prior FSKit-exclusive membership refuses foreign writers for 61.06 s
after safe takeover and refuses Mac activation until an operator reconciles it. This
instrument exercises neither unfenced path and asserts no restart timing. The
fresh liveness-probe mount then shuts down normally while the replacement is
alive, so its Detach leaves no membership behind.

In practice an un-fsynced write usually survives this instrument, because the
page cache does. The harness records that as an observation and never as a
requirement (`ExpectationsAfterRestart`).

## What this harness does not claim

- It does not test whether the physical block device honours its cache
  flushes. Loop files and `dm-log-writes` measure what the filesystem asked the
  device to do, not whether a disk lied about it.
- It does not cover multi-node durability. One authority, one XFS.
- It asserts nothing about a Linux write that was accepted but never fsynced,
  beyond the stale-data rule.
- It covers the authority's FSKit durability claim and nothing on the Mac side.
  What the daemon, the extension or the macOS kernel held and never delivered
  as a callback is outside the instrument; so are FSKit's own flush, fsync and
  unmount semantics. Completed deactivation and resource unloading certify
  local cleanup only; unmount's completion has no error or errno and supplies
  no durability verdict. Successful mutation replies still require authority
  durability, and synchronize still covers only its captured applied cut and
  propagates errors through its serving publication gate. Exact kernel absence
  and daemon/CLI reconciliation require independent evidence. Native
  fsync/F_FULLFSYNC waiting and dirty-page drain remain separate
  [qualification gates](./fskit-mount.md#verification).
- It makes no crash claim for restore hydration's mtime restoration, which is
  not crash-atomic and is not in either workload.
- It makes no per-volume isolation claim for `syncfs`. Every project on one XFS
  cell shares one superblock writeback-error and latency domain: another
  project's dirty data can lengthen an FSKit callback's barrier, and another
  project's writeback error can surface at it.
- It does not restart the authority on a replayed image. Each cut is judged by
  mounting XFS directly; restart and membership behaviour after a real power
  loss is not exercised.
- It does not inject I/O errors. EIO, ENOSPC and EDQUOT at the
  `fsync`/`syncfs` boundary, and the sticky fence that follows, belong to the
  authority's own XFS tests.

## Where the pieces live

| Path | What it is |
| --- | --- |
| `vcs/test/powerloss/logwrites.go` | dm-log-writes log parser and replayer, portable, unit tested anywhere |
| `vcs/test/powerloss/markchannel.go` | the driver half of the mark protocol both workload drivers use |
| `vcs/test/powerloss/ledger.go`, `verify.go` | the Linux fsync ledger and its per-cut contract |
| `vcs/test/powerloss/mutations.go`, `mutations_verify.go` | the FSKit acknowledged-mutation ledger and its per-cut contract |
| `vcs/test/powerloss/points.go` | replay-point selection: every ledger mark, a bounded barrier sweep |
| `vcs/test/powerloss/device_linux.go` | loop, device-mapper, mount and `xfs_repair` orchestration |
| `vcs/test/powerloss/engine_linux_test.go` | harness self-calibration, the kernel-level control, and the shared per-cut replay loop |
| `vcs/test/powerloss/authority_linux_test.go` | the three product-level instruments |
| `vcs/test/powerloss/cmd/pfs-powerloss-driver` | the Linux fsync workload, run as the volume identity |
| `vcs/test/powerloss/cmd/pfs-powerloss-fskit-driver` | the FSKit acknowledged-mutation workload, run as the volume identity |
| `scripts/run-powerloss.sh` | the entrypoint CI calls |
| `.github/workflows/powerloss.yml` | PRs, weekly and on demand; required again before release publication |

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
| `PORTABLEFS_POWERLOSS_BIN_DIR` | the authority, mount and both driver binaries built from this tree |
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
the authority, the mount and both workload drivers are spawned with the
service identity's credentials, never as root.

On top of the Go gates, `scripts/run-powerloss.sh` greps the run for the exact
test names that had to execute and fails the job if any is missing, and fails on
any `--- SKIP` at all, since `REQUIRED=1` should have made one impossible.

## What runs where

| | Any machine | Privileged Docker with `dm-log-writes` | GitHub-hosted `ubuntu-24.04` runner |
| --- | --- | --- | --- |
| Log parsing, replay, point selection, both ledgers and verifiers, both drivers' protocol and workload model | yes | yes | yes |
| `TestReplayReproducesTheDeviceTheKernelWrote` | no | yes | yes |
| `TestXFSHonoursFsyncAtEveryCut` | no | yes | yes |
| `TestFsyncedWritesSurvivePowerLoss` | no | needs host stock FUSE 7.31+ | yes |
| `TestFSKitAcknowledgedMutationsSurvivePowerLoss` | no | yes; no FUSE in the path | yes |
| `TestAuthorityKillDuringWritesKeepsFsyncedData` | no | needs host stock FUSE 7.31+ | yes |

The CI job uses `ubuntu-24.04`. It checks the running kernel's
`CONFIG_DM_LOG_WRITES`, loads `dm-log-writes`, and requires the `log-writes`
target before starting. A missing module or target fails the job. Each hosted
job has its own VM and device-mapper namespace; runs never cancel an active
harness during teardown.

The workflow runs on every pull request, weekly, and on demand. The release
workflow calls the same job on the exact tagged commit, and publication depends
on its success. PR results do not substitute for that tag's run.

`dm-log-writes` is available in privileged Docker provided the host kernel has
`CONFIG_DM_LOG_WRITES` and `/lib/modules` is bind-mounted so `modprobe` can
load it. The entrypoint does both.

### Status for protocol 8

None of the privileged tests above has run against the protocol-8 tree. The
FSKit instrument has never run anywhere: its driver and the authority it drives
must first build on Linux from the integrated tree. Until a run of
`scripts/run-powerloss.sh` passes every required test, the FSKit durability
contract is a stated design property, not power-loss evidence.

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
