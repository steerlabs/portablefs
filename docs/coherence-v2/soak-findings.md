# Protocol 7 real-workload soak

Workstream S tests snapshot `68fd4cff3d1fc05ab06f2a57e6d1f15d7c3c560b` on
`cv2-soak`. Product code is unchanged. The harness lives in `vcs/test/soak`;
one new, gated manager-level reproduction lives under `vcs/internal/fusev3`.
These findings apply to this snapshot, not the concurrent optimization worktree.

The suite uses a real in-process Authority, mutually authenticated TLS, two
stock kernel FUSE mounts and a project-quota XFS tree. Docker runs one soak
container at a time with a 2 GiB memory limit and two CPUs. The VM has four CPUs
and 8 GiB and hosts unrelated services. Timing is not an isolated benchmark.
Each destructive case runs in its own process so a deadlock cannot suppress
later cases. Timeout containment captures goroutines before aborting only
FUSE connections created by that process.

Run the complete workload selection:

```sh
PORTABLEFS_SOAK_TEST=1 \
PORTABLEFS_PROFILE_DIR=/tmp/portablefs-soak \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestSoak' \
bash scripts/xfs-fuse-integration.sh
```

The script installs Node/npm only in soak mode. The real npm fixture contains a
447-entry lockfile, including platform-optional dependencies; npm installs the
platform's applicable subset. It seeds a separate local cache, hashes that
independent install, then runs `npm ci --offline` on A. Every file, directory,
and symlink must match the seed through A, B, and Authority XFS. The additional
20,000-file/3,000-directory tree exercises hard links and explicit
close-before-open publication; it is supplementary coverage, not an assertion
that registry access was unavailable.

## Findings

### S1: epoch replacement cannot interrupt a pending close's durability wait

The two-mount epoch test times out during cold reattachment. B's close worker
holds the epoch read lock while waiting for an old write to become durable;
`EpochChanged` waits for the epoch write lock before dropping those old records.
Neither can finish. The mount never reaches the point where fresh opens and a
fresh run barrier can succeed. This reproduces in both real-mount runs 2 and 4.

`TestSoakEpochChangeUnblocksPendingClose` reduces the cycle to one 19-byte
applied-but-undurable record, one close, and one epoch replacement. It fails in
all three repetitions, then explicitly cancels the close only to contain the
test. The reduction uses a controlled RPC result; the originating soak uses
real XFS, Authority transport and mounts.

```sh
# Linux, no mount needed for the deterministic reduction:
PORTABLEFS_SOAK_TEST=1 go -C vcs test ./internal/fusev3 \
  -run '^TestSoakEpochChangeUnblocksPendingClose$' -count=3 -v

# Real-mount reproduction:
PORTABLEFS_SOAK_TEST=1 PORTABLEFS_PROFILE_DIR=/tmp/soak-epoch \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestSoakFaults$/^authority-new-epoch$' \
bash scripts/xfs-fuse-integration.sh
```

The lock cycle is visible at `vcs/internal/fusev3/delegation_linux.go:1778`
(background close uses the mount lifetime), `:1798` (epoch read lock), `:1892`
(durability wait), and `:1957` (epoch write lock). Fencing admission wakes
capacity waiters but does not cancel the close's durability wait. No product fix
was attempted.

### S2: CONTROL horizon under churn aborts the mount

Cut B's CONTROL socket while B repeatedly creates, renames, reads, lists and
unlinks its own files. A replaces a file held open by B. At the horizon the
cold B lookup returns `ECONNABORTED`, rather than scoped `EIO`, and subsequent
FUSE replies fail with `ENOTCONN`. The Authority log records a definite RECLAIM
EIO immediately before the abort. This is not a DATA-socket partition.

```sh
PORTABLEFS_SOAK_TEST=1 PORTABLEFS_PROFILE_DIR=/tmp/soak-control \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestSoakFaults$/^control-horizon$' \
bash scripts/xfs-fuse-integration.sh
```

Run 5 confirms terminal withdrawal after a CLOSE refusal with
`FAILURE_CLASS_COHERENCE`. The callback reports "authority refused open-file
close of a frontend-owned resource". The cut lasts the full 15 seconds; service
still has not recovered 20 seconds after healing.

The cleanup path at `vcs/internal/fusev3/fuse_linux.go:825` also handles RECLAIM
refusals through `cleanupFailed`, which unconditionally revokes the mount at `:852`.
Authority RECLAIM runs through ordinary mutation admission at
`vcs/internal/authorityrpc/volume_handler_linux.go:1934`. The evidence implicates
cleanup during subscription expiry. The refusal is coherence admission, not
a transport uncertainty; the exact server-side admission decision needs
further tracing.

### S3: dirty unmount can wait indefinitely before its bounded drain

Accept a write, hold its flush before transport assignment, close user file and
root descriptors, stop the Authority, then unmount. The API does not return
within 90 seconds and emits no required loss report. This is not an open-file
`EBUSY` case: the harness closes its retained descriptors before unmount.

```sh
PORTABLEFS_SOAK_TEST=1 PORTABLEFS_PROFILE_DIR=/tmp/soak-unmount \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestSoakFaults$/^dirty-unmount$' \
bash scripts/xfs-fuse-integration.sh
```

The captured stack stops in `FenceAdmissions` at
`vcs/internal/fusev3/delegation_linux.go:1361`, before
`vcs/internal/fusev3/fuse_linux.go:1127` creates the shutdown timeout. A queued
subscription fence waits for the epoch writer while the async close retains
an epoch reader. The injected slow flush observes cancellation; shutdown never
reaches the cancellation that would release it. This shares the epoch-lock
boundary with S1, with a different externally visible failure.

### S4: exclusive lock creation returns EIO under two-mount contention

Both mounts attempt `O_CREAT|O_EXCL` on `.git/index.lock`. Exactly one should win
and the other should receive EEXIST. The winner writes, closes and renames the
lock over `.git/index`; both mounts verify the published bytes before the next
race. Run 4 fails at race 7 with an Authority CREATE EIO, while both initial
transport sessions still report live. Run 5 independently fails at race 75
with `FAILURE_CLASS_COHERENCE` and `uncertain=false`.

```sh
PORTABLEFS_SOAK_TEST=1 PORTABLEFS_PROFILE_DIR=/tmp/soak-lock \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestSoakGitLock$' \
bash scripts/xfs-fuse-integration.sh
```

The reproduction is 100 repetitions of that small protocol in
`vcs/test/soak/gitlock_linux_test.go`. Investigate the existing-identity CREATE
preflight in `vcs/internal/authorityrpc/coherence_mutation_linux.go:118` and
delegation retirement under repeated index replacement. The captured EIO is
pre-apply (`uncertain=false`); the precise refusal has not yet been localized.

### S5: close/reopen/truncate traffic exposes a durability-latency cliff

This is a performance observation, not a proven deadlock. Initial alias,
synthetic-package and Git runs exhausted test-wide budgets while snapshots
showed `waitDurable`. A focused rewrite probe disproved the stronger hang
hypothesis: at its 60-second snapshot the Authority had processed 79 barriers,
7,695 creates and 7,704 writes, with continuing peer opens and reads. No
individual operation exceeded the probe's 15-second bound. Asking for 1,000
iterations within 90 seconds was an invalid harness budget.

The peer repeatedly opens the same heartbeat with `O_TRUNC`, writes, closes,
stats and reads it. `vcs/internal/fusev3/fuse_linux.go:1544` routes delegated
truncate through `Synchronous`; `delegation_linux.go:1079` waits for the prior
cut's durability. That can serialize the loop on fallback durability cadence
(`delegation_linux.go:761`). A `waitDurable` stack alone does not show a lost
watermark or an Authority deadlock.

`TestSoakReproRewriteReadLoop` now measures 30 iterations with per-operation
bounds and latency quantiles. The synthetic package observer keeps its own
heartbeat descriptor open so this unrelated latency does not throttle package
publication; it still continuously reads, stats and lists the package tree.
The seeded alias probe retains 200 cycles with a five-minute budget. Git has a
20-minute budget, path-limited real commits, and progress every 25 commits.
The complete 200-commit/5,000-file workload remains required.

```sh
PORTABLEFS_SOAK_TEST=1 PORTABLEFS_PROFILE_DIR=/tmp/soak-rewrite \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestSoakReproRewriteReadLoop$' \
bash scripts/xfs-fuse-integration.sh
```

## Validation and limits

The default `scripts/verify-local.sh` passed after one pre-existing native test
flake. The initial `SurfacesHydratorCorruptionAsErrCorrupt` run received a refused
Unix connection instead of ErrCorrupt. Twenty focused repeats, twenty full
interop repeats, and twenty full-package repeats did not reproduce it. The test
can hide the server's exit error at `vcs/internal/restoremode/interop_test.go:413`;
this is a test-lifecycle hypothesis, not a confirmed corruption-classification
bug. Full privileged product qualification was not run by this test-only
workstream; the soak selection is not that gate.

The first Git attempt let B's `git status` refresh the shared index and correctly
hit an index.lock conflict. That is normal Git writer contention, not S4. The
observer now uses `GIT_OPTIONAL_LOCKS=0`; S4 separately asserts the exclusive
lock winner. An early recursive observer also throttled synthetic installation;
that rejected measurement and its manually aborted run are not product findings.

Fault probes overlap reduced syscall workloads. A fault preventing recovery
blocks qualification of a complete install/Git/compiler run across that fault.
No successful full-workload restart or dirty-unmount durability guarantee is
claimed while S1-S3 remain reproducible.
