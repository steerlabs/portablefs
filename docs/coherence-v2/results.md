# Protocol 7 integration measurements

The v6 reference is [baseline.md](./baseline.md). These are local engineering
observations, not an SLO or an isolated speedup experiment. Both runs use the
4 CPU, 8 GiB Docker VM, kernel `6.8.0-100-generic`, the digest-pinned Go image,
loopback TLS, real kernel FUSE, and a 1 GiB loop-backed XFS image on tmpfs with
a 512 MiB / 200,000-inode project quota. Unrelated containers share the VM.
Neither run measures physical-disk throughput or a production network.

The workload sizes and denominators are unchanged: 40,000 1 KiB files plus
2,000 directories (42,000 operations) at one and eight workers; cold and warm
Git status over 20,000 tracked files; and 2,000 peer writes plus verified reads
(4,000 operations). Cold PortableFS Git recreates the Authority and mount;
cold direct XFS evicts clean file pages but retains inode/dentry caches.

Protocol 7 setup also runs the formerly failing fresh 20,000-file `git add` at
the shipping 65,536 cached-name capacity. It checks the index count, commits,
passes a root-handle barrier opened before setup, and checks the original mount
is still live. The v6 result needed 4,096 during setup before remounting at
65,536. Protocol 7 makes any enumeration error fatal; it does not retry ESTALE.

A root barrier is opened before each measured mounted phase and fsynced after
it. Workload wall time preserves the v6 POSIX boundary. Barrier latency and
asynchronous CLOSE drain are reported separately; requests include both,
including the extra barrier and root CLOSE, while the root OPEN is outside the
meter. The barrier validates accepted-write loss and durability. Direct-XFS
rows retain the original workload timing and do not imply per-file fsync.
Request counts belong to the fixture handler, so unrelated containers affect
timing but do not enter these counts.

## Reproduction

Unprofiled full-size measurements:

```sh
PORTABLEFS_PERFORMANCE_TEST=1 \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestCoherenceBaseline$' \
bash scripts/xfs-fuse-integration.sh
```

Optional profiles are exported to an explicit host artifact directory:

```sh
PORTABLEFS_PROFILE_DIR=/tmp/portablefs-profiles \
PORTABLEFS_PERFORMANCE_TEST=1 \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestCoherenceBaseline$/(install-portablefs-workers-[18]|git-portablefs)$' \
bash scripts/xfs-fuse-integration.sh
```

The Authority and mount daemon live in one Go test process. CPU profiles label
inherited workers as `component=authority` or `component=frontend`; allocation
profiles use package/function stack filters. Every phase exports CPU, allocation
before/after, mutex, and block profiles plus the exact test executable. CPU and
allocation snapshots cover completion/drain as well as the syscall workload.
Mutex/block snapshots are cumulative process observations. Profiled timings are
kept separate because instrumentation changes scheduling and allocation cost.
The focused wrapper exits 70 for omitted required-suite inventory after a
passing benchmark; that is not a full verification result.

## Before profiling

Run 122 passes every workload in 118.44 seconds. The complete observations are
in [results-before.jsonl](./results-before.jsonl). The wrapper exits 70 only for
unrun inventory. The fresh 20,000-file Git regression passes again after the
Linux/Mac bridge deletion.

| Workload | Target | Workers | Wall (s) | Authority requests | Requests/op | Filesystem requests | Filesystem requests/op | Barrier (s) | Close drain (s) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| install | direct-xfs | 1 | 0.602526 | 0 | 0.000000 | 0 | 0.000000 | 0.000000 | 0.000000 |
| install | direct-xfs | 8 | 0.355244 | 0 | 0.000000 | 0 | 0.000000 | 0.000000 | 0.000000 |
| install | portablefs | 1 | 23.364615 | 329,873 | 7.854119 | 206,005 | 4.904881 | 0.002893 | 0.003370 |
| install | portablefs | 8 | 12.855778 | 274,845 | 6.543929 | 206,238 | 4.910429 | 0.114971 | 0.147401 |
| git-status-cold | direct-xfs | - | 0.008836 | 0 | 0.000000 | 0 | 0.000000 | 0.000000 | 0.000000 |
| git-status-warm | direct-xfs | - | 0.008893 | 0 | 0.000000 | 0 | 0.000000 | 0.000000 | 0.000000 |
| git-status-cold | portablefs | - | 1.589802 | 20,566 | 1.028300 | 20,540 | 1.027000 | 0.000140 | 0.011691 |
| git-status-warm | portablefs | - | 1.105835 | 372 | 0.018600 | 364 | 0.018200 | 0.000194 | 0.011495 |
| two-mount-write-list-read | direct-xfs | - | 0.029348 | 0 | 0.000000 | 0 | 0.000000 | 0.000000 | 0.000000 |
| two-mount-write-list-read | portablefs | - | 2.114936 | 40,304 | 10.076000 | 21,433 | 5.358250 | 0.000095 | 0.001153 |

The initial mounted peer run performs nine scans, no enumeration retries, and
verifies 1,405 files before the writer finishes. Direct XFS performs seven scans
and verifies 1,363 files during the write. The protocol-7 request count is higher
than v6 for this peer run; control cuts, barrier frequency, and the amount of
reader/writer overlap differ. Faster wall time does not imply fewer requests.

## Profiling and changes

The before profiles are runs 125 (install) and 126 (Git), executable build ID
`7c4bd6de75baa58c0a45da7abc6dd68b606d1908`. The final profiles are run 145,
`622cffd29e1c89ccea559db8322d571652420f85`. They are retained locally in
`/tmp/cv2-g-profiles-pre` and `/tmp/cv2-g-profiles-complete`. Example analysis:

```sh
go tool pprof -top -tagfocus=component=authority \
  /tmp/cv2-g-profiles-complete/fusev3.test \
  /tmp/cv2-g-profiles-complete/TestCoherenceBaseline-install-portablefs-workers-8-install.cpu.pprof
go tool pprof -top -tagfocus=component=frontend \
  /tmp/cv2-g-profiles-complete/fusev3.test \
  /tmp/cv2-g-profiles-complete/TestCoherenceBaseline-git-portablefs-cold.cpu.pprof
go tool pprof -top -alloc_space \
  -base /tmp/cv2-g-profiles-complete/TestCoherenceBaseline-install-portablefs-workers-8-install.allocs-before.pprof \
  /tmp/cv2-g-profiles-complete/fusev3.test \
  /tmp/cv2-g-profiles-complete/TestCoherenceBaseline-install-portablefs-workers-8-install.allocs-after.pprof
```

Allocation numbers below are sampled `alloc_space` deltas in MiB. They include
both components, runtime sampling variance, and allocation-profile GC-cycle
lag. They are not live-heap size or a deterministic allocation count. Mutex
numbers are cumulative sampled aggregate waiter-seconds at the end of the
8-worker phase, including the earlier 1-worker phase; they are neither wall
time nor seconds spent holding a lock.

| Observation | Before | Final |
|---|---:|---:|
| 8-worker install sampled allocation | 4,434.79 MiB | 3,774.31 MiB |
| Cold Git status sampled allocation | 577.07 MiB | 518.83 MiB |
| Canonical present-field slice, install flat allocation | 212.18 MiB | no samples after descriptor caching |
| Source signal channels, install flat allocation | 144.52 MiB | no samples after demand allocation |
| Coordinator Poll event-slice growth, install flat allocation | 230.86 MiB | no samples after bounded batch reuse |
| Install cumulative mutex wait | 390.47 s | 11.33 s |

The Authority and frontend CPU views are both dominated by syscalls, runtime
allocation/clearing, and timing. Before changes, the 8-worker CPU sample total
was 21.03 seconds over 14.96 seconds elapsed; final is 22.19 over 15.22. This
is not a CPU-speedup result. The first warm Git profile is only 900 ms of CPU
samples, too small for fine-grained ranking. Kernel `syncfs` wait is not sampled
CPU and is not reliably represented by Go block profiles.

The changes address measured costs without changing the wire:

- Canonical encoding caches immutable descriptor order, checking message
  presence and unknown fields each time. Frozen encoding, presence changes,
  and unknown nested fields are tested. The small-write microbenchmark is
  1,208 ns/op, 72 B/op, 3 allocations/op on the native M5 Max; that is not a
  Linux/VM throughput measurement.
- CONTROL reuses a session batch only after all queued entries drain. A new
  poll cannot mutate a returned response or its exact replay. Storage is bounded
  by 4,096 events and is cleared before waiting. Tests include split frames and
  old-response retention across reuse.
- Source-publication wake channels exist only while needed by waiters, with
  predicate checks and signaling under the same mutex. Source admission still
  checks only request coordinates; its unrelated-coordinate benchmark covers
  4,096 other entries. No per-operation global cache scan was found there.
- A timer/cap flush no longer launches one goroutine per dirty identity. One
  background worker matches the Authority's single delegated-flush lane and
  leaves ordinary client permits available to explicit flushes. Explicit
  fsync, recall, and close remain independent. The native burst benchmark is
  7.76 microseconds for 32 files and 1.946 milliseconds for 4,096 files; it
  uses a fake durable flusher and does not measure network or storage.
- Close batches apply all their files before waiting for durability, then
  release ownership and server handles. A 256-pending-close admission budget
  prevents the measured install from outrunning deferred cleanup. The budget
  assumes the unchanged shipping open-table limits; smaller custom Authority
  limits are not negotiated and can still return ENFILE.

Run 140 found ENFILE after file 6,597 when bounded background dispatch exposed
serialized per-file close barriers. It is a failed run, not omitted noise.
The blocked-durability and deferred-close regressions cover the fix; run 145
then passes both install sizes, fresh Git setup, both status phases, and the
focused delegation tests. The profile wrapper exits 70 for omitted inventory.

An intermediate allocation-only run is preserved in
[results-after-allocations.jsonl](results-after-allocations.jsonl), and profiles
from that stage reduced allocation further in some samples. It is not the final
result: the final scheduler prioritizes bounded work and recall headroom.
Per-file close/barrier timing still changes the number of coalesced durability
RPCs. Profiled final install takes 19.720 seconds (one worker) and 15.198 seconds
(eight), with 22,951 and 23,411 Barrier requests respectively; cold/warm Git take
1.309/1.256 seconds. The final unprofiled table below is the comparison to v6.

Remaining measured costs include defensive protobuf/replay objects, callback
lifetime objects, timers, and exact cache reservations. Their ownership spans
asynchronous replies, so indiscriminate pooling would violate replay or
publication lifetime. Background scheduling scans the bounded active buffer
at a timer/cap event, not on each accepted write. Namespace and cold pathname
lookups still require Authority requests. This work does not claim local-disk
latency or fewer requests for every workload.

## Final unprofiled comparison

Run 150 passes the entire baseline in 112.96 seconds. The wrapper exits 70
only because the focused invocation omits the required full-suite inventory.
[results-final.jsonl](results-final.jsonl) contains every observation and the
filesystem/control request breakdown. Each paired cell is **v6 → final v7**;
barrier time is new v7 evidence and is not included in syscall wall time.

| Workload | Target | Workers | Wall (s), v6 → v7 | Authority requests, v6 → v7 | Requests/op, v6 → v7 | Filesystem requests, v6 → v7 | Filesystem requests/op, v6 → v7 | Close drain (s), v6 → v7 | v7 barrier (s) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| install | direct-xfs | 1 | 0.578806 → 0.392895 | 0 → 0 | 0.000000 → 0.000000 | 0 → 0 | 0.000000 → 0.000000 | 0.000000 → 0.000000 | 0.000000 |
| install | direct-xfs | 8 | 0.344368 → 0.299482 | 0 → 0 | 0.000000 → 0.000000 | 0 → 0 | 0.000000 → 0.000000 | 0.000000 → 0.000000 | 0.000000 |
| install | portablefs | 1 | 386.762771 → 21.028568 | 329,884 → 314,182 | 7.854381 → 7.480524 | 210,201 → 206,005 | 5.004786 → 4.904881 | 0.001376 → 0.013845 | 0.000934 |
| install | portablefs | 8 | 273.738199 → 15.706301 | 317,582 → 287,680 | 7.561476 → 6.849524 | 208,079 → 206,229 | 4.954262 → 4.910214 | 0.002229 → 0.020364 | 0.005549 |
| git-status-cold | direct-xfs | - | 0.037750 → 0.007525 | 0 → 0 | 0.000000 → 0.000000 | 0 → 0 | 0.000000 → 0.000000 | 0.000000 → 0.000000 | 0.000000 |
| git-status-warm | direct-xfs | - | 0.021925 → 0.007188 | 0 → 0 | 0.000000 → 0.000000 | 0 → 0 | 0.000000 → 0.000000 | 0.000000 → 0.000000 | 0.000000 |
| git-status-cold | portablefs | - | 10.572948 → 1.379696 | 20,809 → 20,548 | 1.040450 → 1.027400 | 20,525 → 20,531 | 1.026250 → 1.026550 | 0.000003 → 0.010518 | 0.000200 |
| git-status-warm | portablefs | - | 2.042038 → 1.195970 | 553 → 372 | 0.027650 → 0.018600 | 363 → 364 | 0.018150 → 0.018200 | 0.000004 → 0.011706 | 0.000209 |
| two-mount-write-list-read | direct-xfs | - | 0.063784 → 0.036116 | 0 → 0 | 0.000000 → 0.000000 | 0 → 0 | 0.000000 → 0.000000 | 0.000000 → 0.000000 | 0.000000 |
| two-mount-write-list-read | portablefs | - | 12.536042 → 2.644504 | 31,510 → 39,278 | 7.877500 → 9.819500 | 22,680 → 20,317 | 5.670000 → 5.079250 | 0.001131 → 0.001261 | 0.000229 |

The final peer run performs three scans, no ESTALE/incomplete/vanished retries,
and verifies one file before the writer completes. It verifies all 2,000 files
overall. Direct XFS performs seven scans and verifies 1,672 files during writes.
The first v7 run had substantially more overlap (1,405 files), and the v6
reference had 467. Scheduling and the amount of overlap differ materially;
these peer wall times are observations, not an isolated protocol speedup. The
separate churn and concurrent-writer tests retain their stronger overlap checks.

Final versus initial v7 is mixed: one-worker install is 23.365 → 21.029 seconds,
eight-worker install 12.856 → 15.706, cold status 1.590 → 1.380, warm status
1.106 → 1.196, and peer workload 2.115 → 2.645. The final implementation spends
less sampled allocation and avoids the background lock stampede, but dispatch
and barrier coalescing change. No claim is made that every optimization improved
every wall time. Direct-XFS timings also changed on this shared VM.

Fresh Git preparation again logs `files=20000 cached_name_capacity=65536
committed=true barrier=PASS mount=LIVE`. No setup-capacity workaround or
ESTALE retry remains. This reproduces the exact shipping-capacity scenario
that failed with ENOTCONN on v6 and proves completion on the final v7 build.

## G2 cached metadata, intermediate

The amended F10 keeps Authority-backed Linux entry and attribute validity at
zero. Deterministic callback tests, including PrepareReplyPayload and
ReplyWritten, measured the following allocations per warm call. Authority RPCs
are zero for every row.

| Cached operation | Before allocations/call | After allocations/call |
|---|---:|---:|
| positive LOOKUP | 22 | 0 |
| negative LOOKUP | 9 | 0 |
| GETATTR | 18 | 0 |

The initial mounted check (`/tmp/cv2-g2-cache-mounted3.log`) reports 2,000 warm
`Lstat` operations at 70.042 us median and 81.167 us p95, with zero Authority
LOOKUP or GETATTR RPCs. This is whole-syscall latency, not an isolated FUSE
LOOKUP callback. A separate warmed-absence CREATE issues zero LOOKUP RPCs.
An arbitrary unseen name still needs an Authority fact; this result does not
claim that a daemon can infer absence without a cached negative or a complete
directory snapshot. The below-20-us kernel round-trip target is not established
by this full-stat result. Workload measurements follow after the next changes.

The isolated opcode probe (`/tmp/cv2-g2-cache-mounted7.log`) confirms 2,000
cached FUSE LOOKUPs and zero Authority LOOKUPs. LOOKUP service from reading
`/dev/fuse` through writing its reply is 4.417 us median / 5.708 us p95. This
excludes kernel scheduling before the daemon read. The enclosing `faccessat`
syscall costs 70.125 us median / 79.958 us p95 and also issues 4,000 permission
GETATTRs because attribute validity is zero. These boundaries are reported
separately; dividing syscall latency by its three requests would not prove a
single-request round trip. The repeated Lstat sample is 74.209 / 84.417 us.

## G2 first RPC reductions

Targeted Docker/XFS measurements precede the full baseline below. The 1,000-file
install includes an explicit root completion barrier; close drain still has its
old durability wait at this stage.

| Stage | Files | Seconds | Barrier/file | FLUSH/file | ChangeAck/file | Additional control polls/file |
|---|---:|---:|---:|---:|---:|---:|
| fallback Barrier cap (0a) | 1,000 | 5.36 | 0.007 | unmeasured | unmeasured | unmeasured |
| implicit source progress (0b) | 1,000 | 5.37 | 0.007 | unmeasured | 0 | 0 |
| local unlocked FULL FLUSH (1) | 1,000 | 5.26 | 0.007 | 0 | 0 | 0 |

With READDIRPLUS (2), a cold mounted `ls -ln` over 1,000 entries issues four
READDIR RPCs (0.004/entry) and zero LOOKUP RPCs. Its 0.57-second test duration
includes setup and teardown and is not a listing latency measurement. Source
logs: `/tmp/cv2-g2-durable-mounted2.log`, `/tmp/cv2-g2-own-mounted.log`,
`/tmp/cv2-g2-flush-mounted.log`, and `/tmp/cv2-g2-plus-mounted.log`.

### Baseline after items 0a, 0b, 1, 2, and amended 3/8

Measured commit `68fd4cf` on Linux `6.8.0-100-generic` with:

```sh
PORTABLEFS_PERFORMANCE_TEST=1 PORTABLEFS_GO_TEST_FLAGS='-run ^TestCoherenceBaseline$' PORTABLEFS_PROFILE_RUN=g2-after-1-3 bash scripts/xfs-fuse-integration.sh
```

The install and Git subtests completed; the overall run failed on a peer
READDIRPLUS EIO. This is intermediate measurement evidence, not a passing gate.
The exact output is `/tmp/cv2-g2-baseline-1-3.log`.

| Workload | Direct XFS seconds | PortableFS seconds | Authority requests | Requests/operation | Filesystem requests/operation |
|---|---:|---:|---:|---:|---:|
| Install, 40,000 files + 2,000 directories, 1 worker | 0.624 | 277.050 | 164,750 | 3.9226 | 3.9049 |
| Install, 40,000 files + 2,000 directories, 8 workers | 0.333 | 274.056 | 165,062 | 3.9300 | 3.9094 |
| Git status cold, 20,000 files | 0.00844 | 1.910 | 40,628 | 2.0314 | 1.0261 |
| Git status warm, 20,000 files | 0.00745 | 1.322 | 20,471 | 1.0236 | 0.0182 |

| Install opcode, 1 worker | Requests | Requests/file |
|---|---:|---:|
| CREATE | 40,000 | 1 |
| WRITE | 40,000 | 1 |
| LOOKUP | 42,000 | 1.05 |
| CLOSE | 40,002 | 1.00005 |
| MKDIR | 2,000 | 0.05 |
| OPEN / READDIR | 1 / 1 | 0.000025 each |
| Barrier | 274 | 0.00685 |
| DelegationRelease | 339 | 0.008475 |
| KeepAlive / RenewSubscription | 41 / 92 | 0.001025 / 0.0023 |
| FLUSH / ChangeAck / additional control polls | 0 / 0 / 0 | 0 |

Install time regressed sharply despite fewer requests: the retained close path
still waits for durability while the fallback Barrier now runs at most once per
second. Item 4 must remove that wait before claiming an install speedup. Cold Git
still does 20,140 LOOKUPs; warm Git does two, while both runs reclaim 20,105
capabilities. READDIRPLUS eliminates LOOKUPs for the cold `ls -ln` test but does
not eliminate cold Git's index-driven stat pass. The fresh 20,000-file git-add
regression passes at the shipping 65,536-name capacity and leaves the mount live.

### Applied release and batched close (item 4)

The mounted 1,000-file conformance workload falls from 5.26 seconds after item 1
to 0.69 and 0.64 seconds in two repeats. These are whole-test durations including
fixture setup/teardown, not isolated install timers. The final close collection
window is bounded at 25 milliseconds or 128 handles. The initial 10-millisecond
window measured 1.08 seconds and 69 batches and failed the new amortization
assertion; the final runs issue 19 and 16 batches. Logs:
`/tmp/cv2-g2-close-mounted.log`, `/tmp/cv2-g2-close-mounted2.log`.

| RPC per file, 1,000-file install | After item 1 | After item 4, repeats |
|---|---:|---:|
| Barrier | 0.007 | 0.002 / 0.002 |
| FLUSH | 0 | 0 / 0 |
| ChangeAck | 0 | 0 / 0 |
| Additional control poll | 0 | 0 / 0 |
| Serial CLOSE | unmeasured | 0 / 0 |
| CloseBatch | unavailable | 0.019 / 0.016 |

The full 40,000-file install and Git baseline will be rerun after the remaining
new-name LOOKUP optimization. These focused results do not replace it.

### New-name lookup elimination (item 0c)

The required mounted test creates 1,000 files beneath a newly created directory
with zero LOOKUP RPCs in both repetitions (`/tmp/cv2-g2-complete-mounted.log`).
This is 0 LOOKUP/file, compared with the 1.05 LOOKUP/file measured across the
40,000-file/2,000-directory baseline before completeness caching. The different
workload sizes are explicit; the full baseline below is the comparable result.
Unknown preexisting directories still require an Authority lookup.

### Baseline after items 0–4 (amended kernel-cache policy)

Measured `7ca2d25`, Linux `6.8.0-100-generic`, with
`PORTABLEFS_PERFORMANCE_TEST=1 PORTABLEFS_GO_TEST_FLAGS='-run ^TestCoherenceBaseline$' bash scripts/xfs-fuse-integration.sh`.
All baseline subtests passed in 182.20 seconds. The wrapper exits 70 because
this focused invocation omits the required full-gate inventory; it is not a
full gate pass. Log: `/tmp/cv2-g2-baseline-0-4-plain.log`. Another Docker soak
workload was active on the same VM. A preceding profile-enabled attempt failed
in the second direct-XFS install with ENOSPC before PortableFS ran; the unchanged
plain rerun passed. No cause is established and no profile was captured.

| Workload | Target | Seconds | Authority requests | Requests/operation | Filesystem requests/operation |
|---|---|---:|---:|---:|---:|
| install, 1 worker(s) | direct-xfs | 0.574807 | 0 | 0.000000 | 0.000000 |
| install, 8 worker(s) | direct-xfs | 0.429848 | 0 | 0.000000 | 0.000000 |
| install, 1 worker(s) | portablefs | 34.664636 | 84,043 | 2.001024 | 1.976143 |
| install, 8 worker(s) | portablefs | 15.408795 | 82,976 | 1.975619 | 1.964333 |
| git-status-cold | direct-xfs | 0.011487 | 0 | 0.000000 | 0.000000 |
| git-status-warm | direct-xfs | 0.011241 | 0 | 0.000000 | 0.000000 |
| git-status-cold | portablefs | 2.355368 | 40,628 | 2.031400 | 1.026050 |
| git-status-warm | portablefs | 1.667565 | 20,471 | 1.023550 | 0.018150 |
| two-mount-write-list-read | direct-xfs | 0.046432 | 0 | 0.000000 | 0.000000 |
| two-mount-write-list-read | portablefs | 5.722640 | 97,405 | 24.351250 | 3.154750 |

| Install opcode | 1 worker requests | Requests/file | 8 workers requests | Requests/file |
|---|---:|---:|---:|---:|
| barrier | 35 | 0.000875 | 16 | 0.000400 |
| change_ack | 0 | 0.000000 | 0 | 0.000000 |
| close | 2 | 0.000050 | 2 | 0.000050 |
| close_batch | 994 | 0.024850 | 313 | 0.007825 |
| create | 40,000 | 1.000000 | 40,000 | 1.000000 |
| delegation_release | 994 | 0.024850 | 313 | 0.007825 |
| flush | 0 | 0.000000 | 0 | 0.000000 |
| get_attr | 0 | 0.000000 | 47 | 0.001175 |
| keep_alive | 5 | 0.000125 | 2 | 0.000050 |
| lookup | 0 | 0.000000 | 138 | 0.003450 |
| mkdir | 2,000 | 0.050000 | 2,000 | 0.050000 |
| next_control_event | 0 | 0.000000 | 0 | 0.000000 |
| open | 1 | 0.000025 | 1 | 0.000025 |
| read_dir | 1 | 0.000025 | 1 | 0.000025 |
| reclaim | 0 | 0.000000 | 138 | 0.003450 |
| renew_subscription | 11 | 0.000275 | 5 | 0.000125 |
| write | 40,000 | 1.000000 | 40,000 | 1.000000 |

Compared with the preceding intermediate run, install time falls from
277.050 to 34.665 seconds (one worker) and 274.056 to 15.409 seconds (eight).
The one-worker path reaches one CREATE plus one background WRITE per file,
with directory creation and close/release batches amortized. The eight-worker
run retains 138 LOOKUPs and 47 GETATTRs. Cold Git still performs 20,140 LOOKUPs;
warm Git performs two. Both Git runs issue 20,105 RECLAIMs. The peer workload
now passes but still issues 73,709 RECLAIMs, 4,491 change ACKs and 5,467 control
polls; its request count remains an optimization target.

### Reader-aware write invalidation (item 5)

A deterministic 100-write daemon test compares the previous unconditional
path with the new never-cached-inode path: InodeNotify calls fall from 100 to
zero; the new invalidation fast path allocates zero objects per write. With a
previously closed cached reader, three disjoint writes produce zero immediate
notifications and one merged range at the flush/reopen boundary. Live-reader
writes retain a synchronous notify before successful return. These are operation
counts, not a new full-workload latency measurement.

### Targeted namespace withdrawal (item 6)

With a second mount's CONTROL transport partitioned and its cache confined to
an unrelated directory, a mounted MKDIR completes in 416.794 us. The previous
global wait includes that subscriber until ACK or its approximately 10-second
horizon; forcing the global target set fails the new regression. Related-parent
and newly created-directory completeness arms still block before withdrawal.
This is an isolated partition test, not a claim about ordinary two-mount
throughput. Log: `/tmp/cv2-g2-footprint-mounted.log`.

## G2 handoff durability follow-up

The unchanged 96-round repeated-open/peer-write regression took 99.89 seconds
in the full gate after item 6. Removing the recall durability wait alone left
100.49 seconds; removing the synchronous truncating-open wait as well produced
0.33 and 0.35 seconds on two focused mounted runs. Both paths retain applied
records until durability and detach their old read overlay before handoff.
The 20-second regression bound is unchanged. These are test wall times, not a
full baseline or an isolated VM experiment; request counts were not collected.
Logs: `/tmp/cv2-g2-after-item6-xfs2.log`, `/tmp/cv2-g2-recall-mounted.log`,
`/tmp/cv2-g2-recall-mounted2.log`. Full gates remain required.

## G2 FULL-holder metadata follow-up

The same 2,000-call mounted LOOKUP probe now exercises a shared cached file and
an open FULL holder with a dirty size extension. Both issue zero Authority
LOOKUP and GETATTR requests. Measurements from `/tmp/cv2-g2-holder-mounted.log`:

| Mode | Syscall p50 / p95, us | LOOKUP read-to-reply p50 / p95, us | FUSE permission GETATTRs |
| --- | ---: | ---: | ---: |
| Shared | 71.208 / 82.417 | 4.750 / 6.125 | 4,000 |
| FULL holder | 71.208 / 81.625 | 4.792 / 6.167 | 4,000 |

The syscall includes one LOOKUP and two permission GETATTRs. The daemon timer
starts after reading /dev/fuse and excludes prior kernel scheduling. Neither
number establishes an isolated kernel-to-daemon LOOKUP round trip below 20 us.
The callback allocation regression has a direct before/after result: holder
GETATTR was 13 allocations and is now zero; holder LOOKUP also has zero
allocations. These unit measurements include physical reply settlement.

## G2 READDIR page admission

`BenchmarkReadPageAdmission256`, Apple M5 Max host, three 300 ms samples
(`/tmp/cv2-g2-read-set-bench.log`):

| 256-identity coordinator admission | Time per page | Bytes per page | Allocations | Request turns |
| --- | ---: | ---: | ---: | ---: |
| Former per-entry loop | 64.4–65.4 us | 92,160–92,166 | 1,792 | 256 |
| Composite page guard | 19.0–19.2 us | 32,945 | 520 | 1 |

This isolates coordinator work with no foreign delegation. It excludes storage,
RPC and kernel time. The new guard also remains held through storage revalidation;
the former loop did not provide that exclusion.

## G2 CONTROL batch construction

Actual pre-change and updated handler binaries, Linux arm64 Docker VM,
`BenchmarkCoherenceBatchAssembly`, median of three single-iteration samples.
The VM is shared; these are local CPU-path observations, not latency guarantees.

| Entries | Former repeated prefix sizing | Running byte count |
| ---: | ---: | ---: |
| 64 | 63.208 us | 27.167 us |
| 256 | 489.961 us | 41.042 us |
| 1,024 | 6,949.290 us | 141.126 us |
| 4,096 | 109,887.755 us | 1,118.173 us |

Allocation counts are unchanged after descriptor warmup (278, 1,050, 4,128 and
16,424 per batch respectively). The improvement removes repeated prefix walks;
it does not change CONTROL wire bytes or event count. Logs:
`/tmp/cv2-g2-control-bench-before.log` and `control-bench-after.log`.

## G2 replay fingerprint accounting

The production request reader already hashes bulk bytes during ingress and
passes that digest into canonical metadata hashing (prior G commits `ad12b9c`
and `04cdfab`). No second payload walk remains to remove. Three 750 ms samples
on the Apple M5 Max host, median, `/tmp/cv2-g2-fingerprint-bench.log`:

| 1 MiB WRITE path | Time | Bytes allocated | Allocations |
| --- | ---: | ---: | ---: |
| Standalone fingerprint, including payload SHA-256 | 331.101 us | 520 | 9 |
| Production canonical fingerprint with ingress digest | 1.404 us | 520 | 9 |
| Retained frame read with ingress digest | 329.866 us | 1,105 | 14 |
| Retained frame read without digest | 13.787 us | 504–528 | 10 |
| Protobuf clone | 54.933 us | 1,048,873–1,048,874 | 5 |
| Protobuf marshal | 38.024 us | 1,056,792 | 2 |

These isolate CPU work over an in-memory frame. They are not end-to-end write
latencies or a new before/after implementation claim. Payload authentication
still costs CPU; metadata canonicalization is below one percent of the digesting
reader time. The existing digest-equivalence regression passes with these runs.

## G2 mutation queue scaling

Per-key claim queues replace the repeated global waiter scan. Actual before/after
host binaries, Apple M5 Max, median of three one-iteration contended samples:

| Pending mutations on one key | Former scan | Per-key queues |
| ---: | ---: | ---: |
| 64 | 106.333 us | 15.625 us |
| 256 | 1,679.000 us | 38.916 us |
| 1,024 | 26,856.750 us | 142.458 us |
| 4,096 | 435,402.708 us | 548.375 us |

At 4,096 waiters, retained claim bookkeeping increases this single-key case from
1,016,432 to 1,278,984 allocated bytes, and from 16,393 to 20,495 allocations.
For 256 waiters each reserving a common key plus its own distinct key, removing
repeated reservation-map construction reduces allocation from 5,755,139 to
122,162 bytes. The regression enforces a generous 524,288-byte linear budget.

The existing disjoint workload is unchanged: three 500 ms samples have median
3.731 us before and 3.741 us after for dependency keys, versus 67.990 and
68.108 us for its global-turn reference model. Short one-iteration warmups of
that benchmark were too noisy and are excluded. Logs:
`/tmp/cv2-g2-sequencer-before.log`, `sequencer-after.log`,
`disjoint-before.log`, `disjoint-after.log` (same prefix). These are coordinator
CPU measurements, not RPC or mounted-workload timings.

## G2 shared registry reads

`BenchmarkPhysicalReplyRegistryRead`, Linux arm64 shared Docker VM, four workers,
median of three 500 ms samples:

| Read-only reply tracking | Time per lookup | Allocations |
| --- | ---: | ---: |
| Exclusive registry mutex | 42.75 ns | 0 |
| Shared registry lock | 22.64 ns | 0 |

Logs: `/tmp/cv2-g2-registry-bench-before.log` and `registry-bench-after.log`.
The benchmark contains only readers; real callbacks also acquire exclusive
publication and reference-accounting cuts. No mounted throughput claim follows
from this isolated read-lock result.

## G2 isolated kernel LOOKUP round trip

The first exact probe attempt used `fuse_get_unique`; that symbol did not observe
ordinary requests in this kernel build and produced no samples. It is discarded.
The working [bpftrace probe](../../scripts/cached-lookup-roundtrip.bt) pairs
`queue_request_and_unlock` with `fuse_request_end` by the live request address.
Linux 6.8's [request path](https://github.com/torvalds/linux/blob/v6.8/fs/fuse/dev.c)
places those boundaries before queue insertion and after reply copy, respectively.
The interval includes daemon wakeup/service and kernel reply acceptance; it
excludes initial request allocation and the requester's final wakeup. Permission
GETATTRs are excluded by opcode. Probe overhead after the start is included.

The mounted test pins and labels only its measured syscall thread. Both modes
produce exactly 2,000 unique request pairs, 2,000 daemon LOOKUPs, and zero Authority
LOOKUP or GETATTR RPCs. Kernel entry/attribute validity remains zero. Results on
the shared Linux 6.8.0-100-generic arm64 VM, with another profile run active:

| Mode | Kernel round trip p50 / p95 | Samples below 20 us | Whole syscall p50 / p95 |
| --- | ---: | ---: | ---: |
| Shared cached binding | 2.708 / 14.750 us | 1,931 / 2,000 | 20.000 / 88.334 us |
| Dirty FULL holder | 10.292 / 29.458 us | 1,766 / 2,000 | 72.250 / 155.584 us |

Both medians satisfy the below-20-us target; the holder tail does not. Maximum
samples were approximately 2.5 ms, reflecting the shared scheduling environment.
These are the first measurements at this boundary, so there is no comparable
pre-change kernel-round-trip number. They must not be compared as a speedup
against the earlier daemon-service or whole-syscall figures.

Reproduction: start `bpftrace -q scripts/cached-lookup-roundtrip.bt` as root in a
privileged container in the same VM (mount tracefs there if needed), wait for
`LOOKUP_PROBE_READY`, then run
`PORTABLEFS_GO_TEST_FLAGS='-run ^TestCachedLookupKernelRoundTrip$' bash scripts/xfs-fuse-integration.sh`.
Stop the tracer with SIGINT after both subtests pass. Group `LOOKUP_NS` rows by
label, require exactly 2,000 distinct request IDs each, sort nanoseconds, and
select indices 1,000 and 1,900 for p50/p95. Tracing is optional measurement
infrastructure, not a dependency of the default or full gate. The focused wrapper
exits 70 for omitted inventory. Logs: `/tmp/cv2-g2-lookup-exact-mounted2.log` and
`/tmp/cv2-g2-lookup-kernel2.log`; bpftrace 0.17.0. The unchanged syscall and daemon
service counters remain available alongside the kernel probe.
