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
