# Performance

Status: **protocol-5 Linux candidate measured on the exact diagnostic kernel;
no release SLO yet**

## August 15, 2026 protocol-5 Linux measurement

This is the first byte-verified end-to-end measurement of the protocol-5
transactional-write and post-VFS publication architecture. It is a local
engineering baseline, not a service SLO: the kernel has generic KASAN, XFS
debugging, lockdep/`PROVE_LOCKING`, and fault-injection support compiled in, and
the authority and clients communicate over loopback TLS rather than a production
network.

### Exact environment and workload

- Isolated Lima VZ arm64 VM: 12 vCPU, 24 GiB RAM, running exactly
  `6.12.100-pfs-strict`.
- Kernel patch SHA-256 values: `096d01915824d909316498fdc9de9252730ac4292294fd421a7fa4b24fffa417`,
  `2534c6889f73d02bd2166791298da6e1a8a7689e92166bbf6fd74945c19cc786`,
  and `eb7cddd8726ecc40a0e8fa210aab9694f8e65dbda63f341dd9b2fe94d60bba9f`.
- Dedicated 32 GiB XFS disk mounted with
  `prjquota,nodev,nosuid,noexec,noatime`; the workload ran as uid/gid 200001 in
  project 43001 with an 8 GiB block ceiling.
- Each latency phase contains 200 sequential operations: create, 4 KiB write,
  fsync, close, warm stat, open/read/close, rename, and unlink. The bulk phase
  writes and reads 64 MiB in 1 MiB chunks and verifies SHA-256.
- The direct case uses the same XFS project. The one-mount case uses one strict
  kernel FUSE mount. In the two-mount case the peer first acquires the exact
  negative dentry, positive dentry, file-data, and directory-name state affected
  by each mutation; the mutator therefore includes real peer repair and ACK,
  not an idle second session.
- The table reports the median of five complete runs. The harness prints one
  stable JSON record per observation and is opt-in as
  `TestStrictPerformanceAgainstDirectXFS`; it is a measurement, never a noisy CI
  timing threshold.

### Result

Latency values are milliseconds. Bulk values are MiB/s.

| operation | direct XFS | strict, one mount | strict, active peer |
| --- | ---: | ---: | ---: |
| create p50 / p99 | 0.071 / 0.324 | 0.820 / 1.176 | 1.021 / 1.421 |
| 4 KiB write p50 / p99 | 0.015 / 0.046 | 0.800 / 67.589 | 0.992 / 68.158 |
| fsync p50 / p99 | 0.293 / 0.830 | 0.440 / 0.791 | 0.435 / 1.021 |
| warm stat p50 / p99 | 0.004 / 0.014 | 0.185 / 0.424 | 0.216 / 0.519 |
| open/read/close p50 / p99 | 0.018 / 0.046 | 0.715 / 1.056 | 0.783 / 0.991 |
| rename p50 / p99 | 0.057 / 0.191 | 0.996 / 1.375 | 1.343 / 1.785 |
| unlink p50 / p99 | 0.052 / 0.251 | 0.526 / 0.857 | 0.812 / 1.097 |
| 64 MiB acknowledged write | 1,782.2 | 158.5 (136.9–238.0) | 170.6 (126.2–264.1) |
| 64 MiB read | 2,228.9 | 105.9 (103.8–125.9) | 115.4 (112.7–123.1) |
| complete workload wall time | 0.194 s | 2.472 s | 3.824 s |

The two strict write-throughput ranges overlap; the higher two-mount median is
measurement variance, not a claim that a peer makes writes faster. The stable
comparison is semantic: both strict cases hash the same bytes, and the active
peer has repaired them before the source syscall returns.

Protocol-5 SHARED reads arrive from the authority as bounded in-memory
`ReadResultData`; they are not descriptor-backed. The Linux frontend therefore
disables go-fuse's descriptor-splice response path. Attempting that path cannot
be zero-copy, and at the 1 MiB read bound its pipe request exceeds a typical
1 MiB pipe ceiling once the FUSE header is included. Selecting `writev`
directly removes the futile pipe grow/recovery and its per-read warning without
changing the wire or cache contract.

Against the immediately preceding protocol-5 measurement on this same VM, the
lockless namespace-repair and internal sequenced-retry candidate reduced the
one-mount p50 for the measured metadata operations by about 3–17%, reduced the
complete one-mount workload by 5.3%, and raised its median acknowledged bulk
write rate by 13.1%. Active-peer metadata p50 improved by about 2–10% and the
complete workload by 1.1%. The active-peer write-throughput distributions
overlap too broadly to call their median change an optimization result.

The investigation also removed a real payload-sized client copy. Staged
BEGIN/DATA/ABORT messages now use an explicit caller-owned idempotent API; the
general read/idempotent API keeps its defensive-copy contract. The 1 MiB frame
writer itself is already out-of-line and measures about 0.34 microseconds,
24 B/op, and one allocation. The removed protobuf clone cost 29–46 microseconds,
1,048,889 B/op, and five allocations per DATA fragment on the development
machine. On the exact VM, post-change profiling reduced `runtime.memmove` from
0.39 seconds to 0.04 seconds for the workload; TLS/kernel syscalls now dominate.

The 4 KiB write tail is not hidden: the five runs observed one-mount p99 values
of 45–79 ms and active-peer p99 values of 9–71 ms on this diagnostic kernel.
System-call tracing found no
corresponding 50–100 ms XFS operation, and Go scheduler/GC profiling did not
show a stop-the-world pause of that size. Treat it as an open diagnostic-kernel
tail investigation, not as a production tail SLO.

### Directional Archil context

No current Archil endpoint or test account was placed in scope, so no new
Archil workload was provisioned or charged. The historical cross-cloud
observation below remains the only comparison: Archil measured 71.5/107.8 MiB/s
sequential writes and 102.9/232.5 MiB/s reads at 1/8 jobs. The protocol-5 local
diagnostic run above measures 158.5 MiB/s acknowledged writes and 105.9 MiB/s
reads at one strict mount, but hardware, network, concurrency, cache state, and
success semantics differ. These numbers establish that the exact architecture
is not intrinsically throughput-starved; they do not establish a vendor ranking.

## August 15, 2026 macOS client-path guardrail

There is deliberately no mounted macOS protocol-5 throughput number yet. The
public macOS 26 FSKit API cannot invalidate peer namespace and inode-attribute
caches with the exact post-publication ordering required by PortableFS. Shipping
macOS builds therefore refuse protocol-5 Attach before mounting instead of
silently weakening consistency. This is a functional safety boundary, not a
performance fallback. The separately pinned macOS 27 adapter also remains a
qualification target rather than a shipping claim until an SDK 27 host can run
the complete native cache matrix described in
[macos-27-native-coherence.md](./macos-27-native-coherence.md).

The currently usable measurement is a lower-layer client-pipeline guardrail. On
an 18-core Apple M5 Max MacBook Pro with 128 GiB RAM, macOS 26.5, Xcode 26.6,
and Swift 6.3.3, the release-build
`readWriteChunkingRoundTripsTwentyMiBFile` test performs an exact 20 MiB write
and 20 MiB read through `VolumeCore`, the production Unix-socket framing, and
the mock data-plane implementation. It verifies every returned byte and proves
that both directions remain split into at most 1 MiB protocol requests. Ten warm
runs completed in 0.044-0.049 seconds, with an approximately 0.047-second
median. That is about 851 MiB/s of combined verified client-pipeline byte
movement. It excludes a
mounted FSKit kernel path, authority TLS, XFS, durability, and peer publication,
so it is useful for detecting local framing/copy regressions but must not be
compared directly with the Linux end-to-end or historical Archil figures.

The same macOS tree passed all 342 Xcode-native tests, ten complete Xcode test
iterations, the full Swift package under Thread Sanitizer and Address Sanitizer,
and signed app/extension/service verification. Thread Sanitizer found one race
in a test-only raw-socket server's stop flag; the helper now owns that lifecycle
under a lock, and both sanitizer suites pass after the fix. No production data
path race was reported.

The first controlled v3/protocol-4 investigation was run on August 12-13, 2026.
The results below are engineering measurements, not a published service SLO.
Every older benchmark this project published measured the deleted v2 write-back
engine; those figures remain invalid for this architecture.

## August 2026 protocol-4 investigation

### Environment and method

- Isolated GCP test resources in zone `us-east4-a`.
- Authority: `n2-standard-4`, the isolated `vol_gcp_v3_01` XFS project on its
  existing `pd-balanced` cell disk.
- Runners: `e2-small`; a second temporary VM was used for the genuine
  two-machine strict-coherence matrix.
- Candidate authority used isolated port `20255`. No public
  `portablefs.com`, Railway, or hosted production data-plane endpoint was used
  or modified.
- Sequential figures are MiB/s with 1 MiB synchronous direct-I/O requests.
  Random figures are 4 KiB synchronous direct-I/O IOPS. Repeated bulk results
  report the median where a set exists. The shared read file was hot in the
  authority page cache, so these are protocol/CPU measurements rather than
  device-cold storage measurements.

The runner is a shared-core VM and individual results vary materially. The
numbers support comparisons within this run; they do not establish capacity or
tail-latency SLOs.

### Result

| workload | pre-change PortableFS | protocol 4 candidate | change |
| --- | ---: | ---: | ---: |
| sequential read, 1 job | 192.9 MiB/s | 295.3 MiB/s median | +53% |
| sequential read, 8 jobs | 314.1 MiB/s | 398 MiB/s | +27% |
| strict sequential write, 1 job | 36.8 MiB/s | 40.5 MiB/s median | +10% |
| strict sequential write, 8 jobs | about 35 MiB/s | 53.3 MiB/s | about +52% |
| random read, 1 job | 1,105 IOPS | 1,990 IOPS | +80% |
| random read, 16 jobs | 10,332 IOPS | 11,583 IOPS | +12% |
| strict random write, 1 job | about 335 IOPS | 1,315 IOPS | +293% |
| strict random write, 16 jobs | about 335 IOPS | 1,433 IOPS | +328% |
| strict random-write p99, 16 jobs | 77.1 ms | 14.5 ms | -81% |

The exact `fsops` comparison isolates the coherence-control change from the
larger fio run: strict 4 KiB write p50 fell from 2.797 ms to 0.764 ms, and
create p50 fell from 3.134 ms to 1.589 ms. With the second strict machine having
already resolved the exact file, a 256 MiB overwrite sustained 32.5 MiB/s; the
peer then verified every fio CRC successfully. That lower number is the honest
cost of making an actively caching peer repair every write before return.

Two root changes produced the result:

1. Protocol 4 carries one schema-bound read/write body outside protobuf
   metadata. A 1 MiB frame send now allocates 16 bytes in the framing benchmark;
   receive holds one payload allocation under the server's global frame budget
   through XFS apply. The client no longer hashes mutations: the authority
   streams the canonical body once into a secret per-epoch keyed fingerprint,
   which preserves exact altered-replay rejection without a second client-side
   payload pass.
2. Linux strict coherence atomically acknowledges a repaired visibility cursor
   and long-polls its successor in one request. This removes an empty Ack reply
   and separate Next request from every phase. PREPARE still precedes XFS,
   peers still acknowledge COMPLETE before the mutator returns, and this
   protocol-4 result still included the source self-phases that protocol 5 later
   replaced with an exact local publication gate.

### Correctness evidence for the measured candidate

- Two different GCP VMs, two strict FUSE mounts: 19/19 selected black-box
  cross-mount cases passed, including 100 atomic rename-over replacements,
  append/overwrite integrity, open-after-unlink, and a same-directory mutation
  storm with zero fenced participants.
- Five additional stress rounds each passed 8/8 write/namespace cases, including
  250 atomic replacements per round (1,250 total) and zero fencing in every
  same-directory storm.
- The repository's privileged strict and uncached coherence matrices passed,
  including their disjoint/stale falsifiability controls and peer-loss case.
- The XFS/FUSE integration suite, all Go tests, the full Go race suite, vet, and
  module verification passed for this tree. The mandated
  `scripts/verify-local.sh` release handoff gate passed as well.

### Archil comparison from the same investigation

The Archil mount was reached from the original GCP runner but its disk was in
AWS `us-east-1`; PortableFS authority and clients were same-zone GCP. Caching,
backend disk, cross-cloud path, and acknowledgment semantics differ, so the
table is directional rather than an apples-to-apples product ranking.

| workload | protocol 4 PortableFS | Archil observation |
| --- | ---: | ---: |
| sequential read, 1 / 8 jobs | 295.3 / 398 MiB/s | 102.9 / 232.5 MiB/s |
| sequential write, 1 / 8 jobs | 40.5 / 53.3 MiB/s | 71.5 / 107.8 MiB/s |
| random read, 1 / 16 jobs | 1,990 / 11,583 IOPS | 187 / 385 IOPS |
| random write, 1 / 16 jobs | 1,315 / 1,433 IOPS | 5,183 / 2,863 IOPS |

PortableFS was faster on reads in this setup; Archil remained substantially
faster on writes. Archil also showed large maximum stalls, commit retries, and
SQLite WAL failed with a disk-I/O error. PortableFS's rollback-journal SQLite,
integrity, POSIX, and cross-mount tests passed; WAL remains explicitly
unsupported because it requires shared memory mappings. Most importantly,
PortableFS write success still means authority XFS accepted the bytes, and
strict success still includes peer repair. A faster result obtained from
different acknowledgment or cache semantics must not be presented as the same
guarantee.

## The costs v3 accepts on purpose

These are not regressions to be optimised away later. They are the price of the
guarantees in [consistency-model.md](./consistency-model.md), and a change that
removes one of them has to explain which guarantee it is trading.

**Every data-plane write crosses the wire.** There is no PortableFS-managed
write-back cache. Linux direct-I/O `write(2)` pays at least one authority round
trip. macOS may coalesce application writes in its ordinary kernel page cache;
each FSKit write callback crosses the authority, and `fsync` is the explicit
completion boundary. Benchmarks must identify which syscall boundary they time.

**Names and attributes are coherently cached, and mutation pays for it.** The
single protocol lets repeated path walks be served from the kernel without an
authority lookup. The bill arrives on the other side: a cache-affecting mutation
takes a volume-wide visibility ticket, holds the source's exact local
publication footprint, quiesces affected non-source cache holders, applies to
XFS, drives each peer's repair, and collects acknowledgements before it returns.
With one mount attached there is no network visibility phase. With several, a
mutation that overlaps an actively caching peer costs a PREPARE and COMPLETE
round trip to the slowest such participant; exact semantics cannot remove those
two crossings. Historical or disjoint participants should eventually cost
nothing once the exact cache-grant ledger replaces the current monotone index.

**Shared file-backed `mmap` is refused, not slow.** PortableFS does not advertise
the FUSE capability that would allow shared mapped pages on a direct-I/O inode,
so `MAP_SHARED` on a file fails. Programs that would have used it fall back to
read and write, which is slower and correct. `MAP_PRIVATE` works with ordinary
copy-on-write semantics.

**SQLite WAL mode does not work across machines.** Its wal-index needs a shared
`-shm` mapping and SQLite itself requires every WAL participant to be on one
host. Rollback-journal mode is in the tested compatibility contract and is
slower. A workload that needs WAL keeps that database on machine-local backing or
uses a database service.

**Machine-local routing is the intended answer to dependency trees.** A
`node_modules`, `.venv`, or `target` directory is thousands of small files with no
cross-machine meaning. Routing it to machine-local disk removes it from every one
of the costs above. This is the single largest performance lever the product
offers, and it is a routing decision rather than a tuning knob. See
[agents.md](./agents.md) and [graft-security.md](./graft-security.md).

**One volume has one authority, and therefore one machine's ceiling.** Scale
comes from placing volumes across cells, not from making one volume wider.
Cross-region latency is not hidden; place the authority near its clients.

## What exists to measure with

Five reusable command harnesses live under `vcs/bench/cmd`. The protocol-5
Linux integration package additionally contains the opt-in, end-to-end
direct-XFS/one-mount/active-peer measurement used above. None is a release SLO
gate.

| Tool | What it measures |
| --- | --- |
| `fsops` | Per-syscall latency distributions against a mounted workspace or a plain POSIX directory. Designed to be read against a measured network RTT: roughly one RTT means one round trip, and well under one RTT means the operation was served without the wire. Probe, enumeration, and bulk-write phases. |
| `netprobe` | The protocol-free network floor to an authority endpoint: TCP connect RTT, TLS handshake cost, sustained upload throughput. This is the lower bound any protocol number must be attributed against. It writes nothing and holds no state. |
| `tracestat` | Round trips per operation, derived from a `portablefsd` trace by subtracting daemon-side service time from observed wire round trips. Read-only. |
| `pfs-mount-stress` | A cross-mount stress workload with hashed content and peer done-markers. Its parent-enumeration polling preserves the historical non-shipping macOS qualification experiment; it is not evidence of a supported Mac transport or a protocol-5 namespace workaround. |
| `zratio` | Compressibility and content-defined chunk dedup potential of a real agent corpus. It still runs, but its framing was written against the deleted write-back flusher's batch granularity, so read it as a corpus measurement rather than as a statement about any current code path. |
| `TestStrictPerformanceAgainstDirectXFS` | Byte-identical syscall latency and 64 MiB throughput against direct XFS, one strict mount, and an actively repairing peer. Emits JSON observations and verifies source/peer SHA-256. Linux protocol-5 qualification only. |

The v2 harness drivers (`vcs/bench/run.sh`, `prod-flush-rate.sh`, the weekly
advisory `perf` workflow) and the frozen v2 result files were removed with the
architecture they measured. The surviving tools above are the v3 measurement
starting point. The provisional run above used `fsops`, fio, Linux `perf`, and
the coherence matrix together.

Outside `vcs/bench`, `scripts/package-manager-matrix.sh` is the closest thing to a
realistic workload in the gates. It runs `npm`, `pnpm`, `yarn`, and `bun` installs
on a shared volume path with no machine-local route, while a second mount
enumerates and reads the same tree. It asserts exactly three things — the
installer exited zero, the other mount sees the same entry count and the same
bytes, and both mounts still serve — and it thresholds nothing. Wall time and
authority work counters are recorded into a table for a human to read. That is
deliberate: it is a correctness gate that happens to produce timings, and treating
its timings as a performance gate would make an unrelated CI slowdown look like a
regression.

## What is missing before a number belongs here

1. **A repeatable application-level v3 workload.** The new exact harness covers
   filesystem syscalls and bulk bytes against the direct-XFS ceiling, but a
   repository checkout, compiler run, and metadata-heavy package install still
   need a reproducible production-network job.
2. **Per-RPC observability at the authority.** Several claims one would want to
   make — that a strict path walk avoids lookups, that a routed directory reaches
   the authority zero times — are claims about work performed. The integration
   handler now records exact request counts, but the production authority still
   needs exported per-opcode counters and phase histograms.
3. **Repeatable multi-participant barrier telemetry.** The exact active-peer
   harness is repeatable, but the authority still needs exported
   phase histograms and a repeatable several-machine load job before this cost
   can become a capacity claim.
4. **A macOS number of any kind.** The macOS path has open live-kernel gates
   ([macos-26-coherence-contract.md](./macos-26-coherence-contract.md)); measuring
   it before those are met would measure something that is not yet the product.

Until those exist, the correct answer to "how fast is it" is the exact local
protocol-5 table above plus the historical deployment evidence—not an inferred
SLO. Run `netprobe`, `fsops`, the exact performance integration, and the
coherence matrix against the intended deployment and read them against its own
RTT and participant set.
