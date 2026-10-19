# Performance

Status: **no protocol-8 measurement exists yet.** There is no production SLO
and no qualified performance result for the LAN targets below. Measurements taken under
earlier protocols are not evidence for protocol 8 and are not reproduced here;
git history holds them.

macOS 27 writeBack buffers ordinary writes in the kernel like V2. Every
successful delivered FSKit mutation callback remains durable on authority
storage; coalescing can reduce callbacks, not their durability cost. Native
fsync must cover buffered data and callback errors, pending native proof;
writeBack is not qualified until those proofs pass. Writer loss may lose
undelivered dirty data, as on V2 and a local disk without fsync. Linux peers see
delivered state only. Namespace publication pushes earlier dirty data, and
ordinary unmount drains before ownership release.

An eligible readable existing file opened O_WRONLY or O_APPEND can receive
writeBack after one combined authority read/write OPEN. If read access is
denied by mode or ACL, at most one extra write-only OPEN preserves write
success with noCache; it retains the durable callback cost. A retained writer
needs only one missing-read OPEN on cache upgrade and never loses its existing
description on denial. CREATE can supply legitimate read/write backing rights
even for mode 0200. These are authority access checks, not predictions from
mode bits. Application descriptors remain O_WRONLY and cannot read. Record
actual grants and callback counts when measuring; buffering does not establish
a coalescing size or speedup.

`scripts/diagnose-small-writes.py` is a supplemental diagnostic for separate
review, leaving the fixed acceptance runner unchanged: exactly 10,000
unbuffered 100-byte O_APPEND writes and 64 MiB in 4 KiB chunks on precreated
files, no barrier/close inside either loop. It records loop/write latency,
final fsync and close separately, absolute and monotonic start/end timestamps
for each loop/fsync/close/verification phase with repetition and device/inode
identity, complete write+drain time, and an immediate independent authority
length/hash check. Run the close-only variant separately
on fresh files. Compare V2/V3 on the same authorized 27 host/path before
repeating on 26; bulk with 1 MiB application writes and SQLite's ordered flushes
do not cover many tiny writes to one open file. Keep bounded mode, callback
size/count, durable-reply and final-close traces separate from unpaused timing.

## Metadata callback local work

Package D part 1 is the selected implementation; part 2 is cancelled for
protocol 8. Part 1 removes IPC for fixed-refusal xattr callbacks, removes one
frame-receive continuation resumption, and waits for held GETATTR work to
settle before rechecking ordinary cache and publication admission. A settled
cache hit avoids the authority GETATTR; a real miss still fetches attributes.
Bounded callback traces retain operand identities, wanted masks and
process-local name tokens for diagnosis.

Callback multiplicity remains under the existing Operations/ReadWriteOperations
boundary on both macOS releases. macOS 27 retains DataCacheHandler separately;
there is no Handler result publication to remove later metadata callbacks.
No speedup is recorded until native runs establish one. The 25–35-second local
forecast is withdrawn for this retained scope; adding median callback costs
does not establish an elapsed-time forecast.

## The target

The acceptance workload is unchanged: an initial Git add of 1,200 files through
a macOS mount over a LAN, inside its original 120-second subprocess deadline,
followed by subsequent commits, `git fsck`, a clean status, the full workload,
and integrity checks. A missed deadline stays a failure; report elapsed time
and measured aggregates, with causal attribution unresolved.
It is never met by acknowledging a delivered FSKit mutation before durability,
guessing an OPEN success, widening the deadline, changing the corpus, or adding
Git-specific routing.

The approved qualification target, separately for each supported OS, including macOS 26 and 27, is the
unchanged 1,200-small-file initial `git add .` within 120 seconds at established
authority DATA-path network RTT <= 10 ms, including maximum latency and tails
during the run, with serial non-network work `B <= 15 s`. B includes storage
durability, peer withdrawal, CPU and local IPC; storage is not counted again
as network RTT. Qualify one benchmark job against a healthy authority, without
restore, reconnect or memory pressure, with storage and other-cell load bounded
by B. Peer-reader withdrawal must fit B. Measure cold source reads and warm
retention separately; V3 retention does not prove every source starts warm.
The later 31-commit/fsck workload remains a separate correctness gate.

SQLite's qualification target is four same-process connections, each running
200 transactions with DELETE journaling and FULL synchronization, timeout=60,
all 800 rows present and `integrity_check` passing. Under the same network/load
envelope, target <= 80 ms per serialized commit, including storage and local
work. Record the initialized database/cache state, same-file identity, and each
connection's waits and progress. This is not a cross-host locking promise or a
fairness proof.

These are qualification targets, not yet qualified on either OS. Report
p50/p95/p99/max as observations; average ping, connection setup or p99 alone
does not establish the RTT bound. Earlier failures remain failures.

## What the existing baseline shows

A 32-file diagnostic probe taken before protocol 8 issued **426** foreground
authority requests: Lookup 197, GetAttr 23, Open 43, Create 33, Write 33, Link
32, Unlink 32, Mkdir 30, Rename 1, ReadDir 2. Its 4.279506-second subprocess
divided by 426 is about 10.05 ms. That is an effective elapsed time per request
in one small workload, already including local and storage time; it is not a
measured RPC, network, or disk latency, and the 5.9 ms physical LAN RTT must not
be added to it. The 141 background requests (76 Close, 63 Reclaim, 2 KeepAlive)
are not serial foreground turns, although release pressure can put their waits
on the critical path. The Lookup success counter includes stamped negative
answers, so it does not prove 197 positive lookups. Close counts requests, not
retired tokens.

The protocol cleanup itself removes no demonstrated foreground turn. Direct
WRITE was already used; each successful small CREATE, WRITE, LINK, UNLINK,
MKDIR, and RENAME is one durable foreground turn; CREATE already returns the
real open description, so all 43 OPENs stay in the model. The durable mutation
core is 161 requests per 32 files. The semantically available savings are cache
answers that are valid after source effects settle, proven-absent names in
directories this mount created, and the MKDIR search witness that can replace a
directory's first permission-seeding lookup.

## Conditional model

This arithmetic is a sensitivity tool, not a forecast. For a diagnostic 32-file
run, let `k` be unique Lookups eliminated by source caching and completeness,
`g` unique eliminated GetAttrs, and `m` Lookups eliminated only by the MKDIR
witness and not already in `k`. No operation appears in two categories:

`F32 = 426 - k - g - m`

`m` is not automatically 30; it depends on real child access, witness
eligibility, and the baseline's first-child requests, and a false or
invalidated witness saves nothing.

For the large workload, separate file-scaled, directory-scaled, and fixed work.
With `N` source files, `D` actually created directories, and `a`, `b`, `c` the
retained turns per file, per directory, and fixed:

`F(N, D) = a*N + b*D + c`

`D` is about 254 for the acceptance corpus's object fanout, not 37.5 times the
small run's 30. The witness reduces the directory term, not the per-file term.
Chunking and callback attribution can break the linear model and must be
reported. Two aggregate totals cannot identify `a`, `b`, and `c`; a third
diagnostic size or a same-N, different-D corpus is needed.

Elapsed time also depends on serialization, overlap, per-operation service
time, and durability cost. About 2,655 handleless durability barriers would make
each additional millisecond of non-overlapped barrier latency cost about 2.7
seconds; neither that count nor the lack of overlap has been established. On a
shared cell, `syncfs` cost depends on other projects' dirty data, so mean and
tail both need measuring. The earlier 95–120-second planning range is
withdrawn.

## Snapshot measurement

The next LAN qualification uses elapsed subprocess time, the authority's existing
Prometheus metrics, and the daemon's per-attach metadata-cache and reservation
counters. This needs no service mode, installed plist edit, replacement daemon,
new environment variable, control operation, or process exit. Verify the paired
signed artifact and live service through the normal qualification procedure,
recording artifact revisions, configuration, and process-start witnesses for
both the daemon and the authority worker.

Read `GET /v2/attaches/{attachRef}` over the existing private daemon control
socket with `X-PortableFS-Control-Protocol: 2`. Retain the expected attach and
volume identities and `metadataCache`. Scrape the authority worker's existing
loopback admin `GET /metrics` through the authorized lab connection.

For each measured subprocess, collect both before snapshots before launch,
time the subprocess with the harness's monotonic clock, and collect both after
snapshots after exit or deadline handling. Record each scrape's start and end:
the observations have separate windows, with no atomic cross-process cut.
Keep setup, initial add, subsequent commits, integrity checks, and unmount as
separate phases. Finish the live-attach snapshot before unmount removes the
data plane; collect authority cleanup deltas and actual unmount/inventory
outcomes separately. Do not insert syncs, remounts, or sleeps to manufacture a
measurement boundary.

The external harness owns result files on ordinary local storage outside every
PortableFS mount. It closes them after saving raw snapshots, observation times,
subprocess status, elapsed time, and measurement validity. Rendering snapshots
and writing results use diagnostic/control paths; filesystem requests update
only the existing bounded counters. A failed or slow collector cannot hold a
serving reply or unmount waiting for diagnostic finalization. Short counter-copy
locks remain, so this is not a claim of zero measurement overhead.

Use one measured client/workload on the target volume during initial add, and
leave the later concurrent status observer in its original phase. For the dirty
neighbor experiment, retain the separate-project workload and identify the
shared filesystem. Disclose other clients, background FSKit work, and requests
crossing scrape boundaries. Subtracting an estimated idle rate does not yield
exact foreground traffic.

An attach or worker restart, process-identity change, missing snapshot or
required series, counter decrease, malformed output, or failed scrape invalidates
the delta. A restart invalidates even a numerically increasing counter. Preserve
workload failure when collection also fails; absent data never means zero.
After a timeout, request deltas describe handlers that completed in the observed
window, excluding any attempted or in-flight work that had not completed.

### Counter semantics

`portablefs_authority_rpc_requests_total{volume,opcode,outcome}` counts completed
handler invocations. `close` combines CLOSE and CLOSE_BATCH and counts requests,
not released tokens. Errno-zero stamped-negative Lookup counts as authority
`success`; daemon `lookupPolarity` includes cached replies and cannot partition
authority Lookup outcomes. Daemon cache hits count physically written replies.
A candidate rejected at final exposure records one miss, and its ordinary
authority retry adds neither a second cache decision nor a second polarity.

Retain handler-duration histograms, mutation executed/replayed/refused counters,
physical storage-sync counts/durations/waiters, and FSKit durability-target
counts/durations. Handler latency omits some transport, admission, and frontend
waits. Histogram deltas describe bucket distributions and aggregate duration;
buckets are cumulative, not independent populations. Gauges remain snapshots,
and lifetime high-water gauges are not interval maxima obtained by subtraction.
Do not add overlapping handler, durability, and syscall sums into elapsed time.

Swift's Instruments signposts remain an independent local diagnostic facility,
with a test observer. An operator can attach Instruments for an exploratory
capture and stop it normally without restarting the service. It supplies no
complete callback inventory, zero-loss guarantee, or daemon/authority join.
There are no authority request anchors in this measurement method.

### Permitted conclusions

Report the measured initial-add duration and 120-second verdict, subsequent
workload/integrity/detach outcomes, completed-request deltas by opcode, actual
daemon hits and miss categories, reservation pressure, and aggregate server and
storage costs for the stated windows. Comparisons need an equally specified
earlier run with corpus and artifact differences disclosed.

These observations cannot identify exact foreground serial trips, callback-to-RPC
attribution, OPEN causes, unique eliminated operations, separate source-cache,
completeness, or MKDIR-witness savings, or a critical-path latency decomposition.
Request count multiplied by RTT does not prove elapsed time; cache category
sums do not prove counterfactual savings. A pass establishes the workload result
on that artifact and configuration, not general throughput or all-platform
qualification. A later causal investigation needs its own complete reviewed
implementation.

Run the unchanged 32-file probe and diagnostic 256-file probe with opcode
breakdowns, a third size or same-N/different-D corpus, quiet dedicated-volume
and shared-cell dirty-neighbor conditions on authorized infrastructure, then
the unchanged 1,200-file add and full workload. Keep SQLite 4x200, Git 1,200
files/31 commits, every 120-second subprocess deadline, bulk 4x256 MiB, native
fsync/quota, and the roughly 2,600-item unmount unchanged.

## The costs accepted on purpose

These are the price of the guarantees in
[consistency-model.md](./consistency-model.md). A change that removes one has to
say which guarantee it trades.

**Namespace operations cross the wire.** The authority owns create, rename,
unlink, and the other namespace operations. Independent requests run
concurrently, but sequential namespace operations keep their round trip. An
uncontended Linux delegated write can return from the daemon buffer; fsync,
`O_SYNC`, and the root-directory run barrier wait for durable application.

**Every successful FSKit mutation reply certifies authority-storage durability.**
FSKit has no fsync callback, so each successful mutation pays its barrier: a
handle fsync, or a filesystem-wide syncfs for handleless mutations.

**Cache coherence needs withdrawal.** A Linux subscription caches undelegated
state; a mutation or grant waits for acknowledgment or the subscriber's horizon.
New peer reads of delegated data break the owner for read, and a pre-existing
cacheable peer handle requires per-commit invalidation. Shared kernel name
validity stays zero; the daemon caches bindings and attributes.

**A shared cell shares barrier latency.** Filesystem-wide barriers wait for every
project's dirty data in the cell. Separate filesystems are the only isolation.

**Shared writable mmap is refused**, and **SQLite WAL does not work across
machines**: its wal-index needs a shared mapping and every participant on one
host. Rollback-journal mode works and is slower.

**Machine-local routing is the answer to dependency trees.** A `node_modules`,
`.venv`, or `target` directory routed to local disk leaves every cost above. It
is the largest performance lever the product offers. See [agents.md](./agents.md)
and [graft-security.md](./graft-security.md).

**One volume has one authority**, and therefore one machine's ceiling. Scale
comes from placing volumes across cells. Place the authority near its clients.

## What exists to measure with

None of these is a release SLO gate.

| Tool | What it measures |
| --- | --- |
| `vcs/bench/cmd/fsops` | Per-syscall latency distributions against a mount or a plain directory, read against a measured RTT; probe, enumeration, and bulk-write phases. |
| `vcs/bench/cmd/netprobe` | The protocol-free network floor to an authority endpoint: TCP connect RTT, TLS handshake cost, sustained upload throughput. |
| `vcs/bench/cmd/coherence-bench` | The install, Git status, and two-mount workloads of `vcs/bench/coherencebench` against one or two POSIX paths. |
| `vcs/bench/cmd/pfs-mount-stress` | A cross-mount stress workload with hashed content and peer done-markers. |
| `vcs/bench/cmd/zratio` | Compressibility and content-defined chunk dedup potential of an agent corpus; a corpus measurement, not a statement about a code path. |
| `TestStrictPerformanceAgainstDirectXFS`, `TestCoherenceBaseline`, `TestCachedLookupKernelRoundTrip` | Opt-in Linux measurements inside the privileged suite: syscall latency and 64 MiB throughput against direct XFS, the coherence baseline workloads with request metering, and the kernel LOOKUP round trip. |

`scripts/package-manager-matrix.sh` runs npm, pnpm, yarn, and bun installs on a
shared volume path while a second mount enumerates and reads the same tree. It
asserts only that each installer exits zero, both mounts see the same entries
and bytes, and both mounts keep serving; its timings are for a human to read,
not a gate. Phase 8 of `deploy/opensteer/staging-qualification.sh` drives the
same concurrent-reader shape against a live staging cell.

## What is missing before a number belongs here

1. A protocol-8 run of the diagnostic probes and the unchanged acceptance
   workload on authorized LAN infrastructure.
2. Shared-cell barrier latency under a dirty neighbor, against a dedicated
   filesystem control.
3. A repeatable several-machine load job and exported authority phase
   histograms before any capacity claim.
