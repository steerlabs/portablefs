# Performance

Status: **no protocol-8 measurement exists yet.** There is no production SLO
and no numerical forecast for the LAN target below. Measurements taken under
earlier protocols are not evidence for protocol 8 and are not reproduced here;
git history holds them.

## The target

The acceptance workload is unchanged: an initial Git add of 1,200 files through
a macOS mount over a LAN, inside its original 120-second subprocess deadline,
followed by subsequent commits, `git fsck`, a clean status, the full workload,
and integrity checks. Missing the deadline is reported with its measured cause.
It is never met by deferring durability, guessing an OPEN success, widening the
deadline, changing the corpus, or adding Git-specific routing.

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
seconds; that count and the lack of overlap need trace confirmation. On a
shared cell, `syncfs` cost depends on other projects' dirty data, so mean and
tail both need measuring. The earlier 95–120-second planning range is
withdrawn.

## Correlated trace

Attribution comes from an explicit opt-in, bounded diagnostic trace, not from
aggregate counters alone. `vcs/bench/lantrace` defines the stream and
`vcs/bench/cmd/pfs-lan-trace` collects, reports, and reconciles it:

- Each producer process (Swift frontend, Go daemon, authority, Linux client)
  writes one JSON Lines stream: a header naming the run, layer, and process, a
  bounded sequence of events with per-process monotonic timestamps, and a
  trailer with emitted and lost counts. A stream without its trailer is
  incomplete.
- Every producer follows one sequence rule: each event it accepts consumes the
  next sequence number whether it is written or lost, so every gap in a
  stream's numbers is a counted loss. The collector flags a stream whose
  numbers do not reconcile with its trailer, and the report refuses a
  collection whose sequence history is internally inconsistent.
- The grammar admits only allowlisted keys, enumerated categories, short
  opaque labels and exact trace identifiers from a restricted alphabet,
  bounded integers, and raw names as bounded hex. That excludes free-text fields; it does not establish where a
  value came from. Keeping tokens, credentials, capabilities, file contents,
  pointers, and arbitrary user paths out of the trace, and emitting raw names
  only for the authorized synthetic corpus, is a content rule each producer
  must enforce at its emission sites.
- Producers emit through a bounded queue and byte budget that never block the
  filesystem path; overflow increments the lost count. The collector merges one
  run's streams into a bounded output and keeps bounded correlation state.
- Daemon requests join authority turns by session label and authority request
  ID. Every request-bearing frontend and daemon record carries `frontend_pid`
  (the extension PID; the daemon reads it from the accepted socket's peer),
  `attach_ref` from Resolve, `conn_role` equal to Hello's exact `client_name`,
  and `request_id`. The analyzer derives the cross-process key from
  `(run, frontend_pid, attach_ref, conn_role, request_id)`. Each producer's
  `conn` stays local: a Swift UUID or a daemon origin counter, encoded as a
  string and scoped by its producer stream. No diagnostic wire exchange is
  needed, and those local IDs need not agree.
- A bounded whole-run inventory (at most 256 tuples, never evicted) must prove
  exactly one connection per producer for each PID/attach/role tuple. Duplicate
  same-role connections, PID reuse in another process stream, a connection
  changing its binding, pre-bind attempts, missing fields or inventory overflow
  make the frontend/daemon join unavailable, with zero matches claimed even
  for earlier candidates. These fields must appear on non-anchor request
  records too. The pending-anchor join window remains bounded at 65,536 by
  default. Matching anchors must agree on operation and on mount when both
  provide one. Cross-host clocks are never subtracted.
- The report separates candidate from exposed cache hits, positive from
  stamped-negative Lookups, OPEN reasons (first open, expansion, reopen after
  final close, directory cursor, CREATE description reuse) with emitted versus
  avoided RPCs, barrier kind and syscall latency, coalesced waiters, reservation
  and callback-window pressure, and close/reclaim batch counts versus released
  tokens. Any lost, rejected, incomplete, inconsistent, evicted, unmatched,
  unqualified, or conflicting record marks exact attribution invalid for the
  run; it says nothing about filesystem correctness.

The current diagnostic grammar is `pfs-lan-trace-2`; it replaces the previous
unshipped grammar and has no alternate decoder. The trace format is internal
and may change without notice. Producer
instrumentation belongs to each component and is not yet complete.

Run order: the unchanged 32-file probe and a diagnostic 256-file probe with
opcode breakdowns, a third size or same-N/different-D corpus, quiet
dedicated-volume and shared-cell dirty-neighbor conditions on authorized test
infrastructure, then the unchanged 1,200-file add and full workload. Record
exact artifact revisions and configuration, reconcile trace totals against the
counters, and report mean and tail critical-path contributions.

Local request anchors must be emitted in strictly increasing `request_id`
order per connection on each producer. Reuse or reordering makes the local
join unavailable and clears even earlier matches; non-anchor stages may arrive
out of order. Bounded per-connection high-water marks retain this evidence for
the whole run.

## The costs accepted on purpose

These are the price of the guarantees in
[consistency-model.md](./consistency-model.md). A change that removes one has to
say which guarantee it trades.

**Namespace operations cross the wire.** The authority owns create, rename,
unlink, and the other namespace operations. Independent requests run
concurrently, but sequential namespace operations keep their round trip. An
uncontended Linux delegated write can return from the daemon buffer; fsync,
`O_SYNC`, and the root-directory run barrier wait for durable application.

**Every macOS mutation is durable before it returns.** FSKit has no fsync
callback, so each acknowledged Mac mutation pays its barrier: a handle fsync, or
a filesystem-wide syncfs for handleless mutations.

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
| `vcs/bench/cmd/pfs-lan-trace` | Collects, reports, and reconciles the bounded correlated trace above. |
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

1. Producer instrumentation for the correlated trace in the frontend, daemon,
   authority, and Linux client, reconciled against their counters.
2. A protocol-8 run of the diagnostic probes and the unchanged acceptance
   workload on authorized LAN infrastructure.
3. Shared-cell barrier latency under a dirty neighbor, against a dedicated
   filesystem control.
4. A repeatable several-machine load job and exported authority phase
   histograms before any capacity claim.
