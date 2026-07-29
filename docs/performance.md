# Performance

This document describes how PortableFS performance is measured (the `vcs/bench`
harness), the current numbers on a reference machine, every tuning knob the
performance work added and its coherence implication, and the crash-durability
torture test that guards the write path.

## The physics

A PortableFS mount forwards filesystem operations to a single ordered authority
over TCP. That shape fixes what is cheap and what is expensive:

- Round-trips dominate metadata-heavy workloads. A syscall that must consult
  the authority costs a network round-trip; a workload issuing tens of
  thousands of small syscalls (an `npm ci`-shaped install, a compile touching
  thousands of files) multiplies that latency. This is why write-through W2 is
  ~137x local while the version-coherent warm walk (W1) is at local parity: the
  walk is served from client caches with zero round-trips, the storm pays one
  durable round-trip per mutation.
- Adaptive delegation makes a single writer near-local, automatically. Write
  mode is not a mount property ([writeback-engine.md](./writeback-engine.md)):
  the authority delegates an uncontended subtree on the first write, after
  which mutations under it are accepted into a local overlay + segmented
  mount WAL file descriptor at local-disk latency and one flusher ships them
  in dense batches. The 5 ms / 4 MiB group-sync preserves throughput by not
  forcing physical sync on every `write(2)`.
  The same W2 storm drops from ~200x to ~0.7x local wall time with ZERO
  synchronous round-trips (delegated creates need no probe: the grant's
  children snapshot proves absence locally). No coherence is given up: a peer
  operation overlapping the delegation waits for recall at the authority and
  reads the exact acknowledged bytes, never pre-delegation state; contended
  scopes run write-through and re-delegate once contention clears. `O_APPEND`
  under a delegation resolves at the locally-authoritative EOF (the grant is
  exclusive).
- Durable acknowledgement costs a flush round-trip. Contended (write-through)
  mutations pay it inline (the authority fsyncs its journal before acking, so
  "visible" and "durable" coincide). Delegated mutations defer it: visibility
  is local-fast and the explicit barrier (`fsync`, `synchronize`, unmount —
  all of which mean durable at the authority in v5, never a local-only
  outcome) pays the deferred flush. Nothing makes durability free; the engine
  only moves when it is paid.
- The write-return and power-loss-durability measurements are intentionally
  separate. `storm_visible` measures accepted local writes; `storm_durable`
  includes the explicit local sync, authority drain/apply, and visibility
  barrier. Treating the first as durable would erase the exact performance
  trade-off the engine is designed to expose.
- Multi-writer paths pay for coherence. Reads and opens of shared (undelegated)
  paths revalidate by version against the authority. Open/close tracking for
  cross-mount open-after-unlink semantics (`mark_open` in the op mix) is now
  amortized by the open-registration registry: the first open of an inode
  round-trips (the guarantee requires the hold applied before open() returns),
  a create carries its registration on the create RPC itself, re-opens of
  recently-closed inodes reuse the retained registration for free, and
  last-close unmarks are deferred into batches. Version-gated caching removes
  repeat round-trips (warm walks, repeat ENOENT probes) without a time-based
  staleness window; the negative cache now defaults ON whenever the authority
  stamps `ParentVersion` (baseline in v5; the stamp that makes it invalidation-coherent).
- Conditional xattr updates are one write-through authority mutation.
  `XATTR_CREATE`/`XATTR_REPLACE` do not issue a preceding getxattr, so atomicity
  removes the old TOCTOU race without adding a hot-path round-trip.

## Benchmark harness (pfsbench)

`vcs/bench/cmd/pfsbench` provisions a throwaway stack per run — a disk-backed
`workfs` authority (WAL on disk, fsync before ack) served over loopback
fsproto — and drives coding-agent-shaped workloads against it through one of
three transports:

- `local`: a plain temp directory. The baseline every ratio is computed
  against.
- `core`: the `clientcore` volume in-process, issuing the same logical op
  sequence the FUSE frontend issues (lookup before create, open before read,
  handle-based read/write, close). Measures the client brain + protocol +
  authority without kernel/FUSE dispatch overhead.
- `fuse`: a real kernel mount through the mount binary (Linux `/dev/fuse`).
  Skipped cleanly when the host cannot mount (`PFSBENCH_MOUNT_ONLY=skip`).

Workloads, deterministic (fixed seeds and size distributions):

| workload | shape | what it proxies |
|---|---|---|
| W1 metadata-walk | build a tree (full profile: 10,000 files / 500 dirs), then readdir + per-entry lstat, cold and warm; plus real `git status` when the tree is OS-visible | `git status` over an unchanged tree |
| W2 small-file storm | 5,000 files of 1-16 KiB across 100 dirs; time-to-visible and time-to-durable measured separately; plus an ENOENT probe storm (3 rounds over 2,000 missing names in existing dirs) | `npm ci`; package-manager existence probes |
| W3 append | 1,000 sequential 256 B appends to one log + durability barrier | agent/event logs |
| W4 grep | walk + read every W1 file's bytes, cold and warm | content scan / grep |
| W5 sequential | one 256 MiB file written in 1 MiB chunks + barrier, then cold-read | artifact/binary IO |

Measurement protocol: each phase runs N times (N=3 for the committed full
profile); the p50 wall time is reported, with client round-trip counts (RPCs)
and the authority's per-op counters (`vcs_fsproto_op_<name>`, from the fsproto
server) snapshotted around the p50 run so the "top server ops" column
attributes where the round-trips go.

Caveats, stated once: the `core` transport has no kernel hop, so its absolute
times are a lower bound for a real mount (ratios remain the protocol + client
cost). The `local` baseline cannot drop the OS page cache without privileges,
so local "cold" reads are warmer than PortableFS "cold" (re-attached client)
reads; and macOS `fsync` does not force the platter cache (`F_FULLFSYNC`
would), which flatters the local durability barrier. Both biases are against
PortableFS, not for it.

## Results

### The adaptive engine (current, 2026-07-28)

Full profile, n=3, core transport, committed as
`vcs/bench/results/full-adaptive-core.json`. Machine: Apple M5 Max
(darwin/arm64, 18 CPU, 128 GiB RAM), go1.26.5, macOS 26.5. This is the
default configuration — no write-mode flag exists.

| workload | phase | p50 | RPCs | top server ops |
|---|---|---|---|---|
| W1 | walk_cold | 27.1ms | 500 | readdir:500 |
| W1 | walk_warm | 1.6ms | 0 | - |
| W2 | storm_visible | 197.7ms | 0 | flush_batch:10 |
| W2 | storm_durable | 595.4ms | 0 | flush_batch:70 |
| W2 | probe_miss | 1.3ms | 0 | - |
| W3 | append | 81.2ms | 0 | flush_batch:8 |
| W4 | grep_cold | 40.3s | 20,000 | getattr:10000 mark_open:10000 read:10000 |
| W4 | grep_warm | 39.8s | 10,000 | mark_open:10000 read:10000 |
| W5 | write_seq | 940.8ms | 0 | flush_batch:33 |
| W5 | read_seq_cold | 149.9ms | 257 | read:256 getattr:1 |

Reading it against the local baseline below: the delegated write path now has
ZERO synchronous RPCs — storm_visible at 197.7ms is ~0.7x LOCAL (the overlay
acknowledges faster than APFS creates files), probe_miss is answered from the
delegated children set, and the whole storm ships as ~10 flush batches. The
same run in debug write-through
(`vcs/bench/results/full-write-through-core.json`): storm_visible 56.9s
(15,101 RPCs), append 3.78s — the adaptive engine is ~288x on the storm and
~47x on appends. Write-through itself is unchanged by the engine integration
within noise (quick-profile storm 11.69s before / 11.73s after). One honest
regression, orthogonal to the write path: W4 grep pays a durable
exact-mutation commit per `mark_open` (~4ms/open — the v5 baseline records
every mutation identity durably; 39.8s in BOTH modes, engine-independent),
which predates the engine integration and is the next op-mix target; it does
not affect delegated writes, reads under a delegation, or any gated phase.

### Historical (pre-adaptive labels, 2026-07-03/19)

The tables below predate the adaptive engine: `writeback` was an opt-in mount
mode (`-writeback`, retired) and `default` meant write-through. They remain
the reference for the mark_open reduction narrative and the local baseline.
Machine: same class, go1.26.2.

### Op-mix deltas (the 2026-07-19 round's deliverable)

Same-machine before/after, core transport, full profile. "Before" is the
2026-07-19 rebuild of the pre-change tree (matches the 2026-07-03 committed
run within noise); RPC counts are exact (deterministic workloads), wall times
are p50.

| phase | RPCs before | RPCs after | op-mix change | wall before -> after |
|---|---|---|---|---|
| W2 storm_visible (write-through) | 25,101 (mark_open:10,000 create:5,000 getattr:5,000 write:5,000) | 15,101 (create:5,000 getattr:5,000 write:5,000 — mark_open GONE) | −40% RPCs: registration rides the create; unmark retained/batched | 40.0s -> 39.3s (fsync-bound: the removed ops were the cheap ones) |
| W2 probe_miss (default config) | 6,000 (getattr:6,000, 15x local forever) | 2,000 fill round, 0 steady-state (p50 at n=3: 0 RPCs, 0.9ms) | negative cache now default-on (ParentVersion is baseline) | 127ms -> 53ms (n=2 p50 = fill run; cached runs ~1ms) |
| W4 grep_cold | 40,000 (mark_open:20,000 getattr:10,000 read:10,000) | 30,000 (mark_open:10,000 getattr:10,000 read:10,000) | unmarks gone (retained) | 1.13s -> 0.82s |
| W4 grep_warm | 30,000 (mark_open:20,000 read:10,000) | 10,000 (read:10,000 — mark_open GONE) | −67% RPCs: retained registrations reused, zero per-open round-trips | 841ms -> 400ms |
| W3 append | 1,004 | 1,002 | fused create+register | ~par |
| W5 read_seq_cold | 259 (mark_open:2) | 258 (mark_open:1) | unmark retained | ~par |

The write-back labels show the same read-path wins (grep_cold 40,000 -> 30,000,
grep_warm 30,000 -> 10,000); their W2 storm was already flush-batched and is
unchanged (~10,025 RPCs). One honesty note: under write-back the probe_miss
RPC count is timing-dependent (observed 0-5.4k across runs, before and after —
the storm's asynchronous flush overlaps the probe phase, and cache-clearing
events on the write-back path can force negative re-fills). Re-fills cost
round-trips, never staleness; the write-through probe_miss steady state is the
deterministic 0 shown above.

Headline phases (p50; ratio is vs the 2026-07-03 local baseline for the same
phase; W2 write-through figures from the n=3 re-run):

| phase | local | default (write-through) | writeback | writeback-neg |
|---|---|---|---|---|
| W1 walk_warm | 32.8ms | 2.0ms (0.06x, 0 RPCs) | 2.2ms (0.07x, 0 RPCs) | 2.2ms (0.07x, 0 RPCs) |
| W2 storm_visible | 279ms | 39.3s (141x, 15,101 RPCs) | 3.43s (12.3x, 10,025 RPCs) | 3.48s (12.5x, 10,026 RPCs) |
| W2 storm_durable | 111ms | ~0 (already durable) | 994ms (8.9x, 7 RPCs) | 1.08s (9.7x, 8 RPCs) |
| W2 probe_miss | 8.2ms | 0.9ms (0.1x, 0 RPCs; fill round 2,000) | 111ms (13.5x, 3,051 RPCs) | 133ms (16.2x, 5,362 RPCs) |
| W3 append | 4.9ms | 4.16s (849x, 1,002 RPCs) | 173ms (35x, 4 RPCs) | 166ms (34x, 4 RPCs) |
| W4 grep_warm | 128ms | 400ms (3.1x, 10,000 RPCs) | 414ms (3.2x, 10,000 RPCs) | 389ms (3.0x, 10,000 RPCs) |
| W5 write_seq | 120ms | 1.47s (12.2x, 258 RPCs) | 1.04s (8.7x, 4 RPCs) | 1.11s (9.2x, 4 RPCs) |

(The write-back wall times above ran at n=2 concurrently with other load on
this host and read universally slower than the committed 2026-07-03 n=3 run —
compare RPC counts, which are load-independent, when judging the op-mix work;
the 2026-07-03 table remains the reference for absolute write-back latency.)

Full per-label tables as printed by `pfsbench report` — these are the
2026-07-03 committed run, i.e. the PRE-reduction op mix; read them together
with the op-mix delta table above (mark_open rows are the ones that moved):

### label=default transport=local (baseline)

| workload | phase | p50 | ops/s |
|---|---|---|---|
| W1 | walk_cold | 33.3ms | 315.3k |
| W1 | walk_warm | 32.8ms | 320.1k |
| W1 | git_status | 23.7ms | 422.3k |
| W2 | storm_visible | 279.2ms | 17.9k |
| W2 | storm_durable | 111.1ms | 45.0k |
| W2 | probe_miss | 8.2ms | 729.6k |
| W3 | append | 4.9ms | 203.6k |
| W4 | grep_cold | 131.2ms | 76.2k |
| W4 | grep_warm | 128.1ms | 78.1k |
| W5 | write_seq | 120.1ms | 2.1k |
| W5 | read_seq_cold | 11.2ms | 22.9k |

### label=default transport=core (write-through, all knobs off)

| workload | phase | p50 | ops/s | RPCs | vs local | top server ops |
|---|---|---|---|---|---|---|
| W1 | walk_cold | 24.1ms | 436.5k | 500 | 0.7x | readdir:500 |
| W1 | walk_warm | 1.5ms | 7.2M | 0 | 0.0x | - |
| W2 | storm_visible | 38.38s | 130 | 25101 | 137.5x | mark_open:10000 create:5000 getattr:5000 |
| W2 | storm_durable | 1µs | - | 0 | 0.0x | - |
| W2 | probe_miss | 124.2ms | 48.3k | 6000 | 15.1x | getattr:6000 |
| W3 | append | 3.66s | 273 | 1004 | 746.0x | write:1000 mark_open:2 create:1 |
| W4 | grep_cold | 951.6ms | 10.5k | 40000 | 7.3x | mark_open:20000 getattr:10000 read:10000 |
| W4 | grep_warm | 695.1ms | 14.4k | 30000 | 5.4x | mark_open:20000 read:10000 |
| W5 | write_seq | 1.07s | 238 | 260 | 8.9x | write:256 mark_open:2 create:1 |
| W5 | read_seq_cold | 164.7ms | 1.6k | 259 | 14.7x | read:256 mark_open:2 getattr:1 |

### label=writeback transport=core (`-writeback`)

| workload | phase | p50 | ops/s | RPCs | vs local | top server ops |
|---|---|---|---|---|---|---|
| W1 | walk_cold | 30.2ms | 348.1k | 500 | 0.9x | readdir:500 |
| W1 | walk_warm | 3.0ms | 3.5M | 0 | 0.1x | - |
| W2 | storm_visible | 1.40s | 3.6k | 10023 | 5.0x | getattr:5000 read:5000 flush_batch:23 |
| W2 | storm_durable | 245.7ms | 20.4k | 6 | 2.2x | flush_batch:6 |
| W2 | probe_miss | 125.1ms | 47.9k | 6000 | 15.2x | getattr:6000 |
| W3 | append | 48.5ms | 20.6k | 4 | 9.9x | flush_batch:2 getattr:1 read:1 |
| W4 | grep_cold | 990.3ms | 10.1k | 40000 | 7.5x | mark_open:20000 getattr:10000 read:10000 |
| W4 | grep_warm | 702.1ms | 14.2k | 30000 | 5.5x | mark_open:20000 read:10000 |
| W5 | write_seq | 475.3ms | 539 | 3 | 4.0x | flush_batch:1 getattr:1 read:1 |
| W5 | read_seq_cold | 157.8ms | 1.6k | 259 | 14.1x | read:256 mark_open:2 getattr:1 |

### label=negcache transport=core (`-negcache`)

| workload | phase | p50 | ops/s | RPCs | vs local | top server ops |
|---|---|---|---|---|---|---|
| W1 | walk_cold | 30.4ms | 345.3k | 500 | 0.9x | readdir:500 |
| W1 | walk_warm | 1.6ms | 6.5M | 0 | 0.0x | - |
| W2 | storm_visible | 38.11s | 131 | 25101 | 136.5x | mark_open:10000 create:5000 getattr:5000 |
| W2 | storm_durable | 0µs | - | 0 | 0.0x | - |
| W2 | probe_miss | 857µs | 7.0M | 0 | 0.1x | - |
| W3 | append | 3.61s | 277 | 1004 | 735.1x | write:1000 mark_open:2 create:1 |
| W4 | grep_cold | 1.23s | 8.1k | 40000 | 9.4x | mark_open:20000 getattr:10000 read:10000 |
| W4 | grep_warm | 938.3ms | 10.7k | 30000 | 7.3x | mark_open:20000 read:10000 |
| W5 | write_seq | 1.11s | 231 | 260 | 9.2x | write:256 mark_open:2 create:1 |
| W5 | read_seq_cold | 167.1ms | 1.5k | 259 | 14.9x | read:256 mark_open:2 getattr:1 |

### label=writeback-neg transport=core (`-writeback -negcache`)

| workload | phase | p50 | ops/s | RPCs | vs local | top server ops |
|---|---|---|---|---|---|---|
| W1 | walk_cold | 24.9ms | 421.9k | 500 | 0.7x | readdir:500 |
| W1 | walk_warm | 2.1ms | 5.1M | 0 | 0.1x | - |
| W2 | storm_visible | 1.36s | 3.7k | 10014 | 4.9x | getattr:5000 read:5000 flush_batch:14 |
| W2 | storm_durable | 262.2ms | 19.1k | 6 | 2.4x | flush_batch:6 |
| W2 | probe_miss | 1.6ms | 3.8M | 0 | 0.2x | - |
| W3 | append | 50.0ms | 20.0k | 4 | 10.2x | flush_batch:2 getattr:1 read:1 |
| W4 | grep_cold | 943.9ms | 10.6k | 40000 | 7.2x | mark_open:20000 getattr:10000 read:10000 |
| W4 | grep_warm | 736.0ms | 13.6k | 30000 | 5.7x | mark_open:20000 read:10000 |
| W5 | write_seq | 476.3ms | 537 | 4 | 4.0x | flush_batch:2 getattr:1 read:1 |
| W5 | read_seq_cold | 160.2ms | 1.6k | 259 | 14.3x | read:256 mark_open:2 getattr:1 |

Reading the tables:

- W1 walk_cold at 0.7-0.9x and walk_warm at ~0.05x local is real, not an
  artifact: readdir-plus fills the attribute cache from 500 listings (one RPC
  per directory instead of one lstat per file), and the warm walk revalidates
  by version entirely from memory with zero round-trips, where local disk
  still pays 10,500 syscalls.
- W2 storm under write-through is one durable WAL commit per mutation
  (~1.5 ms each: the op mix was create+write per file, the kernel-shaped
  pre-create lookup, and `mark_open`/unmark per handle — 25,101 RPCs; after
  the reduction the registration rides the create and the unmark is
  retained/batched, so the same storm is 15,101 RPCs with an unchanged
  fsync count). Write-back moves all mutations into ~23 async `flush_batch`
  RPCs; the remaining 10,000 round-trips are the pre-create ENOENT lookup and
  a base read as each session file opens. Those are latency-cheap (no fsync),
  which is why the wall clock drops 27x even though RPCs only drop 2.5x.
- storm_durable being ~0 for write-through is the flip side: durability was
  already paid inline. Write-back pays it at the barrier (6 flush batches,
  2.2x a local fsync sweep).
- probe_miss with the negative cache: the p50 run costs zero RPCs (its first,
  fill round is visible in the run list as ~59-103 ms). Without it every
  repeat probe re-round-trips (15x local forever) — which is why the cache is
  now DEFAULT-ON (`ParentVersion` is baseline in fsproto v5; the
  2026-07-19 default-label probe_miss shows the flip: 6,000 RPCs -> 0
  steady-state).
- W4 grep was read-bound and knob-insensitive at 3 RPCs per file (open-time
  getattr on cold, `mark_open`/unmark per handle, one read); the open-state
  tracking for cross-mount open-after-unlink was 2/3 of the warm op count.
  The mark_open reduction (next section) removed exactly that: warm grep is
  now 1 RPC per file (the read), with the SAME park-instead-of-break
  guarantee — see the delta table.
- W5 sequential IO runs at 256 MiB in ~0.16 s cold read (1.6 GB/s) over
  loopback; write-through write pays per-MiB durable commits (8.9x),
  write-back streams into the local WAL and ships one batch (4.0x).

## The mark_open reduction (open-registration op mix)

The 2026-07 op-mix round attacked the two dominant residuals the previous
tables exposed: `mark_open` (2/3 of the warm-grep op count, 40% of the
write-through storm) and the ENOENT probe storm (the negative cache was
opt-in). Design, driven by the measured distribution:

- What `mark_open` is for: the authority parks (orphans) instead of destroying
  any inode a mount holds open, so a peer's unlink of your open file is
  delete-on-last-close, never a broken fd — plus lease liveness via
  `RenewOpenInodes`. The frozen invariant: at the moment open() returns, the
  registration is applied at the authority (both orderings of the open-vs-
  unlink race stay decided by server apply order, `fs.mu`-atomic with the
  park check). That invariant is why the first registration of an inode can
  never be batched, pipelined past the open return, or made asynchronous —
  and measured, it did not need to be:
- Measured shape (full profile, core transport): W2 storm sent one
  `mark_open` + one unmark per created file (10,000 ops for 5,000 files) even
  though the create RPC already round-trips; W4 grep sent one mark + one
  unmark per open (20,000 ops for 10,000 opens, cold AND warm) even when the
  same files are re-opened seconds later.
- Fix, three legs, all capability-gated on `FeatOpenRegistration` (old
  client + new server and new client + old server both keep the previous
  two-RPC behavior):
  1. Fused create+register (`Request.RegisterOpen` on `OpCreate`): the kernel
     CREATE is create+open, so the authority records the creating owner's
     hold before replying to the create. One RPC where there were two; a peer
     unlink inside the (now sub-RPC) window still degrades the reply to
     ENOENT exactly like the separate MarkOpen did.
  2. Per-inode registration registry with retention: refcounted opens —
     concurrent opens of one inode join a single in-flight MarkOpen; the
     LAST close retains the registration (bounded LRU,
     `PORTABLEFS_OPEN_RETENTION_ENTRIES`, renewed by `RenewOpenInodes`)
     instead of unmarking, so re-opens are zero-RPC. Reuse is gated on the
     authority generation stamp and renewal freshness (lease liveness), and
     given up on any signal the binding changed: peer Orphaned/name-change
     invalidations, stream resubscribe, LRU pressure — and this mount's own
     remove/rename release the retained hold synchronously FIRST (the
     op-order flush window), so a self-remove still destroys instead of
     spuriously parking. A peer's unlink of a retained-but-closed file parks
     briefly; the Orphaned invalidation drops our retention and orphan lease
     GC reaps it — bounded zombie, namespace-invisible.
  3. Batched deferred unmarks (`OpUnmarkOpenInodes`, mirroring the
     `RenewOpenInodes` batch shape): a close has no synchronous contract —
     until the unmark applies the authority errs toward parking, which lease
     GC cleans — so unmarks queue and ship 512 per RPC.
- What was deliberately NOT done: batching/pipelining first-registrations
  (violates the open-return invariant; concurrent opens already overlap their
  mark latency across the connection pool), and a cheaper read-only-open
  tier (the open-after-unlink contract holds for every open kind — a grep'd
  file unlinked mid-read must keep serving that read; reads therefore need
  the same hold, they just stopped paying per-open for it).
- Race coverage: the frozen `TestMarkOpenLosesRaceToUnlink` /
  `TestMarkOpenBeatsUnlinkParks` are untouched;
  `TestCreateRegisterOpenHoldParksPeerUnlink` (fsproto) pins the fused-create
  ordering and `TestRetainedReopenZeroRPCStillParksPeerUnlink` (clientcore)
  pins the zero-RPC re-open (open returns, peer unlinks immediately, inode
  parks and the handle keeps serving).

## Knob reference

The write path has NO knobs: `--fast`, `PORTABLEFS_WRITEBACK`,
`PORTABLEFS_FLUSH_MS`, `PORTABLEFS_FLUSH_MAX_RECORDS`,
`PORTABLEFS_FLUSH_MAX_BYTES`, and the fsync policies are retired. The
authority decides delegation adaptively per scope; batching (128 records /
8 MiB / 10 ms), the local group-sync cadence (5 ms / 4 MiB), the WAL budget,
and the retry/backoff schedule are internal constants of the engine
([writeback-engine.md](./writeback-engine.md)). The one debug override is
`PORTABLEFS_DEBUG_WRITE_THROUGH=1` (never delegate; the engine still
recovers parked streams) — a diagnosis tool, not a mode.

Remaining knobs:

| knob | where | default | effect |
|---|---|---|---|
| `PORTABLEFS_NEGATIVE_CACHE` | mount env | on | version-gated ENOENT caching: a miss is stored against the parent directory version the authority stamps on the miss response (`ParentVersion`, baseline in fsproto v5); any create/remove in that directory advances the version and invalidates the negative. Two-client coherence, including the subdirectory, sibling-create, and default-on shapes, is proven in `clientcore` tests (`TestNegativeCacheSubdirTwoClientCoherence`, `TestNegativeCacheSiblingCreateInvalidatesSubdirNegative`, `TestNegativeCacheDefaultsOnAgainstStampingAuthority`). `"0"` forces off |
| `PORTABLEFS_OPEN_RETENTION_ENTRIES` | mount env | 65536 | bounds retained open registrations (closed-but-still-registered inodes reused by later opens with zero round-trips; see the mark_open reduction section). `0` disables retention — every last close unmarks, the previous behavior |
| `PORTABLEFS_NO_READDIRPLUS` | mount env | off (readdir-plus on) | kill switch for the readdir-time attr-cache fill; changes RPC count only, never observed attrs |
| `vcs_fsproto_op_<name>` counters | fsproto server metrics | always on | per-op server counters behind the report's "top server ops" column |

`pfsbench run` flags for A/B runs: `-write-through` (debug), `-negcache`,
`-no-readdirplus`, `-session-ttl-ms`, `-pool`, `-cpuprofile`.

## Crash durability (pfstorture)

`vcs/bench/cmd/pfstorture` is the kill -9 torture loop, with two campaigns:

- `-mode authority-kill` (default): per iteration it starts a real authority
  OS process (`pfsbench serve`) on a fresh disk-backed WAL, drives a
  W2-shaped small-file storm plus an append log over write-through fsproto,
  SIGKILLs the authority at a random point, records exactly which operations
  were acknowledged, restarts the authority on the same WAL, and verifies
  through the same pooled client (which must reconnect transparently).
- `-mode client-kill`: the authority stays healthy while the write-back
  MOUNT CLIENT (`pfsbench wbstorm` — a real `clientcore` volume running the
  adaptive engine with a persistent local store) is SIGKILLed mid-storm. Kills are
  timer-triggered on even iterations (covering the setup phase and the
  point immediately after the last ack, where the flusher still holds an
  unshipped tail) and ack-count-triggered on odd iterations (squarely
  mid-ack-phase). A fresh client on the same store (`pfsbench wbrecover`)
  must discover the parked stream at its attach-readiness gate, verify it,
  rebind it, and drain it exactly.

The client-kill campaign is a process-loss test, not a sudden-power-loss
test: the OS page cache survives SIGKILL. The write-versus-fsync contract is
pinned separately by `TestWriteAndFsyncHaveDistinctLocalDurabilityBoundaries`.

Both campaigns verify, against the (restarted or always-live) authority:

- every acked create resolves and is reachable through its parent directory
  listings (tree consistency, duplicate-entry check included);
- every acked full-file write reads back with the exact content hash;
- a file whose create acked but whose write was in flight is empty or
  complete, never torn — and nothing is duplicated;
- the append log's acked prefix hashes exactly, with at most one in-flight
  chunk beyond it.

Any violation exits non-zero with the iteration's seed, so a durability bug is
a one-command repro (`-seed <failing> -k 1 -mode <mode>`).

Results on this machine (committed as
`vcs/bench/results/torture-authority-kill-k5.json` and
`torture-client-kill-k5.json`, 2026-07-28): 5/5 iterations passed in each
mode (client-kill additionally re-run at two more seed bases, 15/15 total).
Client-kill iterations acknowledged 15-245 creates/writes before the kill —
one iteration was killed between a create's ack and its write's ack, and one
mid-setup kill exercised the grant-orphaned-before-DELEGATION-frame window
(recovery must sweep the authority-journaled grant of a provably empty
stream; `TestRecoverySweepsGrantOrphanedBeforeDelegationFrame` pins it).
Every accepted byte was present and hash-correct on the authority after
exact attach-time replay, with no duplication. The historical write-through-era
`torture-k10.json` (10/10) is retained.

## Running locally

```bash
cd vcs

# Full matrix (local + core labels, fuse when the host can mount), ~12 min:
./bench/run.sh

# CI-sized:
PROFILE=quick N=2 ./bench/run.sh

# One config directly (the default IS the adaptive engine):
go build -o /tmp/pfsbench ./bench/cmd/pfsbench
/tmp/pfsbench run -transport core -profile quick -n 2 -out /tmp/r.json
/tmp/pfsbench report -dir /tmp

# Torture loops (kill -9 crash durability), ~15 s for K=10:
go build -o /tmp/pfstorture ./bench/cmd/pfstorture
/tmp/pfstorture -serve-bin /tmp/pfsbench -k 10 -seed 42
/tmp/pfstorture -serve-bin /tmp/pfsbench -mode client-kill -k 10 -seed 42
```

## CI

`.github/workflows/perf.yml` runs the quick profile (local + core labels, and
fuse when the ubuntu runner can mount — fuse3 is installed and gated on
`/dev/fuse` + `fusermount3`) plus `pfstorture -k 3`, on `workflow_dispatch` and
a weekly cron. Results JSON is uploaded as an artifact and the report lands in
the step summary. The job is advisory (`continue-on-error: true`, and it never
triggers on pull requests), so it cannot block merges.
