# Performance

Status: **no published v3 measurements**

This document does not report PortableFS v3 numbers, because there are none.
Every benchmark this project ever published was produced by a harness that
measured the v2 client and its write-back engine, both of which were deleted.
Reprinting those figures against a system that acknowledges writes differently
would not be stale documentation; it would be a false claim.

What this document does contain: the costs the v3 design deliberately accepts,
the measurement tools that exist in the tree today, and what would have to be
built and run before any number here is worth stating.

## The costs v3 accepts on purpose

These are not regressions to be optimised away later. They are the price of the
guarantees in [consistency-model.md](./consistency-model.md), and a change that
removes one of them has to explain which guarantee it is trading.

**Every acknowledged write crosses the wire.** There is no client write-back
cache. `write(2)` returns after the authority applied the bytes to XFS, so the
cost of a write is at least one round trip, and a workload that writes many small
files pays that per file. A local filesystem answers from page cache and defers;
PortableFS cannot, because deferring is exactly what would let one machine
acknowledge data another machine cannot see.

**`uncached` crosses the wire for every operation.** In the `uncached` profile
names and attributes have zero TTL, so a path walk of depth *n* is *n* lookups on
the wire, and repeating the same walk repeats them. This profile exists because
it is trivially correct and falsifiable, not because it is fast.

**`strict` caches names and attributes, and pays for it at mutation time.** The
default profile lets repeated path walks be served from the kernel without an
authority lookup. The bill arrives on the other side: a cache-affecting mutation
takes a volume-wide visibility ticket, quiesces every strict participant, applies
to XFS, drives each peer's repair, and collects acknowledgements before it
returns. With one mount attached this is close to free. With several, a mutation
costs a round trip to the slowest participant, and the slowest participant is
bounded only by its declared repair budget. Metadata-heavy workloads across many
mounts are where this shows, and no one has measured how much.

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

Five harnesses live under `vcs/bench/cmd`. None of them is an end-to-end
throughput benchmark, and none is wired into a gate.

| Tool | What it measures |
| --- | --- |
| `fsops` | Per-syscall latency distributions against a mounted workspace or a plain POSIX directory. Designed to be read against a measured network RTT: roughly one RTT means one round trip, and well under one RTT means the operation was served without the wire. Probe, enumeration, and bulk-write phases. |
| `netprobe` | The protocol-free network floor to an authority endpoint: TCP connect RTT, TLS handshake cost, sustained upload throughput. This is the lower bound any protocol number must be attributed against. It writes nothing and holds no state. |
| `tracestat` | Round trips per operation, derived from a `portablefsd` trace by subtracting daemon-side service time from observed wire round trips. Read-only. |
| `pfs-mount-stress` | A cross-mount stress workload with hashed content and peer done-markers. It polls by enumerating the parent rather than by `stat`, deliberately, because a cached negative dentry on macOS is permanent. |
| `zratio` | Compressibility and content-defined chunk dedup potential of a real agent corpus. It still runs, but its framing was written against the deleted write-back flusher's batch granularity, so read it as a corpus measurement rather than as a statement about any current code path. |

The v2 harness drivers (`vcs/bench/run.sh`, `prod-flush-rate.sh`, the weekly
advisory `perf` workflow) and the frozen v2 result files were removed with the
architecture they measured. The surviving tools above are the v3 measurement
starting point; no v3 benchmark numbers have been published yet.

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

1. **An end-to-end v3 workload harness.** `fsops` measures syscalls and
   `netprobe` measures the wire; nothing measures a repository checkout, a
   compiler run, or a metadata storm end to end against a v3 authority.
2. **The XFS comparison.** The honest baseline for this product is the same
   workload on the authority's local XFS, because that is the ceiling PortableFS
   is approaching from below. Proof gate 6 in
   [xfs-authority-architecture.md](./xfs-authority-architecture.md) is exactly
   this, and it is open.
3. **Per-RPC observability at the authority.** Several claims one would want to
   make — that a strict path walk avoids lookups, that a routed directory reaches
   the authority zero times — are claims about work performed, and the authority
   exports no production per-RPC counter to check them against. The coherence
   matrix records this as an unmet observability gate.
4. **Multi-participant barrier latency.** The one cost unique to v3's coherence
   design is unmeasured. It needs several real mounts, a metadata-heavy workload,
   and a distribution rather than a mean.
5. **A macOS number of any kind.** The macOS path has open live-kernel gates
   ([macos-26-coherence-contract.md](./macos-26-coherence-contract.md)); measuring
   it before those are met would measure something that is not yet the product.

Until those exist, the correct answer to "how fast is it" is that it has not been
measured, and the correct thing to do is to run `netprobe` and `fsops` against
your own deployment and read them against your own RTT.
