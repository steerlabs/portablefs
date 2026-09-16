# Coherence v2 implementation plan

Authoritative design: `docs/coherence-v2/design.md` (same content as `design.html`). Read it
in full before touching code. This file is the execution contract: who owns which files,
the shared vocabulary every workstream must use, and the definition of done.

## Ground rules (apply to every workstream)

- Branch base: `coherence-v2` from `origin/main` `67c52ef`. Each workstream works in its own
  git worktree and branch (`cv2-<stream>`), commits with DCO (`git commit -s`), no
  emojis, `gofmt`-clean, table-driven tests, errors wrapped with context.
- This is protocol major **7**. The wire is frozen per COMPATIBILITY.md: v7 gets a new ALPN
  (`portablefs-authority-v7`) and a new protocol major; v6 is refused at the handshake. Inside v7
  we evolve the proto additively (new messages and fields); the v6 lease-family fields stay in
  the .proto for decoding history but are never sent or honoured on v7.
- No fallbacks, no modes, no compatibility shims between v6 and v7 semantics inside a running
  process. Old code paths are deleted, not gated.
- Tests are required for every behaviour: unit tests that fail without the change, and for
  anything touching the frontend, authority, or protocol, the privileged Docker suites
  (`bash scripts/xfs-fuse-integration.sh`, `bash scripts/coherence-matrix-linux.sh`, or the
  full gate `bash scripts/verify-local.sh --full`). Docker is available on this machine
  (4 CPU, 8 GiB Linux VM). Run a single Linux test with
  `PORTABLEFS_GO_TEST_FLAGS='-run ^TestName$' bash scripts/xfs-fuse-integration.sh` and read the
  streamed `--- PASS` lines; the final required-test check will complain about unrun tests,
  which is expected for a focused run.
- Build both targets before claiming done: `CGO_ENABLED=1 GOOS=darwin go -C vcs build ./...` and
  `CGO_ENABLED=0 GOOS=linux go -C vcs build ./...`, plus `go -C vcs vet ./...` and
  `go -C vcs test ./...` (macOS-runnable packages).
- Do not touch files owned by another workstream. If you need an interface from another
  stream, define it in your own package as a Go interface and document it in your final
  report so the integration stream can wire it.
- Performance is a requirement, not a follow-up: no per-operation allocations on hot paths that
  can be avoided, no O(n) scans where an index is natural, no global mutex held across I/O.
  Add benchmarks for hot paths.
- Final report format (in the last message): what was built, file list, how it was tested
  (exact commands and results), interfaces exposed for other streams, known gaps.

## Shared vocabulary

- **Identity**: the 16-byte stable identity of a file (XFS export handle + type), as today.
- **Session**: one attached mount (one participant). Has an epoch-scoped session id and generation.
- **Subscription**: one per session, volume-wide. Fields: watermark (volume version at
  subscribe), TTL horizon (10 s, renewed every 3 s), incarnation (increments on every
  resubscribe). Ack is cumulative by **stream position** and means "every entry through this
  position is fully withdrawn on this client, in this incarnation".
- **Change entry**: `{position, volume_version, kind, identity, parent_identity, name}`
  where kind is one of: namespace-changed (a (parent,name) binding added/removed/replaced),
  attributes-changed (identity), data-changed (identity, optional byte range),
  delegation-granted (identity: stop caching it), delegation-released (identity: may cache
  again), directory-changed (identity of the directory whose listing is stale).
- **Delegation**: `{id, identity, holder session, generation, mode}`; mode is `full`
  (holder buffers) or `writethrough` (some other session holds a cache-capable handle on
  the identity). Exactly one holder per identity. Life cycle: reserved -> granted ->
  (downgraded|upgraded)* -> (released|recalled|expired).
- **Cache-capable handle**: an open handle a session opened with kernel caching allowed
  (FOPEN_KEEP_CACHE). The Authority counts these per (identity, session). A handle opened
  while a delegation exists on the identity is never cache-capable.
- **Break for read**: Authority-side step before answering any operation that consumes a
  delegated identity's data, size, or attributes: ask the holder to flush that identity to an
  accepted-sequence cut, wait for the flush ack (or the holder's recall budget), then answer.
- **Recall**: two-phase withdrawal of a delegation (withdraw -> holder drains and flushes ->
  ack with applied sequence -> Authority reassigns). Budget 5 s. Missed budget: delegation
  dropped, holder's loss sequence advances.
- **Loss sequence**: per-mount monotonically increasing counter, advanced by any dropped
  buffered entry, stale-generation rejection, missed recall, or epoch change with non-durable
  entries outstanding. Observed through the directory-handle barrier.
- **Barrier**: `FUSE_FSYNCDIR` on a handle opened on the mount root. The daemon records the
  loss sequence at OPENDIR of the root; FSYNCDIR takes a cut of every accepted entry, waits for
  application and durability of the cut, and returns EIO if the loss sequence advanced since
  the open. Never built on `FUSE_SYNCFS`.
- **Entry states**: accepted (returned to the process) -> applied (Authority acked the
  write) -> visible (change delivered to subscribers or their horizons passed) -> durable
  (Authority fsync group covered it). Entries are retained until durable.

## State machines

### Delegation (Authority side, per identity)

```
none --(CREATE with write intent | OPEN for write | first WRITE/SETATTR-size/FALLOCATE
        from a session without one)--> reserved(holder=S)
reserved --(withdraw cache permission from every other subscriber: delegation-granted entry;
            wait ack-or-horizon)--> granted(S, gen=g, mode = writethrough if any other session
            holds a cache-capable handle on F, else full)
granted --(another session opens a cache-capable handle on F)--> impossible: such opens are
            direct-IO by rule; but a cache-capable handle opened BEFORE the grant makes mode
            = writethrough until that session closes it, then mode = full (upgrade is an
            entry to the holder)
granted --(peer data-consuming op)--> break-for-read (holder flushes cut) --> granted
granted --(peer data-mutating op)--> recalling --(holder acks)--> granted(peer)
granted --(holder releases: last handle closed and flushed)--> none, delegation-released entry
granted --(holder misses recall budget | session expires)--> none; peers proceed
```

### Subscription (Authority side, per session)

```
subscribe -> {watermark, delegated identity set, incarnation}
entries appended per committed op / delegation event; streamed in batches on CONTROL
ack(position) cumulative; an op or grant that needs withdrawal from session S waits for
  S.acked >= entry.position OR now >= S.horizon
renew every 3 s; horizon = last renew + 10 s
horizon passed -> session fenced (all requests refused until resubscribe); resubscribe
  requires the client to have invalidated everything; new incarnation
```

### Buffered entry (client side)

```
accepted --flush--> applied --(change delivered)--> visible --(durable seq >= entry)--> durable (retired)
accepted --(recall missed | stale generation | epoch change)--> lost (loss sequence++, EIO on handle)
```

## Workstreams

### A. Wire: protocol 7 (`proto/`, `vcs/internal/authorityrpc/protocol.go`, generated pb, handshake)
Owner files: `proto/authority/v1/authority.proto`, `vcs/internal/authorityrpc/protocol.go`,
`vcs/internal/authorityrpc/authorityv1/*.pb.go` (or wherever generated code lives),
`scripts/generate-authority-proto.sh`, `COMPATIBILITY.md`, `docs/coherence-v2/wire.md`.
Deliver: the v7 message set for subscription, change stream, delegation (in CREATE/OPEN
requests and replies, FLUSH-carried id+generation, recall/break events), durable sequence on
write/fsync replies, barrier RPC, cache-capable handle flag on OPEN/CREATE, and the handshake
change (ALPN, major, feature strings). Encoding tests and a `wire.md` that documents every
message and its ordering rules. Do not implement server or client behaviour.

### B. Client write buffer (`vcs/internal/writeback/`, new, pure Go, all platforms)
Deliver a package with: admission (per-mount caps: 64 MiB dirty, 10,000 entries; block, not
fail, at cap), per-identity ordered entries (write ranges, truncate, setattr) with coalescing of
adjacent/overlapping ranges, an extent map for O(log n) overlay reads (dirty ranges over a
fetched image), generation cut (stop admitting under a retiring generation, drain in-flight),
flush scheduling (timer 1 s, cap, explicit flush of one identity or a cut of everything),
four-state tracking and retirement on a durable sequence, O_SYNC waits, the loss sequence,
barrier cut semantics, and a `Flusher` interface the integration stream implements against the
wire. Exhaustive table tests, property/fuzz tests for the extent map and coalescing,
race-detector clean, benchmarks (sequential 4 KiB writes, random writes, overlay reads).

### C. Authority coordinator (`vcs/internal/volumeserver/`, new files only, pure Go)
Deliver `subscription.go` (change stream with batching, cumulative acks, horizons, fencing,
incarnations, ack-or-horizon waits that never hold the commit lock), `delegation.go` (the
delegation state machine above, cache-capable handle accounting per (identity, session),
reserve/withdraw/grant, break-for-read and recall orchestration on separate lanes, release in
batches, budgets), and the hooks the mutation path needs (`OnCommit(changeEntries)`, "needs
withdrawal from sessions X before commit ack"). Reuse the mutation sequencer's dependency
model; do not modify `leases.go`, `visibility.go`, or `locks.go` in this stream. Deadlock
freedom argued in comments and tested (recall during pending withdrawal, overlapping
requests, partitioned subscriber, holder expiry). Benchmarks for entry append/ack and
delegation lookup. Table tests for every transition.

### D. Gate removal (`vcs/internal/fusev3/source_publication_linux.go` and its tests)
Delete the two mount-wide predicates (`unresolvedSourceOverlapLocked`,
`unresolvedGateOverlapsSourceHoldsLocked`, and the mount-wide scan in
`sourcePublicationsBusyLocked`) so gating is exact-coordinate only, keyed per identity and
per (parent,name). Keep the per-identity keyed drain of cache-installing replies (design rule
F12). Prove with a new Linux test that creates in two different directories overlap in time
(both in flight at the Authority at once) and that same-file writes still serialize. Run the
focused coherence tests listed in `docs/coherence-v2/PLAN.md` section "Focused tests" in the
Docker suite and the full `scripts/coherence-matrix-linux.sh`.

### E. Proofs and baseline (`vcs/internal/fusev3/*_proof_linux_test.go`, `vcs/bench/`, `scripts/`)
1. Kernel proof 1: a Linux test that, on a stock FUSE mount with write-back off, maps a file
   MAP_PRIVATE and holds a read fd, issues `notify_inval_inode` from the daemon, and shows that
   after the notify returns both a page fault and a `read(2)` reach the daemon (count daemon READ
   requests). Also show the mapped-page case and the in-flight-read case. 2. Kernel proof 2: a
   test that `fsync` on a directory fd reaches the daemon as FSYNCDIR carrying the handle from
   OPENDIR, and that `syncfs(2)` does NOT reach the daemon. 3. Baseline benchmark harness
   (`vcs/bench/cmd/coherence-bench`): 40,000-file install with 1 and 8 workers, cold and warm
   `git status` over a 20,000-file tree, and a two-mount test (one writes, the other lists and
   reads); reports round trips per op (from Authority metrics) and wall time versus direct
   XFS on the same host. Run it against current `origin/main` in the Docker suite and commit the
   numbers to `docs/coherence-v2/baseline.md`.

### F. Integration (after A, B, C land): client subscription + delegation in `fusev3`
Replace the N/A/E/D lease families with the subscription cache; wire delegations into
open/create/write/setattr/fsync/close; break/recall handling; the dirty-range overlay for the
holder's own reads and the per-write kernel invalidation when a cacheable read handle is open;
direct-IO handles for peers on delegated files; write-through downgrade; the barrier via
OPENDIR/FSYNCDIR on the root; stale-all-handles on epoch change with cold re-attach; delete
the watchdog abort and every coherence-caused `revoke()`. Then the Authority side of the same in
`authorityrpc` (mapping wire <-> volumeserver coordinator), deleting the v6 lease grant paths.

### G. Verification and deletion
Full Docker suites, coherence matrix (update the 23 cases to v7 semantics; every case must
still pass or be replaced by a stronger one), benchmarks after, `docs/performance.md` update,
delete dead code, update `docs/portable-coherence.md` to describe v7.

## Focused tests (existing, must keep passing or be replaced with a stronger equivalent)

fusev3: TestSuccessorGrantLosingToAnEarlierPeerRecallIsNotInstalled,
TestBlockingReadNeverFailsWhileAPeerRewritesTheFile,
TestSaturatedBulkLaneDoesNotStallASourcePurge,
TestRepeatedOpenForReadRacingAPeerWriteKeepsBothMountsServing,
TestDependencyTreeInstallRacingEnumeratingReadersKeepsBothMountsServing,
TestConcurrentCrossMountWritersToOneFile, TestRemoteWriteIsRepairedBeforeTheWritersCallReturns,
TestPagedReaddirReturnsEveryNameExactlyOnce, TestOpenCacheModeFollowsDataLeaseAndWriteCapability.
volumeserver: everything in leases_test.go, locks_test.go, visibility_*_test.go,
mutation_sequencer_test.go.
