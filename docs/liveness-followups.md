# Liveness and coherence follow-ups (post 2026-07-30 incident)

Running ledger of the root-cause items surfaced by the incident and its
validation campaign. Updated as of the fix/root-architecture branch.

## Open

### 2. Path-scoped delegations vs inode-shared FSItems (documented boundary)

A handoff for scope S that has already passed the frontend gate cannot be
re-blocked when an active operation subsequently discovers a hard-link
alias inside S. The old mount-wide operation scopes masked this without
fixing it (attribute reads are delegated per path, not per inode).
Closing it properly means extending an operation's scope post-reply
before publication — which would block on the gate while holding
frontendSerial and deadlock against namespace writers. Needs a design
that decouples alias discovery from the publication gate; do not patch.

### 3. Legacy WAL store checkpoint drops birthtime/flags

The dev/self-host legacy store's manifest checkpoint (`backend.Entry`)
carries no birthtime or flags, so a checkpoint→reload round trip loses
them there. The managed authority is unaffected (its durability is the
PFJ3 journal + PFT2 tree). Fix when the legacy store next changes shape.

### 4. Multi-group setattr is per-group exact, not request-atomic

A combined setattr (size+mode+owner+times+flags) splits into up to five
exact identities sent sequentially. Statically knowable refusals
(capability gates, shape validation) are preflighted before anything
applies, but a later group can still fail — definitely (another session
raced a remove: ENOENT/ESTALE) or indeterminately (transport) — after an
earlier group committed. The window predates the flags work (chmod+chown
have had it since exact sessions). Root direction: an authority-side
atomic setattr batch — one syscall outcome, per-group exact
sub-identities in a single journal record. Design it with the format
machinery; do not paper it with ordering.

### 5. Mount intent for a nonexistent branch cannot reconcile

Reproduced live: a mount attempt against a branch that does not exist
leaves a "starting" operation intent whose release replays the exact
access-lease create — which can only ever return branch-not-found, so
the intent is permanently stuck (umount and umount --force both loop).
Two root fixes: the server should answer lease-create for a missing
branch with a clean typed 404 (today the journal child spawns, gets
VOLUME_BRANCH_NOT_FOUND from the volume API, dies, and the manager
reports a generic internal error after a bootstrap crash-loop); and the
client's reconcile should treat a definite branch-absence as proof the
lease cannot exist, releasing the intent. Related transient: lease
creation in the first ~2 minutes after an authority singleton handoff
can fail UPSTREAM_UNREACHABLE (502) while the router warms; the intent
machinery preserves and later reconciles these correctly, but deploy
tooling should gate on a lease-create probe, not just /readyz.

### 6. (FIXED on fix/root-architecture — see the Fixed list) Handle close
drained its backlog inside the op pipeline. All three root fixes landed:
close(2) returns after WAL admission (fsync remains the durability
barrier), drain completion survives frontend death (permanently-suspended
non-publishing continuations), and the CLI umount preflight classifies
EIO/ETIMEDOUT-with-live-attach as the daemon-owned detach case.

### 9. Unify the pre-lock credit grant with the WAL reservation

The pre-lock lane classifier guarantees a granted write performs no RPC,
transition, or wait under frontend locks; a granted write that still
finds the exact framed-byte reservation full (errDataHeadroom — the
credit ledger counts payload bytes, the WAL counts framed bytes plus
unreclaimed segments) unwinds via ErrLaneChanged with locks released and
retakes the authority lane. Bounded and correct, but the residue is
structural: making errDataHeadroom impossible for a granted write means
the grant must BE the reservation (one ledger, framed units, rotation
cost reserved at grant). Deferred only because it collides with the
control-reserve rewrite landed in the same change set; top follow-up.

### 10. Production recovery gaps (2026-07-31 Railway Postgres outage)

The fencing design held (no split-brain, every acknowledged write
durable), but a ~2-minute database outage became a ~40-minute admission
outage because of three recovery gaps, all root-fixable:
- an authority-manager that fences itself (claim-deadline-exceeded) must
  EXIT so the platform restarts it into a fresh epoch claim — epoch 29
  hung fenced with the process alive and no successor for 40+ minutes;
- volume-api crashed applying metadata migrations while Postgres was
  still in crash recovery and stayed dead (no retry, no platform
  restart) — startup must retry-until-ready or fail the deploy;
- the client daemon wedges silently when its access lease dies:
  pendingBytes frozen, degraded unset, lastFailure empty,
  unmarkOpenBatchManaged in an unbounded retry, and processes on the
  mount left in uninterruptible D state until force-detach. Lease death
  must surface as a definite degraded state with the parked-job path
  engaged, not a silent stall.
Related: §5 already records that deploy tooling must gate on a
lease-create probe, not /readyz.

### 7. Transient ENODATA reading a peer's just-created file

Observed once (two-Mac stress): `read peer done marker: no message
available on STREAM` immediately after the file became visible; retry
succeeded implicitly. Not yet reproduced or root-caused; needs a repro
with daemon tracing before any code changes.

### 8. macOS FSKit platform gaps (Apple; Feedback radars to file)

Kernel-verified on macOS 26:
- Negative dentries are cached permanently: no revalidation against
  parent attributes and no invalidation API, so a pre-creation lookup
  blinds that machine to the name until a LOCAL mutation purges the
  directory's cache. Cross-machine "stat-poll until it appears" cannot
  work; enumeration always consults the filesystem and is the supported
  discovery pattern.
- No advisory-lock operations: cross-machine fcntl exclusion is
  impossible. The supported cross-machine mutual-exclusion primitive is
  O_EXCL create (authority-serialized, exactly-once).
- FSVolumeOpenModes carries no append intent and writes arrive with
  kernel-resolved offsets, so cross-machine O_APPEND interleaving is
  impossible on FSKit (FUSE mounts get true authority-assigned append
  offsets). Use per-writer files or write-tmp+rename.
- Replacing or re-registering an app that hosts an FSKit extension makes
  pkd SIGTERM the running extension instance, killing every live mount
  mid-write. Installers/updaters must drain mounts first.
These belong in user-facing consistency documentation as contracts, with
radars for the API gaps.

## Fixed on fix/root-architecture (round 3)

- **Internal coherence refreshes are distinguished by PROVENANCE, not by a
  clock**: the daemon's own kernel-size refresh installs a marker that is PINNED
  for the whole of its synchronous `ftruncate(2)` and retired by sequence number
  when that syscall returns. The marker used to carry a 5s wall-clock TTL, and
  the resulting FSKit setattr upcall travels the frontend dispatcher, where
  metadata admission can park it far longer than that; when it did, the handler
  reinterpreted the daemon's own no-op as an APPLICATION truncate and sent it to
  the authority, destroying every byte a concurrent writer had appended past the
  sampled size. Elapsed time now cannot decide provenance at all, and a pending
  internal refresh BYPASSES mutation admission outright: it publishes state the
  authority has already applied, so it neither caused the backlog nor can help
  drain it.
- **One dispatcher-ordering contract for every daemon request**: deadline →
  pre-lock admission (holding nothing) → publication membership and the frontend
  mirrors → nonblocking revalidate + mutate. Mutation admission used to run
  INSIDE `lockFrontendRequest`, so a metadata-lane park held the frontend
  serialization lock, the name stripes and a per-handle frontend RLock — and a
  `close(2)` needing that handle gate exclusively queued behind it. The unwind
  obeys the same contract: it drops the mirrors and suspends the request out of
  the publication set before re-admitting.
- **Semantic authority diversions are classified pre-lock**: link,
  unlink-while-open, rename-over-an-open-destination and setattr on a
  hard-linked inode are authority-only by SEMANTICS, not by path coverage, and
  they now force the authority lane in the classifier (`MutationIntent`).
  Structurally, `beginAuthorityMutation` answers `ErrLaneChanged` for any
  classified operation whose resolved lane is delegated, and every remaining
  under-lock release goes through one lane-aware gate, so no blocking drain is
  reachable beneath `nsMu`, a name stripe or a handle lock by any route.
- **The live control API is a frontend**: control mutations take the operation
  deadline and their pre-lock admission before `lockExternalNamespaceWrite`, and
  the locked region does nonblocking revalidation and the mutation only. It used
  to hold the mount-wide EXCLUSIVE namespace gate across a transition claim and a
  delegation release, with the raw HTTP context and no bound — which also
  inverted the one global lock order the rest of the daemon depends on.
- **FUSE writes share one absolute deadline across every unwind pass**:
  `WithOperationDeadline` is installed once in `fuseNode.Write`, outside the
  loop. `AdmitWrite` installs it idempotently, so a loop handing it a
  deadline-free context got a fresh 50s bound per pass and the passes composed
  past the kernel ceiling.
- **Legacy close-out is PEAK-bounded**: the reclaim path's preconditions now
  include the transient peak at the marker barrier (`used + appliedBytes <=
  budget`), decided before a single byte is written, and a physical ENOSPC from
  any close-out append becomes the typed definite `CLOSE_OUT_UNBOUNDED` conflict
  instead of an `errRetryable` that failed every attach forever with the grants
  stranded. Mark-before-reclaim ordering is unchanged and load-bearing (`digestAt`
  cannot rebuild a digest across segments that are already gone).
- **A release drains its OWN scope's tail, not the whole stream**:
  `finishRelease` targeted `w.LastSeq()` — the last sequence of the shared
  stream — so releasing an already-applied metadata scope waited behind every
  byte another scope had appended since. With the data lane deliberately holding
  a backlog at its credit setpoint that was worth 25-30s per transition, and
  `Engine.admit` takes exactly that transition whenever a mutation lands outside
  the current grant, i.e. whenever a workload walks into a fresh directory.
  Measured live: cold-scope mkdir/rmdir/open_creat blocked 26.6s/27.5s/48.7s,
  each returning precisely when the whole backlog hit zero. The flusher already
  indexes pending records by scope, so the drain target is now that scope's own
  last unshipped sequence (`flusher.scopeTail`), and zero when it has none.
- **A release drain reaches a verdict**: `finishRelease` runs detached under the
  engine lifetime context, and `drainThrough` had no bound of its own, so an
  authority that stopped applying left the scope `draining` forever with
  `drainErr` never set — the one state with no exit. `drainThrough` now consults
  the watchdog (`StallVerdict`), returns `ErrUplinkStalled`, and the scope leaves
  draining with a recorded reason that later callers get as a typed failure
  instead of an unbounded wait. `DelegationStatus` reports `Draining` and
  `DrainError` as mutually exclusive: in flight, or answered.
- **Forced detach fences before it locks**: `attach.detach` took
  `frontendSerial` and `nsMu` unconditionally, ahead of the `force` branch, so
  `umount --force` queued behind the very work it exists to abandon (observed
  live: one 12-minute nsMu writer with ~100 frontend goroutines behind it, five
  consecutive force-unmount timeouts, recovery only by killing the daemon). The
  forced path now parks the tail and fences first and takes the namespace locks
  only for the terminal transition. Both unmount paths also name ONE next action
  for a prepared detach instead of two unrelated refusals.
- **One shared stall verdict**: `Engine.StallVerdict` publishes the flusher
  watchdog's live state, and both admission gates consult it at budget expiry
  instead of inferring a verdict from copied duration constants. The old
  `30 + 5 < 40` argument does not prove the verdict — `advance` resets
  `lastProgress`, so a late advance pushes the earliest possible declaration well
  past the budget — and the data lane's expiry used to divert into what could be
  a dead far end on the strength of it.

## Fixed on fix/root-architecture

- **One global lock order for every path-bearing transition** (closes the old
  Open §1): the delegation transition claim is taken BEFORE the frontend's
  namespace lock, for the namespace lane as well as the data lane
  (`clientcore.AdmitMutation` + `writeback.Engine.PrepareDelegatedMutation`,
  called from the daemon's single request dispatcher and from each FUSE
  mutation). The classifier holds that claim through the locked mutation as a
  TOKEN, so no acquisition can install a grant in the window the pre-lock
  release opens, and `beginAuthorityMutation` is reduced to a pure coverage
  CHECK that answers `ErrLaneChanged` — never a wait, never a drain — inside
  the locks. Order: claim → nsMu → handle/inode locks → e.mu → WAL mutex.
- **One absolute operation deadline**: `operationAdmissionBudget` (50s) is
  installed once, outside the unwind loop, and covers classification, credit
  or metadata backpressure, the delegation release a lane diversion needs, and
  the authority RPC. Per-stage budgets compose (40s credit + an unbounded
  post-expiry drain could exceed the 60s kernel ceiling); this one does not.
  Chain: 30s + 5s < 40s < 50s < 60s.
- **Namespace-lane backpressure** (the other half of the old Open §1): a
  delegated namespace mutation that finds the metadata lane momentarily full is
  answered `errMetadataHeadroom` (an `ErrLaneChanged`) under `e.mu` and paces on
  applied progress OUTSIDE every lock in `Engine.AdmitMetadataMutation`, bounded
  by the same watchdog-proved 40s budget. It used to be an instant fatal EIO on
  a healthy, advancing mount, whose only recovery was an application retry.
  `ErrUplinkStalled` now comes only from the watchdog; ENOSPC stays where the
  exact payload sizes are known (the WAL reservation).
- **An unclassified authority status is retryable, not terminal**: the flusher
  parks a stream as a terminal `ErrConflict` only for a PROVEN contradiction
  about the batch's own content (EINVAL typed corruption, EPERM out-of-scope
  records) and fences on ESTALE; every other status — including the authority's
  catch-all EIO and any status a future authority adds — retries under the
  no-progress watchdog. One status-5 reply used to latch `ErrFailedClosed` and
  take a live mount to EIO permanently with its backlog undrained. The authority
  side no longer emits that catch-all for a flush apply failure either: an
  authority-machinery failure answers the typed retryable EAGAIN (the existing
  wire value, because pre-fix clients park on any code they do not recognise).
- **Legacy PFW5 streams reach a definite recovery outcome**: control-frame field
  caps are ADMISSION-only; values already durable in a stream are re-emitted
  through a durable encoder bounded only by the frozen frame decoder, and the
  recovery close-out is budget-aware and crash-safe (exact costs, reclaim the
  fully-applied prefix, typed terminal conflict rather than an unbounded retry).
- **Credit occupancy and debt are one atomic state**: the fast path can no
  longer commit an admission decided against a queue snapshot taken before a
  waiter published itself.
- **Zero committed progress is EIO on both frontends**: a non-empty write that
  commits nothing is never answered as a successful zero-byte write (there is no
  such POSIX outcome); positive counts remain short writes.
- **Drain-time credit controller (write backpressure)**: the instant-
  ENOSPC cliff at the WAL budget is gone. Writes burst to a setpoint
  (measured authority-applied rate × 25s drain target, capped at the
  hard budget) then pace to the uplink; the hard budget remains the sole
  bound via the untouched reservation ledger, now extended so every
  on-disk append — including delegation/release/lifecycle control frames
  — reserves inside the cap (bounded control reserve, worst case &lt;1% of
  a 512 MiB cap). Metadata rides a reserved lane and is never
  credit-charged; transient lane exhaustion is EIO-class (the store
  isn't full), ENOSPC is reserved for operations that can never fit.
  Live-validated: burst-then-pace at the applied rate, 25.3s measured
  drain vs the 25s target, zero ENOSPC past the old 2 GiB cliff.
- **Pre-lock lane classification**: every frontend write resolves its
  lane exactly once from node identity BEFORE any frontend lock
  (Volume.AdmitWrite + Engine.PrepareDelegatedWrite hoists delegation
  transitions outside the locks); under the locks the engine only
  checks, and staleness unwinds with all locks released (ErrLaneChanged
  → reclassify, at most two passes). Orphan/hardlink/pathless writes are
  never charged. A write that cannot obtain delegated credit within a
  40s admission budget (provably after the 30s no-progress watchdog
  would have declared a real stall) succeeds via the authority lane —
  a slow-but-healthy uplink is never reported as stalled.
- **Close is local bookkeeping**: close(2) returns after WAL admission
  (fsync is the durability barrier), never joins exactMu, and the
  engine-owned drain survives frontend death; CLI umount classifies
  dead-volume residue (EIO/ETIMEDOUT with a live attach) definitively.
- **Committed progress is never reported as failure**: the write reply's
  count is decided by the write; a failed post-commit attribute refresh
  answers from the already-published item (closing an O_APPEND
  duplication path). Short writes propagate end-to-end.

- **parkExact claim transfer**: an exact identity that may have been sent
  now reaches a definite outcome before the exclusion it was issued under
  is released to anyone else. The park takes refcounted ownership of the
  caller's release (all three park sites); fence and client teardown are
  definite outcomes, and Close joins every replayer after fencing.
- **Recall-path lock order**: the recall/invalidation path never blocks
  on a NodeState mutex while holding attach.mu (onMarkOrphan collects
  under a.mu, marks outside it; NodeState.orphanIno is atomic so guards
  read it lock-free). Invariant documented at both a.mu sites and
  enforced by deterministic interleaving tests.
- **Operation scopes**: name-mutating operations report precise
  publication scopes covering every known hard-link alias, and binding
  changes bump a path epoch that conservatively widens still-active
  operations. Lookup and Enumerate deliberately REMAIN mount-wide: they
  publish per-inode attributes through per-path delegations, and a
  narrowed scope can race an already-passed handoff of a hard-link
  alias (see Open §2 for the inode-identity gate that would make
  narrowing sound).
- **FUSE publication suspension**: the ReplyGate suspends a request's
  admissions for the length of an authority-bound wait and re-admits
  through the same predicate reads already use; a canceled resume revokes
  the reply (EINTR) rather than publishing unaccounted bytes. The
  advisory-lock lane now genuinely suspends.
- **Data-plane backpressure**: a data mutation is acknowledged locally or
  refused with a definite ENOSPC; it never initiates or joins a
  delegation drain. Fsync of admitted data still drains (that is the
  relief path). Write-through data on a full local store is unaffected.
- **Dead-volume detach**: mount identification uses the kernel mount
  table (Darwin getfsstat / Linux mountinfo), never a stat through the
  possibly-dead filesystem, so a kernel-dead volume with a live daemon
  detaches exactly like a live one.
- **Authority persists birthtime and flags**: PFT2 inode fields 14/15
  (forward-only append, byte-identical goldens for old shapes), creation
  stamps birth from the record's ordered op time, Setattr persists the
  full flag word via wal OpChflags, FeatureFlagPersistence advertised.
  Zero still means "unknown" (old inodes), never 1970.

## Fixed on fix/root-liveness-metadata (merged as PR #28)

- Daemon unmount kernel-reentrancy self-deadlock (admission freeze no
  longer spans unmount(2); reclaim is teardown-safe).
- Mutation-side publication suspension (delegation-acquire, exact
  exclusion, transition-gate admission).
- Invalidation subscription anchor + attach lifetime context (peer
  creates visible in ~1s instead of minutes/never).
- Enumeration paging (stateless name-cursor cookies; verifier stable
  across continuations).
- Append intent carried end-to-end (authority-assigned offsets; FSKit
  kernel remains unable to express it).
- FSKit metadata contract (exact masks, canonical hard-link parents,
  logical AllocSize, honest flags, true ".." identity, tolerant
  unsupported attributes).
- Unlock ownership surrendered per path only after definite authority
  release; delegation-gate EAGAIN retried under suspension instead of
  surfacing errno 35.
