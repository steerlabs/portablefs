# Replicated Readable Store Exploration

Status: design only. This document proposes an additive experiment; it does
not change the v2 architecture or compatibility contract.

## Decision summary

Do not replace the journal architecture now. Finish the active validation
campaign, and in parallel build one narrow, failure-first prototype of a
three-AZ replicated readable store behind the existing `fsproto` server. The
prototype is worth doing because it can remove the measured coupling between
history publication and authority memory. It is not yet evidence that
PortableFS should operate a distributed storage service.

The prototype must test the remote-durable design first. A single-node local
store, or a replicated service tested only on the happy path, answers none of
the deciding questions. The first useful artifact is a three-replica system
that is continuously crashed, partitioned, corrupted, and repaired while
exact operations run. Only after that survives should it be connected to FUSE
and FSKit and compared with the current authority using the same batteries.

## The trade PortableFS would make

**A replicated remote tier gives up PortableFS's local-first durability
acknowledgement.** Today a delegated writer can acknowledge from its local
write-back journal without a network round trip; the remote authority barrier
arrives on `fsync`, synchronize, or clean unmount. A pure replicated-readable
design cannot make the same latency promise. Its durable acknowledgement must
cross the network and reach a write quorum. This is not an implementation
detail. It removes the product's actual differentiator.

There are two honest contracts:

1. **Remote-durable mode.** The authority denies write-back delegation grants.
   A successful mutating authority reply means the new materialized state and
   exact outcome are durable on a quorum in independent availability zones.
   `fsync` adds the existing client-visibility barrier but does not initiate a
   journal drain. This is the Archil-like contract and pays a network plus
   stable-storage round trip.
2. **Hybrid local-first mode.** Keep the existing client WAL and delegation
   protocol as a bounded write-back queue. Delegated `write(2)` remains local;
   `fsync` drains to the replicated readable tier. This is coherent and keeps
   local latency, but a writer-machine loss before the remote barrier can lose
   the undrained tail, other clients must recall/drain before overlapping it,
   and failover cannot recover bytes that exist only on the writer. It retains
   a journal, recovery jobs, and replay at the mount edge.

The hybrid does **not** recreate the current server problem: the remote tier
stores every drained transaction as readable state and does not hold authority
RAM until a cut. It does, however, retain much of the complicated local WAL
and handoff machinery. It should be described as local-first write-back over a
remote replicated filesystem, not as the same durability contract as the pure
mode. The comparison must report both modes separately.

## Proposed system

### Failure model and placement

The initial design is crash-fault tolerant, not Byzantine:

- processes, machines, disks, and one availability zone may fail or become
  unreachable;
- packets may be lost, duplicated, delayed, reordered, or partitioned;
- a process may stop at any persistence point and restart with only bytes that
  were actually synced;
- disk corruption is detectable by checksums and content hashes, but malicious
  replicas and a provider lying about independent failure domains are out of
  scope;
- loss of two voters, loss of a whole three-AZ region, or a correlated storage
  fault may make the volume unavailable or lose data newer than the last
  off-group export. Customer S3 is asynchronous and is not part of the normal
  write acknowledgement.

A replication group has three full, readable voters placed on three declared
availability-zone failure domains in one region. There are no witnesses: a
voter counted toward durability must hold a complete readable copy. A
placement service may assign many volumes to one group to avoid a consensus
group per idle volume, but a hot volume remains a separately movable unit.
Placement intent can live in Postgres; actual membership is committed by the
group and cannot be changed by a control-plane row alone.

Use a vetted crash-consensus implementation rather than designing a new one.
The application-specific work is the persistence acknowledgement described
below, membership policy, and the filesystem state machine. Consensus elects
one leader and establishes a total commit order. It replaces the current
Postgres journal claim as the data-plane fence; keeping both as independent
leaders would create two sources of truth.

### On-replica state and transaction shape

Each replica stores a sequence of immutable materialized state roots:

```text
StateCommit {
  group_id, term, index,
  parent_index, parent_root_digest,
  user_root_ref, recovery_root_ref,
  exact_outcome,
  transaction_digest
}
```

The user root contains files, directories, inode metadata, extents, xattrs,
and stable inode allocation. The recovery root contains exact session slots,
delegations, locks, open pins, parked orphans, write-back watermarks, and the
other PFC2 coordination state required to resume the live filesystem. The
exact operation outcome is committed with the state transition, preserving
the existing lost-reply rule.

The leading storage-format candidate is PFT2: apply the shared
`fstransition` semantics with `pft2.Editor`, write the changed immutable
objects to the replica's local object engine, and atomically install the two
new roots. Unchanged objects are shared. The replica's durable transaction
engine may have its own internal WAL; that is an implementation mechanism,
not a second authoritative mutation format. The important property is that a
restart opens the latest committed roots directly. It does not replay a
volume mutation history or wait for a fold before the bytes are readable.

Consensus still has a durable ordered log, stable term/vote metadata, and a
snapshot/truncation lifecycle. No crash-tolerant consensus design makes those
disappear. The difference from PFJ3 is that a vote is withheld until the log
payload has also become materialized readable state, and every committed root
is already a consensus snapshot boundary. Truncating consensus metadata does
not require constructing a second filesystem image, and restart need apply at
most a bounded committed-but-not-installed tail. If “no log and no replay” is
literal rather than “no separate mutation-only truth requiring a fold,” the
remote replicated design is impossible.

A proposal carries the canonical new object bytes and the state commit, not
only a partial-write intent. Followers verify the parent identity, object
sizes and hashes, and the transaction digest before persisting. Because the
failure model is non-Byzantine, followers need not independently execute every
filesystem operation before acknowledging, although the fault harness should
periodically recompute transitions and compare roots to detect implementation
divergence.

PFT2 is not assumed to win. Its deterministic packs and path-copying trees
were designed for cuts, not for a root on every small write. Per-transaction
metadata churn, immutable-object garbage collection, and rewriting a data
page for a small overwrite may make it the wrong live format. The fallback is
a checksummed transactional extent/metadata KV layout keyed by volume, inode,
dirent, block, xattr, and control identity, with PFT2 retained as the snapshot
and export format. That fallback still stores readable state before
acknowledgement, but snapshots and forks become more work. The prototype must
measure both the PFT2 write amplification and the cost of exporting a
consistent KV root before choosing.

### Write and acknowledgement protocol

For one exact `fsproto` mutation:

1. The router connects the mount to the current group leader. The request
   carries its existing exact session identity. A stale term or non-leader
   refuses and returns a leader hint; it never proxies an ambiguous mutation.
2. The leader establishes a linearizable read fence, checks the session slot,
   and evaluates the operation against the current committed roots. It stamps
   nondeterministic inputs such as operation time once, then builds the
   canonical materialized object delta and exact result.
3. The consensus proposal binds the previous state ID, new root IDs, object
   delta, and exact outcome. Concurrent proposals are ordered; group commit
   may batch independent operations without changing their individual
   indices or outcomes.
4. A replica votes the proposal durable only after every object needed by the
   new roots and the state-commit record is on stable local storage. Prepared
   roots remain invisible until committed. A replica missing the parent state
   cannot vote; it catches up first.
5. The leader acknowledges success only after it and at least one follower in
   a different declared AZ have durably installed the proposal and consensus
   has committed it. Thus two full readable copies exist at reply time.
6. The leader makes the new root visible, publishes commit-indexed cache
   invalidations, and records subscriber progress. `fsync`/synchronize waits
   until every live protocol subscriber has acknowledged the covering
   invalidations, as it does today. A dead or wedged subscriber is dropped
   under a bound rather than blocking the filesystem forever.

The acknowledgement promises: no successful mutation is lost after any one
replica or AZ failure; its exact retry returns the same outcome; the committed
state is readable without journal replay; and linearizable reads never expose
an uncommitted root. It does not promise survival of two simultaneous AZ
losses or a regional loss before asynchronous export.

At the storage protocol, this is strong read-after-write for every connected
client: any read that begins after a successful mutation reply obtains a read
index at least as new as that mutation. Frontend caches are a separate
boundary. The leader must publish the covering invalidation before replying,
and the existing `fsync`/synchronize barrier waits for subscribers to apply
it. A peer may still serve an ordinary pre-barrier cache hit under today's
documented contract.

The repository's current cross-client guarantee is precisely barrier-shaped,
not an unconditional statement about every cache hit: `fsync` and synchronize
wait for invalidation acknowledgements, while ordinary un-fsynced propagation
is asynchronous, and macOS FSKit has documented namespace/attribute cache
limits. The prototype must preserve that exact contract. If the product wants
every successful `write(2)` to be globally visible before reply, step 6 must
become mandatory for every mutation; that is a stronger contract whose slow
client amplification must be measured separately.

### Reads and read-after-write

Normal mounts read from the leader's local materialized state. The leader may
serve a read only after proving it is still leader to a quorum and after its
local applied index reaches the read index. A bounded leader lease may cache
that proof only if the chosen consensus implementation proves the lease safe;
otherwise use its read-index protocol. A follower read is allowed only after
obtaining the same read index from the leader and waiting until its local
applied index covers it. Stale follower reads are never used by mounted
clients.

Every response and invalidation carries the commit index. Client-side caches
remain version-gated through `clientcore`; reconnect discards state from an
old authority generation. Read repair is about integrity, not consistency: a
replica that cannot verify a local object may fetch the same digest from
another replica and repair it, but it must never answer from an older root.

### Exact failure behavior

| Event | Required behavior |
| --- | --- |
| Follower dies mid-write | It casts no persistence vote. If leader plus another follower commit, the operation succeeds. Otherwise the connection returns no definite mutation outcome and the exact identity is retried. |
| Leader dies before quorum persistence | No success was returned. A new leader discards or overwrites the uncommitted prepared root; the same exact request may then execute once. |
| Leader dies after quorum persistence but before reply | Quorum intersection carries the proposal into the next leader's committed history. Retrying the same identity returns the stored result; it never executes twice. |
| One member is lost after an acknowledged write | The remaining group elects only a member whose history is at least as current as every voter it can defeat. Before another write can be acknowledged, a second current full copy must be present. A lagging survivor installs the missing state first. Availability may pause; acknowledged data is not rolled back. |
| Network partition | Only the side with two of three voters may elect/retain a leader and serve linearizable reads or writes. The minority self-fences and closes mounts. With no majority the volume is unavailable. There is no last-writer-wins merge. |
| Replicas have different uncommitted tails | Consensus term/index rules select one tail. Losing prepared roots are unreachable garbage. |
| Replicas disagree on a committed root digest at the same term/index | This is corruption or a safety violation, not a conflict to merge. Quarantine the disagreeing replica and rebuild it when two healthy replicas agree. If no two agree, fail the group closed and require operator restore. |
| One local object fails verification | Stop serving that object, obtain and hash-verify the same digest from a healthy replica, then atomically repair. If no verified copy exists, return an integrity error and quarantine the group rather than serve stale or invented bytes. |
| Client reaches an old leader | Term-fenced handshake or proposal fails. The client reconnects through the router and replays any unknown exact identity. |

### Catch-up, repair, and rebalancing

A replica reports its last committed `(term, index, root digests)` and the
state-chain digest. If that point is on the leader's retained chain, the
leader streams missing materialized transaction bundles. If the replica is
too old, new, or divergent, it installs a snapshot by walking the leader's
current immutable roots and transferring only missing content-addressed
objects, then atomically adopts that state index. It does not replay
filesystem intents from genesis.

Object-level anti-entropy periodically compares rooted object inventories or
Merkle ranges, verifies bytes by digest, and repairs missing/corrupt objects.
State-chain comparison detects a wrong root even when individual objects are
well formed. Repair traffic is rate-limited and isolated from foreground
quorum writes.

Membership changes use learners and joint consensus:

1. place a learner in a new failure domain;
2. transfer and verify a complete current root, then catch up its tail;
3. promote it through a committed joint configuration;
4. remove the old voter through a second committed configuration.

A learner never counts toward write durability. The scheduler must enforce
disk high-water marks, reserve catch-up headroom, spread replicas across AZs,
and throttle concurrent moves. A node above the emergency watermark stops
accepting new placement and triggers relocation; if a quorum cannot allocate
the next transaction, writes fail with a capacity error. Direct store removes
the RAM/cut conservation problem, not the conservation law for disk capacity.

### Snapshots, forks, and customer object storage

With PFT2 live roots, a snapshot is a durable label on an already committed
root, not a cut. A fork starts from that immutable user root with a fresh inode
namespace and empty recovery/control root, preserving the current separation.
An exporter copies missing PFT2 objects and root metadata to the customer's S3
bucket asynchronously. Nothing in normal write acknowledgement waits for it.

If the live format is mutable KV instead, the replica engine must expose a
consistent MVCC snapshot and the exporter builds PFT2 from it. This resembles
materialization but is no longer a memory-release or restart prerequisite; it
can fail indefinitely while the online replicas continue to read their
materialized state.

There is still storage lifecycle work. Roots promised as snapshots/history
and objects not yet exported must stay pinned; unreachable immutable objects
must be garbage-collected. That is a simpler reachability/export frontier,
not the current journal reclamation horizon, but an exporter that falls
behind can eventually consume replica disk. The design removes the discrete
RAM release dependency; it does not make asynchronous capacity management
free.

## What disappears from the current path

These statements describe an eventual direct-store volume mode. The existing
v2 journal mode and its append-only migrations remain untouched while the
experiment runs.

- The Postgres mutation journal is no longer the live data truth:
  `vcs/internal/remotejournal`, PFJ3 append/read/claim/suspend handling, and
  `packages/metadata-db/src/journal.ts` leave the direct-store serving path.
  Postgres remains the control-plane metadata store.
- Cold start no longer loads a base and replays a suffix. The
  `runRemotePrimary` base-proof/replay path in `vcs/cmd/vcs/remote.go` is
  replaced by opening the replica's committed state root.
- HistoryCut capture, fold, ready publication, adoption, and physical journal
  reclamation are not needed to make live bytes readable or reclaim authority
  RAM. `vcs/internal/historycut`, the materialization half of
  `vcs/internal/histworker`, `vcs/cmd/history-worker` materialization, and the
  cut/adoption/reclamation portions of
  `packages/metadata-db/src/history.ts` and migrations 013-038 shrink out of
  this mode.
- The external dirty fold and its discrete adoption release disappear:
  `vcs/cmd/vcs/dirtyfold.go`, `vcs/internal/workfs/dirtyfold.go`, and the
  adopted-base polling/proof path are unnecessary.
- The dirty-RSS cliff, pacing controller, and their trigger coordination
  disappear from the live-store design:
  `vcs/internal/workfs/dirtyrss.go`, `dirtypace.go`, the
  `VCS_DIRTY_RSS_MAX_MB`/`VCS_DIRTY_PACE_PERCENT` behavior, and the manager's
  associated metric aggregation are not part of direct-store volumes.
- `apps/volume-api/src/history-maintenance.ts`, journal reclamation, recovery
  cut recreation, adoption serving pins, and the exact class of “cut relief
  cannot keep up with accepted writes” bugs disappear. Snapshot/export lag
  can still consume disk, but no cut timing holds live bytes in RAM.

`vcs/internal/workfs` does not simply survive unchanged. Its filesystem
semantics are valuable, but its in-memory inode/block representation and its
journal reservation/apply coupling are the current architecture. The
direct-store backend should extract the semantic transaction boundary rather
than wrap the entire existing `workfs.FS` around another log.

## What can be reused

- **Mount frontends unchanged:** `vcs/internal/fusefrontend`, the Linux
  `portablefs mount` frontend, `vcs/internal/portablefsd`,
  `vcs/internal/pfslocal`, and `swift/PortableFSKit`.
- **Client behavior unchanged:** `vcs/internal/clientcore`, including caches,
  invalidation application, handles, local dirs, and the optional local
  write-back engine. Pure remote mode denies delegation; hybrid mode uses it.
- **Wire unchanged:** `vcs/internal/fsproto` v8 and its exact identities. The
  server already presents a `billy.Filesystem` plus `SessionStore`,
  `CoordinationStore`, notifier, version, handle, orphan, xattr, and hard-link
  capability interfaces. Introduce one internal aggregate authority-state
  interface behind `fsproto.Server`; implement it once with current `workfs`
  and once with the replica store. Do not add a second frontend or test-only
  protocol.
- **Filesystem semantics:** `vcs/internal/fstransition`, `vcs/internal/pfc2`,
  inode allocation, exact-session outcomes, delegations, locks, open pins,
  rename-over-open, open-after-unlink, and deterministic validation. These
  transitions become the replicated state machine rather than journal replay
  state.
- **Immutable format and reads:** `vcs/internal/pft2`,
  `packages/core/src/pft2`, Go/TypeScript golden parity,
  `apps/volume-api/src/pft2-read.ts`, history serving, browse, and grep. Even
  if PFT2 loses as the live replica format, it remains the export, snapshot,
  and fork interchange.
- **Object verification:** `vcs/internal/histstore` exact-key hashing and much
  of the scrub/repair thinking can inform replica objects and customer-S3
  export. Replica repair needs a separate trust and membership model.
- **Control plane:** access leases, authentication, the stable router, tenant
  identities, CLI UX, volume metadata, and much of
  `apps/authority-manager`. The production registry changes from spawning one
  disposable journal child per branch to resolving the owning replication
  group and its leader.
- **Tests:** `scripts/live-mount-battery.sh` and
  `scripts/fskit-solo-battery.sh` must run byte-for-byte unchanged against
  both modes. Existing fsproto/clientcore tests for exact replies,
  reconnects, SQLite, Git, locks, delegations, rename-over-open, and
  open-after-unlink remain the semantic oracle.

The seam is therefore:

```text
FUSE / FSKit
    -> clientcore + optional local writeback
    -> fsproto v8
    -> fsproto.Server
    -> AuthorityState                       (new internal seam)
         current: workfs.FS + remotejournal.Log
         trial:   replicated materialized ReplicaStore
```

This is an internal refactor only. Because journal-born volumes, PFT2, the
`/v1` surface, environment names, and mount protocols are frozen by
`COMPATIBILITY.md`, direct-store provisioning needs an additive volume mode
and protocol capability during the experiment. Reinterpreting an existing
`managed_journal` volume or repurposing current environment variables is not
allowed. A product replacement would require the documented deprecation path
or a major version.

Most of the completed coordination work survives above the persistence seam:
exact-once identities and outcomes, ordered application, delegations, fencing
of client sessions, locks, open pins, and write-back handoff. The current
Postgres authority claim, manager/runtime lease facts, and cold-replay fence do
not remain as a second ordering authority. Consensus term and membership are
the data-plane safety fence; manager leases remain authorization and routing
state only.

## What appears

The replacement is a storage system, not a simpler composition of Postgres
and S3. It adds:

- consensus elections, terms, read-index handling, quorum persistence, and
  ambiguous-outcome recovery;
- a durable replica engine with crash-atomic object/root installation,
  checksums, garbage collection, disk-space reservation, and format upgrades;
- group membership, node identity, certificates, placement, joint changes,
  and AZ-failure-domain enforcement;
- snapshot transfer, incremental catch-up, anti-entropy, read repair,
  quarantine, and full replica rebuild;
- capacity forecasting, hot-volume isolation, rebalancing, throttling, disk
  replacement, and noisy-neighbor controls;
- rolling binary and on-disk-format upgrades without losing quorum;
- quorum-aware routing, leader discovery, failover observability, and client
  reconnect behavior;
- backup/export lag monitoring, restore drills, disaster-recovery policy, and
  an explicit regional-loss story;
- storage-node security, tenant isolation, encryption/key rotation, on-call
  runbooks, and incident ownership for the bytes themselves.

Quorum reads are also real complexity even when data comes from one local
replica: the serving node needs a quorum-backed read fence. A reachable
process with a readable disk is not necessarily allowed to answer.

The current system delegates replication, disk replacement, and much of
backup recovery to managed Postgres and S3. Direct store moves those duties
into PortableFS. Eliminating the fold does not eliminate operational toil; it
changes whose pager carries it.

## Derisking order: failure handling first

### Phase 0: executable invariants and format spike (1-2 weeks)

Write a state-machine/failure specification before service code. Model leader
loss before and after each persistence boundary, exact lost replies, quorum
intersection, membership change, and snapshot installation. Select a vetted
consensus component and define precisely what its stable-storage callback
means for materialized objects. Build small replicated PFT2 and KV transaction
spikes only to measure write amplification; do not call either a filesystem
prototype.

Exit criteria:

- reviewers can derive the acknowledgement promise from persistence events;
- no state allows two committed roots at one index or a successful reply with
  fewer than two full AZ copies;
- PFT2's measured write amplification is understood well enough to choose it
  or the KV fallback for Phase 1.

#### Phase 0 executable safety specification

The executable specification lives in
`vcs/internal/directstoremodel`. It is a bounded exhaustive Go model rather
than a second consensus implementation. `go test` can run it in ordinary CI,
the state and transition definitions are reviewable by the engineers who will
build the fault harness, and every failure includes a shortest replay trace.
The default bound is derived from the design above: the old three-voter group,
one replacement learner, the new three-voter group, one declared AZ per
replica, and one tolerated AZ failure. The checker derives stable quorum as
`floor(voters/2)+1` and required durable copies as `tolerated failures+1`.

The complete machine-readable fault contract is the exported
`directstoremodel.PersistenceCutPoints` Go table in
`vcs/internal/directstoremodel/cutpoints.go`. The companion
`directstoremodel.MessageCutPoints` table enumerates loss boundaries, including
the exact success reply. `directstoremodel.PersistenceFaultCases()` expands the
table into the complete actor × before/after cross product, with a stable ID
for every injection. The Phase 1 harness must execute every returned case. It
must also withhold and permanently drop every message-table entry.
If an implementation combines two listed persistence events into one storage
transaction, the harness must demonstrate that no crash can expose the state
between them; deleting either logical event from the contract would hide the
atomicity claim that needs testing.

The persistence events for a mutation at index `i` are:

```text
O(r,i)  materialized object closure is stable on replica r
S(r,i)  StateCommit and the exact request outcome are stable on r; requires O
L(r,i)  consensus entry and hard state are stable on r; requires O and S
A(r,i)  r's append response is emitted; requires O, S, and L
C(i)    an active-configuration quorum of A responses commits the entry
H(l,i)  the leader's committed index is stable
I(l,i)  the leader's visible root and applied index are stable; requires C and H
P(i)    the success reply is emitted; requires C and I
```

For the stable three-voter configuration and one tolerated AZ failure:

```text
P(i)
=> C(i) and I(l,i)                              reply gate
=> exists Q: |Q| >= floor(3/2)+1 = 2           commit rule
=> for every r in Q: A(r,i)
=> for every r in Q: O(r,i) and S(r,i) and L(r,i)
=> at least 2 complete materialized bundles in distinct AZs
=> after loss of any 1 AZ, at least 1 complete committed bundle remains
```

The leader is required to belong to the commit certificate, so these are the
leader plus at least one follower, not two remote witnesses while the leader
is missing its own state. A complete follower bundle can be prepared but not
yet visible: its object closure, root references, exact outcome, and consensus
entry are readable and stable, while the committed-index/root-install events
still fence it from serving. If the original leader is lost, commit/election
quorum intersection forces a future leader to contain the entry before it can
install that bundle. Retrying the exact identity then reads the outcome from
`S(r,i)`; it does not re-execute the mutation. Losing the original reply
therefore changes knowledge at the client, not committed state.

Root uniqueness is derived by the same intersection. Any second commit
certificate for index `i` intersects the first certificate. The intersecting
replica is a durable witness and cannot replace the committed entry while
voting for an eligible future leader. During replacement, joint consensus is
an old-majority AND a new-majority; the model enumerates all old, joint, and
new quorums and checks intersection across each adjacent phase. A learner is
not eligible for either votes or durable-copy counting until snapshot object
closure, snapshot `StateCommit`, consensus snapshot metadata, and the installed
root/applied index have all crossed their listed persistence boundaries.

This acknowledgement costs **one cross-AZ leader/follower network round trip
on the critical path, rather than zero**, plus stable storage on the follower
and the leader's commit/root-install stable barrier. Let `R_lf` be the
cross-AZ round-trip time, `D_p(r)` the time to stabilize objects, state commit,
and consensus entry on replica `r`, and `D_i(l)` the leader commit-index and
root-install barrier. From the time the leader has evaluated the operation,
the lower bound is:

```text
T_ack >= max(D_p(leader), min_follower(R_lf + D_p(follower))) + D_i(leader)
```

The client/leader request-response latency and operation evaluation add to
that expression. Parallel local/follower persistence and group commit can
amortize work but cannot remove `R_lf` from a remote-durable success. By
contrast, today's delegated local-first write acknowledgement has zero
authority or cross-AZ round trips on this path. Phase 0 deliberately assigns
no millisecond constant to `R_lf` or either storage term: they are deployment
parameters to measure, not values that can be derived from the safety model.

Run the specification and its deliberate negative controls with:

```bash
go -C vcs test ./internal/directstoremodel -v
```

The positive checker exhaustively explores mutation persistence
interleavings, process crash/restart and re-election, an exactly lost reply
and retry, competing roots at one index, all stable/joint quorum masks,
learner snapshot installation, and old-to-joint-to-new membership. Two tests
then mutate the transition rules. One permits a leader to commit with only its
own append response; the checker reports `commit-without-quorum` and a trace
ending at that one-replica commit. The other permits overwriting a committed
quorum witness; the checker reports `two-committed-roots-at-one-index` with
both certificates and the complete trace. The test suite fails if either
mutant stops producing its expected counterexample.

This establishes only safety of the finite contract, not safety of a service.
It assumes the adopted consensus component supplies its specified election
and log rules; it does not model that component's implementation. It cannot
establish real `fsync` behavior, torn or reordered writes, filesystem and
device lies, checksum implementation, message transport, corruption repair,
multi-operation log compaction, timing, availability, throughput, or truthful
AZ placement. Phase 1 must try to break the real stable-storage adapter at
every exported cut point, then add short writes, `ENOSPC`, corruption,
partitions, duplication, delay, and restart from only the bytes the adapter
declared stable. A passing model tells Phase 1 what to attack; it does not tell
us that the resulting system works.

Honest exit read: the first two Phase 0 criteria are met at the specification
boundary. The acknowledgement follows mechanically from checked event
preconditions, and exhaustive exploration finds neither a duplicate committed
root nor an under-replicated success in the unmutated model while reporting
both deliberate violations. That is not the same as meeting all of Phase 0:
the format-selection criterion is separate evidence, and Phase 1 must show
that a real consensus/storage adapter implements these modeled events exactly.

### Phase 1: three real replicas under deterministic faults (3-5 weeks)

Build three storage processes with real stable-storage calls, consensus, the
materialized transaction boundary, exact outcome rows, and no mount frontend.
Start the deterministic fault harness with the first transaction: kill any
process before/after object sync, commit-record sync, vote, commit, apply, and
reply; partition every link; lose and duplicate replies; inject short writes,
ENOSPC, checksum failures, and restart with only declared-synced bytes.

The workload is a reference state machine that continuously compares every
acknowledged operation and linearizable read with a model. The test records
the exact random seed and persistence trace for replay.

Exit criteria:

- zero acknowledged-write loss, double apply, stale linearizable read, or
  split-brain commit across at least one million faulted operations and every
  enumerated persistence cut point;
- automatic progress with any one replica or one AZ link set failed;
- fail closed with no majority;
- restart opens the committed root without replay proportional to mutation
  history.

Any unexplained safety failure stops the project until root-caused. Throughput
does not compensate for one.

### Phase 2: catch-up, divergence, membership, and repair (3-4 weeks)

Add learner snapshot transfer, incremental catch-up, joint membership,
object anti-entropy, corruption quarantine, and rebuild. Run foreground writes
through every transition. Exercise a member ten minutes behind at the target
write rate, a new empty member, a corrupt member, a nearly full member, and a
leader dying during each membership phase.

Exit criteria:

- no foreground read returns unverified or older data during repair;
- a ten-minute-behind replica catches up and restores two-current-copy
  redundancy in no more than ten minutes while foreground accepted throughput
  remains at least 7 MiB/s;
- a full replica rebuild and every membership interruption are resumable and
  need no operator data choice;
- two agreeing healthy replicas automatically quarantine/rebuild one
  divergent replica; lack of a trustworthy majority fails closed.

### Phase 3: the existing fsproto seam and semantic batteries (3-4 weeks)

Implement the internal `AuthorityState` adapter and run the unchanged v8
server against the replica leader. Start with remote-durable/write-through
mode; delegation denials exercise the existing authority lane. Preserve exact
sessions and PFC2 coordination in the replicated recovery root. Then run all
fsproto/clientcore suites plus unchanged `live-mount-battery.sh` and
`fskit-solo-battery.sh` against both journal and direct-store volumes.

Add a two-client failover battery: Git and SQLite operate while the leader is
killed, locks are held, rename-over-open and open-after-unlink are active, an
exact reply is dropped, and invalidation subscribers reconnect.

Exit criteria:

- identical semantic batteries pass in both modes;
- every exact lost-reply case returns the original result;
- lock, delegation, pin, orphan, and inode allocator state survive leader
  failover;
- p99 client-visible failover stall is at most 15 seconds, with no manual
  remount; 30 seconds or repeated kernel hangs kills the prototype.

### Phase 4: multi-AZ performance and 72-hour soak (2-3 weeks)

Run three replicas in actual separate AZs, not three localhost processes.
Measure remote-durable mode and hybrid mode separately with the same workload,
logical data, frontend, and failure schedule as the current gate. Hold customer
S3 unavailable during part of the run to prove export is off the write and RAM
paths. Include sequential bulk writes, 4 KiB random overwrites, metadata churn,
Git, SQLite, and a writer offering 6-7 MiB/s.

Mandatory gates:

- sustain at least 10 MiB/s accepted logical writes per hot volume for 30
  minutes in remote-durable mode; below 7 MiB/s after one focused optimization
  pass kills the product direction;
- process RSS remains at or below 1 GiB and flat with total bytes written for
  two hours at 7 MiB/s, including while S3 export is stopped; any residency
  slope tied to cumulative writes kills the design;
- same-region remote durability has p95 mutation/fsync latency at most 20 ms
  and p99 at most 50 ms at 7 MiB/s. Report local-first latency separately; do
  not average the two contracts;
- leader failover p99 remains at most 15 seconds with zero acknowledged loss;
- one-replica physical write amplification is at most 2x for sequential bulk
  data after steady-state GC, measured at a durable commit unit of at least
  16 KiB; cluster-wide amplification is therefore at most 6x before
  customer-S3 export. PFT2 is rejected as the live format above that. For
  4 KiB random overwrites, cluster-wide amplification above 15x, measured in
  steady state with segment cleaning and index compaction included and at a
  stated live-data occupancy, or live replica space above 2x the logical
  working set, rejects the format. See "Corrections to the amplification
  gates" below;
- restart time is bounded by opening/verifying current metadata, not history
  length: at most 10 seconds for the 8 GiB gate and 30 seconds for a 100 GiB
  image on the target node class;
- 72 hours of continuous one-at-a-time failure injection produces no safety
  violation, unbounded repair queue, or manual intervention.

These thresholds are prototype decisions, not promises to tune later. Missing
a format-specific amplification threshold permits one format pivot. Missing
the 7 MiB/s floor, memory-flatness rule, or safety rule ends the direct-store
direction.

#### Corrections to the amplification gates

Three corrections. Each is forced by arithmetic or by measurement, not by
preference. The supporting measurements are in
`vcs/spikes/direct-store-seglog` (Apple M5 Max, macOS 26.5 build 25F71, APFS,
Go 1.26.5; the primary counter is the delta of
`proc_pid_rusage(RUSAGE_INFO_V4).ri_diskio_byteswritten`).

1. **An aggregate gate below 3x is arithmetically impossible.** Three full
   readable replicas store every mutation three times, so cluster-wide
   physical bytes are at least three times one replica's, in any format. A
   gate of "at most 2x across three replicas" cannot be met by any design and
   would reject every candidate for a reason unrelated to the format. The
   budget that is actually being spent is 2x *per replica*, which makes the
   cluster gate 6x. The same arithmetic applies to the random-overwrite gate:
   15x cluster-wide is 5x per replica.

2. **The 2x sequential gate is a statement about the commit unit as much as
   about the format.** One durable append on this filesystem costs a floor
   that barely varies below 16 KiB: a 64-byte append costs 6,144 physical
   bytes, 512 bytes costs 10,240, and 4,096 bytes costs 10,240-11,200. From
   16 KiB upward the charge is exactly the payload. A 4 KiB durable append is
   therefore already 2.5x-2.7x before the format writes one byte of its own,
   and no on-disk format can pass a 2x per-replica gate while committing
   4 KiB at a time. The gate is meaningful only as amortized amplification at
   a durable commit unit of at least 16 KiB; applied per 4 KiB operation it
   measures APFS, not the storage engine. A format spike must therefore
   report the commit unit alongside the ratio.

3. **The 15x random-overwrite gate counts steady-state reclamation, not
   foreground writes.** A foreground-only number is not a format result. An
   append-only log has almost no foreground amplification and pays instead in
   segment cleaning; an LSM pays in compaction. Neither cost appears until
   the store has been overwritten enough times for space to stop growing. The
   gate is met only when the measurement runs to a stable occupancy and
   stable per-window amplification, and it must name the live-data occupancy
   it holds, because cleaning cost is a strong function of occupancy: the
   same segmented log measured at 1 GiB live cost 1.89x-1.91x per replica at
   70% occupancy and 4.35x-4.45x at 90%. An occupancy target is part of the
   gate, not an implementation detail.

### Phase 5: optional local-first hybrid (1-2 weeks)

Only after the pure mode passes, enable existing delegations and client WAL
against the replica leader. Verify bounded local recovery jobs, recall/drain,
machine-loss behavior, and `fsync` to quorum. This phase answers whether the
lost differentiator can be retained without reintroducing the server-side
problem. It must not blur the two durability labels or become a prerequisite
for making the remote mode meet its throughput gate.

## Scope and cost

A useful comparative prototype is approximately 12-18 calendar weeks for two
senior storage/distributed-systems engineers, plus part-time frontend, macOS,
and infrastructure help. Phase 1 is the earliest kill point at roughly week
6; Phase 3 is the earliest meaningful filesystem comparison at roughly week
12. This assumes reuse of a vetted consensus implementation and the existing
filesystem semantics. Writing consensus, a storage engine, or a new frontend
would increase the estimate materially and should be rejected as scope.

A prototype can prove that the acknowledgement boundary is implementable,
that deterministic faults preserve safety, that the current POSIX behavior
fits the new state machine, and that one concrete AZ/storage configuration
meets the measured gate. It cannot prove long-tail disk firmware behavior,
provider failure-domain independence, multi-tenant fleet economics, safe
rolling upgrades over years of formats, regional disaster recovery, or the
quality of the eventual on-call operation.

Turning a passing prototype into a production beta is another 6-9 months for
a four-to-six-person team. A generally available service with capacity
automation, rolling upgrades, backup/restore drills, regional recovery,
security review, tenant isolation, observability, runbooks, and an on-call
rotation is plausibly 9-15 months total and 35-60 engineer-months. The ongoing
cost includes three online copies before customer S3, cross-AZ write traffic,
repair/rebalance traffic, and ownership of data-loss incidents.

Correct failure handling, not a local throughput graph, is what separates the
prototype from a storage system. A fast Phase 0 format spike is evidence about
encoding only.

## Recommendation

**Build the narrower failure-first prototype; do not pivot PortableFS or pause
the current fix campaign.** Keep the current architecture moving through its
next end-to-end gate. In parallel, fund Phases 0-2 as a time-boxed storage
safety experiment, and proceed to the mount comparison only if they pass.
This buys concrete evidence about the crux—remote quorum latency versus the
elimination of cut-coupled RAM—without betting the product on a local-disk
demo or abandoning work that is one gate from validation.

The strongest argument against this recommendation is that the known system
may already have the cheaper answer. Warm incremental cuts measured 25.75
MiB/s against a 6-7 MiB/s writer; the aggregate failure is dominated by cold
cuts, and the current branch has just added folding, pacing, proof, and
reclamation fixes. A local ephemeral spill/readable cache could decouple RAM
from publication while preserving local-first acknowledgement and managed
Postgres/S3 operations. If the next gate shows flat bounded memory and
sustained accepted throughput, a replicated store is likely a costly
distraction that trades PortableFS's differentiator for a multi-year storage
on-call burden. That result should stop this exploration even if its prototype
looks promising.
