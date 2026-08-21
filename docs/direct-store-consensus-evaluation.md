# Direct-store consensus component evaluation

> **Concluded exploration — historical record, not a live decision.**
>
> This is the Phase 0 component evaluation for the replicated readable-store
> experiment described in
> [direct-store-exploration.md](./direct-store-exploration.md). That exploration
> was concluded without adopting a replicated store, so nothing here is an
> active dependency choice: PortableFS v3 runs no consensus protocol and takes
> no dependency on `go.etcd.io/raft/v3`. The design that superseded the
> exploration is recorded in
> [xfs-authority-architecture.md](./xfs-authority-architecture.md).
>
> One artifact survives and is still runnable:
> `vcs/spikes/directstore-stable-boundary` exists in this tree, and
> `go -C vcs test ./spikes/directstore-stable-boundary -v` still runs it. The
> segmented-log measurement spike the exploration cites,
> `vcs/spikes/direct-store-seglog`, does not — it was removed at commit
> `dba5b8f` ("v3: remove the v2 architecture entirely") along with the rest of
> the v2 architecture.
>
> The original status line said this evaluation does not change the v2
> architecture or any frozen protocol. v2 no longer exists, so read that as a
> statement about the document's scope at the time it was written, not about the
> current system.

Status: Phase 0 decision record, retained as a historical evaluation.

Review date: 2026-08-03.

The body below is unedited.

## Decision

Adopt [`go.etcd.io/raft/v3` v3.7.0](https://github.com/etcd-io/raft/releases/tag/v3.7.0)
for the experiment. Use `RawNode` with asynchronous storage writes, explicit
`ConfChangeV2` joint configurations, `ReadOnlySafe`, `CheckQuorum`, and
`PreVote`. Pin the version. Do not copy or modify its consensus algorithm.

Do not write Raft. There is no unmet consensus requirement that justifies a
new implementation. The application-specific problem is below Raft: a replica
may not acknowledge an append until the immutable objects named by that append
are stable too. etcd/raft exposes the response-after-storage boundary needed to
enforce that rule. Building consensus would add election, replication,
reconfiguration, read fencing, snapshot, and upgrade risk without removing any
of the storage-adapter work.

The choice is conditional on the Phase 1 adapter surviving the specified crash
harness. A library with a correct consensus core does not make an incorrect
`fsync` boundary correct.

## Evaluation

| Candidate | Production and correctness evidence | Membership | Snapshots and reads | Integration and maintenance | Result |
| --- | --- | --- | --- | --- | --- |
| **etcd/raft v3.7.0** | Long production lineage through etcd and other storage systems. The implementation is deterministic and has unit, data-driven, quick-check, interaction, and quorum tests. Its repository contains a TLA+ model covering implementation-specific behavior, including reconfiguration, plus implementation-trace validation. This is model checking and trace conformance, not a machine-checked proof of the Go implementation. The TLA+ documentation explicitly lists partially persisted `Ready` state as a known gap. | `ConfChangeV2` implements full joint consensus: a joint quorum is an old majority and a new majority. It also supports learners. | The application owns snapshot creation, installation, and log compaction. `ReadOnlySafe` implements quorum-backed read index for leaders and followers; a lease mode exists but depends on bounded clocks. | Pure Go; the v3.7.0 module uses the Go 1.26 language/toolchain line and is compatible with this repository's Go 1.26.6 toolchain. The core is small and actively maintained. Integration cost is deliberately high because transport, WAL, snapshots, and application are outside the library. That explicitness is the reason it fits this boundary. | **Select.** |
| **HashiCorp Raft v1.7.3** | Mature in Consul, Nomad, and Vault. It has substantial unit/integration coverage and a fuzzy fault framework. No implementation-specific formal model or proof was found. | Supports staging/non-voters and one-at-a-time overlapping configuration changes. It does not expose full joint consensus for an atomic voter replacement. | Provides an integrated FSM snapshot/restore and log truncation lifecycle. `VerifyLeader`, `Barrier`, and `CommitIndex` can be composed into read fencing, but it does not provide an equivalent first-class request-scoped read-index API. | Easier standard FSM integration and actively maintained. Its high-level replication loop owns the moment an append response is sent. Enforcing object-before-append-response would require a custom `LogStore` that decodes application entries and materializes filesystem objects, collapsing consensus storage and the object engine into one awkward layer. | Reject for this design; strong alternative for a conventional log-then-apply FSM. |
| **Dragonboat v3/v4** | Extensive unit, fuzz, I/O-fault, power-loss, monkey, and Knossos/Porcupine linearizability testing is documented. Public production evidence is less legible than etcd/raft or HashiCorp's products. No implementation-specific formal model or proof was found. | Implements the thesis's restricted one-member-at-a-time protocol, not full joint consensus. Learners/non-voters are supported. | Integrated ReadIndex, snapshot, compaction, transport, LogDB, and on-disk state machines are attractive, especially for many groups. | The normal state-machine API applies after a Raft entry commits, so it cannot withhold a follower's append acknowledgement until this design's materialized object closure is stable. Doing that in a custom LogDB would be the same layer violation as the HashiCorp workaround. v3.3.8 was tagged in 2023; v4 remained untagged/unstable at the review date and its main branch's latest source commit was in 2025. | Reject: API-boundary and reconfiguration mismatch, plus higher release risk. |
| **Build a new implementation** | No production record, no compatibility history, and all correctness evidence would have to be created by this project. | Everything would be new. | Everything would be new. | Largest implementation and permanent maintenance cost. It would duplicate solved consensus work while leaving the hard materialization boundary unsolved. | Reject. |

The strongest argument against etcd/raft is that it is only a consensus core.
PortableFS must correctly implement the WAL, transport, storage scheduling,
snapshot transfer, compaction, and all crash ordering around `Ready`. A more
integrated library would remove code and operational surface. That argument
would win for a conventional system where a durable Raft log may be replayed
later to construct the state machine. It does not win here because both
integrated candidates hide or postdate the precise append-response point at
which this design requires the materialized object closure already to exist.

## Stable-storage contract

### The sentence that must remain true

**When the PortableFS etcd/raft adapter delivers any response attached to a
`MsgStorageAppend`, every materialized object transitively referenced by each
corresponding normal entry, the checksummed `StateCommit` containing its exact
outcome, and the Raft entry/required hard state are already durably recoverable
on that replica after power loss.**

The self-directed `MsgStorageAppendResp` is the exact point at which etcd/raft
learns that the entries are stable. The adapter must not step that response,
or transmit a follower `MsgAppResp` attached to the same storage message,
before the condition above is true.

"Durably recoverable" means that all file data and the namespace operations
that make it reachable have completed the storage engine's stable transaction.
For a file implementation this includes syncing the file, atomically installing
its name, and syncing the containing directory. A successful write or rename
that has not crossed that boundary does not count. The assumption that the
filesystem, kernel, device, and cloud volume honor the successful sync is part
of the crash-fault model; the adapter cannot repair a device that lies about
stable media.

`StateCommit` is named for the state it describes, not for consensus visibility.
It is a prepared, invisible record until Raft commits its index.

### Adapter order for an entry at index `i`

Configure `AsyncStorageWrites=true` and process each local append thread in
order. A `MsgStorageAppend` handler performs:

1. Decode and validate every normal entry. Verify the parent state, canonical
   object bytes, object lengths and hashes, transaction digest, and exact
   request fingerprint.
2. Reserve enough local capacity for the complete transaction. Capacity policy
   is an open deployment parameter; an optimistic partial write is not a
   reservation.
3. Write every new object in the transitive closure and make its data and name
   stable. Existing content-addressed objects count only after their stored
   bytes have been hash-verified.
4. Write and stabilize the checksummed `StateCommit`, including both roots and
   the exact outcome. It may now exist as an unreachable prepared root.
5. Append and stabilize the Raft entries, term/vote hard state, and any
   snapshot metadata carried by the storage message. Update the in-memory
   `Storage` view only from this durable result.
6. Only now deliver the `MsgStorageAppend.Responses`. On a follower this is the
   point at which its `MsgAppResp` can reach the leader. On the leader it is the
   point at which its local stable-index tracker advances. Responses unrelated
   to the current storage write may retain the parallelism that the asynchronous
   API explicitly permits.
7. After Raft commits `i`, durably advance the leader's commit record and
   install the visible root/applied index. Only a complete, validated prepared
   bundle may be installed.
8. Emit the client success reply only after step 7 and after the leader has
   evidence that at least one follower in a different declared AZ completed
   step 6 for `i`. Raft commitment still supplies the quorum-ordering proof;
   this extra reply gate ensures the leader plus one follower are full durable
   copies at reply time.

The application deliberately strengthens etcd/raft's `MustSync` result.
etcd/raft may allow a commit-index-only hard-state update to be non-durable
because Raft can rediscover commitment after restart. PortableFS must sync a
reply-covering commit-index advance and the visible-root/applied-index install
before replying. `MustSync=false` is not permission to weaken the product's
acknowledgement boundary.

A stable `StateCommit` is **not allowed** to reference an object whose bytes or
name have not already been synced. The temporary commit bytes may of course be
written before their own sync completes, but object stability precedes even
that write. If a crash leaves the temporary record, recovery ignores it. If
recovery finds a final `StateCommit` or Raft entry whose object closure is
missing or hash-invalid, the replica reports corruption and is ineligible to
vote or serve; it does not call the entry persisted.

The canonical object bytes in the Raft entry can help repair a damaged object
while that entry is retained, and another replica or snapshot can repair it
later. Neither is permission to acknowledge before local object sync. Relying
on replay for the normal durability proof would change the selected design
back into log-durable, later-materialized storage and would make log truncation
capable of deleting the only recovery source.

The corresponding local order is:

```text
object closure stable
    -> StateCommit + exact outcome stable
    -> Raft entry / term / vote stable
    -> append response eligible
    -> quorum commit
    -> commit index + visible root / applied index stable
    -> client success reply eligible
```

Crashes before the Raft record leave only unreachable prepared garbage. A
crash after the Raft record but before the append response leaves a safe entry
that may be reported after restart. A crash after quorum commit but before the
client reply creates an ambiguous client outcome, not ambiguous replicated
state. A crash after the success reply must recover a complete installed root
on the leader and a complete prepared-or-installed bundle on a different-AZ
follower.

### Snapshots and truncation

An outgoing Raft snapshot identifies a committed materialized root and includes
the exact `ConfState`. The complete object closure, its `StateCommit`, snapshot
metadata, and installed index must be stable before the snapshot is advertised.
The log prefix may be truncated only after that snapshot boundary is durable.

For an incoming snapshot, transfer and hash-verify its complete object closure
first, stabilize its `StateCommit` second, persist the Raft snapshot and hard
state third, and install its visible root/applied index last. Do not deliver the
snapshot storage responses or make the learner promotable before those steps
complete. Object reachability pins must cover both the retained log suffix and
every advertised snapshot; garbage collection may not infer liveness from the
current visible root alone.

## Linearizable read fence

Use request-scoped quorum ReadIndex (`ReadOnlySafe`), not a leader lease. No
bound has been established for clock drift, scheduler pauses, stop-the-world
pauses, or storage stalls, so there is no derived safe lease duration.
`CheckQuorum` makes an isolated leader step down eventually and `PreVote`
reduces disruptive elections, but neither is itself a read proof.

For each mounted-client read:

1. Submit `RawNode.ReadIndex` with a unique request context. Do not reuse an old
   `ReadState` as a cacheable lease.
2. Wait for the matching `ReadState`. etcd/raft produces it only after the
   current leader's safe-read protocol has contacted a quorum and the leader
   has committed an entry in its current term as required by Raft.
3. Wait until the local visible/applied index is at least the returned read
   index, then pin and read the immutable root at that index or a later index.
4. A follower may serve only after performing the same ReadIndex exchange
   through the leader and applying through the returned index. A local disk and
   a remembered leader ID are insufficient.

During an election there is no usable read fence, so reads wait or return a
retryable unavailable error according to the caller's deadline. In a partition,
only the majority side can finish a new ReadIndex. A minority old leader may
still believe it is leader until `CheckQuorum` expires, but it cannot complete
the quorum exchange and therefore cannot answer. A ReadIndex that completed
before a later partition remains a valid linearization point for that one
request once the local applied index covers it; it is not reusable for a later
request. With no majority, both reads and writes fail closed.

## Ambiguous mutation outcomes and exact retry

The existing v8 exact identity carries over unchanged:
`(session, generation, slot, slot sequence)` plus the server-computed canonical
request fingerprint. The replicated recovery root carries the slot's next
sequence, latest fingerprint, and exact outcome. That slot transition and the
filesystem roots are fields of the same `StateCommit`, so deduplication cannot
become durable separately from the mutation it describes.

Before proposing, the leader obtains a read fence and checks the slot:

- the next sequence may be proposed once;
- a matching retained identity returns its stored outcome without executing;
- the same identity with different bytes, a gap, or an invalid generation
  commits the existing fence behavior;
- deterministic failures are exact outcomes too and are committed before a
  definite reply.

Once a request might have been proposed, a leadership loss, transport timeout,
or connection close must not be translated into a fresh application failure.
The server sends no definite mutation reply unless that exact outcome crossed
the reply boundary. The client therefore sees the existing
`ErrMutationUnknown`, parks the slot, and resends the identical request bytes
and identity. It never advances that slot or invents a new operation ID.

After a leader dies following commit but before reply, the next leader first
applies through a quorum-backed read index. The retry then finds the committed
slot outcome and returns it with `Duplicate`; it does not execute again. If the
old proposal never committed, consensus may discard its prepared tail and the
same identity is the next admissible sequence, so the new leader may execute it
once. Quorum intersection plus the exact slot record distinguishes these cases;
the client is not asked to guess.

A non-leader may return a transport-level leader hint only when it has not
admitted the exact request. The retry keeps the same identity and the client
does not consume its sequence. Once admission may have happened, close or
unknown is the only honest non-definite result. A router must not proxy an
ambiguous mutation to another leader under a fresh identity.

## Membership policy

Use application-serialized `ConfChangeV2` operations with explicit joint
consensus; do not depend on automatic control-plane membership rows. The move
sequence is:

1. add the replacement as a learner;
2. install and verify a current materialized snapshot, then catch up its tail;
3. enter one explicit joint change that promotes the learner and removes the
   old voter, requiring both old and new majorities;
4. leave the joint configuration with a second committed `ConfChangeV2`.

The application must persist the returned `ConfState` in snapshots and must
serialize configuration proposals. A learner is not promotable and does not
count as a durable copy until its object closure, `StateCommit`, Raft snapshot,
and installed applied index are all stable. Node IDs are unique for the life of
the group and are never addresses or reusable machine identities.

## Stable-boundary spike

`vcs/spikes/directstore-stable-boundary` is a deliberately small process-kill
spike, not a storage engine or consensus implementation. It performs the local
order above with real file and directory `Sync` calls, blocks without sleeps at
every semantic before/after cut, and is killed by the parent test. Recovery
accepts only a hash-complete chain from Raft record to `StateCommit` to object
bytes. A negative control syncs and acknowledges the records before the object;
recovery detects the missing closure, demonstrating why that response would be
a false persistence vote.

Run it with:

```bash
go -C vcs test ./spikes/directstore-stable-boundary -v
```

Process kill does not remove dirty kernel cache and is not a power-loss test.
The spike proves the adapter's program order and recovery validation under
`SIGKILL`; it does not prove a target filesystem or device honors sync. The
Phase 1 harness still must restart from only the bytes declared stable and
inject torn writes, lost directory updates, `ENOSPC`, and lying/erroring syncs.

## Derived facts and open parameters

The experiment contains no new millisecond constant.

- Three voters and a commit quorum of two are derived from tolerating one
  crash/AZ failure: `floor(3/2)+1 = 2`, and complete durable copies required at
  reply are `tolerated failures+1 = 2`.
- `ReadOnlySafe` is derived from the absence of a proven clock-error bound.
- v3.7.0 is the reviewed released module and uses the same Go 1.26 toolchain
  line as this repository; dependency
  upgrades require repeating the API, TLA+ change, and fault-harness review.
- Election and heartbeat ticks, request deadlines, append batching, maximum
  in-flight bytes, capacity reservation, retained-log length, snapshot cadence,
  garbage-collection grace, repair bandwidth, and any future lease bound are
  open measured parameters. They must be derived from the target network,
  pause, storage, workload, and recovery distributions before production use.
- The spike's cut points come directly from the persistence implication chain.
  It has no timing, retry-count, throughput, or size tuning constant. Its
  SHA-256 links mirror the repository's existing PFT2/histstore content
  addressing, and its owner-only file modes are a test isolation choice; the
  spike selects neither a new digest nor a storage parameter.

## What remains undetermined

- The etcd/raft TLA+ work is strong evidence, but it is not a proof of the exact
  Go binary plus this adapter. Its documented partial-persistence gap is the
  exact area the PortableFS harness must cover.
- The durability behavior of the eventual filesystem, kernel, local volume,
  and cloud block device has not been established. Successful `fsync` and
  directory `fsync` are assumptions until power-cut testing confirms them.
- The selected component does not answer whether PFT2 or a transactional KV
  layout can meet the materialization and amplification gates.
- Transport backpressure, snapshot concurrency, group count, and the optimal
  async append batching policy have not been measured on the target node and
  multi-AZ network.
- Public evidence does not establish that every named downstream etcd/raft or
  Dragonboat user runs the reviewed release or exercises joint consensus.

## Primary sources

- [etcd/raft README and production lineage](https://github.com/etcd-io/raft)
- [etcd/raft `Ready`, async storage, and ReadIndex API](https://pkg.go.dev/go.etcd.io/raft/v3)
- [etcd/raft joint-consensus implementation](https://github.com/etcd-io/raft/blob/v3.7.0/confchange/confchange.go)
- [etcd/raft TLA+ model and documented limits](https://github.com/etcd-io/raft/blob/v3.7.0/tla/README.md)
- [HashiCorp Raft API](https://pkg.go.dev/github.com/hashicorp/raft)
- [HashiCorp membership design](https://github.com/hashicorp/raft/blob/v1.7.3/membership.md)
- [HashiCorp fuzzy fault tests](https://github.com/hashicorp/raft/tree/v1.7.3/fuzzy)
- [Dragonboat features and release status](https://github.com/lni/dragonboat)
- [Dragonboat test strategy](https://github.com/lni/dragonboat/blob/master/docs/test.md)
