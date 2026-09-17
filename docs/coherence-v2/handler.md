# Protocol 7 authority handler

F1 wires the epoch-local `CoherenceCoordinator` into `authorityrpc`. The volume
assembly constructs one coordinator and binds it to the volume handler. Linux
mounts use subscriptions and delegations; FSKit retains synchronous repair,
source-publication ownership, and fragmented writes. No Linux request can enter
the historical lease grant, recall, renewal, or discharge handler.

## F2 request contract

Activate the runtime session, then send a cold Subscribe on CONTROL. Activation
does not subscribe implicitly. Every subsequent Linux operation checks the
subscription horizon, including keepalive; renewing runtime authorization does
not renew cache authority. Cold Subscribe can replace expired subscription state.
Detach and attach-recovery plumbing remain available for lifecycle cleanup.

Subscribe freezes the sorted delegated-identity set, including reservations.
Pages share one watermark, incarnation, random 16-byte snapshot token, and horizon
anchored at the first request. An empty `snapshot_id` starts a new incarnation;
`after_identity` must then be empty. Continue with the preceding nonfinal reply's
`next_after_identity`. Repeating an already returned page yields the same page.
Out-of-order or invented cursors return EINVAL; a replaced or expired snapshot
returns EIO/COHERENCE. Each page contains at most 4096 identities and fits the
negotiated reply budget. Renew and control polling can proceed during pagination.
F2 must stage changes until it installs the complete snapshot.

The adapter translates the coordinator's shared log positions into independent,
contiguous, per-incarnation delivery and change cursors, both starting at 1.
`NextControlEvent.after_sequence` advances delivery only. `ChangeAck.position`
advances the withdrawn change prefix. A poll retry returns the retained event;
concurrent polls or invalid delivery positions fail with EINVAL. Recall, break,
and mode-change acknowledgments identify the delivered event, exact delegation,
and issued application cut. Release validates the entire batch before changing
ownership and retains exact retry completion records for the incarnation. Its
applied ticket must cover the exact generation's latest admitted application;
zero or an older issued ticket fails with EINVAL without releasing any member of
the batch. `ReleaseAppliedBatch` performs that check atomically with retirement.

CONTROL acknowledgments and renewals have capacity independent of parked polls.
Linux DATA reserves separate capacity for delegation-bearing WRITE, SETATTR, and
FALLOCATE so a peer operation waiting for a holder cannot occupy every flush
slot. Linux negotiation requires `max_in_flight >= 3`; FSKit retains its existing
minimum of 2. F2 must also reserve client transport and replay-slot capacity for
holder flushes and control completion.

| Refusal | Response |
| --- | --- |
| Missing/expired subscription, wrong incarnation, stale delegation generation | EIO, `FAILURE_CLASS_COHERENCE` |
| Invalid delegation reference on a data flush | EIO, `FAILURE_CLASS_COHERENCE`, no storage mutation or ticket |
| Malformed control coordinate, unknown acknowledgment, unissued ticket, conflicting retry, inconsistent write intent | EINVAL |
| Barrier cut above the session's applied prefix | EINVAL, without a sync or wait for unsent data |
| Linux operation excluded by a live macOS compatibility writer | EBUSY |
| Historical Linux lease request | EOPNOTSUPP |

Storage failures retain the existing errno/failure classification and partial
application reporting. Coherence EIO does not fence the backing volume.

## Opens and storage admission

`write_intent` requires write access in the open flags. Existing files use
Reserve/Grant; replies include the exact opaque delegation id, generation, and
mode. A new CREATE holds the complete parent/name dependency turn through storage
creation and nonblocking ReserveNew. Other handler lookups cannot resolve the new
binding before its identity has a reservation. Grant waits only after storage
stripes and the dependency turn have been released.

Cache admission belongs to a server handle. A requested cache-capable open calls
OpenCacheCapable; a false result requires direct I/O. Write-intent handles use
direct I/O. The handler records each admitted cache-capable handle, unwinds it on
failure, and closes its accounting once when removing the handle. Runtime replay
returns the original handle and mode without repeating admission or close.

READ, GETATTR, attribute-bearing LOOKUP/READDIR, FSYNC, and copy source admission
use DataConsumed. WRITE, SETATTR, FALLOCATE, and copy destinations either pin an
exact DelegationRef with BeginFlush or admit a synchronous mutation. The latter
uses a private generation that ends with the storage operation if the client did
not already hold a grant. Peers wait for that local apply rather than receiving a
recall for an unreported delegation. The coordinator exposes
`BeginSynchronousMutation` for this required handler case. Existing-name CREATE
and truncating OPEN preserve that private generation with `RetainDelegation`
after successful storage application. It returns to reserved state while peer
withdrawal completes, then activates immediately before the DATA reply. A peer
read already waiting on the private generation retries reserved-read admission.
Activating earlier deadlocks an overtaking break against the withheld OPEN reply.
An already installed same-holder grant stays active and returns its application
receipt before the detached visibility wait, like an exact-reference flush.
A failed open cannot leak an unreported grant. The ordinary nontruncating OPEN keeps its reservation until storage and
handle tracking succeed, then grants after releasing storage admission.

Delegation cuts occur before acquiring storage dependencies. Multi-identity
operations preflight each cut separately, acquire one complete dependency set,
and revalidate bindings. CREATE uses the same dependency ordering as LOOKUP and
READDIR. The exported `StorageSequencer` wraps the coordinator package's existing
atomic dependency scheduler; it does not replace XFS mutation stripes.

## Publication and receipts

Storage apply finishes under the operation's storage dependencies. A short
commit-publication mutex then assigns the volume version, rewrites authoritative
post-state, and calls OnCommit. Namespace changes name exact parent/name bindings
and invalidate directory listings; changed objects carry attribute entries.
WRITE and copy data changes carry the committed byte range. Size changes and
range operations that shift the remaining file invalidate the whole identity.

The handler releases storage stripes and the dependency turn before waiting on
peer withdrawal. It uses `context.WithoutCancel` after commit so cancellation
cannot erase the obligation. Namespace operations and synchronous data mutations
return after a targeted withdrawal cut. Each subscription records directory,
attribute and data facts admitted since its cold watermark. Read admissions occur
before releasing their storage dependencies; source post-state admission and the
exact-token target snapshot occur atomically with commit publication. Namespace
changes target parent-directory readers, attribute changes target identity readers
(including hard-link aliases), and data changes target identities that may retain
pages after handle close. Unrelated subscribers still receive the broadcast but
do not delay the syscall. Delegation grant/recall uses its existing global proof.

Each footprint scope is bounded at 65,536 identities. Overflow targets every
coordinate in that scope until a proven cold boundary; entries are never evicted
as a performance shortcut. Footprints are conservative since-watermark sets,
not cleared on individual ACKs. Cold subscription preserves data obligations for
surviving cached handles. Activation metadata supplies identity only: the Linux
root needs a fresh GETATTR before caching attributes under the subscription.

A cold successor cannot inherit its predecessor's source exemption. If it wins
before commit, the old mutation reply is refused as uncertain because storage
may already have changed. If it wins after commit, the frontend's original
publication stamp prevents the old reply from installing into the new cache.
A delegation-bearing flush returns its application
receipt first and performs the visibility wait separately; this response promises
application, not completion of peer withdrawal. F2 must let the holder acknowledge
a break/recall from that receipt without waiting for change withdrawal.

`Response.applied_sequence` is a per-session ticket assigned in volume commit
order to changed WRITE, SETATTR, and FALLOCATE outcomes, including the applied
portion of a partial result. No-op and refused operations leave it zero. Other
operations, including CREATE, OPEN, and copy_file_range, leave it zero. Exact
mutation replay returns the original ticket. Tickets are neither replay-slot
sequences nor volume versions. F2 must preserve rejected suffixes as unapplied.

Cache-installing reads carry the sampled `Response.volume_version`; READ repeats
it in `ReadReply.volume_version`. Negative LOOKUP and empty READDIR also carry a
version. F2 still needs its local publication generation and exact-identity drain
before acknowledging a change; version comparison alone cannot discharge that
obligation. Capture the request-start publication generation and reject/retry the
whole LOOKUP or READDIR reply if any returned identity advanced meanwhile,
including children whose identity became known only from the reply. A grant after
a multi-identity preflight overlaps that read; the read can linearize at its cut,
but cannot install a cache entry across the intervening withdrawal.

## Durability proof

An inode fsync proves that inode's flushed cut but cannot prove a contiguous
volume prefix. F1 therefore leaves the existing fsync group intact and publishes
DurableSequence only after a successful volume SyncFS. Before that syscall, the
handler captures the last published volume version under the publication mutex,
then releases the mutex. A successful sync covers every storage apply through
that captured cut, including namespace changes. Racing later commits are excluded
from the proof even if the syscall happened to cover them.

The application ledger maps each session ticket to its identity and volume
version. A binary search converts the proven durable volume cut to that session's
largest contiguous durable ticket prefix. WRITE, FSYNC, SyncFS, and Barrier report
that prefix. An inode FSYNC may return a lower prefix than its own file's durable
ticket because another inode can still form a hole; success nevertheless retains
the file-fsync guarantee.

Barrier first rejects a requested ticket above the applied prefix. It then takes
a volume SyncFS cut even for ticket zero, covering namespace operations already
acknowledged before the call. Success reports
`applied_sequence >= durable_sequence >= cut_sequence`; failure publishes no new
durable cut. Runtime replay preserves the successful result. F2 performs its own
root-handle loss-sequence check and maps locally accepted entries to these
application tickets before sending Barrier.

## Lifetime and compatibility

Runtime session end calls ExpireSession before retiring permanent server handles.
The coordinator retains the last cache horizon. The runtime's existing Sweep
cadence invokes the new OnSweep hook, which sweeps coherence and forgets retired
session state only after handle retirement and horizon expiry. Cache resubscribe
does not reset application tickets or manufacture durability.

Every FSKit mount retains the macOS compatibility-writer exclusion, including a
read-only Mac mount. The files gateway instead uses the authenticated cacheless
reader profile: exactly read access, no subscription or cache-capable handles,
and BreakForRead before consuming delegated data or attributes. It never joins
Mac exclusion or requires acknowledgment to let a writer proceed. FSKit Activation recalls
existing Linux delegations before enabling the exclusion. Exact-generation holder
flushes bypass the activation admission gate so those recalls can drain;
BeginFlush still validates them, and activation waits for all pins to retire
before publishing the Mac participant. A profile admission gate serializes that activation transition
with Linux writer admission. It is writer-preferred and reference-counted:
ordinary Linux writers hold shared permits across their work, while its mutex
is held only to update admission counters and never across storage or peer I/O.

## Verification and remaining integration work

The tests cover control dispatch and cursor replay, horizon refusal, stale flush
generations, mutation tickets and replay, applied-before-withdrawn ordering,
cache-handle accounting, reserve-before-binding publication, guarded reads and
copy sources, volume durability holes, and lifecycle sweeping. Guard and OnCommit
benchmarks report allocations as well as time.

F1 originally stopped at the handler boundary. Workstream G has since
integrated F2, deleted the old Linux lease paths, and qualified real mounts.
The current evidence and remaining product gates are in [integration.md](integration.md).

Integration replaces ordinal cookies with XFS getdents offsets. The store ReadDirOpen API takes only a cookie and page bound; it returns the
current page stamp for publication revalidation. Continuation seeks to the
store cookie without accepting an unused input verifier. The frozen wire
verifier remains optional and shape-checked; it does not authorize continuation.
The reply publishes the page stamp sampled by the storage-turn revalidation,
not the earlier probe's stamp. The concurrent peer
creator/deleter regression requires every unchanged entry exactly once and refuses
ESTALE or EAGAIN. A page retries legitimate enumeration, child-resolution, and
revalidation races until it succeeds or its request context ends; the fixed
stabilization budget does not escape as a directory errno.

Linux READDIRPLUS may supply up to 4,096 sorted unique 16-byte held identities
for the exact cached page. The handler still resolves each child, acquires the
complete page footprint, and returns its stable identity, attributes, object
version, and snapshot sequence. It omits the Item only when the returned
identity is in that set, and immediately forgets the provisional store
capability instead of charging it to the session. Reclaim accepts the frozen
singular form or an additive batch of at most 4,096 distinct capabilities;
the batch is shape-checked and resolved against session accounting before any
retirement.

Application-ticket history is retired through each session's durable prefix, retaining
only monotonic counters and undurable volume versions. Active delegation cuts validate
their exact ticket floor and newly issued tickets independently. CONTROL ACK replay is
surrendered by the explicit completed-event prefix, not the delivery cursor; release
replay uses serialized contiguous operation/result receipts and retains one result.
Coordinator deadlines still govern unfinished cuts whose adapter replay was surrendered.
Long-lived session tests cover 100,000 application tickets and 10,000 delegation/control
cycles.

Detached change-delivery waits still end at acknowledgment or horizon expiry.
Their workload costs are included in [results.md](results.md).

FSKit retains its existing PREPARE/COMPLETE repair and compatibility-writer
exclusion. Linux mutations now use only the protocol-7 storage turn; the
ExecuteFromExternalSource bridge into the Mac coordinator is deleted. The
pre-apply FSKit repair constraint remains a separate platform boundary.

## Test record

Validation on macOS arm64 with a Linux arm64 Docker VM:

```sh
CGO_ENABLED=1 GOOS=darwin go -C vcs build ./...
CGO_ENABLED=0 GOOS=linux go -C vcs build ./...
go -C vcs vet ./...
go -C vcs test -race ./internal/authorityrpc/... ./internal/volumeserver/...
bash scripts/verify-local.sh
```

All passed. The local gate ran in default mode, including both target builds and
vets, native Go/race tests, vulnerability and release-trust checks, architecture
checks, and the Xcode gate: 344 enumerated tests, 344 passing results. Default mode
is not full mount qualification.

The privileged authority slices reused the integration script's exact XFS,
quota, service-identity, and environment setup. `PORTABLEFS_GO_TEST_FLAGS` supplied
the package list. The normal script appends fusev3 and other packages to that
variable, so this invocation calls its existing provisioners and `suite_command`
directly, without changing the script or weakening any test:

```sh
PORTABLEFS_GO_TEST_FLAGS='./internal/authorityrpc/... ./internal/xfsstore/... ./internal/volumeserver/...' \
docker run --rm -i --privileged --tmpfs /var/tmp:exec,mode=1777 \
  -v "$PWD/vcs:/work/vcs:ro" -v "$PWD/scripts:/work/scripts:ro" \
  -v f1-priv-go:/home/portablefs/gocache \
  -v f1-priv-mod:/home/portablefs/gomodcache \
  -e PORTABLEFS_GO_TEST_FLAGS -w /work \
  golang@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 \
  bash -s <<'SH'
set -euo pipefail
source <(sed '/^case "${1:-}" in/,$d' /work/scripts/xfs-fuse-integration.sh)
install_container_dependencies
create_service_identity
provision_fuse_control
provision_xfs
provision_volume
mapfile -d '' -t command < <(suite_command)
runuser -u portablefs -- "${command[@]}"
SH
```

All three packages passed, including the required production XFS project gates,
authority end-to-end test, route-protection test, and blocked-lock/topology test.
The unprivileged slice skipped the two root-only chown unit tests and the
nonproduction O_TMPFILE unit test on its temporary filesystem. Those exact tests
passed separately with root privileges on tmpfs:

```sh
docker run --rm --privileged --tmpfs /tmp:exec,mode=1777 -e TMPDIR=/tmp \
  -v "$PWD/vcs:/work/vcs:ro" -v f1-gomod:/go/pkg/mod \
  -v f1-gocache:/root/.cache/go-build -w /work/vcs \
  golang:1.26.6-bookworm go test -v ./internal/xfsstore \
  -run '^Test(TmpfileRetainsCreationAccessAndExactLinkability|CreateOfAnExistingFileNeverReportsAnUncertainOutcome|ForeignOwnerFailsClosed)$' -count=1
```

Linux authority/coordinator race tests and the focused handler benchmarks also
passed in Docker:

```sh
docker run --rm -v "$PWD/vcs:/work/vcs:ro" -v f1-gomod:/go/pkg/mod \
  -v f1-gocache:/root/.cache/go-build -w /work/vcs \
  golang:1.26.6-bookworm go test -race \
  ./internal/authorityrpc/... ./internal/volumeserver/... -count=1 -timeout=120s

docker run --rm -v "$PWD/vcs:/work/vcs:ro" -v f1-gomod:/go/pkg/mod \
  -v f1-gocache:/root/.cache/go-build -w /work/vcs \
  golang:1.26.6-bookworm go test ./internal/authorityrpc -run '^TestCoherence' \
  -bench 'BenchmarkCoherence(ReadGuard|HandlerOnCommit)$' -benchmem -count=1
```

| Benchmark | Time | Bytes/op | Allocs/op |
| --- | ---: | ---: | ---: |
| Handler change construction plus OnCommit | 371.2 ns/op | 387 | 1 |
| Read guard | 378.0 ns/op | 328 | 7 |

These are single-run microbenchmarks from the shared four-CPU VM, not workload
latency or mount-throughput claims. The commit benchmark has no subscribers;
withdrawal latency requires the F2 integration workload. Earlier focused runs
through `scripts/xfs-fuse-integration.sh` passed their selected tests but exited 70
because its full required-test inventory rejects a filtered `-run`; the complete
package-slice invocation above exited zero.

## Source map

| Area | Files |
| --- | --- |
| CONTROL translation and transport capacity | `vcs/internal/authorityrpc/coherence_control_linux.go`, `server.go`, `protocol.go` |
| Storage guards, commits, open accounting, profile admission | `vcs/internal/authorityrpc/coherence_mutation_linux.go`, `coherence_reads_linux.go`, `coherence_open_linux.go`, `coherence_profile_linux.go` |
| Durability and FSKit repair | `vcs/internal/authorityrpc/coherence_durability_linux.go`, `coherence_fskit_linux.go`, `visibility_linux.go` |
| Dispatch and store callers | `vcs/internal/authorityrpc/volume_handler_linux.go`, `coordination_linux.go`, `write_linux.go`, `range_mutation_linux.go`, `fskit_write_linux.go` |
| Coordinator and lifetime hooks | `vcs/internal/volumeserver/delegation.go`, `subscription.go`, `session.go`, `coherence_admission.go`, `storage_sequencer.go`, `COHERENCE_V2.md` |
| Tests and deletion | Matching `coherence_*_linux_test.go` files; existing handler, wire, frame, terminal-delivery, range, write, client-bound, and coordinator tests; deleted `authorityrpc/leases_linux.go` |
