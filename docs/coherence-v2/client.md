# Linux protocol-7 client (F2)

The Linux frontend uses a volume subscription for names, attributes, directory
pages, and clean data. It uses `internal/writeback.Buffer` for delegated file
contents and metadata. The kernel writeback cache remains disabled. The wire
contract is [wire.md](wire.md); the Authority handler is a separate workstream.

## Cache admission and withdrawal

A cold subscription first withdraws local cache state, then fetches every page
of one frozen delegated-identity snapshot. The initial request start anchors
the horizon for the entire pagination sequence. No page grants permission on
its own. Cached payloads carry the subscription incarnation, a local publication
generation, and the reply's volume version; equal storage versions cannot make
a pre-withdrawal reply current again.

Renewal runs every three seconds. Polling, renewal, and acknowledgment have
independent admission lanes over CONTROL; one `NextControlEvent` is outstanding
at a time.
Receipt advances the CONTROL cursor while a separate worker withdraws change
batches and cumulatively acknowledges their change positions. Delegation work
runs independently of that worker, so a blocked kernel withdrawal cannot keep
the poll from delivering the recall needed to finish it.

The client stops cache admission one second before the conservative wire
horizon, using the shorter lead when the configured repair budget is below one
second. It withdraws
kernel state at that boundary and starts a cold subscription after failure.
Renewal cannot revive an expired incarnation. Before Subscribe, the client
fences delegation admission, drops the old incarnation's retained buffer with
a loss reason, and clears its grants. Existing server handles remain usable
after cold resubscription and may reacquire write permission.
Transient reverse-notification
failures retry within the remaining budget; an unconfirmed withdrawal marks
the inode stale and does not earn an acknowledgment. A successful cold
withdrawal can repair a coherence-stale inode. It cannot revive an old-epoch
inode or handle.

Names retain zero kernel dentry validity. Their daemon payloads and directory page
entries, including attributes, live under the subscription. This preserves the existing
protection against a kernel rename moving a cached name into a coordinate which never
authorized it. Namespace withdrawal revokes or drains pending replies and purges daemon
bindings; zero entry validity makes an entry notification unnecessary. Inode
notifications still withdraw kernel data and attributes. READ replies which finish
without permission receive a post-write purge before their physical publication drain
completes. The implementation indexes pending data publications by stable identity;
ordinary withdrawal does not scan unrelated pending reads.

The exact-coordinate source gate remains in place. A buffered write closes the
same local identity coordinates as a synchronous mutation and holds them
through the physical FUSE reply. This gate does not serialize unrelated files
or directories. Epoch recovery has a separate callback boundary to prevent an
old callback from admitting data into the replacement epoch's buffer.

## Delegated operations

Writable OPEN and CREATE request `write_intent`. The returned `cache_capable`
bit determines whether a read description may keep kernel data; writers use
direct I/O so the daemon owns admission. FULL mode accepts writes and metadata
into Buffer. WRITETHROUGH flushes each accepted operation before returning.
Buffer supplies extent overlays, coalescing, cuts, and per-file application
ordering. Its flusher sends at most the smaller of 1 MiB and the negotiated
write limit per WRITE, with the exact delegation id and generation on WRITE
and SETATTR. Split entries retain acknowledged-prefix progress across definite
transient failures. Explicit flushes of different identities remain concurrent;
background timer/cap work uses a bounded worker pool while preserving
per-identity order. Deferred close admission is bounded. Close batches wait for
application and release visibility ownership without waiting for durability;
completed replay records remain retained until the durable prefix advances.

Pure Authority mounts negotiate READDIRPLUS. Each 256-entry Authority page
admits daemon name and attribute payloads under its subscription stamp while
kernel entry and attribute validity remain zero. Capability transfer and cursor
advancement are provisional until the physical reply succeeds; failure rolls
back lookup ownership and the cursor. Mixed local-route mounts retain READDIR.

A physically accepted page also retains a bounded, subscription-stamped hint
from its start cookie to its stable identities. A warm READDIRPLUS sends only
that page's identities which still resolve in `nodesByIdentity`; a cold or
unknown page sends none. For an Item-less reply entry, the client resolves
`Dirent.stable_identity` through that table and takes a lookup reference with
`addLookupExisting` before any Item path can run. A missing or mismatched record
fails closed. Kernel FORGET drops lookup ownership but retains the daemon record
and capability while a live subscribed binding fits the registry. Name
eviction, horizon withdrawal, epoch replacement, or unmount retires it.

Unavoidable capabilities are reclaimed in exact batches of at most 4,096.
One collector coalesces same-epoch tokens until the cleanup watermark or a
short timer; FORGET itself remains nonblocking. This bounds cleanup RPCs by
pages or batches instead of entries without weakening replay or epoch fencing.

Under FULL ownership, FUSE FLUSH returns locally after checking loss unless the
closing POSIX lock owner may hold record locks on that identity. SETLK/SETLKW
acquisition attempts record this obligation before dispatch; successful FLUSH
clears only the generation it observed. The Authority remains responsible for
synchronous record-lock release. RELEASE retains its deferred CLOSE obligation.

Holder reads use `Buffer.Read`. GETATTR uses the holder's base attributes with
the buffer's size and metadata overlay. A new ownership interval fetches its
base lazily from the Authority; it does not reuse pre-OPEN LOOKUP attributes.
Every accepted write withdraws the
holder's kernel read range. O_SYNC/O_DSYNC uses `Buffer.WriteSync`; fsync flushes
the identity, performs FSYNC, feeds the returned durable prefix, and waits for
Buffer durability. An independent Barrier worker advances durability after
background flushes, including when admission is waiting for buffer capacity.
The wire has no separate visible-prefix field: a returned durable prefix feeds
VisibleSequence and then DurableSequence, conservatively proving both states.

Append remains Authority-positioned. The client first flushes the identity and
sends a synchronous delegated WRITE with `append=true`; it does not assign EOF
from a kernel offset or a stale local attribute. FALLOCATE and COPY_FILE_RANGE
also wait for preceding buffered operations and use synchronous RPCs because
Buffer has no range-operation entry type. NOW timestamps resolve once at buffer
admission, as specified by the writeback package, so retries retain the same
timestamps.

Recall retires admission, drains that identity's cache-installing replies,
flushes the retirement cut to application, detaches its read overlay, and
acknowledges the applied ticket. Its applied records remain charged until the
durable prefix arrives. Final-handle release uses the same separation of
visibility ownership from durability. Synchronous range mutations detach the
applied overlay and resume buffer admission before dispatch, preserving the
prior records' durability obligation without masking the new Authority bytes. Break flushes a captured cut without
surrendering ownership. Mode downgrade fences admission
through the flush before installing WRITETHROUGH. Upgrade installs FULL before
acknowledgment. A missed budget or an unprovable flush drops retained entries
and advances Buffer's loss sequence. No retry invents a new replay identity for
an uncertain applied entry.

Rename, link, and unlink flush the affected identities before dispatch. A cold
namespace binding is resolved before this dependency check; daemon eviction
cannot hide dirty data from F4. Last-close cleanup collects delegated handles
for at most 25 milliseconds or 128 handles, keeps the server handles alive
through application and sorted DelegationRelease, then sends one CloseBatch. Nondelegated close retains its existing
synchronous error path.

A mount-root OPENDIR records the mount loss sequence. FSYNCDIR on that exact
handle flushes a Buffer cut, sends Barrier with the Authority application ticket,
and waits for its durable prefix. Clean detach also performs a bounded barrier
before stopping the buffer when retained entries or non-durable tickets remain.
FSYNCDIR returns EIO if the barrier fails or a generic loss advanced since
OPENDIR. A definite pre-apply capacity loss retains its original ENOSPC,
EDQUOT, or EFBIG instead. FUSE_SYNCFS is not the completion mechanism.

## Epoch replacement

An Authority epoch change suspends subscription admission and permanently
stales every old server handle and inode capability. Old operations return EIO.
The client drops non-durable buffer entries with an epoch-change reason, drains
old subscription workers, withdraws caches, and cold-attaches through a stable
RPC facade. It publishes a new root capability and then subscribes cold. New
lookups and opens use the replacement session; old handles never inherit its
capabilities. Recovery retries while the mount remains present. Transport death
and operator unmount retain the existing terminal revocation path.

## F1 assumptions and integration boundary

F1 must supply these exact behaviors; fake-Authority tests do not establish
that the handler implements them:

- Linux activation omits all v6 lease state. Every cache-installing reply has
  `Response.volume_version`; READ also repeats it in `ReadReply.volume_version`.
  Existing object/snapshot versions and mutation post-state remain meaningful.
- Subscribe pages repeat the snapshot id, watermark, incarnation, and original
  horizon duration. The delegated set includes reservations and recalls. Event
  sequences and change positions are separately contiguous within an incarnation.
- OPEN/CREATE return a valid delegation when they accept write intent, and
  `cache_capable` reflects Authority accounting for that handle. A locally
  recalled open can request a fresh grant through another OPEN.
- Successful changed WRITE, SETATTR, and FALLOCATE return nonzero per-session
  application tickets. Exact replay preserves those tickets. WRITE returns its
  actual placement, committed size, and post attributes. FSYNC and Barrier
  report contiguous durable prefixes; Barrier uses mutation replay on DATA.
- COPY_FILE_RANGE has no DelegationRef field. F1 must infer destination ownership
  from the destination handle and avoid waiting for a self-break while that
  synchronous operation holds the local ordering boundary. The client flushes
  source and destination dependencies first.
- CONTROL acknowledgments require no mutation replay slot. Recall, break,
  mode change, and release use the same subscription incarnation and exact
  delegation reference. Release arrays sort by delegation id.
- A stale delegation rejection uses the coherence failure class without ending
  the transport. Epoch mismatch remains distinguishable from transport death.
  F1 must preserve independent CONTROL progress while DATA is waiting for an
  acknowledgment.

The mount RPC interface exposes Subscribe, RenewSubscription, NextControlEvent,
ChangeAck, the delegation acknowledgments/releases, and Barrier. The epoch
adapter exposes `RecoverEpoch(context.Context) (RPC, error)` at the frontend
boundary; the concrete Authority client returns a newly attached Client.
Neither the facade nor any old handle mutates its original epoch's capability.

The shared server request allowlist still contains historical lease operation
spellings. The Linux client rejects those requests and responses locally. Their
server-side removal belongs to F1/G.

## Verification and limits

The repository's stale-architecture scan prohibited every `internal/writeback`
import before F2. Its pattern now permits the package explicitly required by
protocol 7. This is the only gate-script scope adjustment; no Authority handler,
coordinator, session implementation, or wire source changed here.

Kernel invalidation and FSYNCDIR proof sources on `cv2-proofs` informed the
ordering. The final report records the commands actually run. A focused Docker
run with `PORTABLEFS_GO_TEST_FLAGS` exercises unit/fake-Authority cases, but the
script's full-suite inventory check can still fail because that selection
intentionally excludes required real-mount tests. It is not end-to-end evidence.
The full real-mount suites require F1's handler and must be rerun after integration.

Delegation bookkeeping retains identities which actually received a grant after
release, preserving safe state references and reacquisition generations. Cold
reads and GETATTR do not allocate this state. Long-lived mounts touching many
writable identities therefore retain per-identity metadata until cold
resubscription, epoch change, or unmount; bytes and completed replay records still retire at durability.


## Changed files

All Go paths below are under `vcs/internal/`.

- `authorityrpc/client.go`, `authorityrpc/coherence_v2_client.go`, and their
  tests: protocol-7 CONTROL methods, lane admission, validation, and epoch attach.
- `fusev3/subscription_linux.go`, `cache_publication_linux.go`,
  `delegation_linux.go`, `delegation_frontend_linux.go`, `epoch_rpc_linux.go`,
  `epoch_frontend_linux.go`: subscription, buffer integration, and recovery.
- `fusev3/fuse_linux.go`, `raw_linux.go`, `coherence_linux.go`,
  `source_publication_linux.go`, `stock_write_linux.go`,
  `range_mutation_linux.go`: frontend callbacks and publication ordering.
  `fusev3/leases_linux.go` is removed.
- `fusev3/subscription_linux_test.go`, `delegation_linux_test.go`,
  `epoch_rpc_linux_test.go`, `epoch_frontend_linux_test.go`,
  `client_v7_linux_test.go`, `create_truncate_linux_test.go`: new coverage.
- `fusev3/fuse_linux_test.go`, `leases_linux_test.go`,
  `lease_read_admission_linux_test.go`, `source_publication_linux_test.go`,
  `stock_fixture_linux_test.go`: updated fixtures and replacement guarantees.
- `mountv3/epoch_linux.go`: production recovery adapter.
- `scripts/verify-local.sh` and this document: writeback scan correction and
  the integration contract.

## Commands and results

Run from the repository root on macOS:

```sh
CGO_ENABLED=1 GOOS=darwin go -C vcs build ./...
CGO_ENABLED=0 GOOS=linux go -C vcs build ./...
go -C vcs vet ./...
go -C vcs test -race ./internal/writeback/... ./internal/mountv3/...
bash scripts/verify-local.sh
```

All passed. The native mountv3 package has no test files. The default gate
includes native Go/race, both builds and vets, vulnerability checks, the
physical-reply seam, release policies, and the exact 344/344 Swift inventory.

The Linux unit/fake-Authority suite was run in the pinned integration image:

```sh
docker run --rm -v "$PWD:/work" -w /work/vcs \
  golang@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 \
  go test -race ./internal/fusev3 \
  -skip '^TestKernelFUSEProbeCompletesInit$' -count=1 -timeout=3m
```

This passes. The excluded probe needs the privileged FUSE device; ordinary
integration tests skip without their real-mount environment. The dedicated
privileged run uses:

```sh
PORTABLEFS_GO_TEST_FLAGS='-run ^Test(Subscription|Delegation|Epoch|V7|CreateTruncate|CoherenceStale|CleanClose|CancelledShutdown) -race' \
  bash scripts/xfs-fuse-integration.sh
```

All 47 selected top-level tests passed with no race reports. The harness
exited 70 solely because this selection omits its required full-suite inventory.

The full integration attempts were:

```sh
bash scripts/verify-local.sh --full
bash scripts/coherence-matrix-linux.sh
```

Workstream G subsequently passed the full gate (run 156), including all 66
required FUSE integration tests and the root-barrier probe. Its separate matrix
run 157 passed all 28 applicable cases, with the existing unsupported chown case
skipped and both controls matching. G2 restored those Docker gates after reversing
the rejected EntryNotify acknowledgement path; see the dated evidence and later
qualification results in [integration.md](./integration.md). The earlier obsolete
lease activation failure is resolved.

Hot-path benchmarks in Linux arm64 report zero allocations for subscription
permission and both cold/live delegation ownership checks. Source publication
admission costs 12 allocations with either zero or 4,096 unrelated coordinates;
its work does not grow with the unrelated coordinate count. Change admission
costs two allocations. Benchmark timings are local observations, not workload
performance claims.


## G2 final-handle cleanup

Final-handle release waits for buffered application, not durability. A logical
release flight blocks same-identity admission while the per-state acquire,
transition, and operation mutexes are free during RPC. Successful release
removes the old overlay; applied records remain retained until a durable prefix.
The next grant resumes a fresh overlay generation. Final descriptor cleanup uses
one replayed `CloseBatch` for at most 128 handles and consumes its ordered
`retired` outcomes. Unknown cleanup ends the mounted session so unresolved
handles remain owned by terminal cleanup. See wire.md for the additive feature
and encoding contract.
