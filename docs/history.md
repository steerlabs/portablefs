# History

History in PortableFS is asynchronous. The fenced Postgres journal is the
authority durability layer: a mutation is authority-durable when that
journal transaction commits, and nothing on the write path ever waits for a
cut, checkpoint, or object storage. A delegated mount may accept `write(2)`
before this point; `fsync` drains through it. History is built behind the
authority write path from the journal itself: a **HistoryCut** pins one exact
journal position in a short database transaction, and an external worker
later reconstructs that cut into immutable, content-addressed **PFT2**
objects in blob storage.

```text
write path:    client -> authority -> fenced Postgres journal -> ack
history path:  cut_create (short txn, pins seq+digest,
                           chained on the branch's newest ready cut)
               -> history-worker claims the cut
               -> deterministic reduction of the exact journal suffix
               -> verified PFT2 objects at write-quorum coverage
               -> atomic O(delta) ready publication
```

Ready cuts are what branching, forking, publishing, and time travel consume.

## HistoryCuts

A cut records one exact immutable filesystem revision. The database
linearizes it at:

```text
(tenant, volume, branch,
 journalGenerationId, journalEpoch,
 sourceBaseCommitId, sourceBaseSeq, sourceBaseDigest,
 cutSeqExclusive, cutDigest,
 recordCodec, materializerVersion)
```

`cutSeqExclusive` and `cutDigest` are copied while holding the same
journal-head row lock the append path uses, so a racing append is wholly
before or after the cut. Capture reads no authority RAM and no object
storage.

Capture chains: a managed-journal cut's frozen source base is the branch's
newest READY cut of the same generation whenever one exists strictly below
the captured head (the generation's adoption-pinned base otherwise). The
fold therefore covers only the tail since the last ready cut, not the
branch's whole backlog since the last adoption. The generation base itself
still advances only through adoption — journal trimming stays adoption's
job, and the captured cumulative backlog counters stay adoption-relative.

Cut kinds (`user`, `recovery`, `conversion_final`) are consumption-rights
labels, not different materializations: every ready cut carries both the
user root and the verified recovery anchor. Capture dedup is kind-agnostic
between `user` and `recovery` — requests for either kind at one exact
boundary converge onto one cut row (one fold, one object set), and a
labeled request converging onto an unlabeled live row adopts the label
(first label wins; the journal position, not the label, is the cut's
identity). `conversion_final` keeps its own dedup axis: it drains whole
legacy generations through a different pipeline.

### State machine

```text
pending -> materializing -> ready
   ^            |
   |            +-> pending (retryable failure/backoff)
   +------------+

pending/materializing -> failed or canceled (definite CAS only)
```

- `pending` is a durable work item and a journal trim pin.
- `materializing` carries a worker id, a monotonically increasing claim
  epoch, a database-time lease, bounded attempt diagnostics, and a
  next-attempt time. An expired lease returns the cut to `pending` under a
  newer claim epoch; a stale epoch can never publish anything.
- Store/network/overload failures are retryable and never tell a user a
  revision is corrupt. Proven journal corruption is definite: it marks the
  cut `failed` and never releases the journal prefix for trimming.
- `ready` is immutable. It names a verified commit/tree plus provenance.
- Only ready cuts can be branched, forked, or published. Pending and failed
  cuts cannot.

Workers claim bounded oldest-first pages with `FOR UPDATE SKIP LOCKED`. All
coordination state — claims, leases, fences, receipts, publication — lives in
PostgreSQL behind the `pfh` SECURITY DEFINER surface; the worker role holds
zero table privileges. The worker itself holds only disposable memory and can
be killed at any instant.

## Deterministic materialization

The worker drives one shared deterministic reduction
(`vcs/internal/historycut`) for every claimed cut:

1. Load and verify the frozen immutable source base (see base modes below).
2. Stream exactly `[sourceBaseSeq, cutSeqExclusive)` through bounded journal
   pages, verifying each record's sidecar hash and the chain digest from the
   frozen base digest to the frozen cut digest
   (`chain = sha256(prev || be64(len) || payload)`).
3. Decode every record strictly (PFJ3 tree intents, PFC2 controls) and fold
   tree records through the one shared filesystem transition engine
   (`vcs/internal/fstransition`) over a `pft2.Editor`, and controls through
   `pfc2.State`.
4. Path-copy exactly the changed PFT2 nodes and assemble the user root plus
   the recovery anchor.
5. Upload every produced object as it is produced — every still-missing
   required domain in parallel — verify each copy by readback, and record
   fenced copy receipts in batched transactions (see object storage below).
6. Publish readiness atomically under the live claim epoch. Registration
   is O(delta) over an adopted base: the worker registers only the objects
   this run produced and the database copies the base cut's closure rows
   server-side (`pfh.cut_objects_add_from_base`). The copied closure is a
   superset of the exact reachable set (objects the fold deleted stay
   registered), so a deterministic ~1-in-16 slice of cuts — a pure function
   of the frozen cut digest, so every retry of one cut makes the same
   choice — publishes the exact recomputed closure instead, keeping
   registration and GC rootedness bounded under churn.

The reduction is deterministic end to end: object boundaries, node splits,
pack boundaries, and therefore every digest depend only on the frozen cut
tuple and fixed constants — never on worker count, scheduling, retry, or
resume. `MaterializerVersion` names this exact reduction; changing any
committed-byte-affecting rule changes the version string. Crash/rerun
convergence follows from determinism: uploads are idempotent at
per-incarnation exact keys and cursors/receipts live in PostgreSQL, so a
rerun emits byte-identical objects. Retries are convergent, not repeated:
before uploading, an attempt batch-locates its object set
(`pfh.object_locate_batch`) and skips every object that already holds
fresh verified copies at the bound incarnation in the required domains, so
an attempt that dies mid-upload leaves receipts the next attempt builds on
instead of re-shipping the whole set.

Folding applies exactly the live authority's per-leaf semantics. Every
envelope-carrying leaf's deterministic outcome (status, ino, count, resolved
offset, orphan ino) is serialized into the anchored control map
byte-identically to what the live apply stored, so a duplicate retry against
an authority that adopts this cut replays the original status instead of
re-executing. An envelope-less leaf may fail only with the explicitly proven
benign replay outcomes cold replay tolerates
(`fstransition.BenignEnvlessOutcome`); anything else fails the cut closed.
Every logged inode identity — deterministic failures and unused reservation
members included — advances the anchored allocator cursor, so an adopting
allocator can never re-issue a burned identity.

The empty filesystem is a first-class fold outcome. A cut whose record range
carries only control traffic (sessions, checkouts, flushes) over a base with
no user filesystem root — a fork-origin generation before its branch writes a
byte — reduces to the EMPTY filesystem: the fold proves that state explicitly
(`Editor.EmptyOverEmptyBase`: no base root, nothing staged) and materializes
the canonical empty root through `pft2.BuildEmptyFilesystem` — inode 1 as an
empty `0755` directory with epoch-zero timestamps, its one-entry inode index,
and the ROOT over both, byte-identical to what a transaction that creates
only inode 1 commits. The anchor over it is an ordinary anchor, and the
editor's own refusal to invent a root from an accidental empty transaction is
untouched. It is NOT a materializer version bump: no cut that ever produced a
root changes a byte.

### Base modes

A cut's base relationship to its branch is explicit and database-proven; the
cut projection carries `baseCommit.baseMode`:

- `adopted` — a PFT2 commit produced by a cut of the same branch. Its
  recovery anchor (controls, orphans, checkout epochs, database-time floor,
  allocator cursor) binds exactly and is re-verified against the hashed
  RecoveryRoot: filesystem root, as-of sequence, namespace, and next-local.
  Chained capture makes this the ordinary case: every managed-journal cut
  with a ready predecessor folds from it.
- `fork` — a PFT2 commit produced by a different branch's cut. Only the
  immutable user root is imported; the source anchor is never even fetched.
  The fork starts with default control state, no orphans, and its own
  never-reused inode namespace.
- `conversion` — a legacy flat-manifest base imported through the conversion
  pipeline. PortableFS volumes are journal-born, so this mode and the
  `legacy_manifest` source kind exist for schema compatibility; the enum and
  its verification are implemented in full (a conversion import verifies
  every blob digest, size, offset, and decompression bound, then proves the
  recomputed canonical tree hash against the pinned anchor commit).

Missing, unknown, or contradictory mode facts fail the cut closed before any
folding.

## User roots and the recovery anchor

A user cut contains filesystem history only. It excludes exact sessions and
reply outcomes, locks and checkouts, open pins and parked-orphan ownership,
flush watermarks, and every manager/runtime/access identity.

Compaction requires a separate internal recovery anchor at the exact same
`(generation, epoch, sequence, digest)`: a `RECOVERY_ROOT` object holding the
control image (a PFC2 `CONTROL_ROOT`), the parked-orphan index, and the
branch's allocator watermarks. The anchor is never reachable from a snapshot,
publish record, or new branch, and the materializer proves the two closures
are disjoint: user APIs only ever serve the user set.

A new branch inherits the ready filesystem root, receives a never-reused
database-issued 31-bit inode namespace and counter 1, and starts sequence
zero with an empty control/orphan anchor. It never copies the source
allocator; inherited inode ids remain stable while sibling branches allocate
disjoint ids.

## Cross-volume fork

A ready cut can also be forked into a NEW volume
(`POST /v1/snapshots/:cutId/fork`, migration `018_managed_volume_fork`).
The fork is zero-copy and atomic in one database transaction:

- The destination volume's default branch is born `managed_journal` at a
  fork-point PFT2 commit carrying the cut's exact immutable user-root
  identity (tree hash from the copied root digest, lineage to the source
  result commit, copied byte count). No PFT2 object is duplicated — both
  volumes serve the same content-addressed objects.
- An ACTIVE `fork` cut consumer bound to the destination branch is the
  durable GC root of the source cut for this fork: the shared objects stay
  pinned for the destination's lifetime.
- The destination gets its own fresh never-reused inode namespace and ZERO
  inherited recovery state — no RecoveryRoot, controls, or orphans, exactly
  like a same-volume branch fork. The immutable
  `pfh.pft2_fork_commits` provenance row (installed by a history-owner
  SECURITY DEFINER re-proof in the same transaction) is what
  `pfh.serving_base_prove` later verifies as `baseMode: "fork"` when the
  destination's first authority claims its seq-0 generation.
- The operation is exact-once: an explicit `operationId` keys the permanent
  resource-operation ledger, an identical retry replays the recorded
  destination, and a refused fork rolls back entirely (no partial volume,
  branch, namespace, consumer, or provenance row survives).

Only ready cuts fork; pending/failed cuts answer the same typed refusals as
branch creation, and lineages without migration 018 refuse typed with
`HISTORY_FORK_UNSUPPORTED`.

## PFT2: the immutable tree format

PFT2 is the digest-verified, strictly canonical object tree ready cuts
materialize into. It is not the ordinary-write journal format.

### Object envelope

```text
"PFT2" || strict-pfwire-body
digest = sha256(exact complete bytes)
```

The body follows the strict deterministic pfwire rules: ascending frozen
fields, minimal varints, omitted defaults, contiguous repeated fields, and
rejection of unknown/duplicate/out-of-order fields, malformed UTF-8, explicit
defaults, overflow, and trailing bytes. Any accepted object re-encodes to
identical bytes, so there is exactly one valid byte representation for any
tree. An object reference carries the raw 32-byte digest and the exact
encoded size; the advertised size is enforced before allocation and fetched
bytes are hashed before decoding.

### Node kinds

```text
1 ROOT              filesystem root: root inode ref, inode index ref,
                    max_ino_seen, inode/dirent/logical-byte counts, features
2 INODE             file/directory/symlink metadata + tree roots
3 DIRECTORY_LEAF    sorted raw-byte dirents (no Unicode normalization)
4 DIRECTORY_INDEX   verified first/last/count child summaries
5 EXTENT_LEAF       page-offset -> DATA_PAGE entries
6 EXTENT_INDEX      verified page-range child summaries
7 INODE_INDEX_LEAF  ino -> INODE entries
8 INODE_INDEX_INDEX verified ino-range child summaries
9 RECOVERY_ROOT     internal anchor: as-of seq, fs root, control root,
                    orphan index, inode namespace, next local counter
10 DATA_PAGE        16 optional 4 KiB cell slots (missing = hole)
11 CONTROL_ROOT     schema, map root, next checkout epoch, db-time floor,
                    per-kind counts
12 CONTROL_LEAF     sorted opaque PFC2 control entries
13 CONTROL_INDEX    verified key-range child summaries
```

Nodes target 64 KiB with a 256 KiB encoded ceiling, at most 4096 leaf
entries or 256 index children, and a maximum tree depth of 12. Deterministic
split/collapse rules make the same ordered element sequence always produce
the same tree.

### Structural separation and per-edge verification

The filesystem `ROOT` has no field that can name session, lock, checkout,
access, manager, or allocation state; those live only under `RECOVERY_ROOT`.
Readers verify the node kind of every fetched reference against the edge it
was reached through, so a user root can never resolve into a recovery or
control node.

A parent's child summary (first key, last key, entry count) is a claim the
wire format cannot prove by itself: a crafted content-addressed graph could
hide, duplicate, reorder, or misroute entries while every individual node
still validates. Every fetched descent therefore cross-checks the decoded
child against the parent advertisement — family kind, exact first key, exact
last key, exact entry count — and the filesystem inode index root pins
against the `ROOT` object's verified facts (`inode_count` exactly, first
inode is 1, last inode `<= max_ino_seen`). Any mismatch fails closed as
corruption before an entry is served or copied. Verification is lazy by
construction: only fetched edges are checked and ordinary reads never scan
unrelated subtrees, so a lie behind a never-fetched edge surfaces on the
first traversal that touches it.

### File content

Extent trees are keyed by 64 KiB-aligned logical page offset; each present
entry references one immutable `DATA_PAGE` of 16 optional 4 KiB cells. A
present `CellRef` carries the sha256 of the canonical 4096 logical bytes,
the packed immutable data object reference, and an aligned offset; the slice
length is structurally exactly 4096. Missing cells and pages are holes that
read as zero, an all-zero cell is canonically a hole, an all-hole page is
omitted, and bytes beyond logical EOF are canonically zero (enforced, not
assumed). Changed nonzero cells pack in deterministic
`(inode, pageOffset, cellIndex)` order into immutable packs of at most
4 MiB, with one exact underfilled terminal pack in 4 KiB increments.

### Stable inode allocation

```text
ino = (namespace << 32) | localCounter
namespace    1..2147483647   (never reused; issued per branch)
localCounter 1..4294967295   (never wraps)
```

The result is positive and fits a PostgreSQL signed `BIGINT`. Namespace 0 is
reserved for inode 1 and verified legacy inode ids. Inherited inode ids
remain unchanged across forks, so hard links and rename identity survive,
and sibling branches can never assign the same id to unrelated files.
Namespace and counter exhaustion are typed terminal errors. Every JSON/
TypeScript boundary serializes inode and allocator values as canonical ASCII
decimal strings, never JavaScript numbers.

### Go and TypeScript parity

Two implementations produce and consume PFT2: the Go writer/reader
(`vcs/internal/pft2`, used by the worker) and the TypeScript reader/builder
(`packages/core/src/pft2`, used by API serving). Both are strict: identical
trees produce byte-identical objects and digests on both sides. The shared
golden file `testdata/pft2/golden.json` — generated by the Go side
(`PFT2_UPDATE_GOLDEN=1 go -C vcs test ./internal/pft2/ -run TestGolden`) —
pins the canonical bytes of every node kind plus deterministic-builder
output for whole filesystems, and both test suites must reproduce it
exactly.

## Exact-key verified object storage

`vcs/internal/histstore` is the object layer under history: one narrow Store
interface (`Put`/`Get`/`Head`/`Delete` at exact keys) over two backends — a
confined local filesystem (openat-style traversal under one root handle,
exclusive temp file, incremental hash proof, fsync, atomic rename, parent
directory fsync) and any S3-compatible endpoint (SigV4, streaming bodies,
per-call deadlines, no whole-object buffering). The Go SigV4 signer mirrors
the TypeScript `@portablefs/storage-s3` signer byte for byte.

Keys are exact and recorded. The worker derives a key once, immediately
before the first PUT, from the full object identity:

```text
t/<tenant>/pft2/sha256/<d[0:2]>/<digest>/i<incarnation>
```

and records the store's fully prefixed key in the database copy receipt.
Every later read, scrub, repair, and delete presents a database-recorded key
verbatim; nothing ever treats a digest-derived path as the location of
truth. Every copy is written to its exact key, independently read back from
that key, size-matched, and hash-verified before the fenced copy receipt is
recorded; still-missing domains are written in parallel and receipts land
in batched transactions — including proven copies of an object whose
quorum attempt failed, so the next attempt converges on them.
`ReadVerified`/`VerifyStream` are the only ways worker code turns a
recorded key into trusted bytes.

Each logical object has an incarnation; physical keys embed it, so a delayed
delete of incarnation N can never remove a re-upload at N+1.

### Failure domains and the replication floor

Every history object is replicated across operator-declared **failure
domains** — attestations of independence (different disks, buckets,
providers), never derived from endpoints. The installed replication policy
(one frozen row, expected-epoch CAS install, 1..8 distinct domains) names
the exact domain set copies may land in. Readiness is a **write quorum**
over it: a cut publishes once every closure object holds W = min(2, N)
independently verified copies in required domains (N = 1 admits 1). Copies
the quorum did not need are healed asynchronously by the ordinary repair
loop, which still targets every policy domain. With the production floor
of exactly two domains W = N = 2 — an outage in either still blocks
readiness; the quorum only relaxes deployments with three or more
independent domains.

The deployment's replication floor is configurable:

- `PFH_WORKER_MIN_FAILURE_DOMAINS` (default `2`) is the minimum number of
  distinct failure domains that must be configured and named by the policy
  before the worker writes history. The default keeps two independently
  verified copies of every object.
- Setting the floor to `1` explicitly admits single-domain deployments — a
  legitimate self-host posture where the host's own storage redundancy is
  trusted.
- Production mode (`VCS_PRODUCTION=1`, the same deployment-wide switch the
  rest of the stack validates against) refuses any floor below 2.

A policy naming fewer domains than the floor, or a required domain this
deployment has no store for, is a typed policy mismatch: retryable operator
work, never something written under the wrong policy and never reported as
corruption.

### Store configuration

`PFH_WORKER_STORES_JSON` declares one exact-key store per failure domain and
is the single logical-domain map for the whole deployment: the history
worker consumes it, and any process serving tenant history reads consumes
the same value, so blob storage is configured once and the domain map cannot
drift.

```json
[
  {"failureDomain": "local-a", "kind": "fs", "rootDir": "/srv/pfs-history-a"},
  {"failureDomain": "bucket-b", "kind": "s3",
   "endpoint": "https://s3.example.com", "region": "auto",
   "bucket": "pfs-history", "pathStyle": true,
   "accessKeyId": "...", "secretAccessKey": "...",
   "prefix": "optional/prefix"}
]
```

Duplicate failure domains and two declarations naming the same physical
target (same filesystem root, same endpoint+bucket) are rejected at
validation, before anything connects.

### Worker configuration

`vcs/cmd/history-worker` is the one resident worker process. Configuration
is environment-only; secrets are never logged (`Config.Redacted()` is the
only loggable projection).

Required:

```text
PFH_WORKER_DATABASE_URL   restricted history-worker role DSN
PFH_WORKER_ID             worker identity in claims/heartbeats (1..128 chars)
PFH_WORKER_POLICY_EPOCH   the policy epoch this deployment was rolled out for
PFH_WORKER_STORES_JSON    the failure-domain store map (above)
```

Optional (bounded; defaults in `histworker.FromEnv`):
`PFH_WORKER_MIN_FAILURE_DOMAINS`, `PFH_WORKER_DB_MAX_CONNS`,
`PFH_WORKER_MATERIALIZE_CONCURRENCY`, `PFH_WORKER_UPLOAD_CONCURRENCY`,
`PFH_WORKER_SCRUB_BATCH`, `PFH_WORKER_SCRUB_CONCURRENCY`,
`PFH_WORKER_REPAIR_BATCH`, `PFH_WORKER_REPAIR_CONCURRENCY`,
`PFH_WORKER_LEASE_TTL_MS`, `PFH_WORKER_HEARTBEAT_MS`, `PFH_WORKER_POLL_MS`,
`PFH_WORKER_OPERATION_TIMEOUT_MS`, `PFH_WORKER_SWEEP_MIN_AGE_MS`,
`PFH_WORKER_FRESHEN_AGE_MS`, `PFH_WORKER_SHUTDOWN_GRACE_MS`,
`PFH_WORKER_TEMP_SWEEP_AGE_MS`, `PFH_WORKER_MAX_CACHE_BYTES`,
`PFH_WORKER_MAX_PENDING_UPLOAD_BYTES`, `PFH_WORKER_MAX_LEGACY_BLOB_BYTES`,
`PFH_WORKER_LEGACY_STORE_JSON`, `PFH_WORKER_LISTEN_ADDR`.

`PFH_WORKER_LISTEN_ADDR` serves `/healthz` (liveness), `/readyz` (database
migration/capability, policy admission, and per-domain store reachability),
and `/metrics` (low-cardinality Prometheus text). There is deliberately no
data-plane surface on the worker.

## Scrub, repair, retention, and GC

The same worker process runs independent maintenance loops, all fenced
through database claims:

**Scrub** claims due copies and verifies each against its own recorded exact
key in its own failure domain, streaming with constant memory. Proven
absence or a content mismatch is a definite negative receipt; transport
trouble records nothing (the pushed-out verify window is the retry lease).
Repeated definite negatives quarantine the object.

**Repair** claims leased missing/failed destination copies, re-verifies a
healthy source at its recorded exact key at repair time (a stale claim row
grants nothing), writes the destination at its exact per-incarnation key,
proves it by readback, and records a fenced repair receipt. Incarnation
supersession fences stale repairs. An object with no verified source
anywhere stays quarantined and reported — it is never "healed" by
fabrication.

**Retention** turns the release cranks the root predicate needs.
`pfh.retention_release` — a bounded worker loop pass — releases adoption
consumers whose adoption is durably superseded (a strictly newer applied
adoption exists for the same generation, or the generation is gone) and
whose serving pin is already released; snapshot/branch/fork/publish/
conversion consumers are owned by their own lifecycles and never
auto-released. Named snapshots are deleted through the caller surface
(`pfh.snapshot_cut_release`, `DELETE /v1/volumes/:volumeId/snapshots/:name`):
the named ready cuts drop their label and snapshot consumers, age out of
the retention window, and the ordinary sweep collects their objects.

**GC** is reachability-safe and performs one fenced object sweep at a time.
Rootedness IS the retention policy (`pfh.object_is_root`): a live
(pending/materializing) fold's upload intents and its base cut's closures
are roots, and a ready cut's closure stays rooted iff the cut is

- **pinned** — an unreleased consumer (branch/fork/publish/conversion/
  adoption/snapshot), an unreleased serving pin, the source base of an
  in-flight fold, or its commit is a branch head, a public snapshot, or a
  live generation base;
- **named** — it carries a user snapshot label, on a live (unretired)
  volume; or
- **recent** — among the newest 8 ready cuts of its branch, on a live
  volume.

Everything that falls out of the root set is collected by the sweep. A
sweep claims one unreferenced incarnation under a database-time lease,
deletes every database-recorded exact copy, proves each key absent with an
independent head, and only then completes with the full
incarnation/reclaim-generation/claim-epoch tuple. A late root or re-upload
resurrects (or bumps the incarnation) instead of losing reachable history;
a delayed tombstone prevents ABA. A time-based grace period is not the
correctness mechanism for an upload-before-commit race. Filesystem backends
additionally sweep only old, structurally named crash-orphaned temporary
uploads; final objects are never swept by age.

## Journal bounding: recovery cuts and adoption

Live PFJ3 generations are admission-bounded: appends stop at the generation
quota (4 GiB / 1,048,576 records by default, plus a fixed hidden control
reserve so fencing and rejection outcomes stay journalable at exhaustion).
Generations are resumed, not rotated, across child restarts, so a branch's
cumulative backlog persists for its lifetime. The ONLY admitted shrink is
**adoption** of a ready cut of that managed journal:

1. `pfh.cut_adopt(cutId, anchorId)` requires a ready cut of a pfj3 managed
   journal and verifies that the anchor is THE anchor of that cut. Any
   ready cut qualifies — every ready cut carries a verified recovery
   anchor, and user/recovery captures at one boundary converge onto one
   row — so a snapshot cut at the trim boundary never forces a second
   fold.
2. The journal-owner primitive verifies the exact old base tuple under the
   append lock order, advances the generation's base
   (commit/sequence/digest) to the cut boundary, and subtracts the captured
   cumulative backlog in O(1). The replaced freeze trigger independently
   re-verifies the change against the durable adoption proof row.
3. Adoption installs a **serving pin** binding the pre-adoption base (and
   the pinned runtime facts: writer fence, manager epoch, authority runtime)
   as a GC root, so a child still serving the old base never loses its
   objects. The pin releases only through
   `pfh.serving_pin_release_fenced` — provable durable supersession
   (advanced writer fence, terminal generation, or a released/expired writer
   lease), never a TTL.

The volume-api's **maintenance loop** drives this end to end (see
[self-hosting.md](./self-hosting.md) for configuration): every cycle it
scans generations past the backlog threshold
(`pfj.generations_past_threshold`, migration 017), creates the recovery cut
under the deterministic operation id `hcut-<generationId>-<baseSeq>`,
adopts the cut once the worker marks it ready under `hadopt-<cutId>`, and
offers every unreleased pin to the fenced release. The base sequence only
advances through adoption, so the operation ids give exactly one cut and one
adoption per (generation, base) across any number of replicas, crashes, and
replays — the permanent resource operations replay the recorded outcome
instead of re-mutating. Fenced refusals (an older pending cut still pinning
the prefix, a pin whose runtime is still live) are the machinery working as
designed and are counted, not logged as errors.

Two operational properties of adoption worth knowing:

- **Adoption requires exact history serving.** The post-adoption base is a
  PFT2 commit the next cold start fetches through `/v1/history/*`. The loop
  therefore holds the adoption step (counting `adoptionsBlocked` in its
  cycle telemetry, with a one-time operator warning) on deployments without
  `PFH_WORKER_STORES_JSON` / `VOLUME_HISTORY_STORES_JSON`; ready cuts wait,
  instantly adoptable once serving is configured.
- **Adopting under a live writer forces that authority to restart.** The
  live child's journal mirror treats any base-commit move it cannot prove as
  poison (fail-closed by design: an unproven base move is indistinguishable
  from corruption), so its next append fences the data plane and steps down;
  the manager demand-starts a replacement that cold-starts FROM the adopted
  base (a short replay, which is the point of adoption). Acknowledged writes
  are journal-durable throughout — the cost is one bounded authority restart
  per adoption on actively-writing branches. A future hot base swap rides
  the `pfh.serving_pin_ack` seam (the child acknowledging the swapped base
  in place); until then the restart IS the swap.

Admin routes under `/v1/admin/history/*` (admin token) expose the same
caller surface for manual drives and inspection: `POST /cuts`,
`GET /cuts/:cutId?tenantId=...`, `POST /cuts/:cutId/adopt`.

## Serving history reads

Tenant history reads are exact. The API first obtains a positive database
proof for the already-claimed journal-base tuple (generation, base sequence
and digest, record codec, control codec); only a positive proof selects a
base, and absence, timeout, contradiction, or malformed data fails closed.
PFT2 objects are located by tenant and digest, read only from
database-recorded exact storage keys in declared failure domains, bounded by
the frozen PFT2 maximum size, and SHA-256 verified before any response bytes
are exposed. A missing or corrupt copy falls through to the next independent
failure domain and is queued for the worker's ordinary scrub/repair loop. No
aggregate blob-store lookup, caller-supplied storage key, absence inference,
or inline repair participates.

## Verification

Unit suites run with no Postgres and no network: the reducer and worker
tests fake the `pfh` surface and the object stores in memory (including an
in-process S3 double that verifies real SigV4 signatures), and cover
adversarial corruption, crash/lost-response convergence, concurrent claims,
fencing, scrub/repair/GC, and rerun determinism.

```text
go -C vcs test ./internal/pft2/... ./internal/histstore/... \
  ./internal/historycut/... ./internal/histworker/... ./cmd/history-worker/...
go -C vcs test -race ./internal/histstore/... ./internal/histworker/...
pnpm --filter @portablefs/core test   # includes the Go<->TS PFT2 golden parity suite
```
