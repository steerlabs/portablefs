# Volume API

All endpoints are under `/v1`. If `VOLUME_API_TOKEN` is configured, clients send `Authorization: Bearer <token>`.

## Release Identity

`GET /v1/release-identity`

Names the exact build serving requests (release id, source revision, migration
lineage digest, capability list). Configured by release tooling; unconfigured
deployments answer `404 RELEASE_IDENTITY_UNAVAILABLE`. See
[release-identity.md](./release-identity.md).

## Volumes

`POST /v1/volumes`

Creates a volume and default branch.

```json
{
  "tenantId": "team_123",
  "volumeId": "vol_optional",
  "branchName": "main",
  "managed": true
}
```

With a tenant token, `tenantId` is optional and defaults to the token's tenant; an
explicit `tenantId` that names a different tenant is rejected. The admin token has no
tenant of its own, so it must pass `tenantId` explicitly.

`managed: true` births the branch journal-native (`managed_journal`): the managed
authority serves it immediately, so it can be mounted with no further step — the
shape `portablefs create` uses. The default (`false`) is the base-authoring shape:
a `legacy_manifest` branch whose committed base is authored through attach-session
manifest commits (what `portablefs adopt` does) and which enters journal service
through `POST /v1/volumes/:volumeId/activate-journal` afterwards.

`POST /v1/volumes/:volumeId/activate-journal`

Converges a base-authored (`legacy_manifest`) branch into managed journal service:
the server converts the committed manifest head into the immutable PFT2 base and
flips the branch mode (the 013 conversion). Idempotent and poll-driven — each call
advances at most one step and answers the current status; the resident history
worker materializes the conversion cut between calls. Mounting requires the branch
to be `managed_journal`; `portablefs adopt` drives this automatically as its final
step, and `portablefs activate` resumes an interrupted activation.

```json
{ "branch": "main" }
```

Response:

```json
{
  "state": "converting",
  "branchMode": "legacy_manifest",
  "conversion": { "conversionId": "hconv_...", "state": "final_cut", "attempt": 1 },
  "cut": { "cutId": "hcut_...", "state": "materializing", "attemptCount": 1 }
}
```

`state` is `active` (terminal: the branch serves managed journal), `converting`
(poll again), or `failed` (the bounded typed error facts ride on `conversion`/
`cut`; calling again re-queues a fresh attempt). A branch that is already
`managed_journal` answers `active` immediately.

`GET /v1/volumes?limit=100`

Lists volumes for a tenant, oldest-first, with each volume's branch heads. A tenant
token always lists its own tenant; the admin token must pass `?tenantId=...`.
`limit` defaults to 100 (max 500). Retired volumes (see `DELETE` below) never
appear.

```json
{
  "volumes": [
    {
      "volumeId": "vol_123",
      "tenantId": "team_123",
      "createdAtMs": 1767000000000,
      "branches": [
        {
          "name": "main",
          "headCommitId": "cmt_..."
        }
      ]
    }
  ]
}
```

`DELETE /v1/volumes/:volumeId`

Retires the volume — receipted, immediate, and irreversible at the API surface.
Tenant-scoped exactly like every other per-volume route: the caller's tenant
must own the volume. Success answers the retirement receipt:

```json
{
  "volumeId": "vol_123",
  "retiredAt": "2026-07-23T07:00:00.000Z"
}
```

Unknown and foreign volumes answer the same non-enumerating
`404 VOLUME_NOT_FOUND` the other routes use, so retirement state is never
distinguishable from non-existence **across tenants**. The owner's own
replay is different: a second `DELETE` of a volume the caller's tenant
already retired answers the **original receipt** again (HTTP `DELETE` is
idempotent), and re-runs the idempotent history cleanup — this is what lets
a control plane's caller-keyed operation ledger recover a lost or crashed
response by replaying the same `Idempotency-Key` until it holds the receipt.
The history-cleanup counts never appear in the receipt; they are logged
server-side.

Effects, transactionally with the flip:

- The volume disappears from `GET /v1/volumes` listings.
- Every per-volume plane refuses with that same 404: attach (plain and
  receipted), writer-lease renewal, grep, branch create/list, snapshot
  create/list, the `commits`/`status`/`head`/`wait-head`/`tree`/`file`/
  `manifest-diff` reads, `activate-journal`, mount-session creation (the
  authority child's attach is refused), and forks FROM the volume's
  snapshots or cuts.
- The retired `/exec` route remains `410 VOLUME_EXEC_RETIRED` independent of
  volume identity or lifecycle and performs no ownership lookup.
- Existing live mounts are **not** force-detached: they lose access as their
  leases and runtime credentials expire and fail to renew.
- Storage reclamation (blobs and history objects) is deferred; retirement
  deletes no data.

`GET /v1/volumes/:volumeId/commits?branch=main&limit=50`

Returns manifest-free commit summaries for a branch, newest-first, walking parent
links from the branch head. The walk crosses branch points, so a forked branch's
history includes its pre-fork ancestry. `branch` defaults to `main`; `limit`
defaults to 50 (max 500). `parentCommitId` is omitted on a volume's root commit.

On a journal-served branch the walk starts from the newest READY history
cut's published commit, so committed PFT2 revisions appear ahead of the
authored base ancestry. PFT2 entries carry the additive
`commitKind: "pft2"` discriminator and their `treeHash` is the stored
content-addressed root identity (`pft2:<hex>`); manifest entries are
unchanged (consumers ignore the unknown field).

```json
{
  "commits": [
    {
      "id": "cmt_new",
      "treeHash": "sha256:...",
      "createdAtMs": 1767000000000,
      "mutationCount": 3,
      "byteCount": 1024,
      "parentCommitId": "cmt_old"
    }
  ]
}
```

Use this endpoint for CLI history views. It never materializes manifests; pair it
with `/manifest-diff` or `/commits/:commitId/manifest` when file-level detail is
needed (PFT2 commits browse through `/tree` and `/file` with `?commit=`).

`GET /v1/volumes/:volumeId/status?branch=main`

Returns the volume, branch, head commit, and active lease/delegation counts.

The head commit includes the full tree manifest. Use this endpoint when a client needs to attach, refresh changed bytes, inspect the tree, or compute a diff.

`GET /v1/volumes/:volumeId/head?branch=main`

Returns the same volume, branch, and active lease/delegation counts, but the head commit is a manifest-free summary.

Use this endpoint for status checks and immediate clean refresh checks. It keeps the normal "has the branch advanced?" path off the large-manifest hot path.

`GET /v1/volumes/:volumeId/wait-head?branch=main&afterCommitId=cmt_...&timeoutMs=25000`

Waits until the branch head differs from `afterCommitId`, or until `timeoutMs` expires, and returns a manifest-free head summary plus `changed`.

```json
{
  "changed": true,
  "branch": {
    "headCommitId": "cmt_new"
  },
  "head": {
    "id": "cmt_new",
    "treeHash": "sha256:..."
  }
}
```

Use this endpoint for clean read-only live sessions. Postgres-backed deployments wake waiters with `LISTEN/NOTIFY` after the commit transaction advances the branch head. Implementations without native notifications may fall back to bounded server-side waiting. Clients still call `/manifest-diff` after a changed response to materialize only affected paths. A disconnected client releases the wait (and its `LISTEN` connection) immediately.

### What "head" means in the journal era

`branches.headCommitId` is the branch's COMMITTED truth, and its meaning
depends on the branch's serving phase:

- While a volume's branch is in its base-authoring phase (every branch a
  plain create/fork produces), the head is the latest manifest commit and
  moves on every commit — `status`, `head`, and `wait-head` behave exactly as
  documented above. This committed base manifest is what the branch's journal
  generation starts from when a live authority first claims it (replay is
  immutable base + journal suffix).
- Once a branch is journal-served (a branch born from a ready history cut,
  or any branch a live authority has claimed), the LIVE head is the journal
  tip inside PostgreSQL — observable through mounts, never through manifest
  routes — and the branch's committed history is published asynchronously as
  history cuts. `status`, `head`, `wait-head`, and `manifest-diff` refuse
  such branches with `409 LIVE_AUTHORITY_ROUTE_REQUIRED` rather than serving
  the stale manifest head as if it were live truth. Committed revisions are
  read through the snapshot (cut) listing, pinned-commit browse, and the
  exact history routes below.

`GET /v1/volumes/:volumeId/manifest-diff?branch=main&baseCommitId=cmt_...&rootPath=`

Returns a manifest diff from `baseCommitId` to the current branch head.

```json
{
  "baseCommitId": "cmt_old",
  "rootPath": "",
  "targetTreeHash": "sha256:...",
  "targetEntryCount": 1000,
  "diff": {
    "added": [],
    "changed": [],
    "removed": [],
    "mutationCount": 0,
    "byteCount": 0
  }
}
```

Use this when a VCS checkpoint reader, server-side reader, or direct API client already has a base manifest and the branch head changed. It avoids sending the full manifest for small updates on large trees. `rootPath` projects the diff to a subdirectory attachment.

## Attach

`POST /v1/volumes/:volumeId/attach`

```json
{
  "branch": "main",
  "mode": "write",
  "shared": false,
  "rootPath": "",
  "holderId": "runner-1",
  "leaseTtlMs": 600000,
  "prefetchPaths": ["src", "package.json"]
}
```

Write mode returns an attach session with a lease and fencing token. Read mode returns the committed manifest without a lease.

`shared: false` is the default exclusive writer mode. It rejects all other active writers and receives an implicit recursive checkout for `rootPath`.

`shared: true` allows multiple writers on one branch. Shared writers must checkout paths before commit. The VCS data plane coordinates live mounted writers; direct API clients must do this explicitly.

`rootPath` attaches a subdirectory as the local workspace root. Manifests returned to the client are projected to that root; commits are expanded back into the full branch tree by the API.

Plain attach serves base-authoring branches only; a journal-served branch
answers `409` (its live filesystem is served by the authority data plane).

`POST /v1/volumes/:volumeId/attach-receipted`

The exact-once attach the live authority uses. The request is the attach
shape plus a mandatory client-chosen `operationId`; the response adds a
`receipt` (`operationId`, `replayed`, `createdAt`) and a `current` projection
(the live branch/session facts observed in the same transaction). The
receipt row is permanent: a lost-response retry with the same `operationId`
and a semantically identical body replays the recorded outcome; the same id
with a different body answers `409 VOLUME_ATTACH_OPERATION_CONFLICT`, and a
replay whose retained prerequisites are gone answers
`410 VOLUME_ATTACH_COMMITTED_GONE`. On a journal-served branch the attach
base is the live generation's base commit (which may intentionally lag the
materialized branch head until a history cut); the response
`branch.headCommitId` names that base — the claimant's expected journal
base. Journal-branch attaches are manifest-free: the base may be a
content-addressed (PFT2) commit that carries no JSON manifest, and the
claimant resolves it through the base-provenance proof, never a manifest
projection — so branches born from cuts, and forks of live branches, attach
and mount normally. Deployments whose migration lineage is incomplete answer
`426 VOLUME_ATTACH_RECEIPTS_UNAVAILABLE`.

## Checkout And Delegations

`POST /v1/attach-sessions/:sessionId/checkout`

```json
{
  "leaseId": "lse_...",
  "fencingToken": 3,
  "path": "prospects/ada.sqlite",
  "recursive": false,
  "force": false
}
```

Claims write ownership for a file or folder. Checkout paths are relative to the attach `rootPath`. Conflicting active delegations return `VOLUME_DELEGATION_BUSY`; `force: true` revokes conflicting delegations and returns them in `revoked`.

`POST /v1/attach-sessions/:sessionId/checkin`

Releases a delegation by `path` or `delegationId`.

`GET /v1/attach-sessions/:sessionId/delegations`

Lists active delegations for a session. Add `includeReleased=true` to include historical released/revoked delegations.

## Blobs

`PUT /v1/blobs/:digest`

Uploads a content-addressed blob. The digest path segment is the literal `sha256:<hex>` value URL-encoded by clients.

`POST /v1/blobs/batch`

```json
{
  "blobs": [
    {
      "digest": "sha256:...",
      "bytesBase64": "..."
    }
  ]
}
```

Uploads multiple small content-addressed blobs in one API request. The API verifies every decoded payload against its digest, writes each blob to the backing store, records blob metadata in one metadata call, and returns the accepted blob refs. VCS checkpoints and direct API clients can use this route for small files; large blobs and large-file chunks continue to use binary `PUT /blobs/:digest`.

`GET /v1/blobs/:digest`

Downloads and verifies blob bytes.

`POST /v1/blobs/probe`

```json
{
  "digests": ["sha256:...", "sha256:..."]
}
```

Returns `{ "missing": ["sha256:..."] }` — the digests the calling tenant must still
upload before a commit can reference them. The probe consults only the caller's own
blob references: a digest another tenant already stored is still reported missing, so
probing never reveals cross-tenant existence and never lets a caller skip the
proof-of-possession upload. The admin token has no tenant and receives every digest
back as missing (deduplicated). 1 to 4096 digests per request. `portablefs adopt`
uses this route to skip re-uploading content the tenant already has.

Raw blob bodies (`PUT /v1/blobs/:digest` and `POST /v1/blobs/batch-binary`) are
capped by `VOLUME_API_MAX_BLOB_BODY_BYTES` (default 64 MiB); larger requests fail
with `413 VOLUME_BODY_TOO_LARGE`.

## Browse

Read-only views of committed trees. Both routes resolve `?branch=` (default `main`)
to the branch head, or pin an exact immutable commit with `?commit=` — a pinned
commit must belong to the addressed volume or the route answers 404. Neither route
touches the live authority; they read the commit manifest and content-addressed
blobs, so they are cheap and safe to poll.

`GET /v1/volumes/:volumeId/tree?path=&branch=&commit=&limit=&cursor=`

Lists the direct children of `path` (default: the volume root): directories first,
then files and symlinks, each group in name order.

```json
{
  "volumeId": "vol_123",
  "branchName": "main",
  "commitId": "cmt_...",
  "treeHash": "sha256:...",
  "path": "src",
  "entries": [
    {
      "name": "app.ts",
      "path": "src/app.ts",
      "kind": "file",
      "size": 22,
      "mode": 420,
      "executable": false,
      "mtimeMs": 1767000000000,
      "digest": "sha256:..."
    }
  ],
  "nextCursor": "app.ts"
}
```

`limit` defaults to 500 (max 2000). When more children remain, `nextCursor` holds the
last returned name; pass it back as `?cursor=` to continue (pin `?commit=` for stable
pagination while a branch is being written). Symlink entries carry `linkTarget`.
Errors: `404 VOLUME_PATH_NOT_FOUND` for a missing path, `409 VOLUME_PATH_NOT_DIRECTORY`
when `path` names a file or symlink.

Both routes also serve pinned PFT2 commits (`?commit=` naming a ready cut's
published commit): the tree is read lazily through the strict PFT2 reader —
every object located by its database registration and hash-verified before
decode. Two format-inherent differences from manifest listings: entries come
in PFT2's canonical raw-byte name order (not directories-first), and file
entries carry no whole-file `digest` (PFT2 content is page-addressed). PFT2
file reads are bounded at 64 MiB per request; use `Range` for larger files.
Branch-head browse on a journal-served branch is refused like the other
manifest head reads.

`GET /v1/volumes/:volumeId/file?path=&branch=&commit=&download=`

Streams one file's bytes from the committed tree. Responses carry a strong
`ETag` (the whole-file blob digest), `x-portablefs-kind: file`, and
`Accept-Ranges: bytes`; single-range `Range` requests answer `206` with
`Content-Range` (invalid ranges answer `416`), and `If-None-Match` answers `304`.
Chunked large files assemble only the chunks overlapping the requested range.
`Cache-Control` is `public, max-age=31536000, immutable` when `?commit=` is pinned
and `no-store` for branch-head reads. Symlinks answer 200 with
`x-portablefs-kind: symlink` and the link target as `text/plain`; directories answer
`409 VOLUME_PATH_NOT_FILE`. `?download=1` adds a `Content-Disposition` attachment
header.

## Commit

`POST /v1/attach-sessions/:sessionId/commit`

```json
{
  "leaseId": "lse_...",
  "fencingToken": 1,
  "expectedHeadCommitId": "cmt_...",
  "manifest": {},
  "mutationCount": 3,
  "byteCount": 1024
}
```

The API validates the lease, referenced blobs, and tree hash before advancing the branch.

The response includes the committed manifest. Use this compatibility route when the caller needs the server-expanded full branch tree immediately.

`POST /v1/attach-sessions/:sessionId/commit-summary`

Accepts the same body as `commit`, but returns a manifest-free commit summary. Use this compatibility route when a caller has a full projected manifest but does not need the full manifest echoed back.

`POST /v1/attach-sessions/:sessionId/commit-delta-summary`

```json
{
  "leaseId": "lse_...",
  "fencingToken": 1,
  "expectedHeadCommitId": "cmt_...",
  "targetTreeHash": "sha256:...",
  "diff": {
    "added": [],
    "changed": [],
    "removed": [],
    "mutationCount": 0,
    "byteCount": 0
  }
}
```

Applies a projected manifest diff to `expectedHeadCommitId` and returns a manifest-free commit summary. VCS checkpoints use this path so small changes on large trees send only changed and removed entries, not the whole manifest. If a shared writer commit merges over a newer head, a client can follow with `/manifest-diff` to materialize only the remote delta.

Exclusive commits require `expectedHeadCommitId` to equal the current branch head.

Shared commits compute the requested diff from `expectedHeadCommitId`. If the branch head has advanced, the API merges disjoint delegated changes onto the latest head. Overlapping changes return `VOLUME_MERGE_CONFLICT`. Readers never see either writer until a commit transaction advances the head.

## Snapshot And Fork

`POST /v1/volumes/:volumeId/snapshots`

Records an exact immutable revision of the branch. The wire shape is
unchanged (`201 { snapshot }`) with additive lifecycle fields:

- On a manifest-headed branch (the base-authoring phase) the snapshot pins
  the committed head exactly as before and is BORN READY: the record carries
  `state: "ready"` and `commitId` is the pinned content commit.
- On a journal-served branch the snapshot is an asynchronous **HistoryCut**:
  the database captures the exact journal position (generation, sequence,
  chain digest) under the append lock order and the resident history worker
  materializes it out of process into content-addressed PFT2 objects. The
  response carries the cut record: `state` starts `pending` (then
  `materializing`, then `ready`, or definitively `failed`/`canceled`),
  `cutId` names the cut, `cutSeqExclusive` the captured position, `commitId`
  the cut's base anchor commit (stable from creation), and `resultCommitId`
  the published PFT2 commit once ready. An optional additive `operationId`
  request field makes retried cut requests exact-once; without it,
  concurrent identical captures still converge on one cut row through the
  database dedup key. Convergence keeps the FIRST capture's `name`: a second
  `name` supplied for the same journal position answers the existing cut
  (same immutable state) under its original label.

```json
{ "branch": "main", "name": "before-rebase", "operationId": "cut-2026-07-18-a" }
```

`GET /v1/volumes/:volumeId/snapshots?branch=main`

Lists snapshot records — commit-pinned records plus this volume's cut-backed
records — oldest-first, each with its additive `state` (and `cutId`/
`resultCommitId` for cut-backed records).

`POST /v1/volumes/:volumeId/branches`

Creates a same-volume branch from a snapshot record.

```json
{
  "branchName": "experiment",
  "fromBranch": "main",
  "fromSnapshotName": "before-rebase"
}
```

- From a commit-pinned (manifest) record: exactly the previous behavior — a
  branch-point manifest commit on the new branch.
- From a READY cut-backed record (`fromSnapshotId` = the cut id): the branch
  is born journal-served at the cut's published PFT2 commit, with a durable
  branch-from-cut consumer and a fresh never-reused inode namespace — the
  exact provenance the serving base proof later verifies. The response's
  `head` is a manifest-free commit summary plus `commitKind: "pft2"` (PFT2
  commits carry no JSON manifest).
- A `pending`/`materializing` cut answers `409 HISTORY_CUT_NOT_READY`; a
  `failed`/`canceled` cut answers `409 HISTORY_CUT_FAILED`. Only ready cuts
  can be branched, forked, or published.

`GET /v1/volumes/:volumeId/branches`

Lists same-volume branches.

`POST /v1/snapshots/:snapshotId/fork`

Creates a new volume and branch at the snapshot commit. The destination is
journal-born: its branch starts at the pinned manifest commit — the
committed base its journal generation starts from when first claimed. This
commit-pinned path is byte-identical to before.

Forking a READY cut-backed (PFT2) record creates a new MANAGED volume
(migration `018_managed_volume_fork`), zero-copy and atomic in one database
transaction: the destination's default branch is born `managed_journal` at a
fork-point PFT2 commit carrying the cut's exact immutable user root (no
object is duplicated), the shared history objects are GC-pinned by the
destination's durable fork cut consumer, and the branch receives its own
fresh never-reused inode namespace — the exact provenance the serving base
proof later verifies as `baseMode: "fork"` when the first authority claims
the volume. The response keeps the fork shape (`volume`/`branch`/`head`)
with the additive `commitKind: "pft2"` (the head is a manifest-free commit
summary, exactly like branch-from-cut), plus `operationId` and `replayed`.
An optional `operationId` request field makes fork retries exact-once: an
identical retry replays the recorded destination; the same id with a changed
payload answers `409 HISTORY_FORK_REJECTED`, as does a destination
`volumeId` that already exists.

Pending and failed cuts refuse with the same typed codes as branch creation
(`HISTORY_CUT_NOT_READY` / `HISTORY_CUT_FAILED`). A repository whose
migration lineage predates 018 keeps answering `409 HISTORY_FORK_UNSUPPORTED`
for cut-backed records (a destination its serving proof could never open
would be a bricked volume).

## Compute And Search

`POST /v1/volumes/:volumeId/exec`

Retained only as a retirement contract. It always answers
`410 VOLUME_EXEC_RETIRED`; the body is not parsed and no volume state is
read. The Volume API never materializes host paths or runs tenant commands.
Mount the volume and execute locally, or use a separately isolated runner
with short-lived mount credentials.

`POST /v1/volumes/:volumeId/grep`

Searches file bytes server-side without mounting a workspace, against the
committed head on an authoring branch or a per-call HistoryCut of the live
state on a live branch.

```json
{
  "branch": "main",
  "directory": "prospects",
  "pattern": "qualified",
  "recursive": true,
  "maxResults": 1000
}
```

Regex compilation and matching run in a resource-limited worker that is
terminated on the request's absolute deadline or disconnect; tenant regex
bytecode never executes on the API event loop. Both legacy manifests and
PFT2 cuts share the same limits: 10,000 files, 16 MiB per file, 64 MiB total
input, 256 KiB per line, 8 MiB matched output, the request's `maxResults`,
and a 60-second maximum deadline. A byte/line/result quota answers
`413 VOLUME_GREP_LIMIT_EXCEEDED`; a deadline returns partial results with
`stoppedReason: "deadline"`.

## Exact History Serving

Tenant history reads are exact: every read obtains a positive database proof
before any storage byte is touched, object bytes come only from
database-recorded exact storage keys in declared failure domains
(`PFH_WORKER_STORES_JSON` / `VOLUME_HISTORY_STORES_JSON` — the same map the
history worker writes with), are bounded by the frozen PFT2 maximum object
size, and are SHA-256 verified before exposure. A missing or corrupt copy
falls through to the next independent failure domain and is queued for the
worker's ordinary scrub/repair loop. Deployments without configured history
stores answer `503 HISTORY_SERVING_UNAVAILABLE`. Routes accept `GET` and
`HEAD` only, refuse request bodies and `Range` headers, and are
tenant-token-only (the admin token is never treated as a tenant).

`GET /v1/history/base-provenance/:commitId?generationId=&baseSeq=&baseDigest=&recordCodec=&controlCodec=`

Atomically proves the exact journal base tuple a claimed generation
returned. The caller presents every fact from its claim; the database
answers a POSITIVE commit family — `{ "provenance": { "kind":
"manifest_v1", ... } }` for a committed base manifest, or `kind: "pft2"`
with the database-proven `baseMode` (`fork` | `conversion` | `adopted`),
the verified root reference, and (for adopted/conversion bases) the recovery
anchor. Absence is `404`; a contradicted tuple is `409
HISTORY_BASE_PROOF_REJECTED`. Callers never infer a commit family from
absence, timeout, or malformed data.

`GET /v1/history/objects/:digest`

Serves one immutable PFT2 object's exact complete bytes. The digest is
located in the tenant-scoped object registry first (an object present in
storage but absent from the database is `404 HISTORY_NOT_FOUND`), then read
from a recorded copy and verified. Responses carry a strong `ETag` and
`Cache-Control: private, max-age=31536000, immutable`. When no verified
copy is available the route answers `503 HISTORY_OBJECT_UNAVAILABLE`.

## Detach And Renew

`POST /v1/leases/:leaseId/renew`

Extends a live write lease when the fencing token still matches.

`POST /v1/attach-sessions/:sessionId/detach`

Releases the write lease and marks the attach session detached.

## Resource Admission And Shutdown

Every request is admitted against three independent budgets BEFORE
authentication and before any body byte is read — resolving a tenant token
is a database query, so unauthenticated floods consume (and are refused by)
the same caps: a global active-request cap (128), a weighted
transient-memory budget (256 MiB; a request weighs its declared
Content-Length at the route's audited parse amplification plus a fixed
response reservation, and chunked bodies prepay the route maximum), and
per-route concurrency caps. All three fail fast with
`429 VOLUME_OVERLOADED`; a Content-Length above the route bound is
`413 VOLUME_BODY_TOO_LARGE` without reading a byte. Success responses are
serialized inside each route's audited bound; larger results answer
`413 VOLUME_RESPONSE_TOO_LARGE` instead of an unbounded body. Admission
permits release when handler WORK settles — never merely because the client
socket closed.

On `SIGTERM`/`SIGINT` the process drains: new requests (including on
surviving keepalive connections) answer `503 VOLUME_DRAINING` with
`Connection: close` while `/healthz` stays 200; dispatched durable effects
(attach, commit, blob record) settle before the repository closes;
read-only waits (wait-head long polls, grep scans, history
reads) are aborted 20 seconds in; and the process hard-exits nonzero rather
than interrupting a dispatched mutation.
