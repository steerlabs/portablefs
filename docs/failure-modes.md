# Failure Modes

## VCS Process Dies

In local development, mounted clients disconnect until the VCS restarts. On restart, the VCS
loads the last committed manifest, replays the local WAL, and resumes from the live-durable
state it had acknowledged.

In production, the authority process is a disposable cache over the remote journal: every
authority-acknowledged write already committed to the fenced PostgreSQL journal before the
client heard "done". The manager demand-starts a replacement child anywhere; it claims the journal
generation (fencing any stale writer in the same transaction), cold-replays the immutable base
plus the retained journal suffix, and serves — no authority-durable write is lost, and there is no
promotion protocol and no warm standby to keep consistent.

## Mount Process Or Machine Dies

A delegated `write(2)` is accepted after its frames reach the local WAL file
descriptor and overlay; it does not wait for physical local sync. The 5 ms /
4 MiB group-sync normally closes that window quickly. A process crash leaves
the kernel page cache available to write the tail, but a complete machine
power loss may lose writes that had not crossed group-sync or `fsync`.

`fsync`, synchronize, explicit flush, and clean unmount
force the local WAL before draining to authority durability. A verified local
tail replays exactly on the next attach. Recovery never guesses: malformed
WAL, identity mismatch, or authority conflict remains a typed blocked job for
an operator.

Any WAL initialization, append, rotation, checkpoint, group-sync, or explicit
sync error latches a terminal mount verdict. Every later mutation fails until
remount; no operation silently becomes write-through and no unrelated scope
continues around the failed stream.

## Manager Restart (Session Token Rejection)

A manager restart is an epoch handoff, and access-lease session tokens are HMACs keyed per
(manager epoch, token generation) — so the moment a new epoch claims, EVERY mount's token is
dead at once. The data-plane router answers a dead token's frame with a one-byte ack `1` and
closes.

The mount client treats that ack (or a clean close right after the token frame, before any ack)
as a typed credential failure, distinct from an ordinary dead socket: redialing with the same
token can never succeed. It surfaces the failure and does not re-resolve, create a replacement
lease, or retry through another route. The operator cleanly unmounts, authenticates if needed,
and mounts again as a new explicit session.

The lease keeper is reactive to the same event on its HTTP path: a renew refused with a typed
terminal code — `ACCESS_LEASE_EPOCH_SUPERSEDED` (which ships as a 503, deliberately overriding
the "5xx is ambiguous, retry the same operation" rule), `ACCESS_LEASE_NOT_FOUND`,
`ACCESS_LEASE_EXPIRED`, `ACCESS_LEASE_REVOKED`, `ACCESS_LEASE_RELEASED`, or
`ACCESS_LEASE_UNAUTHORIZED` — stops that lease and surfaces a terminal mount status. It never
creates a replacement lease.

## Authority Loses Its Fencing

A child that loses its writer lease, its manager lease pipe (EOF, a stale or foreign frame, a
lease deadline passing without a database-grounded extension), or its journal fencing must stop
serving the data plane and report not-ready. The journal rejects appends and suspends from a
superseded manager/runtime binding at the database, so a deposed authority cannot advance the
branch after a replacement has claimed — even if its process lingers.

## Journal Append Failure

If the authority cannot commit a mutation to its durable log — the remote journal in
production, the local WAL in development — it must fail the filesystem operation rather than
acknowledge a write it cannot prove durable. A proven fence, conflict, or integrity failure
poisons the log handle: the node fences its data plane and a replacement recovers from the
journal instead of the poisoned process state.

## Checkpoint Fails After Blob Upload

Uploaded blobs may become orphaned if the metadata commit never lands. The live filesystem state
remains in the VCS working tree and WAL, and the branch head remains unchanged. A later checkpoint
can reuse or re-upload the same content-addressed blobs and commit normally.

## Railway Bucket Failure

Blob upload or download failure affects history materialization or cold content fetch, not the
already acknowledged live journal state. The branch head does not advance until required
content is present and verified.

## Postgres Failure

In production the journal database IS the durability layer: while it is unavailable or cannot
prove its durability evidence, authority-lane writes and durability barriers fail loudly.
Already authority-durable writes stay safe in the journal; a delegated mount may continue to
accept into its bounded local WAL until its own health or capacity gate refuses more. Metadata operations
— lease renewal, branch-head reads, snapshots, forks, history — fail while their database is
unavailable; an authority that cannot renew self-fences before its lease expires. In
development, authority-acknowledged writes remain WAL-durable locally but cannot become
checkpoint-durable until metadata commits resume.

## Local Disk Full

A managed production authority child keeps no persistent local files — its
disk pressure affects only RAM-bounded caches and temp space. Mounts do keep
their delegated stream WAL locally. If that store cannot initialize, append,
rotate, checkpoint, or sync, the mount seals its full mutation gate and
reports a sticky unhealthy verdict; it does not redirect writes to the
authority. In development, an authority-local WAL failure likewise fails the
operation and should report unhealthy/not-ready. Previously committed branch
history remains intact.

## Cache Corruption

The VCS and API verify cached blobs and chunks by digest before serving them. A corrupt cache entry
is discarded and refetched. Cache files are acceleration only; the durable records are the journal
(the local WAL in development) for live state and content-addressed blobs plus Postgres metadata
for committed history.

## Lost Reply (UNKNOWN Mutation Outcome)

A connection can die after a mutation was durably prepared but before its reply arrived. The
authority never invents an errno for such a request — it drops the connection — and the mount
parks the mutation's exact-once identity and replays the identical bytes until it gets a definite
answer: the original execution's stored outcome, a stored rejection, or a session fence. The
caller that was blocked on the mutation sees a definite error after the foreground budget
(`mutation outcome unknown; identity parked for replay`), but the identity keeps replaying in the
background and lands at most once.

Operator guidance: parked identities resolve by exact replay across authority
restarts and failover (against whichever authority holds the durable log);
this is completion of the original identity, not inferred repair. A mount logging repeated
replay attempts indicates the authority is unreachable or cannot record durably (a poisoned
log) — resolve the authority; do not restart the mount to "clear" it, since a remount abandons
the mount's session and its parked identities resolve as fenced.

## Session Fence (ESTALE)

A mount session generation is fenced — every further mutation from it fails ESTALE — for exactly
these reasons:

- **Lease expiry.** The mount stopped renewing (crashed, partitioned past the lease TTL). The
  sweeper durably fences the session and releases its locks and delegations.
- **Supersession.** A newer generation of the same session id established (a remount of the same
  volume identity).
- **Voluntary expire.** A clean unmount expires its own session.
- **Proven client-state corruption.** An identity was replayed with different content, or the
  slot sequence gapped. The authority refuses to execute anything further from that generation
  because interleaving with the lost state would be undefined.

A fenced mount never re-establishes itself: a zombie that auto-minted a fresh generation could
overwrite its successor's writes. Operator guidance: remount. The fence is durable — it survives
authority restarts — and the fenced mount's write-back records are kept locally (never applied,
never compacted away) so nothing is silently lost.

## Manifest-Only Rebuild (Catastrophic Recovery)

Rebuilding an authority from only a committed base — a fresh journal generation with no
retained suffix, or a fresh WAL in development — loses journaled control state: sessions,
exact-once outcomes, and flush watermarks. Under `VCS_REQUIRE_EXACT_SESSIONS=1` (the managed
posture) the authority then fails closed — straggler flushes without a live authenticated
session are fenced ESTALE and apply nothing. Under the permissive development default a
straggler flush would reset its dedup cursor, so after a catastrophic rebuild prefer the
fail-closed posture until mounts have re-established.

## Delegation Conflict

The authority can reject conflicting subtree checkout attempts or force-revoke a stale holder.
Force revocation fences the old holder so delayed flushes from that owner cannot overwrite the new
owner's state.

## Concurrent Reader During Checkpoint

Mounted readers see the live VCS tree. Committed-history readers see the old branch head until the
checkpoint metadata transaction commits. They do not see partial checkpoint blobs or manifests.

## Snapshot During Active Session

On a base-authoring branch, snapshots pin the committed branch head. On a journal-served (live)
branch, a snapshot records a HistoryCut at the current journal position — every
authority-visible write up to the cut is captured — and materializes asynchronously; the record lists as pending
until ready, and a cut that fails to materialize is definitively `failed` (create a fresh one).

## Retired Server-Side Exec

The Volume API never runs tenant commands. The retained `/exec` route answers
`410 VOLUME_EXEC_RETIRED` before parsing its body or reading volume state.
Commands run through a mount in the caller's own isolation boundary, so command
failure has ordinary mounted-filesystem semantics.
